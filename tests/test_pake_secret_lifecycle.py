"""Public PAKE helpers release owned copies on failure, not caller inputs."""

from contextlib import contextmanager
import gc
import unittest
import weakref
from types import SimpleNamespace
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric import ec

from tls20_server import pake, pake_native
from tls20_server.errors import ConfigurationError, ProtocolError


def capture(operation):
    try:
        operation()
    except BaseException as error:
        return error
    raise AssertionError("operation unexpectedly succeeded")


def frames(error):
    pending, seen = [error], set()
    while pending:
        current = pending.pop()
        if id(current) in seen:
            continue
        seen.add(id(current))
        pending.extend(value for value in (current.__cause__, current.__context__) if value is not None)
        trace = current.__traceback__
        while trace:
            yield trace.tb_frame
            trace = trace.tb_next


class PakeSecretLifecycleTests(unittest.TestCase):
    def assert_owned_frames_cleared(self, error):
        owned = [frame for frame in frames(error)
                 if frame.f_globals.get("__name__") in ("tls20_server.pake", "tls20_server.pake_native")]
        self.assertTrue(owned)
        self.assertTrue(all(not frame.f_locals for frame in owned),
                        [(frame.f_code.co_name, tuple(frame.f_locals)) for frame in owned])

    def test_native_base_copy_is_wiped_across_every_setup_boundary(self):
        base, random = b"B" * 32, b"R" * 32  # Public synthetic credentials.
        original_buffer = pake_native._buffer
        for failure in (None, "scope-enter", "ready", "random-buffer", "native", "state", "scope-exit"):
            with self.subTest(failure=failure):
                copies, freed = [], []
                native = SimpleNamespace(_context=1, _live_keys=0)

                def fail_at(stage):
                    callback_marker = "caller callback frame must remain intact"
                    if failure == stage:
                        try:
                            raise ValueError("synthetic cause")
                        except ValueError as cause:
                            raise RuntimeError("synthetic " + stage) from cause
                    return callback_marker

                @contextmanager
                def scope():
                    fail_at("scope-enter")
                    try:
                        yield
                    finally:
                        fail_at("scope-exit")

                def buffer(value):
                    if value == random:
                        fail_at("random-buffer")
                    result = original_buffer(value)
                    if value == base:
                        copies.append(result)
                    return result

                def create(*args):
                    fail_at("native")
                    # No native key is needed to exercise wrapper ownership.
                    return 17 if failure == "state" else 0

                native._native_scope = scope
                native._ready = lambda: fail_at("ready")
                native.lib = SimpleNamespace(OBJ_txt2nid=lambda _: 1, ERR_clear_error=lambda: None)
                provider = SimpleNamespace(provider=native, functions=(),
                    lib=SimpleNamespace(tls20_pwd_new=create, tls20_pwd_free=freed.append))
                with patch.object(pake_native, "_buffer", buffer), patch.object(
                        pake_native, "PakeState", side_effect=lambda *args: fail_at("state")):
                    error = capture(lambda: pake_native.PakeProvider.create(provider, base, random))
                self.assertIsInstance(error, ProtocolError if failure is None else RuntimeError)
                self.assertTrue(all(value.raw == bytes(32) for value in copies))
                self.assertEqual(native._live_keys, 0)
                self.assertEqual(freed, [17] if failure == "state" else [])
                self.assert_owned_frames_cleared(error)
                if failure is not None:
                    callbacks = [frame for frame in frames(error) if frame.f_code.co_name == "fail_at"]
                    self.assertTrue(callbacks)
                    self.assertTrue(all(frame.f_locals["callback_marker"] ==
                        "caller callback frame must remain intact" for frame in callbacks))
                self.assertEqual(base, b"B" * 32)

    def test_partial_native_state_construction_frees_exactly_once(self):
        class FailingCounter(int):
            def __add__(self, other):
                raise MemoryError("synthetic counter allocation failure")

        for failure in (False, True):
            with self.subTest(failure=failure):
                freed = []

                @contextmanager
                def scope():
                    yield

                native = SimpleNamespace(_context=1,
                    _live_keys=FailingCounter(256) if failure else 256,
                    _native_scope=scope, _ready=lambda: None,
                    lib=SimpleNamespace(OBJ_txt2nid=lambda _: 1, ERR_clear_error=lambda: None))
                provider = SimpleNamespace(provider=native, functions=(),
                    lib=SimpleNamespace(tls20_pwd_new=lambda *args: 17,
                                        tls20_pwd_free=freed.append))
                if failure:
                    error = capture(lambda: pake_native.PakeProvider.create(provider, b"B" * 32, b"R" * 32))
                    self.assertIsInstance(error, MemoryError)
                    self.assert_owned_frames_cleared(error)
                else:
                    state = pake_native.PakeProvider.create(provider, b"B" * 32, b"R" * 32)
                    self.assertEqual(native._live_keys, 257)
                    state.close()
                    del state
                gc.collect()
                self.assertEqual(freed, [17])
                self.assertEqual(native._live_keys, 256)
        # Allocation can also stop before __init__ assigns any attributes.
        incomplete = pake_native.PakeState.__new__(pake_native.PakeState)
        incomplete.close()

    def test_retained_error_does_not_keep_wrapper_password_arguments_alive(self):
        class PublicFixture(str):
            __slots__ = ("__weakref__",)

        def fail_then_release_caller(keyword):
            password = PublicFixture("public password fixture")
            reference = weakref.ref(password)
            try:
                if keyword:
                    pake.password_base(username="alice", password=password, salt=b"invalid")
                else:
                    pake.password_base("alice", password, b"invalid")
            except ConfigurationError as error:
                self.assertEqual(password, "public password fixture")
                del password
                return error, reference
            raise AssertionError("invalid salt was accepted")

        for keyword in (False, True):
            with self.subTest(keyword=keyword):
                error, reference = fail_then_release_caller(keyword)
                gc.collect()
                self.assertIsNone(reference())
                self.assert_owned_frames_cleared(error)

    def test_username_bounds_precede_crypto_and_valid_roundtrip_is_unchanged(self):
        for curve, maximum in ((ec.SECP256R1(), 207), (ec.SECP384R1(), 191), (ec.SECP521R1(), 173)):
            private = ec.generate_private_key(curve)
            with self.subTest(curve=curve.name):
                username = "U" * maximum
                encoded = pake.protect_username(username, private.public_key())
                self.assertEqual(len(encoded), 255)
                self.assertEqual(pake.recover_username(encoded, private), username.encode())
                with patch.object(pake.ec, "generate_private_key", side_effect=AssertionError("crypto began")) as generate:
                    error = capture(lambda: pake.protect_username(username + "U", private.public_key()))
                self.assertIsInstance(error, ConfigurationError)
                generate.assert_not_called()
                self.assert_owned_frames_cleared(error)

    def test_password_and_username_failures_clear_derived_frames_and_causes(self):
        private = ec.generate_private_key(ec.SECP256R1())
        encoded = pake.protect_username("alice", private.public_key())
        invalid = encoded[:-1] + bytes((encoded[-1] ^ 1,))
        operations = (
            lambda: pake.password_base("alice", "secret fixture", b"wrong length"),
            lambda: pake.protect_username("U" * 208, private.public_key()),
            lambda: pake.recover_username(invalid, private),
        )
        for operation in operations:
            with self.subTest(operation=operation.__code__.co_firstlineno):
                error = capture(operation)
                self.assertIsInstance(error, (ConfigurationError, ProtocolError))
                self.assert_owned_frames_cleared(error)
        self.assertEqual(len(pake.password_base("alice", "secret fixture")), 32)

    def test_injected_encryption_failure_releases_ecdh_and_hkdf_copies(self):
        private = ec.generate_private_key(ec.SECP256R1())

        def reject_encrypt(*args):
            callback_marker = "callback state is not protocol-owned"
            raise RuntimeError(callback_marker)

        with patch.object(pake, "AESSIV", return_value=SimpleNamespace(encrypt=reject_encrypt)):
            error = capture(lambda: pake.protect_username("alice", private.public_key()))
        self.assertIsInstance(error, RuntimeError)
        self.assert_owned_frames_cleared(error)
        callback = next(frame for frame in frames(error) if frame.f_code.co_name == "reject_encrypt")
        self.assertEqual(callback.f_locals["callback_marker"], "callback state is not protocol-owned")
        # Shared caller provisioning was not invalidated by a failed operation.
        self.assertEqual(pake.recover_username(pake.protect_username("alice", private.public_key()), private), b"alice")


if __name__ == "__main__":
    unittest.main()
