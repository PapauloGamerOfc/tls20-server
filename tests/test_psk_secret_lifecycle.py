"""PSK provisioning failures release owned derived keys, not caller state."""

import asyncio
import unittest
from unittest.mock import patch

from tls20_server import crypto as c, messages as m, psk, tickets


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
        pending.extend(getattr(current, "exceptions", ()))
        trace = current.__traceback__
        while trace:
            yield trace.tb_frame
            trace = trace.tb_next


class PSKSecretLifecycleTests(unittest.TestCase):
    def assert_owned_frames_cleared(self, error):
        owned = [frame for frame in frames(error)
                 if frame.f_globals.get("__name__", "").startswith("tls20_server.")]
        self.assertTrue(owned)
        for frame in owned:
            if frame.f_code.co_name == "guarded":
                self.assertIsNone(frame.f_locals.get("args"))
                self.assertIsNone(frame.f_locals.get("kwargs"))
            else:
                self.assertFalse(frame.f_locals, (frame.f_code.co_name, tuple(frame.f_locals)))

    def test_importer_validates_public_metadata_before_deriving_keys(self):
        cases = (
            {"name": "bad/name"},
            {"protocol": b"p" * 256},
            {"cipher_suite": 0x1302},
            {"max_early_data": -1},
            {"max_early_data": 1 << 32},
            {"combined": True, "max_early_data": 1},
            {"external_identity": b"i" * 32768, "context": b"c" * 32768},
        )
        for changes in cases:
            with self.subTest(fields=tuple(changes)):
                args = dict(base_key=b"public base key fixture", external_identity=b"device",
                            context=b"scope", name="localhost")
                args.update(changes)
                with patch.object(c, "extract", side_effect=AssertionError("derivation began")) as derive:
                    error = capture(lambda: psk.import_psk(**args))
                self.assertIsInstance(error, ValueError)
                derive.assert_not_called()
                self.assert_owned_frames_cleared(error)

    def test_importer_constructor_errors_do_not_keep_the_derived_psk(self):
        base = b"public base key fixture"
        original = psk.ExternalPSK
        for base_hash in ("sha256", "sha384"):
            for target_hash in ("sha256", "sha384"):
                with self.subTest(base_hash=base_hash, target_hash=target_hash):
                    options = dict(base_hash=base_hash, target_hash=target_hash)
                    expected = psk.import_psk(base, b"device", b"scope", "localhost", **options)

                    def fail_constructor(*args, **kwargs):
                        callback_marker = "caller callback must remain intact"
                        # The failure is after deriving the key, not a mocked
                        # input-validation failure that would miss its lifetime.
                        self.assertEqual(args[1], expected.psk)
                        raise RuntimeError(callback_marker)

                    with patch.object(psk, "ExternalPSK", fail_constructor):
                        error = capture(lambda: psk.import_psk(base, b"device", b"scope", "localhost", **options))
                    self.assertIsInstance(error, RuntimeError)
                    self.assert_owned_frames_cleared(error)
                    callback = next(frame for frame in frames(error) if frame.f_code.co_name == "fail_constructor")
                    self.assertEqual(callback.f_locals["callback_marker"], "caller callback must remain intact")
                    self.assertIs(psk.ExternalPSK, original)
                    self.assertEqual(psk.import_psk(base, b"device", b"scope", "localhost", **options).psk, expected.psk)
                    self.assertEqual(base, b"public base key fixture")

    def test_ticket_bounds_precede_key_derivation_and_preserve_existing_tickets(self):
        for invalid in (-1, 1 << 32):
            with self.subTest(max_early_data=invalid):
                store = tickets.TicketStore()
                store.issue(b"S" * 32, "localhost", b"http/1.1")
                previous, size = dict(store._tickets), store._bytes
                with patch.object(c, "label_expand", side_effect=AssertionError("derivation began")) as derive:
                    error = capture(lambda: store.issue(b"S" * 32, "localhost", b"http/1.1", invalid))
                self.assertIsInstance(error, OverflowError)
                derive.assert_not_called()
                self.assert_owned_frames_cleared(error)
                self.assertEqual(dict(store._tickets), previous)
                self.assertEqual(store._bytes, size)

    def test_ticket_constructor_failure_preserves_caller_material_and_store(self):
        chain = [b"public certificate fixture"]
        for suite in (0x1301, 0x1302):
            with self.subTest(suite=hex(suite)):
                secret = b"S" * c.suite(suite).hash_length
                store = tickets.TicketStore()
                store.issue(secret, "localhost", b"http/1.1", cipher_suite=suite)
                previous, size = dict(store._tickets), store._bytes

                def fail_constructor(*args, **kwargs):
                    callback_marker = "application owns this callback"
                    self.assertEqual(len(args[1]), c.suite(suite).hash_length)
                    raise RuntimeError(callback_marker)

                with patch.object(tickets, "SessionTicket", fail_constructor):
                    error = capture(lambda: store.issue(secret, "localhost", b"http/1.1",
                        client_certificate_chain=chain, cipher_suite=suite))
                self.assertIsInstance(error, RuntimeError)
                self.assert_owned_frames_cleared(error)
                callback = next(frame for frame in frames(error) if frame.f_code.co_name == "fail_constructor")
                self.assertEqual(callback.f_locals["callback_marker"], "application owns this callback")
                self.assertEqual(dict(store._tickets), previous)
                self.assertEqual(store._bytes, size)
                self.assertEqual(chain, [b"public certificate fixture"])
                self.assertEqual(secret, b"S" * c.suite(suite).hash_length)
                message = store.issue(secret, "localhost", b"http/1.1", 4096,
                    client_certificate_chain=chain, cipher_suite=suite)
                identity, nonce, _, _, maximum = m.parse_new_session_ticket(message[4:])
                self.assertEqual(maximum, 4096)
                retained = store._tickets[identity]
                expected = c.label_expand(secret, "resumption", nonce,
                                         c.suite(suite).hash_length, c.suite(suite).hash_name)
                self.assertEqual(retained.psk, expected)
                self.assertEqual(retained.client_certificate_chain, chain)
                self.assertIsNot(retained.client_certificate_chain, chain)

    def test_provider_chains_groups_and_cancellation_release_only_protocol_frames(self):
        marker = object()
        base = b"public base key fixture"
        for api in ("importer", "ticket"):
            for cancellation in (False, True):
                with self.subTest(api=api, cancellation=cancellation):
                    store = tickets.TicketStore()

                    def failed_provider(*args, **kwargs):
                        application_owned = marker
                        try:
                            raise ValueError("synthetic provider cause")
                        except ValueError as cause:
                            if cancellation:
                                raise asyncio.CancelledError("synthetic cancellation") from cause
                            raise ExceptionGroup("synthetic failure", [cause, RuntimeError("provider detail")]) from cause

                    operation = (lambda: psk.import_psk(base, b"device", b"scope", "localhost")) if api == "importer" else (
                        lambda: store.issue(b"S" * 32, "localhost", b"http/1.1"))
                    with patch.object(c, "label_expand", failed_provider):
                        error = capture(operation)
                    self.assertIsInstance(error, asyncio.CancelledError if cancellation else ExceptionGroup)
                    self.assert_owned_frames_cleared(error)
                    callbacks = [frame for frame in frames(error) if frame.f_code.co_name == "failed_provider"]
                    self.assertTrue(callbacks)
                    self.assertTrue(all(frame.f_locals["application_owned"] is marker for frame in callbacks))
                    self.assertFalse(store._tickets)
                    self.assertEqual(store._bytes, 0)
                    self.assertEqual(base, b"public base key fixture")
                    operation()  # A failed call did not invalidate shared provisioning.


if __name__ == "__main__":
    unittest.main()
