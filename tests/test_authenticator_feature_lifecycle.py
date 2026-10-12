"""Real authenticator proofs: feature requirements and abandoned key ownership."""

import asyncio
import unittest
from unittest.mock import patch

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, x25519
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from tls20_server import crypto as c, messages as m
from tls20_server.application_auth import AuthenticatorManager, credential_validator
from tls20_server.credential_profiles import CredentialPolicy
from tls20_server.credential_selection import _length
from tls20_server.errors import ProtocolError
from tls20_server.pki import Credentials
from tests.test_application_auth import endpoint
from tests.test_pki import der, issue


def protocol_locals(error):
    seen, pending, retained = set(), [error], []
    while pending:
        current = pending.pop()
        if id(current) in seen:
            continue
        seen.add(id(current))
        pending.extend(value for value in (current.__cause__, current.__context__) if value is not None)
        pending.extend(getattr(current, "exceptions", ()))
        trace = current.__traceback__
        while trace:
            frame = trace.tb_frame
            if (frame.f_globals.get("__name__", "").startswith("tls20_server.")
                    and frame.f_code.co_name != "guarded" and frame.f_locals):
                retained.append((frame.f_code.co_name, tuple(frame.f_locals)))
            trace = trace.tb_next
    return retained


class AuthenticatorFeatureLifecycleTests(unittest.IsolatedAsyncioTestCase):
    def setup_pair(self, role="server", features=()):
        ca = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Authenticator test CA")])
        root = issue(ca, ca, name, name, ca=True)
        private = x25519.X25519PrivateKey.generate()
        extensions = [(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH if role == "server"
                                              else ExtendedKeyUsageOID.CLIENT_AUTH]), False)]
        if features:
            integers = b"".join(b"\x02" + _length(value.to_bytes(max(1, (value.bit_length() + 8) // 8), "big"))
                                for value in features)
            extensions.append((x509.UnrecognizedExtension(x509.ObjectIdentifier("1.3.6.1.5.5.7.1.24"),
                                                          b"\x30" + _length(integers)), False))
        leaf = issue(private, ca, name, name, hostname="localhost", eku=False, extra=extensions)
        credentials = Credentials([der(leaf)], private)
        share = x25519.X25519PrivateKey.generate()
        secret = bytes(range(32))
        client = AuthenticatorManager(endpoint("client", secret, share, b""))
        server = AuthenticatorManager(endpoint("server", secret, None, c.public_bytes(share)))
        offers = client.channel.local_capabilities + ((0xff02, c.public_bytes(share)),)
        client.channel.local_capabilities = server.channel.peer_capabilities = offers
        verifier, prover = (client, server) if role == "server" else (server, client)
        self.addCleanup(verifier.close)
        self.addCleanup(prover.close)
        policy = CredentialPolicy(trust_roots=(root,), peer_name="localhost", revocation_policy="offline",
                                  authorize_client=lambda material, evidence: material == (der(leaf),))
        validator = credential_validator(policy, role=role, authorize=lambda identity: True,
                                         spontaneous_offers=offers)
        return verifier, prover, credentials, validator

    async def test_actual_path_and_mac_features_in_both_directions(self):
        for role, share in (("server", 0xff02), ("client", 0xff03)):
            for features in ((), (50,), (share,), (50, share), (0x1234,)):
                with self.subTest(role=role, features=features):
                    verifier, prover, credentials, validator = self.setup_pair(role, features)
                    request = verifier.request()
                    wire = prover.authenticate(credentials, request=request)
                    self.assertTrue((await verifier.validate(wire, validator)).authenticated)
                    self.assertFalse(verifier._pending)

    async def test_spontaneous_current_path_and_mac_features(self):
        verifier, prover, credentials, validator = self.setup_pair(features=(50, 0xff02))
        wire = prover.authenticate(credentials)
        self.assertTrue((await verifier.validate(wire, validator)).authenticated)

    async def test_actual_delegated_grant_satisfies_its_independent_feature(self):
        from tests.test_credential_profiles import CredentialProfileTests
        for role, share in (("server", 0xff02), ("client", 0xff03)):
            with self.subTest(role=role):
                verifier, prover, _credentials, _validator = self.setup_pair(role)
                fixture = CredentialProfileTests()
                fixture.setUp()
                encoded = b"".join(b"\x02" + _length(value.to_bytes(max(1, (value.bit_length() + 8) // 8), "big"))
                                   for value in (34, 50, share, 0xff04))
                feature = x509.UnrecognizedExtension(x509.ObjectIdentifier("1.3.6.1.5.5.7.1.24"),
                                                     b"\x30" + _length(encoded))
                def feature_parent(*args, **kwargs):
                    kwargs["extra"] = [*kwargs.get("extra", ()), (feature, False)]
                    return issue(*args, **kwargs)
                with patch("tests.test_credential_profiles.issue", side_effect=feature_parent):
                    parent, grant = fixture.parent_and_grant(role=role)
                credentials = Credentials([der(parent)], fixture.key)
                policy = CredentialPolicy(trust_roots=(fixture.root,), peer_name="example.test",
                                          authorize_client=lambda *args: True)
                validator = credential_validator(policy, role=role, authorize=lambda identity: True)
                extra = ((34, m._vec((0xfe00 if role == "server" else 0xfe01).to_bytes(2, "big"), 2)),
                         (0xff04, b"\0\2\x08\x07"))
                request = verifier.request(certificate_algorithms=(0x0403,), extra_extensions=extra)
                wire = prover.authenticate(credentials, request=request, entry_extensions=(((34, grant),),))
                self.assertTrue((await verifier.validate(wire, validator)).authenticated)

    async def test_merely_offered_evidence_or_grant_cannot_satisfy_requirement(self):
        for feature, extra in ((5, ((5, b""),)), (0x1234, ((0x1234, b""),)),
                               (0xff04, ((34, b"\0\2\xfe\0"), (0xff04, b"\0\2\x04\x03")))):
            with self.subTest(feature=feature):
                verifier, prover, credentials, validator = self.setup_pair(features=(feature,))
                request = verifier.request(extra_extensions=extra)
                wire = prover.authenticate(credentials, request=request)
                with self.assertRaisesRegex(ProtocolError, "mandatory TLS Feature"):
                    await verifier.validate(wire, validator)

    async def test_feature_state_does_not_bypass_mac_finished_or_authorization(self):
        for role in ("server", "client"):
            for corruption in ("mac", "finished", "authorization"):
                with self.subTest(role=role, corruption=corruption):
                    verifier, prover, credentials, validator = self.setup_pair(role, (50,))
                    request = verifier.request()
                    wire = prover.authenticate(credentials, request=request)
                    if corruption == "mac":
                        first_end = 4 + int.from_bytes(wire[1:4], "big")
                        position = first_end + 8
                        wire = wire[:position] + bytes([wire[position] ^ 1]) + wire[position + 1:]
                    elif corruption == "finished":
                        wire = wire[:-1] + bytes([wire[-1] ^ 1])
                    else:
                        validator = lambda *args: None
                    caught = None
                    try:
                        await verifier.validate(wire, validator)
                    except ProtocolError as error:
                        caught = error
                    self.assertIsNotNone(caught)
                    self.assertFalse(verifier._pending)
                    self.assertEqual(protocol_locals(caught), [])
                    with self.assertRaises(ProtocolError):
                        await verifier.validate(wire, validator, request=request)

    async def test_bad_request_releases_generated_key_preserving_other_pending(self):
        verifier, prover, credentials, validator = self.setup_pair()
        request = verifier.request()
        before = dict(verifier._pending)
        for kwargs in ({"certificate_algorithms": ()}, {"context": next(iter(before))}):
            caught = None
            try:
                verifier.request(**kwargs)
            except ProtocolError as error:
                caught = error
            self.assertIsNotNone(caught)
            self.assertEqual(protocol_locals(caught), [])
            self.assertEqual(verifier._pending, before)
        wire = prover.authenticate(credentials, request=request)
        self.assertTrue((await verifier.validate(wire, validator)).authenticated)

    async def test_cancelled_validation_consumes_only_its_context(self):
        verifier, prover, credentials, validator = self.setup_pair()
        first, second = verifier.request(), verifier.request()
        wire = prover.authenticate(credentials, request=first)
        entered = asyncio.Event()
        marker = object()
        callback_cancelled = asyncio.Event()
        callback_errors = []

        async def wait_for_policy(*args):
            application_owned = marker
            entered.set()
            try:
                await asyncio.Future()
            except asyncio.CancelledError as error:
                callback_errors.append(error)
                callback_cancelled.set()
                raise
            return application_owned

        task = asyncio.create_task(verifier.validate(wire, wait_for_policy))
        await entered.wait()
        task.cancel()
        caught = None
        try:
            await task
        except asyncio.CancelledError as error:
            caught = error
        self.assertIsNotNone(caught)
        self.assertEqual(protocol_locals(caught), [])
        self.assertEqual(len(verifier._pending), 1)
        # Policy cancellation is deliberately separated from the caller's
        # cancellation so a non-cooperative policy cannot retain our secrets.
        await asyncio.wait_for(callback_cancelled.wait(), 1)
        trace = callback_errors[0].__traceback__
        while trace and trace.tb_frame.f_code.co_name != "wait_for_policy":
            trace = trace.tb_next
        self.assertIsNotNone(trace)
        self.assertIs(trace.tb_frame.f_locals["application_owned"], marker)
        wire = prover.authenticate(credentials, request=second)
        self.assertTrue((await verifier.validate(wire, validator)).authenticated)

    def live_pair(self, role="server"):
        from tls20_server.handshake import SecureChannel, Wire
        from tests.test_robustness import MemoryWriter
        verifier, prover, credentials, validator = self.setup_pair(role)
        for manager in (verifier, prover):
            old = manager.channel
            channel = SecureChannel(Wire(asyncio.StreamReader(), MemoryWriter()), bytes(32), bytes(32),
                exporter_secret=bytes(range(32)), role=old.role, enable_authenticators=True,
                auth_share_secret=old.auth_share_secret, peer_auth_share=old.peer_auth_share,
                local_capabilities=old.local_capabilities, peer_capabilities=old.peer_capabilities)
            channel._authenticators = manager
            manager.channel = channel
            self.addCleanup(channel.abort)
        return verifier, prover, credentials, validator

    async def test_manager_close_releases_spontaneous_share_not_traffic_or_other_capabilities(self):
        verifier, prover, credentials, validator = self.live_pair()
        other, other_prover, other_credential, other_validator = self.live_pair()
        request = verifier.request()
        expected = verifier.channel.exporter("still available")
        verifier.close()
        verifier.close()  # Idempotent capability closure.
        self.assertIsNone(verifier.channel.auth_share_secret)
        self.assertFalse(verifier._pending)
        self.assertFalse(verifier.channel.closed)
        self.assertEqual(verifier.channel.exporter("still available"), expected)
        await verifier.channel.send(b"ordinary application data")
        self.assertTrue(verifier.channel.wire.writer.data)
        with self.assertRaisesRegex(ProtocolError, "open connection"):
            verifier.request()
        self.assertIsNotNone(other.channel.auth_share_secret)
        response = other_prover.authenticate(other_credential)
        self.assertTrue((await other.validate(response, other_validator)).authenticated)
        self.assertIsNotNone(credentials.private_key)  # Shared credentials are not destroyed.

    async def test_closed_capability_revokes_inflight_keys_without_waiting_for_policy(self):
        for role in ("server", "client"):
            for ending in ("manager", "abort", "close", "peer_close"):
                with self.subTest(role=role, ending=ending):
                    verifier, prover, credentials, validator = self.live_pair(role)
                    request = verifier.request()
                    response = prover.authenticate(credentials, request=request)
                    entered, cancelled, release = asyncio.Event(), asyncio.Event(), asyncio.Event()
                    callbacks = []

                    async def stubborn(identity, parsed):
                        callbacks.append(asyncio.current_task())
                        entered.set()
                        try:
                            await asyncio.Future()
                        except asyncio.CancelledError:
                            cancelled.set()
                            await release.wait()  # Deliberately ignore/delay cancellation.
                        return await validator(identity, parsed)

                    with patch.object(verifier, "_keys", wraps=verifier._keys) as derive:
                        task = asyncio.create_task(verifier.validate(response, stubborn))
                        try:
                            await asyncio.wait_for(entered.wait(), 1)
                            state = next(iter(verifier._inflight.values()))
                            self.assertIsNotNone(state.private)
                            derive.assert_not_called()
                            if ending == "manager":
                                verifier.close()
                            elif ending == "abort":
                                verifier.channel.abort()
                            elif ending == "close":
                                await verifier.channel.close()
                            else:
                                peer = c.RecordState(bytes(32), "seal")
                                verifier.channel.wire.reader.feed_data(peer.seal(b"\1\0", 21))
                                peer.close()
                                self.assertIsNone(await verifier.channel.recv())
                            # These references disappear synchronously, before
                            # either validation or its policy task can resume.
                            self.assertIsNone(state.private)
                            self.assertTrue(state.closed.done())
                            self.assertIsNone(verifier.channel.auth_share_secret)
                            self.assertFalse(verifier._inflight)
                            with self.assertRaises(ProtocolError) as failed:
                                await asyncio.wait_for(task, 1)
                            self.assertEqual(protocol_locals(failed.exception), [])
                            await asyncio.wait_for(cancelled.wait(), 1)
                            self.assertFalse(callbacks[0].done())
                            derive.assert_not_called()
                            release.set()
                            self.assertIsNotNone(await asyncio.wait_for(callbacks[0], 1))
                            with self.assertRaises(ProtocolError):
                                await verifier.validate(response, validator, request=request)
                        finally:
                            release.set()
                            if not task.done():
                                task.cancel()
                            await asyncio.gather(task, *callbacks, return_exceptions=True)

    async def test_cancellation_cannot_be_swallowed_or_authorize_the_cancelled_request(self):
        for role in ("server", "client"):
            for behavior in ("wait", "return", "raise"):
                with self.subTest(role=role, behavior=behavior):
                    verifier, prover, credentials, validator = self.live_pair(role)
                    first, second = verifier.request(), verifier.request()
                    response = prover.authenticate(credentials, request=first)
                    entered, cancelled, release = asyncio.Event(), asyncio.Event(), asyncio.Event()
                    callbacks = []
                    async def stubborn(identity, parsed):
                        callbacks.append(asyncio.current_task())
                        entered.set()
                        try:
                            await asyncio.Future()
                        except asyncio.CancelledError:
                            cancelled.set()
                            if behavior == "wait":
                                await release.wait()
                            elif behavior == "raise":
                                raise RuntimeError("late callback failure")
                        return await validator(identity, parsed)
                    task = asyncio.create_task(verifier.validate(response, stubborn))
                    try:
                        await asyncio.wait_for(entered.wait(), 1)
                        state = next(iter(verifier._inflight.values()))
                        task.cancel()
                        with self.assertRaises(asyncio.CancelledError) as failure:
                            await asyncio.wait_for(task, 1)
                        await asyncio.wait_for(cancelled.wait(), 1)
                        self.assertEqual(protocol_locals(failure.exception), [])
                        self.assertIsNone(state.private)
                        self.assertTrue(state.closed.done())
                        self.assertFalse(verifier._inflight)
                        self.assertEqual(len(verifier._pending), 1)
                        self.assertFalse(verifier._closed)
                        self.assertFalse(verifier.channel.closed)
                        if role == "server":
                            self.assertIsNotNone(verifier.channel.auth_share_secret)
                        with self.assertRaises(ProtocolError):
                            await verifier.validate(response, validator, request=first)
                        wire = prover.authenticate(credentials, request=second)
                        self.assertTrue((await verifier.validate(wire, validator)).authenticated)
                    finally:
                        release.set()
                        if not task.done():
                            task.cancel()
                        await asyncio.gather(task, *callbacks, return_exceptions=True)

    async def test_reentrant_policy_closure_never_cancels_the_application_task(self):
        for asynchronous in (False, True):
            with self.subTest(asynchronous=asynchronous):
                verifier, prover, credentials, validator = self.live_pair()
                request = verifier.request()
                response = prover.authenticate(credentials, request=request)
                task = asyncio.current_task()
                cancellations = task.cancelling()
                def close_sync(*args):
                    verifier.close()
                    return object()
                async def close_async(identity, parsed):
                    verifier.close()
                    return await validator(identity, parsed)
                with self.assertRaises(ProtocolError):
                    await verifier.validate(response, close_async if asynchronous else close_sync)
                self.assertEqual(task.cancelling(), cancellations)
                self.assertIsNone(verifier.channel.auth_share_secret)
                self.assertFalse(verifier._inflight)
                self.assertFalse(verifier.channel.closed)
                await verifier.channel.send(b"traffic after capability closure")

    async def test_cancel_spontaneous_validation_preserves_share_until_capability_closes(self):
        verifier, prover, credentials, validator = self.live_pair()
        original = verifier.channel.auth_share_secret
        response = prover.authenticate(credentials)
        entered = asyncio.Event()
        async def wait(*args):
            entered.set()
            await asyncio.Future()
        task = asyncio.create_task(verifier.validate(response, wait))
        await asyncio.wait_for(entered.wait(), 1)
        state = next(iter(verifier._inflight.values()))
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await task
        self.assertIsNone(state.private)
        self.assertIs(verifier.channel.auth_share_secret, original)
        with self.assertRaises(ProtocolError):
            await verifier.validate(response, validator)
        response = prover.authenticate(credentials)
        self.assertTrue((await verifier.validate(response, validator)).authenticated)
        verifier.close()
        self.assertIsNone(verifier.channel.auth_share_secret)

    async def test_channel_abort_completes_blocked_validation_without_external_task_cancel(self):
        verifier, prover, credentials, _validator = self.live_pair()
        request = verifier.request()
        response = prover.authenticate(credentials, request=request)
        entered = asyncio.Event()
        async def blocked(*args):
            entered.set()
            await asyncio.Future()
        task = asyncio.create_task(verifier.validate(response, blocked))
        try:
            await asyncio.wait_for(entered.wait(), 1)
            verifier.channel.abort()
            with self.assertRaises(ProtocolError):
                await asyncio.wait_for(task, 0.5)
        finally:
            if not task.done():
                task.cancel()
            await asyncio.gather(task, return_exceptions=True)

    async def test_late_callback_exception_is_observed_and_does_not_retain_manager_state(self):
        from tls20_server.application_auth import _abandoned_authorizers
        verifier, prover, credentials, _validator = self.live_pair()
        request = verifier.request()
        response = prover.authenticate(credentials, request=request)
        entered, cancelled, release, finished = (asyncio.Event() for _ in range(4))
        callback_task = None
        async def late_failure(*args):
            nonlocal callback_task
            callback_task = asyncio.current_task()
            entered.set()
            try:
                await asyncio.Future()
            except asyncio.CancelledError:
                cancelled.set()
                await release.wait()
            finally:
                finished.set()
            raise RuntimeError("late application exception")
        task = asyncio.create_task(verifier.validate(response, late_failure))
        try:
            await asyncio.wait_for(entered.wait(), 1)
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task
            await asyncio.wait_for(cancelled.wait(), 1)
            self.assertIn(callback_task, _abandoned_authorizers)
            self.assertFalse(verifier._inflight)
            release.set()
            await asyncio.wait_for(finished.wait(), 1)
            await asyncio.sleep(0)  # Let its result-observer callback run.
            self.assertNotIn(callback_task, _abandoned_authorizers)
        finally:
            release.set()
            if not task.done():
                task.cancel()
            await asyncio.gather(task, *([callback_task] if callback_task else []), return_exceptions=True)

    async def test_prover_failure_releases_derived_keys_in_chained_exception(self):
        verifier, prover, credentials, validator = self.setup_pair()
        request = verifier.request()
        marker = object()

        def fail_mac(*args):
            application_owned = marker
            try:
                raise ValueError("provider failure")
            except ValueError as cause:
                raise ProtocolError("proof failed") from cause

        caught = None
        with patch("tls20_server.application_auth.c.mac", side_effect=fail_mac):
            try:
                prover.authenticate(credentials, request=request)
            except ProtocolError as error:
                caught = error
        self.assertIsNotNone(caught)
        self.assertIsInstance(caught.__cause__, ValueError)
        self.assertEqual(protocol_locals(caught), [])
        self.assertEqual(len(verifier._pending), 1)
        verifier.cancel(request)
        self.assertFalse(verifier._pending)


if __name__ == "__main__":
    unittest.main()
