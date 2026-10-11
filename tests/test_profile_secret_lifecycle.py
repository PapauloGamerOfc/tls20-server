"""Nested mixed-password handoffs retain only the established channel secrets."""

import asyncio
import os
import unittest
from unittest.mock import patch

from cryptography import x509

from tests import test_pake_handshake
from tls20_server import handshake as hs, pake_handshake as pwd
from tls20_server.application_auth import AuthorizedIdentity
from tls20_server.errors import ProtocolError
from tls20_server.lab import generate_lab_credentials
from tls20_server.secret_lifecycle import HandshakeSecrets


@unittest.skipUnless(os.environ.get("TLS20_TEST_PAKE") and os.environ.get("TLS20_TEST_OPENSSL"),
                     "explicit native PAKE fixture required")
class MixedHandshakeSecretTests(unittest.IsolatedAsyncioTestCase):
    # Reuse transport/provisioning setup, not its inherited tests.
    asyncSetUp = test_pake_handshake.PakeHandshakeTests.asyncSetUp
    asyncTearDown = test_pake_handshake.PakeHandshakeTests.asyncTearDown
    accept = test_pake_handshake.PakeHandshakeTests.accept
    handle = test_pake_handshake.PakeHandshakeTests.handle

    async def mixed_exchange(self, *, corrupt_finished=False):
        self.options = {"enable_authenticators": True}
        records, scopes = [], []
        original_init, original_record = HandshakeSecrets.__init__, HandshakeSecrets.record
        original_receive = hs.Wire.receive_frame

        def scope_init(scope):
            original_init(scope)
            scopes.append(scope)

        def record(scope, *args, **kwargs):
            state = original_record(scope, *args, **kwargs)
            records.append(state)
            return state

        reader, writer = await asyncio.open_connection("127.0.0.1", self.port)
        self.writers.append(writer)

        async def receive(wire, expected, *args, **kwargs):
            message = await original_receive(wire, expected, *args, **kwargs)
            if corrupt_finished and wire.writer is writer and expected == 20:
                message = message[:-1] + bytes((message[-1] ^ 1,))
            return message

        failure = channel = None
        with patch.object(HandshakeSecrets, "__init__", scope_init), \
                patch.object(HandshakeSecrets, "record", record), \
                patch.object(hs.Wire, "receive_frame", receive):
            try:
                channel = await hs.client_handshake(reader, writer, "localhost", (),
                    revocation_policy="offline", timeout=5, password_credential=self.credential,
                    cipher_suites=(0xc0b0, 0x1301), enable_authenticators=True)
                self.assertEqual(await channel.recv(), b"ready", self.errors)
            except ProtocolError as error:
                failure = error  # Retain the actual exception and traceback.
            if corrupt_finished:
                await asyncio.wait_for(asyncio.gather(*tuple(self.tasks)), 2)

        # The generic client scope and nested PAKE scope must both release all
        # temporary epochs, without closing native provisioning or a live EA key.
        self.assertGreaterEqual(len(scopes), 2)
        self.assertTrue(records)
        for scope in scopes:
            self.assertEqual((scope.records, scope.keys, scope.channel), ([], [], None))
        for state in records:
            self.assertTrue(state.failed)
            self.assertEqual((state.secret, state.key, state.iv), (b"", b"", b""))
            self.assertIsNone(state._cipher)
        self.assertEqual(self.native._live_keys, 0)
        self.assertEqual(self.policy._active, 0)
        return channel, failure

    async def test_mixed_handoff_preserves_spontaneous_and_requested_authenticators(self):
        channel, failure = await self.mixed_exchange()
        self.assertIsNone(failure)
        self.assertIsNotNone(channel.auth_share_secret)
        credentials, _ = generate_lab_credentials("localhost")

        def authorize(identity, request):
            self.assertEqual(identity.chain, tuple(credentials.chain_der))
            return AuthorizedIdentity(x509.load_der_x509_certificate(identity.chain[0]).public_key(),
                                      "synthetic additional identity")

        try:
            cm, sm = channel.authenticators(), self.channels[-1].authenticators()
            for verifier, prover in ((cm, sm), (sm, cm)):
                request = verifier.request()
                response = prover.authenticate(credentials, request=request)
                self.assertTrue((await verifier.validate(response, authorize)).authenticated)
            self.assertTrue((await cm.validate(sm.authenticate(credentials), authorize)).authenticated)
            await channel.send(b"mixed handoff remains live")
            self.assertEqual(await channel.recv(), b"mixed handoff remains live")
            self.assertFalse(channel.sender.failed)
            self.assertFalse(channel.receiver.failed)
        finally:
            channel.abort()

    async def test_mixed_failed_finished_clears_inner_and_outer_protocol_frames(self):
        channel, failure = await self.mixed_exchange(corrupt_finished=True)
        self.assertIsNone(channel)
        self.assertIsInstance(failure, ProtocolError)
        self.assertEqual(failure.alert, 51)
        names = set()
        pending, seen = [failure], set()
        while pending:
            error = pending.pop()
            if id(error) in seen:
                continue
            seen.add(id(error))
            pending.extend(value for value in (error.__cause__, error.__context__) if value is not None)
            trace = error.__traceback__
            while trace:
                frame = trace.tb_frame
                name = frame.f_globals.get("__name__")
                if name in (hs.__name__, pwd.__name__):
                    self.assertFalse(frame.f_locals)
                    names.add(name)
                trace = trace.tb_next
        self.assertEqual(names, {hs.__name__, pwd.__name__})


if __name__ == "__main__":
    unittest.main()
