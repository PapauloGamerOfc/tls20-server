"""Independent real PAKE sessions exercise application identity lifetimes."""

import asyncio
import os
import unittest

from cryptography import x509

from tests import test_pake_handshake
from tls20_server.application_auth import AuthorizedIdentity
from tls20_server.errors import ProtocolError
from tls20_server.lab import generate_lab_credentials
from tls20_server.tickets import TicketCache


@unittest.skipUnless(os.environ.get("TLS20_TEST_PAKE") and os.environ.get("TLS20_TEST_OPENSSL"),
                     "explicit native PAKE fixture required")
class PakeApplicationAuthTests(unittest.IsolatedAsyncioTestCase):
    # Reuse the transport fixture, not its test methods.
    asyncSetUp = test_pake_handshake.PakeHandshakeTests.asyncSetUp
    asyncTearDown = test_pake_handshake.PakeHandshakeTests.asyncTearDown
    accept = test_pake_handshake.PakeHandshakeTests.accept
    handle = test_pake_handshake.PakeHandshakeTests.handle
    connect = test_pake_handshake.PakeHandshakeTests.connect

    async def test_full_resumed_and_early_both_directions_and_spontaneous(self):
        credentials, _ = generate_lab_credentials("localhost")

        def pinned_fixture(identity, request):
            # Pin this complete newly generated identity independently of the
            # password-authenticated channel. No ambient certificate trust.
            if identity.chain != tuple(credentials.chain_der):
                raise ProtocolError("unapproved additional fixture identity")
            return AuthorizedIdentity(
                x509.load_der_x509_certificate(identity.chain[0]).public_key(),
                "additional fixture identity")

        for suite in (0xc0b0, 0xc0b1):
            self.options = {"cipher_suites": (suite,), "enable_authenticators": True}
            self.cache = TicketCache()
            previous_binding = None
            for phase in ("full", "resumed", "early"):
                with self.subTest(suite=hex(suite), phase=phase):
                    client = await self.connect(
                        cipher_suites=(suite,), enable_authenticators=True,
                        early_data=b"public fixture" if phase == "early" else b"")
                    server = self.channels[-1]
                    self.assertEqual(client.resumed, phase != "full")
                    self.assertEqual(client.early_data_accepted, phase == "early")
                    cm, sm = client.authenticators(), server.authenticators()
                    for verifier, prover in ((cm, sm), (sm, cm)):
                        request = verifier.request()
                        response = prover.authenticate(credentials, request=request)
                        result = await verifier.validate(response, pinned_fixture)
                        self.assertTrue(result.authenticated)
                        self.assertEqual(result.identity, "additional fixture identity")
                        with self.assertRaises(ProtocolError):
                            await verifier.validate(response, pinned_fixture)
                    response = sm.authenticate(credentials)
                    self.assertTrue((await cm.validate(response, pinned_fixture)).authenticated)
                    request = cm.request()
                    refusal = sm.authenticate(request=request)
                    result = await cm.validate(refusal, pinned_fixture, request=request)
                    self.assertFalse(result.authenticated)
                    self.assertIsNone(result.identity)
                    request = cm.request()
                    response = sm.authenticate(credentials, request=request)
                    tampered = response[:-1] + bytes((response[-1] ^ 1,))
                    with self.assertRaises(ProtocolError):
                        await cm.validate(tampered, pinned_fixture)
                    self.assertFalse(cm._pending)
                    self.assertFalse(sm._pending)
                    self.assertEqual(client.pake_identity, b"alice")
                    self.assertEqual(server.password_permissions, b"read")
                    self.assertIsNone(server.authenticated_client)
                    binding = client.channel_binding()
                    self.assertEqual(binding, server.channel_binding())
                    self.assertNotEqual(binding, previous_binding)
                    previous_binding = binding
                    await client.key_update(request_peer=True)
                    await client.send(b"drive key update")
                    self.assertEqual(await asyncio.wait_for(client.recv(), 2), b"drive key update")
                    self.assertEqual(client.channel_binding(), binding)
                    request = cm.request()
                    response = sm.authenticate(credentials, request=request)
                    self.assertTrue((await cm.validate(response, pinned_fixture)).authenticated)
                    cm.request()
                    await client.close()
                    self.assertFalse(cm._pending)
                    self.assertIsNone(client.auth_share_secret)
        self.assertFalse(self.errors)

    async def test_disabled_retains_no_spontaneous_verifier_secret(self):
        client = await self.connect()
        self.assertIsNone(client.auth_share_secret)
        with self.assertRaises(ProtocolError):
            client.authenticators()


if __name__ == "__main__":
    unittest.main()
