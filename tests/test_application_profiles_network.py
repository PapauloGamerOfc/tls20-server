"""Application profiles bound to real full/resumed TLS 2.0 loopback sessions."""

import asyncio
from pathlib import Path
import tempfile
from unittest.mock import patch
import unittest

from tests import test_sessions
from tls20_server import _build_features
from tls20_server.application_auth import AuthorizedIdentity
from tls20_server.diagnostics import DiagnosticSink
from tls20_server.errors import ProtocolError
from tls20_server.pki import validate_identity
from tls20_server.tickets import TicketCache


class ApplicationProfilesNetworkTests(unittest.IsolatedAsyncioTestCase):
    accept = test_sessions.SessionTests.accept
    handle = test_sessions.SessionTests.handle
    connect = test_sessions.SessionTests.connect
    asyncTearDown = test_sessions.SessionTests.asyncTearDown

    async def asyncSetUp(self):
        await test_sessions.SessionTests.asyncSetUp(self)
        self.server_options = {"enable_authenticators": True}

    def policy(self, identity, request):
        public = validate_identity(list(identity.chain), trust_roots=self.roots,
                                   role="server", name="localhost",
                                   offered_certificate_algorithms=request.certificate_algorithms
                                   if request else (0x0807, 0x0403))
        return AuthorizedIdentity(public, "localhost application identity")

    async def test_network_requested_spontaneous_and_resumed_identity(self):
        for cipher in (0x1301, 0x1302):
            self.server_options["cipher_suites"] = (cipher,)
            self.cache = TicketCache()
            for resumed in (False, True):
                client = await self.connect(enable_authenticators=True, cipher_suites=(cipher,))
                server = self.channels[-1]
                self.assertEqual(client.resumed, resumed)
                cm, sm = client.authenticators(), server.authenticators()
                self.assertIs(client.authenticators(), cm)
                request = cm.request()
                response = sm.authenticate(self.credentials, request=request)
                self.assertTrue((await cm.validate(response, self.policy)).authenticated)
                response = sm.authenticate(self.credentials)
                self.assertTrue((await cm.validate(response, self.policy)).authenticated)
                self.assertEqual(client.channel_binding(), server.channel_binding())
                binding = client.channel_binding()
                await client.key_update(request_peer=True)
                await client.send(b"drive update")
                self.assertEqual(await asyncio.wait_for(client.recv(), 2), b"drive update")
                self.assertEqual(client.channel_binding(), binding)
                self.assertIsNone(server.authenticated_client)
                self.assertFalse(client._authenticators._pending)

    async def test_disabled_capability_and_pending_cleanup(self):
        client = await self.connect()
        with self.assertRaises(ProtocolError):
            client.authenticators()
        self.assertIsNone(client.auth_share_secret)
        client = await self.connect(enable_authenticators=True)
        manager = client.authenticators()
        manager.request()
        client.abort()
        self.assertFalse(manager._pending)
        self.assertIsNone(client.auth_share_secret)

    async def test_alpn_h2_and_no_post_handshake_client_auth(self):
        self.server_options["application_protocols"] = (b"h2", b"http/1.1")
        client = await self.connect(application_protocols=(b"h2", b"http/1.1"),
                                    post_handshake_auth=True)
        self.assertEqual(client.protocol, b"h2")
        self.assertEqual(self.channels[-1].protocol, b"h2")
        self.assertFalse(client.local_post_handshake_auth)
        self.assertFalse(self.channels[-1].peer_post_handshake_auth)

    @patch.object(_build_features, "TEST_DIAGNOSTICS", True)
    async def test_real_derivation_events_all_labels_and_no_keyupdate_relabel(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "fixture-only.keys"
            with DiagnosticSink(path, authorize_test_data=True, authorize_traffic=True,
                                authorize_exporters=True) as sink:
                self.server_options["diagnostics"] = sink
                await self.connect(diagnostics=sink)
                client = await self.connect(diagnostics=sink, early_data=b"public fixture")
                await client.key_update(request_peer=True)
                await client.send(b"finish update")
                self.assertEqual(await asyncio.wait_for(client.recv(), 2), b"finish update")
                self.assertIsNone(sink.error)
            lines = [line.split(" ") for line in path.read_text().splitlines()]
            expected = {"TLS20_CLIENT_HANDSHAKE_TRAFFIC_SECRET", "TLS20_SERVER_HANDSHAKE_TRAFFIC_SECRET",
                        "TLS20_CLIENT_TRAFFIC_SECRET_0", "TLS20_SERVER_TRAFFIC_SECRET_0",
                        "TLS20_EXPORTER_SECRET", "TLS20_EARLY_EXPORTER_SECRET",
                        "TLS20_CLIENT_EARLY_TRAFFIC_SECRET"}
            self.assertEqual({line[0] for line in lines}, expected)
            # Both endpoints logged the same values. No later generation was
            # mislabeled with _0 and no new random was fabricated for KeyUpdate.
            seen = {}
            for label, random, secret in lines:
                self.assertEqual(len(random), 64)
                self.assertEqual(len(secret), 64)
                key = label, random
                self.assertEqual(seen.setdefault(key, secret), secret)
            self.assertEqual(len({random for _, random in seen}), 2)


if __name__ == "__main__":
    unittest.main()
