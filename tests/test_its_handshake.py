"""Configured native ITS credentials over real TCP, not mocked trust callbacks."""
import asyncio
from dataclasses import replace
import hashlib
import os
from pathlib import Path
import unittest

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from tls20_server.credential_profiles import CredentialPolicy
from tls20_server.errors import ProtocolError
from tls20_server.handshake import client_handshake, server_handshake
from tls20_server.its_credentials import ITSProvider, ITSServicePolicy
from tls20_server.pki import Credentials
from tls20_server.tickets import TicketCache, TicketStore
from tests import test_sessions


def load_live_fixture(profile=""):
    directory = Path(os.environ["TLS20_ITS_FIXTURE_DIR"])
    if profile:
        directory = directory / profile
    wire = (directory / "live-policy.bin").read_bytes()
    cursor = 37
    def vector(width):
        nonlocal cursor
        size = int.from_bytes(wire[cursor:cursor+width], "big")
        cursor += width
        value = wire[cursor:cursor+size]
        cursor += size
        return value
    scope, ssp = vector(2), vector(2)
    provider = ITSProvider(os.environ["TLS20_TEST_ITS_LIBRARY"])
    policy = ITSServicePolicy(provider, "example.test", "server", int.from_bytes(wire[29:37], "big"),
        scope, ssp, ((directory / "live-root.coer").read_bytes(),),
        (hashlib.sha256((directory / "live-leaf.coer").read_bytes()).digest(),), (),
        int.from_bytes(wire[12:20], "big"), int.from_bytes(wire[20:28], "big"), 37)
    return directory, policy


@unittest.skipUnless(os.getenv("TLS20_TEST_ITS_LIBRARY") and os.getenv("TLS20_ITS_FIXTURE_DIR"),
                     "explicit native ITS provider and fresh generated fixture required")
class ITSHandshakeTests(unittest.IsolatedAsyncioTestCase):
    accept = test_sessions.SessionTests.accept
    asyncTearDown = test_sessions.SessionTests.asyncTearDown

    async def asyncSetUp(self):
        directory, self.its_policy = load_live_fixture()
        private = X25519PrivateKey.from_private_bytes(bytes([9])*32)
        self.credentials = Credentials([(directory / "live-server.bin").read_bytes()], private,
            credential_type=3, its_policy=self.its_policy)
        self.client_credentials = Credentials([(directory / "live-client.bin").read_bytes()], private,
            credential_type=3, its_policy=replace(self.its_policy, role="client"))
        self.peer_policy = CredentialPolicy(peer_name="example.test", its_policy=self.its_policy)
        self.store, self.cache = TicketStore(), TicketCache()
        self.tasks, self.channels, self.writers, self.errors, self.early = set(), [], [], [], []
        self.server_options = {}
        self.listener = await asyncio.start_server(self.accept, "127.0.0.1", 0)
        self.port = self.listener.sockets[0].getsockname()[1]

    async def handle(self, reader, writer):
        async def early(data):
            self.early.append(data)
        channel = None
        try:
            channel = await server_handshake(reader, writer, self.credentials, "example.test",
                ticket_store=self.store, max_early_data=65536, on_early_data=early, **self.server_options)
            self.channels.append(channel)
            await channel.send(b"ready")
            while (data := await channel.recv()) is not None:
                await channel.send(data)
        except (ProtocolError, OSError) as exc:
            self.errors.append(str(exc))
        finally:
            if channel:
                await channel.close()
            else:
                writer.close()

    async def connect(self, **options):
        reader, writer = await asyncio.open_connection("127.0.0.1", self.port)
        self.writers.append(writer)
        channel = await asyncio.wait_for(client_handshake(reader, writer, "example.test", [],
            credential_policy=self.peer_policy, server_certificate_types=(3,), ticket_cache=self.cache,
            revocation_policy="offline", **options), 5)
        self.assertEqual(await asyncio.wait_for(channel.recv(), 5), b"ready", self.errors)
        return channel

    async def test_server_full_resumed_early_and_key_update(self):
        first = await self.connect()
        self.assertEqual(first.certificate_type, 3)
        self.assertFalse(first.resumed)
        second = await self.connect(early_data=b"ITS early request")
        self.assertTrue(second.resumed)
        self.assertTrue(second.early_data_accepted)
        self.assertIn(b"ITS early request", self.early)
        await second.key_update(request_peer=True)
        await second.send(b"ITS application")
        self.assertEqual(await asyncio.wait_for(second.recv(), 5), b"ITS application")
        self.assertFalse(self.errors)

    async def test_client_mac_initial_resumption_and_pha(self):
        self.server_options = {"client_credential_policy": CredentialPolicy(peer_name="example.test",
            its_policy=self.client_credentials.its_policy), "require_client_auth": True,
            "client_certificate_types": (3,)}
        await self.connect(client_credentials=self.client_credentials)
        self.assertEqual(self.channels[-1].authenticated_client, tuple(self.client_credentials.chain_der))
        second = await self.connect(client_credentials=self.client_credentials, post_handshake_auth=True,
                                    early_data=b"ITS client early")
        self.assertTrue(second.resumed)
        self.assertTrue(second.early_data_accepted)
        future = await self.channels[-1].request_client_auth(required=True)
        await second.send(b"drive ITS PHA")
        self.assertEqual(await asyncio.wait_for(second.recv(), 5), b"drive ITS PHA")
        self.assertEqual(await asyncio.wait_for(future, 5), tuple(self.client_credentials.chain_der))
        self.assertFalse(self.errors)

    async def test_revocation_invalidates_cached_early_authority(self):
        await self.connect()
        self.peer_policy = replace(self.peer_policy, its_policy=replace(self.its_policy,
            revoked_sha256=self.its_policy.authorized_leaf_sha256))
        with self.assertRaises(ProtocolError):
            await self.connect(early_data=b"must not send")
        self.assertEqual(self.early, [])

    async def test_wrong_local_key_and_remote_service_fail_before_application(self):
        self.credentials = replace(self.credentials, private_key=X25519PrivateKey.generate())
        with self.assertRaises(ProtocolError):
            await self.connect()
        self.assertEqual(self.channels, [])
        self.assertEqual(self.early, [])

    async def test_brainpool_and_implicit_profiles_over_real_tcp(self):
        for profile in ("brainpool256", "brainpool384", "implicit-nist256", "implicit-brainpool256"):
            with self.subTest(profile=profile):
                directory, policy = load_live_fixture(profile)
                private = X25519PrivateKey.from_private_bytes(bytes([9])*32)
                self.credentials = Credentials([(directory / "live-server.bin").read_bytes()], private,
                    credential_type=3, its_policy=policy)
                self.peer_policy = CredentialPolicy(peer_name="example.test", its_policy=policy)
                self.store, self.cache = TicketStore(), TicketCache()
                first = await self.connect()
                self.assertFalse(first.resumed)
                second = await self.connect(early_data=b"profile early data")
                self.assertTrue(second.resumed)
                self.assertTrue(second.early_data_accepted)
                await second.send(b"profile application data")
                self.assertEqual(await asyncio.wait_for(second.recv(), 5), b"profile application data")
        self.assertFalse(self.errors)
