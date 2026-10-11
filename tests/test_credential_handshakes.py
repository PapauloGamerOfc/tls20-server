"""Credential representation negotiation must result in actual authenticated wire paths."""

from dataclasses import replace
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from tls20_server.credential_profiles import CredentialPolicy, RawPublicKeyBinding
from tls20_server.errors import ProtocolError
from tls20_server.handshake import Wire
from tls20_server.pki import Credentials
from tls20_server.tickets import TicketCache
from tests import test_sessions, test_credential_profiles


class CredentialHandshakeTests(unittest.IsolatedAsyncioTestCase):
    asyncSetUp = test_sessions.SessionTests.asyncSetUp
    asyncTearDown = test_sessions.SessionTests.asyncTearDown
    accept = test_sessions.SessionTests.accept
    handle = test_sessions.SessionTests.handle
    connect = test_sessions.SessionTests.connect

    def raw(self):
        key = X25519PrivateKey.generate()
        der = key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        return Credentials([der], key, credential_type=2)

    async def test_server_raw_public_key_exact_binding_then_resumption(self):
        self.credentials = self.raw()
        policy = CredentialPolicy(peer_name="localhost", raw_public_keys=(
            RawPublicKeyBinding("server", "localhost", self.credentials.chain_der[0]),))
        first = await self.connect(credential_policy=policy, server_certificate_types=(2,))
        self.assertEqual(first.certificate_type, 2)
        self.assertEqual(first.certificate_chain, self.credentials.chain_der)
        resumed = await self.connect(credential_policy=policy, server_certificate_types=(2,))
        self.assertTrue(resumed.resumed)
        self.assertEqual(resumed.certificate_type, 2)
        self.cache = TicketCache()
        with self.assertRaises(ProtocolError):
            await self.connect(credential_policy=replace(policy, raw_public_keys=()), server_certificate_types=(2,))

    async def test_client_raw_public_key_initial_and_resumed_identity(self):
        credential = self.raw()
        policy = CredentialPolicy(peer_name="device", raw_public_keys=(
            RawPublicKeyBinding("client", "device", credential.chain_der[0]),))
        self.server_options = {"client_credential_policy": policy, "require_client_auth": True,
                               "client_certificate_types": (2,)}
        client = await self.connect(client_credentials=credential)
        self.assertEqual(self.channels[-1].authenticated_client, tuple(credential.chain_der))
        self.assertFalse(client.resumed)
        client = await self.connect(client_credentials=credential)
        self.assertTrue(client.resumed)
        self.assertEqual(self.channels[-1].authenticated_client, tuple(credential.chain_der))

    async def test_all_compression_algorithms_use_wire_transcript_and_mac(self):
        original = Wire.send_frame
        for algorithm in (1, 2, 3):
            with self.subTest(algorithm=algorithm):
                frames = []
                async def capture(wire, frame, state=None):
                    frames.append(frame)
                    await original(wire, frame, state)
                self.cache = TicketCache()
                with patch.object(Wire, "send_frame", capture):
                    client = await self.connect(certificate_compression=(algorithm,))
                certificate = [value for value in frames if value[0] == 25]
                self.assertEqual(len(certificate), 1)
                self.assertEqual(int.from_bytes(certificate[0][4:6], "big"), algorithm)
                self.assertIn(certificate[0], client.handshake_transcript)
                self.assertEqual(client.handshake_transcript, self.channels[-1].handshake_transcript)

    async def test_cached_server_material_with_and_without_compression(self):
        first = await self.connect()
        snapshot = ((first.certificate_type, tuple(first.certificate_chain)),)
        original = Wire.send_frame
        for compression in ((), (1,), (2,), (3,)):
            with self.subTest(compression=compression):
                frames = []
                async def capture(wire, frame, state=None):
                    frames.append(frame)
                    await original(wire, frame, state)
                self.cache = TicketCache()
                with patch.object(Wire, "send_frame", capture):
                    client = await self.connect(cached_certificates=snapshot, certificate_compression=compression)
                self.assertEqual(client.cache_types, (1,))
                self.assertEqual(client.certificate_chain, first.certificate_chain)
                self.assertIn(25 if compression else 253, [frame[0] for frame in frames])
                self.assertEqual(client.handshake_transcript, self.channels[-1].handshake_transcript)

    async def test_cached_requests_and_compressed_rpk_persist_for_pha(self):
        import asyncio
        credential = self.raw()
        policy = CredentialPolicy(peer_name="device", raw_public_keys=(
            RawPublicKeyBinding("client", "device", credential.chain_der[0]),))
        self.server_options = {"client_credential_policy": policy, "require_client_auth": True,
                               "client_certificate_types": (2,)}
        first = await self.connect(client_credentials=credential)
        self.cache = TicketCache()
        frames, original = [], Wire.send_frame
        async def capture(wire, frame, state=None):
            frames.append(frame)
            await original(wire, frame, state)
        with patch.object(Wire, "send_frame", capture):
            client = await self.connect(client_credentials=credential, post_handshake_auth=True,
                                       cached_requests=first.client_request_templates)
            server = self.channels[-1]
            self.assertEqual(client.cache_types, (2,))
            self.assertIn(252, [frame[0] for frame in frames])
            self.assertEqual(client.handshake_transcript, server.handshake_transcript)
            frames.clear()
            future = await server.request_client_auth(required=True)
            await client.send(b"drive PHA")
            self.assertEqual(await asyncio.wait_for(client.recv(), 2), b"drive PHA")
            self.assertEqual(await asyncio.wait_for(future, 2), tuple(credential.chain_der))
            self.assertEqual([frame[0] for frame in frames], [252, 25, 15, 20])

    async def test_delegated_server_key_is_validated_independently_of_parent_key(self):
        fixture = test_credential_profiles.CredentialProfileTests()
        fixture.setUp()
        parent, grant = fixture.parent_and_grant()
        self.credentials = Credentials([parent.public_bytes(serialization.Encoding.DER)], fixture.key, delegation=grant)
        # Certificate fixture's SAN is example.test; bind connection service to
        # that identity rather than disabling hostname verification.
        self.listener.close()
        await self.listener.wait_closed()
        import asyncio
        from tls20_server.handshake import server_handshake, client_handshake
        errors = []
        async def peer(reader, writer):
            try:
                channel = await server_handshake(reader, writer, self.credentials, "example.test")
                self.channels.append(channel)
                await channel.send(b"delegated")
                await channel.close()
            except BaseException as error:
                errors.append(error)
                writer.close()
        self.listener = await asyncio.start_server(peer, "127.0.0.1", 0)
        reader, writer = await asyncio.open_connection("127.0.0.1", self.listener.sockets[0].getsockname()[1])
        self.writers.append(writer)
        client = await client_handshake(reader, writer, "example.test", [fixture.root],
            revocation_policy="offline", credential_policy=fixture.policy, delegated_credentials=True,
            certificate_compression=(1,))
        self.assertEqual(await client.recv(), b"delegated")
        self.assertEqual(dict(client.certificate_extensions[0])[34], grant)
        self.assertFalse(errors)
