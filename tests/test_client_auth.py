"""Initial/PHA client MAC end-to-end tests with explicit lab authorization."""

import asyncio
import hashlib
import hmac
from datetime import datetime, timedelta, timezone
import unittest
from unittest.mock import patch

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID, ExtensionOID

from tests import test_sessions
from tls20_server import crypto as c
from tls20_server.errors import ProtocolError
from tls20_server.handshake import Wire, server_handshake
from tls20_server.pki import Credentials


def client_credentials(ca_key):
    now = datetime.now(timezone.utc)
    private = x25519.X25519PrivateKey.generate()
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "authorized test user")])
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(private.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=1)).not_valid_after(now + timedelta(days=1))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(False, False, False, False, True, False, False, False, False), critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
            .sign(ca_key, algorithm=None))
    return Credentials([cert.public_bytes(serialization.Encoding.DER)], private)


def proof_oracle(root, private, peer, transcript):
    """Literal spec domains with the provider's independent HKDF backend."""
    H = lambda value: hashlib.sha256(value).digest()
    def expand(secret, label, context):
        full = b"tls20 " + label
        info = b"\x00\x20" + bytes((len(full),)) + full + bytes((len(context),)) + context
        return HKDFExpand(hashes.SHA256(), 32, info).derive(secret)
    exported = expand(expand(root, b"EXPORTER-TLS20-Client-Auth", H(b"")), b"exporter", H(H(transcript)))
    shared = private.exchange(x25519.X25519PublicKey.from_public_bytes(peer))
    key = expand(hmac.digest(exported, shared, "sha256"), b"client mac", b"")
    return hmac.digest(key, b" " * 64 + b"TLS 2.0, client CertificateVerify\0" + H(transcript), "sha256")


class ClientAuthTests(unittest.IsolatedAsyncioTestCase):
    accept = test_sessions.SessionTests.accept
    handle = test_sessions.SessionTests.handle
    connect = test_sessions.SessionTests.connect
    asyncTearDown = test_sessions.SessionTests.asyncTearDown

    async def asyncSetUp(self):
        await test_sessions.SessionTests.asyncSetUp(self)
        self.ca_key = ed25519.Ed25519PrivateKey.generate()
        self.client_credentials = client_credentials(self.ca_key)
        self.authorized = True
        self.validated = 0
        self.server_options = {"client_auth_validator": self.validate_client}

    def validate_client(self, chain):
        if not self.authorized or chain != self.client_credentials.chain_der:
            raise ProtocolError("client not authorized by local policy")
        cert = x509.load_der_x509_certificate(chain[0])
        self.ca_key.public_key().verify(cert.signature, cert.tbs_certificate_bytes)
        if not cert.not_valid_before_utc <= datetime.now(timezone.utc) <= cert.not_valid_after_utc:
            raise ProtocolError("client credential expired")
        if ExtendedKeyUsageOID.CLIENT_AUTH not in cert.extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE).value:
            raise ProtocolError("not a client credential")
        if not cert.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE).value.key_agreement:
            raise ProtocolError("not an agreement key")
        self.validated += 1
        return cert.public_key()

    async def test_initial_mac_and_resumed_client_identity(self):
        self.server_options["require_client_auth"] = True
        first = await self.connect(client_credentials=self.client_credentials)
        self.assertFalse(first.resumed)
        self.assertEqual(self.channels[-1].authenticated_client, tuple(self.client_credentials.chain_der))
        second = await self.connect(client_credentials=self.client_credentials, early_data=b"early authorized")
        self.assertTrue(second.resumed)
        self.assertTrue(second.early_data_accepted)
        self.assertEqual(self.channels[-1].authenticated_client, tuple(self.client_credentials.chain_der))
        self.assertGreaterEqual(self.validated, 2)

    async def test_actual_initial_and_pha_transcripts_against_independent_oracle(self):
        frames, proofs = [], []
        send_frame, client_proof = Wire.send_frame, c.client_proof
        async def record_frame(wire, frame, state=None):
            frames.append(frame)
            return await send_frame(wire, frame, state)
        def record_proof(root, private, peer, transcript):
            actual = client_proof(root, private, peer, transcript)
            self.assertEqual(actual, proof_oracle(root, private, peer, transcript))
            proofs.append((root, transcript))
            return actual
        with patch.object(Wire, "send_frame", record_frame), patch.object(c, "client_proof", record_proof):
            client = await self.connect(client_credentials=self.client_credentials, post_handshake_auth=True)
            server = self.channels[-1]
            flight = [frame for frame in frames if frame[0] != 4]
            self.assertEqual([frame[0] for frame in flight], [1, 2, 8, 13, 11, 15, 20, 11, 15, 20])
            prefix = b"TLS20-EXPERIMENT\r\n" + b"".join(flight[:8])
            self.assertEqual(proofs, [(client.exporter_secret, prefix)] * 2)
            self.assertEqual(client.handshake_transcript, b"TLS20-EXPERIMENT\r\n" + b"".join(flight))
            frames.clear(); proofs.clear()
            future = await server.request_client_auth(required=True)
            await server.key_update(request_peer=True)
            await client.send(b"drive authentication")
            self.assertEqual(await asyncio.wait_for(client.recv(), 2), b"drive authentication")
            await asyncio.wait_for(future, 2)
            flight = [frame for frame in frames if frame[0] != 24]
            self.assertEqual([frame[0] for frame in flight], [13, 11, 15, 20])
            prefix = client.handshake_transcript + b"".join(flight[:2])
            self.assertEqual(proofs, [(client.exporter_secret, prefix)] * 2)

    async def test_optional_refusal_and_required_refusal(self):
        await self.connect()
        self.assertIsNone(self.channels[-1].authenticated_client)
        self.server_options["require_client_auth"] = True
        with self.assertRaises((ProtocolError, OSError, AssertionError)):
            await self.connect()
        self.assertTrue(any("required" in error for error in self.errors))

    async def test_bad_client_mac_never_establishes_identity(self):
        original = c.client_proof
        def damaged(secret, private, peer, transcript):
            value = original(secret, private, peer, transcript)
            return bytes((value[0] ^ 1,)) + value[1:] if private is self.client_credentials.private_key else value
        with patch.object(c, "client_proof", damaged), self.assertRaises((ProtocolError, OSError, AssertionError)):
            await self.connect(client_credentials=self.client_credentials)
        self.assertFalse(self.channels)
        self.assertTrue(any("MAC" in error for error in self.errors))

    async def test_revoked_cached_identity_does_not_authorize_early_data(self):
        self.server_options["require_client_auth"] = True
        await self.connect(client_credentials=self.client_credentials)
        self.authorized = False
        with self.assertRaises((ProtocolError, OSError, AssertionError)):
            await self.connect(client_credentials=self.client_credentials, early_data=b"never authorized")
        self.assertFalse(self.early)

    async def test_ticket_cache_isolates_changed_and_anonymous_client_identity(self):
        await self.connect(client_credentials=self.client_credentials)
        anonymous = await self.connect(early_data=b"not the previous identity")
        self.assertFalse(anonymous.resumed)
        self.assertIsNone(self.channels[-1].authenticated_client)
        self.client_credentials = client_credentials(self.ca_key)
        changed = await self.connect(client_credentials=self.client_credentials,
                                     early_data=b"not the previous credential")
        self.assertFalse(changed.resumed)
        self.assertFalse(changed.early_data_accepted)
        self.assertEqual(self.channels[-1].authenticated_client, tuple(self.client_credentials.chain_der))
        self.assertFalse(self.early)
        resumed = await self.connect(client_credentials=self.client_credentials)
        self.assertTrue(resumed.resumed)

    async def test_bad_binder_does_not_invoke_client_authorization_callback(self):
        await self.connect(client_credentials=self.client_credentials)
        before = self.validated
        original = Wire.send_frame
        async def damage_binder(wire, message, state=None):
            if message[0] == 1:
                message = message[:-1] + bytes((message[-1] ^ 1,))
            return await original(wire, message, state)
        with patch.object(Wire, "send_frame", damage_binder), self.assertRaises((ProtocolError, OSError)):
            await self.connect(client_credentials=self.client_credentials, early_data=b"not authorized")
        self.assertEqual(self.validated, before)
        self.assertTrue(any("binder" in error for error in self.errors))
        self.assertFalse(self.early)

    async def test_pha_does_not_promote_an_existing_anonymous_ticket(self):
        client = await self.connect(post_handshake_auth=True)
        self.assertIsNone(self.channels[-1].authenticated_client)
        ticket = next(iter(self.store._tickets.values()))
        self.assertFalse(ticket.client_certificate_chain)
        client.client_credentials = self.client_credentials
        future = await self.channels[-1].request_client_auth(required=True)
        await client.send(b"authenticate after the ticket was issued")
        self.assertEqual(await asyncio.wait_for(client.recv(), 2), b"authenticate after the ticket was issued")
        self.assertEqual(await asyncio.wait_for(future, 2), tuple(self.client_credentials.chain_der))
        self.assertFalse(ticket.client_certificate_chain)
        resumed = await self.connect()
        self.assertTrue(resumed.resumed)
        self.assertIsNone(self.channels[-1].authenticated_client)

    async def test_concurrent_pha_contexts_and_key_update(self):
        client = await self.connect(client_credentials=self.client_credentials, post_handshake_auth=True)
        server = self.channels[-1]
        first = await server.request_client_auth(required=True)
        second = await server.request_client_auth(required=True)
        self.assertEqual(len(server.pending_client_auth), 2)
        await server.key_update(request_peer=True)
        await client.send(b"keep reading")
        self.assertEqual(await asyncio.wait_for(client.recv(), 2), b"keep reading")
        self.assertEqual(await asyncio.wait_for(first, 2), tuple(self.client_credentials.chain_der))
        self.assertEqual(await asyncio.wait_for(second, 2), tuple(self.client_credentials.chain_der))
        self.assertEqual(server.pending_client_auth, {})
        self.assertIsNone(server._active_client_auth)

    async def test_pha_refusal_and_future_cancellation_cleanup(self):
        client = await self.connect(post_handshake_auth=True)
        server = self.channels[-1]
        refused = await server.request_client_auth()
        await client.send(b"continue")
        self.assertEqual(await asyncio.wait_for(client.recv(), 2), b"continue")
        self.assertIsNone(await asyncio.wait_for(refused, 2))
        pending = await server.request_client_auth()
        state = next(iter(server.pending_client_auth.values()))
        pending.cancel()
        await asyncio.sleep(0)
        self.assertTrue(server.closed)
        self.assertIsNone(state["private"])
        self.assertFalse(server.pending_client_auth)

    async def test_no_pha_without_offer_or_validator(self):
        await self.connect(client_credentials=self.client_credentials)
        with self.assertRaisesRegex(ProtocolError, "unavailable"):
            await self.channels[-1].request_client_auth()
        with self.assertRaises(ValueError):
            await server_handshake(None, None, self.credentials, "localhost", require_client_auth=True)


if __name__ == "__main__":
    unittest.main()
