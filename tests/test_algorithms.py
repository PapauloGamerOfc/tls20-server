"""Negotiated suite/hash/group interoperability, not a shared-code-only oracle."""

import asyncio
import hashlib
import hmac
import unittest

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, AESCCM, ChaCha20Poly1305

from tls20_server import crypto as c
from tls20_server.errors import ProtocolError
from tls20_server.tickets import TicketCache
from tests import test_sessions


class AlgorithmKnownAnswers(unittest.TestCase):
    def test_sha384_schedule_against_independent_provider(self):
        H = lambda data: hashlib.sha384(data).digest()
        def expand(root, label, context):
            full = b"tls20 " + label
            info = b"\x00\x30" + bytes((len(full),)) + full + bytes((len(context),)) + context
            return HKDFExpand(hashes.SHA384(), 48, info).derive(root)
        zero, shared = bytes(48), bytes(range(48))
        early = hmac.digest(zero, zero, "sha384")
        expected = hmac.digest(expand(early, b"derived", H(b"")), shared, "sha384")
        self.assertEqual(c.handshake_secret(shared, hash_name="sha384"), expected)
        transcript = b"TLS20-EXPERIMENT\r\npublic test transcript"
        self.assertEqual(c.finished(expected, transcript),
                         hmac.digest(expand(expected, b"finished", b""), H(transcript), "sha384"))

    def test_records_match_cipher_provider_for_every_suite(self):
        for code in (0x1301, 0x1302, 0x1303, 0x1304, 0x1305):
            with self.subTest(suite=code):
                selected = c.suite(code)
                secret = bytes(range(selected.hash_length))
                def expand(label, length):
                    full = b"tls20 " + label
                    info = length.to_bytes(2, "big") + bytes((len(full),)) + full + b"\0"
                    algo = hashes.SHA384() if code == 0x1302 else hashes.SHA256()
                    return HKDFExpand(algo, length, info).derive(secret)
                key, iv = expand(b"key", selected.key_length), expand(b"iv", 12)
                provider = (AESGCM(key) if code in (0x1301, 0x1302) else
                            ChaCha20Poly1305(key) if code == 0x1303 else
                            AESCCM(key, tag_length=8 if code == 0x1305 else 16))
                plain = b"application\x17\0\0"
                header = b"\x17\x03\x03" + (len(plain) + selected.tag_length).to_bytes(2, "big")
                expected = header + provider.encrypt(iv, plain, header)
                self.assertEqual(c.RecordState(secret, "seal", code).seal(b"application", 23, 2), expected)
                self.assertEqual(c.RecordState(secret, "open", code).open(expected), (b"application", 23))

    def test_all_implemented_groups_validate_their_points(self):
        for group in c.GROUP_LENGTHS:
            if 34 <= group <= 41:  # Optional native providers have explicit fixtures.
                continue
            with self.subTest(group=group):
                left, A = c.traffic_key(group)
                B, shared = c.traffic_server(group, A)
                self.assertEqual(c.traffic_dh(left, group, B), shared)
                for invalid in (bytes(len(B)), B[:-1], B + b"\0"):
                    with self.assertRaises(ProtocolError):
                        c.traffic_dh(left, group, invalid)

    def test_hybrid_rejects_noncanonical_kem_key_and_wrong_wire_direction(self):
        for group, (traditional, _, _, public_size, _, kem_first) in c.HYBRID_GROUPS.items():
            with self.subTest(group=group):
                private, public = c.traffic_key(group)
                classical = public[public_size:] if kem_first else public[:-public_size]
                malformed = bytes([255]) * public_size
                with self.assertRaisesRegex(ProtocolError, "ML-KEM"):
                    c.traffic_server(group, malformed + classical if kem_first else classical + malformed)
                if c.GROUP_LENGTHS[group] != c.SERVER_GROUP_LENGTHS[group]:
                    with self.assertRaises(ProtocolError):
                        c.traffic_dh(private, group, public)

    def test_hybrid_component_order_matches_independent_provider(self):
        for group, (traditional, _, public_type, public_size, ciphertext_size, kem_first) in c.HYBRID_GROUPS.items():
            with self.subTest(group=group):
                private, client_share = c.traffic_key(group)
                server_share, result = c.traffic_server(group, client_share)
                ciphertext = server_share[:ciphertext_size] if kem_first else server_share[-ciphertext_size:]
                classical_share = server_share[ciphertext_size:] if kem_first else server_share[:-ciphertext_size]
                kem = private.kem.decapsulate(ciphertext)
                classical = c.traffic_dh(private.classical, traditional, classical_share)
                self.assertEqual(result, kem + classical if kem_first else classical + kem)

    def test_hybrid_auth_and_traffic_x25519_keys_must_be_independent(self):
        from tls20_server import messages as m
        _, share = c.traffic_key(4588)
        with self.assertRaisesRegex(ProtocolError, "invalid client shares"):
            m.client_hello(share[-32:], share, "localhost", bytes(32), group=4588)
        _, auth = c.traffic_key(29)
        message = m.client_hello(auth, share, "localhost", bytes(32), group=4588)
        with self.assertRaisesRegex(ProtocolError, "independent"):
            m.parse_client_hello(message[4:].replace(auth, share[-32:]))


class NegotiatedAlgorithms(unittest.IsolatedAsyncioTestCase):
    asyncSetUp = test_sessions.SessionTests.asyncSetUp
    asyncTearDown = test_sessions.SessionTests.asyncTearDown
    accept = test_sessions.SessionTests.accept
    handle = test_sessions.SessionTests.handle
    connect = test_sessions.SessionTests.connect

    async def test_every_suite_full_resumed_early_and_updated(self):
        for code in (value for value in c.CIPHER_SUITES if c.suite(value).confidential
                     and c.suite(value).hash_name in ("sha256","sha384") and not c.suite(value).password_authenticated):
            with self.subTest(suite=code):
                self.cache = TicketCache()
                full = await self.connect(cipher_suites=(code,))
                self.assertEqual(full.cipher_suite, code)
                self.assertEqual(len(full.exporter_secret), c.suite(code).hash_length)
                early = await self.connect(cipher_suites=(code,), early_data=b"actual early bytes")
                self.assertTrue(early.resumed)
                self.assertTrue(early.early_data_accepted)
                await early.key_update(True)
                await early.send(b"different suite")
                self.assertEqual(await early.recv(), b"different suite")
                self.assertEqual(early.exporter("test"), self.channels[-1].exporter("test"))

    async def test_sha384_retry_and_all_traffic_groups(self):
        for group in c.GROUP_LENGTHS:
            if 34 <= group <= 41:  # Explicit optional-provider matrix is separate.
                continue
            with self.subTest(group=group):
                self.cache = TicketCache()
                for retry in (False, True):
                    client = await self.connect(cipher_suites=(0x1302,), traffic_group=group, force_retry=retry)
                    await client.send(b"group test")
                    self.assertEqual(await client.recv(), b"group test")

    async def test_incompatible_ticket_hash_falls_back_without_early_bytes(self):
        await self.connect(cipher_suites=(0x1302,))
        other = await self.connect(cipher_suites=(0x1303,), early_data=b"do not send")
        self.assertFalse(other.resumed)
        self.assertFalse(self.early)
