"""Optional SM traffic profile over real streams, without global DLL discovery."""

import asyncio
import hashlib
import hmac
import os
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives import hashes, hmac as native_hmac
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand

from tls20_server import crypto as c
from tls20_server.errors import ProtocolError
from tls20_server.openssl_provider import OpenSSLProvider
from tls20_server.tickets import TicketCache
from tls20_server.psk import ExternalPSK
from tests import test_sessions, test_client_auth


class SM3ScheduleTests(unittest.TestCase):
    def test_schedule_against_independent_hkdf_provider(self):
        def H(value):
            state=hashes.Hash(hashes.SM3()); state.update(value)
            return state.finalize()
        def mac(key,value):
            state=native_hmac.HMAC(key,hashes.SM3()); state.update(value)
            return state.finalize()
        def expand(secret, label, context, length=32):
            full = b"tls20 " + label
            info = length.to_bytes(2, "big") + bytes((len(full),)) + full + bytes((len(context),)) + context
            return HKDFExpand(hashes.SM3(), length, info).derive(secret)
        secret, transcript, shared = bytes(range(32)), b"independent transcript", bytes(range(32, 64))
        schedule = c.KeySchedule("sm3")
        early = mac(bytes(32), bytes(32))
        expected = mac(expand(early, b"derived", H(b"")), shared)
        self.assertEqual(c.handshake_secret(shared, hash_name="sm3"), expected)
        self.assertNotEqual(expected, c.handshake_secret(shared, hash_name="sha256"))
        self.assertEqual(schedule.finished(secret, transcript), mac(expand(secret, b"finished", b""), H(transcript)))
        self.assertEqual(schedule.server_proof(secret, transcript), mac(expand(secret, b"server mac", b""),
            b" " * 64 + b"TLS 2.0, server CertificateVerify\0" + H(transcript)))
        for suite in (0xc6, 0xc7):
            self.assertEqual(c.key_iv(secret, suite), (expand(secret, b"key", b"", 16), expand(secret, b"iv", b"", 12)))
        with self.assertRaisesRegex(ProtocolError, "explicitly selected"):
            c.RecordState(secret, "seal", 0xc6)
        with self.assertRaisesRegex(ProtocolError, "explicitly selected"):
            c.traffic_key(41)


@unittest.skipUnless(os.environ.get("TLS20_TEST_OPENSSL"), "explicit native provider fixture not configured")
class SMNetworkTests(unittest.IsolatedAsyncioTestCase):
    accept = test_sessions.SessionTests.accept
    handle = test_sessions.SessionTests.handle

    async def asyncSetUp(self):
        await test_sessions.SessionTests.asyncSetUp(self)
        self.provider = OpenSSLProvider(os.environ["TLS20_TEST_OPENSSL"])
        self.server_options["native_provider"] = self.provider

    async def asyncTearDown(self):
        await test_sessions.SessionTests.asyncTearDown(self)
        self.provider.close()

    async def connect(self, **kwargs):
        return await test_sessions.SessionTests.connect(self, native_provider=self.provider, **kwargs)

    async def test_entire_sm_network_matrix_without_platform_hashlib_sm3(self):
        original_new,original_mac=hashlib.new,hmac.digest
        def no_sm3_new(name,*args,**kwargs):
            if name == "sm3": raise ValueError("SM3 intentionally unavailable in platform hashlib")
            return original_new(name,*args,**kwargs)
        def no_sm3_mac(key,value,digest):
            if digest == "sm3": raise ValueError("SM3 intentionally unavailable in platform hmac")
            return original_mac(key,value,digest)
        with patch("hashlib.new",side_effect=no_sm3_new),patch("hmac.digest",side_effect=no_sm3_mac):
            self.assertIsInstance(c.hash_context("sm3",self.provider),c.HashContext)
            self.assertEqual(c.digest(b"abc",c.hash_context("sm3",self.provider)).hex(),
                             "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0")
            self.assertEqual(c.digest(b"abc","sm3"),c.digest(b"abc",c.hash_context("sm3",self.provider)))
            await self.test_full_resume_early_keyupdate_exporters_and_independent_groups()

    async def test_full_resume_early_keyupdate_exporters_and_independent_groups(self):
        for suite in (0xc6, 0xc7):
            for group in (41, 29):
                with self.subTest(suite=suite, group=group):
                    self.cache = TicketCache()
                    self.server_options["cipher_suites"] = (suite,)
                    arguments = dict(cipher_suites=(suite,), traffic_group=group, record_size_limit=256)
                    first = await self.connect(**arguments)
                    self.assertFalse(first.resumed)
                    second = await self.connect(**arguments)
                    self.assertTrue(second.resumed)
                    third = await self.connect(**arguments, early_data=b"early authenticated ciphertext")
                    server = self.channels[-1]
                    self.assertTrue(third.early_data_accepted)
                    self.assertIn(b"early authenticated ciphertext", self.early)
                    self.assertEqual(third.exporter("test", b"scope", 47), server.exporter("test", b"scope", 47))
                    self.assertEqual(third.early_exporter("test"), server.early_exporter("test"))
                    await third.key_update(request_peer=True)
                    await third.send(b"updated" * 100)
                    received = b""
                    while len(received) < 700:
                        received += await asyncio.wait_for(third.recv(), 2)
                    self.assertEqual(received, b"updated" * 100)
                    self.assertEqual(self.provider._live_keys, 0)
        self.assertFalse(self.errors)

    async def test_initial_client_mac_and_post_handshake_authentication(self):
        from cryptography.hazmat.primitives.asymmetric import ed25519
        self.ca_key = ed25519.Ed25519PrivateKey.generate()
        self.client_credentials = test_client_auth.client_credentials(self.ca_key)
        self.authorized, self.validated = True, 0
        self.server_options.update(cipher_suites=(0xc7,),
            client_auth_validator=lambda chain: test_client_auth.ClientAuthTests.validate_client(self, chain))
        client = await self.connect(cipher_suites=(0xc7,), traffic_group=41,
                                    client_credentials=self.client_credentials, post_handshake_auth=True)
        server = self.channels[-1]
        self.assertIsNotNone(server.authenticated_client)
        future = await server.request_client_auth(required=True)
        await client.key_update(request_peer=True)
        await client.send(b"drive PHA")
        self.assertEqual(await asyncio.wait_for(client.recv(), 2), b"drive PHA")
        await asyncio.wait_for(future, 2)
        self.assertGreaterEqual(self.validated, 2)

    async def test_sm3_direct_psk_only_and_combined(self):
        for combined in (False, True):
            self.cache = TicketCache()
            psk = ExternalPSK(b"SM3 provisioned", bytes(range(32)), "localhost",
                hash_name="sm3", combined=combined, cipher_suite=0xc6)
            self.server_options.update(cipher_suites=(0xc6,), external_psks=(psk,))
            channel = await self.connect(cipher_suites=(0xc6,), traffic_group=41,
                external_psk=psk, psk_modes=(1,) if combined else (0,))
            self.assertEqual(channel.psk_provenance, "ext")
            await channel.send(b"PSK scope")
            self.assertEqual(await channel.recv(), b"PSK scope")

    async def test_pinning_uses_sm3_not_same_sized_sha256(self):
        from tls20_server.pinning import ServerPinning, PinningCache
        self.server_options.update(cipher_suites=(0xc6,),
            pinning=ServerPinning({bytes(16): bytes(range(32))}, bytes(16)), pinning_port=self.port)
        cache = PinningCache()
        for _ in range(2):
            channel = await self.connect(cipher_suites=(0xc6,), traffic_group=41,
                pinning_cache=cache, pinning_port=self.port)
            self.assertFalse(channel.resumed)
        self.assertTrue(cache.begin("localhost", self.port).extension)
