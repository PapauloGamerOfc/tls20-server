"""Provisioned PSK modes, importer domain separation, and actual wire exchanges."""

from dataclasses import replace
import hashlib
import hmac
import unittest

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand

from tls20_server import crypto as c, messages as m
from tls20_server.errors import ProtocolError
from tls20_server.psk import ExternalPSK, import_psk, bootstrap_public_key_psk
from tls20_server.tickets import TicketCache
from tests import test_sessions


class ImporterTests(unittest.TestCase):
    def test_independent_importer_oracle_and_domain_separation(self):
        for base_name, base_hash in (("sha256", hashes.SHA256()), ("sha384", hashes.SHA384())):
            for target, length, kdf in (("sha256", 32, 1), ("sha384", 48, 2)):
                psk = import_psk(b"a deliberately arbitrary length key", b"device", b"roles/deployment",
                                 "localhost", base_hash=base_name, target_hash=target)
                identity = b"\x00\x06device\x00\x10roles/deployment\x04\x00" + kdf.to_bytes(2, "big")
                self.assertEqual(psk.identity, identity)
                root = hmac.new(bytes(base_hash.digest_size), b"a deliberately arbitrary length key", base_name).digest()
                label = b"tls20 derived psk"
                context = hashlib.new(base_name, identity).digest()
                info = length.to_bytes(2, "big") + bytes((len(label),)) + label + bytes((len(context),)) + context
                self.assertEqual(psk.psk, HKDFExpand(base_hash, length, info).derive(root))
                self.assertNotEqual(c.binder(psk.psk, b"transcript", hash_name=target, kind="imp"),
                                    c.binder(psk.psk, b"transcript", hash_name=target, kind="ext"))

    def test_psk_only_wire_has_no_traffic_share_and_rejects_implicit_fallback(self):
        hello = m.client_hello(b"", b"", "localhost", bytes(32), group=0, psk_modes=(0,),
                               identity=b"provisioned", binder=bytes(32))
        parsed = m.parse_client_hello(hello[4:])
        self.assertEqual(parsed.group, 0)
        self.assertFalse(set(parsed.extensions) & {10, 51, 0xff02})
        self.assertEqual(parsed.psk_modes, (0,))
        with self.assertRaises(ProtocolError):
            m.parse_client_hello(m.client_hello(b"", b"", "localhost", bytes(32), group=0)[4:])

    def test_pok_is_imported_and_combined_only(self):
        psk = bootstrap_public_key_psk(bytes(range(32)), "localhost")
        self.assertTrue(psk.combined)
        self.assertEqual(psk.binder_kind, "imp")
        self.assertIn(b"tls20-bsk", psk.identity)
        with self.assertRaises(ValueError):
            replace(psk, max_early_data=42)


class ExternalHandshakeTests(unittest.IsolatedAsyncioTestCase):
    asyncSetUp = test_sessions.SessionTests.asyncSetUp
    asyncTearDown = test_sessions.SessionTests.asyncTearDown
    accept = test_sessions.SessionTests.accept
    handle = test_sessions.SessionTests.handle
    connect = test_sessions.SessionTests.connect

    async def test_external_direct_imported_psk_modes_and_resumption(self):
        for imported in (False, True):
            for mode in (0, 1):
                for code, name in ((0x1301, "sha256"), (0x1302, "sha384")):
                    with self.subTest(imported=imported, mode=mode, suite=code):
                        self.cache = TicketCache()
                        key = import_psk(b"key material", b"device", b"scoped", "localhost", target_hash=name) if imported else ExternalPSK(
                            b"scoped device", b"arbitrary length external secret", "localhost", hash_name=name, cipher_suite=code)
                        self.server_options = {"external_psks": (key,), "cipher_suites": (code,)}
                        ch = await self.connect(external_psk=key, psk_modes=(mode,), cipher_suites=(code,))
                        self.assertEqual(ch.psk_provenance, "imp" if imported else "ext")
                        self.assertEqual(ch.early_exporter("test"), self.channels[-1].early_exporter("test"))
                        await ch.send(b"explicit external authentication")
                        self.assertEqual(await ch.recv(), b"explicit external authentication")
                        resumed = await self.connect(external_psk=key, psk_modes=(mode,), cipher_suites=(code,))
                        self.assertEqual(resumed.psk_provenance, "res")
                        self.assertTrue(resumed.resumed)
        self.assertFalse(self.errors)

    async def test_combined_authentication_actually_validates_server_credential(self):
        key = ExternalPSK(b"combo", b"key material", "localhost", combined=True)
        self.server_options = {"external_psks": (key,)}
        ch = await self.connect(external_psk=key)
        self.assertEqual(ch.certificate_chain, self.credentials.chain_der)
        self.assertEqual(ch.psk_provenance, "ext")
        await ch.send(b"both proofs")
        self.assertEqual(await ch.recv(), b"both proofs")
        self.cache = TicketCache()
        self.roots = []
        with self.assertRaises(ProtocolError):
            await self.connect(external_psk=key)

    async def test_multiple_external_hashes_and_selected_identity_one(self):
        first = ExternalPSK(b"not provisioned here", b"key one", "localhost", max_early_data=1024)
        second = import_psk(b"key two", b"device two", b"scope", "localhost", target_hash="sha384")
        self.server_options = {"external_psks": (second,), "cipher_suites": (0x1302,)}
        for retry in (False, True):
            self.cache = TicketCache()
            client = await self.connect(external_psks=(first, second), cipher_suites=(0x1301, 0x1302),
                                        force_retry=retry, early_data=b"first PSK must not authorize this")
            self.assertEqual(client.selected_external_psk_identity, second.identity)
            self.assertEqual(client.cipher_suite, 0x1302)
            self.assertFalse(client.early_data_accepted)
            self.assertIsNone(client.early_exporter_secret)
            self.assertFalse(self.early)
            await client.send(b"selected second PSK")
            self.assertEqual(await client.recv(), b"selected second PSK")

    async def test_selected_secondary_binder_is_verified(self):
        first = ExternalPSK(b"other", b"unused secret", "localhost")
        second = ExternalPSK(b"selected", b"correct", "localhost")
        self.server_options = {"external_psks": (second,)}
        with self.assertRaises(ProtocolError):
            await self.connect(external_psks=(first, replace(second, psk=b"incorrect")))
        self.assertIn("PSK binder verification failed", self.errors)

    async def test_invalid_external_binder_rejected_and_no_unrelated_fallback(self):
        key = ExternalPSK(b"device", b"correct secret", "localhost")
        self.server_options = {"external_psks": (key,)}
        with self.assertRaises(ProtocolError):
            await self.connect(external_psk=replace(key, psk=b"wrong"))
        self.assertIn("PSK binder verification failed", self.errors)
        self.server_options = {}
        with self.assertRaises(ProtocolError):
            await self.connect(external_psk=key)

    async def test_external_early_requires_explicit_replay_authorizer(self):
        key = ExternalPSK(b"device", b"correct secret", "localhost", max_early_data=4096)
        self.server_options = {"external_psks": (key,)}
        ch = await self.connect(external_psk=key, early_data=b"not authorized")
        self.assertFalse(ch.early_data_accepted)
        self.assertFalse(self.early)
        self.cache = TicketCache()
        seen = set()
        def authorize(psk, identifier):
            self.assertIs(psk, key)
            if identifier in seen:
                return False
            seen.add(identifier)
            return True
        self.server_options["external_early_replay"] = authorize
        ch = await self.connect(external_psk=key, early_data=b"authorized")
        self.assertTrue(ch.early_data_accepted)
        self.assertEqual(self.early, [b"authorized", b""])
