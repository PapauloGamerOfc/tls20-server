"""Native optional-provider KATs from RFC9058/RFC7836, not self-generated answers."""

import os
import unittest

from cryptography.exceptions import InvalidTag

from tls20_server.errors import ConfigurationError, ProtocolError
from tls20_server.gost_provider import GOSTProvider, GROUPS, SUITES


class GOSTSelectionTests(unittest.TestCase):
    def test_requires_explicit_module(self):
        with self.assertRaises(ConfigurationError):
            GOSTProvider("unused", "gostprov")


@unittest.skipUnless(os.environ.get("TLS20_TEST_OPENSSL") and os.environ.get("TLS20_TEST_GOST_MODULE"),
                     "explicit GOST module fixture not configured")
class GOSTProviderTests(unittest.TestCase):
    def setUp(self):
        self.provider = GOSTProvider(os.environ["TLS20_TEST_OPENSSL"], os.environ["TLS20_TEST_GOST_MODULE"])

    def tearDown(self):
        self.provider.close()

    def test_streebog_hmac_published_answers(self):
        # RFC7836 A.1/A.2: native HMAC uses the explicitly loaded provider digest.
        key, message = bytes(range(32)), bytes.fromhex("0126bdb87800af214341456563780100")
        self.assertEqual(self.provider.hmac("streebog256", key, message).hex(),
                         "a1aa5f7de402d7b3d323f2991c8d4534013137010a83754fd0af6d7cd4922ed9")
        self.assertEqual(self.provider.hmac("streebog512", key, message).hex(),
                         "a59bab22ecae19c65fbde6e5f4e9f5d8549d31f037f9df9b905500e171923a77"
                         "3d5f1530f2ed7e964cb2eedc29e9ad2f3afe93b2814f79f5000ffc0366c251e6")
        self.assertEqual(self.provider.digest("streebog256", b"").hex(),
                         "3f539a213e97c802cc229d474c6aa32a825a360b2a933a949fd925208d9ce1bb")

    def test_mgm_rfc9058_vectors_and_tamper(self):
        vectors = [
            ("kuznyechik-mgm", "8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef",
             "1122334455667700ffeeddccbbaa9988",
             "0202020202020202010101010101010104040404040404040303030303030303ea0505050505050505",
             "1122334455667700ffeeddccbbaa998800112233445566778899aabbcceeff0a"
             "112233445566778899aabbcceeff0a002233445566778899aabbcceeff0a0011aabbcc",
             "a9757b8147956e9055b8a33de89f42fc8075d2212bf9fd5bd3f7069aadc16b39"
             "497ab15915a6ba85936b5d0ea9f6851cc60c14d4d3f883d0ab94420695c76deb2c7552"
             "cf5d656f40c34f5c46e8bb0e29fcdb4c"),
            ("magma-mgm", "ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
             "12def06b3c130a59",
             "01010101010101010202020202020202030303030303030304040404040404040505050505050505ea",
             "ffeeddccbbaa998811223344556677008899aabbcceeff0a0011223344556677"
             "99aabbcceeff0a001122334455667788aabbcceeff0a00112233445566778899aabbcc",
             "c795066c5f9ea03b85113342459185ae1f2e00d6bf2b785d940470b8bb9c8e7d"
             "9a5dd3731f7ddc70ec27cb0ace6fa57670f65c646abb75d547aa37c3bcb5c34e03bb9c"
             "a7928069aa10fd10"),
        ]
        for name, key, nonce, aad, plain, expected in vectors:
            with self.subTest(name=name):
                key, nonce, aad, plain, expected = map(bytes.fromhex, (key, nonce, aad, plain, expected))
                cipher = self.provider.aead(name, key)
                self.assertEqual(cipher.encrypt(nonce, plain, aad), expected)
                self.assertEqual(cipher.decrypt(nonce, expected, aad), plain)
                for offset in (0, len(plain), len(expected) - 1):
                    wrong = bytearray(expected)
                    wrong[offset] ^= 1
                    with self.assertRaises(InvalidTag):
                        cipher.decrypt(nonce, bytes(wrong), aad)
                with self.assertRaises(InvalidTag):
                    cipher.decrypt(nonce, expected, aad + b"x")

    def test_all_seven_groups_and_reject_invalid_points(self):
        for group in GROUPS:
            with self.subTest(group=group):
                a, A = self.provider.generate_gost(group)
                b, B = self.provider.generate_gost(group)
                try:
                    self.assertEqual(self.provider.exchange_gost(a, group, B), self.provider.exchange_gost(b, group, A))
                    for bad in (b"", bytes(len(A)), bytes([255]) * len(A), A[:-1]):
                        with self.assertRaises(ProtocolError):
                            self.provider.exchange_gost(a, group, bad)
                    with self.assertRaises(ProtocolError):
                        self.provider.close()
                finally:
                    a.close()
                    b.close()

    def test_tlstree_sequence_bounds_and_rekey_schedule(self):
        # RFC9367 A.1/A.2 published keys at two independent rollover points.
        self.assertEqual(self.provider.tlstree(0xc105, bytes.fromhex(
            "475e4c514cc6318c3a5f000f1265bd1ab5f0de1af357ed0079ec5ff0afbd030c"), 0).hex(),
            "c8fc93d7c586f2b0a3101baa6a979e4e3886706551e81187e97880409c7e8ee9")
        self.assertEqual(self.provider.tlstree(0xc105, bytes.fromhex(
            "475e4c514cc6318c3a5f000f1265bd1ab5f0de1af357ed0079ec5ff0afbd030c"), 8).hex(),
            "d3cd87d5687407823978344c06b928a85898b739a31d3de5ff2b788ef39196ed")
        self.assertEqual(self.provider.tlstree(0xc104, bytes.fromhex(
            "15d92c5147b21310ededf55b3d7ab776817d6fe2fcf230d7e3f29275f6e241ec"), 128).hex(),
            "93d5d6e1036fdfb3efbf31e6da5eece685171c977ff9cd6c3a3f67c0224ab6eb")
        root = bytes(range(32))
        for suite, (_, _, maximum, masks) in SUITES.items():
            with self.subTest(suite=suite):
                baseline = self.provider.tlstree(suite, root, 0)
                self.assertNotEqual(root, baseline)
                boundary = ((~masks[2]) & ((1 << 64) - 1)) + 1
                self.assertEqual(baseline, self.provider.tlstree(suite, root, boundary - 1))
                self.assertNotEqual(baseline, self.provider.tlstree(suite, root, boundary))
                self.assertEqual(len(self.provider.tlstree(suite, root, maximum)), 32)
                for invalid in (-1, maximum + 1):
                    with self.assertRaises(ProtocolError):
                        self.provider.tlstree(suite, root, invalid)

    def test_record_cache_rekeys_only_necessary_levels_and_nonce_mask(self):
        from unittest.mock import patch
        key = bytes(range(32))
        sender = self.provider.record_cipher(0xc105, key)
        receiver = self.provider.record_cipher(0xc105, key)
        with patch.object(self.provider, "hmac", wraps=self.provider.hmac) as observed:
            first = sender.encrypt_record(0, bytes([128]) + bytes(15), b"hello", b"aad")
            self.assertEqual(observed.call_count, 3)
            sender.encrypt_record(1, bytes(15) + b"\x01", b"hello", b"aad")
            self.assertEqual(observed.call_count, 3)
            sender.encrypt_record(8, bytes(15) + b"\x08", b"hello", b"aad")
            self.assertEqual(observed.call_count, 4)
            sender.encrypt_record(1 << 16, bytes(16), b"hello", b"aad")
            self.assertEqual(observed.call_count, 6)
        self.assertEqual(receiver.decrypt_record(0, bytes(16), first, b"aad"), b"hello")
        with self.assertRaises(ProtocolError):
            self.provider.aead("kuznyechik-mgm", key).encrypt(bytes([128]) + bytes(15), b"x", b"")
        with self.assertRaises(ProtocolError):
            sender.encrypt_record(1 << 42, bytes(16), b"hello", b"aad")
