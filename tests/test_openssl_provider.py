"""Optional native-provider tests; library selection is explicit, never discovery.

SM4 vectors are RFC 8998 Appendix A, independently published known answers.
Set TLS20_TEST_OPENSSL to the trusted OpenSSL 3.5+ library's absolute path.
"""

import os
import unittest

from cryptography.exceptions import InvalidTag

from tls20_server.errors import ConfigurationError, ProtocolError
from tls20_server.openssl_provider import OpenSSLProvider


class ProviderSelectionTests(unittest.TestCase):
    def test_explicit_absolute_existing_library_required(self):
        for name in ("libcrypto.so", "", "C:/does-not-exist/libcrypto.dll"):
            with self.assertRaises(ConfigurationError):
                OpenSSLProvider(name)


@unittest.skipUnless(os.environ.get("TLS20_TEST_OPENSSL"), "explicit native provider fixture not configured")
class NativeProviderTests(unittest.TestCase):
    def setUp(self):
        self.provider = OpenSSLProvider(os.environ["TLS20_TEST_OPENSSL"])

    def tearDown(self):
        self.provider.close()

    def test_rfc8998_sm4_gcm_and_ccm_known_answers(self):
        key = bytes.fromhex("0123456789ABCDEFFEDCBA9876543210")
        nonce = bytes.fromhex("00001234567800000000ABCD")
        aad = bytes.fromhex("FEEDFACEDEADBEEFFEEDFACEDEADBEEFABADDAD2")
        plain = bytes.fromhex("AAAAAAAAAAAAAAAABBBBBBBBBBBBBBBBCCCCCCCCCCCCCCCCDDDDDDDDDDDDDDDD"
                              "EEEEEEEEEEEEEEEEFFFFFFFFFFFFFFFFEEEEEEEEEEEEEEEEAAAAAAAAAAAAAAAA")
        answers = {
            "SM4-GCM": "17F399F08C67D5EE19D0DC9969C4BB7D5FD46FD3756489069157B282BB200735"
                       "D82710CA5C22F0CCFA7CBF93D496AC15A56834CBCF98C397B4024A2691233B8D"
                       "83DE3541E4C2B58177E065A9BF7B62EC",
            "SM4-CCM": "48AF93501FA62ADBCD414CCE6034D895DDA1BF8F132F042098661572E7483094"
                       "FD12E518CE062C98ACEE28D95DF4416BED31A2F04476C18BB40C84A74B97DC5B"
                       "16842D4FA186F56AB33256971FA110F4",
        }
        for algorithm, answer in answers.items():
            with self.subTest(algorithm=algorithm):
                cipher, expected = self.provider.aead(algorithm, key), bytes.fromhex(answer)
                self.assertEqual(cipher.encrypt(nonce, plain, aad), expected)
                self.assertEqual(cipher.decrypt(nonce, expected, aad), plain)
                for offset in (0, 63, 64, 79):
                    bad = bytearray(expected)
                    bad[offset] ^= 1
                    with self.assertRaises(InvalidTag):
                        cipher.decrypt(nonce, bytes(bad), aad)
                with self.assertRaises(InvalidTag):
                    cipher.decrypt(nonce, expected, aad + b"x")
                self.assertEqual(cipher.decrypt(nonce, cipher.encrypt(nonce, b"", b""), b""), b"")

    def test_sm2_curve_ecdh_and_native_key_lifetime(self):
        left, A = self.provider.generate_sm2()
        right, B = self.provider.generate_sm2()
        try:
            shared = self.provider.exchange_sm2(left, B)
            self.assertEqual(shared, self.provider.exchange_sm2(right, A))
            self.assertEqual(len(shared), 32)
            for bad in (b"", bytes(65), b"\x04" + bytes(64), A[:-1], b"\x02" + A[1:]):
                with self.assertRaises(ProtocolError):
                    self.provider.exchange_sm2(left, bad)
            with self.assertRaisesRegex(ProtocolError, "keys are alive"):
                self.provider.close()
        finally:
            left.close()
            right.close()
        with self.assertRaises(ProtocolError):
            self.provider.exchange_sm2(left, B)

    def test_closed_provider_refuses_existing_cipher(self):
        cipher = self.provider.aead("SM4-GCM", bytes(16))
        self.provider.close()
        with self.assertRaises(ProtocolError):
            cipher.encrypt(bytes(12), b"test", b"")

    def test_native_path_validates_real_path_not_only_signatures(self):
        from cryptography.hazmat.primitives import serialization
        from tls20_server.lab import generate_lab_credentials
        credential, root = generate_lab_credentials("localhost")
        leaf, root = credential.chain_der[0], root.public_bytes(serialization.Encoding.DER)
        result = self.provider.verify_certificate_path([leaf], [root], server_name="localhost")
        self.assertEqual(result, (leaf, root))
        with self.assertRaises(ProtocolError):
            self.provider.verify_certificate_path([leaf], [root], server_name="other.invalid")
        with self.assertRaises(ProtocolError):
            self.provider.verify_certificate_path([leaf], [root], server_name="localhost", now=0)
