"""RFC 9150 oracle independent of the TLS 2.0 record/key schedule helpers."""
import hashlib
import hmac
import unittest

from cryptography.exceptions import InvalidTag

from tls20_server.integrity_only import IntegrityOnly


class IntegrityOnlyTests(unittest.TestCase):
    def test_literal_record_formula_and_cleartext(self):
        for name in ("sha256", "sha384"):
            with self.subTest(name=name):
                size = hashlib.new(name).digest_size
                key, nonce = bytes(range(size)), bytes(range(size, size * 2))
                inner = b"non confidential message\x17\x00\x00"
                header = b"\x17\x03\x03" + (len(inner) + size).to_bytes(2, "big")
                expected = inner + hmac.new(key, nonce + header + inner, name).digest()
                state = IntegrityOnly(key, name)
                self.assertFalse(state.confidential)
                self.assertEqual(state.encrypt(nonce, inner, header), expected)
                self.assertEqual(state.decrypt(nonce, expected, header), inner)
                # Alterations anywhere in the tag or the protected plaintext fail.
                for index in range(len(expected)):
                    tampered = bytearray(expected)
                    tampered[index] ^= 1
                    with self.assertRaises(InvalidTag):
                        state.decrypt(nonce, bytes(tampered), header)
                with self.assertRaises(InvalidTag):
                    state.decrypt(bytes(size), expected, header)
                with self.assertRaises(InvalidTag):
                    IntegrityOnly(bytes(size), name).decrypt(nonce, expected, header)

    def test_nonce_key_and_header_lengths_not_gcm_lengths(self):
        for name, size in (("sha256", 32), ("sha384", 48)):
            with self.subTest(name=name):
                for length in (0, 12, 16, size - 1, size + 1):
                    with self.assertRaises(ValueError):
                        IntegrityOnly(bytes(length), name)
                state = IntegrityOnly(bytes(size), name)
                header = b"\x17\x03\x03" + (size + 1).to_bytes(2, "big")
                for length in (0, 12, 16, size - 1, size + 1):
                    with self.assertRaises(ValueError):
                        state.encrypt(bytes(length), b"\x17", header)
                for bad in (b"", header[:-1], header + b"\x00", b"\x16" + header[1:],
                            header[:3] + b"\x00\x00"):
                    with self.assertRaises(ValueError):
                        state.encrypt(bytes(size), b"\x17", bad)

    def test_short_tag_and_empty_plaintext(self):
        state = IntegrityOnly(bytes(32), "sha256")
        header = b"\x17\x03\x03\x00\x20"
        protected = state.encrypt(bytes(32), b"", header)
        self.assertEqual(state.decrypt(bytes(32), protected, header), b"")
        with self.assertRaises(InvalidTag):
            state.decrypt(bytes(32), bytes(31), b"\x17\x03\x03\x00\x1f")
        # RecordState (not the primitive) rejects a missing inner content type.

    def test_unknown_hash_rejected(self):
        with self.assertRaises(ValueError):
            IntegrityOnly(bytes(20), "sha1")
