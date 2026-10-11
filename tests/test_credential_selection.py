"""Credential selection is filtering, not remote trust validation."""

from dataclasses import replace
from datetime import datetime, timedelta, timezone
import unittest

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.x509.oid import ExtensionOID, ExtendedKeyUsageOID, NameOID

from tls20_server.credential_selection import (
    encode_certificate_authorities, parse_certificate_authorities,
    encode_oid_filters, parse_oid_filters, match_credentials, preferred_credentials,
)
from tls20_server.errors import ProtocolError
from tls20_server.pki import Credentials


def name(label):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, label)])


def credential(issuer="issuer", eku=None, usage=None, extensions=True):
    private = x25519.X25519PrivateKey.generate()
    now = datetime.now(timezone.utc)
    builder = (x509.CertificateBuilder().subject_name(name("client"))
               .issuer_name(name(issuer)).serial_number(1).public_key(private.public_key())
               .not_valid_before(now - timedelta(minutes=1)).not_valid_after(now + timedelta(days=1))
               .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True))
    if extensions:
        builder = builder.add_extension(usage or x509.KeyUsage(True, False, False, False, True,
                                                              False, False, True, True), critical=True)
        builder = builder.add_extension(x509.ExtendedKeyUsage(eku or [ExtendedKeyUsageOID.CLIENT_AUTH,
                                                                     ExtendedKeyUsageOID.EMAIL_PROTECTION]), critical=False)
    certificate = builder.sign(ed25519.Ed25519PrivateKey.generate(), None)
    return Credentials([certificate.public_bytes(serialization.Encoding.DER)], private)


class CredentialSelectionTests(unittest.TestCase):
    def test_authority_codec_and_omitted_issuer(self):
        one, two = credential("one"), credential("two")
        extension = encode_certificate_authorities([name("two"), name("root")])
        self.assertEqual(parse_certificate_authorities(extension), (name("two").public_bytes(), name("root").public_bytes()))
        self.assertEqual(preferred_credentials([one, two], {47: extension}), (two, one))
        # CA names guide selection; they never veto the only available identity.
        self.assertTrue(match_credentials(one, {47: extension}))
        self.assertEqual(preferred_credentials([one], {47: extension}), (one,))

    def test_ca_leaf_subject_is_not_ca_and_rpk_is_unconstrained(self):
        one = credential("one")
        raw = replace(one, credential_type=2, chain_der=[one.private_key.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)])
        extension = encode_certificate_authorities([name("client")])
        self.assertEqual(preferred_credentials([one, raw], {47: extension}), (raw, one))
        self.assertTrue(match_credentials(raw, {47: extension}))

    def test_key_usage_is_subset_not_equal(self):
        one = credential()
        request = x509.KeyUsage(False, False, False, False, True, False, False, True, False)
        extension = encode_oid_filters([(ExtensionOID.KEY_USAGE, request)])
        self.assertTrue(match_credentials(one, {48: extension}))
        request = x509.KeyUsage(False, False, True, False, False, False, False, False, False)
        self.assertFalse(match_credentials(one, {48: encode_oid_filters([(ExtensionOID.KEY_USAGE, request)])}))
        self.assertFalse(match_credentials(credential(extensions=False), {48: extension}))

    def test_eku_subset_and_no_implicit_anyeku_wildcard(self):
        extension = encode_oid_filters([(ExtensionOID.EXTENDED_KEY_USAGE,
                                         x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]))])
        self.assertTrue(match_credentials(credential(), {48: extension}))
        self.assertFalse(match_credentials(credential(eku=[ExtendedKeyUsageOID.SERVER_AUTH]), {48: extension}))
        self.assertFalse(match_credentials(credential(eku=[ExtendedKeyUsageOID.ANY_EXTENDED_KEY_USAGE]), {48: extension}))
        with self.assertRaises(ProtocolError):
            encode_oid_filters([(ExtensionOID.EXTENDED_KEY_USAGE,
                                 x509.ExtendedKeyUsage([ExtendedKeyUsageOID.ANY_EXTENDED_KEY_USAGE]))])

    def test_presence_unknown_oid_and_raw_key(self):
        extension = encode_oid_filters([(ExtensionOID.KEY_USAGE, b"")])
        self.assertTrue(match_credentials(credential(), {48: extension}))
        self.assertFalse(match_credentials(credential(extensions=False), {48: extension}))
        raw = replace(credential(), credential_type=2, chain_der=[b"not parsed as a certificate"])
        self.assertFalse(match_credentials(raw, {48: extension}))
        unknown = encode_oid_filters([("1.2.3.4.5", b"unrecognized value need not be parsed")])
        self.assertTrue(match_credentials(raw, {48: unknown}))
        self.assertEqual(parse_oid_filters(encode_oid_filters([])), ())

    def test_delegated_parent_filtered_and_stable_ranking(self):
        one, two = credential(), credential()
        one = replace(one, delegation=b"separate grant validation")
        ext = encode_oid_filters([(ExtensionOID.KEY_USAGE, b"")])
        self.assertTrue(match_credentials(one, {48: ext}))
        self.assertEqual(preferred_credentials([one, two], {48: ext}), (one, two))

    def test_duplicate_oids_and_request_extensions_are_rejected(self):
        with self.assertRaises(ProtocolError):
            encode_oid_filters([(ExtensionOID.KEY_USAGE, b""), ("2.5.29.15", b"")])
        with self.assertRaises(ProtocolError):
            match_credentials(credential(), [(48, b"\0\0"), (48, b"\0\0")])

    def test_known_value_der_errors_and_bounds(self):
        invalid_usage = [b"\x03\x02\x07\x01", b"\x03\x02\x00\x80", b"\x03\x02\x08\x80",
                         b"\x03\x02\x00\x00", b"\x03\x03\x00\x80\x01", b"\x03\x81\x01\x00"]
        for value in invalid_usage:
            with self.subTest(value=value), self.assertRaises(ProtocolError):
                encode_oid_filters([(ExtensionOID.KEY_USAGE, value)])
        for value in (b"\x30\x00", b"\x30\x04\x06\x02\x80\x01", b"\x30\x03\x06\x01\x80"):
            with self.subTest(value=value), self.assertRaises(ProtocolError):
                encode_oid_filters([(ExtensionOID.EXTENDED_KEY_USAGE, value)])
        self.assertTrue(match_credentials(credential(), {48: encode_oid_filters([(ExtensionOID.KEY_USAGE, b"\x03\x01\x00")])}))
        with self.assertRaises(ProtocolError):
            encode_oid_filters([("1.2.3", bytes(65536))])

    def test_malformed_authority_and_filter_vectors(self):
        for encoded in (b"\0\0", b"\0\3\0\1\0", b"\0\4\0\2\x30\0x", b"\0\4\0\2\x31\0"):
            with self.subTest(encoded=encoded), self.assertRaises(ProtocolError):
                parse_certificate_authorities(encoded)
        for encoded in (b"", b"\0\0x", b"\0\3\0\0\0", b"\0\1\xff"):
            with self.subTest(encoded=encoded), self.assertRaises(ProtocolError):
                parse_oid_filters(encoded)

    def test_oid_with_large_first_subidentifier_and_der_long_length(self):
        oid = "2.999.1234567890.7"
        extension = encode_oid_filters([(oid, b"ignored")])
        self.assertEqual(parse_oid_filters(extension), ((oid, b"ignored"),))
        long_name = x509.Name([x509.NameAttribute(oid, "a" * 60) for oid in (
            NameOID.COMMON_NAME, NameOID.ORGANIZATION_NAME, NameOID.ORGANIZATIONAL_UNIT_NAME)])
        self.assertEqual(parse_certificate_authorities(encode_certificate_authorities([long_name])), (long_name.public_bytes(),))


if __name__ == "__main__":
    unittest.main()
