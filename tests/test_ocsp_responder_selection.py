"""An OCSP ResponderID selects candidates, not an unchecked first signer."""

from datetime import timedelta
import unittest

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, ed448, rsa
from cryptography.x509 import ocsp
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from tests import test_credential_profiles as fixtures
from tls20_server.credential_profiles import validate_ocsp_response
from tls20_server.errors import ProtocolError
from tls20_server.pki import _children, _element


def tlv(tag, body):
    size = len(body)
    length = (bytes((size,)) if size < 128 else
              bytes((128 + (size.bit_length() + 7) // 8,))
              + size.to_bytes((size.bit_length() + 7) // 8, "big"))
    return bytes((tag,)) + length + body


def with_certificates(response, certificates):
    """Change only the unsigned auxiliary list, preserving signed bytes."""
    outer = _children(_element(response)[1])
    response_bytes = _children(_element(outer[1][1])[1])
    basic = _children(_element(response_bytes[1][1])[1])
    encoded = b"".join(cert.public_bytes(serialization.Encoding.DER) for cert in certificates)
    changed = tlv(0x30, b"".join(field[2] for field in basic[:3]) + tlv(0xa0, tlv(0x30, encoded)))
    return tlv(0x30, outer[0][2] + tlv(0xa0, tlv(0x30, response_bytes[0][2] + tlv(4, changed))))


class OCSPResponderSelectionTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.CredentialProfileTests()
        self.fixture.setUp()
        self.now = self.fixture.now
        self.name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Rollover responder")])
        self.old_key = ec.generate_private_key(ec.SECP256R1())
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.old = self.responder(self.old_key)
        self.current = self.responder(self.key)

    def responder(self, key, *, issuer_key=None, expiry=None, eku=True, digital_signature=True, critical=False):
        builder = (x509.CertificateBuilder().subject_name(self.name).issuer_name(self.fixture.root.subject)
                   .public_key(key.public_key()).serial_number(x509.random_serial_number())
                   .not_valid_before(self.now-timedelta(days=2))
                   .not_valid_after(expiry or self.now+timedelta(days=1))
                   .add_extension(x509.BasicConstraints(False, None), True)
                   .add_extension(x509.KeyUsage(digital_signature, False, False, False, False,
                                                False, False, False, False), True))
        if eku:
            builder = builder.add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.OCSP_SIGNING]), False)
        if critical:
            builder = builder.add_extension(x509.UnrecognizedExtension(x509.ObjectIdentifier("1.2.3.4"), b"opaque"), True)
        return builder.sign(issuer_key or self.fixture.ca_key, hashes.SHA256())

    def response(self, *, encoding=ocsp.OCSPResponderEncoding.NAME, key=None, responder=None):
        key = key or self.key
        builder = (ocsp.OCSPResponseBuilder().add_response(self.fixture.leaf, self.fixture.root,
            hashes.SHA256(), ocsp.OCSPCertStatus.GOOD, self.now-timedelta(minutes=1),
            self.now+timedelta(hours=1), None, None).responder_id(encoding, responder or self.current)
            .certificates([self.old, responder or self.current]))
        algorithm = None if isinstance(key, (ed25519.Ed25519PrivateKey, ed448.Ed448PrivateKey)) else hashes.SHA256()
        return builder.sign(key, algorithm).public_bytes(serialization.Encoding.DER)

    def validate(self, response):
        return validate_ocsp_response(response, self.fixture.leaf, self.fixture.root)

    def test_rollover_order_changes_neither_authorization_nor_signature(self):
        for encoding in (ocsp.OCSPResponderEncoding.NAME, ocsp.OCSPResponderEncoding.HASH):
            original = self.response(encoding=encoding)
            reference = ocsp.load_der_ocsp_response(original)
            for candidates in ([self.old, self.current], [self.current, self.old], [self.current]):
                with self.subTest(encoding=encoding, candidates=len(candidates)):
                    changed = with_certificates(original, candidates)
                    parsed = ocsp.load_der_ocsp_response(changed)
                    self.assertEqual(reference.tbs_response_bytes, parsed.tbs_response_bytes)
                    self.assertEqual(reference.signature, parsed.signature)
                    self.assertTrue(self.validate(changed))

    def test_same_name_without_actual_signer_is_not_authority(self):
        for candidates in ([], [self.old], [self.fixture.root, self.old]):
            with self.subTest(count=len(candidates)), self.assertRaises(ProtocolError):
                self.validate(with_certificates(self.response(), candidates))

    def test_invalid_candidates_do_not_mask_valid_signer_or_grant_authority(self):
        # All these certificates have the actual signing key and the same DN.
        # Only their authorization is bad; signature failure cannot mask a bug.
        candidates = [self.responder(self.key, issuer_key=ec.generate_private_key(ec.SECP256R1())),
                      self.responder(self.key, expiry=self.now-timedelta(days=1)),
                      self.responder(self.key, eku=False),
                      self.responder(self.key, digital_signature=False),
                      self.responder(self.key, critical=True)]
        original = self.response()
        for index, candidate in enumerate(candidates):
            with self.subTest(candidate=index):
                self.assertTrue(self.validate(with_certificates(original, [candidate, self.current])))
                self.assertTrue(self.validate(with_certificates(original, [self.current, candidate])))
                with self.assertRaises(ProtocolError):
                    self.validate(with_certificates(original, [candidate]))

    def test_unrelated_valid_certificate_cannot_authorize_bad_signature(self):
        attacker = ec.generate_private_key(ec.SECP256R1())
        response = self.response(key=attacker, responder=self.responder(attacker))
        with self.assertRaises(ProtocolError):
            self.validate(with_certificates(response, [self.old, self.current]))

    def test_supported_signer_types_after_wrong_key_candidate(self):
        for key in (ed25519.Ed25519PrivateKey.generate(), ed448.Ed448PrivateKey.generate(),
                    rsa.generate_private_key(public_exponent=65537, key_size=2048), self.key):
            with self.subTest(key=type(key).__name__):
                self.assertTrue(self.validate(self.response(key=key, responder=self.responder(key))))


if __name__ == "__main__":
    unittest.main()
