"""Omitted roots are authenticated signature metadata, never peer trust."""
import tempfile
import unittest
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, x25519
from cryptography.x509.oid import NameOID

from tls20_server.errors import ConfigurationError, ProtocolError
from tls20_server.pki import (certificate_signature_scheme, find_certificate_issuer,
                             load_credentials)
from tests.test_pki import der, issue, replace_signature


class SignatureIssuerTests(unittest.TestCase):
    def setUp(self):
        self.signer = ed25519.Ed25519PrivateKey.generate()
        self.key = x25519.X25519PrivateKey.generate()
        self.name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Local issuer")])
        self.root = issue(self.signer, self.signer, self.name, self.name, ca=True)
        self.leaf = issue(self.key, self.signer, self.name, self.name)

    def test_signature_and_name_are_both_required(self):
        other_key = ed25519.Ed25519PrivateKey.generate()
        wrong_key = issue(other_key, other_key, self.name, self.name, ca=True)
        wrong_name = issue(self.signer, self.signer, x509.Name([]), self.name, ca=True)
        self.assertEqual(find_certificate_issuer(self.leaf, (der(wrong_key), der(self.root))), self.root)
        self.assertIsNone(find_certificate_issuer(self.leaf, (der(wrong_key), der(wrong_name))))
        bad = replace_signature(self.leaf, self.leaf.signature[:-1] + bytes([self.leaf.signature[-1] ^ 1]))
        self.assertIsNone(find_certificate_issuer(bad, (self.root,)))
        self.assertIsNone(find_certificate_issuer(self.leaf, ()))

    def test_authority_key_serial_and_name_are_checked(self):
        ski = self.root.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value.digest
        good = x509.AuthorityKeyIdentifier(ski, [x509.DirectoryName(self.root.issuer)], self.root.serial_number)
        bad_key = x509.AuthorityKeyIdentifier(bytes([ski[0] ^ 1]) + ski[1:], None, None)
        bad_serial = x509.AuthorityKeyIdentifier(ski, [x509.DirectoryName(self.root.issuer)], self.root.serial_number + 1)
        bad_name = x509.AuthorityKeyIdentifier(ski, [x509.DirectoryName(x509.Name([]))], self.root.serial_number)
        for authority in (good, bad_key, bad_serial, bad_name):
            leaf = issue(self.key, self.signer, self.name, self.name, extra=[(authority, False)])
            with self.subTest(authority=authority):
                self.assertEqual(find_certificate_issuer(leaf, (self.root,)), self.root if authority == good else None)

    def test_brainpool_mapping_uses_the_actual_omitted_issuer(self):
        for curve, algorithm, scheme in ((ec.BrainpoolP256R1(), hashes.SHA256(), 0x081a),
                (ec.BrainpoolP384R1(), hashes.SHA384(), 0x081b),
                (ec.BrainpoolP512R1(), hashes.SHA512(), 0x081c)):
            signer = ec.generate_private_key(curve)
            root = issue(signer, signer, self.name, self.name, ca=True, algorithm=algorithm)
            leaf = issue(self.key, signer, self.name, self.name, algorithm=algorithm)
            issuer = find_certificate_issuer(leaf, (der(root),))
            self.assertIsNotNone(issuer)
            self.assertEqual(certificate_signature_scheme(leaf, issuer), scheme)

    def test_inventory_is_bounded_and_der_is_strict(self):
        for inventory in ((der(self.root),) * 65, (der(self.root) + b"x",),
                          (b"x" * 262145,), (None,), iter((self.root,))):
            with self.subTest(kind=type(inventory)), self.assertRaises(ProtocolError):
                find_certificate_issuer(self.leaf, inventory)

    def test_loader_keeps_issuer_metadata_off_the_transmitted_chain(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            (path / "leaf.pem").write_bytes(self.leaf.public_bytes(serialization.Encoding.PEM))
            (path / "key.pem").write_bytes(self.key.private_bytes(serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
            (path / "key.pem").chmod(0o600)
            result = load_credentials(path / "leaf.pem", path / "key.pem", "example.test",
                                      signature_issuers=(self.root,))
            self.assertEqual(result.chain_der, [der(self.leaf)])
            self.assertEqual(result.signature_issuers, (der(self.root),))
            wrong_key = ed25519.Ed25519PrivateKey.generate()
            wrong = issue(wrong_key, wrong_key, self.name, self.name, ca=True)
            with self.assertRaises(ConfigurationError):
                load_credentials(path / "leaf.pem", path / "key.pem", "example.test",
                                 signature_issuers=(wrong,))
