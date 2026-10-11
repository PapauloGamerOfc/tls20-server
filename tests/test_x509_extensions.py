"""An open TLSFeature registry never disables signed certificate policy."""
from datetime import datetime, timezone
import ipaddress
import tempfile
from pathlib import Path
import unittest

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.x509.oid import ExtensionOID, ExtendedKeyUsageOID, NameOID

from tls20_server.errors import ProtocolError
from tls20_server.pki import (Credentials, _load_pkix_der, certificate_extensions,
    find_certificate_issuer, load_credentials, load_trust_roots, validate_chain, validate_identity)
from tls20_server.credential_selection import match_credentials, encode_oid_filters
from tls20_server.credential_profiles import DELEGATION_USAGE, validate_delegation
from tls20_server.credential_evidence import CredentialEvidencePolicy
from tls20_server.x509_extensions import _decode
from tests.test_pki import issue, der, replace_signature


UNKNOWN = x509.UnrecognizedExtension(ExtensionOID.TLS_FEATURE, bytes.fromhex('300402021234'))


class OpenExtensionRegistryTests(unittest.TestCase):
    def setUp(self):
        self.ca = ed25519.Ed25519PrivateKey.generate()
        self.key = x25519.X25519PrivateKey.generate()
        self.name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'Feature CA')])
        self.root = issue(self.ca, self.ca, self.name, self.name, ca=True)

    def leaf(self, **options):
        extra = [(UNKNOWN, False), *options.pop('extra', ())]
        return issue(self.key, self.ca, self.name, self.name, extra=extra, **options)

    def validate_both(self, leaf, root=None, name='example.test'):
        anchors = (root or self.root,)
        expected = self.key.public_key().public_bytes_raw()
        self.assertEqual(validate_identity([der(leaf)], trust_roots=anchors,
            role='server', name=name).public_bytes_raw(), expected)
        self.assertEqual(validate_chain([der(leaf)], anchors, name, 'lab-offline').public_bytes_raw(), expected)

    def test_unknown_unoffered_feature_preserves_exact_signed_certificate(self):
        leaf = self.leaf()
        before = der(leaf)
        with self.assertRaises(KeyError):
            leaf.extensions  # The underlying provider's closed enum is real.
        parsed = _load_pkix_der(before)
        self.assertEqual(der(parsed), before)
        self.assertEqual(parsed.tbs_certificate_bytes, leaf.tbs_certificate_bytes)
        self.validate_both(leaf)
        self.assertTrue(CredentialEvidencePolicy()((leaf, self.root), 'server', (), datetime.now(timezone.utc)))
        self.assertEqual(der(leaf), before)

    def test_unknown_issuer_constraint_cannot_disappear_without_evidence_policy(self):
        root = issue(self.ca, self.ca, self.name, self.name, ca=True, extra=[(UNKNOWN, False)])
        self.validate_both(self.leaf(), root)
        ordinary = issue(self.key, self.ca, self.name, self.name)
        for validator in (lambda: validate_identity([der(ordinary)], trust_roots=(root,), role='server', name='example.test'),
                          lambda: validate_chain([der(ordinary)], (root,), 'example.test', 'lab-offline')):
            with self.assertRaises(ProtocolError):
                validator()

    def test_known_issuer_constraint_also_applies_to_offline_path(self):
        root = issue(self.ca, self.ca, self.name, self.name, ca=True,
            extra=[(x509.TLSFeature([x509.TLSFeatureType.status_request]), False)])
        with self.assertRaises(ProtocolError):
            validate_identity([der(self.leaf())], trust_roots=(root,), role='server', name='example.test')

    def test_names_key_usage_eku_and_validity_are_not_bypassed(self):
        wrong_usage = x509.KeyUsage(True,False,False,False,False,False,False,False,False)
        wrong_eku = x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH])
        leaves = (self.leaf(hostname='wrong.test'), self.leaf(key_usage=wrong_usage),
                  self.leaf(eku=False, extra=[(wrong_eku,False)]), self.leaf(validity=-1))
        for leaf in leaves:
            with self.subTest(serial=leaf.serial_number):
                with self.assertRaises(ProtocolError):
                    validate_identity([der(leaf)], trust_roots=(self.root,), role='server', name='example.test')
                with self.assertRaises(ProtocolError):
                    validate_chain([der(leaf)], (self.root,), 'example.test', 'lab-offline')

    def test_signature_and_critical_constraints_are_not_bypassed(self):
        leaf = self.leaf()
        bad = replace_signature(leaf, leaf.signature[:-1] + bytes((leaf.signature[-1] ^ 1,)))
        with self.assertRaises(ProtocolError):
            validate_identity([bad], trust_roots=(self.root,), role='server', name='example.test')
        unknown_critical = self.leaf(extra=[(x509.UnrecognizedExtension(x509.ObjectIdentifier('1.2.3.4'),b'\x05\x00'),True)])
        with self.assertRaises(ProtocolError):
            validate_identity([der(unknown_critical)], trust_roots=(self.root,), role='server', name='example.test')
        constrained = issue(self.ca,self.ca,self.name,self.name,ca=True,extra=[
            (UNKNOWN,False),(x509.NameConstraints([x509.DNSName('allowed.test')],None),True)])
        with self.assertRaises(ProtocolError):
            validate_identity([der(leaf)],trust_roots=(constrained,),role='server',name='example.test')

    def test_aki_ski_directory_name_and_selection_stay_enforced(self):
        ski = certificate_extensions(self.root).get_extension_for_class(x509.SubjectKeyIdentifier).value.digest
        for serial in (self.root.serial_number, self.root.serial_number + 1):
            authority = x509.AuthorityKeyIdentifier(ski,[x509.DirectoryName(self.root.issuer)],serial)
            leaf = self.leaf(extra=[(authority,False)])
            self.assertEqual(find_certificate_issuer(leaf,(self.root,)), self.root if serial == self.root.serial_number else None)
        credentials = Credentials([der(self.leaf())],self.key)
        for wanted in (ExtendedKeyUsageOID.SERVER_AUTH,ExtendedKeyUsageOID.CLIENT_AUTH):
            request = encode_oid_filters(((ExtensionOID.EXTENDED_KEY_USAGE,x509.ExtendedKeyUsage([wanted])),))
            self.assertEqual(match_credentials(credentials,((48,request),)),wanted == ExtendedKeyUsageOID.SERVER_AUTH)

    def test_ip_san_is_decoded_without_treating_dns_name_as_ip(self):
        leaf = self.leaf(hostname=None,extra=[(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address('::1'))]),False)])
        self.validate_both(leaf,name='::1')
        with self.assertRaises(ProtocolError):
            validate_identity([der(self.leaf(hostname='::1'))],trust_roots=(self.root,),role='server',name='::1')

    def test_loaders_accept_unknown_features_without_reencoding_credentials(self):
        root = issue(self.ca,self.ca,self.name,self.name,ca=True,extra=[(UNKNOWN,False)])
        leaf = self.leaf()
        with tempfile.TemporaryDirectory() as temporary:
            folder = Path(temporary)
            (folder/'roots.pem').write_bytes(root.public_bytes(serialization.Encoding.PEM))
            (folder/'chain.pem').write_bytes(leaf.public_bytes(serialization.Encoding.PEM)+root.public_bytes(serialization.Encoding.PEM))
            (folder/'key.pem').write_bytes(self.key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
            (folder/'key.pem').chmod(0o600)
            self.assertEqual(load_trust_roots(folder/'roots.pem',general_pkix=True),[root])
            self.assertEqual(load_credentials(folder/'chain.pem',folder/'key.pem','example.test').chain_der,[der(leaf),der(root)])

    def test_delegation_parent_can_have_unknown_unoffered_feature(self):
        signer = ed25519.Ed25519PrivateKey.generate()
        parent = issue(signer,self.ca,self.name,self.name,
            key_usage=x509.KeyUsage(True,False,False,False,False,False,False,False,False),
            extra=[(UNKNOWN,False),(x509.UnrecognizedExtension(DELEGATION_USAGE,b'\x05\x00'),False)])
        spki = self.key.public_key().public_bytes(serialization.Encoding.DER,serialization.PublicFormat.SubjectPublicKeyInfo)
        encoded = (3900).to_bytes(4,'big') + b'\xfe\x00' + len(spki).to_bytes(3,'big') + spki + b'\x08\x07'
        signature = signer.sign(b' '*64 + b'TLS20 server delegated credentials\0' + der(parent) + encoded)
        grant = encoded + len(signature).to_bytes(2,'big') + signature
        key,_ = validate_delegation(der(parent),grant,role='server',grant_algorithms=(0x0807,),delegated_schemes=(0xfe00,))
        self.assertEqual(key.public_bytes_raw(),self.key.public_key().public_bytes_raw())

    def test_specific_decoders_reject_noncanonical_or_invalid_usage(self):
        cases = ((ExtensionOID.BASIC_CONSTRAINTS,b'\x30\x03\x01\x01\x00'),
                 (ExtensionOID.BASIC_CONSTRAINTS,b'\x30\x03\x02\x01\x01'),
                 (ExtensionOID.KEY_USAGE,b'\x03\x02\x00\x80'),
                 (ExtensionOID.KEY_USAGE,b'\x03\x02\x07\x81'),
                 (ExtensionOID.EXTENDED_KEY_USAGE,b'\x30\0'),
                 (ExtensionOID.AUTHORITY_KEY_IDENTIFIER,b'\x30\x06\x80\x01a\x80\x01b'))
        for oid,value in cases:
            with self.subTest(oid=oid,value=value),self.assertRaises(ProtocolError):
                _decode(oid,value)


if __name__ == '__main__':
    unittest.main()
