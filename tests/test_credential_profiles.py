"""Credential authorization uses real provider signatures and independent offers."""

from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
import tempfile
import unittest

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa, x25519
from cryptography.x509 import ocsp
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from tls20_server.credential_profiles import (CredentialPolicy, DELEGATION_USAGE,
    RawPublicKeyBinding, parse_x25519_spki, resolve_peer, validate_delegation,
    validate_ocsp_response)
from tls20_server.errors import ConfigurationError, ProtocolError
from tls20_server.pki import (certificate_signature_scheme, validate_identity,
                              validate_pkix_path, verify_public_signature, load_credentials, load_trust_roots)
from tests.test_pki import issue, der


def spki(key):
    return key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


class CredentialProfileTests(unittest.TestCase):
    def setUp(self):
        self.now = datetime.now(timezone.utc)
        self.ca_key = ec.generate_private_key(ec.SECP256R1())
        self.ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Profile CA")])
        self.name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Profile peer")])
        self.root = issue(self.ca_key, self.ca_key, self.ca_name, self.ca_name, ca=True)
        self.key = x25519.X25519PrivateKey.generate()
        self.leaf = issue(self.key, self.ca_key, self.name, self.ca_name)
        self.policy = CredentialPolicy(trust_roots=(self.root,), peer_name="example.test", now=self.now)

    def test_pkix_provider_accepts_noncritical_basic_constraints(self):
        leaf = issue(self.key, self.ca_key, self.name, self.ca_name, bc_critical=False)
        result = resolve_peer([der(leaf)], policy=self.policy)
        self.assertEqual(result.provenance, "x509")
        self.assertEqual(result.public_key.public_bytes_raw(), self.key.public_key().public_bytes_raw())

    def test_rsa_pkcs1_and_pss_certificate_paths(self):
        ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        root = issue(ca_key, ca_key, self.ca_name, self.ca_name, ca=True, algorithm=hashes.SHA256())
        leaf = issue(self.key, ca_key, self.name, self.ca_name, algorithm=hashes.SHA256())
        policy = replace(self.policy, trust_roots=(root,))
        result = resolve_peer([der(leaf)], policy=policy, certificate_algorithms=(0x0401,))
        self.assertEqual(result.public_key.public_bytes_raw(), self.key.public_key().public_bytes_raw())
        with self.assertRaises(ProtocolError):
            resolve_peer([der(leaf)], policy=policy, certificate_algorithms=(0x0403,))
        builder = (x509.CertificateBuilder().subject_name(self.name).issuer_name(self.ca_name)
                   .serial_number(123).public_key(self.key.public_key())
                   .not_valid_before(self.now - timedelta(minutes=1)).not_valid_after(self.now + timedelta(hours=1))
                   .add_extension(x509.SubjectAlternativeName([x509.DNSName("example.test")]), False))
        leaf = builder.sign(ca_key, hashes.SHA256(),
            rsa_padding=padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32))
        self.assertEqual(certificate_signature_scheme(leaf, root), 0x0804)
        resolve_peer([der(leaf)], policy=policy, certificate_algorithms=(0x0804,))

    def test_identity_expiration_and_untrusted_root_fail(self):
        for policy in (replace(self.policy, peer_name="wrong.test"), replace(self.policy, trust_roots=()),
                       replace(self.policy, now=self.now + timedelta(days=2))):
            with self.subTest(policy=policy), self.assertRaises(ProtocolError):
                resolve_peer([der(self.leaf)], policy=policy)
        corrupted = bytearray(der(self.leaf)); corrupted[-1] ^= 1
        with self.assertRaises(ProtocolError):
            resolve_peer([bytes(corrupted)], policy=self.policy)

    def test_provider_enforces_intermediate_name_constraints(self):
        inter_key = ec.generate_private_key(ec.SECP256R1())
        inter_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Constrained CA")])
        inter = issue(inter_key, self.ca_key, inter_name, self.ca_name, ca=True,
                      extra=[(x509.NameConstraints([x509.DNSName("allowed.test")], None), True)])
        leaf = issue(self.key, inter_key, self.name, inter_name)
        with self.assertRaises(ProtocolError):
            resolve_peer([der(leaf), der(inter)], policy=self.policy)
        allowed = issue(self.key, inter_key, self.name, inter_name, hostname="www.allowed.test")
        resolve_peer([der(allowed), der(inter)], policy=replace(self.policy, peer_name="www.allowed.test"))

    def test_local_loader_accepts_rsa_and_checks_partial_chain_constraints(self):
        root_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        root = issue(root_key, root_key, self.ca_name, self.ca_name, ca=True, algorithm=hashes.SHA256())
        inter_key = ec.generate_private_key(ec.SECP384R1())
        inter_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Local constrained issuer")])
        inter = issue(inter_key, root_key, inter_name, self.ca_name, ca=True, algorithm=hashes.SHA256(),
            extra=[(x509.NameConstraints([x509.DNSName("allowed.test")], None), True)])
        leaf = issue(self.key, inter_key, self.name, inter_name, hostname="www.allowed.test", algorithm=hashes.SHA384())
        bad = issue(self.key, inter_key, self.name, inter_name, hostname="www.outside.test", algorithm=hashes.SHA384())
        with tempfile.TemporaryDirectory() as directory:
            chain_path, key_path = Path(directory) / 'chain.pem', Path(directory) / 'key.pem'
            key_path.write_bytes(self.key.private_bytes(serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
            key_path.chmod(0o600)
            for chain in ((leaf, inter, root), (leaf, inter)):
                chain_path.write_bytes(b''.join(cert.public_bytes(serialization.Encoding.PEM) for cert in chain))
                loaded = load_credentials(chain_path, key_path, 'www.allowed.test')
                self.assertEqual(tuple(loaded.chain_der), tuple(der(cert) for cert in chain))
                # Loading an own bundle does not add its issuer to remote trust.
                with self.assertRaises(ProtocolError):
                    validate_identity(loaded.chain_der, trust_roots=(), role='server', name='www.allowed.test')
            chain_path.write_bytes(b''.join(cert.public_bytes(serialization.Encoding.PEM) for cert in (bad, inter)))
            with self.assertRaises(ConfigurationError):
                load_credentials(chain_path, key_path, 'www.outside.test')

    def test_explicit_general_root_loading_preserves_lab_default(self):
        ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        root = issue(ca_key, ca_key, self.ca_name, self.ca_name, ca=True, algorithm=hashes.SHA256())
        leaf = issue(self.key, ca_key, self.name, self.ca_name, algorithm=hashes.SHA256())
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'anchors.pem'
            path.write_bytes(root.public_bytes(serialization.Encoding.PEM))
            with self.assertRaises(ConfigurationError):
                load_trust_roots(path)
            anchors = load_trust_roots(path, general_pkix=True)
            validate_identity([der(leaf)], trust_roots=anchors, role='server', name='example.test')
            path.write_bytes(leaf.public_bytes(serialization.Encoding.PEM))
            with self.assertRaises(ConfigurationError):
                load_trust_roots(path, general_pkix=True)

    def test_client_path_needs_client_eku_and_application_authorization(self):
        client = issue(self.key, self.ca_key, self.name, self.ca_name, eku=False,
                       extra=[(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), False)])
        with self.assertRaises(ProtocolError):
            resolve_peer([der(client)], role="client", policy=self.policy)
        approved = replace(self.policy, authorize_client=lambda material, evidence: material == (der(client),))
        self.assertEqual(resolve_peer([der(client)], role="client", policy=approved).provenance, "x509")
        with self.assertRaises(ProtocolError):
            resolve_peer([der(self.leaf)], role="client", policy=approved)

    def test_rpk_binding_is_exact_and_role_service_scoped(self):
        public = spki(self.key)
        policy = replace(self.policy, raw_public_keys=(RawPublicKeyBinding("server", "example.test", public),))
        result = resolve_peer([public], 2, policy=policy)
        self.assertEqual(result.provenance, "provisioned-rpk")
        for candidate in (self.policy, replace(policy, peer_name="other.test")):
            with self.assertRaises(ProtocolError):
                resolve_peer([public], 2, policy=candidate)
        with self.assertRaises(ProtocolError):
            resolve_peer([public], 2, role="client", policy=policy)
        for invalid in (public + b"\0", public[:-1], public[:12] + bytes(32)):
            with self.subTest(length=len(invalid)), self.assertRaises(ProtocolError):
                parse_x25519_spki(invalid)

    def parent_and_grant(self, *, role="server", valid_time=3900, delegation=True, scheme=0x0807):
        parent_key = ed25519.Ed25519PrivateKey.generate()
        usage = x509.KeyUsage(True, False, False, False, False, False, False, False, False)
        extras = [(x509.UnrecognizedExtension(DELEGATION_USAGE, b"\x05\x00"), False)] if delegation else []
        if role == "client":
            extras.append((x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), False))
        parent = issue(parent_key, self.ca_key, self.name, self.ca_name, key_usage=usage,
                       eku=role != "client", extra=extras)
        public = spki(self.key)
        body = valid_time.to_bytes(4, "big") + (b"\xfe\x00" if role == "server" else b"\xfe\x01")
        body += len(public).to_bytes(3, "big") + public + scheme.to_bytes(2, "big")
        message = b" " * 64 + f"TLS20 {role} delegated credentials".encode() + b"\x00" + der(parent) + body
        signature = parent_key.sign(message)
        return parent, body + len(signature).to_bytes(2, "big") + signature

    def delegated(self, parent, grant, **kwargs):
        return resolve_peer([der(parent)], policy=self.policy,
            certificate_algorithms=(0x0403,), grant_algorithms=(0x0807,), delegated_schemes=(0xfe00,),
            entry_extensions=(((34, grant),),), **kwargs)

    def test_delegation_uses_disjoint_certificate_and_grant_algorithms(self):
        parent, grant = self.parent_and_grant()
        result = self.delegated(parent, grant)
        self.assertEqual(result.provenance, "x509-delegated")
        self.assertEqual(result.public_key.public_bytes_raw(), self.key.public_key().public_bytes_raw())

    def test_delegation_does_not_fallback_after_wrong_role_signature_or_offer(self):
        parent, grant = self.parent_and_grant()
        for invalid in (grant[:-1], grant + b"\0", grant[:-1] + bytes((grant[-1] ^ 1,)),
                        grant[:4] + b"\xfe\x01" + grant[6:]):
            with self.subTest(grant=invalid[:6]), self.assertRaises(ProtocolError):
                self.delegated(parent, invalid)
        with self.assertRaises(ProtocolError):
            resolve_peer([der(parent)], policy=self.policy, certificate_algorithms=(0x0403,),
                grant_algorithms=(0x0403,), delegated_schemes=(0xfe00,), entry_extensions=(((34, grant),),))
        with self.assertRaises(ProtocolError):
            resolve_peer([der(parent)], policy=self.policy, entry_extensions=(((34, grant),),))

    def test_delegation_authorization_lifetime_and_required_policy(self):
        for values in (dict(delegation=False), dict(valid_time=1), dict(valid_time=172800)):
            parent, grant = self.parent_and_grant(**values)
            with self.subTest(values=values), self.assertRaises(ProtocolError):
                self.delegated(parent, grant)
        with self.assertRaises(ProtocolError):
            resolve_peer([der(self.leaf)], policy=replace(self.policy, require_delegation=True))

    def test_client_delegation_is_independently_authorized(self):
        parent, grant = self.parent_and_grant(role="client")
        policy = replace(self.policy, authorize_client=lambda material, evidence: True)
        result = resolve_peer([der(parent)], role="client", policy=policy,
            certificate_algorithms=(0x0403,), grant_algorithms=(0x0807,), delegated_schemes=(0xfe01,),
            entry_extensions=(((34, grant),),))
        self.assertEqual(result.provenance, "x509-delegated")
        with self.assertRaises(ProtocolError):
            self.delegated(parent, grant)

    def test_evidence_is_current_and_not_accepted_by_decoding(self):
        evidence = (((18, b"not a CT proof"),),)
        with self.assertRaises(ProtocolError):
            resolve_peer([der(self.leaf)], policy=self.policy, entry_extensions=evidence)
        missing = replace(self.policy, revocation_policy="require-evidence")
        with self.assertRaises(ProtocolError):
            resolve_peer([der(self.leaf)], policy=missing)
        denied = replace(missing, evidence_validator=lambda path, role, evidence, now: False)
        with self.assertRaises(ProtocolError):
            resolve_peer([der(self.leaf)], policy=denied, entry_extensions=evidence, offered_extensions=(18,))

    def make_ocsp(self, *, status=ocsp.OCSPCertStatus.GOOD, next_update=True, nonce=None):
        builder = (ocsp.OCSPResponseBuilder().add_response(cert=self.leaf, issuer=self.root,
            algorithm=hashes.SHA256(), cert_status=status, this_update=self.now - timedelta(minutes=1),
            next_update=self.now + timedelta(hours=1) if next_update else None,
            revocation_time=self.now - timedelta(hours=1) if status == ocsp.OCSPCertStatus.REVOKED else None,
            revocation_reason=None).responder_id(ocsp.OCSPResponderEncoding.HASH, self.root))
        if nonce is not None:
            builder = builder.add_extension(x509.OCSPNonce(nonce), False)
        return builder.sign(self.ca_key, hashes.SHA256()).public_bytes(serialization.Encoding.DER)

    def test_ocsp_real_signature_binding_status_freshness_and_nonce(self):
        response = self.make_ocsp(nonce=b"test request nonce")
        self.assertTrue(validate_ocsp_response(response, self.leaf, self.root, expected_nonce=b"test request nonce"))
        with self.assertRaises(ProtocolError):
            validate_ocsp_response(response, self.leaf, self.root, expected_nonce=b"different nonce")
        other = issue(self.key, self.ca_key, self.name, self.ca_name)
        with self.assertRaises(ProtocolError):
            validate_ocsp_response(response, other, self.root)
        with self.assertRaises(ProtocolError):
            validate_ocsp_response(response, self.leaf, self.root, now=self.now + timedelta(days=2))
        for status in (ocsp.OCSPCertStatus.REVOKED, ocsp.OCSPCertStatus.UNKNOWN):
            with self.subTest(status=status), self.assertRaises(ProtocolError):
                validate_ocsp_response(self.make_ocsp(status=status), self.leaf, self.root)
        corrupted = bytearray(response); corrupted[-1] ^= 1
        with self.assertRaises(ProtocolError):
            validate_ocsp_response(bytes(corrupted), self.leaf, self.root)

    def test_evidence_adapter_requires_current_ocsp_and_honors_nonce(self):
        from tls20_server.credential_evidence import CredentialEvidencePolicy
        response = self.make_ocsp(nonce=b'nonce')
        wire = b'\x01' + len(response).to_bytes(3, 'big') + response
        validator = CredentialEvidencePolicy(require_ocsp=True, expected_ocsp_nonce=b'nonce')
        policy = replace(self.policy, revocation_policy='require-evidence', evidence_validator=validator)
        result = resolve_peer([der(self.leaf)], policy=policy,
                             entry_extensions=(((5, wire),),), offered_extensions=(5,))
        self.assertEqual(result.provenance, 'x509')
        for evidence in ((), (((5, wire[:-1]),),)):
            with self.assertRaises(ProtocolError):
                resolve_peer([der(self.leaf)], policy=policy, entry_extensions=evidence, offered_extensions=(5,))

    def test_signed_ocsp_single_response_cannot_hide_unknown_critical_extension(self):
        from tls20_server.pki import _children, _element

        def tlv(tag, body):
            length = len(body)
            encoded = bytes((length,)) if length < 128 else (
                bytes((128 + (length.bit_length() + 7) // 8,))
                + length.to_bytes((length.bit_length() + 7) // 8, 'big'))
            return bytes((tag,)) + encoded + body

        # Change only the signed SingleResponse, then sign it with the actual
        # authorized responder. Failure must be policy, not a broken signature.
        original = ocsp.load_der_ocsp_response(self.make_ocsp())
        tbs = _children(_element(original.tbs_response_bytes)[1])
        responses = _children(tbs[2][1])
        for critical in (False, True):
            unknown = tlv(0x30, bytes.fromhex('06032a0304')
                + (bytes.fromhex('0101ff') if critical else b'') + tlv(0x04, b'opaque'))
            entry = tlv(0x30, responses[0][1] + tlv(0xa1, tlv(0x30, unknown)))
            changed = tlv(0x30, b''.join(x[2] if index != 2 else tlv(0x30, entry)
                                        for index, x in enumerate(tbs)))
            signature = self.ca_key.sign(changed, ec.ECDSA(hashes.SHA256()))
            basic = tlv(0x30, changed + bytes.fromhex('300a06082a8648ce3d040302')
                        + tlv(0x03, b'\x00' + signature))
            response = tlv(0x30, bytes.fromhex('0a0100') + tlv(0xa0, tlv(0x30,
                bytes.fromhex('06092b0601050507300101') + tlv(0x04, basic))))
            with self.subTest(critical=critical):
                if critical:
                    with self.assertRaisesRegex(ProtocolError, 'critical OCSP single'):
                        validate_ocsp_response(response, self.leaf, self.root)
                else:
                    self.assertTrue(validate_ocsp_response(response, self.leaf, self.root))

    def test_pss_certificate_parameters_cannot_masquerade_as_tls_scheme(self):
        ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        builder = (x509.CertificateBuilder().subject_name(self.name).issuer_name(self.ca_name)
                   .serial_number(123).public_key(self.key.public_key())
                   .not_valid_before(self.now - timedelta(minutes=1)).not_valid_after(self.now + timedelta(hours=1)))
        for params in (padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=0),
                       padding.PSS(mgf=padding.MGF1(hashes.SHA384()), salt_length=32)):
            certificate = builder.sign(ca_key, hashes.SHA256(), rsa_padding=params)
            with self.assertRaises(ProtocolError):
                certificate_signature_scheme(certificate)

    def test_tls_feature_only_constrains_features_offered_by_client(self):
        from tls20_server.credential_evidence import CredentialEvidencePolicy
        for features in ([x509.TLSFeatureType.status_request],
                         [x509.TLSFeatureType.status_request_v2]):
            leaf = issue(self.key, self.ca_key, self.name, self.ca_name,
                         extra=[(x509.TLSFeature(features), False)])
            self.assertTrue(CredentialEvidencePolicy()([leaf, self.root], "server", (), self.now))
            if x509.TLSFeatureType.status_request in features:
                with self.assertRaises(ProtocolError):
                    CredentialEvidencePolicy(offered_extensions=(5,))([leaf, self.root], "server", (), self.now)


if __name__ == "__main__":
    unittest.main()
