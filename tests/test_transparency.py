from datetime import datetime, timezone
import hashlib
import unittest
from unittest.mock import patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, x25519
from cryptography.x509.oid import NameOID

from tls20_server.errors import ProtocolError
from tls20_server.transparency import (TrustedLog, embedded_transparency,
    precertificate_tbs, validate_ct_v2_list, validate_sct_v1_list, verify_inclusion, verify_consistency)
from tls20_server.credential_evidence import CredentialEvidencePolicy
from tests.test_pki import issue, der


def vec(data, width=2):
    return len(data).to_bytes(width, 'big') + data


def listed(*items):
    return vec(b''.join(vec(item) for item in items))


class TransparencyTests(unittest.TestCase):
    def setUp(self):
        self.now = int(datetime.now(timezone.utc).timestamp() * 1000)
        self.ca_key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'CT CA')])
        self.root = issue(self.ca_key, self.ca_key, name, name, ca=True)
        self.cert = issue(x25519.X25519PrivateKey.generate(), self.ca_key, name, name)
        self.log_key = ec.generate_private_key(ec.SECP256R1())
        spki = self.log_key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        self.log_v1 = TrustedLog(hashlib.sha256(spki).digest(), self.log_key.public_key())
        self.log_v2 = TrustedLog(bytes.fromhex('2b06010401'), self.log_key.public_key())

    def v1(self, precert=False):
        if precert:
            issuer = self.ca_key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
            entry = b'\x00\x01' + hashlib.sha256(issuer).digest() + vec(precertificate_tbs(self.cert, version=1), 3)
        else:
            entry = b'\x00\x00' + vec(der(self.cert), 3)
        signed = b'\x00\x00' + self.now.to_bytes(8, 'big') + entry + b'\x00\x00'
        signature = self.log_key.sign(signed, ec.ECDSA(hashes.SHA256()))
        return b'\x00' + self.log_v1.log_id + self.now.to_bytes(8, 'big') + b'\x00\x00\x04\x03' + vec(signature)

    def v2(self, *, precert=False, extensions=b''):
        issuer = self.ca_key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        tbs = precertificate_tbs(self.cert, version=2) if precert else self.cert.tbs_certificate_bytes
        signed = (b'\x01\x01' if precert else b'\x01\x00') + self.now.to_bytes(8, 'big')
        signed += vec(hashlib.sha256(issuer).digest(), 1) + vec(tbs, 3) + vec(extensions)
        signature = self.log_key.sign(signed, ec.ECDSA(hashes.SHA256()))
        sct = (b'\x01\x03' if precert else b'\x01\x02') + vec(self.log_v2.log_id, 1)
        sct += self.now.to_bytes(8, 'big') + vec(extensions) + vec(signature)
        return sct, hashlib.sha256(b'\x00' + signed).digest()

    def test_v1_real_log_signature_and_precertificate_binding(self):
        for precert in (False, True):
            evidence = listed(self.v1(precert))
            result = validate_sct_v1_list(evidence, der(self.cert), {self.log_v1.log_id:self.log_v1},
                issuer_der=der(self.root), precertificate=precert, now_ms=self.now)
            self.assertEqual(len(result), 1)
            self.assertFalse(result[0].included)
            corrupted = evidence[:-1] + bytes((evidence[-1] ^ 1,))
            with self.assertRaises(ProtocolError):
                validate_sct_v1_list(corrupted, der(self.cert), {self.log_v1.log_id:self.log_v1},
                    issuer_der=der(self.root), precertificate=precert, now_ms=self.now)

    def test_unknown_logs_do_not_vote_and_future_timestamps_fail(self):
        evidence = listed(self.v1())
        self.assertEqual(validate_sct_v1_list(evidence, der(self.cert), {}, now_ms=self.now), ())
        with self.assertRaises(ProtocolError):
            validate_sct_v1_list(evidence, der(self.cert), {self.log_v1.log_id:self.log_v1}, now_ms=self.now - 1)

    def test_v2_sct_precertificate_and_distinct_wire_format(self):
        for precert in (False, True):
            sct, leaf = self.v2(precert=precert)
            result = validate_ct_v2_list(listed(sct), der(self.cert), der(self.root),
                {self.log_v2.log_id:self.log_v2}, now_ms=self.now)
            self.assertEqual(result[0].leaf_hash, leaf)
            with self.assertRaises(ProtocolError):
                validate_ct_v2_list(listed(sct), der(self.cert), der(self.root),
                    {self.log_v2.log_id:self.log_v2}, now_ms=self.now, require_inclusion=True)
        with self.assertRaises(ProtocolError):
            validate_ct_v2_list(listed(self.v1()), der(self.cert), der(self.root),
                {self.log_v2.log_id:self.log_v2}, now_ms=self.now)

    def test_v2_signed_tree_head_and_inclusion_proof(self):
        sct, leaf = self.v2()
        head_data = self.now.to_bytes(8, 'big') + (1).to_bytes(8, 'big') + vec(leaf, 1) + b'\x00\x00'
        signature = self.log_key.sign(head_data, ec.ECDSA(hashes.SHA256()))
        head = b'\x01\x04' + vec(self.log_v2.log_id, 1) + head_data + vec(signature)
        proof = b'\x01\x06' + vec(self.log_v2.log_id, 1) + (1).to_bytes(8, 'big') + bytes(8) + b'\x00\x00'
        result = validate_ct_v2_list(listed(proof, head, sct), der(self.cert), der(self.root),
                {self.log_v2.log_id:self.log_v2}, now_ms=self.now, require_inclusion=True)
        self.assertTrue(result[0].included)
        corrupted = head[:-1] + bytes((head[-1] ^ 1,))
        with self.assertRaises(ProtocolError):
            validate_ct_v2_list(listed(proof, corrupted, sct), der(self.cert), der(self.root),
                {self.log_v2.log_id:self.log_v2}, now_ms=self.now, require_inclusion=True)

    def test_v2_extensions_order_and_duplicate_enforced(self):
        for extensions in (b'\x00\x01\x00\x00' * 2,
                           b'\x00\x02\x00\x00\x00\x01\x00\x00'):
            sct, _ = self.v2(extensions=extensions)
            with self.assertRaises(ProtocolError):
                validate_ct_v2_list(listed(sct), der(self.cert), der(self.root),
                    {self.log_v2.log_id:self.log_v2}, now_ms=self.now)

    def test_inclusion_three_leaf_unbalanced_tree_and_extra_node_rejected(self):
        nodes = [hashlib.sha256(b'\x00' + bytes((i,))).digest() for i in range(3)]
        left = hashlib.sha256(b'\x01' + nodes[0] + nodes[1]).digest()
        root = hashlib.sha256(b'\x01' + left + nodes[2]).digest()
        for index, proof in ((0, (nodes[1],nodes[2])), (1,(nodes[0],nodes[2])), (2,(left,))):
            self.assertTrue(verify_inclusion(nodes[index], index, 3, proof, root))
            with self.assertRaises(ProtocolError):
                verify_inclusion(nodes[index], index, 3, proof + (nodes[0],), root)

    def test_consistency_against_previously_trusted_tree(self):
        nodes = [hashlib.sha256(b'\x00' + bytes((i,))).digest() for i in range(3)]
        left = hashlib.sha256(b'\x01' + nodes[0] + nodes[1]).digest()
        root = hashlib.sha256(b'\x01' + left + nodes[2]).digest()
        self.assertTrue(verify_consistency(1, 3, nodes[0], root, (nodes[1], nodes[2])))
        self.assertTrue(verify_consistency(2, 3, left, root, (nodes[2],)))
        self.assertTrue(verify_consistency(3, 3, root, root, ()))
        for proof in ((), (nodes[0],), (nodes[2],nodes[0])):
            with self.assertRaises(ProtocolError):
                verify_consistency(2, 3, left, root, proof)

    def test_ct_policy_counts_real_distinct_log_votes_and_required_offer(self):
        moment = datetime.fromtimestamp(self.now / 1000, timezone.utc)
        sct, _ = self.v2()
        evidence = (((52, listed(sct, sct)),),)
        policy = CredentialEvidencePolicy(trusted_logs_v2={self.log_v2.log_id:self.log_v2},
                                         minimum_ct_v2_logs=1, offered_extensions=(5,52))
        self.assertTrue(policy((self.cert,self.root), 'server', evidence, moment))
        from dataclasses import replace
        with self.assertRaises(ProtocolError):
            replace(policy, minimum_ct_v2_logs=2)((self.cert,self.root), 'server', evidence, moment)
        with self.assertRaises(ProtocolError):
            replace(policy, offered_extensions=(52,))((self.cert,self.root), 'server', evidence, moment)
        with self.assertRaises(ProtocolError):
            policy((self.cert,self.root), 'client', evidence, moment)

    def test_required_tls_evidence_cannot_borrow_other_source_log_vote(self):
        # Source extraction is substituted to isolate provenance; every SCT
        # below still has a real log signature checked against the exact cert.
        moment = datetime.fromtimestamp(self.now / 1000, timezone.utc)
        for feature in (18,52):
            self.cert = issue(x25519.X25519PrivateKey.generate(),self.ca_key,
                self.root.subject,self.root.subject,extra=[(x509.UnrecognizedExtension(
                    x509.ObjectIdentifier('1.3.6.1.5.5.7.1.24'),
                    b'\x30\x03\x02\x01'+bytes((feature,))),False)])
            good = listed(self.v1(True) if feature == 18 else self.v2(precert=True)[0])
            policy = CredentialEvidencePolicy(
                trusted_logs_v1={self.log_v1.log_id:self.log_v1},
                trusted_logs_v2={self.log_v2.log_id:self.log_v2},
                offered_extensions=(5,feature))
            with patch('tls20_server.credential_evidence.embedded_transparency',return_value={feature:good}):
                with self.subTest(feature=feature), self.assertRaises(ProtocolError):
                    policy((self.cert,self.root),'server',(((feature,b'\0\0'),),),moment)
                self.assertTrue(policy((self.cert,self.root),'server',(((feature,good),),),moment))

    def test_empty_ct_v2_response_is_not_an_empty_embedded_list_or_log_vote(self):
        moment = datetime.fromtimestamp(self.now / 1000, timezone.utc)
        policy = CredentialEvidencePolicy(trusted_logs_v2={self.log_v2.log_id:self.log_v2},
                                          offered_extensions=(5,52))
        # RFC9162 section6.5 permits an empty TLS response, not an encoded
        # TransItemList nor the OCTET STRING list carrier of section7.1.
        self.assertTrue(policy((self.cert,self.root), 'server', (((52,b''),),), moment))
        with patch('tls20_server.credential_evidence.embedded_transparency', return_value={52:b''}):
            with self.assertRaises(ProtocolError):
                policy((self.cert,self.root), 'server', (), moment)
        from dataclasses import replace
        with self.assertRaises(ProtocolError):
            replace(policy, minimum_ct_v2_logs=1)((self.cert,self.root), 'server', (((52,b''),),), moment)
        self.cert = issue(x25519.X25519PrivateKey.generate(), self.ca_key,
            self.root.subject, self.root.subject, extra=[(x509.UnrecognizedExtension(
                x509.ObjectIdentifier('1.3.6.1.5.5.7.1.24'), b'\x30\x03\x02\x01\x34'), False)])
        with self.assertRaisesRegex(ProtocolError, 'no verified log evidence'):
            policy((self.cert,self.root), 'server', (((52,b''),),), moment)


if __name__ == '__main__':
    unittest.main()
