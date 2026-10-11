import base64
import hashlib
import io
import time
import unittest
from datetime import datetime, timedelta, timezone

import dns.dnssec
import dns.name
import dns.rdata
import dns.rrset
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, x25519
from cryptography.x509 import ocsp
from cryptography.x509.oid import NameOID

from tls20_server.dnssec_credentials import (DNSSECChain, DNSSECLimits,
    DANEPolicy, DNSSECWireEvidence, match_tlsa, parse_authentication_chain)
from tls20_server.credential_profiles import CredentialPolicy, resolve_peer
from tls20_server.errors import ProtocolError


class DNSSECCredentialTests(unittest.TestCase):
    def setUp(self):
        self.now = int(time.time())
        self.root = dns.name.from_text('.')
        self.zone = dns.name.from_text('example.test.')
        self.root_key = ed25519.Ed25519PrivateKey.generate()
        self.zone_key = ed25519.Ed25519PrivateKey.generate()
        self.root_dnskey = dns.dnssec.make_dnskey(self.root_key.public_key(), 'ED25519', flags=257)
        self.zone_dnskey = dns.dnssec.make_dnskey(self.zone_key.public_key(), 'ED25519', flags=257)
        self.root_keys = dns.rrset.from_rdata(self.root, 300, self.root_dnskey)
        self.zone_keys = dns.rrset.from_rdata(self.zone, 300, self.zone_dnskey)
        self.ds = dns.rrset.from_rdata(self.zone, 300, dns.dnssec.make_ds(self.zone, self.zone_dnskey, 'SHA256'))
        self.key = x25519.X25519PrivateKey.generate()
        self.spki = self.key.public_key().public_bytes(serialization.Encoding.DER,
                                                  serialization.PublicFormat.SubjectPublicKeyInfo)
        self.owner = '_343._tcp.example.test.'

    def sign(self, rrset, *, root=False, expired=False):
        key, dnskey, signer = ((self.root_key, self.root_dnskey, self.root) if root else
                              (self.zone_key, self.zone_dnskey, self.zone))
        signature = dns.dnssec.sign(rrset, key, signer, dnskey,
                    inception=self.now - 3600, expiration=self.now - 1 if expired else self.now + 3600)
        return rrset, dns.rrset.from_rdata(rrset.name, rrset.ttl, signature)

    def chain(self, *records):
        out = io.BytesIO()
        for record in (*self.sign(self.root_keys, root=True), *self.sign(self.ds, root=True),
                       *self.sign(self.zone_keys), *records):
            record.to_wire(out, compress=None)
        return out.getvalue()

    def validate(self, wire, *, port=343, anchors=None, limits=DNSSECLimits()):
        return DNSSECChain(wire, trust_anchors=anchors or {'.': self.root_keys},
                           now=self.now, limits=limits).validate_service('example.test', port)

    def tlsa(self, owner=None):
        return dns.rrset.from_text(owner or self.owner, 300, 'IN', 'TLSA',
                                  '3 1 1 ' + hashlib.sha256(self.spki).hexdigest())

    def test_real_ds_dnskey_rrsig_tlsa_chain_and_rpk_match(self):
        wire = self.chain(*self.sign(self.tlsa()))
        result = self.validate(wire)
        self.assertFalse(result.authenticated_denial)
        self.assertEqual(result.port, 343)
        self.assertTrue(match_tlsa(result, (self.spki,), credential_type=2, now=self.now))
        with self.assertRaises(ProtocolError):
            match_tlsa(result, (self.spki[:-1] + b'x',), credential_type=2, now=self.now)
        with self.assertRaises(ProtocolError):
            match_tlsa(result, (self.spki,), credential_type=2, now=self.now + 4000)
        with self.assertRaises(ProtocolError):
            self.validate(wire, port=443)

    def test_ds_anchor_and_direct_zone_key_anchor(self):
        wire = self.chain(*self.sign(self.tlsa()))
        for anchors in ({'example.test.': self.ds}, {'example.test.': self.zone_keys}):
            self.assertTrue(match_tlsa(self.validate(wire, anchors=anchors), (self.spki,),
                                      credential_type=2, now=self.now))

    def test_real_dane_policy_resolves_rpk_without_implicit_pin_or_ca(self):
        from datetime import datetime, timezone
        policy = CredentialPolicy(peer_name='example.test', now=datetime.fromtimestamp(self.now, timezone.utc),
            dane_policy=DANEPolicy(trust_anchors={'.': self.root_keys}))
        wire = self.chain(*self.sign(self.tlsa()))
        resolved = resolve_peer((self.spki,), 2, policy=policy,
            entry_extensions=(((59, DNSSECWireEvidence(24, wire).encode()),),), offered_extensions=(59,))
        self.assertEqual(resolved.provenance, 'dane-rpk')
        self.assertEqual(resolved.public_key.public_bytes_raw(), self.spki[12:])
        with self.assertRaises(ProtocolError):
            resolve_peer((self.spki,), 2, policy=policy)

    def test_dane_ee_cannot_forge_ocsp_by_appending_an_unrelated_issuer(self):
        from tls20_server.credential_evidence import CredentialEvidencePolicy
        from tests.test_pki import issue, der
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "DANE actual issuer")])
        peer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "DANE leaf")])
        actual_key = ec.generate_private_key(ec.SECP256R1())
        fake_key = ec.generate_private_key(ec.SECP256R1())
        actual = issue(actual_key, actual_key, name, name, ca=True)
        fake = issue(fake_key, fake_key, name, name, ca=True)
        leaf = issue(self.key, actual_key, peer, name)
        # Authenticate the exact leaf through a real signed DNSSEC chain. No
        # Web-PKI roots are configured, as permitted for DANE-EE usage 3.
        tlsa = dns.rrset.from_text(self.owner, 300, 'IN', 'TLSA', '3 0 1 ' + hashlib.sha256(der(leaf)).hexdigest())
        proof = DNSSECWireEvidence(24, self.chain(*self.sign(tlsa))).encode()
        moment = datetime.now(timezone.utc)
        def staple(issuer, key):
            response = ocsp.OCSPResponseBuilder().add_response(cert=leaf, issuer=issuer,
                algorithm=hashes.SHA256(), cert_status=ocsp.OCSPCertStatus.GOOD,
                this_update=moment-timedelta(seconds=60), next_update=moment+timedelta(hours=1),
                revocation_time=None, revocation_reason=None).responder_id(
                ocsp.OCSPResponderEncoding.HASH, issuer).sign(key, hashes.SHA256())
            wire=response.public_bytes(serialization.Encoding.DER)
            return b'\x01'+len(wire).to_bytes(3,'big')+wire
        policy = CredentialPolicy(peer_name='example.test', dane_policy=DANEPolicy({'.':self.root_keys}),
            revocation_policy='require-evidence', evidence_validator=CredentialEvidencePolicy(require_ocsp=True))
        valid=resolve_peer((der(leaf),der(actual)),policy=policy,offered_extensions=(59,5),
            entry_extensions=(((59,proof),(5,staple(actual,actual_key))),()))
        self.assertEqual(valid.provenance,'dane-x509')
        with self.assertRaises(ProtocolError):
            resolve_peer((der(leaf),der(fake)),policy=policy,offered_extensions=(59,5),
                entry_extensions=(((59,proof),(5,staple(fake,fake_key))),()))

    def test_extension_envelope_is_distinct_from_bare_rr_chain(self):
        wire = self.chain(*self.sign(self.tlsa()))
        for lifetime in (0, 1, 65535):
            envelope = DNSSECWireEvidence(lifetime, wire)
            encoded = envelope.encode()
            self.assertEqual(encoded[:4], lifetime.to_bytes(2, 'big') + len(wire).to_bytes(2, 'big'))
            self.assertEqual(DNSSECWireEvidence.parse(encoded), envelope)
        for value in (b'', b'\0\0\0\0', wire, b'\0\0' + wire,
                      DNSSECWireEvidence(1, wire).encode()[:-1],
                      DNSSECWireEvidence(1, wire).encode() + b'\0'):
            with self.assertRaises(ProtocolError):
                DNSSECWireEvidence.parse(value)
        for lifetime, chain in ((-1, wire), (65536, wire), (True, wire), (0, b''), (0, bytes(65532))):
            with self.assertRaises(ProtocolError):
                DNSSECWireEvidence(lifetime, chain).encode()
        # A promise cannot authenticate unsigned or expired DNS data.
        invalid = self.chain(*self.sign(self.tlsa(), expired=True))
        envelope = DNSSECWireEvidence(65535, invalid).encode()
        with self.assertRaises(ProtocolError):
            DANEPolicy({'.': self.root_keys}).authorize((self.spki,), 2,
                'example.test', (((59, envelope),),))

    def test_untrusted_key_tamper_expired_and_work_budget_fail(self):
        wire = self.chain(*self.sign(self.tlsa()))
        badkey = dns.dnssec.make_dnskey(ed25519.Ed25519PrivateKey.generate().public_key(), 'ED25519', flags=257)
        fake_anchor = dns.rrset.from_rdata(self.root, 300, badkey)
        with self.assertRaises(ProtocolError):
            self.validate(wire, anchors={'.': fake_anchor})
        with self.assertRaises(ProtocolError):
            self.validate(wire[:-1] + bytes((wire[-1] ^ 1,)))
        with self.assertRaises(ProtocolError):
            self.validate(self.chain(*self.sign(self.tlsa(), expired=True)))
        with self.assertRaises(ProtocolError):
            self.validate(wire, limits=DNSSECLimits(max_validations=1))

    def test_signed_cname_and_dname_redirect_require_each_signature(self):
        target = '_343._tcp.target.example.test.'
        cname = dns.rrset.from_text(self.owner, 300, 'IN', 'CNAME', target)
        result = self.validate(self.chain(*self.sign(cname), *self.sign(self.tlsa(target))))
        self.assertEqual(result.owner, target)
        with self.assertRaises(ProtocolError):
            self.validate(self.chain(cname, *self.sign(self.tlsa(target))))
        dname = dns.rrset.from_text('_tcp.example.test.', 300, 'IN', 'DNAME', '_tcp.target.example.test.')
        self.assertEqual(self.validate(self.chain(*self.sign(dname), *self.sign(self.tlsa(target)))).owner, target)

    def test_nsec_nodata_and_insecure_delegation_are_not_positive_authorization(self):
        for owner, text in ((self.owner, 'z.example.test. A RRSIG NSEC'),
                            ('example.test.', 'z.example.test. NS RRSIG NSEC')):
            nsec = dns.rrset.from_text(owner, 300, 'IN', 'NSEC', text)
            result = self.validate(self.chain(*self.sign(nsec)))
            self.assertTrue(result.authenticated_denial)
            self.assertFalse(match_tlsa(result, (self.spki,), credential_type=2, now=self.now))
        nsec = dns.rrset.from_text(self.owner, 300, 'IN', 'NSEC', 'z.example.test. TLSA RRSIG NSEC')
        with self.assertRaises(ProtocolError):
            self.validate(self.chain(*self.sign(nsec)))

    def test_nsec3_exact_nodata_and_iteration_budget(self):
        hashed = dns.dnssec.nsec3_hash(self.owner, b'', 0, 1)
        owner = hashed + '.example.test.'
        nsec = dns.rrset.from_text(owner, 300, 'IN', 'NSEC3', '1 0 0 - ' + hashed + ' A RRSIG')
        self.assertTrue(self.validate(self.chain(*self.sign(nsec))).authenticated_denial)
        hashed = dns.dnssec.nsec3_hash(self.owner, b'', 151, 1)
        nsec = dns.rrset.from_text(hashed + '.example.test.', 300, 'IN', 'NSEC3', '1 0 151 - ' + hashed + ' A RRSIG')
        with self.assertRaises(ProtocolError):
            self.validate(self.chain(*self.sign(nsec)))

    def test_wire_rejects_compression_truncation_and_missing_anchors(self):
        wire = self.chain(*self.sign(self.tlsa()))
        for invalid in (b'', wire[:-1], b'\xc0\x00' + wire[1:]):
            with self.assertRaises(ProtocolError):
                parse_authentication_chain(invalid)
        with self.assertRaises(ProtocolError):
            DNSSECChain(wire, trust_anchors={})

    def test_wildcard_tlsa_needs_validated_next_closer_denial(self):
        wildcard, sig = self.sign(self.tlsa('*.example.test.'))
        wildcard.name = dns.name.from_text(self.owner)
        sig.name = wildcard.name
        wire = self.chain(wildcard, sig)
        with self.assertRaises(ProtocolError):
            self.validate(wire)
        nsec = dns.rrset.from_text('*.example.test.', 300, 'IN', 'NSEC', 'z.example.test. TLSA RRSIG NSEC')
        result = self.validate(self.chain(wildcard, sig, *self.sign(nsec)))
        self.assertTrue(match_tlsa(result, (self.spki,), credential_type=2, now=self.now))

    def test_nsec_nxdomain_requires_no_wildcard_proof_too(self):
        nsec = dns.rrset.from_text('example.test.', 300, 'IN', 'NSEC', 'z.example.test. SOA NS RRSIG NSEC DNSKEY')
        self.assertTrue(self.validate(self.chain(*self.sign(nsec))).authenticated_denial)
        # A range beginning after wildcard proves the concrete name absent but
        # cannot exclude a wildcard TLSA, so it must NOT authorize fallback.
        incomplete = dns.rrset.from_text('a.example.test.', 300, 'IN', 'NSEC', 'z.example.test. A RRSIG NSEC')
        with self.assertRaises(ProtocolError):
            self.validate(self.chain(*self.sign(incomplete)))


if __name__ == '__main__':
    unittest.main()
