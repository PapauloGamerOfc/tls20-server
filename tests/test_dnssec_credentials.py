import base64
import hashlib
import io
import time
import unittest
from dataclasses import replace
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

    def test_validated_dane_and_pkix_paths_retain_omitted_issuer_for_ocsp(self):
        from tls20_server.credential_evidence import CredentialEvidencePolicy
        from tls20_server.pki import validate_identity, validate_pkix_path
        from tests.test_credential_profiles import CredentialProfileTests
        from tests.test_pki import der
        fixture = CredentialProfileTests(); fixture.setUp()
        response = fixture.make_ocsp()
        good = b'\x01' + len(response).to_bytes(3, 'big') + response
        bad = good[:-1] + bytes((good[-1] ^ 1,))
        def validate_path(material, anchor=fixture.root):
            validate_identity(material, trust_roots=(anchor,), role='server',
                              name='example.test', partial_chain=True)
            return validate_pkix_path(material, (anchor,), partial_chain=True)
        for usage in (0, 1, 2):
            association = der(fixture.leaf if usage == 1 else fixture.root)
            rrset = dns.rrset.from_text(self.owner, 300, 'IN', 'TLSA',
                                       f'{usage} 0 0 ' + association.hex())
            proof = DNSSECWireEvidence(24, self.chain(*self.sign(rrset))).encode()
            policy = CredentialPolicy(peer_name='example.test',
                dane_policy=DANEPolicy({'.': self.root_keys}, pkix_validator=validate_path,
                                      dane_path_validator=validate_path),
                evidence_validator=CredentialEvidencePolicy(require_ocsp=True))
            for include_issuer in (False, True):
                material = (der(fixture.leaf),) + ((der(fixture.root),) if include_issuer else ())
                for staple in (good, bad, None):
                    with self.subTest(usage=usage, include_issuer=include_issuer, good=staple is good):
                        leaf_evidence = ((59, proof),) + (((5, staple),) if staple else ())
                        evidence = (leaf_evidence,) + ((),) * (len(material) - 1)
                        if staple is good:
                            peer = resolve_peer(material, policy=policy,
                                offered_extensions=(59, 5), entry_extensions=evidence)
                            self.assertEqual(peer.provenance, 'dane-x509')
                            self.assertEqual(peer.material, material)  # Wire credential is unchanged.
                        else:
                            with self.assertRaises(ProtocolError):
                                resolve_peer(material, policy=policy,
                                    offered_extensions=(59, 5), entry_extensions=evidence)
            # Legacy boolean callbacks must not fabricate an issuer path. They
            # remain compatible, but omitted-issuer evidence needs a real path.
            if usage == 2:
                def legacy(material, anchor):
                    validate_path(material, anchor)
                    return True
                legacy_policy = replace(policy, dane_policy=replace(policy.dane_policy, dane_path_validator=legacy))
                with self.assertRaisesRegex(ProtocolError, 'issuer is not available'):
                    resolve_peer((der(fixture.leaf),), policy=legacy_policy, offered_extensions=(59, 5),
                        entry_extensions=(((59, proof), (5, good)),))
                resolve_peer((der(fixture.leaf), der(fixture.root)), policy=legacy_policy,
                    offered_extensions=(59, 5), entry_extensions=(((59, proof), (5, good)), ()))

    def test_dane_ta_rollover_tries_all_usable_associations(self):
        from tls20_server.pki import validate_identity, validate_pkix_path
        from tests.test_credential_profiles import CredentialProfileTests
        from tests.test_pki import der
        fixture = CredentialProfileTests(); fixture.setUp()
        unrelated = CredentialProfileTests(); unrelated.setUp()
        good, wrong, malformed = der(fixture.root), der(unrelated.root), b'not-a-certificate'
        rrset = dns.rrset.from_text(self.owner, 300, 'IN', 'TLSA',
            *('2 0 0 ' + value.hex() for value in (good, wrong, malformed)))
        authenticated = self.validate(self.chain(*self.sign(rrset)))
        records = {record.cert: record for record in authenticated.records}
        calls = []
        for legacy in (False, True):
            def validate_path(material, anchor):
                calls.append(der(anchor))
                validate_identity(material, trust_roots=(anchor,), role='server',
                                  name='example.test', partial_chain=True)
                return True if legacy else validate_pkix_path(material, (anchor,), partial_chain=True)
            for order in ((good,), (wrong,), (malformed,), (good, wrong),
                          (wrong, good), (malformed, wrong, good)):
                with self.subTest(legacy=legacy, order=tuple(value == good for value in order)):
                    # Every record is from the real signed RRset. Pin its order
                    # after DNSSEC validation, so wire randomization cannot hide
                    # a first-association-only implementation.
                    result = replace(authenticated, records=tuple(records[value] for value in order))
                    calls.clear()
                    if good in order:
                        authorization = match_tlsa(result, (der(fixture.leaf),),
                            dane_path_validator=validate_path, return_authorization=True)
                        self.assertEqual(authorization.usage, 2)
                        self.assertEqual(calls[-1], good)
                        if not legacy:
                            self.assertEqual(tuple(der(cert) for cert in authorization.validated_path),
                                             (der(fixture.leaf), good))
                        else:
                            self.assertEqual(authorization.validated_path, ())
                        self.assertTrue(match_tlsa(result, (der(fixture.leaf),), dane_path_validator=validate_path))
                        self.assertEqual(match_tlsa(result, (der(fixture.leaf),),
                            dane_path_validator=validate_path, return_usage=True), 2)
                    else:
                        with self.assertRaises(ProtocolError):
                            match_tlsa(result, (der(fixture.leaf),), dane_path_validator=validate_path)
        single = replace(authenticated, records=(records[good],))
        with self.assertRaises(ProtocolError):
            match_tlsa(single, (der(fixture.leaf),),
                dane_path_validator=lambda material, anchor: (unrelated.leaf, anchor))

    def test_dane_profile_retains_actual_path_and_checks_reference_identity(self):
        from pathlib import Path
        from tempfile import TemporaryDirectory
        from tls20_server.profiles import load_profile
        from tests.test_credential_profiles import CredentialProfileTests
        from tests.test_pki import der, issue
        fixture = CredentialProfileTests(); fixture.setUp()
        rrset = dns.rrset.from_text(self.owner, 300, 'IN', 'TLSA', '2 0 0 ' + der(fixture.root).hex())
        proof = DNSSECWireEvidence(24, self.chain(*self.sign(rrset))).encode()
        response = fixture.make_ocsp()
        staple = b'\x01' + len(response).to_bytes(3, 'big') + response
        with TemporaryDirectory() as directory:
            directory = Path(directory)
            (directory / 'anchors.zone').write_text(self.root_keys.to_text() + '\n', encoding='ascii')
            (directory / 'client.toml').write_text('role="client"\nservice="example.test"\n'
                'port=343\nmode="certificate"\n[trust.dane]\nanchors_file="anchors.zone"\n'
                '[trust.evidence]\nrequire_ocsp=true\n', encoding='ascii')
            profile = load_profile(directory / 'client.toml', role='client')
            try:
                policy = profile.options['credential_policy']
                peer = resolve_peer((der(fixture.leaf),), policy=policy, offered_extensions=(59, 5),
                    entry_extensions=(((59, proof), (5, staple)),))
                self.assertEqual(peer.provenance, 'dane-x509')
                evidence = (((59, proof),),)
                usage, expiry = policy.dane_policy.authorize((der(fixture.leaf),), 0, 'example.test', evidence)
                self.assertEqual(usage, 2)
                self.assertGreater(expiry, self.now)
                for bad_leaf in (issue(fixture.key, fixture.ca_key, fixture.name, fixture.ca_name,
                                       hostname='wrong.test'),
                                 issue(fixture.key, fixture.ca_key, fixture.name, fixture.ca_name, validity=-1)):
                    with self.assertRaises(ProtocolError):
                        policy.dane_policy.authorize((der(bad_leaf),), 0, 'example.test', evidence)
            finally:
                profile.close()

    def test_dane_ta_retains_dns_issuer_for_ct_v2_binding(self):
        from tls20_server.credential_evidence import CredentialEvidencePolicy
        from tls20_server.pki import validate_identity, validate_pkix_path
        from tests.test_pki import der
        from tests.test_transparency import TransparencyTests, listed
        fixture = TransparencyTests(); fixture.setUp()
        rrset = dns.rrset.from_text(self.owner, 300, 'IN', 'TLSA', '2 0 0 ' + der(fixture.root).hex())
        proof = DNSSECWireEvidence(24, self.chain(*self.sign(rrset))).encode()
        def validate_path(material, anchor):
            validate_identity(material, trust_roots=(anchor,), role='server',
                              name='example.test', partial_chain=True)
            return validate_pkix_path(material, (anchor,), partial_chain=True)
        policy = CredentialPolicy(peer_name='example.test',
            dane_policy=DANEPolicy({'.': self.root_keys}, dane_path_validator=validate_path),
            evidence_validator=CredentialEvidencePolicy(minimum_ct_v2_logs=1,
                trusted_logs_v2={fixture.log_v2.log_id: fixture.log_v2}))
        valid = listed(fixture.v2()[0])
        invalid = valid[:-1] + bytes((valid[-1] ^ 1,))
        for value in (valid, invalid):
            metadata = (((59, proof), (52, value)),)
            if value is valid:
                peer = resolve_peer((der(fixture.cert),), policy=policy,
                    offered_extensions=(59, 5, 52), entry_extensions=metadata)
                self.assertEqual(peer.provenance, 'dane-x509')
            else:
                with self.assertRaises(ProtocolError):
                    resolve_peer((der(fixture.cert),), policy=policy,
                        offered_extensions=(59, 5, 52), entry_extensions=metadata)

    def test_duplicate_leaf_cannot_erase_an_optional_ocsp_response(self):
        from tls20_server.credential_evidence import CredentialEvidencePolicy
        from tls20_server.pki import validate_identity, validate_pkix_path
        from tests.test_credential_profiles import CredentialProfileTests
        from tests.test_pki import der
        fixture = CredentialProfileTests(); fixture.setUp()
        rrset = dns.rrset.from_text(self.owner, 300, 'IN', 'TLSA', '2 0 0 ' + der(fixture.root).hex())
        proof = DNSSECWireEvidence(24, self.chain(*self.sign(rrset))).encode()
        def validate_path(material, anchor):
            # Model a legitimate alternate path provider which tolerates
            # redundant wire certificates. It still validates path and name.
            unique = tuple(dict.fromkeys(material))
            validate_identity(unique, trust_roots=(anchor,), role='server', name='example.test', partial_chain=True)
            return validate_pkix_path(unique, (anchor,), partial_chain=True)
        policy = CredentialPolicy(peer_name='example.test',
            dane_policy=DANEPolicy({'.': self.root_keys}, dane_path_validator=validate_path),
            evidence_validator=CredentialEvidencePolicy(require_ocsp=False))
        response = fixture.make_ocsp()
        good = b'\x01' + len(response).to_bytes(3, 'big') + response
        bad = good[:-1] + bytes((good[-1] ^ 1,))
        for duplicate in (False, True):
            for staple in (good, bad):
                with self.subTest(duplicate=duplicate, valid_signature=staple is good):
                    material = (der(fixture.leaf),) * (2 if duplicate else 1)
                    evidence = (((59, proof), (5, staple)),) + (((),) if duplicate else ())
                    if duplicate or staple is bad:
                        expected = 'ambiguous duplicate' if duplicate else 'OCSP response validation failed'
                        with self.assertRaisesRegex(ProtocolError, expected):
                            resolve_peer(material, policy=policy, offered_extensions=(59, 5), entry_extensions=evidence)
                    else:
                        peer = resolve_peer(material, policy=policy, offered_extensions=(59, 5), entry_extensions=evidence)
                        self.assertEqual(peer.provenance, 'dane-x509')

    def test_dane_reordered_path_preserves_intermediate_ocsp_binding(self):
        from tls20_server.credential_evidence import CredentialEvidencePolicy
        from tls20_server.pki import validate_identity, validate_pkix_path
        from tests.test_credential_profiles import CredentialProfileTests
        from tests.test_pki import der, issue
        fixture = CredentialProfileTests(); fixture.setUp()
        inter_key = ec.generate_private_key(ec.SECP256R1())
        inter_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'DANE intermediate')])
        inter = issue(inter_key, fixture.ca_key, inter_name, fixture.ca_name, ca=True)
        leaf = issue(fixture.key, inter_key, fixture.name, inter_name)
        rrset = dns.rrset.from_text(self.owner, 300, 'IN', 'TLSA', '2 0 0 ' + der(fixture.root).hex())
        proof = DNSSECWireEvidence(24, self.chain(*self.sign(rrset))).encode()
        def validate_path(material, anchor):
            validate_identity(material, trust_roots=(anchor,), role='server', name='example.test', partial_chain=True)
            path = validate_pkix_path(material, (anchor,), partial_chain=True)
            self.assertEqual(tuple(der(cert) for cert in path), (der(leaf), der(inter), der(fixture.root)))
            return path
        def staple(cert, issuer, key):
            moment = datetime.now(timezone.utc)
            response = ocsp.OCSPResponseBuilder().add_response(cert=cert, issuer=issuer,
                algorithm=hashes.SHA256(), cert_status=ocsp.OCSPCertStatus.GOOD,
                this_update=moment-timedelta(seconds=60), next_update=moment+timedelta(hours=1),
                revocation_time=None, revocation_reason=None).responder_id(
                ocsp.OCSPResponderEncoding.HASH, issuer).sign(key, hashes.SHA256())
            wire = response.public_bytes(serialization.Encoding.DER)
            return b'\x01' + len(wire).to_bytes(3, 'big') + wire
        policy = CredentialPolicy(peer_name='example.test',
            dane_policy=DANEPolicy({'.': self.root_keys}, dane_path_validator=validate_path),
            evidence_validator=CredentialEvidencePolicy(require_ocsp=True))
        leaf_staple = staple(leaf, inter, inter_key)
        inter_staple = staple(inter, fixture.root, fixture.ca_key)
        invalid = inter_staple[:-1] + bytes((inter_staple[-1] ^ 1,))
        # Deliberately put root before intermediate on the wire. Evidence must
        # follow DER identity when the validator builds the actual path.
        material = (der(leaf), der(fixture.root), der(inter))
        for value in (inter_staple, invalid):
            evidence = (((59, proof), (5, leaf_staple)), (), ((5, value),))
            if value is inter_staple:
                peer = resolve_peer(material, policy=policy, offered_extensions=(59, 5), entry_extensions=evidence)
                self.assertEqual(peer.provenance, 'dane-x509')
            else:
                with self.assertRaisesRegex(ProtocolError, 'OCSP response validation failed'):
                    resolve_peer(material, policy=policy, offered_extensions=(59, 5), entry_extensions=evidence)

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
