"""CertificateEntry evidence follows DER identity, not a rebuilt path index."""

from dataclasses import replace
from datetime import datetime, timedelta, timezone
import unittest

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509 import ocsp
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from tests import test_credential_profiles, test_sessions
from tests.test_pki import der, issue
from tls20_server.credential_evidence import CredentialEvidencePolicy
from tls20_server.credential_profiles import resolve_peer
from tls20_server.errors import ProtocolError
from tls20_server.pki import Credentials, evidence_for_validated_path, validate_pkix_path
from tls20_server.tickets import TicketCache


class EvidencePathFixture:
    def configure(self):
        self.fixture = test_credential_profiles.CredentialProfileTests()
        self.fixture.setUp()
        self.inter_key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'Evidence intermediate')])
        self.inter = issue(self.inter_key, self.fixture.ca_key, name, self.fixture.ca_name, ca=True)
        self.leaf = issue(self.fixture.key, self.inter_key, self.fixture.name, name,
            hostname='localhost', eku=False,
            extra=[(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH]), False)])
        self.leaf_staple = self.staple(self.leaf, self.inter, self.inter_key)
        self.inter_staple = self.staple(self.inter, self.fixture.root, self.fixture.ca_key)
        self.policy = replace(self.fixture.policy, peer_name='localhost',
            authorize_client=lambda *_: True, evidence_validator=CredentialEvidencePolicy(require_ocsp=True))

    def staple(self, cert, issuer, key, *, status=ocsp.OCSPCertStatus.GOOD):
        now = datetime.now(timezone.utc)
        response = (ocsp.OCSPResponseBuilder().add_response(cert, issuer, hashes.SHA256(), status,
            now-timedelta(minutes=1), now+timedelta(hours=1),
            now-timedelta(hours=1) if status == ocsp.OCSPCertStatus.REVOKED else None, None)
            .responder_id(ocsp.OCSPResponderEncoding.HASH, issuer).sign(key, hashes.SHA256()))
        encoded = response.public_bytes(serialization.Encoding.DER)
        return b'\x01' + len(encoded).to_bytes(3, 'big') + encoded

    def material(self, mode='ordered', *, leaf_staple=None, inter_staple=None):
        leaf = ((5, self.leaf_staple if leaf_staple is None else leaf_staple),)
        inter = ((5, self.inter_staple if inter_staple is None else inter_staple),)
        if mode == 'reordered':
            return (der(self.leaf), der(self.fixture.root), der(self.inter)), (leaf, (), inter)
        if mode == 'omitted-root':
            return (der(self.leaf), der(self.inter)), (leaf, inter)
        return (der(self.leaf), der(self.inter), der(self.fixture.root)), (leaf, inter, ())


class PKIXEvidencePathTests(EvidencePathFixture, unittest.TestCase):
    def setUp(self):
        self.configure()

    def test_valid_reordered_and_omitted_root_metadata_reaches_its_actual_certificate(self):
        for mode in ('ordered', 'reordered', 'omitted-root'):
            material, metadata = self.material(mode)
            captured = []
            validator = self.policy.evidence_validator
            def evidence(path, role, values, moment):
                captured.append((tuple(der(cert) for cert in path), values))
                return validator(path, role, values, moment)
            for role in ('server', 'client'):
                with self.subTest(mode=mode, role=role):
                    peer = resolve_peer(material, role=role, policy=replace(self.policy, evidence_validator=evidence),
                                        offered_extensions=(5,), entry_extensions=metadata)
                    self.assertEqual(peer.material, material)  # The wire snapshot is not rewritten.
                    self.assertEqual(peer.evidence, metadata)
                    path, values = captured[-1]
                    self.assertEqual(path, (der(self.leaf), der(self.inter), der(self.fixture.root)))
                    self.assertEqual(values, (((5, self.leaf_staple),), ((5, self.inter_staple),), ()))

    def test_response_cannot_move_to_a_different_certificate_entry(self):
        material, _ = self.material('reordered')
        misplaced = (((5, self.leaf_staple),), ((5, self.inter_staple),), ())
        with self.assertRaisesRegex(ProtocolError, 'issuer is not available'):
            resolve_peer(material, policy=self.policy, offered_extensions=(5,), entry_extensions=misplaced)

    def test_invalid_or_revoked_staple_remains_rejected_after_reorder(self):
        revoked = self.staple(self.inter, self.fixture.root, self.fixture.ca_key,
                             status=ocsp.OCSPCertStatus.REVOKED)
        bad = self.inter_staple[:-1] + bytes((self.inter_staple[-1] ^ 1,))
        for mode in ('ordered', 'reordered', 'omitted-root'):
            for value in (bad, revoked, self.leaf_staple):
                with self.subTest(mode=mode, evidence=value is revoked):
                    material, metadata = self.material(mode, inter_staple=value)
                    with self.assertRaises(ProtocolError):
                        resolve_peer(material, policy=self.policy, offered_extensions=(5,), entry_extensions=metadata)

    def test_extra_certificates_do_not_contribute_evidence_or_supply_a_fake_path(self):
        extra_key = ec.generate_private_key(ec.SECP256R1())
        extra = issue(extra_key, self.fixture.ca_key,
            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'Unused intermediate')]), self.fixture.ca_name, ca=True)
        material, metadata = self.material('omitted-root')
        material += (der(extra),)
        metadata += ((),)
        peer = resolve_peer(material, policy=self.policy, offered_extensions=(5,), entry_extensions=metadata)
        self.assertEqual(peer.provenance, 'x509')
        extra_staple = self.staple(extra, self.fixture.root, self.fixture.ca_key)
        with self.assertRaisesRegex(ProtocolError, 'absent from the validated path'):
            resolve_peer(material, policy=self.policy, offered_extensions=(5,),
                         entry_extensions=metadata[:-1] + (((5, extra_staple),),))
        with self.assertRaisesRegex(ProtocolError, 'path validation failed'):
            resolve_peer((der(self.leaf), der(extra)), policy=self.policy,
                         offered_extensions=(5,), entry_extensions=(((5, self.leaf_staple),), ()))

    def test_duplicate_cannot_erase_optional_evidence_and_count_is_bound(self):
        material, metadata = self.material('omitted-root')
        policy = replace(self.policy, evidence_validator=CredentialEvidencePolicy())
        path = validate_pkix_path(material, self.policy.trust_roots)
        for duplicate in ((), ((5, self.inter_staple),)):
            with self.assertRaisesRegex(ProtocolError, 'ambiguous duplicate'):
                evidence_for_validated_path(material + (material[0],), metadata + (duplicate,), path)
        self.assertEqual(evidence_for_validated_path(material + (material[0],),
                         metadata + (metadata[0],), path), metadata + ((),))
        # The PKIX provider's stricter duplicate-chain rule is not relaxed.
        with self.assertRaisesRegex(ProtocolError, 'duplicate certificates'):
            resolve_peer(material + (material[0],), policy=policy,
                offered_extensions=(5,), entry_extensions=metadata + (metadata[0],))
        with self.assertRaisesRegex(ProtocolError, 'count exceeds'):
            evidence_for_validated_path(material, metadata + ((),), path)


class PKIXEvidencePathWireTests(EvidencePathFixture, unittest.IsolatedAsyncioTestCase):
    accept = test_sessions.SessionTests.accept
    handle = test_sessions.SessionTests.handle
    connect = test_sessions.SessionTests.connect
    asyncTearDown = test_sessions.SessionTests.asyncTearDown

    async def asyncSetUp(self):
        await test_sessions.SessionTests.asyncSetUp(self)
        self.configure()
        self.roots = [self.fixture.root]

    async def test_full_resumed_early_and_compressed_cached_reference_preserve_binding(self):
        for mode in ('ordered', 'reordered', 'omitted-root'):
            material, metadata = self.material(mode)
            self.credentials = Credentials(list(material), self.fixture.key, entry_extensions=metadata)
            self.cache = TicketCache()
            for resumed, early in ((False, b''), (True, b''), (True, b'public status fixture')):
                with self.subTest(mode=mode, resumed=resumed, early=bool(early)):
                    channel = await self.connect(credential_policy=self.policy, early_data=early,
                        certificate_evidence_extensions=((5, b'\x01\0\0\0\0'),),
                        cached_certificates=((0, material),), certificate_compression=(1,))
                    self.assertEqual(channel.resumed, resumed)
                    self.assertEqual(channel.early_data_accepted, bool(early))
                    self.assertTrue(channel.peer_authenticated)
                    self.assertEqual(tuple(channel.certificate_chain), material)
                    self.assertEqual(channel.certificate_extensions, metadata)
                    if not resumed:
                        self.assertIn(1, channel.cache_types)
                    self.assertEqual(channel.handshake_transcript, self.channels[-1].handshake_transcript)
                    await channel.send(b'evidence stays with its original DER')
                    self.assertEqual(await channel.recv(), b'evidence stays with its original DER')
            self.assertFalse(self.errors)

    async def test_wrong_entry_or_invalid_signature_never_authenticates(self):
        material, metadata = self.material('reordered')
        bad = self.inter_staple[:-1] + bytes((self.inter_staple[-1] ^ 1,))
        for invalid in ((((5, self.leaf_staple),), ((5, self.inter_staple),), ()),
                        (metadata[0], (), ((5, bad),))):
            self.cache = TicketCache()
            self.credentials = Credentials(list(material), self.fixture.key, entry_extensions=invalid)
            before = len(self.channels)
            with self.assertRaises(ProtocolError):
                await self.connect(credential_policy=self.policy,
                    certificate_evidence_extensions=((5, b'\x01\0\0\0\0'),))
            self.assertEqual(len(self.channels), before)
            self.assertFalse(self.cache._tickets)


if __name__ == '__main__':
    unittest.main()
