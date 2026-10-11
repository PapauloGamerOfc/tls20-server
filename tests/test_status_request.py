"""Complete OCSP request semantics and inherited TLS Feature constraints."""

import asyncio
from dataclasses import replace
import unittest

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from tls20_server import messages as m
from tls20_server.credential_evidence import CredentialEvidencePolicy
from tls20_server.credential_profiles import CredentialPolicy, resolve_peer
from tls20_server.credential_selection import _oid_der, _length
from tls20_server.errors import ProtocolError
from tls20_server.handshake import _credential_frame, client_handshake, server_handshake
from tls20_server.pki import Credentials
from tls20_server.status_request import (encode_status_request, parse_status_request,
                                        response_matches_request)
from tls20_server.tls_features import certificate_features, validate_feature_path
from tests import test_credential_profiles as fixtures
from tests.test_pki import issue, der


def nonce_extensions(nonce):
    return b'\x30' + _length(b'\x30' + _length(_oid_der('1.3.6.1.5.5.7.48.1.2')
        + b'\x04' + _length(b'\x04' + _length(nonce))))


class StatusRequestTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.fixture = fixtures.CredentialProfileTests()
        self.fixture.setUp()
        self.response = self.fixture.make_ocsp(nonce=b'request nonce')
        self.request = encode_status_request(request_extensions=nonce_extensions(b'request nonce'))
        self.staple = b'\x01' + len(self.response).to_bytes(3, 'big') + self.response
        self.credential = Credentials([der(self.fixture.leaf), der(self.fixture.root)], self.fixture.key,
                                       entry_extensions=(((5, self.staple),), ()))

    def test_nonce_and_both_responder_id_forms_are_real_constraints(self):
        f = self.fixture
        key_id = x509.SubjectKeyIdentifier.from_public_key(f.root.public_key()).digest
        by_key = b'\xa2' + _length(b'\x04' + _length(key_id))
        by_name = b'\xa1' + _length(f.root.subject.public_bytes())
        self.assertTrue(response_matches_request(self.response, parse_status_request(self.request)))
        self.assertTrue(response_matches_request(self.response, parse_status_request(encode_status_request((by_key, by_name)))))
        self.assertFalse(response_matches_request(self.response, parse_status_request(encode_status_request((by_name,)))))
        wrong = encode_status_request(request_extensions=nonce_extensions(b'other'))
        self.assertFalse(response_matches_request(self.response, parse_status_request(wrong)))
        critical = b'\x30' + _length(b'\x30' + _length(_oid_der('1.2.3.4') + b'\x01\x01\xff\x04\x00'))
        self.assertFalse(response_matches_request(self.response, parse_status_request(encode_status_request(request_extensions=critical))))

    def test_malformed_ocsp_and_nonempty_cr_requests_are_rejected(self):
        for value in (b'', b'garbage', b'\x01', b'\x01\0\0\0\0x', b'\x01\0\0\0\2\x30\0',
                      b'\x01\0\3\0\1x\0\0'):
            # Unknown status types can be ignored; known OCSP must be decoded.
            if value == b'garbage':
                self.assertIsNone(parse_status_request(value))
                continue
            with self.subTest(value=value), self.assertRaises(ProtocolError):
                parse_status_request(value)
        with self.assertRaises(ProtocolError):
            parse_status_request(self.request, certificate_request=True)
        hello = m.client_hello(bytes(range(32)), bytes(range(32,64)), 'example.test', bytes(32),
                               extra_extensions=((5,b'\x01'),))
        with self.assertRaises(ProtocolError):
            m.parse_client_hello(hello[4:])

    def test_sender_does_not_claim_unmatched_staple_fulfills_nonce(self):
        offers = ((50,m._vec(b'\x04\x03',2)), (5,self.request))
        frame = _credential_frame(self.credential, offer_extensions=offers)
        self.assertIn(5, dict(m.parse_certificate(frame[4:],details=True)[1][0]))
        wrong = encode_status_request(request_extensions=nonce_extensions(b'other'))
        frame = _credential_frame(self.credential, offer_extensions=(offers[0],(5,wrong)))
        self.assertNotIn(5, dict(m.parse_certificate(frame[4:],details=True)[1][0]))

    def test_issuer_constraints_are_enforced_independently_of_offered_features(self):
        f = self.fixture
        root = issue(f.ca_key,f.ca_key,f.ca_name,f.ca_name,ca=True,
                     extra=[(x509.TLSFeature([x509.TLSFeatureType.status_request]),False)])
        with self.assertRaises(ProtocolError):
            CredentialEvidencePolicy()([f.leaf,root], 'server', (), f.now)
        leaf = issue(f.key,f.ca_key,f.name,f.ca_name,
                     extra=[(x509.TLSFeature([x509.TLSFeatureType.status_request]),False)])
        self.assertEqual(validate_feature_path((leaf,root)),{5})
        self.assertTrue(CredentialEvidencePolicy()([leaf,root], 'server', (), f.now))
        with self.assertRaises(ProtocolError):
            CredentialEvidencePolicy(offered_extensions=(5,))([leaf,root], 'server', (), f.now)

    def test_unknown_feature_integer_is_not_misread_as_must_staple(self):
        f = self.fixture
        feature = x509.UnrecognizedExtension(x509.ObjectIdentifier('1.3.6.1.5.5.7.1.24'), b'\x30\x04\x02\x02\x12\x34')
        leaf = issue(f.key,f.ca_key,f.name,f.ca_name,extra=[(feature,False)])
        self.assertEqual(certificate_features(leaf),{0x1234})

    def test_offline_policy_does_not_waive_offered_must_staple(self):
        f = self.fixture
        f.leaf = issue(f.key,f.ca_key,f.name,f.ca_name,
            extra=[(x509.TLSFeature([x509.TLSFeatureType.status_request]),False)])
        response = f.make_ocsp()
        staple = b'\x01' + len(response).to_bytes(3,'big') + response
        # The feature was not offered: no new requirement is invented.
        resolve_peer([der(f.leaf)],policy=f.policy)
        for evidence in ((),(((5,staple),),)):
            with self.subTest(evidence=bool(evidence)), self.assertRaises(ProtocolError):
                resolve_peer([der(f.leaf)],policy=f.policy,offered_extensions=(5,),entry_extensions=evidence)
        # Even an approving callback cannot turn absence into satisfied OCSP.
        with self.assertRaises(ProtocolError):
            resolve_peer([der(f.leaf)],policy=replace(f.policy,evidence_validator=lambda *args:True),offered_extensions=(5,))

    def test_actual_offers_enable_real_mandatory_ocsp_validation(self):
        f = self.fixture
        f.leaf = issue(f.key,f.ca_key,f.name,f.ca_name,
            extra=[(x509.TLSFeature([x509.TLSFeatureType.status_request]),False)])
        # The policy's optional defaults omit offered_extensions; the resolver
        # must bind it to the actual handshake instead of overlooking the bit.
        policy = replace(f.policy,evidence_validator=CredentialEvidencePolicy())
        response = f.make_ocsp()
        for encoded in (response,response[:-1]+bytes((response[-1]^1,))):
            staple = b'\x01' + len(encoded).to_bytes(3,'big') + encoded
            if encoded == response:
                self.assertEqual(resolve_peer([der(f.leaf)],policy=policy,
                    entry_extensions=(((5,staple),),),offered_extensions=(5,)).provenance,'x509')
            else:
                with self.assertRaises(ProtocolError):
                    resolve_peer([der(f.leaf)],policy=policy,
                        entry_extensions=(((5,staple),),),offered_extensions=(5,))
        with self.assertRaises(ProtocolError):
            resolve_peer([der(f.leaf)],policy=policy,offered_extensions=(5,))

    def test_mandatory_ct_is_not_validated_by_zero_optional_log_minimum(self):
        f = self.fixture
        for feature in (18,52):
            encoded = b'\x30\x03\x02\x01'+bytes((feature,))
            leaf = issue(f.key,f.ca_key,f.name,f.ca_name,extra=[
                (x509.UnrecognizedExtension(x509.ObjectIdentifier('1.3.6.1.5.5.7.1.24'),encoded),False)])
            policy = replace(f.policy,evidence_validator=CredentialEvidencePolicy())
            with self.subTest(feature=feature),self.assertRaises(ProtocolError):
                resolve_peer([der(leaf)],policy=policy,offered_extensions=(5,feature),
                    entry_extensions=(((feature,b'\0\0'),),))

    def test_unknown_feature_is_ignored_only_while_unoffered(self):
        f = self.fixture
        leaf = issue(f.key,f.ca_key,f.name,f.ca_name,extra=[
            (x509.UnrecognizedExtension(x509.ObjectIdentifier('1.3.6.1.5.5.7.1.24'),bytes.fromhex('300402021234')),False)])
        resolve_peer([der(leaf)],policy=f.policy,offered_extensions=(5,))
        with self.assertRaises(ProtocolError):
            resolve_peer([der(leaf)],policy=f.policy,offered_extensions=(0x1234,))
        with self.assertRaises(ProtocolError):
            resolve_peer([der(leaf)],policy=replace(f.policy,evidence_validator=CredentialEvidencePolicy()),
                offered_extensions=(0x1234,))

    async def test_real_handshake_nonce_match_and_refusal(self):
        f = self.fixture
        channels, failures = [], []
        async def serve(reader,writer):
            try:
                channel = await server_handshake(reader,writer,self.credential,'example.test',timeout=5)
                channels.append(channel)
                await channel.send(b'ok')
            except (ProtocolError,ConnectionError,asyncio.IncompleteReadError) as error:
                failures.append(type(error).__name__)
                writer.close()
        listener = await asyncio.start_server(serve,'127.0.0.1',0)
        try:
            for expected in (b'request nonce',b'wrong nonce'):
                request = encode_status_request(request_extensions=nonce_extensions(expected))
                evidence = CredentialEvidencePolicy(require_ocsp=True,ocsp_request=request,offered_extensions=(5,))
                policy = CredentialPolicy(trust_roots=(f.root,),peer_name='example.test',
                    revocation_policy='require-evidence',evidence_validator=evidence)
                reader,writer = await asyncio.open_connection('127.0.0.1',listener.sockets[0].getsockname()[1])
                if expected == b'wrong nonce':
                    with self.assertRaises(ProtocolError):
                        await client_handshake(reader,writer,'example.test',(f.root,),timeout=5,
                            revocation_policy='require-evidence',credential_policy=policy,certificate_evidence_extensions=((5,request),))
                else:
                    channel = await client_handshake(reader,writer,'example.test',(f.root,),timeout=5,
                        revocation_policy='require-evidence',credential_policy=policy,certificate_evidence_extensions=((5,request),))
                    channels.append(channel)
                    self.assertEqual(await channel.recv(),b'ok')
        finally:
            for channel in channels:
                channel.abort()
            listener.close()
            await listener.wait_closed()


if __name__ == '__main__':
    unittest.main()
