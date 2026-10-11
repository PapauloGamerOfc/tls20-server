"""Actual DANE X.509/RPK handshakes, not acceptance of a parsed TLSA record."""
import hashlib
from dataclasses import replace
import unittest
import time

import dns.rrset
from cryptography.hazmat.primitives import serialization

from tests import test_dnssec_credentials, test_sessions
from tls20_server.credential_profiles import CredentialPolicy
from tls20_server.dnssec_credentials import DANEPolicy, DNSSECWireEvidence
from tls20_server.errors import ProtocolError
from tls20_server.pki import Credentials
from tls20_server.tickets import TicketCache


class DNSSECHandshakeTests(unittest.IsolatedAsyncioTestCase):
    asyncSetUp = test_sessions.SessionTests.asyncSetUp
    asyncTearDown = test_sessions.SessionTests.asyncTearDown
    accept = test_sessions.SessionTests.accept
    handle = test_sessions.SessionTests.handle
    connect = test_sessions.SessionTests.connect

    def configure(self, kind, *, evidence_port=343, binding_port=343, expired=False):
        fixture = test_dnssec_credentials.DNSSECCredentialTests()
        fixture.setUp()
        spki = self.credentials.private_key.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        material = self.credentials.chain_der if kind == 0 else [spki]
        record = dns.rrset.from_text(f'_{evidence_port}._tcp.localhost.', 300, 'IN', 'TLSA',
                                    '3 1 1 ' + hashlib.sha256(spki).hexdigest())
        chain = fixture.chain(*fixture.sign(record, root=True, expired=expired))
        evidence = DNSSECWireEvidence(24, chain).encode()
        self.credentials = Credentials(material, self.credentials.private_key, credential_type=kind,
            entry_extensions=(((59, evidence),),) + ((),) * (len(material) - 1),
            dnssec_service=('localhost', binding_port))
        return CredentialPolicy(peer_name='localhost',
            dane_policy=DANEPolicy({'.': fixture.root_keys}, port=343))

    async def test_x509_and_rpk_full_resumed_early_current_evidence(self):
        for kind in (0, 2):
            with self.subTest(credential_type=kind):
                policy = self.configure(kind)
                self.cache = TicketCache()
                for expected_resumed, early in ((False, b''), (True, b''), (True, b'public fixture')):
                    channel = await self.connect(credential_policy=policy,
                        server_certificate_types=(kind,), early_data=early)
                    self.assertEqual(channel.resumed, expected_resumed)
                    self.assertEqual(channel.early_data_accepted, bool(early))
                    self.assertEqual(channel.certificate_type, kind)
                    # DNSSEC does not waive actual possession/MAC and Finished.
                    self.assertTrue(channel.handshake_completed)
                    self.assertEqual(channel.handshake_transcript, self.channels[-1].handshake_transcript)

    async def test_wrong_service_evidence_and_expired_signatures_rejected(self):
        for kind in (0, 2):
            for options in ({'evidence_port': 443}, {'binding_port': 443}, {'expired': True}):
                with self.subTest(kind=kind, options=options):
                    self.cache = TicketCache()
                    policy = self.configure(kind, **options)
                    with self.assertRaises((ProtocolError, ConnectionError)):
                        await self.connect(credential_policy=policy, server_certificate_types=(kind,))

    async def test_request_port_must_match_policy_and_sni_cannot_be_omitted(self):
        policy = self.configure(2)
        for options in ({'certificate_evidence_extensions': ((59, b'\x01\xbb'),)},
                        {'send_server_name': False}):
            with self.subTest(options=options), self.assertRaises(ValueError):
                await self.connect(credential_policy=policy, server_certificate_types=(2,), **options)

    async def test_local_evidence_without_explicit_service_binding_rejected(self):
        policy = self.configure(2)
        self.credentials = replace(self.credentials, dnssec_service=None)
        with self.assertRaises((ProtocolError, ConnectionError)):
            await self.connect(credential_policy=policy, server_certificate_types=(2,))

    async def test_non_dane_peer_does_not_receive_unsolicited_dnssec_evidence(self):
        self.configure(0)
        channel = await self.connect()
        self.assertTrue(channel.handshake_completed)
        self.assertFalse(any(59 in dict(pairs) for pairs in channel.certificate_extensions))

    async def test_cached_dns_ttl_cannot_restart_across_resumption(self):
        for kind in (0, 2):
            policy = self.configure(kind)
            self.cache = TicketCache()
            original = await self.connect(credential_policy=policy, server_certificate_types=(kind,))
            deadline = original.credential_expires_at
            self.assertGreater(deadline, time.time())
            for _ in range(2):
                resumed = await self.connect(credential_policy=policy, server_certificate_types=(kind,),
                                             early_data=b'public fixture')
                self.assertTrue(resumed.resumed)
                self.assertEqual(resumed.credential_expires_at, deadline)
                self.assertTrue(all(item.credential_expires_at == deadline for item in self.cache._tickets.values()))
            for item in self.cache._tickets.values():
                item.credential_expires_at = time.time() - 1
            fresh = await self.connect(credential_policy=policy, server_certificate_types=(kind,),
                                       early_data=b'public fixture')
            self.assertFalse(fresh.resumed)
            self.assertFalse(fresh.early_data_accepted)

    async def test_missing_original_dns_deadline_forces_fresh_authentication(self):
        policy = self.configure(2)
        await self.connect(credential_policy=policy, server_certificate_types=(2,))
        for item in self.cache._tickets.values():
            item.credential_expires_at = None
        channel = await self.connect(credential_policy=policy, server_certificate_types=(2,),
                                      early_data=b'public fixture')
        self.assertFalse(channel.resumed)
        self.assertFalse(channel.early_data_accepted)


if __name__ == '__main__':
    unittest.main()
