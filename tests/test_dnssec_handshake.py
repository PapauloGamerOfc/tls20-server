"""Actual DANE X.509/RPK handshakes, not acceptance of a parsed TLSA record."""
import hashlib
from dataclasses import replace
import unittest
import time
from unittest.mock import patch

import dns.rrset
from cryptography.hazmat.primitives import serialization

from tests import test_dnssec_credentials, test_sessions
from tls20_server import crypto as c, messages as m
from tls20_server.credential_profiles import CredentialPolicy
from tls20_server.dnssec_credentials import DANEPolicy, DNSSECWireEvidence
from tls20_server.errors import ProtocolError
from tls20_server.handshake import _credential_frame
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

    async def test_case_insensitive_sni_keeps_dane_evidence_and_actual_transcript(self):
        original_credentials, client_hello = self.credentials, m.client_hello
        for kind in (0, 2):
            for name in (b"LOCALHOST", b"LoCaLhOsT"):
                for retry, compression in ((False, ()), (True, (1,))):
                    with self.subTest(kind=kind, name=name, retry=retry):
                        self.credentials = original_credentials
                        self.cache = TicketCache()
                        policy = self.configure(kind)
                        sent = []
                        def offer(*args, **kwargs):
                            hello = client_hello(*args, **kwargs)
                            current = m.extension(0, m._vec(b"\x00" + m._vec(b"localhost", 2), 2))
                            actual = m.extension(0, m._vec(b"\x00" + m._vec(name, 2), 2))
                            self.assertIn(current, hello)
                            hello = hello.replace(current, actual)
                            sent.append(hello)
                            return hello
                        with patch.object(m, "client_hello", offer):
                            channel = await self.connect(credential_policy=policy,
                                server_certificate_types=(kind,), force_retry=retry,
                                certificate_compression=compression)
                        self.assertFalse(channel.resumed)
                        self.assertTrue(channel.peer_authenticated)
                        self.assertIn(59, dict(channel.certificate_extensions[0]))
                        self.assertEqual(channel.handshake_transcript, self.channels[-1].handshake_transcript)
                        self.assertEqual(len(sent), 2 if retry else 1)
                        self.assertIn(sent[-1], channel.handshake_transcript)
                        for hello in sent:
                            parsed = m.parse_client_hello(hello[4:])
                            self.assertEqual(parsed.name, "localhost")
                            self.assertIn(name, dict(parsed.extension_values)[0])
                        await channel.send(b"DANE authenticated application")
                        self.assertEqual(await channel.recv(), b"DANE authenticated application")

    async def test_dnssec_evidence_selection_preserves_service_and_sni_validation(self):
        self.configure(2)
        auth, traffic = c.X25519PrivateKey.generate(), c.X25519PrivateKey.generate()
        hello = m.client_hello(c.public_bytes(auth), c.public_bytes(traffic), "localhost", bytes(32),
            extra_extensions=((59, (343).to_bytes(2, "big")),))
        offered = dict(m.parse_client_hello(hello[4:]).extension_values)
        for changed, remove in (({0: m._vec(b"\x00" + m._vec(b"OTHER.TEST", 2), 2)}, None),
                                ({59: (443).to_bytes(2, "big")}, None), ({}, 0), ({}, 59)):
            with self.subTest(changed=changed, remove=remove):
                values = {**offered, **changed}
                if remove is not None:
                    values.pop(remove)
                response = _credential_frame(self.credentials, offer_extensions=values.items())
                _, metadata = m.parse_certificate(response[4:], details=True)
                self.assertNotIn(59, dict(metadata[0]))
        for malformed in (offered[0][:-1], offered[0] + b"\0",
                          m._vec(b"\x00" + m._vec(b"LOCALHOST\0", 2), 2)):
            with self.subTest(malformed=malformed), self.assertRaises(ProtocolError):
                _credential_frame(self.credentials, offer_extensions={**offered, 0: malformed}.items())

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
