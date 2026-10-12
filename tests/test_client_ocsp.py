"""Real OCSP evidence is negotiated and validated for initial/PHA client auth."""

import asyncio
from dataclasses import replace
from datetime import timedelta
import unittest
from unittest.mock import patch

from cryptography import x509
from cryptography.x509 import ocsp
from cryptography.x509.oid import ExtendedKeyUsageOID

from tls20_server import messages as m
from tls20_server.credential_evidence import CredentialEvidencePolicy
from tls20_server.credential_profiles import CredentialPolicy
from tls20_server.errors import ProtocolError
from tls20_server.handshake import Wire, server_handshake
from tls20_server.pki import Credentials
from tls20_server.tickets import TicketCache
from tests import test_sessions, test_credential_profiles
from tests.test_pki import issue, der


class ClientOcspTests(unittest.IsolatedAsyncioTestCase):
    accept = test_sessions.SessionTests.accept
    handle = test_sessions.SessionTests.handle
    connect = test_sessions.SessionTests.connect
    asyncTearDown = test_sessions.SessionTests.asyncTearDown

    async def asyncSetUp(self):
        await test_sessions.SessionTests.asyncSetUp(self)
        fixture = self.fixture = test_credential_profiles.CredentialProfileTests()
        fixture.setUp()
        fixture.leaf = issue(fixture.key, fixture.ca_key, fixture.name, fixture.ca_name, eku=False,
            extra=[(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), False),
                   (x509.TLSFeature([x509.TLSFeatureType.status_request]), False)])
        self.credential = self.with_response(fixture.make_ocsp())
        self.policy = CredentialPolicy(trust_roots=(fixture.root,),
            authorize_client=lambda material, evidence: material[0] == self.credential.chain_der[0],
            evidence_validator=CredentialEvidencePolicy(require_ocsp=True))
        self.server_options.update(client_credential_policy=self.policy, require_client_auth=True,
            client_certificate_evidence_extensions=((5, b""),), certificate_compression=())

    def with_response(self, response):
        extensions = (((5, b"\x01" + len(response).to_bytes(3, "big") + response),), ()) if response else ()
        return Credentials([der(self.fixture.leaf), der(self.fixture.root)], self.fixture.key,
                           entry_extensions=extensions)

    def invalid_credentials(self):
        good = self.fixture.make_ocsp()
        revoked = self.fixture.make_ocsp(status=ocsp.OCSPCertStatus.REVOKED)
        unknown = self.fixture.make_ocsp(status=ocsp.OCSPCertStatus.UNKNOWN)
        original_now = self.fixture.now
        self.fixture.now -= timedelta(days=2)
        expired = self.fixture.make_ocsp()
        self.fixture.now = original_now
        original_leaf = self.fixture.leaf
        self.fixture.leaf = issue(self.fixture.key, self.fixture.ca_key, self.fixture.name, self.fixture.ca_name)
        unrelated = self.fixture.make_ocsp()
        self.fixture.leaf = original_leaf
        return (("missing", self.with_response(None)),
                ("signature", self.with_response(good[:-1] + bytes((good[-1] ^ 1,)))),
                ("revoked", self.with_response(revoked)), ("unknown", self.with_response(unknown)),
                ("expired", self.with_response(expired)), ("CertID", self.with_response(unrelated)))

    async def test_initial_and_resumed_identity_validate_real_staple(self):
        frames, original = [], Wire.send_frame
        async def capture(wire, frame, state=None):
            frames.append((wire.writer in self.client_writers, frame))
            return await original(wire, frame, state)
        with patch.object(Wire, "send_frame", capture):
            first = await self.connect(client_credentials=self.credential)
            second = await self.connect(client_credentials=self.credential, early_data=b"authorized OCSP identity")
        self.assertFalse(first.resumed)
        self.assertTrue(second.resumed)
        self.assertTrue(second.early_data_accepted)
        self.assertEqual(self.channels[-1].authenticated_client, tuple(self.credential.chain_der))
        requests = [m.parse_certificate_request(frame[4:], details=True)[3]
                    for client, frame in frames if not client and frame[0] == 13]
        self.assertEqual(len(requests), 1)
        self.assertEqual(requests[0][5], b"")
        certificates = [m.parse_certificate(frame[4:], details=True)[1]
                        for client, frame in frames if client and frame[0] == 11]
        self.assertEqual(dict(certificates[0][0])[5], dict(self.credential.entry_extensions[0])[5])
        self.assertFalse(self.errors)

    async def test_initial_rejects_missing_invalid_and_stale_client_evidence(self):
        for name, credential in self.invalid_credentials():
            with self.subTest(evidence=name):
                self.cache = TicketCache()
                before = len(self.channels)
                with self.assertRaises(ProtocolError):
                    await self.connect(client_credentials=credential)
                self.assertEqual(len(self.channels), before)

    async def test_resumption_rechecks_current_ocsp_before_accepting_early_data(self):
        await self.connect(client_credentials=self.credential)
        self.server_options["client_credential_policy"] = replace(self.policy,
            now=self.fixture.now + timedelta(hours=2))
        with self.assertRaises(ProtocolError):
            await self.connect(client_credentials=self.credential, early_data=b"must not be authorized")
        self.assertFalse(self.early)

    async def prepare_pha(self):
        # No OCSP request on the initial handshake: the configured staple is
        # omitted, not sent unsolicited and not an obstacle to using the key.
        self.server_options["client_certificate_evidence_extensions"] = ()
        self.server_options["client_credential_policy"] = replace(self.policy,
            evidence_validator=CredentialEvidencePolicy())
        client = await self.connect(client_credentials=self.credential, post_handshake_auth=True)
        return client, self.channels[-1]

    async def test_pha_real_staple_and_per_request_offer_isolation(self):
        client, server = await self.prepare_pha()
        requests, certificates, original = [], [], Wire.send_frame
        async def capture(wire, frame, state=None):
            if frame[0] == 13:
                requests.append(m.parse_certificate_request(frame[4:], details=True))
            elif wire.writer in self.client_writers and frame[0] == 11:
                context = m._Reader(frame[4:]).vector(1)
                certificates.append((context, m.parse_certificate(frame[4:], context=context, details=True)[1]))
            return await original(wire, frame, state)
        with patch.object(Wire, "send_frame", capture):
            requested = await server.request_client_auth(required=True, certificate_evidence_extensions=((5, b""),))
            omitted = await server.request_client_auth(required=True, certificate_evidence_extensions=())
            await client.send(b"drive PHA")
            self.assertEqual(await asyncio.wait_for(client.recv(), 2), b"drive PHA")
            for future in (requested, omitted):
                self.assertEqual(await asyncio.wait_for(future, 2), tuple(self.credential.chain_der))
        by_context = {context: dict(metadata[0]) for context, metadata in certificates}
        self.assertIn(5, by_context[requests[0][0]])
        self.assertNotIn(5, by_context[requests[1][0]])
        self.assertNotIn(5, dict(server.client_auth_offers))
        self.assertFalse(self.errors)

    async def test_pha_inherits_initial_ocsp_offer(self):
        client = await self.connect(client_credentials=self.credential, post_handshake_auth=True)
        server = self.channels[-1]
        pending = await server.request_client_auth(required=True)
        self.assertEqual(next(iter(server.pending_client_auth.values()))["offers"][5], b"")
        await client.send(b"inherited OCSP request")
        self.assertEqual(await asyncio.wait_for(client.recv(), 2), b"inherited OCSP request")
        self.assertEqual(await asyncio.wait_for(pending, 2), tuple(self.credential.chain_der))

    async def test_pha_rejects_missing_invalid_and_stale_evidence(self):
        for name, credential in self.invalid_credentials():
            with self.subTest(evidence=name):
                self.cache = TicketCache()
                client, server = await self.prepare_pha()
                client.client_credentials = credential
                server.client_credential_policy = self.policy
                pending = await server.request_client_auth(required=True, certificate_evidence_extensions=((5, b""),))
                await client.send(b"drive rejected PHA")
                with self.assertRaises(ProtocolError):
                    # Application echo may precede the failed PHA response.
                    while await asyncio.wait_for(client.recv(), 2) is not None:
                        pass
                self.assertTrue(server.closed)
                self.assertTrue(pending.cancelled())
                self.assertFalse(server.pending_client_auth)

    async def test_invalid_requests_fail_locally_without_aborting_other_pha(self):
        client, server = await self.prepare_pha()
        pending = await server.request_client_auth()
        invalid = (((5, b"\x01\0\0\0\0"),), ((5, b""), (5, b"")), ((18, b""),),
                   ((52, b""),), ((5, bytearray()),), (5,), None)
        for offer in invalid:
            with self.subTest(offer=offer):
                # None means inherit on PHA, but is not a valid initial iterable.
                with self.assertRaises(ValueError):
                    await server_handshake(None, None, None, "localhost",
                        client_credential_policy=self.policy, client_certificate_evidence_extensions=offer)
                if offer is not None:
                    with self.assertRaises(ValueError):
                        await server.request_client_auth(certificate_evidence_extensions=offer)
                    self.assertFalse(server.closed)
                    self.assertFalse(pending.done())
        for policy, types in ((None, (0,)), (replace(self.policy, evidence_validator=None), (0,)),
                              (self.policy, (0, 2)), (self.policy, (2,))):
            with self.assertRaises(ValueError):
                await server_handshake(None, None, None, "localhost", client_credential_policy=policy,
                    client_certificate_types=types, client_certificate_evidence_extensions=((5, b""),))
        server.abort()


if __name__ == "__main__":
    unittest.main()
