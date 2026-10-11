"""MAC-based exported authenticators: direction, trust, replay and lifetimes."""

import asyncio
import hashlib
import hmac
import unittest
from dataclasses import replace
from types import SimpleNamespace
from unittest.mock import patch

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, x25519
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from tls20_server import crypto as c, messages as m
from tls20_server.application_auth import (
    AuthenticatorManager, AuthorizedIdentity, credential_validator, parse_request,
)
from tls20_server.errors import ProtocolError
from tls20_server.lab import generate_lab_credentials
from tls20_server.credential_profiles import CredentialPolicy
from tls20_server.credential_selection import encode_oid_filters
from tls20_server.pki import Credentials
from tests.test_pki import issue, der


def endpoint(role, root, private, peer, suite=0x1301):
    offers = ((50, m._vec(b"\x08\x07\x04\x03", 2)),)
    return SimpleNamespace(
        role=role, cipher_suite=suite, closed=False, handshake_completed=True, native_provider=None,
        enable_authenticators=True, auth_share_secret=private, peer_auth_share=peer,
        local_capabilities=offers, peer_capabilities=offers,
        exporter=lambda label, context=b"", length=32: c.exporter(
            root, label, context, length, c.suite(suite).hash_name),
    )


class AuthenticatorTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.credentials, self.root_cert = generate_lab_credentials("localhost")
        self.secret = bytes(range(32))
        self.share = x25519.X25519PrivateKey.generate()
        self.client_channel = endpoint("client", self.secret, self.share, b"")
        self.server_channel = endpoint("server", self.secret, None, c.public_bytes(self.share))
        self.client = AuthenticatorManager(self.client_channel)
        self.server = AuthenticatorManager(self.server_channel)
        self.validations = 0

    def policy(self, certificate, request):
        self.validations += 1
        if certificate.chain != tuple(self.credentials.chain_der):
            raise ProtocolError("unapproved additional identity")
        # The production caller must validate chain, status, role and scope.
        # This test deliberately pins the complete exact freshly minted chain.
        public = x509.load_der_x509_certificate(certificate.chain[0]).public_key()
        return AuthorizedIdentity(public, "authorized test identity")

    async def test_production_credential_adapter_requires_path_name_and_scope(self):
        from dataclasses import replace
        from tls20_server.credential_profiles import CredentialPolicy
        policy = CredentialPolicy(trust_roots=(self.root_cert,), peer_name="localhost",
                                  revocation_policy="offline")
        for selected, permitted, succeeds in (
                (policy, True, True), (policy, False, False),
                (replace(policy, peer_name="other.example"), True, False),
                (replace(policy, trust_roots=()), True, False)):
            request = self.client.request()
            response = self.server.authenticate(self.credentials, request=request)
            validator = credential_validator(selected, role="server", authorize=lambda identity: permitted)
            if succeeds:
                result = await self.client.validate(response, validator)
                self.assertEqual(result.identity, "localhost")
            else:
                with self.assertRaises(ProtocolError):
                    await self.client.validate(response, validator)

    async def test_spontaneous_adapter_uses_current_offers(self):
        from tls20_server.credential_profiles import CredentialPolicy
        policy = CredentialPolicy(trust_roots=(self.root_cert,), peer_name="localhost",
                                  revocation_policy="offline")
        validator = credential_validator(policy, role="server", authorize=lambda identity: True,
                                        spontaneous_offers=self.client_channel.local_capabilities)
        response = self.server.authenticate(self.credentials)
        self.assertTrue((await self.client.validate(response, validator)).authenticated)
        response = self.server.authenticate(self.credentials)
        without_offers = credential_validator(policy, role="server", authorize=lambda identity: True)
        with self.assertRaises(ProtocolError):
            await self.client.validate(response, without_offers)

    async def test_requested_server_identity_and_context_consumption(self):
        request = self.client.request(context=b"server identity")
        parsed = parse_request(request)
        self.assertEqual(parsed.role, "server")
        self.assertIn(0xff02, dict(parsed.extensions))
        response = self.server.authenticate(self.credentials, request=request)
        result = await self.client.validate(response, self.policy)
        self.assertTrue(result.authenticated)
        self.assertEqual(result.identity, "authorized test identity")
        with self.assertRaises(ProtocolError):
            await self.client.validate(response, self.policy)
        self.assertEqual(self.validations, 1)

    async def test_requested_client_identity_and_directional_exporters(self):
        request = self.server.request(context=b"client identity")
        parsed = parse_request(request)
        self.assertEqual(parsed.role, "client")
        self.assertIn(0xff03, dict(parsed.extensions))
        response = self.client.authenticate(self.credentials, request=request)
        self.assertTrue((await self.server.validate(response, self.policy)).authenticated)
        with self.assertRaises(ProtocolError):
            self.server.authenticate(self.credentials, request=request)

    async def test_requested_oid_filters_select_credentials_or_authenticated_refusal(self):
        ca = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Authenticator filter CA")])
        root = issue(ca, ca, name, name, ca=True)
        for role, verifier, prover, eku in (
                ("server", self.client, self.server, ExtendedKeyUsageOID.SERVER_AUTH),
                ("client", self.server, self.client, ExtendedKeyUsageOID.CLIENT_AUTH)):
            private = x25519.X25519PrivateKey.generate()
            leaf = issue(private, ca, name, name, hostname="localhost", eku=False,
                         extra=[(x509.ExtendedKeyUsage([eku]), False)])
            credentials = Credentials([der(leaf)], private)
            policy = CredentialPolicy(trust_roots=(root,), peer_name="localhost",
                revocation_policy="offline", authorize_client=lambda material, evidence: material == (der(leaf),))
            validator = credential_validator(policy, role=role, authorize=lambda identity: True)
            for oid, requirement, accepted in (
                    ("2.5.29.37", x509.ExtendedKeyUsage([eku]), True),
                    ("2.5.29.37", b"", True),
                    ("2.5.29.37", x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CODE_SIGNING]), False),
                    ("2.5.29.15", x509.KeyUsage(True, False, False, False, False, False, False, False, False), False),
                    ("1.2.3.4", b"", True)):
                with self.subTest(role=role, oid=oid, accepted=accepted):
                    request = verifier.request(extra_extensions=[(48, encode_oid_filters([(oid, requirement)]))])
                    response = prover.authenticate(credentials, request=request, entry_extensions=[()])
                    self.assertEqual(response[0], 11 if accepted else 20)
                    result = await verifier.validate(response, validator, request=request)
                    self.assertEqual(result.authenticated, accepted)
                    if not accepted:
                        self.assertIsNone(result.identity)
                        self.assertIsNone(result.certificate)

    async def test_peer_cannot_bypass_authenticator_oid_filters(self):
        requirement = encode_oid_filters([
            ("2.5.29.37", x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CODE_SIGNING]))])
        for verifier, prover in ((self.client, self.server), (self.server, self.client)):
            request = verifier.request(extra_extensions=[(48, requirement)])
            # Simulate a nonconforming peer: its proof and Finished are valid,
            # but its certificate fails this request's mandatory EKU filter.
            with patch("tls20_server.application_auth.match_credentials", return_value=True):
                response = prover.authenticate(self.credentials, request=request)
            with self.assertRaisesRegex(ProtocolError, "OID filters"):
                await verifier.validate(response, self.policy, request=request)
            self.assertFalse(verifier._pending)
            with self.assertRaises(ProtocolError):
                await verifier.validate(response, self.policy, request=request)
        self.assertEqual(self.validations, 0)

    async def test_path_algorithm_selection_refuses_incompatible_requested_identity(self):
        for verifier, prover in ((self.client, self.server), (self.server, self.client)):
            for algorithms, accepted in (((0x0807,), True), ((0x0403,), False), ((0xaaaa,), False)):
                with self.subTest(role=prover.channel.role, algorithms=algorithms):
                    request = verifier.request(certificate_algorithms=algorithms)
                    response = prover.authenticate(self.credentials, request=request)
                    self.assertEqual(response[0], 11 if accepted else 20)
                    result = await verifier.validate(response, self.policy, request=request)
                    self.assertEqual(result.authenticated, accepted)
                    if not accepted:
                        self.assertIsNone(result.identity)
                        self.assertIsNone(result.certificate)
                    with self.assertRaises(ProtocolError):
                        await verifier.validate(response, self.policy, request=request)
        self.assertEqual(self.validations, 2)
        self.server_channel.peer_capabilities = ((50, m._vec(b"\x04\x03", 2)),)
        with self.assertRaisesRegex(ProtocolError, "no acceptable spontaneous"):
            self.server.authenticate(self.credentials)

    async def test_delegated_selection_uses_independent_current_path_and_grant_offers(self):
        from tests.test_credential_profiles import CredentialProfileTests
        fixture = CredentialProfileTests(); fixture.setUp()
        for role, verifier, prover in (("server", self.client, self.server), ("client", self.server, self.client)):
            parent, grant = fixture.parent_and_grant(role=role)
            credentials = Credentials([der(parent)], fixture.key)
            entries = (((34, grant),),)
            policy = replace(fixture.policy, authorize_client=lambda material, evidence: True)
            validator = credential_validator(policy, role=role, authorize=lambda identity: True)
            for path, signing, accepted in ((0x0403, 0x0807, True), (0x0807, 0x0807, False),
                    (0x0403, 0x0403, False), (0x0403, 0xaaaa, False), (0x0403, None, False)):
                with self.subTest(role=role, path=path, signing=signing):
                    extra = () if signing is None else (
                        (34, m._vec((0xfe00 if role == "server" else 0xfe01).to_bytes(2, "big"), 2)),
                        (0xff04, m._vec(signing.to_bytes(2, "big"), 2)))
                    request = verifier.request(certificate_algorithms=(path,), extra_extensions=extra)
                    response = prover.authenticate(credentials, request=request, entry_extensions=entries)
                    self.assertEqual(response[0], 11 if accepted else 20)
                    result = await verifier.validate(response, validator, request=request)
                    self.assertEqual(result.authenticated, accepted)
            # Spontaneous identities obey current ClientHello offers too.
            if role == "server":
                prover.channel.peer_capabilities = ((50, m._vec(b"\x04\x03", 2)),
                    (34, m._vec(b"\xfe\x00", 2)), (0xff04, m._vec(b"\x04\x03", 2)))
                with self.assertRaisesRegex(ProtocolError, "no acceptable spontaneous"):
                    prover.authenticate(credentials, entry_extensions=entries)
            # A malformed grant is a local error, not an unsupported identity.
            request = verifier.request(certificate_algorithms=(0x0403,))
            with self.assertRaises(ProtocolError):
                prover.authenticate(credentials, request=request, entry_extensions=(((34, grant[:-1]),),))

    async def test_selection_does_not_relax_malformed_requests_or_receiver_validation(self):
        from tls20_server.application_auth import _frame
        policy = CredentialPolicy(trust_roots=(self.root_cert,), peer_name="localhost", revocation_policy="offline")
        request = self.client.request(certificate_algorithms=(0x0403,))
        with patch("tls20_server.application_auth._credential_matches_algorithms", return_value=True):
            response = self.server.authenticate(self.credentials, request=request)
        validator = credential_validator(policy, role="server", authorize=lambda identity: True)
        with self.assertRaisesRegex(ProtocolError, "certificate signature was not offered"):
            await self.client.validate(response, validator, request=request)
        for algorithms in (b"\0\0", b"\0\x01\x08", b"\0\x02\xfe\0"):
            malformed = _frame(17, m._vec(b"malformed", 1) + m._vec(
                m.extension(50, algorithms) + m.extension(0xff02, c.public_bytes(self.share)), 2))
            with self.assertRaises(ProtocolError):
                self.server.authenticate(self.credentials, request=malformed)

    async def test_spontaneous_ocsp_selection_and_validation_use_actual_clienthello(self):
        from tests.test_status_request import StatusRequestTests, nonce_extensions
        from tls20_server.application_auth import _parse_certificate
        from tls20_server.credential_evidence import CredentialEvidencePolicy
        from tls20_server.credential_selection import _oid_der, _length
        from tls20_server.status_request import encode_status_request
        fixture = StatusRequestTests(); fixture.setUp()
        evidence = CredentialEvidencePolicy(require_ocsp=True, offered_extensions=(5,))
        policy = replace(fixture.fixture.policy, revocation_policy="require-evidence", evidence_validator=evidence)
        wrong_responder = b"\xa2\x16\x04\x14" + bytes(20)
        critical = b"\x30" + _length(b"\x30" + _length(_oid_der("1.2.3.4") + b"\x01\x01\xff\x04\x00"))
        for status, accepted in ((fixture.request, True),
                (encode_status_request(request_extensions=nonce_extensions(b"different nonce")), False),
                (encode_status_request((wrong_responder,)), False),
                (encode_status_request(request_extensions=critical), False), (b"\x02", False)):
            with self.subTest(status=status, accepted=accepted):
                offers = ((50, m._vec(b"\x04\x03", 2)), (5, status))
                self.client_channel.local_capabilities = self.server_channel.peer_capabilities = offers
                validator = credential_validator(policy, role="server", authorize=lambda identity: True,
                                                   spontaneous_offers=offers)
                response = self.server.authenticate(fixture.credential, entry_extensions=fixture.credential.entry_extensions)
                end = 4 + int.from_bytes(response[1:4], "big")
                identity = _parse_certificate(response[4:end])
                self.assertEqual(5 in dict(identity.extensions[0]), accepted)
                if accepted:
                    self.assertTrue((await self.client.validate(response, validator)).authenticated)
                else:
                    with self.assertRaisesRegex(ProtocolError, "OCSP staple is absent"):
                        await self.client.validate(response, validator)
                    # A nonconforming peer can still sign a mismatched staple.
                    # The receiver must independently enforce the actual offer.
                    with patch("tls20_server.status_request.response_matches_request", return_value=True):
                        malicious = self.server.authenticate(fixture.credential,
                            entry_extensions=fixture.credential.entry_extensions)
                    with self.assertRaisesRegex(ProtocolError, "actual authenticator request"):
                        await self.client.validate(malicious, validator)

    async def test_requested_ocsp_uses_empty_cr_framing_in_both_directions(self):
        from tests.test_status_request import StatusRequestTests
        from tls20_server.credential_evidence import CredentialEvidencePolicy
        from tls20_server.application_auth import _frame
        for role, verifier, prover in (("server", self.client, self.server), ("client", self.server, self.client)):
            fixture = StatusRequestTests(); fixture.setUp()
            if role == "client":
                f = fixture.fixture
                f.leaf = issue(f.key, f.ca_key, f.name, f.ca_name, eku=False,
                    extra=[(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), False)])
                response = f.make_ocsp()
                staple = b"\x01" + len(response).to_bytes(3, "big") + response
                fixture.credential = Credentials([der(f.leaf), der(f.root)], f.key,
                    entry_extensions=(((5, staple),), ()))
            policy = replace(fixture.fixture.policy, revocation_policy="require-evidence",
                evidence_validator=CredentialEvidencePolicy(require_ocsp=True, offered_extensions=(5,)),
                authorize_client=lambda material, evidence: True)
            request = verifier.request(certificate_algorithms=(0x0403,), extra_extensions=((5, b""),))
            response = prover.authenticate(fixture.credential, request=request,
                                          entry_extensions=fixture.credential.entry_extensions)
            self.assertTrue((await verifier.validate(response, credential_validator(
                policy, role=role, authorize=lambda identity: True), request=request)).authenticated)
            with self.assertRaisesRegex(ProtocolError, "status_request must be empty"):
                verifier.request(extra_extensions=((5, fixture.request),))
            raw = _frame(17 if role == "server" else 13, m._vec(b"bad status framing", 1) + m._vec(
                m.extension(50, m._vec(b"\x04\x03", 2)) + m.extension(5, fixture.request)
                + m.extension(0xff02 if role == "server" else 0xff03, c.public_bytes(self.share)), 2))
            with self.assertRaisesRegex(ProtocolError, "status_request must be empty"):
                prover.authenticate(request=raw)

    async def test_finished_independent_literal_oracle(self):
        request = self.client.request(context=b"oracle")
        response = self.server.authenticate(self.credentials, request=request)
        certificate_length = 4 + int.from_bytes(response[1:4], "big")
        cert = response[:certificate_length]
        cv = response[certificate_length:certificate_length + 40]
        finished = response[certificate_length + 40:]
        context = c.exporter(self.secret, "EXPORTER-server authenticator handshake context", b"", 32)
        key = c.exporter(self.secret, "EXPORTER-server authenticator finished key", b"", 32)
        self.assertEqual(finished, b"\x14\x00\x00\x20" + hmac.digest(key, hashlib.sha256(context + request + cert + cv).digest(), "sha256"))
        self.assertTrue((await self.client.validate(response, self.policy)).authenticated)

    async def test_authenticated_refusal_is_not_identity(self):
        request = self.client.request(context=b"refuse")
        response = self.server.authenticate(request=request)
        self.assertEqual(response[:4], b"\x14\x00\x00\x20")
        with self.assertRaises(ProtocolError):
            await self.client.validate(response, self.policy)
        result = await self.client.validate(response, self.policy, request=request)
        self.assertFalse(result.authenticated)
        self.assertIsNone(result.identity)
        self.assertEqual(self.validations, 0)

    async def test_refusal_rejects_tampered_finished(self):
        request = self.client.request()
        response = self.server.authenticate(request=request)
        with self.assertRaises(ProtocolError):
            await self.client.validate(response[:-1] + bytes((response[-1] ^ 1,)), self.policy, request=request)
        self.assertFalse(self.client._pending)

    async def test_spontaneous_server_requires_explicit_retained_verifier(self):
        response = self.server.authenticate(self.credentials, context=b"spontaneous")
        self.assertTrue((await self.client.validate(response, self.policy)).authenticated)
        response = self.server.authenticate(self.credentials, context=b"no capability")
        self.client_channel.auth_share_secret = None
        with self.assertRaises(ProtocolError):
            await self.client.validate(response, self.policy)
        with self.assertRaises(ProtocolError):
            self.client.authenticate(self.credentials)

    async def test_request_keys_are_independent(self):
        first, second = self.client.request(), self.client.request()
        a, b = parse_request(first), parse_request(second)
        self.assertNotEqual(a.verifier_share, b.verifier_share)
        self.assertNotEqual(a.verifier_share, c.public_bytes(self.share))
        response_b = self.server.authenticate(self.credentials, request=second)
        response_a = self.server.authenticate(self.credentials, request=first)
        self.assertTrue((await self.client.validate(response_b, self.policy)).authenticated)
        self.assertTrue((await self.client.validate(response_a, self.policy)).authenticated)

    async def test_cross_connection_transplant_fails(self):
        request = self.client.request()
        self.server_channel.exporter = endpoint("server", b"x" * 32, None, b"").exporter
        response = self.server.authenticate(self.credentials, request=request)
        with self.assertRaises(ProtocolError):
            await self.client.validate(response, self.policy)

    async def test_no_accepting_exporter_only_forgery(self):
        request = self.client.request()
        response = bytearray(self.server.authenticate(self.credentials, request=request))
        offset = 4 + int.from_bytes(response[1:4], "big")
        response[offset + 8] ^= 1
        context, key = self.server._keys("server")
        response[-32:] = hmac.digest(key, hashlib.sha256(context + request + response[:-36]).digest(), "sha256")
        with self.assertRaisesRegex(ProtocolError, "MAC failed"):
            await self.client.validate(bytes(response), self.policy)

    async def test_policy_must_authorize_effective_x25519_key(self):
        request = self.client.request()
        response = self.server.authenticate(self.credentials, request=request)
        with self.assertRaises(ProtocolError):
            await self.client.validate(response, lambda *_: True)
        with self.assertRaises(ProtocolError):
            await self.client.validate(response, self.policy)

    async def test_sha384_mac_and_finished_lengths(self):
        self.client_channel = endpoint("client", b"a" * 48, self.share, b"", 0x1302)
        self.server_channel = endpoint("server", b"a" * 48, None, c.public_bytes(self.share), 0x1302)
        client, server = AuthenticatorManager(self.client_channel), AuthenticatorManager(self.server_channel)
        request = client.request()
        response = server.authenticate(self.credentials, request=request)
        self.assertEqual(response[-52:-48], b"\x14\x00\x00\x30")
        self.assertTrue((await client.validate(response, self.policy)).authenticated)

    async def test_sm3_uses_negotiated_hash_not_secret_length(self):
        for selected in (0x00c6, 0x00c7):
            with self.subTest(suite=selected):
                client_channel = endpoint("client", self.secret, self.share, b"", selected)
                server_channel = endpoint("server", self.secret, None, c.public_bytes(self.share), selected)
                client, server = AuthenticatorManager(client_channel), AuthenticatorManager(server_channel)
                request = client.request(context=b"SM3")
                response = server.authenticate(self.credentials, request=request)
                context, key = server._keys("server")
                transcript = context + request + response[:-36]
                # Independent Finished oracle: SM3 and SHA-256 both have 32-byte
                # outputs, so accidentally inferring the algorithm from length
                # would make both peers agree on the wrong wire protocol.
                from cryptography.hazmat.primitives import hashes, hmac as native_hmac
                independent_hash=hashes.Hash(hashes.SM3()); independent_hash.update(transcript)
                independent_mac=native_hmac.HMAC(key,hashes.SM3()); independent_mac.update(independent_hash.finalize())
                expected = independent_mac.finalize()
                self.assertEqual(response[-32:], expected)
                self.assertNotEqual(expected, hmac.digest(key, hashlib.sha256(transcript).digest(), "sha256"))
                self.assertTrue((await client.validate(response, self.policy)).authenticated)
                refusal_request = client.request(context=b"SM3 refusal")
                refusal = server.authenticate(request=refusal_request)
                self.assertFalse((await client.validate(refusal, self.policy, request=refusal_request)).authenticated)

    async def test_close_during_async_authorization_cannot_return_identity(self):
        request = self.client.request()
        response = self.server.authenticate(self.credentials, request=request)
        async def policy(*args):
            self.client.close()
            await asyncio.sleep(0)
            return self.policy(*args)
        with self.assertRaises(ProtocolError):
            await self.client.validate(response, policy)

    async def test_context_shared_across_both_directions_and_cancel(self):
        request = self.client.request(context=b"same")
        collision = AuthenticatorManager(self.server_channel).request(context=b"same")
        with self.assertRaises(ProtocolError):
            self.client.authenticate(self.credentials, request=collision)
        self.client.cancel(request)
        self.assertFalse(self.client._pending)
        with self.assertRaises(ProtocolError):
            self.client.request(context=b"same")

    async def test_limits_do_not_evict_consumed_contexts(self):
        client = AuthenticatorManager(self.client_channel, max_contexts=1)
        request = client.request(context=b"one")
        client.cancel(request)
        with self.assertRaises(ProtocolError):
            client.request(context=b"two")

    async def test_gate_before_finished_and_after_close(self):
        self.client_channel.handshake_completed = False
        with self.assertRaises(ProtocolError):
            self.client.request()
        self.client_channel.handshake_completed = True
        self.client_channel.closed = True
        with self.assertRaises(ProtocolError):
            self.client.request()

    async def test_invalid_requests_and_unsolicited_extensions(self):
        for extensions in (((13, b"\0\2\x08\x07"),), ((0xff03, b"x" * 32),),
                           ((34, b"\0\2\xfe\0"),), ((50, b"\0\2\x08\x07"),)):
            with self.subTest(extensions=extensions), self.assertRaises(ProtocolError):
                self.client.request(extra_extensions=extensions)
        request = self.client.request()
        with self.assertRaises(ProtocolError):
            self.server.authenticate(self.credentials, request=request,
                                     entry_extensions=[((5, b"unrequested"),)] * len(self.credentials.chain_der))


if __name__ == "__main__":
    unittest.main()
