"""TLS Feature requirements are bound to authenticated wire selection state."""

import unittest

from cryptography import x509

from tls20_server.credential_evidence import CredentialEvidencePolicy
from tls20_server.credential_profiles import CredentialPolicy, resolve_peer
from tls20_server.credential_selection import _length
from tls20_server.errors import ProtocolError
from tls20_server.pki import Credentials
from tests import test_credential_profiles as fixtures, test_sessions as sessions
from tests.test_pki import issue, der


class NegotiatedFeatureTests(unittest.IsolatedAsyncioTestCase):
    asyncSetUp = sessions.SessionTests.asyncSetUp
    asyncTearDown = sessions.SessionTests.asyncTearDown
    accept = sessions.SessionTests.accept
    handle = sessions.SessionTests.handle
    connect = sessions.SessionTests.connect

    def require_features(self, features, evidence=None):
        fixture = fixtures.CredentialProfileTests()
        fixture.setUp()
        integers = b""
        for feature in features:
            encoded = feature.to_bytes(max(1, (feature.bit_length() + 8) // 8), "big")
            integers += b"\x02" + _length(encoded)
        extension = x509.UnrecognizedExtension(x509.ObjectIdentifier("1.3.6.1.5.5.7.1.24"),
                                               b"\x30" + _length(integers))
        leaf = issue(fixture.key, fixture.ca_key, fixture.name, fixture.ca_name,
                     hostname="localhost", extra=[(extension, False)] if features else [])
        self.credentials = Credentials([der(leaf), der(fixture.root)], fixture.key)
        self.roots = [fixture.root]
        return CredentialPolicy(trust_roots=tuple(self.roots), peer_name="localhost",
                                evidence_validator=evidence)

    async def test_actual_heartbeat_satisfies_default_policy(self):
        for evidence in (None, CredentialEvidencePolicy(), lambda *args: True):
            with self.subTest(policy=type(evidence).__name__):
                policy = self.require_features((15,), evidence)
                self.server_options["heartbeat_mode"] = 1
                channel = await self.connect(credential_policy=policy, heartbeat_mode=1)
                self.assertTrue(channel.handshake_completed)
                self.assertIn(15, channel.certificate_features)

    async def test_claimed_policy_state_cannot_satisfy_absent_heartbeat(self):
        for evidence in (None, CredentialEvidencePolicy(negotiated_extensions=(15,)), lambda *args: True):
            with self.subTest(policy=type(evidence).__name__):
                policy = self.require_features((15,), evidence)
                with self.assertRaisesRegex(ProtocolError, "mandatory TLS Feature"):
                    await self.connect(credential_policy=policy, heartbeat_mode=1)

    async def test_unoffered_feature_remains_irrelevant(self):
        policy = self.require_features((15, 0x1234), CredentialEvidencePolicy())
        await self.connect(credential_policy=policy, psk_modes=(1, 0))

    async def test_actual_base_hello_and_certificate_proof_features(self):
        # These base CH fields were absent from the old credential-extra list.
        policy = self.require_features((43, 51, 16, 50, 0xff02), CredentialEvidencePolicy())
        await self.connect(credential_policy=policy)

    async def test_retry_cookie_is_satisfied_by_authenticated_hrr(self):
        from tls20_server.retry_cookie import RetryCookiePolicy
        policy = self.require_features((44,), CredentialEvidencePolicy())
        self.server_options["retry_cookie_policy"] = RetryCookiePolicy()
        channel = await self.connect(credential_policy=policy)
        self.assertEqual(channel.certificate_features, (44,))

    async def test_serverhello_keyshare_is_not_inferred_on_psk_only_resumption(self):
        policy = self.require_features((51,), CredentialEvidencePolicy())
        await self.connect(credential_policy=policy, psk_modes=(1, 0))
        # With PSK-only no key_share offer or selection exists, so RFC7633
        # creates no requirement. This is not an inferred successful echo.
        resumed = await self.connect(credential_policy=policy, psk_modes=(0,))
        self.assertTrue(resumed.resumed)

    async def test_compressed_certificate_is_a_selection_but_offer_alone_is_not(self):
        policy = self.require_features((27,), CredentialEvidencePolicy())
        await self.connect(credential_policy=policy, certificate_compression=(1,))
        resumed = await self.connect(credential_policy=policy, certificate_compression=(1,), early_data=b"cached certificate")
        self.assertTrue(resumed.resumed)
        self.assertTrue(resumed.early_data_accepted)
        self.cache._tickets.clear()
        self.server_options["certificate_compression"] = ()
        with self.assertRaisesRegex(ProtocolError, "mandatory TLS Feature"):
            await self.connect(credential_policy=policy, certificate_compression=(1,))

    async def test_newly_offered_mandatory_evidence_cannot_release_early_bytes(self):
        from tls20_server.status_request import encode_status_request
        for feature, offer in ((5, encode_status_request()), (18, b""), (52, b"")):
            for legacy in (False, True):
                with self.subTest(feature=feature, legacy=legacy):
                    policy = self.require_features((feature,), CredentialEvidencePolicy())
                    if legacy:
                        policy = None
                    await self.connect(credential_policy=policy)  # Initially not offered.
                    with self.assertRaisesRegex(ProtocolError, "mandatory TLS Feature"):
                        await self.connect(credential_policy=policy, early_data=b"must not be released",
                            certificate_evidence_extensions=((feature, offer),))
                    self.assertEqual(self.early, [])

    async def test_unilateral_pha_offer_is_not_claimed_as_peer_selection(self):
        policy = self.require_features((49,), CredentialEvidencePolicy(negotiated_extensions=(49,)))
        with self.assertRaisesRegex(ProtocolError, "mandatory TLS Feature"):
            await self.connect(credential_policy=policy, post_handshake_auth=True)

    async def test_resumption_rechecks_feature_and_withholds_early_bytes(self):
        policy = self.require_features((15,), CredentialEvidencePolicy(negotiated_extensions=(15,)))
        self.server_options["heartbeat_mode"] = 1
        first = await self.connect(credential_policy=policy, heartbeat_mode=1)
        self.assertFalse(first.resumed)
        ticket = next(iter(self.cache._tickets.values()))
        self.assertEqual(ticket.certificate_feature_offers, (15,))
        self.assertEqual(ticket.certificate_features, (15,))
        resumed = await self.connect(credential_policy=policy, heartbeat_mode=1, early_data=b"private request")
        self.assertTrue(resumed.resumed)
        self.assertFalse(resumed.early_data_accepted)
        self.assertEqual(self.early, [])
        self.server_options["heartbeat_mode"] = None
        with self.assertRaisesRegex(ProtocolError, "mandatory TLS Feature"):
            await self.connect(credential_policy=policy, heartbeat_mode=1, early_data=b"must not be released")
        self.assertEqual(self.early, [])

    async def test_ordinary_early_data_remains_available(self):
        policy = self.require_features((), CredentialEvidencePolicy())
        await self.connect(credential_policy=policy)
        resumed = await self.connect(credential_policy=policy, early_data=b"ordinary request")
        self.assertTrue(resumed.resumed)
        self.assertTrue(resumed.early_data_accepted)
        self.assertEqual(b"".join(self.early), b"ordinary request")

    async def test_certificate_free_psk_resumption_keeps_early_data(self):
        from tls20_server.psk import ExternalPSK
        key = ExternalPSK(b"no certificate", b"test key material", "localhost")
        self.server_options["external_psks"] = (key,)
        first = await self.connect(external_psk=key)
        self.assertFalse(first.certificate_chain)
        resumed = await self.connect(external_psk=key, early_data=b"PSK-only request")
        self.assertTrue(resumed.resumed)
        self.assertTrue(resumed.early_data_accepted)
        self.assertFalse(resumed.certificate_chain)
        self.assertEqual(b"".join(self.early), b"PSK-only request")

    async def test_auth_share_requirement_is_redundant_on_authenticated_resumption(self):
        policy = self.require_features((0xff02,), CredentialEvidencePolicy())
        await self.connect(credential_policy=policy)
        resumed = await self.connect(credential_policy=policy, early_data=b"authenticated lineage")
        self.assertTrue(resumed.resumed)
        self.assertTrue(resumed.early_data_accepted)
        self.assertEqual(b"".join(self.early), b"authenticated lineage")

    async def test_cached_certificate_requirement_is_redundant_on_resumption(self):
        policy = self.require_features((25,), CredentialEvidencePolicy())
        snapshots = ((0, tuple(self.credentials.chain_der)),)
        await self.connect(credential_policy=policy, cached_certificates=snapshots)
        resumed = await self.connect(credential_policy=policy, cached_certificates=snapshots,
                                     early_data=b"cached credential lineage")
        self.assertTrue(resumed.resumed)
        self.assertTrue(resumed.early_data_accepted)
        self.assertEqual(b"".join(self.early), b"cached credential lineage")

    async def test_legacy_lab_path_does_not_bypass_missing_feature(self):
        self.require_features((15,))
        with self.assertRaisesRegex(ProtocolError, "mandatory TLS Feature"):
            await self.connect(heartbeat_mode=1)
        self.server_options["heartbeat_mode"] = 1
        await self.connect(heartbeat_mode=1)

    def test_direct_resolver_does_not_trust_predeclared_policy_state(self):
        policy = self.require_features((15,), CredentialEvidencePolicy(negotiated_extensions=(15,)))
        with self.assertRaisesRegex(ProtocolError, "mandatory TLS Feature"):
            resolve_peer(self.credentials.chain_der, policy=policy, offered_extensions=(15,))
        resolve_peer(self.credentials.chain_der, policy=policy, offered_extensions=(15,),
                     negotiated_extensions=(15,))


if __name__ == "__main__":
    unittest.main()
