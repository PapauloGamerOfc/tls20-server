"""Optional CT policy cannot authorize malformed authenticator framing."""

import unittest
from unittest.mock import patch

from tls20_server import application_auth as a, crypto as c
from tls20_server.credential_evidence import CredentialEvidencePolicy
from tls20_server.credential_profiles import CredentialPolicy
from tls20_server.errors import ProtocolError
from tests import test_authenticator_feature_lifecycle as lifecycle


class AuthenticatorEvidenceEnvelopeTests(unittest.IsolatedAsyncioTestCase):
    setup_pair = lifecycle.AuthenticatorFeatureLifecycleTests.setup_pair
    live_pair = lifecycle.AuthenticatorFeatureLifecycleTests.live_pair

    def pair(self, role, kind, spontaneous=False):
        verifier, prover, credentials, base_validator = self.live_pair(role)
        if spontaneous:
            offers = verifier.channel.local_capabilities + ((kind, b''),)
            verifier.channel.local_capabilities = prover.channel.peer_capabilities = offers
        else:
            offers = ()
        # Use the same production PKIX/evidence adapter as an application.
        # The optional CT policy supplies no trusted log and requires no vote.
        # setup_pair retains the root inside the adapter's CredentialPolicy;
        # obtain that exact policy from the validator closure, without changing
        # trust or relying on a validator that blindly authorizes the identity.
        policy = next(cell.cell_contents for cell in base_validator.__closure__
                      if isinstance(cell.cell_contents, CredentialPolicy))
        from dataclasses import replace
        policy = replace(policy, evidence_validator=CredentialEvidencePolicy(offered_extensions=(kind,)))
        validator = a.credential_validator(policy, role=role, authorize=lambda identity: True,
                                           spontaneous_offers=offers)
        return verifier, prover, credentials, validator

    async def exercise(self, role, kind, body, *, valid, spontaneous=False):
        verifier, prover, credentials, validator = self.pair(role, kind, spontaneous)
        request = None if spontaneous else verifier.request(extra_extensions=((kind, b''),))
        unrelated = verifier.request()
        metadata = (((kind, body),),) + ((),) * (len(credentials.chain_der) - 1)
        if valid:
            wire = prover.authenticate(credentials, request=request, entry_extensions=metadata)
        else:
            # A malicious peer can encode bad syntax but a valid MAC/Finished.
            # Disable only its local envelope preflight while generating wire;
            # the actual receiver and its trust policy remain unmodified.
            with patch('tls20_server.credential_evidence.check_evidence_envelope'):
                wire = prover.authenticate(credentials, request=request, entry_extensions=metadata)
        states = []
        state_type = a._ValidationState
        def capture(*args):
            state = state_type(*args)
            states.append(state)
            return state
        before = bytes(verifier.channel.wire.writer.data)
        with patch.object(a, '_ValidationState', side_effect=capture), patch.object(verifier, '_keys', wraps=verifier._keys) as keys:
            if valid:
                self.assertTrue((await verifier.validate(wire, validator)).authenticated)
            else:
                caught = None
                try:
                    await verifier.validate(wire, validator)
                except ProtocolError as error:
                    caught = error
                self.assertIsNotNone(caught)
                self.assertEqual(lifecycle.protocol_locals(caught), [])
                keys.assert_not_called()  # No derived exporter secret retained.
        self.assertEqual(len(states), 1)
        self.assertIsNone(states[0].private)
        self.assertTrue(states[0].closed.done())
        self.assertFalse(verifier._inflight)
        self.assertEqual(len(verifier._pending), 1)  # Only the unrelated request.
        self.assertFalse(verifier.channel.closed)
        self.assertEqual(bytes(verifier.channel.wire.writer.data), before)  # No TLS alert.
        with self.assertRaises(ProtocolError):
            await verifier.validate(wire, validator, request=request)
        # Bad evidence consumes only its context. Ordinary TLS data and another
        # authenticating request remain usable on the same connection.
        await verifier.channel.send(b'traffic remains usable')
        record = bytes(verifier.channel.wire.writer.data)[len(before):]
        decoder = c.RecordState(bytes(32), 'open')
        try:
            self.assertEqual(decoder.open(record), (b'traffic remains usable', 23))
        finally:
            decoder.close()
        response = prover.authenticate(credentials, request=unrelated)
        self.assertTrue((await verifier.validate(response, validator)).authenticated)
        self.assertFalse(verifier._pending)

    async def test_malformed_optional_ct_rejects_both_roles_and_spontaneous(self):
        cases = [(18, body) for body in (b'', b'\0', b'\0\0', b'\0\2\0\0', b'\0\3\0\2\xff')]
        cases += [(52, body) for body in (b'\0', b'\0\0', b'\0\2\0\0', b'\0\3\0\1\xff', b'\0\3\0\2\xff')]
        for role, spontaneous in (('server', False), ('client', False), ('server', True)):
            for kind, body in cases:
                with self.subTest(role=role, spontaneous=spontaneous, kind=kind, body=body):
                    await self.exercise(role, kind, body, valid=False, spontaneous=spontaneous)

    async def test_well_framed_unknown_versions_and_empty_v2_response_remain_valid(self):
        for role, spontaneous in (('server', False), ('client', False), ('server', True)):
            for kind, body in ((18, b'\0\3\0\1\xff'), (52, b'\0\4\0\2\xff\xff'), (52, b'')):
                with self.subTest(role=role, spontaneous=spontaneous, kind=kind, body=body):
                    await self.exercise(role, kind, body, valid=True, spontaneous=spontaneous)


if __name__ == '__main__':
    unittest.main()
