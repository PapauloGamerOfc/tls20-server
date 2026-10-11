"""Selection extensions cross the actual encrypted initial and PHA flights."""

import asyncio
import unittest
from unittest.mock import patch

from cryptography import x509
from cryptography.x509.oid import ExtensionOID, ExtendedKeyUsageOID

from tests import test_sessions
from tests.test_credential_selection import credential, name
from tls20_server import messages as m
from tls20_server.errors import ProtocolError
from tls20_server.handshake import Wire


class SelectionHandshakeTests(unittest.IsolatedAsyncioTestCase):
    asyncSetUp = test_sessions.SessionTests.asyncSetUp
    asyncTearDown = test_sessions.SessionTests.asyncTearDown
    accept = test_sessions.SessionTests.accept
    handle = test_sessions.SessionTests.handle
    connect = test_sessions.SessionTests.connect

    def provision(self, *credentials):
        # Exact local identity provisioning, not a generic permissive validator.
        def validate(chain):
            if not any(chain == value.chain_der for value in credentials):
                raise ProtocolError("identity was not provisioned")
            return x509.load_der_x509_certificate(chain[0]).public_key()
        self.server_options["client_auth_validator"] = validate

    async def test_initial_ca_preference_selects_candidate_and_isolates_tickets(self):
        one, two = credential("one"), credential("two")
        self.provision(one, two)
        self.server_options.update(require_client_auth=True,
                                   client_certificate_authorities=(name("two"),))
        options = dict(client_credentials=one, client_credential_candidates=(two,))
        first = await self.connect(**options)
        self.assertFalse(first.resumed)
        self.assertEqual(self.channels[-1].authenticated_client, tuple(two.chain_der))
        self.assertTrue((await self.connect(**options)).resumed)
        self.server_options["client_certificate_authorities"] = (name("one"),)
        changed = await self.connect(**options, early_data=b"not the previous identity")
        self.assertFalse(changed.resumed)
        self.assertFalse(changed.early_data_accepted)
        self.assertFalse(self.early)
        self.assertEqual(self.channels[-1].authenticated_client, tuple(one.chain_der))

    async def test_required_oid_filter_selects_matching_candidate(self):
        bad = credential(eku=[ExtendedKeyUsageOID.SERVER_AUTH])
        good = credential(eku=[ExtendedKeyUsageOID.CLIENT_AUTH])
        self.provision(bad, good)
        self.server_options.update(require_client_auth=True,
            client_oid_filters=((ExtensionOID.EXTENDED_KEY_USAGE,
                                 x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH])),))
        await self.connect(client_credentials=bad, client_credential_candidates=(good,))
        self.assertEqual(self.channels[-1].authenticated_client, tuple(good.chain_der))

    async def test_unsatisfied_filter_sends_empty_optional_and_fails_required(self):
        value = credential(eku=[ExtendedKeyUsageOID.SERVER_AUTH])
        self.provision(value)
        self.server_options["client_oid_filters"] = ((ExtensionOID.EXTENDED_KEY_USAGE,
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH])),)
        await self.connect(client_credentials=value)
        self.assertIsNone(self.channels[-1].authenticated_client)
        self.server_options["require_client_auth"] = True
        with self.assertRaises((ProtocolError, OSError, AssertionError)):
            await self.connect(client_credentials=value)
        self.assertTrue(any("required" in error for error in self.errors))

    async def test_pha_can_change_selection_without_promoting_old_tickets(self):
        one, two = credential("one"), credential("two")
        self.provision(one, two)
        client = await self.connect(client_credentials=one, client_credential_candidates=(two,),
                                    post_handshake_auth=True)
        ticket = next(iter(self.store._tickets.values()))
        server = self.channels[-1]
        future = await server.request_client_auth(required=True, certificate_authorities=(name("two"),),
            oid_filters=((ExtensionOID.KEY_USAGE, b""),))
        await client.send(b"drive PHA")
        self.assertEqual(await asyncio.wait_for(client.recv(), 2), b"drive PHA")
        self.assertEqual(await asyncio.wait_for(future, 2), tuple(two.chain_der))
        self.assertEqual(tuple(ticket.client_certificate_chain), tuple(one.chain_der))

    async def test_malformed_request_filter_is_rejected_even_without_credential(self):
        self.provision(credential())
        original = Wire.send_frame
        async def malformed(wire, message, state=None):
            if message[0] == 13:
                context, share, algorithms, extensions = m.parse_certificate_request(message[4:], details=True)
                extras = tuple((kind, value) for kind, value in extensions.items() if kind not in (50, 0xff03))
                message = m.certificate_request(context, share, algorithms,
                    extra_extensions=(*extras, (48, b"\0\x01\xff")))
            return await original(wire, message, state)
        with patch.object(Wire, "send_frame", malformed), self.assertRaises(ProtocolError):
            await self.connect()
        self.assertFalse(self.channels)
