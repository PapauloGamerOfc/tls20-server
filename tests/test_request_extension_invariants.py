"""Mandatory ClientHello pairs and empty CT requests across authentication paths."""

import asyncio
from dataclasses import replace
import unittest
from unittest.mock import patch

from tests import test_application_auth, test_sessions
from tls20_server import messages as m
from tls20_server.application_auth import _frame, parse_request
from tls20_server.credential_cache import cached_request_body
from tls20_server.credential_evidence import CredentialEvidencePolicy
from tls20_server.credential_profiles import CredentialPolicy
from tls20_server.errors import PeerClosed, ProtocolError
from tls20_server.handshake import Wire, _decode_request, _request_extension_block
from tls20_server.psk import ExternalPSK


GROUPS = (10, b"\0\2\0\x1d")
EMPTY_SHARES = (51, b"\0\0")
SHARES = (51, m._vec(b"\0\x1d" + m._vec(b"x" * 32, 2), 2))


def hello(extra=(), *, psk=True):
    return m.client_hello(b"a" * 32, b"", "localhost", b"r" * 32, group=0,
        identity=b"test identity" if psk else b"", binder=b"b" * 32 if psk else b"",
        psk_modes=(0,), extra_extensions=extra)


class RequestExtensionCodecTests(unittest.TestCase):
    def test_group_and_share_pair_is_required_even_with_psk_ke(self):
        for psk in (False, True):
            # Include malformed/unadvertised share bodies: absence is checked
            # before those bodies could produce decode_error/illegal_parameter.
            for extra in ((GROUPS,), (EMPTY_SHARES,), (SHARES,),
                          ((10, b""),), ((51, b""),)):
                with self.subTest(psk=psk, extra=extra):
                    with self.assertRaises(ProtocolError) as caught:
                        m.parse_client_hello(hello(extra, psk=psk)[4:])
                    self.assertEqual(caught.exception.alert, 109)
        for extra in ((), (GROUPS, EMPTY_SHARES), (GROUPS, SHARES)):
            with self.subTest(valid=extra):
                parsed = m.parse_client_hello(hello(extra)[4:])
                self.assertEqual(parsed.psk_modes, (0,))
        with self.assertRaises(ProtocolError) as caught:
            m.parse_client_hello(hello(psk=False)[4:])
        self.assertEqual(caught.exception.alert, 109)

    def test_ct_requests_have_empty_bodies_in_hello_and_plain_or_cached_cr(self):
        for kind in (18, 52):
            for value in (b"", b"\0", b"not an empty request"):
                for context in ("CH", "CR", "cached CR"):
                    with self.subTest(kind=kind, value=value, context=context):
                        extra = ((kind, value), (0xaaaa, b"unknown request bytes"))
                        if context == "CH":
                            parse = lambda: m.parse_client_hello(hello(extra)[4:])
                        else:
                            request = m.certificate_request(b"context", b"v" * 32, extra_extensions=extra)
                            if context == "cached CR":
                                block = _request_extension_block(request)
                                request = m.frame(252, cached_request_body(b"context", block, b"f" * 32))
                                parse = lambda: _decode_request(request, cache_enabled=True, templates=(block,))
                            else:
                                parse = lambda: _decode_request(request)
                        if value:
                            with self.assertRaises(ProtocolError) as caught:
                                parse()
                            self.assertEqual(caught.exception.alert, 50)
                        else:
                            parse()  # Empty CT and unknown-extension payloads are legal.


class RequestExtensionWireTests(unittest.IsolatedAsyncioTestCase):
    asyncSetUp = test_sessions.SessionTests.asyncSetUp
    asyncTearDown = test_sessions.SessionTests.asyncTearDown
    accept = test_sessions.SessionTests.accept
    handle = test_sessions.SessionTests.handle
    connect = test_sessions.SessionTests.connect

    async def exchange(self, extra, expected, **options):
        original, fatal = m.client_hello, Wire.fatal
        alerts = []
        def encode(*args, **kwargs):
            kwargs['extra_extensions'] = (*kwargs.get('extra_extensions', ()), *extra)
            return original(*args, **kwargs)
        async def observe(wire, error, state=None):
            if not isinstance(error, PeerClosed):
                alerts.append((wire.writer in self.client_writers, error.alert))
            return await fatal(wire, error, state)
        self.cache._tickets.clear()
        self.errors.clear()
        with patch.object(m, 'client_hello', encode), patch.object(Wire, 'fatal', observe):
            if expected is not None:
                before = len(self.channels)
                with self.assertRaises(ProtocolError) as caught:
                    await asyncio.wait_for(self.connect(**options), 3)
                self.assertEqual(caught.exception.alert, expected)
                self.assertEqual(alerts, [(False, expected)])  # Real server rejection.
                self.assertEqual(len(self.channels), before)
                return None
            channel = await asyncio.wait_for(self.connect(**options), 3)
            await channel.send(b'authenticated application')
            self.assertEqual(await channel.recv(), b'authenticated application')
            await channel.close()
            self.assertFalse(alerts)
            self.assertFalse(self.errors)
            return channel

    async def test_psk_only_pair_enforced_before_application_traffic(self):
        key = ExternalPSK(b'test device', b'public fixture-only PSK material', 'localhost')
        self.server_options = {'external_psks': (key,)}
        for extra, expected in (((), None), ((GROUPS, EMPTY_SHARES), None),
                                ((GROUPS,), 109), ((EMPTY_SHARES,), 109), ((SHARES,), 109)):
            with self.subTest(extra=extra):
                await self.exchange(extra, expected, external_psk=key, psk_modes=(0,))

    async def test_ct_hello_requests_rejected_with_evidence_support_enabled(self):
        policy = CredentialPolicy(trust_roots=tuple(self.roots), peer_name='localhost',
            revocation_policy='offline', evidence_validator=CredentialEvidencePolicy())
        for kind in (18, 52):
            # CT v2 permits an empty response. A well-framed unknown SCT v1
            # version can be ignored by this explicit zero-log-minimum policy.
            response = b'' if kind == 52 else b'\0\3\0\1\xff'
            metadata = (((kind, response),),) + ((),) * (len(self.credentials.chain_der) - 1)
            self.credentials = replace(self.credentials, entry_extensions=metadata)
            for value in (b'', b'\0', b'not an empty request'):
                with self.subTest(kind=kind, value=value):
                    channel = await self.exchange(((kind, value),), 50 if value else None,
                        credential_policy=policy)
                    if channel is not None:
                        self.assertEqual(channel.certificate_extensions, metadata)


class AuthenticatorCTRequestTests(unittest.IsolatedAsyncioTestCase):
    setUp = test_application_auth.AuthenticatorTests.setUp
    policy = test_application_auth.AuthenticatorTests.policy

    async def test_ct_request_generation_rejects_before_context_consumption(self):
        for verifier, prover in ((self.client, self.server), (self.server, self.client)):
            other = verifier.request()
            before = dict(verifier._pending)
            for kind in (18, 52):
                for value in (b'\0', b'invalid request'):
                    with self.subTest(role=verifier.channel.role, kind=kind, value=value):
                        context = verifier.channel.role.encode('ascii') + bytes((kind,)) + value
                        with self.assertRaises(ProtocolError) as caught:
                            verifier.request(context=context, extra_extensions=((kind, value),))
                        self.assertEqual(caught.exception.alert, 50)
                        self.assertNotIn(context, verifier._used)
                        self.assertEqual(verifier._pending, before)
                        request = verifier.request(context=context, extra_extensions=((kind, b''),))
                        response = prover.authenticate(self.credentials, request=request)
                        self.assertTrue((await verifier.validate(response, self.policy)).authenticated)
            response = prover.authenticate(self.credentials, request=other)
            self.assertTrue((await verifier.validate(response, self.policy)).authenticated)

    async def test_received_ct_request_validated_before_authentication_or_refusal(self):
        for verifier, prover in ((self.client, self.server), (self.server, self.client)):
            for kind in (18, 52):
                for credentials in (None, self.credentials):
                    with self.subTest(role=verifier.channel.role, kind=kind, refusal=credentials is None):
                        request = verifier.request(extra_extensions=((kind, b''), (0xaaaa, b'opaque')))
                        parsed = parse_request(request)
                        values = tuple((code, b'\0' if code == kind else value) for code, value in parsed.extensions)
                        malformed = _frame(request[0], m._vec(parsed.context, 1) + m._vec(
                            b''.join(m.extension(code, value) for code, value in values), 2))
                        pending, used = dict(prover._pending), set(prover._used)
                        with self.assertRaises(ProtocolError) as caught:
                            prover.authenticate(credentials, request=malformed)
                        self.assertEqual(caught.exception.alert, 50)
                        self.assertEqual(prover._pending, pending)
                        self.assertEqual(prover._used, used)
                        response = prover.authenticate(credentials, request=request)
                        retained = verifier._pending[parsed.context]
                        # A malformed explicitly supplied request cannot destroy
                        # the retained key for the correct proof/refusal.
                        with self.assertRaises(ProtocolError):
                            await verifier.validate(response, self.policy, request=malformed)
                        self.assertIs(verifier._pending[parsed.context], retained)
                        self.assertFalse(verifier._inflight)
                        result = await verifier.validate(response, self.policy, request=request)
                        self.assertEqual(result.authenticated, credentials is not None)

    async def test_spontaneous_ct_capabilities_validated_without_burning_context(self):
        for kind in (18, 52):
            with self.subTest(kind=kind):
                original_peer = self.server_channel.peer_capabilities
                original_local = self.client_channel.local_capabilities
                valid = (*original_peer, (kind, b''), (0xaaaa, b'opaque'))
                invalid = (*original_peer, (kind, b'\0'))
                context = b'spontaneous CT' + bytes((kind,))
                self.server_channel.peer_capabilities = invalid
                with self.assertRaises(ProtocolError) as caught:
                    self.server.authenticate(self.credentials, context=context)
                self.assertEqual(caught.exception.alert, 50)
                self.assertNotIn(context, self.server._used)
                self.server_channel.peer_capabilities = valid
                response = self.server.authenticate(self.credentials, context=context)
                self.client_channel.local_capabilities = invalid
                with self.assertRaises(ProtocolError) as caught:
                    await self.client.validate(response, self.policy)
                self.assertEqual(caught.exception.alert, 50)
                self.assertNotIn(context, self.client._used)
                self.assertFalse(self.client._inflight)
                self.client_channel.local_capabilities = valid
                self.assertTrue((await self.client.validate(response, self.policy)).authenticated)
                self.server_channel.peer_capabilities = original_peer
                self.client_channel.local_capabilities = original_local
