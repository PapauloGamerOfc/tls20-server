"""CertificateEntry response solicitation is enforced at the TLS boundary."""
import asyncio
import unittest
from unittest.mock import patch

from cryptography import x509
from cryptography.x509.oid import ExtendedKeyUsageOID

from tests import test_sessions, test_credential_profiles
from tests.test_pki import issue, der
from tls20_server import handshake as h, messages as m
from tls20_server.credential_profiles import CredentialPolicy
from tls20_server.credential_evidence import CredentialEvidencePolicy
from tls20_server.errors import PeerClosed, ProtocolError
from tls20_server.pki import Credentials
from tls20_server.tickets import TicketCache


class CertificateEntryAlertTests(unittest.IsolatedAsyncioTestCase):
    asyncSetUp = test_sessions.SessionTests.asyncSetUp
    asyncTearDown = test_sessions.SessionTests.asyncTearDown
    accept = test_sessions.SessionTests.accept
    handle = test_sessions.SessionTests.handle
    connect = test_sessions.SessionTests.connect

    def client_identity(self):
        fixture = test_credential_profiles.CredentialProfileTests()
        fixture.setUp()
        leaf = issue(fixture.key, fixture.ca_key, fixture.name, fixture.ca_name, eku=False,
                     extra=[(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), False)])
        credential = Credentials([der(leaf), der(fixture.root)], fixture.key)
        policy = CredentialPolicy(trust_roots=(fixture.root,),
                                  authorize_client=lambda material, _: tuple(material) == tuple(credential.chain_der))
        return credential, policy

    async def test_server_extensions_with_legacy_policy_compression_and_cache(self):
        certificate, cached, fatal = m.certificate, h.cached_certificate_body, h.Wire.fatal
        for policy in (False, True):
            for compression, cache in ((False, False), (True, False), (False, True), (True, True)):
                for code in (5, 18, 34, 0xfafa):
                    with self.subTest(policy=policy, compression=compression, cache=cache, code=code):
                        self.cache = TicketCache()
                        emitted = []
                        target = tuple(self.credentials.chain_der)
                        def encode(chain, **kwargs):
                            if tuple(chain) == target:
                                kwargs['entry_extensions'] = (((code, b''),),) + ((),) * (len(chain)-1)
                            return certificate(chain, **kwargs)
                        def reference(chain, blocks, **kwargs):
                            if tuple(chain) == target:
                                blocks = [m.extension(code, b'')] + list(blocks[1:])
                            return cached(chain, blocks, **kwargs)
                        async def observe(wire, error, state=None):
                            if not isinstance(error, PeerClosed):
                                emitted.append((wire.writer in self.client_writers, error.alert))
                            return await fatal(wire, error, state)
                        options = dict(certificate_compression=(1,) if compression else (),
                                       cached_certificates=((0, target),) if cache else ())
                        if policy:
                            options['credential_policy'] = CredentialPolicy(trust_roots=tuple(self.roots), peer_name='localhost')
                        before = len(self.channels)
                        with patch.object(m, 'certificate', encode), patch.object(h, 'cached_certificate_body', reference), patch.object(h.Wire, 'fatal', observe):
                            with self.assertRaises(ProtocolError) as caught:
                                await asyncio.wait_for(self.connect(**options), 3)
                            # RFC 9345 specifies unexpected_message for an
                            # unsolicited delegation, overriding the generic
                            # CertificateEntry unsupported_extension alert.
                            expected = 10 if code == 34 else 110
                            self.assertEqual(caught.exception.alert, expected)
                            self.assertEqual(emitted, [(True, expected)])
                            self.assertEqual(len(self.channels), before)

    async def test_initial_and_post_handshake_client_extensions(self):
        credential, policy = self.client_identity()
        self.server_options.update(client_credential_policy=policy, require_client_auth=True)
        certificate, fatal = m.certificate, h.Wire.fatal
        for pha in (False, True):
            for compression in (False, True):
                self.server_options['certificate_compression'] = (1,) if compression else ()
                for code in (5, 18, 34, 0xfafa):
                    with self.subTest(pha=pha, compression=compression, code=code):
                        self.cache = TicketCache()
                        # The policy API advertises delegation deliberately;
                        # the legacy exact-chain validator does not. Do not
                        # mislabel an offered, malformed grant as unsolicited.
                        self.server_options['client_credential_policy'] = None if code == 34 else policy
                        self.server_options['client_auth_validator'] = (
                            lambda chain: credential.private_key.public_key()
                            if tuple(chain) == tuple(credential.chain_der) else None) if code == 34 else None
                        emitted = []
                        def encode(chain, **kwargs):
                            if tuple(chain) == tuple(credential.chain_der):
                                kwargs['entry_extensions'] = (((code, b''),),) + ((),) * (len(chain)-1)
                            return certificate(chain, **kwargs)
                        async def observe(wire, error, state=None):
                            if not isinstance(error, PeerClosed):
                                emitted.append((wire.writer in self.client_writers, error.alert))
                            return await fatal(wire, error, state)
                        if pha:
                            client = await self.connect(client_credentials=credential, post_handshake_auth=True)
                            server = self.channels[-1]
                            pending = await server.request_client_auth(required=True)
                        with patch.object(m, 'certificate', encode), patch.object(h.Wire, 'fatal', observe):
                            with self.assertRaises(ProtocolError) as caught:
                                if not pha:
                                    await asyncio.wait_for(self.connect(client_credentials=credential), 3)
                                else:
                                    await client.send(b'drive PHA')
                                    while await asyncio.wait_for(client.recv(), 3) is not None:
                                        pass
                            expected = 10 if code == 34 else 110
                            self.assertEqual(caught.exception.alert, expected)
                            self.assertEqual(emitted, [(False, expected)])
                            if pha:
                                self.assertTrue(pending.cancelled())
                                self.assertTrue(server.closed)
                                self.assertFalse(server.pending_client_auth)

    async def test_empty_metadata_remains_valid_in_all_three_flights(self):
        credential, policy = self.client_identity()
        self.server_options.update(client_credential_policy=policy, require_client_auth=True,
                                   certificate_compression=(1,))
        client = await self.connect(client_credentials=credential, post_handshake_auth=True,
                                    certificate_compression=(1,),
                                    cached_certificates=((0, tuple(self.credentials.chain_der)),))
        server = self.channels[-1]
        pending = await server.request_client_auth(required=True)
        await client.send(b'valid initial and PHA')
        self.assertEqual(await asyncio.wait_for(client.recv(), 3), b'valid initial and PHA')
        self.assertEqual(await asyncio.wait_for(pending, 3), tuple(credential.chain_der))
        self.assertFalse(self.errors)

    async def test_offered_nested_evidence_syntax_before_optional_policy(self):
        fixture = test_credential_profiles.CredentialProfileTests()
        fixture.setUp()
        fixture.leaf = issue(fixture.key, fixture.ca_key, fixture.name, fixture.ca_name, hostname='localhost')
        self.credentials = Credentials([der(fixture.leaf), der(fixture.root)], fixture.key)
        self.roots = [fixture.root]
        response = fixture.make_ocsp()
        valid_status = b'\x01' + len(response).to_bytes(3, 'big') + response
        cases = [(5, valid_status, None),
                 (5, b'', 50), (5, b'\x01', 50), (5, b'\x01\0\0', 50),
                 (5, b'\x01\0\0\0', 50), (5, b'\x01\0\0\x02\0', 50),
                 (5, b'\x01\0\0\x01\0\0', 50), (5, b'\x02\0\0\x01\0', 47),
                 # A syntactically valid unknown SCT version may be ignored.
                 # This is not a fake trusted-log or signature success.
                 (18, b'\0\x03\0\x01\xff', None)]
        cases += [(18, value, 50) for value in
                  (b'', b'\0', b'\0\0', b'\0\x01\0', b'\0\x02\0\0',
                   b'\0\x03\0\x02\x01', b'\0\x03\0\x01\x01\0')]
        # RFC9162 permits an absent body as the empty TLS response; it does
        # not permit a present, truncated or empty TransItemList vector.
        cases += [(52, b'', None), (52, b'\0\4\0\2\xff\xff', None)]
        cases += [(52, value, 50) for value in
                  (b'\0', b'\0\0', b'\0\1\0', b'\0\2\0\0',
                   b'\0\3\0\1\xff', b'\0\3\0\2\xff',
                   b'\0\4\0\2\xff\xff\0')]
        certificate, cached = m.certificate, h.cached_certificate_body
        for compression, cache in ((False, False), (True, False), (False, True), (True, True)):
            for code, value, expected in cases:
                with self.subTest(compression=compression, cache=cache, code=code, value=value):
                    self.cache = TicketCache()
                    policy = CredentialPolicy(trust_roots=tuple(self.roots), peer_name='localhost',
                        evidence_validator=CredentialEvidencePolicy(offered_extensions=(code,)))
                    def encode(chain, **kwargs):
                        kwargs['entry_extensions'] = (((code, value),),) + ((),) * (len(chain)-1)
                        return certificate(chain, **kwargs)
                    def reference(chain, blocks, **kwargs):
                        return cached(chain, [m.extension(code, value)] + list(blocks[1:]), **kwargs)
                    options = dict(credential_policy=policy,
                        certificate_evidence_extensions=((code, b'\x01\0\0\0\0' if code == 5 else b''),),
                        certificate_compression=(1,) if compression else (),
                        cached_certificates=((0, tuple(self.credentials.chain_der)),) if cache else ())
                    with patch.object(m, 'certificate', encode), patch.object(h, 'cached_certificate_body', reference):
                        if expected is None:
                            channel = await asyncio.wait_for(self.connect(**options), 3)
                            await channel.send(b'valid evidence envelope')
                            self.assertEqual(await channel.recv(), b'valid evidence envelope')
                            await channel.close()
                        else:
                            before = len(self.channels)
                            with self.assertRaises(ProtocolError) as caught:
                                await asyncio.wait_for(self.connect(**options), 3)
                            self.assertEqual(caught.exception.alert, expected)
                            self.assertEqual(len(self.channels), before)


if __name__ == '__main__':
    unittest.main()
