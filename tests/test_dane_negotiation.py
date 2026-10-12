"""Current algorithm offers and delegated identities on real DANE paths/wires."""

import asyncio
from dataclasses import replace
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import dns.rrset
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.x509.oid import NameOID

from tests import test_credential_profiles, test_dnssec_credentials
from tests.test_pki import der, issue
from tls20_server import handshake, messages as m
from tls20_server.credential_profiles import resolve_peer
from tls20_server.dnssec_credentials import DANEPolicy, DNSSECWireEvidence
from tls20_server.errors import ProtocolError
from tls20_server.pki import Credentials, validate_identity, validate_pkix_path
from tls20_server.profiles import load_profile
from tls20_server.tickets import TicketCache, TicketStore


class DANEProfileFixture:
    def configure(self):
        self.fixture = test_credential_profiles.CredentialProfileTests(); self.fixture.setUp()
        self.dns = test_dnssec_credentials.DNSSECCredentialTests(); self.dns.setUp()
        self.directory_owner = tempfile.TemporaryDirectory(prefix='tls20-dane-offers-')
        self.addCleanup(self.directory_owner.cleanup)
        self.directory = Path(self.directory_owner.name)
        (self.directory / 'anchors.zone').write_text(self.dns.root_keys.to_text() + '\n', encoding='ascii')
        (self.directory / 'root.pem').write_bytes(self.fixture.root.public_bytes(serialization.Encoding.PEM))

    def profile(self, *, delegation=False, require_delegation=False, dane=True):
        path = self.directory / 'client.toml'
        path.write_text('role="client"\nservice="example.test"\nport=343\nmode="certificate"\n'
            '[trust]\nroots="root.pem"\n'
            + ('delegated_credentials=true\n' if delegation else '')
            + ('require_delegation=true\n' if require_delegation else '')
            + ('[trust.dane]\nanchors_file="anchors.zone"\n' if dane else ''), encoding='ascii')
        profile = load_profile(path, role='client')
        self.addCleanup(profile.close)
        return profile

    def proof(self, usage, leaf, *anchors):
        associations = (leaf,) if usage in (1, 3) else anchors or (self.fixture.root,)
        rrset = dns.rrset.from_text(self.dns.owner, 300, 'IN', 'TLSA',
                                   *(f'{usage} 0 0 ' + der(cert).hex() for cert in associations))
        return DNSSECWireEvidence(24, self.dns.chain(*self.dns.sign(rrset))).encode()


class DANENegotiationTests(DANEProfileFixture, unittest.TestCase):
    def setUp(self):
        self.configure()

    def test_loader_checks_delegated_parent_and_independent_grant_offer(self):
        parent, grant = self.fixture.parent_and_grant()
        policy = self.profile(delegation=True).options['credential_policy']
        for usage in (0, 1, 2, 3):
            proof = self.proof(usage, parent)
            options = dict(policy=policy, certificate_algorithms=(0x0403,), grant_algorithms=(0x0807,),
                delegated_schemes=(0xfe00,), offered_extensions=(59,),
                entry_extensions=(((59, proof), (34, grant)),))
            with self.subTest(usage=usage):
                peer = resolve_peer((der(parent),), **options)
                self.assertEqual(peer.provenance, 'dane-x509-delegated')
                self.assertEqual(peer.public_key.public_bytes_raw(), self.fixture.key.public_key().public_bytes_raw())
                for invalid in (grant[:-1] + bytes((grant[-1] ^ 1,)), grant + b'\0',
                                grant[:4] + b'\xfe\x01' + grant[6:]):
                    with self.assertRaises(ProtocolError):
                        resolve_peer((der(parent),), **dict(options,
                            entry_extensions=(((59, proof), (34, invalid)),)))
                with self.assertRaises(ProtocolError):
                    resolve_peer((der(parent),), **dict(options, grant_algorithms=(0x0403,)))
                with self.assertRaises(ProtocolError):
                    resolve_peer((der(parent),), **dict(options, entry_extensions=(((59, proof),),)))
                with self.assertRaises(ProtocolError):
                    resolve_peer((der(parent),), **dict(options, certificate_algorithms=()))
        # Merely configuring DANE cannot enable an unoffered signing-parent path.
        plain = self.profile().options['credential_policy']
        with self.assertRaises(ProtocolError):
            resolve_peer((der(parent),), **dict(options, policy=plain,
                entry_extensions=(((59, self.proof(2, parent)), (34, grant)),)))

    def test_dane_ee_has_no_path_signature_requirement_but_keeps_grant_gate(self):
        policy = self.profile().options['credential_policy']
        leaf = self.fixture.leaf
        for usage in (0, 1, 2, 3):
            options = dict(policy=policy, offered_extensions=(59,),
                certificate_algorithms=(0x0807,), entry_extensions=(((59, self.proof(usage, leaf)),),))
            with self.subTest(usage=usage):
                if usage == 3:
                    self.assertEqual(resolve_peer((der(leaf),), **options).provenance, 'dane-x509')
                else:
                    with self.assertRaises(ProtocolError):
                        resolve_peer((der(leaf),), **options)
        parent, grant = self.fixture.parent_and_grant()
        delegated = self.profile(delegation=True).options['credential_policy']
        # DANE-EE authenticates this exact parent, not its issuer's signature.
        result = resolve_peer((der(parent),), policy=delegated, offered_extensions=(59,),
            certificate_algorithms=(0x0807,), grant_algorithms=(0x0807,), delegated_schemes=(0xfe00,),
            entry_extensions=(((59, self.proof(3, parent)), (34, grant)),))
        self.assertEqual(result.provenance, 'dane-x509-delegated')

    def test_legacy_boolean_path_cannot_bypass_current_algorithm_offer(self):
        policy = self.profile().options['credential_policy']
        original = policy.dane_policy.dane_path_validator
        def legacy(material, anchor):
            original(material, anchor)
            return True
        policy = replace(policy, dane_policy=replace(policy.dane_policy, dane_path_validator=legacy))
        for include_anchor in (False, True):
            material = (der(self.fixture.leaf),) + ((der(self.fixture.root),) if include_anchor else ())
            options = dict(policy=policy, offered_extensions=(59,),
                entry_extensions=(((59, self.proof(2, self.fixture.leaf)),),) + ((),) * (len(material) - 1))
            self.assertEqual(resolve_peer(material, certificate_algorithms=(0x0403,), **options).provenance, 'dane-x509')
            with self.assertRaises(ProtocolError):
                resolve_peer(material, certificate_algorithms=(0x0807,), **options)

    def test_alternative_tlsa_paths_are_checked_before_selection(self):
        # Two cross-signs for the same intermediate key: the first path uses an
        # unoffered Ed25519 signature, the other is entirely ECDSA. Both have real
        # signatures and matching DNSSEC-authenticated full-certificate TAs.
        intermediate_key = ec.generate_private_key(ec.SECP256R1())
        intermediate_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'Shared intermediate')])
        wrong_key = ed25519.Ed25519PrivateKey.generate()
        wrong_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'Ed25519 anchor')])
        wrong_root = issue(wrong_key, wrong_key, wrong_name, wrong_name, ca=True, path_length=2)
        allowed_root = issue(self.fixture.ca_key, self.fixture.ca_key,
            self.fixture.ca_name, self.fixture.ca_name, ca=True, path_length=2)
        wrong_intermediate = issue(intermediate_key, wrong_key, intermediate_name, wrong_name, ca=True)
        allowed_intermediate = issue(intermediate_key, self.fixture.ca_key,
            intermediate_name, self.fixture.ca_name, ca=True)
        leaf = issue(self.fixture.key, intermediate_key, self.fixture.name, intermediate_name)
        material = tuple(map(der, (leaf, wrong_intermediate, allowed_intermediate)))
        selected = []
        def validate_path(material, anchor):
            # An application path builder selects the actual cross-sign for this
            # authorized anchor; unused supplied material does not become a path.
            intermediate = wrong_intermediate if der(anchor) == der(wrong_root) else allowed_intermediate
            candidate = (material[0], der(intermediate))
            validate_identity(candidate, trust_roots=(anchor,), role='server', name='example.test', partial_chain=True)
            return validate_pkix_path(candidate, (anchor,), partial_chain=True)
        policy = replace(self.fixture.policy, dane_policy=DANEPolicy({'.': self.dns.root_keys},
            dane_path_validator=validate_path), evidence_validator=lambda path, *_: selected.append(path) or True)
        for anchors in ((wrong_root, allowed_root), (allowed_root, wrong_root)):
            with self.subTest(order=[cert.subject.rfc4514_string() for cert in anchors]):
                result = resolve_peer(material, policy=policy, certificate_algorithms=(0x0403,),
                    offered_extensions=(59,), entry_extensions=(((59, self.proof(2, leaf, *anchors)),), (), ()))
                self.assertEqual(result.provenance, 'dane-x509')
                self.assertEqual(der(selected[-1][-1]), der(allowed_root))
        with self.assertRaises(ProtocolError):
            resolve_peer(material, policy=policy, certificate_algorithms=(0x0403,), offered_extensions=(59,),
                entry_extensions=(((59, self.proof(2, leaf, wrong_root)),), (), ()))

    def test_non_self_signed_dane_anchor_signature_is_exempt(self):
        external = ed25519.Ed25519PrivateKey.generate()
        issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'Unneeded external issuer')])
        anchor = issue(self.fixture.ca_key, external, self.fixture.ca_name, issuer, ca=True)
        leaf = self.fixture.leaf
        policy = self.profile().options['credential_policy']
        # The offered list excludes the Ed25519 signature on this DNS trust anchor.
        result = resolve_peer((der(leaf),), policy=policy, certificate_algorithms=(0x0403,),
            offered_extensions=(59,), entry_extensions=(((59, self.proof(2, leaf, anchor)),),))
        self.assertEqual(result.provenance, 'dane-x509')


class DANEWireNegotiationTests(DANEProfileFixture, unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.configure()

    async def exchange(self, usage, *, delegated=False, wrong_offer=False, dane=True, retry=False, resume=False):
        leaf, grant = self.fixture.parent_and_grant() if delegated else (self.fixture.leaf, b'')
        credentials = Credentials([der(leaf)], self.fixture.key, delegation=grant,
            entry_extensions=(((59, self.proof(usage, leaf)),),), dnssec_service=('example.test', 343))
        profile = self.profile(delegation=delegated, dane=dane)
        writers, handlers, channels, offered_algorithms, relaxed_calls, server_errors = [], set(), [], [], [], []
        store, cache, received_early = TicketStore(), TicketCache(), []
        async def peer(reader, writer):
            task = asyncio.current_task(); handlers.add(task); writers.append(writer)
            async def early(data):
                received_early.append(data)
            try:
                channel = await handshake.server_handshake(reader, writer, credentials, 'example.test', timeout=5,
                    ticket_store=store, max_early_data=16384, on_early_data=early)
                channels.append(channel)
                await channel.send(b'authenticated DANE fixture')
                await channel.recv()
            except (ProtocolError, ConnectionError) as exc:
                server_errors.append(str(exc))
            finally:
                writer.close()
                try: await writer.wait_closed()
                except ConnectionError: pass
                handlers.discard(task)
        original_check, original_send = handshake._check_certificate_offer, handshake.Wire.send_frame
        def malicious_sender_only(*args, **kwargs):
            if asyncio.current_task() in handlers:
                relaxed_calls.append(kwargs.get('require_match', True))
                return True
            return original_check(*args, **kwargs)
        async def observe(wire, frame, state=None):
            if frame[0] == 1:
                offered_algorithms.append(m._u16_list(dict(m.parse_client_hello(frame[4:]).extension_values)[50]))
            return await original_send(wire, frame, state)
        listener = await asyncio.start_server(peer, '127.0.0.1', 0)
        try:
            algorithms = (0x0807,) if wrong_offer else (0x0403,)
            with patch.object(handshake, '_check_certificate_offer', malicious_sender_only if wrong_offer else original_check), \
                    patch.object(handshake.Wire, 'send_frame', observe):
                options = dict(revocation_policy=profile.revocation_policy, force_retry=retry,
                               server_certificate_algorithms=algorithms, ticket_cache=cache,
                               **profile.options)
                attempts = ((False, b''), (True, b''), (True, b'public early fixture')) if resume else ((False, b''),)
                for expected_resumed, early_data in attempts:
                    reader, writer = await asyncio.open_connection('127.0.0.1', listener.sockets[0].getsockname()[1])
                    writers.append(writer)
                    if wrong_offer and (usage != 3 or not dane):
                        with self.assertRaisesRegex(ProtocolError, 'TLSA records do not authorize|certificate signature was not offered'):
                            await handshake.client_handshake(reader, writer, 'example.test', profile.roots, **options)
                    else:
                        channel = await handshake.client_handshake(reader, writer, 'example.test', profile.roots,
                                                                   early_data=early_data, **options)
                        self.assertEqual(await channel.recv(), b'authenticated DANE fixture')
                        self.assertTrue(channel.peer_authenticated)
                        self.assertEqual(channel.resumed, expected_resumed)
                        self.assertEqual(channel.early_data_accepted, bool(early_data))
                        self.assertEqual(channel.handshake_transcript, channels[-1].handshake_transcript)
                        await channel.close()
            self.assertEqual(offered_algorithms, [algorithms] * len(attempts) * (2 if retry else 1))
            self.assertEqual(received_early, [b'public early fixture', b''] if resume else [])
            if wrong_offer:
                self.assertEqual(relaxed_calls, [False, True])  # Selection and emission, never client verification.
        finally:
            listener.close(); await listener.wait_closed()
            for writer in writers: writer.transport.abort()
            if handlers: await asyncio.gather(*handlers, return_exceptions=True)
            for writer in writers:
                try: await writer.wait_closed()
                except ConnectionError: pass

    async def test_real_profiles_delegation_and_dane_keep_independent_offers(self):
        for usage in (0, 1, 2, 3):
            for delegated in (False, True):
                for wrong_offer in (False, True):
                    with self.subTest(usage=usage, delegated=delegated, wrong_offer=wrong_offer):
                        await self.exchange(usage, delegated=delegated, wrong_offer=wrong_offer)
        await self.exchange(2, delegated=True, retry=True)
        await self.exchange(2, delegated=True, wrong_offer=True, retry=True)
        await self.exchange(2, delegated=True, dane=False)
        await self.exchange(2, wrong_offer=True, dane=False)

    async def test_delegated_dane_profiles_full_resumption_and_early_data(self):
        for usage in (0, 1, 2):
            with self.subTest(usage=usage):
                await self.exchange(usage, delegated=True, resume=True)
