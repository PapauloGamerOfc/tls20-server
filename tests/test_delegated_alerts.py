"""Delegated-grant failures retain their RFC 9345 alerts and fail closed."""

import asyncio
from dataclasses import replace
import unittest
from unittest.mock import patch

from tls20_server import handshake, messages
from tls20_server.credential_profiles import resolve_peer, validate_delegation
from tls20_server.errors import ProtocolError
from tls20_server.lab import generate_lab_credentials
from tls20_server.pki import Credentials, verify_public_signature
from tls20_server.secret_lifecycle import HandshakeSecrets
from tests import test_credential_profiles, test_sessions
from tests.test_pki import der


class DelegationAlertTests(unittest.TestCase):
    def setUp(self):
        self.fixture = test_credential_profiles.CredentialProfileTests()
        self.fixture.setUp()

    def test_both_roles_distinguish_grant_syntax_from_validation(self):
        for role in ("server", "client"):
            parent, grant = self.fixture.parent_and_grant(role=role)
            options = dict(role=role, grant_algorithms=(0x0807,),
                delegated_schemes=(0xfe00 if role == "server" else 0xfe01,), now=self.fixture.now)
            key, _ = validate_delegation(der(parent), grant, **options)
            self.assertEqual(key.public_bytes_raw(), self.fixture.key.public_key().public_bytes_raw())
            variants = {
                "signature": (grant[:-1] + bytes((grant[-1] ^ 1,)), 47),
                "wrong-role": (grant[:4] + (b"\xfe\x01" if role == "server" else b"\xfe\x00") + grant[6:], 47),
                "expired": (bytes(4) + grant[4:], 47),
                "invalid-key": (grant[:21] + bytes(32) + grant[53:], 47),
                "unoffered-scheme": (grant[:53] + b"\x04\x03" + grant[55:], 47),
                "short": (grant[:12], 50),
                "truncated": (grant[:-1], 50),
                "trailing": (grant + b"\x00", 50),
                "empty-signature": (grant[:55] + b"\x00\x00", 50),
                "empty-spki": (grant[:6] + bytes(3) + grant[53:], 50),
            }
            for name, (candidate, alert) in variants.items():
                with self.subTest(role=role, variant=name), self.assertRaises(ProtocolError) as caught:
                    validate_delegation(der(parent), candidate, **options)
                self.assertEqual(caught.exception.alert, alert)
            for values in (dict(delegation=False), dict(valid_time=172800)):
                other_parent, other_grant = self.fixture.parent_and_grant(role=role, **values)
                with self.subTest(role=role, values=values), self.assertRaises(ProtocolError) as caught:
                    validate_delegation(der(other_parent), other_grant, **options)
                self.assertEqual(caught.exception.alert, 47)

    def test_delegation_metadata_alerts_and_independent_parent_validation(self):
        parent, grant = self.fixture.parent_and_grant()
        material = [der(parent), der(self.fixture.root)]
        options = dict(policy=self.fixture.policy, certificate_algorithms=(0x0403,),
                       grant_algorithms=(0x0807,), delegated_schemes=(0xfe00,))
        for metadata, schemes, expected in (
            ((((34, grant),), ()), (), 10),
            (((), ((34, grant),)), (0xfe00,), 47),
            ((((34, grant), (34, grant)), ()), (0xfe00,), 47),
        ):
            with self.subTest(metadata=metadata), self.assertRaises(ProtocolError) as caught:
                resolve_peer(material, entry_extensions=metadata,
                    **dict(options, delegated_schemes=schemes))
            self.assertEqual(caught.exception.alert, expected)
        for policy in (replace(self.fixture.policy, trust_roots=()),
                       replace(self.fixture.policy, peer_name="wrong.test")):
            with self.subTest(policy=policy), self.assertRaises(ProtocolError) as caught:
                resolve_peer(material, entry_extensions=(((34, grant),), ()), **dict(options, policy=policy))
            self.assertNotEqual(caught.exception.alert, 47, "parent failure is not a grant validation failure")
        with self.assertRaises(ProtocolError) as caught:
            verify_public_signature(parent.public_key(), 0x0807, bytes(64), b"unrelated offline object")
        self.assertEqual(caught.exception.alert, 40, "the generic verifier must remain unchanged")


class DelegationWireTests(unittest.IsolatedAsyncioTestCase):
    async def exchange(self, role, variant):
        fixture = test_credential_profiles.CredentialProfileTests()
        fixture.setUp()
        parent, grant = fixture.parent_and_grant(role=role)
        delegated = Credentials([der(parent)], fixture.key, delegation=grant)
        ordinary, root = generate_lab_credentials("example.test")
        server_credentials = delegated if role == "server" else ordinary
        server_options, client_options = {}, {}
        if role == "server":
            roots = [fixture.root]
            client_options = dict(credential_policy=fixture.policy, delegated_credentials=True,
                server_certificate_algorithms=(0x0403,), server_delegation_signature_algorithms=(0x0807,))
        else:
            roots = [root]
            server_options = dict(client_credential_policy=replace(fixture.policy,
                authorize_client=lambda chain, evidence: chain == (der(parent),)), require_client_auth=True,
                client_certificate_algorithms=(0x0403,), client_delegation_signature_algorithms=(0x0807,))
            client_options = dict(client_credentials=delegated)
        if variant == "unsolicited":
            self.assertEqual(role, "server")
            server_credentials, roots = ordinary, [root]
            client_options = {}
        alerts, errors, completed, records, scopes, tasks, writers = [], [], [], [], [], [], []
        original_certificate, original_read = messages.certificate, handshake.Wire.read_record
        original_init, original_record = HandshakeSecrets.__init__, HandshakeSecrets.record

        def certificate(chain, **kwargs):
            if variant == "unsolicited" and chain == ordinary.chain_der:
                kwargs["entry_extensions"] = (((34, grant),),)
            elif variant != "valid":
                replacement = (grant[:-1] + bytes((grant[-1] ^ 1,))) if variant == "signature" else grant[:-1]
                kwargs["entry_extensions"] = tuple(tuple((kind, replacement if kind == 34 and value == grant else value)
                    for kind, value in pairs) for pairs in kwargs.get("entry_extensions", ()))
            return original_certificate(chain, **kwargs)

        async def read(wire, state=None):
            content, kind = await original_read(wire, state)
            if kind == 21 and content[0] == 2:
                alerts.append((state is not None, content))
            return content, kind

        def scope_init(scope):
            original_init(scope)
            scopes.append(scope)

        def record(scope, *args, **kwargs):
            state = original_record(scope, *args, **kwargs)
            records.append(state)
            return state

        async def server(reader, writer):
            writers.append(writer)
            channel = None
            try:
                channel = await handshake.server_handshake(reader, writer, server_credentials,
                    "example.test", timeout=3, **server_options)
                completed.append("server")
                await channel.send(b"authenticated")
                self.assertIsNone(await channel.recv())
            except ProtocolError as error:
                errors.append(error)
            finally:
                if channel is not None:
                    await channel.close()
                writer.close()

        def accept(reader, writer):
            tasks.append(asyncio.create_task(server(reader, writer)))

        with patch.object(messages, "certificate", certificate), patch.object(handshake.Wire, "read_record", read), \
                patch.object(HandshakeSecrets, "__init__", scope_init), patch.object(HandshakeSecrets, "record", record):
            async with await asyncio.start_server(accept, "127.0.0.1", 0) as listener:
                reader, writer = await asyncio.open_connection("127.0.0.1", listener.sockets[0].getsockname()[1])
                writers.append(writer)
                channel = None
                try:
                    channel = await handshake.client_handshake(reader, writer, "example.test", roots,
                        revocation_policy="offline", timeout=3, **client_options)
                    self.assertEqual(await asyncio.wait_for(channel.recv(), 3), b"authenticated")
                    completed.append("client")
                except ProtocolError as error:
                    errors.append(error)
                finally:
                    if channel is not None:
                        await channel.close()
                    writer.close()
                if tasks:
                    await asyncio.wait_for(asyncio.gather(*tasks), 3)
        for writer in writers:
            await asyncio.wait_for(writer.wait_closed(), 2)
        self.assertTrue(records)
        for state in records:
            self.assertTrue(state.failed)
            self.assertEqual((state.secret, state.key, state.iv), (b"", b"", b""))
            self.assertIsNone(state._cipher)
        for scope in scopes:
            self.assertEqual((scope.records, scope.keys, scope.channel), ([], [], None))
        if variant == "valid":
            self.assertCountEqual(completed, ["server", "client"])
            self.assertEqual((alerts, errors), ([], []))
        else:
            expected = {"signature": 47, "truncated": 50, "unsolicited": 10}[variant]
            self.assertEqual(completed, [])
            self.assertEqual(alerts, [(True, bytes((2, expected)))])
            self.assertTrue(errors)
            self.assertTrue(all(error.alert == expected for error in errors))

    async def test_both_roles_send_encrypted_grant_alerts_and_dispose_epochs(self):
        for role in ("server", "client"):
            for variant in ("valid", "signature", "truncated"):
                with self.subTest(role=role, variant=variant):
                    await self.exchange(role, variant)

    async def test_unsolicited_server_grant_uses_unexpected_message(self):
        await self.exchange("server", "unsolicited")


class DelegationPostHandshakeTests(unittest.IsolatedAsyncioTestCase):
    asyncSetUp = test_sessions.SessionTests.asyncSetUp
    asyncTearDown = test_sessions.SessionTests.asyncTearDown
    accept = test_sessions.SessionTests.accept
    handle = test_sessions.SessionTests.handle
    connect = test_sessions.SessionTests.connect

    async def test_bad_client_grant_during_pha_sends_illegal_parameter(self):
        fixture = test_credential_profiles.CredentialProfileTests()
        fixture.setUp()
        parent, grant = fixture.parent_and_grant(role="client")
        credentials = Credentials([der(parent)], fixture.key, delegation=grant)
        self.server_options = dict(client_credential_policy=replace(fixture.policy,
            authorize_client=lambda chain, evidence: chain == (der(parent),)), require_client_auth=True,
            client_certificate_algorithms=(0x0403,), client_delegation_signature_algorithms=(0x0807,))
        client = await self.connect(client_credentials=credentials, post_handshake_auth=True)
        server = self.channels[-1]
        pending = await server.request_client_auth(required=True)
        original_certificate, original_read = messages.certificate, handshake.Wire.read_record
        alerts = []

        def certificate(chain, **kwargs):
            kwargs["entry_extensions"] = tuple(tuple((kind,
                grant[:-1] + bytes((grant[-1] ^ 1,)) if kind == 34 and value == grant else value)
                for kind, value in pairs) for pairs in kwargs.get("entry_extensions", ()))
            return original_certificate(chain, **kwargs)

        async def read(wire, state=None):
            content, kind = await original_read(wire, state)
            if kind == 21 and content[0] == 2:
                alerts.append((state is not None, content))
            return content, kind

        with patch.object(messages, "certificate", certificate), patch.object(handshake.Wire, "read_record", read):
            await client.send(b"drive delegated PHA")
            self.assertEqual(await asyncio.wait_for(client.recv(), 2), b"drive delegated PHA")
            with self.assertRaises(ProtocolError) as caught:
                await asyncio.wait_for(client.recv(), 2)
            self.assertEqual(caught.exception.alert, 47)
        self.assertEqual(alerts, [(True, b"\x02\x2f")])
        with self.assertRaises(asyncio.CancelledError):
            await asyncio.wait_for(pending, 2)
        self.assertTrue(pending.cancelled())
