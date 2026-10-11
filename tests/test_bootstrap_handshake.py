"""Real-loopback POK profile; helpers alone never count as wire support."""

import asyncio
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519

from tests import test_sessions
from tls20_server.bootstrap_credentials import (BootstrapBinding,
    bootstrap_client_handshake, bootstrap_server_handshake)
from tls20_server.errors import ProtocolError
from tls20_server.handshake import Wire
from tls20_server import messages as m
from tls20_server.psk import bootstrap_public_key_psk
from tls20_server.tickets import TicketCache


class BootstrapHandshakeTests(unittest.IsolatedAsyncioTestCase):
    accept = test_sessions.SessionTests.accept
    asyncTearDown = test_sessions.SessionTests.asyncTearDown

    async def asyncSetUp(self):
        await test_sessions.SessionTests.asyncSetUp(self)
        self.private = x25519.X25519PrivateKey.generate()
        public = self.private.public_key().public_bytes(serialization.Encoding.DER,
                                          serialization.PublicFormat.SubjectPublicKeyInfo)
        self.binding = BootstrapBinding(public, 'localhost', 'device-enrollment')

    async def handle(self, reader, writer):
        async def early(data):
            self.early.append(data)
        channel = None
        try:
            channel = await bootstrap_server_handshake(reader, writer, self.credentials,
                getattr(self, 'server_binding', self.binding), ticket_store=self.store,
                max_early_data=65536, on_early_data=early, **self.server_options)
            self.channels.append(channel)
            await channel.send(b'ready')
            while (content := await channel.recv()) is not None:
                await channel.send(content)
        except (ProtocolError, OSError) as exc:
            self.errors.append(str(exc))
        finally:
            if channel:
                await channel.close()
            else:
                writer.transport.abort()

    async def connect(self, *, binding=None, roots=None, private_key=None, **options):
        reader, writer = await asyncio.open_connection('127.0.0.1', self.port)
        self.writers.append(writer)
        channel = await bootstrap_client_handshake(reader, writer, binding or self.binding,
            self.private if private_key is None else private_key,
            self.roots if roots is None else roots, ticket_cache=self.cache, **options)
        self.assertEqual(await asyncio.wait_for(channel.recv(), 2), b'ready', self.errors)
        return channel

    def another_binding(self, scope='second-device', **changes):
        key = x25519.X25519PrivateKey.generate()
        spki = key.public_key().public_bytes(serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo)
        return replace(self.binding, spki=spki, scope=scope, **changes), key

    async def test_nonfirst_bsk_and_hash_retry_then_scoped_resumption(self):
        self.binding = replace(self.binding, target_hashes=('sha256',))
        second, second_key = self.another_binding(target_hashes=('sha256', 'sha384'))
        self.server_binding = (self.binding, second)
        self.server_options = {'cipher_suites': (0x1302,)}
        expected = bootstrap_public_key_psk(second.spki[12:], 'localhost', target_hash='sha384').identity
        for retry in (False, True):
            with self.subTest(retry=retry):
                self.cache = TicketCache()
                channel = await self.connect(binding=(self.binding, second),
                    private_key=(second_key, self.private), force_retry=retry)
                self.assertEqual(channel.cipher_suite, 0x1302)
                self.assertEqual(channel.selected_external_psk_identity, expected)
                self.assertEqual(channel.bootstrap_binding, second)
                self.assertEqual(self.channels[-1].authenticated_client, (second.spki,))
                self.assertEqual(channel.bootstrap_authorization['scope'], second.scope)
                self.assertEqual(next(iter(self.cache._tickets.values())).external_psk_identity, expected)
                third, third_key = self.another_binding(scope='third-device')
                self.server_binding = (third, second)
                resumed = await self.connect(binding=(second, third), private_key=(third_key, second_key),
                    early_data=b'second device only')
                self.assertTrue(resumed.resumed)
                self.assertTrue(resumed.early_data_accepted)
                self.assertFalse(resumed.bootstrap_authorization['fresh_client_possession'])
                self.assertEqual(resumed.bootstrap_binding, second)
                self.server_binding = (self.binding, second)

    async def test_retired_selected_record_cannot_resume_or_authorize_early_data(self):
        second, second_key = self.another_binding(target_hashes=('sha384',))
        self.server_binding = (self.binding, second)
        self.server_options = {'cipher_suites': (0x1302,)}
        # Offer B first so this handshake and ticket are bound to B.
        await self.connect(binding=(second, self.binding), private_key=(self.private, second_key))
        before = len(self.store._tickets)
        self.server_binding = (self.binding,)
        with self.assertRaises((ProtocolError, OSError)):
            await self.connect(binding=(second, self.binding), private_key=(self.private, second_key),
                early_data=b'must not reach provisioning')
        self.assertFalse(self.early)
        self.assertEqual(len(self.store._tickets), before)

    async def test_selected_scope_and_trust_changes_cannot_resume_old_authority(self):
        second, second_key = self.another_binding(target_hashes=('sha384',))
        self.server_binding = (self.binding, second)
        self.server_options = {'cipher_suites': (0x1302,)}
        self.binding = replace(self.binding, target_hashes=('sha256',))
        for changed in (second, replace(second, scope='new-scope'),
                        replace(second, scope='new-scope', trust_mode='provisioning-trust')):
            self.server_binding = (self.binding, changed)
            channel = await self.connect(binding=(self.binding, changed), private_key=(self.private, second_key))
            self.assertFalse(channel.resumed)
            self.assertEqual(channel.bootstrap_authorization['scope'], changed.scope)
            self.assertEqual(channel.bootstrap_authorization['trust_mode'], changed.trust_mode)

    async def test_duplicate_and_wrong_private_inventories_release_no_client_credential(self):
        second, second_key = self.another_binding()
        send = Wire.send_frame
        released = []
        async def capture(wire, message, state=None):
            if wire.writer.get_extra_info('peername')[1] == self.port and message[0] in (11, 25):
                released.append(message)
            return await send(wire, message, state)
        for bindings, keys in (((self.binding, self.binding), (self.private,)),
                ((self.binding, replace(self.binding, scope='ambiguous')), (self.private,)),
                ((self.binding, second), (self.private,)),
                ((self.binding, second), (self.private, self.private))):
            with patch.object(Wire, 'send_frame', capture), self.assertRaises(ProtocolError):
                await self.connect(binding=bindings, private_key=keys)
        self.assertFalse(released)
        self.assertFalse(self.channels)
        self.assertFalse(self.store._tickets)

    async def test_authenticated_nonfirst_selection_never_releases_first_credential(self):
        self.binding = replace(self.binding, target_hashes=('sha256',), trust_mode='provisioning-trust')
        second, second_key = self.another_binding(target_hashes=('sha384',), trust_mode='credential-validated')
        self.server_binding = (self.binding, second)
        self.server_options = {'cipher_suites': (0x1302,)}
        send = Wire.send_frame
        released = []
        async def capture(wire, message, state=None):
            if wire.writer.get_extra_info('peername')[1] == self.port and message[0] in (11, 25):
                released.append(message)
            return await send(wire, message, state)
        with patch.object(Wire, 'send_frame', capture), self.assertRaises(ProtocolError):
            await self.connect(binding=(self.binding, second), private_key=(self.private, second_key), roots=[])
        self.assertFalse(released, 'unselected provisioning trust must not waive the selected credential policy')
        self.assertFalse(self.store._tickets)

    async def test_bad_server_finished_for_nonfirst_bsk_releases_no_credential(self):
        self.binding = replace(self.binding, target_hashes=('sha256',))
        second, second_key = self.another_binding(target_hashes=('sha384',))
        self.server_binding = (self.binding, second)
        self.server_options = {'cipher_suites': (0x1302,)}
        send = Wire.send_frame
        released = []
        async def corrupt(wire, message, state=None):
            client = wire.writer.get_extra_info('peername')[1] == self.port
            if client and message[0] in (11, 25):
                released.append(message)
            elif not client and message[0] == 20:
                message = message[:-1] + bytes((message[-1] ^ 1,))
            return await send(wire, message, state)
        with patch.object(Wire, 'send_frame', corrupt), self.assertRaises(ProtocolError):
            await self.connect(binding=(self.binding, second), private_key=(self.private, second_key))
        self.assertFalse(released)
        self.assertFalse(self.store._tickets)

    async def test_nonfirst_selected_binder_is_verified_before_credential_release(self):
        self.binding = replace(self.binding, target_hashes=('sha256',))
        second, second_key = self.another_binding(target_hashes=('sha384',))
        self.server_binding = (self.binding, second)
        self.server_options = {'cipher_suites': (0x1302,)}
        send = Wire.send_frame
        released = []
        async def corrupt(wire, message, state=None):
            client = wire.writer.get_extra_info('peername')[1] == self.port
            if client and message[0] in (11, 25):
                released.append(message)
            elif client and message[0] == 1:
                message = message[:-1] + bytes((message[-1] ^ 1,))
            return await send(wire, message, state)
        with patch.object(Wire, 'send_frame', corrupt), self.assertRaises(ProtocolError):
            await self.connect(binding=(self.binding, second), private_key=(self.private, second_key))
        self.assertFalse(released)
        self.assertFalse(self.store._tickets)
        self.assertIn('PSK binder verification failed', self.errors)

    async def test_valid_unselected_bsk_cannot_replace_selected_client_credential(self):
        self.binding = replace(self.binding, target_hashes=('sha256',))
        second, second_key = self.another_binding(target_hashes=('sha384',))
        self.server_binding = (self.binding, second)
        self.server_options = {'cipher_suites': (0x1302,)}
        send = Wire.send_frame
        async def substitute(wire, message, state=None):
            if wire.writer.get_extra_info('peername')[1] == self.port and message[0] in (11, 25):
                message = m.certificate([self.binding.spki])
            return await send(wire, message, state)
        with patch.object(Wire, 'send_frame', substitute), self.assertRaises((ProtocolError, OSError, AssertionError)):
            await self.connect(binding=(self.binding, second), private_key=(self.private, second_key))
        await asyncio.wait_for(asyncio.gather(*tuple(self.tasks), return_exceptions=True), 2)
        self.assertFalse(self.channels)
        self.assertFalse(self.store._tickets)
        self.assertIn('bootstrap client credential differs from selected BSK', self.errors)

    async def test_resumed_selected_binding_expiry_is_rechecked_at_both_finished_gates(self):
        now = datetime.now(timezone.utc)
        expiry = now + timedelta(minutes=1)
        self.binding = replace(self.binding, expires_at=expiry)
        send = Wire.send_frame
        for expire_on_client_finished in (False, True):
            with self.subTest(server_gate=expire_on_client_finished):
                self.cache = TicketCache()
                await self.connect()
                before_channels, before_tickets = len(self.channels), len(self.store._tickets)
                with patch('tls20_server.bootstrap_credentials.datetime') as timer:
                    timer.now.return_value = now
                    async def expire(wire, message, state=None):
                        client = wire.writer.get_extra_info('peername')[1] == self.port
                        if message[0] == 20 and client == expire_on_client_finished:
                            timer.now.return_value = expiry + timedelta(seconds=1)
                        return await send(wire, message, state)
                    with patch.object(Wire, 'send_frame', expire), self.assertRaises((ProtocolError, OSError)):
                        await self.connect()
                self.assertEqual(len(self.channels), before_channels)
                self.assertEqual(len(self.store._tickets), before_tickets)

    async def test_nonfirst_bootstrap_alpn_is_bound_to_fresh_and_resumed_authority(self):
        first = await self.connect(application_protocols=(b'h2', b'http/1.1'))
        self.assertEqual(first.protocol, b'http/1.1')
        second = await self.connect(application_protocols=(b'h2', b'http/1.1'), early_data=b'bound to HTTP/1.1')
        self.assertTrue(second.resumed)
        self.assertTrue(second.early_data_accepted)
        self.assertEqual(second.protocol, b'http/1.1')
        original = m.encrypted_extensions
        def change_protocol(protocol=b'http/1.1', **options):
            return original(b'h2', **options)
        with patch.object(m, 'encrypted_extensions', change_protocol), self.assertRaises(ProtocolError) as caught:
            await self.connect(application_protocols=(b'h2', b'http/1.1'))
        self.assertIn('application protocol binding mismatch', str(caught.exception))

    async def test_bootstrap_real_mac_then_resumption_and_early_data(self):
        first = await self.connect()
        self.assertEqual(first.bootstrap_authorization['scope'], 'device-enrollment')
        self.assertEqual(self.channels[-1].authenticated_client, (self.binding.spki,))
        second = await self.connect(early_data=b'scoped replay-safe probe')
        self.assertTrue(second.resumed)
        self.assertTrue(second.early_data_accepted)
        self.assertEqual(second.bootstrap_authorization['scope'], 'device-enrollment')
        self.assertFalse(second.bootstrap_authorization['fresh_client_possession'])
        self.assertIn(b'scoped replay-safe probe', self.early)

    async def test_scope_change_and_expiry_do_not_reuse_authority(self):
        await self.connect()
        self.binding = replace(self.binding, scope='different-enrollment')
        changed = await self.connect()
        self.assertFalse(changed.resumed)
        self.binding = replace(self.binding, expires_at=datetime.now(timezone.utc) - timedelta(seconds=1))
        with self.assertRaises((ProtocolError, OSError)):
            await self.connect()

    async def test_explicit_provisioning_trust_works_without_ca_but_is_never_fallback(self):
        with self.assertRaises((ProtocolError, OSError)):
            await self.connect(roots=[])
        self.binding = replace(self.binding, trust_mode='provisioning-trust')
        channel = await self.connect(roots=[])
        self.assertEqual(channel.bootstrap_authorization['trust_mode'], 'provisioning-trust')
        self.assertEqual(channel.bootstrap_authorization['scope'], self.binding.scope)

    async def test_wrong_provisioned_key_does_not_issue_ticket(self):
        other = x25519.X25519PrivateKey.generate()
        spki = other.public_key().public_bytes(serialization.Encoding.DER,
                                             serialization.PublicFormat.SubjectPublicKeyInfo)
        reader, writer = await asyncio.open_connection('127.0.0.1', self.port)
        self.writers.append(writer)
        with self.assertRaises((ProtocolError, OSError)):
            await bootstrap_client_handshake(reader, writer, replace(self.binding, spki=spki),
                                              other, self.roots)
        self.assertFalse(self.channels)
        self.assertEqual(len(self.store._tickets), 0)

    async def test_correct_psk_binder_cannot_authorize_another_bsk_or_issue_ticket(self):
        wrong = x25519.X25519PrivateKey.generate().public_key().public_bytes(serialization.Encoding.DER,
                                             serialization.PublicFormat.SubjectPublicKeyInfo)
        send = Wire.send_frame
        changed = []
        async def substitute(wire, message, state=None):
            if wire.writer.get_extra_info('peername')[1] == self.port and message[0] in (11,25):
                message = m.certificate([wrong])
                changed.append(True)
            return await send(wire, message, state)
        with patch.object(Wire, 'send_frame', substitute), self.assertRaises((ProtocolError, OSError, AssertionError)):
            await self.connect()
        await asyncio.wait_for(asyncio.gather(*tuple(self.tasks), return_exceptions=True), 2)
        self.assertTrue(changed)
        self.assertFalse(self.channels)
        self.assertEqual(len(self.store._tickets), 0)
        self.assertTrue(any('bootstrap' in error.lower() for error in self.errors), self.errors)

    async def test_provisioning_trust_bad_server_mac_does_not_release_bsk(self):
        self.binding = replace(self.binding, trust_mode='provisioning-trust')
        send = Wire.send_frame
        client_certificates = []
        async def substitute(wire, message, state=None):
            client = wire.writer.get_extra_info('peername')[1] == self.port
            if client and message[0] in (11,25):
                client_certificates.append(message)
            elif not client and message[0] == 15:
                message = message[:-1] + bytes((message[-1] ^ 1,))
            return await send(wire, message, state)
        with patch.object(Wire, 'send_frame', substitute), self.assertRaises((ProtocolError, OSError)):
            await self.connect(roots=[])
        await asyncio.wait_for(asyncio.gather(*tuple(self.tasks), return_exceptions=True), 2)
        self.assertFalse(client_certificates)
        self.assertFalse(self.channels)
        self.assertEqual(len(self.store._tickets), 0)


if __name__ == '__main__':
    unittest.main()
