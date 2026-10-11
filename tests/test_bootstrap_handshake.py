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
                self.binding, ticket_store=self.store, max_early_data=65536, on_early_data=early)
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

    async def connect(self, *, binding=None, roots=None, **options):
        reader, writer = await asyncio.open_connection('127.0.0.1', self.port)
        self.writers.append(writer)
        channel = await bootstrap_client_handshake(reader, writer, binding or self.binding,
            self.private, self.roots if roots is None else roots, ticket_cache=self.cache, **options)
        self.assertEqual(await asyncio.wait_for(channel.recv(), 2), b'ready', self.errors)
        return channel

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
