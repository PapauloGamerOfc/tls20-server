"""Continuity proofs across real loopback TLS 2.0 handshakes."""

import asyncio
import os
import unittest
from unittest.mock import patch

from tests import test_sessions
from tls20_server.errors import ProtocolError
from tls20_server.handshake import Wire, client_handshake
from tls20_server.lab import generate_lab_credentials
from tls20_server.pinning import PinningCache, ServerPinning


class PinningHandshakeTests(unittest.IsolatedAsyncioTestCase):
    accept = test_sessions.SessionTests.accept
    handle = test_sessions.SessionTests.handle
    asyncTearDown = test_sessions.SessionTests.asyncTearDown

    async def asyncSetUp(self):
        await test_sessions.SessionTests.asyncSetUp(self)
        self.identity, self.secret = os.urandom(16), os.urandom(32)
        self.pinning = ServerPinning({self.identity: self.secret}, self.identity)
        self.pins = PinningCache()
        self.server_options = {'pinning': self.pinning, 'pinning_port': self.port}

    async def connect(self, **options):
        reader, writer = await asyncio.open_connection('127.0.0.1', self.port)
        self.writers.append(writer)
        channel = await client_handshake(reader, writer, 'localhost', self.roots,
            revocation_policy='lab-offline', ticket_cache=self.cache,
            pinning_cache=self.pins, pinning_port=self.port, **options)
        self.assertEqual(await asyncio.wait_for(channel.recv(), 2), b'ready', self.errors)
        return channel

    async def test_initial_refresh_hash_change_and_retry_never_select_psk(self):
        for options in ({}, {'cipher_suites': (0x1302,)}, {'force_retry': True}):
            channel = await self.connect(**options)
            self.assertFalse(channel.resumed)
            self.assertFalse(channel.early_data_accepted)
            self.assertTrue(self.pins.begin('localhost', self.port).extension)
            await channel.send(b'pinned application')
            self.assertEqual(await channel.recv(), b'pinned application')
        self.assertTrue(self.cache._tickets)  # Tickets may exist; pinning never offers them.

    async def test_key_rotation_and_new_ca_identity_preserve_continuity(self):
        await self.connect()
        old_pin = self.pins.begin('localhost', self.port).extension
        self.credentials, root = generate_lab_credentials('localhost')
        self.roots = [root]
        new_id = os.urandom(16)
        self.server_options['pinning'] = ServerPinning(
            {self.identity: self.secret, new_id: os.urandom(32)}, new_id)
        await self.connect()
        self.assertNotEqual(old_pin, self.pins.begin('localhost', self.port).extension)

    async def test_missing_or_invalid_proof_keeps_pin_and_prevents_client_flight(self):
        await self.connect()
        previous = self.pins.begin('localhost', self.port).extension
        self.server_options.pop('pinning')
        with self.assertRaises((ProtocolError, OSError)):
            await self.connect()
        self.assertEqual(previous, self.pins.begin('localhost', self.port).extension)
        self.server_options['pinning'] = self.pinning
        original = self.pinning.respond
        def wrong_proof(*args, **kwargs):
            response = original(*args, **kwargs)
            return response[:1] + bytes(32) + response[33:]
        observed = []
        send_frame = Wire.send_frame
        async def watch(wire, message, state=None):
            if message[0] in (11, 20):
                observed.append((wire.writer.get_extra_info('peername')[1], message[0]))
            return await send_frame(wire, message, state)
        with patch.object(self.pinning, 'respond', wrong_proof), patch.object(Wire, 'send_frame', watch):
            with self.assertRaises((ProtocolError, OSError)):
                await self.connect(client_credentials=self.credentials)
        # Client's peer port is listener port; server's peer port is ephemeral.
        self.assertFalse([kind for port, kind in observed if port == self.port])
        self.assertEqual(previous, self.pins.begin('localhost', self.port).extension)

    async def test_invalid_credentials_cannot_enroll_and_authenticated_ramp_down(self):
        roots = self.roots
        self.roots = []
        with self.assertRaises((ProtocolError, OSError)):
            await self.connect()
        self.assertEqual(self.pins.begin('localhost', self.port).extension, b'')
        self.roots = roots
        await self.connect()
        self.server_options['pinning'] = ServerPinning(
            {self.identity: self.secret}, self.identity, ramp_down=True)
        await self.connect()
        self.assertEqual(self.pins.begin('localhost', self.port).extension, b'')

    async def test_early_payload_is_not_silently_sent_in_pin_exchange(self):
        await self.connect()
        with self.assertRaises(ValueError):
            await self.connect(early_data=b'not permitted')
        self.assertFalse(self.early)


if __name__ == '__main__':
    unittest.main()
