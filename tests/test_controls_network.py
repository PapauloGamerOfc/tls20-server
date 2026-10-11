"""Control profiles over authenticated records, not just extension parsers."""
import asyncio
from dataclasses import replace
import unittest

from tests import test_sessions
from tls20_server.errors import ProtocolError
from tls20_server.optional_controls import SignalingBinding, TicketRequest


class ControlNetworkTests(unittest.IsolatedAsyncioTestCase):
    asyncSetUp = test_sessions.SessionTests.asyncSetUp
    asyncTearDown = test_sessions.SessionTests.asyncTearDown
    accept = test_sessions.SessionTests.accept
    handle = test_sessions.SessionTests.handle
    connect = test_sessions.SessionTests.connect

    async def test_heartbeat_both_directions_and_key_update(self):
        self.server_options = {"heartbeat_mode": 1, "record_size_limit": 64}
        channel = await self.connect(heartbeat_mode=1, record_size_limit=128)
        # recv must keep processing records while the application waits for a probe.
        reader = asyncio.create_task(channel.recv())
        try:
            for index in range(2):
                if index:
                    await channel.key_update(request_peer=True)
                probe = await channel.request_heartbeat(b"client probe")
                self.assertEqual(await asyncio.wait_for(probe, 2), b"client probe")
                probe = await self.channels[-1].request_heartbeat(b"server probe")
                self.assertEqual(await asyncio.wait_for(probe, 2), b"server probe")
            await channel.send(b"still usable")
            self.assertEqual(await asyncio.wait_for(reader, 2), b"still usable")
        finally:
            reader.cancel()
            await asyncio.gather(reader, return_exceptions=True)

    async def test_directional_permission_and_no_implicit_negotiation(self):
        self.server_options = {"heartbeat_mode": 2}
        channel = await self.connect(heartbeat_mode=1)
        with self.assertRaises(ProtocolError):
            await channel.request_heartbeat()
        # The server can ask because the client independently permitted requests.
        reader = asyncio.create_task(channel.recv())
        try:
            probe = await self.channels[-1].request_heartbeat(b"one direction")
            self.assertEqual(await asyncio.wait_for(probe, 2), b"one direction")
            await channel.send(b"ok")
            self.assertEqual(await asyncio.wait_for(reader, 2), b"ok")
        finally:
            reader.cancel()
            await asyncio.gather(reader, return_exceptions=True)
        channel = await self.connect()
        with self.assertRaises(ProtocolError):
            await channel.request_heartbeat()
        with self.assertRaises(ProtocolError):
            await self.channels[-1].request_heartbeat()

    async def test_malformed_heartbeat_never_echoes_declared_missing_bytes(self):
        self.server_options = {"heartbeat_mode": 1}
        channel = await self.connect(heartbeat_mode=1)
        async with channel.send_lock:
            await channel._send_heartbeat_locked(b"\x01\xff\xff" + b"x" * 16)
        # If bogus input were echoed, this would fail while parsing the record.
        await channel.send(b"after malformed heartbeat")
        self.assertEqual(await asyncio.wait_for(channel.recv(), 2), b"after malformed heartbeat")

    async def test_ticket_counts_new_resumed_zero_and_local_budget(self):
        self.server_options = {"ticket_count_limit": 7}
        first = await self.connect(ticket_request=TicketRequest(3, 2))
        self.assertEqual(first.expected_ticket_count, 3)
        second = await self.connect(ticket_request=TicketRequest(3, 2))
        self.assertTrue(second.resumed)
        self.assertEqual(second.expected_ticket_count, 2)
        third = await self.connect(ticket_request=TicketRequest(0, 0))
        self.assertEqual(third.expected_ticket_count, 0)
        fourth = await self.connect(ticket_request=TicketRequest(255, 255))
        self.assertEqual(fourth.expected_ticket_count, 7)

    async def test_mfl_and_record_limit_precedence(self):
        for mfl in (1, 2, 3, 4):
            channel = await self.connect(max_fragment_length=mfl)
            self.assertEqual(channel.sender.record_limit, (1 << (8 + mfl)) + 1)
            self.assertEqual(channel.receiver.record_limit, channel.sender.record_limit)
            content = b"fragment me" * 1000
            await channel.send(content)
            received = bytearray()
            while len(received) < len(content):
                received.extend(await asyncio.wait_for(channel.recv(), 2))
            self.assertEqual(received, content)
        self.server_options = {"record_size_limit": 128}
        channel = await self.connect(max_fragment_length=1, record_size_limit=256)
        self.assertEqual(channel.sender.record_limit, 128)
        self.assertEqual(channel.receiver.record_limit, 256)

    async def test_signaling_is_external_current_policy_not_peer_assertion(self):
        client = SignalingBinding(b"a" * 32, b"b" * 32, b"c" * 20, b"s" * 20)
        server = SignalingBinding(client.peer_hash, client.local_hash,
                                  client.peer_session_id, client.local_session_id)
        self.server_options = {"signaling": server}
        channel = await self.connect(signaling=client, force_retry=True)
        await channel.send(b"bound")
        self.assertEqual(await channel.recv(), b"bound")
        with self.assertRaises((ProtocolError, ConnectionError)):
            await self.connect(signaling=replace(client, peer_hash=b"z" * 32))
        with self.assertRaises((ProtocolError, ConnectionError)):
            await self.connect()
