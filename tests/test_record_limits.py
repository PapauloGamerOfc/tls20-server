import unittest
from unittest.mock import patch

from tls20_server import crypto as c
from tls20_server import messages as m
from tls20_server.errors import ProtocolError
from tls20_server.handshake import Wire, _peer_record_limit
from tests import test_sessions


class RecordLimitTests(unittest.TestCase):
    def test_server_accepts_future_client_limit_but_never_exceeds_protocol_limit(self):
        self.assertEqual(_peer_record_limit(b"\xff\xff", server=True), 16385)
        with self.assertRaises(ProtocolError):
            _peer_record_limit(b"\xff\xff")
        for server in (False, True):
            with self.assertRaises(ProtocolError):
                _peer_record_limit(b"\x00\x3f", server=server)

    def test_inner_type_and_padding_are_included_in_limit(self):
        sender = c.RecordState(bytes(32), "seal", record_limit=64)
        receiver = c.RecordState(bytes(32), "open", record_limit=64)
        self.assertEqual(receiver.open(sender.seal(b"x" * 60, 23, 3)), (b"x" * 60, 23))
        with self.assertRaises(ProtocolError):
            sender.seal(b"x" * 60, 23, 4)
        sender = c.RecordState(bytes(32), "seal")
        with self.assertRaises(ProtocolError):
            c.RecordState(bytes(32), "open", record_limit=64).open(sender.seal(b"x" * 64, 23))


class RecordLimitNetworkTests(unittest.IsolatedAsyncioTestCase):
    asyncSetUp = test_sessions.SessionTests.asyncSetUp
    asyncTearDown = test_sessions.SessionTests.asyncTearDown
    accept = test_sessions.SessionTests.accept
    handle = test_sessions.SessionTests.handle
    connect = test_sessions.SessionTests.connect

    async def test_asymmetric_limits_fragment_handshake_and_application_records(self):
        self.server_options = {"record_size_limit": 64}
        channel = await self.connect(record_size_limit=512)
        self.assertEqual(channel.sender.record_limit, 64)
        self.assertEqual(channel.receiver.record_limit, 512)
        self.assertEqual(self.channels[-1].sender.record_limit, 512)
        self.assertEqual(self.channels[-1].receiver.record_limit, 64)
        data = bytes(range(256)) * 8
        await channel.send(data)
        echoed = bytearray()
        while len(echoed) < len(data):
            echoed.extend(await channel.recv())
        self.assertEqual(echoed, data)
        await channel.key_update(True)
        await channel.send(b"after update")
        self.assertEqual(await channel.recv(), b"after update")

    async def test_unoffered_limit_is_not_silently_enforced(self):
        self.server_options = {"record_size_limit": 64}
        channel = await self.connect()
        self.assertEqual(channel.sender.record_limit, 16385)
        self.assertEqual(self.channels[-1].receiver.record_limit, 16385)

    async def test_large_ee_allowed_only_when_record_limit_is_not_negotiated(self):
        original_send, original_ee = Wire.send_frame, m.encrypted_extensions
        async def padded_ee(wire, message, state=None):
            if message[0] == 8:
                previous, state.record_limit = state.record_limit, 16385
                wire.writer.write(state.seal(message, 22, 100))
                await wire.writer.drain()
                state.record_limit = previous
            else:
                await original_send(wire, message, state)
        def decline_rsl(*args, **kwargs):
            kwargs["extra_extensions"] = tuple(pair for pair in kwargs.get("extra_extensions", ()) if pair[0] != 28)
            return original_ee(*args, **kwargs)
        with patch.object(Wire, "send_frame", padded_ee), patch.object(m, "encrypted_extensions", decline_rsl):
            channel = await self.connect(record_size_limit=64)
            self.assertEqual(channel.receiver.record_limit, 16385)
        self.cache._tickets.clear()
        with patch.object(Wire, "send_frame", padded_ee), self.assertRaises(ProtocolError) as failure:
            await self.connect(record_size_limit=64)
        self.assertEqual(failure.exception.alert, 22)

    async def test_resumed_early_data_uses_remembered_record_limit(self):
        self.server_options = {"record_size_limit": 64}
        await self.connect(record_size_limit=512)
        ticket = next(iter(self.cache._tickets.values()))
        self.assertEqual(ticket.record_size_limit, 64)
        client = await self.connect(record_size_limit=512, early_data=b"x" * 513)
        self.assertTrue(client.early_data_accepted)
        self.assertEqual(b"".join(self.early), b"x" * 513)
        self.assertTrue(all(len(chunk) <= 63 for chunk in self.early))

    async def test_oversized_early_record_is_rejected_before_callback(self):
        self.server_options = {"record_size_limit": 64}
        await self.connect(record_size_limit=512)
        ticket = next(iter(self.cache._tickets.values()))
        ticket.record_size_limit = 16385  # Model an authenticated but nonconforming client.
        with self.assertRaises((ProtocolError, OSError)):
            await self.connect(record_size_limit=512, early_data=b"x" * 64)
        self.assertFalse(self.early)
        self.assertTrue(any("record limit" in error for error in self.errors), self.errors)

    async def test_plaintext_fatal_alert_for_bad_initial_key_share(self):
        import asyncio
        from tls20_server import messages as m
        reader, writer = await asyncio.open_connection("127.0.0.1", self.port)
        self.writers.append(writer)
        wire = Wire(reader, writer)
        writer.write(c.PREFACE)
        _, public = c.traffic_key(29)
        await wire.send_frame(m.client_hello(bytes(32), public, "localhost", bytes(32)))
        self.assertEqual(await reader.read(), b"\x15\x03\x03\x00\x02\x02\x28")
