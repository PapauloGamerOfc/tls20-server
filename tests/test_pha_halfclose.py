"""Peer half-close consumes PHA verifiers without cancelling the write side."""

import asyncio
import unittest

from tests.test_duplex_control_ordering import PausedWriter
from tests.test_robustness import MemoryWriter
from tls20_server import crypto as c, handshake as hs, messages as m
from tls20_server.errors import ProtocolError
from tls20_server.lab import generate_lab_credentials


class PHAHalfCloseTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.channels, self.writers, self.tasks, self.listeners = [], [], [], []

    async def asyncTearDown(self):
        for channel in self.channels:
            channel.abort()
        for writer in self.writers:
            if isinstance(writer, PausedWriter):
                writer.release_all()
            writer.close()
        for task in self.tasks:
            if not task.done():
                task.cancel()
        await asyncio.gather(*self.tasks, return_exceptions=True)
        await asyncio.gather(*(writer.wait_closed() for writer in self.writers), return_exceptions=True)
        for listener in self.listeners:
            listener.close()
            await listener.wait_closed()

    async def pair(self, suite):
        credentials, root = generate_lab_credentials("localhost")
        accepted = asyncio.get_running_loop().create_future()

        async def handle(reader, writer):
            self.writers.append(writer)
            try:
                server = await hs.server_handshake(reader, writer, credentials, "localhost",
                    cipher_suites=(suite,), client_auth_validator=lambda chain: None)
                self.channels.append(server)
                accepted.set_result(server)
            except BaseException as error:
                if not accepted.done():
                    accepted.set_exception(error)

        def accept(reader, writer):
            self.tasks.append(asyncio.create_task(handle(reader, writer)))

        listener = await asyncio.start_server(accept, "127.0.0.1", 0)
        self.listeners.append(listener)
        reader, writer = await asyncio.open_connection("127.0.0.1", listener.sockets[0].getsockname()[1])
        self.writers.append(writer)
        client = await hs.client_handshake(reader, writer, "localhost", [root],
            revocation_policy="lab-offline", post_handshake_auth=True, cipher_suites=(suite,))
        self.channels.append(client)
        return client, await asyncio.wait_for(accepted, 3)

    async def settled(self):
        # Future callbacks run after recv() returns, not necessarily within it.
        for _ in range(3):
            await asyncio.sleep(0)

    async def test_real_peer_close_preserves_response_with_pending_or_active_pha(self):
        for suite in (0x1301, 0x1302):
            for mode in ("no-pha", "pending", "active", "multiple"):
                with self.subTest(suite=suite, mode=mode):
                    client, server = await self.pair(suite)
                    states = []
                    for _ in range(2 if mode == "multiple" else int(mode != "no-pha")):
                        await server.request_client_auth()
                        state = list(server.pending_client_auth.values())[-1]
                        states.append(state)
                        request = await asyncio.wait_for(client.wire.receive_frame(13, client.receiver), 3)
                        context = m.parse_certificate_request(request[4:])[0]
                        self.assertEqual(context, state["context"])
                    if mode == "active":
                        await client.send_handshake(m.certificate([], context=states[0]["context"], allow_empty=True))
                    # The wire alert closes only the client->server direction.
                    client.wire.writer.write(client.sender.seal(b"\x01\x00", 21))
                    await client.wire.writer.drain()
                    client.sent_close = True
                    client.sender.close()
                    self.assertIsNone(await asyncio.wait_for(server.recv(), 3))
                    await self.settled()
                    self.assertFalse(server.closed)
                    self.assertTrue(server.received_close)
                    self.assertFalse(server.sent_close)
                    self.assertTrue(server.receiver.failed)
                    self.assertFalse(server.sender.failed)
                    self.assertFalse(server.pending_client_auth)
                    self.assertIsNone(server._active_client_auth)
                    self.assertIsNone(server.authenticated_client)
                    for state in states:
                        self.assertTrue(state["future"].cancelled())
                        self.assertIsNone(state["private"])
                    response = b"response after authenticated peer half-close"
                    await server.send(response)
                    self.assertEqual(await asyncio.wait_for(client.wire.read_record(client.receiver), 3),
                                     (response, 23))
                    await server.close()
                    self.assertEqual(await asyncio.wait_for(client.wire.read_record(client.receiver), 3),
                                     (b"\x01\x00", 21))
                    self.assertTrue(server.sender.failed)
                    self.assertIsNone(server.exporter_secret)
                    client.abort()

    async def pending_channel(self, writer=None):
        writer = writer or MemoryWriter()
        channel = hs.SecureChannel(hs.Wire(asyncio.StreamReader(), writer), bytes(32), bytes(32),
            role="server", peer_post_handshake_auth=True, client_auth_validator=lambda chain: None,
            handshake_transcript=b"test handshake transcript", exporter_secret=b"e" * 32)
        self.channels.append(channel)
        self.writers.append(writer)
        future = await channel.request_client_auth()
        return channel, future, next(iter(channel.pending_client_auth.values()))

    async def test_explicit_future_cancellation_still_aborts_before_or_after_peer_close(self):
        for peer_close in (False, True):
            with self.subTest(peer_close=peer_close):
                channel, future, state = await self.pending_channel()
                self.assertTrue(future.cancel())
                if peer_close:
                    peer = c.RecordState(bytes(32), "seal")
                    try:
                        channel.wire.reader.feed_data(peer.seal(b"\x01\x00", 21))
                        # All input is buffered. Cleanup runs before the callback.
                        self.assertIsNone(await channel.recv())
                        self.assertFalse(channel.closed)
                    finally:
                        peer.close()
                await self.settled()
                self.assertTrue(channel.closed)
                self.assertTrue(channel.wire.writer.transport.aborted)
                self.assertTrue(channel.sender.failed)
                self.assertTrue(channel.receiver.failed)
                self.assertIsNone(channel.exporter_secret)
                self.assertIsNone(state["private"])
                self.assertIsNone(channel.authenticated_client)
                with self.assertRaises(ProtocolError):
                    await channel.send(b"not allowed after explicit cancellation")

    async def test_pending_pha_cleanup_does_not_drop_a_backpressured_response(self):
        writer = PausedWriter(pauses=(2,))  # Request first, application record second.
        channel, future, state = await self.pending_channel(writer)
        channel.sender.record_limit = 64
        upload = asyncio.create_task(channel.send(b"x" * 189))
        self.tasks.append(upload)
        await asyncio.wait_for(writer.entered[2].wait(), 3)
        peer, observer = c.RecordState(bytes(32), "seal"), c.RecordState(bytes(32), "open")
        try:
            channel.wire.reader.feed_data(peer.seal(b"\x01\x00", 21))
            self.assertIsNone(await channel.recv())
            await self.settled()
            self.assertFalse(channel.closed)
            self.assertTrue(future.cancelled())
            self.assertIsNone(state["private"])
            writer.release_all()
            await asyncio.wait_for(upload, 3)
            records = [observer.open(record) for record in writer.records]
            self.assertEqual([kind for _, kind in records], [22, 23, 23, 23])
            self.assertEqual(b"".join(content for content, kind in records if kind == 23), b"x" * 189)
            await channel.close()
            self.assertEqual(observer.open(writer.records[-1]), (b"\x01\x00", 21))
        finally:
            peer.close()
            observer.close()


if __name__ == "__main__":
    unittest.main()
