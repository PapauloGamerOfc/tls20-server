"""Transport/resource tests; authenticated handshake tests live separately."""

from __future__ import annotations

import asyncio
from contextlib import suppress
import socket
import unittest
from unittest.mock import patch

from tls20_server.config import Config, Endpoint
from tls20_server.server import RunningServer, start_server, _close_writer


class FakeChannel:
    """Test double only: its byte stream is intentionally not encrypted."""

    def __init__(self, reader, writer):
        self.reader = reader
        self.writer = writer
        self.clean_close = False

    async def recv(self):
        content = await self.reader.read(16384)
        return content if content else None

    async def send(self, content):
        self.writer.write(content)
        await self.writer.drain()

    async def close(self):
        self.clean_close = True
        self.writer.close()
        await self.writer.wait_closed()

    def abort(self):
        self.writer.transport.abort()


class BufferedWriter:
    """Graceful close never finishes until an explicit transport abort."""

    def __init__(self):
        self.transport = self
        self.aborted = False
        self.closed = False
        self.finished = asyncio.Event()

    def close(self):
        self.closed = True

    def abort(self):
        self.aborted = True
        self.finished.set()

    async def wait_closed(self):
        await self.finished.wait()


class ServerTransportTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.running = []
        self.backends = []
        self.backend_tasks = set()
        self.clients = []
        self.backend_connections = 0
        self.received = bytearray()
        self.channels = []

        async def fake_handshake(reader, writer, credentials, server_name, timeout=10):
            marker = await reader.readexactly(1)
            if marker != b"A":
                raise ValueError("Test authentication failed")
            channel = FakeChannel(reader, writer)
            self.channels.append(channel)
            return channel

        self.handshake_patch = patch("tls20_server.server.server_handshake", fake_handshake)
        self.handshake_patch.start()
        self.addCleanup(self.handshake_patch.stop)

    async def asyncTearDown(self):
        for running in self.running:
            await running.close()
        for writer in self.clients:
            writer.close()
            with suppress(Exception):
                await writer.wait_closed()
        for backend in self.backends:
            backend.close()
        tasks = tuple(self.backend_tasks)
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        for backend in self.backends:
            await backend.wait_closed()

    async def make_backend(self, callback=None):
        async def serve(reader, writer):
            task = asyncio.current_task()
            self.backend_tasks.add(task)
            self.backend_connections += 1
            try:
                if callback:
                    await callback(reader, writer)
                else:
                    while content := await reader.read(16384):
                        self.received.extend(content)
                        writer.write(content)
                        await writer.drain()
            finally:
                writer.close()
                with suppress(Exception, asyncio.CancelledError):
                    await writer.wait_closed()
                self.backend_tasks.discard(task)

        backend = await asyncio.start_server(serve, "127.0.0.1", 0)
        self.backends.append(backend)
        return Endpoint("127.0.0.1", backend.sockets[0].getsockname()[1])

    async def make_server(self, callback=None, **limits):
        upstream = await self.make_backend(callback)
        config = Config(listen=Endpoint("127.0.0.1", 0), upstream=upstream, **limits)
        running = await start_server(config, credentials=object())
        self.running.append(running)
        return running

    async def connect(self, running, authenticate=True):
        reader, writer = await asyncio.open_connection(
            "127.0.0.1", running.server.sockets[0].getsockname()[1]
        )
        self.clients.append(writer)
        if authenticate:
            writer.write(b"A")
            await writer.drain()
        return reader, writer

    async def wait_until(self, predicate, timeout=2):
        async with asyncio.timeout(timeout):
            while not predicate():
                await asyncio.sleep(0.005)

    async def test_no_upstream_before_authentication_or_on_failure(self):
        running = await self.make_server()
        reader, writer = await self.connect(running, authenticate=False)
        await asyncio.sleep(0.025)
        self.assertEqual(self.backend_connections, 0)
        writer.write(b"X")
        await writer.drain()
        self.assertEqual(await asyncio.wait_for(reader.read(), 2), b"")
        self.assertEqual(self.backend_connections, 0)

    async def test_successful_duplex_relay_preserves_exact_bytes(self):
        running = await self.make_server()
        reader, writer = await self.connect(running)
        payload = b"POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 4\r\n\r\n\x00\xffxy"
        writer.write(payload)
        await writer.drain()
        self.assertEqual(await asyncio.wait_for(reader.readexactly(len(payload)), 2), payload)
        self.assertEqual(bytes(self.received), payload)
        self.assertEqual(self.backend_connections, 1)

    async def test_handshake_timeout_and_admission_capacity(self):
        running = await self.make_server(max_connections=1, handshake_timeout_seconds=0.2)
        first, _ = await self.connect(running, authenticate=False)
        await self.wait_until(lambda: len(running._tasks) == 1)
        second, _ = await self.connect(running, authenticate=False)
        self.assertEqual(await asyncio.wait_for(second.read(), 1), b"")
        self.assertEqual(await asyncio.wait_for(first.read(), 1), b"")
        await self.wait_until(lambda: not running._tasks)
        self.assertEqual(self.backend_connections, 0)

    async def test_shutdown_closes_live_and_handshaking_connections(self):
        running = await self.make_server()
        active, _ = await self.connect(running)
        pending, _ = await self.connect(running, authenticate=False)
        await self.wait_until(lambda: self.backend_connections == 1)
        await running.close()
        self.assertEqual(await asyncio.wait_for(active.read(), 1), b"")
        self.assertEqual(await asyncio.wait_for(pending.read(), 1), b"")
        self.assertEqual(len(running._tasks), 0)
        self.assertFalse(running.server.is_serving())
        await running.close()  # Idempotent.

    async def test_shutdown_before_handler_first_execution_closes_transport(self):
        running = await self.make_server()
        writer = BufferedWriter()
        # Call the synchronous accept hook, then close immediately without an
        # event-loop yield that would let the newly scheduled handler start.
        running._accept(asyncio.StreamReader(), writer)
        await running.close()
        self.assertTrue(writer.closed)
        self.assertTrue(writer.aborted)
        self.assertFalse(running._tasks)
        self.assertFalse(running._writers)

    async def test_close_writer_timeout_error_and_cancellation_force_abort(self):
        writer = BufferedWriter()
        with patch("tls20_server.server.CLOSE_WAIT_SECONDS", 0.02):
            await asyncio.wait_for(_close_writer(writer), 1)
        self.assertTrue(writer.aborted)

        class FailingWriter(BufferedWriter):
            async def wait_closed(self):
                raise OSError("Synthetic failure")

        failed = FailingWriter()
        await _close_writer(failed)
        self.assertTrue(failed.aborted)
        cancelled = BufferedWriter()
        task = asyncio.create_task(_close_writer(cancelled))
        await asyncio.sleep(0)
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await task
        self.assertTrue(cancelled.aborted)

    async def test_shutdown_wait_for_listener_is_bounded(self):
        class StalledListener:
            def close(self):
                pass

            async def wait_closed(self):
                await asyncio.Event().wait()

        running = RunningServer(Config(), object())
        running.server = StalledListener()
        incoming, outgoing = BufferedWriter(), BufferedWriter()
        running._writers.add(incoming)
        running._upstream_writers.add(outgoing)
        with patch("tls20_server.server.CLOSE_WAIT_SECONDS", 0.02):
            await asyncio.wait_for(running.close(), 1)
        self.assertTrue(incoming.aborted)
        self.assertTrue(outgoing.aborted)

    async def test_rejected_connections_abort_without_buffered_graceful_close(self):
        running = RunningServer(Config(), object())
        running._closing = True
        writer = BufferedWriter()
        running._accept(asyncio.StreamReader(), writer)
        self.assertTrue(writer.aborted)
        self.assertFalse(running._tasks)

    async def test_admission_slot_is_not_released_before_transport_abort(self):
        running = RunningServer(Config(max_connections=1), object())
        slots_at_abort = []

        class ObservedWriter(BufferedWriter):
            def abort(self):
                slots_at_abort.append(len(running._tasks))
                super().abort()

        async def synthetic_handler(reader, writer):
            # Emulate a handler failing before its own cleanup could run.
            return

        running._handle = synthetic_handler
        writer = ObservedWriter()
        running._accept(asyncio.StreamReader(), writer)
        await self.wait_until(lambda: not running._tasks)
        self.assertEqual(slots_at_abort, [1])
        self.assertTrue(writer.aborted)
        self.assertFalse(running._writers)

    async def test_unread_loopback_output_is_aborted_and_no_transport_is_left_behind(self):
        accepted = asyncio.get_running_loop().create_future()

        def accept(reader, writer):
            accepted.set_result(writer)

        listener = await asyncio.start_server(accept, "127.0.0.1", 0)
        client = None
        server_writer = None
        try:
            _, client = await asyncio.open_connection("127.0.0.1", listener.sockets[0].getsockname()[1])
            server_writer = await accepted
            client.transport.pause_reading()
            client.get_extra_info("socket").setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
            server_writer.get_extra_info("socket").setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4096)
            server_writer.write(b"x" * (2 * 1024 * 1024))
            # Proactor transports may count their first write as in-flight
            # rather than buffered; a second immediate write is queued too.
            server_writer.write(b"y" * (2 * 1024 * 1024))
            self.assertGreater(server_writer.transport.get_write_buffer_size(), 0)
            with patch("tls20_server.server.CLOSE_WAIT_SECONDS", 0.03):
                await asyncio.wait_for(_close_writer(server_writer), 1)
            await asyncio.sleep(0)
            self.assertEqual(server_writer.transport.get_write_buffer_size(), 0)
            # A still-buffered accepted transport would hang wait_closed on
            # modern asyncio even though its handler had already completed.
            listener.close()
            await asyncio.wait_for(listener.wait_closed(), 1)
        finally:
            if client is not None:
                client.transport.abort()
            if server_writer is not None:
                server_writer.transport.abort()
            listener.close()
            await asyncio.wait_for(listener.wait_closed(), 1)

    async def test_shared_idle_timer_does_not_kill_a_one_way_download(self):
        async def download(reader, writer):
            for _ in range(8):
                writer.write(b"x")
                await writer.drain()
                await asyncio.sleep(0.025)

        running = await self.make_server(download, idle_timeout_seconds=0.12)
        reader, _ = await self.connect(running)
        self.assertEqual(await asyncio.wait_for(reader.read(), 2), b"x" * 8)
        self.assertTrue(self.channels[0].clean_close)

    async def test_idle_timeout_and_total_lifetime(self):
        for limits in (
            {"idle_timeout_seconds": 0.1},
            {"max_connection_seconds": 0.1, "idle_timeout_seconds": 10},
        ):
            with self.subTest(limits=limits):
                running = await self.make_server(**limits)
                reader, _ = await self.connect(running)
                self.assertEqual(await asyncio.wait_for(reader.read(), 2), b"")
                self.assertFalse(self.channels[-1].clean_close)

    async def test_upload_and_download_byte_quotas_do_not_forward_over_limit(self):
        running = await self.make_server(max_bytes_per_direction=3)
        reader, writer = await self.connect(running)
        writer.write(b"ABCDE")
        await writer.drain()
        self.assertEqual(await asyncio.wait_for(reader.read(), 2), b"")
        self.assertEqual(bytes(self.received), b"")

        async def download(reader, writer):
            writer.write(b"ABCDE")
            await writer.drain()

        running = await self.make_server(download, max_bytes_per_direction=3)
        reader, _ = await self.connect(running)
        self.assertEqual(await asyncio.wait_for(reader.read(), 2), b"")
        self.assertFalse(self.channels[-1].clean_close)

    async def test_verified_client_close_ends_stream_without_later_response(self):
        running = await self.make_server()
        reader, writer = await self.connect(running)
        writer.write(b"request")
        await writer.drain()
        self.assertEqual(await asyncio.wait_for(reader.readexactly(7), 2), b"request")
        # Only the test double maps TCP EOF to verified close_notify. The real
        # SecureChannel rejects unauthenticated network EOF instead.
        writer.write_eof()
        self.assertEqual(await asyncio.wait_for(reader.read(), 2), b"")
        self.assertEqual(bytes(self.received), b"request")
        self.assertTrue(self.channels[0].clean_close)

    async def test_bad_credentials_fail_before_binding(self):
        with patch("tls20_server.server.load_credentials", side_effect=ValueError), patch(
            "tls20_server.server.asyncio.start_server"
        ) as listen:
            with self.assertRaises(ValueError):
                await start_server(Config())
            listen.assert_not_called()

    async def test_empty_application_record_is_not_eof(self):
        running = await self.make_server()
        reader, writer = await self.connect(running)
        await self.wait_until(lambda: len(self.channels) == 1)
        channel = self.channels[0]
        original_recv = channel.recv
        calls = 0

        async def recv_with_empty():
            nonlocal calls
            calls += 1
            if calls == 1:
                return b""
            return await original_recv()

        # Patch before the backend's connection completes / next receive;
        # either the current or next receive returns the test empty record.
        channel.recv = recv_with_empty
        writer.write(b"first")
        await writer.drain()
        self.assertEqual(await asyncio.wait_for(reader.readexactly(5), 2), b"first")
        writer.write(b"second")
        await writer.drain()
        self.assertEqual(await asyncio.wait_for(reader.readexactly(6), 2), b"second")
        self.assertGreaterEqual(calls, 2)


if __name__ == "__main__":
    unittest.main()
