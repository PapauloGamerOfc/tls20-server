"""Real loopback early HTTP tests; no external listener or production keys."""

import asyncio
from contextlib import suppress
import io
import unittest

from tls20_server.client import fetch
from tls20_server.config import Config, Endpoint
from tls20_server.handshake import client_handshake
from tls20_server.lab import generate_lab_credentials
from tls20_server.server import start_server
from tls20_server.tickets import TicketCache


class DelayClientFinished:
    """Allow CH/early/EOED onto the wire; hold CF until backend observed early HTTP."""

    def __init__(self, writer, backend_event):
        self.writer = writer
        self.backend_event = backend_event
        self.encrypted_records = 0
        self.blocked_before_finished = False

    def __getattr__(self, name):
        return getattr(self.writer, name)

    def write(self, data):
        if data[:1] == b"\x17":
            self.encrypted_records += 1
        self.writer.write(data)

    async def drain(self):
        await self.writer.drain()
        if self.encrypted_records == 2:
            self.blocked_before_finished = True
            await asyncio.wait_for(self.backend_event.wait(), 2)


class EarlyRelayTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.credentials, ca = generate_lab_credentials("localhost")
        self.roots = [ca]
        self.requests = []
        self.tasks = set()
        self.writers = set()
        self.early_observed = asyncio.Event()
        self.backend_refuses_early = False

        async def backend(reader, writer):
            self.tasks.add(asyncio.current_task())
            self.writers.add(writer)
            try:
                request = await reader.readuntil(b"\r\n\r\n")
                self.requests.append(request)
                if b"Early-Data: 1\r\n" in request:
                    self.early_observed.set()
                if self.backend_refuses_early and b"Early-Data: 1\r\n" in request:
                    writer.write(b"HTTP/1.1 103 Early Hints\r\nLink: </style.css>\r\n\r\n"
                                 b"HTTP/1.1 425 Too Early\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                else:
                    writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
                await writer.drain()
            finally:
                writer.close()
                with suppress(OSError):
                    await writer.wait_closed()
                self.writers.discard(writer)

        self.backend = await asyncio.start_server(backend, "127.0.0.1", 0)
        port = self.backend.sockets[0].getsockname()[1]
        self.running = await start_server(Config(
            listen=Endpoint("127.0.0.1", 0), upstream=Endpoint("127.0.0.1", port),
            upstream_early_data_aware=True, early_data_paths=("/",),
        ), self.credentials)
        self.port = self.running.server.sockets[0].getsockname()[1]

    async def asyncTearDown(self):
        await self.running.close()
        self.backend.close()
        for writer in tuple(self.writers):
            writer.close()
        for task in self.tasks:
            if not task.done():
                task.cancel()
        await asyncio.gather(*self.tasks, return_exceptions=True)
        await self.backend.wait_closed()

    async def test_real_early_request_reaches_backend_before_client_finished(self):
        cache = TicketCache()
        context = f"localhost:{self.port}".encode("ascii")
        request = f"GET / HTTP/1.1\r\nHost: localhost:{self.port}\r\nConnection: close\r\n\r\n".encode("ascii")
        for attempt in range(2):
            reader, writer = await asyncio.open_connection("127.0.0.1", self.port)
            wrapper = DelayClientFinished(writer, self.early_observed) if attempt else writer
            channel = None
            try:
                channel = await client_handshake(reader, wrapper, "localhost", self.roots,
                    revocation_policy="lab-offline", ticket_cache=cache,
                    cache_context=context, early_data=request if attempt else b"")
                self.assertEqual(channel.resumed, bool(attempt))
                self.assertEqual(channel.early_data_accepted, bool(attempt))
                if attempt:
                    self.assertTrue(wrapper.blocked_before_finished)
                    self.assertTrue(self.early_observed.is_set())
                else:
                    await channel.send(request)
                response = bytearray()
                while (part := await channel.recv()) is not None:
                    response.extend(part)
                self.assertTrue(response.endswith(b"\r\n\r\nok"))
            finally:
                if channel:
                    await channel.close()
                else:
                    writer.close()
                    await writer.wait_closed()
        self.assertEqual(len(self.requests), 2)
        self.assertNotIn(b"Early-Data:", self.requests[0])
        self.assertEqual(self.requests[1].count(b"Early-Data: 1\r\n"), 1)

    async def test_http_425_retries_once_without_early_forwarding(self):
        cache = TicketCache()
        for path in ("/", "/not-allowlisted"):
            output = io.BytesIO()
            await fetch(f"httpps://localhost:{self.port}{path}", self.roots,
                        revocation_policy="lab-offline", connect_host="127.0.0.1",
                        ticket_cache=cache, use_early_data=True, output=output)
            self.assertTrue(output.getvalue().startswith(b"HTTP/1.1 200 OK"))
            self.assertNotIn(b"425", output.getvalue())
        self.assertEqual(len(self.requests), 2)
        self.assertIn(b"GET /not-allowlisted HTTP/1.1", self.requests[1])
        self.assertNotIn(b"Early-Data:", self.requests[1])

    async def test_backend_103_then_425_retries_without_early(self):
        cache = TicketCache()
        self.backend_refuses_early = True
        for _ in range(2):
            output = io.BytesIO()
            await fetch(f"httpps://localhost:{self.port}/", self.roots,
                        revocation_policy="lab-offline", connect_host="127.0.0.1",
                        ticket_cache=cache, use_early_data=True, output=output)
            self.assertTrue(output.getvalue().startswith(b"HTTP/1.1 200 OK"))
            self.assertNotIn(b"425", output.getvalue())
        self.assertEqual(len(self.requests), 3)
        self.assertIn(b"Early-Data: 1\r\n", self.requests[1])
        self.assertNotIn(b"Early-Data:", self.requests[2])
