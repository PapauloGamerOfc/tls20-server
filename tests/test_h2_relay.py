"""Real HTTP/2 multiplexing over authenticated TLS 2.0 and a loopback backend."""
import asyncio
from contextlib import suppress
import unittest

from h2.config import H2Configuration
from h2.connection import H2Connection
from h2.events import DataReceived, RequestReceived, ResponseReceived, StreamEnded

from tls20_server.config import Config, ConfigError, Endpoint
from tls20_server.handshake import client_handshake
from tls20_server.lab import generate_lab_credentials
from tls20_server.server import start_server


class H2RelayTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.tasks = set()
        self.writers = []
        self.errors = []
        self.requests = []
        self.connections = 0
        self.credentials, self.root = generate_lab_credentials("localhost")

        async def serve(reader, writer):
            self.connections += 1
            self.writers.append(writer)
            connection = H2Connection(H2Configuration(client_side=False, header_encoding="utf-8"))
            connection.initiate_connection()
            writer.write(connection.data_to_send())
            try:
                while data := await reader.read(65536):
                    for event in connection.receive_data(data):
                        if isinstance(event, RequestReceived):
                            headers = dict(event.headers)
                            self.requests.append(headers)
                            body = (headers[":scheme"] + " " + headers[":path"]).encode()
                            connection.send_headers(event.stream_id, [
                                (":status", "200"), ("content-type", "text/plain"),
                                ("content-length", str(len(body))), ("cache-control", "no-store")])
                            connection.send_data(event.stream_id, body, end_stream=True)
                        elif isinstance(event, DataReceived):
                            connection.acknowledge_received_data(event.flow_controlled_length, event.stream_id)
                    writer.write(connection.data_to_send())
                    await writer.drain()
            except (ConnectionError, asyncio.CancelledError):
                pass
            except Exception as error:
                self.errors.append(error)
            finally:
                writer.close()

        def accept(reader, writer):
            task = asyncio.create_task(serve(reader, writer))
            self.tasks.add(task)
            task.add_done_callback(self.tasks.discard)

        self.backend = await asyncio.start_server(accept, "127.0.0.1", 0)
        config = Config(listen=Endpoint("127.0.0.1", 0),
                        upstream=Endpoint("127.0.0.1", self.backend.sockets[0].getsockname()[1]),
                        upstream_protocol="h2")
        self.running = await start_server(config, credentials=self.credentials)

    async def asyncTearDown(self):
        await self.running.close()
        self.backend.close()
        await self.backend.wait_closed()
        tasks = tuple(self.tasks)
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        for writer in self.writers:
            writer.transport.abort()
            with suppress(OSError):
                await writer.wait_closed()

    async def connect(self, **options):
        reader, writer = await asyncio.open_connection(
            "127.0.0.1", self.running.server.sockets[0].getsockname()[1])
        self.writers.append(writer)
        return await client_handshake(reader, writer, "localhost", [self.root],
                                      revocation_policy="lab-offline", **options)

    async def test_parallel_h2_requests_share_one_authenticated_backend(self):
        channel = await self.connect(application_protocols=(b"h2", b"http/1.1"),
                                      post_handshake_auth=True)
        self.assertEqual(channel.protocol, b"h2")
        self.assertFalse(channel.local_post_handshake_auth)
        connection = H2Connection(H2Configuration(client_side=True, header_encoding="utf-8"))
        connection.initiate_connection()
        streams = list(range(1, 32, 2))
        for stream in streams:
            connection.send_headers(stream, [(":method", "GET"), (":scheme", "httpps"),
                                             (":authority", "localhost"), (":path", f"/{stream}")],
                                    end_stream=True)
        await channel.send(connection.data_to_send())
        responses, statuses, completed = {}, {}, set()
        async with asyncio.timeout(5):
            while len(completed) != len(streams):
                data = await channel.recv()
                self.assertIsNotNone(data)
                for event in connection.receive_data(data):
                    if isinstance(event, ResponseReceived):
                        statuses[event.stream_id] = dict(event.headers)[":status"]
                    elif isinstance(event, DataReceived):
                        responses.setdefault(event.stream_id, bytearray()).extend(event.data)
                        connection.acknowledge_received_data(event.flow_controlled_length, event.stream_id)
                    elif isinstance(event, StreamEnded):
                        completed.add(event.stream_id)
                if outgoing := connection.data_to_send():
                    await channel.send(outgoing)
        self.assertEqual(self.connections, 1)
        self.assertEqual(len(self.requests), len(streams))
        self.assertFalse(self.errors)
        for stream in streams:
            self.assertEqual(statuses[stream], "200")
            self.assertEqual(responses[stream], f"httpps /{stream}".encode())
        await channel.close()

    async def test_incompatible_alpn_does_not_open_backend(self):
        with self.assertRaises(ValueError):
            await self.connect(application_protocols=(b"http/1.1",))
        self.assertEqual(self.connections, 0)

    def test_h2_cannot_use_http1_route_early_gate(self):
        with self.assertRaises(ConfigError):
            Config(upstream_protocol="h2", upstream_early_data_aware=True, early_data_paths=("/safe",))
