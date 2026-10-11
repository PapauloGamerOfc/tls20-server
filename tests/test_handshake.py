"""Loopback-only network tests; all credentials are generated per test run."""

import asyncio
from dataclasses import replace
import io
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from tls20_server import crypto as c, messages as m
from tls20_server.client import fetch, parse_url
from tls20_server.config import Config, Endpoint
from tls20_server.errors import ConfigurationError, ProtocolError
from tls20_server.handshake import Wire, client_handshake, server_handshake
from tls20_server.lab import create_lab
from tls20_server.pki import load_credentials, load_trust_roots
from tls20_server.server import start_server


class URLTests(unittest.TestCase):
    def test_url_and_default(self):
        self.assertEqual(parse_url("httpps://localhost/"), ("localhost", 343, "/"))
        self.assertEqual(parse_url("httpps://example.com:343/a?b=2"), ("example.com", 343, "/a?b=2"))
        self.assertEqual(parse_url("httpps://LOCALHOST/café"), ("localhost", 343, "/caf%C3%A9"))
        self.assertEqual(parse_url("httpps://example.com:8443/a"), ("example.com", 8443, "/a"))
        self.assertEqual(parse_url("httpps://example.com:1021/"), ("example.com", 1021, "/"))
        self.assertEqual(parse_url("httpps://127.0.0.1/"), ("127.0.0.1", 343, "/"))
        self.assertEqual(parse_url("httpps://[2001:0DB8:0:0:0:0:0:1]:8443/a"), ("2001:db8::1", 8443, "/a"))

    def test_invalid_urls(self):
        for url in ("https://localhost/", "http://localhost/", "httpps://127.0.00.1/",
                    "httpps://[fe80::1%25eth0]/", "httpps://[::1]trailer/",
                    "httpps://user@localhost/", "httpps://localhost:0/", "httpps://localhost:65536/",
                    "httpps://localhost/#fragment", "httpps://localhost/\r\nX:1", "httpps://localhost./"):
            with self.subTest(url=url), self.assertRaises(ConfigurationError):
                parse_url(url)


class NetworkTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="httpps-tests-")
        self.directory = Path(self.temp.name) / "lab"
        create_lab(self.directory, "localhost")
        self.credentials = load_credentials(self.directory / "fullchain.pem", self.directory / "server.key", "localhost")
        self.roots = load_trust_roots(self.directory / "ca.pem")
        self.listeners = []
        self.tasks = set()
        self.writers = []
        self.proxies = []
        self.backend_connections = 0
        self.backend_requests = []

    async def asyncTearDown(self):
        for proxy in self.proxies:
            await proxy.close()
        for listener in self.listeners:
            listener.close()
            await listener.wait_closed()
        for writer in self.writers:
            writer.close()
        for task in tuple(self.tasks):
            task.cancel()
        await asyncio.gather(*self.tasks, return_exceptions=True)
        for writer in self.writers:
            try:
                await asyncio.wait_for(writer.wait_closed(), 1)
            except (OSError, TimeoutError):
                pass
        self.temp.cleanup()

    async def listener(self, handler):
        def accept(reader, writer):
            self.writers.append(writer)
            task = asyncio.create_task(handler(reader, writer))
            self.tasks.add(task)
            # Keep completed tasks until teardown so their errors are retrieved.
        listener = await asyncio.start_server(accept, "127.0.0.1", 0)
        self.listeners.append(listener)
        return listener.sockets[0].getsockname()[1]

    async def connect(self, port):
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        self.writers.append(writer)
        return reader, writer

    async def backend(self, reader, writer):
        self.backend_connections += 1
        request = await reader.readuntil(b"\r\n\r\n")
        self.backend_requests.append(request)
        body = b"hello through HTTPPS\n" * 2000
        writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: " + str(len(body)).encode() + b"\r\nConnection: close\r\n\r\n" + body)
        await writer.drain()
        writer.close()

    async def proxy(self, **changes):
        port = await self.listener(self.backend)
        config = Config(listen=Endpoint("127.0.0.1", 0), upstream=Endpoint("127.0.0.1", port),
                        certificate_chain=self.directory / "fullchain.pem", private_key=self.directory / "server.key")
        config = replace(config, **changes)
        proxy = await start_server(config)
        self.proxies.append(proxy)
        return proxy.server.sockets[0].getsockname()[1]

    async def test_real_certificate_http_roundtrip(self):
        port = await self.proxy()
        output = io.BytesIO()
        count = await fetch(f"httpps://localhost:{port}/test?ok=1", self.roots,
                            revocation_policy="lab-offline", connect_host="127.0.0.1", output=output)
        response = output.getvalue()
        self.assertEqual(count, len(response))
        self.assertTrue(response.startswith(b"HTTP/1.1 200 OK\r\n"))
        self.assertTrue(response.endswith(b"hello through HTTPPS\n" * 2000))
        self.assertEqual(self.backend_connections, 1)
        self.assertIn(b"GET /test?ok=1 HTTP/1.1\r\n", self.backend_requests[0])

    async def test_concurrent_sessions(self):
        port = await self.proxy()
        outputs = [io.BytesIO() for _ in range(8)]
        await asyncio.gather(*(fetch(f"httpps://localhost:{port}/", self.roots,
                              revocation_policy="lab-offline", connect_host="127.0.0.1", output=output)
                              for output in outputs))
        self.assertEqual(self.backend_connections, 8)
        self.assertTrue(all(output.getvalue() == outputs[0].getvalue() for output in outputs))

    async def test_configured_retry_cookie_preserves_authenticated_http_forwarding(self):
        port = await self.proxy(retry_cookie=True, retry_cookie_lifetime_seconds=15)
        output = io.BytesIO()
        await fetch(f"httpps://localhost:{port}/cookie", self.roots,
                    revocation_policy="lab-offline", connect_host="127.0.0.1", output=output)
        self.assertTrue(output.getvalue().startswith(b"HTTP/1.1 200 OK"))
        self.assertEqual(self.backend_connections, 1)

    async def test_fetch_explicit_general_pkix_policy(self):
        port = await self.proxy()
        output = io.BytesIO()
        await fetch(f"httpps://localhost:{port}/", self.roots,
                    revocation_policy="offline", connect_host="127.0.0.1", output=output)
        self.assertTrue(output.getvalue().startswith(b"HTTP/1.1 200 OK\r\n"))

    async def test_default_port_and_http_host_through_real_handshake(self):
        actual_port = await self.proxy()
        open_connection = asyncio.open_connection
        for url, requested_port, authority in (
            ("httpps://localhost/", 343, "localhost"),
            ("httpps://localhost:343/", 343, "localhost"),
            ("httpps://localhost:8443/", 8443, "localhost:8443"),
        ):
            with self.subTest(url=url):
                calls = []

                async def route_test_port(host, port, **kwargs):
                    # Keep real crypto and sockets, without binding a privileged
                    # port in tests. The proxy's backend connections are intact.
                    if port == requested_port:
                        calls.append((host, port))
                        port = actual_port
                    return await open_connection(host, port, **kwargs)

                output = io.BytesIO()
                with patch("tls20_server.client.asyncio.open_connection", side_effect=route_test_port):
                    await fetch(url, self.roots, revocation_policy="lab-offline",
                                connect_host="127.0.0.1", output=output)
                self.assertEqual(calls, [("127.0.0.1", requested_port)])
                self.assertTrue(output.getvalue().startswith(b"HTTP/1.1 200 OK\r\n"))
                self.assertIn(f"\r\nHost: {authority}\r\n".encode(), self.backend_requests[-1])

    async def test_plaintext_and_standard_tls_never_open_backend(self):
        port = await self.proxy(handshake_timeout_seconds=0.15)
        for invalid in (b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n", bytes.fromhex("160301") + bytes(30)):
            reader, writer = await self.connect(port)
            writer.write(invalid)
            await writer.drain()
            self.assertEqual(await asyncio.wait_for(reader.read(), 1), b"")
        self.assertEqual(self.backend_connections, 0)

    async def test_handshake_deadline_not_reset_by_partial_input(self):
        port = await self.proxy(handshake_timeout_seconds=0.1)
        reader, writer = await self.connect(port)
        writer.write(c.PREFACE[:1])
        await writer.drain()
        await asyncio.sleep(0.06)
        writer.write(c.PREFACE[1:2])
        await writer.drain()
        self.assertEqual(await asyncio.wait_for(reader.read(), 0.15), b"")
        self.assertEqual(self.backend_connections, 0)

    async def test_untrusted_cert_never_reaches_backend(self):
        other = Path(self.temp.name) / "other"
        create_lab(other, "localhost")
        roots = load_trust_roots(other / "ca.pem")
        port = await self.proxy()
        with self.assertRaises(ProtocolError):
            await fetch(f"httpps://localhost:{port}/", roots, revocation_policy="lab-offline",
                        connect_host="127.0.0.1", output=io.BytesIO())
        await asyncio.sleep(0.02)
        self.assertEqual(self.backend_connections, 0)

    async def test_wrong_service_name_never_reaches_backend(self):
        port = await self.proxy()
        with self.assertRaises(ProtocolError):
            await fetch(f"httpps://wrong.invalid:{port}/", self.roots, revocation_policy="lab-offline",
                        connect_host="127.0.0.1", output=io.BytesIO())
        self.assertEqual(self.backend_connections, 0)

    async def test_zero_shares_and_trailing_client_hello_are_rejected(self):
        port = await self.proxy()
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
        a = c.public_bytes(X25519PrivateKey.generate())
        b = c.public_bytes(X25519PrivateKey.generate())
        equal_shares = bytearray(m.client_hello(a, b, "localhost", bytes(32)))
        equal_shares[74:106] = a
        for hello in (m.client_hello(bytes(32), b, "localhost", bytes(32)),
                      bytes(equal_shares),
                      m.client_hello(a, b, "localhost", bytes(32)) + b"extra"):
            reader, writer = await self.connect(port)
            writer.write(c.PREFACE + b"\x16\x03\x03" + len(hello).to_bytes(2, "big") + hello)
            await writer.drain()
            alert = await asyncio.wait_for(reader.read(), 1)
            self.assertEqual(alert[:6], b"\x15\x03\x03\x00\x02\x02")
            self.assertEqual(len(alert), 7)
        self.assertEqual(self.backend_connections, 0)

    async def test_server_does_not_connect_before_client_finished(self):
        port = await self.proxy(handshake_timeout_seconds=0.15)
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
        a = c.public_bytes(X25519PrivateKey.generate())
        b = c.public_bytes(X25519PrivateKey.generate())
        reader, writer = await self.connect(port)
        wire = Wire(reader, writer)
        writer.write(c.PREFACE)
        await wire.send_frame(m.client_hello(a, b, "localhost", bytes(32)))
        self.assertEqual((await wire.receive_frame(2, boundary=True))[0], 2)
        # Receive the server flight but never complete client authentication.
        await asyncio.wait_for(reader.read(), 1)
        await asyncio.sleep(0.2)
        self.assertEqual(self.backend_connections, 0)

    async def test_tampered_record_is_fatal(self):
        received = asyncio.get_running_loop().create_future()
        async def handler(reader, writer):
            channel = await server_handshake(reader, writer, self.credentials, "localhost")
            try:
                await channel.recv()
                received.set_result(False)
            except ProtocolError:
                received.set_result(True)
            finally:
                await channel.close()
        port = await self.listener(handler)
        reader, writer = await self.connect(port)
        channel = await client_handshake(reader, writer, "localhost", self.roots, revocation_policy="lab-offline")
        record = bytearray(channel.sender.seal(b"not valid", 23))
        record[-1] ^= 1
        writer.write(record)
        await writer.drain()
        self.assertTrue(await asyncio.wait_for(received, 1))
        with self.assertRaises(ProtocolError):
            await channel.recv()

    async def test_authenticated_close_and_unclean_eof_differ(self):
        for clean in (True, False):
            async def handler(reader, writer):
                channel = await server_handshake(reader, writer, self.credentials, "localhost")
                if clean:
                    await channel.close()
                else:
                    channel.abort()
            port = await self.listener(handler)
            reader, writer = await self.connect(port)
            channel = await client_handshake(reader, writer, "localhost", self.roots, revocation_policy="lab-offline")
            if clean:
                self.assertIsNone(await channel.recv())
            else:
                with self.assertRaises(ProtocolError):
                    await channel.recv()
            await channel.close()

    async def test_client_response_limit(self):
        port = await self.proxy()
        with self.assertRaises(ProtocolError):
            await fetch(f"httpps://localhost:{port}/", self.roots, revocation_policy="lab-offline",
                        connect_host="127.0.0.1", output=io.BytesIO(), max_response_bytes=10)

    async def test_fragmented_frame_and_oversized_header(self):
        async def handler(reader, writer):
            wire = Wire(reader, writer)
            try:
                raw = await wire.receive_frame(1, boundary=True)
                await wire.send_frame(raw)
            except ProtocolError:
                pass
            finally:
                writer.close()
        port = await self.listener(handler)
        raw = m.frame(1, b"body")
        reader, writer = await self.connect(port)
        for fragment in (raw[:2], raw[2:5], raw[5:]):
            writer.write(b"\x16\x03\x03" + len(fragment).to_bytes(2, "big") + fragment)
            await writer.drain()
        self.assertEqual(await Wire(reader, writer).receive_frame(1, boundary=True), raw)
        reader, writer = await self.connect(port)
        writer.write(b"\x16\x03\x03\x00\x04\x01\xff\xff\xff")
        await writer.drain()
        self.assertEqual(await asyncio.wait_for(reader.read(), 1), b"")


if __name__ == "__main__":
    unittest.main()
