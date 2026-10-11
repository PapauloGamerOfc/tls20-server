"""Literal-IP diagnostic requests authenticate IP SANs and format HTTP authority."""
import asyncio
import io
import unittest

from cryptography import x509
from tls20_server.client import fetch
from tls20_server.handshake import server_handshake
from tls20_server.lab import generate_lab_credentials


class IPClientTests(unittest.IsolatedAsyncioTestCase):
    async def test_generated_ip_san_and_fetch_authority(self):
        for service in ("127.0.0.1", "::1"):
            credentials, root = generate_lab_credentials(service)
            san = x509.load_der_x509_certificate(credentials.chain_der[0]).extensions.get_extension_for_class(x509.SubjectAlternativeName).value
            self.assertEqual(len(san.get_values_for_type(x509.IPAddress)), 1)
            self.assertFalse(san.get_values_for_type(x509.DNSName))
            requests, errors, tasks = [], [], set()

            async def peer(reader, writer):
                task = asyncio.current_task()
                tasks.add(task)
                try:
                    async with asyncio.timeout(5):
                        channel = await server_handshake(reader, writer, credentials, service)
                        request = b""
                        while b"\r\n\r\n" not in request:
                            fragment = await channel.recv()
                            if fragment is None:
                                raise AssertionError("early client close")
                            request += fragment
                        requests.append(request)
                        await channel.send(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")
                        await channel.close()
                except Exception as error:
                    errors.append(error)
                finally:
                    writer.close()
                    await writer.wait_closed()
                    tasks.discard(task)

            server = await asyncio.start_server(peer, "127.0.0.1", 0)
            try:
                port = server.sockets[0].getsockname()[1]
                host = f"[{service}]" if ":" in service else service
                output = io.BytesIO()
                await fetch(f"httpps://{host}:{port}/", [root], revocation_policy="offline",
                            connect_host="127.0.0.1", output=output, timeout=5)
                if tasks:
                    await asyncio.gather(*tasks)
                self.assertFalse(errors)
                self.assertEqual(len(requests), 1)
                self.assertIn(f"\r\nHost: {host}:{port}\r\n".encode(), requests[0])
                self.assertTrue(output.getvalue().endswith(b"OK"))
            finally:
                server.close()
                await server.wait_closed()
