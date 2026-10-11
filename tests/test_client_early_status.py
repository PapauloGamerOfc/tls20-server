import asyncio
import io
import unittest
from unittest.mock import AsyncMock, patch

from tls20_server.client import _EarlyResponseStatus, fetch
from tls20_server.errors import ProtocolError


class EarlyStatusTests(unittest.TestCase):
    def test_fragmented_informational_then_425(self):
        status = _EarlyResponseStatus()
        self.assertIsNone(status.feed(b"HTTP/1.1 103 Early Hints\r\nLink: </style.css>\r\n"))
        self.assertIsNone(status.feed(b"\r\nHTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 42"))
        self.assertTrue(status.feed(b"5 Too Early\r\nContent-Length: 0\r\n\r\n"))

    def test_preserves_hints_for_successful_response(self):
        response = b"HTTP/1.1 103 Early Hints\r\n\r\nHTTP/1.1 200 OK\r\n\r\nbody"
        status = _EarlyResponseStatus()
        self.assertFalse(status.feed(response))
        self.assertEqual(status.buffer, response)

    def test_bounded_headers_and_status(self):
        for response in (b"a" * 8193,
                         b"HTTP/1.1 103 Early Hints\r\nX: " + b"a" * 65536,
                         b"HTTP/1.1 103 Early Hints\r\n\r\n" * 17,
                         b"HTTP/1.1 42x Invalid\r\n"):
            with self.subTest(response=response[:32]), self.assertRaises(ProtocolError):
                _EarlyResponseStatus().feed(response)


class EarlyRetryDeadlineTests(unittest.IsolatedAsyncioTestCase):
    async def test_retry_uses_remaining_deadline(self):
        budgets = []

        class Channel:
            def __init__(self, early):
                self.early_data_accepted = early
                self.done = False

            async def send(self, data):
                pass

            async def close(self):
                pass

            async def recv(self):
                if self.done:
                    return None
                self.done = True
                if self.early_data_accepted:
                    await asyncio.sleep(0.05)
                    return b"HTTP/1.1 425 Too Early\r\n\r\n"
                return b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"

        async def handshake(*args, timeout, **kwargs):
            budgets.append(timeout)
            return Channel(bool(kwargs["early_data"]))

        output = io.BytesIO()
        with patch("tls20_server.client.asyncio.open_connection", AsyncMock(return_value=(None, object()))), \
                patch("tls20_server.client.client_handshake", handshake):
            await fetch("httpps://localhost/", [], revocation_policy="lab-offline",
                        output=output, timeout=1, use_early_data=True)
        self.assertEqual(len(budgets), 2)
        self.assertLess(budgets[1], budgets[0] - 0.04)
        self.assertGreater(budgets[1], 0)
        self.assertTrue(output.getvalue().startswith(b"HTTP/1.1 200"))
