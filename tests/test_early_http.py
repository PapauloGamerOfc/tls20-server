import unittest

from tls20_server.early_http import EarlyRequestGate
from tls20_server.errors import ProtocolError


class EarlyHTTPTests(unittest.TestCase):
    def gate(self, limit=16384):
        return EarlyRequestGate(("/", "/static"), "localhost", 343, limit)

    def test_fragmented_allowlisted_request_inserts_early_header_once(self):
        gate = self.gate()
        self.assertIsNone(gate.feed(b"GET /static HTTP/1.1\r\nHost: local"))
        result = gate.feed(b"host:343\r\nConnection: close\r\n\r\n")
        self.assertEqual(result, b"GET /static HTTP/1.1\r\nHost: localhost:343\r\nConnection: close\r\nEarly-Data: 1\r\n\r\n")
        self.assertIsNone(gate.feed(b""))
        self.assertTrue(gate.forwarded)
        self.assertFalse(gate.rejected)

    def test_existing_early_header_is_preserved_without_duplication(self):
        result = self.gate().feed(b"HEAD / HTTP/1.1\r\nHost: localhost\r\nEarly-Data: 1\r\n\r\n")
        self.assertEqual(result.count(b"Early-Data:"), 1)

    def test_non_replay_safe_or_ambiguous_requests_are_never_returned(self):
        requests = [
            b"POST / HTTP/1.1\r\nHost: localhost\r\n\r\n",
            b"GET /delete HTTP/1.1\r\nHost: localhost\r\n\r\n",
            b"GET /?action=delete HTTP/1.1\r\nHost: localhost\r\n\r\n",
            b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n",
            b"GET http://localhost/ HTTP/1.1\r\nHost: localhost\r\n\r\n",
            b"GET / HTTP/1.1\r\nHost: other\r\n\r\n",
            b"GET / HTTP/1.1\r\nHost: localhost:999\r\n\r\n",
            b"GET / HTTP/1.1\r\n\r\n",
            b"GET / HTTP/1.1\r\nHost: localhost\r\nHost: localhost\r\n\r\n",
            b"GET / HTTP/1.1\r\nHost : localhost\r\n\r\n",
            b"GET / HTTP/1.1\r\nHost: localhost\r\n x: y\r\n\r\n",
            b"GET / HTTP/1.1\r\nHost: localhost\r\nX: a\nInjected: yes\r\n\r\n",
            b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\nextra",
        ]
        for header in (b"Content-Length: 0", b"Transfer-Encoding: chunked", b"Authorization: x",
                       b"Cookie: a=b", b"Proxy-Authorization: x", b"Expect: 100-continue",
                       b"Upgrade: websocket", b"Connection: content-length", b"Early-Data: 0"):
            requests.append(b"GET / HTTP/1.1\r\nHost: localhost\r\n" + header + b"\r\n\r\n")
        for request in requests:
            with self.subTest(request=request):
                gate = self.gate()
                self.assertIsNone(gate.feed(request))
                gate.feed(b"")
                self.assertTrue(gate.rejected)
                self.assertFalse(gate.forwarded)

    def test_incomplete_overflow_empty_and_repeated_requests(self):
        gate = self.gate(4)
        self.assertIsNone(gate.feed(b"GET /"))
        self.assertTrue(gate.rejected)
        gate = self.gate()
        gate.feed(b"GET / HTTP/1.1\r\nHost: local")
        gate.feed(b"")
        self.assertTrue(gate.rejected)
        gate = self.gate()
        gate.feed(b"")
        self.assertFalse(gate.rejected)
        with self.assertRaises(ProtocolError):
            gate.feed(b"late")
        gate = self.gate()
        gate.feed(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
        with self.assertRaises(ProtocolError):
            gate.feed(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
