import base64
import hashlib
import unittest

from tls20_server.errors import ProtocolError
from tls20_server.optional_controls import (
    Heartbeat, SignalingBinding, TicketRequest, heartbeat_mode,
    ticket_hint, webrtc_assertion_hash, assertion_hash,
)


class HeartbeatTests(unittest.TestCase):
    def test_roundtrip_one_outstanding_and_distinct_random_padding(self):
        client, server = Heartbeat(1, 1), Heartbeat(1, 1)
        request = client.request(b"literal payload")
        with self.assertRaises(ProtocolError):
            client.request()
        response = server.receive(request)
        self.assertEqual(response[:18], b"\x02\x00\x0fliteral payload")
        self.assertNotEqual(request[-16:], response[-16:])
        self.assertIsNone(client.receive(b"\x02\x00\x01x" + bytes(16)))
        self.assertEqual(client.pending, b"literal payload")
        client.receive(response)
        self.assertIsNone(client.pending)
        self.assertEqual(client.matched_response, b"literal payload")
        client.request(b"")
        client.cancel()
        client.request()

    def test_heartbleed_style_declared_length_never_echoes(self):
        peer = Heartbeat(1, 1)
        for malformed in (b"", b"\x01\xff\xff" + bytes(16), b"\x01\x00\x10" + bytes(30),
                          b"\x01\x00\x00" + bytes(15), b"\x03\x00\x00" + bytes(16)):
            self.assertIsNone(peer.receive(malformed))

    def test_directions_and_asymmetric_size_limits(self):
        client = Heartbeat(2, 1, receive_limit=64, send_limit=1024)
        request = client.request(bytes(44))
        server = Heartbeat(1, 2, receive_limit=1024, send_limit=64)
        self.assertEqual(len(server.receive(request)), 63)
        client.cancel()
        with self.assertRaises(ValueError):
            client.request(bytes(45))
        with self.assertRaises(ProtocolError):
            server.request()
        self.assertIsNone(client.receive(request))
        for encoded in (b"", b"\x00", b"\x03", b"\x01\x00"):
            with self.assertRaises(ProtocolError):
                heartbeat_mode(encoded)


class SignalingBindingTests(unittest.TestCase):
    def test_directions_exact_octets_and_policy_scope(self):
        left = SignalingBinding(bytes(32), bytes([1]) * 32, b"a" * 20, b"b" * 20)
        right = SignalingBinding(left.peer_hash, left.local_hash, left.peer_session_id, left.local_session_id)
        left.validate(right.extensions())
        right.validate(left.extensions())
        with self.assertRaises(ProtocolError):
            left.validate(left.extensions())
        with self.assertRaises(ProtocolError):
            left.validate({})
        with self.assertRaises(ProtocolError):
            left.validate({55: b"\x01x", 56: right.extensions()[56]})
        self.assertNotEqual(left.context(), right.context())
        # Hash exact decoded UTF-8 bytes, not a canonicalized JSON object.
        text = b' { "fixture": "identity" } '
        self.assertEqual(webrtc_assertion_hash(base64.b64encode(text)), hashlib.sha256(text).digest())
        self.assertNotEqual(assertion_hash(text), assertion_hash(text.strip()))

    def test_absence_is_distinct_from_empty_assertion(self):
        policy = SignalingBinding(b"", b"", b"a" * 20, b"b" * 20)
        peer = {55: b"\x00", 56: b"\x14" + b"b" * 20}
        policy.validate(peer)
        peer[55] = b"\x20" + hashlib.sha256(b"").digest()
        with self.assertRaises(ProtocolError):
            policy.validate(peer)
        for invalid in (b"a" * 19, b"a" * 256, b"a" * 19 + b"\xff"):
            with self.assertRaises(ValueError):
                SignalingBinding(b"", b"", invalid, b"b" * 20)


class TicketHintTests(unittest.TestCase):
    def test_full_uint8_range_and_zero_hint(self):
        request = TicketRequest.parse(bytes((255, 0)))
        self.assertEqual(request.encode(), bytes((255, 0)))
        self.assertEqual(request.select(resumed=False, local_limit=100), 100)
        self.assertEqual(request.select(resumed=True, local_limit=100), 0)
        self.assertEqual(ticket_hint(b"\xff"), 255)
        for value in (b"", bytes(3)):
            with self.assertRaises(ProtocolError):
                TicketRequest.parse(value)
        with self.assertRaises(ValueError):
            TicketRequest(256, 0)
