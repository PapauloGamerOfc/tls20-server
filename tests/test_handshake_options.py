import unittest

from tls20_server.errors import ProtocolError
from tls20_server.handshake_options import client_controls, server_controls, client_control_selection
from tls20_server.optional_controls import SignalingBinding, TicketRequest


class ControlNegotiationTests(unittest.TestCase):
    def test_full_offer_selection_is_directional(self):
        client = SignalingBinding(b"", bytes(32), b"c" * 20, b"s" * 20)
        server = SignalingBinding(bytes(32), b"", b"s" * 20, b"c" * 20)
        request = TicketRequest(10, 2)
        offers = dict(client_controls(heartbeat=2, tickets=request, signaling=client))
        selection = server_controls(offers, heartbeat=1, ticket_limit=7, signaling=server)
        self.assertEqual(selection.expected_tickets, 7)
        final = client_control_selection(dict(selection.extensions), heartbeat=2, tickets=request, signaling=client)
        self.assertEqual((selection.heartbeat_local_mode, selection.heartbeat_peer_mode), (1, 2))
        self.assertEqual((final.heartbeat_local_mode, final.heartbeat_peer_mode), (2, 1))
        self.assertEqual(final.expected_tickets, 7)
        self.assertEqual(server_controls(offers, resumed=True, ticket_limit=7).expected_tickets, 2)
        self.assertEqual(server_controls(offers, tickets_enabled=False).expected_tickets, 0)

    def test_absence_unoffered_malformed(self):
        self.assertEqual(client_controls(), ())
        self.assertEqual(server_controls({}, heartbeat=1).extensions, ())
        self.assertIsNone(client_control_selection({}, heartbeat=1).heartbeat_peer_mode)
        self.assertEqual(server_controls({15: b"\x01"}).extensions, ())
        for responses in ({15: b"\x01"}, {58: b"\x00"}, {55: b"\x00"}, {56: b"\x14" + b"x" * 20}):
            with self.assertRaises(ProtocolError):
                client_control_selection(responses)
        for offers in ({15: b"\x03"}, {58: b"\x00"}):
            with self.assertRaises(ProtocolError):
                server_controls(offers)

    def test_required_signaling_cannot_be_silently_omitted(self):
        policy = SignalingBinding(b"", b"", b"c" * 20, b"s" * 20)
        for function in (server_controls, client_control_selection):
            with self.assertRaises(ProtocolError):
                function({}, signaling=policy)
