"""Malformed ticket vectors produce decode_error on the authenticated wire."""
import asyncio
import unittest
from unittest.mock import patch

from tests import test_sessions
from tls20_server import messages as m
from tls20_server.errors import PeerClosed, ProtocolError
from tls20_server.handshake import Wire
from tls20_server.tickets import TicketCache


def ticket_body(extensions=b"", nonce=b"N", identity=b"T"):
    return (3600).to_bytes(4, "big") + bytes(4) + m._vec(nonce, 1) + m._vec(identity, 2) + m._vec(extensions, 2)


class TicketSyntaxAlertTests(unittest.IsolatedAsyncioTestCase):
    asyncSetUp = test_sessions.SessionTests.asyncSetUp
    asyncTearDown = test_sessions.SessionTests.asyncTearDown
    accept = test_sessions.SessionTests.accept
    handle = test_sessions.SessionTests.handle
    connect = test_sessions.SessionTests.connect

    async def check_ticket(self, body, expected):
        # Keep each positive control from selecting a previous synthetic ticket.
        self.cache = TicketCache()
        emitted = []
        received = []
        peer_alert = asyncio.Event()
        fatal, read_record = Wire.fatal, Wire.read_record

        async def observe(wire, error, state=None):
            if not isinstance(error, PeerClosed):
                emitted.append((wire.writer in self.client_writers, error.alert))
            return await fatal(wire, error, state)

        async def read(wire, state=None):
            content, kind = await read_record(wire, state)
            if kind == 21 and content[:1] == b"\x02":
                received.append((wire.writer in self.client_writers, state is not None, content))
                peer_alert.set()
            return content, kind

        with patch.object(m, "new_session_ticket", return_value=m.frame(4, body)), \
                patch.object(Wire, "fatal", observe), patch.object(Wire, "read_record", read):
            if expected is None:
                channel = await asyncio.wait_for(self.connect(), 3)
                self.assertEqual(len(self.cache._tickets), 1)
                await channel.send(b"after ticket")
                self.assertEqual(await channel.recv(), b"after ticket")
                await channel.close()
                self.assertEqual(emitted, [])
            else:
                with self.assertRaises(ProtocolError) as caught:
                    await asyncio.wait_for(self.connect(), 3)
                self.assertEqual(caught.exception.alert, expected)
                self.assertEqual(emitted, [(True, expected)])
                await asyncio.wait_for(peer_alert.wait(), 2)
                self.assertEqual(received, [(False, True, bytes((2, expected)))])
                self.assertFalse(self.cache._tickets)

    async def test_malformed_lengths_are_decode_error(self):
        prefix = (3600).to_bytes(4, "big") + bytes(4)
        cases = [
            ("empty-ticket", ticket_body(identity=b"")),
            ("nonce-overflow", prefix + b"\xff" + bytes(8)),
            ("ticket-overflow", prefix + b"\x01N\x01\x00T\x00\x00"),
        ]
        cases.extend((f"early-length-{size}", ticket_body(m.extension(42, bytes(size))))
                     for size in (0, 1, 3, 5))
        for name, body in cases:
            with self.subTest(name=name):
                await self.check_ticket(body, 50)

    async def test_valid_tickets_and_unknown_extensions_continue(self):
        for name, body in (
            ("ordinary", ticket_body()),
            ("empty-nonce", ticket_body(nonce=b"")),
            ("early-limit", ticket_body(m.extension(42, bytes(4)))),
            ("unknown-extension", ticket_body(m.extension(0xfafa, b"unknown"))),
        ):
            with self.subTest(name=name):
                await self.check_ticket(body, None)


if __name__ == "__main__":
    unittest.main()
