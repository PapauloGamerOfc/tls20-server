"""Authenticated record types obey the current phase, including early epochs."""

import os
import unittest
from unittest.mock import patch

from tests import test_pake_handshake, test_sessions
from tls20_server import messages as m
from tls20_server.errors import ProtocolError
from tls20_server.handshake import Wire
from tls20_server.tickets import TicketCache, TicketStore


class EarlyRecordCases:
    async def test_authenticated_record_types_before_client_finished(self):
        for stage in ("handshake", "accepted_early", "rejected_early"):
            for kind, content in ((21, b"\1\x5a"), (22, m.frame(24, b"\0")),
                                  (23, b"extra early bytes"), (24, b"heartbeat")):
                with self.subTest(stage=stage, kind=kind):
                    self.store, self.cache = TicketStore(), TicketCache()
                    self.early.clear()
                    options = self.options if hasattr(self, "options") else self.server_options
                    options.clear()
                    if stage != "handshake":
                        await self.connect()
                    if stage == "rejected_early":
                        for ticket in self.store._tickets.values():
                            ticket.early_used = True
                    before = len(self.channels)
                    original, client_writer, injected = Wire.send_frame, None, False

                    async def inject(wire, message, state=None):
                        nonlocal client_writer, injected
                        if message[0] == 1:
                            client_writer = wire.writer
                        if (wire.writer is client_writer and not injected
                                and message[0] == (5 if stage == "accepted_early" else 20)):
                            injected = True
                            wire.writer.write(state.seal(content, kind))
                            await wire.writer.drain()
                        return await original(wire, message, state)

                    connect_options = {} if stage == "handshake" else {"early_data": b"early probe"}
                    accepted = kind == 21 or kind == 23 and stage == "accepted_early"
                    with patch.object(Wire, "send_frame", inject):
                        if accepted:
                            channel = await self.connect(**connect_options)
                            await channel.send(b"authenticated application control")
                            self.assertEqual(await channel.recv(), b"authenticated application control")
                            self.assertEqual(len(self.channels), before + 1)
                            await channel.close()
                        else:
                            with self.assertRaises(ProtocolError) as failure:
                                await self.connect(**connect_options)
                            self.assertEqual(failure.exception.alert, 10)
                            self.assertEqual(len(self.channels), before)
                    self.assertTrue(injected)
                    if stage == "rejected_early":
                        self.assertFalse(self.early)
                    # No unexpected control may be delivered as application.
                    if kind in (22, 24):
                        self.assertNotIn(content, self.early)


class CertificateEarlyTypeTests(EarlyRecordCases, unittest.IsolatedAsyncioTestCase):
    asyncSetUp = test_sessions.SessionTests.asyncSetUp
    asyncTearDown = test_sessions.SessionTests.asyncTearDown
    accept = test_sessions.SessionTests.accept
    handle = test_sessions.SessionTests.handle
    connect = test_sessions.SessionTests.connect


@unittest.skipUnless(os.environ.get("TLS20_TEST_PAKE") and os.environ.get("TLS20_TEST_OPENSSL"),
                     "explicit native PAKE fixture required")
class PasswordEarlyTypeTests(EarlyRecordCases, unittest.IsolatedAsyncioTestCase):
    asyncSetUp = test_pake_handshake.PakeHandshakeTests.asyncSetUp
    asyncTearDown = test_pake_handshake.PakeHandshakeTests.asyncTearDown
    accept = test_pake_handshake.PakeHandshakeTests.accept
    handle = test_pake_handshake.PakeHandshakeTests.handle
    connect = test_pake_handshake.PakeHandshakeTests.connect
