"""Dummy CCS validation is identical in retry and early-data discard paths."""

import os
import unittest
from unittest.mock import patch

from tests import test_pake_handshake, test_sessions
from tls20_server.errors import ProtocolError
from tls20_server.handshake import Wire
from tls20_server.retry_cookie import RetryCookiePolicy
from tls20_server.tickets import TicketCache, TicketStore


class CCSCases:
    async def check_ccs(self, stage, fragment, record_type=20):
        self.store, self.cache = TicketStore(), TicketCache()
        options = self.options if hasattr(self, "options") else self.server_options
        options.clear()
        if stage != "retry":
            await self.connect()
        if stage in ("retry", "retry_early"):
            options["retry_cookie_policy"] = RetryCookiePolicy()
        elif stage == "rejected_early":
            for ticket in self.store._tickets.values():
                ticket.early_used = True
        before_channels, before_early = len(self.channels), len(self.early)
        original, client_writer, hello_count, injected = Wire.send_frame, None, 0, False

        async def inject(wire, message, state=None):
            nonlocal client_writer, hello_count, injected
            # CH identifies the client writer independently of accept ordering.
            if message[0] == 1:
                client_writer = wire.writer
                hello_count += 1
            expected = (message[0] == 1 and hello_count == 2 if stage.startswith("retry")
                        else message[0] == (5 if stage == "accepted_early" else 20))
            if wire.writer is client_writer and expected and not injected:
                injected = True
                wire.writer.write(bytes((record_type, 3, 3)) + len(fragment).to_bytes(2, "big") + fragment)
                await wire.writer.drain()
            return await original(wire, message, state)

        connect_options = {"early_data": b"early probe"} if stage != "retry" else {}
        with patch.object(Wire, "send_frame", inject):
            if record_type == 20 and fragment == b"\1":
                channel = await self.connect(**connect_options)
                await channel.send(b"authenticated application control")
                self.assertEqual(await channel.recv(), b"authenticated application control")
                self.assertEqual(len(self.channels), before_channels + 1)
                self.assertEqual(channel.early_data_accepted, stage == "accepted_early")
                await channel.close()
            else:
                with self.assertRaises(ProtocolError) as caught:
                    await self.connect(**connect_options)
                # The actual peer alert, not just the locally raised error.
                self.assertEqual(caught.exception.alert, 10)
                self.assertEqual(len(self.channels), before_channels)
        self.assertTrue(injected)
        if stage in ("retry_early", "rejected_early"):
            self.assertEqual(len(self.early), before_early)

    async def test_dummy_ccs_after_retry_and_during_early_data(self):
        for stage in ("retry", "retry_early", "rejected_early", "accepted_early"):
            for fragment in (b"\1", b"\0", b"\1\1", b""):
                with self.subTest(stage=stage, fragment=fragment.hex()):
                    await self.check_ccs(stage, fragment)

    async def test_other_unexpected_plaintext_types_after_retry(self):
        for stage in ("retry", "retry_early"):
            for record_type in (0, 19, 24, 255):
                with self.subTest(stage=stage, record_type=record_type):
                    await self.check_ccs(stage, b"\1", record_type)
        # Application records may only be discarded after an early-data offer.
        await self.check_ccs("retry", b"\0" * 16, 23)


class CertificateCCSTests(CCSCases, unittest.IsolatedAsyncioTestCase):
    asyncSetUp = test_sessions.SessionTests.asyncSetUp
    asyncTearDown = test_sessions.SessionTests.asyncTearDown
    accept = test_sessions.SessionTests.accept
    handle = test_sessions.SessionTests.handle
    connect = test_sessions.SessionTests.connect


@unittest.skipUnless(os.environ.get("TLS20_TEST_PAKE") and os.environ.get("TLS20_TEST_OPENSSL"),
                     "explicit native PAKE fixture required")
class PasswordCCSTests(CCSCases, unittest.IsolatedAsyncioTestCase):
    asyncSetUp = test_pake_handshake.PakeHandshakeTests.asyncSetUp
    asyncTearDown = test_pake_handshake.PakeHandshakeTests.asyncTearDown
    accept = test_pake_handshake.PakeHandshakeTests.accept
    handle = test_pake_handshake.PakeHandshakeTests.handle
    connect = test_pake_handshake.PakeHandshakeTests.connect
