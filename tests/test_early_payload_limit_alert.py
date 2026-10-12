"""Advertised 0-RTT byte limits: exact boundary and authenticated fatal alert."""

import asyncio
import os
import unittest
from unittest.mock import patch

from tests import test_sessions, test_pake_handshake
from tls20_server.errors import ProtocolError
from tls20_server.handshake import Wire


class EarlyPayloadLimitAlertTests(unittest.IsolatedAsyncioTestCase):
    async def check_limit(self, *, password=False):
        # This is a payload allowance, independently of each record's RSL.
        for extra_size in (0, 1, 16384):
            with self.subTest(password=password, extra=extra_size):
                fixture = (test_pake_handshake.PakeHandshakeTests() if password else
                           test_sessions.SessionTests())
                await fixture.asyncSetUp()
                channel = None
                try:
                    seed = await fixture.connect()
                    await seed.close()
                    await asyncio.wait_for(asyncio.gather(*tuple(fixture.tasks)), 3)
                    before = len(fixture.channels)
                    original_send, original_fatal = Wire.send_frame, Wire.fatal
                    rejected = asyncio.Event()
                    alerts, sealed, injected = [], [], []

                    async def send(wire, message, state=None):
                        if (extra_size and message[0] == 5 and
                                wire.writer.get_extra_info("peername")[1] == fixture.port):
                            wire.writer.write(state.seal(b"X" * extra_size, 23))
                            await wire.writer.drain()
                            injected.append(extra_size)
                        return await original_send(wire, message, state)

                    async def fatal(wire, error, state=None):
                        if wire.writer.get_extra_info("peername")[1] == fixture.port:
                            return await original_fatal(wire, error, state)
                        alerts.append(error.alert)
                        self.assertIsNotNone(state, "failure must use the current authenticated write epoch")
                        original_seal = state.seal

                        def seal(content, kind, *args, **kwargs):
                            sealed.append((content, kind))
                            return original_seal(content, kind, *args, **kwargs)

                        with patch.object(state, "seal", seal):
                            await original_fatal(wire, error, state)
                        rejected.set()

                    with patch.object(Wire, "send_frame", send), patch.object(Wire, "fatal", fatal):
                        if extra_size:
                            with self.assertRaises((ProtocolError, ConnectionError)):
                                await fixture.connect(early_data=b"a" * 65536)
                            await asyncio.wait_for(rejected.wait(), 3)
                            self.assertEqual(alerts, [10])
                            self.assertEqual(sealed, [(b"\x02\x0a", 21)])
                            self.assertEqual(injected, [extra_size])
                            self.assertEqual(len(fixture.channels), before)
                            self.assertNotIn(b"", fixture.early, "overflow must not report successful EndOfEarlyData")
                        else:
                            channel = await fixture.connect(early_data=b"a" * 65536)
                            self.assertTrue(channel.resumed)
                            self.assertTrue(channel.early_data_accepted)
                            self.assertEqual(alerts, [])
                            self.assertEqual(fixture.early[-1], b"")
                            await channel.send(b"boundary still works")
                            self.assertEqual(await channel.recv(), b"boundary still works")
                            await channel.close()
                            await asyncio.wait_for(asyncio.gather(*tuple(fixture.tasks)), 3)
                            self.assertFalse(fixture.errors)
                    self.assertEqual(b"".join(fixture.early), b"a" * 65536)
                finally:
                    if channel is not None:
                        channel.abort()
                    await fixture.asyncTearDown()

    async def test_ordinary_exact_limit_and_one_or_more_bytes_overflow(self):
        await self.check_limit()

    @unittest.skipUnless(os.environ.get("TLS20_TEST_PAKE") and os.environ.get("TLS20_TEST_OPENSSL"),
                         "native PAKE fixture required")
    async def test_password_successor_exact_limit_and_overflow(self):
        await self.check_limit(password=True)
