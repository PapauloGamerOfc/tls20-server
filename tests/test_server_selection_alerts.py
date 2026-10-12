"""ServerHello consistency failures have their prescribed wire alert."""

import asyncio
import os
import unittest
from unittest.mock import patch

from tests import test_pake_handshake
from tls20_server import crypto as c, messages as m
from tls20_server.errors import ProtocolError
from tls20_server.handshake import Wire, client_handshake
from tls20_server.lab import generate_lab_credentials
from tls20_server.psk import ExternalPSK
from tls20_server.tickets import TicketCache, TicketStore


class ServerSelectionAlertTests(unittest.IsolatedAsyncioTestCase):
    async def test_server_hello_rejects_inconsistent_selection(self):
        for mode, expected in (("session_id", 47), ("unsolicited_psk", 110),
                               ("psk_index", 47), ("psk_hash", 47),
                               ("psk_mode", 47), ("unoffered_share", 47)):
            with self.subTest(mode=mode):
                _, root = generate_lab_credentials("localhost")
                received = asyncio.get_running_loop().create_future()
                tasks, writers = [], []

                async def peer(reader, writer):
                    writers.append(writer)
                    wire = Wire(reader, writer)
                    try:
                        self.assertEqual(await wire.exact(len(c.PREFACE)), c.PREFACE)
                        hello = m.parse_client_hello((await wire.receive_frame(1))[4:])
                        group = 23 if mode == "unoffered_share" else 0 if mode == "psk_mode" else 29
                        private, public = c.traffic_key(group) if group else (None, b"")
                        await wire.send_frame(m.server_hello(public, bytes(32), group=group,
                            session_id=b"not echoed" if mode == "session_id" else b"",
                            resumed=mode.startswith("psk_") or mode == "unsolicited_psk",
                            selected_identity=1 if mode == "psk_index" else 0,
                            cipher_suite=0x1302 if mode == "psk_hash" else 0x1301))
                        received.set_result(await wire.read_record())
                        private = None
                    except BaseException as error:
                        if not received.done():
                            received.set_exception(error)
                    finally:
                        writer.close()

                def accept(reader, writer):
                    tasks.append(asyncio.create_task(peer(reader, writer)))

                listener = await asyncio.start_server(accept, "127.0.0.1", 0)
                try:
                    reader, writer = await asyncio.open_connection("127.0.0.1", listener.sockets[0].getsockname()[1])
                    writers.append(writer)
                    options = {"supported_groups": (29, 23)}
                    if mode.startswith("psk_"):
                        options.update(external_psk=ExternalPSK(b"identity", b"public test fixture", "localhost"),
                                       psk_modes=(1,), cipher_suites=(0x1301, 0x1302))
                    with self.assertRaises(ProtocolError) as failure:
                        await client_handshake(reader, writer, "localhost", [root],
                            revocation_policy="lab-offline", timeout=2, **options)
                    self.assertEqual(failure.exception.alert, expected)
                    self.assertEqual(await asyncio.wait_for(received, 2), (bytes((2, expected)), 21))
                finally:
                    listener.close()
                    await listener.wait_closed()
                    for writer in writers:
                        writer.close()
                    await asyncio.gather(*tasks, return_exceptions=True)
                    if received.done() and not received.cancelled():
                        received.exception()
                    for writer in writers:
                        try:
                            await writer.wait_closed()
                        except OSError:
                            pass


@unittest.skipUnless(os.environ.get("TLS20_TEST_PAKE") and os.environ.get("TLS20_TEST_OPENSSL"),
                     "explicit native PAKE fixture required")
class PasswordServerSelectionAlertTests(unittest.IsolatedAsyncioTestCase):
    asyncSetUp = test_pake_handshake.PakeHandshakeTests.asyncSetUp
    asyncTearDown = test_pake_handshake.PakeHandshakeTests.asyncTearDown
    accept = test_pake_handshake.PakeHandshakeTests.accept
    handle = test_pake_handshake.PakeHandshakeTests.handle
    connect = test_pake_handshake.PakeHandshakeTests.connect

    async def test_successor_selection_errors_are_illegal_parameter(self):
        for mode in ("psk_index", "psk_mode", "unoffered_share"):
            with self.subTest(mode=mode):
                self.store, self.cache = TicketStore(), TicketCache()
                await self.connect()
                original_hello, original_fatal = m.server_hello, Wire.fatal
                alerts = []

                def inconsistent(public, random, **kwargs):
                    self.assertTrue(kwargs["resumed"])
                    if mode == "psk_index":
                        kwargs["selected_identity"] = 1
                    elif mode == "psk_mode":
                        kwargs["group"], public = 0, b""
                    else:
                        kwargs["group"] = 23
                        private, public = c.traffic_key(23)
                    return original_hello(public, random, **kwargs)

                async def fatal(wire, error, state=None):
                    if wire.writer.get_extra_info("peername")[1] == self.port:
                        self.assertIsNone(state)  # Rejected before key derivation.
                        original_write = wire.writer.write
                        def write(record):
                            alerts.append(record)
                            return original_write(record)
                        with patch.object(wire.writer, "write", write):
                            return await original_fatal(wire, error, state)
                    return await original_fatal(wire, error, state)

                with patch.object(m, "server_hello", inconsistent), patch.object(Wire, "fatal", fatal):
                    with self.assertRaises(ProtocolError) as failure:
                        await self.connect()
                    self.assertEqual(failure.exception.alert, 47)
                    self.assertEqual(alerts, [b"\x15\x03\x03\0\2\2\x2f"])
