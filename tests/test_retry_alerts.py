"""HRR alert classifications asserted on the actual plaintext wire."""

import asyncio
import unittest

from tls20_server import crypto as c, messages as m
from tls20_server.errors import ProtocolError
from tls20_server.handshake import Wire, client_handshake
from tls20_server.lab import generate_lab_credentials
from tls20_server.psk import ExternalPSK


class RetryAlertTests(unittest.IsolatedAsyncioTestCase):
    async def check_retry(self, mode, expected):
        _, root = generate_lab_credentials("localhost")
        complete = asyncio.get_running_loop().create_future()
        tasks, writers = [], []
        second = mode.startswith("repeated") or mode == "changed_suite"

        async def peer(reader, writer):
            writers.append(writer)
            wire = Wire(reader, writer)
            try:
                self.assertEqual(await wire.exact(len(c.PREFACE)), c.PREFACE)
                hello = m.parse_client_hello((await wire.receive_frame(1))[4:])
                self.assertEqual(hello.groups, () if mode == "psk_only" else (29,))
                group = 23 if mode in ("unoffered", "psk_only") else 29
                await wire.send_frame(m.server_hello(b"", bytes(32), retry=True, group=group,
                    cipher_suite=0x1302 if mode == "unoffered_suite" else 0x1301))
                if second:
                    await wire.receive_frame(1)
                    reply = m.server_hello(bytes(range(32)) if mode == "changed_suite" else b"",
                        bytes(32), retry=mode != "changed_suite", group=29,
                        cipher_suite=0x1301 if mode == "repeated" else 0x1302)
                    if mode == "repeated_unknown_suite":
                        reply = reply[:39] + b"\xaa\xaa" + reply[41:]
                    elif mode == "repeated_unknown_group":
                        reply = reply[:-2] + b"\xfa\xfa"
                    await wire.send_frame(reply)
                complete.set_result(await wire.read_record())
            except BaseException as error:
                if not complete.done():
                    complete.set_exception(error)
            finally:
                writer.close()

        def accept(reader, writer):
            tasks.append(asyncio.create_task(peer(reader, writer)))

        listener = await asyncio.start_server(accept, "127.0.0.1", 0)
        try:
            reader, writer = await asyncio.open_connection("127.0.0.1", listener.sockets[0].getsockname()[1])
            writers.append(writer)
            options = dict(supported_groups=(29,), force_retry=second,
                cipher_suites=(0x1301, 0x1302) if second else (0x1301,))
            if mode == "psk_only":
                options.update(external_psk=ExternalPSK(b"test identity", b"public test secret", "localhost"),
                               psk_modes=(0,))
            with self.assertRaises(ProtocolError) as caught:
                await client_handshake(reader, writer, "localhost", [root],
                    revocation_policy="lab-offline", timeout=2, **options)
            self.assertEqual(caught.exception.alert, expected)
            self.assertEqual(await asyncio.wait_for(complete, 2), (bytes((2, expected)), 21))
        finally:
            listener.close()
            await listener.wait_closed()
            for writer in writers:
                writer.close()
            await asyncio.gather(*tasks, return_exceptions=True)
            for writer in writers:
                try:
                    await writer.wait_closed()
                except OSError:
                    pass

    async def test_unoffered_or_already_sent_group_is_illegal_parameter(self):
        for mode in ("unoffered", "psk_only", "already_sent"):
            with self.subTest(mode=mode):
                await self.check_retry(mode, 47)

    async def test_second_retry_is_unexpected_even_if_cipher_also_changes(self):
        for mode in ("repeated", "repeated_changed_suite", "repeated_unknown_suite", "repeated_unknown_group"):
            with self.subTest(mode=mode):
                await self.check_retry(mode, 10)

    async def test_unoffered_or_changed_cipher_is_illegal_parameter(self):
        for mode in ("unoffered_suite", "changed_suite"):
            with self.subTest(mode=mode):
                await self.check_retry(mode, 47)
