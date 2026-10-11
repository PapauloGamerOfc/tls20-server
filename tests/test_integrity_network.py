"""The non-confidential profile needs explicit policy on BOTH peers."""
import asyncio
import unittest

from tests import test_sessions
from tls20_server import crypto as c
from tls20_server.config import Config, ConfigError
from tls20_server.errors import ProtocolError
from tls20_server.tickets import TicketCache


class IntegrityNetworkTests(unittest.IsolatedAsyncioTestCase):
    asyncSetUp = test_sessions.SessionTests.asyncSetUp
    asyncTearDown = test_sessions.SessionTests.asyncTearDown
    accept = test_sessions.SessionTests.accept
    handle = test_sessions.SessionTests.handle
    connect = test_sessions.SessionTests.connect

    async def test_full_resumed_early_and_key_update_report_non_confidential(self):
        for suite in (0xC0B4, 0xC0B5):
            self.cache = TicketCache()
            options = {"allow_non_confidential": True, "cipher_suites": (suite,),
                       "application_protocols": (b"fixture/non-confidential",)}
            self.server_options = options
            for resumed in (False, True):
                channel = await self.connect(**options, **({"early_data": b"public only"} if resumed else {}))
                self.assertFalse(channel.confidential)
                self.assertFalse(self.channels[-1].confidential)
                self.assertEqual(channel.resumed, resumed)
                self.assertEqual(channel.early_data_accepted, resumed)
                size = 32 if suite == 0xC0B4 else 48
                self.assertEqual(len(channel.sender.key), size)
                self.assertEqual(len(channel.sender.iv), size)
                await channel.key_update(request_peer=True)
                await channel.send(b"public status")
                self.assertEqual(await asyncio.wait_for(channel.recv(), 2), b"public status")

    async def test_cipher_offer_is_not_policy_authorization(self):
        # The server's own allow-list is insufficient without its opt-in.
        self.server_options = {"cipher_suites": (0xC0B4,)}
        with self.assertRaises((ProtocolError, ConnectionError)):
            await self.connect(cipher_suites=(0xC0B4,), allow_non_confidential=True)
        self.assertFalse(self.channels)
        # The client's suite list cannot silently opt it into cleartext either.
        self.server_options["allow_non_confidential"] = True
        with self.assertRaises((ProtocolError, ConnectionError)):
            await self.connect(cipher_suites=(0xC0B4,))
        self.assertFalse(self.channels)

    async def test_resumption_cannot_promote_cleartext_to_confidential(self):
        self.server_options = {"cipher_suites": (0xC0B4,), "allow_non_confidential": True}
        first = await self.connect(cipher_suites=(0xC0B4,), allow_non_confidential=True)
        self.assertFalse(first.confidential)
        self.server_options = {"cipher_suites": (0x1301,)}
        second = await self.connect(cipher_suites=(0x1301,))
        self.assertTrue(second.confidential)
        self.assertFalse(second.resumed)
        self.assertFalse(second.early_data_accepted)

    def test_normal_httpps_relay_cannot_enable_integrity_suites(self):
        for suite in (0xC0B4, 0xC0B5):
            with self.assertRaises(ConfigError):
                Config(cipher_suites=(suite,))

    def test_record_replay_and_key_update_old_epoch_fail(self):
        for suite in (0xC0B4, 0xC0B5):
            size = 32 if suite == 0xC0B4 else 48
            sender, receiver = (c.RecordState(bytes(size), role, suite) for role in ("seal", "open"))
            wire = sender.seal(b"clear public data", 23, padding=7)
            self.assertIn(b"clear public data", wire)
            self.assertEqual(receiver.open(wire), (b"clear public data", 23))
            with self.assertRaises(ProtocolError):
                receiver.open(wire)
            receiver = c.RecordState(bytes(size), "open", suite)
            receiver.update()
            with self.assertRaises(ProtocolError):
                receiver.open(wire)
