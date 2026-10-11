"""Synthetic partial-construction, ticket-failure and early-epoch ownership cases."""

import asyncio
from contextlib import contextmanager
import unittest
from unittest.mock import Mock, patch

from tests.test_robustness import MemoryWriter
from tests import test_sessions
from tls20_server import crypto as c
from tls20_server.errors import PeerClosed, ProtocolError
from tls20_server.handshake import SecureChannel, Wire
from tls20_server.secret_lifecycle import HandshakeSecrets
from tls20_server.tickets import TicketCache, TicketStore


class ScopeCleanupEdges(unittest.TestCase):
    def test_all_finalizers_run_and_active_protocol_failure_is_preserved(self):
        for active_failure in (False, True):
            with self.subTest(active_failure=active_failure):
                scope = HandshakeSecrets()
                channel = Mock()
                channel.abort.side_effect = RuntimeError("channel cleanup fixture")
                records, keys = [Mock(), Mock()], [Mock(), Mock()]
                records[0].close.side_effect = RuntimeError("record cleanup fixture")
                keys[0].close.side_effect = RuntimeError("key cleanup fixture")
                scope.establish(channel)
                scope.records.extend(records)
                scope.keys.extend(keys)
                if active_failure:
                    with self.assertRaisesRegex(ProtocolError, "original protocol failure") as failure:
                        try:
                            raise ProtocolError("original protocol failure", alert=51)
                        finally:
                            scope.close()
                    self.assertEqual(failure.exception.alert, 51)
                else:
                    with self.assertRaisesRegex(RuntimeError, "channel cleanup fixture"):
                        scope.close()
                channel.abort.assert_called_once_with()
                for item in records + keys:
                    item.close.assert_called_once_with()
                self.assertEqual((scope.records, scope.keys, scope.channel), ([], [], None))
                scope.close()

    def test_failed_success_finalizer_aborts_unreturned_channel(self):
        scope, channel = HandshakeSecrets(), Mock()
        first, last = Mock(), Mock()
        first.close.side_effect = RuntimeError("finalizer fixture")
        scope.records.extend((first, last))
        scope.establish(channel)
        with self.assertRaisesRegex(RuntimeError, "finalizer fixture"):
            scope.release(channel)
        first.close.assert_called_once_with()
        last.close.assert_called_once_with()
        channel.abort.assert_called_once_with()
        self.assertEqual((scope.records, scope.keys, scope.channel), ([], [], None))

    def test_failed_retry_key_close_remains_owned_for_final_cleanup(self):
        scope, key = HandshakeSecrets(), Mock()
        key.close.side_effect = [RuntimeError("retry cleanup fixture"), None]
        scope.keys.append(key)
        with self.assertRaisesRegex(RuntimeError, "retry cleanup fixture"):
            scope.close_key(key)
        self.assertEqual(scope.keys, [key])
        scope.close()
        self.assertEqual(key.close.call_count, 2)
        self.assertFalse(scope.keys)


class HandshakeLifecycleEdges(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.case = test_sessions.SessionTests()
        await self.case.asyncSetUp()

    async def asyncTearDown(self):
        await self.case.asyncTearDown()

    def assert_record_closed(self, state):
        self.assertTrue(state.failed)
        self.assertEqual((state.secret, state.key, state.iv), (b"", b"", b""))
        self.assertIsNone(state._cipher)

    @contextmanager
    def tracked_handshakes(self):
        scopes, records, channels = [], [], []
        original_init = HandshakeSecrets.__init__
        original_record = HandshakeSecrets.record
        original_establish = HandshakeSecrets.establish
        def initialize(scope):
            original_init(scope)
            scopes.append(scope)
        def record(scope, *args, **kwargs):
            state = original_record(scope, *args, **kwargs)
            records.append(state)
            return state
        def establish(scope, channel):
            original_establish(scope, channel)
            channels.append(channel)
        with patch.object(HandshakeSecrets, "__init__", initialize), \
                patch.object(HandshakeSecrets, "record", record), \
                patch.object(HandshakeSecrets, "establish", establish):
            yield channels
        self.assertTrue(records)
        for state in records:
            self.assert_record_closed(state)
        for scope in scopes:
            self.assertEqual((scope.records, scope.keys, scope.channel), ([], [], None))

    async def test_partial_channel_record_constructor_failures_release_secrets(self):
        for failed_operation in ("seal", "open"):
            with self.subTest(failed_operation=failed_operation):
                original, states = c.RecordState._reset_cipher, []
                def cipher(state):
                    states.append(state)
                    if state.operation == failed_operation:
                        raise RuntimeError("record constructor fixture failure")
                    return original(state)
                channel = SecureChannel.__new__(SecureChannel)
                with patch.object(c.RecordState, "_reset_cipher", cipher):
                    with self.assertRaisesRegex(RuntimeError, "record constructor fixture failure"):
                        channel.__init__(Wire(asyncio.StreamReader(), MemoryWriter()), b"s" * 32, b"r" * 32,
                            exporter_secret=b"e" * 32, resumption_secret=b"m" * 32,
                            early_exporter_secret=b"d" * 32, enable_authenticators=True,
                            auth_share_secret=c.X25519PrivateKey.generate())
                self.assertEqual(len(states), 1 if failed_operation == "seal" else 2)
                for state in states:
                    self.assert_record_closed(state)
                self.assertIsNone(channel.auth_share_secret)
                self.assertIsNone(channel.exporter_secret)
                self.assertIsNone(channel.resumption_secret)
                self.assertIsNone(channel.early_exporter_secret)

    async def test_ticket_issuance_failure_aborts_unreturned_channel(self):
        with self.tracked_handshakes() as channels:
            with patch.object(self.case.store, "issue", side_effect=ProtocolError("ticket fixture failure", alert=80)):
                with self.assertRaises(PeerClosed) as failure:
                    await self.case.connect()
        self.assertEqual(failure.exception.alert, 80)
        server = next(channel for channel in channels if channel.role == "server")
        self.assertNotIn(server, self.case.channels)
        self.assertTrue(server.closed)
        self.assert_record_closed(server.sender)
        self.assert_record_closed(server.receiver)
        self.assertIsNone(server.exporter_secret)
        self.assertIsNone(server.early_exporter_secret)
        self.assertEqual(server.handshake_transcript, b"")
        self.assertTrue(any("ticket fixture failure" in message for message in self.case.errors))

    async def test_successful_and_failed_early_epochs_release_all_transient_states(self):
        for accepted in (True, False):
            for fail_finished in (False, True):
                with self.subTest(accepted=accepted, fail_finished=fail_finished):
                    self.case.cache, self.case.store = TicketCache(), TicketStore()
                    await self.case.connect()
                    next(iter(self.case.store._tickets.values())).early_used = not accepted
                    original = Wire.send_frame
                    async def send(wire, message, state=None):
                        if fail_finished and wire.writer is self.case.writers[-1] and message[0] == 20:
                            message = message[:-1] + bytes((message[-1] ^ 1,))
                        return await original(wire, message, state)
                    with self.tracked_handshakes() as channels, patch.object(Wire, "send_frame", send):
                        if fail_finished:
                            with self.assertRaises(PeerClosed) as failure:
                                await self.case.connect(early_data=b"synthetic early data")
                            self.assertEqual(failure.exception.alert, 51)
                        else:
                            channel = await self.case.connect(early_data=b"synthetic early data")
                            self.assertTrue(channel.resumed)
                            self.assertEqual(channel.early_data_accepted, accepted)
                    if fail_finished:
                        self.assertEqual(len(channels), 1)
                        self.assertTrue(channels[0].closed)
                        self.assert_record_closed(channels[0].sender)
                        self.assert_record_closed(channels[0].receiver)
                    else:
                        self.assertEqual(len(channels), 2)
                        for live in channels:
                            self.assertFalse(live.sender.failed)
                            self.assertFalse(live.receiver.failed)
                        await channel.send(b"application survives transient cleanup")
                        self.assertEqual(await channel.recv(), b"application survives transient cleanup")


if __name__ == "__main__":
    unittest.main()
