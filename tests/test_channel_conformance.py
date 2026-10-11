"""Regression tests for directional key updates, PHA ordering and record alerts."""

import asyncio
import unittest

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from tests.test_robustness import MemoryWriter
from tls20_server import crypto as c, messages as m
from tls20_server.errors import ProtocolError
from tls20_server.handshake import SecureChannel, Wire


class RecordAlertTests(unittest.TestCase):
    def record(self, plaintext):
        # Public, fixed fixture material; never used outside these unit tests.
        key, iv = c.key_iv(bytes(32))
        header = b"\x17\x03\x03" + (len(plaintext) + 16).to_bytes(2, "big")
        return header + AESGCM(key).encrypt(iv, plaintext, header)

    def test_authenticated_invalid_inner_records_have_specific_alerts(self):
        cases = ((b"\x16", 10), (b"\x15", 10), (b"data\x19", 10),
                 (b"\0" * 32, 10), (b"", 10), (b"\x02\x15", 50),
                 (b"\x02\x28\x01\x15", 50), (b"a" * 16385 + b"\x17", 22))
        for plaintext, alert in cases:
            with self.subTest(length=len(plaintext), tail=plaintext[-4:]):
                state = c.RecordState(bytes(32), "open")
                with self.assertRaises(ProtocolError) as caught:
                    state.open(self.record(plaintext))
                self.assertEqual(caught.exception.alert, alert)
                self.assertTrue(state.failed)

    def test_framing_overflow_and_authentication_are_distinct(self):
        good = self.record(b"content\x17")
        cases = ((b"\x17\x03", 50), (b"\x16" + good[1:], 10),
                 (good[:3] + b"\x00\x01" + good[5:], 50),
                 (b"\x17\x03\x03\x41\x01" + bytes(16641), 22),
                 (b"\x17\x03\x03\x00\x00", 20),
                 (good[:-1] + bytes((good[-1] ^ 1,)), 20))
        for record, alert in cases:
            with self.subTest(alert=alert, size=len(record)):
                with self.assertRaises(ProtocolError) as caught:
                    c.RecordState(bytes(32), "open").open(record)
                self.assertEqual(caught.exception.alert, alert)

    def test_empty_application_record_remains_valid(self):
        self.assertEqual(c.RecordState(bytes(32), "open").open(self.record(b"\x17")), (b"", 23))

    def test_epoch_bound_applies_only_to_sender(self):
        sender, receiver = c.RecordState(bytes(32), "seal"), c.RecordState(bytes(32), "open")
        sender.epoch = receiver.epoch = c.MAX_SEND_EPOCH - 1
        sender.update()
        receiver.update()
        self.assertEqual(sender.epoch, c.MAX_SEND_EPOCH)
        before = sender.secret
        with self.assertRaises(ProtocolError):
            sender.update()
        self.assertEqual(sender.secret, before)
        self.assertEqual(receiver.open(sender.seal(b"last epoch remains usable", 23))[0], b"last epoch remains usable")
        receiver.update()
        self.assertEqual(receiver.epoch, c.MAX_SEND_EPOCH + 1)


class ChannelConformanceTests(unittest.IsolatedAsyncioTestCase):
    def channel(self, writer=None, **options):
        reader, writer = asyncio.StreamReader(), writer or MemoryWriter()
        return SecureChannel(Wire(reader, writer), bytes(32), bytes(32), **options)

    async def test_requested_update_waits_for_peer_but_unrequested_does_not_clear_it(self):
        channel = self.channel()
        await channel.key_update(True)
        before = bytes(channel.wire.writer.data)
        with self.assertRaisesRegex(ProtocolError, "pending"):
            await channel.key_update(True)
        self.assertEqual(channel.wire.writer.data, before)
        self.assertFalse(channel.closed)
        await channel.key_update(False)
        self.assertTrue(channel._key_update_requested)
        await channel._post_handshake(m.frame(24, b"\x00"))
        self.assertFalse(channel._key_update_requested)
        await channel.key_update(True)
        self.assertEqual(channel.sender.epoch, 3)

    async def test_response_during_drain_clears_the_outstanding_request(self):
        class RespondingWriter(MemoryWriter):
            async def drain(self):
                await channel._post_handshake(m.frame(24, b"\x00"))
        channel = self.channel(RespondingWriter())
        await channel.key_update(True)
        self.assertFalse(channel._key_update_requested)
        await channel.key_update(True)
        self.assertFalse(channel._key_update_requested)

    async def test_epoch_exhaustion_never_announces_an_unusable_key(self):
        channel = self.channel()
        channel.sender.epoch = c.MAX_SEND_EPOCH
        with self.assertRaisesRegex(ProtocolError, "epoch exhausted"):
            await channel.key_update()
        self.assertEqual(channel.wire.writer.data, b"")
        self.assertFalse(channel.closed)
        # A request beyond our sending bound is ignored, but not the peer's
        # own receive-direction update. Application records remain readable.
        channel.receiver.epoch = c.MAX_SEND_EPOCH
        await channel._post_handshake(m.frame(24, b"\x01"))
        self.assertEqual(channel.receiver.epoch, c.MAX_SEND_EPOCH + 1)
        self.assertEqual(channel.wire.writer.data, b"")
        await channel.send(b"remaining safe use of last epoch")
        self.assertTrue(channel.wire.writer.data)

    async def test_automatic_rekey_at_exhaustion_closes_without_output(self):
        for heartbeat in (False, True):
            with self.subTest(heartbeat=heartbeat):
                options = {"heartbeat_local_mode": 1, "heartbeat_peer_mode": 1} if heartbeat else {}
                channel = self.channel(**options)
                channel.sender.epoch = c.MAX_SEND_EPOCH
                channel.sender.sequence = c.MAX_RECORDS - 1
                with self.assertRaisesRegex(ProtocolError, "epoch exhausted"):
                    if heartbeat:
                        await channel.request_heartbeat(b"probe")
                    else:
                        await channel.send(b"application")
                self.assertEqual(channel.wire.writer.data, b"")
                self.assertTrue(channel.closed)

    async def test_empty_plaintext_handshake_or_alert_is_unexpected(self):
        for kind in (21, 22):
            channel = self.channel()
            channel.wire.reader.feed_data(bytes((kind, 3, 3, 0, 0)))
            with self.assertRaises(ProtocolError) as caught:
                await channel.wire.raw_record()
            self.assertEqual(caught.exception.alert, 10)

    async def pha(self):
        channel = self.channel(exporter_secret=bytes(32), handshake_transcript=b"finished transcript",
                               peer_post_handshake_auth=True, client_auth_validator=lambda chain: None)
        future = await channel.request_client_auth()
        context = next(iter(channel.pending_client_auth))
        certificate = m.certificate([], context=context, allow_empty=True)
        finished = m.frame(20, channel.schedule.finished(bytes(32),
                           bytes(channel.pending_client_auth[context]["transcript"]) + certificate))
        return channel, future, certificate, finished

    async def test_data_is_allowed_while_waiting_but_response_is_consecutive(self):
        channel, future, certificate, finished = await self.pha()
        peer = c.RecordState(bytes(32), "seal")
        for data, kind in ((b"before", 23), (certificate + finished, 22), (b"after", 23)):
            channel.wire.reader.feed_data(peer.seal(data, kind))
        self.assertEqual(await channel.recv(), b"before")
        self.assertFalse(future.done())
        self.assertEqual(await channel.recv(), b"after")
        self.assertIsNone(await future)

    async def test_app_control_and_key_update_cannot_interrupt_pha_response(self):
        for content, kind in ((b"interleaved", 23), (b"heartbeat", 24),
                              (m.frame(24, b"\x00"), 22), (b"\x01\x5a", 21)):
            with self.subTest(kind=kind):
                channel, future, certificate, finished = await self.pha()
                peer = c.RecordState(bytes(32), "seal")
                for data, record_kind in ((certificate, 22), (content, kind), (finished, 22)):
                    channel.wire.reader.feed_data(peer.seal(data, record_kind))
                with self.assertRaises(ProtocolError) as caught:
                    await channel.recv()
                self.assertEqual(caught.exception.alert, 10)
                self.assertTrue(future.cancelled())
                self.assertTrue(channel.closed)
                self.assertIsNone(channel._active_client_auth)

    async def test_close_notify_abandons_incomplete_pha(self):
        channel, future, certificate, _ = await self.pha()
        peer = c.RecordState(bytes(32), "seal")
        channel.wire.reader.feed_data(peer.seal(certificate, 22) + peer.seal(b"\x01\x00", 21))
        self.assertIsNone(await channel.recv())
        self.assertTrue(future.cancelled())
        self.assertIsNone(channel._active_client_auth)


if __name__ == "__main__":
    unittest.main()
