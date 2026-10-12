"""Authenticated duplex controls preempt unsent records under backpressure."""

import asyncio
import unittest

from tests.test_robustness import MemoryWriter
from tls20_server import crypto as c, messages as m
from tls20_server.errors import PeerClosed, ProtocolError
from tls20_server.handshake import SecureChannel, Wire


class PausedWriter(MemoryWriter):
    def __init__(self, pauses=(1,), fail_after_pause=False):
        super().__init__()
        self.records = []
        self.entered = {index: asyncio.Event() for index in pauses}
        self.releases = {index: asyncio.Event() for index in pauses}
        self.fail_after_pause = fail_after_pause

    def write(self, record):
        self.records.append(record)
        super().write(record)

    async def drain(self):
        index = len(self.records)
        if index in self.entered:
            self.entered[index].set()
            await self.releases[index].wait()
            if self.fail_after_pause:
                raise OSError("synthetic write failure")

    def release_all(self):
        for event in self.releases.values():
            event.set()


class DuplexControlTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.channels, self.tasks = [], []

    async def asyncTearDown(self):
        for channel in self.channels:
            channel.wire.writer.release_all()
            channel.abort()
        for task in self.tasks:
            if not task.done():
                task.cancel()
        await asyncio.gather(*self.tasks, return_exceptions=True)

    def channel(self, role, writer=None):
        writer = writer or PausedWriter()
        channel = SecureChannel(Wire(asyncio.StreamReader(), writer), bytes(32), bytes(32),
            role=role, send_record_limit=64, exporter_secret=b"e" * 32,
            resumption_secret=b"r" * 32, early_exporter_secret=b"y" * 32)
        self.channels.append(channel)
        return channel

    def task(self, coroutine):
        task = asyncio.create_task(coroutine)
        self.tasks.append(task)
        return task

    async def settled(self):
        for _ in range(3):
            await asyncio.sleep(0)

    def decode(self, writer):
        observer = c.RecordState(bytes(32), "open")
        records = []
        try:
            for record in writer.records:
                content, kind = observer.open(record)
                records.append((kind, content))
                if kind == 22 and content[:4] == b"\x18\0\0\1":
                    observer.update()
        finally:
            observer.close()
        return records

    def assert_closed(self, channel):
        self.assertTrue(channel.closed)
        self.assertTrue(channel.sender.failed)
        self.assertTrue(channel.receiver.failed)
        self.assertEqual(channel.sender.secret, b"")
        self.assertIsNone(channel.exporter_secret)
        self.assertIsNone(channel.resumption_secret)
        self.assertIsNone(channel.early_exporter_secret)

    async def test_key_update_precedes_next_application_record_under_backpressure(self):
        for role in ("client", "server"):
            for requested in (False, True):
                with self.subTest(role=role, requested=requested):
                    channel = self.channel(role)
                    writer, peer = channel.wire.writer, c.RecordState(bytes(32), "seal")
                    self.addCleanup(peer.close)
                    upload = self.task(channel.send(b"x" * 189))
                    await writer.entered[1].wait()
                    channel.wire.reader.feed_data(peer.seal(m.frame(24, bytes((requested,))), 22))
                    peer.update()
                    channel.wire.reader.feed_data(peer.seal(b"peer response", 23))
                    receiving = self.task(channel.recv())
                    # Reading is not stalled behind a blocked upload. This also
                    # lets a following peer fatal alert promptly revoke writes.
                    self.assertEqual(await asyncio.wait_for(asyncio.shield(receiving), 0.5), b"peer response")
                    self.assertEqual(channel.receiver.epoch, 1)
                    self.assertEqual(len(writer.records), 1)
                    writer.release_all()
                    await upload
                    records = self.decode(writer)
                    self.assertEqual([kind for kind, _ in records],
                                     [23, 22, 23, 23] if requested else [23, 23, 23])
                    if requested:
                        self.assertEqual(records[1], (22, m.frame(24, b"\0")))
                    self.assertEqual(b"".join(content for kind, content in records if kind == 23), b"x" * 189)

    async def test_new_request_during_response_drain_is_answered_before_application(self):
        for role in ("client", "server"):
            with self.subTest(role=role):
                writer = PausedWriter(pauses=(1, 2))
                channel, peer = self.channel(role, writer), c.RecordState(bytes(32), "seal")
                self.addCleanup(peer.close)
                upload = self.task(channel.send(b"x" * 189))
                await writer.entered[1].wait()
                for index in (1, 2):
                    channel.wire.reader.feed_data(peer.seal(m.frame(24, b"\1"), 22))
                    peer.update()
                    channel.wire.reader.feed_data(peer.seal(bytes((index,)), 23))
                    self.assertEqual(await channel.recv(), bytes((index,)))
                    if index == 1:
                        writer.releases[1].set()
                        await writer.entered[2].wait()  # Peer can consume KU1 here.
                writer.release_all()
                await upload
                self.assertEqual([kind for kind, _ in self.decode(writer)], [23, 22, 22, 23, 23])

    async def test_fatal_stops_active_and_queued_application_or_handshake_writes(self):
        for role in ("client", "server"):
            for remote in (False, True):
                for handshake in (False, True):
                    with self.subTest(role=role, remote=remote, handshake=handshake):
                        channel = self.channel(role)
                        writer, peer = channel.wire.writer, c.RecordState(bytes(32), "seal")
                        self.addCleanup(peer.close)
                        frame = m.certificate([], context=b"c" * 180, allow_empty=True)
                        upload = self.task(channel.send_handshake(frame) if handshake else channel.send(b"x" * 189))
                        await writer.entered[1].wait()
                        queued = self.task(channel.send(b"queued application"))
                        record = peer.seal(b"\2\x28", 21) if remote else b"\x17\x03\x03\0\0"
                        channel.wire.reader.feed_data(record)
                        receiving = self.task(channel.recv())
                        await self.settled()
                        self.assertTrue(channel.closed)  # Before the upload can drain.
                        if remote:
                            with self.assertRaises(PeerClosed):
                                await asyncio.wait_for(asyncio.shield(receiving), 0.5)
                        writer.release_all()
                        outcomes = await asyncio.gather(upload, queued, receiving, return_exceptions=True)
                        self.assertTrue(all(isinstance(value, ProtocolError) for value in outcomes), outcomes)
                        # Already-written bytes are not retractable; no later
                        # application/handshake fragment may be newly emitted.
                        self.assertEqual(len(writer.records), 1 if remote else 2)
                        if not remote:
                            self.assertEqual(self.decode(writer)[-1], (21, b"\2\x14"))
                        self.assert_closed(channel)

    async def test_local_fatal_has_a_deadline_even_when_writer_lock_is_blocked(self):
        channel = self.channel("server")
        writer = channel.wire.writer
        upload = self.task(channel.send(b"x" * 189))
        await writer.entered[1].wait()
        channel.wire.reader.feed_data(b"\x17\x03\x03\0\0")
        with self.assertRaises(ProtocolError):
            await asyncio.wait_for(channel.recv(), 1.0)
        self.assert_closed(channel)
        self.assertTrue(writer.transport.aborted)
        writer.release_all()
        with self.assertRaises(ProtocolError):
            await upload
        self.assertEqual(len(writer.records), 1)

    async def test_cancel_or_failure_during_key_update_response_aborts_ambiguous_epoch(self):
        for role in ("client", "server"):
            for cancelled in (False, True):
                with self.subTest(role=role, cancelled=cancelled):
                    writer = PausedWriter(fail_after_pause=not cancelled)
                    channel, peer = self.channel(role, writer), c.RecordState(bytes(32), "seal")
                    self.addCleanup(peer.close)
                    channel.wire.reader.feed_data(peer.seal(m.frame(24, b"\1"), 22))
                    receiving = self.task(channel.recv())
                    await writer.entered[1].wait()
                    if cancelled:
                        receiving.cancel()
                    else:
                        writer.release_all()
                    with self.assertRaises(asyncio.CancelledError if cancelled else OSError):
                        await receiving
                    self.assert_closed(channel)
                    with self.assertRaises(ProtocolError):
                        await channel.send(b"must not reuse old epoch")

    async def test_fatal_interrupts_key_update_or_close_drain_without_extra_output(self):
        for role in ("client", "server"):
            for updating in (False, True):
                for remote in (False, True):
                    with self.subTest(role=role, updating=updating, remote=remote):
                        channel = self.channel(role)
                        writer, peer = channel.wire.writer, c.RecordState(bytes(32), "seal")
                        self.addCleanup(peer.close)
                        sending = self.task(channel.key_update() if updating else channel.close())
                        await writer.entered[1].wait()
                        channel.wire.reader.feed_data(peer.seal(b"\2\x28", 21) if remote else b"\x17\x03\x03\0\0")
                        receiving = self.task(channel.recv())
                        await self.settled()
                        self.assertTrue(channel.closed)
                        if remote:
                            with self.assertRaises(PeerClosed):
                                await asyncio.wait_for(asyncio.shield(receiving), 0.5)
                        writer.release_all()
                        result, error = await asyncio.gather(sending, receiving, return_exceptions=True)
                        self.assertIsInstance(error, ProtocolError)
                        self.assertIsInstance(result, ProtocolError) if updating and remote else self.assertIsNone(result)
                        self.assertEqual(len(writer.records), 1 if remote else 2)
                        if not remote:
                            self.assertEqual(self.decode(writer)[-1], (21, b"\2\x14"))
                        self.assert_closed(channel)

    async def test_local_fatal_during_response_or_automatic_update_sends_only_new_epoch_alert(self):
        for role in ("client", "server"):
            for automatic in (False, True):
                for heartbeat in (False, True):
                    with self.subTest(role=role, automatic=automatic, heartbeat=heartbeat):
                        channel = self.channel(role)
                        writer = channel.wire.writer
                        # A public, already-at-limit byte counter triggers KU
                        # without changing the actual cipher/sequence observed.
                        if automatic:
                            channel.sender.content_bytes = c.MAX_CONTENT_BYTES - 5
                        else:
                            channel._key_update_response_pending = True
                        async def send_heartbeat():
                            async with channel.send_lock:
                                await channel._send_heartbeat_locked(b"heartbeat")
                        sending = self.task(send_heartbeat() if heartbeat else channel.send(b"unsent"))
                        await writer.entered[1].wait()  # KU written, drain blocked.
                        self.assertEqual(self.decode(writer), [(22, m.frame(24, b"\0"))])
                        channel.wire.reader.feed_data(b"\x17\x03\x03\0\0")
                        receiving = self.task(channel.recv())
                        await self.settled()
                        self.assertTrue(channel.closed)
                        writer.release_all()
                        outcomes = await asyncio.gather(sending, receiving, return_exceptions=True)
                        self.assertTrue(all(isinstance(value, ProtocolError) for value in outcomes))
                        self.assertEqual(self.decode(writer), [(22, m.frame(24, b"\0")), (21, b"\2\x14")])
                        self.assert_closed(channel)

    async def test_peer_half_close_preserves_active_and_queued_send_direction(self):
        for role in ("client", "server"):
            with self.subTest(role=role):
                channel = self.channel(role)
                writer, peer = channel.wire.writer, c.RecordState(bytes(32), "seal")
                self.addCleanup(peer.close)
                upload = self.task(channel.send(b"x" * 189))
                await writer.entered[1].wait()
                queued = self.task(channel.send(b"queued response"))
                channel.wire.reader.feed_data(peer.seal(b"\1\0", 21))
                self.assertIsNone(await channel.recv())
                self.assertFalse(channel.closed)
                writer.release_all()
                await asyncio.gather(upload, queued)
                self.assertEqual(b"".join(value for kind, value in self.decode(writer) if kind == 23),
                                 b"x" * 189 + b"queued response")

    async def test_cancel_upload_or_close_timeout_prevents_unsent_tail(self):
        for role in ("client", "server"):
            for cancellation in (False, True):
                with self.subTest(role=role, cancellation=cancellation):
                    channel = self.channel(role)
                    writer = channel.wire.writer
                    upload = self.task(channel.send(b"x" * 189))
                    await writer.entered[1].wait()
                    if cancellation:
                        upload.cancel()
                        with self.assertRaises(asyncio.CancelledError):
                            await upload
                    else:
                        await channel.close()  # Bounded even while acquiring send_lock.
                    self.assert_closed(channel)
                    writer.release_all()
                    await asyncio.gather(upload, return_exceptions=True)
                    self.assertEqual(len(writer.records), 1)

    async def test_peer_half_close_preserves_required_key_update_response(self):
        for role in ("client", "server"):
            with self.subTest(role=role):
                channel = self.channel(role)
                writer, peer = channel.wire.writer, c.RecordState(bytes(32), "seal")
                self.addCleanup(peer.close)
                upload = self.task(channel.send(b"x" * 126))
                await writer.entered[1].wait()
                channel.wire.reader.feed_data(peer.seal(m.frame(24, b"\1"), 22))
                peer.update()
                channel.wire.reader.feed_data(peer.seal(b"\1\0", 21))
                self.assertIsNone(await asyncio.wait_for(channel.recv(), 0.5))
                self.assertTrue(channel.received_close)
                self.assertIsNone(channel.auth_share_secret)
                writer.release_all()
                await upload
                self.assertEqual(self.decode(writer), [
                    (23, b"x" * 63), (22, m.frame(24, b"\0")), (23, b"x" * 63)])
