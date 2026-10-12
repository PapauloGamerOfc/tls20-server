"""Regression tests for directional key updates, PHA ordering and record alerts."""

import asyncio
import unittest

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from tests.test_robustness import MemoryWriter
from tls20_server import crypto as c, messages as m
from tls20_server.errors import PeerClosed, ProtocolError
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
    async def test_unexpected_post_handshake_messages_have_exact_wire_alerts(self):
        hello = m.client_hello(bytes(range(32)), bytes(range(32, 64)), "localhost", bytes(32))
        request = m.certificate_request(b"request context", bytes(32))
        cases = (("server", hello), ("client", m.frame(5, b"")),
                 ("client", request), ("server", request),
                 ("server", m.new_session_ticket(b"ticket", b"nonce", 60, 0, 0)),
                 ("client", b"\x00\x00\x00\x00"))
        from tls20_server.credential_cache import compress_certificate
        certificate = m.certificate([], context=b"unsolicited", allow_empty=True)
        cases += tuple((role, frame) for role in ("client", "server") for frame in
            (certificate, m.certificate_verify(bytes(32), client=True), m.frame(20, bytes(32)),
             m.frame(25, compress_certificate(certificate[4:], 1))))
        for role, frame in cases:
            with self.subTest(role=role, kind=frame[0]):
                channel = self.channel(role=role)
                peer = c.RecordState(bytes(32), "seal")
                observer = c.RecordState(bytes(32), "open")
                try:
                    channel.wire.reader.feed_data(peer.seal(frame, 22))
                    with self.assertRaises(ProtocolError) as failure:
                        await channel.recv()
                    self.assertEqual(failure.exception.alert, 10)
                    self.assertEqual(observer.open(bytes(channel.wire.writer.data)), (b"\x02\x0a", 21))
                    self.assertTrue(channel.closed)
                    self.assertIsNone(channel.authenticated_client)
                finally:
                    peer.close()
                    observer.close()
                    channel.abort()

    async def test_pending_pha_response_order_context_and_encoding_alerts(self):
        for scenario, alert in (("proof_before_certificate", 10), ("finished_before_certificate", 10),
                                ("proof_after_empty_certificate", 10), ("duplicate_certificate", 10),
                                ("unknown_context", 47), ("empty_body", 50), ("truncated_context", 50),
                                ("bad_finished", 51)):
            with self.subTest(scenario=scenario):
                channel, future, certificate, finished = await self.pha()
                peer = c.RecordState(bytes(32), "seal")
                observer = c.RecordState(bytes(32), "open")
                observer.open(bytes(channel.wire.writer.data))  # Consume the request's record.
                channel.wire.writer.data.clear()
                proof = m.certificate_verify(bytes(32), client=True)
                frames = {
                    "proof_before_certificate": (proof,),
                    "finished_before_certificate": (finished,),
                    "proof_after_empty_certificate": (certificate, proof),
                    "duplicate_certificate": (certificate, certificate),
                    "unknown_context": (m.certificate([], context=b"unknown", allow_empty=True),),
                    "empty_body": (m.frame(11, b""),),
                    "truncated_context": (m.frame(11, b"\x04x"),),
                    "bad_finished": (certificate, finished[:-1] + bytes((finished[-1] ^ 1,))),
                }[scenario]
                try:
                    for frame in frames:
                        channel.wire.reader.feed_data(peer.seal(frame, 22))
                    with self.assertRaises(ProtocolError) as failure:
                        await channel.recv()
                    self.assertEqual(failure.exception.alert, alert)
                    self.assertEqual(observer.open(bytes(channel.wire.writer.data)), (bytes((2, alert)), 21))
                    self.assertTrue(channel.closed)
                    self.assertTrue(future.cancelled())
                    self.assertIsNone(channel.authenticated_client)
                finally:
                    peer.close()
                    observer.close()
                    channel.abort()

    async def test_pha_context_errors_remain_distinct_from_unsolicited_requests(self):
        for context, seen, alert in ((b"", (), 47), (b"duplicate", (b"duplicate",), 47),
                                     (b"fresh", tuple(str(i).encode() for i in range(4096)), 40)):
            with self.subTest(context=context, alert=alert):
                channel = self.channel(local_post_handshake_auth=True)
                channel._seen_auth_contexts.update(seen)
                peer = c.RecordState(bytes(32), "seal")
                observer = c.RecordState(bytes(32), "open")
                try:
                    frame = m.certificate_request(context, bytes(32))
                    channel.wire.reader.feed_data(peer.seal(frame, 22))
                    with self.assertRaises(ProtocolError) as failure:
                        await channel.recv()
                    self.assertEqual(failure.exception.alert, alert)
                    self.assertEqual(observer.open(bytes(channel.wire.writer.data)), (bytes((2, alert)), 21))
                    self.assertTrue(channel.closed)
                finally:
                    peer.close()
                    observer.close()
                    channel.abort()

    async def test_key_update_body_alerts_on_authenticated_wire(self):
        for body, alert in ((b"", 50), (b"\0\0", 50), (b"\x02", 47)):
            with self.subTest(body=body):
                channel = self.channel()
                sender, receiver = c.RecordState(bytes(32), "seal"), c.RecordState(bytes(32), "open")
                try:
                    raw = b"\x18" + len(body).to_bytes(3, "big") + body
                    channel.wire.reader.feed_data(sender.seal(raw, 22))
                    with self.assertRaises(ProtocolError) as caught:
                        await channel.recv()
                    self.assertEqual(caught.exception.alert, alert)
                    self.assertEqual(receiver.open(bytes(channel.wire.writer.data)), (bytes((2, alert)), 21))
                    self.assertTrue(channel.closed)
                finally:
                    sender.close()
                    receiver.close()
                    channel.abort()

    async def test_key_update_valid_request_values_advance_receive_epoch(self):
        for body in (b"\0", b"\1"):
            with self.subTest(body=body):
                channel = self.channel()
                sender, receiver = c.RecordState(bytes(32), "seal"), c.RecordState(bytes(32), "open")
                try:
                    channel.wire.reader.feed_data(sender.seal(m.frame(24, body), 22))
                    sender.update()
                    channel.wire.reader.feed_data(sender.seal(b"new epoch data", 23))
                    self.assertEqual(await channel.recv(), b"new epoch data")
                    self.assertEqual(channel.receiver.epoch, 1)
                    if body == b"\1":
                        self.assertEqual(receiver.open(bytes(channel.wire.writer.data)), (m.frame(24, b"\0"), 22))
                        self.assertEqual(channel.sender.epoch, 1)
                    else:
                        self.assertFalse(channel.wire.writer.data)
                finally:
                    sender.close()
                    receiver.close()
                    channel.abort()

    def channel(self, writer=None, **options):
        reader, writer = asyncio.StreamReader(), writer or MemoryWriter()
        return SecureChannel(Wire(reader, writer), bytes(32), bytes(32), **options)

    def assert_secrets_unavailable(self, channel, states):
        for state in states:
            self.assertTrue(state.failed)
            self.assertEqual((state.secret, state.key, state.iv), (b"", b"", b""))
            self.assertIsNone(state._cipher)
            self.assertIsNone(state.provider)
            state.close()  # Repeated cleanup must remain safe.
            with self.assertRaises(ProtocolError):
                state.update()
        self.assertIsNone(channel.exporter_secret)
        self.assertIsNone(channel.resumption_secret)
        self.assertIsNone(channel.early_exporter_secret)
        self.assertIsNone(channel.client_credentials)
        self.assertFalse(channel.client_credential_candidates)
        with self.assertRaises(ProtocolError):
            channel.exporter("after teardown")
        with self.assertRaises(ProtocolError):
            channel.early_exporter("after teardown")
        with self.assertRaises(ProtocolError):
            states[0].seal(b"after teardown", 23)
        record = c.RecordState(bytes(32), "seal").seal(b"after teardown", 23)
        with self.assertRaises(ProtocolError):
            states[1].open(record)
        with self.assertRaises(ProtocolError):
            states[1].try_open(record)

    async def test_terminal_paths_release_secrets_and_owned_capabilities(self):
        from unittest.mock import Mock
        from tls20_server.exporter_access import ExporterAccess
        credential, provider = object(), Mock()
        for ending in ("fatal", "malformed", "abort", "close"):
            with self.subTest(ending=ending):
                channel = self.channel(exporter_secret=b"e" * 32, resumption_secret=b"r" * 32,
                    early_exporter_secret=b"v" * 32, client_credentials=credential, native_provider=provider)
                states = channel.sender, channel.receiver  # Keep references across teardown.
                access = ExporterAccess(channel.exporter_secret, stage="server-finished", role="client")
                channel._exporter_accesses = (access,)
                if ending in ("fatal", "malformed"):
                    record = (c.RecordState(bytes(32), "seal").seal(b"\x02\x28", 21)
                              if ending == "fatal" else b"\x17\x03\x03\x00\x00")
                    channel.wire.reader.feed_data(record)
                    with self.assertRaises(ProtocolError) as failure:
                        await channel.recv()
                    self.assertEqual(failure.exception.alert, 40 if ending == "fatal" else 20)
                    if ending == "fatal":
                        self.assertEqual(channel.wire.writer.data, b"")
                    else:
                        self.assertEqual(c.RecordState(bytes(32), "open").open(bytes(channel.wire.writer.data)),
                                         (b"\x02\x14", 21))
                elif ending == "abort":
                    channel.abort()
                else:
                    await channel.close()
                    self.assertEqual(c.RecordState(bytes(32), "open").open(bytes(channel.wire.writer.data)),
                                     (b"\x01\x00", 21))
                self.assertTrue(channel.closed)
                self.assertFalse(access.active)
                self.assert_secrets_unavailable(channel, states)
                provider.close.assert_not_called()

    async def test_peer_half_close_preserves_send_until_full_close(self):
        channel = self.channel(exporter_secret=b"e" * 32)
        states = channel.sender, channel.receiver
        expected = channel.exporter("half close")
        peer = c.RecordState(bytes(32), "seal")
        channel.wire.reader.feed_data(peer.seal(b"\x01\x00", 21))
        self.assertIsNone(await channel.recv())
        self.assertFalse(channel.closed)
        self.assertTrue(channel.receiver.failed)
        self.assertEqual(channel.receiver.secret, b"")
        self.assertEqual(channel.exporter("half close"), expected)
        await channel.send(b"last response")
        observer = c.RecordState(bytes(32), "open")
        self.assertEqual(observer.open(bytes(channel.wire.writer.data)), (b"last response", 23))
        channel.wire.writer.data.clear()
        await channel.close()
        self.assertEqual(observer.open(bytes(channel.wire.writer.data)), (b"\x01\x00", 21))
        self.assert_secrets_unavailable(channel, states)

    async def test_cancelled_read_releases_secrets_but_can_send_authenticated_close(self):
        channel = self.channel(exporter_secret=b"e" * 32, resumption_secret=b"r" * 32,
                               early_exporter_secret=b"v" * 32)
        states = channel.sender, channel.receiver
        task = asyncio.create_task(channel.recv())
        await asyncio.sleep(0)
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await task
        self.assertTrue(channel.read_cancelled)
        self.assertFalse(channel.sender.failed)
        self.assertTrue(channel.receiver.failed)
        self.assertEqual(channel.receiver.secret, b"")
        with self.assertRaises(ProtocolError):
            channel.exporter("cancelled")
        with self.assertRaises(ProtocolError):
            channel.early_exporter("cancelled")
        with self.assertRaises(ProtocolError):
            await channel.key_update()
        with self.assertRaises(ProtocolError):
            await channel.send_handshake(m.frame(24, b"\x00"))
        await channel.close()
        self.assertEqual(c.RecordState(bytes(32), "open").open(bytes(channel.wire.writer.data)),
                         (b"\x01\x00", 21))
        self.assert_secrets_unavailable(channel, states)

    async def test_cancelled_write_releases_both_record_directions(self):
        class BlockedWriter(MemoryWriter):
            async def drain(self):
                await asyncio.Future()
        channel = self.channel(BlockedWriter(), exporter_secret=b"e" * 32,
                               resumption_secret=b"r" * 32, early_exporter_secret=b"v" * 32)
        states = channel.sender, channel.receiver
        task = asyncio.create_task(channel.send(b"pending"))
        await asyncio.sleep(0)
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await task
        self.assertTrue(channel.closed)
        self.assertTrue(channel.wire.writer.transport.aborted)
        self.assert_secrets_unavailable(channel, states)

    async def test_cancelled_fatal_flush_aborts_and_releases_secrets(self):
        channel = self.channel(exporter_secret=b"e" * 32, resumption_secret=b"r" * 32,
                               early_exporter_secret=b"v" * 32)
        states = channel.sender, channel.receiver
        await channel.send_lock.acquire()
        try:
            channel.wire.reader.feed_data(b"\x17\x03\x03\x00\x00")
            task = asyncio.create_task(channel.recv())
            await asyncio.sleep(0)
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task
        finally:
            channel.send_lock.release()
        self.assertTrue(channel.closed)
        self.assertTrue(channel.wire.writer.transport.aborted)
        self.assert_secrets_unavailable(channel, states)

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

    async def test_fragmented_post_handshake_alerts_abort_and_clear_authentication(self):
        for active_pha in (False, True):
            for alert in (0, 40, 90):
                with self.subTest(active_pha=active_pha, alert=alert):
                    channel, future, certificate, finished = await self.pha()
                    pending = next(iter(channel.pending_client_auth.values()))
                    observer = c.RecordState(bytes(32), "open")
                    observer.open(bytes(channel.wire.writer.data))  # Initial PHA request.
                    channel.wire.writer.data.clear()
                    peer = c.RecordState(bytes(32), "seal")
                    if active_pha:
                        channel.wire.reader.feed_data(peer.seal(certificate, 22))
                    frame = finished if active_pha else m.frame(24, b"\x00")
                    for content, kind in ((frame[:2], 22), (bytes((2, alert)), 21),
                                          (frame[2:], 22), (b"must not escape", 23)):
                        channel.wire.reader.feed_data(peer.seal(content, kind))
                    with self.assertRaises(ProtocolError) as failure:
                        await channel.recv()
                    self.assertEqual(failure.exception.alert, 40 if alert == 40 else 10)
                    self.assertEqual(isinstance(failure.exception, PeerClosed), alert == 40)
                    if alert == 40:
                        self.assertEqual(channel.wire.writer.data, b"")
                    else:
                        self.assertEqual(observer.open(bytes(channel.wire.writer.data)), (b"\x02\x0a", 21))
                    self.assertTrue(channel.closed)
                    self.assertTrue(channel.wire.writer.transport.is_closing())
                    self.assertFalse(channel.received_close)
                    self.assertTrue(future.cancelled())
                    self.assertIsNone(pending["private"])
                    self.assertFalse(channel.pending_client_auth)
                    self.assertIsNone(channel._active_client_auth)
                    with self.assertRaisesRegex(ProtocolError, "closed"):
                        await channel.recv()


if __name__ == "__main__":
    unittest.main()
