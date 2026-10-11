"""Deterministic malformed-input smoke tests, not a complete fuzz campaign."""

import asyncio
import random
import unittest
from unittest.mock import patch

from tls20_server import crypto as c, messages as m
from tls20_server.errors import PeerClosed, ProtocolError
from tls20_server.handshake import SecureChannel, Wire, Transcript
from tls20_server.lab import generate_lab_credentials
from tls20_server.pki import validate_chain


class ParserRobustnessTests(unittest.TestCase):
    def test_random_malformed_encodings_are_bounded(self):
        # Pseudorandomness here creates public parser junk, never session keys.
        source = random.Random(137014)
        parsers = (m.decode_frame, m.parse_client_hello, m.parse_server_hello,
                   m.parse_certificate, m.parse_encrypted_extensions)
        for parser in parsers:
            for _ in range(1000):
                value = source.randbytes(source.randrange(0, 800))
                try:
                    parser(value)
                except ProtocolError:
                    pass

    def test_every_mutated_certificate_byte_is_rejected(self):
        credentials, root = generate_lab_credentials("localhost")
        certificate = credentials.chain_der[0]
        for index in range(len(certificate)):
            changed = bytearray(certificate)
            changed[index] ^= 1
            with self.subTest(offset=index), self.assertRaises(ProtocolError):
                validate_chain([bytes(changed)], [root], "localhost", "lab-offline")

    def test_transcript_limit(self):
        transcript = Transcript()
        with self.assertRaises(ProtocolError):
            transcript.add(bytes(1048576))
        self.assertEqual(transcript.snapshot(), c.PREFACE)


class MemoryTransport:
    def __init__(self):
        self.aborted = False
        self.closing = False
        self.buffered = 0

    def is_closing(self):
        return self.closing

    def get_write_buffer_size(self):
        return self.buffered

    def abort(self):
        self.aborted = True
        self.closing = True
        self.buffered = 0


class MemoryWriter:
    def __init__(self):
        self.data = bytearray()
        self.transport = MemoryTransport()

    def write(self, content):
        self.data.extend(content)

    async def drain(self):
        pass

    def close(self):
        self.transport.closing = True

    async def wait_closed(self):
        pass


class AsyncRobustnessTests(unittest.IsolatedAsyncioTestCase):
    async def test_alerts_cannot_interleave_fragmented_handshakes(self):
        message = m.frame(20, bytes(32))
        for protected in (False, True):
            for alert in (0, 40, 90):
                with self.subTest(protected=protected, alert=alert):
                    reader = asyncio.StreamReader()
                    sender = c.RecordState(bytes(32), "seal") if protected else None
                    receiver = c.RecordState(bytes(32), "open") if protected else None
                    for content, kind in ((message[:2], 22), (bytes((1, alert)), 21), (message[2:], 22)):
                        reader.feed_data(sender.seal(content, kind) if sender else
                            bytes((kind, 3, 3)) + len(content).to_bytes(2, "big") + content)
                    with self.assertRaises(ProtocolError) as failure:
                        await Wire(reader, MemoryWriter()).receive_frame(20, receiver)
                    self.assertEqual(failure.exception.alert, 40 if alert == 40 else 10)
                    self.assertEqual(isinstance(failure.exception, PeerClosed), alert == 40)

    async def test_user_canceled_between_complete_handshake_messages_is_advisory(self):
        message = m.frame(20, bytes(32))
        reader = asyncio.StreamReader()
        reader.feed_data(b"\x15\x03\x03\x00\x02\x01\x5a"
                         + b"\x16\x03\x03" + len(message).to_bytes(2, "big") + message)
        self.assertEqual(await Wire(reader, MemoryWriter()).receive_frame(20), message)

    async def test_plaintext_record_legacy_version_is_not_version_negotiation(self):
        for legacy in (b"\x00\x00", b"\x03\x01", b"\x04\x00", b"\xff\xff"):
            reader = asyncio.StreamReader()
            message = m.frame(1, b"body")
            reader.feed_data(b"\x16" + legacy + len(message).to_bytes(2, "big") + message)
            wire = Wire(reader, MemoryWriter())
            self.assertEqual(await wire.receive_frame(1), message)

    async def test_cancelled_protected_control_send_is_irrecoverable(self):
        for operation in ("key_update", "send_handshake"):
            entered = asyncio.Event()
            class StalledWriter(MemoryWriter):
                async def drain(self):
                    entered.set()
                    await asyncio.Event().wait()
            writer = StalledWriter()
            channel = SecureChannel(Wire(asyncio.StreamReader(), writer), bytes(32), bytes(32))
            call = channel.key_update() if operation == "key_update" else channel.send_handshake(
                m.new_session_ticket(b"ticket", b"nonce", 60, 0, 0))
            task = asyncio.create_task(call)
            await asyncio.wait_for(entered.wait(), 1)
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task
            self.assertTrue(channel.closed)
            self.assertTrue(writer.transport.aborted)
            with self.assertRaises(ProtocolError):
                await channel.send(b"must not reuse old epoch")

    async def test_abort_after_completed_close_preserves_authenticated_close(self):
        secret = bytes(range(32))
        writer = MemoryWriter()
        channel = SecureChannel(Wire(asyncio.StreamReader(), writer), secret, secret)
        await channel.close()
        # Selector transports may discard their loop after wait_closed().
        with patch.object(writer.transport, "abort", side_effect=AttributeError("detached loop")):
            channel.abort()
            channel.abort()
        self.assertTrue(channel.closed)
        self.assertFalse(writer.transport.aborted)
        self.assertEqual(c.RecordState(secret, "open").open(bytes(writer.data)), (b"\x01\x00", 21))

    async def test_abort_still_discards_closing_transport_output(self):
        writer = MemoryWriter()
        channel = SecureChannel(Wire(asyncio.StreamReader(), writer), bytes(32), bytes(32))
        writer.transport.buffered = 16384
        writer.close()
        channel.closed = True  # close() sets this before wait_closed completes.
        channel.abort()
        self.assertTrue(writer.transport.aborted)
        self.assertEqual(writer.transport.get_write_buffer_size(), 0)

    async def test_abort_open_empty_transport_is_idempotent(self):
        writer = MemoryWriter()
        channel = SecureChannel(Wire(asyncio.StreamReader(), writer), bytes(32), bytes(32))
        with patch.object(writer.transport, "abort", wraps=writer.transport.abort) as abort:
            channel.abort()
            channel.abort()
        abort.assert_called_once()
        self.assertTrue(channel.closed)

    async def test_cancelled_close_still_aborts_buffered_transport(self):
        waiting = asyncio.Event()

        class StalledWriter(MemoryWriter):
            async def wait_closed(self):
                waiting.set()
                await asyncio.Event().wait()

        writer = StalledWriter()
        writer.transport.buffered = 16384
        channel = SecureChannel(Wire(asyncio.StreamReader(), writer), bytes(32), bytes(32))
        task = asyncio.create_task(channel.close())
        await asyncio.wait_for(waiting.wait(), 1)
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await task
        self.assertTrue(writer.transport.aborted)
        self.assertEqual(writer.transport.get_write_buffer_size(), 0)

    async def test_cancel_partial_receive_still_allows_authenticated_close(self):
        secret = bytes(range(32))
        reader = asyncio.StreamReader()
        writer = MemoryWriter()
        channel = SecureChannel(Wire(reader, writer), secret, secret)
        record = c.RecordState(secret, "seal").seal(b"partial input", 23)
        reader.feed_data(record[:8])
        task = asyncio.create_task(channel.recv())
        await asyncio.sleep(0)
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await task
        with self.assertRaises(ProtocolError):
            await channel.recv()
        with self.assertRaises(ProtocolError):
            await channel.send(b"no application data after cancellation")
        await channel.close()
        self.assertFalse(writer.transport.aborted)
        self.assertEqual(c.RecordState(secret, "open").open(bytes(writer.data)), (b"\x01\x00", 21))

    async def test_cancel_receive_consumes_pending_client_authentication(self):
        reader, writer = asyncio.StreamReader(), MemoryWriter()
        channel = SecureChannel(Wire(reader, writer), bytes(32), bytes(32),
            exporter_secret=bytes(32), handshake_transcript=b"finished transcript",
            client_auth_validator=lambda chain: None, peer_post_handshake_auth=True)
        future = await channel.request_client_auth()
        state = next(iter(channel.pending_client_auth.values()))
        task = asyncio.create_task(channel.recv())
        await asyncio.sleep(0)
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await task
        self.assertTrue(channel.closed)
        self.assertTrue(future.cancelled())
        self.assertIsNone(state["private"])
        self.assertFalse(channel.pending_client_auth)
        with self.assertRaises(ProtocolError):
            await channel.request_client_auth()

    async def test_expired_deadline_rejects_already_buffered_input(self):
        reader = asyncio.StreamReader()
        writer = MemoryWriter()
        wire = Wire(reader, writer)
        reader.feed_data(b"already buffered")
        wire.deadline = asyncio.get_running_loop().time() - 1
        with self.assertRaises(TimeoutError):
            await wire.exact(1)
        with self.assertRaises(TimeoutError):
            await wire.send_frame(m.frame(1, b"data"))
        self.assertEqual(writer.data, b"")

    async def test_application_transition_requires_empty_reassembly(self):
        wire = Wire(asyncio.StreamReader(), MemoryWriter())
        wire.pending.extend(b"leftover")
        with self.assertRaises(ProtocolError):
            SecureChannel(wire, bytes(32), bytes(32))

    async def test_handshake_record_budget(self):
        wire = Wire(asyncio.StreamReader(), MemoryWriter())
        wire.handshake_records = 4096
        with self.assertRaises(ProtocolError):
            await wire.send_frame(m.frame(1, b"data"))
        self.assertEqual(wire.writer.data, b"")


class SelectorTransportTests(unittest.TestCase):
    def test_channel_close_then_abort_on_real_selector_transport(self):
        async def exercise():
            accepted = asyncio.get_running_loop().create_future()

            def accept(reader, writer):
                accepted.set_result((reader, writer))

            listener = await asyncio.start_server(accept, "127.0.0.1", 0)
            client = server_writer = None
            try:
                client_reader, client = await asyncio.open_connection(
                    "127.0.0.1", listener.sockets[0].getsockname()[1])
                reader, server_writer = await accepted
                secret = bytes(range(32))
                channel = SecureChannel(Wire(reader, server_writer), secret, secret)
                await channel.close()
                channel.abort()
                channel.abort()
                data = await asyncio.wait_for(client_reader.read(), 1)
                self.assertEqual(c.RecordState(secret, "open").open(data), (b"\x01\x00", 21))
            finally:
                for writer in (client, server_writer):
                    if writer is not None:
                        writer.close()
                        await writer.wait_closed()
                listener.close()
                await asyncio.wait_for(listener.wait_closed(), 1)

        # Exercise Linux's transport family on Windows too.
        with asyncio.Runner(loop_factory=asyncio.SelectorEventLoop) as runner:
            runner.run(exercise())


if __name__ == "__main__":
    unittest.main()
