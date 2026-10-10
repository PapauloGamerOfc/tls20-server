"""Deterministic malformed-input smoke tests, not a complete fuzz campaign."""

import asyncio
import random
import unittest

from tls20_server import crypto as c, messages as m
from tls20_server.errors import ProtocolError
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

    def abort(self):
        self.aborted = True


class MemoryWriter:
    def __init__(self):
        self.data = bytearray()
        self.transport = MemoryTransport()

    def write(self, content):
        self.data.extend(content)

    async def drain(self):
        pass

    def close(self):
        pass

    async def wait_closed(self):
        pass


class AsyncRobustnessTests(unittest.IsolatedAsyncioTestCase):
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


if __name__ == "__main__":
    unittest.main()
