"""Certificate codec alerts and cached-object framing on authenticated wires."""

import asyncio
from contextlib import contextmanager
import unittest
import zlib
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from tls20_server import credential_cache, handshake, messages
from tls20_server.credential_profiles import CredentialPolicy, RawPublicKeyBinding
from tls20_server.errors import ProtocolError
from tls20_server.pki import Credentials
from tls20_server.tickets import TicketCache
from tests import test_sessions


def altered_compression(body, algorithm, variant):
    packed = credential_cache.compress_certificate(body, algorithm)
    if variant == "garbage":
        data = b"not a valid compressed stream"
        return packed[:5] + len(data).to_bytes(3, "big") + data
    if variant in ("short", "long"):
        delta = -1 if variant == "short" else 1
        return packed[:2] + (len(body) + delta).to_bytes(3, "big") + packed[5:]
    if variant == "truncated":
        return packed[:-1]
    if variant == "trailing":
        return packed + b"x"
    if variant == "empty-vector":
        return packed[:5] + bytes(3)
    if variant == "unoffered":
        return (1 if algorithm != 1 else 2).to_bytes(2, "big") + packed[2:]
    if variant == "unknown":
        return b"\xff\xff" + packed[2:]
    if variant == "declared-zero":
        return packed[:2] + bytes(3) + packed[5:]
    if variant == "empty-decoded":
        if algorithm == 1:
            data = zlib.compress(b"")
        elif algorithm == 2:
            import brotli
            data = brotli.compress(b"")
        else:
            import zstandard
            data = zstandard.ZstdCompressor().compress(b"")
        return packed[:2] + bytes(3) + len(data).to_bytes(3, "big") + data
    return packed


VARIANT_ALERTS = {"garbage": 42, "short": 42, "long": 42, "truncated": 50,
    "trailing": 50, "empty-vector": 50, "unoffered": 47, "unknown": 47,
    "declared-zero": 42, "empty-decoded": 50}


@contextmanager
def coalesce_codec_flights(testcase, *, before_send=None):
    """Send each test credential/proof/Finished flight in one record.

    These tests assert the peer's exact alert, not transport-close races. If
    the malformed credential goes out separately, the peer can close before
    the remaining proof/Finished writes, and TCP may reset instead of exposing
    its alert. Keep the actual generated handshake bytes and transcript intact.
    """
    original_send = handshake.Wire.send_frame
    pending, sent = {}, []

    async def send(wire, message, state=None):
        if message[0] != 25 and wire not in pending:
            return await original_send(wire, message, state)
        if wire not in pending:
            pending[wire] = (state, [])
        expected_state, frames = pending[wire]
        testcase.assertIs(state, expected_state)
        frames.append(message)
        if message[0] != 20:
            return
        del pending[wire]
        testcase.assertEqual([frame[0] for frame in frames], [25, 15, 20])
        flight = b"".join(frames)
        testcase.assertIsNotNone(state)
        testcase.assertLessEqual(len(flight), min(16384, state.record_limit - 1))
        if before_send is not None:
            await before_send(wire, tuple(frames))
        sent.append(flight)
        await original_send(wire, flight, state)

    try:
        with patch.object(handshake.Wire, "send_frame", send):
            yield sent
        testcase.assertFalse(pending, "incomplete test credential flight")
    finally:
        pending.clear()


class CodecAlertTests(unittest.TestCase):
    def test_codec_failure_alerts_do_not_change_outer_checks(self):
        body = b"a test credential" * 4
        for algorithm in (1, 2, 3):
            packed = credential_cache.compress_certificate(body, algorithm)
            self.assertEqual(credential_cache.decompress_certificate(packed, (algorithm,)), body)
            for variant in ("garbage", "short", "long"):
                with self.subTest(algorithm=algorithm, variant=variant), self.assertRaises(ProtocolError) as caught:
                    credential_cache.decompress_certificate(altered_compression(body, algorithm, variant), (algorithm,))
                self.assertEqual(caught.exception.alert, 42)
            # A malformed envelope or an unoffered algorithm never reaches a
            # codec and must not masquerade as a bad_certificate decode failure.
            for invalid, offers in ((packed[:-1], (algorithm,)), (packed + b"x", (algorithm,)), (packed, ())):
                with self.subTest(algorithm=algorithm, invalid=invalid), self.assertRaises(ProtocolError) as caught:
                    credential_cache.decompress_certificate(invalid, offers)
                self.assertNotEqual(caught.exception.alert, 42)

    def test_compressed_envelope_syntax_semantics_and_local_limits(self):
        body = b"bounded credential" * 20
        for algorithm in (1, 2, 3):
            packed = credential_cache.compress_certificate(body, algorithm)
            for variant, alert in VARIANT_ALERTS.items():
                with self.subTest(algorithm=algorithm, variant=variant):
                    invalid = altered_compression(body, algorithm, variant)
                    if variant == "empty-decoded":
                        self.assertEqual(credential_cache.decompress_certificate(invalid, (algorithm,)), b"")
                    else:
                        with self.assertRaises(ProtocolError) as caught:
                            credential_cache.decompress_certificate(invalid, (algorithm,))
                        self.assertEqual(caught.exception.alert, alert)
            for size in range(8):
                with self.assertRaises(ProtocolError) as caught:
                    credential_cache.decompress_certificate(packed[:size], (algorithm,))
                self.assertEqual(caught.exception.alert, 50)
            with self.assertRaises(ProtocolError) as caught:
                credential_cache.decompress_certificate(packed, (algorithm,), max_size=len(body) - 1)
            self.assertEqual(caught.exception.alert, 40)
            with self.assertRaises(ProtocolError) as caught:
                credential_cache.decompress_certificate(packed, (algorithm,), max_size=1)
            self.assertEqual(caught.exception.alert, 40)

    def test_unknown_cached_hash_must_still_have_valid_vector_length(self):
        for length in (1, 32, 255):
            data = bytes((255, length)) + bytes(length)
            self.assertEqual(handshake._cache_offer(len(data).to_bytes(2, "big") + data), ((255, bytes(length)),))
        for kind in (1, 2, 255):
            with self.subTest(kind=kind), self.assertRaises(ProtocolError) as caught:
                handshake._cache_offer(b"\x00\x02" + bytes((kind, 0)))
            self.assertEqual(caught.exception.alert, 50)


class CodecWireTests(unittest.IsolatedAsyncioTestCase):
    asyncSetUp = test_sessions.SessionTests.asyncSetUp
    asyncTearDown = test_sessions.SessionTests.asyncTearDown
    accept = test_sessions.SessionTests.accept
    handle = test_sessions.SessionTests.handle
    connect = test_sessions.SessionTests.connect

    @staticmethod
    def client_credential():
        key = X25519PrivateKey.generate()
        raw = key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        credential = Credentials([raw], key, credential_type=2)
        policy = CredentialPolicy(peer_name="device", raw_public_keys=(RawPublicKeyBinding("client", "device", raw),))
        return credential, policy

    async def test_both_credential_directions_emit_encrypted_bad_certificate(self):
        credential, policy = self.client_credential()
        original_read = handshake.Wire.read_record
        for role in ("server", "client"):
            for algorithm in (1, 2, 3):
                for variant in ("valid", *VARIANT_ALERTS):
                    with self.subTest(role=role, algorithm=algorithm, variant=variant):
                        self.cache = TicketCache()
                        self.server_options = {} if role == "server" else {
                            "client_credential_policy": policy, "require_client_auth": True,
                            "client_certificate_types": (2,), "certificate_compression": (algorithm,)}
                        options = {"certificate_compression": (algorithm,)} if role == "server" else {
                            "client_credentials": credential}
                        seen, received = [], asyncio.Event()

                        async def capture(wire, state=None):
                            data, kind = await original_read(wire, state)
                            if kind == 21 and data != b"\x01\x00":
                                seen.append((state is not None, data))
                                received.set()
                            return data, kind

                        def compress(body, selected):
                            self.assertEqual(selected, algorithm)
                            return altered_compression(body, selected, variant)

                        with patch.object(handshake, "compress_certificate", compress), \
                             patch.object(handshake.Wire, "read_record", capture), \
                             coalesce_codec_flights(self) as flights:
                            if variant == "valid":
                                client = await self.connect(**options)
                                await client.send(b"codec control")
                                self.assertEqual(await client.recv(), b"codec control")
                                self.assertEqual(client.handshake_transcript, self.channels[-1].handshake_transcript)
                                self.assertEqual(seen, [])
                                await client.close()
                            else:
                                with self.assertRaises(ProtocolError) as caught:
                                    await self.connect(**options)
                                self.assertEqual(caught.exception.alert, VARIANT_ALERTS[variant])
                                await asyncio.wait_for(received.wait(), 2)
                                self.assertEqual(seen, [(True, bytes((2, VARIANT_ALERTS[variant])))])
                            self.assertEqual(len(flights), 1)

    async def test_post_handshake_client_codec_errors_use_bad_certificate(self):
        credential, policy = self.client_credential()
        for algorithm in (1, 2, 3):
            for variant in ("valid", *VARIANT_ALERTS):
                with self.subTest(algorithm=algorithm, variant=variant):
                    self.cache = TicketCache()
                    self.server_options = {"client_credential_policy": policy, "require_client_auth": True,
                        "client_certificate_types": (2,), "certificate_compression": (algorithm,)}
                    client = await self.connect(client_credentials=credential, post_handshake_auth=True)
                    pending = await self.channels[-1].request_client_auth(required=True)
                    def compress(body, selected):
                        self.assertEqual(selected, algorithm)
                        return altered_compression(body, selected, variant)
                    with patch.object(handshake, "compress_certificate", compress), \
                         coalesce_codec_flights(self) as flights:
                        await client.send(b"drive codec PHA")
                        # Existing application data may be echoed before the
                        # server receives the subsequent PHA response. Read it
                        # without mistaking that ordering for PHA acceptance.
                        self.assertEqual(await asyncio.wait_for(client.recv(), 2), b"drive codec PHA")
                        if variant == "valid":
                            self.assertEqual(await asyncio.wait_for(pending, 2), tuple(credential.chain_der))
                            await client.close()
                        else:
                            with self.assertRaises(ProtocolError) as received:
                                await asyncio.wait_for(client.recv(), 2)
                            self.assertEqual(received.exception.alert, VARIANT_ALERTS[variant])
                            # A fatal record aborts the channel and cancels its
                            # outstanding PHA promise; the peer already proved
                            # the exact encrypted alert above.
                            with self.assertRaises(asyncio.CancelledError):
                                await asyncio.wait_for(pending, 2)
                            self.assertTrue(pending.cancelled())
                        self.assertEqual(len(flights), 1)

    async def test_codec_flight_is_complete_before_peer_can_abort(self):
        """A forced scheduling break cannot expose a partial malformed flight."""
        credential, policy = self.client_credential()
        self.server_options = {"client_credential_policy": policy, "require_client_auth": True,
            "client_certificate_types": (2,), "certificate_compression": (2,)}
        client = await self.connect(client_credentials=credential, post_handshake_auth=True)
        server = self.channels[-1]
        pending = await server.request_client_auth(required=True)
        reached_flush, release_flush, received_flight = (asyncio.Event() for _ in range(3))
        observed, fatal_alerts = [], []
        original_read, original_fatal = handshake.Wire.read_record, handshake.Wire.fatal

        async def before_send(wire, frames):
            self.assertIs(wire, client.wire)
            self.assertEqual([frame[0] for frame in frames], [25, 15, 20])
            reached_flush.set()
            await release_flush.wait()

        async def capture(wire, state=None):
            data, kind = await original_read(wire, state)
            if wire is server.wire and kind == 22:
                observed.append(data)
                received_flight.set()
            return data, kind

        async def fatal(wire, error, state=None):
            if wire is server.wire:
                self.assertTrue(received_flight.is_set())
                fatal_alerts.append(error.alert)
            return await original_fatal(wire, error, state)

        drive = None
        try:
            with patch.object(handshake, "compress_certificate", lambda body, algorithm:
                    altered_compression(body, algorithm, "unknown")), \
                 patch.object(handshake.Wire, "read_record", capture), \
                 patch.object(handshake.Wire, "fatal", fatal), \
                 coalesce_codec_flights(self, before_send=before_send) as flights:
                await client.send(b"drive codec PHA")
                drive = asyncio.create_task(client.recv())
                await asyncio.wait_for(reached_flush.wait(), 2)
                self.assertFalse(received_flight.is_set())
                self.assertEqual(fatal_alerts, [])
                self.assertFalse(pending.done())
                release_flush.set()
                self.assertEqual(await asyncio.wait_for(drive, 2), b"drive codec PHA")
                with self.assertRaises(ProtocolError) as received:
                    await asyncio.wait_for(client.recv(), 2)
                self.assertEqual(received.exception.alert, 47)
                with self.assertRaises(asyncio.CancelledError):
                    await asyncio.wait_for(pending, 2)
                self.assertTrue(pending.cancelled())
                self.assertEqual(fatal_alerts, [47])
                self.assertEqual(len(flights), 1)
                self.assertEqual(observed, flights)
        finally:
            release_flush.set()
            if drive is not None:
                drive.cancel()
                await asyncio.gather(drive, return_exceptions=True)

    async def test_unknown_cache_type_ignores_only_well_framed_hashes(self):
        original = messages.client_hello
        for value, valid in ((b"\x00\x03\xff\x01x", True), (b"\x00\x02\xff\x00", False)):
            with self.subTest(value=value):
                self.cache = TicketCache()
                def altered(*args, **kwargs):
                    kwargs["extra_extensions"] = tuple(kwargs.get("extra_extensions", ())) + ((25, value),)
                    return original(*args, **kwargs)
                with patch.object(messages, "client_hello", altered):
                    if valid:
                        client = await self.connect()
                        self.assertEqual(client.cache_types, ())
                        await client.send(b"unknown cache object")
                        self.assertEqual(await client.recv(), b"unknown cache object")
                        await client.close()
                    else:
                        with self.assertRaises(ProtocolError) as caught:
                            await self.connect()
                        self.assertEqual(caught.exception.alert, 50)
