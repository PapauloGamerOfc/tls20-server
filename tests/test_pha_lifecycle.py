"""Retained exceptions must not keep abandoned PHA ephemeral key locals."""

import asyncio
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from tls20_server.handshake import SecureChannel, Wire
from tests.test_robustness import MemoryWriter


def retained_protocol_keys(error):
    seen, pending, retained = set(), [error], []
    while pending:
        current = pending.pop()
        if id(current) in seen:
            continue
        seen.add(id(current))
        pending.extend(value for value in (current.__cause__, current.__context__) if value is not None)
        pending.extend(getattr(current, "exceptions", ()))
        trace = current.__traceback__
        while trace is not None:
            frame = trace.tb_frame
            if frame.f_globals.get("__name__", "").startswith("tls20_server."):
                retained.extend((frame.f_code.co_name, name) for name, value in frame.f_locals.items()
                                if isinstance(value, X25519PrivateKey))
            trace = trace.tb_next
    return retained


class PhaLifecycleTests(unittest.IsolatedAsyncioTestCase):
    def channel(self, writer=None):
        return SecureChannel(Wire(asyncio.StreamReader(), writer or MemoryWriter()), bytes(32), bytes(32),
            role="server", exporter_secret=bytes(32), handshake_transcript=b"finished transcript",
            peer_post_handshake_auth=True, client_auth_validator=lambda chain: None)

    async def test_write_exception_and_cancellation_release_completed_frame_keys(self):
        for error_type in (OSError, asyncio.CancelledError):
            with self.subTest(error=error_type.__name__):
                class FailingWriter(MemoryWriter):
                    async def drain(self):
                        raise error_type("controlled write interruption")
                channel = self.channel(FailingWriter())
                caught = None
                try:
                    await channel.request_client_auth()
                except BaseException as error:
                    caught = error
                self.assertIsInstance(caught, error_type)
                self.assertTrue(channel.closed)
                self.assertEqual(channel.pending_client_auth, {})
                self.assertEqual(retained_protocol_keys(caught), [])

    async def test_pre_send_error_preserves_other_request_but_releases_failed_frame(self):
        channel = self.channel()
        try:
            pending = await channel.request_client_auth()
            state = next(iter(channel.pending_client_auth.values()))
            original_key = state["private"]
            before = bytes(channel.wire.writer.data)
            caught = None
            try:
                await channel.request_client_auth(certificate_algorithms=())
            except BaseException as error:
                caught = error
            self.assertIsInstance(caught, ValueError)
            self.assertFalse(channel.closed)
            self.assertIs(state["private"], original_key)
            self.assertFalse(pending.done())
            self.assertEqual(len(channel.pending_client_auth), 1)
            self.assertEqual(bytes(channel.wire.writer.data), before)
            self.assertEqual(retained_protocol_keys(caught), [])
        finally:
            channel.abort()

    async def test_pre_send_cancellation_releases_failed_protocol_frame(self):
        channel = self.channel()
        # Patch only the encoder to fail after ephemeral generation. The
        # operation's completed frame, not application callback locals, is owned.
        for error_type in (OSError, asyncio.CancelledError):
            with self.subTest(error=error_type.__name__):
                caught = None
                with patch("tls20_server.handshake.m.certificate_request", side_effect=error_type("encoder failure")):
                    try:
                        await channel.request_client_auth()
                    except BaseException as error:
                        caught = error
                self.assertIsInstance(caught, error_type)
                self.assertFalse(channel.closed)
                self.assertFalse(channel.pending_client_auth)
                self.assertFalse(channel.wire.writer.data)
                self.assertEqual(retained_protocol_keys(caught), [])
        channel.abort()

    async def test_chained_encoder_failure_preserves_application_callback_frame(self):
        channel = self.channel()
        marker = object()
        def fail_encoding(*args, **kwargs):
            application_owned = marker
            try:
                raise OSError("encoder cause")
            except OSError as cause:
                raise ValueError("encoder wrapper") from cause
        caught = None
        try:
            with patch("tls20_server.handshake.m.certificate_request", side_effect=fail_encoding):
                try:
                    await channel.request_client_auth()
                except BaseException as error:
                    caught = error
            self.assertIsInstance(caught, ValueError)
            self.assertIsInstance(caught.__cause__, OSError)
            self.assertEqual(retained_protocol_keys(caught), [])
            trace = caught.__cause__.__traceback__
            while trace and trace.tb_frame.f_code.co_name != "fail_encoding":
                trace = trace.tb_next
            self.assertIsNotNone(trace)
            self.assertIs(trace.tb_frame.f_locals["application_owned"], marker)
            self.assertFalse(channel.closed)
            self.assertFalse(channel.pending_client_auth)
        finally:
            channel.abort()


if __name__ == "__main__":
    unittest.main()
