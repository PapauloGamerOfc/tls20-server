"""Exporter input/provider errors release only completed protocol frames."""

import asyncio
import unittest
from unittest.mock import patch

from tests import test_sessions
from tls20_server import crypto as c
from tls20_server.errors import ProtocolError


def exception_frames(error):
    pending, seen = [error], set()
    while pending:
        current = pending.pop()
        if id(current) in seen:
            continue
        seen.add(id(current))
        pending.extend(value for value in (current.__cause__, current.__context__) if value is not None)
        pending.extend(getattr(current, "exceptions", ()))
        trace = current.__traceback__
        while trace is not None:
            yield trace.tb_frame
            trace = trace.tb_next


class ExporterSecretLifecycleTests(unittest.IsolatedAsyncioTestCase):
    asyncSetUp = test_sessions.SessionTests.asyncSetUp
    asyncTearDown = test_sessions.SessionTests.asyncTearDown
    accept = test_sessions.SessionTests.accept
    handle = test_sessions.SessionTests.handle
    connect = test_sessions.SessionTests.connect

    async def exporter_channel(self, suite):
        self.server_options = {"cipher_suites": (suite,)}
        warmup = await self.connect(cipher_suites=(suite,))
        await warmup.close()
        handles = []
        channel = await self.connect(cipher_suites=(suite,), on_exporter=handles.append,
                                     on_early_exporter=handles.append)
        self.assertTrue(channel.resumed)
        by_stage = {access.stage: access for access in handles}
        self.assertEqual(set(by_stage), {"early", "server-finished"})
        calls = (channel.exporter, channel.early_exporter,
                 by_stage["server-finished"].export, by_stage["early"].export)
        return channel, handles, calls

    def assert_protocol_frames_released(self, error):
        inspected = False
        for frame in exception_frames(error):
            if (frame.f_globals.get("__name__", "").startswith("tls20_server.")
                    and frame.f_code.co_name != "guarded"):
                inspected = True
                self.assertFalse(frame.f_locals, frame.f_code.co_name)
        self.assertTrue(inspected)

    async def test_argument_errors_do_not_retain_normal_or_early_exporter_roots(self):
        for suite in (0x1301, 0x1302):
            channel, handles, calls = await self.exporter_channel(suite)
            saved = []
            try:
                for index, call in enumerate(calls):
                    expected = call("valid", b"scope", 32)
                    for label, context, length in (("probe", b"", -1),
                            ("probe", b"", 255 * c.suite(suite).hash_length + 1),
                            ("x" * 250, b"", 32), ("non-ascii-\u00e9", b"", 32),
                            ("probe", None, 32)):
                        with self.subTest(suite=hex(suite), api=index, label=label, length=length):
                            caught = None
                            try:
                                call(label, context, length)
                            except (ProtocolError, TypeError, ValueError) as error:
                                caught = error
                            self.assertIsNotNone(caught)
                            saved.append(caught)
                            self.assert_protocol_frames_released(caught)
                            self.assertEqual(call("valid", b"scope", 32), expected)
                            self.assertFalse(channel.closed)
                await channel.send(b"exporter argument errors leave the channel usable")
                self.assertEqual(await channel.recv(), b"exporter argument errors leave the channel usable")
            finally:
                await channel.close()
            self.assertIsNone(channel.exporter_secret)
            self.assertIsNone(channel.early_exporter_secret)
            self.assertTrue(all(not access.active for access in handles))
            for error in saved:
                self.assert_protocol_frames_released(error)

    async def test_provider_errors_and_cancellation_preserve_application_frames(self):
        for suite in (0x1301, 0x1302):
            channel, handles, calls = await self.exporter_channel(suite)
            retained = []
            original_digest = c.digest
            marker = object()

            def provider_digest(data, hash_name="sha256"):
                application_owned = marker
                if data == b"fail after deriving the intermediate":
                    try:
                        raise ValueError("provider detail")
                    except ValueError as cause:
                        if cancellation:
                            raise asyncio.CancelledError("provider cancelled") from cause
                        raise ExceptionGroup("provider failed", [cause, RuntimeError("second detail")]) from cause
                self.assertIs(application_owned, marker)
                return original_digest(data, hash_name)

            try:
                for index, call in enumerate(calls):
                    expected = call("valid", b"scope")
                    for cancellation in (False, True):
                        with self.subTest(suite=hex(suite), api=index, cancellation=cancellation):
                            caught = None
                            with patch.object(c, "digest", provider_digest):
                                try:
                                    call("probe", b"fail after deriving the intermediate")
                                except (ExceptionGroup, asyncio.CancelledError) as error:
                                    caught = error
                            self.assertIsNotNone(caught)
                            retained.append(caught)
                            self.assert_protocol_frames_released(caught)
                            callbacks = [frame for frame in exception_frames(caught)
                                         if frame.f_code.co_name == "provider_digest"]
                            self.assertTrue(callbacks)
                            for frame in callbacks:
                                self.assertIs(frame.f_locals["application_owned"], marker)
                            self.assertEqual(call("valid", b"scope"), expected)
                            self.assertFalse(channel.closed)
                await channel.send(b"exporter provider failures leave unrelated traffic usable")
                self.assertEqual(await channel.recv(), b"exporter provider failures leave unrelated traffic usable")
            finally:
                await channel.close()
            self.assertTrue(all(not access.active for access in handles))
            for error in retained:
                self.assert_protocol_frames_released(error)
