import asyncio
import unittest
from unittest.mock import patch

from tls20_server.errors import ProtocolError
from tls20_server.handshake import Wire
from tests import test_sessions


class ExporterAccessTests(unittest.IsolatedAsyncioTestCase):
    asyncSetUp = test_sessions.SessionTests.asyncSetUp
    asyncTearDown = test_sessions.SessionTests.asyncTearDown
    accept = test_sessions.SessionTests.accept
    handle = test_sessions.SessionTests.handle
    connect = test_sessions.SessionTests.connect

    async def test_both_exporters_available_before_client_finished(self):
        await self.connect()
        accesses = {"client": [], "server": []}
        self.server_options = {
            "on_exporter": accesses["server"].append,
            "on_early_exporter": accesses["server"].append,
        }
        original = Wire.send_frame
        reached = []
        async def send(wire, message, state=None):
            if message[0] == 20 and len(accesses["client"]) == 2:
                # Only the client has both handles once ServerFinished has
                # arrived. ServerFinished itself precedes that point.
                self.assertEqual(len(accesses["server"]), 2)
                for values in accesses.values():
                    self.assertTrue(all(not value.handshake_completed for value in values))
                by_stage = lambda role: {value.stage: value for value in accesses[role]}
                for stage in ("early", "server-finished"):
                    self.assertEqual(by_stage("client")[stage].export("application", b"scope"),
                                     by_stage("server")[stage].export("application", b"scope"))
                self.assertFalse(any(value.peer_authenticated for value in accesses["server"]))
                reached.append(True)
            return await original(wire, message, state)
        with patch.object(Wire, "send_frame", send):
            channel = await self.connect(on_exporter=accesses["client"].append,
                on_early_exporter=accesses["client"].append, early_data=b"early")
        self.assertEqual(reached, [True])
        self.assertTrue(all(value.handshake_completed for values in accesses.values() for value in values))
        await channel.close()
        for value in accesses["client"]:
            self.assertFalse(value.active)
            with self.assertRaises(ProtocolError):
                value.export("after close")

    async def test_callback_failure_revokes_handle_and_closes_transport(self):
        handles = []
        def fail(value):
            handles.append(value)
            raise ValueError("application refused exporter use")
        with self.assertRaisesRegex(ValueError, "application refused"):
            await self.connect(on_exporter=fail)
        self.assertEqual(len(handles), 1)
        self.assertFalse(handles[0].active)
        self.assertEqual(len(self.client_writers), 1)
        self.assertTrue(next(iter(self.client_writers)).is_closing())

    async def test_callback_failure_with_server_writer_registered_last(self):
        self.defer_server_writer_registration = True
        await self.test_callback_failure_revokes_handle_and_closes_transport()
        self.assertNotIn(self.writers[-1], self.client_writers)

    async def test_retry_revokes_initial_early_exporter(self):
        await self.connect()
        handles = []
        channel = await self.connect(force_retry=True, on_early_exporter=handles.append)
        self.assertTrue(channel.resumed)
        self.assertEqual(len(handles), 1)
        self.assertFalse(handles[0].active)
