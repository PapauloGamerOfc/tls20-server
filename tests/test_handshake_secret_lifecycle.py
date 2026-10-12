"""Synthetic loopback ownership tests, including retained failure tracebacks."""

import asyncio
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch, Mock

from tls20_server import handshake as hs, pake_handshake as pwd
from tls20_server.errors import ProtocolError
from tls20_server.lab import create_lab
from tls20_server.pki import load_credentials, load_trust_roots
from tls20_server.secret_lifecycle import HandshakeSecrets, clear_protocol_tracebacks


class SecretScopeTests(unittest.TestCase):
    def test_retiring_record_removes_owner_but_failed_close_remains_owned(self):
        scope = HandshakeSecrets()
        first, second = Mock(), Mock()
        second.close.side_effect = [RuntimeError("retirement failed"), None]
        scope.records = [first, second]
        scope.close_record(first)
        self.assertEqual(scope.records, [second])
        with self.assertRaisesRegex(RuntimeError, "retirement failed"):
            scope.close_record(second)
        self.assertEqual(scope.records, [second])
        scope.close()
        first.close.assert_called_once_with()
        self.assertEqual(second.close.call_count, 2)
        self.assertEqual(scope.records, [])

    def test_owned_native_keys_close_once_and_borrowed_provider_survives(self):
        scope = HandshakeSecrets()
        provider, first, second = Mock(), Mock(), Mock()
        with patch("tls20_server.crypto.traffic_key", side_effect=[(first, b"a"), (second, b"b")]):
            scope.traffic_key(41, provider)
            scope.close_key(first)
            scope.traffic_key(34, provider)
        scope.close()
        scope.close()
        first.close.assert_called_once_with()
        second.close.assert_called_once_with()
        provider.close.assert_not_called()

    def test_channel_handoff_and_unreturned_channel_abort(self):
        scope, channel = HandshakeSecrets(), Mock()
        scope.establish(channel)
        self.assertIs(scope.release(channel), channel)
        scope.close()
        channel.abort.assert_not_called()
        scope.establish(channel)
        scope.close()
        channel.abort.assert_called_once_with()

    def test_traceback_cause_cleanup_keeps_application_frames(self):
        # Functions with real package globals model protocol-owned helper
        # frames; the application frame and formatted traceback remain intact.
        namespace = {"__name__": "tls20_server.lifecycle_fixture"}
        exec("def fail():\n secret = b'fixture'\n try:\n  raise ValueError('inner')\n except ValueError as cause:\n  raise RuntimeError('outer') from cause", namespace)
        try:
            namespace["fail"]()
        except RuntimeError as error:
            clear_protocol_tracebacks(error)
            self.assertEqual(str(error), "outer")
            for failure in (error, error.__cause__):
                trace = failure.__traceback__
                found = False
                while trace:
                    if trace.tb_frame.f_globals.get("__name__") == namespace["__name__"]:
                        self.assertFalse(trace.tb_frame.f_locals)
                        found = True
                    trace = trace.tb_next
                self.assertTrue(found)
            self.assertIsNotNone(namespace["fail"])


class HandshakeSecretTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="tls20-secrets-")
        root = Path(self.temp.name) / "lab"
        create_lab(root, "localhost")
        self.credentials = load_credentials(root / "fullchain.pem", root / "server.key", "localhost")
        self.roots = load_trust_roots(root / "ca.pem")
        self.writers, self.tasks, self.channels = [], [], []
        self.listeners, self.scopes, self.records = [], [], []
        self.native = None

    async def asyncTearDown(self):
        for channel in self.channels:
            channel.abort()
        for writer in self.writers:
            writer.close()
        for task in self.tasks:
            if not task.done():
                task.cancel()
        await asyncio.gather(*self.tasks, return_exceptions=True)
        for writer in self.writers:
            try:
                await writer.wait_closed()
            except (OSError, asyncio.CancelledError):
                pass
        for listener in self.listeners:
            listener.close()
            await listener.wait_closed()
        if self.native:
            self.native.close()
        self.temp.cleanup()

    async def exchange(self, *, fail_role=None, failure="proof", password=False, retry=False):
        original_init, original_record = HandshakeSecrets.__init__, HandshakeSecrets.record
        original_receive, original_fatal = hs.Wire.receive_frame, hs.Wire.fatal
        reached = asyncio.Event()
        role_by_writer = {}
        role_by_task, fatal_states, first_senders = {}, [], {}
        errors = {}
        if password:
            from tls20_server.openssl_provider import OpenSSLProvider
            from tls20_server.pake_native import PakeProvider
            from tls20_server.pake import PasswordAccount, PasswordServer, PasswordCredential
            self.native = OpenSSLProvider(os.environ["TLS20_TEST_OPENSSL"])
            provider = PakeProvider(self.native, os.environ["TLS20_TEST_PAKE"])
            policy = PasswordServer("localhost", provider, [PasswordAccount.provision("user", "test pass")])
            credential = PasswordCredential("localhost", "user", "test pass", provider)
        timeout = .15 if failure == "timeout" else 3

        def scope_init(scope):
            original_init(scope)
            self.scopes.append(scope)

        def record(scope, *args, **kwargs):
            state = original_record(scope, *args, **kwargs)
            self.records.append(state)
            role = role_by_task.get(asyncio.current_task())
            if state.operation == "seal" and role not in first_senders:
                first_senders[role] = state
                if role == fail_role and failure == "retire":
                    original_close = state.close
                    raised = False
                    def close():
                        nonlocal raised
                        if not raised:
                            raised = True
                            raise ProtocolError("injected retirement failure", alert=80)
                        original_close()
                    state.close = close
            return state

        async def fatal(wire, error, state=None):
            if role_by_writer.get(wire.writer) == fail_role:
                fatal_states.append((state, state.failed if state else None))
            return await original_fatal(wire, error, state)

        async def receive(wire, expected, *args, **kwargs):
            role = role_by_writer.get(wire.writer)
            target = 20 if password or fail_role == "server" or failure != "proof" else 15
            if role == fail_role and expected == target and failure in ("cancel", "timeout"):
                reached.set()
                await asyncio.Event().wait()
            message = await original_receive(wire, expected, *args, **kwargs)
            if role == fail_role and expected == target and failure == "proof":
                message = message[:-1] + bytes((message[-1] ^ 1,))
            return message

        async def run(role, reader, writer):
            role_by_writer[writer] = role
            role_by_task[asyncio.current_task()] = role
            self.writers.append(writer)
            async def on_exporter(access):
                if role == fail_role and failure == "callback":
                    raise ProtocolError("injected exporter failure", alert=80)
            try:
                if password:
                    channel = (await pwd.server(reader, writer, policy, timeout=timeout, on_exporter=on_exporter) if role == "server" else
                               await pwd.client(reader, writer, credential, timeout=timeout, on_exporter=on_exporter))
                elif role == "server":
                    channel = await hs.server_handshake(reader, writer, self.credentials, "localhost", timeout=timeout,
                                                        enable_authenticators=True, on_exporter=on_exporter)
                else:
                    channel = await hs.client_handshake(reader, writer, "localhost", self.roots,
                        revocation_policy="lab-offline", timeout=timeout, force_retry=retry,
                        enable_authenticators=True, on_exporter=on_exporter)
                self.channels.append(channel)
                return channel
            except BaseException as error:
                errors[role] = error  # Deliberately retain the original traceback.
                return None

        server_task = asyncio.get_running_loop().create_future()
        def accept(reader, writer):
            task = asyncio.create_task(run("server", reader, writer))
            self.tasks.append(task)
            server_task.set_result(task)

        with patch.object(HandshakeSecrets, "__init__", scope_init), patch.object(HandshakeSecrets, "record", record), \
                patch.object(hs.Wire, "receive_frame", receive), patch.object(hs.Wire, "fatal", fatal):
            listener = await asyncio.start_server(accept, "127.0.0.1", 0)
            self.listeners.append(listener)
            reader, writer = await asyncio.open_connection("127.0.0.1", listener.sockets[0].getsockname()[1])
            client_task = asyncio.create_task(run("client", reader, writer))
            self.tasks.append(client_task)
            peer_task = await server_task
            if failure == "cancel" and fail_role:
                await asyncio.wait_for(reached.wait(), 2)
                (client_task if fail_role == "client" else peer_task).cancel()
            await asyncio.wait_for(asyncio.gather(client_task, peer_task), 5)

        self.assertTrue(self.records)
        for state in self.records:
            self.assertTrue(state.failed)
            self.assertEqual((state.secret, state.key, state.iv), (b"", b"", b""))
            self.assertIsNone(state._cipher)
        for scope in self.scopes:
            self.assertEqual((scope.records, scope.keys, scope.channel), ([], [], None))
        if fail_role:
            error = errors[fail_role]
            expected = {"proof": ProtocolError, "cancel": asyncio.CancelledError, "timeout": TimeoutError,
                        "callback": ProtocolError, "retire": ProtocolError}[failure]
            self.assertIsInstance(error, expected)
            if failure == "proof":
                # PWD server deliberately conceals account/proof distinctions.
                self.assertEqual(error.alert, 20 if password and fail_role == "server" else 51, str(error))
            if failure in ("retire", "callback"):
                self.assertEqual(error.alert, 80)
                self.assertEqual(len(fatal_states), 1)
                self.assertFalse(fatal_states[0][1])
                if fail_role == "server":
                    self.assertIsNot(fatal_states[0][0], first_senders["server"])
                else:
                    self.assertIs(fatal_states[0][0], first_senders["client"])
            found = False
            for failure_error in (error, error.__cause__, error.__context__):
                trace = failure_error.__traceback__ if failure_error else None
                while trace:
                    frame = trace.tb_frame
                    if frame.f_globals.get("__name__") in (hs.__name__, pwd.__name__):
                        self.assertFalse(frame.f_locals)
                        found = True
                    trace = trace.tb_next
            self.assertTrue(found)
        else:
            self.assertFalse(errors)
            self.assertEqual(len(self.channels), 2)
            a, b = self.channels
            self.assertEqual(a.exporter("scope-test"), b.exporter("scope-test"))
            await a.send(b"still usable")
            self.assertEqual(await b.recv(), b"still usable")
            for channel in (a, b):
                self.assertFalse(channel.sender.failed)
                self.assertFalse(channel.receiver.failed)
            if not password:
                client = next(channel for channel in (a, b) if channel.role == "client")
                self.assertIsNotNone(client.auth_share_secret)
        # Shared provisioning remains usable: it was never owned by the scope.
        self.assertTrue(self.credentials.private_key.public_key())
        if password:
            self.assertEqual(policy._active, 0)

    async def test_success_and_retry_release_only_temporary_epochs(self):
        await self.exchange(retry=True)

    async def test_server_retirement_failure_uses_live_application_alert_epoch(self):
        await self.exchange(fail_role="server", failure="retire")

    async def test_server_exporter_failure_uses_live_application_alert_epoch(self):
        await self.exchange(fail_role="server", failure="callback")

    async def test_client_exporter_failure_keeps_pending_handshake_alert_epoch(self):
        await self.exchange(fail_role="client", failure="callback")

    @unittest.skipUnless(os.environ.get("TLS20_TEST_PAKE") and os.environ.get("TLS20_TEST_OPENSSL"), "native PAKE fixture required")
    async def test_password_server_retirement_failure_uses_application_epoch(self):
        await self.exchange(password=True, fail_role="server", failure="retire")

    async def test_client_mac_failure_releases_states_and_traceback_locals(self):
        await self.exchange(fail_role="client")

    async def test_server_finished_failure_releases_states_and_traceback_locals(self):
        await self.exchange(fail_role="server")

    async def test_client_cancellation_releases_states(self):
        await self.exchange(fail_role="client", failure="cancel")

    async def test_server_cancellation_releases_states(self):
        await self.exchange(fail_role="server", failure="cancel")

    async def test_client_timeout_releases_states_and_chained_frames(self):
        await self.exchange(fail_role="client", failure="timeout")

    async def test_server_timeout_releases_states_and_chained_frames(self):
        await self.exchange(fail_role="server", failure="timeout")

    @unittest.skipUnless(os.environ.get("TLS20_TEST_PAKE") and os.environ.get("TLS20_TEST_OPENSSL"), "native PAKE fixture required")
    async def test_password_client_failure_cleanup(self):
        await self.exchange(password=True, fail_role="client")

    @unittest.skipUnless(os.environ.get("TLS20_TEST_PAKE") and os.environ.get("TLS20_TEST_OPENSSL"), "native PAKE fixture required")
    async def test_password_server_failure_cleanup(self):
        await self.exchange(password=True, fail_role="server")

    @unittest.skipUnless(os.environ.get("TLS20_TEST_PAKE") and os.environ.get("TLS20_TEST_OPENSSL"), "native PAKE fixture required")
    async def test_password_cancel_cleanup(self):
        await self.exchange(password=True, fail_role="client", failure="cancel")

    @unittest.skipUnless(os.environ.get("TLS20_TEST_PAKE") and os.environ.get("TLS20_TEST_OPENSSL"), "native PAKE fixture required")
    async def test_password_success_handoff(self):
        await self.exchange(password=True)
