"""Early-exporter lineage, HRR API revocation and positive non-HRR controls."""

import asyncio
from contextlib import ExitStack
import os
import unittest
from unittest.mock import patch

from tests import test_pake_handshake, test_sessions
from tls20_server import crypto as c, handshake, messages as m, pake_handshake
from tls20_server.errors import ProtocolError
from tls20_server.handshake import Wire, Transcript, handshake_keys, application_keys
from tls20_server.psk import ExternalPSK, import_psk
from tls20_server.retry_cookie import RetryCookiePolicy
from tls20_server.tickets import TicketCache


class ExporterProbe:
    """Observe public capabilities and diagnostic labels without logging keys."""

    def __init__(self, test, module, *, available):
        self.test, self.module, self.available = test, module, available
        self.handles = {"client": [], "server": []}
        self.labels = {"client": [], "server": []}
        self.hellos, self.client_writer, self.client_finished = [], None, 0

    def callback(self, role):
        def receive(access):
            self.test.assertTrue(access.active)
            self.test.assertFalse(access.handshake_completed)
            self.handles[role].append(access)
        return receive

    def __enter__(self):
        original = Wire.send_frame

        async def send(wire, message, state=None):
            if message[0] == 1:
                self.client_writer = wire.writer
                self.hellos.append(message)
                if len(self.hellos) == 2:
                    # Revoke as soon as HRR is processed, before awaiting CH2
                    # transmission or the final ServerHello, not just at return.
                    self.test.assertEqual(len(self.handles["client"]), 1)
                    self.assert_closed(self.handles["client"])
            if message[0] == 20 and wire.writer is self.client_writer:
                self.client_finished += 1
                self.test.assertEqual(len(self.handles["server"]), int(self.available))
                if self.available:
                    client, server = self.handles["client"][0], self.handles["server"][0]
                    self.test.assertFalse(server.handshake_completed)
                    self.test.assertFalse(server.peer_authenticated)
                    self.test.assertEqual(client.export("before Finished", b"scope"),
                                          server.export("before Finished", b"scope"))
            return await original(wire, message, state)

        def diagnostic(sink, label, _random, _secret):
            self.labels[sink].append(label)

        self.stack = ExitStack()
        self.stack.enter_context(patch.object(Wire, "send_frame", send))
        self.stack.enter_context(patch.object(self.module, "emit_diagnostic", diagnostic))
        return self

    def __exit__(self, *args):
        return self.stack.__exit__(*args)

    def assert_closed(self, handles):
        for access in handles:
            self.test.assertFalse(access.active)
            self.test.assertIsNone(access._secret)
            with self.test.assertRaises(ProtocolError):
                access.export("revoked")

    async def finish(self, client, server):
        self.test.assertEqual(self.client_finished, 1)
        self.test.assertEqual(len(self.handles["client"]), 1)
        self.test.assertEqual(self.labels["client"].count("TLS20_EARLY_EXPORTER_SECRET"), 1)
        self.test.assertEqual(self.labels["server"].count("TLS20_EARLY_EXPORTER_SECRET"),
                              int(self.available))
        for channel in (client, server):
            self.test.assertEqual(channel.early_exporter_secret is not None, self.available)
            if not self.available:
                with self.test.assertRaisesRegex(ProtocolError, "early exporter unavailable"):
                    channel.early_exporter("after retry")
        if self.available:
            self.test.assertEqual(client.early_exporter("completed"), server.early_exporter("completed"))
        else:
            self.assert_closed(self.handles["client"])
        await client.send(b"independent 1-RTT application")
        self.test.assertEqual(await client.recv(), b"independent 1-RTT application")
        await client.close()
        # close() flushes the client's close_notify, but the server handler may
        # still be decrypting it. Join our handlers before destroying their keys;
        # selector and proactor loops need not schedule the two endpoints alike.
        await asyncio.wait_for(asyncio.gather(*tuple(self.test.tasks)), 2)
        self.test.assertFalse(self.test.errors)
        server.abort()
        for handles in self.handles.values():
            self.assert_closed(handles)


class OrdinaryEarlyExporterTests(unittest.IsolatedAsyncioTestCase):
    asyncSetUp = test_sessions.SessionTests.asyncSetUp
    asyncTearDown = test_sessions.SessionTests.asyncTearDown
    accept = test_sessions.SessionTests.accept
    handle = test_sessions.SessionTests.handle
    connect = test_sessions.SessionTests.connect

    async def test_probe_waits_for_handler_completion_before_aborting(self):
        handler_at_exit, release_handler, aborted = (asyncio.Event() for _ in range(3))
        original_handle = self.handle

        async def delayed_handler(reader, writer):
            await original_handle(reader, writer)
            handler_at_exit.set()
            await release_handler.wait()

        self.handle = delayed_handler
        key = ExternalPSK(b"fixture PSK", b"fixture secret", "localhost")
        probe = ExporterProbe(self, handshake, available=True)
        self.server_options = {"external_psks": (key,),
            "on_early_exporter": probe.callback("server"), "diagnostics": "server"}
        with probe:
            client = await self.connect(external_psks=(key,),
                on_early_exporter=probe.callback("client"), diagnostics="client")
        server = self.channels[-1]
        original_abort = type(server).abort

        def observe_abort(channel):
            if channel is server:
                aborted.set()
            return original_abort(channel)

        with patch.object(type(server), "abort", observe_abort):
            completion = asyncio.create_task(probe.finish(client, server))
            try:
                await asyncio.wait_for(handler_at_exit.wait(), 2)
                # A deliberately delayed handler makes the teardown ordering
                # deterministic even on loops where close_notify usually wins.
                self.assertFalse(completion.done())
                self.assertFalse(aborted.is_set())
            finally:
                release_handler.set()
                await asyncio.wait_for(completion, 2)
        self.assertTrue(aborted.is_set())
        self.assertFalse(self.errors)

    async def test_first_vs_later_identity_with_and_without_retry_or_early_payload(self):
        first = ExternalPSK(b"first sha256", b"public fixture one", "localhost", max_early_data=1024)
        second = import_psk(b"public fixture two", b"second sha384", b"scope", "localhost",
                            target_hash="sha384")
        keys = (first, second)
        for retry in (False, True):
            for index in (0, 1):
                for payload in (b"", b"early request"):
                    with self.subTest(retry=retry, selected=index, payload=bool(payload)):
                        self.cache = TicketCache()
                        available = not retry and index == 0
                        probe = ExporterProbe(self, handshake, available=available)
                        self.server_options = {
                            "external_psks": (keys[index],), "cipher_suites": (keys[index].cipher_suite,),
                            "on_early_exporter": probe.callback("server"), "diagnostics": "server",
                        }
                        with probe:
                            client = await self.connect(external_psks=keys, cipher_suites=(0x1301, 0x1302),
                                force_retry=retry, early_data=payload,
                                on_early_exporter=probe.callback("client"), diagnostics="client")
                        parsed = [m.parse_client_hello(frame[4:]) for frame in probe.hellos]
                        self.assertEqual(len(parsed), 2 if retry else 1)
                        self.assertEqual(len(parsed[0].psk_offers), 2)
                        if retry:
                            self.assertEqual([offer[0] for offer in parsed[1].psk_offers], [keys[index].identity])
                        self.assertEqual(client.selected_external_psk_identity, keys[index].identity)
                        # No external early-data replay authorization was configured.
                        # Rejected or absent payload must NOT disable PSK0's exporter.
                        self.assertFalse(client.early_data_accepted)
                        await probe.finish(client, self.channels[-1])
        self.assertFalse(self.early)
        self.assertFalse(self.errors)

    async def test_cookie_retry_revokes_same_session_psk_without_waiting_for_finished(self):
        await (await self.connect()).close()
        probe = ExporterProbe(self, handshake, available=False)
        self.server_options = {"retry_cookie_policy": RetryCookiePolicy(),
            "on_early_exporter": probe.callback("server"), "diagnostics": "server"}
        with probe:
            client = await self.connect(on_early_exporter=probe.callback("client"), diagnostics="client")
        self.assertTrue(client.resumed)
        identities = [m.parse_client_hello(frame[4:]).psk_offers[0][0] for frame in probe.hellos]
        self.assertEqual(len(identities), 2)
        self.assertEqual(identities[0], identities[1])
        await probe.finish(client, self.channels[-1])


@unittest.skipUnless(os.environ.get("TLS20_TEST_PAKE") and os.environ.get("TLS20_TEST_OPENSSL"),
                     "explicit native PAKE fixture required")
class PasswordEarlyExporterTests(unittest.IsolatedAsyncioTestCase):
    asyncSetUp = test_pake_handshake.PakeHandshakeTests.asyncSetUp
    accept = test_pake_handshake.PakeHandshakeTests.accept
    handle = test_pake_handshake.PakeHandshakeTests.handle
    connect = test_pake_handshake.PakeHandshakeTests.connect

    async def asyncTearDown(self):
        for channel in self.channels:
            channel.abort()
        await test_pake_handshake.PakeHandshakeTests.asyncTearDown(self)

    async def test_same_psk_exporter_retry_policy_and_rejected_or_absent_payload(self):
        for suite in (0xc0b0, 0xc0b1):
            for retry in ("none", "group", "cookie"):
                for payload in (b"", b"replayed early request"):
                    with self.subTest(suite=hex(suite), retry=retry, payload=bool(payload)):
                        self.cache = TicketCache()
                        self.options = {"cipher_suites": (suite,)}
                        seed = await self.connect(cipher_suites=(suite,))
                        await seed.close()
                        cached = next(iter(self.cache._tickets.values()))
                        self.store._tickets[cached.identity].early_used = True
                        probe = ExporterProbe(self, pake_handshake, available=retry == "none")
                        self.options.update(on_early_exporter=probe.callback("server"), diagnostics="server")
                        if retry == "cookie":
                            self.options["retry_cookie_policy"] = RetryCookiePolicy()
                        original, built = m.client_hello, []

                        def make_hello(*args, **kwargs):
                            if retry == "group" and not built:
                                kwargs["empty_share"] = True
                            message = original(*args, **kwargs)
                            built.append(message)
                            return message

                        with probe, patch.object(m, "client_hello", make_hello):
                            client = await self.connect(cipher_suites=(suite,), early_data=payload,
                                on_early_exporter=probe.callback("client"), diagnostics="client")
                        self.assertTrue(client.resumed)
                        self.assertFalse(client.early_data_accepted)
                        self.assertEqual(len(probe.hellos), 1 if retry == "none" else 2)
                        self.assertTrue(all(m.parse_client_hello(frame[4:]).psk_offers[0][0] == cached.identity
                                            for frame in probe.hellos))
                        await probe.finish(client, self.channels[-1])
        self.assertFalse(self.early)
        self.assertFalse(self.errors)

    async def test_hrr_removal_of_first_psk_does_not_promote_successor_to_early_exporter(self):
        callbacks, diagnostic_labels = [], []
        self.options = {"on_early_exporter": callbacks.append}
        self.store.issue(b"s" * 48, "localhost", b"http/1.1", 65536,
            context=self.policy.context(b"http/1.1"), pake_identity=b"alice", cipher_suite=0x1302)
        ticket = next(iter(self.store._tickets.values()))
        transcript, schedule = Transcript(), c.KeySchedule("sha384")
        random = os.urandom(32)
        private, public = c.traffic_key(29)
        offers = [(b"unknown first sha256", 0, bytes(32)),
                  (ticket.identity, ticket.obfuscated_age(), bytes(48))]

        def hello(*, second=False):
            return m.client_hello(b"", public, "localhost", random, group=29,
                certificate_algorithms=(), cipher_suites=(0x1301, 0x1302), psk_offers=offers,
                early_data=not second, empty_share=not second)

        def bound_hello(prefix, *, second=False):
            message = hello(second=second)
            parsed = m.parse_client_hello(message[4:])
            offers[-1] = (*offers[-1][:2], c.binder(ticket.psk,
                prefix + message[:-parsed.binder_vector_size], hash_name="sha384"))
            return hello(second=second)

        ch1 = bound_hello(c.PREFACE)
        early_root = c.extract(bytes(32), b"u" * 32)
        early = c.RecordState(c.derive_secret(early_root, "c e traffic", c.PREFACE + ch1), "seal")
        records = [early]
        reader, writer = await asyncio.open_connection("127.0.0.1", self.port)
        self.writers.append(writer)
        wire = Wire(reader, writer)

        def diagnostic(_sink, label, _random, _secret):
            diagnostic_labels.append(label)

        try:
            with patch.object(pake_handshake, "emit_diagnostic", diagnostic):
                writer.write(c.PREFACE)
                await wire.send_frame(ch1)
                writer.write(early.seal(b"rejected first PSK request", 23))
                await writer.drain()
                hrr = await wire.receive_frame(2)
                self.assertTrue(m.parse_server_hello(hrr[4:], with_suite=True)[4])
                transcript.retry(ch1, hrr, "sha384")
                offers = [(ticket.identity, ticket.obfuscated_age(), bytes(48))]
                ch2 = bound_hello(transcript.snapshot(), second=True)
                await wire.send_frame(ch2)
                sh = await wire.receive_frame(2)
                peer, _, resumed, group, retry, _, suite = m.parse_server_hello(sh[4:], with_suite=True)
                self.assertEqual((resumed, group, retry, suite), (True, 29, False, 0x1302))
                self.assertEqual(m.server_hello_extensions(sh[4:])[41], b"\x00\x00")
                transcript.add(ch2)
                transcript.add(sh)
                root = c.handshake_secret(c.traffic_dh(private, group, peer), ticket.psk, "sha384")
                client_secret, server_secret = handshake_keys(root, transcript, "sha384")
                sender, receiver = c.RecordState(client_secret, "seal", suite), c.RecordState(server_secret, "open", suite)
                records.extend((sender, receiver))
                ee = await wire.receive_frame(8, receiver)
                self.assertNotIn(42, m.extensions(ee[6:]))
                transcript.add(ee)
                sf = await wire.receive_frame(20, receiver)
                self.assertTrue(schedule.verify_finished(server_secret, transcript.snapshot(), sf[4:]))
                transcript.add(sf)
                client_app, server_app = application_keys(root, transcript, "sha384")
                self.assertFalse(callbacks)
                self.assertNotIn("TLS20_EARLY_EXPORTER_SECRET", diagnostic_labels)
                await wire.send_frame(m.frame(20, schedule.finished(client_secret, transcript.snapshot())), sender)
                app_sender, app_receiver = c.RecordState(client_app, "seal", suite), c.RecordState(server_app, "open", suite)
                records.extend((app_sender, app_receiver))
                self.assertEqual((await wire.read_record(app_receiver))[1], 22)
                self.assertEqual(await wire.read_record(app_receiver), (b"ready", 23))
                server = self.channels[-1]
                self.assertIsNone(server.early_exporter_secret)
                self.assertFalse(callbacks)
                self.assertNotIn("TLS20_EARLY_EXPORTER_SECRET", diagnostic_labels)
                self.assertFalse(self.early)
                writer.write(app_sender.seal(b"valid 1-RTT", 23))
                await writer.drain()
                self.assertEqual(await wire.read_record(app_receiver), (b"valid 1-RTT", 23))
                writer.write(app_sender.seal(b"\x01\x00", 21))
                await writer.drain()
                await asyncio.wait_for(asyncio.gather(*tuple(self.tasks)), 2)
                self.assertFalse(self.errors)
        finally:
            for state in records:
                state.close()
            for channel in self.channels:
                channel.abort()
            writer.close()


if __name__ == "__main__":
    unittest.main()
