"""Real loopback tests of resumption, early epochs, replay gates and updates."""

import asyncio
from dataclasses import replace
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, patch

from tls20_server import crypto as c
from tls20_server.errors import PeerClosed, ProtocolError
from tls20_server.handshake import Wire, client_handshake, server_handshake, _retry_psks_unchanged
from tls20_server.messages import ClientHello
from tls20_server import messages as m
from tls20_server.lab import generate_lab_credentials
from tls20_server.tickets import TicketCache, TicketStore


class SessionTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.credentials, root = generate_lab_credentials("localhost")
        self.roots = [root]
        self.store, self.cache = TicketStore(), TicketCache()
        self.tasks, self.channels, self.writers = set(), [], []
        self.client_writers = set()
        self.client_connected = asyncio.Event()
        self.defer_server_writer_registration = False
        self.errors, self.early = [], []
        self.callback_event = asyncio.Event()
        self.server_options = {}
        self.listener = await asyncio.start_server(self.accept, "127.0.0.1", 0)
        self.port = self.listener.sockets[0].getsockname()[1]

    def accept(self, reader, writer):
        if getattr(self, "defer_server_writer_registration", False):
            async def handle_after_client_registration():
                await self.client_connected.wait()
                self.writers.append(writer)
                await self.handle(reader, writer)
            task = asyncio.create_task(handle_after_client_registration())
        else:
            self.writers.append(writer)
            task = asyncio.create_task(self.handle(reader, writer))
        self.tasks.add(task)
        task.add_done_callback(self.tasks.discard)

    async def handle(self, reader, writer):
        async def early(data):
            self.early.append(data)
            self.callback_event.set()
        channel = None
        try:
            channel = await server_handshake(reader, writer, self.credentials, "localhost",
                ticket_store=self.store, max_early_data=65536, on_early_data=early, **self.server_options)
            self.channels.append(channel)
            await channel.send(b"ready")
            while (content := await channel.recv()) is not None:
                await channel.send(content)
        except (ProtocolError, OSError) as exc:
            self.errors.append(str(exc))
        finally:
            if channel:
                await channel.close()
            else:
                writer.close()

    async def connect(self, **options):
        self.client_connected.clear()
        reader, writer = await asyncio.open_connection("127.0.0.1", self.port)
        self.writers.append(writer)
        # The accepted server writer can be registered before OR after this
        # continuation. Identify the injection endpoint by role, not list order.
        self.client_writers.add(writer)
        self.client_connected.set()
        channel = await client_handshake(reader, writer, "localhost", self.roots,
            revocation_policy="lab-offline", ticket_cache=self.cache, **options)
        self.assertEqual(await asyncio.wait_for(channel.recv(), 2), b"ready", self.errors)
        return channel

    async def asyncTearDown(self):
        self.listener.close()
        for writer in self.writers:
            writer.transport.abort()
        await asyncio.wait_for(self.listener.wait_closed(), 2)
        for task in tuple(self.tasks):
            task.cancel()
        await asyncio.gather(*self.tasks, return_exceptions=True)
        for writer in self.writers:
            try:
                await asyncio.wait_for(writer.wait_closed(), 1)
            except (OSError, TimeoutError, asyncio.CancelledError):
                pass

    async def test_full_resumed_and_exporters(self):
        first = await self.connect()
        self.assertFalse(first.resumed)
        self.assertEqual(first.exporter("example", b"scope", 64), self.channels[-1].exporter("example", b"scope", 64))
        self.assertEqual(len(self.cache._tickets), 1)
        second = await self.connect()
        self.assertTrue(second.resumed)
        self.assertEqual(second.exporter("example"), self.channels[-1].exporter("example"))
        self.assertNotEqual(first.exporter("example"), second.exporter("example"))
        await second.send(b"resumed application")
        self.assertEqual(await second.recv(), b"resumed application")

    async def test_p256_and_group_retry_full_and_resumed(self):
        for group, retry in ((23, False), (29, True), (23, True)):
            with self.subTest(group=group, retry=retry):
                channel = await self.connect(traffic_group=group, force_retry=retry)
                await channel.send(b"p256 or retry")
                self.assertEqual(await channel.recv(), b"p256 or retry")
        self.assertFalse(self.errors)

    async def test_early_bytes_arrive_before_client_finished(self):
        await self.connect()
        reader, writer = await asyncio.open_connection("127.0.0.1", self.port)
        self.writers.append(writer)
        original = Wire.send_frame
        events = []
        ticket = next(iter(self.cache._tickets.values()))
        client_hello = []
        async def gate(wire, message, state=None):
            if wire.writer is writer and message[0] == 1:
                client_hello.append(message)
            if wire.writer is writer and message[0] == 5:
                expected = c.derive_secret(c.extract(bytes(32), ticket.psk),
                    "c e traffic", b"TLS20-EXPERIMENT\r\n" + client_hello[0])
                self.assertEqual(state.secret, expected, "EndOfEarlyData must use early, not handshake keys")
            if wire.writer is writer and message[0] == 20:
                await asyncio.wait_for(self.callback_event.wait(), 1)
                events.append("client Finished")
                self.assertIn(b"early request", self.early)
            return await original(wire, message, state)
        with patch.object(Wire, "send_frame", gate):
            channel = await client_handshake(reader, writer, "localhost", self.roots,
                revocation_policy="lab-offline", ticket_cache=self.cache, early_data=b"early request")
        self.assertTrue(channel.resumed)
        self.assertTrue(channel.early_data_accepted)
        self.assertEqual(await channel.recv(), b"ready")
        self.assertEqual(events, ["client Finished"])
        self.assertEqual(self.early, [b"early request", b""])

    async def test_early_ticket_is_consumed_atomically_and_not_replayed(self):
        await self.connect()
        ticket = replace(next(iter(self.cache._tickets.values())))
        first = await self.connect(early_data=b"first early")
        self.assertTrue(first.early_data_accepted)
        self.cache.put(ticket)
        replay = await self.connect(early_data=b"replayed early")
        self.assertTrue(replay.resumed)
        self.assertFalse(replay.early_data_accepted)
        self.assertEqual(self.early, [b"first early", b""])
        await replay.send(b"retry after rejection")
        self.assertEqual(await replay.recv(), b"retry after rejection")

    async def test_early_epoch_alerts_use_normal_closure_semantics(self):
        # Accepted early records use early keys; after rejection, authenticated
        # alerts use handshake keys. Both paths must stop without replying to
        # a peer's fatal alert, and ignore advisory user_canceled until closure.
        for accepted in (False, True):
            for descriptions in ((0,), (90, 0), (40,), (203,)):
                with self.subTest(accepted=accepted, descriptions=descriptions):
                    self.cache, self.store = TicketCache(), TicketStore()
                    await self.connect()
                    next(iter(self.store._tickets.values())).early_used = not accepted
                    reader, writer = await asyncio.open_connection("127.0.0.1", self.port)
                    self.writers.append(writer)
                    original_send, original_fatal = Wire.send_frame, Wire.fatal
                    observed, injected = [], False
                    stopped = asyncio.Event()
                    async def send(wire, message, state=None):
                        nonlocal injected
                        if wire.writer is writer:
                            if not injected and message[0] == (5 if accepted else 20):
                                injected = True
                                for description in descriptions:
                                    wire.writer.write(state.seal(bytes((1, description)), 21))
                                await wire.writer.drain()
                                return
                            if injected and message[0] == 20:
                                return  # This crafted client ended its sending flight.
                        return await original_send(wire, message, state)
                    async def fatal(wire, error, state=None):
                        before = state.sequence if state else None
                        await original_fatal(wire, error, state)
                        if wire.writer is not writer:
                            observed.append((error, before, state.sequence if state else None))
                            stopped.set()
                    with patch.object(Wire, "send_frame", send), patch.object(Wire, "fatal", fatal):
                        channel = await client_handshake(reader, writer, "localhost", self.roots,
                            revocation_policy="lab-offline", ticket_cache=self.cache, early_data=b"early")
                        await asyncio.wait_for(stopped.wait(), 2)
                        channel.abort()
                    self.assertTrue(injected)
                    self.assertEqual(len(observed), 1)
                    error, before, after = observed[0]
                    self.assertIsInstance(error, PeerClosed)
                    self.assertEqual(error.alert, descriptions[-1])
                    self.assertEqual(before, after, "peer closure must not emit another encrypted alert")

    async def test_rejected_early_alert_commits_to_handshake_epoch(self):
        for corrupt_after_alert in (False, True):
            with self.subTest(corrupt_after_alert=corrupt_after_alert):
                self.cache, self.store = TicketCache(), TicketStore()
                await self.connect()
                next(iter(self.store._tickets.values())).early_used = True
                original = Wire.send_frame
                async def send(wire, message, state=None):
                    if wire.writer in self.client_writers and message[0] == 20:
                        wire.writer.write(state.seal(b"\x01\x5a", 21))
                        if corrupt_after_alert:
                            # An injected bad record does not consume the
                            # legitimate sender's next handshake sequence.
                            wire.writer.write(bytes.fromhex("1703030010") + bytes(16))
                        await wire.writer.drain()
                    return await original(wire, message, state)
                with patch.object(Wire, "send_frame", send):
                    if corrupt_after_alert:
                        with self.assertRaises(PeerClosed) as failure:
                            await self.connect(early_data=b"rejected early bytes")
                        self.assertEqual(failure.exception.alert, 20)
                    else:
                        channel = await self.connect(early_data=b"rejected early bytes")
                        self.assertTrue(channel.resumed)
                        self.assertFalse(channel.early_data_accepted)
                        await channel.send(b"valid handshake after advisory alert")
                        self.assertEqual(await channel.recv(), b"valid handshake after advisory alert")
                self.assertFalse(self.early)

    async def test_restart_invalidates_tickets_and_discards_early_data(self):
        await self.connect()
        self.store = TicketStore()
        channel = await self.connect(early_data=b"never forwarded")
        self.assertFalse(channel.resumed)
        self.assertFalse(channel.early_data_accepted)
        self.assertFalse(self.early)

    async def test_rejected_early_probe_rejects_authenticated_malformed_records(self):
        self.server_options["record_size_limit"] = 64
        for plaintext, alert in ((None, None), (b"x\xff", 10), (b"\x00", 10),
                                 (b"\x01\x15", 50), (b"x" * 64 + b"\x17", 22)):
            with self.subTest(plaintext=plaintext):
                self.cache, self.store = TicketCache(), TicketStore()
                await self.connect(record_size_limit=64)
                next(iter(self.store._tickets.values())).early_used = True
                original, injected = Wire.send_frame, False
                async def send(wire, message, state=None):
                    nonlocal injected
                    if wire.writer in self.client_writers and message[0] == 20:
                        injected = True
                        if plaintext is None:
                            record = bytes.fromhex("1703030010") + bytes(16)
                        else:
                            header = b"\x17\x03\x03" + (len(plaintext) + state.suite.tag_length).to_bytes(2, "big")
                            # Valid handshake-epoch AEAD, deliberately invalid
                            # inner plaintext. A following valid CF must not
                            # turn this into an ignorable stale early record.
                            record = header + state._cipher.encrypt(
                                c.nonce(state.iv, state.sequence), plaintext, header)
                        wire.writer.write(record)
                        await wire.writer.drain()
                    return await original(wire, message, state)
                with patch.object(Wire, "send_frame", send):
                    if alert is not None:
                        with self.assertRaises(PeerClosed) as failure:
                            await self.connect(record_size_limit=64, early_data=b"rejected early bytes")
                        self.assertEqual(failure.exception.alert, alert)
                    else:
                        channel = await self.connect(record_size_limit=64, early_data=b"rejected early bytes")
                        self.assertTrue(channel.resumed)
                        self.assertFalse(channel.early_data_accepted)
                        await channel.send(b"valid after stale early records")
                        self.assertEqual(await channel.recv(), b"valid after stale early records")
                self.assertTrue(injected)
                self.assertFalse(self.early)

    async def test_early_record_injection_with_server_writer_registered_last(self):
        # Force the ordering observed by the macOS event loop without sleeps.
        # Both malformed-record hooks must still target only Client Finished.
        self.defer_server_writer_registration = True
        await self.test_rejected_early_alert_commits_to_handshake_epoch()
        await self.test_rejected_early_probe_rejects_authenticated_malformed_records()
        self.assertNotIn(self.writers[-1], self.client_writers)

    async def test_retry_rejects_early_data_without_forwarding(self):
        await self.connect()
        channel = await self.connect(early_data=b"do not forward", force_retry=True)
        self.assertTrue(channel.resumed)
        self.assertFalse(channel.early_data_accepted)
        self.assertFalse(self.early)

    async def test_bad_binder_never_forwards_early_bytes(self):
        await self.connect()
        ticket = next(iter(self.cache._tickets.values()))
        ticket.psk = bytes(32)
        with self.assertRaises((ProtocolError, ConnectionResetError)):
            await self.connect(early_data=b"forged")
        self.assertFalse(self.early)
        self.assertTrue(any("binder" in error for error in self.errors))

    async def test_key_update_both_directions_and_exporter_stability(self):
        channel = await self.connect()
        exporter = channel.exporter("test")
        initial_send, initial_recv = channel.sender.secret, channel.receiver.secret
        await channel.key_update(request_peer=True)
        await channel.send(b"after update")
        self.assertEqual(await channel.recv(), b"after update")
        self.assertNotEqual(initial_send, channel.sender.secret)
        self.assertNotEqual(initial_recv, channel.receiver.secret)
        self.assertEqual(exporter, channel.exporter("test"))
        await self.channels[-1].key_update()
        await channel.send(b"second update")
        self.assertEqual(await channel.recv(), b"second update")

    async def test_changed_trust_context_does_not_resume(self):
        await self.connect(cache_context=b"port-A")
        channel = await self.connect(cache_context=b"port-B", early_data=b"not sent")
        self.assertFalse(channel.resumed)
        self.assertFalse(channel.early_data_accepted)
        self.assertFalse(self.early)

    async def test_nonempty_session_id_gets_dummy_ccs_after_first_server_hello(self):
        for retry in (False, True):
            reader, writer = await asyncio.open_connection("127.0.0.1", self.port)
            self.writers.append(writer)
            wire = Wire(reader, writer)
            a, b = c.traffic_key(29)[1], c.traffic_key(29)[1]
            writer.write(c.PREFACE)
            await wire.send_frame(m.client_hello(a, b, "localhost", bytes(32),
                session_id=b"compatibility", empty_share=retry))
            sh = await wire.receive_frame(2, boundary=True)
            self.assertEqual(m.parse_server_hello(sh[4:], details=True)[1], b"compatibility")
            self.assertEqual(await wire.raw_record(), b"\x14\x03\x03\x00\x01\x01")

    async def test_invalid_cached_certificate_falls_back_to_full(self):
        await self.connect()
        ticket = next(iter(self.cache._tickets.values()))
        ticket.certificate_chain = [b"broken"]
        channel = await self.connect(early_data=b"not sent")
        self.assertFalse(channel.resumed)
        self.assertFalse(channel.early_data_accepted)
        self.assertFalse(self.early)

    async def test_automatic_key_update_before_record_quota(self):
        channel = await self.connect()
        initial = channel.sender.secret
        with patch.object(c, "MAX_RECORDS", 4):
            for index in range(10):
                content = f"message {index}".encode()
                await channel.send(content)
                self.assertEqual(await channel.recv(), content)
        self.assertNotEqual(channel.sender.secret, initial)

    async def test_ticket_byte_budget_never_breaks_a_valid_handshake(self):
        self.store = TicketStore(max_bytes=1)
        channel = await self.connect()
        self.assertFalse(channel.resumed)
        self.assertFalse(self.cache._tickets)
        await channel.send(b"connection without optional ticket")
        self.assertEqual(await channel.recv(), b"connection without optional ticket")


class TicketBoundsTests(unittest.TestCase):
    def test_issued_ticket_remembers_early_record_limit_and_rejects_invalid_limits(self):
        store = TicketStore()
        store.issue(bytes(32), "localhost", b"http/1.1", record_size_limit=512)
        self.assertEqual(next(iter(store._tickets.values())).record_size_limit, 512)
        for limit in (True, 63, 16386, 512.0):
            with self.subTest(limit=limit), self.assertRaises(ValueError):
                store.issue(bytes(32), "localhost", b"http/1.1", record_size_limit=limit)

    def test_store_and_cache_reject_boolean_and_noninteger_bounds(self):
        for value in (True, False, 1.5, "3", None, 0, -1):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    TicketStore(lifetime=value)
                with self.assertRaises(ValueError):
                    TicketStore(capacity=value)
                with self.assertRaises(ValueError):
                    TicketStore(max_bytes=value)
                with self.assertRaises(ValueError):
                    TicketCache(capacity=value)

    def test_total_ticket_bytes_evict_and_expire_with_constant_time_accounting(self):
        store = TicketStore(max_bytes=2000)
        for index in range(3):
            self.assertIsNotNone(store.issue(bytes(32), "example", b"http/1.1",
                                            client_certificate_chain=[bytes(600)]))
            self.assertEqual(len(store._tickets), 1)
            self.assertLessEqual(store._bytes, store.max_bytes)
        last = next(iter(store._tickets.values()))
        last.issued -= last.lifetime + 1
        self.assertIsNone(store.lookup(last.identity, "example", b"http/1.1"))
        self.assertEqual(store._bytes, 0)
        self.assertIsNone(store.issue(bytes(32), "example", b"http/1.1",
                                     client_certificate_chain=[bytes(3000)]))
        self.assertFalse(store._tickets)
        self.assertEqual(store._bytes, 0)

    def test_retry_psk_continuity(self):
        hello = ClientHello("localhost", b"http/1.1", b"a"*32, b"b"*32, bytes(32),
            psk_offers=((b"sha384", 1, bytes(48)), (b"sha256", 2, bytes(32)), (b"last", 3, bytes(32))))
        known_hashes = {b"sha384": "sha384", b"sha256": "sha256", b"last": "sha256"}
        for offers in (hello.psk_offers, hello.psk_offers[1:],
                       ((b"sha384", 4, b"x"*48), (b"sha256", 5, b"y"*32), (b"last", 6, b"z"*32))):
            self.assertTrue(_retry_psks_unchanged(hello, replace(hello, psk_offers=offers),
                                                 known_hashes=known_hashes))
        for offers in (hello.psk_offers[:2], hello.psk_offers[::-1],
                       hello.psk_offers + ((b"new", 4, bytes(32)),),
                       ((b"sha384", 1, bytes(32)),) + hello.psk_offers[1:]):
            self.assertFalse(_retry_psks_unchanged(hello, replace(hello, psk_offers=offers),
                                                  known_hashes=known_hashes))

    def test_retry_psk_continuity_does_not_infer_hash_from_binder_length(self):
        hello = ClientHello("localhost", b"http/1.1", b"a"*32, b"b"*32, bytes(32),
            psk_offers=((b"sm3", 1, bytes(32)), (b"selected", 2, bytes(32)), (b"opaque", 3, bytes(32))))
        known_hashes = {b"sm3": "sm3", b"selected": "sha256"}
        for offers in (hello.psk_offers[1:], hello.psk_offers[1:2]):
            self.assertTrue(_retry_psks_unchanged(hello, replace(hello, psk_offers=offers),
                                                 known_hashes=known_hashes))
        for offers in (hello.psk_offers[:1], hello.psk_offers[::-1],
                       ((b"selected", 2, bytes(48)),), ((b"new", 2, bytes(32)),)):
            self.assertFalse(_retry_psks_unchanged(hello, replace(hello, psk_offers=offers),
                                                  known_hashes=known_hashes))
        # Without provisioning/lookup knowledge, any offered identity could
        # belong to a different same-sized KDF; opacity is not an error.
        self.assertTrue(_retry_psks_unchanged(hello, replace(hello, psk_offers=())))

    def test_lifetime_capacity_context_and_single_use(self):
        store = TicketStore(capacity=1)
        store.issue(bytes(32), "example", b"http/1.1", 16, b"credential")
        ticket = next(iter(store._tickets.values()))
        self.assertIsNone(store.lookup(ticket.identity, "other", b"http/1.1", b"credential"))
        self.assertIsNone(store.lookup(ticket.identity, "example", b"http/1.1", b"other"))
        self.assertTrue(store.consume_early(ticket, ticket.obfuscated_age()))
        self.assertFalse(store.consume_early(ticket, ticket.obfuscated_age()))
        store.issue(bytes(32), "example", b"http/1.1", 16, b"credential")
        self.assertIsNone(store.lookup(ticket.identity, "example", b"http/1.1", b"credential"))
        new = next(iter(store._tickets.values()))
        new.issued -= new.lifetime + 1
        self.assertIsNone(store.lookup(new.identity, "example", b"http/1.1", b"credential"))

    def test_record_padding_and_key_update(self):
        sender, receiver = c.RecordState(bytes(32), "seal"), c.RecordState(bytes(32), "open")
        self.assertEqual(receiver.open(sender.seal(b"zero\0", 23, 300)), (b"zero\0", 23))
        sender.update(); receiver.update()
        self.assertEqual(sender.sequence, 0)
        self.assertEqual(receiver.open(sender.seal(b"new key", 23)), (b"new key", 23))


class SessionFixtureTests(unittest.IsolatedAsyncioTestCase):
    async def test_shared_accept_without_optional_ordering_fixture(self):
        # Optional-provider fixtures reuse accept with their own setup.
        fixture = SimpleNamespace(handle=AsyncMock(), tasks=set(), writers=[])
        reader, writer = object(), object()
        SessionTests.accept(fixture, reader, writer)
        self.assertEqual(fixture.writers, [writer])
        await asyncio.gather(*fixture.tasks)
        fixture.handle.assert_awaited_once_with(reader, writer)


if __name__ == "__main__":
    unittest.main()
