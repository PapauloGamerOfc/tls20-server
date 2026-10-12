"""Wire regressions for PSK vector syntax and non-first password resumption."""

import asyncio
import os
import unittest
from unittest.mock import patch

from tests import test_pake_handshake, test_sessions
from tls20_server import crypto as c, messages as m
from tls20_server.errors import PeerClosed
from tls20_server.handshake import Wire, Transcript, handshake_keys, application_keys
from tls20_server.secret_lifecycle import HandshakeSecrets
from tls20_server.tickets import TicketStore


class PSKVectorSyntaxTests(unittest.IsolatedAsyncioTestCase):
    asyncSetUp = test_sessions.SessionTests.asyncSetUp
    asyncTearDown = test_sessions.SessionTests.asyncTearDown
    accept = test_sessions.SessionTests.accept
    handle = test_sessions.SessionTests.handle
    connect = test_sessions.SessionTests.connect

    async def test_empty_vectors_decode_error_but_nonempty_count_mismatch_illegal_parameter(self):
        def vector(data):
            return len(data).to_bytes(2, "big") + data

        identity = vector(b"unknown") + bytes(4)
        binder = bytes((32,)) + bytes(32)
        original = m.client_hello
        for ids, binders, alert in ((b"", b"", 50), (b"", binder, 50),
                                    (identity, b"", 50), (identity, binder * 2, 47),
                                    (identity * 2, binder, 47), (identity, binder, None)):
            with self.subTest(identities=len(ids), binders=len(binders), alert=alert):
                def mutate(*args, **kwargs):
                    kwargs["extra_extensions"] = tuple(kwargs.get("extra_extensions", ())) + (
                        (41, vector(ids) + vector(binders)),)
                    return original(*args, **kwargs)

                before = len(self.channels)
                with patch.object(m, "client_hello", mutate):
                    if alert is not None:
                        # This is the actual peer alert received on the wire,
                        # not just the parser exception on the rejecting side.
                        with self.assertRaises(PeerClosed) as failure:
                            await asyncio.wait_for(self.connect(), 3)
                        self.assertEqual(failure.exception.alert, alert)
                        self.assertEqual(len(self.channels), before)
                    else:
                        channel = await asyncio.wait_for(self.connect(), 3)
                        self.assertFalse(channel.resumed)
                        await channel.send(b"unknown PSK falls back to certificate authentication")
                        self.assertEqual(await channel.recv(),
                                         b"unknown PSK falls back to certificate authentication")
                        await channel.close()


@unittest.skipUnless(os.environ.get("TLS20_TEST_PAKE") and os.environ.get("TLS20_TEST_OPENSSL"),
                     "explicit native PAKE fixture required")
class PasswordPSKSelectionTests(unittest.IsolatedAsyncioTestCase):
    asyncSetUp = test_pake_handshake.PakeHandshakeTests.asyncSetUp
    accept = test_pake_handshake.PakeHandshakeTests.accept

    async def asyncTearDown(self):
        for channel in self.channels:
            channel.abort()
        await test_pake_handshake.PakeHandshakeTests.asyncTearDown(self)

    async def handle(self, reader, writer):
        try:
            await test_pake_handshake.PakeHandshakeTests.handle(self, reader, writer)
        except Exception as error:
            # Surface a regression such as UnboundLocalError to the client
            # assertion without leaving an unobserved background task error.
            self.errors.append(error)

    async def exchange(self, selected_index, offer_early, *, corrupt_binder=False,
                       replayed=False):
        self.store = TicketStore()
        self.store.issue(b"s" * 32, "localhost", b"http/1.1", 65536,
                         context=self.policy.context(b"http/1.1"), pake_identity=b"alice")
        ticket = next(iter(self.store._tickets.values()))
        ticket.early_used = replayed
        reader, writer = await asyncio.open_connection("127.0.0.1", self.port)
        self.writers.append(writer)
        wire = Wire(reader, writer)
        private, public = c.traffic_key(29)
        random = os.urandom(32)
        offers = [(b"unknown-" + bytes((index,)), 0, bytes(32))
                  for index in range(selected_index)]
        offers.append((ticket.identity, ticket.obfuscated_age(), bytes(32)))

        def hello():
            return m.client_hello(b"", public, "localhost", random, group=29,
                                  certificate_algorithms=(), psk_offers=offers,
                                  early_data=offer_early)

        ch = hello()
        parsed = m.parse_client_hello(ch[4:])
        binder = c.binder(ticket.psk, c.PREFACE + ch[:-parsed.binder_vector_size])
        if corrupt_binder:
            binder = bytes((binder[0] ^ 1,)) + binder[1:]
        offers[selected_index] = (*offers[selected_index][:2], binder)
        ch = hello()
        records, temporary = [], []
        original_record = HandshakeSecrets.record

        def record(scope, *args, **kwargs):
            state = original_record(scope, *args, **kwargs)
            temporary.append(state)
            return state

        before, early_before = len(self.channels), len(self.early)
        try:
            with patch.object(HandshakeSecrets, "record", record):
                writer.write(c.PREFACE)
                await wire.send_frame(ch)
                early = None
                if offer_early:
                    # Encrypt with identity zero's key even when an unrelated
                    # later identity is the only one the server recognizes.
                    first_psk = ticket.psk if selected_index == 0 else b"u" * 32
                    early_secret = c.derive_secret(c.extract(bytes(32), first_psk),
                                                   "c e traffic", c.PREFACE + ch)
                    early = c.RecordState(early_secret, "seal")
                    records.append(early)
                    writer.write(early.seal(b"early request", 23))
                    await writer.drain()
                if corrupt_binder:
                    with self.assertRaises(PeerClosed) as failure:
                        await wire.receive_frame(2)
                    self.assertEqual(failure.exception.alert, 51)
                    self.assertEqual(len(self.channels), before)
                    self.assertEqual(len(self.early), early_before)
                    return
                sh = await wire.receive_frame(2)
                peer, _, resumed, group, retry, _, suite = m.parse_server_hello(sh[4:], with_suite=True)
                self.assertTrue(resumed)
                self.assertFalse(retry)
                self.assertEqual((group, suite), (29, 0x1301))
                self.assertEqual(m.server_hello_extensions(sh[4:])[41], selected_index.to_bytes(2, "big"))
                transcript = Transcript()
                transcript.add(ch)
                transcript.add(sh)
                root = c.handshake_secret(c.traffic_dh(private, group, peer), ticket.psk)
                client_secret, server_secret = handshake_keys(root, transcript)
                sender, receiver = c.RecordState(client_secret, "seal"), c.RecordState(server_secret, "open")
                records.extend((sender, receiver))
                ee = await wire.receive_frame(8, receiver)
                transcript.add(ee)
                accepted = 42 in m.extensions(ee[6:])
                self.assertEqual(accepted, offer_early and selected_index == 0 and not replayed)
                sf = await wire.receive_frame(20, receiver)
                self.assertTrue(c.verify_finished(server_secret, transcript.snapshot(), sf[4:]))
                transcript.add(sf)
                client_app, server_app = application_keys(root, transcript)
                if accepted:
                    eoed = m.frame(5, b"")
                    await wire.send_frame(eoed, early)
                    transcript.add(eoed)
                await wire.send_frame(m.frame(20, c.finished(client_secret, transcript.snapshot())), sender)
                app_sender, app_receiver = c.RecordState(client_app, "seal"), c.RecordState(server_app, "open")
                records.extend((app_sender, app_receiver))
                content, kind = await wire.read_record(app_receiver)
                self.assertEqual(kind, 22)
                ticket_kind, ticket_body = m.decode_frame(content)
                self.assertEqual(ticket_kind, 4)
                m.parse_new_session_ticket(ticket_body)
                self.assertEqual(await wire.read_record(app_receiver), (b"ready", 23), self.errors)
                self.assertEqual(len(self.channels), before + 1)
                self.assertEqual(self.channels[-1].pake_identity, b"alice")
                self.assertEqual(self.channels[-1].early_exporter_secret is not None, selected_index == 0)
                self.assertEqual(self.early[early_before:], [b"early request", b""] if accepted else [])
                writer.write(app_sender.seal(b"application after resumption", 23))
                await writer.drain()
                self.assertEqual(await wire.read_record(app_receiver), (b"application after resumption", 23))
                writer.write(app_sender.seal(b"\x01\x00", 21))
                await writer.drain()
            self.assertTrue(temporary)
            for state in temporary:
                self.assertTrue(state.failed)
                self.assertEqual((state.secret, state.key, state.iv), (b"", b"", b""))
                self.assertIsNone(state._cipher)
        finally:
            for state in records:
                state.close()
            writer.close()
            try:
                await writer.wait_closed()
            except OSError:
                pass

    async def test_first_and_later_psks_with_or_without_early_data(self):
        for index in (0, 1, 2):
            for early in (False, True):
                with self.subTest(selected_identity=index, early_data=early):
                    await asyncio.wait_for(self.exchange(index, early), 4)

    async def test_bad_binder_and_replayed_early_stay_rejected(self):
        for index in (0, 1):
            with self.subTest(bad_binder_index=index):
                await asyncio.wait_for(self.exchange(index, True, corrupt_binder=True), 4)
        await asyncio.wait_for(self.exchange(0, True, replayed=True), 4)


if __name__ == "__main__":
    unittest.main()
