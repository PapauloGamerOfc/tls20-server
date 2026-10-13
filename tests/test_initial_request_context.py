"""Initial request-context semantics, distinct from valid PHA contexts."""

import asyncio
import unittest
from unittest.mock import patch

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ed25519

from tests.test_client_auth import client_credentials
from tls20_server import handshake as hs, messages as m
from tls20_server.errors import PeerClosed, ProtocolError
from tls20_server.lab import generate_lab_credentials
from tls20_server.secret_lifecycle import HandshakeSecrets


class InitialRequestContextTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.credentials, root = generate_lab_credentials("localhost")
        self.roots = [root]
        self.client_credential = client_credentials(ed25519.Ed25519PrivateKey.generate())

    async def exchange(self, suite, context, *, cached_requests=()):
        roles, errors, channels, writers, tasks = {}, {}, {}, [], []
        scopes, records, requests, client_frames, wire_alerts = [], [], [], [], []
        server_flight, server_flight_state = [], None
        accepted = asyncio.get_running_loop().create_future()
        listener = None
        validated = 0
        original_send, original_alert = hs.Wire.send_frame, hs.Wire.process_alert
        original_init, original_record = HandshakeSecrets.__init__, HandshakeSecrets.record

        def validate_client(chain):
            nonlocal validated
            self.assertEqual(chain, self.client_credential.chain_der)
            validated += 1
            return x509.load_der_x509_certificate(chain[0]).public_key()

        def scope_init(scope):
            original_init(scope)
            scopes.append(scope)

        def record(scope, *args, **kwargs):
            state = original_record(scope, *args, **kwargs)
            records.append(state)
            return state

        async def send(wire, message, state=None):
            nonlocal server_flight_state
            role = roles[wire.writer]
            if role == "server" and message[0] in (13, 252):
                body = message[4:]
                self.assertEqual(body[0], 0)
                message = m.frame(message[0], bytes((len(context),)) + context + body[1:])
                # Both encodings remain structurally valid. A nonempty context
                # is valid for PHA but not in this initial-handshake state.
                self.assertEqual(hs._decode_request(message, cache_enabled=bool(cached_requests),
                    templates=cached_requests)[0], context)
                requests.append(message[0])
            if role == "client":
                client_frames.append(message[0])
            if role == "server" and state is not None:
                # Rejecting CR must not race late Certificate/CV/Finished
                # writes, which can cause an OS-dependent TCP reset instead
                # of delivering the authenticated alert. Send the real flight
                # as one bounded record; transcripts and keys stay unchanged.
                if server_flight_state is None:
                    server_flight_state = state
                self.assertIs(state, server_flight_state)
                server_flight.append(message)
                if message[0] != 20:
                    return
                self.assertEqual([value[0] for value in server_flight],
                                 [8, 252 if cached_requests else 13, 11, 15, 20])
                message = b"".join(server_flight)
                self.assertLessEqual(len(message), min(16384, state.record_limit - 1))
            return await original_send(wire, message, state)

        def alert(wire, fragment):
            # Observe the peer's actual authenticated record after decryption,
            # not merely the local exception or attempted fatal-alert write.
            wire_alerts.append((roles[wire.writer], bytes(fragment)))
            return original_alert(wire, fragment)

        async def run(role, reader, writer):
            roles[writer] = role
            writers.append(writer)
            try:
                if role == "server":
                    channel = await hs.server_handshake(reader, writer, self.credentials, "localhost",
                        client_auth_validator=validate_client, require_client_auth=True,
                        cipher_suites=(suite,), timeout=3)
                else:
                    channel = await hs.client_handshake(reader, writer, "localhost", self.roots,
                        revocation_policy="lab-offline", client_credentials=self.client_credential,
                        cached_requests=cached_requests, cipher_suites=(suite,), timeout=3)
                channels[role] = channel
            except ProtocolError as error:
                errors[role] = error

        def accept(reader, writer):
            task = asyncio.create_task(run("server", reader, writer))
            tasks.append(task)
            accepted.set_result(task)

        try:
            with patch.object(hs.Wire, "send_frame", send), patch.object(hs.Wire, "process_alert", alert), \
                    patch.object(HandshakeSecrets, "__init__", scope_init), \
                    patch.object(HandshakeSecrets, "record", record):
                listener = await asyncio.start_server(accept, "127.0.0.1", 0)
                reader, writer = await asyncio.open_connection("127.0.0.1", listener.sockets[0].getsockname()[1])
                tasks.append(asyncio.create_task(run("client", reader, writer)))
                await accepted
                await asyncio.wait_for(asyncio.gather(*tasks), 4)
            self.assertEqual(requests, [252 if cached_requests else 13])
            if not context:
                self.assertFalse(errors)
                self.assertEqual(set(channels), {"server", "client"})
                self.assertEqual(validated, 1)
                self.assertEqual(channels["server"].authenticated_client,
                                 tuple(self.client_credential.chain_der))
                self.assertEqual(channels["client"].exporter("request-context"),
                                 channels["server"].exporter("request-context"))
                self.assertFalse(wire_alerts)
                return tuple(channels["client"].client_request_templates)
            self.assertFalse(channels)
            self.assertEqual(validated, 0)
            self.assertEqual(client_frames, [1])  # No credential, proof or Finished released.
            self.assertEqual(set(errors), {"server", "client"})
            self.assertEqual(errors["client"].alert, 47)
            self.assertIsInstance(errors["server"], PeerClosed)
            self.assertEqual(errors["server"].alert, 47)
            self.assertEqual(wire_alerts, [("server", b"\x02\x2f")])
            self.assertTrue(records)
            self.assertTrue(all(state.failed and not state.secret and not state.key and not state.iv
                                and state._cipher is None for state in records))
            self.assertTrue(all(not scope.keys and not scope.records and scope.channel is None
                                for scope in scopes))
            for error in errors.values():
                trace = error.__traceback__
                while trace is not None:
                    if trace.tb_frame.f_code.co_name in ("client_handshake", "server_handshake"):
                        self.assertFalse(trace.tb_frame.f_locals)
                    trace = trace.tb_next
            return ()
        finally:
            for channel in channels.values():
                channel.abort()
            for writer in writers:
                writer.close()
            for task in tasks:
                if not task.done():
                    task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            await asyncio.gather(*(writer.wait_closed() for writer in writers), return_exceptions=True)
            if listener is not None:
                listener.close()
                await listener.wait_closed()

    async def test_initial_request_context_alert_for_ordinary_and_cached_requests(self):
        for suite in (0x1301, 0x1302):
            templates = await self.exchange(suite, b"")
            self.assertTrue(templates)
            for cached in ((), templates):
                for context in (b"", b"x", b"x" * 255):
                    with self.subTest(suite=hex(suite), cached=bool(cached), context_length=len(context)):
                        await self.exchange(suite, context, cached_requests=cached)
