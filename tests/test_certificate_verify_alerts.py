"""MAC CertificateVerify syntax and direction are not failed-MAC checks."""

import asyncio
import unittest
from unittest.mock import patch

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ed25519

from tests.test_client_auth import client_credentials
from tls20_server import crypto as c, handshake as hs, messages as m
from tls20_server.errors import PeerClosed, ProtocolError
from tls20_server.lab import generate_lab_credentials
from tls20_server.secret_lifecycle import HandshakeSecrets


MUTATIONS = ("valid", "opposite", "unknown", "malformed_vector", "malformed_and_unknown",
             "other_hash", "short", "bad_mac")


def mutate(message, role, mutation, hash_length):
    if mutation == "valid":
        return message
    body = message[4:]
    if mutation == "opposite":
        body = (b"\xfe\x01" if role == "server" else b"\xfe\x00") + body[2:]
    elif mutation == "unknown":
        body = b"\x08\x07" + body[2:]  # Well-framed public signature code, not a TLS20 MAC.
    elif mutation in ("malformed_vector", "malformed_and_unknown"):
        code = b"\x08\x07" if mutation == "malformed_and_unknown" else body[:2]
        body = code + b"\x00\x01" + body[4:]
    elif mutation in ("other_hash", "short"):
        size = (48 if hash_length == 32 else 32) if mutation == "other_hash" else 31
        proof = (body[4:] + bytes(size))[:size]
        body = body[:2] + size.to_bytes(2, "big") + proof
    elif mutation == "bad_mac":
        body = body[:-1] + bytes((body[-1] ^ 1,))
    else:
        raise AssertionError("unknown fixture mutation")
    # Bypass the outbound codec: this is an adversarial peer on the receive path.
    return b"\x0f" + len(body).to_bytes(3, "big") + body


def expected_alert(mutation):
    return 47 if mutation in ("opposite", "unknown") else 51 if mutation == "bad_mac" else 50


class CertificateVerifyParserTests(unittest.TestCase):
    def test_fixed_negotiated_length_and_direction_before_mac_verification(self):
        for size in (32, 48):
            for client in (False, True):
                message = m.certificate_verify(bytes(size), client=client)
                self.assertEqual(m.parse_certificate_verify(message[4:], hash_length=size, client=client), bytes(size))
                role = "client" if client else "server"
                for mutation in MUTATIONS[1:]:
                    if mutation == "bad_mac":
                        continue  # Cryptographic verification belongs to the authenticated caller.
                    with self.subTest(size=size, client=client, mutation=mutation):
                        body = mutate(message, role, mutation, size)[4:]
                        with self.assertRaises(ProtocolError) as caught:
                            m.parse_certificate_verify(body, hash_length=size, client=client)
                        self.assertEqual(caught.exception.alert, expected_alert(mutation))


class CertificateVerifyAlertTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.credentials, root = generate_lab_credentials("localhost")
        self.roots = [root]
        self.credential = client_credentials(ed25519.Ed25519PrivateKey.generate())

    async def exchange(self, suite, mutated_sender, mutation, *, pha=False):
        roles, errors, channels, flights = {}, {}, {}, {}
        tasks, writers, wire_alerts, scopes, records, states = [], [], [], [], [], []
        client_started, accepted = asyncio.Event(), asyncio.Event()
        listener = None
        initial = True
        send, read = hs.Wire.send_frame, hs.Wire.read_record
        scope_init, make_record = HandshakeSecrets.__init__, HandshakeSecrets.record

        def init(scope):
            scope_init(scope)
            scopes.append(scope)

        def record(scope, *args, **kwargs):
            value = make_record(scope, *args, **kwargs)
            records.append(value)
            return value

        async def observed(wire, state=None):
            content, kind = await read(wire, state)
            if kind == 21:
                wire_alerts.append((roles[wire.writer], bytes(content)))
            return content, kind

        async def changed(wire, message, state=None):
            role = roles[wire.writer]
            if role == mutated_sender and message[0] == 15 and (not pha or not initial):
                message = mutate(message, role, mutation, c.suite(suite).hash_length)
            if state is not None and (initial or role == "client"):
                # Coalesce each genuine authentication flight. No late write
                # races the rejection and turns a TLS alert into a TCP reset.
                flights.setdefault(role, []).append(message)
                if message[0] != 20:
                    return
                message = b"".join(flights.pop(role))
                self.assertLessEqual(len(message), state.record_limit - 1)
            return await send(wire, message, state)

        async def run(role, reader, writer):
            roles[writer] = role
            writers.append(writer)
            try:
                if role == "server":
                    channels[role] = await hs.server_handshake(reader, writer, self.credentials, "localhost",
                        cipher_suites=(suite,), timeout=3, require_client_auth=not pha,
                        client_auth_validator=lambda chain: x509.load_der_x509_certificate(chain[0]).public_key())
                else:
                    channels[role] = await hs.client_handshake(reader, writer, "localhost", self.roots,
                        cipher_suites=(suite,), timeout=3, revocation_policy="lab-offline",
                        client_credentials=None if pha else self.credential, post_handshake_auth=pha)
            except ProtocolError as error:
                errors[role] = error

        async def accept(reader, writer):
            # Force registration after the client task exists. Different event
            # loops can otherwise hide a snapshot race in gather(*tasks).
            await client_started.wait()
            tasks.append(asyncio.current_task())
            accepted.set()
            await run("server", reader, writer)

        try:
            with patch.object(hs.Wire, "send_frame", changed), patch.object(hs.Wire, "read_record", observed), \
                    patch.object(HandshakeSecrets, "__init__", init), patch.object(HandshakeSecrets, "record", record):
                listener = await asyncio.start_server(accept, "127.0.0.1", 0)
                reader, writer = await asyncio.open_connection("127.0.0.1", listener.sockets[0].getsockname()[1])
                tasks.append(asyncio.create_task(run("client", reader, writer)))
                client_started.set()
                await asyncio.wait_for(accepted.wait(), 4)
                await asyncio.wait_for(asyncio.gather(*tasks), 4)
                initial = False
                if pha:
                    self.assertFalse(errors)
                    client, server = channels["client"], channels["server"]
                    self.assertIsNone(server.authenticated_client)
                    client.client_credentials = self.credential
                    client.client_credential_candidates = (self.credential,)
                    future = await server.request_client_auth(required=True)
                    states.extend(server.pending_client_auth.values())
                    server_read = asyncio.create_task(server.recv())
                    client_read = asyncio.create_task(client.recv())
                    tasks.extend((server_read, client_read))
                    if mutation == "valid":
                        self.assertEqual(await asyncio.wait_for(future, 3), tuple(self.credential.chain_der))
                        await server.send(b"PHA verified")
                        self.assertEqual(await asyncio.wait_for(client_read, 3), b"PHA verified")
                        self.assertFalse(server.pending_client_auth)
                        self.assertTrue(all(state["private"] is None for state in states))
                    else:
                        results = await asyncio.wait_for(asyncio.gather(server_read, client_read, return_exceptions=True), 3)
                        self.assertIsInstance(results[0], ProtocolError)
                        self.assertIsInstance(results[1], PeerClosed)
                        errors = dict(zip(("server", "client"), results))
                        self.assertTrue(future.cancelled())
                        self.assertIsNone(server.authenticated_client)
                        self.assertFalse(server.pending_client_auth)
                        self.assertTrue(all(state["private"] is None for state in states))
                elif mutation != "valid" and mutated_sender == "client":
                    # Server has already switched to application sending keys.
                    # Read the actual alert through the established client.
                    with self.assertRaises(PeerClosed) as caught:
                        await asyncio.wait_for(channels["client"].recv(), 3)
                    errors["client"] = caught.exception

            if mutation == "valid":
                self.assertFalse(errors)
                self.assertEqual(set(channels), {"server", "client"})
                self.assertEqual(channels["server"].authenticated_client, tuple(self.credential.chain_der))
                self.assertEqual(channels["client"].exporter("CV-alert"), channels["server"].exporter("CV-alert"))
                self.assertFalse(wire_alerts)
            else:
                recipient = "client" if mutated_sender == "server" else "server"
                alert = expected_alert(mutation)
                self.assertEqual(set(errors), {"server", "client"})
                self.assertNotIsInstance(errors[recipient], PeerClosed)
                self.assertIsInstance(errors[mutated_sender], PeerClosed)
                self.assertEqual({error.alert for error in errors.values()}, {alert})
                self.assertEqual(wire_alerts, [(mutated_sender, bytes((2, alert)))])
                for channel in channels.values():
                    self.assertTrue(channel.closed)
                    self.assertIsNone(channel.exporter_secret)
                    self.assertIsNone(channel.auth_share_secret)
                    self.assertTrue(channel.sender.failed and channel.receiver.failed)
                self.assertTrue(records)
                self.assertTrue(all(state.failed and not state.secret and not state.key and not state.iv
                                    and state._cipher is None for state in records))
                self.assertTrue(all(not scope.records and not scope.keys and scope.channel is None for scope in scopes))
                for error in errors.values():
                    trace = error.__traceback__
                    while trace:
                        frame = trace.tb_frame
                        if (frame.f_globals.get("__name__", "").startswith("tls20_server.")
                                and frame.f_code.co_name != "guarded"):
                            self.assertFalse(frame.f_locals, frame.f_code.co_name)
                        trace = trace.tb_next
        finally:
            for channel in channels.values():
                channel.abort()
            for task in tasks:
                if not task.done():
                    task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            for writer in writers:
                writer.close()
            await asyncio.gather(*(writer.wait_closed() for writer in writers), return_exceptions=True)
            if listener is not None:
                listener.close()
                await listener.wait_closed()

    async def test_initial_server_and_client_mac_alerts(self):
        for suite in (0x1301, 0x1302):
            for role in ("server", "client"):
                for mutation in MUTATIONS:
                    with self.subTest(suite=hex(suite), sender=role, mutation=mutation):
                        await self.exchange(suite, role, mutation)

    async def test_post_handshake_client_mac_alerts(self):
        for suite in (0x1301, 0x1302):
            for mutation in MUTATIONS:
                with self.subTest(suite=hex(suite), mutation=mutation):
                    await self.exchange(suite, "client", mutation, pha=True)
