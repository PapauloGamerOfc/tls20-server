"""Negotiated Finished syntax, distinct from authentication failure policy."""

import asyncio
import os
import unittest
from unittest.mock import patch

from tests import test_client_auth
from tls20_server import crypto as c, handshake as hs, pake_handshake as pwd
from tls20_server.errors import ProtocolError
from tls20_server.lab import generate_lab_credentials


def changed_finished(message, mutation, size):
    if mutation == "valid":
        return message
    body = message[4:]
    if mutation == "bad_mac":
        body = body[:-1] + bytes((body[-1] ^ 1,))
    else:
        length = (48 if size == 32 else 32) if mutation == "other_hash" else mutation
        body = (body + bytes(length))[:length]
    # Deliberately bypass outbound syntax validation to exercise the receiver.
    return b"\x14" + len(body).to_bytes(3, "big") + body


class FinishedSyntaxTests(unittest.TestCase):
    def test_negotiated_length_precedes_mac_verification(self):
        for name in ("sha256", "sha384", "sm3"):
            schedule = c.KeySchedule(name)
            size = c.hash_length(name)
            secret, transcript = bytes(size), b"synthetic Finished transcript"
            proof = schedule.finished(secret, transcript)
            with self.subTest(hash=name):
                self.assertTrue(hs._verify_finished(schedule, secret, transcript, proof))
                self.assertFalse(hs._verify_finished(schedule, secret, transcript + b"x", proof))
                for length in (0, 31, 32, 33, 48, 49):
                    if length == size:
                        continue
                    with self.subTest(length=length), patch.object(c.KeySchedule, "verify_finished") as verify:
                        with self.assertRaises(ProtocolError) as caught:
                            hs._verify_finished(schedule, secret, transcript, bytes(length))
                        self.assertEqual(caught.exception.alert, 50)
                        verify.assert_not_called()

    def test_crypto_component_keeps_its_boolean_contract(self):
        for name in ("sha256", "sha384"):
            secret, transcript = bytes(c.hash_length(name)), b"component contract"
            proof = c.finished(secret, transcript, name)
            self.assertTrue(c.verify_finished(secret, transcript, proof, name))
            self.assertFalse(c.verify_finished(secret, transcript, proof + b"x", name))


class FinishedNetworkTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.credentials, root = generate_lab_credentials("localhost")
        self.roots = [root]

    async def exchange(self, suite, mutated_sender, mutation, *, password=False):
        roles, errors, channels, writers, tasks, alerts = {}, {}, {}, [], [], {}
        accepted = asyncio.get_running_loop().create_future()
        native = listener = None
        original_send, original_fatal = hs.Wire.send_frame, hs.Wire.fatal
        if password:
            from tls20_server.openssl_provider import OpenSSLProvider
            from tls20_server.pake_native import PakeProvider
            from tls20_server.pake import PasswordAccount, PasswordCredential, PasswordServer
            native = OpenSSLProvider(os.environ["TLS20_TEST_OPENSSL"])
            provider = PakeProvider(native, os.environ["TLS20_TEST_PAKE"])
            policy = PasswordServer("localhost", provider, [PasswordAccount.provision("user", "test password")])
            credential = PasswordCredential("localhost", "user", "test password", provider)

        async def send(wire, message, state=None):
            if message[0] == 20 and roles.get(wire.writer) == mutated_sender:
                message = changed_finished(message, mutation, c.suite(suite).hash_length)
            return await original_send(wire, message, state)

        async def fatal(wire, error, state=None):
            alerts[roles[wire.writer]] = error.alert
            return await original_fatal(wire, error, state)

        async def run(role, reader, writer):
            roles[writer] = role
            writers.append(writer)
            try:
                if password:
                    channel = (await pwd.server(reader, writer, policy, cipher_suites=(suite,), timeout=3)
                               if role == "server" else
                               await pwd.client(reader, writer, credential, cipher_suites=(suite,), timeout=3))
                elif role == "server":
                    channel = await hs.server_handshake(reader, writer, self.credentials, "localhost",
                                                        cipher_suites=(suite,), timeout=3)
                else:
                    channel = await hs.client_handshake(reader, writer, "localhost", self.roots,
                        revocation_policy="lab-offline", cipher_suites=(suite,), timeout=3)
                channels[role] = channel
            except ProtocolError as error:
                errors[role] = error

        def accept(reader, writer):
            task = asyncio.create_task(run("server", reader, writer))
            tasks.append(task)
            accepted.set_result(task)

        try:
            with patch.object(hs.Wire, "send_frame", send), patch.object(hs.Wire, "fatal", fatal):
                listener = await asyncio.start_server(accept, "127.0.0.1", 0)
                reader, writer = await asyncio.open_connection("127.0.0.1", listener.sockets[0].getsockname()[1])
                tasks.append(asyncio.create_task(run("client", reader, writer)))
                await accepted
                await asyncio.wait_for(asyncio.gather(*tasks), 4)
            recipient = "client" if mutated_sender == "server" else "server"
            if mutation == "valid":
                self.assertFalse(errors)
                self.assertEqual(set(channels), {"client", "server"})
                self.assertEqual(channels["client"].exporter("finished-test"),
                                 channels["server"].exporter("finished-test"))
            else:
                expected = (20 if password and recipient == "server" else 51) if mutation == "bad_mac" else 50
                self.assertNotIn(recipient, channels)
                self.assertEqual(errors[recipient].alert, expected, str(errors[recipient]))
                self.assertEqual(alerts[recipient], expected)
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
            if native is not None:
                native.close()

    async def test_initial_finished_syntax_and_mac_in_both_directions(self):
        for suite in (0x1301, 0x1302):
            for role in ("client", "server"):
                for mutation in ("valid", "bad_mac", "other_hash", 0, 31, 33, 49):
                    with self.subTest(suite=hex(suite), sender=role, mutation=mutation):
                        await self.exchange(suite, role, mutation)

    @unittest.skipUnless(os.environ.get("TLS20_TEST_PAKE") and os.environ.get("TLS20_TEST_OPENSSL"),
                         "explicit native PAKE fixture required")
    async def test_password_finished_syntax_preserves_authentication_mask(self):
        for suite in (0xc0b0, 0xc0b1):
            for role in ("client", "server"):
                for mutation in ("valid", "bad_mac", "other_hash", 0, 31, 33, 49):
                    with self.subTest(suite=hex(suite), sender=role, mutation=mutation):
                        await self.exchange(suite, role, mutation, password=True)

    async def test_pha_finished_syntax_for_credentials_and_refusals(self):
        for suite in (0x1301, 0x1302):
            for with_credentials in (False, True):
                for mutation in ("valid", "bad_mac", "other_hash", 0, 31, 33, 49):
                    with self.subTest(suite=hex(suite), credentials=with_credentials, mutation=mutation):
                        fixture = test_client_auth.ClientAuthTests("test_optional_refusal_and_required_refusal")
                        await fixture.asyncSetUp()
                        client = None
                        try:
                            fixture.server_options["cipher_suites"] = (suite,)
                            client = await fixture.connect(post_handshake_auth=True, cipher_suites=(suite,),
                                client_credentials=fixture.client_credentials if with_credentials else None)
                            server = fixture.channels[-1]
                            send, fatal = hs.Wire.send_frame, hs.Wire.fatal
                            alerts = []
                            alert_ready = asyncio.Event()

                            async def changed(wire, frame, state=None):
                                if frame[0] == 20 and wire is client.wire:
                                    frame = changed_finished(frame, mutation, c.suite(suite).hash_length)
                                return await send(wire, frame, state)

                            async def capture(wire, error, state=None):
                                if wire is server.wire:
                                    alerts.append(error.alert)
                                    alert_ready.set()
                                return await fatal(wire, error, state)

                            with patch.object(hs.Wire, "send_frame", changed), patch.object(hs.Wire, "fatal", capture):
                                future = await server.request_client_auth(required=with_credentials)
                                await client.send(b"drive authentication")
                                self.assertEqual(await asyncio.wait_for(client.recv(), 2), b"drive authentication")
                                if mutation == "valid":
                                    result = await asyncio.wait_for(future, 2)
                                    self.assertEqual(result, tuple(fixture.client_credentials.chain_der) if with_credentials else None)
                                    self.assertFalse(alerts)
                                else:
                                    with self.assertRaises(asyncio.CancelledError):
                                        await asyncio.wait_for(future, 2)
                                    # Cleanup cancels the pending future before acquiring the alert's send lock.
                                    await asyncio.wait_for(alert_ready.wait(), 2)
                                    self.assertEqual(alerts, [51 if mutation == "bad_mac" else 50])
                        finally:
                            if client is not None:
                                client.abort()
                            await fixture.asyncTearDown()
