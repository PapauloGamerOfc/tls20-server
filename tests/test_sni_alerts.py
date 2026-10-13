"""SNI syntax, semantic errors and service policy have distinct peer alerts."""

import asyncio
import unittest
from unittest.mock import patch

from tls20_server import handshake as hs, messages as m
from tls20_server.errors import PeerClosed, ProtocolError
from tls20_server.lab import generate_lab_credentials
from tls20_server.secret_lifecycle import HandshakeSecrets


def name(value, kind=0):
    return bytes((kind,)) + m._vec(value, 2)


def invalid_offers():
    one = name(b"localhost")
    yield "empty-list", b"\0\0", 50
    yield "empty-host", m._vec(name(b""), 2), 50
    yield "truncated-host", m._vec(one[:-1], 2), 50
    yield "truncated-name-vector", m._vec(b"\0\0", 2), 50
    yield "trailing-outer", m._vec(one, 2) + b"x", 50
    yield "duplicate-host", m._vec(one + one, 2), 47
    yield "duplicate-different-host", m._vec(one + name(b"other.test"), 2), 47
    yield "duplicate-truncated", m._vec(one + one[:-1], 2), 50
    yield "duplicate-empty", m._vec(one + name(b""), 2), 50
    yield "unsupported-type", m._vec(name(b"opaque", 1), 2), 47
    yield "unsupported-after-host", m._vec(one + name(b"opaque", 1), 2), 47
    yield "unsupported-truncated", m._vec(one + name(b"opaque", 1)[:-1], 2), 50
    for value in (b"localhost.", b"a..b", b"-a", b"a_", b"a\0b", b"a\xffb",
                  b"127.0.0.1", b"::1", b"xn--.test", b"a" * 64 + b".test"):
        yield repr(value), m._vec(name(value), 2), 47


class SNIParserTests(unittest.TestCase):
    def test_wire_syntax_semantics_and_configuration_are_separate(self):
        for offered, expected in ((b"localhost", "localhost"), (b"LOCALHOST", "localhost"),
                                  (b"XN--BCHER-KVA.TeSt", "xn--bcher-kva.test")):
            self.assertEqual(m.parse_server_name(m._vec(name(offered), 2)), expected)
        for label, offer, expected in invalid_offers():
            with self.subTest(case=label):
                with self.assertRaises(ProtocolError) as caught:
                    m.parse_server_name(offer)
                self.assertEqual(caught.exception.alert, expected, label)
        # A wire parser must not change shared local configuration validation.
        for invalid in ("", "a..b", "localhost.", "127.0.0.1"):
            with self.subTest(configuration=invalid), self.assertRaises(ProtocolError) as caught:
                m.validate_name(invalid)
            self.assertEqual(caught.exception.alert, 40)


class SNIWireAlertTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.credentials, root = generate_lab_credentials("localhost")
        self.roots = [root]

    async def exchange(self, offer, expected, *, suite=0x1301):
        channels, errors, roles, scopes = {}, {}, {}, []
        writers, tasks, alerts, server_frames = [], [], [], []
        listener = None
        accepted = asyncio.get_running_loop().create_future()
        builder, process, send = m.client_hello, hs.Wire.process_alert, hs.Wire.send_frame
        scope_init = HandshakeSecrets.__init__

        def hello(*args, **kwargs):
            message = builder(*args, **kwargs)
            parsed = m.parse_client_hello(message[4:])
            extension_data = b"".join(m.extension(kind, offer if kind == 0 else value)
                for kind, value in parsed.extension_values if kind != 0 or offer is not None)
            return m.frame(1, parsed.fixed_hello + m._vec(extension_data, 2))

        def observe(wire, content):
            alerts.append((roles[wire.writer], bytes(content)))
            return process(wire, content)

        async def emitted(wire, message, state=None):
            if roles[wire.writer] == "server":
                server_frames.append(message[0])
            return await send(wire, message, state)

        def init(scope):
            scope_init(scope)
            scopes.append(scope)

        async def run(role, reader, writer):
            roles[writer] = role
            writers.append(writer)
            try:
                if role == "server":
                    channel = await hs.server_handshake(reader, writer, self.credentials, "localhost",
                        require_server_name=offer is not None, cipher_suites=(suite,), timeout=3)
                else:
                    channel = await hs.client_handshake(reader, writer, "localhost", self.roots,
                        send_server_name=offer is not None, cipher_suites=(suite,),
                        revocation_policy="lab-offline", timeout=3)
                channels[role] = channel
            except ProtocolError as error:
                errors[role] = error

        def accept(reader, writer):
            task = asyncio.create_task(run("server", reader, writer))
            tasks.append(task)
            accepted.set_result(task)

        try:
            with patch.object(m, "client_hello", hello), patch.object(hs.Wire, "process_alert", observe), \
                    patch.object(hs.Wire, "send_frame", emitted), \
                    patch.object(HandshakeSecrets, "__init__", init):
                listener = await asyncio.start_server(accept, "127.0.0.1", 0)
                reader, writer = await asyncio.open_connection("127.0.0.1", listener.sockets[0].getsockname()[1])
                tasks.append(asyncio.create_task(run("client", reader, writer)))
                await accepted
                await asyncio.wait_for(asyncio.gather(*tasks), 4)
            if expected is None:
                self.assertFalse(errors)
                self.assertEqual(set(channels), {"client", "server"})
                self.assertTrue(channels["client"].peer_authenticated)
                self.assertEqual(channels["client"].exporter("sni-control"),
                                 channels["server"].exporter("sni-control"))
                await channels["server"].send(b"sni control")
                self.assertEqual(await channels["client"].recv(), b"sni control")
                self.assertFalse(alerts)
            else:
                self.assertFalse(channels)
                self.assertFalse(server_frames)  # Rejected before credentials or traffic keys.
                self.assertEqual(set(errors), {"client", "server"})
                self.assertEqual(errors["server"].alert, expected)
                self.assertIsInstance(errors["client"], PeerClosed)
                self.assertEqual(errors["client"].alert, expected)
                self.assertEqual(alerts, [("client", bytes((2, expected)))])
                self.assertTrue(all(not scope.keys and not scope.records and scope.channel is None
                                    for scope in scopes))
                for error in errors.values():
                    trace = error.__traceback__
                    while trace is not None:
                        if trace.tb_frame.f_code.co_name in ("client_handshake", "server_handshake"):
                            self.assertFalse(trace.tb_frame.f_locals)
                        trace = trace.tb_next
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

    async def test_valid_absent_unknown_and_invalid_sni_alerts(self):
        for suite in (0x1301, 0x1302):
            for offer in (None, m._vec(name(b"localhost"), 2), m._vec(name(b"LOCALHOST"), 2)):
                with self.subTest(suite=suite, positive=offer):
                    await self.exchange(offer, None, suite=suite)
        await self.exchange(m._vec(name(b"other.test"), 2), 112)
        for label, offer, expected in invalid_offers():
            with self.subTest(case=label):
                await self.exchange(offer, expected)


if __name__ == "__main__":
    unittest.main()
