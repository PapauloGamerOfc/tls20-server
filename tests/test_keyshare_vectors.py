"""KeyShareEntry is nonempty even when its group is unknown to this peer."""

import asyncio
import unittest
from unittest.mock import patch

from tests import test_sessions
from tls20_server import crypto as c, messages as m
from tls20_server.errors import PeerClosed, ProtocolError
from tls20_server.handshake import Wire
from tls20_server.psk import ExternalPSK


UNKNOWN_GROUPS = (0xfeff, 0xaaaa)  # Unassigned and GREASE, respectively.


def append_share(message, group, value):
    body = message[4:]
    reader = m._Reader(body)
    reader.take(34)
    reader.vector(1)
    reader.vector(2)
    reader.vector(1)
    fixed = body[:reader.position]
    extensions = m.extensions(reader.vector(2))
    reader.end()
    groups = m._u16_list(extensions[10])
    if group not in groups:
        extensions[10] = m._vec(extensions[10][2:] + group.to_bytes(2, 'big'), 2)
    extensions[51] = m._vec(extensions[51][2:] + group.to_bytes(2, 'big')
                            + m._vec(value, 2), 2)
    return m.frame(1, fixed + m._vec(b''.join(m.extension(kind, data)
        for kind, data in extensions.items()), 2))


class KeyShareVectorCodecTests(unittest.TestCase):
    def hello(self, **options):
        return m.client_hello(b'a' * 32, b'b' * 32, 'localhost', b'r' * 32, **options)

    def test_empty_entry_is_a_decode_error_for_known_unknown_and_grease_groups(self):
        for group in (*c.GROUP_LENGTHS, *UNKNOWN_GROUPS):
            with self.subTest(group=group):
                with self.assertRaises(ProtocolError) as caught:
                    m.parse_client_hello(append_share(self.hello(), group, b'')[4:])
                self.assertEqual(caught.exception.alert, 50)

    def test_unknown_nonempty_entries_are_ignored_without_changing_the_selected_share(self):
        baseline = m.parse_client_hello(self.hello()[4:])
        for group in UNKNOWN_GROUPS:
            for value in (b'x', b'unknown group encoding'):
                with self.subTest(group=group, value=value):
                    parsed = m.parse_client_hello(append_share(self.hello(), group, value)[4:])
                    self.assertEqual(parsed.group, baseline.group)
                    self.assertEqual(parsed.B, baseline.B)

    def test_nonempty_known_wrong_width_still_is_illegal_parameter(self):
        with self.assertRaises(ProtocolError) as caught:
            m.parse_client_hello(append_share(self.hello(), 23, b'x')[4:])
        self.assertEqual(caught.exception.alert, 47)

    def test_entire_empty_share_list_remains_legal_for_retry_and_psk_ke(self):
        for psk in (False, True):
            with self.subTest(psk=psk):
                options = dict(empty_share=True)
                if psk:
                    options.update(identity=b'public fixture', binder=b'x' * 32, psk_modes=(0,))
                parsed = m.parse_client_hello(self.hello(**options)[4:])
                self.assertEqual(dict(parsed.extension_values)[51], b'\0\0')
                self.assertEqual(parsed.B, b'')


class KeyShareVectorWireTests(unittest.IsolatedAsyncioTestCase):
    asyncSetUp = test_sessions.SessionTests.asyncSetUp
    asyncTearDown = test_sessions.SessionTests.asyncTearDown
    accept = test_sessions.SessionTests.accept
    handle = test_sessions.SessionTests.handle
    connect = test_sessions.SessionTests.connect

    async def reject_empty_entry(self, group, *, retry):
        original, fatal = m.client_hello, Wire.fatal
        alerts, hellos = [], []

        def encode(*args, **kwargs):
            message = original(*args, **kwargs)
            # With retry, preserve legal empty CH1 and corrupt only CH2.
            if not kwargs.get('empty_share'):
                message = append_share(message, group, b'')
            hellos.append(message)
            return message

        async def observe(wire, error, state=None):
            if not isinstance(error, PeerClosed):
                alerts.append((wire.writer in self.client_writers, error.alert))
            return await fatal(wire, error, state)

        self.cache._tickets.clear()
        self.errors.clear()
        before = len(self.channels)
        with patch.object(m, 'client_hello', encode), patch.object(Wire, 'fatal', observe):
            with self.assertRaises(ProtocolError) as caught:
                await asyncio.wait_for(self.connect(force_retry=retry), 3)
        self.assertEqual(caught.exception.alert, 50)
        self.assertEqual(alerts, [(False, 50)])  # The server emitted the fatal alert.
        self.assertEqual(len(self.channels), before)
        self.assertEqual(len(hellos), 2 if retry else 1)

    async def test_initial_empty_entry_rejected_before_application_traffic(self):
        for group in (23, *UNKNOWN_GROUPS):
            with self.subTest(group=group):
                await self.reject_empty_entry(group, retry=False)

    async def test_retry_empty_entry_rejected_before_application_traffic(self):
        for group in (23, *UNKNOWN_GROUPS):
            with self.subTest(group=group):
                await self.reject_empty_entry(group, retry=True)

    async def test_unknown_nonempty_entries_allow_an_authenticated_exchange(self):
        original = m.client_hello
        for group in UNKNOWN_GROUPS:
            def encode(*args, **kwargs):
                return append_share(original(*args, **kwargs), group, b'x')
            with self.subTest(group=group), patch.object(m, 'client_hello', encode):
                self.cache._tickets.clear()
                channel = await asyncio.wait_for(self.connect(), 3)
                await channel.send(b'unknown group is ignored')
                self.assertEqual(await channel.recv(), b'unknown group is ignored')
                await channel.close()
        self.assertFalse(self.errors)

    async def test_empty_list_completes_retry_and_psk_only_connections(self):
        channel = await asyncio.wait_for(self.connect(force_retry=True), 3)
        await channel.send(b'empty list caused retry')
        self.assertEqual(await channel.recv(), b'empty list caused retry')
        await channel.close()
        self.cache._tickets.clear()
        key = ExternalPSK(b'empty share list', b'public fixture-only PSK material', 'localhost')
        self.server_options = {'external_psks': (key,)}
        channel = await asyncio.wait_for(self.connect(external_psk=key, psk_modes=(0,),
            certificate_evidence_extensions=((10, b'\0\2\0\x1d'), (51, b'\0\0'))), 3)
        self.assertEqual(dict(channel.local_capabilities)[51], b'\0\0')
        await channel.send(b'empty list with PSK-only')
        self.assertEqual(await channel.recv(), b'empty list with PSK-only')
        await channel.close()
        self.assertFalse(self.errors)


if __name__ == '__main__':
    unittest.main()
