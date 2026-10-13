"""Version-first negotiation and nonempty ServerHello KeyShareEntry vectors."""

import asyncio
import unittest
from unittest.mock import patch

from tests import test_sessions
from tests.test_hello_syntax_alerts import hello_extensions
from tls20_server import crypto as c, messages as m
from tls20_server.errors import PeerClosed, ProtocolError
from tls20_server.handshake import Wire
from tls20_server.psk import ExternalPSK


def hello_parameters(message, *, cipher_suite=None, compression=None):
    body = bytearray(message[4:])
    reader = m._Reader(body)
    reader.take(34)
    reader.vector(1)
    if cipher_suite is not None:
        body[reader.position:reader.position + 2] = cipher_suite.to_bytes(2, 'big')
    if compression is not None:
        body[reader.position + 2] = compression
    return m.frame(2, bytes(body))


def hello_share(message, group, value):
    return hello_extensions(message, {51: group.to_bytes(2, 'big') + m._vec(value, 2)})


VERSION_ERRORS = ((None, 109), (b'', 50), (b'\x04', 50), (b'\x04\0\0', 50),
                  (b'\x03\x04', 47), (b'\x05\0', 47), (b'\xaa\xaa', 47))


class ServerHelloValidationCodecTests(unittest.TestCase):
    def hello(self, *, retry=False):
        return m.server_hello(b'' if retry else b'e' * 32, b'r' * 32, retry=retry)

    def assert_alert(self, message, alert, *, after_retry=False):
        with self.assertRaises(ProtocolError) as caught:
            m.parse_server_hello(message[4:], after_retry=after_retry)
        self.assertEqual(caught.exception.alert, alert)

    def test_empty_key_exchange_is_decode_error_for_all_suites_and_groups(self):
        # The inner vector bound applies even to unknown and GREASE groups,
        # before ordinary/PWD group-specific width and semantic validation.
        for cipher_suite in c.CIPHER_SUITES:
            for group in (*c.GROUP_LENGTHS, 0xfeff, 0xaaaa):
                with self.subTest(suite=cipher_suite, group=group):
                    message = hello_parameters(self.hello(), cipher_suite=cipher_suite)
                    self.assert_alert(hello_share(message, group, b''), 50)

    def test_nonempty_wrong_width_and_unknown_group_are_illegal_parameter(self):
        for group in (29, 23, 0xfeff, 0xaaaa):
            with self.subTest(group=group):
                self.assert_alert(hello_share(self.hello(), group, b'x'), 47)
        # An empty key-share vector is not the same as a missing optional
        # key_share in a legal PSK-only ServerHello.
        psk_only = m.server_hello(b'', b'r' * 32, group=0, resumed=True)
        self.assertEqual(m.parse_server_hello(psk_only[4:], details=True)[:4],
                         (b'', b'', True, 0))
        self.assertEqual(m.parse_server_hello(self.hello()[4:]), b'e' * 32)

    def test_retry_selected_group_is_not_a_key_exchange_vector(self):
        retry = self.hello(retry=True)
        self.assertEqual(m.parse_server_hello(retry[4:], details=True)[3:5], (29, True))
        self.assert_alert(hello_share(retry, 29, b''), 50)
        cookie_only = m.server_hello(b'', b'r' * 32, group=0, retry=True, cookie=b'cookie')
        self.assertEqual(m.parse_server_hello(cookie_only[4:], details=True)[3:6],
                         (0, True, b'cookie'))

    def test_version_selection_precedes_suite_compression_and_share_validation(self):
        for retry, after_retry in ((False, False), (True, False), (False, True)):
            for version, alert in VERSION_ERRORS:
                for suite, compression in ((0x1301, 0), (0xffff, 0), (0x1301, 1), (0xffff, 1)):
                    with self.subTest(retry=retry, after_retry=after_retry, version=version,
                                      suite=suite, compression=compression):
                        message = hello_parameters(self.hello(retry=retry),
                            cipher_suite=suite, compression=compression)
                        message = hello_extensions(message, {43: version, 51: b''})
                        self.assert_alert(message, alert, after_retry=after_retry)

    def test_version_selection_precedes_other_extension_semantics(self):
        for retry in (False, True):
            for version, alert in VERSION_ERRORS:
                for kind in (0, 0xfeff):  # Known wrong context and unknown response.
                    with self.subTest(retry=retry, version=version, kind=kind):
                        message = hello_extensions(self.hello(retry=retry), {43: version, kind: b''})
                        self.assert_alert(message, alert)

    def test_valid_version_does_not_disable_other_validation(self):
        for retry in (False, True):
            message = self.hello(retry=retry)
            m.parse_server_hello(message[4:])
            for suite, compression in ((0xffff, 0), (0x1301, 1), (0xffff, 1)):
                with self.subTest(retry=retry, suite=suite, compression=compression):
                    self.assert_alert(hello_parameters(message, cipher_suite=suite, compression=compression), 47)
            self.assert_alert(hello_extensions(message, {0: b''}), 47)
            self.assert_alert(hello_extensions(message, {0xfeff: b''}), 110)
            self.assert_alert(hello_extensions(message, {51: b''}), 50)

    def test_structural_legacy_and_second_retry_guards_remain(self):
        for retry in (False, True):
            message = hello_parameters(self.hello(retry=retry), cipher_suite=0xffff, compression=1)
            message = hello_extensions(message, {43: None})
            body = message[4:]
            self.assert_alert(m.frame(2, b'\x04\0' + body[2:]), 70)
            self.assert_alert(m.frame(2, body[:34] + b'\x21' + b's' * 33 + body[35:]), 50)
            # Decode the complete framing before considering extension values.
            self.assert_alert(m.frame(2, body[:-1]), 50)
            self.assert_alert(m.frame(2, body + b'\0'), 50)
        for version, _ in VERSION_ERRORS:
            repeated = hello_extensions(self.hello(retry=True), {43: version})
            repeated = hello_parameters(repeated, cipher_suite=0xffff, compression=1)
            self.assert_alert(repeated, 10, after_retry=True)


class ServerHelloValidationWireTests(unittest.IsolatedAsyncioTestCase):
    asyncSetUp = test_sessions.SessionTests.asyncSetUp
    asyncTearDown = test_sessions.SessionTests.asyncTearDown
    accept = test_sessions.SessionTests.accept
    handle = test_sessions.SessionTests.handle
    connect = test_sessions.SessionTests.connect

    async def reject_server_message(self, mutate, alert, *, stage):
        original, fatal = m.server_hello, Wire.fatal
        alerts, hellos, injected = [], [], []

        def encode(*args, **kwargs):
            message = original(*args, **kwargs)
            retry = bool(kwargs.get('retry'))
            if retry == (stage == 'retry'):
                message = mutate(message)
                injected.append(message)
            hellos.append(retry)
            return message

        async def observe(wire, error, state=None):
            if wire.writer in self.client_writers and not isinstance(error, PeerClosed):
                alerts.append((wire.writer in self.client_writers, error.alert))
            return await fatal(wire, error, state)

        self.cache._tickets.clear()
        self.errors.clear()
        before = len(self.channels)
        with patch.object(m, 'server_hello', encode), patch.object(Wire, 'fatal', observe):
            with self.assertRaises(ProtocolError) as caught:
                await asyncio.wait_for(self.connect(force_retry=stage != 'initial'), 3)
            # Finish this peer's rejection before the next injection. The
            # server may already be in an encrypted epoch when our mutated
            # ServerHello makes the client reject it in the clear epoch.
            await asyncio.wait_for(asyncio.gather(*tuple(self.tasks)), 3)
        self.assertEqual(caught.exception.alert, alert)
        self.assertEqual(alerts, [(True, alert)])  # The reference client emits it.
        self.assertEqual(len(self.channels), before)
        self.assertEqual(len(injected), 1)
        self.assertEqual(hellos, [True, False] if stage == 'after-retry'
                         else [stage == 'retry'])

    async def test_empty_exchange_rejected_on_initial_and_post_retry_server_hello(self):
        for stage in ('initial', 'after-retry'):
            for group in (29, 0xfeff, 0xaaaa):
                with self.subTest(stage=stage, group=group):
                    await self.reject_server_message(lambda message: hello_share(message, group, b''),
                                                     50, stage=stage)

    async def test_version_errors_emitted_before_other_negotiated_parameters(self):
        for stage in ('initial', 'retry', 'after-retry'):
            for version, alert in VERSION_ERRORS:
                for suite, compression in ((0xffff, 0), (0x1301, 1)):
                    with self.subTest(stage=stage, version=version, suite=suite, compression=compression):
                        def mutate(message):
                            return hello_extensions(hello_parameters(message, cipher_suite=suite,
                                compression=compression), {43: version})
                        await self.reject_server_message(mutate, alert, stage=stage)

    async def test_valid_version_preserves_other_wire_rejections(self):
        for stage in ('initial', 'retry', 'after-retry'):
            for suite, compression in ((0xffff, 0), (0x1301, 1)):
                with self.subTest(stage=stage, suite=suite, compression=compression):
                    await self.reject_server_message(lambda message: hello_parameters(message,
                        cipher_suite=suite, compression=compression), 47, stage=stage)
        for stage in ('initial', 'after-retry'):
            await self.reject_server_message(lambda message: hello_share(message, 29, b'x'),
                                             47, stage=stage)

    async def test_full_retry_resumed_and_psk_only_exchanges_remain_authenticated(self):
        for retry in (False, True):
            self.cache._tickets.clear()
            full = await asyncio.wait_for(self.connect(force_retry=retry), 3)
            self.assertFalse(full.resumed)
            await full.send(b'full authenticated')
            self.assertEqual(await full.recv(), b'full authenticated')
            await full.close()
            resumed = await asyncio.wait_for(self.connect(), 3)
            self.assertTrue(resumed.resumed)
            await resumed.send(b'resumed authenticated')
            self.assertEqual(await resumed.recv(), b'resumed authenticated')
            await resumed.close()
        self.cache._tickets.clear()
        psk = ExternalPSK(b'parser regression', b'public fixture-only PSK material', 'localhost')
        self.server_options = {'external_psks': (psk,)}
        channel = await asyncio.wait_for(self.connect(external_psk=psk, psk_modes=(0,)), 3)
        await channel.send(b'PSK-only needs no server key share')
        self.assertEqual(await channel.recv(), b'PSK-only needs no server key share')
        await channel.close()
        self.assertFalse(self.errors)


if __name__ == '__main__':
    unittest.main()
