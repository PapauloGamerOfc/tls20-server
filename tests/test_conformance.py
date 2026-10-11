"""Wire-level regressions for extension placement, exact alerts and HRR cookies."""
import asyncio
import unittest
from unittest.mock import patch

from tls20_server import crypto as c, messages as m
from tls20_server.client import parse_url
from tls20_server.errors import ConfigurationError, ProtocolError
from tls20_server.handshake import Wire
from tls20_server.retry_cookie import RetryCookiePolicy
from tests import test_sessions


def replace_extensions(message, update):
    hello = m.parse_client_hello(message[4:])
    values = dict(hello.extension_values)
    update(values)
    return m.frame(1, hello.fixed_hello + m._vec(b"".join(m.extension(k, v) for k, v in values.items()), 2))


class CodecConformanceTests(unittest.TestCase):
    def assert_alert(self, alert, function, *args, **kwargs):
        with self.assertRaises(ProtocolError) as raised:
            function(*args, **kwargs)
        self.assertEqual(raised.exception.alert, alert)

    def test_certificate_request_placements_and_delegation_lists(self):
        for kind in (0, 1, 10, 15, 16, 19, 20, 21, 25, 28, 29, 30, 31, 32,
                     33, 41, 42, 43, 44, 45, 49, 51, 55, 56, 58, 59, 0xff02):
            request = m.certificate_request(b"", bytes(32), extra_extensions=((kind, b""),))
            self.assert_alert(47, m.parse_certificate_request, request[4:])
        for pairs, expected in ((((34, b"\x00\x02\xfe\x01"),), 109),
                                 (((0xff04, b"\x00\x02\x08\x07"),), 47),
                                 (((34, b"\x00\x02\xfe\x01"), (0xff04, b"\x00\x00")), 50),
                                 (((34, b"\x00\x02\xfe\x01"), (0xff04, b"\x00\x02\xfe\x00")), 47)):
            request = m.certificate_request(b"", bytes(32), extra_extensions=pairs)
            self.assert_alert(expected, m.parse_certificate_request, request[4:])
        # Unknown extensions are not forbidden; grant and path offers need not match.
        request = m.certificate_request(b"", bytes(32), algorithms=(0x0403,), extra_extensions=(
            (34, b"\x00\x02\xfe\x01"), (0xff04, b"\x00\x02\x08\x07"), (0xabab, b"x")))
        self.assertEqual(m.parse_certificate_request(request[4:])[2], (0x0403,))

    def test_version_alerts_and_unknown_offers(self):
        hello = m.client_hello(bytes(32), bytes([1]) * 32, "localhost", bytes(32))
        for value, expected in ((None, 109), (b"\x02\x03\x04", 70),
                                (b"\x00", 50), (b"\x01\x04", 50), (b"\x02\x04", 50)):
            changed = replace_extensions(hello, lambda ext: ext.pop(43) if value is None else ext.update({43: value}))
            self.assert_alert(expected, m.parse_client_hello, changed[4:])
        changed = replace_extensions(hello, lambda ext: ext.update({0xabab: b"x"}))
        m.parse_client_hello(changed[4:])
        cert = m.certificate([b"parser fixture"], entry_extensions=(((43, m.VERSION),),))
        self.assert_alert(47, m.parse_certificate, cert[4:])
        self.assert_alert(47, m.parse_certificate, cert[4:], details=True)

    def test_cached_and_application_requests_use_same_placement_rules(self):
        from tls20_server.application_auth import parse_request
        from tls20_server.credential_cache import cached_request_body
        from tls20_server.handshake import _decode_request, _request_extension_block
        request = m.certificate_request(b"scope", bytes(32), extra_extensions=((43, m.VERSION),))
        block = _request_extension_block(request)
        reference = m.frame(252, cached_request_body(b"scope", block, bytes(32)))
        self.assert_alert(47, _decode_request, reference, cache_enabled=True, templates=(block,))
        for role, kind, share in (("server", 17, 0xff02), ("client", 13, 0xff03)):
            for extra, alert in ((((43, m.VERSION),), 47), (((34, b"\x00\x02\xfe\x00"),), 109),
                                 (((0xff04, b"\x00\x02\x08\x07"),), 47)):
                pairs = ((50, b"\x00\x02\x08\x07"), (share, bytes(32)), *extra)
                body = m._vec(b"scope", 1) + m._vec(b"".join(m.extension(k, v) for k, v in pairs), 2)
                wire = bytes([kind]) + len(body).to_bytes(3, "big") + body
                with self.subTest(role=role, extra=extra):
                    self.assert_alert(alert, parse_request, wire)

    def test_server_legacy_version_distinct_from_selected_version_alert(self):
        for retry in (False, True):
            hello = m.server_hello(bytes([7]) * 32, bytes(32), group=29, retry=retry)
            with self.subTest(retry=retry):
                self.assert_alert(70, m.parse_server_hello, b"\x04\x00" + hello[6:])
                # A well-framed but unsupported supported_versions selection
                # remains illegal_parameter, not protocol_version.
                body = hello[4:].replace(m.extension(43, m.VERSION), m.extension(43, b"\x03\x04"))
                self.assert_alert(47, m.parse_server_hello, body)

    def test_url_full_authority_is_checked_independently_of_python_version(self):
        for value in ("[::1]tail", "[::1]:", "[::1]:+343", "[::1]:٣٤٣", "[::1]:343:1",
                      "[::1]@host", "[127.0.0.1]", "host:", "host:+343", "host:٣٤٣"):
            with self.subTest(authority=value), self.assertRaises(ConfigurationError):
                parse_url("httpps://" + value + "/")
        self.assertEqual(parse_url("httpps://[::1]:343/"), ("::1", 343, "/"))

    def test_cookie_authentication_expiry_context_and_bounded_encoding(self):
        class Peer:
            def __init__(self, ip="127.0.0.1"): self.ip = ip
            def get_extra_info(self, name): return (self.ip, 10000)
        now = [100.0]
        policy = RetryCookiePolicy(clock=lambda: now[0])
        cookie = policy.issue(Peer(), b"first hello", 0x1301, 29)
        self.assertEqual(len(cookie), 57)
        policy.verify(cookie, Peer(), b"first hello", 0x1301, 29)
        for changed, peer, hello, suite, group in (
            (cookie[:-1], Peer(), b"first hello", 0x1301, 29),
            (cookie[:-1] + bytes([cookie[-1] ^ 1]), Peer(), b"first hello", 0x1301, 29),
            (cookie, Peer("127.0.0.2"), b"first hello", 0x1301, 29),
            (cookie, Peer(), b"other hello", 0x1301, 29),
            (cookie, Peer(), b"first hello", 0x1302, 29),
            (cookie, Peer(), b"first hello", 0x1301, 23)):
            self.assert_alert(47, policy.verify, changed, peer, hello, suite, group)
        now[0] = 131
        self.assert_alert(47, policy.verify, cookie, Peer(), b"first hello", 0x1301, 29)

    def test_cookie_configuration_is_strict_and_disabled_by_default(self):
        from tls20_server.config import Config, ConfigError
        self.assertFalse(Config().retry_cookie)
        for kwargs in ({"retry_cookie": 1}, {"retry_cookie_lifetime_seconds": 0},
                       {"retry_cookie_lifetime_seconds": 301}, {"retry_cookie_lifetime_seconds": True}):
            with self.assertRaises(ConfigError):
                Config(**kwargs)


class WireConformanceTests(unittest.IsolatedAsyncioTestCase):
    # Reuse only the loopback fixture, not the inherited test collection.
    asyncSetUp = test_sessions.SessionTests.asyncSetUp
    asyncTearDown = test_sessions.SessionTests.asyncTearDown
    accept = test_sessions.SessionTests.accept
    handle = test_sessions.SessionTests.handle
    connect = test_sessions.SessionTests.connect

    async def test_invalid_offers_produce_exact_wire_alert_even_with_normal_credentials(self):
        hello = m.client_hello(bytes(32), bytes([1]) * 32, "localhost", bytes(32))
        mutations = (({34: b"\x00\x02\xfe\x00"}, None, 109),
                     ({0xff04: b"\x00\x02\x08\x07"}, None, 47),
                     ({34: b"\x00\x02\xfe\x00", 0xff04: b"\x00\x02\x08\x07"}, 50, 109),
                     ({34: b"\x00\x02\xfe\x00", 0xff04: b"\x00\x00"}, None, 50),
                     ({43: b"\x02\x03\x04"}, None, 70), ({43: b"\x01\x04"}, None, 50),
                     ({}, 43, 109), ({48: b"\x00\x00"}, None, 47))
        for values, remove, alert in mutations:
            def mutate(ext):
                ext.update(values)
                if remove is not None: ext.pop(remove)
            changed = replace_extensions(hello, mutate)
            reader, writer = await asyncio.open_connection("127.0.0.1", self.port)
            self.writers.append(writer)
            writer.write(c.PREFACE); await writer.drain()
            wire = Wire(reader, writer)
            await wire.send_frame(changed)
            self.assertEqual(await asyncio.wait_for(wire.raw_record(), 2), b"\x15\x03\x03\x00\x02\x02" + bytes([alert]))
            writer.close()
        self.assertFalse(self.channels)

    async def test_cookie_only_group_cookie_resume_early_and_psk_only(self):
        self.server_options["retry_cookie_policy"] = RetryCookiePolicy()
        for options in ({}, {"force_retry": True}, {"early_data": b"must reject"}, {"psk_modes": (0,)}):
            channel = await self.connect(**options)
            self.assertFalse(channel.early_data_accepted)
            await channel.send(b"cookie works")
            self.assertEqual(await channel.recv(), b"cookie works")
        self.assertFalse(self.early)
        self.assertFalse(self.errors)

    async def test_server_legacy_version_alert_on_full_and_retry_wire(self):
        original = Wire.send_frame
        for retry in (False, True):
            self.server_options["retry_cookie_policy"] = RetryCookiePolicy() if retry else None
            alerts = []
            original_alert = Wire.fatal

            async def send(wire, message, state=None):
                if message[0] == 2:
                    self.assertEqual(message[6:38] == m.HRR_RANDOM, retry)
                    message = message[:4] + b"\x04\x00" + message[6:]
                return await original(wire, message, state)

            async def alert(wire, error, state=None):
                alerts.append(error.alert)
                return await original_alert(wire, error, state)

            with self.subTest(retry=retry), patch.object(Wire, "send_frame", send), \
                    patch.object(Wire, "fatal", alert), self.assertRaises(ProtocolError) as raised:
                await self.connect()
            self.assertEqual(raised.exception.alert, 70)
            self.assertIn(70, alerts)
        self.assertFalse(self.channels)

    async def test_selected_external_psk_binder_cannot_disappear_during_cookie_retry(self):
        from tls20_server.psk import ExternalPSK
        key = ExternalPSK(b"known", b"a" * 32, "localhost")
        self.server_options.update(external_psks=(key,), retry_cookie_policy=RetryCookiePolicy())
        for length, remove in ((48, False), (32, False), (32, True)):
            with self.subTest(length=length, remove=remove):
                options = dict(identity=key.identity, binder=bytes(length))
                hello = m.client_hello(bytes([2]) * 32, bytes([1]) * 32, "localhost", bytes(32), **options)
                reader, writer = await asyncio.open_connection("127.0.0.1", self.port)
                self.writers.append(writer)
                writer.write(c.PREFACE); await writer.drain()
                wire = Wire(reader, writer)
                await wire.send_frame(hello)
                if length == 32:
                    retry = await asyncio.wait_for(wire.receive_frame(2), 2)
                    cookie = m.parse_server_hello(retry[4:], details=True)[5]
                    if remove: options = {}
                    second = m.client_hello(bytes([2]) * 32, bytes([1]) * 32, "localhost", bytes(32),
                                            cookie=cookie, **options)
                    await wire.send_frame(second)
                expected = 47 if remove else 51
                self.assertEqual(await asyncio.wait_for(wire.raw_record(), 2),
                                 b"\x15\x03\x03\x00\x02\x02" + bytes([expected]))
                writer.close()
        self.assertFalse(self.channels)

    async def test_invalid_delegation_offer_rejected_before_resumption_binder(self):
        await self.connect()
        self.assertTrue(self.cache._tickets)
        original = Wire.send_frame
        async def send(wire, message, state=None):
            if message[0] == 1:
                self.assertTrue(m.parse_client_hello(message[4:]).psk_offers)
                # Preserve PSK as the final extension. Even an invalid binder
                # does not hide the prior syntactic/capability failure.
                def mutate(ext):
                    psk = ext.pop(41)
                    ext[34] = b"\x00\x02\xfe\x00"
                    ext[41] = psk
                message = replace_extensions(message, mutate)
            return await original(wire, message, state)
        with patch.object(Wire, "send_frame", send), self.assertRaises(ProtocolError) as raised:
            await self.connect()
        self.assertEqual(raised.exception.alert, 109)
        self.assertEqual(len(self.channels), 1)

    async def test_missing_changed_expired_cookie_and_changed_cookie_only_share_fail(self):
        for mode in ("missing", "changed", "expired", "share"):
            now = [100.0]
            self.server_options["retry_cookie_policy"] = RetryCookiePolicy(clock=lambda: now[0])
            original = Wire.send_frame
            count = 0
            async def send(wire, message, state=None):
                nonlocal count
                if message[0] == 1:
                    count += 1
                    if count == 2:
                        def mutate(ext):
                            if mode == "missing": ext.pop(44)
                            elif mode == "changed": ext[44] = ext[44][:-1] + bytes([ext[44][-1] ^ 1])
                            elif mode == "share": ext[51] = ext[51][:-1] + bytes([ext[51][-1] ^ 1])
                            else: now[0] = 131
                        message = replace_extensions(message, mutate)
                return await original(wire, message, state)
            with patch.object(Wire, "send_frame", send), self.assertRaises(ProtocolError):
                await self.connect()
        self.assertFalse(self.channels)

    async def test_initial_certificate_request_wrong_context_rejected_on_real_wire(self):
        self.server_options["client_auth_validator"] = lambda chain: None
        original = m.certificate_request
        def invalid(*args, **kwargs):
            kwargs["extra_extensions"] = tuple(kwargs.get("extra_extensions", ())) + ((43, m.VERSION),)
            return original(*args, **kwargs)
        with patch.object(m, "certificate_request", invalid), self.assertRaises(ProtocolError) as raised:
            await self.connect()
        self.assertEqual(raised.exception.alert, 47)
        self.assertFalse(self.channels)

    async def test_user_canceled_during_handshake_is_advisory(self):
        original = Wire.send_frame
        async def send(wire, message, state=None):
            if message[0] == 1:
                wire.writer.write(b"\x15\x03\x03\x00\x02\x01\x5a")
            return await original(wire, message, state)
        self.server_options["retry_cookie_policy"] = RetryCookiePolicy()
        with patch.object(Wire, "send_frame", send):
            channel = await self.connect()
        await channel.send(b"not fatal")
        self.assertEqual(await channel.recv(), b"not fatal")
        self.assertFalse(self.errors)

    async def test_user_canceled_then_close_does_not_trigger_fatal_response(self):
        reader, writer = await asyncio.open_connection("127.0.0.1", self.port)
        self.writers.append(writer)
        writer.write(c.PREFACE + b"\x15\x03\x03\x00\x02\x01\x5a"
                     + b"\x15\x03\x03\x00\x02\x01\x00")
        await writer.drain()
        self.assertEqual(await asyncio.wait_for(reader.read(), 2), b"")
        self.assertFalse(self.channels)

    async def test_pha_wrong_context_rejected_before_client_identity_response(self):
        self.server_options["client_auth_validator"] = lambda chain: None
        client = await self.connect(post_handshake_auth=True)
        server = self.channels[-1]
        invalid = m.certificate_request(b"pha-context", bytes([7]) * 32, extra_extensions=((43, m.VERSION),))
        await server.send_handshake(invalid)
        with self.assertRaises(ProtocolError) as raised:
            await asyncio.wait_for(client.recv(), 2)
        self.assertEqual(raised.exception.alert, 47)
        self.assertIsNone(server.authenticated_client)
