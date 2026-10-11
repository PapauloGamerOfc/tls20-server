import unittest
from unittest.mock import patch

from tls20_server import crypto as c, messages as m
from tls20_server.errors import ProtocolError
from tls20_server.psk import ExternalPSK
from tests import test_sessions


class GenericHandshakeTests(unittest.IsolatedAsyncioTestCase):
    asyncSetUp = test_sessions.SessionTests.asyncSetUp
    asyncTearDown = test_sessions.SessionTests.asyncTearDown
    accept = test_sessions.SessionTests.accept
    handle = test_sessions.SessionTests.handle
    connect = test_sessions.SessionTests.connect

    async def test_malformed_authorities_vector_sends_decode_error(self):
        for value in (b"", b"\0", b"\0\0", b"\0\3\0\1", b"\0\4\0\2\x31\0"):
            with self.subTest(value=value), self.assertRaises(ProtocolError) as caught:
                await self.connect(certificate_evidence_extensions=((47, value),))
            self.assertEqual(caught.exception.alert, 50)
        self.assertFalse(self.channels)
        # A well-framed empty Name is a valid hint, not a trust requirement.
        channel = await self.connect(certificate_evidence_extensions=((47, b"\0\4\0\2\x30\0"),))
        await channel.send(b"valid authority hint")
        self.assertEqual(await channel.recv(), b"valid authority hint")

    async def test_psk_ke_ignores_groups_without_a_common_traffic_group(self):
        key = ExternalPSK(b"PSK-only groups", b"explicit public test fixture", "localhost")
        self.server_options = {"external_psks": (key,)}
        for groups in (b"\x2a\x2a", b"\xfe\xff", b"\x2a\x2a\xfe\xff"):
            with self.subTest(groups=groups):
                channel = await self.connect(external_psk=key, psk_modes=(0,),
                    certificate_evidence_extensions=((10, m._vec(groups, 2)),))
                await channel.send(b"PSK-only data")
                self.assertEqual(await channel.recv(), b"PSK-only data")
        self.assertFalse(self.errors)

    async def test_wire_sni_is_case_insensitive_across_retry_and_resumption(self):
        original = m.client_hello
        def mixed_case(*args, **kwargs):
            return original(*args, **kwargs).replace(b"localhost", b"LocalHost")
        with patch.object(m, "client_hello", mixed_case):
            for options in ({"force_retry": True}, {}, {"early_data": b"early case-insensitive SNI"}):
                channel = await self.connect(**options)
                self.assertIn(b"LocalHost", channel.handshake_transcript)
                await channel.send(b"case-insensitive service identity")
                self.assertEqual(await channel.recv(), b"case-insensitive service identity")
        self.assertFalse(self.errors)

    async def test_supported_groups_in_encrypted_extensions_is_advisory(self):
        original = m.encrypted_extensions
        def with_groups(*args, **kwargs):
            kwargs['extra_extensions'] = (*kwargs.get('extra_extensions', ()),
                (10, m._vec(b'\x00\x17\x00\x1d\xfe\xff', 2)))
            return original(*args, **kwargs)
        with patch.object(m, 'encrypted_extensions', with_groups):
            channel = await self.connect()
            await channel.send(b'server group preferences')
            self.assertEqual(await channel.recv(), b'server group preferences')

    async def test_malformed_or_unsolicited_ee_groups_fail(self):
        original = m.encrypted_extensions
        for value in (b'\x00\x00', b'\x00\x01\x1d', b'\x00\x02\x00'):
            def with_groups(*args, **kwargs):
                kwargs['extra_extensions'] = (*kwargs.get('extra_extensions', ()), (10, value))
                return original(*args, **kwargs)
            with self.subTest(value=value), patch.object(m, 'encrypted_extensions', with_groups), self.assertRaises(ProtocolError) as caught:
                await self.connect()
            self.assertEqual(caught.exception.alert, 50)
        key = ExternalPSK(b'groups absent', b'explicit secret', 'localhost')
        self.server_options = {'external_psks': (key,)}
        def unsolicited(*args, **kwargs):
            kwargs['extra_extensions'] = (*kwargs.get('extra_extensions', ()), (10, b'\x00\x02\x00\x1d'))
            return original(*args, **kwargs)
        with patch.object(m, 'encrypted_extensions', unsolicited), self.assertRaises(ProtocolError) as caught:
            await self.connect(external_psk=key, psk_modes=(0,))
        self.assertEqual(caught.exception.alert, 110)

    async def test_no_sni_or_alpn_with_out_of_band_service_identity(self):
        self.server_options = {"require_server_name": False, "require_alpn": False,
                               "application_protocols": ()}
        options = {"send_server_name": False, "require_alpn": False, "application_protocols": ()}
        first = await self.connect(**options)
        self.assertEqual(first.protocol, b"")
        resumed = await self.connect(**options, early_data=b"generic early payload")
        self.assertTrue(resumed.resumed)
        self.assertTrue(resumed.early_data_accepted)
        self.assertEqual(resumed.protocol, b"")
        await resumed.send(b"generic protocol")
        self.assertEqual(await resumed.recv(), b"generic protocol")

    async def test_psk_only_without_sni_or_alpn(self):
        key = ExternalPSK(b"device", b"explicit secret", "localhost", protocol=b"")
        self.server_options = {"require_server_name": False, "require_alpn": False,
                               "application_protocols": (), "external_psks": (key,)}
        channel = await self.connect(send_server_name=False, require_alpn=False, application_protocols=(),
                                     external_psk=key, psk_modes=(0,))
        self.assertEqual(channel.psk_provenance, "ext")
        await channel.send(b"provisioned device data")
        self.assertEqual(await channel.recv(), b"provisioned device data")

    async def test_http_profile_does_not_silently_become_generic(self):
        with self.assertRaises(ProtocolError):
            await self.connect(send_server_name=False)
        with self.assertRaises(ProtocolError):
            await self.connect(require_alpn=False, application_protocols=())

    async def test_explicit_unauthenticated_mode_never_populates_authenticated_cache(self):
        self.roots = []
        handles = []
        first = await self.connect(allow_unauthenticated_server=True, normal_httpps=False,
                                   on_exporter=handles.append)
        self.assertFalse(first.peer_authenticated)
        self.assertEqual(first.psk_provenance, "unauthenticated")
        self.assertFalse(handles[0].peer_authenticated)
        self.assertFalse(self.cache._tickets)
        second = await self.connect(allow_unauthenticated_server=True, normal_httpps=False)
        self.assertFalse(second.resumed)
        with self.assertRaises(ProtocolError):
            await self.connect()  # No automatic fallback after normal trust failure.
        with self.assertRaises(ValueError):
            await self.connect(allow_unauthenticated_server=True)  # HTTPPS forbids it.

    async def test_unauthenticated_mode_still_checks_server_possession(self):
        # Corrupt the wire message rather than the shared verification primitive.
        original_frame = m.certificate_verify
        def malformed(proof, *, client=False):
            return original_frame(proof if client else bytes((proof[0] ^ 1,)) + proof[1:], client=client)
        with patch.object(m, "certificate_verify", malformed), self.assertRaises(ProtocolError):
            await self.connect(allow_unauthenticated_server=True, normal_httpps=False)

    def test_unoffered_sni_response_rejected_and_optional_alpn_absence_allowed(self):
        wire = m.encrypted_extensions(b"", acknowledge_name=False)
        self.assertFalse(m.parse_encrypted_extensions(wire[4:], (), require_alpn=False, offered_name=False))
        with self.assertRaises(ProtocolError):
            m.parse_encrypted_extensions(m.encrypted_extensions(b"", acknowledge_name=True)[4:], (),
                                          require_alpn=False, offered_name=False)
