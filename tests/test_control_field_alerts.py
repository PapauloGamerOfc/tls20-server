"""Fixed-width extension syntax is decode_error, unlike invalid enum values.

These mutate only the serializer after an actual offer has been constructed;
both peers still use the real handshake/record parsers and cryptography.
"""
import asyncio
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519

from tls20_server import messages as m
from tls20_server.credential_profiles import CredentialPolicy
from tls20_server.errors import PeerClosed, ProtocolError
from tls20_server.handshake import Wire
from tls20_server.pki import Credentials
from tests import test_sessions


class ControlFieldAlertTests(unittest.IsolatedAsyncioTestCase):
    asyncSetUp = test_sessions.SessionTests.asyncSetUp
    asyncTearDown = test_sessions.SessionTests.asyncTearDown
    accept = test_sessions.SessionTests.accept
    handle = test_sessions.SessionTests.handle
    connect = test_sessions.SessionTests.connect

    async def check_wire(self, context, kind, value, expected):
        hello, encrypted = m.client_hello, m.encrypted_extensions
        fatal = Wire.fatal
        emitted = []

        def mutate(encode, args, kwargs):
            kwargs['extra_extensions'] = tuple(
                (code, data) for code, data in kwargs.get('extra_extensions', ())
                if code != kind) + ((kind, value),)
            return encode(*args, **kwargs)

        def request(*args, **kwargs):
            return mutate(hello, args, kwargs) if context == 'CH' else hello(*args, **kwargs)

        def response(*args, **kwargs):
            return mutate(encrypted, args, kwargs) if context == 'EE' else encrypted(*args, **kwargs)

        async def observe(wire, error, state=None):
            if not isinstance(error, PeerClosed):
                emitted.append((wire.writer in self.client_writers, error.alert))
            return await fatal(wire, error, state)

        options = ({'record_size_limit': 64} if kind == 28 else
                   {'max_fragment_length': 1} if kind == 1 else {'heartbeat_mode': 1})
        if kind == 20:
            options = dict(server_certificate_types=(0, 2), credential_policy=CredentialPolicy(
                trust_roots=tuple(self.roots), peer_name='localhost'))
        elif kind == 19:
            private = x25519.X25519PrivateKey.generate()
            spki = private.public_key().public_bytes(serialization.Encoding.DER,
                                                    serialization.PublicFormat.SubjectPublicKeyInfo)
            options = dict(client_credentials=Credentials([spki], private, credential_type=2))
        # Do not let earlier positive controls turn a later case into resumption.
        self.cache._tickets.clear()
        self.errors.clear()
        with patch.object(m, 'client_hello', request), patch.object(m, 'encrypted_extensions', response), patch.object(Wire, 'fatal', observe):
            if expected is None:
                channel = await asyncio.wait_for(self.connect(**options), 3)
                await channel.send(b'valid control')
                self.assertEqual(await channel.recv(), b'valid control')
                await channel.close()
                self.assertEqual(emitted, [])
            else:
                before = len(self.channels)
                with self.assertRaises(ProtocolError) as caught:
                    await asyncio.wait_for(self.connect(**options), 3)
                self.assertEqual(caught.exception.alert, expected)
                self.assertEqual(emitted, [(context == 'EE', expected)])
                self.assertEqual(len(self.channels), before)

    async def test_fixed_width_fields_in_both_directions(self):
        cases = (
            (28, ((b'\x00\x40', None), (b'', 50), (b'\x00', 50),
                  (b'\x00\x40\x00', 50), (b'\x00\x3f', 47))),
            (1, ((b'\x01', None), (b'', 50), (b'\x01\x00', 50), (b'\x05', 47))),
            (15, ((b'\x01', None), (b'', 50), (b'\x01\x00', 50), (b'\x00', 47))),
        )
        for context in ('CH', 'EE'):
            for kind, values in cases:
                for value, expected in values:
                    with self.subTest(context=context, kind=kind, value=value):
                        await self.check_wire(context, kind, value, expected)

    async def test_absent_optional_controls_are_not_malformed(self):
        channel = await self.connect()
        await channel.send(b'no optional controls')
        self.assertEqual(await channel.recv(), b'no optional controls')
        await channel.close()

    async def test_encrypted_certificate_type_scalars(self):
        for kind, valid in ((19, b'\x02'), (20, b'\x00')):
            for value, expected in ((valid, None), (b'', 50), (valid + b'\x00', 50), (b'\x03', 47)):
                with self.subTest(kind=kind, value=value):
                    await self.check_wire('EE', kind, value, expected)

    async def test_record_size_limit_request_supersedes_fragment_limit(self):
        hello = m.client_hello
        for ignored in (b'', b'\x01\x00', b'\x05'):
            with self.subTest(ignored=ignored):
                self.cache._tickets.clear()
                def request(*args, **kwargs):
                    kwargs['extra_extensions'] = tuple(kwargs.get('extra_extensions', ())) + ((1, ignored),)
                    return hello(*args, **kwargs)
                with patch.object(m, 'client_hello', request):
                    channel = await self.connect(record_size_limit=64)
                    await channel.send(b'RSL wins')
                    self.assertEqual(await channel.recv(), b'RSL wins')
                    await channel.close()


if __name__ == '__main__':
    unittest.main()
