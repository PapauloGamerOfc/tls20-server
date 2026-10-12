"""Salt-only PWD retries change a proactive commitment without changing group."""

import asyncio
import os
import unittest
from unittest.mock import patch

from tests import test_pake_handshake
from tls20_server import crypto as c, messages as m, pake_handshake as pwd
from tls20_server.errors import ProtocolError
from tls20_server.handshake import Wire
from tls20_server.pake import SUITES, password_base


class PasswordSaltRetryEncodingTests(unittest.TestCase):
    def test_salt_is_a_useful_retry_without_key_share_or_cookie(self):
        hello = m.server_hello(b"", bytes(32), group=0, retry=True,
                               cipher_suite=0xc0b0, password_salt=bytes(32))
        self.assertEqual(set(m.server_hello_extensions(hello[4:])), {31, 43})
        self.assertEqual(m.parse_server_hello(hello[4:], with_suite=True)[3:],
                         (0, True, b"", 0xc0b0))
        # An empty/malformed salt is not a way around syntax validation.
        prefix = hello[4:4 + 38]
        for salt, alert in ((b"", 50), (b"\0\x20" + bytes(31), 50),
                            (b"\0\0", 47), (b"\0\x1f" + bytes(31), 47)):
            encoded = m.extension(43, m.VERSION) + m.extension(31, salt)
            with self.assertRaises(ProtocolError) as failure:
                m.parse_server_hello(prefix + m._vec(encoded, 2))
            self.assertEqual(failure.exception.alert, alert)


@unittest.skipUnless(os.environ.get("TLS20_TEST_PAKE") and os.environ.get("TLS20_TEST_OPENSSL"),
                     "explicit native PAKE fixture required")
class PasswordSaltRetryHandshakeTests(unittest.IsolatedAsyncioTestCase):
    asyncSetUp = test_pake_handshake.PakeHandshakeTests.asyncSetUp
    asyncTearDown = test_pake_handshake.PakeHandshakeTests.asyncTearDown
    accept = test_pake_handshake.PakeHandshakeTests.accept
    handle = test_pake_handshake.PakeHandshakeTests.handle
    connect = test_pake_handshake.PakeHandshakeTests.connect

    async def test_proactive_commitment_recomputed_for_salt_only_retry(self):
        for suite in SUITES:
            for group in (23, 24):
                with self.subTest(suite=hex(suite), group=group):
                    self.options = {"cipher_suites": (suite,), "groups": (group,)}
                    random = os.urandom(32)
                    state = self.provider.create(password_base("alice", "correct horse", None),
                        random, group=group, hash_name=c.suite(suite).hash_name)
                    try:
                        commitment = state.commit()
                    finally:
                        state.close()
                    ch = m.client_hello(b"", commitment, "localhost", random,
                        cipher_suites=(suite,), certificate_algorithms=(), group=group,
                        supported_groups=(group,), extra_extensions=(self.credential.name_extension(),),
                        password_authenticated=True)
                    reader, writer = await asyncio.open_connection("127.0.0.1", self.port)
                    self.writers.append(writer)
                    wire = Wire(reader, writer)
                    wire.deadline = asyncio.get_running_loop().time() + self.timeout
                    writer.write(c.PREFACE)
                    await wire.send_frame(ch)
                    wire.allow_ccs = True
                    try:
                        retry = await wire.receive_frame(2)
                        self.assertEqual(set(m.server_hello_extensions(retry[4:])), {31, 43})
                        channel = await pwd.client(reader, writer, self.credential,
                            timeout=self.timeout, cipher_suites=(suite,), groups=(group,),
                            _first_flight=(wire, ch, retry))
                        self.assertEqual(await channel.recv(), b"ready")
                        self.assertEqual(channel.exporter("salt retry"), self.channels[-1].exporter("salt retry"))
                        await channel.send(b"authenticated after salt")
                        self.assertEqual(await channel.recv(), b"authenticated after salt")
                        await channel.close()
                    finally:
                        writer.close()
                        try:
                            await writer.wait_closed()
                        except OSError:
                            pass
        self.assertFalse(self.errors)

    async def test_empty_share_still_requires_explicit_retry_group(self):
        original = m.server_hello

        def omit_group(public, random, **kwargs):
            message = original(public, random, **kwargs)
            if kwargs.get("retry"):
                values = m.server_hello_extensions(message[4:])
                values.pop(51, None)
                encoded = b"".join(m.extension(k, v) for k, v in values.items())
                return m.frame(2, message[4:4 + 38] + m._vec(encoded, 2))
            return message

        with patch.object(m, "server_hello", omit_group):
            with self.assertRaises(ProtocolError) as failure:
                await self.connect()
        self.assertEqual(failure.exception.alert, 47)
        self.assertFalse(self.channels)
