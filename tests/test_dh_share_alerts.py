"""Well-framed but invalid peer DH shares have illegal_parameter alerts."""

import os
import unittest
from unittest.mock import patch

from tls20_server import crypto as c, messages as m
from tls20_server.errors import ProtocolError
from tls20_server.tickets import TicketCache
from tests import test_sessions


class ShareAlertTests(unittest.TestCase):
    def check_group(self, group, provider=None):
        first, public = c.traffic_key(group, provider)
        second, peer = c.traffic_key(group, provider)
        try:
            self.assertEqual(c.traffic_dh(first, group, peer, provider),
                             c.traffic_dh(second, group, public, provider))
            invalid = (b"\x04" + bytes(len(public) - 1) if group in c.EC_GROUPS or group == 41
                       else bytes(len(public)))
            with self.assertRaises(ProtocolError) as caught:
                c.traffic_dh(first, group, invalid, provider)
            self.assertEqual(caught.exception.alert, 47)
            # A rejected peer must not consume a local key or poison provider.
            self.assertEqual(c.traffic_dh(first, group, peer, provider),
                             c.traffic_dh(second, group, public, provider))
        finally:
            for key in (first, second):
                if hasattr(key, "close"):
                    key.close()

    def test_python_groups(self):
        for group in (29, 30, *c.EC_GROUPS, 256):
            with self.subTest(group=group):
                self.check_group(group)

    @unittest.skipUnless(os.environ.get("TLS20_TEST_OPENSSL"), "explicit native provider required")
    def test_sm2_point_rejection_is_not_provider_unavailability(self):
        from tls20_server.openssl_provider import OpenSSLProvider
        provider = OpenSSLProvider(os.environ["TLS20_TEST_OPENSSL"])
        try:
            self.check_group(41, provider)
            native, public = provider.generate_sm2()
            try:
                # Provider/context creation failures remain local, not an
                # illegal_parameter attributed to an otherwise valid peer.
                with patch.object(provider.lib, "EVP_PKEY_CTX_new_from_name", return_value=None), \
                     self.assertRaises(ProtocolError) as caught:
                    provider.exchange_sm2(native, public)
                self.assertEqual(caught.exception.alert, 40)
            finally:
                native.close()
        finally:
            provider.close()

    @unittest.skipUnless(os.environ.get("TLS20_TEST_OPENSSL") and os.environ.get("TLS20_TEST_GOST_MODULE"),
                         "explicit GOST provider required")
    def test_gost_points(self):
        from tls20_server.gost_provider import GOSTProvider
        provider = GOSTProvider(os.environ["TLS20_TEST_OPENSSL"], os.environ["TLS20_TEST_GOST_MODULE"])
        try:
            for group in range(34, 41):
                with self.subTest(group=group):
                    self.check_group(group, provider)
        finally:
            provider.close()


class ShareWireTests(unittest.IsolatedAsyncioTestCase):
    asyncSetUp = test_sessions.SessionTests.asyncSetUp
    asyncTearDown = test_sessions.SessionTests.asyncTearDown
    accept = test_sessions.SessionTests.accept
    handle = test_sessions.SessionTests.handle
    connect = test_sessions.SessionTests.connect

    async def test_client_and_server_reject_invalid_semantic_points_with_47(self):
        for group in (29, 30, 23, 24, 25, 31, 32, 33, 256):
            for role in ("client", "server"):
                with self.subTest(group=group, role=role):
                    self.cache = TicketCache()
                    invalid = b"\x04" + bytes(c.GROUP_LENGTHS[group] - 1) if group in c.EC_GROUPS else bytes(c.GROUP_LENGTHS[group])
                    if role == "client":
                        original = m.server_hello
                        def hello(public, *args, **kwargs):
                            return original(invalid, *args, **kwargs)
                        name = "server_hello"
                    else:
                        original = m.client_hello
                        def hello(auth, public, *args, **kwargs):
                            return original(auth, invalid, *args, **kwargs)
                        name = "client_hello"
                    with patch.object(m, name, hello), self.assertRaises(ProtocolError) as caught:
                        await self.connect(traffic_group=group, supported_groups=(group,))
                    self.assertEqual(caught.exception.alert, 47)
            self.cache = TicketCache()
            channel = await self.connect(traffic_group=group, supported_groups=(group,))
            await channel.send(b"valid share control")
            self.assertEqual(await channel.recv(), b"valid share control")
            await channel.close()
