"""IP reference identities remain separate from DNS SNI and DNSName SANs."""

import asyncio
import ipaddress
import unittest
from unittest.mock import patch

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.x509.oid import NameOID

from tests import test_sessions
from tests.test_pki import issue, der
from tls20_server import messages as m
from tls20_server.handshake import Wire, client_handshake, server_handshake
from tls20_server.errors import ProtocolError
from tls20_server.pki import Credentials


class IPHandshakeTests(unittest.IsolatedAsyncioTestCase):
    asyncSetUp = test_sessions.SessionTests.asyncSetUp
    asyncTearDown = test_sessions.SessionTests.asyncTearDown
    accept = test_sessions.SessionTests.accept

    def identity(self, address, *, dns_san=False):
        self.service = address
        ca_key, key = ed25519.Ed25519PrivateKey.generate(), x25519.X25519PrivateKey.generate()
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "IP test")])
        root = issue(ca_key, ca_key, name, name, ca=True)
        leaf = issue(key, ca_key, name, name, hostname=address if dns_san else None,
            extra=[] if dns_san else [(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address(address))]), False)])
        self.credentials, self.roots = Credentials([der(leaf)], key), [root]

    async def handle(self, reader, writer):
        try:
            channel = await server_handshake(reader, writer, self.credentials, self.service, ticket_store=self.store)
            self.channels.append(channel)
            await channel.send(b"ready")
            await channel.close()
        except (ProtocolError, OSError) as error:
            self.errors.append(str(error))
            writer.close()

    async def connect(self):
        reader, writer = await asyncio.open_connection("127.0.0.1", self.port)
        self.writers.append(writer)
        channel = await client_handshake(reader, writer, self.service, self.roots,
            revocation_policy="lab-offline", ticket_cache=self.cache)
        self.assertEqual(await channel.recv(), b"ready")
        return channel

    async def test_ipv4_ipv6_full_resumed_never_send_sni(self):
        original, offers = Wire.send_frame, []
        async def inspect(wire, frame, state=None):
            if frame[0] == 1:
                offers.append(m.parse_client_hello(frame[4:]))
            return await original(wire, frame, state)
        with patch.object(Wire, "send_frame", inspect):
            for address in ("127.0.0.1", "::1"):
                self.identity(address)
                first, second = await self.connect(), await self.connect()
                self.assertFalse(first.resumed)
                self.assertTrue(second.resumed)
                self.assertTrue(first.peer_authenticated)
        self.assertTrue(all(not value.name and 0 not in value.extensions for value in offers))
        self.assertFalse(self.errors)

    async def test_dns_san_text_cannot_authenticate_ip_reference(self):
        self.identity("127.0.0.1", dns_san=True)
        with self.assertRaises(ProtocolError):
            await self.connect()

    def test_canonical_service_identity_does_not_relax_sni_parser(self):
        for value in ("127.0.0.1", "::1"):
            self.assertEqual(m.validate_service_identity(value), value)
            with self.assertRaises(ProtocolError):
                m.validate_name(value)
        for value in ("127.000.0.1", "[::1]", "fe80::1%3", "2001:0db8::1"):
            with self.assertRaises(ProtocolError):
                m.validate_service_identity(value)
