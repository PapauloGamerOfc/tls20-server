"""Actual peer alerts distinguish optional-extension syntax from semantics."""

import asyncio
import unittest
from unittest.mock import patch

from cryptography import x509
from cryptography.x509.oid import ExtendedKeyUsageOID

from tests import test_client_auth, test_sessions
from tls20_server import messages as m
from tls20_server.credential_selection import _der, _length, _oid_der, encode_oid_filters
from tls20_server.errors import ProtocolError
from tls20_server.handshake import Wire


def vector(value, width=2):
    return len(value).to_bytes(width, "big") + value


def oid_filter(oid, value=b""):
    return vector(vector(oid, 1) + vector(value))


def status_request(*, responder=None, extensions=b""):
    return b"\x01" + vector(b"" if responder is None else vector(responder)) + vector(extensions)


def ocsp_extension(oid, value, *, critical=False):
    body = _oid_der(oid) + (b"\x01\x01\xff" if critical else b"") + b"\x04" + _length(value)
    return b"\x30" + _length(body)


def sequence(body):
    return b"\x30" + _length(body)


def replace_alpn(frame, value):
    if frame[0] == 1:
        hello = m.parse_client_hello(frame[4:])
        prefix, pairs = hello.fixed_hello, hello.extension_values
    else:
        prefix, pairs = b"", tuple(m.extensions(frame[6:]).items())
    encoded = b"".join(m.extension(kind, value if kind == 16 else data) for kind, data in pairs)
    return m.frame(frame[0], prefix + vector(encoded))


class ExtensionSyntaxAlertTests(unittest.IsolatedAsyncioTestCase):
    async def exchange(self, builder, kind, value, expected=None, *, client_auth=False):
        # A fresh fixture per input prevents tickets/resumption from bypassing
        # the mutated full-handshake message or authenticating a negative case.
        fixture = test_client_auth.ClientAuthTests() if client_auth else test_sessions.SessionTests()
        await fixture.asyncSetUp()
        if client_auth:
            fixture.server_options["require_client_auth"] = True
        original, read = getattr(m, builder), Wire.read_record
        alerts, received = [], asyncio.Event()

        def inject(*args, **options):
            if kind == 16:
                return replace_alpn(original(*args, **options), value)
            options["extra_extensions"] = tuple(options.get("extra_extensions", ())) + ((kind, value),)
            return original(*args, **options)

        async def observe(wire, state=None):
            content, record_type = await read(wire, state)
            if record_type == 21 and content[:1] == b"\x02":
                alerts.append((wire.writer in fixture.client_writers, state is not None, content))
                received.set()
            return content, record_type

        try:
            with patch.object(m, builder, inject), patch.object(Wire, "read_record", observe):
                options = {"client_credentials": fixture.client_credentials} if client_auth else {}
                if expected is None:
                    channel = await asyncio.wait_for(fixture.connect(**options), 5)
                    self.assertFalse(channel.resumed)
                    await channel.send(b"valid extension application data")
                    self.assertEqual(await asyncio.wait_for(channel.recv(), 3), b"valid extension application data")
                    if client_auth:
                        self.assertEqual(fixture.channels[-1].authenticated_client,
                                         tuple(fixture.client_credentials.chain_der))
                        self.assertGreater(fixture.validated, 0)
                    await channel.close()
                    if fixture.tasks:
                        await asyncio.wait_for(asyncio.gather(*tuple(fixture.tasks)), 3)
                    self.assertFalse(alerts)
                    self.assertFalse(fixture.errors)
                else:
                    with self.assertRaises(ProtocolError) as caught:
                        await asyncio.wait_for(fixture.connect(**options), 5)
                    self.assertEqual(caught.exception.alert, expected)
                    await asyncio.wait_for(received.wait(), 3)
                    # CH errors reach the client in cleartext; CR/EE errors
                    # reach the server encrypted with the handshake epoch.
                    from_ch = builder == "client_hello"
                    self.assertEqual(alerts, [(from_ch, not from_ch, bytes((2, expected)))])
                    self.assertFalse(fixture.channels)
                    self.assertFalse(fixture.early)
                    if client_auth:
                        self.assertEqual(fixture.validated, 0)
        finally:
            await fixture.asyncTearDown()

    async def test_alpn_syntax_alerts_in_both_directions(self):
        for builder in ("client_hello", "encrypted_extensions"):
            for label, value, expected in (
                ("valid", vector(vector(b"http/1.1", 1)), None),
                ("empty-name", b"\0\1\0", 50),
                ("empty-list", b"\0\0", 50),
                ("truncated-name", b"\0\2\2x", 50),
                ("trailing-vector", b"\0\2\1x\0", 50),
            ):
                with self.subTest(builder=builder, case=label):
                    await self.exchange(builder, 16, value, expected)
        # A well-framed but unoffered selection is semantic, not decode_error.
        await self.exchange("encrypted_extensions", 16, vector(vector(b"h2", 1)), 47)

    async def test_oid_filters_syntax_and_semantics(self):
        ku, eku = _oid_der("2.5.29.15"), _oid_der("2.5.29.37")
        one = oid_filter(ku)
        client_eku = x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]).public_bytes()
        any_eku = x509.ExtendedKeyUsage([ExtendedKeyUsageOID.ANY_EXTENDED_KEY_USAGE]).public_bytes()
        for label, value, expected in (
            ("empty-list", b"\0\0", None),
            ("known-presence", one, None),
            ("known-ku", oid_filter(ku, b"\x03\x02\x03\x08"), None),
            ("known-eku", oid_filter(eku, client_eku), None),
            ("unknown-opaque", encode_oid_filters([("1.2.3.4", b"not DER")]), None),
            ("trailing-vector", b"\0\0x", 50),
            ("empty-oid-field", oid_filter(b""), 50),
            ("empty-oid-der", oid_filter(b"\x06\0"), 50),
            ("truncated-oid", oid_filter(b"\x06\x02\x2a"), 50),
            ("nonminimal-oid", oid_filter(b"\x06\x02\x80\x01"), 50),
            ("truncated-oid-arc", oid_filter(b"\x06\x01\x81"), 50),
            ("duplicate-oid", vector(one[2:] * 2), 47),
            ("truncated-ku", oid_filter(ku, b"\x03\x02\0"), 50),
            ("nonminimal-ku", oid_filter(ku, b"\x03\x02\0\x80"), 50),
            ("undefined-ku-bit", oid_filter(ku, b"\x03\x03\x06\0\x40"), 47),
            ("empty-eku", oid_filter(eku, b"\x30\0"), 50),
            ("malformed-eku-oid", oid_filter(eku, b"\x30\x03\x06\x01\x81"), 50),
            ("forbidden-any-eku", oid_filter(eku, any_eku), 47),
        ):
            with self.subTest(case=label):
                await self.exchange("certificate_request", 48, value, expected, client_auth=True)

    async def test_status_request_nested_syntax_and_semantics(self):
        unknown = ocsp_extension("1.2.3.4", b"opaque")
        nonce = ocsp_extension("1.3.6.1.5.5.7.48.1.2", b"\x04\x03abc")
        unknown_critical = ocsp_extension("1.2.3.4", b"opaque", critical=True)
        for label, value, expected in (
            ("no-constraints", status_request(), None),
            ("responder-key", status_request(responder=b"\xa2\x16\x04\x14" + bytes(20)), None),
            ("responder-name", status_request(responder=b"\xa1\x02\x30\0"), None),
            ("nonce", status_request(extensions=sequence(nonce)), None),
            ("unknown-extension", status_request(extensions=sequence(unknown)), None),
            ("unknown-critical-not-fulfilled", status_request(extensions=sequence(unknown_critical)), None),
            ("unknown-status-type", b"\x02opaque", None),
            ("empty-responder", status_request(responder=b""), 50),
            ("truncated-responder", status_request(responder=b"\xa2\x01"), 50),
            ("responder-name-der", status_request(responder=b"\xa1\x02\x30\x01"), 50),
            ("responder-name-empty-rdn", status_request(responder=b"\xa1\x04\x30\x02\x31\0"), 50),
            ("responder-hash-der", status_request(responder=b"\xa2\x02\x04\x14"), 50),
            ("truncated-extensions", status_request(extensions=b"\x30\x01"), 50),
            ("truncated-extension", status_request(extensions=b"\x30\x02\x30\x01"), 50),
            ("malformed-extension-oid", status_request(extensions=sequence(sequence(b"\x06\x01\x80\x04\0"))), 50),
            ("truncated-extension-value", status_request(extensions=sequence(sequence(_oid_der("1.2.3.4") + b"\x04\1"))), 50),
            ("truncated-critical-value", status_request(extensions=sequence(sequence(_oid_der("1.2.3.4") + b"\x01\x01\xff\x04\1"))), 50),
            ("nonce-inner-der", status_request(extensions=sequence(ocsp_extension("1.3.6.1.5.5.7.48.1.2", b"\x04\x01"))), 50),
            ("duplicate-extension", status_request(extensions=sequence(unknown * 2)), 47),
        ):
            with self.subTest(case=label):
                await self.exchange("client_hello", 5, value, expected)

    def test_shared_der_consumer_defaults_are_unchanged(self):
        for options, expected in (({}, 40), ({"alert": 50}, 50)):
            with self.subTest(options=options), self.assertRaises(ProtocolError) as caught:
                _der(b"\x30\1", **options)
            self.assertEqual(caught.exception.alert, expected)


if __name__ == "__main__":
    unittest.main()
