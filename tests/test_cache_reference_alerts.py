"""Cached credentials and requests retain the core's syntax/semantic alerts."""

import asyncio
import unittest
from unittest.mock import patch

from tests import test_credential_handshakes
from tls20_server import credential_cache as cache, handshake as h
from tls20_server.credential_profiles import CredentialPolicy, RawPublicKeyBinding
from tls20_server.errors import ProtocolError
from tls20_server.tickets import TicketCache


def metadata(body, value):
    return body[:33] + len(value).to_bytes(3, "big") + value


def unknown_hash(body):
    cursor = 1 + body[0]
    return body[:cursor] + bytes([body[cursor] ^ 1]) + body[cursor + 1:]


class CacheReferenceAlertTests(unittest.IsolatedAsyncioTestCase):
    async def exchange(self, transform, expected, *, algorithm=0, request=False, pha=False):
        # Every input gets fresh trust, a fresh transport and no resumable PSK.
        fixture = test_credential_handshakes.CredentialHandshakeTests()
        await fixture.asyncSetUp()
        name = "cached_request_body" if request else "cached_certificate_body"
        encode, read = getattr(h, name), h.Wire.read_record
        alerts, received, encoded = [], asyncio.Event(), []
        future = client = None
        armed = not pha
        try:
            options = {"certificate_compression": (algorithm,) if algorithm else ()}
            if request:
                credential = fixture.raw()
                fixture.server_options = dict(require_client_auth=True, client_certificate_types=(2,),
                    client_credential_policy=CredentialPolicy(peer_name="device", raw_public_keys=(
                        RawPublicKeyBinding("client", "device", credential.chain_der[0]),)))
                first = await fixture.connect(client_credentials=credential)
                templates = first.client_request_templates
                await first.close()
                if fixture.tasks:
                    await asyncio.wait_for(asyncio.gather(*tuple(fixture.tasks)), 3)
                fixture.cache = TicketCache()
                fixture.channels.clear()
                options.update(client_credentials=credential, cached_requests=templates, post_handshake_auth=pha)
            else:
                options["cached_certificates"] = ((0, tuple(fixture.credentials.chain_der)),)

            def inject(*args, **kwargs):
                value = encode(*args, **kwargs)
                if not armed:
                    return value
                value = transform(value)
                encoded.append(value)
                return value

            async def observe(wire, state=None):
                content, kind = await read(wire, state)
                if kind == 21 and content[:1] == b"\x02":
                    alerts.append((wire.writer in fixture.client_writers, state is not None, content))
                    received.set()
                return content, kind

            with patch.object(h, name, inject), patch.object(h.Wire, "read_record", observe):
                if pha:
                    client = await fixture.connect(**options)
                    self.assertFalse(client.resumed)
                    armed = True
                    future = await fixture.channels[-1].request_client_auth(required=True)
                if expected is None:
                    if not pha:
                        client = await asyncio.wait_for(fixture.connect(**options), 5)
                    self.assertFalse(client.resumed)
                    self.assertIn(2 if request else 1, client.cache_types)
                    await client.send(b"authenticated cached reference")
                    self.assertEqual(await asyncio.wait_for(client.recv(), 3), b"authenticated cached reference")
                    if request:
                        self.assertEqual(fixture.channels[-1].authenticated_client, tuple(credential.chain_der))
                    if pha:
                        self.assertEqual(await asyncio.wait_for(future, 3), tuple(credential.chain_der))
                    await client.close()
                    if fixture.tasks:
                        await asyncio.wait_for(asyncio.gather(*tuple(fixture.tasks)), 3)
                    self.assertFalse(alerts)
                    self.assertFalse(fixture.errors)
                else:
                    with self.assertRaises(ProtocolError) as caught:
                        if pha:
                            await asyncio.wait_for(client.recv(), 3)
                        else:
                            await asyncio.wait_for(fixture.connect(**options), 5)
                    self.assertEqual(caught.exception.alert, expected)
                    await asyncio.wait_for(received.wait(), 3)
                    self.assertEqual(alerts, [(False, True, bytes((2, expected)))])
                    if fixture.tasks:
                        await asyncio.wait_for(asyncio.gather(*tuple(fixture.tasks)), 3)
                    if pha:
                        self.assertTrue(future.cancelled())
                        self.assertTrue(client.closed)
                        self.assertTrue(fixture.channels[-1].closed)
                        self.assertFalse(fixture.channels[-1].pending_client_auth)
                    else:
                        self.assertFalse(fixture.channels)
                self.assertEqual(len(encoded), 1)
        finally:
            await fixture.asyncTearDown()

    async def test_cached_certificate_syntax_and_semantics_in_every_codec(self):
        cases = (
            ("valid", lambda b: b, None),
            ("missing-context", lambda b: b"", 50),
            ("truncated-context", lambda b: b"\x02x", 50),
            ("truncated-hash", lambda b: b[:17], 50),
            ("truncated-metadata-length", lambda b: b[:35], 50),
            ("truncated-metadata", lambda b: b[:-1], 50),
            ("trailing-data", lambda b: b + b"x", 50),
            ("truncated-entry-length", lambda b: metadata(b, b"\0"), 50),
            ("truncated-entry", lambda b: metadata(b, b"\0\x02x"), 50),
            ("truncated-extra-entry", lambda b: metadata(b, b[36:] + b"\0"), 50),
            ("missing-entry", lambda b: metadata(b, b[36:-2]), 47),
            ("extra-entry", lambda b: metadata(b, b[36:] + b"\0\0"), 47),
            ("unknown-hash", unknown_hash, 47),
            ("nonempty-context", lambda b: b"\x01x" + b[1:], 47),
        )
        for algorithm in (0, 1, 2, 3):
            for label, transform, expected in cases:
                # CompressCertificate requires a nonempty decoded body. An
                # empty local encoder failure is not a remote parser test.
                if algorithm and label == "missing-context":
                    continue
                with self.subTest(algorithm=algorithm, case=label):
                    await self.exchange(transform, expected, algorithm=algorithm)

    async def test_cached_request_syntax_and_semantics_initial_and_post_handshake(self):
        for pha in (False, True):
            for label, transform, expected in (
                ("valid", lambda b: b, None),
                ("missing-context", lambda b: b"", 50),
                ("truncated-context", lambda b: b"\x02x", 50),
                ("truncated-hash", lambda b: b[:1 + b[0] + 17], 50),
                ("truncated-share", lambda b: b[:-1], 50),
                ("trailing-data", lambda b: b + b"x", 50),
                ("unknown-hash", unknown_hash, 47),
            ):
                with self.subTest(pha=pha, case=label):
                    await self.exchange(transform, expected, request=True, pha=pha)

    def test_wire_alert_override_does_not_reclassify_local_helpers_or_budgets(self):
        for call in (
            lambda: cache._take(b"", 0, 1),
            lambda: cache.request_template(b"\0"),
            lambda: cache.resolve_cached_certificate(b"x" * (cache.MAX_CREDENTIAL_BODY + 1), ()),
        ):
            with self.assertRaises(ProtocolError) as caught:
                call()
            self.assertEqual(caught.exception.alert, 40)


if __name__ == "__main__":
    unittest.main()
