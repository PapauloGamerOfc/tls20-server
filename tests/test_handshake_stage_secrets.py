"""Stage ownership checks while real handshake callbacks are suspended.

Only presence/ownership is inspected: Python cannot promise physical erasure of
immutable allocations, nor revoke copies retained by application/provider code.
"""

import asyncio
import inspect
import os
import unittest
from unittest.mock import patch

from cryptography import x509

from tests import test_sessions, test_pake_handshake
from tls20_server import handshake as hs
from tls20_server.application_auth import AuthorizedIdentity
from tls20_server.lab import generate_lab_credentials


def stage_snapshot():
    """Do not retain frame objects or the secrets inspected by this test."""
    frame = inspect.currentframe()
    snapshots = []
    try:
        while frame is not None:
            module = frame.f_globals.get("__name__", "")
            if ((module == "tls20_server.handshake" and frame.f_code.co_name in
                 ("client_handshake", "server_handshake")) or
                (module == "tls20_server.pake_handshake" and frame.f_code.co_name in
                 ("client", "server"))):
                values = frame.f_locals
                snapshots.append({
                    "function": (module, frame.f_code.co_name),
                    "present": {name: values.get(name) is not None for name in
                        ("auth_shared", "auth_root", "traffic_shared", "traffic_private",
                         "shared", "ordinary_private", "auth_private")},
                    "owned_keys": len(values["secrets"].keys),
                })
                del values
            frame = frame.f_back
    finally:
        del frame
    return snapshots


class HandshakeStageSecretTests(unittest.IsolatedAsyncioTestCase):
    async def exchange(self, *, password=False, mixed=False, authenticators=False,
                       traffic_group=29, native_provider=None):
        fixture = (test_pake_handshake.PakeHandshakeTests() if password else
                   test_sessions.SessionTests())
        await fixture.asyncSetUp()
        channel = task = None
        try:
            for resumed in (False, True):
                with self.subTest(password=password, mixed=mixed, authenticators=authenticators,
                                  resumed=resumed, group=traffic_group):
                    arrived = {role: asyncio.Event() for role in ("client", "server")}
                    release = asyncio.Event()
                    snapshots, accesses, proof_snapshots = {}, {}, []

                    def callback(role):
                        async def hold(access):
                            snapshots[role] = stage_snapshot()
                            accesses[role] = access
                            arrived[role].set()
                            await release.wait()
                        return hold

                    server_options = {"enable_authenticators": authenticators,
                                      "on_exporter": callback("server")}
                    if native_provider is not None:
                        server_options.update(native_provider=native_provider, cipher_suites=(0x00c6,))
                    if password:
                        fixture.options = server_options
                    else:
                        fixture.server_options = server_options
                    options = {"enable_authenticators": authenticators,
                               "on_exporter": callback("client")}
                    if not password:
                        options["traffic_group"] = traffic_group
                    if native_provider is not None:
                        options.update(native_provider=native_provider, cipher_suites=(0x00c6,))

                    async def connect():
                        if not mixed:
                            return await fixture.connect(**options)
                        reader, writer = await asyncio.open_connection("127.0.0.1", fixture.port)
                        fixture.writers.append(writer)
                        connected = await hs.client_handshake(reader, writer, "localhost", (),
                            revocation_policy="offline", password_credential=fixture.credential,
                            cipher_suites=(0xc0b0, 0x1301), ticket_cache=fixture.cache, **options)
                        self.assertEqual(await connected.recv(), b"ready", fixture.errors)
                        return connected

                    original_send = hs.Wire.send_frame

                    async def send(wire, message, state=None):
                        if message[0] == 15 and wire.writer.get_extra_info("peername")[1] != fixture.port:
                            proof_snapshots.extend(stage_snapshot())
                        return await original_send(wire, message, state)

                    with patch.object(hs.Wire, "send_frame", send):
                        task = asyncio.create_task(connect())
                        try:
                            await asyncio.wait_for(asyncio.gather(*(event.wait() for event in arrived.values())), 3)
                            self.assertEqual(accesses["client"].export("stage", b"context"),
                                             accesses["server"].export("stage", b"context"))
                            self.assertTrue(all(not access.handshake_completed for access in accesses.values()))
                            for role, frames in snapshots.items():
                                self.assertTrue(frames, role)
                                self.assertEqual(any(frame["present"]["auth_private"] for frame in frames),
                                                 role == "client" and authenticators)
                                for snapshot in frames:
                                    expected = {name: False for name in snapshot["present"]}
                                    # Direct delegation of a successor to PWD
                                    # happens before the outer client creates a.
                                    expected["auth_private"] = snapshot["present"]["auth_private"]
                                    self.assertEqual(snapshot["present"], expected, snapshot["function"])
                                    self.assertEqual(snapshot["owned_keys"], 0, snapshot["function"])
                            if not password and not resumed:
                                self.assertEqual(len(proof_snapshots), 1)
                                self.assertFalse(any(proof_snapshots[0]["present"].values()))
                            if native_provider is not None:
                                self.assertEqual(native_provider._live_keys, 0)
                        finally:
                            release.set()
                        channel = await asyncio.wait_for(task, 3)
                    self.assertEqual(channel.resumed, resumed)
                    self.assertEqual(channel.auth_share_secret is not None, authenticators)
                    self.assertEqual(channel.exporter("stage", b"context"),
                                     accesses["server"].export("stage", b"context"))
                    if authenticators:
                        credential, _ = generate_lab_credentials("localhost")

                        def authorize(identity, request):
                            self.assertEqual(identity.chain, tuple(credential.chain_der))
                            return AuthorizedIdentity(x509.load_der_x509_certificate(identity.chain[0]).public_key(),
                                                      "stage lifecycle fixture")

                        client_manager = channel.authenticators()
                        server_manager = fixture.channels[-1].authenticators()
                        # Spontaneous server authentication needs the retained a;
                        # requested authentication exercises both directions.
                        self.assertTrue((await client_manager.validate(
                            server_manager.authenticate(credential), authorize)).authenticated)
                        for verifier, prover in ((client_manager, server_manager), (server_manager, client_manager)):
                            request = verifier.request()
                            self.assertTrue((await verifier.validate(
                                prover.authenticate(credential, request=request), authorize)).authenticated)
                    await channel.send(b"stage ownership preserves traffic")
                    self.assertEqual(await channel.recv(), b"stage ownership preserves traffic")
                    await channel.close()
                    await asyncio.wait_for(asyncio.gather(*tuple(fixture.tasks)), 3)
                    self.assertFalse(fixture.errors)
                    self.assertTrue(all(not access.active for access in accesses.values()))
                    channel = task = None
        finally:
            if task is not None:
                if not task.done():
                    task.cancel()
                await asyncio.gather(task, return_exceptions=True)
            if channel is not None:
                channel.abort()
            await fixture.asyncTearDown()

    async def test_ordinary_full_and_resumed_release_before_callbacks(self):
        await self.exchange()

    async def test_only_explicit_authenticator_capability_retains_auth_share(self):
        await self.exchange(authenticators=True)

    @unittest.skipUnless(os.environ.get("TLS20_TEST_OPENSSL"), "native provider required")
    async def test_native_traffic_private_is_closed_before_callback(self):
        from tls20_server.openssl_provider import OpenSSLProvider
        provider = OpenSSLProvider(os.environ["TLS20_TEST_OPENSSL"])
        try:
            await self.exchange(traffic_group=41, native_provider=provider)
        finally:
            provider.close()

    @unittest.skipUnless(os.environ.get("TLS20_TEST_PAKE") and os.environ.get("TLS20_TEST_OPENSSL"),
                         "native PAKE fixture required")
    async def test_password_full_and_resumed_release_before_callbacks(self):
        await self.exchange(password=True)

    @unittest.skipUnless(os.environ.get("TLS20_TEST_PAKE") and os.environ.get("TLS20_TEST_OPENSSL"),
                         "native PAKE fixture required")
    async def test_mixed_password_handoff_releases_outer_frame_temporaries(self):
        await self.exchange(password=True, mixed=True)

    @unittest.skipUnless(os.environ.get("TLS20_TEST_PAKE") and os.environ.get("TLS20_TEST_OPENSSL"),
                         "native PAKE fixture required")
    async def test_password_authenticator_capability_survives_cleanup(self):
        await self.exchange(password=True, mixed=True, authenticators=True)
