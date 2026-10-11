"""Real provider-bound Streebog/MGM handshakes and record transitions."""
import asyncio
import os
import unittest
from tests import test_sessions
from tls20_server import crypto as c
from tls20_server.gost_provider import GOSTProvider, SUITES, GROUPS
from tls20_server.tickets import TicketCache
from tls20_server.errors import ProtocolError


@unittest.skipUnless(os.environ.get("TLS20_TEST_OPENSSL") and os.environ.get("TLS20_TEST_GOST_MODULE"),"explicit GOST fixture required")
class GOSTHandshakeTests(unittest.IsolatedAsyncioTestCase):
    accept=test_sessions.SessionTests.accept
    handle=test_sessions.SessionTests.handle
    connect=test_sessions.SessionTests.connect

    async def asyncSetUp(self):
        await test_sessions.SessionTests.asyncSetUp(self)
        self.native=GOSTProvider(os.environ["TLS20_TEST_OPENSSL"],os.environ["TLS20_TEST_GOST_MODULE"])

    async def asyncTearDown(self):
        await test_sessions.SessionTests.asyncTearDown(self)
        self.native.close()

    async def test_all_suites_groups_full_resume_early_update(self):
        for suite in SUITES:
            for group in GROUPS:
                with self.subTest(suite=hex(suite),group=group):
                    self.cache=TicketCache()
                    self.server_options={"native_provider":self.native,"cipher_suites":(suite,)}
                    options={"native_provider":self.native,"cipher_suites":(suite,),"traffic_group":group}
                    first=await self.connect(**options)
                    self.assertFalse(first.resumed)
                    self.assertEqual(first.exporter("fixture"),self.channels[-1].exporter("fixture"))
                    second=await self.connect(**options,early_data=b"early")
                    self.assertTrue(second.resumed)
                    self.assertTrue(second.early_data_accepted)
                    self.assertEqual(second.early_exporter("fixture"),self.channels[-1].early_exporter("fixture"))
                    await second.key_update(True)
                    await second.send(b"GOST application")
                    self.assertEqual(await second.recv(),b"GOST application")
        self.assertFalse(self.errors)

    async def test_retry_and_provider_required(self):
        self.server_options={"native_provider":self.native,"cipher_suites":(0xc103,)}
        channel=await self.connect(native_provider=self.native,cipher_suites=(0xc103,),traffic_group=34,force_retry=True)
        self.assertEqual(channel.cipher_suite,0xc103)
        for side in ("seal","open"):
            with self.assertRaises(ProtocolError):
                c.RecordState(bytes(32),side,0xc103)

    async def test_initial_client_mac_pha_and_external_psk_modes(self):
        from tests.test_client_auth import client_credentials
        from cryptography.hazmat.primitives.asymmetric import ed25519
        credentials=client_credentials(ed25519.Ed25519PrivateKey.generate())
        def validate(chain):
            if chain!=credentials.chain_der:raise ProtocolError("unprovisioned client")
            return credentials.private_key.public_key()
        options={"native_provider":self.native,"cipher_suites":(0xc104,)}
        self.server_options={**options,"client_auth_validator":validate,"require_client_auth":True}
        channel=await self.connect(**options,client_credentials=credentials,post_handshake_auth=True)
        server=self.channels[-1]
        future=await server.request_client_auth(required=True)
        await server.key_update(True)
        await channel.send(b"drive PHA")
        self.assertEqual(await channel.recv(),b"drive PHA")
        self.assertEqual(await asyncio.wait_for(future,2),tuple(credentials.chain_der))
        from tls20_server.psk import ExternalPSK
        for mode,combined in ((0,False),(1,False),(1,True)):
            self.cache=TicketCache()
            psk=ExternalPSK(b"gost external",bytes(range(32)),"localhost",hash_name="streebog256",cipher_suite=0xc104,combined=combined)
            self.server_options={**options,"external_psks":(psk,)}
            peer=await self.connect(**options,external_psk=psk,psk_modes=(mode,))
            self.assertEqual(peer.psk_provenance,"ext")
            self.assertEqual(peer.exporter("external"),self.channels[-1].exporter("external"))

    def test_record_tree_boundaries_and_nonce_topbit(self):
        for suite,(_,_,maximum,masks) in SUITES.items():
            send=c.RecordState(bytes(32),"seal",suite,provider=self.native)
            recv=c.RecordState(bytes(32),"open",suite,provider=self.native)
            for sequence in (0,1,7,8,127,128,8191,8192):
                send.sequence=recv.sequence=sequence
                record=send.seal(b"bound",23,padding=4)
                self.assertEqual(recv.open(record),(b"bound",23))
            recv.sequence=maximum+1
            with self.assertRaises(ProtocolError):recv.open(record)
            send.update();recv=c.RecordState(bytes(32),"open",suite,provider=self.native);recv.update()
            self.assertEqual(recv.open(send.seal(b"updated",23)),(b"updated",23))
