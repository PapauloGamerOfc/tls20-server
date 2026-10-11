"""Real native password exchanges, not password-derived external PSKs."""
import asyncio
import os
import unittest
from dataclasses import replace
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric import ec
from tls20_server import pake_handshake as pwd
from tls20_server.errors import ProtocolError
from tls20_server.openssl_provider import OpenSSLProvider
from tls20_server.pake_native import PakeProvider
from tls20_server.pake import PasswordCredential, PasswordAccount, PasswordServer, SUITES
from tls20_server.tickets import TicketCache, TicketStore
from tls20_server.handshake import Wire


@unittest.skipUnless(os.environ.get("TLS20_TEST_PAKE") and os.environ.get("TLS20_TEST_OPENSSL"), "explicit native PAKE fixture required")
class PakeHandshakeTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.native=OpenSSLProvider(os.environ["TLS20_TEST_OPENSSL"])
        self.provider=PakeProvider(self.native,os.environ["TLS20_TEST_PAKE"])
        self.account=PasswordAccount.provision("alice","correct horse",permissions=b"read")
        self.policy=PasswordServer("localhost",self.provider,[self.account],max_attempts=100,global_attempts=200)
        self.credential=PasswordCredential("localhost","alice","correct horse",self.provider)
        self.store,self.cache=TicketStore(),TicketCache()
        self.options={};self.tasks=set();self.writers=[];self.channels=[];self.errors=[];self.early=[];self.timeout=4
        self.early_event=asyncio.Event()
        self.listener=await asyncio.start_server(self.accept,"127.0.0.1",0)
        self.port=self.listener.sockets[0].getsockname()[1]

    def accept(self,reader,writer):
        self.writers.append(writer)
        task=asyncio.create_task(self.handle(reader,writer));self.tasks.add(task);task.add_done_callback(self.tasks.discard)

    async def handle(self,reader,writer):
        async def early(data):
            self.early.append(data);self.early_event.set()
        try:
            channel=await pwd.server(reader,writer,self.policy,timeout=self.timeout,ticket_store=self.store,
                max_early_data=65536,on_early_data=early,**self.options)
            self.channels.append(channel)
            await channel.send(b"ready")
            while (data:=await channel.recv()) is not None:
                await channel.send(data)
        except (ProtocolError,OSError,ValueError,TimeoutError) as error:
            self.errors.append(error)
        finally:
            writer.close()

    async def connect(self,**options):
        reader,writer=await asyncio.open_connection("127.0.0.1",self.port);self.writers.append(writer)
        channel=await pwd.client(reader,writer,self.credential,timeout=self.timeout,ticket_cache=self.cache,**options)
        self.assertEqual(await asyncio.wait_for(channel.recv(),2),b"ready",self.errors)
        return channel

    async def asyncTearDown(self):
        self.listener.close()
        for writer in self.writers:writer.transport.abort()
        await asyncio.wait_for(self.listener.wait_closed(),2)
        for task in tuple(self.tasks):task.cancel()
        await asyncio.gather(*self.tasks,return_exceptions=True)
        for writer in self.writers:
            try:await writer.wait_closed()
            except (OSError,asyncio.CancelledError):pass
        self.native.close()

    async def test_four_suites_three_groups_and_successor_tickets(self):
        for suite in SUITES:
            for group in (23,24,25):
                with self.subTest(suite=hex(suite),group=group):
                    self.cache=TicketCache();self.options={"cipher_suites":(suite,)}
                    first=await self.connect(cipher_suites=(suite,),groups=(group,))
                    self.assertFalse(first.resumed)
                    self.assertEqual(first.pake_identity,b"alice")
                    self.assertEqual(self.channels[-1].password_permissions,b"read")
                    self.assertEqual(first.exporter("fixture"),self.channels[-1].exporter("fixture"))
                    second=await self.connect(cipher_suites=(suite,),groups=(group,),early_data=b"early")
                    self.assertTrue(second.resumed)
                    self.assertEqual(second.early_data_accepted,suite!=0xc0b3)
                    await second.key_update(request_peer=True)
                    await second.send(b"application")
                    self.assertEqual(await second.recv(),b"application")
        self.assertFalse(self.errors)

    async def test_wrong_password_unknown_account_and_revoked_ticket(self):
        for name,password in (("alice","wrong"),("unknown","correct horse")):
            self.credential=PasswordCredential("localhost",name,password,self.provider)
            with self.assertRaises((ProtocolError,OSError)):
                await self.connect()
        self.assertFalse(self.channels)
        self.credential=PasswordCredential("localhost","alice","correct horse",self.provider)
        await self.connect();self.policy.revoke("alice")
        with self.assertRaises((ProtocolError,OSError)):
            await self.connect(early_data=b"forbidden")
        self.assertFalse(self.early)
        self.assertEqual(self.policy._active,0)

    async def test_password_ticket_modes_remain_bound_before_early_authorization(self):
        from tls20_server import messages
        await self.connect()
        cached = next(iter(self.cache._tickets.values()))
        server_ticket = self.store._tickets[cached.identity]
        self.assertEqual(cached.allowed_psk_modes, (1,))
        self.assertEqual(server_ticket.allowed_psk_modes, (1,))
        original = messages.client_hello
        def forbidden_mode(A, B, *args, **kwargs):
            if kwargs.get("identity"):
                kwargs["psk_modes"] = (0,)
                kwargs["group"] = 0
                B = b""
            return original(A, B, *args, **kwargs)
        with patch.object(messages, "client_hello", forbidden_mode):
            with self.assertRaises(ProtocolError):
                await self.connect(early_data=b"forbidden password early")
        self.assertFalse(server_ticket.early_used)
        self.assertFalse(self.early)
        self.assertEqual(len(self.store._tickets), 1)
        # The honest mode-1 client discards an incompatible cache entry and
        # proves the password afresh without forwarding the old early request.
        self.cache.put(replace(cached, allowed_psk_modes=(0,)))
        channel = await self.connect(early_data=b"old cache authority")
        self.assertFalse(channel.resumed)
        self.assertFalse(channel.early_data_accepted)
        self.assertFalse(self.early)

    async def test_cookie_bound_password_retry_and_successor_retry(self):
        from tls20_server.retry_cookie import RetryCookiePolicy
        self.options["retry_cookie_policy"] = RetryCookiePolicy()
        first = await self.connect()
        self.assertFalse(first.resumed)
        second = await self.connect(early_data=b"rejected after retry")
        self.assertTrue(second.resumed)
        self.assertFalse(second.early_data_accepted)
        await second.send(b"password cookie")
        self.assertEqual(await second.recv(), b"password cookie")
        self.assertFalse(self.early)
        self.assertFalse(self.errors)

    async def test_password_successor_bad_binder_has_exact_alert_before_or_after_retry(self):
        from tls20_server import messages as m
        from tls20_server.retry_cookie import RetryCookiePolicy
        from tests.test_conformance import replace_extensions
        self.options["retry_cookie_policy"] = RetryCookiePolicy()
        for length in (48, 32):
            self.cache = TicketCache()
            await self.connect()
            original = Wire.send_frame
            async def send(wire, message, state=None):
                if message[0] == 1:
                    def mutate(ext):
                        reader = m._Reader(ext[41])
                        identities = reader.vector(2)
                        reader.vector(2); reader.end()
                        ext[41] = m._vec(identities, 2) + m._vec(m._vec(bytes(length), 1), 2)
                    message = replace_extensions(message, mutate)
                return await original(wire, message, state)
            with self.subTest(length=length), patch.object(Wire, "send_frame", send), self.assertRaises(ProtocolError) as raised:
                await self.connect()
            self.assertEqual(raised.exception.alert, 51)
        self.assertEqual(len(self.channels), 2)

    async def test_successor_selection_uses_ticket_hash_not_first_ordinary_offer(self):
        from tls20_server import messages
        self.options={"cipher_suites":(0xc0b1,)}
        await self.connect(cipher_suites=(0xc0b1,))
        original=messages.client_hello
        for suites in ((0x1301,0x1302),(0x1302,0x1301)):
            def multiple(*args,**kwargs):
                if kwargs.get("identity"):
                    kwargs["cipher_suites"]=suites
                return original(*args,**kwargs)
            with patch.object(messages,"client_hello",multiple):
                channel=await self.connect(cipher_suites=(0xc0b1,),early_data=b"sha384")
            self.assertEqual(channel.cipher_suite,0x1302)
            self.assertTrue(channel.resumed)
            self.assertTrue(channel.early_data_accepted)
        self.assertFalse(self.errors)
        self.options={"cipher_suites":(0xc0b0,)}
        with self.assertRaises(ProtocolError):
            await self.connect(cipher_suites=(0xc0b1,))

    async def test_changed_client_suite_policy_discards_incompatible_successor(self):
        for initial in (0xc0b1,0xc0b2):
            self.cache=TicketCache()
            await self.connect(cipher_suites=(initial,))
            channel=await self.connect(cipher_suites=(0xc0b0,),early_data=b"must-not-send")
            self.assertFalse(channel.resumed)
            self.assertFalse(channel.early_data_accepted)
            self.assertEqual(channel.cipher_suite,0xc0b0)
            self.assertFalse(self.early)

    async def test_mixed_offer_password_selection_and_real_successor_early(self):
        from tls20_server.handshake import client_handshake
        for early in (b'',b'early'):
            reader,writer=await asyncio.open_connection("127.0.0.1",self.port);self.writers.append(writer)
            channel=await client_handshake(reader,writer,'localhost',(),revocation_policy='offline',
                timeout=5,password_credential=self.credential,cipher_suites=(0xc0b0,0x1301),
                ticket_cache=self.cache,early_data=early)
            self.assertEqual(await channel.recv(),b'ready',self.errors)
            self.assertEqual(channel.pake_identity,b'alice')
            self.assertEqual(channel.resumed,bool(early))
            self.assertEqual(channel.early_data_accepted,bool(early))
            self.assertEqual(channel.exporter('mixed'),self.channels[-1].exporter('mixed'))
        self.assertFalse(self.errors)

    async def test_mixed_offer_ordinary_selection_and_no_auth_failure_fallback(self):
        from tls20_server.handshake import client_handshake, server_handshake
        from tls20_server.lab import create_lab
        from tls20_server.pki import load_credentials, load_trust_roots
        from pathlib import Path
        import tempfile
        with tempfile.TemporaryDirectory() as directory:
            folder=Path(directory)/'lab';create_lab(folder,'localhost')
            credentials=load_credentials(folder/'fullchain.pem',folder/'server.key','localhost')
            roots=load_trust_roots(folder/'ca.pem')
            async def ordinary(reader,writer):
                self.writers.append(writer)
                task=asyncio.current_task();self.tasks.add(task)
                try:
                    channel=await server_handshake(reader,writer,credentials,'localhost',timeout=5)
                    self.channels.append(channel);await channel.send(b'ordinary')
                except (ProtocolError,OSError):
                    writer.close()
                finally:self.tasks.discard(task)
            listener=await asyncio.start_server(ordinary,'127.0.0.1',0)
            try:
                for trust in (roots,()):
                    reader,writer=await asyncio.open_connection('127.0.0.1',listener.sockets[0].getsockname()[1]);self.writers.append(writer)
                    parameters=dict(revocation_policy='offline',timeout=5,password_credential=self.credential,cipher_suites=(0xc0b0,0x1301))
                    if trust:
                        channel=await client_handshake(reader,writer,'localhost',trust,**parameters)
                        self.assertEqual(await channel.recv(),b'ordinary')
                        self.assertFalse(channel.pake_identity)
                    else:
                        with self.assertRaises(ProtocolError):
                            await client_handshake(reader,writer,'localhost',trust,**parameters)
            finally:
                listener.close()
                for writer in self.writers:writer.transport.abort()
                await listener.wait_closed()

    async def test_protected_username_and_small_record_early_before_finished(self):
        protection=ec.generate_private_key(ec.SECP256R1())
        self.policy=PasswordServer("localhost",self.provider,[self.account],protection_key=protection)
        self.credential=replace(self.credential,protection_key=protection.public_key())
        self.options={"record_size_limit":64}
        await self.connect(record_size_limit=64)
        original=Wire.send_frame
        async def held(wire,message,state=None):
            if message[0]==5:
                await asyncio.wait_for(self.early_event.wait(),1)
                self.assertEqual(b"".join(self.early),b"x"*200)
            return await original(wire,message,state)
        with patch.object(Wire,"send_frame",held):
            second=await self.connect(record_size_limit=64,early_data=b"x"*200)
        self.assertTrue(second.early_data_accepted)
        self.assertEqual(b"".join(self.early),b"x"*200)
        self.assertEqual(second.sender.record_limit,64)
        self.assertEqual(second.early_exporter("fixture"),self.channels[-1].early_exporter("fixture"))

    async def test_consumed_early_ticket_not_replayed_and_exporter_lifecycle(self):
        await self.connect()
        captured=replace(next(iter(self.cache._tickets.values())))
        accesses=[]
        first=await self.connect(early_data=b"one",on_exporter=accesses.append,on_early_exporter=accesses.append)
        self.assertTrue(first.early_data_accepted)
        self.assertEqual(len(accesses),2)
        self.assertTrue(all(access.handshake_completed and access.peer_authenticated for access in accesses))
        self.assertTrue(accesses[0].replayable)
        await first.close()
        self.assertTrue(all(not access.active for access in accesses))
        self.cache=TicketCache();self.cache.put(captured)
        second=await self.connect(early_data=b"replay")
        self.assertTrue(second.resumed)
        self.assertFalse(second.early_data_accepted)
        self.assertEqual(self.early,[b"one",b""])

    async def test_retry_identity_mutation_and_rate_budget(self):
        original=Wire.send_frame
        count=0
        async def mutate(wire,message,state=None):
            nonlocal count
            if message[0]==1:
                count+=1
                if count==2:message=message.replace(b"alice",b"other")
            return await original(wire,message,state)
        with patch.object(Wire,"send_frame",mutate):
            with self.assertRaises((ProtocolError,OSError)):
                await self.connect()
        self.assertFalse(self.channels)
        self.assertEqual(self.policy._active,0)
        self.policy=PasswordServer("localhost",self.provider,[self.account],max_attempts=1)
        self.credential=replace(self.credential,password="wrong")
        for _ in range(2):
            with self.assertRaises((ProtocolError,OSError)):
                await self.connect()
        self.assertEqual(self.policy._active,0)
        self.assertEqual(len(self.policy._global),1)

    async def test_unsalted_account_and_anonymous_alpn_policy(self):
        account=PasswordAccount.provision("alice","correct horse",salted=False)
        self.policy=PasswordServer("localhost",self.provider,[account])
        self.options={"application_protocols":(),"require_alpn":False,"require_server_name":False}
        channel=await self.connect(application_protocols=(),require_alpn=False,send_server_name=False)
        self.assertEqual(channel.protocol,b"")
        self.assertTrue(channel.peer_authenticated)

    async def test_ffc_wire_all_groups_and_nontruncated_scalars(self):
        from tls20_server.ffdhe import SIZES
        # Full-entropy FFC8192 under a no-assembly provider is intentionally
        # slow. This is a crypto interoperability test, not a 4-second SLA.
        self.timeout=30
        for group in SIZES:
            self.cache=TicketCache()
            channel=await self.connect(groups=(group,),cipher_suites=(0xc0b0,))
            await channel.send(b"FFC")
            self.assertEqual(await channel.recv(),b"FFC")
            self.assertFalse(channel.resumed)


class NativeSchedulingTests(unittest.IsolatedAsyncioTestCase):
    async def test_cancelled_native_job_is_joined_and_its_state_discarded(self):
        import threading
        started, release = threading.Event(), threading.Event()
        disposed = []
        def operation():
            started.set();release.wait(2)
            return "owned-state"
        task=asyncio.create_task(pwd._native_work(operation,discard=disposed.append))
        for _ in range(100):
            if started.is_set():break
            await asyncio.sleep(.001)
        self.assertTrue(started.is_set())
        task.cancel();await asyncio.sleep(.01)
        self.assertFalse(task.done())
        # The event loop remains responsive while native CPU work owns a slot.
        release.set()
        with self.assertRaises(asyncio.CancelledError):await task
        self.assertEqual(disposed,["owned-state"])

    async def test_native_timeout_fails_after_safe_join_without_hiding_error(self):
        import time
        with self.assertRaises(TimeoutError):
            async with asyncio.timeout(.001):
                await pwd._native_work(lambda:time.sleep(.02))
        with self.assertRaisesRegex(ValueError,"native failure"):
            await pwd._native_work(lambda:(_ for _ in ()).throw(ValueError("native failure")))
