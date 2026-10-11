"""Provisioned PSK modes, importer domain separation, and actual wire exchanges."""

from dataclasses import replace
import asyncio
import hashlib
import hmac
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand

from tls20_server import crypto as c, messages as m
from tls20_server.errors import ProtocolError
from tls20_server.handshake import Transcript, Wire
from tls20_server.psk import ExternalPSK, import_psk, bootstrap_public_key_psk
from tls20_server.tickets import TicketCache, TicketStore
from tests import test_sessions


class ImporterTests(unittest.TestCase):
    def test_independent_importer_oracle_and_domain_separation(self):
        for base_name, base_hash in (("sha256", hashes.SHA256()), ("sha384", hashes.SHA384())):
            for target, length, kdf in (("sha256", 32, 1), ("sha384", 48, 2)):
                psk = import_psk(b"a deliberately arbitrary length key", b"device", b"roles/deployment",
                                 "localhost", base_hash=base_name, target_hash=target)
                identity = b"\x00\x06device\x00\x10roles/deployment\x04\x00" + kdf.to_bytes(2, "big")
                self.assertEqual(psk.identity, identity)
                root = hmac.new(bytes(base_hash.digest_size), b"a deliberately arbitrary length key", base_name).digest()
                label = b"tls20 derived psk"
                context = hashlib.new(base_name, identity).digest()
                info = length.to_bytes(2, "big") + bytes((len(label),)) + label + bytes((len(context),)) + context
                self.assertEqual(psk.psk, HKDFExpand(base_hash, length, info).derive(root))
                self.assertNotEqual(c.binder(psk.psk, b"transcript", hash_name=target, kind="imp"),
                                    c.binder(psk.psk, b"transcript", hash_name=target, kind="ext"))

    def test_psk_only_wire_has_no_traffic_share_and_rejects_implicit_fallback(self):
        hello = m.client_hello(b"", b"", "localhost", bytes(32), group=0, psk_modes=(0,),
                               identity=b"provisioned", binder=bytes(32))
        parsed = m.parse_client_hello(hello[4:])
        self.assertEqual(parsed.group, 0)
        self.assertFalse(set(parsed.extensions) & {10, 51, 0xff02})
        self.assertEqual(parsed.psk_modes, (0,))
        with self.assertRaises(ProtocolError):
            m.parse_client_hello(m.client_hello(b"", b"", "localhost", bytes(32), group=0)[4:])

    def test_pok_is_imported_and_combined_only(self):
        psk = bootstrap_public_key_psk(bytes(range(32)), "localhost")
        self.assertTrue(psk.combined)
        self.assertEqual(psk.binder_kind, "imp")
        self.assertIn(b"tls20-bsk", psk.identity)
        with self.assertRaises(ValueError):
            replace(psk, max_early_data=42)


class ExternalHandshakeTests(unittest.IsolatedAsyncioTestCase):
    asyncSetUp = test_sessions.SessionTests.asyncSetUp
    asyncTearDown = test_sessions.SessionTests.asyncTearDown
    accept = test_sessions.SessionTests.accept
    handle = test_sessions.SessionTests.handle
    connect = test_sessions.SessionTests.connect

    async def test_external_direct_imported_psk_modes_and_resumption(self):
        for imported in (False, True):
            for mode in (0, 1):
                for code, name in ((0x1301, "sha256"), (0x1302, "sha384")):
                    with self.subTest(imported=imported, mode=mode, suite=code):
                        self.cache = TicketCache()
                        key = import_psk(b"key material", b"device", b"scoped", "localhost", target_hash=name) if imported else ExternalPSK(
                            b"scoped device", b"arbitrary length external secret", "localhost", hash_name=name, cipher_suite=code)
                        self.server_options = {"external_psks": (key,), "cipher_suites": (code,)}
                        ch = await self.connect(external_psk=key, psk_modes=(mode,), cipher_suites=(code,))
                        self.assertEqual(ch.psk_provenance, "imp" if imported else "ext")
                        self.assertEqual(ch.early_exporter("test"), self.channels[-1].early_exporter("test"))
                        await ch.send(b"explicit external authentication")
                        self.assertEqual(await ch.recv(), b"explicit external authentication")
                        resumed = await self.connect(external_psk=key, psk_modes=(mode,), cipher_suites=(code,))
                        self.assertEqual(resumed.psk_provenance, "res")
                        self.assertTrue(resumed.resumed)
        self.assertFalse(self.errors)

    async def test_combined_authentication_actually_validates_server_credential(self):
        key = ExternalPSK(b"combo", b"key material", "localhost", combined=True)
        self.server_options = {"external_psks": (key,)}
        ch = await self.connect(external_psk=key)
        self.assertEqual(ch.certificate_chain, self.credentials.chain_der)
        self.assertEqual(ch.psk_provenance, "ext")
        await ch.send(b"both proofs")
        self.assertEqual(await ch.recv(), b"both proofs")
        self.cache = TicketCache()
        self.roots = []
        with self.assertRaises(ProtocolError):
            await self.connect(external_psk=key)

    async def test_combined_ticket_modes_remain_dhe_only_across_early_successors(self):
        key = ExternalPSK(b"combo modes", b"key material", "localhost", combined=True)
        self.server_options = {"external_psks": (key,)}
        first = await self.connect(external_psk=key, psk_modes=(1,))
        self.assertFalse(first.resumed)
        for index in range(3):
            cached = next(iter(self.cache._tickets.values()))
            self.assertEqual(cached.allowed_psk_modes, (1,))
            self.assertEqual(self.store._tickets[cached.identity].allowed_psk_modes, (1,))
            channel = await self.connect(external_psk=key, psk_modes=(0, 1),
                                         early_data=f"successor {index}".encode())
            self.assertTrue(channel.resumed)
            self.assertTrue(channel.early_data_accepted)
            self.assertEqual(dict(channel.local_capabilities)[45], b"\x01\x01")
            self.assertIn(51, dict(channel.local_capabilities))
            self.assertEqual(channel.allowed_psk_modes, (1,))
        self.assertFalse(self.errors)

    async def test_ticket_mode_state_normalizes_duplicates_and_ignores_unknown_modes(self):
        key = ExternalPSK(b"combo repeated", b"key material", "localhost", combined=True)
        self.server_options = {"external_psks": (key,)}
        await self.connect(external_psk=key, psk_modes=(1, 255, 1))
        cached = next(iter(self.cache._tickets.values()))
        self.assertEqual(cached.allowed_psk_modes, (1,))
        self.assertEqual(self.store._tickets[cached.identity].allowed_psk_modes, (1,))
        resumed = await self.connect(external_psk=key, psk_modes=(1, 0), early_data=b"valid descendant")
        self.assertTrue(resumed.resumed)
        self.assertTrue(resumed.early_data_accepted)
        self.assertEqual(resumed.allowed_psk_modes, (1,))
        self.assertFalse(self.errors)

    async def test_combined_offer_can_authorize_later_psk_only_but_not_widen_successor(self):
        key = ExternalPSK(b"combo both", b"key material", "localhost", combined=True)
        self.server_options = {"external_psks": (key,)}
        await self.connect(external_psk=key, psk_modes=(1, 0))
        self.assertEqual(next(iter(self.cache._tickets.values())).allowed_psk_modes, (1, 0))
        for modes in ((0,), (1, 0), (0, 1)):
            channel = await self.connect(external_psk=key, psk_modes=modes, early_data=b"permitted early")
            self.assertTrue(channel.resumed)
            self.assertTrue(channel.early_data_accepted)
            self.assertNotIn(51, dict(channel.local_capabilities))
            self.assertEqual(dict(channel.local_capabilities)[45], b"\x01\x00")
            cached = next(iter(self.cache._tickets.values()))
            self.assertEqual(cached.allowed_psk_modes, (0,))
            self.assertEqual(self.store._tickets[cached.identity].allowed_psk_modes, (0,))
        self.assertFalse(self.errors)

    async def test_server_rejects_forged_ticket_mode_before_early_authorization(self):
        key = ExternalPSK(b"combo reject", b"key material", "localhost", combined=True)
        self.server_options = {"external_psks": (key,)}
        await self.connect(external_psk=key, psk_modes=(1,))
        cached = next(iter(self.cache._tickets.values()))
        server_ticket = self.store._tickets[cached.identity]
        cached.allowed_psk_modes = (0,)  # Bypass the honest client filter.
        before = len(self.store._tickets)
        with self.assertRaises(ProtocolError):
            await self.connect(external_psk=key, psk_modes=(0,), early_data=b"must not be authorized")
        self.assertFalse(server_ticket.early_used)
        self.assertFalse(self.early)
        self.assertEqual(len(self.store._tickets), before)

    async def test_retry_rechecks_final_ticket_modes_after_first_candidate_expires(self):
        from tls20_server.retry_cookie import RetryCookiePolicy
        for first_mode, final_mode in ((1, 0), (0, 1), (1, 1), (0, 0)):
            with self.subTest(first_mode=first_mode, final_mode=final_mode):
                self.server_options = {}
                self.cache = TicketCache()
                await self.connect(psk_modes=(first_mode,))
                first = next(iter(self.cache._tickets.values()))
                self.cache = TicketCache()
                await self.connect(psk_modes=(final_mode,))
                final = next(iter(self.cache._tickets.values()))
                first_server = self.store._tickets[first.identity]
                final_server = self.store._tickets[final.identity]
                self.server_options["retry_cookie_policy"] = RetryCookiePolicy()
                _, public = c.traffic_key(29)
                group = 29 if first_mode else 0
                def hello(prefix, *, cookie=b"", empty_share=False):
                    offers = tuple((value.identity, value.obfuscated_age(), bytes(32)) for value in (first, final))
                    options = dict(group=group, psk_modes=(1, 0), psk_offers=offers,
                                   cookie=cookie, empty_share=empty_share)
                    frame = m.client_hello(bytes([2]) * 32, public if group else b"",
                                           "localhost", bytes(32), **options)
                    parsed = m.parse_client_hello(frame[4:])
                    context = prefix + frame[:-parsed.binder_vector_size]
                    options["psk_offers"] = tuple((identity, age, c.binder(value.psk, context))
                        for value, (identity, age, _) in zip((first, final), offers))
                    return m.client_hello(bytes([2]) * 32, public if group else b"",
                                          "localhost", bytes(32), **options)
                reader, writer = await asyncio.open_connection("127.0.0.1", self.port)
                self.writers.append(writer)
                writer.write(c.PREFACE)
                wire = Wire(reader, writer)
                initial = hello(c.PREFACE, empty_share=bool(group))
                await wire.send_frame(initial)
                retry = await asyncio.wait_for(wire.receive_frame(2), 2)
                cookie = m.parse_server_hello(retry[4:], details=True)[5]
                self.assertTrue(cookie)
                # Expire A during the actual HRR network boundary. B remains
                # authorized; its own modes must govern the final selection.
                first_server.issued -= first_server.lifetime + 1
                transcript = Transcript()
                transcript.retry(initial, retry)
                await wire.send_frame(hello(transcript.snapshot(), cookie=cookie))
                record = await asyncio.wait_for(wire.raw_record(), 2)
                if first_mode != final_mode:
                    self.assertEqual(record, b"\x15\x03\x03\x00\x02\x02\x28")
                else:
                    self.assertEqual(record[0], 22)
                    self.assertEqual(m.server_hello_extensions(record[9:])[41], b"\x00\x01")
                self.assertFalse(final_server.early_used)
                self.assertFalse(self.early)
                writer.close()

    async def test_no_ticket_mode_overlap_does_not_offer_ticket_or_early_data(self):
        key = ExternalPSK(b"combo no overlap", b"key material", "localhost", combined=True)
        self.server_options = {"external_psks": (key,)}
        await self.connect(external_psk=key, psk_modes=(1,))
        seen = []
        original = Wire.send_frame
        async def capture(wire, frame, state=None):
            if frame[0] == 1:
                seen.append(frame)
            return await original(wire, frame, state)
        # A fresh combined exchange also requires DHE. A caller insisting on
        # only mode 0 cannot silently revive the old mode-1 ticket instead.
        with patch.object(Wire, "send_frame", capture):
            with self.assertRaises(ProtocolError):
                await self.connect(external_psk=key, psk_modes=(0,), early_data=b"not sent")
        self.assertFalse(seen)  # Invalid combined-only mode is rejected locally.
        self.assertFalse(self.early)

    async def test_no_ticket_mode_overlap_allows_fresh_credential_handshake(self):
        await self.connect(psk_modes=(0,))
        channel = await self.connect(psk_modes=(1,), early_data=b"old ticket does not authorize this")
        self.assertFalse(channel.resumed)
        self.assertFalse(channel.early_data_accepted)
        self.assertEqual(channel.allowed_psk_modes, (1,))
        self.assertFalse(self.early)
        self.assertFalse(self.errors)

    async def test_new_external_policy_performs_fresh_combined_authentication(self):
        key = ExternalPSK(b"combo policy", b"old key material", "localhost", combined=True)
        self.server_options = {"external_psks": (key,)}
        await self.connect(external_psk=key, psk_modes=(1,))
        renewed = replace(key, psk=b"renewed independent external secret")
        self.server_options = {"external_psks": (renewed,)}
        channel = await self.connect(external_psk=renewed, psk_modes=(1, 0), early_data=b"old authority")
        self.assertFalse(channel.resumed)
        self.assertFalse(channel.early_data_accepted)
        self.assertEqual(channel.psk_provenance, "ext")
        self.assertEqual(channel.allowed_psk_modes, (1, 0))
        self.assertFalse(self.early)
        self.assertFalse(self.errors)

    async def test_declined_external_successor_cannot_fall_back_to_credential_only(self):
        for combined in (False, True):
            with self.subTest(combined=combined):
                self.cache = TicketCache()
                key = ExternalPSK(b"required external", b"key material", "localhost", combined=combined)
                self.server_options = {"external_psks": (key,)}
                await self.connect(external_psk=key)
                self.store = TicketStore()  # Restart loses the opaque ticket.
                with self.assertRaisesRegex(ProtocolError, "declined the required provisioned PSK"):
                    await self.connect(external_psk=key, early_data=b"do not downgrade")
                self.assertFalse(self.early)

    async def test_multiple_external_hashes_and_selected_identity_one(self):
        first = ExternalPSK(b"not provisioned here", b"key one", "localhost", max_early_data=1024)
        second = import_psk(b"key two", b"device two", b"scope", "localhost", target_hash="sha384")
        self.server_options = {"external_psks": (second,), "cipher_suites": (0x1302,)}
        for retry in (False, True):
            self.cache = TicketCache()
            client = await self.connect(external_psks=(first, second), cipher_suites=(0x1301, 0x1302),
                                        force_retry=retry, early_data=b"first PSK must not authorize this")
            self.assertEqual(client.selected_external_psk_identity, second.identity)
            self.assertEqual(client.cipher_suite, 0x1302)
            self.assertFalse(client.early_data_accepted)
            self.assertIsNone(client.early_exporter_secret)
            self.assertFalse(self.early)
            await client.send(b"selected second PSK")
            self.assertEqual(await client.recv(), b"selected second PSK")

    async def test_selected_secondary_binder_is_verified(self):
        first = ExternalPSK(b"other", b"unused secret", "localhost")
        second = ExternalPSK(b"selected", b"correct", "localhost")
        self.server_options = {"external_psks": (second,)}
        with self.assertRaises(ProtocolError):
            await self.connect(external_psks=(first, replace(second, psk=b"incorrect")))
        self.assertIn("PSK binder verification failed", self.errors)

    async def test_invalid_external_binder_rejected_and_no_unrelated_fallback(self):
        key = ExternalPSK(b"device", b"correct secret", "localhost")
        self.server_options = {"external_psks": (key,)}
        with self.assertRaises(ProtocolError):
            await self.connect(external_psk=replace(key, psk=b"wrong"))
        self.assertIn("PSK binder verification failed", self.errors)
        self.server_options = {}
        with self.assertRaises(ProtocolError):
            await self.connect(external_psk=key)

    async def test_external_early_requires_explicit_replay_authorizer(self):
        key = ExternalPSK(b"device", b"correct secret", "localhost", max_early_data=4096)
        self.server_options = {"external_psks": (key,)}
        ch = await self.connect(external_psk=key, early_data=b"not authorized")
        self.assertFalse(ch.early_data_accepted)
        self.assertFalse(self.early)
        self.cache = TicketCache()
        seen = set()
        def authorize(psk, identifier):
            self.assertIs(psk, key)
            if identifier in seen:
                return False
            seen.add(identifier)
            return True
        self.server_options["external_early_replay"] = authorize
        ch = await self.connect(external_psk=key, early_data=b"authorized")
        self.assertTrue(ch.early_data_accepted)
        self.assertEqual(self.early, [b"authorized", b""])

    async def test_external_replay_identifier_ignores_unverified_secondary_binders(self):
        selected = ExternalPSK(b"selected replay key", b"correct secret", "localhost", max_early_data=4096)
        unused = ExternalPSK(b"unused replay key", b"other secret", "localhost")
        seen, observations = set(), []
        def authorize(psk, identifier):
            observations.append(identifier)
            if identifier in seen:
                return False
            seen.add(identifier)
            return True
        self.server_options = {'external_psks': (selected,), 'external_early_replay': authorize}
        _, auth = c.traffic_key(29)
        _, share = c.traffic_key(29)
        placeholders = ((selected.identity, 0, bytes(32)), (unused.identity, 0, bytes(32)))
        hello = m.client_hello(auth, share, 'localhost', bytes(32), early_data=True, psk_offers=placeholders)
        parsed = m.parse_client_hello(hello[4:])
        truncated = hello[:-parsed.binder_vector_size]
        proof = c.binder(selected.psk, c.PREFACE + truncated, kind='ext')
        for secondary_proof in (bytes(32), b'x' * 32):
            reader, writer = await asyncio.open_connection('127.0.0.1', self.port)
            self.writers.append(writer)
            changed = m.client_hello(auth, share, 'localhost', bytes(32), early_data=True,
                psk_offers=((selected.identity, 0, proof), (unused.identity, 0, secondary_proof)))
            writer.write(c.PREFACE + b'\x16\x03\x03' + len(changed).to_bytes(2, 'big') + changed)
            await writer.drain()
            # Server invokes the replay policy before sending its ServerHello;
            # no client Finished or early-record authentication is needed here.
            header = await asyncio.wait_for(reader.readexactly(5), 2)
            await reader.readexactly(int.from_bytes(header[3:5], 'big'))
            writer.transport.abort()
        self.assertEqual(len(observations), 2)
        self.assertEqual(observations[0], observations[1])
        self.assertEqual(len(seen), 1)
        self.assertFalse(self.early)
