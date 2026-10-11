"""Configured profiles reach real protocol/relay paths, not only constructors."""

import asyncio
import base64
from dataclasses import replace
import hashlib
import io
import os
from pathlib import Path
import tempfile
import unittest

from cryptography.hazmat.primitives import serialization

from tls20_server.client import fetch
from tls20_server.config import Config, Endpoint, load_config
from tls20_server.errors import ConfigurationError, ProtocolError
from tls20_server.lab import create_lab
from tls20_server.pki import load_credentials
from tls20_server.profiles import load_profile
from tls20_server.server import start_server
from tls20_server.tickets import TicketCache


class ProfileTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name) / "lab"
        create_lab(self.directory, "localhost")
        self.credentials = load_credentials(self.directory / "fullchain.pem", self.directory / "server.key", "localhost")
        (self.directory / "server.spki").write_bytes(self.credentials.private_key.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo))

    def file(self, name, value, *, private=False):
        path = self.directory / name
        path.write_bytes(value.encode() if isinstance(value, str) else value)
        if private:
            path.chmod(0o600)
        return path

    def profile(self, role, extra="", mode="certificate", port=343, service="localhost"):
        return self.file(role + ".toml", f'role="{role}"\nservice="{service}"\nport={port}\nmode="{mode}"\n' + extra)

    def test_certificate_and_raw_key_loader(self):
        for raw in (False, True):
            with self.subTest(raw=raw):
                field = 'raw_public_key="server.spki"' if raw else 'chain="fullchain.pem"'
                server = load_profile(self.profile("server", '[credential]\nprivate_key="server.key"\n'+field), role="server")
                self.addCleanup(server.close)
                self.assertEqual(server.credentials.credential_type, 2 if raw else 0)
                trust = 'raw_public_keys=["server.spki"]' if raw else 'roots="ca.pem"'
                client = load_profile(self.profile("client", '[trust]\n'+trust), role="client")
                self.addCleanup(client.close)
                self.assertEqual(client.options["server_certificate_types"], (2,) if raw else (0,))

    def test_strict_fields_roles_service_port_and_no_bypass(self):
        cases = ('unknown=true', 'mode="unknown"', '[trust]\nignore_errors=true',
                 '[trust]\nroots="ca.pem"\nserver_certificate_types=[true]',
                 '[trust]\nroots="ca.pem"\nrequire_delegation=true',
                 '[trust]\nrevocation_policy="ignore"',
                 '[trust]\nroots="ca.pem"\nrevocation_policy="require-evidence"',
                 '[negotiation]\ncipher_suites=[0xc0b4]',
                 '[negotiation]\ncipher_suites=[0xc0b0]',
                 '[negotiation]\ncipher_suites=[0xc103]',
                 '[negotiation]\ncipher_suites=[0x00c6]',
                 '[provider]\nlibrary="missing.dll"',
                 '[trust]\nroots="ca.pem"\n[password]\nusername_file="x"')
        for data in cases:
            with self.subTest(data=data), self.assertRaises((ConfigurationError, ProtocolError)):
                load_profile(self.profile("client", data), role="client")
        path = self.profile("client", '[trust]\nroots="ca.pem"')
        for kwargs in ({"role":"server"}, {"role":"client", "service":"wrong.test"}, {"role":"client", "port":444}):
            with self.subTest(kwargs=kwargs), self.assertRaises(ConfigurationError):
                load_profile(path, **kwargs)

    def test_signature_issuer_metadata_is_local_and_ocsp_request_is_preserved(self):
        from cryptography import x509
        self.file("leaf-only.pem",x509.load_der_x509_certificate(self.credentials.chain_der[0]).public_bytes(serialization.Encoding.PEM))
        server = load_profile(self.profile("server", '[credential]\nchain="leaf-only.pem"\nprivate_key="server.key"\nsignature_issuers="ca.pem"'),role="server")
        self.addCleanup(server.close)
        self.assertEqual(len(server.credentials.chain_der),1)
        self.assertEqual(len(server.credentials.signature_issuers),1)
        from tests.test_status_request import nonce_extensions
        from tls20_server.status_request import encode_status_request
        request=encode_status_request(request_extensions=nonce_extensions(b'explicit nonce'))
        self.file("request.bin",request)
        client=load_profile(self.profile("client",'[trust]\nroots="ca.pem"\n[trust.evidence]\nrequire_ocsp=true\nocsp_request="request.bin"'),role="client")
        self.addCleanup(client.close)
        self.assertEqual(dict(client.options["certificate_evidence_extensions"])[5],request)
        self.assertEqual(client.options["credential_policy"].evidence_validator.ocsp_request,request)
        self.file("request.bin",b'\x01')
        with self.assertRaises(ProtocolError):
            load_profile(self.directory/"client.toml",role="client")

    def test_psk_secrets_are_separate_and_import_is_explicit(self):
        self.file("key.bin", b"k"*32, private=True)
        for imported in (False, True):
            psk = '[[psks]]\nidentity_hex="6163636f756e74"\nkey_file="key.bin"\n'
            if imported:
                psk += 'import_context_hex="726f6c6573"\n'
            loaded = load_profile(self.profile("client", psk, mode="psk"), role="client")
            self.addCleanup(loaded.close)
            secret = loaded.options["external_psks"][0]
            self.assertEqual(secret.binder_kind, "imp" if imported else "ext")
            self.assertNotIn("kkkk", repr(secret))
            self.assertEqual(secret.max_early_data, 0)

    def test_requirements_cannot_be_silently_skipped_by_profile(self):
        self.file("key.bin", b"k"*32, private=True)
        psk='[[psks]]\nidentity_hex="6162"\nkey_file="key.bin"\n'
        cases=(("certificate", '[trust]\nraw_public_keys=["server.spki"]\nrevocation_policy="require-evidence"\n[trust.evidence]\nrequire_ocsp=true'),
               ("certificate", '[trust]\nroots="ca.pem"\nserver_certificate_types=[0,2]\n[trust.evidence]\nrequire_ocsp=true'),
               ("psk",psk+'[trust]\nroots="ca.pem"'),
               ("psk",psk+'combined=true'),
               ("certificate",'[trust]\nroots="ca.pem"\nserver_certificate_types=[0,2]\ndelegated_credentials=true\nrequire_delegation=true'))
        for mode,data in cases:
            with self.subTest(mode=mode,data=data),self.assertRaises(ConfigurationError):
                load_profile(self.profile("client",data,mode),role="client")

    def test_private_key_trailing_objects_and_unordered_bundle_rejected(self):
        key=(self.directory/"server.key").read_bytes()
        self.file("two.key",key+key,private=True)
        with self.assertRaises(ConfigurationError):
            load_profile(self.profile("server",'[credential]\nraw_public_key="server.spki"\nprivate_key="two.key"'),role="server")
        chain=(self.directory/"fullchain.pem").read_bytes()
        self.file("wrong.pem",(self.directory/"ca.pem").read_bytes()+chain)
        with self.assertRaises((ConfigurationError,ProtocolError)):
            load_profile(self.profile("server",'[credential]\nchain="wrong.pem"\nprivate_key="server.key"'),role="server")

    def test_ct_profile_preserves_pss_key_family_and_restrictions(self):
        from cryptography.hazmat.primitives.asymmetric import rsa
        from tests.test_signature_profiles import tlv, pss_parameters
        from tls20_server.pki import _children, _element, RSAPSSPublicKey
        key=rsa.generate_private_key(public_exponent=65537,key_size=2048).public_key()
        spki=key.public_bytes(serialization.Encoding.DER,serialization.PublicFormat.SubjectPublicKeyInfo)
        fields=_children(_element(spki)[1])
        encoded=tlv(0x30,tlv(0x30,tlv(6,bytes.fromhex('2a864886f70d01010a'))+pss_parameters())+fields[1][2])
        pem=b'-----BEGIN PUBLIC KEY-----\n'+base64.b64encode(encoded)+b'\n-----END PUBLIC KEY-----\n'
        self.file("log.pem",pem)
        trust='[trust]\nroots="ca.pem"\n[trust.evidence]\nminimum_ct_v1_logs=1\n[[trust.evidence.logs]]\n'+\
            'version=1\nsignature_scheme=0x0809\npublic_key="log.pem"\nid_hex="'+hashlib.sha256(encoded).hexdigest()+'"'
        loaded=load_profile(self.profile("client",trust),role="client")
        self.addCleanup(loaded.close)
        log=next(iter(loaded.options["credential_policy"].evidence_validator.trusted_logs_v1.values()))
        self.assertIsInstance(log.public_key,RSAPSSPublicKey)
        self.assertEqual(log.public_key.restrictions,('sha256','sha256',32,1))
        self.file("log.pem",pem+pem)
        with self.assertRaises(ConfigurationError):
            load_profile(self.directory/"client.toml",role="client")

    def test_profile_path_relative_to_server_configuration(self):
        path = self.file("server-config.toml", 'profile_file="client.toml"')
        self.assertEqual(load_config(path).profile_file, (self.directory/"client.toml").resolve())

    def test_bad_client_auth_and_evidence_policy_fail_before_listening(self):
        credential = '[credential]\nchain="fullchain.pem"\nprivate_key="server.key"\n'
        for data in ('[client_auth]\nroots="ca.pem"', '[client_auth]\nrequired=false',
                     '[client_auth]\nraw_public_keys=["ca.pem"]'):
            with self.subTest(data=data), self.assertRaises((ConfigurationError, ProtocolError)):
                load_profile(self.profile("server", credential+data), role="server")
        for evidence in ('minimum_ct_v1_logs=1', 'require_ocsp=1', 'minimum_ct_v2_logs=-1'):
            with self.subTest(evidence=evidence), self.assertRaises(ConfigurationError):
                load_profile(self.profile("client", '[trust]\nroots="ca.pem"\n[trust.evidence]\n'+evidence), role="client")

    def test_dnssec_anchor_file_is_real_rrset_inventory(self):
        import dns.dnssec
        import dns.rrset
        from cryptography.hazmat.primitives.asymmetric import ed25519
        key=ed25519.Ed25519PrivateKey.generate()
        rrset=dns.rrset.from_rdata(".",300,dns.dnssec.make_dnskey(key.public_key(),"ED25519",flags=257))
        self.file("anchors.zone",rrset.to_text()+"\n")
        loaded=load_profile(self.profile("client", '[trust]\nserver_certificate_types=[2]\n'
            '[trust.dane]\nanchors_file="anchors.zone"'),role="client")
        self.addCleanup(loaded.close)
        self.assertEqual(loaded.options["credential_policy"].dane_policy.trust_anchors["."],rrset)
        self.file("anchors.zone",". 300 IN A 192.0.2.1\n")
        with self.assertRaises(ConfigurationError):
            load_profile(self.directory/"client.toml",role="client")


class ProfileNetworkTests(ProfileTests, unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.requests = []
        self.tasks = set()
        async def backend(reader, writer):
            task=asyncio.current_task(); self.tasks.add(task)
            try:
                self.requests.append(await reader.readuntil(b"\r\n\r\n"))
                writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")
                await writer.drain()
            finally:
                writer.close(); await writer.wait_closed(); self.tasks.discard(task)
        self.backend = await asyncio.start_server(backend, "127.0.0.1", 0)
        self.backend_port = self.backend.sockets[0].getsockname()[1]

    async def asyncTearDown(self):
        self.backend.close()
        await self.backend.wait_closed()
        if self.tasks:
            await asyncio.gather(*self.tasks)

    async def run_pair(self, mode, server_data, client_data, *, expect_early=True, request_early=True, service="localhost", client_mode=None):
        server_path = self.profile("server", server_data, mode, service=service)
        config = Config(listen=Endpoint("127.0.0.1", 0), upstream=Endpoint("127.0.0.1", self.backend_port),
            server_name=service, profile_file=server_path, upstream_early_data_aware=True, early_data_paths=("/",))
        running = await start_server(config)
        client = None
        try:
            port = running.server.sockets[0].getsockname()[1]
            client = load_profile(self.profile("client", client_data, client_mode or mode, port, service), role="client")
            cache = TicketCache()
            for early in (False, True):
                output=io.BytesIO()
                await fetch(f"httpps://{service}:{port}/", (), revocation_policy=None,
                    output=output, connect_host="127.0.0.1", timeout=10, ticket_cache=cache,
                    use_early_data=early and request_early, profile=client)
                self.assertTrue(output.getvalue().endswith(b"OK"))
            self.assertEqual(len(self.requests), 2)
            self.assertEqual(b"Early-Data: 1" in self.requests[-1],expect_early)
        finally:
            await running.close()
            if client is not None: client.close()

    async def test_configured_certificate_and_actual_early_relay(self):
        await self.run_pair("certificate", '[credential]\nchain="fullchain.pem"\nprivate_key="server.key"',
                            '[trust]\nroots="ca.pem"')

    async def test_configured_rpk_and_actual_early_relay(self):
        await self.run_pair("certificate", '[credential]\nraw_public_key="server.spki"\nprivate_key="server.key"',
                            '[trust]\nraw_public_keys=["server.spki"]')

    async def test_configured_psk_and_actual_early_relay(self):
        self.file("psk.bin", b"k"*32, private=True)
        data = '[[psks]]\nidentity_hex="616263"\nkey_file="psk.bin"'
        await self.run_pair("psk", data, data)

    async def test_configured_psk_only_imported_and_actual_early_relay(self):
        self.file("psk.bin", b"k"*32, private=True)
        data = '[negotiation]\npsk_modes=[0]\n[[psks]]\nidentity_hex="616263"\nkey_file="psk.bin"\nimport_context_hex="6465706c6f79"'
        await self.run_pair("psk", data, data)

    async def test_configured_combined_psk_requires_both_credentials_and_secret(self):
        self.file("psk.bin",b"k"*32,private=True)
        data='[[psks]]\nidentity_hex="616263"\nkey_file="psk.bin"\ncombined=true\n'
        await self.run_pair("psk",data+'[credential]\nchain="fullchain.pem"\nprivate_key="server.key"',
                            data+'[trust]\nroots="ca.pem"')

    async def test_configured_pinning_keeps_real_connections_fresh(self):
        self.file("pin.bin",b"p"*32,private=True)
        server='[credential]\nchain="fullchain.pem"\nprivate_key="server.key"\n'+\
               '[pinning]\ncurrent_id_hex="'+('ab'*16)+'"\n[[pinning.keys]]\nid_hex="'+('ab'*16)+'"\nkey_file="pin.bin"'
        client='[trust]\nroots="ca.pem"\n[pinning]\ncapacity=32'
        await self.run_pair("certificate",server,client,expect_early=False,request_early=False)

    async def test_configured_pok_bootstrap_and_successor_early_relay(self):
        common='[bootstrap]\npublic_key="server.spki"\nscope="test-service"\n'
        server='[credential]\nchain="fullchain.pem"\nprivate_key="server.key"\n'+common
        client='[trust]\nroots="ca.pem"\n'+common+'private_key="server.key"'
        await self.run_pair("pok",server,client)

    @unittest.skipUnless(os.environ.get("TLS20_TEST_OPENSSL"),"Explicit SM native provider required")
    async def test_configured_sm_suite_group_and_early_relay(self):
        common='[provider]\nlibrary='+repr(os.environ["TLS20_TEST_OPENSSL"])+\
               '\n[negotiation]\ncipher_suites=[0x00c6]\nsupported_groups=[41]\n'
        await self.run_pair("certificate",common+'[credential]\nchain="fullchain.pem"\nprivate_key="server.key"',
            common+'traffic_group=41\n[trust]\nroots="ca.pem"')

    @unittest.skipUnless(os.environ.get("TLS20_TEST_OPENSSL") and os.environ.get("TLS20_TEST_GOST_MODULE"),"Explicit GOST provider required")
    async def test_configured_gost_suite_group_and_early_relay(self):
        common='[provider]\nlibrary='+repr(os.environ["TLS20_TEST_OPENSSL"])+\
               '\ngost_module='+repr(os.environ["TLS20_TEST_GOST_MODULE"])+\
               '\n[negotiation]\ncipher_suites=[0xc103]\nsupported_groups=[34]\n'
        await self.run_pair("certificate",common+'[credential]\nchain="fullchain.pem"\nprivate_key="server.key"',
            common+'traffic_group=34\n[trust]\nroots="ca.pem"')

    @unittest.skipUnless(os.getenv("TLS20_TEST_ITS_LIBRARY") and os.getenv("TLS20_ITS_FIXTURE_DIR"),
                         "Explicit native ITS provider and live fixture required")
    async def test_configured_its_grant_and_actual_early_relay(self):
        from tests.test_its_handshake import load_live_fixture
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
        directory,policy=load_live_fixture()
        self.file("its-grant.bin",(directory/"live-server.bin").read_bytes())
        self.file("its-root.coer",policy.trust_roots[0])
        self.file("its.key",X25519PrivateKey.from_private_bytes(bytes([9])*32).private_bytes(
            serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()),private=True)
        settings=('library='+repr(os.environ["TLS20_TEST_ITS_LIBRARY"])+f'\npsid={policy.psid}\n'+
            'application_scope_hex="'+policy.application_scope.hex()+'"\nssp_coer_hex="'+policy.ssp_coer.hex()+'"\n'+
            'roots=["its-root.coer"]\nauthorized_leaf_sha256=["'+policy.authorized_leaf_sha256[0].hex()+'"]\n'+
            f'inventory_valid_until={policy.inventory_valid_until}\nmax_grant_lifetime_microseconds={policy.max_grant_lifetime_microseconds}\n'+
            f'tai_utc_offset={policy.tai_utc_offset}\n')
        server='[credential]\nits_grant="its-grant.bin"\nprivate_key="its.key"\n[credential.its]\n'+settings
        client='[trust.its]\n'+settings
        await self.run_pair("certificate",server,client,service="example.test")
        bad=client.replace(f'inventory_valid_until={policy.inventory_valid_until}', 'inventory_valid_until=1')
        with self.assertRaises(ConfigurationError):
            load_profile(self.profile("client",bad,service="example.test"),role="client")

    async def test_configured_client_rpk_authorization_and_early_identity(self):
        server='[credential]\nchain="fullchain.pem"\nprivate_key="server.key"\n'+\
               '[client_auth]\nidentity="localhost"\nraw_public_keys=["server.spki"]'
        client='[credential]\nraw_public_key="server.spki"\nprivate_key="server.key"\n'+\
               '[trust]\nroots="ca.pem"'
        await self.run_pair("certificate",server,client)

    async def test_explicit_group_policy_performs_useful_retry(self):
        server='[negotiation]\nsupported_groups=[23]\n[credential]\nchain="fullchain.pem"\nprivate_key="server.key"'
        client='[negotiation]\nsupported_groups=[29,23]\ntraffic_group=29\n[trust]\nroots="ca.pem"'
        await self.run_pair("certificate",server,client,expect_early=False)

    @unittest.skipUnless(os.environ.get("TLS20_TEST_OPENSSL") and os.environ.get("TLS20_TEST_PAKE"), "Explicit native PAKE provider required")
    async def test_configured_password_and_actual_early_relay(self):
        from tls20_server.pake import PasswordAccount
        account = PasswordAccount.provision("alice", "correct horse battery staple")
        self.file("accounts.toml", '[[accounts]]\nusername_hex="'+account.username.hex()+'"\nbase_hex="'+account.base.hex()+
                  '"\nsalt_hex="'+account.salt.hex()+'"\n', private=True)
        self.file("username.txt", "alice", private=True)
        self.file("password.txt", "correct horse battery staple", private=True)
        provider = '[provider]\nlibrary='+repr(os.environ["TLS20_TEST_OPENSSL"])+ '\npake_helper='+repr(os.environ["TLS20_TEST_PAKE"])+"\n"
        await self.run_pair("pake", provider+'[password]\naccounts_file="accounts.toml"',
                            provider+'[password]\nusername_file="username.txt"\npassword_file="password.txt"')

    @unittest.skipUnless(os.environ.get("TLS20_TEST_OPENSSL") and os.environ.get("TLS20_TEST_PAKE"), "Explicit native PAKE provider required")
    async def test_configured_mixed_selection_and_successor_early_relay(self):
        from tls20_server.pake import PasswordAccount
        account=PasswordAccount.provision("alice","correct horse battery staple")
        self.file("accounts.toml",'[[accounts]]\nusername_hex="'+account.username.hex()+'"\nbase_hex="'+account.base.hex()+
            '"\nsalt_hex="'+account.salt.hex()+'"\n',private=True)
        self.file("username.txt","alice",private=True)
        self.file("password.txt","correct horse battery staple",private=True)
        provider='[provider]\nlibrary='+repr(os.environ["TLS20_TEST_OPENSSL"])+ '\npake_helper='+repr(os.environ["TLS20_TEST_PAKE"])+"\n"
        client=(provider+'[negotiation]\nenable_authenticators=true\nmax_fragment_length=1\n'+
            '[password]\nusername_file="username.txt"\npassword_file="password.txt"\n[trust]\nroots="ca.pem"')
        for mode,server in (("pake",provider+'[negotiation]\nenable_authenticators=true\n[password]\naccounts_file="accounts.toml"'),
                            ("certificate",'[credential]\nchain="fullchain.pem"\nprivate_key="server.key"')):
            with self.subTest(selected=mode):
                self.requests.clear()
                await self.run_pair(mode,server,client,client_mode="mixed")
        for extra in ('[negotiation]\ncipher_suites=[0xc0b0]',
                      '[negotiation]\ncipher_suites=[0x1301]',
                      '[negotiation]\nsupported_groups=[29]',
                      '[pinning]\nignored=true'):
            with self.subTest(rejected=extra),self.assertRaises((ConfigurationError,ProtocolError)):
                load_profile(self.profile("client",provider+extra,mode="mixed"),role="client")
        with self.assertRaises(ConfigurationError):
            load_profile(self.profile("server",provider,mode="mixed"),role="server")
