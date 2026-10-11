"""Optional SM2 PKIX/DC integration using an independently signing OpenSSL CLI.

Both executable and provider paths must be explicitly selected by the operator;
tests never search PATH for a cryptographic library or download one.
"""

from dataclasses import replace
from datetime import datetime, timezone
import asyncio
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519

from tls20_server.credential_profiles import CredentialPolicy, resolve_peer
from tls20_server.errors import ProtocolError
from tls20_server.openssl_provider import OpenSSLProvider
from tls20_server.pki import (Credentials, SM2PublicKey, certificate_public_key,
    certificate_signature_scheme, load_credentials, load_trust_roots,
    supported_certificate_algorithms, validate_identity, verify_public_signature)


@unittest.skipUnless(os.environ.get("TLS20_TEST_OPENSSL") and os.environ.get("TLS20_TEST_OPENSSL_CLI"),
                     "explicit native provider and OpenSSL signing CLI not configured")
class SM2CredentialTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.work = Path(self.directory.name)
        self.provider = OpenSSLProvider(os.environ["TLS20_TEST_OPENSSL"])
        self.addCleanup(self.provider.close)
        self.cli = os.environ["TLS20_TEST_OPENSSL_CLI"]
        if not Path(self.cli).is_absolute():
            self.fail("signing fixture CLI path must be absolute")
        self.run_cli('genpkey', '-algorithm', 'SM2', '-out', 'root.key')
        self.write('root.cnf', '[req]\ndistinguished_name=dn\n[dn]\n[x509]\n'
                   'basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\n'
                   'subjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid:always\n')
        self.run_cli('req', '-new', '-x509', '-key', 'root.key', '-sm3', '-days', '2',
                     '-sigopt', 'distid:1234567812345678',
                     '-subj', '/CN=Explicit SM2 Test Root', '-config', 'root.cnf',
                     '-extensions', 'x509', '-out', 'root.pem')
        self.key = x25519.X25519PrivateKey.generate()
        self.write('leaf.key', self.key.private_bytes(serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        (self.work / 'leaf.key').chmod(0o600)
        self.write('leaf.pub', self.key.public_key().public_bytes(serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo))
        self.issue('leaf', 'leaf.pub', 'keyAgreement')
        self.root, self.leaf = self.cert('root'), self.cert('leaf')
        self.policy = CredentialPolicy(trust_roots=(self.root,), peer_name='example.test',
                                        signature_provider=self.provider)

    def write(self, name, value):
        (self.work / name).write_bytes(value.encode() if isinstance(value, str) else value)

    def run_cli(self, *args):
        process = subprocess.run((self.cli, *args), cwd=self.work, capture_output=True, timeout=20)
        if process.returncode:
            self.fail(f"signing fixture {args[0]} failed: {process.stderr.decode(errors='replace')}")

    def cert(self, stem):
        return x509.load_pem_x509_certificate((self.work / f'{stem}.pem').read_bytes())

    def der(self, cert):
        return cert.public_bytes(serialization.Encoding.DER)

    def issue(self, stem, public_file, usage, *, eku='serverAuth', extra=''):
        self.write(f'{stem}.cnf', '[extensions]\nbasicConstraints=critical,CA:FALSE\n'
                   f'keyUsage=critical,{usage}\nextendedKeyUsage={eku}\n'
                   'subjectAltName=DNS:example.test\nsubjectKeyIdentifier=hash\n'
                   'authorityKeyIdentifier=keyid:always\n' + extra)
        self.run_cli('x509', '-new', '-force_pubkey', public_file, '-CA', 'root.pem',
                     '-CAkey', 'root.key', '-set_serial', str(100 + len(stem)), '-subj',
                     '/CN=SM2 Test Endpoint', '-sm3', '-days', '1', '-extfile', f'{stem}.cnf',
                     '-sigopt', 'distid:1234567812345678',
                     '-extensions', 'extensions', '-out', f'{stem}.pem')

    def test_real_sm2_path_and_independent_offer(self):
        self.assertEqual(certificate_signature_scheme(self.leaf, self.root), 0x0708)
        self.assertNotIn(0x0708, supported_certificate_algorithms())
        self.assertIn(0x0708, supported_certificate_algorithms(self.provider))
        result = resolve_peer([self.der(self.leaf)], policy=self.policy,
                              certificate_algorithms=(0x0708,))
        self.assertEqual(result.public_key.public_bytes_raw(), self.key.public_key().public_bytes_raw())
        for policy, offers in ((self.policy, (0x0403,)),
                               (replace(self.policy, peer_name='wrong.test'), (0x0708,)),
                               (replace(self.policy, trust_roots=()), (0x0708,))):
            with self.subTest(policy=policy.peer_name, offers=offers), self.assertRaises(ProtocolError):
                resolve_peer([self.der(self.leaf)], policy=policy, certificate_algorithms=offers)

    def test_explicit_root_and_local_bundle_loading(self):
        roots = load_trust_roots(self.work / 'root.pem', general_pkix=True,
                                 signature_provider=self.provider)
        self.assertIsInstance(certificate_public_key(roots[0], signature_provider=self.provider), SM2PublicKey)
        with self.assertRaises(ProtocolError):
            certificate_public_key(roots[0])
        self.write('chain.pem', (self.work / 'leaf.pem').read_bytes() + (self.work / 'root.pem').read_bytes())
        credentials = load_credentials(self.work / 'chain.pem', self.work / 'leaf.key',
                                        'example.test', signature_provider=self.provider)
        self.assertEqual(credentials.private_key.public_key().public_bytes_raw(), self.key.public_key().public_bytes_raw())

    def test_client_purpose_is_not_silently_server_purpose(self):
        self.issue('client', 'leaf.pub', 'keyAgreement', eku='clientAuth')
        client = self.der(self.cert('client'))
        key = validate_identity([client], trust_roots=(self.root,), role='client',
                                signature_provider=self.provider, offered_certificate_algorithms=(0x0708,))
        self.assertEqual(key.public_bytes_raw(), self.key.public_key().public_bytes_raw())
        with self.assertRaises(ProtocolError):
            validate_identity([client], trust_roots=(self.root,), role='server', name='example.test',
                              signature_provider=self.provider, offered_certificate_algorithms=(0x0708,))

    def delegated_fixture(self):
        self.run_cli('genpkey', '-algorithm', 'SM2', '-out', 'parent.key')
        self.run_cli('pkey', '-in', 'parent.key', '-pubout', '-out', 'parent.pub')
        self.issue('parent', 'parent.pub', 'digitalSignature', extra='1.3.6.1.4.1.44363.44=DER:05:00\n')
        parent = self.cert('parent')
        public = self.key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        valid_time = int((datetime.now(timezone.utc) - parent.not_valid_before_utc).total_seconds()) + 600
        signed = valid_time.to_bytes(4, 'big') + b'\xfe\x00' + len(public).to_bytes(3, 'big') + public + b'\x07\x08'
        message = b' ' * 64 + b'TLS20 server delegated credentials\x00' + self.der(parent) + signed
        self.write('message.bin', message)
        self.run_cli('pkeyutl', '-sign', '-rawin', '-digest', 'sm3', '-inkey', 'parent.key',
                     '-pkeyopt', 'distid:TLSv1.3+GM+Cipher+Suite', '-in', 'message.bin', '-out', 'signature.bin')
        signature = (self.work / 'signature.bin').read_bytes()
        grant = signed + len(signature).to_bytes(2, 'big') + signature
        return parent, grant, signature, message

    def test_sm2_delegation_signature_context_and_parent_path(self):
        parent, grant, signature, message = self.delegated_fixture()
        result = resolve_peer([self.der(parent)], policy=self.policy, certificate_algorithms=(0x0708,),
            grant_algorithms=(0x0708,), delegated_schemes=(0xfe00,), entry_extensions=(((34, grant),),))
        self.assertEqual(result.provenance, 'x509-delegated')
        self.assertEqual(result.public_key.public_bytes_raw(), self.key.public_key().public_bytes_raw())
        public_key = certificate_public_key(parent, signature_provider=self.provider)
        verify_public_signature(public_key, 0x0708, signature, message)
        for changed in (message + b'x', b'TLS20 client' + message):
            with self.assertRaises(ProtocolError):
                verify_public_signature(public_key, 0x0708, signature, changed)
        with self.assertRaises(ProtocolError):
            verify_public_signature(public_key, 0x0708, signature, message,
                                    sm2_identifier=b'1234567812345678')

    def test_real_tcp_sm2_chain_and_delegated_grant_full_resume_early(self):
        from tls20_server.handshake import client_handshake, server_handshake
        from tls20_server.tickets import TicketCache, TicketStore
        parent, grant, _, _ = self.delegated_fixture()

        async def exercise():
            for delegated in (False, True):
                for suite in (0xc6, 0xc7):
                    credentials = Credentials([self.der(parent if delegated else self.leaf), self.der(self.root)],
                        self.key, delegation=grant if delegated else b'')
                    cache, store = TicketCache(), TicketStore()
                    tasks, writers, errors, channels, early = set(), [], [], [], []
                    async def received_early(data):
                        early.append(data)
                    async def handle(reader, writer):
                        writers.append(writer)
                        try:
                            channel = await server_handshake(reader, writer, credentials, 'example.test',
                                cipher_suites=(suite,), native_provider=self.provider,
                                ticket_store=store, max_early_data=4096, on_early_data=received_early, timeout=5)
                            channels.append(channel)
                            await channel.send(b'authenticated')
                            while (value := await channel.recv()) is not None:
                                await channel.send(value)
                        except Exception as exc:
                            errors.append(str(exc))
                        finally:
                            writer.close()
                    def accept(reader, writer):
                        task = asyncio.create_task(handle(reader, writer))
                        tasks.add(task)
                        task.add_done_callback(tasks.discard)
                    listener = await asyncio.start_server(accept, '127.0.0.1', 0)
                    port = listener.sockets[0].getsockname()[1]
                    try:
                        for index in range(3):
                            reader, writer = await asyncio.open_connection('127.0.0.1', port)
                            writers.append(writer)
                            client = await client_handshake(reader, writer, 'example.test', [self.root],
                                revocation_policy='offline', credential_policy=self.policy,
                                cipher_suites=(suite,), native_provider=self.provider, traffic_group=41,
                                delegated_credentials=delegated, ticket_cache=cache,
                                early_data=b'SM2 log-free early application' if index == 2 else b'', timeout=5)
                            self.assertEqual(await asyncio.wait_for(client.recv(), 3), b'authenticated', errors)
                            self.assertEqual(client.resumed, index > 0)
                            self.assertEqual(client.early_data_accepted, index == 2)
                            self.assertEqual(client.exporter('identity scope'), channels[-1].exporter('identity scope'))
                            await client.key_update(request_peer=True)
                            await client.send(b'current SM3 epoch')
                            self.assertEqual(await asyncio.wait_for(client.recv(), 3), b'current SM3 epoch')
                        self.assertEqual(early, [b'SM2 log-free early application', b''])
                        self.assertFalse(errors)
                    finally:
                        listener.close()
                        for writer in writers:
                            writer.transport.abort()
                        await asyncio.wait_for(listener.wait_closed(), 2)
                        pending = tuple(tasks)
                        for task in pending:
                            task.cancel()
                        await asyncio.gather(*pending, return_exceptions=True)
        async def bounded():
            await asyncio.wait_for(exercise(), 30)
        asyncio.run(bounded())
