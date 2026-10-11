"""Real GOST CA/leaf and offline grants signed by a separate OpenSSL process."""

from dataclasses import replace
from datetime import datetime, timezone, timedelta
import base64
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
from tls20_server.gost_provider import GOSTProvider
from tls20_server.pki import (GOSTPublicKey, certificate_public_key, certificate_signature_scheme,
    find_certificate_issuer, load_credentials, load_trust_roots, supported_certificate_algorithms, verify_public_signature)


@unittest.skipUnless(all(os.environ.get(name) for name in
    ("TLS20_TEST_OPENSSL", "TLS20_TEST_OPENSSL_CLI", "TLS20_TEST_GOST_MODULE")), "explicit GOST fixtures unavailable")
class GOSTCredentialTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.work = Path(self.directory.name)
        self.provider = GOSTProvider(os.environ["TLS20_TEST_OPENSSL"], os.environ["TLS20_TEST_GOST_MODULE"])
        self.addCleanup(self.provider.close)
        self.cli = os.environ["TLS20_TEST_OPENSSL_CLI"]
        self.module = os.environ["TLS20_TEST_GOST_MODULE"]
        if not Path(self.cli).is_absolute():
            self.fail("CLI must be an explicit absolute path")
        self.key = x25519.X25519PrivateKey.generate()
        self.write("leaf.key", self.key.private_bytes(serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        (self.work / "leaf.key").chmod(0o600)
        self.write("leaf.pub", self.key.public_key().public_bytes(serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo))

    def write(self, filename, value):
        (self.work / filename).write_bytes(value.encode() if isinstance(value, str) else value)

    def run_cli(self, command, *args):
        process = subprocess.run((self.cli, command, "-provider", "default", "-provider", self.module, *args),
                                 cwd=self.work, capture_output=True, timeout=20)
        if process.returncode:
            self.fail(f"GOST signing fixture {command}: {process.stderr.decode(errors='replace')}")

    def cert(self, name):
        return x509.load_pem_x509_certificate((self.work / f"{name}.pem").read_bytes())

    def der(self, cert):
        return cert.public_bytes(serialization.Encoding.DER)

    def canonical_signature(self, name):
        # gost-engine's current X509 signer emits NULL parameters. RFC9215
        # requires absent parameters. Rebuild the public TBS and re-sign with
        # the independent CLI, never relaxing the verifier to fit that bug.
        from tls20_server.pki import _element, _children
        def tlv(tag, body):
            size = len(body)
            length = bytes([size]) if size < 128 else bytes([0x80 | ((size.bit_length() + 7) // 8)]) + size.to_bytes((size.bit_length() + 7) // 8, "big")
            return bytes([tag]) + length + body
        outer = _children(_element(self.der(self.cert(name)))[1])
        tbs = _children(outer[0][1])
        index = 2 if tbs[0][0] == 0xa0 else 1
        algorithm = tlv(0x30, _children(tbs[index][1])[0][2])
        body = tlv(0x30, b"".join(algorithm if i == index else item[2] for i, item in enumerate(tbs)))
        self.write("tbs.bin", body)
        self.run_cli("dgst", "-" + self.hash, "-sign", "root.key", "-out", "certificate.sig", "tbs.bin")
        cert = tlv(0x30, body + algorithm + tlv(3, b"\0" + (self.work / "certificate.sig").read_bytes()))
        encoded = base64.b64encode(cert)
        self.write(name + ".pem", b"-----BEGIN CERTIFICATE-----\n" + b"\n".join(encoded[i:i+64] for i in range(0, len(encoded), 64)) + b"\n-----END CERTIFICATE-----\n")

    def create_chain(self, group, root_extra=""):
        self.algorithm = "gost2012_512" if group >= 38 else "gost2012_256"
        curve = ("A", "B", "C")[group - 38] if group >= 38 else ("TCA", "TCB", "TCC", "TCD")[group - 34]
        self.hash = "md_gost12_512" if group >= 38 else "md_gost12_256"
        self.scheme = 0x0709 + group - 34
        self.run_cli("genpkey", "-algorithm", self.algorithm, "-pkeyopt", f"paramset:{curve}", "-out", "root.key")
        self.write("root.cnf", "[req]\ndistinguished_name=dn\n[dn]\n[x509]\n"
            "basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\n"
            "subjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid:always\n" + root_extra)
        self.run_cli("req", "-new", "-x509", "-key", "root.key", "-" + self.hash, "-days", "2",
            "-subj", "/CN=Explicit GOST Test Root", "-config", "root.cnf", "-extensions", "x509", "-out", "root.pem")
        self.canonical_signature("root")
        self.issue("leaf", "leaf.pub", "keyAgreement")
        self.root, self.leaf = self.cert("root"), self.cert("leaf")
        self.policy = CredentialPolicy(trust_roots=(self.root,), peer_name="example.test", signature_provider=self.provider)

    def issue(self, stem, public, usage, extra="", eku="serverAuth"):
        self.write(stem + ".cnf", "[extensions]\nbasicConstraints=critical,CA:FALSE\n"
            f"keyUsage=critical,{usage}\nextendedKeyUsage={eku}\nsubjectAltName=DNS:example.test\n"
            "subjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid:always\n" + extra)
        self.run_cli("x509", "-new", "-force_pubkey", public, "-CA", "root.pem", "-CAkey", "root.key",
            "-set_serial", str(100 + len(stem)), "-subj", "/CN=GOST Test Endpoint", "-" + self.hash,
            "-days", "1", "-extfile", stem + ".cnf", "-extensions", "extensions", "-out", stem + ".pem")
        self.canonical_signature(stem)

    def test_all_seven_signature_schemes_validate_real_pkix_and_wrong_name(self):
        for group in range(34, 41):
            with self.subTest(group=group):
                self.create_chain(group)
                self.assertEqual(certificate_signature_scheme(self.leaf, self.root), self.scheme)
                issuer = find_certificate_issuer(self.leaf, (self.der(self.root),), signature_provider=self.provider)
                self.assertEqual(issuer, self.root)
                self.assertEqual(certificate_signature_scheme(self.leaf, issuer), self.scheme)
                bad = self.der(self.leaf)[:-1] + bytes([self.der(self.leaf)[-1] ^ 1])
                self.assertIsNone(find_certificate_issuer(bad, (self.root,), signature_provider=self.provider))
                self.assertNotIn(self.scheme, supported_certificate_algorithms())
                self.assertIn(self.scheme, supported_certificate_algorithms(self.provider))
                authorized = resolve_peer([self.der(self.leaf)], policy=self.policy, certificate_algorithms=(self.scheme,))
                self.assertEqual(authorized.public_key.public_bytes_raw(), self.key.public_key().public_bytes_raw())
                for policy, offers in ((self.policy, (0x0807,)), (replace(self.policy, peer_name="wrong.test"), (self.scheme,))):
                    with self.assertRaises(ProtocolError):
                        resolve_peer([self.der(self.leaf)], policy=policy, certificate_algorithms=offers)

    def test_offline_grant_uses_exact_rfc9367_encoding_and_loader(self):
        self.create_chain(34)
        roots = load_trust_roots(self.work / "root.pem", general_pkix=True, signature_provider=self.provider)
        self.assertIsInstance(certificate_public_key(roots[0], signature_provider=self.provider), GOSTPublicKey)
        self.write("chain.pem", (self.work / "leaf.pem").read_bytes() + (self.work / "root.pem").read_bytes())
        self.assertEqual(load_credentials(self.work / "chain.pem", self.work / "leaf.key", "example.test",
            signature_provider=self.provider).private_key.public_key().public_bytes_raw(), self.key.public_key().public_bytes_raw())
        self.run_cli("pkey", "-in", "root.key", "-pubout", "-out", "parent.pub")
        self.issue("parent", "parent.pub", "digitalSignature", "1.3.6.1.4.1.44363.44=DER:05:00\n")
        parent = self.cert("parent")
        public = self.key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        duration = int((datetime.now(timezone.utc) - parent.not_valid_before_utc).total_seconds()) + 600
        signed = duration.to_bytes(4, "big") + b"\xfe\x00" + len(public).to_bytes(3, "big") + public + self.scheme.to_bytes(2, "big")
        message = b" " * 64 + b"TLS20 server delegated credentials\0" + self.der(parent) + signed
        self.write("message.bin", message)
        self.run_cli("dgst", "-" + self.hash, "-sign", "root.key", "-out", "signature.bin", "message.bin")
        signature = (self.work / "signature.bin").read_bytes()[::-1]
        grant = signed + len(signature).to_bytes(2, "big") + signature
        result = resolve_peer([self.der(parent)], policy=self.policy, certificate_algorithms=(self.scheme,),
            grant_algorithms=(self.scheme,), delegated_schemes=(0xfe00,), entry_extensions=(((34, grant),),))
        self.assertEqual(result.public_key.public_bytes_raw(), self.key.public_key().public_bytes_raw())
        public_key = certificate_public_key(parent, signature_provider=self.provider)
        for scheme, sig, data in ((self.scheme + 1, signature, message), (self.scheme, signature[::-1], message),
                                  (self.scheme, signature, message + b"x")):
            with self.assertRaises(ProtocolError):
                verify_public_signature(public_key, scheme, sig, data)

    def test_gost_signature_bridge_does_not_bypass_pkix(self):
        self.create_chain(34)
        leaf, root = self.der(self.leaf), self.der(self.root)
        self.provider.verify_certificate_path([leaf], [root], server_name="example.test")
        bad = leaf[:-1] + bytes([leaf[-1] ^ 1])
        for material, policy in ((bad, {}), (leaf, {"server_name": "wrong.test"}), (leaf, {"now": 0})):
            with self.subTest(policy=policy), self.assertRaises(ProtocolError):
                self.provider.verify_certificate_path([material], [root], **policy)
        self.issue("wrong_eku", "leaf.pub", "keyAgreement", eku="clientAuth")
        self.issue("critical", "leaf.pub", "keyAgreement", "1.2.3.99=critical,DER:05:00\n")
        self.issue("wrong_ku", "leaf.pub", "digitalSignature")
        for stem in ("wrong_eku", "critical", "wrong_ku"):
            with self.subTest(stem=stem), self.assertRaises(ProtocolError):
                resolve_peer([self.der(self.cert(stem))], policy=self.policy, certificate_algorithms=(self.scheme,))
        # Same textual issuer name, but an unrelated key/anchor must fail.
        self.create_chain(34)
        with self.assertRaises(ProtocolError):
            self.provider.verify_certificate_path([leaf], [self.der(self.root)])
        self.create_chain(34, "nameConstraints=critical,permitted;DNS:other.test\n")
        with self.assertRaises(ProtocolError):
            self.provider.verify_certificate_path([self.der(self.leaf)], [self.der(self.root)])

    def test_signature_bridge_never_overrides_rsa_or_ecdsa(self):
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec, rsa
        from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
        now = datetime.now(timezone.utc)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Non-GOST Test Root")])
        for signing in (ec.generate_private_key(ec.SECP256R1()), rsa.generate_private_key(65537, 2048)):
            root = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(signing.public_key())
                .serial_number(1).not_valid_before(now - timedelta(days=1)).not_valid_after(now + timedelta(days=1))
                .add_extension(x509.BasicConstraints(ca=True, path_length=0), True)
                .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), True)
                .add_extension(x509.SubjectKeyIdentifier.from_public_key(signing.public_key()), False)
                .sign(signing, hashes.SHA256()))
            leaf = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(self.key.public_key())
                .serial_number(2).not_valid_before(now - timedelta(days=1)).not_valid_after(now + timedelta(days=1))
                .add_extension(x509.BasicConstraints(ca=False, path_length=None), True)
                .add_extension(x509.KeyUsage(False, False, False, False, True, False, False, False, False), True)
                .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), False)
                .add_extension(x509.SubjectAlternativeName([x509.DNSName("example.test")]), False)
                .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(signing.public_key()), False)
                .sign(signing, hashes.SHA256()))
            raw = self.der(leaf)
            self.provider.verify_certificate_path([raw], [self.der(root)], server_name="example.test")
            with self.assertRaises(ProtocolError):
                self.provider.verify_certificate_path([raw[:-1] + bytes([raw[-1] ^ 1])], [self.der(root)])
