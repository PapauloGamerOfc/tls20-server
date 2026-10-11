"""Real certificate chains cross the same bounded loading and wire paths."""

from pathlib import Path
import os
import unittest
from unittest.mock import Mock, patch

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.x509.oid import NameOID

from tls20_server import messages as m, pki
from tls20_server.credential_profiles import CredentialPolicy
from tls20_server.errors import ConfigurationError, ProtocolError
from tests.test_pki import der, issue
from tests import test_sessions


def chain_material(count):
    """Return public, freshly generated test certificates and their leaf key."""
    root_key = ed25519.Ed25519PrivateKey.generate()
    name = lambda value: x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, value)])
    root_name = name("Budget root")
    root = issue(root_key, root_key, root_name, root_name, ca=True, path_length=count)
    issuer_key, issuer_name, intermediates = root_key, root_name, []
    for index in range(count - 1):
        key = ed25519.Ed25519PrivateKey.generate()
        subject = name(f"Intermediate {index}")
        intermediates.append(issue(key, issuer_key, subject, issuer_name,
            ca=True, path_length=count - index - 2,
            extra=[(x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()), False)]))
        issuer_key, issuer_name = key, subject
    leaf_key = x25519.X25519PrivateKey.generate()
    leaf = issue(leaf_key, issuer_key, name("localhost"), issuer_name, hostname="localhost",
        extra=[(x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()), False)])
    return [leaf, *reversed(intermediates)], leaf_key, root


def load_material(certs, key):
    chain_pem = b"".join(cert.public_bytes(serialization.Encoding.PEM) for cert in certs)
    key_pem = key.private_bytes(serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    with patch.object(pki, "_read_file", side_effect=lambda path, limit, private=False:
                      key_pem if private else chain_pem):
        return pki.load_credentials(Path("in-memory-chain.pem"), Path("in-memory-key.pem"), "localhost")


class CertificateBudgetTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.certs, cls.key, cls.root = chain_material(64)
        cls.chain = list(map(der, cls.certs))

    def test_64_presented_certificates_plus_separate_anchor(self):
        credentials = load_material(self.certs, self.key)
        self.assertEqual(credentials.chain_der, self.chain)
        self.assertEqual(m.parse_certificate(m.certificate(self.chain)[4:]), self.chain)
        path = pki.validate_pkix_path(self.chain, (self.root,))
        self.assertEqual(len(path), 65)
        self.assertEqual(der(path[-1]), der(self.root))
        self.assertEqual(pki.validate_chain(self.chain, [self.root], "localhost", "lab-offline").public_bytes_raw(),
                         self.key.public_key().public_bytes_raw())
        # The native-provider boundary has the same allowance for one anchor.
        provider = Mock()
        provider.verify_certificate_path.return_value = tuple(map(der, path))
        self.assertEqual(len(pki.validate_pkix_path(self.chain, (self.root,), signature_provider=provider)), 65)
        provider.verify_certificate_path.return_value += (der(self.root),)
        with self.assertRaises(ProtocolError):
            pki.validate_pkix_path(self.chain, (self.root,), signature_provider=provider)

    def test_65_presented_certificates_are_rejected_before_path_work(self):
        too_many = [*self.chain, der(self.root)]
        with self.assertRaises(ConfigurationError):
            load_material([*self.certs, self.root], self.key)
        with self.assertRaises(ProtocolError):
            m.certificate(too_many)
        with patch.object(pki, "_load_pkix_der") as parse_der:
            with self.assertRaises(ProtocolError):
                pki.validate_pkix_path(too_many, (self.root,))
            parse_der.assert_not_called()
        with self.assertRaises(ProtocolError):
            pki.validate_chain(too_many, [self.root], "localhost", "lab-offline")

    @unittest.skipUnless(os.environ.get("TLS20_TEST_OPENSSL"), "explicit native provider fixture not configured")
    def test_native_provider_64_certificates_plus_anchor(self):
        from tls20_server.openssl_provider import OpenSSLProvider
        provider = OpenSSLProvider(os.environ["TLS20_TEST_OPENSSL"])
        try:
            path = pki.validate_pkix_path(self.chain, (self.root,), signature_provider=provider)
            self.assertEqual(tuple(map(der, path)), (*self.chain, der(self.root)))
            with self.assertRaises(ProtocolError):
                provider.verify_certificate_path([*self.chain, der(self.root)], (der(self.root),))
        finally:
            provider.close()

    def test_pkix_rejects_minimal_encoded_body_over_budget_before_der(self):
        # Four individually bounded certificates still exceed the body budget
        # once the context/list/entry length fields are included.
        chain = [b"x" * 65536] * 4
        with patch.object(pki, "_load_pkix_der") as parse_der:
            with self.assertRaises(ProtocolError):
                pki.validate_pkix_path(chain, (self.root,))
            parse_der.assert_not_called()

    def test_loader_rejects_valid_der_chain_that_cannot_fit_wire_body(self):
        original_issue = issue
        def padded_issue(key, issuer_key, *args, **kwargs):
            if key is issuer_key:  # The separate trust anchor is not sent.
                return original_issue(key, issuer_key, *args, **kwargs)
            extra = kwargs.pop("extra", [])
            def build(size):
                padding = x509.UnrecognizedExtension(x509.ObjectIdentifier("1.2.3.4"), b"p" * size)
                return original_issue(key, issuer_key, *args, **kwargs, extra=[*extra, (padding, False)])
            probe = build(64000)
            return build(64000 + 65536 - len(der(probe)))
        with patch(__name__ + ".issue", padded_issue):
            certs, key, _ = chain_material(4)
        self.assertEqual([len(der(cert)) for cert in certs], [65536] * 4)
        with self.assertRaises(ConfigurationError):
            load_material(certs, key)


class CertificateChainHandshakeTests(unittest.IsolatedAsyncioTestCase):
    asyncSetUp = test_sessions.SessionTests.asyncSetUp
    asyncTearDown = test_sessions.SessionTests.asyncTearDown
    accept = test_sessions.SessionTests.accept
    handle = test_sessions.SessionTests.handle
    connect = test_sessions.SessionTests.connect

    async def test_long_certificate_chains_complete_handshake_and_echo(self):
        for count in (9, 64):
            certs, key, root = chain_material(count)
            self.credentials, self.roots = load_material(certs, key), [root]
            for policy in (None, CredentialPolicy(trust_roots=(root,), peer_name="localhost", revocation_policy="offline")):
                with self.subTest(count=count, generic=policy is not None):
                    self.cache = test_sessions.TicketCache()
                    channel = await self.connect(credential_policy=policy)
                    self.assertFalse(channel.resumed)
                    await channel.send(b"eight certificates are not a protocol limit")
                    self.assertEqual(await channel.recv(), b"eight certificates are not a protocol limit")
                    await channel.close()
        self.assertFalse(self.errors)
