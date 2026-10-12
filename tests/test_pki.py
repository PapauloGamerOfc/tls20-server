"""Positive and adversarial lab-certificate tests using real signatures."""

from datetime import datetime, timedelta, timezone
import base64
import ipaddress
import os
from pathlib import Path
import tempfile
import unittest

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, utils, x25519
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from tls20_server.errors import ConfigurationError, ProtocolError
from tls20_server.lab import create_lab, generate_lab_credentials
from tls20_server.pki import _children, _element, _parse_der, load_credentials, load_trust_roots, validate_chain, validate_server_name, validate_service_identity


def der(cert):
    return cert.public_bytes(serialization.Encoding.DER)


def replace_signature(cert, signature):
    """Re-envelope a test signature without relying on a valid signing key."""
    def tlv(tag, body):
        size = len(body)
        count = max(1, (size.bit_length() + 7) // 8)
        length = bytes([size]) if size < 128 else bytes([0x80 | count]) + size.to_bytes(count, "big")
        return bytes([tag]) + length + body
    _, body, _, _ = _element(der(cert))
    children = _children(body)
    return tlv(0x30, children[0][2] + children[1][2] + tlv(0x03, b"\x00" + signature))


def issue(key, issuer_key, subject, issuer, *, ca=False, path_length=None,
          hostname="example.test", eku=True, bc_critical=True, key_usage=None,
          validity=0, extra=None, algorithm=None, serial=None):
    now = datetime.now(timezone.utc)
    start = now - timedelta(minutes=5) if validity <= 0 else now + timedelta(days=1)
    end = now + timedelta(days=1) if validity >= 0 else now - timedelta(minutes=1)
    if validity < 0:
        start = now - timedelta(days=1)
    builder = (x509.CertificateBuilder().subject_name(subject).issuer_name(issuer)
               .public_key(key.public_key()).serial_number(x509.random_serial_number() if serial is None else serial)
               .not_valid_before(start).not_valid_after(end if validity <= 0 else now + timedelta(days=2))
               .add_extension(x509.BasicConstraints(ca, path_length), critical=bc_critical)
               .add_extension(key_usage or x509.KeyUsage(False, False, False, False,
                              not ca, ca, ca, False, False), critical=True)
               .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False))
    if not ca:
        if hostname is not None:
            builder = builder.add_extension(x509.SubjectAlternativeName([x509.DNSName(hostname)]), critical=False)
        if eku:
            builder = builder.add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
    if extra:
        for value, critical in extra:
            builder = builder.add_extension(value, critical)
    if algorithm is None and isinstance(issuer_key, ec.EllipticCurvePrivateKey):
        algorithm = hashes.SHA256()
    return builder.sign(issuer_key, algorithm)


class CertificateTests(unittest.TestCase):
    def setUp(self):
        self.ca_key = ed25519.Ed25519PrivateKey.generate()
        self.key = x25519.X25519PrivateKey.generate()
        self.ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test CA")])
        self.name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "ignored.example")])
        self.root = issue(self.ca_key, self.ca_key, self.ca_name, self.ca_name, ca=True, path_length=1)
        self.leaf = issue(self.key, self.ca_key, self.name, self.ca_name)

    def validate(self, leaf=None, roots=None, name="example.test", chain=None):
        return validate_chain(chain or [der(leaf or self.leaf)],
                              [self.root] if roots is None else roots, name, "lab-offline")

    def test_real_ed25519_chain_and_optional_sent_root(self):
        expected = self.key.public_key().public_bytes_raw()
        self.assertEqual(self.validate().public_bytes_raw(), expected)
        self.assertEqual(self.validate(chain=[der(self.leaf), der(self.root)]).public_bytes_raw(), expected)

    def test_ip_reference_uses_only_ip_san_and_never_sni(self):
        for address in ("127.0.0.1", "2001:db8::1"):
            with self.subTest(address=address):
                cert = issue(self.key, self.ca_key, self.name, self.ca_name, hostname=None,
                    extra=[(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address(address))]), False)])
                self.assertEqual(self.validate(leaf=cert, name=address).public_bytes_raw(), self.key.public_key().public_bytes_raw())
                with self.assertRaises(ProtocolError):
                    validate_server_name(address)
                self.assertEqual(validate_service_identity(address), address)
                wrong_type = issue(self.key, self.ca_key, self.name, self.ca_name, hostname=address)
                with self.assertRaises(ProtocolError):
                    self.validate(leaf=wrong_type, name=address)
        for address in ("127.000.0.1", "[::1]", "fe80::1%eth0", "2001:0db8::1", "2001:DB8::1"):
            with self.subTest(address=address), self.assertRaises(ProtocolError):
                validate_service_identity(address)

    def test_generic_local_loader_accepts_ip_address_san(self):
        leaf = issue(self.key, self.ca_key, self.name, self.ca_name, hostname=None,
            extra=[(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("::1"))]), False)])
        with tempfile.TemporaryDirectory() as temporary:
            chain_path, key_path = Path(temporary) / "chain.pem", Path(temporary) / "key.pem"
            chain_path.write_bytes(leaf.public_bytes(serialization.Encoding.PEM) + self.root.public_bytes(serialization.Encoding.PEM))
            key_path.write_bytes(self.key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
            key_path.chmod(0o600)
            self.assertEqual(load_credentials(chain_path, key_path, "::1").chain_der, [der(leaf), der(self.root)])
            with self.assertRaises((ConfigurationError, ProtocolError)):
                load_credentials(chain_path, key_path, "::2")

    def test_real_p256_issuer(self):
        ca_key = ec.generate_private_key(ec.SECP256R1())
        root = issue(ca_key, ca_key, self.ca_name, self.ca_name, ca=True)
        leaf = issue(self.key, ca_key, self.name, self.ca_name)
        self.assertEqual(self.validate(leaf, [root]).public_bytes_raw(), self.key.public_key().public_bytes_raw())

    def test_intermediate_and_path_length(self):
        inter_key = ec.generate_private_key(ec.SECP256R1())
        inter_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Intermediate")])
        intermediate = issue(inter_key, self.ca_key, inter_name, self.ca_name, ca=True, path_length=0)
        leaf = issue(self.key, inter_key, self.name, inter_name)
        chain = [der(leaf), der(intermediate)]
        self.validate(chain=chain)
        restricted_root = issue(self.ca_key, self.ca_key, self.ca_name, self.ca_name, ca=True, path_length=0)
        with self.assertRaises(ProtocolError):
            self.validate(chain=chain, roots=[restricted_root])
        with self.assertRaises(ProtocolError):
            self.validate(chain=[der(intermediate), der(leaf)])

    def test_absent_or_untrusted_anchors(self):
        _, wrong_root = generate_lab_credentials("example.test")
        for roots in ([], [wrong_root]):
            with self.subTest(roots=len(roots)), self.assertRaises(ProtocolError):
                self.validate(roots=roots)
        with self.assertRaises(ProtocolError):
            self.validate(roots=[wrong_root], chain=[der(self.leaf), der(self.root)])

    def test_bad_signature_and_corrupt_der(self):
        corrupted = bytearray(der(self.leaf))
        corrupted[-1] ^= 1
        for value in (bytes(corrupted), der(self.leaf) + b"\x00", der(self.leaf)[:-1], b"", b"X" * 65537):
            with self.subTest(length=len(value)), self.assertRaises(ProtocolError):
                self.validate(chain=[value])

    def test_invalid_x509_version_is_normalized_to_protocol_error(self):
        mutated = bytearray(der(self.leaf))
        version = mutated.index(b"\xa0\x03\x02\x01\x02") + 4
        mutated[version] = 3
        with self.assertRaises(ProtocolError):
            self.validate(chain=[bytes(mutated)])

    def test_signature_bit_string_unused_bits_are_rejected_deterministically(self):
        # Public fixed test keys, dates and serial make this independent of the
        # random CA/leaf fixtures. Its signature ends with 0x0a (one zero bit).
        # cryptography accepts unused_bits=1 and preserves signature octets, so
        # ordinary signature verification would accept the alternate encoding.
        ca_key = ed25519.Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "BIT STRING regression")])
        cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
                .public_key(x25519.X25519PrivateKey.from_private_bytes(bytes(range(32, 64))).public_key())
                .serial_number(3).not_valid_before(datetime(2020, 1, 1, tzinfo=timezone.utc))
                .not_valid_after(datetime(2040, 1, 1, tzinfo=timezone.utc)).sign(ca_key, None))
        self.assertEqual(cert.signature[-1], 0x0a)
        original = der(cert)
        signature_offset = len(original) - len(cert.signature) - 1
        self.assertEqual(original[signature_offset - 2:signature_offset + 1], b"\x03\x41\x00")
        self.assertEqual(_parse_der(original).signature, cert.signature)
        for unused_bits in range(1, 8):
            changed = original[:signature_offset] + bytes([unused_bits]) + original[signature_offset + 1:]
            with self.subTest(unused_bits=unused_bits), self.assertRaises(ProtocolError):
                _parse_der(changed)

    def test_signature_algorithm_encoding_and_size_bounds(self):
        for size in (0, 63, 65):
            with self.subTest(algorithm="Ed25519", size=size), self.assertRaises(ProtocolError):
                _parse_der(replace_signature(self.leaf, bytes(size)))
        ca_key = ec.generate_private_key(ec.SECP256R1())
        leaf = issue(self.key, ca_key, self.name, self.ca_name)
        malformed = (b"", b"garbage", utils.encode_dss_signature(0, 1),
                     utils.encode_dss_signature(1, 0), utils.encode_dss_signature(1 << 256, 1))
        for signature in malformed:
            with self.subTest(algorithm="P256", signature=signature.hex()), self.assertRaises(ProtocolError):
                _parse_der(replace_signature(leaf, signature))

    def test_unsupported_general_name_is_normalized_to_protocol_error(self):
        # A signed SubjectAlternativeName with the unsupported x400Address arm.
        san = x509.UnrecognizedExtension(x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME,
                                        bytes.fromhex("3002a300"))
        leaf = issue(self.key, self.ca_key, self.name, self.ca_name, hostname=None,
                     extra=[(san, False)])
        with self.assertRaises(ProtocolError):
            self.validate(leaf)

    def test_wrong_issuer_key_even_with_same_name(self):
        wrong_key = ed25519.Ed25519PrivateKey.generate()
        leaf = issue(self.key, wrong_key, self.name, self.ca_name)
        with self.assertRaises(ProtocolError):
            self.validate(leaf)

    def test_hostname_and_no_common_name_fallback(self):
        with self.assertRaises(ProtocolError):
            self.validate(name="wrong.test")
        leaf = issue(self.key, self.ca_key, self.name, self.ca_name, hostname=None)
        with self.assertRaises(ProtocolError):
            self.validate(leaf, name="ignored.example")

    def test_wildcards_are_one_complete_leftmost_label(self):
        leaf = issue(self.key, self.ca_key, self.name, self.ca_name, hostname="*.example.test")
        self.validate(leaf, name="www.example.test")
        for name in ("example.test", "one.two.example.test", "xn--bcher-kva.example.test"):
            with self.subTest(name=name), self.assertRaises(ProtocolError):
                self.validate(leaf, name=name)
        partial = issue(self.key, self.ca_key, self.name, self.ca_name, hostname="w*.example.test")
        with self.assertRaises(ProtocolError):
            self.validate(partial, name="www.example.test")

    def test_expected_name_validation(self):
        for name in ("EXAMPLE.test", "127.0.0.1", "::1", "example.test.", "a..test", "-a.test",
                     "a-.test", "*.test", "a\x00.test", "bücher.test", "xn--.test", "a" * 64 + ".test"):
            with self.subTest(name=name), self.assertRaises(ProtocolError):
                validate_server_name(name)
        self.assertEqual(validate_server_name("xn--bcher-kva.test"), "xn--bcher-kva.test")

    def test_validity_applies_to_leaf_and_anchor(self):
        for validity in (-1, 1):
            bad_leaf = issue(self.key, self.ca_key, self.name, self.ca_name, validity=validity)
            bad_root = issue(self.ca_key, self.ca_key, self.ca_name, self.ca_name, ca=True, validity=validity)
            with self.subTest(validity=validity):
                with self.assertRaises(ProtocolError):
                    self.validate(bad_leaf)
                with self.assertRaises(ProtocolError):
                    self.validate(roots=[bad_root])

    def test_required_leaf_profile(self):
        cases = [dict(eku=False), dict(bc_critical=False), dict(ca=True),
                 dict(key_usage=x509.KeyUsage(True, False, False, False, True, False, False, False, False))]
        for kwargs in cases:
            leaf = issue(self.key, self.ca_key, self.name, self.ca_name, **kwargs)
            with self.subTest(kwargs=kwargs), self.assertRaises(ProtocolError):
                self.validate(leaf)
        signing_leaf = issue(ed25519.Ed25519PrivateKey.generate(), self.ca_key, self.name, self.ca_name)
        with self.assertRaises(ProtocolError):
            self.validate(signing_leaf)

    def test_certificate_with_low_order_x25519_key_is_rejected(self):
        class LowOrderKey:
            def public_key(self):
                return x25519.X25519PublicKey.from_public_bytes(bytes(32))
        leaf = issue(LowOrderKey(), self.ca_key, self.name, self.ca_name)
        with self.assertRaises(ProtocolError):
            self.validate(leaf)

    def test_ca_eku_restriction_is_not_ignored(self):
        root = issue(self.ca_key, self.ca_key, self.ca_name, self.ca_name, ca=True,
                     extra=[(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), False)])
        with self.assertRaises(ProtocolError):
            self.validate(roots=[root])

    def test_unknown_critical_extension_and_unsupported_constraints(self):
        values = [
            (x509.UnrecognizedExtension(x509.ObjectIdentifier("1.2.3.4.5"), b"\x05\x00"), True),
            (x509.NameConstraints([x509.DNSName("example.test")], None), False),
            (x509.CertificatePolicies([x509.PolicyInformation(x509.ObjectIdentifier("1.2.3.4"), None)]), False),
            (x509.PolicyConstraints(0, None), False),
        ]
        for value in values:
            leaf = issue(self.key, self.ca_key, self.name, self.ca_name, extra=[value])
            with self.subTest(extension=type(value[0]).__name__), self.assertRaises(ProtocolError):
                self.validate(leaf)

    def test_noncritical_opaque_extension_does_not_grant_trust(self):
        leaf = issue(self.key, self.ca_key, self.name, self.ca_name,
                     extra=[(x509.UnrecognizedExtension(x509.ObjectIdentifier("1.2.3.4.5"), b"\x05\x00"), False)])
        self.validate(leaf)

    def test_unsupported_signature_curve_and_hash(self):
        for curve, algorithm in ((ec.SECP384R1(), hashes.SHA256()), (ec.SECP256R1(), hashes.SHA384())):
            ca_key = ec.generate_private_key(curve)
            root = issue(ca_key, ca_key, self.ca_name, self.ca_name, ca=True, algorithm=algorithm)
            leaf = issue(self.key, ca_key, self.name, self.ca_name, algorithm=algorithm)
            with self.subTest(curve=curve.name, hash=algorithm.name), self.assertRaises(ProtocolError):
                self.validate(leaf, roots=[root])

    def test_explicit_revocation_policy_and_chain_bounds(self):
        for policy in ("", "none", "online", None):
            with self.subTest(policy=policy), self.assertRaises(ProtocolError):
                validate_chain([der(self.leaf)], [self.root], "example.test", policy)
        for chain in ([], [der(self.leaf)] * 2, [der(self.leaf)] * 9):
            with self.subTest(length=len(chain)), self.assertRaises(ProtocolError):
                validate_chain(chain, [self.root], "example.test", "lab-offline")

    def test_issuer_needs_ca_authorization(self):
        false_root = issue(self.ca_key, self.ca_key, self.ca_name, self.ca_name, ca=False)
        with self.assertRaises(ProtocolError):
            self.validate(roots=[false_root])
        bad_ku = x509.KeyUsage(True, False, False, False, False, False, False, False, False)
        root = issue(self.ca_key, self.ca_key, self.ca_name, self.ca_name, ca=True, key_usage=bad_ku)
        with self.assertRaises(ProtocolError):
            self.validate(roots=[root])


class CredentialFileTests(unittest.TestCase):
    def test_create_load_and_validate_new_lab(self):
        with tempfile.TemporaryDirectory() as parent:
            directory = Path(parent) / "lab"
            files = create_lab(directory, "localhost")
            self.assertEqual(set(files), {"fullchain.pem", "server.key", "ca.pem"})
            credentials = load_credentials(files["fullchain.pem"], files["server.key"], "localhost")
            roots = load_trust_roots(files["ca.pem"])
            public = validate_chain(credentials.chain_der, roots, "localhost", "lab-offline")
            self.assertEqual(public.public_bytes_raw(), credentials.private_key.public_key().public_bytes_raw())
            with self.assertRaises(ConfigurationError):
                create_lab(directory, "localhost")
            if os.name == "posix":
                self.assertEqual(directory.stat().st_mode & 0o777, 0o700)
                self.assertEqual(files["server.key"].stat().st_mode & 0o777, 0o600)

    def test_repeated_generation_uses_fresh_random_keys(self):
        first, root1 = generate_lab_credentials("localhost")
        second, root2 = generate_lab_credentials("localhost")
        self.assertNotEqual(first.private_key.public_key().public_bytes_raw(), second.private_key.public_key().public_bytes_raw())
        self.assertNotEqual(der(root1), der(root2))

    def test_wrong_key_and_bad_bundles(self):
        with tempfile.TemporaryDirectory() as parent:
            first = create_lab(Path(parent) / "first", "localhost")
            second = create_lab(Path(parent) / "second", "localhost")
            with self.assertRaises(ConfigurationError):
                load_credentials(first["fullchain.pem"], second["server.key"], "localhost")
            for data in (b"junk", first["ca.pem"].read_bytes() + b"TRAILING", b"x" * (2 * 1024 * 1024 + 1)):
                path = Path(parent) / "invalid.pem"
                path.write_bytes(data)
                with self.assertRaises(ConfigurationError):
                    load_trust_roots(path)

    def test_key_file_has_no_ignored_extra_object_or_text(self):
        with tempfile.TemporaryDirectory() as parent:
            files = create_lab(Path(parent) / "lab", "localhost")
            key = files["server.key"].read_bytes()
            for value in (key + key, key + b"garbage", b"garbage" + key):
                files["server.key"].write_bytes(value)
                with self.assertRaises(ConfigurationError):
                    load_credentials(files["fullchain.pem"], files["server.key"], "localhost")

    def test_key_der_trailing_bytes_inside_pem_are_rejected(self):
        with tempfile.TemporaryDirectory() as parent:
            files = create_lab(Path(parent) / "lab", "localhost")
            key = serialization.load_pem_private_key(files["server.key"].read_bytes(), password=None)
            key_der = key.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8,
                                        serialization.NoEncryption())
            files["server.key"].write_bytes(b"-----BEGIN PRIVATE KEY-----\n" + base64.b64encode(key_der + b"\x00")
                                           + b"\n-----END PRIVATE KEY-----\n")
            with self.assertRaises(ConfigurationError):
                load_credentials(files["fullchain.pem"], files["server.key"], "localhost")

    @unittest.skipUnless(os.name == "posix", "POSIX mode check; Windows uses inherited ACLs")
    def test_reject_publicly_readable_private_key(self):
        with tempfile.TemporaryDirectory() as parent:
            files = create_lab(Path(parent) / "lab", "localhost")
            files["server.key"].chmod(0o644)
            with self.assertRaises(ConfigurationError):
                load_credentials(files["fullchain.pem"], files["server.key"], "localhost")


if __name__ == "__main__":
    unittest.main()
