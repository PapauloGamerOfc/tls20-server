"""Real native ITS validation. Opt in with explicit library + generated fixtures."""
from dataclasses import replace
from datetime import datetime, timezone
import hashlib
import os
from pathlib import Path
import tempfile
import unittest

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import x25519, ec, utils

from tls20_server.credential_profiles import CredentialPolicy, resolve_peer
from tls20_server.errors import ProtocolError
from tls20_server.its_credentials import ITSProvider, ITSServicePolicy, ITS_EPOCH_UNIX_SECONDS


@unittest.skipUnless(os.getenv("TLS20_TEST_ITS_LIBRARY") and os.getenv("TLS20_ITS_FIXTURE_DIR"),
                     "explicit ITS provider and independently generated test fixtures required")
class ITSNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.provider = ITSProvider(os.environ["TLS20_TEST_ITS_LIBRARY"])
        directory = Path(os.environ["TLS20_ITS_FIXTURE_DIR"])
        cls.grant = (directory / "grant.bin").read_bytes()
        cls.wire = (directory / "policy.bin").read_bytes()
        cls.root = (directory / "root.coer").read_bytes()
        cls.leaf = (directory / "leaf.coer").read_bytes()
        # Read local generated fixture policy, not untrusted remote bytes.
        cursor = 4
        def integer(n):
            nonlocal cursor
            v = int.from_bytes(cls.wire[cursor:cursor+n], "big")
            cursor += n
            return v
        def vector(n):
            nonlocal cursor
            length = integer(n)
            v = cls.wire[cursor:cursor+length]
            cursor += length
            return v
        now, until, max_lifetime, role, psid = integer(8), integer(8), integer(8), integer(1), integer(8)
        scope, ssp = vector(2), vector(2)
        cls.now = datetime.fromtimestamp(now / 1_000_000 + ITS_EPOCH_UNIX_SECONDS - 37, timezone.utc)
        cls.policy = ITSServicePolicy(cls.provider, "example.test", "server", psid, scope, ssp,
            (cls.root,), (hashlib.sha256(cls.leaf).digest(),), (), until, max_lifetime, 37)

    def test_real_grant_key_and_policy_wire(self):
        self.assertEqual(self.policy.policy_bytes(now=self.now), self.wire)
        auth = resolve_peer((self.grant,), 3, policy=CredentialPolicy(peer_name="example.test",
                          its_policy=self.policy, now=self.now))
        expected = x25519.X25519PrivateKey.from_private_bytes(bytes([9])*32).public_key().public_bytes_raw()
        self.assertEqual(auth.public_key.public_bytes_raw(), expected)
        self.assertEqual(auth.provenance, "its-x25519-grant")
        self.assertEqual(auth.identity, "example.test")
        self.assertGreater(auth.expires_at, self.now)

    def test_independent_openssl_signature_and_grant_hash_oracle(self):
        directory = Path(os.environ["TLS20_ITS_FIXTURE_DIR"])
        for prefix, issuer, key_byte, container in (("root", b"", 1, self.root),
                ("leaf", self.root, 1, self.leaf), ("proof", self.leaf, 2, self.grant)):
            tbs = (directory / (prefix + "-tbs.bin")).read_bytes()
            raw = (directory / (prefix + "-signature.bin")).read_bytes()
            self.assertIn(tbs, container)
            signature = utils.encode_dss_signature(int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:], "big"))
            public = ec.derive_private_key(int.from_bytes(bytes([key_byte])*32, "big"), ec.SECP256R1()).public_key()
            message = hashlib.sha256(tbs).digest() + hashlib.sha256(issuer).digest()
            public.verify(signature, message, ec.ECDSA(hashes.SHA256()))
        grant_tbs = (directory / "grant-tbs.bin").read_bytes()
        proof_tbs = (directory / "proof-tbs.bin").read_bytes()
        digest = hashlib.sha256(b" "*64 + b"TLS20 ITS server grant\0" + grant_tbs).digest()
        self.assertIn(digest, proof_tbs)
        self.assertTrue(self.grant.startswith(grant_tbs))

    def test_each_wire_byte_and_all_truncations_fail(self):
        for index in range(len(self.grant)):
            changed = bytearray(self.grant)
            changed[index] ^= 128
            with self.assertRaises(ProtocolError):
                self.provider.authorize(bytes(changed), self.wire)
        for size in range(len(self.grant)):
            with self.assertRaises(ProtocolError):
                self.provider.authorize(self.grant[:size], self.wire)

    def test_brainpool_and_implicit_profiles_with_independent_openssl_oracle(self):
        directory = Path(os.environ["TLS20_ITS_FIXTURE_DIR"])
        variants = (("brainpool256", ec.BrainpoolP256R1(), hashes.SHA256(), None),
                    ("brainpool384", ec.BrainpoolP384R1(), hashes.SHA384(), None),
                    ("implicit-nist256", ec.SECP256R1(), hashes.SHA256(),
                     int("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16)),
                    ("implicit-brainpool256", ec.BrainpoolP256R1(), hashes.SHA256(),
                     int("A9FB57DBA1EEA9BC3E660A909D838D718C397AA3B561A6F7901E0E82974856A7", 16)))
        for name, curve, algorithm, order in variants:
            with self.subTest(profile=name):
                files = directory / name
                wire = (files / "policy.bin").read_bytes()
                grant = (files / "grant.bin").read_bytes()
                key, _, _ = self.provider.authorize(grant, wire)
                self.assertEqual(key, self.provider.authorize(self.grant, self.wire)[0])
                root, leaf = (files / "root.coer").read_bytes(), (files / "leaf.coer").read_bytes()
                width = curve.key_size // 8
                root_scalar = int.from_bytes(b"\x01" * width, "big")
                leaf_scalar = int.from_bytes(b"\x02" * width, "big")
                if order:
                    # IEEE 1609.2 ECQV uses all 256 hash bits, not SEC4 truncation.
                    tbs = (files / "leaf-tbs.bin").read_bytes()
                    e = int.from_bytes(hashlib.sha256(hashlib.sha256(tbs).digest()
                                       + hashlib.sha256(root).digest()).digest(), "big")
                    leaf_scalar = (e * leaf_scalar + root_scalar) % order
                for prefix, issuer, scalar in (("root", b"", root_scalar),
                                               ("proof", leaf, leaf_scalar)):
                    tbs = (files / (prefix + "-tbs.bin")).read_bytes()
                    raw = (files / (prefix + "-signature.bin")).read_bytes()
                    self.assertEqual(len(raw), width * 2)
                    der = utils.encode_dss_signature(int.from_bytes(raw[:width], "big"),
                                                     int.from_bytes(raw[width:], "big"))
                    digest = hashlib.sha256 if width == 32 else hashlib.sha384
                    message = digest(tbs).digest() + digest(issuer).digest()
                    ec.derive_private_key(scalar, curve).public_key().verify(der, message, ec.ECDSA(algorithm))

    def test_identity_role_policy_and_clock_are_explicit(self):
        for policy in (replace(self.policy, role="client"), replace(self.policy, identity="other.test"),
                       replace(self.policy, application_scope=b"elsewhere"), replace(self.policy, psid=43),
                       replace(self.policy, revoked_sha256=self.policy.authorized_leaf_sha256),
                       replace(self.policy, inventory_valid_until=1), replace(self.policy, tai_utc_offset=0)):
            with self.assertRaises(ProtocolError):
                policy.authorize(self.grant, role="server", identity="example.test", now=self.now)
        with self.assertRaises(ProtocolError):
            resolve_peer((self.grant,), 3, policy=CredentialPolicy(peer_name="example.test", now=self.now))
        with self.assertRaises(ProtocolError):
            self.policy.policy_bytes(now=datetime(2020, 1, 1))

    def test_geographic_authority_wire_and_exact_region_binding(self):
        directory = Path(os.environ["TLS20_ITS_FIXTURE_DIR"]) / "geometry-static"
        root, leaf = (directory / "root.coer").read_bytes(), (directory / "leaf.coer").read_bytes()
        outer, inner = (directory / "outer.coer").read_bytes(), (directory / "inner.coer").read_bytes()
        grant, wire = (directory / "grant.bin").read_bytes(), (directory / "policy.bin").read_bytes()
        policy = replace(self.policy, trust_roots=(root,), authorized_leaf_sha256=(hashlib.sha256(leaf).digest(),),
                         allowed_regions_coer=(inner,), geographic_containment=((outer, inner), (inner, inner)))
        self.assertEqual(policy.policy_bytes(now=self.now), wire)
        key, _, _ = policy.authorize(grant, role="server", identity="example.test", now=self.now)
        self.assertEqual(key.public_bytes_raw(), self.provider.authorize(self.grant, self.wire)[0])
        for pairs in ((), ((inner, outer), (inner, inner)), ((outer, outer), (inner, inner))):
            changed = replace(policy, geographic_containment=pairs)
            self.assertNotEqual(changed.context(), policy.context())
            with self.assertRaises(ProtocolError):
                changed.authorize(grant, role="server", identity="example.test", now=self.now)

    def test_profile_loads_only_explicit_local_geographic_authority(self):
        from tls20_server.errors import ConfigurationError
        from tls20_server.profiles import load_profile
        directory = Path(os.environ["TLS20_ITS_FIXTURE_DIR"]) / "geometry-static"
        outer, inner = (directory / "outer.coer").read_bytes(), (directory / "inner.coer").read_bytes()
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            (base / "root.coer").write_bytes(self.root)
            (base / "outer.coer").write_bytes(outer)
            (base / "inner.coer").write_bytes(inner)
            settings = ('role="client"\nservice="example.test"\nport=343\nmode="certificate"\n[trust.its]\n'
                + 'library=' + repr(self.provider.library_path) + '\npsid=42\n'
                + 'application_scope_hex="' + self.policy.application_scope.hex() + '"\n'
                + 'ssp_coer_hex="' + self.policy.ssp_coer.hex() + '"\nroots=["root.coer"]\n'
                + 'authorized_leaf_sha256=["' + self.policy.authorized_leaf_sha256[0].hex() + '"]\n'
                + 'inventory_valid_until=18446744073709551615\nmax_grant_lifetime_microseconds=2000000000\ntai_utc_offset=37\n')
            profile = base / "client.toml"
            def load(statement):
                profile.write_text(settings + statement, encoding="utf8")
                return load_profile(profile, role="client")
            result = load('geographic_containment=[{parent="outer.coer",child="inner.coer"}]\n')
            try:
                policy = result.options["credential_policy"].its_policy
                self.assertEqual(policy.geographic_containment, ((outer, inner),))
            finally:
                result.close()
            for value in ('[{parent="outer.coer"}]', '[{parent="outer.coer",child="missing.coer"}]',
                          '[{parent="outer.coer",child="inner.coer",trusted=true}]', 'false'):
                with self.assertRaises(ConfigurationError):
                    load('geographic_containment=' + value)
            (base / "inner.coer").write_bytes(b"")
            with self.assertRaises(ConfigurationError):
                load('geographic_containment=[{parent="outer.coer",child="inner.coer"}]')

    def test_context_changes_with_inventory_and_no_evidence_bypass(self):
        self.assertNotEqual(self.policy.context(), replace(self.policy,
            revoked_sha256=self.policy.authorized_leaf_sha256).context())
        a, b, c = b"a"*32, b"b"*32, b"c"*32
        self.assertNotEqual(replace(self.policy, authorized_leaf_sha256=(a,b), revoked_sha256=(c,)).context(),
                            replace(self.policy, authorized_leaf_sha256=(a,), revoked_sha256=(b,c)).context())
        with self.assertRaises(ProtocolError):
            resolve_peer((self.grant,), 3, policy=CredentialPolicy(peer_name="example.test",
                its_policy=self.policy, now=self.now), entry_extensions=({5:b"fake"},), offered_extensions=(5,))
        first = replace(self.policy, geographic_containment=((b"parent", b"child"),))
        inverse = replace(self.policy, geographic_containment=((b"child", b"parent"),))
        self.assertNotEqual(first.context(), self.policy.context())
        self.assertNotEqual(first.context(), inverse.context())
        for invalid in (first, replace(self.policy, geographic_containment=((b"", b"child"),))):
            with self.assertRaises(ProtocolError):
                invalid.authorize(self.grant, role="server", identity="example.test", now=self.now)


class ITSConfigurationTests(unittest.TestCase):
    def test_no_auto_discovery(self):
        for value in ("tls20_its.dll", "missing.dll"):
            with self.assertRaises(ProtocolError):
                ITSProvider(value)
