from dataclasses import replace
from datetime import datetime, timedelta, timezone
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519

from tls20_server.bootstrap_credentials import (BootstrapBinding, authorize_bootstrap_client,
    bootstrap_client_material, provisioning_server_key, resolve_bootstrap_identity)
from tls20_server.psk import bootstrap_public_key_psk
from tls20_server.errors import ProtocolError


class BootstrapCredentialTests(unittest.TestCase):
    def setUp(self):
        self.key = x25519.X25519PrivateKey.generate()
        self.spki = self.key.public_key().public_bytes(serialization.Encoding.DER,
                                      serialization.PublicFormat.SubjectPublicKeyInfo)
        self.binding = BootstrapBinding(self.spki, "device.test", "device-enrollment")
        self.flight = dict(combined=True, fresh_key_share=True, initial_early_data=False,
                           client_credential_type=2, client_request_present=True)

    def test_exact_imported_identity_service_scope_and_kdf_binding(self):
        for target_hash in ("sha256", "sha384"):
            psk = bootstrap_public_key_psk(self.spki[12:], "device.test", target_hash=target_hash)
            binding, resolved = resolve_bootstrap_identity(psk.identity, (self.binding,), service="device.test")
            self.assertEqual(binding, self.binding)
            self.assertEqual(resolved.psk, psk.psk)
            self.assertTrue(resolved.combined)
            self.assertEqual(resolved.binder_kind, "imp")
            for identity in (psk.identity[:-1], psk.identity + b"x", bytes(len(psk.identity))):
                with self.assertRaises(ProtocolError):
                    resolve_bootstrap_identity(identity, (self.binding,), service="device.test")
            with self.assertRaises(ProtocolError):
                resolve_bootstrap_identity(psk.identity, (self.binding,), service="other.test")
            with self.assertRaises(ProtocolError):
                resolve_bootstrap_identity(psk.identity,
                    (self.binding, replace(self.binding, scope="unrelated")), service="device.test")

    def test_expired_and_malformed_inventory_fails(self):
        psk = bootstrap_public_key_psk(self.spki[12:], "device.test")
        expired = replace(self.binding, expires_at=datetime.now(timezone.utc) - timedelta(seconds=1))
        with self.assertRaises(ProtocolError):
            resolve_bootstrap_identity(psk.identity, (expired,), service="device.test")
        with self.assertRaises(ProtocolError):
            replace(self.binding, spki=self.spki[:12] + bytes(32))
        self.assertNotIn(self.spki.hex(), repr(self.binding))

    def test_public_key_release_requires_complete_server_proofs_and_selected_profile(self):
        self.assertEqual(bootstrap_client_material(self.binding, server_mac_verified=True,
            server_finished_verified=True, **self.flight), (self.spki,))
        for key, value in (('combined', False), ('fresh_key_share', False),
                           ('initial_early_data', True), ('client_credential_type', 0),
                           ('client_request_present', False)):
            flight = dict(self.flight, **{key: value})
            with self.assertRaises(ProtocolError):
                bootstrap_client_material(self.binding, server_mac_verified=True,
                    server_finished_verified=True, **flight)
        for mac, finished in ((False, True), (True, False), (False, False)):
            with self.assertRaises(ProtocolError):
                bootstrap_client_material(self.binding, server_mac_verified=mac,
                    server_finished_verified=finished, **self.flight)

    def test_exact_bsk_plus_mac_finished_required_for_authorization(self):
        result = authorize_bootstrap_client(self.binding, (self.spki,), credential_type=2,
                                            client_mac_verified=True, client_finished_verified=True)
        self.assertEqual(result['scope'], 'device-enrollment')
        for material, kind, mac, finished in (((self.spki,), 0, True, True),
                ((), 2, True, True), ((self.spki,), 2, False, True), ((self.spki,), 2, True, False)):
            with self.assertRaises(ProtocolError):
                authorize_bootstrap_client(self.binding, material, credential_type=kind,
                    client_mac_verified=mac, client_finished_verified=finished)

    def test_provisioning_exception_is_not_normal_web_or_credential_validated_fallback(self):
        binding = replace(self.binding, trust_mode="provisioning-trust")
        result = provisioning_server_key((self.spki,), 2, binding=binding)
        self.assertEqual(result.provenance, "provisioning-trust")
        for opts in (dict(binding=self.binding), dict(binding=binding, normal_httpps=True),
                     dict(binding=binding, entry_extensions=(((34, b"grant"),),))):
            with self.assertRaises(ProtocolError):
                provisioning_server_key((self.spki,), 2, **opts)


if __name__ == '__main__':
    unittest.main()
