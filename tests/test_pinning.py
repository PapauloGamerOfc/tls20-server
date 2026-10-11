import os
import hashlib
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519

from tls20_server import crypto as c
from tls20_server.errors import ProtocolError
from tls20_server.pinning import (PinningCache, ServerPinning, parse_client_extension,
    parse_server_extension, pinning_proof, pinning_secret)


class PinningTests(unittest.TestCase):
    def setUp(self):
        self.time = 1000
        self.key_id, self.master = os.urandom(16), os.urandom(32)
        self.server = ServerPinning({self.key_id: self.master}, self.key_id,
                                   lifetime=100, clock=lambda: self.time, clock_skew=10)
        self.cache = PinningCache(clock=lambda: self.time)
        self.spki = x25519.X25519PrivateKey.generate().public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        self.root, self.transcript = os.urandom(32), c.PREFACE + b'CH SH'

    def exchange(self, *, server=None, cache=None, spki=None, root=None, transcript=None):
        server, cache = server or self.server, cache or self.cache
        root, transcript, spki = root or self.root, transcript or self.transcript, spki or self.spki
        attempt = cache.begin('example.test', 343)
        extension = server.respond(attempt.extension, 'example.test', 343, root, transcript, spki)
        attempt.complete(extension, root, transcript, spki, authenticated=True)
        return extension

    def test_enroll_refresh_and_rotated_certificate_hash(self):
        first = self.exchange()
        self.assertFalse(parse_server_extension(first)[0])
        before = self.cache.begin('example.test').extension
        other_spki = x25519.X25519PrivateKey.generate().public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        second = self.exchange(spki=other_spki, root=os.urandom(48), transcript=c.PREFACE + b'new CH SH')
        self.assertEqual(len(parse_server_extension(second)[0]), 48)
        self.assertNotEqual(before, self.cache.begin('example.test').extension)
        self.assertNotIn(self.master, first)

    def test_ip_service_scope_remains_separate_from_dns_and_port(self):
        for service in ("127.0.0.1", "::1"):
            attempt = self.cache.begin(service, 343)
            response = self.server.respond(attempt.extension, service, 343, self.root, self.transcript, self.spki)
            attempt.complete(response, self.root, self.transcript, self.spki, authenticated=True)
            self.assertTrue(self.cache.begin(service, 343).extension)
            self.assertEqual(self.cache.begin(service, 443).extension, b"")
        self.assertEqual(self.cache.begin("localhost", 343).extension, b"")

    def test_missing_bad_proof_cannot_remove_pin_or_fallback(self):
        self.exchange()
        original = self.cache.begin('example.test').extension
        for mutate in (lambda _: None, lambda value: value[:1] + bytes(32) + value[33:], lambda _: b''):
            attempt = self.cache.begin('example.test')
            response = self.server.respond(attempt.extension, 'example.test', 343, self.root,
                                           self.transcript, self.spki)
            with self.assertRaises(ProtocolError):
                attempt.complete(mutate(response), self.root, self.transcript, self.spki, authenticated=True)
            self.assertEqual(self.cache.begin('example.test').extension, original)
        with self.assertRaises(ValueError):
            self.cache.forget('example.test')
        self.cache.forget('example.test', trusted_recovery=True)
        self.assertEqual(self.cache.begin('example.test').extension, b'')

    def test_ticket_integrity_service_port_and_key_rotation(self):
        self.exchange()
        extension = self.cache.begin('example.test').extension
        for service, port, wire in (('elsewhere.test', 343, extension),
                                   ('example.test', 443, extension),
                                   ('example.test', 343, extension[:-1] + bytes((extension[-1] ^ 1,)))):
            with self.assertRaises(ProtocolError):
                self.server.respond(wire, service, port, self.root, self.transcript, self.spki)
        second_id = os.urandom(16)
        rotated = ServerPinning({self.key_id: self.master, second_id: os.urandom(32)},
                               second_id, clock=lambda: self.time)
        response = self.exchange(server=rotated)
        self.assertEqual(parse_server_extension(response)[1][1:17], second_id)

    def test_only_authenticated_completion_and_ramp_down(self):
        attempt = self.cache.begin('example.test')
        response = self.server.respond(b'', 'example.test', 343, self.root, self.transcript, self.spki)
        with self.assertRaises(ProtocolError):
            attempt.complete(response, self.root, self.transcript, self.spki)
        self.assertEqual(self.cache.begin('example.test').extension, b'')
        self.exchange()
        ramp = ServerPinning({self.key_id: self.master}, self.key_id, ramp_down=True, clock=lambda: self.time)
        response = self.exchange(server=ramp)
        proof, ticket, lifetime = parse_server_extension(response)
        self.assertEqual((len(proof), ticket, lifetime), (32, b'', 0))
        self.assertEqual(self.cache.begin('example.test').extension, b'')

    def test_capacity_and_parallel_ramp_down_keep_newer_pin(self):
        cache = PinningCache(capacity=1, clock=lambda: self.time)
        self.exchange(cache=cache)
        old = cache.begin('example.test')
        old_wire = old.extension
        self.exchange(cache=cache, root=os.urandom(32))
        current = cache.begin('example.test').extension
        ramp = ServerPinning({self.key_id: self.master}, self.key_id, ramp_down=True, clock=lambda: self.time)
        old.complete(ramp.respond(old_wire, 'example.test', 343, self.root, self.transcript, self.spki),
                     self.root, self.transcript, self.spki, authenticated=True)
        self.assertEqual(cache.begin('example.test').extension, current)
        attempt = cache.begin('second.test')
        response = self.server.respond(attempt.extension, 'second.test', 343, self.root, self.transcript, self.spki)
        with self.assertRaises(ProtocolError):
            attempt.complete(response, self.root, self.transcript, self.spki, authenticated=True)
        self.assertEqual(cache.begin('example.test').extension, current)
        self.time += 200
        self.assertEqual(cache.begin('example.test').extension, b'')

    def test_proof_binds_new_session_effective_key_and_exact_format(self):
        secret = pinning_secret(self.root, self.transcript)
        proof = pinning_proof(secret, self.root, self.transcript, self.spki)
        self.assertNotEqual(proof, pinning_proof(secret, self.root, self.transcript + b'x', self.spki))
        self.assertEqual(parse_client_extension(b'\0\0'), b'')
        for bad in (b'\0', b'\0\2x', b'\0\0x'):
            with self.assertRaises(ProtocolError):
                parse_client_extension(bad)
        response = self.server.respond(b'', 'example.test', 343, self.root, self.transcript, self.spki)
        for bad in (response[:-1], response + b'x', b'\0' * 6):
            with self.assertRaises(ProtocolError):
                parse_server_extension(bad)

    def test_explicit_sm3_hash_cannot_be_inferred_from_32_byte_secret(self):
        provider = None
        if os.environ.get("TLS20_TEST_OPENSSL"):
            from tls20_server.openssl_provider import OpenSSLProvider
            provider = OpenSSLProvider(os.environ["TLS20_TEST_OPENSSL"])
            self.addCleanup(provider.close)
        algorithm = c.hash_context("sm3", provider)
        self.assertNotEqual(pinning_secret(self.root, self.transcript, 'sha256'),
                            pinning_secret(self.root, self.transcript, algorithm))
        # Cross-hash continuity uses the current exchange hash, even if the
        # previous secret happens to have the same byte length.
        self.exchange()
        attempt = self.cache.begin('example.test')
        response = self.server.respond(attempt.extension, 'example.test', 343,
            self.root, self.transcript, self.spki, hash_name=algorithm)
        proof = parse_server_extension(response)[0]
        expected = pinning_proof(attempt.previous.secret, self.root, self.transcript, self.spki, algorithm)
        self.assertEqual(proof, expected)
        self.assertNotEqual(proof, pinning_proof(attempt.previous.secret, self.root, self.transcript, self.spki, 'sha256'))
        attempt.complete(response, self.root, self.transcript, self.spki, authenticated=True, hash_name=algorithm)

    def test_failed_proof_attempt_is_irreversible(self):
        self.exchange()
        attempt = self.cache.begin('example.test')
        response = self.server.respond(attempt.extension, 'example.test', 343,
                                        self.root, self.transcript, self.spki)
        with self.assertRaises(ProtocolError):
            attempt.verify(None, self.root, self.transcript, self.spki, authenticated=True)
        with self.assertRaisesRegex(ProtocolError, 'fresh authenticated'):
            attempt.verify(response, self.root, self.transcript, self.spki, authenticated=True)


if __name__ == '__main__':
    unittest.main()
