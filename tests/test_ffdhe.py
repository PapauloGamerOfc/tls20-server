"""RFC 7919 numerical constants and provider-enforced peer validation."""

from decimal import Decimal, localcontext
import hashlib
import unittest

from tls20_server import crypto as c, ffdhe
from tls20_server.errors import ProtocolError


class FFDHETests(unittest.TestCase):
    def test_fast_public_membership_matches_independent_euler_criterion(self):
        for prime in ffdhe.PRIMES.values():
            # Euler's criterion is deliberately used only as a slow test
            # oracle. Deterministic samples cover both signs and full width.
            samples = (2, prime - 2, int.from_bytes(hashlib.shake_256(
                str(prime).encode()).digest(prime.bit_length() // 8), "big") % prime)
            for value in samples:
                self.assertEqual(ffdhe._quadratic_residue(value, prime),
                                 pow(value, (prime - 1) // 2, prime) == 1)

    def test_exact_rfc7919_public_prime_formulas(self):
        # Independent check of every transcribed digit, using the RFC's public
        # reproducible formulas. No secret exponent uses Decimal or Python pow.
        with localcontext() as context:
            context.prec = 3000
            e = Decimal(1).exp()
            for group, bits, offset in ((256, 2048, 560316), (257, 3072, 2625351),
                    (258, 4096, 5736041), (259, 6144, 15705020), (260, 8192, 10965728)):
                middle = int((Decimal(2) ** (bits - 130)) * e) + offset
                expected = (1 << bits) - (1 << (bits - 64)) + (middle << 64) - 1
                self.assertEqual(ffdhe.PRIMES[group], expected)
                self.assertEqual(ffdhe.SIZES[group], bits // 8)

    def test_provider_rejects_nonmembers_and_out_of_range_values(self):
        for group, prime in ffdhe.PRIMES.items():
            with self.subTest(group=group):
                private, own = c.traffic_key(group)
                for peer in (0, 1, prime - 2, prime - 1, prime):
                    with self.assertRaises(ProtocolError):
                        c.traffic_dh(private, group, peer.to_bytes(ffdhe.SIZES[group], "big"))
                response, secret = c.traffic_server(group, own)
                self.assertEqual(secret, c.traffic_dh(private, group, response))
                self.assertEqual(len(secret), ffdhe.SIZES[group])
