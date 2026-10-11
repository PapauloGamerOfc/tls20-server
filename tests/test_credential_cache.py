import hashlib
import unittest

from tls20_server import credential_cache as cache
from tls20_server.errors import ProtocolError


class CredentialCacheTests(unittest.TestCase):
    def test_cached_entries_share_certificate_count_and_der_budgets(self):
        for entries in ((b"x",) * 64, (b"x" * 65536,)):
            self.assertTrue(cache.cached_material(entries))
        for entries in ((b"x",) * 65, (b"x" * 65537,)):
            with self.assertRaises(ProtocolError):
                cache.cached_material(entries)

    def test_all_codecs_roundtrip_and_exact_declared_length(self):
        body = b"credential" * 2000
        for algorithm in cache.COMPRESSION_ALGORITHMS:
            with self.subTest(algorithm=algorithm):
                packed = cache.compress_certificate(body, algorithm)
                self.assertEqual(cache.decompress_certificate(packed, (algorithm,)), body)
                for invalid in (packed[:-1], packed + b"x", packed[:2] + b"\x00\x00\x01" + packed[5:]):
                    with self.assertRaises(ProtocolError):
                        cache.decompress_certificate(invalid, (algorithm,))
                with self.assertRaises(ProtocolError):
                    cache.decompress_certificate(packed, ())
                with self.assertRaises(ProtocolError):
                    cache.decompress_certificate(packed, (algorithm,), max_size=10)

    def test_codec_trailing_and_concatenated_frames_rejected(self):
        for algorithm in cache.COMPRESSION_ALGORITHMS:
            packed = cache.compress_certificate(b"chain", algorithm)
            for extra in (b"garbage", packed[8:]):
                data = packed[8:] + extra
                altered = packed[:5] + len(data).to_bytes(3, "big") + data
                with self.subTest(algorithm=algorithm, extra=extra), self.assertRaises(ProtocolError):
                    cache.decompress_certificate(altered, (algorithm,))

    def test_cache_hash_is_static_material_not_metadata_or_context(self):
        entries = (b"first DER", b"second DER")
        wire = b"\x00\x00\x19\x00\x00\x09first DER\x00\x00\x0asecond DER"
        self.assertEqual(cache.cached_material(entries), wire)
        self.assertEqual(cache.material_hash(entries), hashlib.sha256(wire).digest())
        body = cache.cached_certificate_body(entries, (b"new OCSP", b""))
        decoded = cache.resolve_cached_certificate(body, ((0, entries),))
        self.assertEqual(decoded, (entries, (b"new OCSP", b"")))
        compressed = cache.compress_certificate(body, 2)
        self.assertEqual(cache.resolve_cached_certificate(cache.decompress_certificate(compressed, (2,)),
                                                          ((0, entries),)), decoded)

    def test_cache_resolution_missing_representation_count_context_fail(self):
        entries = (b"one",)
        body = cache.cached_certificate_body(entries, (b"",))
        for snapshots in ((), ((0, (b"other",)),), ((2, entries),)):
            with self.assertRaises(ProtocolError):
                cache.resolve_cached_certificate(body, snapshots)
        malformed = body[:33] + b"\0\0\0"
        with self.assertRaises(ProtocolError):
            cache.resolve_cached_certificate(malformed, ((0, entries),))
        with self.assertRaises(ProtocolError):
            cache.resolve_cached_certificate(body, ((0, entries),), expected_context=b"different")

    def test_request_template_retains_order_and_independent_offers(self):
        offers = b"\x00\x32\x00\x04\x00\x02\x04\x03\xff\x04\x00\x04\x00\x02\x08\x07"
        old = offers[:8] + b"\xff\x03\x00\x20" + b"a" * 32 + offers[8:]
        self.assertEqual(cache.request_template(old), len(offers).to_bytes(2, "big") + offers)
        ref = cache.cached_request_body(b"new-context", old, b"b" * 32)
        context, reconstructed = cache.resolve_cached_request(ref, (old,))
        self.assertEqual(context, b"new-context")
        self.assertEqual(reconstructed, offers + b"\xff\x03\x00\x20" + b"b" * 32)
        for invalid in (ref[:-1], ref + b"x", ref[:12] + bytes(32) + ref[-32:]):
            with self.assertRaises(ProtocolError):
                cache.resolve_cached_request(invalid, (old,))
        with self.assertRaises(ProtocolError):
            cache.request_template(b"\x00\x0d\x00\x00")


if __name__ == "__main__":
    unittest.main()
