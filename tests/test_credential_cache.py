import hashlib
import unittest
from unittest import mock

import zstandard

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

    def test_codec_trailing_bytes_and_excess_output_rejected(self):
        for algorithm in cache.COMPRESSION_ALGORITHMS:
            packed = cache.compress_certificate(b"chain", algorithm)
            for extra in (b"garbage", packed[8:]):
                data = packed[8:] + extra
                altered = packed[:5] + len(data).to_bytes(3, "big") + data
                with self.subTest(algorithm=algorithm, extra=extra), self.assertRaises(ProtocolError):
                    cache.decompress_certificate(altered, (algorithm,))

    @staticmethod
    def zstandard_body(data, declared):
        return b"\x00\x03" + declared.to_bytes(3, "big") + len(data).to_bytes(3, "big") + data

    @staticmethod
    def skippable_frame(data=b"metadata", magic=0x184D2A50):
        return magic.to_bytes(4, "little") + len(data).to_bytes(4, "little") + data

    def test_zstandard_concatenated_frames_and_all_skippable_magics(self):
        parts = (b"first certificate" * 1200, b"second certificate" * 1600)
        plain = b"".join(parts)
        for content_size in (False, True):
            for checksum in (False, True):
                compressor = zstandard.ZstdCompressor(write_content_size=content_size,
                                                       write_checksum=checksum)
                first, second = (compressor.compress(part) for part in parts)
                empty = compressor.compress(b"")
                for magic in range(0x184D2A50, 0x184D2A60):
                    skip = self.skippable_frame(magic=magic)
                    for data in (first + second, skip + first + empty + skip + second + skip,
                                 empty + first + self.skippable_frame(b"", magic) + second + empty):
                        with self.subTest(content_size=content_size, checksum=checksum, magic=magic):
                            packed = self.zstandard_body(data, len(plain))
                            self.assertEqual(cache.decompress_certificate(packed, (3,)), plain)

    def test_zstandard_every_truncated_frame_and_skip_are_rejected(self):
        first = zstandard.ZstdCompressor().compress(b"first")
        for content_size in (False, True):
            second = zstandard.ZstdCompressor(write_content_size=content_size,
                                             write_checksum=True).compress(b"second")
            # A truncated second frame must not be mistaken for EOF after the
            # valid first frame, including when its expected output is empty.
            for frame in (second, zstandard.ZstdCompressor(write_checksum=True).compress(b""),
                          self.skippable_frame()):
                for length in range(1, len(frame)):
                    with self.subTest(content_size=content_size, length=length, frame=frame):
                        packed = self.zstandard_body(first + frame[:length], len(b"first"))
                        with self.assertRaises(ProtocolError):
                            cache.decompress_certificate(packed, (3,))
            for length in range(len(second)):
                packed = self.zstandard_body(second[:length], len(b"second"))
                with self.assertRaises(ProtocolError):
                    cache.decompress_certificate(packed, (3,))

    def test_zstandard_rejects_corruption_junk_and_length_mismatches(self):
        compressor = zstandard.ZstdCompressor(write_checksum=True)
        first, second = compressor.compress(b"first"), compressor.compress(b"second")
        corrupted = second[:-1] + bytes([second[-1] ^ 1])
        reserved_block = bytearray(second)
        reserved_block[zstandard.frame_header_size(second)] |= 6
        for data, declared in ((first + corrupted, 11), (first + reserved_block, 11),
                               (first + second + b"garbage", 11),
                               (first + second, 10), (first + second, 12),
                               (self.skippable_frame(), 1)):
            with self.subTest(data=data, declared=declared), self.assertRaises(ProtocolError):
                cache.decompress_certificate(self.zstandard_body(data, declared), (3,))

    def test_zstandard_raw_and_rle_block_boundaries(self):
        # A raw block's length counts encoded bytes; an RLE block's length
        # counts decoded bytes, but its payload is always one encoded byte.
        raw = b"\x28\xb5\x2f\xfd\x20\x03" + ((3 << 3) | 1).to_bytes(3, "little") + b"raw"
        rle = b"\x28\xb5\x2f\xfd\x20\x05" + ((5 << 3) | 3).to_bytes(3, "little") + b"x"
        data = raw + self.skippable_frame() + rle
        self.assertEqual(cache.decompress_certificate(self.zstandard_body(data, 8), (3,)), b"rawxxxxx")
        with self.assertRaises(ProtocolError):
            cache.decompress_certificate(self.zstandard_body(data[:-1], 8), (3,))

    def test_zstandard_unknown_size_output_and_window_are_bounded(self):
        parameters = zstandard.ZstdCompressionParameters.from_level(3, window_log=10,
                                                                     write_content_size=False)
        frame = zstandard.ZstdCompressor(compression_params=parameters).compress(b"a" * 1_000_000)
        self.assertEqual(zstandard.get_frame_parameters(frame).content_size, zstandard.CONTENTSIZE_UNKNOWN)
        # Observe the bounded streaming destination, not an unbounded
        # decompression followed by a length check after allocation.
        original_decoder = zstandard.ZstdDecompressor
        output_capacities = []

        class CheckedReader:
            def __init__(self, reader):
                self.reader = reader

            def __enter__(self):
                self.reader.__enter__()
                return self

            def __exit__(self, *args):
                return self.reader.__exit__(*args)

            def readinto(self, destination):
                output_capacities.append(len(destination))
                return self.reader.readinto(destination)

        def checked_decoder(**kwargs):
            decoder = original_decoder(**kwargs)
            return mock.Mock(stream_reader=lambda *args, **options:
                             CheckedReader(decoder.stream_reader(*args, **options)))

        with mock.patch.object(zstandard, "ZstdDecompressor", side_effect=checked_decoder):
            with self.assertRaises(ProtocolError):
                cache.decompress_certificate(self.zstandard_body(frame, 64), (3,))
        self.assertEqual(output_capacities, [65])
        excessive_window = bytearray(frame)
        excessive_window[5] = 0x88  # 128 MiB window, though the declared output is small.
        with self.assertRaisesRegex(ProtocolError, "window exceeds"):
            cache.decompress_certificate(self.zstandard_body(excessive_window, 64), (3,))

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
