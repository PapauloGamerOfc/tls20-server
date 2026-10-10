"""Codec vectors and strict rejection of malformed handshake messages."""

import json
from pathlib import Path
import unittest

from tls20_server import messages as m
from tls20_server.errors import ProtocolError

VECTORS = json.loads((Path(__file__).parent / "data" / "draft-01.json").read_text("utf-8"))


class MessageTests(unittest.TestCase):
    def setUp(self):
        self.A, self.B, self.E = bytes(range(32)), bytes(range(32, 64)), bytes(range(64, 96))
        self.random = bytes(range(128, 160))
        self.ch = m.client_hello(self.A, self.B, "example.test", self.random)

    def test_exact_spec_hello_and_extensions_vectors(self):
        v = VECTORS
        pub = {k: bytes.fromhex(x) for k, x in v["public_keys"].items()}
        expected = {k: bytes.fromhex(x) for k, x in v["handshake_frames"].items()}
        ch = m.client_hello(pub["a_client_auth"], pub["b_client_traffic"],
                            "vector.invalid", bytes(range(128, 160)), b"component-test")
        self.assertEqual(ch, expected["client_hello"])
        decoded = m.parse_client_hello(ch[4:])
        self.assertEqual((decoded.A, decoded.B, decoded.name, decoded.protocol),
                         (pub["a_client_auth"], pub["b_client_traffic"], "vector.invalid", b"component-test"))
        sh = m.server_hello(pub["e_server_traffic"], bytes(range(160, 192)))
        self.assertEqual(sh, expected["server_hello"])
        self.assertEqual(m.parse_server_hello(sh[4:]), pub["e_server_traffic"])
        ee = m.encrypted_extensions(b"component-test")
        self.assertEqual(ee, expected["encrypted_extensions"])
        m.parse_encrypted_extensions(ee[4:], b"component-test")
        synthetic = m.parse_certificate(expected["certificate"][4:])
        self.assertEqual(m.certificate(synthetic), expected["certificate"])
        # This deliberately proves envelope handling only: synthetic is not DER.
        self.assertTrue(synthetic[0].startswith(b"NOT-X509"))

    def test_valid_dns_names_and_limits(self):
        for name in ("localhost", "a", "example.test", "xn--bcher-kva.example",
                     "a" * 63 + ".test", ".".join(["a" * 63] * 3 + ["b" * 61])):
            self.assertEqual(m.validate_name(name), name)
        for name in ("", "EXAMPLE.test", "exämple.test", "a..b", ".test", "test.", "-a", "a-",
                     "a_b", "*", "*.test", "x\x00.test", "a" * 64 + ".test", "a" * 254,
                     "127.0.0.1", "001.002.003.004", "::1", "xn--.test", "xn--a.test"):
            with self.subTest(name=name), self.assertRaises(ProtocolError):
                m.validate_name(name)

    def test_client_hello_exact_consumption_and_mutations(self):
        body = self.ch[4:]
        for length in range(len(body)):
            with self.assertRaises(ProtocolError):
                m.parse_client_hello(body[:length])
        for index in (0, 1, 34, 35, 36, 37, 102, 103, len(body) - 9):
            mutated = bytearray(body)
            mutated[index] ^= 128
            with self.subTest(index=index), self.assertRaises(ProtocolError):
                m.parse_client_hello(bytes(mutated))
        with self.assertRaises(ProtocolError):
            m.parse_client_hello(body + b"\x00")
        for a, b, rnd, protocol in ((self.A, self.A, self.random, b"http/1.1"),
                                    (self.A[:-1], self.B, self.random, b"http/1.1"),
                                    (self.A, self.B, b"", b"http/1.1"),
                                    (self.A, self.B, self.random, b""),
                                    (self.A, self.B, self.random, b"x" * 256)):
            with self.assertRaises(ProtocolError):
                m.client_hello(a, b, "example.test", rnd, protocol)
        equal = body[:70] + body[38:70] + body[102:]
        with self.assertRaises(ProtocolError):
            m.parse_client_hello(equal)

    def test_client_hello_maximum_name_and_opaque_protocol(self):
        name = ".".join(["a" * 63] * 3 + ["b" * 61])
        protocol = bytes(range(255))
        wire = m.client_hello(self.A, self.B, name, self.random, protocol)
        self.assertEqual(len(wire) - 4, 613)
        decoded = m.parse_client_hello(wire[4:])
        self.assertEqual((decoded.name, decoded.protocol), (name, protocol))
        m.parse_encrypted_extensions(m.encrypted_extensions(protocol)[4:], protocol)

    def test_server_hello_rejects_wrong_parameters_and_lengths(self):
        body = m.server_hello(self.E, self.random)[4:]
        for size in range(len(body)):
            with self.assertRaises(ProtocolError):
                m.parse_server_hello(body[:size])
        for index in (0, 1, 34, 35, 36, 37):
            changed = bytearray(body)
            changed[index] ^= 1
            with self.assertRaises(ProtocolError):
                m.parse_server_hello(bytes(changed))
        with self.assertRaises(ProtocolError):
            m.parse_server_hello(body + b"x")
        with self.assertRaises(ProtocolError):
            m.server_hello(b"", self.random)

    def test_extensions_reject_every_change_unknown_duplicate_reordering(self):
        body = m.encrypted_extensions()[4:]
        for index in range(len(body)):
            changed = bytearray(body)
            changed[index] ^= 1
            with self.assertRaises(ProtocolError):
                m.parse_encrypted_extensions(bytes(changed))
        for changed in (body[:-1], body + b"\x00", body + body[2:6],
                         body[:2] + body[6:] + body[2:6]):
            with self.assertRaises(ProtocolError):
                m.parse_encrypted_extensions(changed)
        with self.assertRaises(ProtocolError):
            m.parse_encrypted_extensions(body, b"other")

    def test_certificate_envelope_limits(self):
        for items in ([b"x"], [b"x", b"yz"], [b"x"] * 8, [b"x" * 65536]):
            self.assertEqual(m.parse_certificate(m.certificate(items)[4:]), items)
        for items in ([], [b""], [b"x"] * 9, [b"x" * 65537], [b"x" * 65536] * 4):
            with self.assertRaises(ProtocolError):
                m.certificate(items)
        # Request context, entries length, per-certificate length and extension
        # vectors are all checked independently, not treated as opaque bytes.
        body = m.certificate([b"abc", b"def"])[4:]
        for length in range(len(body)):
            with self.assertRaises(ProtocolError):
                m.parse_certificate(body[:length])
        for index in (0, 1, 2, 3, 4, 5, 6, 10, 11):
            changed = bytearray(body)
            changed[index] ^= 1
            with self.subTest(index=index), self.assertRaises(ProtocolError):
                m.parse_certificate(bytes(changed))
        for bad in (body + b"x", b"\x00\x00\x00\x00", b"x" * (m.MAX_HANDSHAKE_BODY + 1)):
            with self.assertRaises(ProtocolError):
                m.parse_certificate(bad)
        nine = b"\x00\x00\x01x\x00\x00" * 9
        with self.assertRaises(ProtocolError):
            m.parse_certificate(b"\x00" + len(nine).to_bytes(3, "big") + nine)

    def test_handshake_frame_envelopes(self):
        self.assertEqual(m.decode_frame(self.ch), (1, self.ch[4:]))
        for bad in (b"", self.ch[:3], self.ch[:-1], self.ch + b"x", b"\xff" + self.ch[1:]):
            with self.assertRaises(ProtocolError):
                m.decode_frame(bad)
        for kind in (15, 20):
            for length in (0, 31, 33):
                with self.assertRaises(ProtocolError):
                    m.frame(kind, bytes(length))
            self.assertEqual(m.decode_frame(m.frame(kind, bytes(32))), (kind, bytes(32)))
        with self.assertRaises(ProtocolError):
            m.frame(1, bytes(m.MAX_HANDSHAKE_BODY + 1))


if __name__ == "__main__":
    unittest.main()
