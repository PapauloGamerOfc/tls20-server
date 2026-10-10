"""Known answers and negative record cases; fixed keys are PUBLIC test data."""

import json
from pathlib import Path
import unittest

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand

from tls20_server import crypto as c
from tls20_server.errors import ProtocolError

VECTORS = json.loads((Path(__file__).parent / "data" / "draft-01.json").read_text("utf-8"))


def unhex(value):
    return bytes.fromhex(value)


class CryptoTests(unittest.TestCase):
    def test_rfc7748_known_answer(self):
        alice = X25519PrivateKey.from_private_bytes(unhex(
            "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"))
        bob = X25519PrivateKey.from_private_bytes(unhex(
            "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"))
        self.assertEqual(c.public_bytes(alice).hex(),
                         "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
        self.assertEqual(c.public_bytes(bob).hex(),
                         "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
        self.assertEqual(c.dh(alice, c.public_bytes(bob)), c.dh(bob, c.public_bytes(alice)))
        self.assertEqual(c.dh(alice, c.public_bytes(bob)).hex(),
                         "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")

    def test_rfc5869_known_answer(self):
        prk = c.extract(bytes(range(13)), b"\x0b" * 22)
        self.assertEqual(prk.hex(), "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5")
        self.assertEqual(c.expand(prk, bytes(range(240, 250)), 42).hex(),
                         "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
                         "34007208d5b887185865")

    def test_hkdf_provider_and_input_bounds(self):
        prk = c.digest(b"public test")
        for length in (0, 1, 31, 32, 33, 255, 8160):
            expected = HKDFExpand(hashes.SHA256(), length, b"test").derive(prk)
            self.assertEqual(c.expand(prk, b"test", length), expected)
        for length in (-1, 8161):
            with self.assertRaises(ProtocolError):
                c.expand(prk, b"", length)
        for label, context, secret in (("a" * 242, b"", prk), ("á", b"", prk),
                                        ("a", b"x" * 256, prk), ("a", b"", b"short")):
            with self.assertRaises(ProtocolError):
                c.label_expand(secret, label, context, 32)

    def test_dh_rejects_invalid_and_low_order_values(self):
        key = X25519PrivateKey.from_private_bytes(bytes(range(32)))
        for public in (b"", b"x" * 31, b"x" * 33, bytes(32), b"\x01" + bytes(31)):
            with self.assertRaises(ProtocolError):
                c.dh(key, public)
        with self.assertRaises(ProtocolError):
            c.dh(bytes(32), bytes(32))
        with self.assertRaises(ProtocolError):
            c.public_bytes(bytes(32))

    def test_exact_spec_vectors_and_key_schedule(self):
        v = VECTORS
        private = {k: X25519PrivateKey.from_private_bytes(unhex(x))
                   for k, x in v["private_test_inputs"].items()}
        public = {k: c.public_bytes(key) for k, key in private.items()}
        for name, value in public.items():
            self.assertEqual(value.hex(), v["public_keys"][name])
        zt = c.dh(private["b_client_traffic"], public["e_server_traffic"])
        za = c.dh(private["a_client_auth"], public["s_server_static"])
        self.assertEqual(zt.hex(), v["shared_secrets"]["Zt"])
        self.assertEqual(za.hex(), v["shared_secrets"]["Za"])
        self.assertEqual(zt, c.dh(private["e_server_traffic"], public["b_client_traffic"]))
        self.assertEqual(za, c.dh(private["s_server_static"], public["a_client_auth"]))
        hroot, aroot = c.extract(c.ZERO32, zt), c.extract(c.ZERO32, za)
        self.assertEqual(hroot.hex(), v["secrets"]["HRoot"])
        self.assertEqual(aroot.hex(), v["secrets"]["ARoot"])
        t = {k: unhex(x["bytes"]) for k, x in v["transcripts"].items()}
        for name, value in t.items():
            self.assertEqual(c.digest(value).hex(), v["transcripts"][name]["sha256"])
        chs = c.label_expand(hroot, "c hs", c.digest(t["T0"]), 32)
        shs = c.label_expand(hroot, "s hs", c.digest(t["T0"]), 32)
        self.assertEqual(chs.hex(), v["secrets"]["c_hs"])
        self.assertEqual(shs.hex(), v["secrets"]["s_hs"])
        proof = c.server_proof(aroot, t["Tcert"])
        self.assertEqual(proof.hex(), v["authenticators"]["proof"])
        self.assertTrue(c.verify_proof(aroot, t["Tcert"], proof))
        self.assertEqual(c.finished(shs, t["Tproof"]).hex(), v["authenticators"]["server_finished"])
        self.assertEqual(c.finished(chs, t["Tserver_finished"]).hex(), v["authenticators"]["client_finished"])
        app_root = c.label_expand(hroot, "application", c.digest(t["Tfull"]), 32)
        self.assertEqual(app_root.hex(), v["secrets"]["app_root"])
        for name, label in (("c_app", "c ap"), ("s_app", "s ap")):
            self.assertEqual(c.label_expand(app_root, label, c.digest(t["Tfull"]), 32).hex(),
                             v["secrets"][name])
        self.assertEqual(c.PREFACE.hex(), v["preface"])

    def test_every_transcript_byte_is_authenticated(self):
        transcript = unhex(VECTORS["transcripts"]["Tcert"]["bytes"])
        root = unhex(VECTORS["secrets"]["ARoot"])
        proof = c.server_proof(root, transcript)
        for index in range(len(transcript)):
            mutated = bytearray(transcript)
            mutated[index] ^= 1
            self.assertFalse(c.verify_proof(root, bytes(mutated), proof), index)
        self.assertFalse(c.verify_proof(root, transcript, proof[:-1]))
        secret = unhex(VECTORS["secrets"]["s_hs"])
        value = c.finished(secret, transcript)
        self.assertTrue(c.verify_finished(secret, transcript, value))
        self.assertFalse(c.verify_finished(secret, transcript + b"x", value))
        self.assertFalse(c.verify_finished(secret, transcript, value + b"x"))

    def test_each_exact_spec_record(self):
        for name, record in VECTORS["records"].items():
            secret = unhex(VECTORS["secrets"][name])
            content, kind = unhex(record["content"]), record["inner_type"]
            wire = unhex(record["wire"])
            self.assertEqual(c.key_iv(secret), (unhex(record["key"]), unhex(record["iv"])))
            self.assertEqual(c.RecordState(secret, "seal").seal(content, kind), wire)
            self.assertEqual(c.RecordState(secret, "open").open(wire), (content, kind))

    def test_tamper_replay_reorder_wrong_epoch_and_direction(self):
        secret = unhex(VECTORS["secrets"]["c_app"])
        sender = c.RecordState(secret, "seal")
        first, second = sender.seal(b"first", 23), sender.seal(b"second", 23)
        for index in range(len(first)):
            mutated = bytearray(first)
            mutated[index] ^= 1
            receiver = c.RecordState(secret, "open")
            with self.assertRaises(ProtocolError):
                receiver.open(bytes(mutated))
            self.assertTrue(receiver.failed)
            self.assertEqual(receiver.sequence, 0)
            with self.assertRaises(ProtocolError):
                receiver.open(first)
        receiver = c.RecordState(secret, "open")
        receiver.open(first)
        with self.assertRaises(ProtocolError):
            receiver.open(first)
        for wrong in (second, first + b"x", first[:-1]):
            with self.assertRaises(ProtocolError):
                c.RecordState(secret, "open").open(wrong)
        for name in ("s_app", "c_hs"):
            with self.assertRaises(ProtocolError):
                c.RecordState(unhex(VECTORS["secrets"][name]), "open").open(first)

    def test_record_quotas_and_nonce(self):
        secret = bytes(32)
        sender, receiver = c.RecordState(secret, "seal"), c.RecordState(secret, "open")
        self.assertEqual(receiver.open(sender.seal(b"", 23)), (b"", 23))
        self.assertEqual(receiver.open(sender.seal(b"x" * c.MAX_CONTENT, 23)), (b"x" * c.MAX_CONTENT, 23))
        for attr, value in (("sequence", c.MAX_RECORDS), ("sequence", 1 << 64),
                            ("sequence", -1), ("content_bytes", c.MAX_CONTENT_BYTES)):
            sender = c.RecordState(secret, "seal")
            setattr(sender, attr, value)
            with self.assertRaises(ProtocolError):
                sender.seal(b"x", 23)
            self.assertTrue(sender.failed)
        sender = c.RecordState(secret, "seal")
        sender.content_bytes = c.MAX_CONTENT_BYTES - 1
        sender.seal(b"x", 23)
        sender.seal(b"", 23)
        with self.assertRaises(ProtocolError):
            sender.seal(b"x", 23)
        for sequence in (-1, 1 << 64):
            with self.assertRaises(ProtocolError):
                c.nonce(bytes(12), sequence)
        self.assertEqual(c.nonce(bytes(12), 256), bytes(10) + b"\x01\x00")
        with self.assertRaises(ProtocolError):
            c.RecordState(secret, "seal").seal(b"x" * (c.MAX_CONTENT + 1), 23)

    def test_record_bad_inner_content_and_operation(self):
        secret = bytes(32)
        key, iv = c.key_iv(secret)
        for content, kind in ((b"", 22), (b"", 21), (b"x", 21), (b"xxx", 21), (b"x", 0), (b"x", 20)):
            with self.assertRaises(ProtocolError):
                c.RecordState(secret, "seal").seal(content, kind)
            plain = content + bytes((kind,))
            header = b"\x17\x03\x03" + (len(plain) + 16).to_bytes(2, "big")
            wire = header + AESGCM(key).encrypt(c.nonce(iv, 0), plain, header)
            receiver = c.RecordState(secret, "open")
            with self.assertRaises(ProtocolError):
                receiver.open(wire)
            self.assertTrue(receiver.failed)
        wire = c.RecordState(secret, "seal").seal(b"ok", 23)
        sender = c.RecordState(secret, "seal")
        with self.assertRaises(ProtocolError):
            sender.open(wire)
        self.assertTrue(sender.failed)
        with self.assertRaises(ProtocolError):
            c.RecordState(secret, "both")
        self.assertNotIn(secret.hex(), repr(c.RecordState(secret, "seal")))

    def test_receiver_quotas_before_content_delivery(self):
        secret = bytes(32)
        key, iv = c.key_iv(secret)
        for sequence, content_bytes, content in (
                (c.MAX_RECORDS, 0, b"x"),
                (0, c.MAX_CONTENT_BYTES, b"x"),
                (0, 0, b"x" * (c.MAX_CONTENT + 1))):
            receiver = c.RecordState(secret, "open")
            receiver.sequence, receiver.content_bytes = sequence, content_bytes
            plaintext = content + b"\x17"
            header = b"\x17\x03\x03" + (len(plaintext) + 16).to_bytes(2, "big")
            wire = header + AESGCM(key).encrypt(c.nonce(iv, sequence), plaintext, header)
            with self.assertRaises(ProtocolError):
                receiver.open(wire)
            self.assertTrue(receiver.failed)
            self.assertEqual(receiver.sequence, sequence)
            self.assertEqual(receiver.content_bytes, content_bytes)

    def test_rfc7748_high_bit_input_decoding(self):
        # RFC 7748 accepts the high bit masked in the final X25519 input byte.
        # The transport still binds exact peer bytes in the transcript.
        a = X25519PrivateKey.from_private_bytes(bytes(range(32)))
        b = X25519PrivateKey.from_private_bytes(bytes(range(32, 64)))
        public = c.public_bytes(b)
        equivalent = public[:-1] + bytes((public[-1] ^ 128,))
        self.assertEqual(c.dh(a, public), c.dh(a, equivalent))
        self.assertNotEqual(c.digest(public), c.digest(equivalent))


if __name__ == "__main__":
    unittest.main()
