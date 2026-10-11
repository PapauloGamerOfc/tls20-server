"""Known answers and negative record cases; fixed keys are PUBLIC test data."""

import hashlib
import hmac
import unittest
from unittest.mock import Mock, patch

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand

from tls20_server import crypto as c
from tls20_server.errors import ProtocolError
from tls20_server import messages as m

TEST_SECRETS = {"c_app": bytes(range(32)), "s_app": bytes(range(32, 64)),
                "c_hs": bytes(range(64, 96))}


def unhex(value):
    return bytes.fromhex(value)


class CryptoTests(unittest.TestCase):
    def test_failed_record_construction_releases_partial_keys(self):
        for target, name in ((c, "key_iv"), (c.RecordState, "_reset_cipher")):
            with self.subTest(stage=name):
                provider = Mock()
                state = c.RecordState.__new__(c.RecordState)
                with patch.object(target, name, side_effect=RuntimeError("provider failed")):
                    with self.assertRaisesRegex(RuntimeError, "provider failed"):
                        state.__init__(bytes(32), "open", provider=provider)
                self.assertTrue(state.failed)
                self.assertEqual((state.secret, state.key, state.iv), (b"", b"", b""))
                self.assertIsNone(state._cipher)
                self.assertIsNone(state.provider)
                provider.close.assert_not_called()

    def test_failed_epoch_probe_construction_closes_both_states(self):
        state, trials = c.RecordState(bytes(32), "open"), []
        def fail(trial):
            trials.append(trial)
            raise RuntimeError("provider failed")
        with patch.object(c.RecordState, "_reset_cipher", fail):
            with self.assertRaisesRegex(RuntimeError, "provider failed"):
                state.try_open(bytes.fromhex("1703030010") + bytes(16))
        self.assertEqual(len(trials), 1)
        for closed in (state, *trials):
            self.assertTrue(closed.failed)
            self.assertEqual((closed.secret, closed.key, closed.iv), (b"", b"", b""))
            self.assertIsNone(closed._cipher)

    def test_provider_record_failures_close_state_and_release_secrets(self):
        record = c.RecordState(bytes(32), "seal").seal(b"fixture", 23)
        for operation in ("seal", "open"):
            for failure in (RuntimeError, MemoryError):
                with self.subTest(operation=operation, failure=failure.__name__):
                    state = c.RecordState(bytes(32), operation)
                    state._cipher = Mock()
                    method = state._cipher.encrypt if operation == "seal" else state._cipher.decrypt
                    method.side_effect = failure("provider failed")
                    with self.assertRaises(failure):
                        if operation == "seal":
                            state.seal(b"fixture", 23)
                        else:
                            state.open(record)
                    self.assertTrue(state.failed)
                    self.assertEqual((state.secret, state.key, state.iv), (b"", b"", b""))
                    self.assertIsNone(state._cipher)
                    self.assertIsNone(state.provider)
                    with self.assertRaises(ProtocolError):
                        if operation == "seal":
                            state.seal(b"retry", 23)
                        else:
                            state.open(record)

    def test_failed_record_update_releases_partial_epoch_state(self):
        for target, name in ((c, "label_expand"), (c, "key_iv"), (c.RecordState, "_reset_cipher")):
            with self.subTest(stage=name):
                state = c.RecordState(bytes(32), "seal")
                with patch.object(target, name, side_effect=RuntimeError("provider failed")):
                    with self.assertRaisesRegex(RuntimeError, "provider failed"):
                        state.update()
                self.assertTrue(state.failed)
                self.assertEqual((state.secret, state.key, state.iv), (b"", b"", b""))
                self.assertIsNone(state._cipher)
                with self.assertRaises(ProtocolError):
                    state.seal(b"inconsistent epoch", 23)

    def test_epoch_probe_releases_trial_secrets_and_closes_terminal_failures(self):
        from contextlib import nullcontext
        record = c.RecordState(bytes(32), "seal").seal(b"probe", 23)
        original_close = c.RecordState.close
        for outcome in ("valid", "bad_tag", "provider_error"):
            with self.subTest(outcome=outcome):
                state, trials = c.RecordState(bytes(32), "open"), []
                def track_close(trial):
                    trials.append(trial)
                    original_close(trial)
                fault = (patch.object(c.RecordState, "open", side_effect=RuntimeError("provider failed"))
                         if outcome == "provider_error" else nullcontext())
                with patch.object(c.RecordState, "close", track_close), fault:
                    if outcome == "provider_error":
                        with self.assertRaisesRegex(RuntimeError, "provider failed"):
                            state.try_open(record)
                    elif outcome == "bad_tag":
                        self.assertIsNone(state.try_open(record[:-1] + bytes((record[-1] ^ 1,))))
                    else:
                        self.assertEqual(state.try_open(record), (b"probe", 23))
                self.assertEqual(state.failed, outcome == "provider_error")
                self.assertEqual(state.sequence, int(outcome == "valid"))
                self.assertTrue(trials)
                for trial in trials:
                    self.assertEqual((trial.secret, trial.key, trial.iv), (b"", b"", b""))
                    self.assertIsNone(trial._cipher)

    def test_epoch_probe_propagates_authenticated_plaintext_errors(self):
        for plaintext, alert in ((b"x\xff", 10), (b"\x00", 10), (b"", 10),
                                 (b"\x16", 10), (b"\x01\x15", 50),
                                 (b"x" * 64 + b"\x17", 22)):
            with self.subTest(plaintext=plaintext):
                sender = c.RecordState(bytes(32), "seal")
                header = b"\x17\x03\x03" + (len(plaintext) + sender.suite.tag_length).to_bytes(2, "big")
                record = header + sender._cipher.encrypt(c.nonce(sender.iv, 0), plaintext, header)
                state = c.RecordState(bytes(32), "open", record_limit=64)
                with self.assertRaises(ProtocolError) as failure:
                    state.try_open(record)
                self.assertEqual(failure.exception.alert, alert)
                self.assertTrue(state.failed)
                self.assertEqual((state.secret, state.key, state.iv), (b"", b"", b""))
                self.assertIsNone(state._cipher)
                with self.assertRaises(ProtocolError):
                    state.try_open(sender.seal(b"valid after invalid", 23))

    def test_epoch_probe_discards_only_authentication_failures(self):
        sender, state = c.RecordState(bytes(32), "seal"), c.RecordState(bytes(32), "open")
        valid = sender.seal(b"handshake epoch", 23)
        for record in (b"\x17\x03\x03\x00\x00", b"\x17\x03\x03\x00\x10" + bytes(16),
                       valid[:-1] + bytes((valid[-1] ^ 1,))):
            self.assertIsNone(state.try_open(record))
            self.assertFalse(state.failed)
            self.assertEqual(state.sequence, 0)
        self.assertEqual(state.try_open(valid), (b"handshake epoch", 23))
        for record, alert in ((b"\x16\x03\x03\x00\x00", 10),
                              (b"\x17\x03\x01\x00\x00", 47),
                              (b"\x17\x03\x03\x00\x01", 50)):
            state = c.RecordState(bytes(32), "open")
            with self.assertRaises(ProtocolError) as failure:
                state.try_open(record)
            self.assertEqual(failure.exception.alert, alert)
            self.assertTrue(state.failed)

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
        for label, context, secret in (("a" * 250, b"", prk), ("á", b"", prk),
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
        # Independent provider and literal wire-domain labels. This must not
        # validate a modified schedule against values made by that same helper.
        H = lambda value: hashlib.sha256(value).digest()
        extract = lambda salt, value: hmac.digest(salt, value, "sha256")
        def expand(secret, label, context, length=32):
            full = b"tls20 " + label
            info = length.to_bytes(2, "big") + bytes((len(full),)) + full + bytes((len(context),)) + context
            return HKDFExpand(hashes.SHA256(), length, info).derive(secret)
        zero, shared, auth = bytes(32), bytes(range(32)), bytes(range(32, 64))
        transcript = b"TLS20-EXPERIMENT\r\n" + b"public framed handshake fixture"
        early = extract(zero, zero)
        hs = extract(expand(early, b"derived", H(b"")), shared)
        master = extract(expand(hs, b"derived", H(b"")), zero)
        self.assertEqual(c.handshake_secret(shared), hs)
        self.assertEqual(c.master_secret(hs), master)
        aroot = extract(expand(hs, b"auth salt", H(transcript)), auth)
        self.assertEqual(c.authentication_root(hs, auth, transcript), aroot)
        proof = extract(expand(aroot, b"server mac", b""),
                        b" " * 64 + b"TLS 2.0, server CertificateVerify\0" + H(transcript))
        self.assertEqual(c.server_proof(aroot, transcript), proof)
        shs = expand(hs, b"s hs traffic", H(transcript))
        self.assertEqual(c.finished(shs, transcript), extract(expand(shs, b"finished", b""), H(transcript)))
        self.assertEqual(c.PREFACE, b"TLS20-EXPERIMENT\r\n")
        self.assertEqual(len(c.PREFACE), 18)
        res_binder = expand(extract(zero, auth), b"res binder", H(b""))
        self.assertEqual(c.binder(auth, transcript), extract(expand(res_binder, b"finished", b""), H(transcript)))
        exp_master = expand(master, b"exp master", H(transcript))
        self.assertEqual(c.exporter(exp_master, "example", b"context", 40),
            expand(expand(exp_master, b"example", H(b"")), b"exporter", H(b"context"), 40))

    def test_every_transcript_byte_is_authenticated(self):
        transcript = b"TLS20-EXPERIMENT\r\n\x01\x00\x00\x05hello\x0b\x00\x00\x04cert"
        root = bytes(range(32))
        proof = c.server_proof(root, transcript)
        for index in range(len(transcript)):
            mutated = bytearray(transcript)
            mutated[index] ^= 1
            self.assertFalse(c.verify_proof(root, bytes(mutated), proof), index)
        self.assertFalse(c.verify_proof(root, transcript, proof[:-1]))
        secret = bytes(range(32, 64))
        value = c.finished(secret, transcript)
        self.assertTrue(c.verify_finished(secret, transcript, value))
        self.assertFalse(c.verify_finished(secret, transcript + b"x", value))
        self.assertFalse(c.verify_finished(secret, transcript, value + b"x"))

    def test_initial_and_pha_client_mac_independent_spec_known_answers(self):
        # Frozen results of tls20-spec/tests/test_components.py's independent
        # HKDFExpand-provider client_proof_oracle at 0c9c8bf. These are not
        # generated by this implementation and need no sibling repo in CI.
        client = X25519PrivateKey.from_private_bytes(unhex(
            "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"))
        verifier = X25519PrivateKey.from_private_bytes(unhex(
            "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"))
        root = hashlib.sha256(b"initial exporter root").digest()
        for suffix, expected_hex in (
            (b"initial flight through client certificate",
             "94a65402ccd5bc8776f57cef7cdeb2b866f80d4ce2e6838f65c6bfd3403eee8d"),
            (b"initial handshake + PHA request + certificate",
             "042063fa78e6f34d7df3dc524b947d318c7bfb7cfe24011287c5d4476ef7e23a")):
            transcript = b"TLS20-EXPERIMENT\r\n" + suffix
            expected = unhex(expected_hex)
            self.assertEqual(c.client_proof(root, client, c.public_bytes(verifier), transcript), expected)
            self.assertEqual(c.client_proof(root, verifier, c.public_bytes(client), transcript), expected)
            self.assertEqual(m.certificate_verify(expected, client=True), b"\x0f\x00\x00\x24\xfe\x01\x00\x20" + expected)
            self.assertNotEqual(c.client_proof(root, client, c.public_bytes(verifier), transcript + b"x"), expected)

    def test_each_exact_spec_record(self):
        secret = bytes(range(32))
        for content, kind, padding in ((b"abc", 23, 0), (b"abc\0", 23, 17), (b"x", 22, 100)):
            plain = content + bytes((kind,)) + bytes(padding)
            header = b"\x17\x03\x03" + (len(plain)+16).to_bytes(2, "big")
            key = HKDFExpand(hashes.SHA256(), 16, b"\x00\x10\x09tls20 key\x00").derive(secret)
            iv = HKDFExpand(hashes.SHA256(), 12, b"\x00\x0c\x08tls20 iv\x00").derive(secret)
            wire = header + AESGCM(key).encrypt(iv, plain, header)
            self.assertEqual(c.RecordState(secret, "seal").seal(content, kind, padding), wire)
            self.assertEqual(c.RecordState(secret, "open").open(wire), (content, kind))

    def test_tamper_replay_reorder_wrong_epoch_and_direction(self):
        secret = TEST_SECRETS["c_app"]
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
                c.RecordState(TEST_SECRETS[name], "open").open(first)

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

    def test_receiver_accepts_peer_rekey_policy_but_enforces_wire_limits(self):
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
            if len(content) > c.MAX_CONTENT:
                with self.assertRaises(ProtocolError):
                    receiver.open(wire)
                self.assertTrue(receiver.failed)
                self.assertEqual(receiver.sequence, sequence)
                self.assertEqual(receiver.content_bytes, content_bytes)
            else:
                self.assertEqual(receiver.open(wire), (content, 23))
                self.assertEqual(receiver.sequence, sequence + 1)
        receiver = c.RecordState(secret, "open")
        receiver.sequence = 1 << 64
        with self.assertRaises(ProtocolError):
            receiver.open(c.RecordState(secret, "seal").seal(b"x", 23))

    def test_rfc7748_high_bit_input_decoding(self):
        # RFC 7748 accepts the high bit masked in the final X25519 input byte.
        # The transport still binds exact peer bytes in the transcript.
        a = X25519PrivateKey.from_private_bytes(bytes(range(32)))
        b = X25519PrivateKey.from_private_bytes(bytes(range(32, 64)))
        public = c.public_bytes(b)
        equivalent = public[:-1] + bytes((public[-1] ^ 128,))
        self.assertEqual(c.dh(a, public), c.dh(a, equivalent))
        self.assertNotEqual(c.digest(public), c.digest(equivalent))

    def test_padding_cannot_hide_an_oversized_plaintext(self):
        secret = bytes(32)
        key, iv = c.key_iv(secret)
        plaintext = b"x\x17" + bytes(16384)
        header = b"\x17\x03\x03" + (len(plaintext) + 16).to_bytes(2, "big")
        record = header + AESGCM(key).encrypt(iv, plaintext, header)
        self.assertLess(len(record) - 5, 16640)
        with self.assertRaisesRegex(ProtocolError, "padded plaintext"):
            c.RecordState(secret, "open").open(record)


if __name__ == "__main__":
    unittest.main()
