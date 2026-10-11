"""TLS 2.0 SHA-256/AES-128-GCM primitives and RFC-shaped key schedule.

Copyright (c) 2026 TLS 2.0 specification contributors. See LICENSE and
https://github.com/PapauloGamerOfc/tls20-spec for the original component tests.
This module is not a standard TLS implementation or a security proof.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import hmac

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .errors import ProtocolError

PREFACE = b"TLS20-EXPERIMENT\r\n"
LABEL_PREFIX = b"tls20 "
PROOF_CONTEXT = b" " * 64 + b"TLS 2.0, server CertificateVerify\x00"
ZERO32 = bytes(32)
MAX_CONTENT = 1 << 14
MAX_RECORDS = 1 << 20
MAX_CONTENT_BYTES = 1 << 30
INNER_TYPES = frozenset((21, 22, 23))


def digest(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def mac(key: bytes, data: bytes) -> bytes:
    return hmac.digest(key, data, "sha256")


def extract(salt: bytes, ikm: bytes) -> bytes:
    return mac(salt, ikm)


def expand(prk: bytes, info: bytes, length: int) -> bytes:
    if not 0 <= length <= 255 * 32:
        raise ProtocolError("HKDF output length out of bounds")
    result = b""
    previous = b""
    for counter in range(1, (length + 31) // 32 + 1):
        previous = mac(prk, previous + info + bytes((counter,)))
        result += previous
    return result[:length]


def label_info(label: str, context: bytes, length: int) -> bytes:
    try:
        full_label = LABEL_PREFIX + label.encode("ascii")
    except UnicodeEncodeError as exc:
        raise ProtocolError("labels must be ASCII") from exc
    if not 0 <= length <= 255 * 32:
        raise ProtocolError("HKDF output length out of bounds")
    if len(full_label) > 255 or len(context) > 255:
        raise ProtocolError("label or context exceeds uint8 length")
    return (length.to_bytes(2, "big") + bytes((len(full_label),)) + full_label
            + bytes((len(context),)) + context)


def label_expand(secret: bytes, label: str, context: bytes, length: int) -> bytes:
    if len(secret) != 32:
        raise ProtocolError("SHA-256 secrets must have length 32")
    return expand(secret, label_info(label, context, length), length)


def public_bytes(key: X25519PrivateKey | X25519PublicKey) -> bytes:
    if isinstance(key, X25519PrivateKey):
        key = key.public_key()
    if not isinstance(key, X25519PublicKey):
        raise ProtocolError("expected an X25519 key")
    return key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def dh(private: X25519PrivateKey, public: bytes) -> bytes:
    if not isinstance(private, X25519PrivateKey) or len(public) != 32:
        raise ProtocolError("expected X25519 private key and 32-byte public input")
    try:
        shared = private.exchange(X25519PublicKey.from_public_bytes(public))
    except ValueError as exc:
        raise ProtocolError("invalid X25519 shared secret") from exc
    if hmac.compare_digest(shared, ZERO32):
        raise ProtocolError("all-zero X25519 shared secret")
    return shared


def traffic_key(group: int):
    if group == 0x001d:
        private = X25519PrivateKey.generate()
        return private, public_bytes(private)
    if group == 0x0017:
        private = ec.generate_private_key(ec.SECP256R1())
        return private, private.public_key().public_bytes(
            serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
    raise ProtocolError("unsupported traffic group")


def traffic_dh(private, group: int, public: bytes) -> bytes:
    if group == 0x001d:
        return dh(private, public)
    if group == 0x0017 and len(public) == 65 and public[0] == 4:
        try:
            peer = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), public)
            return private.exchange(ec.ECDH(), peer)
        except (ValueError, TypeError) as exc:
            raise ProtocolError("invalid P-256 traffic share") from exc
    raise ProtocolError("invalid traffic group or share")


def server_proof(auth_root: bytes, transcript: bytes) -> bytes:
    thash = digest(transcript)
    return mac(label_expand(auth_root, "server mac", b"", 32), PROOF_CONTEXT + thash)


def derive_secret(secret: bytes, label: str, transcript: bytes) -> bytes:
    return label_expand(secret, label, digest(transcript), 32)


def handshake_secret(shared: bytes, psk: bytes = ZERO32) -> bytes:
    early = extract(ZERO32, psk)
    return extract(derive_secret(early, "derived", b""), shared)


def master_secret(handshake: bytes) -> bytes:
    return extract(derive_secret(handshake, "derived", b""), ZERO32)


def authentication_root(handshake: bytes, shared: bytes, transcript: bytes) -> bytes:
    return extract(label_expand(handshake, "auth salt", digest(transcript), 32), shared)


def binder(psk: bytes, truncated_transcript: bytes) -> bytes:
    key = derive_secret(extract(ZERO32, psk), "res binder", b"")
    return finished(key, truncated_transcript)


def exporter(secret: bytes, label: str, context: bytes, length: int) -> bytes:
    intermediate = derive_secret(secret, label, b"")
    return label_expand(intermediate, "exporter", digest(context), length)


def client_proof(exporter_secret: bytes, private: X25519PrivateKey, peer: bytes,
                 transcript: bytes) -> bytes:
    thash = digest(transcript)
    salt = exporter(exporter_secret, "EXPORTER-TLS20-Client-Auth", thash, 32)
    root = extract(salt, dh(private, peer))
    key = label_expand(root, "client mac", b"", 32)
    return mac(key, b" " * 64 + b"TLS 2.0, client CertificateVerify\x00" + thash)


def verify_proof(auth_root: bytes, transcript: bytes, proof: bytes) -> bool:
    return len(proof) == 32 and hmac.compare_digest(server_proof(auth_root, transcript), proof)


def finished(secret: bytes, transcript: bytes) -> bytes:
    return mac(label_expand(secret, "finished", b"", 32), digest(transcript))


def verify_finished(secret: bytes, transcript: bytes, value: bytes) -> bool:
    return len(value) == 32 and hmac.compare_digest(finished(secret, transcript), value)


def key_iv(secret: bytes) -> tuple[bytes, bytes]:
    return label_expand(secret, "key", b"", 16), label_expand(secret, "iv", b"", 12)


def nonce(iv: bytes, sequence: int) -> bytes:
    if len(iv) != 12 or not 0 <= sequence < 1 << 64:
        raise ProtocolError("invalid IV or sequence number")
    padded = bytes(4) + sequence.to_bytes(8, "big")
    return bytes(left ^ right for left, right in zip(iv, padded))


def validate_inner(content: bytes, inner_type: int) -> None:
    if inner_type not in INNER_TYPES:
        raise ProtocolError("invalid inner type")
    if inner_type == 22 and not content:
        raise ProtocolError("empty handshake record")
    if inner_type == 21 and len(content) != 2:
        raise ProtocolError("alert content must have length 2")


@dataclass(repr=False)
class RecordState:
    """One direction and epoch; a failed operation permanently closes the state.

    The transport must enforce handshake/application ordering and close_notify.
    No state reset exists. Counter attributes are exposed for boundary tests.
    Python cannot guarantee erasure of immutable secret bytes or provider memory.
    """

    secret: bytes
    operation: str
    sequence: int = field(default=0, init=False)
    content_bytes: int = field(default=0, init=False)
    failed: bool = field(default=False, init=False)

    def __post_init__(self) -> None:
        if self.operation not in ("seal", "open"):
            raise ProtocolError("record operation must be seal or open")
        self.key, self.iv = key_iv(self.secret)
        self._cipher = AESGCM(self.key)

    def _ready(self, operation: str, content_length: int) -> None:
        if self.failed:
            raise ProtocolError("record state is closed")
        if operation != self.operation:
            raise ProtocolError("record direction operation mismatch")
        if not 0 <= self.sequence < min(MAX_RECORDS, 1 << 64):
            raise ProtocolError("record count limit")
        if not 0 <= content_length <= MAX_CONTENT:
            raise ProtocolError("record content length limit")
        if not 0 <= self.content_bytes <= MAX_CONTENT_BYTES - content_length:
            raise ProtocolError("traffic key content-byte limit")

    def _advance(self, content_length: int) -> None:
        self.sequence += 1
        self.content_bytes += content_length

    def seal(self, content: bytes, inner_type: int, padding: int = 0) -> bytes:
        try:
            self._ready("seal", len(content))
            validate_inner(content, inner_type)
            if not isinstance(padding, int) or not 0 <= padding <= 16385 - len(content) - 1:
                raise ProtocolError("record padding length")
            plaintext = content + bytes((inner_type,)) + bytes(padding)
            header = b"\x17\x03\x03" + (len(plaintext) + 16).to_bytes(2, "big")
            result = header + self._cipher.encrypt(nonce(self.iv, self.sequence), plaintext, header)
            self._advance(len(content))
            return result
        except (ValueError, OverflowError):
            self.failed = True
            raise

    def open(self, record: bytes) -> tuple[bytes, int]:
        try:
            if len(record) < 22 or record[:3] != b"\x17\x03\x03":
                raise ProtocolError("invalid encrypted record header")
            ciphertext_length = int.from_bytes(record[3:5], "big")
            if ciphertext_length != len(record) - 5:
                raise ProtocolError("encrypted record length mismatch")
            if not 17 <= ciphertext_length <= 16640:
                raise ProtocolError("encrypted record size")
            self._ready("open", 0)
            plaintext = self._cipher.decrypt(nonce(self.iv, self.sequence), record[5:], record[:5])
            if len(plaintext) > MAX_CONTENT + 1:
                raise ProtocolError("padded plaintext exceeds record limit")
            if not plaintext:
                raise ProtocolError("missing inner type")
            stripped = plaintext.rstrip(b"\x00")
            if not stripped:
                raise ProtocolError("missing inner type")
            content, inner_type = stripped[:-1], stripped[-1]
            self._ready("open", len(content))
            validate_inner(content, inner_type)
            self._advance(len(content))
            return content, inner_type
        except (ValueError, OverflowError, InvalidTag) as exc:
            self.failed = True
            if isinstance(exc, InvalidTag):
                raise ProtocolError("record authentication failed") from exc
            raise

    def try_open(self, record: bytes) -> tuple[bytes, int] | None:
        """Probe an epoch transition; failed AEAD trial never mutates this state."""
        trial = RecordState(self.secret, self.operation)
        trial.sequence, trial.content_bytes = self.sequence, self.content_bytes
        try:
            result = trial.open(record)
        except ProtocolError:
            return None
        self.sequence, self.content_bytes = trial.sequence, trial.content_bytes
        return result

    def update(self) -> None:
        if self.failed:
            raise ProtocolError("record state is closed")
        self.secret = label_expand(self.secret, "traffic upd", b"", 32)
        self.sequence = self.content_bytes = 0
        self.key, self.iv = key_iv(self.secret)
        self._cipher = AESGCM(self.key)
