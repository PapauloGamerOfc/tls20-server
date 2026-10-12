"""TLS 2.0 negotiated cryptographic primitives and RFC-shaped key schedule.

Copyright (c) 2026 TLS 2.0 specification contributors. See LICENSE and
https://github.com/PapauloGamerOfc/tls20-spec for the original component tests.
This module is not a standard TLS implementation or a security proof.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import hmac

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import serialization, hashes, hmac as native_hmac
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import x448
from cryptography.hazmat.primitives.asymmetric import mlkem
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, AESCCM, ChaCha20Poly1305

from .errors import ProtocolError
from . import ffdhe

PREFACE = b"TLS20-EXPERIMENT\r\n"
LABEL_PREFIX = b"tls20 "
PROOF_CONTEXT = b" " * 64 + b"TLS 2.0, server CertificateVerify\x00"
ZERO32 = bytes(32)
MAX_CONTENT = 1 << 14
MAX_RECORDS = 1 << 20
MAX_CONTENT_BYTES = 1 << 30
MAX_SEND_EPOCH = (1 << 48) - 1
INNER_TYPES = frozenset((21, 22, 23, 24))


@dataclass(frozen=True)
class CipherSuite:
    code: int
    hash_name: str
    key_length: int
    cipher: str
    tag_length: int = 16
    iv_length: int = 12
    confidential: bool = True
    password_authenticated: bool = False

    @property
    def hash_length(self):
        return hash_length(self.hash_name)

    def aead(self, key, provider=None):
        if self.cipher in ("kuznyechik-mgm", "magma-mgm"):
            raise ProtocolError("GOST TLS records require per-record TLSTREE, not a reusable raw AEAD")
        if self.cipher in ("SM4-GCM", "SM4-CCM"):
            if provider is None:
                raise ProtocolError("SM4 requires an explicitly selected native provider")
            return provider.aead(self.cipher, key)
        if self.cipher == "gcm":
            return AESGCM(key)
        if self.cipher == "chacha":
            return ChaCha20Poly1305(key)
        if self.cipher == "hmac":
            from .integrity_only import IntegrityOnly
            return IntegrityOnly(key, self.hash_name)
        return AESCCM(key, tag_length=self.tag_length)


CIPHER_SUITES = {
    0x1301: CipherSuite(0x1301, "sha256", 16, "gcm"),
    0x1302: CipherSuite(0x1302, "sha384", 32, "gcm"),
    0x1303: CipherSuite(0x1303, "sha256", 32, "chacha"),
    0x1304: CipherSuite(0x1304, "sha256", 16, "ccm"),
    0x1305: CipherSuite(0x1305, "sha256", 16, "ccm", 8),
    0xc0b4: CipherSuite(0xc0b4, "sha256", 32, "hmac", 32, 32, False),
    0xc0b5: CipherSuite(0xc0b5, "sha384", 48, "hmac", 48, 48, False),
    0x00c6: CipherSuite(0x00c6, "sm3", 16, "SM4-GCM"),
    0x00c7: CipherSuite(0x00c7, "sm3", 16, "SM4-CCM"),
    0xc0b0: CipherSuite(0xc0b0, "sha256", 16, "gcm", password_authenticated=True),
    0xc0b1: CipherSuite(0xc0b1, "sha384", 32, "gcm", password_authenticated=True),
    0xc0b2: CipherSuite(0xc0b2, "sha256", 16, "ccm", password_authenticated=True),
    0xc0b3: CipherSuite(0xc0b3, "sha384", 32, "ccm", password_authenticated=True),
    0xc103: CipherSuite(0xc103, "streebog256", 32, "kuznyechik-mgm", 16, 16),
    0xc104: CipherSuite(0xc104, "streebog256", 32, "magma-mgm", 8, 8),
    0xc105: CipherSuite(0xc105, "streebog256", 32, "kuznyechik-mgm", 16, 16),
    0xc106: CipherSuite(0xc106, "streebog256", 32, "magma-mgm", 8, 8),
}
EC_GROUPS = {23: ec.SECP256R1, 24: ec.SECP384R1, 25: ec.SECP521R1,
             31: ec.BrainpoolP256R1, 32: ec.BrainpoolP384R1, 33: ec.BrainpoolP512R1}
GROUP_LENGTHS = {29: 32, 30: 56, 41: 65, **{group: 1 + 2 * ((curve().key_size + 7) // 8)
                                   for group, curve in EC_GROUPS.items()}, **ffdhe.SIZES,
                 **{group: 64 if group < 38 else 128 for group in range(34,41)}}
HYBRID_GROUPS = {
    4588: (29, mlkem.MLKEM768PrivateKey, mlkem.MLKEM768PublicKey, 1184, 1088, True),
    4587: (23, mlkem.MLKEM768PrivateKey, mlkem.MLKEM768PublicKey, 1184, 1088, False),
    4589: (24, mlkem.MLKEM1024PrivateKey, mlkem.MLKEM1024PublicKey, 1568, 1568, False),
}
SERVER_GROUP_LENGTHS = dict(GROUP_LENGTHS)
for _group, (_ec, _, _, _public_size, _ciphertext_size, _) in HYBRID_GROUPS.items():
    GROUP_LENGTHS[_group] = GROUP_LENGTHS[_ec] + _public_size
    SERVER_GROUP_LENGTHS[_group] = GROUP_LENGTHS[_ec] + _ciphertext_size


@dataclass(repr=False)
class HybridPrivate:
    group: int
    classical: object
    kem: object


def traffic_auth_component(group, share):
    """Expose only an X25519 traffic component for independence checks."""
    if group == 29:
        return share
    if group == 4588:
        return share[-32:]
    return b""


def suite(code=0x1301):
    try:
        return CIPHER_SUITES[code]
    except KeyError as exc:
        raise ProtocolError("unsupported cipher suite") from exc


@dataclass(frozen=True)
class HashContext:
    """Explicit provider-bound algorithm, never inferred from secret bytes."""
    name: str
    provider: object = field(repr=False)

    def __post_init__(self):
        if self.name == "sm3":
            from .openssl_provider import OpenSSLProvider
            if not isinstance(self.provider, OpenSSLProvider):
                raise ProtocolError("SM3 hash requires an explicit native provider")
            return
        if self.name not in ("streebog256", "streebog512"):
            raise ProtocolError("unsupported provider hash")
        from .gost_provider import GOSTProvider
        if not isinstance(self.provider, GOSTProvider):
            raise ProtocolError("GOST hash requires an explicit GOST provider")


def hash_context(name, provider=None):
    if isinstance(name, HashContext):
        return name
    return HashContext(name, provider) if name in ("streebog256", "streebog512") or name == "sm3" and provider is not None else name


def hash_length(name):
    name = name.name if isinstance(name, HashContext) else name
    if name in ("sm3", "streebog256", "streebog512"):
        return 64 if name == "streebog512" else 32
    return hashlib.new(name).digest_size


def secret_hash(secret, hash_name=None):
    name = hash_name or ("sha384" if len(secret) == 48 else "sha256")
    if not isinstance(name, HashContext) and name not in ("sha256", "sha384", "sm3"):
        raise ProtocolError("unsupported schedule hash")
    return name


def digest(data: bytes, hash_name="sha256") -> bytes:
    if isinstance(hash_name, HashContext):
        return hash_name.provider.digest(hash_name.name, data)
    if hash_name == "sm3":
        # Standalone component APIs use the pinned cryptography provider, not
        # a platform-dependent algorithm list in Python's unrelated hashlib.
        context = hashes.Hash(hashes.SM3())
        context.update(data)
        return context.finalize()
    return hashlib.new(hash_name, data).digest()


def mac(key: bytes, data: bytes, hash_name=None) -> bytes:
    name = secret_hash(key, hash_name)
    if isinstance(name, HashContext):
        return name.provider.hmac(name.name, key, data)
    if name == "sm3":
        context = native_hmac.HMAC(key, hashes.SM3())
        context.update(data)
        return context.finalize()
    return hmac.digest(key, data, name)


def extract(salt: bytes, ikm: bytes, hash_name=None) -> bytes:
    return mac(salt, ikm, hash_name)


def expand(prk: bytes, info: bytes, length: int, hash_name=None) -> bytes:
    name = secret_hash(prk, hash_name)
    size = hash_length(name)
    if not 0 <= length <= 255 * size:
        raise ProtocolError("HKDF output length out of bounds")
    result = b""
    previous = b""
    for counter in range(1, (length + size - 1) // size + 1):
        previous = mac(prk, previous + info + bytes((counter,)), name)
        result += previous
    return result[:length]


def label_info(label: str, context: bytes, length: int) -> bytes:
    try:
        full_label = LABEL_PREFIX + label.encode("ascii")
    except UnicodeEncodeError as exc:
        raise ProtocolError("labels must be ASCII") from exc
    if not 0 <= length <= 65535:
        raise ProtocolError("HKDF output length out of bounds")
    if len(full_label) > 255 or len(context) > 255:
        raise ProtocolError("label or context exceeds uint8 length")
    return (length.to_bytes(2, "big") + bytes((len(full_label),)) + full_label
            + bytes((len(context),)) + context)


def label_expand(secret: bytes, label: str, context: bytes, length: int, hash_name=None) -> bytes:
    name = secret_hash(secret, hash_name)
    if len(secret) != hash_length(name):
        raise ProtocolError("schedule secret length does not match hash")
    return expand(secret, label_info(label, context, length), length, name)


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
        raise ProtocolError("invalid X25519 shared secret", alert=47) from exc
    if hmac.compare_digest(shared, ZERO32):
        raise ProtocolError("all-zero X25519 shared secret", alert=47)
    return shared


def traffic_key(group: int, provider=None):
    if 34 <= group <= 40:
        from .gost_provider import GOSTProvider
        if not isinstance(provider, GOSTProvider):
            raise ProtocolError("GOST group requires an explicit GOST provider")
        return provider.generate_gost(group)
    if group == 41:
        if provider is None:
            raise ProtocolError("curveSM2 requires an explicitly selected native provider")
        return provider.generate_sm2()
    if group in ffdhe.SIZES:
        return ffdhe.generate(group)
    if group in HYBRID_GROUPS:
        traditional, key_type, _, _, _, kem_first = HYBRID_GROUPS[group]
        classical, share = traffic_key(traditional)
        kem = key_type.generate()
        public = kem.public_key().public_bytes_raw()
        return HybridPrivate(group, classical, kem), public + share if kem_first else share + public
    if group == 0x001d:
        private = X25519PrivateKey.generate()
        return private, public_bytes(private)
    if group == 30:
        private = x448.X448PrivateKey.generate()
        return private, private.public_key().public_bytes_raw()
    if group in EC_GROUPS:
        private = ec.generate_private_key(EC_GROUPS[group]())
        return private, private.public_key().public_bytes(
            serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
    raise ProtocolError("unsupported traffic group")


def traffic_dh(private, group: int, public: bytes, provider=None) -> bytes:
    if 34 <= group <= 40:
        from .gost_provider import GOSTProvider
        if not isinstance(provider, GOSTProvider):
            raise ProtocolError("GOST group requires an explicit GOST provider")
        return provider.exchange_gost(private, group, public)
    if group == 41:
        if provider is None:
            raise ProtocolError("curveSM2 requires an explicitly selected native provider")
        return provider.exchange_sm2(private, public)
    if group in ffdhe.SIZES:
        return ffdhe.exchange(private, group, public)
    if group in HYBRID_GROUPS:
        traditional, _, _, _, ciphertext_size, kem_first = HYBRID_GROUPS[group]
        if not isinstance(private, HybridPrivate) or private.group != group or len(public) != SERVER_GROUP_LENGTHS[group]:
            raise ProtocolError("invalid hybrid server share", alert=47)
        ciphertext = public[:ciphertext_size] if kem_first else public[-ciphertext_size:]
        traditional_share = public[ciphertext_size:] if kem_first else public[:-ciphertext_size]
        classical = traffic_dh(private.classical, traditional, traditional_share)
        try:
            shared = private.kem.decapsulate(ciphertext)
        except ValueError as exc:
            raise ProtocolError("hybrid decapsulation failed", alert=80) from exc
        return shared + classical if kem_first else classical + shared
    if group == 0x001d:
        return dh(private, public)
    if group == 30 and len(public) == 56 and isinstance(private, x448.X448PrivateKey):
        try:
            return private.exchange(x448.X448PublicKey.from_public_bytes(public))
        except ValueError as exc:
            raise ProtocolError("invalid X448 traffic share", alert=47) from exc
    if group in EC_GROUPS and len(public) == GROUP_LENGTHS[group] and public[0] == 4:
        try:
            peer = ec.EllipticCurvePublicKey.from_encoded_point(EC_GROUPS[group](), public)
            return private.exchange(ec.ECDH(), peer)
        except (ValueError, TypeError) as exc:
            raise ProtocolError("invalid elliptic-curve traffic share", alert=47) from exc
    raise ProtocolError("invalid traffic group or share", alert=47)


def traffic_server(group: int, client_share: bytes, provider=None) -> tuple[bytes, bytes]:
    """Produce a server share and IKM. KEM ciphertexts are not DH public keys."""
    if group not in HYBRID_GROUPS:
        private, public = traffic_key(group, provider)
        try:
            return public, traffic_dh(private, group, client_share, provider)
        finally:
            if 34 <= group <= 41:
                private.close()
    traditional, _, key_type, public_size, _, kem_first = HYBRID_GROUPS[group]
    if len(client_share) != GROUP_LENGTHS[group]:
        raise ProtocolError("invalid hybrid client share", alert=47)
    kem_public = client_share[:public_size] if kem_first else client_share[-public_size:]
    traditional_share = client_share[public_size:] if kem_first else client_share[:-public_size]
    private, public = traffic_key(traditional)
    classical = traffic_dh(private, traditional, traditional_share)
    try:
        # The provider performs FIPS 203 encapsulation-key validation, including
        # the encoded polynomial modulus check, before encapsulation.
        peer = key_type.from_public_bytes(kem_public)
        shared, ciphertext = peer.encapsulate()
    except ValueError as exc:
        raise ProtocolError("invalid ML-KEM encapsulation key", alert=47) from exc
    return ((ciphertext + public, shared + classical) if kem_first
            else (public + ciphertext, classical + shared))


def server_proof(auth_root: bytes, transcript: bytes, hash_name=None) -> bytes:
    name = secret_hash(auth_root, hash_name)
    thash = digest(transcript, name)
    return mac(label_expand(auth_root, "server mac", b"", len(auth_root), name), PROOF_CONTEXT + thash, name)


def derive_secret(secret: bytes, label: str, transcript: bytes, hash_name=None) -> bytes:
    name = secret_hash(secret, hash_name)
    return label_expand(secret, label, digest(transcript, name), len(secret), name)


def handshake_secret(shared: bytes, psk: bytes | None = None, hash_name="sha256") -> bytes:
    zeros = bytes(hash_length(hash_name))
    early = extract(zeros, zeros if psk is None else psk, hash_name)
    return extract(derive_secret(early, "derived", b"", hash_name), shared, hash_name)


def master_secret(handshake: bytes, hash_name=None) -> bytes:
    name = secret_hash(handshake, hash_name)
    return extract(derive_secret(handshake, "derived", b"", name), bytes(len(handshake)), name)


def authentication_root(handshake: bytes, shared: bytes, transcript: bytes, hash_name=None) -> bytes:
    name = secret_hash(handshake, hash_name)
    return extract(label_expand(handshake, "auth salt", digest(transcript, name), len(handshake), name), shared, name)


def binder(psk: bytes, truncated_transcript: bytes, *, hash_name=None, kind="res") -> bytes:
    name = secret_hash(psk, hash_name)
    if kind not in ("res", "ext", "imp"):
        raise ProtocolError("unknown PSK provenance")
    key = derive_secret(extract(bytes(hash_length(name)), psk, name), kind + " binder", b"", name)
    return finished(key, truncated_transcript, name)


def exporter(secret: bytes, label: str, context: bytes, length: int, hash_name=None) -> bytes:
    name = secret_hash(secret, hash_name)
    intermediate = derive_secret(secret, label, b"", name)
    return label_expand(intermediate, "exporter", digest(context, name), length, name)


def client_proof(exporter_secret: bytes, private: X25519PrivateKey, peer: bytes,
                 transcript: bytes, hash_name=None) -> bytes:
    name = secret_hash(exporter_secret, hash_name)
    thash = digest(transcript, name)
    salt = exporter(exporter_secret, "EXPORTER-TLS20-Client-Auth", thash, len(exporter_secret), name)
    root = extract(salt, dh(private, peer), name)
    key = label_expand(root, "client mac", b"", len(root), name)
    return mac(key, b" " * 64 + b"TLS 2.0, client CertificateVerify\x00" + thash, name)


def verify_proof(auth_root: bytes, transcript: bytes, proof: bytes, hash_name=None) -> bool:
    return len(proof) == len(auth_root) and hmac.compare_digest(server_proof(auth_root, transcript, hash_name), proof)


def finished(secret: bytes, transcript: bytes, hash_name=None) -> bytes:
    name = secret_hash(secret, hash_name)
    return mac(label_expand(secret, "finished", b"", len(secret), name), digest(transcript, name), name)


def verify_finished(secret: bytes, transcript: bytes, value: bytes, hash_name=None) -> bool:
    return len(value) == len(secret) and hmac.compare_digest(finished(secret, transcript, hash_name), value)


@dataclass(frozen=True)
class KeySchedule:
    """Explicit negotiated hash context; equal secret sizes are not algorithms."""

    hash_name: str | HashContext

    def __post_init__(self):
        secret_hash(b"", self.hash_name)

    def derive_secret(self, secret, label, transcript):
        return derive_secret(secret, label, transcript, self.hash_name)

    def master_secret(self, secret):
        return master_secret(secret, self.hash_name)

    def authentication_root(self, secret, shared, transcript):
        return authentication_root(secret, shared, transcript, self.hash_name)

    def server_proof(self, secret, transcript):
        return server_proof(secret, transcript, self.hash_name)

    def verify_proof(self, secret, transcript, proof):
        return verify_proof(secret, transcript, proof, self.hash_name)

    def client_proof(self, secret, private, peer, transcript):
        return client_proof(secret, private, peer, transcript, self.hash_name)

    def finished(self, secret, transcript):
        return finished(secret, transcript, self.hash_name)

    def verify_finished(self, secret, transcript, proof):
        return verify_finished(secret, transcript, proof, self.hash_name)

    def exporter(self, secret, label, context, length):
        return exporter(secret, label, context, length, self.hash_name)

    def label_expand(self, secret, label, context, length):
        return label_expand(secret, label, context, length, self.hash_name)


def key_iv(secret: bytes, cipher_suite=0x1301, provider=None) -> tuple[bytes, bytes]:
    selected = suite(cipher_suite)
    if len(secret) != selected.hash_length:
        raise ProtocolError("traffic secret hash mismatch")
    context = hash_context(selected.hash_name, provider)
    return (label_expand(secret, "key", b"", selected.key_length, context),
            label_expand(secret, "iv", b"", selected.iv_length, context))


def nonce(iv: bytes, sequence: int) -> bytes:
    if len(iv) not in (8, 12, 16, 32, 48) or not 0 <= sequence < 1 << 64:
        raise ProtocolError("invalid IV or sequence number")
    padded = bytes(len(iv) - 8) + sequence.to_bytes(8, "big")
    return bytes(left ^ right for left, right in zip(iv, padded))


def validate_inner(content: bytes, inner_type: int) -> None:
    if inner_type not in INNER_TYPES:
        raise ProtocolError("invalid inner type", alert=10)
    if inner_type == 22 and not content:
        raise ProtocolError("empty handshake record", alert=10)
    if inner_type == 21 and len(content) != 2:
        raise ProtocolError("alert content must have length 2", alert=10 if not content else 50)


class _RecordAuthenticationError(ProtocolError):
    """Only an unauthenticated ciphertext may be skipped by an epoch probe."""


@dataclass(repr=False)
class RecordState:
    """One direction and epoch; a failed operation permanently closes the state.

    The transport must enforce handshake/application ordering and close_notify.
    No state reset exists. Counter attributes are exposed for boundary tests.
    Python cannot guarantee erasure of immutable secret bytes or provider memory.
    """

    secret: bytes
    operation: str
    cipher_suite: int = 0x1301
    record_limit: int = 16385
    provider: object = None
    sequence: int = field(default=0, init=False)
    content_bytes: int = field(default=0, init=False)
    failed: bool = field(default=False, init=False)
    max_opened_plaintext: int = field(default=0, init=False)
    epoch: int = field(default=0, init=False)

    def __post_init__(self) -> None:
        try:
            if self.operation not in ("seal", "open"):
                raise ProtocolError("record operation must be seal or open")
            if type(self.record_limit) is not int or not 64 <= self.record_limit <= 16385:
                raise ProtocolError("invalid negotiated record size limit")
            self.suite = suite(self.cipher_suite)
            self.hash_context = hash_context(self.suite.hash_name, self.provider)
            self.key, self.iv = key_iv(self.secret, self.cipher_suite, self.provider)
            self._reset_cipher()
        except BaseException:
            # A failed constructor can remain reachable through its traceback.
            # Release any keys already derived without closing shared providers.
            self.close()
            raise

    def _reset_cipher(self):
        self._tree_cipher = self.suite.hash_name == "streebog256"
        self._cipher = (self.provider.record_cipher(self.cipher_suite, self.key) if self._tree_cipher
                        else self.suite.aead(self.key, self.provider))

    def close(self):
        """Release this direction's secrets and cipher, without closing a shared provider.

        Dropping Python references does not guarantee physical memory erasure.
        """
        self.failed = True
        self.secret = self.key = self.iv = b""
        self._cipher = self.provider = self.hash_context = None

    def _ready(self, operation: str, content_length: int) -> None:
        if self.failed:
            raise ProtocolError("record state is closed")
        if operation != self.operation:
            raise ProtocolError("record direction operation mismatch")
        # Our conservative automatic-rekey policy constrains only our writes.
        # A conforming peer may use a different (suite-safe) rekey policy.
        record_bound = min(MAX_RECORDS, 1 << 64) if operation == "seal" else 1 << 64
        if self._tree_cipher:
            from .gost_provider import SUITES
            record_bound = min(record_bound, SUITES[self.cipher_suite][2] + 1)
        if not 0 <= self.sequence < record_bound:
            raise ProtocolError("record count limit")
        if not 0 <= content_length <= MAX_CONTENT:
            raise ProtocolError("record content length limit", alert=22)
        if self.content_bytes < 0 or operation == "seal" and self.content_bytes > MAX_CONTENT_BYTES - content_length:
            raise ProtocolError("traffic key content-byte limit")

    def _advance(self, content_length: int) -> None:
        self.sequence += 1
        self.content_bytes += content_length

    def seal(self, content: bytes, inner_type: int, padding: int = 0) -> bytes:
        try:
            self._ready("seal", len(content))
            validate_inner(content, inner_type)
            if not isinstance(padding, int) or not 0 <= padding <= self.record_limit - len(content) - 1:
                raise ProtocolError("record padding length")
            plaintext = content + bytes((inner_type,)) + bytes(padding)
            header = b"\x17\x03\x03" + (len(plaintext) + self.suite.tag_length).to_bytes(2, "big")
            iv = nonce(self.iv, self.sequence)
            result = header + (self._cipher.encrypt_record(self.sequence,iv,plaintext,header) if self._tree_cipher
                               else self._cipher.encrypt(iv,plaintext,header))
            self._advance(len(content))
            return result
        except BaseException:
            self.close()
            raise

    def open(self, record: bytes) -> tuple[bytes, int]:
        try:
            if len(record) < 5:
                raise ProtocolError("truncated encrypted record header", alert=50)
            if record[0] != 23:
                raise ProtocolError("unexpected encrypted record type", alert=10)
            if record[1:3] != b"\x03\x03":
                raise ProtocolError("invalid encrypted record version", alert=47)
            ciphertext_length = int.from_bytes(record[3:5], "big")
            if ciphertext_length != len(record) - 5:
                raise ProtocolError("encrypted record length mismatch", alert=50)
            if ciphertext_length > 16640:
                raise ProtocolError("encrypted record size", alert=22)
            if ciphertext_length < self.suite.tag_length:
                raise _RecordAuthenticationError("record authentication failed", alert=20)
            self._ready("open", 0)
            iv = nonce(self.iv, self.sequence)
            plaintext = (self._cipher.decrypt_record(self.sequence,iv,record[5:],record[:5]) if self._tree_cipher
                         else self._cipher.decrypt(iv,record[5:],record[:5]))
            if len(plaintext) > self.record_limit:
                raise ProtocolError("padded plaintext exceeds record limit", alert=22)
            if not plaintext:
                raise ProtocolError("missing inner type", alert=10)
            stripped = plaintext.rstrip(b"\x00")
            if not stripped:
                raise ProtocolError("missing inner type", alert=10)
            content, inner_type = stripped[:-1], stripped[-1]
            self._ready("open", len(content))
            validate_inner(content, inner_type)
            self.max_opened_plaintext = max(self.max_opened_plaintext, len(plaintext))
            self._advance(len(content))
            return content, inner_type
        except BaseException as exc:
            self.close()
            if isinstance(exc, InvalidTag):
                raise _RecordAuthenticationError("record authentication failed", alert=20) from exc
            raise

    def try_open(self, record: bytes) -> tuple[bytes, int] | None:
        """Skip only failed authentication, never authenticated record errors."""
        if self.failed:
            raise ProtocolError("record state is closed")
        trial = None
        try:
            trial = RecordState(self.secret, self.operation, self.cipher_suite, self.record_limit, self.provider)
            trial.sequence, trial.content_bytes = self.sequence, self.content_bytes
            trial.epoch = self.epoch
            result = trial.open(record)
        except _RecordAuthenticationError:
            return None
        except BaseException:
            # Successful decryption commits the receive epoch even if its
            # plaintext is invalid. Framing/provider failures are terminal too.
            self.close()
            raise
        else:
            self.sequence, self.content_bytes = trial.sequence, trial.content_bytes
            self.max_opened_plaintext = max(self.max_opened_plaintext, trial.max_opened_plaintext)
            return result
        finally:
            if trial is not None:
                trial.close()

    def update(self) -> None:
        if self.failed:
            raise ProtocolError("record state is closed")
        # The RFC bound applies only to locally sent epochs. Receivers must
        # continue accepting conforming key updates beyond this policy bound.
        if self.operation == "seal" and self.epoch >= MAX_SEND_EPOCH:
            raise ProtocolError("sending key-update epoch exhausted", alert=80)
        try:
            self.secret = label_expand(self.secret, "traffic upd", b"", len(self.secret), self.hash_context)
            self.epoch += 1
            self.sequence = self.content_bytes = 0
            self.key, self.iv = key_iv(self.secret, self.cipher_suite, self.provider)
            self._reset_cipher()
        except BaseException:
            self.close()
            raise
