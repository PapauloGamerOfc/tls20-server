"""Explicit RFC 8672 continuity pins, isolated from TLS/session credentials.

Pinning is a second factor: neither a decoded ticket nor a correct proof
replaces current credential validation and the server MAC/Finished. Protection
keys must be provisioned, synchronized and backed up by the endpoint operator;
this module never silently generates short-lived keys for long-lived promises.
"""

from dataclasses import dataclass
import hmac
import os
import threading
import time

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand

from . import crypto as c
from .errors import ProtocolError
from .pki import validate_service_identity
from .credential_profiles import parse_x25519_spki


DOMAIN = b"TLS20 pinning ticket\x00"


def _service(name, port):
    validate_service_identity(name)
    if type(port) is not int or not 1 <= port <= 65535:
        raise ValueError("invalid pinning service port")
    encoded = name.lower().encode("ascii")
    return (name.lower(), port), len(encoded).to_bytes(2, "big") + encoded + port.to_bytes(2, "big")


def parse_client_extension(value):
    # An empty extension enrolls; subsequent extensions contain one V16 ticket.
    if not isinstance(value, bytes):
        raise ProtocolError("invalid pinning client extension", alert=50)
    if not value:
        return b""
    if len(value) < 2 or int.from_bytes(value[:2], "big") != len(value) - 2:
        raise ProtocolError("invalid pinning client ticket vector", alert=50)
    return value[2:]


def parse_server_extension(value):
    if not isinstance(value, bytes) or len(value) < 7:
        raise ProtocolError("invalid pinning server extension", alert=50)
    proof_size = value[0]
    offset = 1 + proof_size
    if offset + 6 > len(value):
        raise ProtocolError("truncated pinning proof", alert=50)
    size = int.from_bytes(value[offset:offset + 2], "big")
    if offset + 2 + size + 4 != len(value):
        raise ProtocolError("invalid pinning ticket vector", alert=50)
    proof, ticket = value[1:offset], value[offset + 2:offset + 2 + size]
    lifetime = int.from_bytes(value[-4:], "big")
    if not ticket and lifetime:
        raise ProtocolError("pinning lifetime requires a ticket", alert=47)
    return proof, ticket, lifetime


def pinning_secret(handshake_secret, transcript, hash_name=None):
    return c.derive_secret(handshake_secret, "pinning secret", transcript, hash_name)


def pinning_proof(original_secret, handshake_secret, transcript, effective_spki, hash_name=None):
    parse_x25519_spki(effective_spki)
    # The original secret may use a different hash length: HMAC here uses the
    # CURRENT exchange hash, not a hash inferred from the old HMAC key length.
    hash_name = hash_name or c.secret_hash(handshake_secret)
    proof_secret = c.derive_secret(handshake_secret, "pinning proof 1", transcript, hash_name)
    return c.mac(original_secret, b"pinning proof 2" + proof_secret
                 + c.digest(effective_spki, hash_name), hash_name)


class ServerPinning:
    """Stateless AEAD tickets with explicit, independently managed key IDs.

    ``keys`` maps 16-byte public IDs to 32-byte secret protection master keys.
    Keep every old key for every promised lifetime plus clock skew; instantiate
    a replacement policy containing both old and new keys to rotate. ``ramp_down``
    proves existing tickets but issues none. It is not abrupt removal of keys.
    Per-ticket 256-bit entropy derives a separate AES key AND nonce, following
    RFC 8672 section 6.8's nonce-domain alternative for clustered deployments.
    """

    def __init__(self, keys, current_id, *, lifetime=14 * 86400, ramp_down=False,
                 clock=time.time, clock_skew=300):
        if (type(lifetime) is not int or not 0 <= lifetime < 1 << 32
                or type(clock_skew) is not int or clock_skew < 0):
            raise ValueError("invalid pinning lifetime")
        keys = dict(keys)
        if (not keys or current_id not in keys or len(keys) > 256
                or any(type(k) is not bytes or len(k) != 16
                       or type(v) is not bytes or len(v) != 32 for k, v in keys.items())):
            raise ValueError("pinning requires explicit 16-byte IDs and 32-byte protection keys")
        self._keys, self.current_id = keys, current_id
        self.lifetime, self.ramp_down = lifetime, bool(ramp_down)
        self.clock, self.clock_skew = clock, clock_skew

    @staticmethod
    def _aead(master, random):
        key = HKDFExpand(algorithm=hashes.SHA256(), length=32,
                         info=DOMAIN + random + b"key").derive(master)
        nonce = HKDFExpand(algorithm=hashes.SHA256(), length=12,
                           info=DOMAIN + random + b"nonce").derive(master)
        return AESGCM(key), nonce

    def _seal(self, secret, scope):
        random = os.urandom(32)
        header = b"\x01" + self.current_id + random
        cipher, nonce = self._aead(self._keys[self.current_id], random)
        expiry = int(self.clock()) + self.lifetime + self.clock_skew
        plaintext = expiry.to_bytes(8, "big") + bytes((len(secret),)) + secret
        return header + cipher.encrypt(nonce, plaintext, DOMAIN + scope + header)

    def _open(self, ticket, scope):
        try:
            if len(ticket) not in (106, 122) or ticket[0] != 1:
                raise ValueError("pin ticket format")
            header, identity, random = ticket[:49], ticket[1:17], ticket[17:49]
            master = self._keys.get(identity)
            if master is None:
                raise ValueError("pin protection key unavailable")
            cipher, nonce = self._aead(master, random)
            plaintext = cipher.decrypt(nonce, ticket[49:], DOMAIN + scope + header)
            expiry, size = int.from_bytes(plaintext[:8], "big"), plaintext[8]
            if size not in (32, 48) or len(plaintext) != 9 + size or self.clock() >= expiry:
                raise ValueError("expired or malformed pin")
            return plaintext[9:]
        except (InvalidTag, ValueError, IndexError) as exc:
            raise ProtocolError("pinning ticket could not be authenticated", alert=40) from exc

    def respond(self, client_extension, service, port, handshake_secret,
                transcript_through_sh, effective_spki, *, hash_name=None):
        _, scope = _service(service, port)
        parse_x25519_spki(effective_spki)
        original = parse_client_extension(client_extension)
        proof = (pinning_proof(self._open(original, scope), handshake_secret,
                              transcript_through_sh, effective_spki, hash_name) if original else b"")
        ticket = (b"" if self.ramp_down else self._seal(
            pinning_secret(handshake_secret, transcript_through_sh, hash_name), scope))
        lifetime = 0 if self.ramp_down else self.lifetime
        return bytes((len(proof),)) + proof + len(ticket).to_bytes(2, "big") + ticket + lifetime.to_bytes(4, "big")


@dataclass(frozen=True, repr=False)
class _Pin:
    ticket: bytes
    secret: bytes
    expires: float


class PinningCache:
    """Explicit per-profile pin store; no unexpired-pin eviction or retry bypass.

    Retain the instance between connections. Persistence belongs to the host
    application, and must preserve scope and expiry; this class does not claim
    durable browser pin storage. ``forget`` is an explicit trusted recovery or
    user opt-out action, never called on verification failure or cache pressure.
    """

    def __init__(self, *, capacity=4096, clock=time.monotonic):
        if type(capacity) is not int or capacity < 1:
            raise ValueError("invalid pin cache capacity")
        self.capacity, self.clock = capacity, clock
        self._pins, self._lock = {}, threading.Lock()

    def begin(self, service, port=343):
        key, _ = _service(service, port)
        with self._lock:
            previous = self._pins.get(key)
            if previous is not None and self.clock() >= previous.expires:
                del self._pins[key]
                previous = None
        return PinAttempt(self, key, previous)

    def forget(self, service, port=343, *, trusted_recovery=False):
        if trusted_recovery is not True:
            raise ValueError("removing a continuity pin requires explicit trusted recovery")
        key, _ = _service(service, port)
        with self._lock:
            self._pins.pop(key, None)

    def _commit(self, key, previous, replacement):
        with self._lock:
            # A parallel connection may already have completed a newer exchange.
            # Never let its outstanding pin disappear because an older attempt
            # completed ramp-down or enrollment later.
            if self._pins.get(key) is not previous:
                return
            if replacement is None:
                self._pins.pop(key, None)
                return
            if key not in self._pins and len(self._pins) >= self.capacity:
                for old_key, value in tuple(self._pins.items()):
                    if self.clock() >= value.expires:
                        del self._pins[old_key]
                if len(self._pins) >= self.capacity:
                    raise ProtocolError("local pin cache capacity exhausted; existing pins retained")
            self._pins[key] = replacement


@dataclass(repr=False)
class PinAttempt:
    cache: PinningCache
    key: tuple
    previous: _Pin | None
    completed: bool = False
    _used: bool = False
    _verified: bool = False
    _replacement: _Pin | None = None
    _peer_supported: bool = False

    @property
    def extension(self):
        ticket = self.previous.ticket if self.previous else b""
        return len(ticket).to_bytes(2, "big") + ticket if ticket else b""

    def verify(self, server_extension, handshake_secret, transcript_through_sh,
               effective_spki, *, authenticated=False, hash_name=None):
        """Check after server MAC/Finished, before sending client credentials.

        Verification stages no cache mutation. The handshake calls ``commit``
        only after sending its own Finished successfully; aborted attempts keep
        the original pin. Repeated verification on one attempt is prohibited.
        """
        if self.completed or self._used or authenticated is not True:
            raise ProtocolError("pinning completion requires a fresh authenticated handshake")
        self._used = True
        if server_extension is None:
            if self.previous is not None:
                raise ProtocolError("required server continuity proof is missing", alert=40)
            self._verified = True
            return False  # An unpinned server may simply not support enrollment.
        proof, ticket, lifetime = parse_server_extension(server_extension)
        if self.previous is None:
            if proof:
                raise ProtocolError("unsolicited pinning proof", alert=40)
        else:
            expected = pinning_proof(self.previous.secret, handshake_secret,
                                    transcript_through_sh, effective_spki, hash_name)
            if not hmac.compare_digest(proof, expected):
                raise ProtocolError("server continuity proof failed", alert=40)
        # A proof-authenticated empty response performs ramp-down. Lifetime zero
        # is an authenticated replacement that expires immediately, not a way
        # for an absent/invalid response to remove the outstanding original pin.
        self._replacement = (_Pin(ticket, pinning_secret(handshake_secret, transcript_through_sh, hash_name),
                                  self.cache.clock() + lifetime) if ticket and lifetime else None)
        self._verified, self._peer_supported = True, True
        return bool(ticket and lifetime)

    def commit(self):
        if self.completed or not self._verified:
            raise ProtocolError("pinning was not verified or was already committed")
        self.completed = True
        if self._peer_supported:
            self.cache._commit(self.key, self.previous, self._replacement)
        return self._replacement is not None

    def complete(self, server_extension, handshake_secret, transcript_through_sh,
                 effective_spki, *, authenticated=False, hash_name=None):
        self.verify(server_extension, handshake_secret, transcript_through_sh,
                    effective_spki, authenticated=authenticated, hash_name=hash_name)
        return self.commit()
