"""Explicit password account provisioning and bounded online-guess policy.

Passwords/bases are credentials, never high-entropy PSKs. Store bases with the
same protection as passwords. Immutable Python caller buffers cannot be erased.
This endpoint policy requires PWD (or its authorized successor ticket); it never
falls back to an ordinary certificate or external-PSK account.
"""

from collections import OrderedDict, deque
from dataclasses import dataclass, field
import hashlib
import hmac
import os
import threading
import time
from types import MappingProxyType

from precis_i18n import get_profile
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESSIV
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from . import messages as m
from .errors import ConfigurationError, ProtocolError
from .pake_native import PakeProvider

SUITES = (0xc0b0, 0xc0b1, 0xc0b2, 0xc0b3)
RESUMPTION_SUITES = {0xc0b0: 0x1301, 0xc0b1: 0x1302, 0xc0b2: 0x1304, 0xc0b3: 0x1302}


def opaque(value):
    if not isinstance(value, str):
        raise ConfigurationError("password account strings must be Unicode text")
    try:
        return get_profile("OpaqueString").enforce(value).encode("utf-8")
    except UnicodeError as error:
        raise ConfigurationError("invalid RFC8265 OpaqueString") from error


def password_base(username, password, salt=None):
    username, password = opaque(username), opaque(password)
    if not 1 <= len(username) <= 255 or not password:
        raise ConfigurationError("password account name/password bounds")
    if salt is not None and (not isinstance(salt, bytes) or len(salt) != 32):
        raise ConfigurationError("password salt must be 32 random octets")
    return (hashlib.sha256(username + password).digest() if salt is None
            else hmac.digest(salt, username + password, "sha256"))


def _protection_parameters(key):
    if not isinstance(key, (ec.EllipticCurvePublicKey, ec.EllipticCurvePrivateKey)):
        raise ConfigurationError("username protection requires a separately provisioned EC key")
    if not isinstance(key.curve, (ec.SECP256R1, ec.SECP384R1, ec.SECP521R1)):
        raise ConfigurationError("unsupported username protection group")
    width = (key.curve.key_size + 7) // 8
    algorithm, size = (hashes.SHA256(), 32) if width <= 32 else (hashes.SHA384(), 48) if width <= 48 else (hashes.SHA512(), 64)
    return width, algorithm, size


def protect_username(username, public_key):
    if not isinstance(public_key, ec.EllipticCurvePublicKey):
        raise ConfigurationError("provisioned username protection public key required")
    value = opaque(username)
    width, algorithm, size = _protection_parameters(public_key)
    # Library native ECDH and AES-SIV; no private scalar arithmetic in Python.
    private = ec.generate_private_key(public_key.curve)
    secret = private.exchange(ec.ECDH(), public_key)
    key = HKDF(algorithm, size, None, b"").derive(secret)
    encoded = private.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.CompressedPoint)[1:]
    result = encoded + AESSIV(key).encrypt(value + bytes(max(0, 128-len(value))), [])
    if len(result) > 255:
        raise ConfigurationError("protected username does not fit the RFC8492 vector")
    return result


def recover_username(value, private_key):
    if not isinstance(private_key, ec.EllipticCurvePrivateKey):
        raise ConfigurationError("provisioned username protection private key required")
    width, algorithm, size = _protection_parameters(private_key)
    if not isinstance(value, bytes) or not width + 17 <= len(value) <= 255:
        raise ProtocolError("invalid protected password identity")
    try:
        public = ec.EllipticCurvePublicKey.from_encoded_point(private_key.curve, b"\x02" + value[:width])
        secret = private_key.exchange(ec.ECDH(), public)
        key = HKDF(algorithm, size, None, b"").derive(secret)
        username = AESSIV(key).decrypt(value[width:], []).rstrip(b"\x00")
        text = username.decode("utf-8")
        if opaque(text) != username:
            raise ValueError("noncanonical username")
        return username
    except (ValueError, UnicodeError, InvalidTag) as error:
        raise ProtocolError("invalid protected password identity") from error


@dataclass(frozen=True, repr=False)
class PasswordCredential:
    service: str
    username: str
    password: str
    provider: PakeProvider
    protection_key: object = None

    def __post_init__(self):
        m.validate_service_identity(self.service)
        password_base(self.username, self.password)
        if not isinstance(self.provider, PakeProvider) or self.provider.test_only:
            raise ConfigurationError("operational PAKE requires the production native helper")
        if self.protection_key is not None:
            if not isinstance(self.protection_key, ec.EllipticCurvePublicKey):
                raise ConfigurationError("client requires a username protection public key")
            _protection_parameters(self.protection_key)

    @property
    def identity(self):
        return opaque(self.username)

    def context(self):
        return hashlib.sha256(b"TLS20 PWD client\x00" + self.service.encode("ascii") + b"\x00"
            + self.identity + password_base(self.username, self.password)
            + (self.protection_key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
               if self.protection_key is not None else b"")).digest()

    def name_extension(self):
        return ((30, m._vec(self.identity, 1)) if self.protection_key is None else
                (29, m._vec(protect_username(self.username, self.protection_key), 1)))


@dataclass(frozen=True, repr=False)
class PasswordAccount:
    username: bytes
    base: bytes
    salt: bytes | None = None
    permissions: bytes = b""

    def __post_init__(self):
        if (not isinstance(self.username, bytes) or not 1 <= len(self.username) <= 255
                or opaque(self.username.decode("utf-8")) != self.username or len(self.base) != 32
                or self.salt is not None and len(self.salt) != 32 or not isinstance(self.permissions, bytes)):
            raise ConfigurationError("invalid explicit password account record")

    @classmethod
    def provision(cls, username, password, *, salted=True, permissions=b""):
        salt = os.urandom(32) if salted else None
        return cls(opaque(username), password_base(username, password, salt), salt, permissions)


class PasswordServer:
    def __init__(self, service, provider, accounts, *, protection_key=None,
                 max_attempts=5, window=60, global_attempts=100, capacity=4096, max_active=4):
        m.validate_service_identity(service)
        if not isinstance(provider, PakeProvider) or provider.test_only:
            raise ConfigurationError("operational PAKE requires the production native helper")
        if any(type(value) is not int or value <= 0 for value in (max_attempts, window, global_attempts, capacity, max_active)):
            raise ConfigurationError("positive explicit PAKE rate/resource policy required")
        records = tuple(accounts)
        if not records or any(not isinstance(record, PasswordAccount) for record in records):
            raise ConfigurationError("explicit password account database required")
        if len({record.username for record in records}) != len(records):
            raise ConfigurationError("duplicate password account")
        # Consistent salting/HRR policy avoids an account-existence oracle.
        if len({record.salt is not None for record in records}) != 1:
            raise ConfigurationError("all endpoint accounts must use the same salting policy")
        if protection_key is not None:
            if not isinstance(protection_key, ec.EllipticCurvePrivateKey):
                raise ConfigurationError("server requires a username protection private key")
            _protection_parameters(protection_key)
        self.service, self.provider, self.protection_key = service, provider, protection_key
        self.accounts = MappingProxyType({record.username: record for record in records})
        self.salted = records[0].salt is not None
        self.max_attempts, self.window, self.global_attempts = max_attempts, window, global_attempts
        self.capacity, self.max_active = capacity, max_active
        self._secret, self._policy = os.urandom(32), os.urandom(32)
        self._attempts, self._global, self._revoked = OrderedDict(), deque(), set()
        self._lock, self._active = threading.Lock(), 0

    def context(self, protocol):
        return hashlib.sha256(b"TLS20 PWD server\x00" + self._policy + protocol).digest()

    def revoke(self, username):
        with self._lock:
            self._revoked.add(opaque(username))

    def authorized(self, username):
        with self._lock:
            return username in self.accounts and username not in self._revoked

    def acquire(self, ext):
        selected = next((number for number in (29, 30) if number in ext), None)
        if selected is None:
            raise ProtocolError("PWD account identity missing")
        reader = m._Reader(ext[selected]); value = reader.vector(1); reader.end()
        try:
            if selected == 29:
                if self.protection_key is None:
                    raise ProtocolError("protected account unavailable")
                identity = recover_username(value, self.protection_key)
            else:
                identity = opaque(value.decode("utf-8"))
                if identity != value:
                    raise ProtocolError("noncanonical account")
        except (ProtocolError, ConfigurationError, UnicodeError, ValueError):
            identity = b"\x00" + hashlib.sha256(value).digest()
        with self._lock:
            now = time.monotonic()
            while self._global and self._global[0] <= now-self.window:
                self._global.popleft()
            key = hmac.digest(self._secret, identity, "sha256")
            attempts = self._attempts.pop(key, deque())
            while attempts and attempts[0] <= now-self.window:
                attempts.popleft()
            while len(self._attempts) >= self.capacity:
                self._attempts.popitem(last=False)
            if self._active >= self.max_active or len(self._global) >= self.global_attempts or len(attempts) >= self.max_attempts:
                self._attempts[key] = attempts
                raise ProtocolError("password authentication temporarily unavailable")
            attempts.append(now);self._global.append(now);self._attempts[key]=attempts;self._active+=1
            record = self.accounts.get(identity)
            permitted = record is not None and identity not in self._revoked
        if record is None:
            # Unknown accounts do equivalent PAKE work with a secret fake base,
            # not an early username-specific error or public deterministic key.
            record = PasswordAccount(b"unknown", hmac.digest(self._secret, b"base"+identity, "sha256"),
                hmac.digest(self._secret, b"salt"+identity, "sha256") if self.salted else None)
        return identity, record, permitted

    def release(self):
        with self._lock:
            self._active -= 1
