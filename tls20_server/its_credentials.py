"""Explicit offline IEEE 1609.2 ITS-X25519 grant profile.

The native provider verifies COER, signatures, path and permission constraints;
the normal TLS20 handshake must still verify the X25519 MAC and Finished.
Neither an ITS pseudonym nor successful parsing implies a Web PKI identity.
"""
from __future__ import annotations

import ctypes
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import os
from pathlib import Path
import time

from .errors import ProtocolError

ITS_EPOCH_UNIX_SECONDS = 1072915200
MAX_INPUT = 262144


def _vector(value, width):
    if not isinstance(value, bytes) or len(value) >= 1 << (8 * width):
        raise ProtocolError("ITS policy vector exceeds bounds")
    return len(value).to_bytes(width, "big") + value


def _uint(value, width):
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value < 1 << (8 * width):
        raise ProtocolError("invalid ITS policy integer")
    return value.to_bytes(width, "big")


class ITSProvider:
    """Load one explicitly selected, permissively licensed native validator."""
    def __init__(self, library_path):
        path = Path(library_path)
        if not path.is_absolute() or not path.is_file():
            raise ProtocolError("ITS provider requires an explicit absolute library path")
        try:
            self._lib = ctypes.CDLL(str(path), winmode=0x00001100) if os.name == "nt" else ctypes.CDLL(str(path))
            version = self._lib.tls20_its_abi_version
            version.argtypes = []
            version.restype = ctypes.c_uint32
            if version() != 1:
                raise ProtocolError("unsupported ITS provider ABI")
            self._authorize = self._lib.tls20_its_authorize
            self._authorize.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p,
                                       ctypes.c_size_t, ctypes.c_void_p, ctypes.c_size_t]
            self._authorize.restype = ctypes.c_int
        except (AttributeError, OSError) as exc:
            raise ProtocolError("cannot load the explicit ITS provider") from exc
        self.library_path = str(path.resolve())

    def authorize(self, grant, policy):
        if (not isinstance(grant, bytes) or not isinstance(policy, bytes)
                or not grant or not policy or len(grant) > MAX_INPUT or len(policy) > MAX_INPUT):
            raise ProtocolError("ITS material exceeds provider budget")
        output = ctypes.create_string_buffer(72)
        if self._authorize(grant, len(grant), policy, len(policy), output, 72) != 1:
            raise ProtocolError("ITS credential signature, trust or application authorization failed")
        value = output.raw
        return value[:32], int.from_bytes(value[32:40], "big"), value[40:]


@dataclass(frozen=True)
class ITSServicePolicy:
    """Provisioned policy for exactly one service, role and PSID owner's grant.

    Revocation inventory must come from an authenticated local provisioning
    process and be refreshed before inventory_valid_until (IEEE Time64). This
    provider does not download or pretend to parse signed ITS CRLs. The explicit
    tai_utc_offset must be maintained by the deployment's trusted time source.
    SSP is exact canonical COER ServiceSpecificPermissions, or empty for absent.
    """
    provider: ITSProvider
    identity: str
    role: str
    psid: int
    application_scope: bytes
    ssp_coer: bytes
    trust_roots: tuple[bytes, ...]
    authorized_leaf_sha256: tuple[bytes, ...]
    revoked_sha256: tuple[bytes, ...]
    inventory_valid_until: int
    max_grant_lifetime_microseconds: int
    tai_utc_offset: int
    allowed_regions_coer: tuple[bytes, ...] = ()

    def policy_bytes(self, *, now=None):
        if (not isinstance(self.provider, ITSProvider) or not isinstance(self.identity, str)
                or not self.identity or len(self.identity) > 4096 or self.role not in ("server", "client")
                or type(self.tai_utc_offset) is not int or not 0 <= self.tai_utc_offset <= 100
                or not 1 <= len(self.trust_roots) <= 32
                or not 1 <= len(self.authorized_leaf_sha256) <= 1024
                or len(self.revoked_sha256) > 4096 or len(self.allowed_regions_coer) > 32):
            raise ProtocolError("invalid or absent ITS service policy")
        if now is not None:
            if not isinstance(now, datetime) or now.tzinfo is None:
                raise ProtocolError("ITS validation time must be timezone aware")
            unix_ns = int(now.timestamp() * 1_000_000_000)
        else:
            unix_ns = time.time_ns()
        time64 = unix_ns // 1000 + (self.tai_utc_offset - ITS_EPOCH_UNIX_SECONDS) * 1_000_000
        roots = b"".join(_vector(root, 3) for root in self.trust_roots)
        if any(not root or len(root) > 16384 for root in self.trust_roots):
            raise ProtocolError("invalid ITS trust anchor size")
        for hashes in (self.authorized_leaf_sha256, self.revoked_sha256):
            if any(not isinstance(value, bytes) or len(value) != 32 for value in hashes):
                raise ProtocolError("ITS inventory uses exact SHA256 fingerprints")
        value = (b"ITS1" + _uint(time64, 8) + _uint(self.inventory_valid_until, 8)
            + _uint(self.max_grant_lifetime_microseconds, 8)
            + bytes([0 if self.role == "server" else 1]) + _uint(self.psid, 8)
            + _vector(self.application_scope, 2) + _vector(self.ssp_coer, 2)
            + _vector(roots, 3) + _vector(b"".join(self.authorized_leaf_sha256), 3)
            + _vector(b"".join(self.revoked_sha256), 3)
            + _vector(b"".join(_vector(region, 3) for region in self.allowed_regions_coer), 3))
        if len(value) > MAX_INPUT:
            raise ProtocolError("ITS policy exceeds provider budget")
        return value

    def context(self):
        # Time-independent binding for tickets. A frozen policy and a fresh
        # inventory are revalidated on every resolution, including resumption.
        # Keep vector CATEGORY boundaries: moving a fingerprint from the allow
        # inventory to the revoked inventory MUST change this context.
        epoch = datetime.fromtimestamp(ITS_EPOCH_UNIX_SECONDS - self.tai_utc_offset, timezone.utc)
        h = hashlib.sha256(b"TLS20 ITS service policy\x00")
        for value in (self.identity.encode("utf8"), self.provider.library_path.encode("utf8"),
                      _uint(self.tai_utc_offset, 1), self.policy_bytes(now=epoch)):
            h.update(_vector(value, 3))
        return h.digest()

    def authorize(self, grant, *, role, identity, now=None):
        if role != self.role or identity != self.identity:
            raise ProtocolError("ITS policy is not provisioned for this service and role")
        key, expiry, leaf_hash = self.provider.authorize(grant, self.policy_bytes(now=now))
        from .credential_profiles import parse_x25519_spki, X25519_SPKI_PREFIX
        key = parse_x25519_spki(X25519_SPKI_PREFIX + key)
        expiry_utc = datetime.fromtimestamp(
            expiry / 1_000_000 + ITS_EPOCH_UNIX_SECONDS - self.tai_utc_offset, timezone.utc)
        return key, expiry_utc, leaf_hash
