"""Explicitly provisioned, origin-scoped external PSKs and RFC 9258 import.

The parser never turns an untrusted identity into a secret or authorization.
Applications provision these objects out of band. Their repr omits key material.
"""

from dataclasses import dataclass, field
import hashlib

from . import crypto as c, messages as m
from .errors import ProtocolError


@dataclass(frozen=True, repr=False)
class ExternalPSK:
    identity: bytes
    psk: bytes
    name: str
    protocol: bytes = b"http/1.1"
    hash_name: str = "sha256"
    binder_kind: str = "ext"
    combined: bool = False
    cipher_suite: int = 0x1301
    max_early_data: int = 0
    certificate_chain: tuple = field(default_factory=tuple)
    client_certificate_chain: tuple = field(default_factory=tuple)
    record_size_limit: int = 16385

    def __post_init__(self):
        m.validate_service_identity(self.name)
        if self.protocol:
            m._protocol(self.protocol)
        if (not isinstance(self.identity, bytes) or not 1 <= len(self.identity) <= 65535
                or not isinstance(self.psk, bytes) or not self.psk
                or self.hash_name not in ("sha256", "sha384", "sm3", "streebog256")
                or self.binder_kind not in ("ext", "imp")
                or c.suite(self.cipher_suite).hash_name != self.hash_name
                or type(self.max_early_data) is not int or not 0 <= self.max_early_data < 1 << 32
                or type(self.record_size_limit) is not int or not 64 <= self.record_size_limit <= 16385
                or self.combined and self.max_early_data):
            raise ValueError("invalid external PSK provisioning")

    def obfuscated_age(self):
        return 0  # External identities have no resumption-ticket age.

    @property
    def hash_length(self):
        return c.hash_length(self.hash_name)

    def policy_digest(self):
        fields = (self.identity, self.name.encode("ascii"), self.protocol,
                  self.hash_name.encode("ascii"), self.binder_kind.encode("ascii"),
                  bytes((self.combined,)), self.cipher_suite.to_bytes(2, "big"),
                  self.max_early_data.to_bytes(4, "big"), self.record_size_limit.to_bytes(2, "big"), c.digest(self.psk))
        return c.digest(b"TLS20 provisioned PSK\x00" + b"".join(
            len(value).to_bytes(4, "big") + value for value in fields))


def import_psk(base_key: bytes, external_identity: bytes, context: bytes, name: str, *,
               protocol=b"http/1.1", base_hash="sha256", target_hash="sha256",
               combined=False, cipher_suite=None, max_early_data=0):
    """RFC 9258 importer, using TLS20's label namespace and protocol 0x0400.

    The caller must dedicate base_key to this importer, bind deployment/roles in
    context and never provision the base key itself as an ordinary TLS PSK.
    """
    if not base_key or not external_identity or base_hash not in ("sha256", "sha384"):
        raise ProtocolError("invalid importer base key or identity")
    target = {"sha256": 1, "sha384": 2}.get(target_hash)
    if target is None:
        raise ProtocolError("unsupported importer target KDF")
    identity = (m._vec(external_identity, 2) + m._vec(context, 2)
                + m.VERSION + target.to_bytes(2, "big"))
    root = c.extract(bytes(hashlib.new(base_hash).digest_size), base_key, base_hash)
    derived = c.label_expand(root, "derived psk", c.digest(identity, base_hash),
                             hashlib.new(target_hash).digest_size, base_hash)
    return ExternalPSK(identity, derived, name, protocol, target_hash, "imp", combined,
                       cipher_suite or (0x1302 if target_hash == "sha384" else 0x1301), max_early_data)


def bootstrap_public_key_psk(public_key: bytes, name: str, *, target_hash="sha256",
                             protocol=b"http/1.1", cipher_suite=None):
    """Derive TLS20-POK's public bootstrap PSK; NOT sufficient authentication.

    Only the POK-specific combined exchange plus exact RPK and client MAC can
    authorize a peer. This result is therefore marked combined, never ordinary.
    """
    if len(public_key) != 32:
        raise ProtocolError("POK bootstrap key must be X25519")
    bsk = bytes.fromhex("302a300506032b656e032100") + public_key
    root = c.extract(bytes(32), bsk, "sha256")
    identity = c.expand(root, b"tls20-bspsk-identity", 32, "sha256")
    return import_psk(bsk, identity, b"tls20-bsk", name, protocol=protocol,
                      target_hash=target_hash, combined=True, cipher_suite=cipher_suite)
