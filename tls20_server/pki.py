"""Strict, deliberately restricted certificate validation for offline lab PKI.

This is not a general RFC 5280 path builder. Only an explicitly ordered path,
Ed25519 or P-256/SHA-256 signatures, and simple DNS identities are supported.
Constraint/policy features outside this subset fail closed, even if noncritical.
No certificate-provided URL is fetched. Revocation is explicitly lab-offline.
"""

from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass
from datetime import datetime, timezone
import ipaddress
import os
from pathlib import Path
import re
import stat

from cryptography import x509
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, utils, x25519
from cryptography.x509.oid import ExtendedKeyUsageOID, ExtensionOID

from .errors import ConfigurationError, ProtocolError


MAX_CERT = 65536
MAX_CHAIN_BODY = 262144
MAX_PEM_FILE = 2 * 1024 * 1024
_PEM = re.compile(rb"-----BEGIN CERTIFICATE-----\s*([A-Za-z0-9+/=\r\n\t ]+)\s*-----END CERTIFICATE-----")
_KEY_PEM = re.compile(rb"\s*-----BEGIN PRIVATE KEY-----\s*([A-Za-z0-9+/=\r\n\t ]+)\s*-----END PRIVATE KEY-----\s*")
_SUPPORTED_EXTENSIONS = {
    ExtensionOID.BASIC_CONSTRAINTS, ExtensionOID.KEY_USAGE,
    ExtensionOID.EXTENDED_KEY_USAGE, ExtensionOID.SUBJECT_ALTERNATIVE_NAME,
    ExtensionOID.SUBJECT_KEY_IDENTIFIER, ExtensionOID.AUTHORITY_KEY_IDENTIFIER,
}
_UNSUPPORTED_POLICY = {
    ExtensionOID.NAME_CONSTRAINTS, ExtensionOID.CERTIFICATE_POLICIES,
    ExtensionOID.POLICY_CONSTRAINTS, ExtensionOID.INHIBIT_ANY_POLICY,
    x509.ObjectIdentifier("2.5.29.33"),  # policyMappings
}
_ED25519_ALGORITHM = bytes.fromhex("300506032b6570")
_P256_SHA256_ALGORITHM = bytes.fromhex("300a06082a8648ce3d040302")
# Several documented x509 parse failures inherit directly from Exception rather
# than ValueError. Normalize them at the public trust boundary, including when
# parsing is deferred until accessing a certificate's extensions or names.
_CERTIFICATE_ERRORS = (
    ValueError, TypeError, UnsupportedAlgorithm, x509.InvalidVersion,
    x509.DuplicateExtension, x509.UnsupportedGeneralNameType,
)


@dataclass(frozen=True)
class Credentials:
    chain_der: list[bytes]
    private_key: x25519.X25519PrivateKey


def validate_server_name(name: str) -> str:
    """Accept already-normalized draft-01 DNS A-labels, not IP literals."""
    if not isinstance(name, str) or name != name.lower():
        raise ProtocolError("server name must be lowercase ASCII DNS")
    try:
        encoded = name.encode("ascii")
    except UnicodeError as exc:
        raise ProtocolError("server name must use ASCII DNS A-labels") from exc
    if not 1 <= len(encoded) <= 253:
        raise ProtocolError("invalid DNS name length")
    for part in name.split("."):
        if not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", part):
            raise ProtocolError("invalid DNS label")
        if part.startswith("xn--"):
            try:
                if part.encode("ascii").decode("idna").encode("idna").decode("ascii") != part:
                    raise UnicodeError("noncanonical A-label")
            except UnicodeError as exc:
                raise ProtocolError("invalid DNS A-label") from exc
    try:
        ipaddress.ip_address(name)
    except ValueError:
        return name
    raise ProtocolError("IP-literal identities are outside draft-01")


def _element(data: bytes, offset: int = 0) -> tuple[int, bytes, int, bytes]:
    """Read one bounded minimal-length DER TLV; cryptography parses its value."""
    start = offset
    if offset + 2 > len(data):
        raise ProtocolError("truncated certificate DER")
    tag = data[offset]
    length = data[offset + 1]
    offset += 2
    if length & 128:
        count = length & 127
        if count == 0 or count > 4 or offset + count > len(data) or data[offset] == 0:
            raise ProtocolError("invalid DER length")
        length = int.from_bytes(data[offset:offset + count], "big")
        offset += count
        if length < 128:
            raise ProtocolError("nonminimal DER length")
    end = offset + length
    if end > len(data):
        raise ProtocolError("truncated certificate DER")
    return tag, data[offset:end], end, data[start:end]


def _children(data: bytes) -> list[tuple[int, bytes, bytes]]:
    result = []
    pos = 0
    while pos < len(data):
        tag, body, pos, raw = _element(data, pos)
        result.append((tag, body, raw))
    return result


def _encoding(cert: x509.Certificate) -> tuple[bytes, bytes]:
    """Return exact SPKI and signature AlgorithmIdentifier, enforcing consistency."""
    der = cert.public_bytes(serialization.Encoding.DER)
    tag, body, end, _ = _element(der)
    if tag != 0x30 or end != len(der):
        raise ProtocolError("invalid certificate envelope")
    outer = _children(body)
    if len(outer) != 3 or [entry[0] for entry in outer] != [0x30, 0x30, 0x03]:
        raise ProtocolError("invalid certificate structure")
    tbs = _children(outer[0][1])
    if len(tbs) < 7 or tbs[0][2] != b"\xa0\x03\x02\x01\x02":
        raise ProtocolError("X.509 v3 certificate required")
    if tbs[2][2] != outer[1][2]:
        raise ProtocolError("certificate signature algorithms differ")
    # Signatures in this profile are octet strings carried by ASN.1 BIT STRING.
    # Some parsers accept a nonzero unused-bit count while returning unchanged
    # signature octets when those trailing bits happen to be zero. That byte is
    # outside TBSCertificate, so signature verification alone cannot reject it.
    signature_bits = outer[2][1]
    if len(signature_bits) < 2 or signature_bits[0] != 0:
        raise ProtocolError("certificate signature BIT STRING must be octet-aligned")
    signature = signature_bits[1:]
    algorithm = outer[1][2]
    if algorithm == _ED25519_ALGORITHM and len(signature) != 64:
        raise ProtocolError("Ed25519 certificate signature must be 64 bytes")
    if algorithm == _P256_SHA256_ALGORITHM:
        try:
            r, s = utils.decode_dss_signature(signature)
        except ValueError as exc:
            raise ProtocolError("invalid ECDSA certificate signature encoding") from exc
        if not (0 < r < 1 << 256 and 0 < s < 1 << 256):
            raise ProtocolError("ECDSA certificate signature is outside the P-256 size bounds")
    if tbs[6][0] != 0x30:
        raise ProtocolError("invalid public key encoding")
    return tbs[6][2], algorithm


def _parse_der(der: bytes) -> x509.Certificate:
    if not isinstance(der, bytes) or not 1 <= len(der) <= MAX_CERT:
        raise ProtocolError("certificate exceeds size bounds")
    try:
        tag, _, end, _ = _element(der)
        if tag != 0x30 or end != len(der):
            raise ProtocolError("certificate DER contains trailing bytes")
        cert = x509.load_der_x509_certificate(der)
        _encoding(cert)
        return cert
    except _CERTIFICATE_ERRORS as exc:
        raise ProtocolError("invalid certificate DER") from exc


def _extension(cert: x509.Certificate, oid: x509.ObjectIdentifier, *, critical: bool | None = None):
    try:
        ext = cert.extensions.get_extension_for_oid(oid)
    except x509.ExtensionNotFound as exc:
        raise ProtocolError("certificate is missing a required extension") from exc
    if critical is not None and ext.critical != critical:
        raise ProtocolError("certificate extension has incorrect criticality")
    return ext.value


def _common_checks(cert: x509.Certificate, now: datetime) -> None:
    if cert.version != x509.Version.v3 or not 0 < cert.serial_number < (1 << 159):
        raise ProtocolError("invalid certificate version or serial")
    if not cert.issuer:
        raise ProtocolError("certificate issuer must not be empty")
    if not cert.not_valid_before_utc <= now <= cert.not_valid_after_utc:
        raise ProtocolError("certificate is expired or not yet valid")
    spki, _ = _encoding(cert)
    canonical = cert.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    if spki != canonical:
        raise ProtocolError("unsupported certificate public key parameters")
    for ext in cert.extensions:
        if ext.oid in _UNSUPPORTED_POLICY:
            raise ProtocolError("certificate constraints/policies are outside the lab validator")
        if ext.critical and ext.oid not in _SUPPORTED_EXTENSIONS:
            raise ProtocolError("unsupported critical certificate extension")


def _matches_dns(pattern: str, server_name: str) -> bool:
    # Deliberately restrict wildcards to a complete leftmost label and at least
    # two suffix labels. Do not wildcard-match an internationalized A-label.
    pattern = pattern.lower()
    if pattern.startswith("*."):
        suffix = pattern[2:]
        validate_server_name(suffix)
        return (len(suffix.split(".")) >= 2
                and len(server_name.split(".")) == len(suffix.split(".")) + 1
                and not server_name.split(".")[0].startswith("xn--")
                and server_name.endswith("." + suffix))
    validate_server_name(pattern)
    return pattern == server_name


def _leaf_checks(cert: x509.Certificate, server_name: str, now: datetime) -> x25519.X25519PublicKey:
    _common_checks(cert, now)
    key = cert.public_key()
    if not isinstance(key, x25519.X25519PublicKey):
        raise ProtocolError("server certificate must contain an X25519 key")
    bc = _extension(cert, ExtensionOID.BASIC_CONSTRAINTS, critical=True)
    ku = _extension(cert, ExtensionOID.KEY_USAGE, critical=True)
    if bc.ca or bc.path_length is not None:
        raise ProtocolError("server certificate cannot be a CA")
    if (not ku.key_agreement or ku.digital_signature or ku.content_commitment
            or ku.key_encipherment or ku.data_encipherment or ku.key_cert_sign
            or ku.crl_sign or ku.encipher_only or ku.decipher_only):
        raise ProtocolError("server key usage must be keyAgreement only")
    eku = _extension(cert, ExtensionOID.EXTENDED_KEY_USAGE)
    if ExtendedKeyUsageOID.SERVER_AUTH not in eku:
        raise ProtocolError("server certificate is not authorized for server authentication")
    san = _extension(cert, ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
    if not cert.subject:
        _extension(cert, ExtensionOID.SUBJECT_ALTERNATIVE_NAME, critical=True)
    if not any(_matches_dns(name, server_name) for name in san.get_values_for_type(x509.DNSName)):
        raise ProtocolError("certificate DNS identity does not match")
    # A certified low-order public key is unusable and must not reach a session.
    try:
        x25519.X25519PrivateKey.from_private_bytes(bytes(range(32))).exchange(key)
    except ValueError as exc:
        raise ProtocolError("invalid X25519 certificate public key") from exc
    return key


def _ca_checks(cert: x509.Certificate, now: datetime, ca_below: int) -> None:
    _common_checks(cert, now)
    if not cert.subject:
        raise ProtocolError("CA subject must not be empty")
    key = cert.public_key()
    if not (isinstance(key, ed25519.Ed25519PublicKey)
            or isinstance(key, ec.EllipticCurvePublicKey) and isinstance(key.curve, ec.SECP256R1)):
        raise ProtocolError("unsupported CA public key")
    bc = _extension(cert, ExtensionOID.BASIC_CONSTRAINTS, critical=True)
    ku = _extension(cert, ExtensionOID.KEY_USAGE, critical=True)
    if not bc.ca or not ku.key_cert_sign:
        raise ProtocolError("issuer is not an authorized CA")
    if bc.path_length is not None and ca_below > bc.path_length:
        raise ProtocolError("certificate path length exceeded")
    try:
        eku = cert.extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE).value
        if ExtendedKeyUsageOID.SERVER_AUTH not in eku:
            raise ProtocolError("CA extended key usage excludes server authentication")
    except x509.ExtensionNotFound:
        pass


def _verify_issuer(cert: x509.Certificate, issuer: x509.Certificate) -> None:
    if cert.issuer != issuer.subject:
        raise ProtocolError("certificate chain is not in issuer order")
    try:
        authority = cert.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_KEY_IDENTIFIER).value
        if authority.authority_cert_issuer is not None or authority.authority_cert_serial_number is not None:
            raise ProtocolError("authority certificate references are outside the lab validator")
        if authority.key_identifier is not None:
            ski = _extension(issuer, ExtensionOID.SUBJECT_KEY_IDENTIFIER)
            if authority.key_identifier != ski.digest:
                raise ProtocolError("authority key identifier mismatch")
    except x509.ExtensionNotFound:
        pass
    key = issuer.public_key()
    _, algorithm = _encoding(cert)
    try:
        if isinstance(key, ed25519.Ed25519PublicKey) and algorithm == _ED25519_ALGORITHM:
            key.verify(cert.signature, cert.tbs_certificate_bytes)
        elif (isinstance(key, ec.EllipticCurvePublicKey) and isinstance(key.curve, ec.SECP256R1)
              and algorithm == _P256_SHA256_ALGORITHM):
            key.verify(cert.signature, cert.tbs_certificate_bytes, ec.ECDSA(hashes.SHA256()))
        else:
            raise ProtocolError("unsupported certificate signature algorithm")
    except InvalidSignature as exc:
        raise ProtocolError("certificate signature is invalid") from exc


def _chain(chain_der: list[bytes]) -> list[x509.Certificate]:
    if not isinstance(chain_der, list) or not 1 <= len(chain_der) <= 8:
        raise ProtocolError("certificate chain must contain 1 through 8 certificates")
    if 4 + sum(5 + len(der) for der in chain_der) > MAX_CHAIN_BODY:
        raise ProtocolError("certificate chain body exceeds limit")
    certs = [_parse_der(der) for der in chain_der]
    if len(set(chain_der)) != len(chain_der):
        raise ProtocolError("duplicate certificates in chain")
    return certs


def validate_chain(chain_der: list[bytes], trust_roots: list[x509.Certificate], server_name: str,
                   revocation_policy: str) -> x25519.X25519PublicKey:
    """Validate the exact peer path against explicit local lab anchors, or fail."""
    try:
        if revocation_policy != "lab-offline":
            raise ProtocolError("explicit lab-offline revocation policy is required")
        validate_server_name(server_name)
        certs = _chain(chain_der)
        if not trust_roots or len(trust_roots) > 32:
            raise ProtocolError("explicit bounded trust anchors are required")
        now = datetime.now(timezone.utc)
        public_key = _leaf_checks(certs[0], server_name, now)
        for index, issuer in enumerate(certs[1:], start=1):
            _ca_checks(issuer, now, index - 1)
            _verify_issuer(certs[index - 1], issuer)
        last = certs[-1]
        for root in trust_roots:
            try:
                root_der = root.public_bytes(serialization.Encoding.DER)
                same_root = chain_der[-1] == root_der
                _ca_checks(root, now, len(certs) - 2 if same_root else len(certs) - 1)
                if same_root:
                    if len(certs) == 1:
                        continue
                else:
                    _verify_issuer(last, root)
                return public_key
            except _CERTIFICATE_ERRORS:
                continue
        raise ProtocolError("certificate chain does not terminate at an accepted trust anchor")
    except _CERTIFICATE_ERRORS as exc:
        if isinstance(exc, ProtocolError):
            raise
        raise ProtocolError("certificate validation failed") from exc


def _read_file(path: Path, limit: int, *, private: bool = False) -> bytes:
    descriptor = None
    try:
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
        if private:
            flags |= getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
            raise ConfigurationError("credential file is not a bounded regular file")
        if private and os.name == "posix" and info.st_mode & 0o077:
            raise ConfigurationError("private key permissions must deny group/other access (chmod 600)")
        with os.fdopen(descriptor, "rb") as stream:
            descriptor = None
            data = stream.read(limit + 1)
        if len(data) > limit:
            raise ConfigurationError("credential file exceeds limit")
        return data
    except OSError as exc:
        raise ConfigurationError("cannot read credential file") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _pem_certificates(data: bytes, maximum: int) -> list[x509.Certificate]:
    certs = []
    end = 0
    for match in _PEM.finditer(data):
        if data[end:match.start()].strip() or len(certs) >= maximum:
            raise ConfigurationError("invalid certificate PEM bundle")
        try:
            der = base64.b64decode(re.sub(rb"\s", b"", match[1]), validate=True)
            certs.append(_parse_der(der))
        except (ValueError, binascii.Error) as exc:
            raise ConfigurationError("invalid certificate PEM") from exc
        end = match.end()
    if not certs or data[end:].strip():
        raise ConfigurationError("invalid certificate PEM bundle")
    return certs


def load_trust_roots(path: Path) -> list[x509.Certificate]:
    roots = _pem_certificates(_read_file(Path(path), MAX_PEM_FILE), 32)
    try:
        now = datetime.now(timezone.utc)
        for root in roots:
            _ca_checks(root, now, 0)
    except _CERTIFICATE_ERRORS as exc:
        raise ConfigurationError("invalid local lab trust anchor") from exc
    return roots


def load_credentials(chain_path: Path, key_path: Path, server_name: str) -> Credentials:
    certs = _pem_certificates(_read_file(Path(chain_path), MAX_PEM_FILE), 8)
    key_data = _read_file(Path(key_path), 16384, private=True)
    try:
        # Accept only one unencrypted PKCS#8 PEM object, never ignored trailing data.
        key_match = _KEY_PEM.fullmatch(key_data)
        if key_match is None:
            raise ConfigurationError("private key must be one unencrypted PKCS#8 PEM object")
        key_der = base64.b64decode(re.sub(rb"\s", b"", key_match[1]), validate=True)
        tag, _, key_end, _ = _element(key_der)
        if tag != 0x30 or key_end != len(key_der):
            raise ConfigurationError("private key DER has trailing data")
        key = serialization.load_der_private_key(key_der, password=None)
        if not isinstance(key, x25519.X25519PrivateKey):
            raise ConfigurationError("server private key must be X25519")
        validate_server_name(server_name)
        chain_der = [cert.public_bytes(serialization.Encoding.DER) for cert in certs]
        _chain(chain_der)
        now = datetime.now(timezone.utc)
        leaf_key = _leaf_checks(certs[0], server_name, now)
        if leaf_key.public_bytes_raw() != key.public_key().public_bytes_raw():
            raise ConfigurationError("server certificate and private key do not match")
        for index, issuer in enumerate(certs[1:], start=1):
            _ca_checks(issuer, now, index - 1)
            _verify_issuer(certs[index - 1], issuer)
        # Last signature is checked by the client using its local trust anchor.
        _, algorithm = _encoding(certs[-1])
        if algorithm not in (_ED25519_ALGORITHM, _P256_SHA256_ALGORITHM):
            raise ConfigurationError("unsupported certificate signature algorithm")
        return Credentials(chain_der, key)
    except _CERTIFICATE_ERRORS as exc:
        if isinstance(exc, ConfigurationError):
            raise
        raise ConfigurationError("invalid server credentials") from exc
