"""Certificate loading and explicit-policy validation.

The legacy lab helpers retain their deliberately restricted, ordered-path
offline profile. ``validate_pkix_path`` and ``validate_identity`` instead use
the OpenSSL PKIX provider with explicit trust anchors and separate identity,
credential-algorithm and revocation policy checks. Neither path imports the
operating-system trust store or fetches certificate-provided URLs implicitly.
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
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, ed448, padding, rsa, utils, x25519
from cryptography.x509.oid import ExtendedKeyUsageOID, ExtensionOID

from .errors import ConfigurationError, ProtocolError
from .credential_limits import MAX_CERTIFICATES, MAX_CERT_DER, MAX_CERTIFICATE_BODY


MAX_CERT = MAX_CERT_DER
MAX_CHAIN_BODY = MAX_CERTIFICATE_BODY
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


def certificate_extensions(cert):
    """Policy fields from the exact signed certificate, with an open registry."""
    from .x509_extensions import certificate_extensions as decode
    return decode(cert)


@dataclass(frozen=True)
class Credentials:
    chain_der: list[bytes]
    private_key: x25519.X25519PrivateKey
    credential_type: int = 0
    entry_extensions: tuple = ()
    delegation: bytes = b""
    # Logical service, not the bound socket/NAT target. Evidence is sent only
    # when the client's SNI and extension59 port match this local binding.
    dnssec_service: tuple[str, int] | None = None
    # Optional explicitly provisioned ITS-X25519 grant service policy.
    its_policy: object = None
    # Local issuer metadata for selecting the actual signature scheme when a
    # fullchain omits its root. Never emitted, installed as peer trust, or used
    # as a substitute for the peer's independent path validation.
    signature_issuers: tuple[bytes, ...] = ()


# Public signatures authenticate certificate paths/offline grants only. Neither
# role's online MAC tag is a certificate-signature algorithm.
SUPPORTED_CERTIFICATE_ALGORITHMS = (
    0x0807, 0x0808, 0x0403, 0x0503, 0x0603, 0x081a, 0x081b, 0x081c,
    0x0804, 0x0805, 0x0806, 0x0809, 0x080a, 0x080b,
    0x0401, 0x0501, 0x0601,
)
_SIGNATURE_HASHES = {4: hashes.SHA256, 5: hashes.SHA384, 6: hashes.SHA512}
_SM2_SPKI_ALGORITHM = bytes.fromhex("301306072a8648ce3d020106082a811ccf5501822d")
SM2_CERTIFICATE_IDENTIFIER = b"1234567812345678"
SM2_GRANT_IDENTIFIER = b"TLSv1.3+GM+Cipher+Suite"


@dataclass(frozen=True)
class RSAPSSPublicKey:
    """Preserve PSS SPKI constraints that cryptography's RSA object drops."""
    spki_der: bytes
    key: rsa.RSAPublicKey
    # None means absent parameters (unrestricted PSS), not an empty sequence.
    restrictions: tuple | None

    def public_bytes(self, encoding, format):
        if encoding != serialization.Encoding.DER or format != serialization.PublicFormat.SubjectPublicKeyInfo:
            raise ValueError("PSS identity supports exact DER SubjectPublicKeyInfo only")
        return self.spki_der


def _pss_key_restrictions(algorithm_fields):
    if len(algorithm_fields) == 1:
        return None
    if len(algorithm_fields) != 2 or algorithm_fields[1][0] != 0x30:
        raise ProtocolError("invalid RSA-PSS key parameters")
    hash_name, mgf_hash, minimum_salt, trailer = "sha1", "sha1", 20, 1
    previous = -1
    def digest_algorithm(encoded):
        tag, body, end, _ = _element(encoded)
        values = _children(body)
        if (tag != 0x30 or end != len(encoded) or not 1 <= len(values) <= 2
                or values[0][0] != 6 or len(values) == 2 and values[1][2] != b"\x05\x00"):
            raise ProtocolError("invalid PSS digest AlgorithmIdentifier")
        known = {bytes.fromhex("2b0e03021a"): "sha1", **{
            bytes.fromhex("6086480165030402") + bytes([number]): name
            for number, name in ((1, "sha256"), (2, "sha384"), (3, "sha512"))}}
        if values[0][1] not in known:
            raise ProtocolError("unsupported PSS digest constraint")
        return known[values[0][1]]
    for tag, body, _ in _children(algorithm_fields[1][1]):
        if tag not in (0xa0, 0xa1, 0xa2, 0xa3) or tag <= previous:
            raise ProtocolError("invalid or duplicate PSS parameter")
        previous = tag
        if tag == 0xa0:
            hash_name = digest_algorithm(body)
        elif tag == 0xa1:
            inner_tag, inner, end, _ = _element(body)
            values = _children(inner)
            if (inner_tag != 0x30 or end != len(body) or len(values) != 2 or values[0][0] != 6
                    or values[0][1] != bytes.fromhex("2a864886f70d010108")):
                raise ProtocolError("PSS key requires MGF1")
            mgf_hash = digest_algorithm(values[1][2])
        else:
            inner_tag, value, end, _ = _element(body)
            if (inner_tag != 2 or end != len(body) or not value or value[0] & 128
                    or len(value) > 1 and value[0] == 0 and not value[1] & 128 or len(value) > 4):
                raise ProtocolError("invalid PSS integer constraint")
            if tag == 0xa2:
                minimum_salt = int.from_bytes(value, "big")
            else:
                trailer = int.from_bytes(value, "big")
    return hash_name, mgf_hash, minimum_salt, trailer


@dataclass(frozen=True)
class SM2PublicKey:
    """An opaque SM2 key bound to an explicitly selected native provider.

    DER recognition alone is not key or trust validation. The provider parses
    and checks the point when verifying a signature or building a PKIX path.
    """
    spki_der: bytes
    provider: object

    def public_bytes(self, encoding, format):
        if encoding != serialization.Encoding.DER or format != serialization.PublicFormat.SubjectPublicKeyInfo:
            raise ValueError("SM2 key supports exact DER SubjectPublicKeyInfo only")
        return self.spki_der


@dataclass(frozen=True)
class GOSTPublicKey:
    spki_der: bytes
    provider: object
    group: int

    def public_bytes(self, encoding, format):
        if encoding != serialization.Encoding.DER or format != serialization.PublicFormat.SubjectPublicKeyInfo:
            raise ValueError("GOST key supports exact DER SubjectPublicKeyInfo only")
        return self.spki_der


def supported_certificate_algorithms(signature_provider=None):
    """Do not advertise optional SM2 verification without an installed provider."""
    return (SUPPORTED_CERTIFICATE_ALGORITHMS + ((0x0708,) if signature_provider is not None else ())
            + (tuple(range(0x0709, 0x0710)) if callable(getattr(signature_provider, "verify_gost", None)) else ()))


def certificate_public_key(cert, *, signature_provider=None):
    """Extract a key without asking cryptography to instantiate unsupported SM2."""
    _, certificate_body, _, _ = _element(cert.public_bytes(serialization.Encoding.DER))
    outer = _children(certificate_body)
    tbs = _children(outer[0][1])
    offset = 1 if tbs and tbs[0][0] == 0xa0 else 0
    spki = tbs[offset + 5][2]
    return load_signature_public_key(spki, signature_provider=signature_provider)


def load_signature_public_key(spki, *, signature_provider=None):
    """Load exact DER SPKI without losing PSS constraints or optional families.

    The caller supplies independent trust for this key (e.g. a CT log inventory);
    parsing and native-provider availability alone do not confer authority.
    """
    if not isinstance(spki, bytes) or not 1 <= len(spki) <= MAX_CERT:
        raise ProtocolError("public signature key exceeds local bounds")
    tag, body, end, _ = _element(spki)
    fields = _children(body)
    if (tag != 0x30 or end != len(spki) or len(fields) != 2 or fields[0][0] != 0x30
            or fields[1][0] != 3 or not fields[1][1] or fields[1][1][0] != 0):
        raise ProtocolError("invalid public-key SPKI")
    algorithms = _children(fields[0][1])
    if not algorithms or algorithms[0][0] != 6:
        raise ProtocolError("public-key algorithm identifier is missing")
    oid = algorithms[0][1]
    if oid == bytes.fromhex("2a864886f70d01010a"):
        return RSAPSSPublicKey(spki, serialization.load_der_public_key(spki), _pss_key_restrictions(algorithms))
    if fields and fields[0][2] == _SM2_SPKI_ALGORITHM:
        if (signature_provider is None or end != len(spki) or len(fields) != 2
                or fields[1][0] != 0x03 or len(fields[1][1]) != 66
                or fields[1][1][:2] != b"\x00\x04"):
            raise ProtocolError("SM2 public key requires its explicit native provider and canonical point encoding")
        return SM2PublicKey(spki, signature_provider)
    if oid in (bytes.fromhex("2a85030701010101"), bytes.fromhex("2a85030701010102")):
        if not callable(getattr(signature_provider, "verify_gost", None)):
            raise ProtocolError("GOST public key requires an explicit GOST provider")
        from .gost_provider import spki_group
        return GOSTPublicKey(spki, signature_provider, spki_group(spki))
    try:
        return serialization.load_der_public_key(spki)
    except (ValueError, TypeError, UnsupportedAlgorithm) as exc:
        raise ProtocolError("invalid or unsupported signature public key") from exc


def verify_public_signature(key, scheme: int, signature: bytes, message: bytes,
                            *, sm2_identifier=SM2_GRANT_IDENTIFIER,
                            gost_certificate_encoding=False) -> None:
    """Verify an explicitly selected TLS public signature using the provider.

    This API is for signed offline objects, never CertificateVerify. Scheme/key
    mismatches and unsupported algorithms fail; no alternate scheme is tried.
    """
    try:
        if scheme == 0x0708 and isinstance(key, SM2PublicKey):
            key.provider.verify_sm2(key.spki_der, message, signature, identifier=sm2_identifier)
        elif 0x0709 <= scheme <= 0x070f and isinstance(key, GOSTPublicKey):
            key.provider.verify_gost(key.spki_der, message, signature, scheme,
                                     certificate_encoding=gost_certificate_encoding)
        elif scheme == 0x0807 and isinstance(key, ed25519.Ed25519PublicKey):
            key.verify(signature, message)
        elif scheme == 0x0808 and isinstance(key, ed448.Ed448PublicKey):
            key.verify(signature, message)
        elif scheme in (0x0403, 0x0503, 0x0603, 0x081a, 0x081b, 0x081c) and isinstance(key, ec.EllipticCurvePublicKey):
            curve, digest = {0x0403: (ec.SECP256R1, hashes.SHA256), 0x0503: (ec.SECP384R1, hashes.SHA384),
                0x0603: (ec.SECP521R1, hashes.SHA512), 0x081a: (ec.BrainpoolP256R1, hashes.SHA256),
                0x081b: (ec.BrainpoolP384R1, hashes.SHA384), 0x081c: (ec.BrainpoolP512R1, hashes.SHA512)}[scheme]
            if not isinstance(key.curve, curve):
                raise ProtocolError("signature scheme and curve differ")
            key.verify(signature, message, ec.ECDSA(digest()))
        elif scheme in (0x0401, 0x0501, 0x0601) and isinstance(key, rsa.RSAPublicKey):
            if key.key_size < 2048:
                raise ProtocolError("RSA key is below the local minimum")
            key.verify(signature, message, padding.PKCS1v15(), _SIGNATURE_HASHES[scheme >> 8]())
        elif scheme in (0x0804, 0x0805, 0x0806, 0x0809, 0x080a, 0x080b) and isinstance(key, (rsa.RSAPublicKey, RSAPSSPublicKey)):
            constrained = isinstance(key, RSAPSSPublicKey)
            if constrained != (scheme >= 0x0809):
                raise ProtocolError("PSS signature family differs from key SPKI")
            rsa_key = key.key if constrained else key
            if rsa_key.key_size < 2048:
                raise ProtocolError("RSA key is below the local minimum")
            index = scheme - (0x0804 if scheme < 0x0809 else 0x0809) + 4
            algorithm = _SIGNATURE_HASHES[index]()
            if constrained and key.restrictions is not None:
                digest, mgf, salt, trailer = key.restrictions
                if digest != algorithm.name or mgf != algorithm.name or salt > algorithm.digest_size or trailer != 1:
                    raise ProtocolError("PSS signature violates public-key restrictions")
            rsa_key.verify(signature, message, padding.PSS(mgf=padding.MGF1(algorithm),
                        salt_length=algorithm.digest_size), algorithm)
        else:
            raise ProtocolError("unsupported public signature scheme or key")
    except (InvalidSignature, ValueError, TypeError, UnsupportedAlgorithm) as exc:
        raise ProtocolError("public signature validation failed") from exc


def certificate_signature_scheme(cert: x509.Certificate, issuer: x509.Certificate | None = None) -> int:
    """Map an actual certificate signature, independently of grant offers."""
    oid = cert.signature_algorithm_oid.dotted_string
    fixed = {"1.3.101.112": 0x0807, "1.3.101.113": 0x0808,
             "1.2.156.10197.1.501": 0x0708,
             "1.2.840.113549.1.1.11": 0x0401, "1.2.840.113549.1.1.12": 0x0501,
             "1.2.840.113549.1.1.13": 0x0601,
             "1.2.840.10045.4.3.2": 0x0403, "1.2.840.10045.4.3.3": 0x0503,
             "1.2.840.10045.4.3.4": 0x0603}
    if oid in fixed:
        if fixed[oid] in (0x0403, 0x0503, 0x0603) and issuer is not None:
            key = issuer.public_key()
            if isinstance(key, ec.EllipticCurvePublicKey):
                brainpool = {"brainpoolP256r1": (0x0403, 0x081a), "brainpoolP384r1": (0x0503, 0x081b),
                             "brainpoolP512r1": (0x0603, 0x081c)}.get(key.curve.name)
                if brainpool is not None:
                    if fixed[oid] != brainpool[0]:
                        raise ProtocolError("Brainpool certificate curve/hash do not match its TLS scheme")
                    return brainpool[1]
        return fixed[oid]
    if oid in ("1.2.643.7.1.1.3.2", "1.2.643.7.1.1.3.3"):
        if issuer is None:
            raise ProtocolError("GOST certificate signature mapping requires the actual issuer")
        _, child_body, _, _ = _element(cert.public_bytes(serialization.Encoding.DER))
        if len(_children(_children(child_body)[1][1])) != 1:
            raise ProtocolError("GOST certificate signature parameters must be absent (RFC9215)")
        from .gost_provider import spki_group
        _, body, _, _ = _element(issuer.public_bytes(serialization.Encoding.DER))
        tbs = _children(_children(body)[0][1])
        offset = 1 if tbs and tbs[0][0] == 0xa0 else 0
        group = spki_group(tbs[offset + 5][2])
        if oid != ("1.2.643.7.1.1.3.3" if group >= 38 else "1.2.643.7.1.1.3.2"):
            raise ProtocolError("GOST certificate signature and issuer key disagree")
        return 0x0709 + group - 34
    if oid == "1.2.840.113549.1.1.10":
        algorithm = cert.signature_hash_algorithm
        offset = {"sha256": 0, "sha384": 1, "sha512": 2}.get(algorithm.name)
        if offset is None or not isinstance(cert.signature_algorithm_parameters, padding.PSS):
            raise ProtocolError("unsupported certificate PSS parameters")
        expected = padding.PSS(mgf=padding.MGF1(algorithm), salt_length=algorithm.digest_size)
        if cert.signature_algorithm_parameters != expected:
            raise ProtocolError("certificate PSS parameters do not match the TLS signature scheme")
        # A PSS-constrained issuer has a distinct TLS signature-scheme family.
        base = 0x0809 if issuer is not None and issuer.public_key_algorithm_oid.dotted_string == oid else 0x0804
        return base + offset
    raise ProtocolError("unsupported certificate signature algorithm")


def _load_pkix_der(der: bytes) -> x509.Certificate:
    """Strict outer DER framing, without the deliberately narrower lab profile."""
    if not isinstance(der, bytes) or not 1 <= len(der) <= MAX_CERT:
        raise ProtocolError("certificate exceeds local size budget")
    try:
        tag, body, end, _ = _element(der)
        outer = _children(body)
        if tag != 0x30 or end != len(der) or len(outer) != 3 or [x[0] for x in outer] != [0x30, 0x30, 0x03]:
            raise ProtocolError("invalid certificate DER envelope")
        if not outer[2][1] or outer[2][1][0] != 0:
            raise ProtocolError("certificate signature BIT STRING must be octet-aligned")
        fields = _children(outer[0][1])
        offset = 1 if fields and fields[0][0] == 0xa0 else 0
        if len(fields) < offset + 6 or fields[offset + 1][2] != outer[1][2]:
            raise ProtocolError("certificate signature algorithms differ")
        cert = x509.load_der_x509_certificate(der)
        if cert.public_bytes(serialization.Encoding.DER) != der:
            raise ProtocolError("noncanonical certificate encoding")
        # Force lazy parsing before crossing the authorization boundary.
        certificate_extensions(cert)
        return cert
    except _CERTIFICATE_ERRORS as exc:
        if isinstance(exc, ProtocolError):
            raise
        raise ProtocolError("invalid certificate DER") from exc


def find_certificate_issuer(cert, issuers, *, signature_provider=None):
    """Find an explicitly supplied, cryptographically matching certificate issuer.

    This is signature-scheme metadata, NOT a trust/path/authorization decision.
    It permits omitted roots without guessing a GOST curve, Brainpool group or
    constrained PSS family from the child's signature AlgorithmIdentifier alone.
    Caller-controlled candidates remain bounded and must have canonical DER.
    """
    if isinstance(cert, x509.Certificate):
        cert = _load_pkix_der(cert.public_bytes(serialization.Encoding.DER))
    else:
        cert = _load_pkix_der(cert)
    if not isinstance(issuers, (tuple, list)) or len(issuers) > 64:
        raise ProtocolError("local signature issuer inventory exceeds bounds")
    candidates = []
    total = 0
    for candidate in issuers:
        encoded = candidate.public_bytes(serialization.Encoding.DER) if isinstance(candidate, x509.Certificate) else candidate
        if not isinstance(encoded, bytes):
            raise ProtocolError("invalid local signature issuer material")
        total += len(encoded)
        if total > MAX_CHAIN_BODY:
            raise ProtocolError("local signature issuer inventory exceeds bounds")
        candidates.append(_load_pkix_der(encoded))
    try:
        authority = certificate_extensions(cert).get_extension_for_class(x509.AuthorityKeyIdentifier).value
    except x509.ExtensionNotFound:
        authority = None
    for issuer in candidates:
        if cert.issuer != issuer.subject:
            continue
        if authority is not None:
            if authority.authority_cert_serial_number is not None and authority.authority_cert_serial_number != issuer.serial_number:
                continue
            if authority.authority_cert_issuer is not None:
                names = [name.value for name in authority.authority_cert_issuer
                         if isinstance(name, x509.DirectoryName)]
                if not names or issuer.issuer not in names:
                    continue
            if authority.key_identifier is not None:
                try:
                    subject_key = certificate_extensions(issuer).get_extension_for_class(x509.SubjectKeyIdentifier).value.digest
                except x509.ExtensionNotFound:
                    subject_key = None
                if subject_key is not None and authority.key_identifier != subject_key:
                    continue
        try:
            verify_public_signature(certificate_public_key(issuer, signature_provider=signature_provider),
                certificate_signature_scheme(cert, issuer), cert.signature, cert.tbs_certificate_bytes,
                sm2_identifier=SM2_CERTIFICATE_IDENTIFIER, gost_certificate_encoding=True)
        except (ProtocolError, *_CERTIFICATE_ERRORS):
            continue
        return issuer
    return None


def validate_pkix_path(chain_der, trust_roots, *, now=None, partial_chain=False,
                       signature_provider=None, purpose="server"):
    """Build and validate a path with OpenSSL, against ONLY explicit anchors.

    No OS roots, AIA network fetch or critical-extension bypass is enabled.
    Explicit partial-chain policy is used only to check locally configured
    credential bundles whose final issuer need not include its root. It is off
    for remote peer validation. Identity/role/revocation are separate checks.
    """
    if (not chain_der or len(chain_der) > MAX_CERTIFICATES
            or 4 + sum(5 + len(x) for x in chain_der) > MAX_CHAIN_BODY):
        raise ProtocolError("certificate chain exceeds local budget")
    if not trust_roots or len(trust_roots) > 256:
        raise ProtocolError("explicit bounded trust anchors are required")
    certs = [_load_pkix_der(item) for item in chain_der]
    if len(set(chain_der)) != len(chain_der):
        raise ProtocolError("duplicate certificates in chain")
    if signature_provider is not None:
        # All path constraints remain the native provider's responsibility;
        # never substitute a sequence of successful signature checks for PKIX.
        path = signature_provider.verify_certificate_path(tuple(chain_der),
            tuple(root.public_bytes(serialization.Encoding.DER) for root in trust_roots),
            now=now, partial_chain=partial_chain, purpose=purpose)
        # A full verified path may add its separately configured trust anchor;
        # that anchor is not part of the peer's transmitted Certificate budget.
        if (not path or len(path) > MAX_CERTIFICATES + 1
                or sum(len(value) for value in path) > MAX_CHAIN_BODY + MAX_CERT
                or path[0] != chain_der[0]):
            raise ProtocolError("PKIX provider returned an invalid verified path")
        return tuple(_load_pkix_der(value) for value in path)
    try:
        from OpenSSL import crypto as openssl
        store = openssl.X509Store()
        store.set_time(now or datetime.now(timezone.utc))
        store.set_flags(openssl.X509StoreFlags.POLICY_CHECK)
        if partial_chain:
            store.set_flags(openssl.X509StoreFlags.PARTIAL_CHAIN)
        for root in trust_roots:
            store.add_cert(openssl.X509.from_cryptography(root))
        context = openssl.X509StoreContext(store, openssl.X509.from_cryptography(certs[0]),
                    [openssl.X509.from_cryptography(cert) for cert in certs[1:]])
        return tuple(cert.to_cryptography() for cert in context.get_verified_chain())
    except ImportError as exc:
        raise ProtocolError("PKIX provider is unavailable") from exc
    except (openssl.Error, openssl.X509StoreContextError, ValueError, TypeError) as exc:
        raise ProtocolError("PKIX certificate path validation failed") from exc


def validate_identity(chain_der, *, trust_roots, role, name=None,
                      offered_certificate_algorithms=SUPPORTED_CERTIFICATE_ALGORITHMS,
                      revocation_policy="offline", evidence_validator=None,
                      evidence=(), now=None, signing_leaf=False, partial_chain=False,
                      signature_provider=None):
    """Validate PKIX identity and usage, with explicit offline/status policy.

    `offline` checks no online status and is reported by the caller as such.
    `require-evidence` additionally requires an approving evidence validator;
    parsing an OCSP/DANE/CT blob is never an approval. A signing leaf is allowed
    only for validation of an independently verified offline delegation grant.
    """
    if role not in ("server", "client") or revocation_policy not in ("offline", "require-evidence"):
        raise ProtocolError("invalid identity or revocation policy")
    if not offered_certificate_algorithms or any(x in (0xfe00, 0xfe01, 0x0420, 0x0520, 0x0620)
                                               for x in offered_certificate_algorithms):
        raise ProtocolError("invalid certificate signature offer")
    path = validate_pkix_path(chain_der, trust_roots, now=now, partial_chain=partial_chain,
                              signature_provider=signature_provider, purpose=role)
    from .tls_features import validate_feature_path
    validate_feature_path(path)
    moment = now or datetime.now(timezone.utc)
    eku_oid = ExtendedKeyUsageOID.SERVER_AUTH if role == "server" else ExtendedKeyUsageOID.CLIENT_AUTH
    for index, cert in enumerate(path):
        if not cert.not_valid_before_utc <= moment <= cert.not_valid_after_utc:
            raise ProtocolError("certificate is outside its validity interval")
        if index < len(path) - 1 and certificate_signature_scheme(cert, path[index + 1]) not in offered_certificate_algorithms:
            raise ProtocolError("certificate signature was not offered")
        try:
            eku = certificate_extensions(cert).get_extension_for_class(x509.ExtendedKeyUsage).value
            if eku_oid not in eku and ExtendedKeyUsageOID.ANY_EXTENDED_KEY_USAGE not in eku:
                raise ProtocolError("certificate extended usage excludes this role")
        except x509.ExtensionNotFound:
            pass
    leaf = path[0]
    key = certificate_public_key(leaf, signature_provider=signature_provider)
    if signing_leaf:
        if not isinstance(key, (rsa.RSAPublicKey, RSAPSSPublicKey, ec.EllipticCurvePublicKey, ed25519.Ed25519PublicKey, ed448.Ed448PublicKey, SM2PublicKey, GOSTPublicKey)):
            raise ProtocolError("delegation parent must have a public signing key")
    elif not isinstance(key, x25519.X25519PublicKey):
        raise ProtocolError("endpoint identity must have an X25519 proof key")
    try:
        constraints = certificate_extensions(leaf).get_extension_for_class(x509.BasicConstraints).value
        if constraints.ca:
            raise ProtocolError("endpoint certificate is a CA")
    except x509.ExtensionNotFound:
        pass
    try:
        usage = certificate_extensions(leaf).get_extension_for_class(x509.KeyUsage).value
        if signing_leaf and not usage.digital_signature:
            raise ProtocolError("delegation parent does not permit digital signatures")
        if not signing_leaf and (not usage.key_agreement or usage.digital_signature or usage.content_commitment
                or usage.key_encipherment or usage.data_encipherment or usage.key_cert_sign or usage.crl_sign):
            raise ProtocolError("X25519 key usage is incompatible with key agreement")
    except x509.ExtensionNotFound:
        if signing_leaf:
            raise ProtocolError("delegation parent is missing signing usage")
    if role == "server":
        if not name:
            raise ProtocolError("server reference identity is required")
        validate_service_identity(name)
        try:
            san = certificate_extensions(leaf).get_extension_for_class(x509.SubjectAlternativeName).value
            try:
                address = ipaddress.ip_address(name)
            except ValueError:
                validate_server_name(name)
                matches = any(_matches_dns(value, name) for value in san.get_values_for_type(x509.DNSName))
            else:
                matches = address in san.get_values_for_type(x509.IPAddress)
            if not matches:
                raise ProtocolError("certificate reference identity does not match")
        except x509.ExtensionNotFound as exc:
            raise ProtocolError("certificate reference identity is missing") from exc
    if not signing_leaf:
        try:
            x25519.X25519PrivateKey.from_private_bytes(bytes(range(32))).exchange(key)
        except ValueError as exc:
            raise ProtocolError("invalid X25519 identity key") from exc
    if evidence_validator is not None:
        if evidence_validator(path, role, evidence, moment) is not True:
            raise ProtocolError("credential evidence was not authorized")
    elif revocation_policy == "require-evidence":
        raise ProtocolError("required credential evidence validator is unavailable")
    return key


def validate_server_name(name: str) -> str:
    """Accept normalized DNS A-labels, never IP literals in an SNI host_name."""
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
        if len(name.split(".")) == 4 and all(part.isdigit() for part in name.split(".")):
            raise ProtocolError("noncanonical IP literal is not a DNS identity")
        return name
    raise ProtocolError("IP literals cannot be used as DNS SNI identities")


def validate_service_identity(name: str) -> str:
    """Validate a canonical DNS or IP reference identity, separate from SNI."""
    if not isinstance(name, str) or "%" in name:
        raise ProtocolError("invalid service identity")
    try:
        address = ipaddress.ip_address(name)
    except ValueError:
        return validate_server_name(name)
    if str(address) != name:
        raise ProtocolError("IP service identity must be canonical")
    return name


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
        ext = certificate_extensions(cert).get_extension_for_oid(oid)
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
    for ext in certificate_extensions(cert):
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
    try:
        address = ipaddress.ip_address(server_name)
    except ValueError:
        matches = any(_matches_dns(name, server_name) for name in san.get_values_for_type(x509.DNSName))
    else:
        matches = address in san.get_values_for_type(x509.IPAddress)
    if not matches:
        raise ProtocolError("certificate reference identity does not match")
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
        eku = certificate_extensions(cert).get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE).value
        if ExtendedKeyUsageOID.SERVER_AUTH not in eku:
            raise ProtocolError("CA extended key usage excludes server authentication")
    except x509.ExtensionNotFound:
        pass


def _verify_issuer(cert: x509.Certificate, issuer: x509.Certificate) -> None:
    if cert.issuer != issuer.subject:
        raise ProtocolError("certificate chain is not in issuer order")
    try:
        authority = certificate_extensions(cert).get_extension_for_oid(ExtensionOID.AUTHORITY_KEY_IDENTIFIER).value
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
    if not isinstance(chain_der, list) or not 1 <= len(chain_der) <= MAX_CERTIFICATES:
        raise ProtocolError(f"certificate chain must contain 1 through {MAX_CERTIFICATES} certificates")
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
        validate_service_identity(server_name)
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
                from .tls_features import validate_feature_path
                validate_feature_path(certs if same_root else [*certs, root])
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


def _pem_certificates(data: bytes, maximum: int, *, general_pkix=False) -> list[x509.Certificate]:
    certs = []
    end = 0
    for match in _PEM.finditer(data):
        if data[end:match.start()].strip() or len(certs) >= maximum:
            raise ConfigurationError("invalid certificate PEM bundle")
        try:
            der = base64.b64decode(re.sub(rb"\s", b"", match[1]), validate=True)
            certs.append(_load_pkix_der(der) if general_pkix else _parse_der(der))
        except (ValueError, binascii.Error) as exc:
            raise ConfigurationError("invalid certificate PEM") from exc
        end = match.end()
    if not certs or data[end:].strip():
        raise ConfigurationError("invalid certificate PEM bundle")
    return certs


def load_trust_roots(path: Path, *, general_pkix=False, signature_provider=None) -> list[x509.Certificate]:
    """Load explicit anchors; never import operating-system or peer roots.

    The default preserves the legacy lab profile. ``general_pkix=True`` loads
    ordinary PKIX CA algorithms/constraints for validate_identity's provider.
    """
    roots = _pem_certificates(_read_file(Path(path), MAX_PEM_FILE),
                              256 if general_pkix else 32, general_pkix=general_pkix)
    try:
        now = datetime.now(timezone.utc)
        for root in roots:
            if not general_pkix:
                _ca_checks(root, now, 0)
                continue
            if (not root.not_valid_before_utc <= now <= root.not_valid_after_utc
                    or not certificate_extensions(root).get_extension_for_class(x509.BasicConstraints).value.ca
                    or not isinstance(certificate_public_key(root, signature_provider=signature_provider),
                        (rsa.RSAPublicKey, RSAPSSPublicKey, ec.EllipticCurvePublicKey,
                         ed25519.Ed25519PublicKey, ed448.Ed448PublicKey, SM2PublicKey, GOSTPublicKey))):
                raise ConfigurationError("invalid local PKIX CA trust anchor")
            try:
                if not certificate_extensions(root).get_extension_for_class(x509.KeyUsage).value.key_cert_sign:
                    raise ConfigurationError("local CA trust anchor cannot sign certificates")
            except x509.ExtensionNotFound:
                pass
    except _CERTIFICATE_ERRORS as exc:
        raise ConfigurationError("invalid local trust anchor") from exc
    return roots


def load_credentials(chain_path: Path, key_path: Path, server_name: str,
                     *, signature_provider=None, signature_issuers=()) -> Credentials:
    """Check an operator's own X25519 key and ordered local credential bundle.

    The last configured issuer is a temporary *local consistency* anchor only:
    it is not installed into any remote-peer trust store. This allows normal
    fullchain files that omit their root; clients still require independent
    anchors and perform their own complete path/identity/evidence validation.
    """
    certs = _pem_certificates(_read_file(Path(chain_path), MAX_PEM_FILE), MAX_CERTIFICATES, general_pkix=True)
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
        validate_service_identity(server_name)
        chain_der = [cert.public_bytes(serialization.Encoding.DER) for cert in certs]
        # Local files are an ordered chain, not an arbitrary bag silently
        # reduced to one valid subset by a path builder.
        for child, issuer in zip(certs, certs[1:]):
            if signature_provider is None:
                child.verify_directly_issued_by(issuer)
            else:
                if child.issuer != issuer.subject:
                    raise ConfigurationError("local credential bundle is not in issuer order")
                verify_public_signature(certificate_public_key(issuer, signature_provider=signature_provider),
                    certificate_signature_scheme(child, issuer), child.signature, child.tbs_certificate_bytes,
                    sm2_identifier=SM2_CERTIFICATE_IDENTIFIER, gost_certificate_encoding=True)
        leaf_key = validate_identity(chain_der, trust_roots=(certs[-1],),
            role="server", name=server_name, partial_chain=True, signature_provider=signature_provider,
            offered_certificate_algorithms=supported_certificate_algorithms(signature_provider))
        if leaf_key.public_bytes_raw() != key.public_key().public_bytes_raw():
            raise ConfigurationError("server certificate and private key do not match")
        # Validate explicitly supplied metadata now, but do not append it to
        # the transmitted chain or confer trust on any candidate.
        if not isinstance(signature_issuers, (tuple, list)) or len(signature_issuers) > 64:
            raise ConfigurationError("local signature issuer inventory exceeds bounds")
        local_issuers = tuple(issuer.public_bytes(serialization.Encoding.DER)
            if isinstance(issuer, x509.Certificate) else issuer for issuer in signature_issuers)
        if local_issuers and find_certificate_issuer(certs[-1], local_issuers,
                signature_provider=signature_provider) is None:
            raise ConfigurationError("no local signature issuer matches the final certificate")
        return Credentials(chain_der, key, signature_issuers=local_issuers)
    except _CERTIFICATE_ERRORS as exc:
        if isinstance(exc, ConfigurationError):
            raise
        raise ConfigurationError("invalid server credentials") from exc
