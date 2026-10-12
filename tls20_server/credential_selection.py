"""Certificate selection hints and constraints (RFC 9846 sections 4.3.4/5).

These helpers select local credentials; they do not establish trust, authorize
an identity, or replace proof of possession. CA names are preferences, not trust
anchors. OID filters are mandatory only for extension semantics understood here.
Certificate values are read through cryptography's X.509 provider.
"""

from __future__ import annotations

from collections.abc import Mapping

from cryptography import x509
from cryptography.x509.oid import ExtensionOID, ExtendedKeyUsageOID

from .errors import ProtocolError
from .pki import _load_pkix_der, certificate_extensions


CERTIFICATE_AUTHORITIES = 47
OID_FILTERS = 48
_KU = ExtensionOID.KEY_USAGE.dotted_string
_EKU = ExtensionOID.EXTENDED_KEY_USAGE.dotted_string


def _vector(value: bytes, width: int) -> bytes:
    if not isinstance(value, bytes) or len(value) >= 1 << (width * 8):
        raise ProtocolError("certificate selection vector overflow")
    return len(value).to_bytes(width, "big") + value


def _take(data: bytes, offset: int, width: int) -> tuple[bytes, int]:
    if offset + width > len(data):
        raise ProtocolError("truncated certificate selection vector", alert=50)
    size = int.from_bytes(data[offset:offset + width], "big")
    offset += width
    if size > len(data) - offset:
        raise ProtocolError("truncated certificate selection vector", alert=50)
    return data[offset:offset + size], offset + size


def _der(data: bytes, offset: int = 0, *, alert: int = 40) -> tuple[int, bytes, int]:
    """Minimal definite-length DER envelope, bounded by the enclosing vector.

    Wire-extension parsers select decode_error explicitly. Other consumers,
    including certificate evidence validation, retain their existing defaults.
    """
    if offset + 2 > len(data):
        raise ProtocolError("truncated selection DER", alert=alert)
    tag, size = data[offset:offset + 2]
    offset += 2
    if tag & 31 == 31:
        raise ProtocolError("unsupported selection DER tag", alert=alert)
    if size & 128:
        count = size & 127
        if not count or count > 3 or offset + count > len(data) or data[offset] == 0:
            raise ProtocolError("invalid selection DER length", alert=alert)
        size = int.from_bytes(data[offset:offset + count], "big")
        offset += count
        if size < 128:
            raise ProtocolError("non-minimal selection DER length", alert=alert)
    if size > len(data) - offset:
        raise ProtocolError("truncated selection DER value", alert=alert)
    return tag, data[offset:offset + size], offset + size


def _single_der(data: bytes, tag: int, *, alert: int = 40) -> bytes:
    actual, value, end = _der(data, alert=alert)
    if actual != tag or end != len(data):
        raise ProtocolError("unexpected selection DER structure", alert=alert)
    return value


def _oid(data: bytes, *, alert: int = 40) -> str:
    raw = _single_der(data, 6, alert=alert)
    if not raw:
        raise ProtocolError("empty selection OID", alert=alert)
    arcs, value, start = [], 0, True
    for item in raw:
        if start and item == 128:
            raise ProtocolError("non-minimal selection OID", alert=alert)
        value = (value << 7) | (item & 127)
        start = not bool(item & 128)
        if start:
            arcs.append(value)
            value = 0
    if not start:
        raise ProtocolError("truncated selection OID", alert=alert)
    first = min(arcs[0] // 40, 2)
    return ".".join(str(item) for item in (first, arcs[0] - 40 * first, *arcs[1:]))


def _length(value: bytes) -> bytes:
    size = len(value)
    if size < 128:
        return bytes((size,)) + value
    raw = size.to_bytes((size.bit_length() + 7) // 8, "big")
    return bytes((128 | len(raw),)) + raw + value


def _oid_der(value) -> bytes:
    if isinstance(value, bytes):
        _oid(value)
        return value
    try:
        oid = value if isinstance(value, x509.ObjectIdentifier) else x509.ObjectIdentifier(value)
        arcs = [int(item) for item in oid.dotted_string.split(".")]
    except (TypeError, ValueError, AttributeError) as exc:
        raise ProtocolError("invalid selection OID") from exc
    output = bytearray()
    for arc in (40 * arcs[0] + arcs[1], *arcs[2:]):
        current = [arc & 127]
        while arc >> 7:
            arc >>= 7
            current.insert(0, 128 | (arc & 127))
        output.extend(current)
    encoded = b"\x06" + _length(bytes(output))
    if len(encoded) > 255:
        raise ProtocolError("selection OID too large")
    return encoded


def _name(data: bytes, *, alert: int = 40) -> None:
    """Check DER Name framing without interpreting its authorization meaning."""
    sequence = _single_der(data, 48, alert=alert)
    offset = 0
    while offset < len(sequence):
        tag, rdn, offset = _der(sequence, offset, alert=alert)
        if tag != 49 or not rdn:
            raise ProtocolError("invalid authority RDN", alert=alert)
        cursor, previous = 0, b""
        while cursor < len(rdn):
            start = cursor
            tag, attribute, cursor = _der(rdn, cursor, alert=alert)
            encoded = rdn[start:cursor]
            if tag != 48 or (previous and encoded < previous):
                raise ProtocolError("invalid authority attribute or DER ordering", alert=alert)
            previous = encoded
            _, _, oid_end = _der(attribute, alert=alert)
            _oid(attribute[:oid_end], alert=alert)
            _, _, end = _der(attribute, oid_end, alert=alert)
            if end != len(attribute):
                raise ProtocolError("trailing authority attribute data", alert=alert)


def parse_certificate_authorities(data: bytes) -> tuple[bytes, ...]:
    names, end = _take(data, 0, 2)
    if end != len(data) or len(names) < 3:
        raise ProtocolError("invalid certificate_authorities list", alert=50)
    offset, output = 0, []
    while offset < len(names):
        value, offset = _take(names, offset, 2)
        if not value:
            raise ProtocolError("empty authority name", alert=50)
        try:
            _name(value)
        except ProtocolError as exc:
            # This only validates the offered Name's DER syntax; trust and
            # credential-selection policy are evaluated elsewhere.
            raise ProtocolError("invalid certificate_authorities name encoding", alert=50) from exc
        output.append(value)
    return tuple(output)


def encode_certificate_authorities(names) -> bytes:
    body = _vector(b"".join(_vector(name.public_bytes() if isinstance(name, x509.Name) else name, 2)
                              for name in names), 2)
    parse_certificate_authorities(body)
    return body


def _requested_usage(value: bytes) -> frozenset[int]:
    bits = _single_der(value, 3, alert=50)
    if not bits or bits[0] > 7 or (len(bits) == 1 and bits[0]) or len(bits) > 3:
        raise ProtocolError("invalid keyUsage filter", alert=50)
    unused, raw = bits[0], bits[1:]
    if raw and (raw[-1] & ((1 << unused) - 1) or raw[-1] == 0):
        raise ProtocolError("non-minimal keyUsage filter", alert=50)
    if raw and unused != (raw[-1] & -raw[-1]).bit_length() - 1:
        raise ProtocolError("non-minimal keyUsage filter bit length", alert=50)
    count = len(raw) * 8 - unused
    if count > 9:
        raise ProtocolError("undefined keyUsage filter bit", alert=47)
    return frozenset(index for index in range(count) if raw[index // 8] & (128 >> (index % 8)))


def _requested_eku(value: bytes) -> frozenset[str]:
    body = _single_der(value, 48, alert=50)
    if not body:
        raise ProtocolError("empty encoded extendedKeyUsage filter", alert=50)
    output, offset = set(), 0
    while offset < len(body):
        start = offset
        _, _, offset = _der(body, offset, alert=50)
        oid = _oid(body[start:offset], alert=50)
        if oid == ExtendedKeyUsageOID.ANY_EXTENDED_KEY_USAGE.dotted_string:
            raise ProtocolError("anyExtendedKeyUsage is forbidden in an OID filter", alert=47)
        output.add(oid)
    return frozenset(output)


def parse_oid_filters(data: bytes) -> tuple[tuple[str, bytes], ...]:
    body, end = _take(data, 0, 2)
    if end != len(data):
        raise ProtocolError("trailing oid_filters data", alert=50)
    output, seen, offset = [], set(), 0
    while offset < len(body):
        encoded_oid, offset = _take(body, offset, 1)
        value, offset = _take(body, offset, 2)
        oid = _oid(encoded_oid, alert=50)
        if oid in seen:
            raise ProtocolError("duplicate certificate extension OID filter", alert=47)
        seen.add(oid)
        if value and oid == _KU:
            _requested_usage(value)
        elif value and oid == _EKU:
            _requested_eku(value)
        output.append((oid, value))
    return tuple(output)


def encode_oid_filters(filters) -> bytes:
    parts = []
    for oid, value in filters:
        if isinstance(value, (x509.KeyUsage, x509.ExtendedKeyUsage)):
            value = value.public_bytes()
        parts.append(_vector(_oid_der(oid), 1) + _vector(value, 2))
    output = _vector(b"".join(parts), 2)
    parse_oid_filters(output)
    return output


def _request_extensions(extensions) -> dict[int, bytes]:
    result = {}
    for kind, value in (extensions.items() if isinstance(extensions, Mapping) else extensions):
        if kind in result:
            raise ProtocolError("duplicate certificate request extension")
        result[kind] = value
    if CERTIFICATE_AUTHORITIES in result:
        parse_certificate_authorities(result[CERTIFICATE_AUTHORITIES])
    if OID_FILTERS in result:
        parse_oid_filters(result[OID_FILTERS])
    return result


def _certificate_usage(value: x509.KeyUsage) -> frozenset[int]:
    flags = (value.digital_signature, value.content_commitment, value.key_encipherment,
             value.data_encipherment, value.key_agreement, value.key_cert_sign,
             value.crl_sign, value.encipher_only if value.key_agreement else False,
             value.decipher_only if value.key_agreement else False)
    return frozenset(index for index, enabled in enumerate(flags) if enabled)


def match_credentials(credentials, request_extensions) -> bool:
    """Apply mandatory recognized OID filters, not CA preference or trust.

    For delegated credentials the filters apply to the delegating certificate.
    A raw public key has no certificate extensions and cannot satisfy KU/EKU
    presence requirements. Unknown extension semantics are explicitly ignored.
    """
    extensions = _request_extensions(request_extensions)
    filters = parse_oid_filters(extensions.get(OID_FILTERS, b"\0\0"))
    recognized = [(oid, value) for oid, value in filters if oid in (_KU, _EKU)]
    if not recognized:
        return True
    if credentials.credential_type != 0 or not credentials.chain_der:
        return False
    cert = _load_pkix_der(credentials.chain_der[0])
    for oid, requested in recognized:
        try:
            actual = certificate_extensions(cert).get_extension_for_oid(x509.ObjectIdentifier(oid)).value
        except x509.ExtensionNotFound:
            return False
        if not requested:
            continue
        if oid == _KU and not _requested_usage(requested) <= _certificate_usage(actual):
            return False
        if oid == _EKU and not _requested_eku(requested) <= {item.dotted_string for item in actual}:
            return False
    return True


def credential_algorithms_match(credentials, request_extensions, *, role,
                                signature_provider=None, entry_extensions=None) -> bool:
    """Select independent path/grant algorithms; invalid local material raises.

    This checks compatibility, not peer trust. Non-X.509 representations retain
    their own native algorithms and are validated by their credential provider.
    """
    from . import crypto as c, messages as m
    from .credential_profiles import validate_delegation
    from .handshake import _check_certificate_offer, _credential_extensions
    from .pki import supported_certificate_algorithms
    if role not in ("server", "client"):
        raise ValueError("credential selection requires an explicit direction")
    if credentials.credential_type != 0:
        return True
    offered = _request_extensions(request_extensions)
    m.validate_delegation_offer(offered)
    metadata = _credential_extensions(credentials) if entry_extensions is None else entry_extensions
    if not credentials.chain_der or len(metadata) != len(credentials.chain_der):
        raise ProtocolError("invalid local certificate chain or entry metadata")
    for index, pairs in enumerate(metadata):
        values = m.extensions(b"".join(m.extension(kind, value) for kind, value in pairs), context="CE")
        if index and 34 in values:
            raise ProtocolError("misplaced local delegated credential")
    matches = _check_certificate_offer(credentials.chain_der,
        m._u16_list(offered[50]) if 50 in offered else (), signature_provider,
        credentials.signature_issuers, require_match=False)
    grant = dict(metadata[0]).get(34)
    if grant is not None:
        # Validate first, against local capabilities. A malformed or wrong-key
        # grant is not an ordinary refusal merely because its scheme is absent.
        key, _ = validate_delegation(credentials.chain_der[0], grant, role=role,
            grant_algorithms=supported_certificate_algorithms(signature_provider),
            delegated_schemes=(0xfe00 if role == "server" else 0xfe01,),
            signature_provider=signature_provider)
        reader = m._Reader(grant)
        reader.take(6); reader.vector(3)
        scheme = int.from_bytes(reader.take(2), "big")
        matches = matches and 34 in offered and (0xfe00 if role == "server" else 0xfe01) in m._u16_list(offered[34])
        matches = matches and scheme in m._u16_list(offered[0xff04])
    else:
        key = _load_pkix_der(credentials.chain_der[0]).public_key()
    if c.public_bytes(key) != c.public_bytes(credentials.private_key):
        raise ProtocolError("local credential does not match its private key")
    return matches


def preferred_credentials(candidates, request_extensions, *, role=None, signature_provider=None) -> tuple:
    """Stable candidates satisfying OID filters, preferred CA matches first.

    A leaf issuer matches even when the CA is omitted from the outgoing chain.
    Other CA names match actual CA subjects only, never a non-CA leaf subject.
    RPKs are neutral to CA preferences. A role additionally filters by independent
    path/grant offers before ranking. This function does not authorize peers.
    """
    extensions = _request_extensions(request_extensions)
    names = set(parse_certificate_authorities(extensions[CERTIFICATE_AUTHORITIES])) if CERTIFICATE_AUTHORITIES in extensions else set()
    ranked = []
    for credential in candidates:
        if role is not None and not credential_algorithms_match(credential, extensions,
                role=role, signature_provider=signature_provider):
            continue
        if not match_credentials(credential, extensions):
            continue
        preferred = not names or credential.credential_type != 0
        if names and credential.credential_type == 0 and credential.chain_der:
            certificates = [_load_pkix_der(value) for value in credential.chain_der]
            preferred = certificates[0].issuer.public_bytes() in names
            for cert in certificates[1:]:
                try:
                    is_ca = certificate_extensions(cert).get_extension_for_class(x509.BasicConstraints).value.ca
                except x509.ExtensionNotFound:
                    is_ca = False
                preferred |= is_ca and cert.subject.public_bytes() in names
        ranked.append((not preferred, credential))
    return tuple(item[1] for item in sorted(ranked, key=lambda item: item[0]))
