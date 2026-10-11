"""Read policy-relevant extensions without a closed TLSFeature registry.

The original certificate object/DER is never changed. Signature and PKIX checks
still use that exact object. These accessors only decode fields needed by local
policy; they neither build a certificate nor establish trust.
"""

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import ExtensionOID
import ipaddress

from .errors import ProtocolError


def _one(encoded, expected):
    from .pki import _element
    tag, body, end, _ = _element(encoded)
    if tag != expected or end != len(encoded):
        raise ProtocolError("invalid certificate extension DER")
    return body


def _oid(body):
    if not body:
        raise ProtocolError("empty certificate extension OID")
    arcs, value, start = [], 0, True
    for octet in body:
        if start and octet == 128:
            raise ProtocolError("nonminimal certificate extension OID")
        value = (value << 7) | (octet & 127)
        start = not octet & 128
        if start:
            arcs.append(value)
            value = 0
    if not start:
        raise ProtocolError("truncated certificate extension OID")
    first = min(arcs[0] // 40, 2)
    return x509.ObjectIdentifier(".".join(map(str, (first, arcs[0] - first * 40, *arcs[1:]))))


def _integer(body):
    if (not body or body[0] & 128 or len(body) > 1 and body[0] == 0 and not body[1] & 128):
        raise ProtocolError("invalid nonnegative certificate extension integer")
    return int.from_bytes(body, "big")


def raw_extensions(cert):
    """Canonical, duplicate-free (OID, critical, extnValue) inventory."""
    from .pki import _children, _element, MAX_CERT
    encoded = cert.public_bytes(serialization.Encoding.DER)
    if not 1 <= len(encoded) <= MAX_CERT:
        raise ProtocolError("certificate exceeds extension parser budget")
    outer = _children(_one(encoded, 48))
    if len(outer) != 3 or outer[0][0] != 48:
        raise ProtocolError("invalid certificate extension envelope")
    fields = _children(outer[0][1])
    found, seen, result = False, set(), []
    for index, (tag, body, _) in enumerate(fields):
        if tag != 0xa3:
            continue
        if found or index != len(fields) - 1:
            raise ProtocolError("duplicate or misplaced certificate extensions")
        found = True
        entries = _children(_one(body, 48))
        if not entries:
            raise ProtocolError("empty certificate Extensions sequence")
        for kind, value, _ in entries:
            parts = _children(value)
            if kind != 48 or not 2 <= len(parts) <= 3 or parts[0][0] != 6:
                raise ProtocolError("invalid certificate Extension structure")
            oid = _oid(parts[0][1])
            if oid in seen:
                raise ProtocolError("duplicate certificate extension")
            seen.add(oid)
            critical = len(parts) == 3
            if critical and parts[1][2] != b"\x01\x01\xff":
                raise ProtocolError("noncanonical certificate extension criticality")
            if parts[-1][0] != 4:
                raise ProtocolError("certificate extension value is not an OCTET STRING")
            result.append((oid, critical, parts[-1][1]))
    return tuple(result)


def _name(encoded):
    from .pki import _children
    names = []
    for tag, rdn, _ in _children(_one(encoded, 48)):
        if tag != 49 or not rdn:
            raise ProtocolError("invalid directoryName RDN")
        attributes, previous = [], b""
        for kind, body, raw in _children(rdn):
            parts = _children(body)
            if kind != 48 or len(parts) != 2 or parts[0][0] != 6 or previous and raw < previous:
                raise ProtocolError("invalid directoryName attribute")
            previous = raw
            oid = _oid(parts[0][1])
            codec = {12: "utf-8", 18: "ascii", 19: "ascii", 20: "latin1", 22: "ascii",
                     26: "ascii", 28: "utf-32-be", 30: "utf-16-be"}.get(parts[1][0])
            if codec is None:
                raise ProtocolError("unsupported directoryName string encoding")
            text = parts[1][1].decode(codec)
            # Name equality is defined by attributes, not their ASN.1 string
            # tag. Original DER remains available for signature/path validation.
            attributes.append(x509.NameAttribute(oid, text))
        names.append(x509.RelativeDistinguishedName(attributes))
    return x509.Name(names)


def _general_names(body):
    from .pki import _children
    result = []
    for tag, value, _ in _children(body):
        if tag in (0x81, 0x82, 0x86):
            text = value.decode("ascii")
            result.append({0x81: x509.RFC822Name, 0x82: x509.DNSName, 0x86: x509.UniformResourceIdentifier}[tag](text))
        elif tag == 0x87:
            if len(value) not in (4, 16):
                raise ProtocolError("invalid subjectAltName IP address")
            result.append(x509.IPAddress(ipaddress.ip_address(value)))
        elif tag == 0xa4:
            result.append(x509.DirectoryName(_name(value)))
        elif tag == 0x88:
            result.append(x509.RegisteredID(_oid(value)))
        elif tag == 0xa0:
            parts = _children(value)
            if len(parts) != 2 or parts[0][0] != 6 or parts[1][0] != 0xa0:
                raise ProtocolError("invalid otherName")
            # The explicit value must contain exactly one complete DER TLV.
            from .pki import _element
            _, _, end, _ = _element(parts[1][1])
            if end != len(parts[1][1]):
                raise ProtocolError("trailing otherName value")
            result.append(x509.OtherName(_oid(parts[0][1]), parts[1][1]))
        else:
            raise ProtocolError("unsupported certificate GeneralName")
    if not result:
        raise ProtocolError("empty certificate GeneralNames")
    return result


def _decode(oid, value):
    from .pki import _children
    if oid == ExtensionOID.BASIC_CONSTRAINTS:
        fields = _children(_one(value, 48))
        ca = bool(fields and fields[0][0] == 1)
        if ca:
            if fields.pop(0)[2] != b"\x01\x01\xff":
                raise ProtocolError("noncanonical BasicConstraints boolean")
        path = None
        if fields:
            if len(fields) != 1 or fields[0][0] != 2 or not ca:
                raise ProtocolError("invalid BasicConstraints path length")
            path = _integer(fields[0][1])
        return x509.BasicConstraints(ca, path)
    if oid == ExtensionOID.KEY_USAGE:
        bits = _one(value, 3)
        if not bits or bits[0] > 7 or len(bits) > 3:
            raise ProtocolError("invalid KeyUsage BIT STRING")
        unused, raw = bits[0], bits[1:]
        if not raw or raw[-1] == 0 or raw[-1] & ((1 << unused) - 1):
            raise ProtocolError("nonminimal KeyUsage BIT STRING")
        if unused != (raw[-1] & -raw[-1]).bit_length() - 1 or len(raw) * 8 - unused > 9:
            raise ProtocolError("invalid KeyUsage named bits")
        flags = tuple(index < len(raw) * 8 - unused and bool(raw[index // 8] & (128 >> (index % 8))) for index in range(9))
        if (flags[7] or flags[8]) and not flags[4]:
            raise ProtocolError("KeyUsage only flags require key agreement")
        return x509.KeyUsage(*flags)
    if oid == ExtensionOID.EXTENDED_KEY_USAGE:
        fields = _children(_one(value, 48))
        if not fields or any(tag != 6 for tag, _, _ in fields):
            raise ProtocolError("invalid ExtendedKeyUsage")
        return x509.ExtendedKeyUsage([_oid(body) for _, body, _ in fields])
    if oid == ExtensionOID.SUBJECT_ALTERNATIVE_NAME:
        return x509.SubjectAlternativeName(_general_names(_one(value, 48)))
    if oid == ExtensionOID.SUBJECT_KEY_IDENTIFIER:
        return x509.SubjectKeyIdentifier(_one(value, 4))
    if oid == ExtensionOID.AUTHORITY_KEY_IDENTIFIER:
        key, names, serial, previous = None, None, None, -1
        for tag, body, _ in _children(_one(value, 48)):
            number = {0x80: 0, 0xa1: 1, 0x82: 2}.get(tag)
            if number is None or number <= previous:
                raise ProtocolError("invalid AuthorityKeyIdentifier fields")
            previous = number
            if number == 0:
                key = body
            elif number == 1:
                names = _general_names(body)
            else:
                serial = _integer(body)
        return x509.AuthorityKeyIdentifier(key, names, serial)
    # TLSFeature is intentionally not converted to cryptography.TLSFeature:
    # the extension registry is open. tls_features.py interprets its integers.
    return x509.UnrecognizedExtension(oid, value)


def certificate_extensions(cert):
    """Return compatible extension accessors, preserving unknown TLSFeature IDs.

    Prefer the library's complete decoder. Its specific closed-registry
    KeyError is the only fallback: malformed certificates are not retried with
    a more lenient certificate. The fallback strictly decodes the signed DER.
    """
    raw = raw_extensions(cert)
    try:
        return cert.extensions
    except KeyError:
        feature = next((value for oid, _, value in raw if oid == ExtensionOID.TLS_FEATURE), None)
        if feature is None:
            raise ProtocolError("unsupported certificate extension decoder") from None
        from .tls_features import certificate_features
        if not certificate_features(cert).difference((5, 17)):
            raise ProtocolError("invalid certificate extension decoder result") from None
        try:
            return x509.Extensions([x509.Extension(oid, critical, _decode(oid, value)) for oid, critical, value in raw])
        except (ValueError, TypeError, UnicodeError) as exc:
            raise ProtocolError("invalid certificate extension value") from exc
