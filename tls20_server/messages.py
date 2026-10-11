"""Bounded RFC-shaped TLS 2.0 codecs; certificate trust is a separate operation."""

from __future__ import annotations

from dataclasses import dataclass
import ipaddress
import re

from .errors import ProtocolError
from . import crypto as c
from .credential_selection import parse_certificate_authorities, parse_oid_filters
from .status_request import parse_status_request

HANDSHAKE_TYPES = frozenset((1, 2, 4, 5, 8, 11, 13, 15, 20, 24, 25, 252, 253))
MAX_HANDSHAKE_BODY = 1 << 18
HTTP_PROTOCOL = b"http/1.1"
PARAMETERS = b"\x13\x01\x00\x1d"
VERSION = b"\x04\x00"
CERT_ALGORITHMS = (0x0807, 0x0808, 0x0403, 0x0503, 0x0603,
                   0x0401, 0x0501, 0x0601, 0x0804, 0x0805, 0x0806, 0x0809, 0x080a, 0x080b,
                   0x081a, 0x081b, 0x081c)
HRR_RANDOM = bytes.fromhex("cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c")


def validate_name(name: str) -> str:
    try:
        wire = name.encode("ascii")
    except (UnicodeEncodeError, AttributeError) as exc:
        raise ProtocolError("server name must be lowercase ASCII DNS") from exc
    if not 1 <= len(wire) <= 253:
        raise ProtocolError("server name length")
    for label in name.split("."):
        if not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label):
            raise ProtocolError("invalid DNS label")
        if label.startswith("xn--"):
            try:
                decoded = label.encode("ascii").decode("idna")
                if decoded.encode("idna").decode("ascii") != label:
                    raise UnicodeError("A-label does not round trip")
            except UnicodeError as exc:
                raise ProtocolError("invalid DNS A-label") from exc
    try:
        ipaddress.ip_address(name)
    except ValueError:
        pass
    else:
        raise ProtocolError("IP identities are not supported")
    # Numeric dotted quad variants must not be interpreted as DNS identities.
    if len(name.split(".")) == 4 and all(part.isdigit() for part in name.split(".")):
        raise ProtocolError("IP identities are not supported")
    return name


def validate_service_identity(name: str) -> str:
    """Validate a canonical reference identity, separately from DNS-only SNI.

    IP references are authenticated by iPAddress SANs or explicit RPK/PSK
    provisioning. They are never encoded as an SNI host_name or DNSName SAN.
    Brackets and interface scope IDs belong to URLs/routing, not certificates.
    """
    if not isinstance(name, str) or "%" in name:
        raise ProtocolError("invalid service identity")
    try:
        address = ipaddress.ip_address(name)
    except ValueError:
        return validate_name(name)
    if str(address) != name:
        raise ProtocolError("IP service identity must be canonical")
    return name


def is_ip_identity(name: str) -> bool:
    try:
        ipaddress.ip_address(name)
        return True
    except ValueError:
        return False


def _vec(data: bytes, width: int) -> bytes:
    if len(data) >= 1 << (8 * width):
        raise ProtocolError("vector length overflow")
    return len(data).to_bytes(width, "big") + data


def _protocol(protocol: bytes) -> None:
    if not isinstance(protocol, bytes) or not 1 <= len(protocol) <= 255:
        raise ProtocolError("application protocol length")


class _Reader:
    def __init__(self, data: bytes):
        self.data, self.position = data, 0

    def take(self, length: int) -> bytes:
        if length < 0 or length > len(self.data) - self.position:
            raise ProtocolError("truncated message", alert=50)
        value = self.data[self.position:self.position + length]
        self.position += length
        return value

    def vector(self, width: int) -> bytes:
        return self.take(int.from_bytes(self.take(width), "big"))

    def end(self) -> None:
        if self.position != len(self.data):
            raise ProtocolError("trailing message data", alert=50)


def frame(kind: int, body: bytes) -> bytes:
    if kind not in HANDSHAKE_TYPES or len(body) > MAX_HANDSHAKE_BODY:
        raise ProtocolError("invalid handshake type or length")
    if kind == 20 and len(body) not in (32, 48):
        raise ProtocolError("Finished body must have the negotiated hash length", alert=50)
    if kind == 15 and (len(body) not in (36, 52) or body[:2] not in (b"\xfe\x00", b"\xfe\x01")
                       or int.from_bytes(body[2:4], "big") != len(body) - 4):
        raise ProtocolError("MAC envelope", alert=50)
    if kind == 5 and body:
        raise ProtocolError("EndOfEarlyData must be empty", alert=50)
    if kind == 24 and body not in (b"\x00", b"\x01"):
        raise ProtocolError("KeyUpdate request value", alert=47)
    return bytes((kind,)) + len(body).to_bytes(3, "big") + body


def decode_frame(wire: bytes) -> tuple[int, bytes]:
    if len(wire) < 4 or int.from_bytes(wire[1:4], "big") != len(wire) - 4:
        raise ProtocolError("handshake envelope length", alert=50)
    frame(wire[0], wire[4:])
    return wire[0], wire[4:]


@dataclass(frozen=True)
class ClientHello:
    name: str
    protocol: bytes
    A: bytes
    B: bytes
    random: bytes
    session_id: bytes = b""
    certificate_algorithms: tuple[int, ...] = ()
    psk_identity: bytes = b""
    psk_age: int = 0
    binder: bytes = b""
    early_data: bool = False
    extensions: tuple[int, ...] = ()
    group: int = 0x001d
    groups: tuple[int, ...] = ()
    extension_values: tuple = ()
    fixed_hello: bytes = b""
    psk_offers: tuple = ()
    binder_vector_size: int = 0
    share_groups: tuple[int, ...] = ()
    cipher_suites: tuple[int, ...] = (0x1301,)
    psk_modes: tuple[int, ...] = ()
    protocols: tuple[bytes, ...] = ()


def extension(kind: int, data: bytes) -> bytes:
    return kind.to_bytes(2, "big") + _vec(data, 2)


def extensions(data: bytes, *, context=None) -> dict[int, bytes]:
    r = _Reader(data)
    result = {}
    while r.position < len(data):
        kind = int.from_bytes(r.take(2), "big")
        value = r.vector(2)
        if kind in result or kind == 13:
            raise ProtocolError("duplicate or forbidden extension", alert=47)
        result[kind] = value
    if context is not None:
        validate_extension_context(result, context)
    return result


# Known TLS 2.0 extension placements. Unknown offers remain ignorable; known
# extensions cannot be smuggled into an unrelated message, even if the caller
# chooses not to use that optional facility. SH/EE additionally enforce offers.
_EXTENSION_CONTEXTS = {
    0: {"CH", "EE", "ASR"}, 1: {"CH", "EE"},
    5: {"CH", "CR", "ASR", "ACR", "CE"}, 10: {"CH", "EE"},
    13: set(), 15: {"CH", "EE"}, 16: {"CH", "EE"},
    17: {"CH"}, 18: {"CH", "CR", "ASR", "ACR", "CE"},
    19: {"CH", "EE"}, 20: {"CH", "EE"}, 21: {"CH"},
    25: {"CH", "EE"}, 27: {"CH", "CR"}, 28: {"CH", "EE"},
    29: {"CH"}, 30: {"CH"}, 31: {"HRR"}, 32: {"CH", "EE"},
    33: {"CH", "SH"}, 34: {"CH", "CR", "ASR", "ACR", "CE"},
    41: {"CH", "SH"}, 42: {"CH", "EE", "NST"},
    43: {"CH", "SH", "HRR"}, 44: {"CH", "HRR"}, 45: {"CH"},
    47: {"CH", "CR", "ASR", "ACR"}, 48: {"CR", "ASR", "ACR"},
    49: {"CH"}, 50: {"CH", "CR", "ASR", "ACR"},
    51: {"CH", "SH", "HRR"}, 52: {"CH", "CR", "ASR", "ACR", "CE"},
    55: {"CH", "EE"}, 56: {"CH", "EE"}, 58: {"CH", "EE"},
    59: {"CH", "CE"}, 0xff02: {"CH", "ASR"},
    0xff03: {"CR", "ACR"}, 0xff04: {"CH", "CR", "ASR", "ACR"},
}


def validate_extension_context(values, context):
    for kind in values:
        if kind in _EXTENSION_CONTEXTS and context not in _EXTENSION_CONTEXTS[kind]:
            raise ProtocolError("extension in a forbidden message context", alert=47)


def validate_delegation_offer(values):
    if 34 in values and (50 not in values or 0xff04 not in values):
        raise ProtocolError("delegation requires certificate and grant signature offers", alert=109)
    if 0xff04 in values and 34 not in values:
        raise ProtocolError("grant signature offer requires delegation", alert=47)
    for kind in (50, 0xff04):
        if kind in values:
            algorithms = _u16_list(values[kind])
            if set(algorithms) & {0xfe00, 0xfe01, 0x0420, 0x0520, 0x0620}:
                raise ProtocolError("online proof identifier in public signature offer", alert=47)
    if 34 in values:
        _u16_list(values[34])


def _u16_list(data: bytes) -> tuple[int, ...]:
    r = _Reader(data)
    value = r.vector(2)
    r.end()
    if not value or len(value) % 2:
        raise ProtocolError("invalid uint16 list", alert=50)
    return tuple(int.from_bytes(value[i:i + 2], "big") for i in range(0, len(value), 2))


def pwd_share_valid(group, share):
    if group in c.ffdhe.SIZES:
        width=c.ffdhe.SIZES[group]
        length=int.from_bytes(share[width:width+2],"big")
        return bool(1<=length<=width and len(share)==width+2+length)
    width = {23: 32, 24: 48, 25: 66}.get(group)
    return bool(width and len(share) >= 2 * width + 2
                and 1 <= share[2 * width] <= width
                and len(share) == 2 * width + 1 + share[2 * width])


def client_hello(A: bytes, B: bytes, name: str, random: bytes,
                 protocol: bytes = HTTP_PROTOCOL, *, identity: bytes = b"",
                 age: int = 0, binder: bytes = b"", early_data: bool = False,
                 group: int = 0x001d, empty_share: bool = False, cookie: bytes = b"",
                 session_id: bytes = b"", post_handshake_auth: bool = False,
                 cipher_suites: tuple[int, ...] = (0x1301,),
                 supported_groups: tuple[int, ...] = (29, 23, 24, 25, 30, 31, 32, 33, 4588, 4587, 4589, 256, 257, 258, 259, 260),
                 psk_modes: tuple[int, ...] = (1,), psk_offers=(), combined_psk=False,
                 extra_extensions=(), certificate_algorithms=CERT_ALGORITHMS,
                 password_authenticated=False) -> bytes:
    if name:
        validate_name(name)
    protocols = (protocol,) if isinstance(protocol, bytes) else tuple(protocol)
    for value in protocols:
        _protocol(value)
    valid_share = pwd_share_valid(group, B) if password_authenticated else len(B) == c.GROUP_LENGTHS.get(group)
    if ((A and len(A) != 32) or (group and (not empty_share and not valid_share
            or group not in supported_groups)) or (not group and B) or len(random) != 32
            or (A and A == c.traffic_auth_component(group, B)) or len(session_id) > 32
            or not cipher_suites or not psk_modes):
        raise ProtocolError("invalid client shares or random")
    ext = extension(0, _vec(b"\x00" + _vec(name.encode("ascii"), 2), 2)) if name else b""
    ext += extension(43, b"\x02" + VERSION)
    if group:
        ext += extension(10, _vec(b"".join(x.to_bytes(2, "big") for x in supported_groups), 2))
        ext += extension(51, _vec(b"" if empty_share else group.to_bytes(2, "big") + _vec(B, 2), 2))
    if certificate_algorithms:
        ext += extension(50, _vec(b"".join(x.to_bytes(2, "big") for x in certificate_algorithms), 2))
    if A:
        ext += extension(0xff02, A)
    if protocols:
        ext += extension(16, _vec(b"".join(_vec(value, 1) for value in protocols), 2))
    ext += extension(45, _vec(bytes(psk_modes), 1))
    if post_handshake_auth:
        ext += extension(49, b"")
    if cookie:
        ext += extension(44, _vec(cookie, 2))
    offers = tuple(psk_offers) if psk_offers else ((identity, age, binder),) if identity else ()
    if combined_psk:
        if not offers or not A or not group or early_data:
            raise ProtocolError("combined PSK requires credentials and DHE, without early data")
        ext += extension(33, b"")
    for kind, data in extra_extensions:
        ext += extension(kind, data)
    if early_data:
        if not offers:
            raise ProtocolError("early data requires a PSK")
        ext += extension(42, b"")
    if offers:
        if any(not ident or len(proof) not in (32, 48) or not 0 <= obfuscated < 1 << 32
               for ident, obfuscated, proof in offers):
            raise ProtocolError("invalid PSK identity, binder or age")
        ext += extension(41, _vec(b"".join(_vec(ident, 2) + obfuscated.to_bytes(4, "big")
                             for ident, obfuscated, _ in offers), 2)
                         + _vec(b"".join(_vec(proof, 1) for _, _, proof in offers), 2))
    extensions(ext)  # Duplicate/forbidden extensions are never emitted.
    return frame(1, b"\x03\x03" + random + _vec(session_id, 1)
                 + _vec(b"".join(x.to_bytes(2, "big") for x in cipher_suites), 2)
                 + b"\x01\x00" + _vec(ext, 2))


def parse_client_hello(body: bytes, *, enabled_groups=None, password_authenticated=None) -> ClientHello:
    r = _Reader(body)
    if r.take(2) != b"\x03\x03":
        raise ProtocolError("invalid ClientHello legacy version", alert=70)
    random = r.take(32)
    sid = r.vector(1)
    if len(sid) > 32:
        raise ProtocolError("legacy session id length", alert=50)
    suites = r.vector(2)
    if not suites or len(suites) % 2:
        raise ProtocolError("invalid cipher suite offer", alert=50)
    cipher_suites = tuple(int.from_bytes(suites[i:i+2], "big") for i in range(0, len(suites), 2))
    if not any(value in c.CIPHER_SUITES for value in cipher_suites):
        raise ProtocolError("no supported cipher suite")
    if r.vector(1) != b"\x00":
        raise ProtocolError("invalid legacy compression", alert=47)
    fixed_hello = body[:r.position]
    ext = extensions(r.vector(2))
    r.end()
    validate_extension_context(ext, "CH")
    validate_delegation_offer(ext)
    if 5 in ext:
        parse_status_request(ext[5])
    if 47 in ext:
        parse_certificate_authorities(ext[47])
    if 48 in ext:
        raise ProtocolError("oid_filters is only permitted in CertificateRequest", alert=47)
    if 0xff03 in ext or 49 in ext and ext[49]:
        raise ProtocolError("wrong-role auth share or malformed post_handshake_auth", alert=50)
    for required in (43,):
        if required not in ext:
            raise ProtocolError("missing required ClientHello extension", alert=109)
    vr = _Reader(ext[43]); versions = vr.vector(1); vr.end()
    if not versions or len(versions) % 2:
        raise ProtocolError("invalid supported_versions", alert=50)
    if VERSION not in [versions[i:i+2] for i in range(0, len(versions), 2)]:
        raise ProtocolError("unsupported protocol version", alert=70)
    groups = _u16_list(ext[10]) if 10 in ext else ()
    if groups and not set(groups) & c.GROUP_LENGTHS.keys():
        raise ProtocolError("no supported traffic group")
    sr = _Reader(ext.get(51, b"\x00\x00")); shares = _Reader(sr.vector(2)); sr.end()
    names = {29, 30} & set(ext)
    pwd_suites = [c.suite(value) for value in cipher_suites if value in c.CIPHER_SUITES
                  and c.suite(value).password_authenticated]
    if names:
        if len(names) != 1 or not pwd_suites or 51 not in ext:
            raise ProtocolError("invalid password authentication offer", alert=47)
        nr = _Reader(ext[next(iter(names))]); username = nr.vector(1); nr.end()
        if not username:
            raise ProtocolError("empty password account identity", alert=47)
    if password_authenticated is None:
        pwd_only = all(value in c.CIPHER_SUITES and c.suite(value).password_authenticated
                       for value in cipher_suites)
        password_authenticated = bool(names and pwd_only and len({value.hash_name for value in pwd_suites}) == 1)
        if names and shares.data and not password_authenticated:
            raise ProtocolError("mixed PWD hashes or modes require empty initial key shares", alert=47)
    seen, shares_by_group = set(), {}
    while shares.position < len(shares.data):
        group = int.from_bytes(shares.take(2), "big")
        share = shares.vector(2)
        if group in seen:
            raise ProtocolError("duplicate key share", alert=47)
        seen.add(group)
        if group not in groups:
            raise ProtocolError("key share not in supported_groups", alert=47)
        if group in c.GROUP_LENGTHS:
            if not (pwd_share_valid(group, share) if password_authenticated else len(share) == c.GROUP_LENGTHS[group]):
                raise ProtocolError("traffic share length", alert=47)
            shares_by_group[group] = share
    preference = (29, 23, 24, 25, 30, 31, 32, 33, 41, 34,35,36,37,38,39,40,4588,4587,4589,256,257,258,259,260)
    if enabled_groups is not None:
        preference = tuple(value for value in preference if value in enabled_groups)
    group = next((value for value in preference if value in shares_by_group),
                 next((value for value in preference if value in groups), 0))
    B = shares_by_group.get(group, b"")
    A = ext.get(0xff02, b"")
    if 0xff02 in ext and len(A) != 32:
        raise ProtocolError("invalid authentication share length", alert=50)
    if A and B and A == c.traffic_auth_component(group, B):
        raise ProtocolError("invalid independent key shares", alert=47)
    name = ""
    if 0 in ext:
        nr = _Reader(ext[0]); names = _Reader(nr.vector(2)); nr.end()
        if names.take(1) != b"\x00":
            raise ProtocolError("unsupported name type", alert=47)
        try:
            name = names.vector(2).decode("ascii")
        except UnicodeDecodeError as exc:
            raise ProtocolError("non-ASCII server name", alert=47) from exc
        validate_name(name)
        names.end()
    if 59 in ext and (0 not in ext or len(ext[59]) != 2 or ext[59] == b"\x00\x00"):
        raise ProtocolError("DNSSEC chain requires DNS SNI and an exact nonzero service port", alert=50)
    offered = []
    if 16 in ext:
        pr = _Reader(ext[16]); protocols = _Reader(pr.vector(2)); pr.end()
        while protocols.position < len(protocols.data):
            value = protocols.vector(1); _protocol(value); offered.append(value)
        if not offered:
            raise ProtocolError("empty ALPN offer", alert=50)
    protocol = HTTP_PROTOCOL if HTTP_PROTOCOL in offered else offered[0] if offered else b""
    cert_algs = _u16_list(ext[50]) if 50 in ext else ()
    if any(value in (0xfe00, 0xfe01, 0x0420, 0x0520, 0x0620) for value in cert_algs):
        raise ProtocolError("invalid certificate signature scheme", alert=47)
    identity, age, binder = b"", 0, b""
    offers, binder_size = [], 0
    modes = b""
    if 45 in ext:
        mr = _Reader(ext[45]); modes = mr.vector(1); mr.end()
        if not modes:
            raise ProtocolError("empty PSK modes", alert=50)
    if 41 in ext:
        if 45 not in ext:
            raise ProtocolError("PSK offer requires key exchange modes", alert=109)
        if list(ext)[-1] != 41:
            raise ProtocolError("PSK must be the last ClientHello extension", alert=47)
        p = _Reader(ext[41]); ids = _Reader(p.vector(2)); bs = _Reader(p.vector(2)); p.end()
        identities = []
        while ids.position < len(ids.data):
            value = ids.vector(2); obfuscated = int.from_bytes(ids.take(4), "big")
            if not value:
                raise ProtocolError("empty PSK identity", alert=50)
            identities.append((value, obfuscated))
        binders = []
        while bs.position < len(bs.data):
            value = bs.vector(1)
            if len(value) < 32:
                raise ProtocolError("invalid binder size", alert=50)
            binders.append(value)
        if not identities or len(identities) != len(binders):
            raise ProtocolError("PSK identities and binders differ", alert=47)
        offers = [(value, obfuscated, proof) for (value, obfuscated), proof in zip(identities, binders)]
        identity, age, binder = offers[0]
        binder_size = 2 + len(bs.data)
    if 42 in ext and (ext[42] or not identity):
        raise ProtocolError("invalid early_data offer", alert=47)
    if (not identity or 0 not in modes) and (10 not in ext or 51 not in ext):
        raise ProtocolError("DHE requires supported_groups and key_share", alert=109)
    if 33 in ext and (ext[33] or not identity or 1 not in modes or 42 in ext):
        raise ProtocolError("invalid combined PSK offer", alert=47)
    return ClientHello(name, protocol, A, B, random, sid, cert_algs,
                       identity, age, binder, 42 in ext, tuple(ext), group, groups,
                       tuple(ext.items()), fixed_hello, tuple(offers), binder_size, tuple(seen),
                       cipher_suites, tuple(modes), tuple(offered))


def server_hello(E: bytes, random: bytes, *, session_id: bytes = b"", resumed: bool = False,
                 group: int = 0x001d, retry: bool = False, selected_identity: int = 0,
                 cipher_suite: int = 0x1301, combined_psk=False, password_salt=None, cookie=b"") -> bytes:
    pwd = c.suite(cipher_suite).password_authenticated
    valid_share = pwd_share_valid(group, E) if pwd else len(E) == c.SERVER_GROUP_LENGTHS.get(group)
    if (not retry and group and not valid_share) or len(random) != 32:
        raise ProtocolError("invalid server share or random")
    if len(session_id) > 32:
        raise ProtocolError("legacy session id length", alert=50)
    ext = extension(43, VERSION)
    if group:
        ext += extension(51, group.to_bytes(2, "big") + (b"" if retry else _vec(E, 2)))
    elif E or (retry and not cookie) or (not retry and not resumed):
        raise ProtocolError("absent key share requires PSK-only selection")
    if cookie:
        if not retry:
            raise ProtocolError("cookies are only sent in HelloRetryRequest", alert=47)
        ext += extension(44, _vec(cookie, 2))
    if combined_psk:
        if not resumed or not group:
            raise ProtocolError("combined PSK requires DHE and a PSK")
        ext += extension(33, b"")
    if resumed:
        ext += extension(41, selected_identity.to_bytes(2, "big"))
    if password_salt is not None:
        if not retry or not pwd or len(password_salt) != 32:
            raise ProtocolError("password salt requires a PWD retry")
        ext += extension(31, _vec(password_salt, 2))
    return frame(2, b"\x03\x03" + (HRR_RANDOM if retry else random)
                 + _vec(session_id, 1) + cipher_suite.to_bytes(2, "big") + b"\x00" + _vec(ext, 2))


def parse_server_hello(body: bytes, *, details: bool = False, with_suite: bool = False):
    r = _Reader(body)
    if r.take(2) != b"\x03\x03":
        raise ProtocolError("invalid ServerHello legacy version", alert=70)
    random = r.take(32)
    sid = r.vector(1)
    cipher_suite = int.from_bytes(r.take(2), "big")
    if len(sid) > 32 or cipher_suite not in c.CIPHER_SUITES or r.take(1) != b"\x00":
        raise ProtocolError("invalid ServerHello", alert=47)
    ext = extensions(r.vector(2)); r.end()
    retry = random == HRR_RANDOM
    validate_extension_context(ext, "HRR" if retry else "SH")
    pwd = c.suite(cipher_suite).password_authenticated
    if 43 not in ext:
        raise ProtocolError("missing required ServerHello version", alert=109)
    if len(ext[43]) != 2:
        raise ProtocolError("malformed ServerHello version", alert=50)
    if ext[43] != VERSION:
        raise ProtocolError("unsupported ServerHello version", alert=47)
    if set(ext) - ({43, 51, 44, 31} if retry and pwd else {43, 51, 44} if retry else {43, 51, 41, 33}):
        raise ProtocolError("unsupported ServerHello extension", alert=110)
    group, E = 0, b""
    if 51 in ext:
        sr = _Reader(ext[51]); group = int.from_bytes(sr.take(2), "big")
        E = b"" if retry else sr.vector(2); sr.end()
        valid_share = pwd_share_valid(group, E) if pwd else len(E) == c.SERVER_GROUP_LENGTHS.get(group)
        if group not in c.GROUP_LENGTHS or not retry and not valid_share:
            raise ProtocolError("invalid server traffic share", alert=47)
    elif (retry and 44 not in ext) or (not retry and 41 not in ext):
        raise ProtocolError("missing server traffic share or useful retry", alert=109)
    if 41 in ext and len(ext[41]) != 2:
        raise ProtocolError("invalid PSK selected identity", alert=50)
    if 33 in ext and (ext[33] or 41 not in ext or not group):
        raise ProtocolError("invalid combined PSK selection", alert=47)
    if pwd and (41 in ext or 33 in ext):
        raise ProtocolError("fresh PWD cannot select a PSK", alert=47)
    if 31 in ext and (len(ext[31]) != 34 or ext[31][:2] != b"\x00\x20"):
        raise ProtocolError("invalid PWD salt", alert=50)
    cookie = b""
    if 44 in ext:
        cr = _Reader(ext[44]); cookie = cr.vector(2); cr.end()
        if not cookie:
            raise ProtocolError("empty retry cookie", alert=50)
    result = (E, sid, 41 in ext, group, retry, cookie)
    return result + (cipher_suite,) if with_suite else result if details else E


def server_hello_extensions(body):
    r = _Reader(body)
    r.take(34); r.vector(1); r.take(3)
    result = extensions(r.vector(2)); r.end()
    return result


def encrypted_extensions(protocol: bytes = HTTP_PROTOCOL, *, early_data: bool = False, extra_extensions=(),
                          acknowledge_name=True) -> bytes:
    ext = extension(0, b"") if acknowledge_name else b""
    if protocol:
        _protocol(protocol)
        ext += extension(16, _vec(_vec(protocol, 1), 2))
    if early_data:
        ext += extension(42, b"")
    for kind, value in extra_extensions:
        ext += extension(kind, value)
    extensions(ext)
    return frame(8, _vec(ext, 2))


def parse_encrypted_extensions(body: bytes, protocol: bytes = HTTP_PROTOCOL, *, offered_early: bool = False,
                                details=False, allowed_extensions=(), with_extensions=False,
                                offered_name=True, require_alpn=True):
    r = _Reader(body); ext = extensions(r.vector(2)); r.end()
    validate_extension_context(ext, "EE")
    selected = b""
    if 16 in ext:
        pr = _Reader(ext[16]); chosen = _Reader(pr.vector(2)); pr.end()
        selected = chosen.vector(1); chosen.end(); _protocol(selected)
    offered = (protocol,) if isinstance(protocol, bytes) else tuple(protocol)
    if set(ext) - {0, 16, 42, *allowed_extensions} or 0 in ext and not offered_name:
        raise ProtocolError("unsolicited EncryptedExtensions response", alert=110)
    if 0 in ext and ext[0] or 42 in ext and ext[42]:
        raise ProtocolError("nonempty empty-response extension", alert=50)
    if selected and selected not in offered:
        raise ProtocolError("unoffered application protocol", alert=47)
    if require_alpn and not selected:
        raise ProtocolError("required application protocol missing", alert=120)
    if 42 in ext and not offered_early:
        raise ProtocolError("unsolicited early_data selection", alert=110)
    if 10 in ext:
        _u16_list(ext[10])  # Server preferences are advisory, not a new share selection.
    return (42 in ext, selected, ext) if with_extensions else (42 in ext, selected) if details else 42 in ext


def certificate_verify(proof: bytes, *, client: bool = False) -> bytes:
    return frame(15, (b"\xfe\x01" if client else b"\xfe\x00") + _vec(proof, 2))


def certificate_request(context: bytes, verifier_public: bytes,
                         algorithms: tuple[int, ...] = CERT_ALGORITHMS, *, extra_extensions=()) -> bytes:
    if len(verifier_public) != 32:
        raise ProtocolError("invalid client verifier share or algorithm offer")
    ext = extension(50, _vec(b"".join(x.to_bytes(2, "big") for x in algorithms), 2)) if algorithms else b""
    ext += extension(0xff03, verifier_public)
    for kind, value in extra_extensions:
        ext += extension(kind, value)
    extensions(ext)
    return frame(13, _vec(context, 1) + _vec(ext, 2))


def parse_certificate_request(body: bytes, *, details=False):
    r = _Reader(body); context = r.vector(1); ext = extensions(r.vector(2)); r.end()
    validate_extension_context(ext, "CR")
    validate_delegation_offer(ext)
    if 5 in ext:
        parse_status_request(ext[5], certificate_request=True)
    if 47 in ext:
        parse_certificate_authorities(ext[47])
    if 48 in ext:
        parse_oid_filters(ext[48])
    if 0xff03 not in ext:
        raise ProtocolError("missing client authentication extension", alert=109)
    if len(ext[0xff03]) != 32:
        raise ProtocolError("wrong client authentication extension length", alert=50)
    algorithms = _u16_list(ext[50]) if 50 in ext else ()
    if any(x in (0xfe00, 0xfe01, 0x0420, 0x0520, 0x0620) for x in algorithms):
        raise ProtocolError("invalid client certificate signature list", alert=47)
    result = context, ext[0xff03], algorithms
    return result + (ext,) if details else result


def new_session_ticket(identity: bytes, nonce: bytes, lifetime: int, age_add: int, max_early_data: int) -> bytes:
    ext = extension(42, max_early_data.to_bytes(4, "big")) if max_early_data else b""
    return frame(4, lifetime.to_bytes(4, "big") + age_add.to_bytes(4, "big")
                 + _vec(nonce, 1) + _vec(identity, 2) + _vec(ext, 2))


def parse_new_session_ticket(body: bytes):
    r = _Reader(body)
    lifetime = int.from_bytes(r.take(4), "big"); age_add = int.from_bytes(r.take(4), "big")
    nonce = r.vector(1); identity = r.vector(2); ext = extensions(r.vector(2)); r.end()
    validate_extension_context(ext, "NST")
    if not identity or lifetime > 604800 or set(ext) & {43, 50, 0xff02, 0xff03}:
        raise ProtocolError("invalid NewSessionTicket")
    if 42 in ext and len(ext[42]) != 4:
        raise ProtocolError("invalid ticket early-data limit", alert=50)
    maximum = int.from_bytes(ext.get(42, b"\x00\x00\x00\x00"), "big")
    return identity, nonce, lifetime, age_add, maximum


def certificate(chain_der: list[bytes], *, context: bytes = b"", allow_empty: bool = False,
                 entry_extensions=()) -> bytes:
    if not (0 if allow_empty else 1) <= len(chain_der) <= 8:
        raise ProtocolError("certificate count")
    entries = []
    metadata = entry_extensions or ((),) * len(chain_der)
    if len(metadata) != len(chain_der):
        raise ProtocolError("certificate metadata count")
    for item, pairs in zip(chain_der, metadata):
        if not 1 <= len(item) <= 65536:
            raise ProtocolError("certificate length")
        block = b"".join(extension(kind, value) for kind, value in pairs)
        extensions(block)
        entries.append(_vec(item, 3) + _vec(block, 2))
    return frame(11, _vec(context, 1) + _vec(b"".join(entries), 3))


def parse_certificate(body: bytes, *, context: bytes = b"", allow_empty: bool = False,
                       details=False) -> list[bytes]:
    """Decode the list envelope, not DER, certificate profiles or path trust."""
    if len(body) > MAX_HANDSHAKE_BODY:
        raise ProtocolError("Certificate body too large")
    r = _Reader(body)
    if r.vector(1) != context:
        raise ProtocolError("unexpected certificate request context", alert=47)
    entries = _Reader(r.vector(3))
    r.end()
    result, metadata = [], []
    while entries.position < len(entries.data):
        item = entries.vector(3)
        if not 1 <= len(item) <= 65536 or len(result) >= 8:
            raise ProtocolError("certificate count or length", alert=50)
        block = entries.vector(2)
        values = extensions(block, context="CE")
        if block and not details:
            raise ProtocolError("certificate extensions are unsupported", alert=110)
        result.append(item)
        metadata.append(tuple(values.items()))
    if not result and not allow_empty:
        raise ProtocolError("empty certificate chain", alert=50)
    return (result, tuple(metadata)) if details else result
