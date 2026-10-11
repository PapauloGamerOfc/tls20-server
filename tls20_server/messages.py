"""Bounded RFC-shaped TLS 2.0 codecs; certificate trust is a separate operation."""

from __future__ import annotations

from dataclasses import dataclass
import ipaddress
import re

from .errors import ProtocolError

HANDSHAKE_TYPES = frozenset((1, 2, 4, 5, 8, 11, 13, 15, 20, 24))
MAX_HANDSHAKE_BODY = 1 << 18
HTTP_PROTOCOL = b"http/1.1"
PARAMETERS = b"\x13\x01\x00\x1d"
VERSION = b"\x04\x00"
CERT_ALGORITHMS = (0x0807, 0x0403)
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
            raise ProtocolError("truncated message")
        value = self.data[self.position:self.position + length]
        self.position += length
        return value

    def vector(self, width: int) -> bytes:
        return self.take(int.from_bytes(self.take(width), "big"))

    def end(self) -> None:
        if self.position != len(self.data):
            raise ProtocolError("trailing message data")


def frame(kind: int, body: bytes) -> bytes:
    if kind not in HANDSHAKE_TYPES or len(body) > MAX_HANDSHAKE_BODY:
        raise ProtocolError("invalid handshake type or length")
    if kind == 20 and len(body) != 32:
        raise ProtocolError("Finished body must have length 32")
    if kind == 15 and (len(body) != 36 or body[:4] not in (b"\xfe\x00\x00\x20", b"\xfe\x01\x00\x20")):
        raise ProtocolError("MAC envelope")
    if kind == 5 and body:
        raise ProtocolError("EndOfEarlyData must be empty")
    if kind == 24 and body not in (b"\x00", b"\x01"):
        raise ProtocolError("KeyUpdate request value")
    return bytes((kind,)) + len(body).to_bytes(3, "big") + body


def decode_frame(wire: bytes) -> tuple[int, bytes]:
    if len(wire) < 4 or int.from_bytes(wire[1:4], "big") != len(wire) - 4:
        raise ProtocolError("handshake envelope length")
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


def extension(kind: int, data: bytes) -> bytes:
    return kind.to_bytes(2, "big") + _vec(data, 2)


def extensions(data: bytes) -> dict[int, bytes]:
    r = _Reader(data)
    result = {}
    while r.position < len(data):
        kind = int.from_bytes(r.take(2), "big")
        value = r.vector(2)
        if kind in result or kind == 13:
            raise ProtocolError("duplicate or forbidden extension")
        result[kind] = value
    return result


def _u16_list(data: bytes) -> tuple[int, ...]:
    r = _Reader(data)
    value = r.vector(2)
    r.end()
    if not value or len(value) % 2:
        raise ProtocolError("invalid uint16 list")
    return tuple(int.from_bytes(value[i:i + 2], "big") for i in range(0, len(value), 2))


def client_hello(A: bytes, B: bytes, name: str, random: bytes,
                 protocol: bytes = HTTP_PROTOCOL, *, identity: bytes = b"",
                 age: int = 0, binder: bytes = b"", early_data: bool = False,
                 group: int = 0x001d, empty_share: bool = False, cookie: bytes = b"",
                 session_id: bytes = b"", post_handshake_auth: bool = False) -> bytes:
    validate_name(name)
    _protocol(protocol)
    if (len(A) != 32 or len(B) != (65 if group == 0x0017 else 32)
            or group not in (0x001d, 0x0017) or len(random) != 32 or A == B or len(session_id) > 32):
        raise ProtocolError("invalid client shares or random")
    ext = extension(0, _vec(b"\x00" + _vec(name.encode("ascii"), 2), 2))
    ext += extension(43, b"\x02" + VERSION)
    ext += extension(10, b"\x00\x04\x00\x1d\x00\x17")
    ext += extension(51, _vec(b"" if empty_share else group.to_bytes(2, "big") + _vec(B, 2), 2))
    ext += extension(50, _vec(b"".join(x.to_bytes(2, "big") for x in CERT_ALGORITHMS), 2))
    ext += extension(0xff02, A)
    ext += extension(16, _vec(_vec(protocol, 1), 2))
    ext += extension(45, b"\x01\x01")  # psk_dhe_ke, also requests future tickets.
    if post_handshake_auth:
        ext += extension(49, b"")
    if cookie:
        ext += extension(44, _vec(cookie, 2))
    if early_data:
        if not identity:
            raise ProtocolError("early data requires a PSK")
        ext += extension(42, b"")
    if identity:
        if len(binder) != 32 or not 0 <= age < 1 << 32:
            raise ProtocolError("invalid PSK binder or age")
        ext += extension(41, _vec(_vec(identity, 2) + age.to_bytes(4, "big"), 2)
                         + _vec(_vec(binder, 1), 2))
    return frame(1, b"\x03\x03" + random + _vec(session_id, 1) + b"\x00\x02\x13\x01"
                 + b"\x01\x00" + _vec(ext, 2))


def parse_client_hello(body: bytes) -> ClientHello:
    r = _Reader(body)
    if r.take(2) != b"\x03\x03":
        raise ProtocolError("invalid ClientHello legacy version")
    random = r.take(32)
    sid = r.vector(1)
    if len(sid) > 32:
        raise ProtocolError("legacy session id length")
    suites = r.vector(2)
    if not suites or len(suites) % 2 or b"\x13\x01" not in [suites[i:i+2] for i in range(0, len(suites), 2)]:
        raise ProtocolError("no supported cipher suite")
    if r.vector(1) != b"\x00":
        raise ProtocolError("invalid legacy compression")
    fixed_hello = body[:r.position]
    ext = extensions(r.vector(2))
    r.end()
    if 0xff03 in ext or 49 in ext and ext[49]:
        raise ProtocolError("wrong-role auth share or malformed post_handshake_auth")
    for required in (0, 43, 10, 51, 16):
        if required not in ext:
            raise ProtocolError("missing required ClientHello extension")
    vr = _Reader(ext[43]); versions = vr.vector(1); vr.end()
    if not versions or len(versions) % 2:
        raise ProtocolError("invalid supported_versions")
    if VERSION not in [versions[i:i+2] for i in range(0, len(versions), 2)]:
        raise ProtocolError("unsupported protocol version")
    groups = _u16_list(ext[10])
    if not set(groups) & {0x001d, 0x0017}:
        raise ProtocolError("no supported traffic group")
    sr = _Reader(ext[51]); shares = _Reader(sr.vector(2)); sr.end()
    seen, shares_by_group = set(), {}
    while shares.position < len(shares.data):
        group = int.from_bytes(shares.take(2), "big")
        share = shares.vector(2)
        if group in seen:
            raise ProtocolError("duplicate key share")
        seen.add(group)
        if group not in groups:
            raise ProtocolError("key share not in supported_groups")
        if group in (0x001d, 0x0017):
            if len(share) != (32 if group == 0x001d else 65):
                raise ProtocolError("traffic share length")
            shares_by_group[group] = share
    group = next((value for value in (0x001d, 0x0017) if value in shares_by_group),
                 next(value for value in (0x001d, 0x0017) if value in groups))
    B = shares_by_group.get(group, b"")
    A = ext.get(0xff02, b"")
    if (A and len(A) != 32) or (B and A == B):
        raise ProtocolError("invalid independent key shares")
    nr = _Reader(ext[0]); names = _Reader(nr.vector(2)); nr.end()
    if names.take(1) != b"\x00":
        raise ProtocolError("unsupported name type")
    try:
        name = names.vector(2).decode("ascii")
    except UnicodeDecodeError as exc:
        raise ProtocolError("non-ASCII server name") from exc
    validate_name(name)
    names.end()
    pr = _Reader(ext[16]); protocols = _Reader(pr.vector(2)); pr.end()
    offered = []
    while protocols.position < len(protocols.data):
        value = protocols.vector(1); _protocol(value); offered.append(value)
    if not offered:
        raise ProtocolError("empty ALPN offer")
    protocol = HTTP_PROTOCOL if HTTP_PROTOCOL in offered else offered[0]
    cert_algs = _u16_list(ext[50]) if 50 in ext else ()
    if any(value in (0xfe00, 0xfe01, 0x0420, 0x0520, 0x0620) for value in cert_algs):
        raise ProtocolError("invalid certificate signature scheme")
    identity, age, binder = b"", 0, b""
    offers, binder_size = [], 0
    if 45 in ext:
        mr = _Reader(ext[45]); modes = mr.vector(1); mr.end()
        if not modes:
            raise ProtocolError("empty PSK modes")
    if 41 in ext:
        if list(ext)[-1] != 41 or 45 not in ext or 1 not in modes:
            raise ProtocolError("PSK must be last and offer psk_dhe_ke")
        p = _Reader(ext[41]); ids = _Reader(p.vector(2)); bs = _Reader(p.vector(2)); p.end()
        identities = []
        while ids.position < len(ids.data):
            value = ids.vector(2); obfuscated = int.from_bytes(ids.take(4), "big")
            if not value:
                raise ProtocolError("empty PSK identity")
            identities.append((value, obfuscated))
        binders = []
        while bs.position < len(bs.data):
            value = bs.vector(1)
            if len(value) < 32:
                raise ProtocolError("invalid binder size")
            binders.append(value)
        if not identities or len(identities) != len(binders):
            raise ProtocolError("PSK identities and binders differ")
        offers = [(value, obfuscated, proof) for (value, obfuscated), proof in zip(identities, binders)]
        identity, age, binder = offers[0]
        binder_size = 2 + len(bs.data)
    if 42 in ext and (ext[42] or not identity):
        raise ProtocolError("invalid early_data offer")
    return ClientHello(name, protocol, A, B, random, sid, cert_algs,
                       identity, age, binder, 42 in ext, tuple(ext), group, groups,
                       tuple(ext.items()), fixed_hello, tuple(offers), binder_size, tuple(seen))


def server_hello(E: bytes, random: bytes, *, session_id: bytes = b"", resumed: bool = False,
                 group: int = 0x001d, retry: bool = False, selected_identity: int = 0) -> bytes:
    if (not retry and len(E) != (65 if group == 0x0017 else 32)) or len(random) != 32:
        raise ProtocolError("invalid server share or random")
    if len(session_id) > 32:
        raise ProtocolError("legacy session id length")
    ext = extension(43, VERSION) + extension(51, group.to_bytes(2, "big") + (b"" if retry else _vec(E, 2)))
    if resumed:
        ext += extension(41, selected_identity.to_bytes(2, "big"))
    return frame(2, b"\x03\x03" + (HRR_RANDOM if retry else random)
                 + _vec(session_id, 1) + b"\x13\x01\x00" + _vec(ext, 2))


def parse_server_hello(body: bytes, *, details: bool = False):
    r = _Reader(body)
    if r.take(2) != b"\x03\x03":
        raise ProtocolError("invalid ServerHello legacy version")
    random = r.take(32)
    sid = r.vector(1)
    if len(sid) > 32 or r.take(3) != b"\x13\x01\x00":
        raise ProtocolError("invalid ServerHello")
    ext = extensions(r.vector(2)); r.end()
    retry = random == HRR_RANDOM
    if set(ext) - ({43, 51, 44} if retry else {43, 51, 41}) or ext.get(43) != VERSION:
        raise ProtocolError("unsupported ServerHello version or extension")
    group, E = 0, b""
    if 51 in ext:
        sr = _Reader(ext[51]); group = int.from_bytes(sr.take(2), "big")
        E = b"" if retry else sr.vector(2); sr.end()
        if group not in (0x001d, 0x0017) or not retry and len(E) != (32 if group == 0x001d else 65):
            raise ProtocolError("invalid server traffic share")
    elif not retry or 44 not in ext:
        raise ProtocolError("missing server traffic share or useful retry")
    if 41 in ext and ext[41] != b"\x00\x00":
        raise ProtocolError("unknown PSK selected identity")
    cookie = b""
    if 44 in ext:
        cr = _Reader(ext[44]); cookie = cr.vector(2); cr.end()
        if not cookie:
            raise ProtocolError("empty retry cookie")
    return (E, sid, 41 in ext, group, retry, cookie) if details else E


def encrypted_extensions(protocol: bytes = HTTP_PROTOCOL, *, early_data: bool = False) -> bytes:
    _protocol(protocol)
    selection = _vec(_vec(protocol, 1), 2)
    ext = extension(0, b"") + extension(16, selection)
    if early_data:
        ext += extension(42, b"")
    return frame(8, _vec(ext, 2))


def parse_encrypted_extensions(body: bytes, protocol: bytes = HTTP_PROTOCOL, *, offered_early: bool = False) -> bool:
    r = _Reader(body); ext = extensions(r.vector(2)); r.end()
    if set(ext) - {0, 16, 42} or ext.get(0) != b"" or ext.get(16) != _vec(_vec(protocol, 1), 2):
        raise ProtocolError("invalid extension structure or protocol selection")
    if 42 in ext and (not offered_early or ext[42]):
        raise ProtocolError("unsolicited early_data selection")
    return 42 in ext


def certificate_verify(proof: bytes, *, client: bool = False) -> bytes:
    return frame(15, (b"\xfe\x01" if client else b"\xfe\x00") + _vec(proof, 2))


def certificate_request(context: bytes, verifier_public: bytes,
                         algorithms: tuple[int, ...] = CERT_ALGORITHMS) -> bytes:
    if len(verifier_public) != 32 or not algorithms:
        raise ProtocolError("invalid client verifier share or algorithm offer")
    ext = extension(50, _vec(b"".join(x.to_bytes(2, "big") for x in algorithms), 2))
    ext += extension(0xff03, verifier_public)
    return frame(13, _vec(context, 1) + _vec(ext, 2))


def parse_certificate_request(body: bytes):
    r = _Reader(body); context = r.vector(1); ext = extensions(r.vector(2)); r.end()
    if len(ext.get(0xff03, b"")) != 32 or 0xff02 in ext or 50 not in ext:
        raise ProtocolError("missing or wrong client authentication extension")
    algorithms = _u16_list(ext[50])
    if any(x in (0xfe00, 0xfe01, 0x0420, 0x0520, 0x0620) for x in algorithms):
        raise ProtocolError("invalid client certificate signature list")
    return context, ext[0xff03], algorithms


def new_session_ticket(identity: bytes, nonce: bytes, lifetime: int, age_add: int, max_early_data: int) -> bytes:
    ext = extension(42, max_early_data.to_bytes(4, "big")) if max_early_data else b""
    return frame(4, lifetime.to_bytes(4, "big") + age_add.to_bytes(4, "big")
                 + _vec(nonce, 1) + _vec(identity, 2) + _vec(ext, 2))


def parse_new_session_ticket(body: bytes):
    r = _Reader(body)
    lifetime = int.from_bytes(r.take(4), "big"); age_add = int.from_bytes(r.take(4), "big")
    nonce = r.vector(1); identity = r.vector(2); ext = extensions(r.vector(2)); r.end()
    if not identity or lifetime > 604800 or set(ext) & {43, 50, 0xff02, 0xff03}:
        raise ProtocolError("invalid NewSessionTicket")
    if 42 in ext and len(ext[42]) != 4:
        raise ProtocolError("invalid ticket early-data limit")
    maximum = int.from_bytes(ext.get(42, b"\x00\x00\x00\x00"), "big")
    return identity, nonce, lifetime, age_add, maximum


def certificate(chain_der: list[bytes], *, context: bytes = b"", allow_empty: bool = False) -> bytes:
    if not (0 if allow_empty else 1) <= len(chain_der) <= 8:
        raise ProtocolError("certificate count")
    entries = []
    for item in chain_der:
        if not 1 <= len(item) <= 65536:
            raise ProtocolError("certificate length")
        entries.append(_vec(item, 3) + b"\x00\x00")
    return frame(11, _vec(context, 1) + _vec(b"".join(entries), 3))


def parse_certificate(body: bytes, *, context: bytes = b"", allow_empty: bool = False) -> list[bytes]:
    """Decode the list envelope, not DER, certificate profiles or path trust."""
    if len(body) > MAX_HANDSHAKE_BODY:
        raise ProtocolError("Certificate body too large")
    r = _Reader(body)
    if r.vector(1) != context:
        raise ProtocolError("unexpected certificate request context")
    entries = _Reader(r.vector(3))
    r.end()
    result = []
    while entries.position < len(entries.data):
        item = entries.vector(3)
        if not 1 <= len(item) <= 65536 or len(result) >= 8:
            raise ProtocolError("certificate count or length")
        if entries.vector(2):
            raise ProtocolError("certificate extensions are unsupported")
        result.append(item)
    if not result and not allow_empty:
        raise ProtocolError("empty certificate chain")
    return result
