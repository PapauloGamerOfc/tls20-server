"""Strict draft-01 message codecs; certificate trust is a separate operation.

Wire layout follows the original MIT-licensed tls20-spec, draft-01.
"""

from __future__ import annotations

from dataclasses import dataclass
import ipaddress
import re

from .errors import ProtocolError

HANDSHAKE_TYPES = frozenset((1, 2, 8, 11, 15, 20))
MAX_HANDSHAKE_BODY = 1 << 18
HTTP_PROTOCOL = b"http/1.1"
PARAMETERS = b"\x13\x01\x00\x1d"


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
    if kind in (15, 20) and len(body) != 32:
        raise ProtocolError("proof and Finished bodies must have length 32")
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


def client_hello(A: bytes, B: bytes, name: str, random: bytes,
                 protocol: bytes = HTTP_PROTOCOL) -> bytes:
    validate_name(name)
    _protocol(protocol)
    if len(A) != 32 or len(B) != 32 or len(random) != 32 or A == B:
        raise ProtocolError("invalid client shares or random")
    return frame(1, b"\x00\x01" + random + PARAMETERS + A + B
                 + _vec(name.encode("ascii"), 2) + _vec(protocol, 1))


def parse_client_hello(body: bytes) -> ClientHello:
    if not 107 <= len(body) <= 613:
        raise ProtocolError("ClientHello body length")
    r = _Reader(body)
    if r.take(2) != b"\x00\x01":
        raise ProtocolError("unsupported revision")
    random = r.take(32)
    if r.take(4) != PARAMETERS:
        raise ProtocolError("unsupported cipher or group")
    A, B = r.take(32), r.take(32)
    if A == B:
        raise ProtocolError("client shares must differ")
    try:
        name = r.vector(2).decode("ascii")
    except UnicodeDecodeError as exc:
        raise ProtocolError("non-ASCII server name") from exc
    validate_name(name)
    protocol = r.vector(1)
    _protocol(protocol)
    r.end()
    return ClientHello(name, protocol, A, B, random)


def server_hello(E: bytes, random: bytes) -> bytes:
    if len(E) != 32 or len(random) != 32:
        raise ProtocolError("invalid server share or random")
    return frame(2, b"\x00\x01" + random + PARAMETERS + E)


def parse_server_hello(body: bytes) -> bytes:
    if len(body) != 70 or body[:2] != b"\x00\x01" or body[34:38] != PARAMETERS:
        raise ProtocolError("invalid ServerHello")
    return body[38:]


def encrypted_extensions(protocol: bytes = HTTP_PROTOCOL) -> bytes:
    _protocol(protocol)
    selection = _vec(_vec(protocol, 1), 2)
    return frame(8, _vec(b"\x00\x00\x00\x00\x00\x10" + _vec(selection, 2), 2))


def parse_encrypted_extensions(body: bytes, protocol: bytes = HTTP_PROTOCOL) -> None:
    # Comparing the exact canonical bytes also rejects reordered, duplicate,
    # unknown, omitted and trailing extensions, lengths and protocol changes.
    if body != encrypted_extensions(protocol)[4:]:
        raise ProtocolError("invalid extension structure or protocol selection")


def certificate(chain_der: list[bytes]) -> bytes:
    if not 1 <= len(chain_der) <= 8:
        raise ProtocolError("certificate count")
    entries = []
    for item in chain_der:
        if not 1 <= len(item) <= 65536:
            raise ProtocolError("certificate length")
        entries.append(_vec(item, 3) + b"\x00\x00")
    return frame(11, b"\x00" + _vec(b"".join(entries), 3))


def parse_certificate(body: bytes) -> list[bytes]:
    """Decode the list envelope, not DER, certificate profiles or path trust."""
    if len(body) > MAX_HANDSHAKE_BODY:
        raise ProtocolError("Certificate body too large")
    r = _Reader(body)
    if r.vector(1):
        raise ProtocolError("nonempty certificate request context")
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
    if not result:
        raise ProtocolError("empty certificate chain")
    return result
