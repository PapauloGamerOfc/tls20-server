"""Narrow HTTP/1.1 admission policy for replayable, opt-in early requests.

This is not a general HTTP proxy parser. The ordinary authenticated byte-stream
relay is unchanged. Only explicitly configured replay-safe routes may be sent
to an early-data-aware backend before Client Finished. Method names alone do
not establish that an application is safe to replay.
"""

from __future__ import annotations

import re

from .errors import ProtocolError


TOO_EARLY_RESPONSE = (
    b"HTTP/1.1 425 Too Early\r\nContent-Length: 0\r\n"
    b"Cache-Control: no-store\r\nConnection: close\r\n\r\n"
)
_TOKEN = re.compile(rb"[!#$%&'*+.^_`|~0-9A-Za-z-]+\Z")
_FORBIDDEN = frozenset((
    b"content-length", b"transfer-encoding", b"authorization", b"cookie",
    b"proxy-authorization", b"expect", b"upgrade", b"trailer", b"te",
))


class EarlyRequestGate:
    """Assemble at most one bounded, bodyless, explicitly allowlisted request.

    feed() returns a sanitized complete request once. A refusal is handled as
    HTTP 425 after handshake completion; it is not a retroactive TLS rejection.
    Extra early data after an admitted request aborts instead of forwarding a
    second request or generating a retry for an already forwarded request.
    """

    def __init__(self, paths: tuple[str, ...], hostname: str, port: int, limit: int):
        self.paths = frozenset(path.encode("ascii") for path in paths)
        host_field = f"[{hostname}]" if ":" in hostname else hostname
        self.authorities = {host_field.encode("ascii"), f"{host_field}:{port}".encode("ascii")}
        self.limit = limit
        self.buffer = bytearray()
        self.seen = False
        self.forwarded = False
        self.rejected = False
        self.finished = False

    def feed(self, data: bytes) -> bytes | None:
        if self.finished:
            raise ProtocolError("early HTTP after EndOfEarlyData")
        if not data:
            self.finished = True
            if self.buffer and not self.forwarded:
                self.rejected = True
            self.buffer.clear()
            return None
        self.seen = True
        if self.forwarded:
            raise ProtocolError("multiple early HTTP requests are not permitted by this application policy")
        if self.rejected:
            return None
        if len(data) > self.limit - len(self.buffer):
            self.rejected = True
            self.buffer.clear()
            return None
        self.buffer.extend(data)
        marker = self.buffer.find(b"\r\n\r\n")
        if marker < 0:
            return None
        request = bytes(self.buffer)
        self.buffer.clear()
        forwarded = self._parse(request, marker)
        if forwarded is None:
            self.rejected = True
            return None
        self.forwarded = True
        return forwarded

    def _parse(self, request: bytes, marker: int) -> bytes | None:
        if marker + 4 != len(request):
            return None  # Body, pipelining or ambiguous framing.
        lines = request[:-4].split(b"\r\n")
        parts = lines[0].split(b" ")
        if len(parts) != 3 or parts[0] not in (b"GET", b"HEAD") or parts[2] != b"HTTP/1.1":
            return None
        if parts[1] not in self.paths:
            return None
        seen: set[bytes] = set()
        output = [lines[0]]
        for line in lines[1:]:
            if b":" not in line:
                return None
            name, value = line.split(b":", 1)
            if not _TOKEN.fullmatch(name) or any(char < 32 and char != 9 or char >= 127 for char in value):
                return None
            name = name.lower()
            value = value.strip(b" \t")
            if name in seen or name in _FORBIDDEN:
                return None
            seen.add(name)
            if name == b"host" and value.lower() not in self.authorities:
                return None
            if name == b"early-data":
                if value != b"1":
                    return None
                continue
            if name == b"connection" and value.lower() not in (b"close", b"keep-alive"):
                return None
            output.append(line)
        if b"host" not in seen:
            return None
        output.append(b"Early-Data: 1")
        return b"\r\n".join(output) + b"\r\n\r\n"
