"""Explicit, bounded HelloRetryRequest address-validation cookie policy.

Cookies are opaque, short lived and authenticate the first Hello and peer IP.
The policy keeps no per-cookie collection. This does not make the TCP handshake
stateless: the stream still retains its transcript and admission/deadline budget.
A cookie proves reachability, not identity, and never permits 0-RTT after HRR.
"""

import hashlib
import hmac
import ipaddress
import secrets
import time

from .errors import ProtocolError


class RetryCookiePolicy:
    def __init__(self, *, lifetime_seconds=30, key=None, clock=time.time):
        if type(lifetime_seconds) is not int or not 1 <= lifetime_seconds <= 300:
            raise ValueError("retry cookie lifetime must be 1..300 seconds")
        if key is not None and (not isinstance(key, bytes) or len(key) != 32):
            raise ValueError("retry cookie key must contain 32 random bytes")
        self._key = secrets.token_bytes(32) if key is None else key
        self._clock = clock
        self.lifetime_seconds = lifetime_seconds

    @staticmethod
    def _binding(writer, first_hello, suite, group):
        peer = writer.get_extra_info("peername")
        if not peer or not isinstance(peer[0], str):
            raise ValueError("retry cookies require a transport peer IP")
        address = ipaddress.ip_address(peer[0]).packed
        return (b"tls20 retry cookie\x00" + bytes((len(address),)) + address
                + suite.to_bytes(2, "big") + group.to_bytes(2, "big")
                + hashlib.sha256(first_hello).digest())

    def issue(self, writer, first_hello, suite, group):
        prefix = b"\x01" + int(self._clock()).to_bytes(8, "big") + secrets.token_bytes(16)
        return prefix + hmac.digest(self._key, prefix + self._binding(writer, first_hello, suite, group), "sha256")

    def verify(self, cookie, writer, first_hello, suite, group):
        if not isinstance(cookie, bytes) or len(cookie) != 57 or cookie[0] != 1:
            raise ProtocolError("invalid retry cookie", alert=47)
        age = self._clock() - int.from_bytes(cookie[1:9], "big")
        tag = hmac.digest(self._key, cookie[:25] + self._binding(writer, first_hello, suite, group), "sha256")
        if not 0 <= age <= self.lifetime_seconds or not hmac.compare_digest(tag, cookie[25:]):
            raise ProtocolError("invalid or expired retry cookie", alert=47)


def validate_retry_cookie(policy, values, sent_cookie, writer, first_hello, suite, group):
    from .messages import _Reader
    if not sent_cookie:
        if 44 in values:
            raise ProtocolError("unsolicited retry cookie", alert=47)
        return
    if 44 not in values:
        raise ProtocolError("missing requested retry cookie", alert=109)
    reader = _Reader(values[44])
    received = reader.vector(2)
    reader.end()
    if not hmac.compare_digest(received, sent_cookie):
        raise ProtocolError("retry cookie was changed", alert=47)
    policy.verify(received, writer, first_hello, suite, group)
