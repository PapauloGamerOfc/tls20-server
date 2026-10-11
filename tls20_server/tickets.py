"""Bounded in-memory protocol-isolated session tickets, never serialized to disk.

The server shares ONE store across its listener. A restart loses the random
opaque identities and their PSKs, so old early data is rejected, not replayed.
Multi-process deployments must share an atomic replay store or disable 0-RTT.
"""

from collections import OrderedDict
from dataclasses import dataclass, field
import os
import threading
import time

from . import crypto as c, messages as m


@dataclass(repr=False)
class SessionTicket:
    identity: bytes
    psk: bytes
    name: str
    protocol: bytes
    issued: float
    lifetime: int
    age_add: int
    max_early_data: int
    early_used: bool = False
    context: bytes = b""
    certificate_chain: list[bytes] = field(default_factory=list)
    client_certificate_chain: list[bytes] = field(default_factory=list)
    _storage_size: int = 0

    def expired(self, now=None):
        return (time.monotonic() if now is None else now) - self.issued >= self.lifetime

    def obfuscated_age(self):
        return (int((time.monotonic() - self.issued) * 1000) + self.age_add) % (1 << 32)


class TicketStore:
    def __init__(self, lifetime=86400, capacity=4096, max_bytes=16 * 1024 * 1024):
        if (type(lifetime) is not int or type(capacity) is not int or type(max_bytes) is not int
                or not 1 <= lifetime <= 604800 or not 1 <= capacity <= 100000 or max_bytes < 1):
            raise ValueError("invalid session ticket store bounds")
        self.lifetime, self.capacity, self.max_bytes = lifetime, capacity, max_bytes
        self._tickets = OrderedDict()
        self._lock = threading.Lock()
        self._bytes = 0

    def _evict_oldest(self):
        _, ticket = self._tickets.popitem(last=False)
        self._bytes -= ticket._storage_size

    def issue(self, secret, name, protocol, max_early_data=0, context=b"", client_certificate_chain=None):
        nonce, identity = os.urandom(8), os.urandom(32)
        age_add = int.from_bytes(os.urandom(4), "big")
        psk = c.label_expand(secret, "resumption", nonce, 32)
        message = m.new_session_ticket(identity, nonce, self.lifetime, age_add, max_early_data)
        chain = list(client_certificate_chain or [])
        # Count retained variable bytes plus a conservative per-object allowance.
        # This is a local cache resource policy, never a limit on TLS credentials.
        size = (512 + len(identity) + len(psk) + len(name.encode("utf-8"))
                + len(protocol) + len(context) + sum(64 + len(der) for der in chain))
        if size > self.max_bytes:
            return None  # Complete the valid handshake without issuing a ticket.
        with self._lock:
            now = time.monotonic()
            # Entries have the same configured lifetime, and insertion-time
            # timestamps are obtained inside this lock. Expiry order therefore
            # equals insertion order: amortized O(1), not a full per-ticket scan.
            while self._tickets and next(iter(self._tickets.values())).expired(now):
                self._evict_oldest()
            while len(self._tickets) >= self.capacity or self._bytes + size > self.max_bytes:
                self._evict_oldest()
            ticket = SessionTicket(identity, psk, name, protocol, now, self.lifetime,
                                   age_add, max_early_data, context=context,
                                   client_certificate_chain=chain, _storage_size=size)
            self._tickets[identity] = ticket
            self._bytes += size
        return message

    def lookup(self, identity, name, protocol, context=b""):
        with self._lock:
            ticket = self._tickets.get(identity)
            if ticket is not None and ticket.expired():
                del self._tickets[identity]
                self._bytes -= ticket._storage_size
                return None
            if (ticket is None or ticket.name != name
                    or ticket.protocol != protocol or ticket.context != context):
                return None
            return ticket

    def consume_early(self, ticket, obfuscated_age):
        """Must be called only AFTER valid binder; permanently burns early use."""
        with self._lock:
            if (self._tickets.get(ticket.identity) is not ticket or ticket.expired()
                    or ticket.early_used or not ticket.max_early_data):
                return False
            advertised = (obfuscated_age - ticket.age_add) % (1 << 32)
            actual = int((time.monotonic() - ticket.issued) * 1000)
            if abs(actual - advertised) > 10000:
                return False
            ticket.early_used = True
            return True


class TicketCache:
    def __init__(self, capacity=32):
        if type(capacity) is not int or not 1 <= capacity <= 4096:
            raise ValueError("invalid ticket cache capacity")
        self.capacity = capacity
        self._tickets = OrderedDict()

    def take(self, name, protocol, context=b""):
        ticket = self._tickets.pop((name, protocol, context), None)
        return None if ticket is None or ticket.expired() else ticket

    def put(self, ticket):
        if not ticket.lifetime:
            return
        key = ticket.name, ticket.protocol, ticket.context
        self._tickets.pop(key, None)
        while len(self._tickets) >= self.capacity:
            self._tickets.popitem(last=False)
        self._tickets[key] = ticket
