"""Bounded in-memory protocol-isolated session tickets, never serialized to disk.

The server shares ONE store across its listener. A restart loses the random
opaque identities and their PSKs, so old early data is rejected, not replayed.
Multi-process deployments must share an atomic replay store or disable 0-RTT.
"""

from collections import OrderedDict
from dataclasses import dataclass, field
import os
import math
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
    cipher_suite: int = 0x1301
    certificate_type: int = 0
    certificate_extensions: tuple = ()
    client_certificate_type: int = 0
    client_certificate_extensions: tuple = ()
    record_size_limit: int = 16385
    external_psk_identity: bytes = b""
    pake_identity: bytes = b""
    # Original wall-clock credential deadline. Revalidating cached DNSSEC
    # evidence must not restart its TTL for every resumption/new ticket.
    credential_expires_at: float | None = None
    # Local state, not an NST wire field. A successor cannot acquire a mode
    # that the ClientHello authorizing its ancestor ticket did not offer.
    allowed_psk_modes: tuple[int, ...] = (1, 0)

    def expired(self, now=None):
        return ((time.monotonic() if now is None else now) - self.issued >= self.lifetime
                or self.credential_expires_at is not None and
                (not math.isfinite(self.credential_expires_at) or time.time() >= self.credential_expires_at))

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

    def issue(self, secret, name, protocol, max_early_data=0, context=b"", client_certificate_chain=None,
              *, cipher_suite=0x1301, client_certificate_type=0, client_certificate_extensions=(),
              external_psk_identity=b"", pake_identity=b"", native_provider=None,
              allowed_psk_modes=(1, 0)):
        allowed_psk_modes = tuple(allowed_psk_modes)
        if (not allowed_psk_modes or len(set(allowed_psk_modes)) != len(allowed_psk_modes)
                or any(type(mode) is not int or mode not in (0, 1) for mode in allowed_psk_modes)):
            raise ValueError("invalid ticket PSK key exchange modes")
        nonce, identity = os.urandom(8), os.urandom(32)
        age_add = int.from_bytes(os.urandom(4), "big")
        selected = c.suite(cipher_suite)
        psk = c.label_expand(secret, "resumption", nonce, selected.hash_length, c.hash_context(selected.hash_name,native_provider))
        message = m.new_session_ticket(identity, nonce, self.lifetime, age_add, max_early_data)
        chain = list(client_certificate_chain or [])
        # Count retained variable bytes plus a conservative per-object allowance.
        # This is a local cache resource policy, never a limit on TLS credentials.
        size = (512 + len(identity) + len(psk) + len(name.encode("utf-8"))
                + len(protocol) + len(context) + len(external_psk_identity) + len(pake_identity) + sum(64 + len(der) for der in chain)
                + sum(64 + len(value) for entry in client_certificate_extensions for _, value in entry))
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
                                   client_certificate_chain=chain, _storage_size=size, cipher_suite=cipher_suite)
            ticket.client_certificate_type = client_certificate_type
            ticket.client_certificate_extensions = tuple(client_certificate_extensions)
            ticket.external_psk_identity = external_psk_identity
            ticket.pake_identity = pake_identity
            ticket.allowed_psk_modes = allowed_psk_modes
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
