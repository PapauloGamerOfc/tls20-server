"""Wire/state helpers for the spec's explicitly negotiated control profiles.

These helpers do not negotiate themselves. The handshake must check extension
placement, authenticate negotiation, preserve offers across HRR and bind tickets.
Heartbeat input must already have authenticated application-record protection.
"""

from dataclasses import dataclass
import base64
import hashlib
import hmac
import os

from .errors import ProtocolError


def heartbeat_mode(encoded):
    if encoded not in (b"\x01", b"\x02"):
        raise ProtocolError("invalid heartbeat mode", alert=47)
    return encoded[0]


class Heartbeat:
    def __init__(self, local_mode, peer_mode, *, receive_limit=16385, send_limit=16385):
        if local_mode not in (1, 2) or peer_mode not in (1, 2):
            raise ValueError("heartbeat requires negotiated directions")
        if any(type(value) is not int or not 64 <= value <= 16385
               for value in (receive_limit, send_limit)):
            raise ValueError("invalid heartbeat record limit")
        self.local_mode, self.peer_mode = local_mode, peer_mode
        self.receive_limit, self.send_limit = receive_limit, send_limit
        self.pending = None
        self.matched_response = None

    def _encode(self, kind, payload, padding=16):
        return bytes((kind,)) + len(payload).to_bytes(2, "big") + payload + os.urandom(padding)

    def request(self, payload=None, *, padding=16):
        if self.peer_mode != 1:
            raise ProtocolError("peer disallows heartbeat requests", alert=10)
        if self.pending is not None:
            raise ProtocolError("one heartbeat request may be outstanding", alert=10)
        if payload is None:
            payload = os.urandom(16)
        if type(payload) is not bytes or type(padding) is not int or padding < 16:
            raise ValueError("heartbeat requires bytes and at least 16 bytes of random padding")
        # The response can use minimal padding; it must also fit our own RSL.
        if (len(payload) + 3 + padding + 1 > min(16385, self.send_limit)
                or len(payload) + 3 + 16 + 1 > min(16385, self.receive_limit)):
            raise ValueError("heartbeat request/response exceeds negotiated record size")
        result = self._encode(1, payload, padding)
        self.pending, self.matched_response = payload, None
        return result

    def receive(self, authenticated_content):
        """Return a response or None. Bad lengths/mismatches are silent drops."""
        data = authenticated_content
        if len(data) < 19 or len(data) + 1 > self.receive_limit:
            return None
        length = int.from_bytes(data[1:3], "big")
        if length > len(data) - 3 - 16:
            return None  # Never read or echo the declared-but-missing bytes.
        payload = data[3:3 + length]
        if data[0] == 1:
            if self.local_mode != 1 or length + 3 + 16 + 1 > self.send_limit:
                return None
            return self._encode(2, payload)
        if data[0] == 2 and self.pending is not None and hmac.compare_digest(payload, self.pending):
            self.matched_response, self.pending = payload, None
        return None

    def cancel(self):
        """Application timeout/cancellation; TCP needs no protocol retransmit."""
        self.pending = None


def assertion_hash(assertion_octets):
    """Hash exact independently verified assertion bytes, without canonicalizing."""
    if assertion_octets is None:
        return b""
    if type(assertion_octets) is not bytes:
        raise ValueError("identity assertion must be exact bytes")
    return hashlib.sha256(assertion_octets).digest()


def webrtc_assertion_hash(identity_attribute):
    """Decode the SDP identity value; JSON whitespace is significant (RFC8844)."""
    try:
        octets = base64.b64decode(identity_attribute, validate=True)
        octets.decode("utf-8")
    except (ValueError, UnicodeError) as error:
        raise ValueError("invalid encoded WebRTC assertion") from error
    return assertion_hash(octets)


def passport_assertion_hash(full_signed_identity_digest):
    """Caller supplies the decoded full PASSporT, never the compact form.

    Expansion and signature/identity/fingerprint verification belong to the
    signaling application. This function does not establish trust in a token.
    """
    return assertion_hash(full_signed_identity_digest)


def _vector8(value, lengths, what):
    if type(value) is not bytes or len(value) not in lengths:
        raise ValueError("invalid " + what)
    return bytes((len(value),)) + value


def _parse_vector8(encoded, lengths, what):
    if not encoded or encoded[0] != len(encoded) - 1 or encoded[0] not in lengths:
        raise ProtocolError("invalid " + what, alert=50)
    return encoded[1:]


@dataclass(frozen=True)
class SignalingBinding:
    """Values from independently authenticated signaling for ONE connection.

    The caller verifies both identities and their credential fingerprints before
    constructing this policy. Empty hashes explicitly mean no identity assertion,
    not authenticated equality. Session IDs are the exact SDP tls-id ASCII bytes.
    This object never learns expected peer values from the TLS peer itself.
    """
    local_hash: bytes
    peer_hash: bytes
    local_session_id: bytes
    peer_session_id: bytes
    required: bool = True

    def __post_init__(self):
        for value in (self.local_hash, self.peer_hash):
            _vector8(value, (0, 32), "signaling assertion hash")
        for value in (self.local_session_id, self.peer_session_id):
            _vector8(value, range(20, 256), "signaling session identifier")
            if not value.isascii() or any(char < 33 or char > 126 for char in value):
                raise ValueError("SDP tls-id must use its exact printable ASCII encoding")
        if type(self.required) is not bool:
            raise ValueError("required must be boolean")

    def extensions(self):
        return {55: _vector8(self.local_hash, (0, 32), "signaling assertion hash"),
                56: _vector8(self.local_session_id, range(20, 256), "signaling session identifier")}

    def validate(self, extensions):
        for kind, expected, lengths in ((55, self.peer_hash, (0, 32)),
                                         (56, self.peer_session_id, range(20, 256))):
            encoded = extensions.get(kind)
            if encoded is None:
                if self.required:
                    raise ProtocolError("required signaling binding missing", alert=109)
                continue
            value = _parse_vector8(encoded, lengths, "signaling binding")
            if not hmac.compare_digest(value, expected):
                raise ProtocolError("external signaling binding mismatch", alert=47)

    def context(self):
        """Directional, unambiguous local ticket policy scope; not a wire field."""
        return hashlib.sha256(b"TLS20 signaling\x00" + bytes((self.required,)) + b"".join(
            bytes((len(value),)) + value for value in
            (self.local_hash, self.peer_hash, self.local_session_id, self.peer_session_id))).digest()


@dataclass(frozen=True)
class TicketRequest:
    new_session_count: int
    resumption_count: int

    def __post_init__(self):
        for value in (self.new_session_count, self.resumption_count):
            if type(value) is not int or not 0 <= value <= 255:
                raise ValueError("ticket count must fit uint8")

    def encode(self):
        return bytes((self.new_session_count, self.resumption_count))

    @classmethod
    def parse(cls, encoded):
        if len(encoded) != 2:
            raise ProtocolError("invalid ticket request", alert=50)
        return cls(encoded[0], encoded[1])

    def select(self, *, resumed, local_limit):
        if type(local_limit) is not int or not 0 <= local_limit <= 255:
            raise ValueError("local ticket issuance limit must fit uint8")
        return min(local_limit, self.resumption_count if resumed else self.new_session_count)


def ticket_hint(encoded):
    if len(encoded) != 1:
        raise ProtocolError("invalid ticket count hint", alert=50)
    return encoded[0]
