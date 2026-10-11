"""Connection-bound TLS 2.0 application authenticators (not TLS records).

Applications negotiate/framing ``tls20-authenticator`` themselves. A validator
must independently authorize every additional X.509 identity; this module never
promotes it to the original connection identity. Python cannot guarantee erasure
of immutable bytes or cryptographic provider allocations.
"""

from __future__ import annotations

from dataclasses import dataclass
import hmac
import inspect
import secrets
from types import SimpleNamespace

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey

from . import crypto as c
from . import messages as m
from .credential_selection import match_credentials, credential_algorithms_match
from .errors import ProtocolError


@dataclass(frozen=True)
class AuthenticatorRequest:
    wire: bytes
    context: bytes
    role: str
    verifier_share: bytes
    extensions: tuple[tuple[int, bytes], ...]

    @property
    def certificate_algorithms(self):
        return m._u16_list(dict(self.extensions)[50])


@dataclass(frozen=True)
class CertificateIdentity:
    chain: tuple[bytes, ...]
    extensions: tuple[tuple[tuple[int, bytes], ...], ...]
    context: bytes


@dataclass(frozen=True)
class AuthorizedIdentity:
    """Returned by the caller's credential AND application authorization policy."""

    public_key: X25519PublicKey
    identity: object


@dataclass(frozen=True)
class AuthenticationResult:
    authenticated: bool
    identity: object = None
    certificate: CertificateIdentity | None = None


def credential_validator(policy, *, role, authorize, spontaneous_offers=()):
    """Build a validator with current PKIX/DC/evidence and application policy.

    ``authorize(AuthorizedCredential)`` must return True for this application
    scope. It is a pure policy check, NOT notification of a completed proof: only
    the AuthenticationResult returned by validate() establishes key possession.
    Spontaneous offers must be the current connection's local capabilities, not
    a cached ticket's capabilities. An RPK handshake does not change EA's X.509
    representation. This never updates the original connection identity.
    """
    from .credential_profiles import CredentialPolicy, resolve_peer
    if not isinstance(policy, CredentialPolicy) or role not in ("server", "client") or not callable(authorize):
        raise ValueError("explicit credential, direction and application policies are required")
    spontaneous_offers = tuple(spontaneous_offers)

    async def validate(identity, request):
        if request is not None and request.role != role:
            raise ProtocolError("authenticator credential policy direction mismatch")
        offers = dict(request.extensions if request is not None else spontaneous_offers)
        _offers(offers, role)
        _check_status_responses(identity, offers, requested=request is not None)
        resolved = resolve_peer(identity.chain, 0, role, policy=policy,
            certificate_algorithms=m._u16_list(offers[50]),
            grant_algorithms=m._u16_list(offers[0xff04]) if 0xff04 in offers else (),
            delegated_schemes=m._u16_list(offers[34]) if 34 in offers else (),
            entry_extensions=identity.extensions, offered_extensions=tuple(offers))
        permitted = authorize(resolved)
        if inspect.isawaitable(permitted):
            permitted = await permitted
        if permitted is not True:
            raise ProtocolError("additional identity is not authorized for this application")
        return AuthorizedIdentity(resolved.public_key, resolved.identity)
    return validate


def _frame(kind, body):
    if not 0 <= len(body) < 1 << 24:
        raise ProtocolError("authenticator message length")
    return bytes((kind,)) + len(body).to_bytes(3, "big") + body


def _read_frame(reader, expected):
    kind = reader.take(1)[0]
    length = int.from_bytes(reader.take(3), "big")
    body = reader.take(length)
    if kind != expected:
        raise ProtocolError("unexpected authenticator message")
    return _frame(kind, body), body


def _offers(extensions, role):
    m.validate_delegation_offer(extensions)
    if 50 not in extensions:
        raise ProtocolError("authenticator request requires certificate path algorithms")
    algorithms = m._u16_list(extensions[50])
    if {0xfe00, 0xfe01} & set(algorithms):
        raise ProtocolError("MAC identifiers are not certificate path algorithms")
    if (34 in extensions) != (0xff04 in extensions):
        raise ProtocolError("delegation requires independent grant and MAC offers")
    if 34 in extensions:
        # An offer may contain only unknown or unsupported delegated schemes.
        # That disables delegation for this request, not direct credentials.
        # Credential selection and validation enforce the role's actual scheme.
        m._u16_list(extensions[34])
        grants = m._u16_list(extensions[0xff04])
        if {0xfe00, 0xfe01} & set(grants):
            raise ProtocolError("MAC identifiers are not grant signing algorithms")


def parse_request(wire):
    reader = m._Reader(wire)
    kind = reader.take(1)[0]
    body = m._Reader(reader.take(int.from_bytes(reader.take(3), "big")))
    reader.end()
    if kind not in (13, 17):
        raise ProtocolError("not an application authenticator request")
    role = "server" if kind == 17 else "client"
    context, extensions = body.vector(1), m.extensions(body.vector(2))
    body.end()
    m.validate_extension_context(extensions, "ASR" if role == "server" else "ACR")
    expected, forbidden = (0xff02, 0xff03) if role == "server" else (0xff03, 0xff02)
    if len(extensions.get(expected, b"")) != 32 or forbidden in extensions:
        raise ProtocolError("invalid application authenticator verifier share")
    # Unknown request extensions are ignored. Known handshake-only placements
    # cannot be repurposed as application authentication capabilities.
    if set(extensions) & {10, 16, 19, 20, 21, 28, 32, 41, 42, 43, 44, 45, 49, 51}:
        raise ProtocolError("misplaced application authenticator extension")
    if role == "client" and 0 in extensions:
        raise ProtocolError("server_name is only allowed in a client-generated request")
    _offers(extensions, role)
    _status_request(extensions, requested=True)
    return AuthenticatorRequest(wire, context, role, extensions[expected], tuple(extensions.items()))


def _certificate(chain, context, entry_extensions=None):
    if entry_extensions is None:
        entry_extensions = [()] * len(chain)
    if len(entry_extensions) != len(chain):
        raise ProtocolError("certificate extensions count mismatch")
    entries = []
    for der, extensions in zip(chain, entry_extensions):
        if not der:
            raise ProtocolError("empty certificate entry")
        values = b"".join(m.extension(kind, value) for kind, value in extensions)
        m.extensions(values)  # Reject duplicates and forbidden signature_algorithms.
        entries.append(m._vec(der, 3) + m._vec(values, 2))
    return _frame(11, m._vec(context, 1) + m._vec(b"".join(entries), 3))


def _parse_certificate(body):
    reader = m._Reader(body)
    context, entries = reader.vector(1), m._Reader(reader.vector(3))
    reader.end()
    chain, extensions = [], []
    while entries.position < len(entries.data):
        der = entries.vector(3)
        if not der:
            raise ProtocolError("empty authenticator certificate entry")
        chain.append(der)
        extensions.append(tuple(m.extensions(entries.vector(2), context="CE").items()))
    return CertificateIdentity(tuple(chain), tuple(extensions), context)


def _check_certificate_extensions(identity, offered):
    # EA always carries X.509 Certificate entries. It does not inherit an RPK
    # representation from the original handshake and never echoes request ff04.
    for index, entries in enumerate(identity.extensions):
        for kind, _value in entries:
            if kind not in offered or kind not in (5, 18, 34, 52, 59) or (kind == 34 and index):
                raise ProtocolError("unsolicited or misplaced authenticator certificate extension")


def _check_certificate_filters(identity, offered):
    if not match_credentials(SimpleNamespace(chain_der=identity.chain, credential_type=0), offered):
        raise ProtocolError("authenticator certificate does not satisfy requested OID filters")


def _credential_matches_algorithms(credentials, identity, offered, role, provider):
    return credential_algorithms_match(credentials, offered, role=role,
        signature_provider=provider, entry_extensions=identity.extensions)


def _status_request(offered, *, requested):
    from .status_request import parse_status_request
    # Both RFC9261 request structures use CR extensions: status_request is
    # empty. Only spontaneous server authentication inherits a full CH request.
    return parse_status_request(offered[5], certificate_request=requested) if 5 in offered else None


def _check_status_responses(identity, offered, *, requested):
    from .status_request import response_matches_request
    from .credential_evidence import _status_response
    request = _status_request(offered, requested=requested)
    for entries in identity.extensions:
        for kind, value in entries:
            if kind == 5 and not response_matches_request(_status_response(value), request):
                raise ProtocolError("OCSP evidence does not match the actual authenticator request")


def _proof(finished_key, private, share, transcript, role, name):
    hashed = c.digest(transcript, name)
    root = c.extract(finished_key, c.dh(private, share), name)
    key = c.label_expand(root, role + " ea mac", hashed, len(root), name)
    context = b" " * 64 + ("TLS 2.0, " + role + " exported authenticator").encode("ascii") + b"\0"
    return c.mac(key, context + hashed, name)


class AuthenticatorManager:
    """One manager per connection, shared across both application directions.

    Limits below are adjustable local memory budgets, not wire restrictions.
    At exhaustion fail closed; never evict consumed contexts and allow replay.
    """

    def __init__(self, channel, *, max_contexts=65536, max_message_bytes=1 << 20):
        if (type(max_contexts) is not int or max_contexts < 1
                or type(max_message_bytes) is not int or max_message_bytes < 8):
            raise ValueError("invalid authenticator resource budget")
        self.channel = channel
        self.max_contexts, self.max_message_bytes = max_contexts, max_message_bytes
        self._used, self._pending = set(), {}
        self._closed = False

    def _ready(self):
        if (self._closed or self.channel.closed or not self.channel.handshake_completed
                or self.channel.role not in ("client", "server")):
            raise ProtocolError("application authenticators require a completed open connection")

    def _claim(self, context):
        if not isinstance(context, bytes) or len(context) > 255:
            raise ProtocolError("authenticator context length")
        if context in self._used:
            raise ProtocolError("authenticator context already used")
        if len(self._used) >= self.max_contexts:
            raise ProtocolError("local authenticator context budget exhausted")
        self._used.add(context)

    def _bounded(self, wire):
        if not isinstance(wire, bytes) or len(wire) > self.max_message_bytes:
            raise ProtocolError("local authenticator message budget exhausted")

    def _keys(self, role):
        length = c.suite(self.channel.cipher_suite).hash_length
        return tuple(self.channel.exporter("EXPORTER-" + role + " authenticator " + label, b"", length)
                     for label in ("handshake context", "finished key"))

    def request(self, *, context=None, certificate_algorithms=None, extra_extensions=()):
        self._ready()
        context = secrets.token_bytes(32) if context is None else context
        role = "client" if self.channel.role == "server" else "server"
        private = X25519PrivateKey.generate()
        if certificate_algorithms is None:
            certificate_algorithms = m.CERT_ALGORITHMS
        extensions = [(50, m._vec(b"".join(x.to_bytes(2, "big") for x in certificate_algorithms), 2)),
                      (0xff03 if role == "client" else 0xff02, c.public_bytes(private)),
                      *extra_extensions]
        wire = _frame(13 if role == "client" else 17, m._vec(context, 1) + m._vec(
            b"".join(m.extension(kind, value) for kind, value in extensions), 2))
        self._bounded(wire)
        request = parse_request(wire)
        self._claim(context)
        self._pending[context] = (request, private)
        return wire

    def cancel(self, request):
        """Cancellation consumes a locally generated context and releases its key."""
        parsed = parse_request(request)
        pending = self._pending.get(parsed.context)
        if pending is None or pending[0].wire != request:
            raise ProtocolError("not a pending local authenticator request")
        del self._pending[parsed.context]

    def close(self):
        self._pending.clear()
        self._closed = True

    def authenticate(self, credentials=None, *, request=None, context=None, entry_extensions=None):
        self._ready()
        role = self.channel.role
        if request is not None:
            self._bounded(request)
            parsed = parse_request(request)
            if parsed.role != role or context is not None:
                raise ProtocolError("authenticator request direction or context mismatch")
            context, share, offers = parsed.context, parsed.verifier_share, dict(parsed.extensions)
        else:
            if role != "server" or credentials is None or not self.channel.peer_auth_share:
                raise ProtocolError("unsolicited client authenticator or missing server capability")
            if not self.channel.enable_authenticators:
                raise ProtocolError("spontaneous authenticators were not enabled")
            context = secrets.token_bytes(32) if context is None else context
            share, offers = self.channel.peer_auth_share, dict(self.channel.peer_capabilities)
            _offers(offers, "server")
        certificate = _certificate([] if credentials is None else credentials.chain_der,
                                   context, entry_extensions)
        identity = _parse_certificate(certificate[4:])
        # A local delegated identity can be unavailable because delegation was
        # not offered; other unsolicited/misplaced entry extensions still fail.
        _check_certificate_extensions(identity, {**offers, 34: offers.get(34, b"")})
        if 5 in offers:
            from .status_request import response_matches_request
            from .credential_evidence import _status_response
            status = _status_request(offers, requested=request is not None)
            metadata = tuple(tuple((kind, value) for kind, value in entries
                if kind != 5 or response_matches_request(_status_response(value), status))
                for entries in identity.extensions)
            certificate = _certificate(identity.chain, context, metadata)
            identity = _parse_certificate(certificate[4:])
        if credentials is not None and (not _credential_matches_algorithms(
                credentials, identity, offers, role, self.channel.native_provider)
                or not match_credentials(credentials, offers)):
            if request is None:
                raise ProtocolError("no acceptable spontaneous authenticator credential")
            # A valid identity outside the current request's path/grant or
            # recognized KU/EKU constraints produces an authenticated refusal.
            credentials, entry_extensions = None, None
            certificate = _certificate([], context)
            identity = _parse_certificate(certificate[4:])
        self._claim(context)
        handshake_context, finished_key = self._keys(role)
        name = c.hash_context(c.suite(self.channel.cipher_suite).hash_name, self.channel.native_provider)
        _check_certificate_extensions(identity, offers)
        transcript = handshake_context + (request or b"") + certificate
        if credentials is None:
            return _frame(20, c.mac(finished_key, c.digest(transcript, name), name))
        if not identity.chain or not isinstance(credentials.private_key, X25519PrivateKey):
            raise ProtocolError("authenticator requires an X25519 credential")
        # Delegated credentials are validated by the credential provider. Direct
        # credentials must actually contain the proof key, not an arbitrary key.
        if 34 not in dict(identity.extensions[0]):
            try:
                public = x509.load_der_x509_certificate(identity.chain[0]).public_key()
            except ValueError as exc:
                raise ProtocolError("invalid authenticator X.509 credential") from exc
            if not isinstance(public, X25519PublicKey) or c.public_bytes(public) != c.public_bytes(credentials.private_key):
                raise ProtocolError("authenticator credential/key mismatch")
        proof = _proof(finished_key, credentials.private_key, share, transcript, role, name)
        cv = _frame(15, (0xfe00 if role == "server" else 0xfe01).to_bytes(2, "big") + m._vec(proof, 2))
        final = _frame(20, c.mac(finished_key, c.digest(transcript + cv, name), name))
        wire = certificate + cv + final
        self._bounded(wire)
        return wire

    async def validate(self, authenticator, validator, *, request=None):
        """Validate with a locally retained verifier key and explicit trust policy.

        ``validator(CertificateIdentity, AuthenticatorRequest | None)`` must
        return AuthorizedIdentity after checking path, evidence, the request's
        independent algorithm lists, role, expected name and application scope.
        An authenticated refusal returns authenticated=False, never an identity.
        """
        self._ready()
        self._bounded(authenticator)
        role = "server" if self.channel.role == "client" else "client"
        reader = m._Reader(authenticator)
        refusal = authenticator[:1] == b"\x14"
        identity, certificate = None, None
        if refusal:
            if request is None:
                raise ProtocolError("refusal requires its exact local request")
            self._bounded(request)
            parsed = parse_request(request)
            context = parsed.context
        else:
            certificate, body = _read_frame(reader, 11)
            identity = _parse_certificate(body)
            context = identity.context
            if not identity.chain:
                raise ProtocolError("empty Certificate is not an authenticated refusal")
        pending = self._pending.get(context)
        if pending is not None:
            parsed, private = pending
            if request is not None and parsed.wire != request:
                raise ProtocolError("authenticator does not match retained local request")
            request = parsed.wire
            offers = dict(parsed.extensions)
            del self._pending[context]  # Consume even if subsequent validation fails.
        else:
            if request is not None or role != "server" or refusal:
                raise ProtocolError("no retained local authenticator request")
            if (not self.channel.enable_authenticators or self.channel.auth_share_secret is None):
                raise ProtocolError("spontaneous authenticator capability is unavailable")
            self._claim(context)
            parsed, private = None, self.channel.auth_share_secret
            offers = dict(self.channel.local_capabilities)
            _offers(offers, role)
        handshake_context, finished_key = self._keys(role)
        name = c.hash_context(c.suite(self.channel.cipher_suite).hash_name, self.channel.native_provider)
        if refusal:
            certificate = _certificate([], context)
        transcript = handshake_context + (request or b"") + certificate
        authorized = None
        if not refusal:
            _check_certificate_extensions(identity, offers)
            _check_certificate_filters(identity, offers)
            cv, body = _read_frame(reader, 15)
            cv_reader = m._Reader(body)
            algorithm, proof = int.from_bytes(cv_reader.take(2), "big"), cv_reader.vector(2)
            cv_reader.end()
            if algorithm != (0xfe00 if role == "server" else 0xfe01) or len(proof) != len(finished_key):
                raise ProtocolError("invalid application authenticator MAC envelope")
            authorized = validator(identity, parsed)
            if inspect.isawaitable(authorized):
                authorized = await authorized
            self._ready()  # A concurrent close cancels pending authorization.
            if not isinstance(authorized, AuthorizedIdentity) or not isinstance(authorized.public_key, X25519PublicKey):
                raise ProtocolError("identity policy did not authorize an X25519 credential")
            expected = _proof(finished_key, private, c.public_bytes(authorized.public_key), transcript, role, name)
            if not hmac.compare_digest(proof, expected):
                raise ProtocolError("application authenticator MAC failed")
            transcript += cv
        _finished, value = _read_frame(reader, 20)
        reader.end()
        expected = c.mac(finished_key, c.digest(transcript, name), name)
        if len(value) != len(expected) or not hmac.compare_digest(value, expected):
            raise ProtocolError("application authenticator Finished failed")
        return AuthenticationResult(not refusal, authorized.identity if authorized else None, identity)
