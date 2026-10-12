"""Explicit TLS 2.0 credential policies, not implicit trust from wire parsing.

The generic PKIX provider validates paths; this layer binds their authorized
identity to X25519 or a role-specific offline delegation. RPKs require an exact
locally provisioned binding. External evidence validators remain explicit and
are never substituted by successfully decoding the evidence.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
from typing import Callable

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, ed448, padding, rsa, x25519
from cryptography.x509 import ocsp
from cryptography.x509.oid import ExtendedKeyUsageOID

from .errors import ProtocolError
from .pki import (SUPPORTED_CERTIFICATE_ALGORITHMS, _load_pkix_der,
                  certificate_extensions,
                  certificate_public_key, certificate_signature_scheme,
                  find_certificate_issuer,
                  evidence_for_validated_path,
                  supported_certificate_algorithms, SM2_CERTIFICATE_IDENTIFIER,
                  validate_identity, verify_public_signature)


X25519_SPKI_PREFIX = bytes.fromhex("302a300506032b656e032100")
DELEGATION_USAGE = x509.ObjectIdentifier("1.3.6.1.4.1.44363.44")


@dataclass(frozen=True)
class RawPublicKeyBinding:
    role: str
    identity: str
    spki: bytes


@dataclass(frozen=True)
class CredentialPolicy:
    trust_roots: tuple = ()
    peer_name: str | None = None
    raw_public_keys: tuple[RawPublicKeyBinding, ...] = ()
    revocation_policy: str = "offline"
    evidence_validator: Callable | None = None
    authorize_client: Callable | None = None
    now: datetime | None = None
    max_delegated_lifetime_seconds: int = 604800
    require_delegation: bool = False
    dane_policy: object = None
    signature_provider: object = None
    its_policy: object = None


@dataclass(frozen=True)
class AuthorizedCredential:
    public_key: x25519.X25519PublicKey
    identity: str
    provenance: str
    material: tuple[bytes, ...]
    evidence: tuple
    expires_at: datetime | None = None


def parse_x25519_spki(value: bytes) -> x25519.X25519PublicKey:
    """Parse the exact RFC 8410 form and reject low-order/all-zero agreement."""
    if not isinstance(value, bytes) or len(value) != 44 or not value.startswith(X25519_SPKI_PREFIX):
        raise ProtocolError("credential must contain a canonical X25519 SPKI")
    try:
        key = x25519.X25519PublicKey.from_public_bytes(value[12:])
        x25519.X25519PrivateKey.from_private_bytes(bytes(range(32))).exchange(key)
        return key
    except ValueError as exc:
        raise ProtocolError("invalid X25519 credential public key") from exc


def _read_vector(data, cursor, width):
    if cursor + width > len(data):
        raise ProtocolError("truncated credential vector")
    size = int.from_bytes(data[cursor:cursor + width], "big")
    cursor += width
    if not size or cursor + size > len(data):
        raise ProtocolError("invalid credential vector length")
    return data[cursor:cursor + size], cursor + size


def _entry_metadata(material, entry_extensions, offered_extensions, delegated_schemes):
    if not entry_extensions:
        return tuple(() for _ in material)
    if len(entry_extensions) != len(material):
        raise ProtocolError("certificate entry metadata count mismatch")
    output = []
    for index, extensions in enumerate(entry_extensions):
        pairs = tuple(extensions.items()) if isinstance(extensions, dict) else tuple(extensions)
        seen = set()
        for kind, value in pairs:
            if kind == 17:
                raise ProtocolError("status_request_v2 is forbidden in CertificateEntry")
            if kind in seen or not isinstance(value, bytes):
                raise ProtocolError("duplicate or malformed certificate evidence")
            seen.add(kind)
            if kind == 34:
                if index != 0 or not delegated_schemes:
                    raise ProtocolError("unsolicited or misplaced delegated credential")
            elif kind not in offered_extensions:
                raise ProtocolError("unsolicited certificate entry extension")
        output.append(pairs)
    return tuple(output)


def validate_delegation(parent_der, grant, *, role, grant_algorithms,
                        delegated_schemes, now=None, max_lifetime_seconds=604800,
                        signature_provider=None):
    """Verify a grant only AFTER its parent path/identity has been validated."""
    if role not in ("server", "client") or len(grant) < 13:
        raise ProtocolError("invalid delegated credential")
    expected_scheme = 0xfe00 if role == "server" else 0xfe01
    valid_time = int.from_bytes(grant[:4], "big")
    online_scheme = int.from_bytes(grant[4:6], "big")
    spki, offset = _read_vector(grant, 6, 3)
    if offset + 2 > len(grant):
        raise ProtocolError("truncated delegation signature scheme")
    signed = grant[:offset + 2]
    scheme = int.from_bytes(grant[offset:offset + 2], "big")
    signature, end = _read_vector(grant, offset + 2, 2)
    if end != len(grant) or online_scheme != expected_scheme or online_scheme not in delegated_schemes:
        raise ProtocolError("delegation direction or proof scheme mismatch")
    if scheme not in grant_algorithms or scheme not in supported_certificate_algorithms(signature_provider):
        raise ProtocolError("delegation signature scheme was not authorized")
    parent = _load_pkix_der(parent_der)
    try:
        usage = certificate_extensions(parent).get_extension_for_oid(DELEGATION_USAGE)
        if usage.critical or not isinstance(usage.value, x509.UnrecognizedExtension) or usage.value.value != b"\x05\x00":
            raise ProtocolError("invalid DelegationUsage extension")
        if not certificate_extensions(parent).get_extension_for_class(x509.KeyUsage).value.digital_signature:
            raise ProtocolError("delegation parent cannot sign grants")
    except x509.ExtensionNotFound as exc:
        raise ProtocolError("certificate does not authorize delegation") from exc
    moment = now or datetime.now(timezone.utc)
    if isinstance(max_lifetime_seconds, bool) or not isinstance(max_lifetime_seconds, int) or max_lifetime_seconds <= 0:
        raise ProtocolError("invalid delegated credential lifetime policy")
    expiry = parent.not_valid_before_utc + timedelta(seconds=valid_time)
    if (not parent.not_valid_before_utc <= moment <= expiry
            or expiry >= parent.not_valid_after_utc
            or expiry > moment + timedelta(seconds=max_lifetime_seconds)):
        raise ProtocolError("delegated credential is outside its authorized lifetime")
    parent_oid = parent.public_key_algorithm_oid.dotted_string
    if ((scheme in (0x0804, 0x0805, 0x0806) and parent_oid != "1.2.840.113549.1.1.1")
            or (scheme in (0x0809, 0x080a, 0x080b) and parent_oid != "1.2.840.113549.1.1.10")):
        raise ProtocolError("delegation signature family mismatches parent SPKI")
    public_key = parse_x25519_spki(spki)
    message = b" " * 64 + f"TLS20 {role} delegated credentials".encode("ascii") + b"\x00" + parent_der + signed
    verify_public_signature(certificate_public_key(parent, signature_provider=signature_provider), scheme, signature, message)
    return public_key, expiry


def _mandatory_evidence_validator(policy, material, evidence, offered_extensions, negotiated_extensions):
    """Bind enabled certificate requirements to actual protocol offers.

    Offline revocation policy is not a waiver for a feature the endpoint has
    offered and its certificate requires. Unknown *unoffered* registry values
    remain harmless. An offered evidence requirement needs an installed
    validator, not merely a syntactically present blob or the word 'offline'.
    Other features must be satisfied by the protocol's real selection state.
    """
    from .tls_features import certificate_features
    required = certificate_features(_load_pkix_der(material[0])).intersection(offered_extensions)
    validator = policy.evidence_validator
    leaf = dict(evidence[0]) if evidence else {}
    # Only the protocol caller supplies authenticated selection state. Policy
    # configuration is not evidence that a peer negotiated an extension.
    if required - set(leaf) - set(negotiated_extensions):
        raise ProtocolError("an offered mandatory TLS Feature was not satisfied")
    if required.intersection((5, 18, 52)) - set(leaf):
        raise ProtocolError("required offered certificate evidence is absent")
    if required.intersection((5, 18, 52)) and validator is None:
        raise ProtocolError("mandatory offered TLS Feature has no installed validator")
    from .credential_evidence import CredentialEvidencePolicy
    if isinstance(validator, CredentialEvidencePolicy):
        # The standard policy must use this handshake's real offers. A caller
        # may strengthen minimum counts, but cannot accidentally suppress a
        # mandatory CT check by leaving the optional minimum at its default 0.
        validator = replace(validator, offered_extensions=tuple(offered_extensions),
            negotiated_extensions=tuple(negotiated_extensions),
            enforce_tls_feature=True, require_ocsp=validator.require_ocsp or 5 in required,
            minimum_ct_v1_logs=max(validator.minimum_ct_v1_logs, int(18 in required)),
            minimum_ct_v2_logs=max(validator.minimum_ct_v2_logs, int(52 in required)))
    return validator


def resolve_peer(material, credential_type=0, role="server", *, policy,
                 certificate_algorithms=SUPPORTED_CERTIFICATE_ALGORITHMS,
                 grant_algorithms=(), delegated_schemes=(), entry_extensions=(),
                 offered_extensions=(), negotiated_extensions=(), feature_offers=None):
    """Resolve current authenticated X.509/DC/RPK material to a MAC proof key.

    An AuthorizedCredential does not assert the peer possesses its key: the
    handshake/application authenticator still MUST verify MAC and Finished.
    Client authorization is an explicit application callback, not trust-root
    membership alone. No unauthenticated fallback is selected here.
    """
    if not isinstance(policy, CredentialPolicy) or role not in ("server", "client"):
        raise ProtocolError("explicit credential policy and direction are required")
    material = tuple(material)
    if not material or len(material) > 64 or sum(len(x) for x in material) > 262144:
        raise ProtocolError("credential material exceeds local budget")
    evidence = _entry_metadata(material, entry_extensions, offered_extensions, delegated_schemes)
    if credential_type == 0 and (not certificate_algorithms or any(value in (
            0xfe00, 0xfe01, 0x0420, 0x0520, 0x0620) for value in certificate_algorithms)):
        raise ProtocolError("invalid certificate signature offer")
    identity = policy.peer_name or ""
    dane_usage, dane_expiry = None, None
    dane_path = ()
    if policy.dane_policy is not None:
        from .dnssec_credentials import DANEPolicy
        if role != "server" or not isinstance(policy.dane_policy, DANEPolicy):
            raise ProtocolError("DNSSEC credential binding requires an explicit server DANE policy")
        def path_constraints(path, anchor):
            # Check actual path signatures, not the provider's global supported
            # list or the independent delegated-grant offer. Do this before a
            # TLSA candidate is selected so another authorized path can succeed.
            if path:
                pairs = zip(path, path[1:])  # The trust anchor's signature is exempt.
            else:
                # Legacy boolean callbacks expose no path. Conservatively check
                # supplied certificates against cryptographically matching known
                # issuers, exempting only the exact authenticated DANE anchor.
                certificates = tuple(_load_pkix_der(value) for value in material)
                encoded_anchor = anchor.public_bytes(serialization.Encoding.DER)
                issuers = tuple(dict.fromkeys((*material, encoded_anchor)))
                pairs = ((cert, find_certificate_issuer(cert, issuers,
                    signature_provider=policy.signature_provider)) for cert in certificates
                    if cert.public_bytes(serialization.Encoding.DER) != encoded_anchor)
            for cert, issuer in pairs:
                if issuer is None or certificate_signature_scheme(cert, issuer) not in certificate_algorithms:
                    raise ProtocolError("certificate signature was not offered")
            return True
        authorization = policy.dane_policy.authorize(material, credential_type,
            identity, evidence, now=policy.now, return_authorization=True,
            path_constraints=path_constraints if credential_type == 0 else None)
        dane_usage, dane_expiry = authorization.usage, authorization.expires_at
        dane_path = authorization.validated_path
    if credential_type == 2:
        if (len(material) != 1 or policy.require_delegation
                or any(kind != 59 for item in evidence for kind, _ in item)):
            raise ProtocolError("unsupported raw-key evidence or representation")
        key = parse_x25519_spki(material[0])
        if not identity or dane_usage is None and not any(binding.role == role and binding.identity == identity
                and hmac.compare_digest(binding.spki, material[0]) for binding in policy.raw_public_keys):
            raise ProtocolError("raw public key has no authorized identity binding")
        return AuthorizedCredential(key, identity, "dane-rpk" if dane_usage is not None else "provisioned-rpk",
                                    material, evidence, datetime.fromtimestamp(dane_expiry, timezone.utc)
                                    if dane_expiry is not None else None)
    if credential_type == 3:
        from .its_credentials import ITSServicePolicy
        if (len(material) != 1 or any(evidence) or policy.require_delegation
                or policy.dane_policy is not None or not isinstance(policy.its_policy, ITSServicePolicy)):
            raise ProtocolError("ITS requires one grant and an explicit ITS application policy")
        key, expiry, _ = policy.its_policy.authorize(material[0], role=role, identity=identity, now=policy.now)
        return AuthorizedCredential(key, identity, "its-x25519-grant", material,
                                    evidence, expiry)
    if credential_type != 0:
        raise ProtocolError("credential representation has no installed trust provider")
    grant = dict(evidence[0]).get(34)
    if policy.require_delegation and grant is None:
        raise ProtocolError("required delegated credential is absent")
    if grant is not None and (not grant_algorithms or not certificate_algorithms):
        raise ProtocolError("delegation requires independent certificate and grant offers")
    evidence_validator = _mandatory_evidence_validator(policy, material, evidence,
        offered_extensions if feature_offers is None else feature_offers, negotiated_extensions)
    if dane_usage is not None:
        # DANE-EE authenticates the exact endpoint material independently of
        # CA trust, certificate names and validity. Other usages have already
        # performed their explicit PKIX/DANE path callback inside DANEPolicy.
        key = certificate_public_key(_load_pkix_der(material[0]), signature_provider=policy.signature_provider)
        if grant is None:
            spki = key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
            key = parse_x25519_spki(spki)
        if evidence_validator is not None:
            path = dane_path or tuple(_load_pkix_der(value) for value in material)
            path_evidence = evidence
            if dane_path:
                # The validated path can add a DNS-published or local trust
                # anchor and can reorder supplied intermediates. Preserve each
                # entry's evidence binding instead of shifting it by position.
                path_evidence = evidence_for_validated_path(material, evidence, path)
            # In particular DANE-EE authenticates the endpoint, not arbitrary
            # issuer certificates appended by its peer. OCSP/CT policy must not
            # accept an attacker-selected issuer key merely because it occupies
            # index 1. Authenticate each supplied issuer relationship before
            # treating this ordered material as a source of evidence issuers.
            # This is NOT extra PKIX trust/expiry imposed on DANE-EE: DNSSEC
            # remains its authority; the checks only bind evidence to the leaf.
            for child, issuer in zip(path, path[1:]):
                if child.issuer != issuer.subject:
                    raise ProtocolError("DANE evidence issuer identity is not bound to its certificate")
                verify_public_signature(certificate_public_key(issuer, signature_provider=policy.signature_provider),
                    certificate_signature_scheme(child, issuer), child.signature, child.tbs_certificate_bytes,
                    sm2_identifier=SM2_CERTIFICATE_IDENTIFIER, gost_certificate_encoding=True)
            if evidence_validator(path, role, path_evidence, policy.now or datetime.now(timezone.utc)) is not True:
                raise ProtocolError("additional DANE credential evidence policy failed")
        elif policy.revocation_policy == "require-evidence":
            raise ProtocolError("required credential status validator is unavailable")
    else:
        key = validate_identity(list(material), trust_roots=policy.trust_roots,
            role=role, name=policy.peer_name, offered_certificate_algorithms=certificate_algorithms,
            revocation_policy=policy.revocation_policy, evidence_validator=evidence_validator,
            evidence=evidence, now=policy.now, signing_leaf=grant is not None,
            signature_provider=policy.signature_provider)
    if role == "client":
        if policy.authorize_client is None or policy.authorize_client(material, evidence) is not True:
            raise ProtocolError("client identity has not been authorized by the application")
        identity = identity or hashlib.sha256(material[0]).hexdigest()
    expiry = _load_pkix_der(material[0]).not_valid_after_utc
    if grant is not None:
        key, expiry = validate_delegation(material[0], grant, role=role,
            grant_algorithms=grant_algorithms, delegated_schemes=delegated_schemes,
            now=policy.now, max_lifetime_seconds=policy.max_delegated_lifetime_seconds,
            signature_provider=policy.signature_provider)
    if dane_expiry is not None:
        dns_expiry = datetime.fromtimestamp(dane_expiry, timezone.utc)
        expiry = min(expiry, dns_expiry) if grant is not None else dns_expiry
    provenance = ("dane-x509-delegated" if grant is not None else "dane-x509") if dane_usage is not None else (
                   "x509-delegated" if grant is not None else "x509")
    return AuthorizedCredential(key, identity, provenance,
                                material, evidence, expiry)


def validate_ocsp_response(response_der, certificate, issuer, *, now=None,
                           expected_nonce=None, max_age_seconds=86400):
    """Validate one stapled OCSP response with a provider-backed signature.

    No network retrieval is performed. Delegated responders must be directly
    issued by the certificate issuer, valid now, and authorized for OCSP signing.
    A responder certificate alone is not an independent trust anchor.
    """
    from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
    try:
        if not isinstance(response_der, bytes) or not 1 <= len(response_der) <= 1024 * 1024:
            raise ProtocolError("OCSP response exceeds local size budget")
        response = ocsp.load_der_ocsp_response(response_der)
        if response.response_status != ocsp.OCSPResponseStatus.SUCCESSFUL:
            raise ProtocolError("OCSP response did not succeed")
        moment = now or datetime.now(timezone.utc)
        if max_age_seconds <= 0 or response.produced_at_utc > moment:
            raise ProtocolError("invalid OCSP response time")
        for extension in response.extensions:
            if extension.critical and not isinstance(extension.value, x509.OCSPNonce):
                raise ProtocolError("unrecognized critical OCSP response extension")
        algorithm = response.signature_hash_algorithm
        if algorithm is not None and algorithm.name not in ("sha256", "sha384", "sha512"):
            raise ProtocolError("OCSP signature is disallowed by local algorithm policy")
        for candidate in [issuer, *response.certificates]:
            # ResponderID locates candidates, not a unique authorized signer:
            # key rollover can produce several certificates with the same DN.
            # Do not commit to a candidate until its signature also verifies.
            try:
                signer = candidate.public_key()
                if response.responder_name is not None:
                    if response.responder_name != candidate.subject:
                        continue
                elif response.responder_key_hash is not None:
                    # The responderKeyHash is SHA-1 over subjectPublicKey bits.
                    key_hash = x509.SubjectKeyIdentifier.from_public_key(signer).digest
                    if not hmac.compare_digest(response.responder_key_hash, key_hash):
                        continue
                else:
                    continue
                if candidate.public_bytes(serialization.Encoding.DER) != issuer.public_bytes(serialization.Encoding.DER):
                    candidate.verify_directly_issued_by(issuer)
                    for extension in certificate_extensions(candidate):
                        if extension.critical and not isinstance(extension.value, (
                                x509.BasicConstraints, x509.KeyUsage, x509.ExtendedKeyUsage)):
                            raise ProtocolError("unsupported critical OCSP responder constraint")
                    if not candidate.not_valid_before_utc <= moment <= candidate.not_valid_after_utc:
                        continue
                    eku = certificate_extensions(candidate).get_extension_for_class(x509.ExtendedKeyUsage).value
                    if ExtendedKeyUsageOID.OCSP_SIGNING not in eku:
                        continue
                    try:
                        if not certificate_extensions(candidate).get_extension_for_class(x509.KeyUsage).value.digital_signature:
                            continue
                    except x509.ExtensionNotFound:
                        pass
                if isinstance(signer, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
                    signer.verify(response.signature, response.tbs_response_bytes)
                elif isinstance(signer, ec.EllipticCurvePublicKey):
                    signer.verify(response.signature, response.tbs_response_bytes, ec.ECDSA(algorithm))
                elif isinstance(signer, rsa.RSAPublicKey) and response.signature_algorithm_oid.dotted_string in (
                        "1.2.840.113549.1.1.11", "1.2.840.113549.1.1.12", "1.2.840.113549.1.1.13"):
                    signer.verify(response.signature, response.tbs_response_bytes, padding.PKCS1v15(), algorithm)
                else:
                    continue
            except (ValueError, TypeError, InvalidSignature, UnsupportedAlgorithm,
                    x509.ExtensionNotFound, x509.DuplicateExtension):
                # Invalid/unauthorized auxiliary certificates must not mask a
                # later valid signer. No candidate can bypass these checks.
                continue
            else:
                break
        else:
            raise ProtocolError("OCSP response validation failed: no authorized responder signature")
        _check_ocsp_single_extensions(response.tbs_response_bytes)
        if expected_nonce is not None:
            nonce = response.extensions.get_extension_for_class(x509.OCSPNonce).value.nonce
            if not hmac.compare_digest(nonce, expected_nonce):
                raise ProtocolError("OCSP nonce does not match the request")
        matches = []
        for status in response.responses:
            reference = ocsp.OCSPRequestBuilder().add_certificate(certificate, issuer, status.hash_algorithm).build()
            if (status.serial_number == reference.serial_number
                    and hmac.compare_digest(status.issuer_name_hash, reference.issuer_name_hash)
                    and hmac.compare_digest(status.issuer_key_hash, reference.issuer_key_hash)):
                matches.append(status)
        if len(matches) != 1:
            raise ProtocolError("OCSP certificate binding is missing or ambiguous")
        status = matches[0]
        if (status.certificate_status != ocsp.OCSPCertStatus.GOOD or status.this_update_utc > moment
                or status.this_update_utc > response.produced_at_utc
                or moment - status.this_update_utc > timedelta(seconds=max_age_seconds)
                or status.next_update_utc is not None and (moment > status.next_update_utc
                    or status.next_update_utc < status.this_update_utc)):
            raise ProtocolError("OCSP status is not currently good")
        return True
    except (ValueError, TypeError, InvalidSignature, UnsupportedAlgorithm,
            x509.ExtensionNotFound, x509.DuplicateExtension) as exc:
        if isinstance(exc, ProtocolError):
            raise
        raise ProtocolError("OCSP response validation failed") from exc


def _check_ocsp_single_extensions(tbs_response):
    """Reject unprocessed critical SingleResponse extensions after signature.

    cryptography exposes response-wide extensions, but not per-entry extensions
    on its multi-response iterator. This bounded DER walk only enforces their
    criticality/uniqueness; it is not an alternate signature or status validator.
    """
    from .pki import _element, _children
    tag, body, end, _ = _element(tbs_response)
    fields = _children(body)
    offset = 1 if fields and fields[0][0] == 0xa0 else 0
    if tag != 0x30 or end != len(tbs_response) or len(fields) < offset + 3:
        raise ProtocolError("malformed OCSP ResponseData")
    responses = fields[offset + 2]
    if responses[0] != 0x30:
        raise ProtocolError("malformed OCSP SingleResponses")
    for tag, body, _ in _children(responses[1]):
        if tag != 0x30:
            raise ProtocolError("malformed OCSP SingleResponse")
        fields = _children(body)
        for tag, body, _ in fields[3:]:
            if tag != 0xa1:
                continue  # nextUpdate [0] has already been parsed by provider.
            wrapped = _children(body)
            if len(wrapped) != 1 or wrapped[0][0] != 0x30:
                raise ProtocolError("malformed OCSP single extensions")
            seen = set()
            for tag, body, _ in _children(wrapped[0][1]):
                parts = _children(body)
                if (tag != 0x30 or len(parts) not in (2, 3) or parts[0][0] != 0x06
                        or parts[-1][0] != 0x04 or parts[0][1] in seen):
                    raise ProtocolError("malformed or duplicate OCSP single extension")
                seen.add(parts[0][1])
                if len(parts) == 3:
                    if parts[1][0] != 0x01 or parts[1][1] not in (b"\x00", b"\xff"):
                        raise ProtocolError("malformed OCSP extension criticality")
                    if parts[1][1] == b"\xff":
                        raise ProtocolError("unprocessed critical OCSP single extension")
