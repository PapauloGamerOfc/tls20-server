"""Explicit provisioning inventory and proof-release gates for TLS20-POK.

The public BSK is a sensitive provisioning datum, not a general trust anchor.
Resolving the public-derived PSK proves NO private-key possession. Only the
combined handshake's verified client MAC and Finished authorize bootstrap.
"""

from dataclasses import dataclass
from datetime import datetime, timezone
import hmac
import hashlib

from cryptography.hazmat.primitives.asymmetric import x25519

from .credential_profiles import (AuthorizedCredential, CredentialPolicy,
                                  RawPublicKeyBinding, parse_x25519_spki)
from .errors import ProtocolError
from .pki import Credentials, _load_pkix_der
from .psk import bootstrap_public_key_psk


@dataclass(frozen=True, repr=False)
class BootstrapBinding:
    spki: bytes
    service: str
    scope: str
    trust_mode: str = "credential-validated"
    target_hashes: tuple[str, ...] = ("sha256", "sha384")
    expires_at: datetime | None = None

    def __post_init__(self):
        parse_x25519_spki(self.spki)
        if (not self.service or not self.scope or self.trust_mode not in (
                "credential-validated", "provisioning-trust") or not self.target_hashes
                or any(value not in ("sha256", "sha384") for value in self.target_hashes)
                or len(set(self.target_hashes)) != len(self.target_hashes)):
            raise ProtocolError("invalid explicit bootstrap provisioning binding")
        if self.expires_at is not None and self.expires_at.tzinfo is None:
            raise ProtocolError("bootstrap expiry must include its time zone")


def resolve_bootstrap_identity(identity: bytes, bindings, *, service: str, now=None):
    """Return the exact current local binding and imported PSK, never identity trust."""
    moment = now or datetime.now(timezone.utc)
    result = None
    if len(identity) > 65535:
        raise ProtocolError("bootstrap identity exceeds wire length")
    for binding in bindings:
        if not isinstance(binding, BootstrapBinding) or binding.service != service:
            continue
        if binding.expires_at is not None and moment >= binding.expires_at:
            continue
        for target_hash in binding.target_hashes:
            record = bootstrap_public_key_psk(binding.spki[12:], binding.service, target_hash=target_hash)
            if hmac.compare_digest(record.identity, identity):
                if result is not None and result[0] != binding:
                    raise ProtocolError("ambiguous bootstrap provisioning authority")
                result = binding, record
    if result is None:
        raise ProtocolError("bootstrap identity is not currently provisioned for this service")
    return result


def require_bootstrap_flight(*, combined, fresh_key_share, initial_early_data,
                             client_credential_type, client_request_present):
    if (combined is not True or fresh_key_share is not True or initial_early_data
            or client_credential_type != 2 or client_request_present is not True):
        raise ProtocolError("TLS20-POK requires combined fresh agreement and requested client RPK")


def bootstrap_client_material(binding, *, server_mac_verified, server_finished_verified,
                              combined, fresh_key_share, initial_early_data,
                              client_credential_type, client_request_present):
    """Caller may release the BSK only after BOTH server proofs were checked."""
    require_bootstrap_flight(combined=combined, fresh_key_share=fresh_key_share,
        initial_early_data=initial_early_data, client_credential_type=client_credential_type,
        client_request_present=client_request_present)
    if server_mac_verified is not True or server_finished_verified is not True:
        raise ProtocolError("bootstrap public key release precedes authenticated server Finished")
    if not isinstance(binding, BootstrapBinding):
        raise ProtocolError("bootstrap provisioning binding is required")
    _current_binding(binding)
    return (binding.spki,)


def authorize_bootstrap_client(binding, material, *, credential_type,
                                client_mac_verified, client_finished_verified):
    if not isinstance(binding, BootstrapBinding) or credential_type != 2 or tuple(material) != (binding.spki,):
        raise ProtocolError("bootstrap client key differs from the selected provisioned BSK")
    if client_mac_verified is not True or client_finished_verified is not True:
        raise ProtocolError("bootstrap authorization requires client MAC and Finished")
    _current_binding(binding)
    # Explicit provenance is also the resumption authorization label. A ticket
    # must retain scope/trust_mode and recheck inventory; this is not Web-PKI.
    return {"profile": "tls20-pok", "scope": binding.scope, "service": binding.service,
            "trust_mode": binding.trust_mode, "bsk": binding.spki,
            "fresh_client_possession": True}


def provisioning_server_key(material, credential_type, *, binding,
                             entry_extensions=(), normal_httpps=False):
    """Narrow explicit trust exception; never a fallback after PKIX failure.

    Only ordinary X25519 X.509/RPK material can waive PKIX here. Delegation,
    DNSSEC, pinning and ITS have independent authority and must use their real
    validators instead. The caller still verifies server MAC AND Finished.
    """
    if (not isinstance(binding, BootstrapBinding) or binding.trust_mode != "provisioning-trust"
            or normal_httpps or any(entry_extensions)):
        raise ProtocolError("provisioning trust was not explicitly selected for this application")
    material = tuple(material)
    if not material or len(material) > 64 or sum(len(value) for value in material) > 262144:
        raise ProtocolError("invalid provisioning server credential")
    if credential_type == 2 and len(material) == 1:
        key = parse_x25519_spki(material[0])
    elif credential_type == 0:
        certificates = [_load_pkix_der(value) for value in material]
        key = certificates[0].public_key()
        if not isinstance(key, x25519.X25519PublicKey):
            raise ProtocolError("provisioning server certificate lacks an X25519 proof key")
        try:
            x25519.X25519PrivateKey.from_private_bytes(bytes(range(32))).exchange(key)
        except ValueError as exc:
            raise ProtocolError("invalid provisioning server proof key") from exc
    else:
        raise ProtocolError("unsupported provisioning server credential representation")
    return AuthorizedCredential(key, binding.scope, "provisioning-trust", material, ())


def bootstrap_binding_fingerprint(binding):
    """Domain-separated ticket/cache scope, without logging the provisioning BSK."""
    if not isinstance(binding, BootstrapBinding):
        raise ProtocolError("one explicit bootstrap binding is required")
    fields = (binding.spki, binding.service.encode('utf-8'), binding.scope.encode('utf-8'),
              binding.trust_mode.encode('ascii'), ','.join(binding.target_hashes).encode('ascii'),
              binding.expires_at.isoformat().encode('ascii') if binding.expires_at else b'')
    return hashlib.sha256(b'TLS20-POK current provisioning policy\x00' + b''.join(
                len(value).to_bytes(4, 'big') + value for value in fields)).digest()


def _current_binding(binding):
    if not isinstance(binding, BootstrapBinding):
        raise ProtocolError("bootstrap endpoint requires one explicit binding, not an inventory collection")
    if binding.expires_at is not None and datetime.now(timezone.utc) >= binding.expires_at:
        raise ProtocolError("bootstrap provisioning binding expired")
    return binding


def current_bootstrap_bindings(binding, *, service=None):
    """Normalize explicit local inventory; expired entries confer no authority."""
    try:
        bindings = (binding,) if isinstance(binding, BootstrapBinding) else tuple(binding)
    except TypeError as exc:
        raise ProtocolError("explicit bootstrap provisioning bindings are required") from exc
    if not bindings or any(not isinstance(value, BootstrapBinding) for value in bindings):
        raise ProtocolError("explicit bootstrap provisioning bindings are required")
    service = service or bindings[0].service
    if any(value.service != service for value in bindings):
        raise ProtocolError("bootstrap bindings belong to different services")
    if len({value.spki for value in bindings}) != len(bindings):
        raise ProtocolError("duplicate or ambiguous bootstrap provisioning binding")
    moment = datetime.now(timezone.utc)
    current = tuple(value for value in bindings if value.expires_at is None or moment < value.expires_at)
    if not current:
        raise ProtocolError("bootstrap provisioning binding expired")
    return current


async def bootstrap_server_handshake(reader, writer, credentials, binding, *,
                                      application_protocols=(b'http/1.1',), **options):
    """Serve one binding or an explicit inventory, selecting by verified PSK."""
    from .handshake import server_handshake
    bindings = current_bootstrap_bindings(binding)
    reserved = {'external_psks', 'bootstrap_binding', 'client_credential_policy',
                'client_certificate_types', 'require_client_auth', 'client_auth_validator'}
    if reserved.intersection(options) or not application_protocols:
        raise ProtocolError("bootstrap security policy cannot be overridden by generic handshake options")
    external = tuple(bootstrap_public_key_psk(value.spki[12:], value.service,
                        target_hash=hash_name, protocol=protocol)
                     for value in bindings for hash_name in value.target_hashes for protocol in application_protocols)
    service = bindings[0].service
    policy = CredentialPolicy(peer_name=service,
        raw_public_keys=tuple(RawPublicKeyBinding('client', service, value.spki) for value in bindings))
    channel = await server_handshake(reader, writer, credentials, service,
        external_psks=external, bootstrap_binding=bindings, client_credential_policy=policy,
        client_certificate_types=(2,), require_client_auth=True,
        application_protocols=application_protocols, **options)
    if getattr(channel, 'bootstrap_binding', None) not in bindings or not getattr(channel, 'bootstrap_authorization', None):
        channel.wire.writer.transport.abort()
        raise ProtocolError("bootstrap handshake did not establish its selected scoped authority")
    return channel


async def bootstrap_client_handshake(reader, writer, binding, private_key, trust_roots=(), *,
                                      revocation_policy='offline', target_hash=None,
                                      application_protocols=(b'http/1.1',), **options):
    """Offer one binding/key or inventories; release only the authenticated choice.

    With target_hash omitted, offer every authorized compatible KDF. Private
    keys may be supplied in any order and are matched by their exact SPKI.
    """
    from .handshake import client_handshake
    from cryptography.hazmat.primitives import serialization
    bindings = current_bootstrap_bindings(binding)
    reserved = {'external_psk', 'external_psks', 'bootstrap_binding', 'client_credentials',
                'client_credential_candidates', 'cache_context'}
    if (reserved.intersection(options) or not application_protocols
            or target_hash is not None and not any(target_hash in value.target_hashes for value in bindings)):
        raise ProtocolError("invalid bootstrap client configuration")
    try:
        keys = (private_key,) if isinstance(private_key, x25519.X25519PrivateKey) else tuple(private_key)
    except TypeError as exc:
        raise ProtocolError("bootstrap client private keys must be X25519") from exc
    if not keys or any(not isinstance(key, x25519.X25519PrivateKey) for key in keys):
        raise ProtocolError("bootstrap client private keys must be X25519")
    keyed = {key.public_key().public_bytes(serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo): key for key in keys}
    if len(keyed) != len(keys) or any(value.spki not in keyed for value in bindings):
        raise ProtocolError("bootstrap private key differs from the provisioned BSK")
    credentials = tuple(Credentials([value.spki], keyed[value.spki], credential_type=2) for value in bindings)
    service = bindings[0].service
    external = tuple(bootstrap_public_key_psk(value.spki[12:], service,
        target_hash=hash_name, protocol=application_protocols[0]) for value in bindings
        for hash_name in value.target_hashes if target_hash is None or hash_name == target_hash)
    options.setdefault('cipher_suites', tuple(dict.fromkeys(value.cipher_suite for value in external)))
    options.setdefault('normal_httpps', False)  # This API explicitly selects a provisioning application.
    channel = await client_handshake(reader, writer, service, trust_roots,
        revocation_policy=revocation_policy, external_psks=external,
        bootstrap_binding=bindings, client_credential_candidates=credentials,
        application_protocols=application_protocols, **options)
    if getattr(channel, 'bootstrap_binding', None) not in bindings or not getattr(channel, 'bootstrap_authorization', None):
        channel.wire.writer.transport.abort()
        raise ProtocolError("bootstrap client did not establish its explicit provisioning scope")
    return channel
