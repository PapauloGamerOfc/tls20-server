"""Strict file-backed protocol profiles for the CLI and HTTPPS relay.

Profiles select existing verified protocol paths; they cannot import Python
callbacks, disable peer authentication, or make peer-supplied keys trusted.
Loaded policy/provider instances are retained for the lifetime of the endpoint.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
import base64
import hashlib
import hmac
import os
from pathlib import Path
import tomllib
import re

from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519

from . import crypto as c
from .errors import ConfigurationError, ProtocolError
from .messages import validate_service_identity
from .pki import (Credentials, _read_file, _pem_certificates, MAX_PEM_FILE,
                  load_trust_roots, supported_certificate_algorithms,
                  validate_identity)


def _table(value, allowed, label):
    if type(value) is not dict or set(value) - set(allowed):
        raise ConfigurationError(f"Invalid or unsupported {label} fields")
    return value


def _integer(value, low, high, label):
    if type(value) is not int or not low <= value <= high:
        raise ConfigurationError(f"Invalid {label} integer")
    return value


def _boolean(value, label):
    if type(value) is not bool:
        raise ConfigurationError(f"Invalid {label} boolean")
    return value


def _text(value, label, maximum=4096):
    if type(value) is not str or not value or len(value) > maximum or "\0" in value:
        raise ConfigurationError(f"Invalid {label} text")
    return value


def _hex(value, label, *, length=None, maximum=65535):
    if type(value) is not str or len(value) > maximum * 2 or any(ch not in "0123456789abcdefABCDEF" for ch in value):
        raise ConfigurationError(f"Invalid {label} hexadecimal encoding")
    try:
        result = bytes.fromhex(value)
    except ValueError as exc:
        raise ConfigurationError(f"Invalid {label} hexadecimal encoding") from exc
    if length is not None and len(result) != length:
        raise ConfigurationError(f"Invalid {label} byte length")
    return result


def _array(value, label, *, maximum=256):
    if type(value) is not list or len(value) > maximum:
        raise ConfigurationError(f"Invalid {label} array")
    return value


def _ids(value, allowed, label, *, empty=False):
    result = tuple(_array(value, label))
    if (not result and not empty or any(type(item) is not int or item not in allowed for item in result)
            or len(set(result)) != len(result)):
        raise ConfigurationError(f"Invalid or duplicate {label} IDs")
    return result


class _Files:
    def __init__(self, directory):
        self.directory = directory

    def path(self, value):
        path = Path(_text(value, "profile path"))
        return (path if path.is_absolute() else self.directory / path).resolve()

    def read(self, value, maximum=65535, *, private=False):
        return _read_file(self.path(value), maximum, private=private)

    def toml(self, value, maximum=65536, *, private=False):
        try:
            return tomllib.loads(self.read(value, maximum, private=private).decode("utf-8"))
        except (UnicodeError, tomllib.TOMLDecodeError) as exc:
            # TOML exceptions can include a line containing secret values.
            raise ConfigurationError("Profile data must be valid UTF-8 TOML") from exc

    def key(self, value):
        try:
            from .pki import _KEY_PEM, _element
            data = self.read(value, 16384, private=True)
            match = _KEY_PEM.fullmatch(data)
            if match is None:
                raise ValueError("Expected one PKCS8 object")
            der = base64.b64decode(re.sub(rb"\s", b"", match[1]), validate=True)
            tag, _, end, _ = _element(der)
            if tag != 0x30 or end != len(der):
                raise ValueError("Trailing private-key data")
            return serialization.load_der_private_key(der, password=None)
        except (ValueError, TypeError, UnsupportedAlgorithm) as exc:
            raise ConfigurationError("Private key must be one supported unencrypted PKCS8 PEM object") from exc

    def public_key(self, value, provider=None):
        from .pki import load_signature_public_key
        data = self.read(value)
        match = re.fullmatch(rb"\s*-----BEGIN PUBLIC KEY-----\s*([A-Za-z0-9+/=\r\n]+)\s*-----END PUBLIC KEY-----\s*",data)
        if match is None:
            raise ConfigurationError("Public key must be one PEM SubjectPublicKeyInfo object")
        try:
            der = base64.b64decode(re.sub(rb"\s", b"",match[1]),validate=True)
            return load_signature_public_key(der,signature_provider=provider)
        except (ValueError,TypeError,UnsupportedAlgorithm) as exc:
            raise ConfigurationError("Unsupported or malformed public key") from exc


def _credentials(data, files, service, role, provider):
    from .credential_profiles import parse_x25519_spki, validate_delegation
    data = _table(data, ("chain", "private_key", "raw_public_key", "delegation", "evidence", "dnssec_port", "its_grant", "its", "signature_issuers"), "credential")
    key = files.key(data.get("private_key"))
    if not isinstance(key, x25519.X25519PrivateKey):
        raise ConfigurationError("Online MAC private key must be X25519")
    its_policy = None
    signature_issuers = ()
    if "signature_issuers" in data:
        if "chain" not in data or "raw_public_key" in data or "its_grant" in data:
            raise ConfigurationError("Local signature issuers are only valid for an X509 chain")
        signature_issuers = tuple(cert.public_bytes(serialization.Encoding.DER) for cert in
            _pem_certificates(files.read(data["signature_issuers"], MAX_PEM_FILE), 64, general_pkix=True))
    if "its_grant" in data:
        if set(data) & {"chain", "raw_public_key", "delegation", "evidence", "dnssec_port"}:
            raise ConfigurationError("ITS grant cannot masquerade as a certificate, RPK or delegated credential")
        its_policy = _its(data.get("its"), files, role=role, identity=service)
        material = (files.read(data["its_grant"], 262144),)
        authorized, _, _ = its_policy.authorize(material[0], role=role, identity=service)
        kind, delegation = 3, b""
    elif "its" in data:
        raise ConfigurationError("Local ITS policy requires an ITS grant")
    elif "raw_public_key" in data:
        if "chain" in data or "delegation" in data:
            raise ConfigurationError("RPK cannot also specify a certificate chain or delegation")
        material = (files.read(data["raw_public_key"], 44),)
        authorized = parse_x25519_spki(material[0])
        kind, delegation = 2, b""
    else:
        certificates = _pem_certificates(files.read(data.get("chain"), MAX_PEM_FILE), 64, general_pkix=True)
        material = tuple(cert.public_bytes(serialization.Encoding.DER) for cert in certificates)
        if signature_issuers:
            from .pki import find_certificate_issuer
            if find_certificate_issuer(certificates[-1], signature_issuers, signature_provider=provider) is None:
                raise ConfigurationError("Local signature issuer does not authenticate the final transmitted certificate")
        from .pki import (certificate_public_key, certificate_signature_scheme,
                          verify_public_signature, SM2_CERTIFICATE_IDENTIFIER)
        for child, issuer in zip(certificates, certificates[1:]):
            if child.issuer != issuer.subject:
                raise ConfigurationError("Local credential bundle is not in issuer order")
            verify_public_signature(certificate_public_key(issuer, signature_provider=provider),
                certificate_signature_scheme(child, issuer), child.signature, child.tbs_certificate_bytes,
                sm2_identifier=SM2_CERTIFICATE_IDENTIFIER, gost_certificate_encoding=True)
        delegation = files.read(data["delegation"]) if "delegation" in data else b""
        # This final issuer anchors only consistency of the operator's local
        # bundle. It is never copied into the peer trust policy.
        authorized = validate_identity(material, trust_roots=(certificates[-1],), role=role,
            name=service if role == "server" else None, partial_chain=True,
            signing_leaf=bool(delegation), signature_provider=provider,
            offered_certificate_algorithms=supported_certificate_algorithms(provider))
        if delegation:
            authorized, _ = validate_delegation(material[0], delegation, role=role,
                grant_algorithms=supported_certificate_algorithms(provider),
                delegated_schemes=(0xfe00 if role == "server" else 0xfe01,), signature_provider=provider)
        kind = 0
    if not hmac.compare_digest(authorized.public_bytes_raw(), key.public_key().public_bytes_raw()):
        raise ConfigurationError("Credential proof key and private key differ")
    entries = [dict() for _ in material]
    for entry in _array(data.get("evidence", []), "certificate evidence", maximum=128):
        entry = _table(entry, ("index", "type", "file"), "certificate evidence")
        index = _integer(entry.get("index", 0), 0, len(entries) - 1, "evidence index")
        number = _integer(entry.get("type"), 0, 65535, "evidence extension")
        if number not in (5, 18, 52, 59) or number in entries[index] or kind == 2 and number != 59:
            raise ConfigurationError("Unsupported, duplicate or misplaced credential evidence")
        entries[index][number] = files.read(entry.get("file"))
    dnssec_service = None
    if any(59 in entry for entry in entries):
        from .dnssec_credentials import DNSSECWireEvidence
        if role != "server" or 59 not in entries[0] or any(59 in item for item in entries[1:]):
            raise ConfigurationError("DNSSEC evidence belongs only to the server leaf")
        DNSSECWireEvidence.parse(entries[0][59])
        dnssec_service = service, _integer(data.get("dnssec_port"), 1, 65535, "DNSSEC logical port")
    elif "dnssec_port" in data:
        raise ConfigurationError("DNSSEC logical port requires its evidence file")
    return Credentials(list(material), key, kind, tuple(tuple(item.items()) for item in entries), delegation, dnssec_service, its_policy, signature_issuers)


def _provider(data, files):
    from .openssl_provider import OpenSSLProvider
    data = _table(data, ("library", "gost_module", "pake_helper"), "native provider")
    if "gost_module" in data:
        from .gost_provider import GOSTProvider
        return GOSTProvider(files.path(data.get("library")), files.path(data["gost_module"]))
    return OpenSSLProvider(files.path(data.get("library")))


def _psks(items, files, service, protocol):
    from .psk import ExternalPSK, import_psk
    result = []
    for item in _array(items, "PSKs", maximum=64):
        item = _table(item, ("identity_hex", "key_file", "hash", "suite", "combined", "import_context_hex", "base_hash"), "PSK")
        identity = _hex(item.get("identity_hex"), "PSK identity")
        secret = files.read(item.get("key_file"), 4096, private=True)
        if len(secret) < 16:
            raise ConfigurationError("Provisioned PSK must contain at least 128 bits")
        hash_name = item.get("hash", "sha256")
        suite = _integer(item.get("suite", 0x1302 if hash_name == "sha384" else 0x1301), 0, 65535, "PSK suite")
        combined = _boolean(item.get("combined", False), "combined PSK")
        if "import_context_hex" in item:
            record = import_psk(secret, identity, _hex(item["import_context_hex"], "PSK import context"), service,
                protocol=protocol, base_hash=item.get("base_hash", "sha256"), target_hash=hash_name,
                combined=combined, cipher_suite=suite)
        else:
            if "base_hash" in item:
                raise ConfigurationError("base_hash requires an imported PSK")
            record = ExternalPSK(identity, secret, service, protocol, hash_name, combined=combined, cipher_suite=suite)
        result.append(record)
    if not result or len({item.identity for item in result}) != len(result) or len({item.combined for item in result}) != 1:
        raise ConfigurationError("PSK profile requires unique identities with one consistent authentication mode")
    # External 0-RTT needs a distributed atomic replay backend. The CLI only
    # enables early data on its own single-listener resumption tickets.
    return tuple(result)


@dataclass(repr=False)
class LoadedProfile:
    role: str
    service: str
    port: int
    mode: str
    options: dict = field(default_factory=dict)
    credentials: object = None
    roots: tuple = ()
    revocation_policy: str = "offline"
    provider: object = None
    password: object = None
    bootstrap: object = None
    bootstrap_key: object = None
    bootstrap_hash: str = "sha256"
    protocol: bytes = b"http/1.1"

    def close(self):
        if self.provider is not None:
            self.provider.close()
            self.provider = None

    async def server_handshake(self, reader, writer, **options):
        options.update(self.options)
        options["application_protocols"] = (self.protocol,)
        if self.mode == "pake":
            from .pake_handshake import server
            options.pop("certificate_compression", None)
            return await server(reader, writer, self.password, **options)
        if self.mode == "pok":
            from .bootstrap_credentials import bootstrap_server_handshake
            return await bootstrap_server_handshake(reader, writer, self.credentials, self.bootstrap, **options)
        from .handshake import server_handshake
        return await server_handshake(reader, writer, self.credentials, self.service, **options)

    async def client_handshake(self, reader, writer, **options):
        options.update(self.options)
        options["application_protocols"] = (self.protocol,)
        if self.mode == "pake":
            from .pake_handshake import client
            options.pop("cache_context", None)
            return await client(reader, writer, self.password, **options)
        if self.mode == "pok":
            from .bootstrap_credentials import bootstrap_client_handshake
            options.pop("cache_context", None)
            return await bootstrap_client_handshake(reader, writer, self.bootstrap, self.bootstrap_key, self.roots,
                revocation_policy=self.revocation_policy, normal_httpps=True, target_hash=self.bootstrap_hash, **options)
        from .handshake import client_handshake
        return await client_handshake(reader, writer, self.service, self.roots,
            revocation_policy=self.revocation_policy, **options)


def load_profile(path, *, role, service=None, port=None, protocol=b"http/1.1"):
    """Load and validate before opening sockets. No implicit provider or CA."""
    location = Path(path).resolve()
    files = _Files(location.parent)
    data = _table(files.toml(str(location)), ("role", "service", "port", "mode", "provider", "negotiation",
        "credential", "credential_candidates", "trust", "psks", "password", "bootstrap", "pinning", "client_auth",
        "signaling", "cache", "server_certificate_authorities"), "profile")
    if data.get("role") != role or role not in ("server", "client"):
        raise ConfigurationError("Profile role does not match this endpoint")
    name = _text(data.get("service"), "profile service", 253)
    validate_service_identity(name)
    logical_port = _integer(data.get("port", 343), 1, 65535, "profile port")
    if service is not None and service != name or port not in (None, 0, logical_port):
        raise ConfigurationError("Profile service or port differs from the requested endpoint")
    mode = data.get("mode", "certificate")
    if mode not in ("certificate", "psk", "pake", "pok", "mixed") or mode == "mixed" and role != "client":
        raise ConfigurationError("Unknown authenticated HTTPPS profile mode")
    result = LoadedProfile(role, name, logical_port, mode, protocol=protocol)
    try:
        if "provider" in data:
            result.provider = _provider(data["provider"], files)
        _configure(result, data, files)
        return result
    except (TypeError, KeyError, OverflowError, UnsupportedAlgorithm) as exc:
        result.close()
        raise ConfigurationError("Invalid profile value type or missing required field") from exc
    except BaseException:
        result.close()
        raise


def _configure(result, data, files):
    role, mode, provider, options = result.role, result.mode, result.provider, result.options
    negotiation = _table(data.get("negotiation", {}), ("cipher_suites", "traffic_group", "groups", "supported_groups", "psk_modes",
        "record_size_limit", "max_fragment_length", "certificate_compression", "heartbeat_mode",
        "ticket_request", "ticket_count_limit", "enable_authenticators", "post_handshake_auth"), "negotiation")
    defaults = [0xc0b0] if mode == "pake" else [0x1301, 0xc0b0] if mode == "mixed" else [0x1301]
    suites = _ids(negotiation.get("cipher_suites", defaults),
                  c.CIPHER_SUITES, "cipher suites")
    if (any(not c.suite(item).confidential or mode != "mixed" and c.suite(item).password_authenticated != (mode == "pake") for item in suites)
            or mode == "mixed" and {c.suite(item).password_authenticated for item in suites} != {False, True}):
        raise ConfigurationError("Cipher suites do not match the selected confidential authentication profile")
    if any(c.suite(item).hash_name in ("sm3", "streebog256") for item in suites) and provider is None:
        raise ConfigurationError("Selected cipher suites require an explicit native provider")
    if any(c.suite(item).hash_name == "streebog256" for item in suites) and not callable(getattr(provider, "record_cipher", None)):
        raise ConfigurationError("GOST suites require the explicitly configured GOST module")
    options["cipher_suites"] = suites
    if "supported_groups" in negotiation:
        if mode == "pake":
            raise ConfigurationError("Password profile uses its explicit commitment groups")
        permitted = tuple(value for value in c.GROUP_LENGTHS if (value != 41 or provider is not None)
                          and (not 34 <= value <= 40 or callable(getattr(provider, "exchange_gost", None))))
        options["supported_groups"] = _ids(negotiation["supported_groups"], permitted, "supported groups")
    for field_name, low, high in (("record_size_limit", 64, 16385), ("heartbeat_mode", 1, 2), ("ticket_count_limit", 0, 255)):
        if field_name in negotiation:
            if field_name == "ticket_count_limit" and role != "server":
                raise ConfigurationError("ticket_count_limit is server-only")
            options[field_name] = _integer(negotiation[field_name], low, high, field_name)
    if "traffic_group" in negotiation:
        if role != "client" or mode == "pake":
            raise ConfigurationError("traffic_group is for a non-password client")
        options["traffic_group"] = _ids([negotiation["traffic_group"]], c.GROUP_LENGTHS, "traffic group")[0]
        group = options["traffic_group"]
        if group == 41 and provider is None:
            raise ConfigurationError("Selected group requires an explicit native provider")
        if 34 <= group <= 40 and not callable(getattr(provider, "exchange_gost", None)):
            raise ConfigurationError("Selected GOST group requires the explicit GOST module")
    if role == "client" and "supported_groups" in options and options.get("traffic_group", 29) not in options["supported_groups"]:
        raise ConfigurationError("Initial traffic group must belong to the explicit supported groups")
    if "groups" in negotiation:
        from .pake_native import GROUPS
        if mode != "pake":
            raise ConfigurationError("groups selects password commitment groups")
        options["groups"] = _ids(negotiation["groups"], GROUPS, "password groups")
    if "max_fragment_length" in negotiation:
        if role != "client":
            raise ConfigurationError("max_fragment_length is client-only")
        options["max_fragment_length"] = _integer(negotiation["max_fragment_length"], 1, 4, "max_fragment_length")
    for field_name in ("certificate_compression", "psk_modes"):
        if field_name in negotiation:
            if mode == "pake":
                raise ConfigurationError("Password authentication does not use certificate/PSK mode offers")
            options[field_name] = _ids(negotiation[field_name], (1, 2, 3) if field_name == "certificate_compression" else (0, 1),
                                        field_name, empty=field_name == "certificate_compression")
    for field_name in ("enable_authenticators", "post_handshake_auth"):
        if field_name in negotiation:
            if field_name == "post_handshake_auth" and (role != "client" or mode == "pake"):
                raise ConfigurationError("Authentication capability is not applicable to this profile")
            options[field_name] = _boolean(negotiation[field_name], field_name)
    if "ticket_request" in negotiation:
        from .optional_controls import TicketRequest
        counts = _array(negotiation["ticket_request"], "ticket request", maximum=2)
        if role != "client" or len(counts) != 2:
            raise ConfigurationError("Client ticket_request requires two counts")
        options["ticket_request"] = TicketRequest(*counts)
    if "signaling" in data:
        from .optional_controls import SignalingBinding
        signaling = _table(data["signaling"], ("local_hash_hex", "peer_hash_hex", "local_session_id", "peer_session_id"), "signaling")
        options["signaling"] = SignalingBinding(_hex(signaling.get("local_hash_hex", ""), "local signaling assertion"),
            _hex(signaling.get("peer_hash_hex", ""), "peer signaling assertion"),
            _text(signaling.get("local_session_id"), "local signaling session", 255).encode("ascii"),
            _text(signaling.get("peer_session_id"), "peer signaling session", 255).encode("ascii"))
    if mode == "pake":
        if set(data) & {"credential", "credential_candidates", "trust", "psks", "bootstrap", "pinning", "client_auth", "cache", "server_certificate_authorities"}:
            raise ConfigurationError("Password profile cannot silently combine other trust mechanisms")
        _password(result, data.get("password"), data.get("provider", {}), files)
        return
    if mode == "mixed":
        if set(data) & {"psks", "bootstrap", "pinning"}:
            raise ConfigurationError("Mixed password/credential selection cannot combine external-PSK, bootstrap or pinning profiles")
        from .pake_native import GROUPS
        if not any(value in GROUPS for value in options.get("supported_groups", c.GROUP_LENGTHS)):
            raise ConfigurationError("Mixed profile needs a supported password commitment group")
        _password(result, data.get("password"), data.get("provider", {}), files)
        options["password_credential"] = result.password
    elif "password" in data or "pake_helper" in data.get("provider", {}):
        raise ConfigurationError("Password files/helper require explicit password mode")
    if provider is not None:
        options["native_provider"] = provider
    if role == "client":
        options.setdefault("certificate_compression", (1, 2, 3))
    if "cache" in data:
        if role != "client":
            raise ConfigurationError("Configured credential cache snapshots are client-only")
        cache = _table(data["cache"], ("certificates", "request_templates"), "credential cache")
        certificates = []
        for item in _array(cache.get("certificates", []), "cached credentials", maximum=16):
            item = _table(item, ("type", "files"), "cached credential")
            kind = _ids([item.get("type", 0)], (0, 2), "cached credential type")[0]
            material = tuple(files.read(value, 65536) for value in _array(item.get("files"), "cached material", maximum=64))
            from .credential_cache import material_hash
            material_hash(material, kind)
            certificates.append((kind, material))
        from .credential_cache import request_template_hash
        templates = tuple(files.read(value) for value in _array(cache.get("request_templates", []), "cached request templates", maximum=16))
        for value in templates:
            request_template_hash(value)
        options.update(cached_certificates=tuple(certificates), cached_requests=templates)
    if "server_certificate_authorities" in data:
        if role != "client":
            raise ConfigurationError("Server authority preferences are client-only")
        from .credential_selection import encode_certificate_authorities
        names = tuple(files.read(value, 65535) for value in _array(data["server_certificate_authorities"], "authority names", maximum=128))
        if names:
            encode_certificate_authorities(names)
        options["server_certificate_authorities"] = names
    if "credential" in data:
        result.credentials = _credentials(data["credential"], files, result.service, role, provider)
    candidates = tuple(_credentials(item, files, result.service, role, provider)
                       for item in _array(data.get("credential_candidates", []), "credential candidates", maximum=16))
    if candidates:
        options[f"{role}_credential_candidates"] = candidates
    if role == "client" and result.credentials is not None:
        options["client_credentials"] = result.credentials
    if mode in ("certificate", "pok") and role == "server" and result.credentials is None:
        raise ConfigurationError("Server profile requires explicit local credentials")
    if mode == "psk":
        options["external_psks"] = _psks(data.get("psks"), files, result.service, result.protocol)
        if any(record.hash_name not in {c.suite(value).hash_name for value in suites} for record in options["external_psks"]):
            raise ConfigurationError("Every provisioned PSK needs a compatible negotiated hash")
        if options["external_psks"][0].combined and role == "server" and result.credentials is None:
            raise ConfigurationError("Combined PSK server requires its independently validated credential")
        if options["external_psks"][0].combined and 1 not in options.get("psk_modes", (1,)):
            raise ConfigurationError("Combined PSK requires the fresh key-agreement mode")
        if not options["external_psks"][0].combined and (data.get("trust") or "client_auth" in data):
            raise ConfigurationError("Pure PSK authentication cannot enforce certificate trust or client-auth policies; select combined mode")
    elif "psks" in data:
        raise ConfigurationError("External PSKs require explicit PSK mode")
    _trust(result, data.get("trust", {}), files)
    if mode == "pok":
        _bootstrap(result, data.get("bootstrap"), files)
    elif "bootstrap" in data:
        raise ConfigurationError("Bootstrap inventory requires explicit POK mode")
    if "pinning" in data:
        if mode != "certificate":
            raise ConfigurationError("Pinning requires fresh credential-only mode")
        _pinning(result, data["pinning"], files)
    if "client_auth" in data:
        if role != "server" or mode == "pok":
            raise ConfigurationError("Client authorization table is for non-bootstrap servers")
        _client_auth(result, data["client_auth"], files)


def _password(result, data, provider_data, files):
    from .pake import PasswordAccount, PasswordCredential, PasswordServer
    from .pake_native import PakeProvider
    data = _table(data, ("accounts_file", "username_file", "password_file", "protection_key",
                         "max_attempts", "window", "global_attempts", "capacity", "max_active"), "password")
    if result.provider is None or "pake_helper" not in provider_data:
        raise ConfigurationError("Password profile requires explicit library and production PAKE helper")
    helper = PakeProvider(result.provider, files.path(provider_data["pake_helper"]))
    if result.role == "client":
        if set(data) - {"username_file", "password_file", "protection_key"}:
            raise ConfigurationError("Server account policy is not a client password configuration")
        protection = files.public_key(data["protection_key"], result.provider) if "protection_key" in data else None
        try:
            username = files.read(data.get("username_file"), 1024, private=True).decode("utf-8")
            password = files.read(data.get("password_file"), 4096, private=True).decode("utf-8")
        except UnicodeError as exc:
            raise ConfigurationError("Password input files must contain exact UTF-8 text") from exc
        result.password = PasswordCredential(result.service, username, password, helper, protection)
    else:
        if set(data) & {"username_file", "password_file"}:
            raise ConfigurationError("Server requires provisioned account bases, not plaintext client passwords")
        database = _table(files.toml(data.get("accounts_file"), 1048576, private=True), ("accounts",), "password database")
        accounts = []
        for item in _array(database.get("accounts"), "password accounts", maximum=4096):
            item = _table(item, ("username_hex", "base_hex", "salt_hex", "permissions_hex"), "password account")
            accounts.append(PasswordAccount(_hex(item.get("username_hex"), "username", maximum=255),
                _hex(item.get("base_hex"), "password base", length=32),
                _hex(item["salt_hex"], "password salt", length=32) if "salt_hex" in item else None,
                _hex(item.get("permissions_hex", ""), "password permissions", maximum=4096)))
        limits = {name: _integer(data[name], 1, 100000, name) for name in
                  ("max_attempts", "window", "global_attempts", "capacity", "max_active") if name in data}
        protection = files.key(data["protection_key"]) if "protection_key" in data else None
        result.password = PasswordServer(result.service, helper, accounts, protection_key=protection, **limits)


def _roots(data, files, provider):
    return tuple(load_trust_roots(files.path(data), general_pkix=True, signature_provider=provider)) if data is not None else ()


def _bindings(items, files, *, role, identity):
    from .credential_profiles import RawPublicKeyBinding, parse_x25519_spki
    output = []
    for value in _array(items, "raw key bindings", maximum=64):
        spki = files.read(value, 44)
        parse_x25519_spki(spki)
        output.append(RawPublicKeyBinding(role, identity, spki))
    return tuple(output)


def _evidence(data, files, provider=None):
    from .credential_evidence import CredentialEvidencePolicy
    from .transparency import TrustedLog
    data = _table(data, ("require_ocsp", "ocsp_max_age_seconds", "minimum_ct_v1_logs", "minimum_ct_v2_logs",
                         "require_ct_v2_inclusion", "logs", "tree_heads", "ocsp_request"), "credential evidence policy")
    options = {}
    for name in ("require_ocsp", "require_ct_v2_inclusion"):
        options[name] = _boolean(data.get(name, False), name)
    for name in ("minimum_ct_v1_logs", "minimum_ct_v2_logs"):
        options[name] = _integer(data.get(name, 0), 0, 64, name)
    options["ocsp_max_age_seconds"] = _integer(data.get("ocsp_max_age_seconds", 86400), 1, 604800, "OCSP maximum age")
    logs = {1: {}, 2: {}}
    for item in _array(data.get("logs", []), "trusted CT logs", maximum=128):
        item = _table(item, ("version", "id_hex", "public_key", "signature_scheme", "hash", "valid_from_ms",
                           "valid_until_ms", "maximum_merge_delay_seconds"), "trusted CT log")
        version = _integer(item.get("version"), 1, 2, "CT version")
        key = files.public_key(item.get("public_key"), provider)
        identity = _hex(item.get("id_hex"), "CT log identifier", maximum=127)
        if version == 1 and (len(identity) != 32 or identity != hashlib.sha256(key.public_bytes(
                serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)).digest()):
            raise ConfigurationError("CT v1 log ID differs from its configured public key")
        if identity in logs[version]:
            raise ConfigurationError("Duplicate trusted CT log")
        logs[version][identity] = TrustedLog(identity, key,
            _integer(item.get("signature_scheme", 0x0403), 0, 65535, "CT signature scheme"), item.get("hash", "sha256"),
            _integer(item.get("valid_from_ms", 0), 0, (1 << 64) - 1, "log validity start"),
            _integer(item.get("valid_until_ms", (1 << 64) - 1), 0, (1 << 64) - 1, "log validity end"),
            _integer(item.get("maximum_merge_delay_seconds", 86400), 1, 604800, "log merge delay"))
    for version in (1, 2):
        if options[f"minimum_ct_v{version}_logs"] > len(logs[version]):
            raise ConfigurationError("CT minimum exceeds the independently provisioned log inventory")
        options[f"trusted_logs_v{version}"] = logs[version]
    heads = {}
    for item in _array(data.get("tree_heads", []), "trusted CT tree heads", maximum=128):
        item = _table(item, ("log_id_hex", "size", "timestamp_ms", "root_hex"), "trusted CT tree head")
        identity = _hex(item.get("log_id_hex"), "CT log identifier", maximum=127)
        if identity not in logs[2] or identity in heads:
            raise ConfigurationError("Tree head requires one known, unambiguous CT v2 log")
        heads[identity] = (_integer(item.get("size"), 0, (1 << 64)-1, "tree size"),
            _integer(item.get("timestamp_ms"), 0, (1 << 64)-1, "tree time"),
            _hex(item.get("root_hex"), "tree root", length=hashlib.new(logs[2][identity].hash_name).digest_size))
    options["trusted_tree_heads"] = heads
    if options["require_ct_v2_inclusion"] and not options["minimum_ct_v2_logs"]:
        raise ConfigurationError("Required inclusion needs a positive CT v2 log policy")
    from .status_request import parse_status_request
    request = files.read(data["ocsp_request"]) if "ocsp_request" in data else b"\x01\0\0\0\0"
    if parse_status_request(request) is None:
        raise ConfigurationError("Evidence policy requires an OCSP status request")
    options["ocsp_request"] = request
    offered = [(5, request)]
    if logs[1]:
        offered.append((18, b""))
    if logs[2]:
        offered.append((52, b""))
    options["offered_extensions"] = tuple(number for number, _ in offered)
    return CredentialEvidencePolicy(**options), tuple(offered)


def _dane(data, files, result):
    import dns.name
    import dns.rdatatype
    import dns.rrset
    import dns.zone
    from .dnssec_credentials import DANEPolicy
    from .pki import validate_pkix_path
    data = _table(data, ("anchors_file", "allow_authenticated_denial"), "DANE policy")
    try:
        zone = dns.zone.from_text(files.read(data.get("anchors_file"), 1048576).decode("ascii"),
                                  origin=dns.name.root, relativize=False, check_origin=False)
        anchors = {}
        for name, node in zone.nodes.items():
            for rdataset in node.rdatasets:
                if rdataset.rdtype not in (dns.rdatatype.DNSKEY, dns.rdatatype.DS):
                    raise ConfigurationError("DNSSEC anchor inventory permits only DNSKEY and DS records")
                if name.to_text() in anchors:
                    raise ConfigurationError("Use one DS or DNSKEY trust-anchor RRset per owner")
                anchors[name.to_text()] = dns.rrset.from_rdata_list(name, rdataset.ttl, list(rdataset))
        if not anchors or len(anchors) > 64:
            raise ConfigurationError("DNSSEC anchor inventory is empty or too large")
    except (UnicodeError, dns.exception.DNSException) as exc:
        raise ConfigurationError("Invalid explicit DNSSEC trust-anchor zone file") from exc
    def pkix(material):
        validate_identity(material, trust_roots=result.roots, role="server", name=result.service,
            signature_provider=result.provider, offered_certificate_algorithms=supported_certificate_algorithms(result.provider))
        return validate_pkix_path(material, result.roots, signature_provider=result.provider)
    def dane_path(material, anchor):
        validate_identity(material, trust_roots=(anchor,), role="server", name=result.service,
            partial_chain=True, signature_provider=result.provider,
            offered_certificate_algorithms=supported_certificate_algorithms(result.provider))
        return True
    return DANEPolicy(anchors, result.port, _boolean(data.get("allow_authenticated_denial", False), "DANE denial fallback"),
                      pkix if result.roots else None, dane_path)


def _trust(result, data, files):
    from .credential_profiles import CredentialPolicy
    data = _table(data, ("roots", "revocation_policy", "raw_public_keys", "server_certificate_types",
                        "delegated_credentials", "require_delegation", "evidence", "dane", "its"), "server trust")
    if result.role == "server":
        if data:
            raise ConfigurationError("Server-peer trust table is client-only; use client_auth on a server")
        return
    result.roots = _roots(data.get("roots"), files, result.provider)
    result.revocation_policy = data.get("revocation_policy", "offline")
    if result.revocation_policy not in ("offline", "require-evidence"):
        raise ConfigurationError("Profile requires explicit offline or require-evidence validation")
    bindings = _bindings(data.get("raw_public_keys", []), files, role="server", identity=result.service)
    types = _ids(data.get("server_certificate_types", [3] if "its" in data else [2] if bindings else [0]), (0, 2, 3), "server certificate types")
    delegation = _boolean(data.get("delegated_credentials", False), "delegated_credentials")
    require_delegation = _boolean(data.get("require_delegation", False), "require_delegation")
    if require_delegation and not delegation:
        raise ConfigurationError("Required delegation must also be offered")
    evidence, offers = _evidence(data["evidence"], files, result.provider) if "evidence" in data else (None, ())
    if result.revocation_policy == "require-evidence" and evidence is None:
        raise ConfigurationError("Required current evidence needs an explicit evidence policy")
    if result.revocation_policy == "require-evidence" and not (evidence.require_ocsp or evidence.minimum_ct_v1_logs or evidence.minimum_ct_v2_logs):
        raise ConfigurationError("Required evidence must specify a positive OCSP or CT requirement")
    dane = _dane(data["dane"], files, result) if "dane" in data else None
    its = _its(data["its"], files, role="server", identity=result.service) if "its" in data else None
    if 3 in types and its is None or its is not None and (delegation or require_delegation or evidence or dane):
        raise ConfigurationError("ITS credentials require their own explicit authorization policy")
    if any(kind != 0 for kind in types) and (evidence is not None or result.revocation_policy == "require-evidence" or require_delegation):
        raise ConfigurationError("X509 evidence/delegation requirements cannot be bypassed by offering a different credential type")
    combined = result.mode == "psk" and result.options["external_psks"][0].combined
    if not result.roots and not bindings and dane is None and its is None and (result.mode != "psk" or combined):
        raise ConfigurationError("Certificate/POK client needs independently provisioned trust")
    result.options.update(credential_policy=CredentialPolicy(trust_roots=result.roots, peer_name=result.service,
        raw_public_keys=bindings, revocation_policy=result.revocation_policy, evidence_validator=evidence,
        require_delegation=require_delegation, dane_policy=dane, signature_provider=result.provider, its_policy=its),
        server_certificate_types=types, delegated_credentials=delegation, certificate_evidence_extensions=offers)


def _client_auth(result, data, files):
    from .credential_profiles import CredentialPolicy
    data = _table(data, ("required", "roots", "identity", "raw_public_keys", "allowed_certificates_sha256",
                        "certificate_types", "require_delegation", "its", "certificate_authorities", "oid_filters"), "client authorization")
    identity = _text(data.get("identity", "authorized-client"), "client authorization identity", 255)
    bindings = _bindings(data.get("raw_public_keys", []), files, role="client", identity=identity)
    fingerprints = tuple(_hex(value, "authorized client certificate fingerprint", length=32) for value in
                         _array(data.get("allowed_certificates_sha256", []), "client certificate fingerprints", maximum=4096))
    roots = _roots(data.get("roots"), files, result.provider)
    its = _its(data["its"], files, role="client", identity=identity) if "its" in data else None
    if not bindings and not its and (not roots or not fingerprints):
        raise ConfigurationError("Client authorization requires exact RPK pins or roots AND allowed leaf fingerprints")
    def authorize(material, evidence):
        fingerprint = hashlib.sha256(material[0]).digest()
        return any(hmac.compare_digest(fingerprint, allowed) for allowed in fingerprints)
    result.options.update(client_credential_policy=CredentialPolicy(trust_roots=roots, peer_name=identity,
        raw_public_keys=bindings, authorize_client=authorize,
        require_delegation=_boolean(data.get("require_delegation", False), "client delegation requirement"),
        signature_provider=result.provider, its_policy=its),
        require_client_auth=_boolean(data.get("required", True), "required client authentication"),
        client_certificate_types=_ids(data.get("certificate_types", [3] if its else [2] if bindings and not roots else [0]), (0, 2, 3), "client certificate types"))
    if 3 in result.options["client_certificate_types"] and its is None:
        raise ConfigurationError("ITS client authentication requires an explicit ITS service policy")
    if data.get("require_delegation", False) and result.options["client_certificate_types"] != (0,):
        raise ConfigurationError("Required client delegation needs only X509 credential offers")
    types = result.options["client_certificate_types"]
    if 0 in types and (not roots or not fingerprints) or 2 in types and not bindings:
        raise ConfigurationError("Every offered client credential type needs its own explicit authorization")
    from .credential_selection import encode_certificate_authorities, encode_oid_filters
    names = tuple(files.read(value) for value in _array(data.get("certificate_authorities", []), "client authority names", maximum=128))
    if names:
        encode_certificate_authorities(names)
    filters = []
    for item in _array(data.get("oid_filters", []), "client certificate OID filters", maximum=128):
        item = _table(item, ("oid", "value_hex"), "certificate OID filter")
        filters.append((_text(item.get("oid"), "certificate extension OID", 255), _hex(item.get("value_hex", ""), "OID filter value")))
    encode_oid_filters(filters)
    result.options.update(client_certificate_authorities=names, client_oid_filters=tuple(filters))


def _bootstrap(result, data, files):
    from .bootstrap_credentials import BootstrapBinding
    data = _table(data, ("public_key", "private_key", "scope", "expires_at", "target_hashes", "target_hash"), "bootstrap inventory")
    expiry = None
    if "expires_at" in data:
        try:
            expiry = datetime.fromisoformat(_text(data["expires_at"], "bootstrap expiry", 64))
        except ValueError as exc:
            raise ConfigurationError("Bootstrap expiry must be an ISO8601 timestamp") from exc
        if expiry.tzinfo is None or expiry <= datetime.now(timezone.utc):
            raise ConfigurationError("Bootstrap binding is expired or lacks its time zone")
    targets = tuple(_array(data.get("target_hashes", ["sha256", "sha384"]), "bootstrap target hashes", maximum=2))
    result.bootstrap = BootstrapBinding(files.read(data.get("public_key"), 44), result.service,
        _text(data.get("scope"), "bootstrap authorization scope"), "credential-validated", targets, expiry)
    if result.role == "client":
        result.bootstrap_hash = data.get("target_hash", "sha256")
        if result.bootstrap_hash not in targets or result.bootstrap_hash not in {c.suite(value).hash_name for value in result.options["cipher_suites"]}:
            raise ConfigurationError("Bootstrap target hash must match its provisioning and offered suites")
        result.bootstrap_key = files.key(data.get("private_key"))
        if not isinstance(result.bootstrap_key, x25519.X25519PrivateKey) or not hmac.compare_digest(
                result.bootstrap_key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo),
                result.bootstrap.spki):
            raise ConfigurationError("Bootstrap private key does not match its explicitly provisioned public key")
        if "client_credentials" in result.options or "client_credential_candidates" in result.options:
            raise ConfigurationError("Bootstrap credential is determined only by the provisioned BSK")
    elif "private_key" in data or "target_hash" in data:
        raise ConfigurationError("Bootstrap server accepts inventory, not client key/selection settings")


def _pinning(result, data, files):
    from .pinning import PinningCache, ServerPinning
    if result.role == "client":
        data = _table(data, ("capacity",), "client pinning")
        result.options.update(pinning_cache=PinningCache(capacity=_integer(data.get("capacity", 4096), 1, 100000, "pin capacity")),
                              pinning_port=result.port)
        return
    data = _table(data, ("keys", "current_id_hex", "lifetime_seconds", "ramp_down"), "server pinning")
    keys = {}
    for item in _array(data.get("keys"), "pin protection keys", maximum=256):
        item = _table(item, ("id_hex", "key_file"), "pin protection key")
        identity = _hex(item.get("id_hex"), "pin key ID", length=16)
        key = files.read(item.get("key_file"), 32, private=True)
        if len(key) != 32 or identity in keys:
            raise ConfigurationError("Pin protection keys require unique IDs and exactly 32 secret bytes")
        keys[identity] = key
    result.options.update(pinning=ServerPinning(keys, _hex(data.get("current_id_hex"), "current pin key ID", length=16),
        lifetime=_integer(data.get("lifetime_seconds", 1209600), 0, (1 << 32)-1, "pin lifetime"),
        ramp_down=_boolean(data.get("ramp_down", False), "pin ramp-down")), pinning_port=result.port)


def _its(data, files, *, role, identity):
    from .its_credentials import ITSProvider, ITSServicePolicy
    data = _table(data, ("library", "psid", "application_scope_hex", "ssp_coer_hex", "roots",
        "authorized_leaf_sha256", "revoked_sha256", "inventory_valid_until", "max_grant_lifetime_microseconds",
        "tai_utc_offset", "allowed_regions", "geographic_containment"), "ITS authorization")
    containment = []
    for relation in _array(data.get("geographic_containment", []), "ITS geographic containment", maximum=256):
        relation = _table(relation, ("parent", "child"), "ITS geographic containment statement")
        parent = files.read(relation.get("parent"), 16384)
        child = files.read(relation.get("child"), 16384)
        if not parent or not child:
            raise ConfigurationError("ITS geographic containment requires nonempty COER region files")
        containment.append((parent, child))
    policy = ITSServicePolicy(ITSProvider(files.path(data.get("library"))), identity, role,
        _integer(data.get("psid"), 0, (1 << 64)-1, "ITS PSID"),
        _hex(data.get("application_scope_hex"), "ITS application scope"),
        _hex(data.get("ssp_coer_hex", ""), "ITS permissions"),
        tuple(files.read(value, 16384) for value in _array(data.get("roots"), "ITS roots", maximum=32)),
        tuple(_hex(value, "authorized ITS fingerprint", length=32) for value in
              _array(data.get("authorized_leaf_sha256"), "authorized ITS leaves", maximum=1024)),
        tuple(_hex(value, "revoked ITS fingerprint", length=32) for value in
              _array(data.get("revoked_sha256", []), "revoked ITS leaves", maximum=4096)),
        _integer(data.get("inventory_valid_until"), 1, (1 << 64)-1, "ITS inventory expiry"),
        _integer(data.get("max_grant_lifetime_microseconds"), 1, (1 << 64)-1, "ITS grant lifetime"),
        _integer(data.get("tai_utc_offset"), 0, 100, "trusted TAI-UTC offset"),
        tuple(files.read(value, 16384) for value in _array(data.get("allowed_regions", []), "ITS regions", maximum=32)),
        tuple(containment))
    policy_bytes = policy.policy_bytes()
    if policy.inventory_valid_until <= int.from_bytes(policy_bytes[4:12], "big"):
        raise ConfigurationError("ITS authorization inventory is already expired")
    return policy


def create_password_record(username_file, password_file, output):
    """Create one salted verifier database exclusively, without CLI secrets."""
    from .pake import PasswordAccount
    files = _Files(Path.cwd())
    try:
        username = files.read(str(username_file), 1024, private=True).decode("utf-8")
        password = files.read(str(password_file), 4096, private=True).decode("utf-8")
    except UnicodeError as exc:
        raise ConfigurationError("Password input files must contain exact UTF-8 text") from exc
    record = PasswordAccount.provision(username, password)
    encoded = ('# Sensitive password-equivalent verifier; protect this file.\n[[accounts]]\n'
        f'username_hex = "{record.username.hex()}"\nbase_hex = "{record.base.hex()}"\n'
        f'salt_hex = "{record.salt.hex()}"\n').encode("ascii")
    descriptor = None
    try:
        descriptor = os.open(Path(output), os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            descriptor = None
            stream.write(encoded)
    except OSError as exc:
        raise ConfigurationError("Cannot exclusively create password record; no existing file is overwritten") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)
