"""Fresh local test CA and X25519 server credentials; never a public CA."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import ipaddress
import os
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from .errors import ConfigurationError, ProtocolError
from .pki import Credentials, validate_service_identity


def generate_lab_credentials(server_name: str) -> tuple[Credentials, x509.Certificate]:
    """Create fresh in-memory lab material; CA private key is never serialized."""
    try:
        validate_service_identity(server_name)
    except ProtocolError as exc:
        raise ConfigurationError(str(exc)) from exc
    now = datetime.now(timezone.utc)
    try:
        alternative_name = x509.IPAddress(ipaddress.ip_address(server_name))
    except ValueError:
        alternative_name = x509.DNSName(server_name)
    ca_key = ed25519.Ed25519PrivateKey.generate()
    server_key = x25519.X25519PrivateKey.generate()
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "TLS20 local experimental CA")])
    ca = (x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name)
          .public_key(ca_key.public_key()).serial_number(x509.random_serial_number())
          .not_valid_before(now - timedelta(minutes=5)).not_valid_after(now + timedelta(days=365))
          .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
          .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True)
          .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
          .sign(ca_key, algorithm=None))
    leaf = (x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, server_name)]))
            .issuer_name(ca_name).public_key(server_key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=5)).not_valid_after(now + timedelta(days=30))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(False, False, False, False, True, False, False, False, False), critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .add_extension(x509.SubjectAlternativeName([alternative_name]), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
            .sign(ca_key, algorithm=None))
    return Credentials([leaf.public_bytes(serialization.Encoding.DER)], server_key), ca


def create_lab(directory: Path, server_name: str) -> dict[str, Path]:
    """Write to a NEW private directory only; never overwrite existing material.

    On Windows permissions are inherited ACLs: choose a user-private location.
    POSIX directory and file modes are 0700 and 0600, respectively.
    """
    credentials, ca = generate_lab_credentials(server_name)
    directory = Path(directory)
    try:
        directory.mkdir(mode=0o700, parents=False, exist_ok=False)
    except OSError as exc:
        raise ConfigurationError("lab destination must be a new directory under an existing parent") from exc
    leaf = x509.load_der_x509_certificate(credentials.chain_der[0])
    materials = {
        "fullchain.pem": leaf.public_bytes(serialization.Encoding.PEM),
        "server.key": credentials.private_key.private_bytes(serialization.Encoding.PEM,
                     serialization.PrivateFormat.PKCS8, serialization.NoEncryption()),
        "ca.pem": ca.public_bytes(serialization.Encoding.PEM),
    }
    results = {}
    try:
        for name, data in materials.items():
            path = directory / name
            descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), 0o600)
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(data)
            results[name] = path
    except OSError as exc:
        # Preserve partial output for inspection. Never delete an uncertain path.
        raise ConfigurationError("could not complete lab files; inspect the new directory before retrying") from exc
    return results
