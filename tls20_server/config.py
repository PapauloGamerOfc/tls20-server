"""Strict, bounded configuration for the experimental local HTTP proxy."""

from __future__ import annotations

from dataclasses import dataclass
import ipaddress
import math
from pathlib import Path
import re
import tomllib

from .constants import DEFAULT_PORT

MAX_CONFIG_BYTES = 65536


class ConfigError(ValueError):
    """The configuration is malformed or outside the supported profile."""


@dataclass(frozen=True)
class Endpoint:
    host: str
    port: int

    def __str__(self) -> str:
        host = f"[{self.host}]" if ":" in self.host else self.host
        return f"{host}:{self.port}"


@dataclass(frozen=True)
class Config:
    listen: Endpoint = Endpoint("127.0.0.1", DEFAULT_PORT)
    upstream: Endpoint = Endpoint("127.0.0.1", 8080)
    server_name: str = "localhost"
    certificate_chain: Path = Path("fullchain.pem")
    private_key: Path = Path("server.key")
    max_connections: int = 128
    handshake_timeout_seconds: float = 10
    connect_timeout_seconds: float = 5
    idle_timeout_seconds: float = 60
    max_connection_seconds: float = 3600
    max_bytes_per_direction: int = 16777216
    session_tickets: bool = True
    ticket_lifetime_seconds: int = 86400
    ticket_capacity: int = 4096
    upstream_early_data_aware: bool = False
    early_data_paths: tuple[str, ...] = ()
    max_early_data_bytes: int = 16384

    def __post_init__(self) -> None:
        # Port zero is useful only to callers of the Python API (OS-selected
        # test ports). The configuration file deliberately rejects port zero.
        _validate_endpoint(self.listen, loopback=False, allow_zero=True)
        _validate_endpoint(self.upstream, loopback=True)
        _validate_server_name(self.server_name)
        for name in ("certificate_chain", "private_key"):
            if not isinstance(getattr(self, name), Path):
                raise ConfigError(f"{name} must be a pathlib.Path")
        _positive_integer("max_connections", self.max_connections)
        _positive_integer("max_bytes_per_direction", self.max_bytes_per_direction)
        for name in (
            "handshake_timeout_seconds", "connect_timeout_seconds",
            "idle_timeout_seconds", "max_connection_seconds",
        ):
            _positive_number(name, getattr(self, name))
        for name in ("session_tickets", "upstream_early_data_aware"):
            if type(getattr(self, name)) is not bool:
                raise ConfigError(f"{name} must be a boolean")
        _positive_integer("ticket_lifetime_seconds", self.ticket_lifetime_seconds)
        if self.ticket_lifetime_seconds > 604800:
            raise ConfigError("ticket_lifetime_seconds exceeds the seven-day TLS ticket lifetime")
        _positive_integer("ticket_capacity", self.ticket_capacity)
        if self.ticket_capacity > 100000:
            raise ConfigError("ticket_capacity exceeds this implementation's in-memory budget")
        if type(self.max_early_data_bytes) is not int or not 0 <= self.max_early_data_bytes <= 0xffffffff:
            raise ConfigError("max_early_data_bytes must fit the TLS uint32 field")
        if type(self.early_data_paths) is not tuple or any(
            type(path) is not str or not path.startswith("/") or path.startswith("//")
            or not path.isascii() or any(ord(char) < 33 or ord(char) == 127 for char in path)
            or any(char in path for char in ("?", "#", "\\", "%"))
            for path in self.early_data_paths
        ):
            raise ConfigError("early_data_paths must be exact ASCII origin paths without query or escapes")
        if len(set(self.early_data_paths)) != len(self.early_data_paths):
            raise ConfigError("early_data_paths contains duplicate paths")
        if self.early_data_paths and (not self.session_tickets or not self.upstream_early_data_aware):
            raise ConfigError("Early HTTP requires session_tickets and an explicitly early-data-aware upstream")


def _positive_integer(name: str, value: object) -> None:
    if type(value) is not int or value < 1:
        raise ConfigError(f"{name} must be a positive integer")


def _positive_number(name: str, value: object) -> None:
    if type(value) not in (int, float):
        raise ConfigError(f"{name} must be a positive finite number")
    try:
        valid = math.isfinite(value) and value > 0
    except OverflowError:
        valid = False
    if not valid:
        raise ConfigError(f"{name} must be a positive finite number")


def _validate_endpoint(
    value: Endpoint, *, loopback: bool, allow_zero: bool = False
) -> None:
    if not isinstance(value, Endpoint) or type(value.host) is not str:
        raise ConfigError("Endpoint must contain a literal IP address and port")
    if "%" in value.host:
        raise ConfigError("Scoped IP addresses are not supported")
    try:
        address = ipaddress.ip_address(value.host)
    except ValueError as exc:
        raise ConfigError("Endpoints must use literal IP addresses, not DNS names") from exc
    if loopback and not address.is_loopback:
        raise ConfigError("The HTTP upstream must be a literal loopback address")
    lower = 0 if allow_zero else 1
    if type(value.port) is not int or not lower <= value.port <= 65535:
        raise ConfigError(f"Port must be an integer between {lower} and 65535")


def parse_endpoint(value: object, *, loopback: bool = False) -> Endpoint:
    if not isinstance(value, str) or len(value) > 128 or value != value.strip():
        raise ConfigError("Endpoint must be IP:port or [IPv6]:port")
    if value.startswith("["):
        match = re.fullmatch(r"\[([^\]]+)\]:([0-9]+)", value)
        if not match or ":" not in match[1]:
            raise ConfigError("An IPv6 endpoint must be written [IPv6]:port")
        host, port_text = match.groups()
    else:
        match = re.fullmatch(r"([^:]+):([0-9]+)", value)
        if not match:
            raise ConfigError("Endpoint must be IP:port or [IPv6]:port")
        host, port_text = match.groups()
    endpoint = Endpoint(host, int(port_text))
    _validate_endpoint(endpoint, loopback=loopback)
    return endpoint


def _validate_server_name(value: object) -> None:
    if not isinstance(value, str) or not 1 <= len(value) <= 253:
        raise ConfigError("server_name must be an ASCII DNS name of 1 to 253 characters")
    if not value.isascii() or value != value.lower():
        raise ConfigError("server_name must be a lowercase ASCII DNS name")
    for label in value.split("."):
        if not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label):
            raise ConfigError("server_name contains an invalid DNS label")
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return
    raise ConfigError("server_name must be a DNS name, not an IP address")


def _path(value: object, name: str, directory: Path) -> Path:
    if not isinstance(value, str) or not value or "\x00" in value or len(value) > 4096:
        raise ConfigError(f"{name} must be a nonempty filesystem path")
    path = Path(value)
    try:
        return (path if path.is_absolute() else directory / path).resolve()
    except (OSError, ValueError) as exc:
        raise ConfigError(f"{name} is not a valid filesystem path") from exc


def load_config(path: str | Path) -> Config:
    """Read one bounded TOML file; relative key paths use its directory."""
    config_path = Path(path).resolve()
    try:
        with config_path.open("rb") as stream:
            content = stream.read(MAX_CONFIG_BYTES + 1)
    except OSError as exc:
        raise ConfigError("Cannot read the configuration file") from exc
    if len(content) > MAX_CONFIG_BYTES:
        raise ConfigError(f"Configuration exceeds {MAX_CONFIG_BYTES} bytes")
    try:
        values = tomllib.loads(content.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise ConfigError("Configuration must be valid UTF-8 TOML") from exc
    unknown = set(values) - set(Config.__dataclass_fields__)
    if unknown:
        # Do not repeat arbitrary user-controlled TOML keys in a log message.
        raise ConfigError("Configuration contains unsupported keys")
    defaults = Config()
    if "early_data_paths" in values:
        if type(values["early_data_paths"]) is not list:
            raise ConfigError("early_data_paths must be an array of paths")
        values["early_data_paths"] = tuple(values["early_data_paths"])
    values["listen"] = parse_endpoint(values.get("listen", str(defaults.listen)))
    values["upstream"] = parse_endpoint(
        values.get("upstream", str(defaults.upstream)), loopback=True
    )
    for name in ("certificate_chain", "private_key"):
        values[name] = _path(values.get(name, str(getattr(defaults, name))), name, config_path.parent)
    return Config(**values)
