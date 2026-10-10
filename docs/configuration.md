# Server configuration

The server reads one UTF-8 TOML file, at most 64 KiB. Unknown fields, malformed
values, invalid ports and unsupported identities cause startup to fail. Use
`python -m tls20_server check-config --config server.toml` to validate without
opening a listener. It does not test backend availability.

| Setting | Default | Meaning |
| --- | --- | --- |
| `listen` | `127.0.0.1:1021` | Literal local IPv4/IPv6 address and TCP port |
| `upstream` | `127.0.0.1:8080` | Fixed literal loopback HTTP endpoint |
| `server_name` | `localhost` | One exact expected lowercase ASCII DNS identity |
| `certificate_chain` | `fullchain.pem` | Leaf-first certificate PEM bundle |
| `private_key` | `server.key` | Matching unencrypted PKCS#8 X25519 key |
| `max_connections` | `128` | Maximum accepted active or handshaking sessions |
| `handshake_timeout_seconds` | `10` | Absolute handshake deadline, at most 30 seconds |
| `connect_timeout_seconds` | `5` | HTTP backend connection deadline |
| `idle_timeout_seconds` | `60` | Time without nonempty application bytes in either direction |
| `max_connection_seconds` | `3600` | Absolute accepted-connection lifetime |
| `max_bytes_per_direction` | `16777216` | Application byte quota for each direction |

Relative paths resolve against the TOML file's directory. IPv6 endpoints require
brackets, for example `[::1]:1021`. DNS names are not accepted as listener or
backend addresses. Remote backends are intentionally unsupported in this alpha:
plaintext application traffic stays on the same host. The `server_name` remains
a DNS identity even when TCP uses an IP address.

The server does not become an open forward proxy. It always forwards to the
single configured backend, never to a client-selected Host, URL or CONNECT
target. It is a byte relay, not an HTTP parser: configure the backend itself
not to offer a forward proxy, unrestricted CONNECT, or unintended virtual hosts.
It does not rewrite Host, Location, cookies, Forwarded headers or application
URLs. A backend-generated `https://` link still names ordinary HTTPS, not HTTPPS.

## Ports and deliberate external binding

`1021/TCP` is a shared experimentation port, not a registered HTTPPS service.
The default applies only to controlled experiments whose endpoints can be
updated. No port or URL scheme registration is claimed. Any valid explicit
port can be configured, but the program will not change its default to an
unassigned system port or claim that a configurable port is globally reserved.
See [RFC 6335 section 6.1](https://www.rfc-editor.org/rfc/rfc6335.html#section-6.1)
and [RFC 7605 section 7.7](https://www.rfc-editor.org/rfc/rfc7605.html#section-7.7).

To listen on all IPv4 interfaces deliberately, use `0.0.0.0:1021` and configure
the host and provider firewalls separately. The software does not expose the
listener by default or modify firewall rules. Do not expose this experimental
service or its plain HTTP backend to untrusted networks as a production service.

On Linux, ports below 1024 commonly require `CAP_NET_BIND_SERVICE` or equivalent
service setup. Prefer an unprivileged high port for local work. Do not give a
general-purpose Python executable elevated capabilities merely to run this test,
and do not run an interactive root Python session. A supervised deployment can
grant a dedicated service only the privileges it needs.

## Credentials

The certificate file accepts one through eight PEM certificates. The leaf must
have an X25519 SPKI, critical `basicConstraints: CA=false`, critical keyAgreement-
only key usage, serverAuth EKU and a matching DNS SAN. Certificates may be signed
by Ed25519 or P-256/SHA-256 issuers. No Common Name fallback is used.

The client receives its trust root separately using `--ca`; a root sent in the
handshake never creates trust. The root certificate is normally omitted from
`fullchain.pem`. A lab generated directly under a root therefore has only its
leaf in `fullchain.pem`; this is a complete transmitted chain for that setup.

POSIX key files must exclude all group/other permission bits (usually mode 0600);
the lab directory is created with mode 0700. Windows inherits ACLs from the
parent directory: choose a user-private parent and protect it using Windows ACLs.
Never place key files under the backend HTTP document root. Keys are unencrypted
on disk for unattended loading; protect the host and backups accordingly.

The local generator uses fresh OS-backed cryptographic randomness, creates a
30-day server certificate and a 365-day CA certificate, and never writes the CA
private key. Regenerating requires a new directory and explicit client trust
update. Real deployments need their own issuance/rotation process. This alpha
has no automatic renewal, hot reload, certificate enrollment or OS trust-store
installation. Restart after deliberately replacing credentials.
