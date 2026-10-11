# Server configuration

The server reads one UTF-8 TOML file, at most 64 KiB. Unknown fields, malformed
values, invalid ports and unsupported identities cause startup to fail. Use
`python -m tls20_server check-config --config server.toml` to validate without
opening a listener. It does not test backend availability.

| Setting | Default | Meaning |
| --- | --- | --- |
| `listen` | `127.0.0.1:343` | Literal local IPv4/IPv6 address and TCP port |
| `upstream` | `127.0.0.1:8080` | Fixed literal loopback HTTP endpoint |
| `server_name` | `localhost` | One exact expected lowercase ASCII DNS identity |
| `certificate_chain` | `fullchain.pem` | Leaf-first certificate PEM bundle |
| `private_key` | `server.key` | Matching unencrypted PKCS#8 X25519 key |
| `max_connections` | `128` | Maximum accepted active or handshaking sessions |
| `handshake_timeout_seconds` | `10` | Positive finite absolute handshake deadline; local policy, not a wire-protocol limit |
| `connect_timeout_seconds` | `5` | HTTP backend connection deadline |
| `idle_timeout_seconds` | `60` | Time without nonempty application bytes in either direction |
| `max_connection_seconds` | `3600` | Absolute accepted-connection lifetime |
| `max_bytes_per_direction` | `16777216` | Application byte quota for each direction |
| `session_tickets` | `true` | Enable bounded, memory-only session resumption |
| `ticket_lifetime_seconds` | `86400` | Positive ticket lifetime, at most the TLS maximum of 604800 seconds |
| `ticket_capacity` | `4096` | In-memory tickets; local implementation maximum 100000 |
| `upstream_early_data_aware` | `false` | Operator confirms the backend honors Early-Data/425 and audited early routes |
| `early_data_paths` | `[]` | Exact replay-safe paths permitted before Client Finished; no query, escapes or wildcard |
| `max_early_data_bytes` | `16384` | Per-connection advertised early byte limit; zero disables early data |

Relative paths resolve against the TOML file's directory. IPv6 endpoints require
brackets, for example `[::1]:343`. DNS names are not accepted as listener or
backend addresses. Remote backends are intentionally unsupported in this alpha:
plaintext application traffic stays on the same host. The `server_name` remains
a DNS identity even when TCP uses an IP address.

The server does not become an open forward proxy. It always forwards to the
single configured backend, never to a client-selected Host, URL or CONNECT
target. Normal authenticated traffic is a byte relay: configure the backend itself
not to offer a forward proxy, unrestricted CONNECT, or unintended virtual hosts.
It does not rewrite Host, Location, cookies, Forwarded headers or application
URLs. A backend-generated `https://` link still names ordinary HTTPS, not HTTPPS.

## Resumption and 0-RTT policy

Tickets are protocol-, server-credential-, name- and ALPN-bound. They and their
atomic early-use state are shared by all connections of one listener. A restart
invalidates them; do not share or restore tickets across processes without a
shared atomic replay store. An evicted or expired ticket causes a full handshake,
not reuse of untracked early authorization. Resumption alone is enabled by default;
0-RTT additionally needs the explicit backend and route settings above.

The early path is a deliberately narrow HTTP parser. It permits one complete
GET or HEAD to an allowlisted path and the configured Host, with no body,
query, Authorization, Cookie, upgrade or ambiguous/pipelined framing. It inserts
exactly one `Early-Data: 1` header and forwards the request **before Client
Finished**, after validating the PSK binder and atomically reserving early use.
The route allowlist is an application policy, not a new TLS protocol restriction.
A safe method name does not make a route safe to repeat.

TLS-level early rejection is distinguished from an HTTP-policy refusal after
TLS acceptance. The latter returns `425 Too Early` on the authenticated channel
without forwarding the rejected request. The test client retries that GET once
without early data; a peer must not blindly retry state-changing operations.
Backend processing can begin early, but response forwarding waits for Client
Finished. This saves request transit/backend time without treating early traffic
as client identity. Backend access control is still required.

## Ports and deliberate external binding

`343/TCP` is the project-defined default for HTTPPS. The client uses this port
when a URL omits the port: `httpps://example.com/` and
`httpps://example.com:343/` select the same endpoint. The HTTP Host header omits
the default port. Explicit nondefault ports remain supported, for example
`httpps://example.com:8443/`. No exclusive port or URL scheme registration is
claimed; deployments must check for conflicts with other local services.

To listen on all IPv4 interfaces deliberately, use `0.0.0.0:343` and configure
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
