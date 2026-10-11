# Server configuration

The server reads one UTF-8 TOML file, at most 64 KiB. Unknown fields, malformed
values, invalid ports and unsupported identities cause startup to fail. Use
`python -m tls20_server check-config --config server.toml` to validate without
opening a listener. It does not test backend availability.

| Setting | Default | Meaning |
| --- | --- | --- |
| `listen` | `127.0.0.1:343` | Literal local IPv4/IPv6 address and TCP port |
| `upstream` | `127.0.0.1:8080` | Fixed literal loopback HTTP endpoint |
| `upstream_protocol` | `"http/1.1"` | Select `h2` only for a cleartext HTTP/2 prior-knowledge backend; no HTTP version translation |
| `cipher_suites` | `[0x1301, 0x1302, 0x1303, 0x1304, 0x1305]` | Ordered permitted AES-GCM, ChaCha20-Poly1305 and AES-CCM/CCM8 suites; integrity-only is not HTTPPS |
| `record_size_limit` | `16385` | Negotiated receive limit (64..16385), including inner type and padding; enforced only if offered |
| `certificate_compression` | `[1, 2, 3]` | Permitted zlib, Brotli and Zstandard codecs; empty list disables negotiation |
| `heartbeat_mode` | `0` | Off (0), permit peer probes (1), or negotiate while disallowing peer probes (2); no periodic timer |
| `ticket_count_limit` | `1` | Per-handshake issuance budget (0..255); client ticket requests are bounded hints |
| `server_name` | `localhost` | One exact lowercase ASCII DNS identity or canonical IP reference identity |
| `certificate_chain` | `fullchain.pem` | Leaf-first certificate PEM bundle |
| `private_key` | `server.key` | Matching unencrypted PKCS#8 X25519 key |
| `profile_file` | unset | Optional strict role/service/port-bound authentication and cryptographic profile; see [profiles](profiles.md) |
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
plaintext application traffic stays on the same host. A DNS `server_name` is
authenticated as a DNS SAN even when TCP routes to an IP address. A literal IP
reference requires a matching `iPAddress` SAN; it is never sent as DNS SNI and
an IP-looking `dNSName` cannot authorize it. IPv6 HTTP authorities use brackets.

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

The current route-aware early-data gate requires `upstream_protocol = "http/1.1"`.
With `h2`, normal authenticated multiplexed HTTP/2 is relayed unchanged, but
`early_data_paths` must remain empty: an HTTP/1 parser cannot authorize HTTP/2
frames. The low-level channel accepts application-specific early-data policies;
that API does not automatically authorize early HTTP/2 requests.

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

The settings below describe the simple default certificate path. Optional
[profiles](profiles.md) expose the implemented RPK/delegation, PSK, PAKE, native
national algorithms, evidence, client authorization and ITS policies through
the same CLI. A profile does not relax the fixed backend, early-data gate or
connection quotas. It is executable/trust configuration and must not be supplied
by an untrusted remote peer.

The general credential loader accepts up to 64 PEM certificates. The default leaf
has an X25519 SPKI, compatible non-CA/keyAgreement usage, appropriate serverAuth
EKU constraints and a matching DNS or IP SAN. The separate generated lab profile
uses stricter critical usage and path constraints. Certificates may use the
supported RSA, ECDSA or EdDSA issuer signatures, with provider-backed consistency
checks including name constraints. No Common Name fallback is used. The final
supplied issuer is only a local consistency anchor for loading the operator's
own incomplete chain; it is never installed as a remote client's trust root.

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
