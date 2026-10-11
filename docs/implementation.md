# Protocol implementation and compatibility

The implementation targets the first TLS 2.0 specification, revision
[0c9c8bf0914697d521050554e545a167fa8fc345](https://github.com/PapauloGamerOfc/tls20-spec/tree/0c9c8bf0914697d521050554e545a167fa8fc345).
The negotiated version is `0x0400`; older TLS versions and the former prototype
wire format are not accepted. The bootstrap is `TLS20-EXPERIMENT\r\n` and the KDF
label prefix is `tls20 `. The application protocol is the exact byte string
`http/1.1`, describing the inner HTTP stream, not ordinary HTTPS interoperability.

Client URLs use `httpps://hostname[:port]/path`, default TCP port 343. The
diagnostic client makes a GET with `Connection: close` and writes raw response
bytes. A trusted `--connect-host` override changes routing only; identity
validation still uses the URL's hostname. The client does not render pages,
follow redirects, manage cookies or install a browser protocol handler.

## Implemented connection flows

1. The dedicated listener checks the bootstrap and parses TLS-style Hello
   messages and extensions, selecting only version `0x0400`. It rejects
   `signature_algorithms`; certificate signature preferences are separate.
2. The fresh client authentication share is X25519. Traffic agreement is
   independent, supporting X25519 and secp256r1/P-256. HelloRetryRequest uses
   the synthetic message-hash transcript, preserves the bootstrap once and
   rejects early data for that handshake.
3. ClientHello and ServerHello are plaintext; subsequent server handshake
   records are encrypted. The certificate's static X25519 key authenticates through
   MAC-based CertificateVerify (`0xfe00`), not an online digital signature.
   The client validates the certificate, hostname, MAC and Finished before
   accepting the server. Client Finished and subsequent records are protected.
4. The default forwarding path opens the fixed local backend only after client
   Finished verification. Independent directional application keys protect a
   bounded duplex relay. Authentication failures never trigger downgrade.
5. A listener-local ticket store enables PSK+DHE resumption. Tickets bind the
   hostname, application protocol and server certificate chain; binders are
   verified before use. Client caches also bind their trust policy, target
   context and configured client credential (or anonymous identity). An
   authenticated client identity saved in a ticket is reauthorized after the
   binder check and before any early-data admission. The initial full handshake
   is still required to obtain a ticket.
6. Optional 0-RTT decrypts authenticated early records and can forward one
   authorized request to the backend **before client Finished**. See the policy
   below. TLS rejection of early data returns to the ordinary application-data
   path; no rejected early bytes reach the backend.
7. Encrypted NewSessionTicket and KeyUpdate messages are processed after the
   handshake. KeyUpdate changes one direction at a time and is sent before the
   implementation's per-epoch quota is exhausted. Exporters are available from
   an authenticated channel; padding and compatibility CCS handling are tested.
8. The low-level API optionally requests an initial client certificate and
   verifies its MAC (`0xfe01`) with a fresh verifier share. Post-handshake client
   authentication (PHA) uses independent request contexts and verifier keys.
   Neither feature is enabled or configured by the forwarding CLI by default.

Server authentication alone does not identify the client. The default forwarding
CLI performs no client-certificate authentication. Even when the low-level API
authenticates a client, application authorization remains an explicit policy.

## Optional client authentication API

`server_handshake(..., client_auth_validator=callback,
require_client_auth=False)` requests initial client authentication on a full
handshake. `require_client_auth=True` requires a validator and refuses an empty
client Certificate. The default is no request. The callback receives a list of
DER certificates and may be synchronous or async; it must validate trust,
client identity and authorization, validity, appropriate key usage/clientAuth
EKU, and the application's revocation policy. It must return the authorized
`X25519PublicKey` of the actual leaf, not merely extract a key or return a private
key. The server's restricted server-EKU validator is not substituted for this
client policy. Callback approval is not identity establishment: MAC and Finished
must also pass before `channel.authenticated_client` is populated.

`client_handshake(..., client_credentials=Credentials(...),
post_handshake_auth=True)` supplies an optional client chain/private key and
advertises PHA. Both options default off. Initial client credentials are sent
only after the server's CertificateVerify and Finished have been verified.
There are no corresponding CLI/configuration fields or automatic credential UI.

After the handshake, `await channel.request_client_auth(required=False)` on the
server returns a Future. The application must keep driving `channel.recv()` so
the response can be verified and the Future resolved. A successful result is the
authenticated DER-chain tuple; optional refusal returns `None`. Each response
binds its unique request context, original handshake transcript and original
normal exporter root. PHA Finished uses the current client application traffic
secret, including intervening KeyUpdates. Requests have a local pending budget
(`max_pending=128` by default); the client also bounds remembered contexts.
Closing the channel, cancelling the returned Future, or cancelling reception
with authentication pending consumes its retained verifier state. Python cannot
promise physical erasure of that memory.

Changing or removing the configured client credential isolates the client ticket
cache, so another identity cannot silently inherit an old session. The server
revalidates a cached client identity before resumption; rejection falls back to
a full handshake without accepting that ticket's early data. A new client MAC
cannot authorize bytes already sent early. Tickets issued before PHA retain the
identity present when issued; later PHA does not promote those earlier tickets.

## Optimizations and 0-RTT policy

Session tickets are enabled by default. Tickets and replay state live only in
bounded process memory. Restarting discards both, causing a fresh handshake;
the server never restores tickets without their replay state. Expired entries
are removed from the insertion-ordered prefix, avoiding a full cache scan per
handshake. Capacity eviction invalidates a ticket rather than forgetting its
replay state while continuing to accept it.

Besides the configured entry count, `TicketStore` has a default 16 MiB accounted
byte budget. It counts retained identity, PSK, context and client-certificate
bytes plus conservative per-object allowances; it is not an exact process-RSS
limit. Eviction and expiry update cached byte accounting without a whole-store
scan. A single entry larger than the budget is not issued, but its valid
connection remains usable without a ticket. Embedders can set `max_bytes` in the
constructor; the forwarding CLI uses the default. These are local cache limits,
not new wire-protocol restrictions.

0-RTT forwarding additionally requires `upstream_early_data_aware = true` and
an explicit `early_data_paths` allowlist. Only one complete, bodyless GET/HEAD
with an exact configured path and expected Host is accepted. Cookies,
Authorization, query strings, ambiguous framing and pipelined early requests
are refused. The proxy adds `Early-Data: 1`; the backend must implement the
corresponding replay-aware semantics and may return HTTP 425. GET alone is not
proof that repeating a request is safe. Do not enable this for an unaudited
upstream. The [configuration guide](configuration.md) lists the settings.

A valid binder atomically reserves a ticket's early-data use before forwarding.
This is listener-local replay protection, **not** a distributed exactly-once
guarantee. Multiple instances would require coordinated replay state or early
data disabled. Early data also lacks the forward-secrecy properties of the
fresh DHE application-data keys. Backend response forwarding starts after
Finished, although backend processing of the early request can begin before it.

The diagnostic client supports an in-memory ticket cache, `get --repeat N` and
`--early-data`. It retries its bodyless GET once without early data after HTTP
425, including when informational responses precede 425. The retry shares the
original request deadline. Authentication errors are never retried as plaintext.

## Modules

| Module | Responsibility |
| --- | --- |
| `crypto.py` | Provider-backed key agreement, key schedule, MAC, AEAD and updates |
| `messages.py` | Strict wire encodings, extension parsing and DNS syntax |
| `tickets.py` | Bounded ticket, client session and early-replay state |
| `pki.py` | Credential parsing and restricted explicit-trust lab validation |
| `handshake.py` | Reassembly, transcripts, state transitions and record channel |
| `early_http.py` | Narrow replay-aware early HTTP request gate |
| `config.py` | Configuration parsing and local endpoint policy |
| `server.py` | Admission, lifetime management and duplex forwarding |
| `client.py` | HTTPPS URL handling and diagnostic client |
| `lab.py` | Fresh local CA and server credential generation |

## Coverage boundaries

This is not an implementation of every optional profile in the specification.
The current application profile uses HTTP/1.1, AES-128-GCM/SHA-256 and server
X.509 authentication, with optional initial/PHA client MAC authentication through
the low-level API described above. Raw public keys, delegated credentials, external PSKs,
certificate compression, exported authenticators, PAKE/POK and other optional
profiles are not advertised or implemented. Unsupported profiles must not be
mistaken for negotiated capabilities.

The Python certificate validator remains an explicit-trust, ordered-chain
**lab-offline** profile using Ed25519/P-256 CA signatures. It is not a general
public WebPKI verifier, revocation service or replacement for a browser's
certificate verifier. Phromium has its own browser validation and cache policy;
cross-repository tests must identify both actual source revisions.

## Closure, resources and tests

Unexpected TCP EOF is not an authenticated close. Encrypted close_notify is
distinguished from truncation; cancelled partial records are not resumed.
Backend EOF causes close_notify but does not prove HTTP message completeness;
applications still need HTTP framing validation. The terminal client is a raw
diagnostic tool, not a general HTTP client.

Records carry at most 16 KiB of content. Epoch, message, transcript, ticket and
connection quotas are local resource limits, not extra protocol-version
restrictions. The absolute handshake deadline does not restart on partial input.
The server uses bounded asyncio streams and backpressure, caps accepted tasks
and cancels owned pumps on shutdown. Cryptographic work runs in the event loop;
high-load throughput is not established and no volumetric DoS claim is made.

Tests cover full/resumed handshakes, both traffic groups, retry transcripts,
binders, ticket replay/restart, early rejection, backend receipt before client
Finished, HTTP 425 retry, KeyUpdate, exporters, malformed records, certificates,
identity, MACs, quotas and teardown. Passing tests are not a formal security
proof, an independent audit or evidence of compatibility with ordinary HTTPS.
Client-MAC tests include independent spec-derived known answers, captured initial
and PHA transcripts, intervening KeyUpdate, identity-isolated caches, refused or
revoked credentials, and cancellation cleanup. These checks supplement, rather
than replace, end-to-end tests that share implementation code.
