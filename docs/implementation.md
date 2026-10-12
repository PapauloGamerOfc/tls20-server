# Protocol implementation and compatibility

The implementation targets the first TLS 2.0 specification, revision
[dee31da9826e10bd590f58acc0f9f46143505fd1](https://github.com/PapauloGamerOfc/tls20-spec/tree/dee31da9826e10bd590f58acc0f9f46143505fd1).
The negotiated version is `0x0400`; older TLS versions and the former prototype
wire format are not accepted. The bootstrap is `TLS20-EXPERIMENT\r\n` and the KDF
label prefix is `tls20 `. ALPN describes the inner application: the forwarding
CLI selects `http/1.1`, or `h2` with an explicitly configured prior-knowledge
HTTP/2 backend. This is not ordinary HTTPS interoperability.

Client URLs use `httpps://hostname[:port]/path`, default TCP port 343. The
diagnostic client makes a GET with `Connection: close` and writes raw response
bytes. A trusted `--connect-host` override changes routing only; identity
validation still uses the URL's hostname. The client does not render pages,
follow redirects, manage cookies or install a browser protocol handler.

## Implemented connection flows

TLS Feature requirements are checked against the actual ClientHello and the
authenticated selection/message state, not a caller's predeclared negotiation
list. Resumption rechecks current negotiation and cached certificate evidence.
Requirements that depend on the new ServerHello/EncryptedExtensions prevent
early application data until they can be checked; ordinary eligible 0-RTT
remains available. A missing Certificate flight on PSK resumption does not
require redundant certificate compression, caching or a fresh certificate MAC.
Newly offered mandatory OCSP/CT evidence is checked before sending early bytes,
including on the legacy lab trust path.

Invalid certificate decompression or a decompressed-length mismatch produces
`bad_certificate` (42). Outer framing, unoffered algorithms and allocation
limits retain their separate checks. CachedObject hashes must be nonempty even
for unknown object types; well-formed unknown types are still ignored.

PHA request failures and cancellation clear completed protocol traceback
frames, releasing abandoned ephemeral-key references. A validation error
before sending a new request does not destroy independent pending requests.
This is managed-reference cleanup, not guaranteed erasure of Python memory;
see [SECURITY.md](../SECURITY.md).

1. The dedicated listener checks the bootstrap and parses TLS-style Hello
   messages and extensions, selecting only version `0x0400`. It rejects
   `signature_algorithms`; certificate signature preferences are separate.
2. The fresh client authentication share is X25519. Traffic agreement is
   independent, supporting X25519/X448, NIST P-256/P-384/P-521, the three
   TLS Brainpool groups, RFC 7919 FFDHE groups and the three RFC 10024 ML-KEM
   hybrid groups. HelloRetryRequest uses
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

### Explicit retry-cookie policy

`server_handshake(..., retry_cookie_policy=RetryCookiePolicy())` and the password
server API can send a cookie-only HelloRetryRequest, or combine the cookie with
the necessary group/salt retry. The forwarding configuration exposes
`retry_cookie=false` (default) and `retry_cookie_lifetime_seconds=30` (1..300).
Enabling it adds one RTT and rejects 0-RTT for that exchange; it is not enabled
as a general performance optimization. The ordinary fast resumption/early-data
path remains unchanged with the default.

Password-authenticated successor tickets use ordinary traffic key agreement,
including a group retry with or without a cookie. The retry updates the ticket
age and binder, preserves the selected identity and rejects early data. PSK
continuity distinguishes hash identities, not just binder lengths: SHA-256 and
SM3 are different KDFs even though both produce 32-byte binders. A server cannot
infer the hash of an unrecognized opaque PSK identity.

`tls20_server.retry_cookie.RetryCookiePolicy` uses an OS-random 256-bit HMAC key,
fixed-size opaque cookies and a bounded lifetime. It binds the cookie to the
transport peer IP, exact initial ClientHello, selected suite and requested
group; changed/missing/expired cookies are rejected before proceeding. No
per-cookie store grows with traffic. The listener's key is not persisted and
restart invalidates cookies. TCP connection/transcript state remains bounded
by the existing connection and handshake limits: this is a stateless cookie
token, not a claim of an entirely stateless TCP server. A cookie proves
reachability only, never credential authentication or replay-safe early data.

The parser validates recognized extension placement and delegation offers
before selecting ordinary credentials or resumption. This also applies to
initial/PHA/cached certificate requests and application-authenticator requests.
Version negotiation uses the specification's distinct `protocol_version`,
`missing_extension`, `decode_error` and `illegal_parameter` alerts. Unknown
offers still follow their defined ignore rules. An unknown-only supported-group
list does not prevent an otherwise valid PSK-only (`psk_ke`) exchange. Received
DNS SNI is compared case-insensitively; the original extension bytes remain in
the transcript and retry-continuity checks. Configuration names stay canonical.
`user_canceled` is advisory between complete handshake messages, not permission
to interleave an alert into a fragmented message. Received fatal alerts terminate
the connection without an alert-response loop.
These rules also apply to accepted and rejected 0-RTT. Once a rejected-early-data
connection authenticates a handshake-key record, even an advisory alert, it
leaves discard mode; later authentication failures cannot be skipped as early
data.

When both record-size extensions are offered, `record_size_limit` takes precedence
and `max_fragment_length` is ignored, including an unrecognized MFL value.
Tickets retain the previously negotiated server receive limit for 0-RTT; external
PSKs use their explicitly provisioned early-record limit. The resumed handshake
negotiates independent limits for its later handshake/application records. This
also applies to password-authenticated sessions: adding, omitting or changing a
record-limit offer cannot retroactively change the limit on early records.

### Client certificate policy

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

Certificate-chain signatures and delegation-grant signatures have independent
preference lists. The server API accepts `client_certificate_algorithms` and
`client_delegation_signature_algorithms`; the client API accepts
`server_certificate_algorithms` and `server_delegation_signature_algorithms`.
Each defaults to the available provider's supported public signature schemes,
but explicit nonempty lists may differ (for example an ECDSA chain and Ed25519
grant). Unknown, duplicate, unavailable or online-MAC schemes are rejected as
local policy errors. PHA can override the two lists for an individual request
using `certificate_algorithms` and `delegation_signature_algorithms`; enabling
the latter requires an existing delegation verifier. Resumption is isolated
when either handshake preference changes. These are embedding API controls,
not additional mandatory server configuration fields.

To request client OCSP, set
`client_certificate_evidence_extensions=((5, b""),)` on `server_handshake` and
install `client_credential_policy` with an actual evidence validator (for example
`CredentialEvidencePolicy(require_ocsp=True)`). Only X.509 client credential
types may be enabled with this request. Unlike ClientHello, CertificateRequest's
`status_request` value is empty; it cannot carry nonce/responder preferences.
`request_client_auth(certificate_evidence_extensions=...)` overrides this offer
for that PHA request only: `None` inherits the handshake policy and `()` omits
the request. Removing an offer does not disable a locally required OCSP policy.
The client sends configured OCSP evidence only when requested; real signature,
CertID, authority, status and freshness checks still govern its acceptance.
Cached client evidence is checked again before accepting resumption or 0-RTT.
This API does not implicitly enable client CT, which requires its own explicit
application profile in the specification.

`client_handshake(..., client_credentials=Credentials(...),
post_handshake_auth=True)` supplies an optional client chain/private key and
advertises PHA. Both options default off. Initial client credentials are sent
only after the server's CertificateVerify and Finished have been verified.
The [profile configuration](profiles.md) can provision initial credentials,
authorization and the PHA capability. Triggering PHA remains an application API
decision; no automatic credential-selection UI or HTTP identity header is added.

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
Failed PHA responses also clear secret-bearing completed protocol traceback
frames at the public receive boundary, including malformed shares and provider
failures/cancellation. Application callback frames remain application-owned.

Changing or removing the configured client credential isolates the client ticket
cache, so another identity cannot silently inherit an old session. The server
revalidates a cached client identity before resumption; rejection falls back to
a full handshake without accepting that ticket's early data. A new client MAC
cannot authorize bytes already sent early. Tickets issued before PHA retain the
identity present when issued; later PHA does not promote those earlier tickets.

## Optimizations and 0-RTT policy

Session tickets are enabled by default. Tickets and replay state live only in
bounded process memory. Restarting discards both, requiring fresh authentication;
the server never restores tickets without their replay state. Expired entries
are removed from the insertion-ordered prefix, avoiding a full cache scan per
handshake. Capacity eviction invalidates a ticket rather than forgetting its
replay state while continuing to accept it.

Each ticket locally retains the allowed `psk_key_exchange_modes` from its
authorizing ClientHello. Resumption intersects that restriction with the new
offer and current server policy before any early-data authorization; successor
tickets cannot widen it. The final selected identity is checked again after
HelloRetryRequest, so an expired first candidate cannot lend its modes to a
different ticket selected afterward. This also applies to combined-PSK and password-session
descendants, without adding an NST wire field. A client with no compatible mode
discards the cached ticket and authenticates afresh without early data. If an
explicit external PSK is required and the server declines its descendant ticket,
the client rejects credential-only fallback; a new attempt must prove the
provisioned external key instead of silently losing that authentication factor.

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
| `pki.py` | Provider-backed explicit-root PKIX and separate laboratory policy |
| `credential_profiles.py`, `credential_evidence.py` | X.509, delegation, RPK and current OCSP/CT policy |
| `dnssec_credentials.py`, `transparency.py` | Signed DNSSEC/DANE and CT evidence with explicit trust |
| `credential_cache.py` | Bounded codecs and cached credential objects |
| `application_auth.py` | Connection-bound application authenticators |
| `bootstrap_credentials.py`, `psk.py` | Explicit bootstrap and external/imported PSK authorization |
| `optional_controls.py`, `handshake_options.py` | Control, ticket and signaling negotiation |
| `diagnostics.py` | Separately built, explicitly authorized test secret sink |
| `handshake.py` | Reassembly, transcripts, state transitions and record channel |
| `early_http.py` | Narrow replay-aware early HTTP request gate |
| `config.py` | Configuration parsing and local endpoint policy |
| `profiles.py` | Strict file-backed authentication, provider and evidence policies |
| `pake.py`, `pake_native.py`, `pake_handshake.py` | Native EC/FFC password commitments, authorization and successor tickets |
| `openssl_provider.py`, `gost_provider.py` | Explicit private provider contexts, national algorithms and GOST record trees |
| `its_credentials.py`, `native/its` | Provisioned ITS service/permission/grant verification |
| `server.py` | Admission, lifetime management and duplex forwarding |
| `client.py` | HTTPPS URL handling and diagnostic client |
| `lab.py` | Fresh local CA and server credential generation |

## Coverage boundaries

The following inventory distinguishes negotiated protocol implementations from
deployment policy and application interfaces. Optional mechanisms require their
explicit policy or provider; they are not all enabled by default. The library
and forwarding CLI have different interfaces:

| Capability | Implemented interface and verification |
| --- | --- |
| Baseline suites 0x1301..0x1305 | Full handshake, resumption, early data and KeyUpdate; cross-language native peer tests |
| External/imported and combined PSK, `psk_ke`/`psk_dhe_ke` | Explicit library provisioning, independent identity/hash selection and policy-bound tickets |
| X.509/RPK/delegation | Current credential policy, actual proof and Finished, including client authentication |
| Compression/cache | Negotiated certificate flights and transcript binding; zlib, Brotli, Zstandard; bounded decompression |
| Initial/PHA client MAC | Explicit application policy; `h2` does not permit TLS PHA |
| Application authenticators | Both directions, requested and spontaneous server identities, including opt-in after PAKE; independent application framing/authorization |
| Channel binding | Normal exporter, stable over KeyUpdate |
| POK bootstrap | Explicit binding/trust mode; fresh possession distinguished from ticket authority; real loopback bootstrap/resumption |
| RSL/MFL/heartbeat/ticket requests | CH/EE plus protected records; malformed lengths, both directions and resumed counts tested |
| External signaling | Independently verified identity hashes/session IDs; required missing/mismatched bindings fail |
| Literal IP references | Exact `iPAddress` SAN verification without DNS SNI; full/resumed/early paths and IPv6 HTTP authority tests |
| Integrity-only 0xc0b4/0xc0b5 | Explicit bilateral library opt-in; never normal HTTPPS or confidential resumption |
| HTTP/2 | Fixed backend relay with multiple streams on one connection; no HTTP version translation |
| OCSP/CT/DNSSEC | Complete OCSP request/responder/nonce matching and TLSFeature issuer constraints; provider-backed evidence validators and explicit roots/logs/policy, not trust from decoding |
| Diagnostic secrets | Separate test wheel, explicit scoped consent, protected new file; unavailable in production wheel |
| PAKE 0xc0b0..0xc0b3 | Native EC23/24/25 and FFC256..260 commitments, salt retry, protected usernames, Finished, authorized successor tickets and real 0-RTT; explicit mixed credential/PWD offers select one mode in HRR without authentication-failure fallback |
| SM2/SM3/SM4 | Explicit optional public OpenSSL provider, separate hash context, both SM4 suites and role-specific certificate/grant identifiers |
| GOST | Explicit private provider; seven groups, four MGM suites, per-record TLSTREE, native certificate/grant validation and resumed/early/KU tests |
| ITS-X25519 grants | Explicit native COER/signature/path/PSID/SSP/service/revocation policy, initial/PHA MAC and proof-bound resumption |
| Operational profiles | Server `profile_file`, client `get --profile`, strict schema, independent trust inventories and no automatic provider discovery |

These optional profiles have real implementations and tests, not aliases for
ordinary PSK/X.509. Native providers still require explicit compatible builds.
The ITS validator implements its documented, explicitly provisioned P-256/P-384
PSID/SSP grant profile, not every ITS deployment, enrollment or revocation
transport. PAKE includes the approved TLS 2.0 clarification of expanded hunting
output and full-entropy FFC V16 scalars; EC retains V8 scalars. These protocol
clarifications must also be present in the communicating implementation.
Phromium coverage must be verified independently; a Python feature does not
imply a browser UI or every deployment policy exists.

Dynamic PHA and application-authenticator requests are application APIs, not
automatic relay behavior. Credential issuance, user account provisioning,
distributed replay coordination and online revocation/log transports remain
deployment responsibilities. The relay intentionally disallows integrity-only
records and arbitrary early HTTP side effects; this is an application policy,
not missing wire negotiation. Algorithm and ITS policy subsets are explicit
and fail closed rather than advertising unsupported choices.

`CredentialPolicy` provides a separate explicit-root OpenSSL path validator,
RSA/EdDSA/ECDSA signatures, name constraints, role and key-usage checks.
`CredentialEvidencePolicy` can require current OCSP/CT evidence. The separate
`lab-offline` diagnostic mode does not check revocation. No mode silently fetches
peer-supplied URLs, imports remote roots or replaces browser WebPKI policy.
Cross-repository tests must identify both actual source revisions, including
dirty worktrees during development.

### Application authenticators

Applications negotiate and frame `tls20-authenticator` messages themselves; no
HTTP header is invented. `credential_validator(policy, role=..., authorize=...)`
combines current PKIX/evidence with additional application-scope authorization.
Only a successful `AuthenticationResult` after MAC and Finished establishes key
possession; a policy callback is not a success notification. Additional identities
never replace the original connection identity, and consumed contexts cannot be
reused. An appropriate application framing can use these over `h2`; its TLS PHA
prohibition is not a prohibition of application authenticators.
Recognized OID filters (including key usage and extended key usage) constrain
both local credential selection and received authenticators, before application
authorization. An unsuitable requested credential produces an authenticated
refusal; a peer cannot bypass the filter with a valid MAC/Finished. CA-name lists
remain selection preferences, not independent trust or authorization decisions.
Local selection also checks certificate-path and delegation-grant signature
offers independently, in both directions. An incompatible requested identity
produces a Finished-only refusal; an incompatible spontaneous identity is a
local error. Malformed requests or delegated credentials remain errors rather
than being hidden by credential selection.
Well-framed unknown/GREASE or wrong-role schemes in the optional delegation
offer do not exclude an independently compatible direct X25519 credential.
They do not authorize an unoffered delegated proof: actual grant selection and
verification still enforce the role-specific MAC and grant-signature lists.

TLS Feature requirements use the current authenticator's actual path/grant and
role-MAC mechanisms, not a blanket copy of its offers or a previous handshake.
Required OCSP/CT evidence must still be present and valid; advertising a grant
algorithm without returning a delegated credential cannot satisfy that feature.
Request, proof-generation and validation failures clear completed protocol
traceback frames, including chained exceptions and cancellation. Other pending
requests and application-owned callback frames remain intact. This releases
managed references to abandoned verifier/derived keys, not a guarantee of
physical erasure of Python or provider memory.

Closing the authenticator capability releases the retained connection
`auth_share` without closing ordinary traffic. In-flight validations own a
revocable key slot: capability/connection closure clears it immediately, even
while application authorization is suspended. Derived exporter/MAC keys are
created only after authorization returns. Async policy callbacks run in a
separate task; cancelling validation cannot be suppressed by the callback.
A callback that ignores cancellation may continue its application work, but
receives no protocol private or derived key, cannot authorize the cancelled
request, and has its eventual exception observed. Applications should still
make callbacks cancellation-cooperative. Cancelling one request preserves
other pending requests and the enabled spontaneous-identity capability.

### Test-only diagnostic build

`python tools/build_test_wheel.py` builds a separately named diagnostic wheel
without changing the production checkout flag. `DiagnosticSink` requires an
absolute new file and explicit test-data/traffic authorization; exporter roots
require separate opt-in. `SSLKEYLOGFILE` does not activate it. Treat output as
decryption material. `tools/check_wheel.py` verifies that production remains disabled.

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
and cancels owned pumps on shutdown. Slow native PAKE operations run off the event
loop; cancellation joins the native operation and cleans owned state before
releasing admission. Other provider operations may still execute synchronously.
Large FFC groups are expensive, especially without assembly. High-load throughput
is not established and no volumetric DoS claim is made. Native use of secure BNs,
constant-time flags, blinding and bounded hunting does not constitute a formal
whole-program side-channel audit of Python, providers or platform code.

Tests cover full/resumed handshakes, both traffic groups, retry transcripts,
binders, ticket replay/restart, early rejection, backend receipt before client
Finished, HTTP 425 retry, KeyUpdate, exporters, malformed records, certificates,
identity, MACs, quotas and teardown. Passing tests are not a formal security
proof, an independent audit or evidence of compatibility with ordinary HTTPS.
Client-MAC tests include independent spec-derived known answers, captured initial
and PHA transcripts, intervening KeyUpdate, identity-isolated caches, refused or
revoked credentials, and cancellation cleanup. These checks supplement, rather
than replace, end-to-end tests that share implementation code.

### Duplex control ordering and CertificateEntry path binding: 2026-10-12

A requested KeyUpdate is serviced before the next application record even when
an upload is paused in transport backpressure. Fatal input revokes subsequent
writes immediately, without waiting for the send lock. A locally generated fatal
alert retains only the sending epoch needed for its bounded delivery; a received
fatal alert does not cause a response loop. If a KeyUpdate was already emitted,
the alert uses the new sending epoch. Cancellation and actual transport failures
still abort ambiguous record states; a peer's clean half-close still allows the
independent send direction to finish.

Event-gated duplex regressions exercise both roles, queued writers, repeated
updates, fatal errors during application/handshake/update/close writes and
cleanup. Retry regressions cover valid dummy CCS, malformed CCS and other
unexpected record types with ordinary and password handshakes, including accepted
and rejected early data. Protocol errors remain distinct from local byte budgets.

CertificateEntry evidence is matched by the exact original certificate DER when
the PKIX validator reorders intermediates or adds a local trust anchor. A staple
cannot shift to a different certificate because its position in the validated
path changed. Full, resumed, early-data and cached/compressed handshakes exercise
this binding, including misplaced, revoked and incorrectly signed evidence.
Unused extra certificates without evidence remain subject to ordinary path
building; supplied evidence is never silently moved or discarded.

TLS response extensions are checked against the actual handshake offer before
credential policy evaluation, including initial and post-handshake client
authentication and cached/compressed Certificate messages. Unsolicited
CertificateEntry extensions normally produce `unsupported_extension`; RFC 9345
specifically requires `unexpected_message` for unsolicited delegation. Malformed fixed
width control fields and OCSP/SCT vectors produce `decode_error`, while validly
encoded unsupported scalar values remain `illegal_parameter`. Optional CT policy
may ignore an unknown SCT version, but cannot turn an empty or truncated SCT list
into a valid extension. Shared envelope checks also reject malformed evidence in
exported authenticators at the application layer: only that request context is
consumed, its private verifier reference is released, and TLS traffic and other
requests remain usable. CT v2 permits an empty `transparency_info` response body
(RFC 9162 section 6.5), not a present but empty/truncated `TransItemList` vector.
The empty response supplies no log vote or mandatory TLS Feature evidence; its
exception does not extend to embedded certificate or OCSP list carriers.

### Early-exporter lineage and extension syntax

Early exporters and their diagnostic labels remain associated with the first
PSK in the original ClientHello. Removing an incompatible PSK after a retry
must not promote a different PSK into that early-key lineage merely because it
now occupies index zero. Regressions exercise ordinary external PSKs and
password-session successor tickets, including hash changes, valid 1-RTT
continuation and capability cleanup. This implementation revokes early-exporter
capabilities on HelloRetryRequest, consistently in both roles and password
sessions; this is its API availability policy, not a claim that the RFC forbids
every early-exporter use after a retry. Without a retry, availability does not
require a nonempty early payload or successful 0-RTT admission.

Malformed ALPN protocol-name lengths, OID-filter vectors and OCSP request DER
produce `decode_error` (50). Repeated OID filters and well-formed forbidden
selection values retain `illegal_parameter` (47). These parsing checks do not
replace certificate, grant, responder-trust or application-authorization checks;
the shared DER helpers retain their existing defaults for other consumers.

CachedCertificate and CachedCertificateRequest references follow the same
syntax/semantic distinction: truncated contexts, hashes, shares or metadata
vectors and trailing bytes produce `decode_error`; well-framed unknown hashes,
wrong contexts and metadata-count mismatches produce `illegal_parameter`.
Wire regressions cover plain and compressed certificates and initial and
post-handshake requests. Local reconstruction budgets remain independent of
peer syntax validation.

Early-exporter test teardown waits for the peer handler to consume close_notify
before explicitly destroying its record keys. An event-gated regression checks
that ordering without sleeps; selector and proactor event loops need not
schedule peer shutdown identically.
The transport backpressure fixture likewise waits for actual blocked output
from a non-reading loopback peer within a bounded write budget, rather than
assuming a fixed number of bytes fills every operating system's TCP buffers.
It checks that shutdown really invokes transport abort and leaves no buffered
output behind.

Password retries may carry only a salt after a proactive ClientHello with one
password key share: the group remains unchanged and the commitment is recomputed.
Empty or mixed initial offers still require an explicit group selection. The
browser uses that latter mode; both paths distinguish malformed salt vectors from
well-formed salts of an invalid length.

### Authenticator teardown and DANE/OCSP policy: 2026-10-12

Regressions cover immediate capability/connection cleanup during stalled or
cancellation-resistant authorization, independent DANE path/grant signature
offers, DANE with explicitly enabled delegation, and OCSP responder key rollover
with the same subject name. Negative controls retain mandatory trust, identity,
signature, authorization, freshness and request-context checks.

Windows native-provider suites on Python 3.11 and 3.12 each ran 743 tests:
741 passed and two platform-specific checks were skipped. The minimal Python
3.12 run completed the same suite with 92 explicit provider/platform skips.
All 24 ordinary Phromium interoperability commands and 19 optional-provider
commands passed against this worktree. Source/wheel packaging and isolated
installation/CLI checks also passed. Logs are under `build/audit-fixes-*` and
the browser's `out/*/audit-fixes-*`. This is local Windows evidence, not a
remote Linux/macOS CI result or a guarantee of physical memory erasure.

### Zstandard multi-frame certificate validation: 2026-10-12

Certificate decompression accepts the RFC 8478 concatenation of Zstandard
frames, including all skippable-frame magic values and unknown content sizes.
An envelope check rejects truncated frames before bounded streaming decoding;
the provider still verifies compressed contents, dictionary requirements and
checksums. Output is bounded during decoding to the declared length plus one
overflow byte, and every frame's window remains within the local memory budget.
Neither concatenation nor metadata permits trailing junk or extra output.

Regressions cover known/unknown sizes, empty, raw and RLE frames, every truncated
boundary, invalid checksums, reserved blocks, declared-size and window limits.
Real initial and post-handshake client authentication verifies transcript/MAC
binding with multi-frame and skippable-frame certificate flights. The former
decoder fails the new valid-frame regressions.

Windows native-provider suites on Python 3.11 and 3.12 each completed 672 tests:
670 passed and two POSIX-only checks were skipped. Independent Phromium tests
also cover full and cached certificate representations, including corrupted
cache references after successful initial authentication. Logs are retained
under `build/zstd-dane-*` and the browser's `out/*/zstd-dane-*`. These local
results are not a claim of completed remote CI or a formal security audit.

### DANE names, post-handshake alerts and deterministic fixtures: 2026-10-12

DANE evidence selection uses the same strict, case-insensitive DNS-name parser
as ClientHello lookup. The original SNI extension bytes remain in transcripts
and retry checks. Authenticated X.509 and raw-key tests cover uppercase and
mixed-case names, retry/compression, wrong names/ports and malformed encodings.

Unsolicited and out-of-order post-handshake messages emit `unexpected_message`.
PHA context errors, malformed framing and invalid Finished values retain their
distinct alerts. Encrypted-wire tests verify both the alert and connection
closure rather than only the raised Python exception.

Early-record and cleanup fixtures identify client writers by role, not callback
ordering. Event-gated tests force the server writer to register last without
sleeps. The regression rejects the old ordering-dependent implementation and
passes 20 repeated runs. A provider-independent test also covers reuse of the
accept helper by fixtures with their own setup.

Final Windows runs on Python 3.11 and 3.12 each completed 666 tests with native
providers: 664 passed and two POSIX-only checks were skipped. Minimal-provider
runs on both versions completed 666 tests with 92 explicit provider/OS skips.
Resource warnings were errors. An initial native run caught a missing default
in the shared ITS fixture; it was corrected before both complete final reruns.
Source/wheel packaging, isolated wheel/CLI checks, module compilation and local
documentation links passed. Logs are under `build/request-conformance-*`.
These local results do not claim remote Linux/macOS CI completion or a formal
security audit.

### Certificate budgets and request/retry alerts: 2026-10-11

Credential loading, wire encoding/decoding, cached material and path validation
now share the 64-presented-certificate budget. The separately configured trust
anchor may extend a verified path to 65 entries; this does not extend the peer's
wire budget. Per-certificate and aggregate byte budgets still apply, including
Certificate contexts and entry extensions. Real chains of 9 and 64 certificates
exercise configuration, initial authentication and post-handshake authentication;
65 presented entries and byte-budget overflows are rejected.

Malformed authority-name vectors and DER, malformed KeyUpdate lengths and
invalid KeyUpdate enum values produce their specified fatal alerts. A second
HelloRetryRequest is rejected as unexpected before processing its new selection,
including unknown suite/group codes, in ordinary and password-authenticated
handshakes. First invalid retries remain illegal-parameter errors. Positive
controls retain valid KeyUpdate, initial retry and certificate requests.

Local Windows validation on Python 3.11 and 3.12 each ran 656 server tests with
optional native providers: 654 passed and two POSIX-specific checks were skipped.
Minimal-provider runs on
Python 3.11 and 3.12 each ran 656 tests with 92 explicit optional-provider/OS
skips. Resource warnings were treated as errors. All 22 portable Phromium
interoperability invocations and 19 optional-provider commands passed, including
25 chain checks with seven actual connections. Documentation, module compilation,
source/wheel builds and isolated wheel installation/CLI checks passed. Evidence
is retained under `build/cert-conformance-*` and the browser's
`out/httpps-native/cert-conformance-*`. These are local validation results,
not a claim of completed remote Linux/macOS CI or a formal security audit.

### Password negotiation and early-record rejection validation: 2026-10-11

Unknown cipher-suite codes (including GREASE) are ignored when classifying a
proactive password offer, while remaining in the authenticated transcript.
Known ordinary/password mixtures and incompatible password hashes still require
an empty first key-share offer. Parser and full native-handshake regressions
exercise valid unknown-code offers and both prohibited mixtures.

Oversized 0-RTT tests now verify the server's sealed `record_overflow` alert,
absence of delivered early data and absence of an established channel. They
exercise both ordinary scheduling and client Finished after server rejection;
a peer-close transport error is not sufficient by itself to pass a test.
Negative controls confirm that wrong alerts, delivered early data and accepted
oversized records fail these assertions.

Local Windows validation completed 639 tests with native providers: 637 passed
and two OS-specific checks were skipped. The minimal environment completed
639 tests: 549 passed and 90 optional-provider/OS checks were skipped.
The 108-test focused run and 32 repeated race/password regressions passed.
All 21 portable Phromium interoperability invocations and 18 optional-provider
commands passed. Compilation, documentation, wheel/source-archive builds and
isolated wheel installation/CLI checks passed. Logs are under
`build/grease-ci-*`, `build/four-fixes-overflow-negative.*` and the browser's
`out/httpps-native/four-fixes-*`. These are local results, not a completed
remote Linux/macOS CI run or a formal security audit.

### Retry and authenticator conformance validation: 2026-10-11

The Windows suite completed 598 tests with all optional native providers
supplied; only two POSIX-specific checks were skipped. The minimal-provider run
also completed 598 tests, with 82 optional-provider/OS skips. Resource warnings
were treated as errors. New regressions cover independent authenticator
path/grant offers, password-successor group/cookie retries and refreshed ages,
same-length/different-hash PSKs, and accepted/rejected early-data alerts.
An adversarial regression confirms that a forged record following an
authenticated advisory alert is rejected, not discarded before a valid Finished.

All 19 portable Phromium interoperability invocations and all 18 provider
commands passed. The actual Windows browser passed 38 end-to-end assertions and
34 profile cases under each of the default and explicitly enabled network-sandbox
policies. Python compilation, documentation checks, source/wheel builds and an
isolated wheel installation/CLI check passed. Logs are retained locally under
`build/retry-conformance-*` and the browser's `out/*/retry-conformance-*`.
These are local Windows results, not a claim that remote Linux/macOS CI or a
formal security audit has completed.

### Conformance and secret-lifecycle validation: 2026-10-11

The final Windows suite ran 586 tests successfully with all optional native
providers supplied; two POSIX-specific checks were skipped. The minimal-provider
run also completed 586 tests, with 76 optional-provider/OS skips. Regressions
cover remembered/provisioned 0-RTT record limits (including PAKE), MFL/RSL
precedence, PSK-only unknown groups, mixed-case SNI through retry/resumption,
authenticator KU/EKU filters, and alert interleaving in both initial and
post-handshake messages. Terminal connection and record-state cleanup is checked
with references retained across teardown, injected key-derivation failures,
cancellation, idempotent cleanup, unavailable exporters and valid half-close.

All 19 portable Phromium interoperability invocations and all 18 optional-provider
commands passed against this worktree, including the pinned-spec oracle. Python
module compilation, documentation links, wheel/source-archive build and an
isolated wheel installation/CLI check passed. Test logs are retained locally under
`build/conformance-fixes-*`; these results do not claim that a future remote CI
run or full-browser Linux/macOS build has passed. The Python memory-erasure
limitations in [SECURITY.md](../SECURITY.md#keys-and-process-memory) still apply.

### Historical local validation: 2026-10-11

The final Windows native-provider suite completed successfully: 534 tests.
The two skips are Windows-specific POSIX-mode and
symlink-privilege checks, not missing cryptographic profiles. Optional OpenSSL,
PAKE, GOST and ITS providers were supplied explicitly; missing native coverage
is an error in the runner. The production wheel and source archive were rebuilt
and the wheel's CLI verified in an isolated environment outside the checkout.
Python 3.11 was also checked separately: 534 tests completed successfully,
with 74 optional-provider/OS skips in that minimal environment. In particular,
the strict IPv6 authority regression that failed the earlier CI is covered.

A repeated run exposed a native thread-lifetime defect before these results:
executor threads retained OpenSSL resources after their private context was
freed. Reentrant native scopes now detach resources on the executing thread,
before context destruction. Regression tests retain workers across context
creation/destruction, exercise failure paths and check cleanup ordering; a
negative control with the former scope fails the new assertions. This was a
wrapper lifetime correction, not a change to the protocol or cryptographic
primitive. The corresponding Phromium wrapper was corrected independently.

CI also builds and tests on Linux and macOS. These local Windows results do not
claim that the new revision's remote CI has already run, nor a formal audit.
