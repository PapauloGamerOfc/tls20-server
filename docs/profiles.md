# Configurable authentication and cryptographic profiles

The server and diagnostic client can load an explicit, role/service/port-bound
UTF-8 TOML profile (maximum 64 KiB). This selects implemented protocol paths;
it does not load arbitrary Python callbacks or authorize peer-provided roots.
Every relative path is relative to this profile file. Unknown fields and
inapplicable combinations fail before a listener or client connection opens.

In `server.toml`, add `profile_file = "server-profile.toml"`. The profile's
credential replaces the simple `certificate_chain`/`private_key` settings;
explicit profile negotiation settings override their simple server equivalents.
The listener, fixed loopback backend, connection quotas and early HTTP gate
remain in `server.toml`. Its `server_name`, listening port and the profile's
service/port must agree. The backend determines ALPN, never a misleading profile
override. Configure `upstream_protocol = "h2"` only for an HTTP/2 backend.

```sh
python -m tls20_server check-config --config server.toml
python -m tls20_server serve --config server.toml
python -m tls20_server get httpps://example.test/ --profile client-profile.toml --repeat 2
```

`--profile` replaces `--ca` and `--revocation-policy`; trust is specified in the
profile. `--connect-host` changes TCP routing, not the bound service. The GET
client uses HTTP/1.1. Neither profile nor diagnostic client persists tickets or
continuity pins to disk. Keep the loaded profile instance to retain its pin
cache between calls to the Python API. Restarting deliberately loses that cache.

## Certificate and RPK profiles

Server:

```toml
role = "server"
service = "example.test"
port = 343
mode = "certificate"

[negotiation]
cipher_suites = [0x1301, 0x1302, 0x1303, 0x1304, 0x1305]
supported_groups = [29, 23, 24, 25, 4588]
certificate_compression = [1, 2, 3]

[credential]
chain = "fullchain.pem"
private_key = "server.key"
```

Client:

```toml
role = "client"
service = "example.test"
port = 343
mode = "certificate"

[negotiation]
cipher_suites = [0x1301, 0x1302, 0x1303]
traffic_group = 29
certificate_compression = [1, 2, 3]
record_size_limit = 16385

[trust]
roots = "independently-provisioned-ca.pem"
revocation_policy = "offline"
```

`offline` deliberately does not establish current revocation status. To require
current evidence, use the policy below. No OS CA store or network fetch is
silently enabled. The endpoint's static MAC key is always X25519, independently
of traffic groups or certificate/grant issuer signature algorithms.

If the transmitted `chain` omits its final issuer, optional
`signature_issuers = "local-issuers.pem"` under `[credential]` supplies local
issuer metadata for exact signature-scheme selection (including GOST and
RSA-PSS/Brainpool). Its actual issuing signature is checked. These certificates
are not transmitted, installed as peer trust anchors, or used to widen trust.

An RPK server replaces `chain` with `raw_public_key = "server-spki.der"` (the
canonical 44-byte X25519 SPKI). The client replaces roots with
`raw_public_keys = ["independently-provisioned-server-spki.der"]` and sets
`server_certificate_types = [2]` under `[trust]`. Parsing an RPK is not trust;
the client checks the exact pre-provisioned key for the configured identity.
X.509-only OCSP/CT or required-delegation policies cannot be combined with an
RPK/ITS offer: the profile rejects that combination instead of ignoring the
requirement on the alternate credential path.

For an offline delegated credential, keep the signing parent's chain, set
`delegation = "grant.bin"` and use the delegated X25519 `private_key`. The
client explicitly sets `delegated_credentials = true`; optional
`require_delegation = true` disallows an ordinary leaf. Issuer signatures,
grant signatures, role, validity and proof-key correspondence are independently
checked. `[[credential_candidates]]` accepts additional complete credential
tables; selection follows negotiated representation and certificate filters.

## Negotiation controls

All fields below belong to `[negotiation]`. Numeric IDs are the actual wire IDs,
not named aliases. Unsupported combinations fail; they are not silently ignored.

| Field | Applicability |
| --- | --- |
| `cipher_suites` | Nonempty, distinct supported IDs; default `[0x1301]`, or `[0xc0b0]` in password mode |
| `supported_groups` | Allowed ordinary traffic groups on either endpoint; optional subset, not authentication-key choice |
| `traffic_group` | Client's initial ordinary group; default 29; must belong to its allowed subset |
| `groups` | Password endpoint's supported commitment groups; 23/24/25 or 256..260 |
| `psk_modes` | Ordinary PSK modes `[1]`, `[0]` or `[1,0]`; combined mode still requires fresh agreement |
| `record_size_limit` | 64..16385, negotiated directionally |
| `max_fragment_length` | Client enum 1..4; RSL takes precedence when both are offered |
| `certificate_compression` | Ordered codec IDs 1=zlib, 2=Brotli, 3=Zstandard; `[]` disables; client profile defaults to all three |
| `heartbeat_mode` | 1 allows peer probes, 2 denies them; omission disables; no periodic background timer |
| `ticket_request` | Client `[fresh_count, resumed_count]`, each 0..255 |
| `ticket_count_limit` | Server issuance budget, 0..255 |
| `enable_authenticators` | Retain required roots/shares for the application-authenticator API |
| `post_handshake_auth` | Client PHA capability; application framing and server requests remain explicit API operations |

Integrity-only suites are deliberately not offered by this HTTPPS relay. They
remain available through the explicitly non-confidential library API. An
ordinary web relay must not describe plaintext authenticated records as HTTPS-
style encryption. PHA is prohibited with `h2`; application authenticators can
be framed separately by an application over an authenticated HTTP/2 stream.

Client `[cache]` optionally contains `[[cache.certificates]]` tables with
`type = 0` (X.509) or `2` (RPK), and `files = ["leaf.der", "issuer.der"]`.
`request_templates = ["request-extension-block.bin"]` supplies explicit cached
CertificateRequest templates. References save transmission, not validation:
the peer's current proof, metadata, expiry and trust policy are still checked.
These are public exact DER/wire snapshots, never serialized session secrets.

`server_certificate_authorities = ["distinguished-name.der"]` is a client
top-level preference. Server `[client_auth]` can provide
`certificate_authorities` similarly and `oid_filters = [{oid="2.5.29.15",
value_hex="..."}]`, using the DER extension value. Authorities are preferences;
recognized key-usage/EKU filters are enforced constraints.

## Explicit native providers and national suites

```toml
[provider]
library = "/absolute/path/to/libcrypto.so.3"
# Only when GOST is selected:
gost_module = "/absolute/path/to/gostprov.so"
```

Paths may also be relative to the trusted profile. They resolve to explicit
absolute paths before loading. There is no PATH search, automatic download or
global engine registration. Use mutually compatible, independently built
artifacts from the repository's pinned provider-build tooling. Loading a native
library executes its code: protect the configuration and binaries as executable
security policy, not untrusted site data.

The optional OpenSSL provider enables `0x00c6`/`0x00c7` (SM4-GCM/CCM, SM3),
curveSM2 group 41 and SM2 certificate/grant verification with their distinct
required identifiers. The explicit GOST module enables suites `0xc103` through
`0xc106`, groups 34..40 and supported GOST certificate/grant signatures. GOST
records use the required per-record TLSTREE/MGM processing, not reusable raw MGM.
X448 and Brainpool are available through the ordinary Python cryptography
provider; they do not require an unrelated extra DLL in this implementation.

## External/imported PSK

Set `mode = "psk"` and configure matching explicitly provisioned identities on
both endpoints:

```toml
[[psks]]
identity_hex = "6465766963652d6964656e74697479"
key_file = "secret-psk.bin"
hash = "sha256"
suite = 0x1301
combined = false
# Optional RFC9258 importer (base key must be dedicated to this purpose):
# import_context_hex = "6465706c6f796d656e742d616e642d726f6c6573"
# base_hash = "sha256"
```

The key file contains at least 16 raw secret bytes, not hexadecimal text. Every
identity is service/ALPN/hash-bound. Imported keys support registered SHA256/
SHA384 KDF identifiers; a same-length hash is not a compatible substitute.
`combined = true` additionally requires the independently trusted certificate
flow and fresh agreement. Do not reuse an importer base as a direct PSK.
Pure PSK mode rejects certificate trust and client-auth policy tables that it
would not enforce; choose combined mode when both authorizations are required.
The CLI does not authorize external-PSK early data without a distributed replay
backend. It can use 0-RTT on its own subsequent listener-local resumption tickets,
subject to the ordinary explicit HTTP route gate.

## Native password authentication (PAKE)

Set `mode = "pake"`, configure the explicit OpenSSL `library`, and add
`pake_helper = "/absolute/path/to/tls20-pake.dll"` under `[provider]`. This must
be the production helper, never the test-oracle build. Password mode uses actual
RFC8492-derived native commitments; it is not a password disguised as a PSK.
It never falls back to a certificate or a different authentication mode.

Create exact UTF-8 username/password files in a private directory, with no
unintended trailing newline. The RFC8265 OpaqueString profile is applied. Do not
pass passwords on the command line. Generate a new salted server record:

```sh
python -m tls20_server password-record --username-file username.txt --password-file password.txt --output account.toml
```

The command refuses to overwrite an existing file. It writes `[[accounts]]`
records containing `username_hex`, `base_hex`, and `salt_hex`; the base is
password-equivalent sensitive material. A trusted operator can assemble multiple
records in one database; all accounts on an endpoint must use the same salting
policy to avoid an account-existence signal.

Server `[password]` uses `accounts_file = "account.toml"`. Optional integer
resource controls are `max_attempts` (5), `window` seconds (60),
`global_attempts` (100), `capacity` (4096 identity counters), and `max_active` (4).
They count attempts rather than waiting for a password failure. Unknown accounts
perform native work with a secret fake record; no successful Finished is issued.
Client `[password]` uses `username_file` and `password_file`.

For protected usernames, both `[password]` tables add `protection_key`: the
server's P-256/P-384/P-521 private PEM key versus the client's independently
provisioned public PEM key. It is not learned from an unauthenticated server.

Fresh PWD suites are `0xc0b0`..`0xc0b3`. EC groups use V8 scalars; FFC256..260
use full-entropy V16 scalars as clarified in the TLS 2.0 specification. Large
FFC groups can take seconds without assembly acceleration; configure a realistic
absolute handshake deadline. Native work is off the event loop. Cancellation
retains its admission slot until the native call safely finishes and cleans up.
Subsequent authorized tickets use ordinary matching AEAD suites and can resume
with actual early data. Fresh password authentication never accepts 0-RTT.

A client may explicitly select `mode = "mixed"`, configure both `[password]`
and its independent `[trust]` policy, and offer ordinary and PWD cipher suites
(default `[0x1301, 0xc0b0]`). It sends one empty key-share offer; the server's
HelloRetryRequest selects the ordinary or password exchange on that connection.
`supported_groups` must include a password commitment group, such as 23. The
server still selects an explicit `certificate` or `pake` endpoint policy.
This authorizes alternatives before authentication, not a fallback after a bad
certificate, bad password, MAC failure or Finished failure. External PSK,
bootstrap and pinning are separate profile choices. Successor tickets retain
which authentication policy established them, and cache partitioning includes
both the password identity and the independent credential trust policy.

`enable_authenticators = true` is also available on password profiles. The
application API can then establish additional certificate-based identities after
the password handshake, without replacing the password identity. Requested and
spontaneous server authenticators are opt-in; no HTTP header or credential UI is
invented. Fresh PWD still does not send a CertificateRequest or TLS PHA.

## Current evidence, DANE and client authorization

`[[credential.evidence]]` specifies `index` (zero-based chain entry), `type`
(5=OCSP, 18=CTv1, 52=CTv2, 59=DNSSEC) and `file` containing the exact extension
body. An OCSP file includes its TLS status type/length wrapper, not bare DER.
DNSSEC uses the RFC9102 wrapper and additionally requires `dnssec_port` under
`[credential]`; it is sent only for the matching SNI/logical port. Files are
bounded; no remote evidence location is fetched or trusted.

Client `[trust.evidence]` accepts `require_ocsp`, `ocsp_max_age_seconds`,
`minimum_ct_v1_logs`, `minimum_ct_v2_logs` and `require_ct_v2_inclusion`.
Optional `ocsp_request = "status-request.bin"` supplies the complete extension5
body: status type, responder-ID vector and DER request-extension vector.
Responder preferences and a requested nonce must match the actual response;
malformed requests fail and unsupported critical request requirements do not
count as fulfilled. A server omits a configured staple that cannot satisfy the
request, and a client requiring it aborts. A fresh per-attempt nonce requires
the programmatic API or regenerated file and matching responder evidence;
new nonce generators should use at least 32 CSPRNG bytes. Reusing a static file
does not establish per-connection nonce freshness. The parser accepts the
1..128-byte compatibility range; the relay does not fetch untrusted responder
URLs automatically. TLS Feature
processing also verifies the issuer-to-child feature-set constraints, not only
the leaf's must-staple bit.
`revocation_policy = "require-evidence"` also requires a positive OCSP/CT policy,
not a callback that merely returns true. Configure `[[trust.evidence.logs]]`
with `version` (1/2), `id_hex`, `public_key` PEM, `signature_scheme`, `hash`,
`valid_from_ms`, `valid_until_ms`, and `maximum_merge_delay_seconds`. V1 log IDs
must equal SHA256(SPKI). `[[trust.evidence.tree_heads]]` can retain independently
trusted CTv2 `log_id_hex`, `size`, `timestamp_ms`, and `root_hex` for consistency
checking. Signed SCT promises alone are not inclusion proofs.

`[trust.dane]` requires `anchors_file`: a DNS zone-format inventory containing
only explicitly trusted DNSKEY or DS RRsets, one kind per owner. The profile's
port identifies the logical TLSA service. DNSSEC signatures, delegation, denial,
names, ports and TLSA binding are validated. `allow_authenticated_denial = true`
permits only authenticated absence to continue to separately configured trust;
bogus data never downgrades. Usage0/1 require the separate PKIX roots; usage2
validates a DNS-authorized trust-anchor path; usage3 authenticates the exact
endpoint. The original evidence deadline is retained in session caches.

Server `[client_auth]` supports `required = true` (default), `identity`,
`roots`, and `allowed_certificates_sha256` (exact SHA256 DER-leaf fingerprints).
CA membership alone is not application authorization. Alternatively provision
`raw_public_keys`, with `certificate_types = [2]`. `require_delegation` can
require a verified client grant. The client supplies its own `[credential]`.
The HTTP relay gates access to its one backend; it does not insert a claimed
identity HTTP header or invent per-route authorization from certificate fields.

## POK, pinning and ITS

`mode = "pok"` uses `[bootstrap]` with `public_key` (BSK SPKI), `scope`, optional
ISO8601 `expires_at` with time zone, and `target_hashes` (`sha256`/`sha384`). Only
the client also supplies its `private_key`. Its optional `target_hash` selects
one provisioned hash compatible with its offered suite. The HTTPPS profile always uses
`credential-validated` trust; a public-derived bootstrap PSK is not identity
proof. Exact BSK possession through client MAC and Finished is mandatory.
The separate programmatic provisioning-trust API is not a web trust bypass.

Server `[pinning]` uses `current_id_hex` (16-byte ID), `lifetime_seconds`,
`ramp_down`, and `[[pinning.keys]]` entries with `id_hex` and a `key_file` of
32 raw secret bytes. Preserve old protection keys throughout their promised
lifetimes when rotating. Client `[pinning]` accepts `capacity` and holds pins
in memory during that loaded profile's lifetime. Missing/bad proofs do not erase
an existing pin. Pinning forces fresh credential mode, not PSK or early data.
The GET client rejects `--early-data` with a pinning profile before connecting.

ITS type3 is an explicitly provisioned application profile, not ordinary WebPKI.
Local credentials use `its_grant`, `private_key`, and `[credential.its]`;
client validation uses `[trust.its]`, and server-side client validation uses
`[client_auth.its]`. Each policy requires its native `library`, `psid`,
`application_scope_hex`, `ssp_coer_hex`, `roots` (COER files),
`authorized_leaf_sha256`, `revoked_sha256`, `inventory_valid_until` (IEEE Time64),
`max_grant_lifetime_microseconds`, and a trusted `tai_utc_offset`.
`allowed_regions` contains COER files for authenticated service footprints.
Optional `geographic_containment` is an array of `{parent="parent.coer",
child="child.coer"}` tables referencing canonical COER region files, resolved
relative to the profile. Each exact, directional pair must be provisioned by
the application's trusted geography authority and asserts valid geometry plus
containment of the child in the parent. It must never be constructed from a
peer's unsupported region or obtained by trust on first use. Native WGS84
circle, rectangle-union and administrative-hierarchy checks cannot be
overridden when they reject containment. General geodesic polygon/cross-kind
containment requires these local statements; it is not inferred from a planar
approximation. Polygon equality also needs its exact `(region, region)` validity
statement. The complete policy, including statement direction, binds resumption
tickets and its lifetime is capped by the inventory expiry. The trusted inventory and
clock offset must be maintained externally; the implementation does not pretend
to fetch/verify arbitrary ITS CRLs. Signature/path/permission/grant validation
and the normal online MAC/Finished are all required. A parser alone is not
authorization. Use only a provider build whose implemented ITS profile matches
the separately provisioned credentials and application policy.

Optional `[signaling]` specifies independently authenticated `local_hash_hex`,
`peer_hash_hex`, `local_session_id`, and `peer_session_id`. Missing/mismatched
bindings fail. Supplying a peer's unverified claim as the expected value defeats
the purpose; this table is not a signaling authentication implementation.

## Secret and policy handling

PSKs, password inputs/verifiers, private keys and pin protection keys use bounded
regular-file reads. POSIX requires no group/other permission bits. On Windows,
use a user/service-private directory and restrict inherited ACLs. Keep native
binaries and public trust/evidence inventories protected against modification as
well. No secret is printed by profile validation or password-record generation.
Python immutable secret bytes are not guaranteed to be physically erased.
Private PEM keys must contain exactly one unencrypted PKCS8 object, with no
ignored trailing keys. Local certificate bundles must be in issuer order.
Restart the endpoint deliberately after replacing policy or credentials; no hot
reload races or automatic credential renewal are implied.
