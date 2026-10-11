# Security and limitations

This repository is an alpha research implementation of an independent protocol.
Do not use it to protect production credentials, personal data or valuable
services. It is neither an official TLS successor nor a formally verified secure
channel. The `httpps` scheme and experimental TCP default are not registrations.

## Trust boundary

The client must be configured with a trusted CA independently of the server and
must know the expected DNS identity. Certificate path, hostname, server proof and
Finished checks all have to pass for a new full-handshake identity. Explicit
0-RTT instead uses a ticket from a previously authenticated connection and
revalidates its retained certificate under the current client policy. Receiving a
certificate or successfully decrypting a record alone does not establish trust.
There is no skip-verification switch and no fallback after authentication failure.

The server key is a static X25519 agreement key, not a public symmetric key.
The MAC key derived per handshake is symmetric. This allows an honest client to
authenticate relative to its private state while allowing that client to simulate
the proof offline. It does not promise non-transferability against a cooperating
online witness or prevent separately signed application receipts.

Client Finished alone is key confirmation, not client identity. The forwarding
CLI adds no login, client-certificate authorization or HTTP authentication. An
optional low-level API supports initial/PHA client MAC authentication, but only
with an application-supplied validator for client trust, identity, authorization,
validity, key usage and revocation. Extracting a public key is not validation.
The API reports identity only after both the client MAC and Finished verify;
the application must still decide which operations that identity may perform.
The plaintext backend is restricted to loopback but remains trusted. Local administrators,
malware, debuggers and a compromised backend can observe application plaintext.

## Restricted certificate policy

The client validates an explicitly ordered path to an explicit local trust root,
not an arbitrary public Web PKI graph. Supported signatures are Ed25519 and
P-256/SHA-256. RSA is not implemented. Unknown critical extensions fail closed;
name constraints and certificate-policy extensions are rejected rather than
partially processed, even when noncritical. This deliberately rejects some
otherwise valid certificates instead of silently ignoring restrictions.

The only revocation policy implemented is the explicit `lab-offline` policy.
It performs no CRL or OCSP checking, so a revoked-but-unexpired lab certificate
can still be accepted. It fetches no certificate-supplied URL. This is suitable
only for controlled short-lived experiments with an agreed out-of-band trust
replacement process, not a deployment requiring fresh revocation status.

This restricted policy and Python secret handling mean the project does not
claim complete implementation of every core or optional TLS 2.0 facility.

## Early data and session state

Early data is replayable and not forward-secret against compromise of its PSK.
Only explicitly audited bodyless GET/HEAD routes may reach an early-data-aware
backend before Client Finished; the proxy inserts `Early-Data: 1`. Ordinary
traffic and non-allowlisted routes do not acquire early authorization simply
because the client offers it. Atomic early-use admission is local to one shared
listener store, not a promise of global exactly-once HTTP execution. A backend
can still return HTTP 425 when it cannot safely process a request early.

Ticket/replay state is never serialized by this implementation. Restarting loses
both and rejects old early data. Multi-process/shared-ticket deployments require
a shared atomic replay service, or must leave early data disabled. Client caches
are scoped to origin, trust policy and the configured client credential or
anonymous identity; ticket-bearing connections revalidate saved certificates.
Server-side client authorization is rechecked after a valid binder and before
early-use admission. New client authentication cannot retroactively authorize
early data. Completing PHA does not promote a previously issued anonymous ticket
to the newly authenticated identity. Cache eviction must never recreate early-use
permission.

Ticket retention has both an entry limit and a default 16 MiB accounted-byte
budget, including cached client chains and per-object allowances. This bounds
cache retention, not total process memory. An oversized ticket is omitted without
rejecting the established connection. Applications embedding the API can choose
another `TicketStore(max_bytes=...)` resource budget.

PHA requires a prior client offer, unique request contexts and fresh independent
verifier keys. Pending authentication state is bounded and consumed on completion,
closure or cancellation. A cancelled receive stream cannot be reused to resume
partially processed authentication. The application must keep reading to complete
PHA and enforce its own idle/lifetime deadlines; no certificate prompt or
authorization UI is supplied by this API.

## Keys and process memory

Cryptographic keys and randoms are generated with the cryptography provider and
the OS random source, not Python's `random` module. Public deterministic test
vectors are explicitly test-only. The lab CA private key is never written to
disk. Server private keys are unencrypted PKCS#8 files protected by host access
controls; Windows ACLs are inherited and must be appropriate for the destination.

The Python runtime and cryptographic provider may retain copies of immutable
secret bytes. This implementation **does not guarantee secure erasure**, locked
memory, exclusion from swap/crash dumps, or whole-program side-channel resistance.
References becoming unreachable is not physical erasure. No connection secret
or application plaintext is intentionally logged. Do not enable a debugger or
collect process dumps if their exposure would be unacceptable.

## Resource limits and operational precautions

Keep the listener on loopback for initial tests. Never serve the repository or
credential directory using the backend's file server. Bind the backend only to
loopback and verify that it is not an open forward proxy. The frontend forwards
HTTP bytes unchanged and does not sanitize request headers for a backend that
is unsafe when directly exposed.

Connection admission, absolute deadlines, record bounds, traffic quotas and
backpressure reduce resource misuse but do not establish denial-of-service
resistance. The client/server share much of the same code, so matching results
do not replace independent interoperability testing. Test coverage is finite;
formal analysis, systematic fuzzing and independent assessment remain future work.

The implemented cipher profile is AES-128-GCM/SHA-256. Raw public keys, delegated
credentials, external PSKs, certificate compression, exported authenticators,
PAKE/POK and other optional profiles are not implemented or advertised. Initial
and PHA client MAC support does not imply support for those separate features.

## Reporting

Report reproducible issues through the repository's security advisories if
private reporting is available, or an issue containing only non-sensitive
reproduction details. Never attach real private keys, production traffic or
unredacted process dumps. No response-time commitment is implied.
