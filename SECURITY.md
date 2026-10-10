# Security and limitations

This repository is an alpha research implementation of an independent protocol.
Do not use it to protect production credentials, personal data or valuable
services. It is neither an official TLS successor nor a formally verified secure
channel. The `httpps` scheme and experimental TCP default are not registrations.

## Trust boundary

The client must be configured with a trusted CA independently of the server and
must know the expected DNS identity. Certificate path, hostname, server proof and
Finished checks all have to pass before application data is sent. Receiving a
certificate or successfully decrypting a record alone does not establish trust.
There is no skip-verification switch and no fallback after authentication failure.

The server key is a static X25519 agreement key, not a public symmetric key.
The MAC key derived per handshake is symmetric. This allows an honest client to
authenticate relative to its private state while allowing that client to simulate
the proof offline. It does not promise non-transferability against a cooperating
online witness or prevent separately signed application receipts.

Client Finished is key confirmation, not client identity. This proxy adds no
login, client-certificate authorization or HTTP authentication. Its plaintext
backend is restricted to loopback but remains trusted. Local administrators,
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
claim complete conformance to every draft-01 implementation requirement.

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

## Reporting

Report reproducible issues through the repository's security advisories if
private reporting is available, or an issue containing only non-sensitive
reproduction details. Never attach real private keys, production traffic or
unredacted process dumps. No response-time commitment is implied.
