# Protocol implementation and compatibility

The target wire profile is TLS 2.0 **draft-01**, pinned to specification commit
[`babaa838a45713764031becae3420f489f8ffca8`](https://github.com/PapauloGamerOfc/tls20-spec/tree/babaa838a45713764031becae3420f489f8ffca8).
The application identifier is the exact byte string `http/1.1`. It describes
the inner HTTP stream; it does not imply standard TLS or registered HTTPPS ALPN.

Client URLs use `httpps://hostname[:port]/path`. The test client defaults to TCP
1021, makes one GET with `Connection: close`, and prints raw response bytes. It
does not render pages, follow redirects, manage cookies, parse response framing,
or install a browser protocol handler. A trusted local `--connect-host` override
changes routing only; identity validation always uses the URL's DNS hostname.
Names use a conservative ASCII/IDNA2003-compatible subset, not every IDNA2008 name.

## Connection flow

1. The dedicated listener checks the exact experimental preface and parses a
   bounded ClientHello. Standard TLS and plaintext HTTP are rejected.
2. The two independent client shares authenticate against the certified static
   key and agree traffic with a freshly generated server ephemeral key.
3. The server encrypts its extensions, real certificate chain, MAC proof and
   Finished. The client validates its locally trusted path, expected identity,
   proof and Finished before sending its own Finished.
4. Only after the server verifies that Finished does it connect to the fixed
   local HTTP backend. Application records use independent directional keys.
5. A bounded duplex relay forwards authenticated bytes. Authentication failure,
   timeout or a quota violation aborts the channel without retry or downgrade.

Server authentication does not identify or authorize the client. A compatible
client that can complete the handshake may use the backend; application access
control remains the backend's responsibility.

## Modules

| Module | Responsibility |
| --- | --- |
| `crypto.py` | Provider-backed key agreement, KDF, MAC and AEAD records |
| `messages.py` | Strict message-body encoding, decoding and DNS syntax |
| `pki.py` | Exact credential parsing and restricted explicit-trust lab validation |
| `handshake.py` | Stream reassembly, transcript, ordered state and authenticated channel |
| `config.py` | Bounded configuration parsing and local endpoint policy |
| `server.py` | Admission, lifetime management and local duplex forwarding |
| `client.py` | HTTPPS URL handling and one-response terminal client |
| `lab.py` | Fresh local CA and server credential generation |

## Closure and limits

Unexpected TCP EOF is not an authenticated close. A valid encrypted close_notify
is distinguished from truncation; a cancelled partial record is never resumed.
The proxy closes both relay directions after authenticated client closure.
Backend EOF results in an encrypted close_notify, but does not prove HTTP-level
response completeness. HTTP clients still need Content-Length/chunk framing and
their application semantics to detect a truncated response. The test client is
a raw diagnostic client, not a fully validating HTTP implementation.

Each record carries at most 16 KiB of content. Each directional epoch permits at
most 2^20 records and 2^30 content bytes; configured application limits can be
lower. Handshake message, transcript and record-count bounds follow draft-01.
The handshake timeout is absolute and does not restart on partial bytes.
An expired deadline is rechecked after synchronous local certificate processing.

The server uses bounded asyncio streams and drain-based backpressure. It caps
accepted tasks before doing handshake work, cancels both relay pumps on shutdown,
and closes admitted sockets even if their task never began execution. It does
not claim to resist volumetric network denial of service or provide a per-IP
rate limiter. Certificate checks and cryptographic work run in the Python event
loop; high-load performance is not established.

## Test scope

Known-answer and deterministic cross-repository vectors validate the primitive
and transcript calculations. Negative tests cover malformed lengths, shares,
certificates, identity, MACs, replay, quotas and timeouts. Loopback integration
tests create real certificates, exchange protected application records and fetch
HTTP through the proxy, including concurrent sessions and shutdown behavior.

These tests do not establish independent implementation interoperability,
formal cryptographic security, guaranteed memory erasure or complete public-PKI
conformance. There is no browser integration or compatibility with HTTPS clients.
