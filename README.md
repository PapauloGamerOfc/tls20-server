# TLS 2.0 Server

An experimental HTTPPS termination proxy and test client for the independent
[TLS 2.0 specification](https://github.com/PapauloGamerOfc/tls20-spec/blob/dee31da9826e10bd590f58acc0f9f46143505fd1/SPECIFICATION.md).
The server loads an X25519 leaf certificate chain and its matching private key,
authenticates a new encrypted channel, and relays its HTTP bytes to a configured
local HTTP server. It does not redirect the client to an unencrypted URL.

**Alpha research software, not for production.** This is not an IETF TLS version
or an implementation of standard TLS 1.3. Ordinary browsers, Caddy TLS listeners,
OpenSSL clients and ordinary curl do not speak this wire protocol. The included
client uses the experimental `httpps://` scheme; there is no automatic downgrade
to HTTPS or HTTP.

## What is included

- Server authentication using a certified static X25519 key and a per-client MAC.
- Independent traffic keys, negotiated SHA-256/SHA-384 schedules and all five
  baseline AES-GCM, ChaCha20-Poly1305 and AES-CCM/CCM8 suites.
- A configurable TCP listener and a fixed, loopback-only HTTP backend.
- Real X.509 laboratory certificates, explicit client trust and hostname checks.
- Connection, handshake, idle, lifetime and traffic limits; bounded buffering.
- A terminal test client, local credential generator and loopback integration tests.
- In-memory session tickets, resumed handshakes, exporters and traffic-key updates.
- Opt-in 0-RTT HTTP processing with atomic replay admission and explicit replay-safe routes.
- Optional initial/PHA client MAC authentication with explicit trust and application
  authorization; initial authentication is configurable, dynamic PHA uses the API.
- HTTP/2 relay to a prior-knowledge HTTP/2 backend, with connection multiplexing.
- Configurable profiles for raw keys, delegated credentials, external/imported
  PSKs, native PAKE, explicit mixed credential/PWD selection, certificate
  compression/cache, evidence and POK bootstrap.
- Opt-in application authenticators above ordinary or password-established
  channels, without replacing the original connection identity.
- Explicit optional providers for SM2/SM3/SM4, GOST/TLSTREE/MGM and provisioned
  ITS-X25519 grants; no native library is automatically discovered or trusted.
- Negotiated record limits, heartbeat, ticket requests and external signaling
  bindings, with loopback tests of real records rather than parsers alone.

The library has an explicit-root OpenSSL PKIX policy and optional current OCSP,
CT and DNSSEC/DANE evidence validation. The simple diagnostic CLI requires a
deliberate `offline` or restricted `lab-offline` choice; neither checks current
revocation. `get --profile` can instead require independently configured current
evidence. No path imports peer-supplied trust roots.
An available API is not automatic certificate enrollment or a browser identity UI.
Python cannot guarantee secret erasure. See
[security and limitations](SECURITY.md) before running an experiment.

## Install

Requires Python 3.11 or newer on Windows, Linux or macOS. From this repository:

```sh
python -m venv .venv
```

Activate it with `.venv\Scripts\Activate.ps1` in PowerShell, or
`source .venv/bin/activate` on Linux/macOS. If PowerShell policy disallows
activation, invoke `.venv\Scripts\python.exe` directly in the commands below.

```sh
python -m pip install .
python -m tls20_server --help
```

Installation downloads the declared dependencies. No server starts, CA is
installed, firewall is changed, or certificate is generated during installation.

## Run a local experiment

Generate fresh credentials in a new directory. This refuses to overwrite an
existing directory and never saves the CA's private key:

```sh
python -m tls20_server lab-init --directory lab --name localhost
python -m tls20_server check-config --config lab/server.toml
```

Start your existing HTTP application on `127.0.0.1:8080`. For a temporary test,
run Python's simple HTTP server in a separate terminal **from a directory
containing only files you intend to serve**, not this repository or a key folder:

```sh
python -m http.server 8080 --bind 127.0.0.1
```

Then start the proxy and, in another terminal, the client:

```sh
python -m tls20_server serve --config lab/server.toml
python -m tls20_server get httpps://localhost/ --ca lab/ca.pem --revocation-policy lab-offline --connect-host 127.0.0.1
```

The client prints the raw HTTP response. `--connect-host` only changes where TCP
connects; the expected certificate identity still comes from the URL. It never
disables verification. `lab-offline` explicitly acknowledges that this experiment
does not check revocation. The CA is supplied to this client only, not trusted
system-wide. Stop the proxy with Ctrl+C.

The project-defined HTTPPS default is **343/TCP**: `httpps://example.com/`
connects to port 343 without requiring `:343` in the URL. This is a project
convention, not a claim of an exclusive port assignment. Low ports can require a service capability
or other OS-specific permission. For unprivileged testing, change `listen` to
`127.0.0.1:8443` and use `httpps://localhost:8443/`. Keep both endpoint settings
consistent. See [configuration](docs/configuration.md) for public binding and
service operation precautions.

### Session resumption and early HTTP

Session tickets are enabled by default and live only in the listener's memory.
Repeated connections can skip the certificate flight while retaining fresh
traffic key agreement. Restarting the server invalidates the tickets.
The store is bounded by entry count and a default 16 MiB accounted-memory budget,
including any retained client certificate chains.

0-RTT sends a repeat request before the handshake finishes; it is replayable.
Do not enable it solely because a route accepts GET. After auditing the exact
routes and configuring the backend to honor `Early-Data: 1` and HTTP 425, set:

```toml
upstream_early_data_aware = true
early_data_paths = ["/static/index.html"]
max_early_data_bytes = 16384
```

Then test two fresh connections in one client process:

```sh
python -m tls20_server get httpps://localhost/static/index.html --ca lab/ca.pem --revocation-policy lab-offline --connect-host 127.0.0.1 --repeat 2 --early-data
```

The first connection authenticates normally. A subsequent compatible ticket
can send the bodyless GET early. Rejected TLS early data is resent only after
the handshake; HTTP 425 causes one retry without early data. There is no retry
after certificate or authentication failure. This test client does not persist
session secrets to disk. See [configuration](docs/configuration.md) for limits.

The [profile guide](docs/profiles.md) documents opt-in file-backed authentication,
native providers and trust/evidence policies. The [implementation guide](docs/implementation.md)
documents dynamic APIs, ticket identity isolation and precise coverage boundaries.
An API or configuration option does not create a browser credential-selection UI.

## Supply your own credentials

Copy `server.example.toml` to `server.toml` and set the paths and ports. Paths
are relative to the configuration file, not the current working directory.

```toml
listen = "127.0.0.1:343"
upstream = "127.0.0.1:8080"
server_name = "example.com"
certificate_chain = "fullchain.pem"
private_key = "server.key"
```

`fullchain.pem` starts with the X25519 leaf and then its intermediate issuers;
the root normally stays out of that file. `server.key` is its matching,
unencrypted PKCS#8 X25519 private key. An ordinary RSA/ECDSA HTTPS leaf does not
meet this profile. The client must independently trust the issuing lab CA.
The server validates configuration, identity, supported chain structure and
key correspondence before listening. It does not obtain or renew certificates.

## Test and package

```sh
python -m pip install -r requirements-dev.txt
python -W error -m unittest discover -s tests -v
python -m compileall -q tls20_server tests
python tools/check_docs.py
python -m build
python tools/check_wheel.py
```

Tests generate fresh short-lived lab credentials in temporary directories and
use only loopback listeners. Public deterministic primitive vectors and
independent spec-derived MAC known answers are test data, not deployed keys.
CI tests Windows, Ubuntu
and macOS and builds a Python wheel and source archive. These are Python
packages, not standalone native executables or installers.

The PSK boundary regressions cover password-session resumption when the server
selects a later offered identity: early data is discarded, while authenticated
1-RTT traffic remains usable. Ticket and delegated-credential regressions check
the encrypted wire alerts as well as valid controls, independent parent trust,
and disposal of temporary traffic states. The password tests require the
explicit native-provider manifest described in the profile guide; ordinary
test discovery reports their absence rather than claiming native coverage.

Finished regressions distinguish a body whose size differs from the negotiated
hash (`decode_error`, 50) from a correctly sized, invalid MAC (`decrypt_error`,
51, or the password server's authentication-failure mask, 20). Loopback tests
cover both directions, both SHA-256/SHA-384 sizes, and post-handshake client
authentication with a selected identity or an authenticated refusal. Credential
request tests validate CA/OID filters before refusing an identity; compression
tests distinguish malformed framing, unoffered algorithms and decoding failure.
Lifecycle regressions verify that retired traffic epochs and temporary keys are
released after their last permitted use, including error paths.

## Further documentation

- [Configuration](docs/configuration.md)
- [Authentication and cryptographic profiles](docs/profiles.md)
- [Protocol implementation and compatibility](docs/implementation.md)
- [Security model and limitations](SECURITY.md)
- [Contribution guide](CONTRIBUTING.md)

Original code and documentation are MIT-licensed. Adapted primitive helpers and
public test vectors retain the specification contributors' attribution.
