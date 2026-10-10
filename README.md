# TLS 2.0 Server

An experimental HTTPPS termination proxy and test client for the independent
[TLS 2.0 draft-01 specification](https://github.com/PapauloGamerOfc/tls20-spec/blob/babaa838a45713764031becae3420f489f8ffca8/SPECIFICATION.md).
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
- Independent ephemeral X25519 traffic keys, HKDF-SHA-256 and AES-128-GCM records.
- A configurable TCP listener and a fixed, loopback-only HTTP backend.
- Real X.509 laboratory certificates, explicit client trust and hostname checks.
- Connection, handshake, idle, lifetime and traffic limits; bounded buffering.
- A terminal test client, local credential generator and loopback integration tests.

The certificate validator accepts a deliberately restricted lab PKI, not general
public-PKI paths. Python cannot guarantee secret erasure. See
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

The local default port is **1021/TCP**, one of the shared experimental ports,
not an exclusive HTTPPS assignment. Low ports can require a service capability
or other OS-specific permission. For unprivileged testing, change `listen` to
`127.0.0.1:8443` and use `httpps://localhost:8443/`. Keep both endpoint settings
consistent. See [configuration](docs/configuration.md) for public binding and
service operation precautions.

## Supply your own credentials

Copy `server.example.toml` to `server.toml` and set the paths and ports. Paths
are relative to the configuration file, not the current working directory.

```toml
listen = "127.0.0.1:1021"
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
python -m unittest discover -s tests -v
python -m compileall -q tls20_server tests
python -m build
```

Tests generate fresh short-lived lab credentials in temporary directories and
use only loopback listeners. Public deterministic primitive vectors are copied
from the specification; they are not deployed keys. CI tests Windows, Ubuntu
and macOS and builds a Python wheel and source archive. These are Python
packages, not standalone native executables or installers.

## Further documentation

- [Configuration](docs/configuration.md)
- [Protocol implementation and compatibility](docs/implementation.md)
- [Security model and limitations](SECURITY.md)
- [Contribution guide](CONTRIBUTING.md)

Original code and documentation are MIT-licensed. Adapted primitive helpers and
public test vectors retain the specification contributors' attribution.
