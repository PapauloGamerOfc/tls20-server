# Explicit ITS-X25519 offline grant validator

This optional library implements a configured IEEE 1609.2 certificate profile
for the TLS 2.0 specification's ITS-X25519 grant (CertificateType 3). It does
**not** make an ITS pseudonym a Web PKI identity, enable automatic trust, or
replace the live X25519 MAC and Finished. No provider is loaded implicitly.

## Implemented profile

- Canonical COER via pinned `rasn-its` 0.28.14, including certificate and
  `Ieee1609Dot2Data` parsing. The schema is IEEE 1609.2-2022.
- Explicit certificates with canonical compressed NIST P-256/P-384 verification
  points and x-only ECDSA signatures; SHA-256/SHA-384 and mixed issuer/leaf curves.
  Real signatures use the RustCrypto providers, not handwritten curve math.
- A bounded leaf-first path to an **exact provisioned root**, correct issuer
  identifiers, certificate signatures, time containment, path length,
  end-entity issuance type, and opaque/bitmap SSP delegation containment.
- One explicitly provisioned PSID per certificate and one issuance group.
  The application must configure the PSID owner's permission to delegate to the
  chosen TLS 2.0 role, the exact SSP, scope, and leaf/service identity binding.
  Merely having permission to sign ordinary ITS messages is not enough.
- Exact grant role/version/scope/X25519 SPKI, grant validity contained in the
  leaf certificate, exact external SHA-256 grant hash, proof PSID/generation time,
  `pduFunctionalType=tlsHandshake`, no unrelated HeaderInfo fields, and exact
  leaf signer. The signed-data signature verifies the IEEE double-hash input.
- A fresh, locally authenticated revocation inventory with an explicit expiry.
  Its lifetime caps the returned authorization lifetime. Revoked roots,
  intermediates and leaves fail. This is provisioned revocation state, **not**
  a claim to implement ITS CRL signature/linkage processing.
- Optional geographically restricted credentials only where the deployment
  explicitly provisions the service's exact COER region. This profile accepts
  inheritance or identical child/parent regions, not arbitrary geographic
  containment calculations.

Unsupported profiles fail closed: implicit ECQV certificates, Brainpool/SM2 ITS
signatures, multiple PSIDs/issuance groups, arbitrary geographic containment,
unknown certificate extensions, encryption keys, and enrollment/request/rollover
permissions. This is not a claim that CertificateType 3 accepts every ITS PKI.

## Time and provisioning

Every native time is IEEE `Time64`: microseconds since 2004-01-01 00:00:00 TAI.
The Python policy requires the deployment's explicit current TAI-UTC offset;
it never silently treats Unix time as Time64. Update that offset and revocation
inventory through an authenticated local configuration process. Production
policy must not copy the test fixture's PSID, time offset, roots, identities or
private keys. The fixture authorizes only an artificial test service.

## C ABI (version 1)

```
uint32_t tls20_its_abi_version(void);
int tls20_its_authorize(const uint8_t *grant, size_t grant_size,
                        const uint8_t *policy, size_t policy_size,
                        uint8_t *output, size_t output_size);
```

Input/output buffers belong to the caller and must be valid for their sizes.
No allocator crosses the ABI. Success is exactly `1`; failure is `0`, with
the entire 72-byte output cleared. Panics are caught and fail closed. The input
grant is the specification's complete CertificateEntry `cert_data` (one entry).

The 72-byte output is raw X25519 public key (32), authorization expiry Time64
(8, big endian), and SHA-256 of the exact leaf certificate (32). The caller must
also reject invalid/low-order X25519 keys using its existing agreement provider
and verify the live role-specific MAC and Finished before accepting a peer.

Policy encoding (all integers big endian; Vn is an n-byte length then bytes):

```
"ITS1" || U64(now) || U64(inventory_valid_until) || U64(max_grant_lifetime)
 || U8(role: server=0/client=1) || U64(psid)
 || V2(application_scope) || V2(COER ServiceSpecificPermissions or empty)
 || V3(V3(root_certificate_COER) ...)
 || V3(authorized_leaf_SHA256[32] ...)
 || V3(revoked_certificate_SHA256[32] ...)
 || V3(V3(authorized_service_region_COER) ...)
```

The caller binds that policy to its exact service identity and role. Bind ticket
cache entries to an unambiguous hash of **all** policy fields with vector/category
boundaries and the service identity. Revalidate cached grants with current time
and revocation state **before** sending early data. Never fall back to accepting
an unvalidated credential when this profile fails.

## Bounds and codec maintenance

The library limits each input to 256 KiB, each COER object to 16 KiB, chains to
8 certificates, anchors to 32, explicitly authorized leaves to 1024, revoked
fingerprints to 4096 and regions to 32. Unsupported forms fail before use.

`vendor/rasn` is the unmodified 0.28.14 crate `src`, manifest, README and license
except for `src/oer/de.rs`: recursion is capped at 32, and SEQUENCE OF quantity
is capped at 1024 and remaining input bytes **before** allocation, with
`try_reserve` replacing attacker-controlled `with_capacity`. Original crate
checksum is recorded in `UPSTREAM.md`. This small local hardening is required
before exposing the decoder inside the browser process. Do not replace the
vendor with the upstream crate without preserving or superseding those guards.

## Build and tests

Use a current Rust toolchain (edition 2024 is required by rasn):

```
cargo test --manifest-path native/its/Cargo.toml --locked -j 1
cargo build --manifest-path native/its/Cargo.toml --locked --release -j 1
```

The release library is `native/its/target/release/tls20_its.dll` on Windows,
`libtls20_its.so` on Linux or `libtls20_its.dylib` on macOS. Configure its explicit
absolute path. The production library contains no fixture keys or generator.

For cross-language tests, create an empty development-only directory and set
`TLS20_ITS_FIXTURE_DIR` to its absolute path when running the Rust test above.
That explicit test option writes public fixture files, including fresh live
server/client grants. Then set `TLS20_TEST_ITS_LIBRARY` to the absolute built
library and run:

```
python -m unittest tests.test_its_credentials tests.test_its_handshake -v
```

Tests include an independent OpenSSL/cryptography ECDSA/hash oracle, mutation of
every grant byte, all truncations, hostile sequence quantities, policy changes,
real TCP full/resumed/0-RTT connections, KeyUpdate, initial client MAC and PHA.
Live fixture inventories expire after 25 minutes; regenerate rather than disable
the expiry check.
