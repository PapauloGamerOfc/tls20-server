# Third-party provenance

The complete dependency graph and source checksums are fixed by `Cargo.lock`.
Build with `--locked`; dependency upgrades require renewed license/security
review. This module elects the MIT option where available, BSD-3-Clause for
`subtle`, and additionally preserves Unicode-3.0 for `unicode-ident`. No GPL or
LGPL licensing option is elected. The target-conditional `r-efi` dependency
offers MIT OR Apache-2.0 OR LGPL; this project explicitly selects MIT.

Direct providers:

| Package | Version | License | Source |
| --- | --- | --- | --- |
| rasn / rasn-its | 0.28.14 | MIT OR Apache-2.0, MIT elected | https://github.com/librasn/rasn |
| p256 | 0.13.2 | MIT OR Apache-2.0, MIT elected | https://github.com/RustCrypto/elliptic-curves |
| p384 | 0.13.1 | MIT OR Apache-2.0, MIT elected | https://github.com/RustCrypto/elliptic-curves |
| sha2 | 0.10.9 | MIT OR Apache-2.0, MIT elected | https://github.com/RustCrypto/hashes |

The two rasn crates were published from upstream commit
`398c530cb0a4e1a2ab9515eac5da79111dd3014e`.

- rasn 0.28.14 crate SHA-256:
  `0d1b71dd951343df0fe30b11bca09518f3aba8e5bd0ece4564adbc2dabd875fa`
- rasn-its 0.28.14 crate SHA-256:
  `0012839dfbc489d5f16bc248876d1bc2d81b3ed68f8a871e7932f7d7262d21ca`

`vendor/rasn` contains the upstream crate source, manifest, README and original
license files. Its only code changes are the bounded OER decoder described in
README. Other dependencies are fetched by Cargo using the lockfile checksums.
`rasn-its` omits the workspace license file from its crate; the license is the
same original MIT workspace license preserved in `vendor/rasn/LICENCE-MIT`.

Generate/check redistribution notices with:

```
python native/its/check_licenses.py --cargo /absolute/path/to/cargo
```

The script rejects unreviewed SPDX expressions, includes every resolved package
(including target-conditional/build dependencies), and writes deterministic
`THIRD_PARTY_NOTICES.txt`. Distribute that file with the native library.

Relevant specifications: TLS20 `docs/credentials.md` section ITS-X25519;
RFC 8902 sections 5 and 7; IEEE 1609.2 (COER, certificate permission/path and
signed-data processing). The application-specific PSID authorization and
revocation provisioning remain explicit deployment responsibilities.
