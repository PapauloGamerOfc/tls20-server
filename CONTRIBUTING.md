# Contributing

Changes must stay within the independent experimental protocol and retain its
explicit separation from standard TLS. Discuss incompatible wire changes in the
specification before changing this implementation's preface, KDF labels or
message fields. A new implementation revision is not a new registered TLS version.

Use Python 3.11-compatible source and provider-backed cryptographic primitives.
Add negative cases for every new parser or acceptance rule. Never weaken identity,
certificate, proof or Finished checks merely to make an integration test pass.

Run the full unittest suite, compileall and package build before submitting a
change. Network tests must use loopback and ephemeral ports and clean up listeners
and tasks. Generate credential material in temporary directories; do not commit
usable private keys. Fixed public vectors must remain clearly test-only.

Do not label a passing test suite as a proof of security, a production audit or
independent interoperability. Document restrictions alongside the supported
feature, including any effects on certificate acceptance and closure behavior.
