# License and packaging boundary

The Stage-A arithmetic is Rust-only and introduces no project-maintained crypto
FFI, separately linked native cryptographic library, OpenSSL, GMP, MPFR, MPC,
or Rug dependency. Operating-system entropy remains an explicit dependency
boundary: `getrandom` and its target-specific `libc` support use reviewed
dependency `unsafe`, system calls/FFI, and package build scripts. The crate's
own source forbids `unsafe`.

Direct normal dependencies, plus the explicit transitive OS boundary, are:

| Dependency | Version | License | Role |
|---|---:|---|---|
| `crypto-bigint` | 0.7.5 | Apache-2.0 OR MIT | Fixed-width constant-time-oriented arithmetic |
| `crypto-primes` | 0.7.2 | Apache-2.0 OR MIT | Offline sieve and primality checks |
| `chacha20` | 0.10.0 | Apache-2.0 OR MIT | Zeroizing CSPRNG after OS seeding |
| `rand_core` | 0.10.0 | Apache-2.0 OR MIT | RNG traits |
| `getrandom` | 0.4.3 | Apache-2.0 OR MIT | Fallible operating-system entropy boundary |
| `libc` | 0.2.x | Apache-2.0 OR MIT | Target-specific transitive OS FFI/build support |
| `zeroize` | 1.x | Apache-2.0 OR MIT | Secret memory hygiene |
| `sha2` | 0.10.x | Apache-2.0 OR MIT | Public diagnostic fingerprints only |
| `thiserror` | 2.x | Apache-2.0 OR MIT | Structured errors |

`num-bigint` and `num-traits` are dev-only differential-test oracles and do not
enter release binaries. `proptest` and `static_assertions` are also dev-only.

The crate package contains its own Apache-2.0 `LICENSE` and project `NOTICE`.
Release packaging must retain those files, dependency license notices,
Cargo.lock, and the generated SBOM. Run the workspace license policy and
dependency-provenance checks after every dependency update. The absence of a
separately linked native cryptographic library avoids crypto-library
dynamic-link/relink obligations on supported x86_64 and AArch64 targets; the OS
entropy boundary still requires target-specific review.

The current workspace SBOM script roots its release graphs at `thunderboltd`
and `thunderbolt-cli`. Because Stage A is intentionally unintegrated, neither
release SBOM contains this crate yet. The future integration change must either
place this crate in a release dependency closure or add an explicit component
SBOM, and its gate must assert that `thunderbolt-paillier` plus the production
dependencies above are present. A standalone CycloneDX 1.5 smoke generation
from the verified crate package included `crypto-bigint`, `crypto-primes`,
`getrandom`, and `libc`; its package-local locked RustSec audit passed. These
are evidence, not a checked-in release SBOM. A Stage-A workspace policy run
passed the license and registry-source checks; the combined workspace advisory
run remained blocked by the pre-existing `rustls-pemfile` advisory in the
unrelated runtime/RPC dependency graph.

GMP/Rug remains a rejected alternative for the default backend because it
would add LGPL-3.0+ compliance, native linking, source/relinking obligations,
and a separate side-channel audit. OpenSSL remains a rejected alternative
because the existing wrapper uses ordinary modular exponentiation and a safe
replacement would require a custom FFI and packaging boundary.
