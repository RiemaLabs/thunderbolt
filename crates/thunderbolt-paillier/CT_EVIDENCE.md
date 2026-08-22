# Constant-time evidence harnesses

These harnesses are opt-in diagnostic evidence. They do not prove that the
backend is constant-time and they are not part of the default test suite.
Statistical non-detection can miss weak leakage, while a large signal requires
investigation before it can be attributed to secret-dependent code.

## Statistical experiments

The two ignored tests in `src/timing_tests.rs` use balanced, pseudorandomly
shuffled class order, a separate warmup, fixed public inputs, and online
Welch-t statistics:

- `timing_decrypt_welch_t_experiment` decrypts one fixed ciphertext under the
  same exact public modulus. Class 0 uses the certified Carmichael exponent
  `lambda`; class 1 uses the equivalent valid exponent `2 * lambda` with its
  matching inverse. Correctness is checked before measurement.
- `timing_proof_response_welch_t_experiment` fixes the public key, challenge,
  statement ciphertext, and commitment ciphertext. Class 0 uses fixed valid
  opening nonces; class 1 uses freshly sampled valid opening nonces. Input
  preparation and random sampling occur outside the measured region.

Both experiments black-box their results and report class counts, mean
nanoseconds, variances, Welch's t statistic, approximate degrees of freedom,
source seed, and a public-input fingerprint. Non-finite statistics, fewer than
two samples per class, zero standard error, and invalid degrees of freedom are
reported as `invalid_statistics` and make the opt-in test fail. `|t| >= 10` is
printed only as an investigation heuristic. It never makes the test fail and
is not a security threshold.

For decrypt, key selection happens before `Instant::now`; the timer includes
`decrypt`, result checking, and result black-boxing, then stops before class
statistics and returned-plaintext drop/zeroization. For proof response, class
order, nonce sampling, and opening preparation happen before the timer. The
timer includes `consume_proof_openings`, including consumed-opening drop and
zeroization, result checking, and result black-boxing; it stops before class
statistics and public-result drop.

Run one experiment at a time on an isolated core:

```bash
mkdir -p /tmp/thunderbolt-ct-samples
THUNDERBOLT_CT_RUN=1 \
THUNDERBOLT_CT_SAMPLES=512 \
THUNDERBOLT_CT_WARMUP=32 \
THUNDERBOLT_CT_SEED=c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7 \
THUNDERBOLT_CT_CSV_DIR=/tmp/thunderbolt-ct-samples \
cargo test --release -p thunderbolt-paillier \
  timing_decrypt_welch_t_experiment -- \
  --ignored --nocapture --test-threads=1
```

Replace the test filter with `timing_proof_response_welch_t_experiment` for the
proof-response experiment. Counts must be even. Defaults are 512 measured
samples and 32 warmup samples. If `THUNDERBOLT_CT_RUN=1` is absent, even an
explicit ignored-test run prints a skip record and performs no measurements.
If `THUNDERBOLT_CT_CSV_DIR` names an existing directory, the harness creates a
new per-operation CSV containing measurement index, class order, and duration;
it refuses to replace an existing CSV. CSV output occurs after all timing.

## Assembly and call-graph scan

`scripts/ct-assembly-scan.sh` first creates a Cargo package from the selected
crate, records the exact archive hash, and extracts it outside the repository.
It accepts only the package's own frozen registry lock with checksums, vendors
that dependency closure offline, installs crate-local O0/O3 profiles and a
crate-local source-replacement configuration, then builds from that standalone
tree. The live workspace manifest, workspace profiles, path patches, and Cargo
configuration are not in the compile boundary and cannot affect the emitted
assembly after packaging.

The isolated build runs with an empty environment, a fresh `HOME`,
`CARGO_HOME`, target directory, and temporary directory, an explicit Cargo and
rustc from one sysroot, a fixed linker, at most four jobs, and Cargo's frozen
offline mode. One recorded `RUSTFLAGS` value remaps the unique extracted source
root to `/thunderbolt-paillier-source`, so embedded dependency assertion paths
and O0 debug paths do not make the assembly hash depend on the evidence output
directory. Ambient Cargo, rustc, profile, linker, SDK, and C/C++ flag
overrides are rejected before packaging. Output must be outside the live
repository, and live repository `.cargo/config*` files are rejected. Package
and vendor preparation also run offline under a Cargo home containing only a
link to the local registry cache; that cache is not a compile input after the
vendor snapshot exists.

Before and after compilation, `scripts/ct-input-manifest.sh` hashes the entire
extracted package, crate-local profiles and configuration, lock, scanner,
vendored dependency sources and build scripts, toolchain `bin` and `lib`
trees, selected linker tools, and the relevant platform SDK libraries. The
built-in target specification is bound by the rustc binary and commit; the
effective target `cfg` and target library directory are also recorded inside
the sealed tree. The scan fails before writing `scan_passed` if either complete
input manifest differs. `scripts/ct-input-manifest-self-test.sh` locks this
behavior with mutations to the manifest, lock, Cargo config, vendored source
and build script, scanner, effective target record, sanitized environment
record, compiler, compiler library, and linker, plus an added path-patch file.

After compilation, `scripts/ct-scan.awk` starts from ten online secret-path
roots, follows direct Rust-symbol calls, and resolves x86_64 GOT function
pointers propagated through registers/stack slots. Forward control-flow joins
taint any mapping changed on only one path; stack/frame-pointer movement
invalidates stack-slot mappings. It fails when:

- an expected root is absent;
- a reachable division or floating square-root instruction is not on the
  reviewed public-parameter allowlist; or
- a reachable symbol/reference containing `vartime` is not on the narrow
  reviewed allowlist; or
- an unresolved reachable indirect control transfer is not on the reviewed
target/compiler/count-specific allowlist; or
- a reachable named external call is not one of the reviewed memory,
  OS-entropy, or unwinding functions.

The supported matrix is x86_64/AArch64 on Linux/macOS at O0 and O3. Both levels
disable debug assertions and retain overflow checks. Disabling debug assertions
is deliberate: dependency debug assertions branch on invariant checks and are
not part of the production arithmetic contract. O0 still disables ordinary
optimization and exposes non-inlined dependency call paths.

Example:

```bash
scripts/ct-assembly-scan.sh \
  x86_64-unknown-linux-gnu O0 /tmp/thunderbolt-paillier-x86-o0
scripts/ct-assembly-scan.sh \
  x86_64-unknown-linux-gnu O3 /tmp/thunderbolt-paillier-x86-o3
```

Run `scripts/ct-scan-self-test.sh` and
`scripts/ct-input-manifest-self-test.sh` first. The scanner test asserts that a
clean synthetic call graph passes and that injected reachable division,
unreviewed `vartime`, named division helper, SIMD division, AArch64 `br`/`blr`,
x86 stack-rebase, branch-skip, subregister-clobber, and generic
unresolved-indirect fixtures all make the scanner fail. The input-manifest test
asserts that every modeled compile-input class changes the seal.

The evidence directory contains the exact Cargo archive, standalone source and
vendor tree, fixed profiles/configuration, build environment and target
records, complete pre/post input manifests, tool output, metadata, scan report,
and assembly. It refuses to replace an existing directory. The manifest is the
authoritative byte-level record; package generation is provenance for that
record and is not a claim that a dirty live workspace was itself immutable.

### Reviewed allowlists

The only allowed variable-time symbols are:

- `random_mod_vartime`, its core helper, and `bits_vartime`, all on the private
  fresh-randomness sampler under public `N`; and
- `Choice::to_u8_vartime` when called by RustCrypto's branchless mask builders;
  the dependency implementation returns the stored byte and then uses
  wrapping negation to form a mask.

The only allowed hardware divisions are on public bit/limb counts:

- SafeGCD's iteration bound from fixed `Uint::BITS`;
- `u32::div_ceil` used for public exponent/modulus/shift bounds;
- AArch64 `random_bits_core` division of the public requested bit length by the
  limb width; and
- AArch64 SafeGCD shift helpers, whose shift is the public fixed-batch schedule.

The scanner prints every allowance. A dependency/compiler change must be
reviewed against source data flow before updating these patterns.

All x86 integer, scalar/packed SSE/AVX, and x87 divide and square-root mnemonic
families are rejected unless the enclosing helper is on the public-parameter
allowlist. The scanner self-test includes `vdivsd` and an external
`__udivti3`-style helper.

The generic allowed unresolved indirect transfers are Linux OS-entropy backend
dispatch and O0 atomic ordering jump tables. The former handles fresh
randomness before secret arithmetic; the latter switches on fixed public memory
ordering values. Linux x86_64 O3 additionally pins exact reviewed indirect
sites in exponentiation/encrypt/decrypt/proof-response functions to either the
retained historical assembly SHA-256 or the current isolated-driver assembly
SHA-256, plus the compiler commit, target, optimization, enclosing symbols, and
counts. Every instruction location/operand is printed. Any unlisted assembly,
count, compiler, target, or optimization change fails. Named GOT calls and
Rust function pointers are resolved where the conservative CFG pass can prove
their provenance. Reachable named externals are limited to `memcpy`/`memmove`/
`memset`/`memcmp`/`bcmp`/`bzero`, OS `getentropy`, and unwinding; compiler
division helpers are rejected.

## Limits and remaining work

The call graph is not secret-taint analysis and its x86_64 pointer propagation
is intentionally narrow. The input seal covers Cargo/rustc sources and selected
link/SDK inputs, not the kernel, firmware, CPU, filesystem implementation, or
all dynamically loaded host services. Host and tool versions remain part of
the evidence record. The scanner does not model caches, speculation,
interrupts, frequency scaling, or remote noise.
The timing tests are a compact dudect-style experiment, not the upstream dudect
harness. Timecop/Valgrind taint testing, longer multi-machine campaigns, and an
external cryptographic audit remain required before a production constant-time
claim.
