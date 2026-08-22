# Release assembly review

Review date: 2026-08-22

Status: macOS release-instruction scan complete for the Stage-A candidate.
Linux, O0, data-flow, and dynamic timing gates remain open; this is not
constant-time clearance.

The release gate must record the exact source commit, Rust toolchain, target,
CPU, optimization settings, and dependency lock. Review both x86_64 and AArch64
release assembly for plaintext ingress, encrypt, decrypt, homomorphic
operations, consuming proof-opening combination, and the response-equation
paths.

Minimum commands:

```bash
cargo rustc --locked --release -p thunderbolt-paillier --lib -- --emit=asm
uv run /path/to/constant-time-analysis/ct_analyzer/analyzer.py \
  --arch arm64 --opt-level O3 crates/thunderbolt-paillier/src/lib.rs
uv run /path/to/constant-time-analysis/ct_analyzer/analyzer.py \
  --arch x86_64 --opt-level O3 crates/thunderbolt-paillier/src/lib.rs
```

Every division, conditional branch, table access, and variable shift must be
traced to public data, fixed loop structure, fresh randomness, or an explicitly
offline operation. A clean instruction scan is necessary but insufficient;
complete the statistical and dynamic program in `CONSTANT_TIME.md`.

## Stage-A results

Toolchain: Rust 1.90.0, LLVM 20.1.8. Native target:
`aarch64-apple-darwin`. Cross target: `x86_64-apple-darwin`. Both used the
workspace release profile with thin LTO and overflow checks. The scan ran on an
uncommitted Stage-A candidate while the shared workspace HEAD and dependency
lock were changing in parallel; it must be repeated after the crate and
root-owned dependency lock are frozen.

The crate was compiled to assembly for both targets. The exact symbol bodies
for plaintext ingress, `PublicKey3072::encrypt`, homomorphic add/subtract/public
exponentiation, `consume_proof_openings`, `response_lhs`,
`SecretKey3072::decrypt`, and the exact `L` division helper contained no
AArch64 `udiv`/`sdiv`/floating division and no x86_64
`div`/`idiv`/floating-division instructions. Whole-file division instructions
mapped to FIPS probable-prime validation and `generate_prime`, both explicitly
offline.

The scan does not establish that every conditional branch or memory access is
secret-independent. RustCrypto exponentiation, inversion, division, and
Montgomery multiplication remain dependency code whose documented
constant-time contract and target restrictions are part of the argument.
Automated analysis could not run because the configured skill's analyzer script
and `uv` executable were unavailable in this environment. The manual result is
therefore a release-candidate input, not a proof or external audit. No Linux
target, O0, conditional-branch/data-flow, dudect, or Timecop result exists yet.
