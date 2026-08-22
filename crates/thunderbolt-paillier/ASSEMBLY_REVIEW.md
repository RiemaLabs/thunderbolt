# Assembly and call-graph review

Review date: 2026-08-22

Status: reproducible O0/O3 scanners and opt-in statistical harnesses are
present. This evidence is not production constant-time clearance.

## Reproducible gate

Run `scripts/ct-scan-self-test.sh` and
`scripts/ct-input-manifest-self-test.sh`, then invoke
`scripts/ct-assembly-scan.sh TARGET O0|O3 OUTPUT_DIRECTORY`. The gate records:

- the exact standalone Cargo archive, registry-only dependency lock, vendored
  sources/build scripts, crate-local profile/config, scanner, compiler and
  compiler libraries, selected linker/SDK inputs, target, host, and
  optimization level;
- emitted assembly plus its SHA-256 digest;
- all ten required secret-path roots and their reachable Rust call graph;
- every reviewed public-parameter division and allowed variable-time symbol;
  and
- every narrowly allowed unresolved OS-randomness/public-ordering dispatch.

The compile runs outside the repository with isolated Cargo state, a sanitized
environment, frozen offline resolution, and matching full pre/post input
manifests. This prevents workspace profiles, Cargo config, path patches, or a
concurrent live-workspace edit from silently changing the compiled input after
the package boundary. It fails on a missing root, unreviewed reachable integer,
SSE, AVX, or x87 division/square root, unexpected `vartime` reference, named
compiler-division helper, or unresolved indirect control transfer. Reviewed unresolved Linux O3
sites are bound to one of the exact retained/current assembly
SHA/compiler/target/level/site sets. O0 and O3 both disable dependency debug
assertions and retain overflow checks; the distinction is ordinary compiler
optimization. See
[CT_EVIDENCE.md](CT_EVIDENCE.md) for the exact allowlist and its source-level
data-flow justification.

## macOS matrix

The current Stage-A candidate was scanned with Rust 1.90.0 / LLVM 20.1.8 on:

| Target | Level | Result |
|---|---|---|
| `x86_64-apple-darwin` | O0 | pass |
| `x86_64-apple-darwin` | O3 | pass |
| `aarch64-apple-darwin` | O0 | pass |
| `aarch64-apple-darwin` | O3 | pass |

At O3 the secret arithmetic produced no reachable hardware division. O0 kept
dependency helpers out of line. Its reviewed divisions used only public
bit-length, limb-count, and fixed SafeGCD shift/iteration parameters; the gate
prints each occurrence. The only reviewed variable-time sampling path remains
fresh rejection sampling below public `N`.

## Linux evidence

The authorized Linux x86_64 run, exact hashes, resource ceilings, statistical
outputs, and cleanup record are stored under `evidence/`. The committed record
must be read together with the raw-result hashes; no timing result is promoted
to a proof or production claim.

The current strict scanner was applied offline to the retained hash-verified
Linux and macOS assemblies. Those committed `evidence/postscan/` reports
supersede the scanner verdicts produced during the original remote commands.

## Limitations

Assembly call-graph reachability does not establish that every branch or memory
access is secret-independent. RustCrypto exponentiation, inversion, exact
division, and Montgomery multiplication remain dependency code whose
documented contract and target restrictions are part of the argument. The
scanner's x86_64 function-pointer propagation is deliberately narrow and any
new unresolved transfer fails closed.

The statistical tests can detect a signal but cannot prove its absence. Longer
upstream-dudect campaigns, Timecop/Valgrind secret-taint testing, production
CPU/OS replication, and external cryptographic review remain open.
