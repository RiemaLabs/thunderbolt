# Thunderbolt

Thunderbolt is an off-chain Bitcoin transfer protocol that uses Sigma-protocol zero-knowledge proofs over Paillier encryption and secp256k1 elliptic curves. Transfers happen off-chain while preserving a fixed on-chain key, with support for both single-committee and threshold-committee configurations.

This repository contains the core Rust implementation and the evaluation benchmarks described in the accompanying CCS 2026 paper.

## Repository Structure

```
crates/
  thunderbolt-core/    Core protocol: ZKP (invoice + transfer proofs), Paillier,
                       threshold VESS, Bitcoin scripts and transactions
  thunderbolt-eval/    Benchmarks and evaluation harness (published as thunderbolt-mock)
  bitcoin-utils/       Bitcoin key management and address utilities
benchmarks/
  sp1-transfer-benchmark/       SP1 zkVM comparison benchmark (reduced-parameter)
  groth16-transfer-benchmark/   Groth16 comparison benchmark
  local-lightning-benchmark/    Local Lightning regtest comparison
artifacts/             Pre-computed benchmark outputs and reproduction scripts
CORE_ZKP.md            Detailed mathematical specification of the ZKP construction
```

## Prerequisites

- **Rust** toolchain (see `rust-toolchain` for the exact version, currently 1.90.0)
- **Cargo** (comes with Rust)

For the SP1 comparison benchmark (RQ3) only:
- **SP1 toolchain** — install via [sp1up](https://docs.succinct.xyz/docs/getting-started/install):
  ```bash
  curl -L https://sp1up.succinct.xyz | bash
  sp1up
  ```
  This installs the SP1 prover toolchain and the `cargo prove` subcommand. The benchmark pins SP1 SDK v6.0.1.
- **Rust 1.91.1** — the SP1 benchmark workspace uses its own `rust-toolchain` file (1.91.1), separate from the main workspace (1.90.0). Rustup will install it automatically on first build.
- **protoc** (Protocol Buffers compiler) — automatically bootstrapped by `benchmarks/ensure_protoc.sh` if not already installed.
- **Docker** — required by the SP1 Gnark prover backend (`native-gnark` feature). Ensure Docker is running before starting the SP1 benchmark.

## Building

```bash
cargo build --release
```

To run the test suite:

```bash
cargo test
```

## Reproducing the Evaluation

All paper benchmarks can be reproduced with a single command:

```bash
./artifacts/reproduce-eval.sh
```

This runs three benchmarks and writes results to `artifacts/`:

| Benchmark | Output | Paper Section | Est. Time |
|-----------|--------|---------------|-----------|
| Single-committee microbenchmark (100 iter) | `single-committee-benchmark.txt` | RQ1 (Table 1) | ~2 min |
| Scalability benchmark (chain lengths 1..1000) | `scalability-benchmark.csv` | RQ1 (scalability) | ~20 min |
| Threshold-committee benchmark (4 shapes, 3 iter) | `threshold-committee-benchmark.{txt,csv}` | RQ2 (Figure 3) | ~15 min |

Total estimated time: **~40 minutes** on a modern Apple Silicon or comparable x86-64 machine.

### Expected Results

After running `reproduce-eval.sh`, verify:

- **RQ1 (Table 1):** `single-committee-benchmark.txt` should report a total off-chain transfer average of ~1.0s (within 0.8--1.3s depending on hardware). The nine stage names and relative proportions should match Table 1 in the paper.
- **RQ1 (scalability):** `scalability-benchmark.csv` should show constant per-transfer latency (~1.0s) across all chain lengths from 1 to 1000, confirming O(1) cost.
- **RQ2 (Figure 3):** `threshold-committee-benchmark.csv` should show committee communication latency growing roughly linearly with committee size, and degrading gracefully under non-responsive members. Compare with Figure 3 in the paper.

### Running Benchmarks Individually

**Single-committee microbenchmark:**

```bash
cargo run -p thunderbolt-mock --release --example single_committee_benchmark -- 100
```

**Scalability benchmark:**

```bash
cargo run -p thunderbolt-mock --release --example scalability_benchmark -- --lengths 1,10,50,100,500,1000
```

**Threshold-committee benchmark:**

```bash
cargo run -p thunderbolt-mock --release --example threshold_committee_benchmark -- 3 \
  --shapes 3-of-5,11-of-15,34-of-50,67-of-100 --fanout 4
```

**SP1 comparison (RQ3):**

Requires the SP1 toolchain and Docker (see Prerequisites above).

```bash
./artifacts/reproduce-sp1-proof-256bit.sh
```

Or run it manually:

```bash
cd benchmarks/sp1-transfer-benchmark/script
PROTOC="$(bash ../../ensure_protoc.sh)" cargo run --release -- \
  --prove --iterations 5 --paillier-bits 256 --json
```

Or run the combined comparison example from the repo root:

```bash
cargo run -p thunderbolt-mock --release --example compare_single_committee_transfer -- 1 \
  --with-sp1 --sp1-paillier-bits 256
```

### Tuning Parameters

The reproduction script accepts environment variables:

```bash
SINGLE_COMMITTEE_ITERATIONS=100 \
THRESHOLD_COMMITTEE_ITERATIONS=3 \
THRESHOLD_COMMITTEE_SHAPES=3-of-5,11-of-15,34-of-50,67-of-100 \
SCALABILITY_LENGTHS=1,10,50,100,500,1000 \
  ./artifacts/reproduce-eval.sh
```

## Core ZKP Construction

Thunderbolt uses two NIZK proofs per transfer:

1. **Invoice Consistency Proof** (`prove_invoice` / `verify_invoice`): proves that the public delta point and two Paillier ciphertexts (to Bob and the Committee) all encode the same refresh value.

2. **Transfer Consistency Proof** (`prove_transfer` / `verify_transfer`): proves that Alice's contribution to the next holder ciphertext uses the actual current holder secret consistent with the public anchor.

See [CORE_ZKP.md](CORE_ZKP.md) for the full mathematical specification.

## License

Apache-2.0
