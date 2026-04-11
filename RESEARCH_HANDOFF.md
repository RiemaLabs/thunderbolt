# Research Handoff

This document is the quickest way for another researcher to understand what in this repo is:

- **implemented**
- **benchmarked**
- **still missing**
- and **safe to cite as an experimental result**

## 1. Current research scope

The active implementation scope is **not** the full Thunderbolt protocol described in `README.md`.

The codebase currently implements:

1. **A specialized proof kernel for `CORE_ZKP.md`**
   - Core Proof 1: invoice consistency
   - Core Proof 2: transfer consistency
2. **A single-committee off-chain benchmark harness**
3. **Comparison harnesses** against:
   - local Core Lightning regtest payments
   - a general-purpose SP1 proof of the same transfer-step semantics

The codebase does **not** currently implement a full production Thunderbolt state machine with:

- ledger persistence
- invoice spent-set enforcement
- full context row append/update semantics
- register / redeem-readiness proofs
- threshold committee resharing / PVSS

## 2. Files that matter

### Specialized Thunderbolt proof kernel

- `CORE_ZKP.md`
- `crates/thunderbolt-core/src/zkp/mod.rs`
- `crates/thunderbolt-core/src/zkp/types.rs`
- `crates/thunderbolt-core/src/zkp/transcript.rs`
- `crates/thunderbolt-core/src/zkp/invoice.rs`
- `crates/thunderbolt-core/src/zkp/transfer.rs`
- `crates/thunderbolt-core/src/paillier.rs`
- `crates/thunderbolt-core/tests/core_zkp.rs`

### Single-committee specialized benchmark

- `crates/thunderbolt-eval/src/benchmark.rs`
- `crates/thunderbolt-eval/examples/single_committee_benchmark.rs`

### Comparison harnesses

- `crates/thunderbolt-eval/src/comparison.rs`
- `crates/thunderbolt-eval/examples/compare_single_committee_transfer.rs`
- `benchmarks/local-lightning-benchmark/`
- `benchmarks/sp1-transfer-benchmark/`

## 3. What each benchmark means

### A. Specialized Thunderbolt benchmark

Command:

```bash
cargo run -p thunderbolt-mock --release --example single_committee_benchmark -- 10
```

Measures:

- invoice setup
- invoice proof generation
- invoice proof verification
- transfer setup
- transfer proof generation
- anchor transition verification
- transfer proof verification
- Bob decrypt
- committee decrypt/update
- total off-chain transfer elapsed time

It **does not** include:

- Paillier key generation
- networking
- chain settlement
- ledger persistence

Interpretation:

> This is the cost of the current **specialized off-chain proof path** for one transfer step with a single committee member.

### B. Local Lightning benchmark

Command:

```bash
python3 benchmarks/local-lightning-benchmark/run_benchmark.py --iterations 10
```

Measures:

- invoice creation on `cln2`
- payment settlement on `cln1`
- total local regtest payment time

It uses:

- 1 local `bitcoind`
- 2 local Core Lightning nodes
- 1 direct channel

Interpretation:

> This is a **best-case local Lightning** benchmark (single machine, regtest, prebuilt channel). It is useful for apples-to-apples local comparison, but **not** representative of Lightning mainnet latency tails.

### C. Public Lightning reference comparison

The compare example also includes **reference numbers** derived from published Core Lightning / Blockstream probe-payment experiments.

These numbers are intended to support claims about:

- route finding
- retries
- liquidity dependence
- long-tail latency

Interpretation:

> Use these references to highlight that Thunderbolt avoids Lightning’s dependence on routing liquidity and hop-by-hop retries. Do **not** present them as a same-machine apples-to-apples benchmark.

### D. SP1 comparison

Command:

```bash
cargo run -p thunderbolt-mock --release --example compare_single_committee_transfer -- 1 --with-sp1
```

Standalone:

```bash
cd benchmarks/sp1-transfer-benchmark/script
PROTOC=/tmp/protoc29/bin/protoc cargo run --release -- --execute --iterations 1
PROTOC=/tmp/protoc29/bin/protoc cargo run --release -- --prove --iterations 1 --json
```

Interpretation:

> This benchmark proves the **same transfer-step semantics** in a general-purpose zkVM. It is **not** a byte-for-byte reimplementation of the Paillier + specialized Sigma/Fiat–Shamir proof system.

## 4. Experimental claims that are safe right now

Reasonably safe:

- the specialized proof kernel exists and passes focused tests
- the specialized single-committee benchmark is measurable and reproducible
- local Lightning regtest payments can be benchmarked in the repo
- SP1 can be used as a general-purpose comparison target for the same transfer-step semantics

Not safe yet:

- “the full Thunderbolt protocol is implemented”
- “mainnet-ready end-to-end Thunderbolt transfer exists in this repo”
- “the eval/mock transfer path is the real Thunderbolt protocol path”

## 5. Main limitations

1. `README.md` is a **protocol/spec document**, not a strict statement of implemented code.
2. `crates/thunderbolt-eval` still includes mock/demo transaction flows that are **not the full Thunderbolt protocol state machine**.
3. The specialized benchmark uses **committee = 1**, which simplifies the committee side.
4. The local Lightning benchmark is **1-hop regtest**, so it is a lower-bound / best-case comparison.
5. The SP1 comparison proves the **same arithmetic relation**, not the exact same cryptographic statement objects.

## 6. Environment notes

### Local Lightning benchmark

Requirements:

- Docker Desktop / Docker Engine
- Docker Compose v2

### SP1 benchmark

Requirements:

- `cargo-prove`
- Docker
- a working `PROTOC`

On this machine, a working fallback binary was downloaded to:

```bash
/tmp/protoc29/bin/protoc
```

If your system `protoc` is broken, set:

```bash
PROTOC=/tmp/protoc29/bin/protoc
```

The compare example also uses:

```bash
RUSTUP_TOOLCHAIN=1.91.1-aarch64-apple-darwin
```

for the SP1 subprocess.

## 7. Suggested next steps

Highest-value next research steps:

1. Build an **in-memory Thunderbolt ledger/state-machine** that actually consumes:
   - invoice objects
   - one-time invoice identifiers
   - anchor transitions
   - proof verification
2. Add a **single-committee full protocol harness** (not just proof-kernel timing)
3. Add **multi-iteration percentile summaries** (`p50/p95/p99`) for all benchmark modes
4. Move comparison baselines into a small `results/` or `artifacts/` directory for paper-ready tables
5. If needed, generalize from committee=1 to a threshold committee simulation

## 8. Minimal reproducibility commands

### Specialized path

```bash
cargo test -p thunderbolt-core --quiet
cargo run -p thunderbolt-mock --release --example single_committee_benchmark -- 10
```

### Local Lightning

```bash
python3 benchmarks/local-lightning-benchmark/run_benchmark.py --iterations 10 --json
```

### Combined comparison

```bash
cargo run -p thunderbolt-mock --release --example compare_single_committee_transfer -- 10
cargo run -p thunderbolt-mock --release --example compare_single_committee_transfer -- 10 --with-local-lightning
cargo run -p thunderbolt-mock --release --example compare_single_committee_transfer -- 1 --with-sp1
```
