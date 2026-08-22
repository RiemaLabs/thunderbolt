# Evaluation Reproducibility Bundle

This directory is the reproducibility bundle for the evaluation experiments in the CCS 2026 paper.

It follows a simple CCS-style artifact layout:

- `README.md`: claims, environment, commands, expected outputs
- `reproduce-eval.sh`: one-command regeneration of the checked-in benchmark outputs
- `reproduce-sp1-proof-256bit.sh`: reproduction script for the checked-in SP1 RQ4 artifact
- `single-committee-benchmark.txt`: raw stdout for the single-committee microbenchmark
- `scalability-benchmark.csv`: machine-readable scalability benchmark results (per-transfer latency across chain lengths)
- `sp1-proof-256bit-5iters.json`: raw JSON summary for the reduced-parameter SP1 proof benchmark
- `sp1-proof-256bit-5iters.md`: measurement metadata for the reduced-parameter SP1 proof benchmark
- `threshold-committee-benchmark.txt`: raw stdout for the threshold-committee benchmark
- `threshold-committee-benchmark.csv`: machine-readable threshold benchmark results

## Claims Covered

These artifacts cover the concrete benchmark claims in `eval.tex`:

1. Per-stage microbenchmark of a single off-chain transfer
2. Threshold-committee delay benchmark over committee shape and delayed-member fraction
3. Reduced-parameter SP1 proof-cost measurement used in RQ4

The Lightning discussion in `eval.tex` is conceptual. The Groth16 discussion is qualitative only:
the paper does not claim a checked-in full Groth16 implementation artifact.

## Environment

Required:

- Rust toolchain with Cargo
- release builds enabled locally

Used on this machine:

- Apple M3 Max
- macOS 15.2
- `rustc` 1.90.0

## One-Command Reproduction

From the repo root:

```bash
./research/artifacts/reproduce-eval.sh
```

This regenerates:

- `research/artifacts/single-committee-benchmark.txt`
- `research/artifacts/scalability-benchmark.csv`
- `research/artifacts/threshold-committee-benchmark.txt`
- `research/artifacts/threshold-committee-benchmark.csv`

## Exact Commands

Single-committee microbenchmark:

```bash
cargo run -p thunderbolt-mock --release --example single_committee_benchmark -- 100 > research/artifacts/single-committee-benchmark.txt
```

Threshold-committee benchmark:

```bash
cargo run -p thunderbolt-mock --release --example threshold_committee_benchmark -- 3 --shapes 3-of-5,11-of-15,34-of-50,67-of-100 > research/artifacts/threshold-committee-benchmark.txt
```

The threshold benchmark also writes the CSV artifact automatically to:

```text
research/artifacts/threshold-committee-benchmark.csv
```

## Optional Related Commands

These commands are relevant to the broader evaluation discussion in `eval.tex`, but
they are not part of the checked-in primary artifact outputs in this directory.

Local Lightning regtest:

```bash
python3 research/benchmarks/local-lightning-benchmark/run_benchmark.py --iterations 10 --json
```

SP1 comparison:

```bash
cargo run -p thunderbolt-mock --release --example compare_single_committee_transfer -- 1 --with-sp1 --sp1-paillier-bits 256
```

SP1 paper artifact:

```bash
./research/artifacts/reproduce-sp1-proof-256bit.sh
```

Standalone SP1:

```bash
cd research/benchmarks/sp1-transfer-benchmark/script
PROTOC="$(bash ../../ensure_protoc.sh)" cargo run --release -- --prove --iterations 5 --paillier-bits 256 --json
```

## Expected Outputs

Single-committee output:

- Human-readable per-stage timings
- Includes average / min / max / total

Threshold benchmark output:

- Human-readable list of points for a single delay-adversary curve family
- Committee setups default to `3-of-5`, `11-of-15`, `34-of-50`, and `67-of-100`
- x-axis = delayed fraction `f / (n - t)`
- Each point reports:
  - end-to-end total transfer latency
  - committee-completion latency

Threshold CSV output:

- One row per `(committee_shape, delayed_members)` point
- Columns:
  - `committee_label`
  - `committee_size`
  - `threshold`
  - `slack_members`
  - `delayed_members`
  - `delayed_fraction`
  - `baseline_rtt_ms`
  - `honest_jitter_max_ms`
  - `delayed_member_penalty_ms`
  - total-latency summary columns
  - committee-completion summary columns
  - `iterations`

SP1 256-bit artifact output:

- JSON summary containing `prove`, `verify`, and `total` timing aggregates over 5 runs
- Markdown metadata recording the exact reproduction command and benchmark-source hashes

## Tunable Knobs

The helper script supports environment-variable overrides:

```bash
SINGLE_COMMITTEE_ITERATIONS=100
THRESHOLD_COMMITTEE_ITERATIONS=3
THRESHOLD_COMMITTEE_SHAPES=3-of-5,11-of-15,34-of-50,67-of-100
SCALABILITY_LENGTHS=1,10,50,100,500,1000
ARTIFACT_DIR=artifacts
```

Example:

```bash
THRESHOLD_COMMITTEE_ITERATIONS=3 THRESHOLD_COMMITTEE_SHAPES=3-of-5,11-of-15 ./research/artifacts/reproduce-eval.sh
```

## Notes

- The threshold benchmark excludes one-time committee key generation and initial channel-open sharing from the reported per-transfer latency.
- Re-running the threshold benchmark overwrites `research/artifacts/threshold-committee-benchmark.csv` by default.
