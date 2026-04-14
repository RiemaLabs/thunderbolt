# Evaluation Reproducibility Bundle

This directory is the reproducibility bundle for the experiments reported in
[latex/thunderbolt_ccs26/sections/eval.tex](/Users/hongbowen/code/thunderbolt-lib/latex/thunderbolt_ccs26/sections/eval.tex).

It follows a simple CCS-style artifact layout:

- `README.md`: claims, environment, commands, expected outputs
- `reproduce-eval.sh`: one-command regeneration of the checked-in benchmark outputs
- `single-committee-benchmark.txt`: raw stdout for the single-committee microbenchmark
- `threshold-committee-benchmark.txt`: raw stdout for the threshold-committee benchmark
- `threshold-committee-benchmark.csv`: machine-readable threshold benchmark results

## Claims Covered

These artifacts cover the concrete benchmark claims in `eval.tex`:

1. Per-stage microbenchmark of a single off-chain transfer
2. Threshold-committee benchmark over committee size and malicious fraction

The Lightning discussion in `eval.tex` is conceptual, and the SNARK section is a mixed measured/projected comparison. They are not part of the checked-in primary artifact outputs in this directory.

## Environment

Required:

- Rust toolchain with Cargo
- release builds enabled locally

Used on this machine:

- Apple M4
- macOS 15.3
- `rustc` 1.87-nightly

## One-Command Reproduction

From the repo root:

```bash
./artifacts/reproduce-eval.sh
```

This regenerates:

- `artifacts/single-committee-benchmark.txt`
- `artifacts/threshold-committee-benchmark.txt`
- `artifacts/threshold-committee-benchmark.csv`

## Exact Commands

Single-committee microbenchmark:

```bash
cargo run -p thunderbolt-mock --release --example single_committee_benchmark -- 100 > artifacts/single-committee-benchmark.txt
```

Threshold-committee benchmark:

```bash
cargo run -p thunderbolt-mock --release --example threshold_committee_benchmark -- 1 --sizes 6,12,18 > artifacts/threshold-committee-benchmark.txt
```

The threshold benchmark also writes the CSV artifact automatically to:

```text
artifacts/threshold-committee-benchmark.csv
```

## Optional Related Commands

These commands are relevant to the broader evaluation discussion in `eval.tex`, but
they are not part of the checked-in primary artifact outputs in this directory.

Local Lightning regtest:

```bash
python3 benchmarks/local-lightning-benchmark/run_benchmark.py --iterations 10 --json
```

SP1 comparison:

```bash
cargo run -p thunderbolt-mock --release --example compare_single_committee_transfer -- 1 --with-sp1
```

Standalone SP1:

```bash
cd benchmarks/sp1-transfer-benchmark/script
PROTOC=/tmp/protoc29/bin/protoc cargo run --release -- --execute --iterations 1
PROTOC=/tmp/protoc29/bin/protoc cargo run --release -- --prove --iterations 1 --json
```

## Expected Outputs

Single-committee output:

- Human-readable per-stage timings
- Includes average / min / max / total

Threshold benchmark output:

- Human-readable table with x-axis = committee size
- Three series = `0%`, `16.7%`, `33.3%` malicious members
- Two tables:
  - end-to-end total transfer latency
  - committee-completion latency

Threshold CSV output:

- One row per `(committee_size, malicious_fraction)` point
- Columns:
  - `committee_size`
  - `threshold`
  - `malicious_label`
  - `malicious_fraction`
  - `malicious_members`
  - `honest_members`
  - total-latency summary columns
  - committee-completion summary columns
  - `iterations`

## Tunable Knobs

The helper script supports environment-variable overrides:

```bash
SINGLE_COMMITTEE_ITERATIONS=100
THRESHOLD_COMMITTEE_ITERATIONS=1
THRESHOLD_COMMITTEE_SIZES=6,12,18
ARTIFACT_DIR=artifacts
```

Example:

```bash
THRESHOLD_COMMITTEE_ITERATIONS=3 THRESHOLD_COMMITTEE_SIZES=6,12 ./artifacts/reproduce-eval.sh
```

## Notes

- The threshold benchmark excludes one-time committee key generation and initial channel-open sharing from the reported per-transfer latency.
- Re-running the threshold benchmark overwrites `artifacts/threshold-committee-benchmark.csv` by default.
