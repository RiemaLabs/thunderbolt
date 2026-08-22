#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT_DIR="$ROOT_DIR/benchmarks/sp1-transfer-benchmark/script"
ARTIFACT_DIR="${ARTIFACT_DIR:-$ROOT_DIR/artifacts}"
ITERATIONS="${SP1_PROVE_ITERATIONS:-5}"
PAILLIER_BITS="${SP1_PAILLIER_BITS:-256}"
OUTPUT_PATH="${OUTPUT_PATH:-$ARTIFACT_DIR/sp1-proof-256bit-5iters.json}"

mkdir -p "$ARTIFACT_DIR"

cd "$SCRIPT_DIR"
export PROTOC
PROTOC="$(bash ../../ensure_protoc.sh)"

cargo run --quiet --release -- --prove --iterations "$ITERATIONS" --paillier-bits "$PAILLIER_BITS" --json > "$OUTPUT_PATH"

printf 'wrote %s\n' "$OUTPUT_PATH"
