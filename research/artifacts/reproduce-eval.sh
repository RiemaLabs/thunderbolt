#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

ARTIFACT_DIR="${ARTIFACT_DIR:-${SCRIPT_DIR}}"
SINGLE_COMMITTEE_ITERATIONS="${SINGLE_COMMITTEE_ITERATIONS:-100}"
THRESHOLD_COMMITTEE_ITERATIONS="${THRESHOLD_COMMITTEE_ITERATIONS:-3}"
THRESHOLD_COMMITTEE_SHAPES="${THRESHOLD_COMMITTEE_SHAPES:-3-of-5,11-of-15,34-of-50,67-of-100}"
THRESHOLD_COMMITTEE_FANOUT="${THRESHOLD_COMMITTEE_FANOUT:-4}"

SCALABILITY_LENGTHS="${SCALABILITY_LENGTHS:-1,10,50,100,500,1000}"

cd "${REPO_ROOT}"
mkdir -p "${ARTIFACT_DIR}"

echo "[artifacts] generating single-committee benchmark output"
cargo run -p thunderbolt-mock --release --example single_committee_benchmark -- "${SINGLE_COMMITTEE_ITERATIONS}" \
  > "${ARTIFACT_DIR}/single-committee-benchmark.txt"

echo "[artifacts] generating scalability benchmark output and csv"
cargo run -p thunderbolt-mock --release --example scalability_benchmark -- --lengths "${SCALABILITY_LENGTHS}" --csv "${ARTIFACT_DIR}/scalability-benchmark.csv" \
  | tee "${ARTIFACT_DIR}/scalability-benchmark.txt"

echo "[artifacts] generating threshold-committee benchmark output and csv"
cargo run -p thunderbolt-mock --release --example threshold_committee_benchmark -- "${THRESHOLD_COMMITTEE_ITERATIONS}" --shapes "${THRESHOLD_COMMITTEE_SHAPES}" --fanout "${THRESHOLD_COMMITTEE_FANOUT}" --csv "${ARTIFACT_DIR}/threshold-committee-benchmark.csv" \
  > "${ARTIFACT_DIR}/threshold-committee-benchmark.txt"

echo "[artifacts] done"
echo "[artifacts] wrote ${ARTIFACT_DIR}/single-committee-benchmark.txt"
echo "[artifacts] wrote ${ARTIFACT_DIR}/scalability-benchmark.txt"
echo "[artifacts] wrote ${ARTIFACT_DIR}/scalability-benchmark.csv"
echo "[artifacts] wrote ${ARTIFACT_DIR}/threshold-committee-benchmark.txt"
echo "[artifacts] wrote ${ARTIFACT_DIR}/threshold-committee-benchmark.csv"
