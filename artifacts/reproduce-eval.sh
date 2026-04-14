#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

ARTIFACT_DIR="${ARTIFACT_DIR:-artifacts}"
SINGLE_COMMITTEE_ITERATIONS="${SINGLE_COMMITTEE_ITERATIONS:-100}"
THRESHOLD_COMMITTEE_ITERATIONS="${THRESHOLD_COMMITTEE_ITERATIONS:-1}"
THRESHOLD_COMMITTEE_SIZES="${THRESHOLD_COMMITTEE_SIZES:-6,12,18}"

cd "${REPO_ROOT}"
mkdir -p "${ARTIFACT_DIR}"

echo "[artifacts] generating single-committee benchmark output"
cargo run -p thunderbolt-mock --release --example single_committee_benchmark -- "${SINGLE_COMMITTEE_ITERATIONS}" \
  > "${ARTIFACT_DIR}/single-committee-benchmark.txt"

echo "[artifacts] generating threshold-committee benchmark output and csv"
cargo run -p thunderbolt-mock --release --example threshold_committee_benchmark -- "${THRESHOLD_COMMITTEE_ITERATIONS}" --sizes "${THRESHOLD_COMMITTEE_SIZES}" --csv "${ARTIFACT_DIR}/threshold-committee-benchmark.csv" \
  > "${ARTIFACT_DIR}/threshold-committee-benchmark.txt"

echo "[artifacts] done"
echo "[artifacts] wrote ${ARTIFACT_DIR}/single-committee-benchmark.txt"
echo "[artifacts] wrote ${ARTIFACT_DIR}/threshold-committee-benchmark.txt"
echo "[artifacts] wrote ${ARTIFACT_DIR}/threshold-committee-benchmark.csv"
