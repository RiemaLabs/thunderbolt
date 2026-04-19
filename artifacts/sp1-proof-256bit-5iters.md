# SP1 256-bit Proof Benchmark Artifact

This file records the local SP1 proving measurement used by the paper's RQ4 discussion.

## Measurement

- measured at: `2026-04-19 03:59:14 PDT`
- benchmark: `benchmarks/sp1-transfer-benchmark/script`
- mode: `--prove`
- iterations: `5`
- Paillier bits: `256`
- raw result: `artifacts/sp1-proof-256bit-5iters.json`
- reproduction script: `artifacts/reproduce-sp1-proof-256bit.sh`

## Summary

- prove average: `54.557137008400005 s`
- prove min: `52.660283875 s`
- prove max: `56.320994708 s`
- verify average: `0.06711705 s`
- total average: `55.233627175 s`

## Exact Command

Run from the repo root:

```bash
./artifacts/reproduce-sp1-proof-256bit.sh
```

Equivalent manual command:

```bash
cd benchmarks/sp1-transfer-benchmark/script
PROTOC="$(bash ../../ensure_protoc.sh)" cargo run --quiet --release -- --prove --iterations 5 --paillier-bits 256 --json > ../../../artifacts/sp1-proof-256bit-5iters.json
```

## Environment

- repo HEAD: `4c4bed8409d86f100244ae08f83d36c3505513b7`
- host: `aarch64-apple-darwin`
- rustc: `1.90.0 (1159e78c4 2025-09-14)`
- macOS: `15.2 (24C101)`

## Source Fingerprints

These hashes identify the exact SP1 benchmark sources present in the workspace at measurement time.

```text
cf0304a5fb9b0f807f6dbf2790b3910b24580067da23f7e7c6365f521a339cad  benchmarks/sp1-transfer-benchmark/Cargo.toml
20e432ac4cb964153ed1c19d95d6dddd591fcb0566c9c62d934b806f0bf1f2eb  benchmarks/sp1-transfer-benchmark/lib/Cargo.toml
b376c328a99703625a970c84581407753c524057c31031b61132ab9256ee270c  benchmarks/sp1-transfer-benchmark/lib/src/lib.rs
3dfbddd50f7fb7b02963f5510ff211b89ef3a8cdf51e693c9d76d2c63eea7814  benchmarks/sp1-transfer-benchmark/program/Cargo.toml
8d371841390335fe77186253adde4a5d5a57fe17a385543173489b09f1b418aa  benchmarks/sp1-transfer-benchmark/program/src/main.rs
5a1cec82d5f6c8b0adaaf31e7dab123c520a5019cdb05199b777704cd0bd4e75  benchmarks/sp1-transfer-benchmark/script/Cargo.toml
f522499ea43d0eaa8e1a6e2c9eadcf0f55797631dbfa3e6ffddad13e96beb51d  benchmarks/sp1-transfer-benchmark/script/src/bin/main.rs
```

## Notes

- The paper uses this reduced-parameter 256-bit SP1 setup as the final RQ4 measurement.
- The workspace was dirty at measurement time. The hashes above pin the exact benchmark-source state that produced this artifact.
- Re-running the script overwrites the JSON artifact by default.
