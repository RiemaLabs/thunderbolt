# SP1 single-transfer benchmark

This benchmark measures a general-purpose zkVM proof of the Thunderbolt invoice/transfer
Paillier verification equations under a reduced Paillier modulus parameter.

It preserves the same proof structure as the Thunderbolt consistency checks, but intentionally
uses a much smaller modulus than the paper's 3072-bit deployment setting. The paper's final RQ4
artifact uses `--paillier-bits 256`; larger moduli were not feasible for local proving on the
evaluation machine due to memory pressure and substantially longer proving time.

## Run

```bash
cd benchmarks/sp1-transfer-benchmark/script
bash ../../ensure_protoc.sh >/dev/null
PROTOC="$(bash ../../ensure_protoc.sh)" cargo run --release -- --prove --iterations 5 --paillier-bits 256 --json
```

The helper script downloads a repo-local official `protoc` binary into `benchmarks/.tools/`
if you do not already have a working one.
