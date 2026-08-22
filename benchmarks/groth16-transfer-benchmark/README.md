# Groth16 single-transfer benchmark

This benchmark measures a real Groth16 proof for the same simplified
transfer-step semantics used by the SP1 comparison benchmark:

- holder update: `x_{s+1} = x_s + r_s`
- committee update: `y_{s+1} = y_s - r_s`
- invariant preservation: `x_{s+1} + y_{s+1} = x_s + y_s`

It is still a simplification of the full Thunderbolt relations: it does not
encode Paillier ciphertext arithmetic or the native Sigma proofs byte-for-byte.
The purpose is to provide real local Groth16 prove/verify data for the same
semantic transfer relation already used in the SP1 benchmark.

## Run

```bash
cd benchmarks/groth16-transfer-benchmark/script
cargo run --release -- --iterations 1
cargo run --release -- --iterations 1 --json
```
