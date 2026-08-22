# SP1 single-transfer benchmark

This benchmark measures a general-purpose zkVM proof for the same *transfer-step semantics*
as the specialized single-committee Thunderbolt benchmark:

- holder update: `x_{s+1} = x_s + r_s`
- committee update: `y_{s+1} = y_s - r_s`
- invariant preservation: `x_{s+1} + y_{s+1} = x_s + y_s`

It does **not** model Paillier ciphertext arithmetic or the specialized Sigma/Fiat–Shamir proof
objects byte-for-byte. Instead, it measures a general-purpose proof of the same transfer relation.

## Run

```bash
cd benchmarks/sp1-transfer-benchmark/script
cargo run --release -- --execute --iterations 1
cargo run --release -- --prove --iterations 1 --json
```

If your local `protoc` is broken, set `PROTOC` to a working binary before running.
