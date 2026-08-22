# Testing

## Standard checks

Run the locked workspace checks from the repository root:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --all-features --locked --no-deps
cargo test --workspace --all-features --locked --lib --bins --tests
```

Release packages also run dependency, license, secret, provenance, and software-bill-of-materials checks.

## Test layers

Package tests cover:

- canonical codecs and maximum-size boundaries
- signatures, proof statements, and wrong-context rejection
- deterministic block execution and application hashes
- SQLite commit, restart, corruption, and replay behavior
- outbox, cursor, and first-occurrence reconciliation
- rollback-floor compare-and-swap and history compaction
- CometBFT header, validator, witness, source-rotation, and checkpoint handling
- local control deadlines, cancellation, request replay, and shutdown

Property tests generate malformed inputs, alternate signatures, reordered entries, copied state, boundary sizes, and arbitrary codec bytes.

## CometBFT interoperability

The opt-in CometBFT harness uses the signed upstream v0.38.25 release with four validators and four independent application databases. It checks deterministic application hashes, invalid transactions, crash-before-commit replay, application restart, validator restart, exact height progression, and process cleanup.

The harness is feature-gated and ignored in the normal unit-test run because it starts external processes.

## Bitcoin Core interoperability

The Bitcoin harness runs against the official Bitcoin Core v31.1.0 regtest binary. It covers network and genesis checks, transaction retrieval, coinbase maturity, confirmation policy, a one-block reorganization, replacement history, and same-datadir restart.

Run external harnesses only with the exact pinned releases and isolated temporary directories. Do not point them at an operator wallet or data directory.

## Release topology

The full release gate starts Bitcoin Core, the Ledger validator set, the rollback floor, two Holders, and independent committee members. It executes Open, Invoice, Transfer, committee update, repeated ownership transfer, and Finalize while injecting process restarts and ambiguous network outcomes.

A release is not promoted on package tests alone. The packaged binaries and example configuration must pass the same topology from a clean installation.
