# Testing

Bitcoin Thunderbolt separates automatic source checks, research regression coverage, and live dependency gates. A passing library test does not establish a complete protocol deployment.

## Automatic checks

The main CI workflow runs formatting, strict Clippy, workspace tests, and documentation tests with the locked dependency graph. It enables all features so legacy research code remains checked.

Release binaries use a narrower build:

```bash
cargo build --locked --release --package thunderboltd --package thunderbolt-cli
```

That build does not enable `legacy-research`, `insecure-regression`, or `insecure-regtest`. It excludes `bitcoin-utils`, `thunderbolt-eval`, the old static two-key settlement prototype, and the single-process committee dealer from the release binaries.

## Bitcoin Core v31.1.0 live gate

The current release evidence includes a passing run against the official Bitcoin Core v31.1.0 binary. Before the run, the archive SHA256 matched the published checksum. Verification of `SHA256SUMS.asc` reported 11 valid and 0 bad signatures.

The test used a disposable regtest datadir with zero peers. It checked:

- rejection of the wrong Bitcoin network
- exact regtest genesis and chain-cursor synchronization
- raw transaction identity and a mined coinbase UTXO
- rejection below the 100-confirmation coinbase maturity boundary and acceptance at exactly 100
- invalidation and disconnect of one tip block
- mining and connection of a distinct replacement block
- persistence of the funding UTXO through the reorganization
- graceful Bitcoin Core shutdown and restart with the same datadir
- a complete rerun of the backend contract after restart

The final chain height was 101. Cleanup left zero Bitcoin Core processes and zero temporary datadirs.

This is measured release evidence. It is not an automatic CI guarantee. The repository test is marked ignored, requires explicit environment variables, and does not download or pin the Bitcoin Core binary itself. See [`live_regtest.rs`](../crates/thunderbolt-bitcoin/tests/live_regtest.rs).

## Running the opt-in harness

The caller must provide an isolated Bitcoin Core regtest, a mature unspent coinbase output outside the block that will be invalidated, and these variables:

```text
THUNDERBOLT_BITCOIN_LIVE_RPC_URL
THUNDERBOLT_BITCOIN_LIVE_COOKIE
THUNDERBOLT_BITCOIN_LIVE_TXID
THUNDERBOLT_BITCOIN_LIVE_VOUT
THUNDERBOLT_BITCOIN_LIVE_BITCOIN_CLI
THUNDERBOLT_BITCOIN_LIVE_DATADIR
THUNDERBOLT_BITCOIN_LIVE_MINING_ADDRESS
```

Run the ignored test only against the disposable datadir:

```bash
cargo test --locked --package thunderbolt-bitcoin \
  --test live_regtest live_regtest_backend_contract_and_reorg \
  -- --ignored --exact
```

The Rust test performs network, cursor, UTXO, maturity, and reorganization checks. The release gate wraps it with verified binary setup, graceful restart, a second complete run, and final process and directory cleanup.

## Remaining integration tests

The repository still lacks a multi-process test with two Holders, three independent committee members, the Ledger, and Bitcoin Core. That gate must exercise durable outboxes and cursors, lost acknowledgements, duplicate delivery, quorum loss, role restarts, and the Open-to-Finalize settlement path. Open and Finalize cannot pass faithfully until the DKG, `R_own`, and combined-key FROST designs are implemented.
