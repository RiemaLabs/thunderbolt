# Bitcoin Thunderbolt

Bitcoin Thunderbolt is the open source Rust implementation of Thunderbolt, a protocol for asynchronous off-chain transfer of Bitcoin UTXO ownership. A UTXO is locked once under a fixed public key shared by its current Holder and a Threshold Committee. Ownership can then pass between Holders without moving the UTXO on the Bitcoin Chain.

The paper "Thunderbolt: Fast Asynchronous Off-Chain Bitcoin Transfers" has been accepted to ACM CCS 2026. The paper was accepted, not this software product.

> Release status: `v1.0.0-rc.1`. Mainnet is disabled. This release includes the cryptographic core, versioned public messages, a deterministic Ledger state machine, durable SQLite storage, and a runnable Ledger daemon with a control CLI. It does not include Holder or committee runtimes, production proof verification, a Byzantine-fault-tolerant Thunderbolt Ledger, metrics, or Bitcoin settlement. Do not use it with real funds.

## Why Thunderbolt

Thunderbolt is built for a different transfer model from the Lightning Network:

- The recipient does not need to be online at the same time as the current Holder.
- A transfer does not need a routed channel graph or a capacity-sufficient path.
- The same fixed-denomination UTXO can pass through an unbounded sequence of Holders.
- The Bitcoin Chain sees channel Open and Finalize transactions, not each ownership transfer.

Bitcoin Thunderbolt follows the proven operator shape of Lightning implementations: a long-running daemon owns state and keys, while a thin client controls it through an authenticated local interface. Thunderbolt does not implement the Lightning BOLT specifications and is not wire-compatible with Lightning nodes.

## Roles

| Role | Responsibility |
| --- | --- |
| Holder | Controls the current off-chain ownership secret. The Holder can transfer ownership or request Finalize. |
| Recipient | Creates an invoice with a fresh secret. After a valid transfer and committee update, the Recipient becomes the next Holder. |
| Threshold Committee | Holds the complementary share of the fixed lock key. At least `t` of `n` members update their shares and participate in finalization. |
| Thunderbolt Ledger | Commits authenticated protocol entries in an append-only, per-channel order and makes them available to participants. It holds no Holder or committee secret. |
| Bitcoin Chain | Acts as the settlement layer for Open and Finalize. It does not process the intermediate ownership transfers. |

The paper assumes that at most `t - 1` committee members are corrupted and that at least `t` honest members remain responsive. The Thunderbolt Ledger must provide append-only persistence, a single order for each channel, and eventual inclusion and retrieval of valid entries.

## Architecture

The runnable RC is a single reference Ledger service:

```text
operator
   |
thunderbolt-cli
   |
authenticated loopback HTTP, port 19736 by default
   |
thunderboltd, Ledger role
   |
durable SQLite event log and channel snapshots
```

`thunderbolt-cli` is a stateless operator tool. It reads the configured endpoint and bearer-token file, then calls the daemon's JSON API. `thunderboltd` accepts only `node.role = "ledger"` in this release. Holder and committee participants remain clients; their independent runtimes and the Bitcoin Core connection are target work.

See [Architecture](docs/architecture.md) for component boundaries and the current implementation gap.

## Channel lifecycle

1. Open: the initial Holder and Threshold Committee derive the combined lock key and fund a Taproot UTXO on the Bitcoin Chain.
2. Invoice: the Recipient publishes a fresh public delta, encrypted copies of the refresh secret, and an Invoice Consistency Proof to the Thunderbolt Ledger.
3. Transfer: the current Holder verifies the invoice, creates the next ownership credential, updates the public anchor, and publishes a Transfer Consistency Proof.
4. Committee update: committee members verify the committed entries and update their shares. The Recipient decrypts the credential and becomes the next Holder.
5. Finalize: the current Holder proves ownership and joins at least `t` committee members to authorize the closing transaction on the Bitcoin Chain.

Steps 2 through 4 may repeat without touching the Bitcoin Chain.

## Build and test the current tree

The repository pins its Rust toolchain in [`rust-toolchain`](rust-toolchain).

```bash
cargo build --workspace --release
cargo test --workspace
```

The existing workspace contains:

```text
crates/
  thunderbolt-core/    Proofs, Paillier operations, threshold primitives,
                       and Bitcoin transaction building blocks
  thunderbolt-protocol/ Deterministic Ledger entries and channel reducer
  thunderbolt-wire/    Bounded, versioned public proof-message encoding
  thunderbolt-storage/ Durable SQLite Ledger entries and channel snapshots
  thunderbolt-config/  Strict configuration and local token authorization
  thunderbolt-node/    Loopback JSON API and Ledger service runtime
  thunderboltd/        Reference Ledger daemon
  thunderbolt-cli/     Operator control client
  bitcoin-utils/       Bitcoin key, address, and account utilities
  thunderbolt-eval/    Research benchmarks and regression harnesses
research/benchmarks/   Lightning, Groth16, and SP1 comparison harnesses
research/artifacts/    Published benchmark outputs and reproduction scripts
```

The research harness is useful for regression testing, but it is not a deployable multi-process network.

## Quickstart

Build the release binaries, then initialize a no-clobber regtest instance:

```bash
cargo build --workspace --release

./target/release/thunderboltd \
  --config ./thunderbolt.toml \
  init --data-dir ./data --node-id thunderbolt-node

./target/release/thunderboltd --config ./thunderbolt.toml check
./target/release/thunderboltd \
  --config ./thunderbolt.toml \
  start --log-format pretty
```

The last command stays in the foreground. In another terminal:

```bash
./target/release/thunderbolt-cli --config ./thunderbolt.toml health --ready
./target/release/thunderbolt-cli --config ./thunderbolt.toml getinfo
./target/release/thunderbolt-cli --config ./thunderbolt.toml config show
./target/release/thunderbolt-cli --config ./thunderbolt.toml channel list
./target/release/thunderbolt-cli --config ./thunderbolt.toml database integrity
./target/release/thunderbolt-cli --config ./thunderbolt.toml database backup
./target/release/thunderbolt-cli --config ./thunderbolt.toml stop
```

Event submission fails closed because no production proof verifier is wired into the daemon. For a state-machine demonstration on development regtest only, start with `--development-allow-unverified-demo-events`. The daemon rejects client-supplied verification evidence and marks its own synthetic attestations as unverified demo data.

The container demo uses that explicit development mode:

```bash
make regtest-up

docker compose --file deploy/regtest/compose.yaml exec -T thunderboltd \
  thunderbolt-cli \
  --config /etc/bitcoin-thunderbolt/thunderbolt.toml \
  health --ready

make regtest-down
```

The container does not run Bitcoin Core, Holder software, or committee nodes. It exercises the Ledger API and storage path only.

For a hardened service wrapper and signet example, see [`thunderboltd.service`](deploy/systemd/thunderboltd.service), [`thunderbolt.sysusers`](deploy/systemd/thunderbolt.sysusers), and the [systemd configuration](deploy/systemd/thunderbolt.toml). These assets package the same reference Ledger and do not turn it into a production protocol deployment.

## Security and limitations

This RC is a protocol implementation under active hardening. It has not completed an external security audit and is not approved for mainnet funds.

Important limits:

- Finalization depends on a responsive threshold of committee members.
- The unilateral-exit and off-chain splitting overlays discussed in the paper are not implemented.
- Transfers cover ownership of a whole locked UTXO. They are not routed Lightning payments.
- The base design does not promise transaction unlinkability.
- A production Ledger must satisfy the paper's persistence, ordering, inclusion, and data-availability guarantees under the stated committee fault bound.
- Safe operation also depends on durable encrypted state, correct backups, Bitcoin reorganization handling, nonce safety, authenticated transport, and operator discipline. These controls are release gates, not assumptions that may be skipped.
- The current daemon uses authenticated loopback HTTP. The configured Unix socket path is reserved but not listened on. Remote control, metrics, Holder and committee runtimes, and Bitcoin settlement remain target work.
- The manual database backup is verified but not encrypted by the daemon. Protect it at the filesystem or volume layer.
- The RC wire codec enforces a 2048-bit Paillier modulus, while the accepted paper evaluates 3072-bit Paillier. The production parameter and wire version must be reconciled before mainnet approval.

Read [Security](docs/security.md), [Threat model](docs/threat-model.md), and [SECURITY.md](SECURITY.md) before testing a deployment. Report suspected vulnerabilities privately. Do not open a public issue for a security report.

## Documentation

| Document | Purpose |
| --- | --- |
| [Architecture](docs/architecture.md) | Roles, processes, trust boundaries, and planned deployment shape |
| [Operator guide](docs/operator-guide.md) | Safe setup, operation, monitoring, backup, and recovery |
| [Configuration](docs/configuration.md) | Configuration sources, secure defaults, and target schema |
| [Security](docs/security.md) | Operational controls and mainnet gates |
| [Threat model](docs/threat-model.md) | Assets, adversaries, assumptions, guarantees, and exclusions |
| [API](docs/api.md) | Control API, Ledger events, idempotency, and versioning |
| [Release process](docs/release-process.md) | RC policy, verification, signing, and promotion gates |
| [Publication checklist](docs/publication-checklist.md) | Legal, security, history, and repository publication gates |
| [History sanitization](docs/history-sanitization.md) | Known historical secrets and generated build artifacts that must be removed before publication |
| [Core ZKP](CORE_ZKP.md) | Mathematical specification of the proof construction |
| [Research artifacts](research/artifacts/README.md) | Paper benchmark reproduction |

## Contributing

Start with [CONTRIBUTING.md](CONTRIBUTING.md), [GOVERNANCE.md](GOVERNANCE.md), and the [Code of Conduct](CODE_OF_CONDUCT.md). Protocol, cryptography, persistence, and signing changes need focused review and tests for invalid as well as valid inputs.

General questions and bug reports belong in the repository's public issues. Security reports follow [SECURITY.md](SECURITY.md).

## License

Bitcoin Thunderbolt is licensed under the [Apache License 2.0](LICENSE). See [NOTICE](NOTICE) for project and third-party attributions.
