# Bitcoin Thunderbolt

Bitcoin Thunderbolt is an open source protocol for asynchronous off-chain transfers of Bitcoin UTXO ownership. A Bitcoin UTXO is locked once under a fixed public key shared by its current Holder and a Threshold Committee. Ownership can then move between Holders without an on-chain transaction for every transfer.

Thunderbolt lets the sender and recipient complete a transfer at different times.

## Release status

The `release/1.0` branch is the active release candidate. Regtest and signet are the supported deployment targets during the RC. Mainnet activation will follow the remaining signing and settlement integration and an external security audit.

## Roles

| Role | Responsibility |
| --- | --- |
| Holder | Controls the current ownership secret, creates transfers, and can request final settlement. |
| Recipient | Creates an invoice with a fresh secret and becomes the next Holder after a valid transfer and committee update. |
| Committee member | Holds one share of the fixed lock key, verifies committed transfers, updates its share, and participates in settlement. |
| Thunderbolt Ledger | Orders authenticated protocol entries, persists channel state, and makes committed entries available to participants. Participant secrets remain with Holders and committee members. |
| Bitcoin Core | Provides funding, confirmation, reorganization, and settlement data for the Bitcoin UTXO. |

Each Holder, committee member, and Ledger validator runs as a separate process with its own state and credentials. A thin local CLI talks to the daemon through an owner-only Unix socket.

## Architecture

```text
                               Bitcoin Core
                                    |
                                    |
Holder daemon  <---->  Thunderbolt Ledger  <---->  Committee daemons
     |                    CometBFT                     |
     |                                                |
encrypted vault                              encrypted share vaults
     |                                                |
     +---------- externally anchored rollback floor --+
```

The Ledger application is deterministic and runs behind CometBFT. Clients verify finality before issuing capabilities to Holder or committee code. Participant state is encrypted locally and fenced by an independently anchored rollback floor. Administrative control stays on a local Unix socket and is separate from protocol traffic.

The protocol lifecycle is:

1. Open a channel by funding a Taproot UTXO under the combined Holder and committee key.
2. The Recipient publishes an invoice with a fresh public delta and encrypted refresh material.
3. The current Holder verifies the invoice and publishes the transfer.
4. Committee members verify the committed entries and update their shares.
5. The Recipient decrypts the new credential and becomes the Holder.
6. The current Holder and a committee quorum can finalize the channel on Bitcoin.

Steps 2 through 5 repeat off-chain.

## Repository layout

| Component | Purpose |
| --- | --- |
| `thunderboltd` | Role-aware daemon and local operator control plane |
| `thunderbolt-cli` | Local operator client |
| `thunderbolt-holder-node` | Durable Holder service, outbox, and Ledger cursor |
| `thunderbolt-committee-node` | Durable committee service and compact finalized evidence |
| `thunderbolt-ledger-app` | Crash-safe Ledger application and request index |
| `thunderbolt-ledger-abci` | ABCI adapter for the Ledger application |
| `thunderbolt-abci-server` | Bounded local ABCI server for CometBFT |
| `thunderbolt-cometbft-*` | Authenticated RPC, light-client finality, and durable coordination |
| `thunderbolt-floor-*` | Signed rollback-floor application, proofs, and ABCI integration |
| `thunderbolt-runtime-config` | Strict role configuration and deployment identity checks |
| `thunderbolt-keystore` | Encrypted participant records and crash-safe state transitions |
| `thunderbolt-bitcoin` | Bitcoin Core RPC, chain tracking, funding, and settlement validation |
| `thunderbolt-core`, `thunderbolt-protocol`, `thunderbolt-wire` | Cryptography, state transitions, and bounded public messages |
| `research/` | Paper benchmarks and reproducibility artifacts |

## Build

The repository pins its Rust toolchain in [`rust-toolchain`](rust-toolchain).

```bash
cargo build --locked --release
cargo test --workspace --all-features --locked --lib --bins --tests
```

Build only the operator binaries with:

```bash
cargo build --locked --release \
  --package thunderboltd \
  --package thunderbolt-cli
```

## Run the operator shell

Thunderbolt uses one owner-only TOML configuration per process. Examples for the Ledger, Holder, and committee roles are in [`crates/thunderbolt-runtime-config/examples`](crates/thunderbolt-runtime-config/examples). Replace the example paths and public manifest hashes with the files provisioned for your deployment.

Validate the configuration before starting:

```bash
thunderboltd --config /var/lib/thunderbolt/runtime.toml check
thunderboltd --config /var/lib/thunderbolt/runtime.toml start
```

Use the local CLI from the same operating-system account:

```bash
thunderbolt-cli --config /var/lib/thunderbolt/runtime.toml status
thunderbolt-cli --config /var/lib/thunderbolt/runtime.toml blockers
thunderbolt-cli --config /var/lib/thunderbolt/runtime.toml redacted-config
thunderbolt-cli --config /var/lib/thunderbolt/runtime.toml drain
thunderbolt-cli --config /var/lib/thunderbolt/runtime.toml stop
```

See the [operator guide](docs/operator-guide.md) for provisioning, process supervision, recovery, and regtest instructions.

## Security

Please report vulnerabilities through GitHub private vulnerability reporting. Do not open a public issue for a security report. See [SECURITY.md](SECURITY.md) for scope and response details.

## Documentation

| Document | Purpose |
| --- | --- |
| [Architecture](docs/architecture.md) | Roles, processes, data flow, and trust boundaries |
| [Operator guide](docs/operator-guide.md) | Setup, operation, recovery, and monitoring |
| [Configuration](docs/configuration.md) | Configuration schema and deployment checks |
| [API](docs/api.md) | Local control and protocol interfaces |
| [Security](docs/security.md) | Operational security controls |
| [Threat model](docs/threat-model.md) | Assets, adversaries, assumptions, and guarantees |
| [Testing](docs/testing.md) | Automated and live integration tests |
| [Release process](docs/release-process.md) | Release construction and verification |
| [Roadmap](docs/roadmap.md) | Remaining work toward mainnet activation |
| [Research artifacts](research/artifacts/README.md) | Paper benchmark reproduction |

## Contributing

Read [CONTRIBUTING.md](CONTRIBUTING.md), [GOVERNANCE.md](GOVERNANCE.md), and the [Code of Conduct](CODE_OF_CONDUCT.md) before opening a pull request. Protocol, cryptography, persistence, and signing changes need tests for invalid inputs as well as the expected flow.

## License

Bitcoin Thunderbolt is licensed under the [Apache License 2.0](LICENSE). See [NOTICE](NOTICE) for project and third-party attributions.

## Citation

If you use Bitcoin Thunderbolt in academic work, please cite the protocol paper:

```bibtex
@inproceedings{wen2026thunderbolt,
  author    = {Hongbo Wen and Hanzhi Liu and Yanju Chen and Jingyu Ke and Dahlia Malkhi and Yu Feng},
  title     = {Thunderbolt: Fast Asynchronous Off-Chain Bitcoin Transfers},
  booktitle = {Proceedings of the 2026 ACM Conference on Computer and Communications Security},
  year      = {2026}
}
```
