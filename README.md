# Bitcoin Thunderbolt

Bitcoin Thunderbolt is the open source Rust implementation of Thunderbolt, a protocol for asynchronous off-chain transfer of Bitcoin UTXO ownership. A UTXO is locked once under a fixed public key shared by its current Holder and a Threshold Committee. Ownership can then pass between Holders without moving the UTXO on the Bitcoin Chain.

The paper "Thunderbolt: Fast Asynchronous Off-Chain Bitcoin Transfers" has been accepted to ACM CCS 2026. The paper was accepted, not this software product.

> Release status: `v1.0.0-rc.1`. Mainnet is disabled. This release includes the version 1 reference Ledger, a standalone version 2 Ledger contract and reducer, Holder and committee libraries, encrypted participant storage, and Bitcoin Core access. The runnable `thunderboltd` remains a version 1 single-node Ledger and does not configure a production verifier, role adapter, version 2 application, or consensus engine. There is no complete Open-to-Finalize deployment, Byzantine-fault-tolerant Ledger, or mainnet support. Do not use it with real funds.

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

`thunderbolt-cli` is a stateless operator tool. It reads the configured endpoint and bearer-token file, then calls the daemon's JSON API. `thunderboltd` accepts only `node.role = "ledger"` in this release. It does not construct a Holder engine, committee engine, Keystore, or Bitcoin Core client. The node library can accept an injected Trusted Verifier for Invoice and Transfer, but the shipped daemon has no configuration or CLI path that supplies one.

The repository now contains several libraries intended for those future role processes:

| Library | Current boundary |
| --- | --- |
| `thunderbolt-ledger` | Defines chain-scoped BIP340 `SignedProposalV2`, actor-derived participant IDs, executed-entry metadata, ordered Merkle proofs, and incremental application hashes. It proves deterministic execution, not consensus finality, and contains no network, database, ABCI server, quorum certificate, or durable request index. |
| `thunderbolt-protocol` v2 | Reduces authenticated version 2 entries at positive consensus time, supports a bounded concurrent Invoice set, consumes one selected Invoice by exact entry hash, and orders Finalize. Its Open, Invoice, Transfer, and Finalize proof hooks are abstract and have no production implementation. |
| `thunderbolt-holder` | Creates v1 single-committee and threshold Invoice packages and manages Holder credentials and Transfers. `KeystoreSecretVault` is a concrete encrypted adapter with exact checkpoint fencing and finalized-receipt pruning. It still has no daemon service, outbox, Ledger cursor, or trusted `DurableAcknowledgement` source. |
| `thunderbolt-committee` | Verifies the bound Recipient share, distribution, committed Transfer, and abstract Ledger receipt before a one-share update. `KeystoreCommitteeVault` is a concrete fenced adapter with finalized-history pruning. It still has no concrete quorum receipt, DKG, audited FROST signer, or role service. |
| `thunderbolt-verifier` | Verifies bounded Invoice and Transfer artifacts against trusted deployment and Ledger state. `thunderbolt-node` can inject it into the atomic append path. It does not verify Open, Finalize, actor signatures, or Bitcoin state. |
| `thunderbolt-keystore` | Provides encrypted multi-record transactions whose reads and outputs are fenced by an exact external checkpoint containing revision and encrypted-state digest. It has idempotent receipts, nonce tombstones, exact-checkpoint restore, and bounded pruning. The repository has no production `RollbackFloorStore`. |
| `thunderbolt-bitcoin` | Provides a bounded Bitcoin Core RPC client, network checks, reorganization-aware cursors, and funding and closing validators. It passed the official Bitcoin Core v31.1.0 live regtest, reorganization, and restart gate. It has no wallet or signing API and is not connected to the daemon. |

The version 2 libraries form a deterministic application contract. They are not connected to `thunderboltd`, and an `ExecutedBlockV2`, application hash, or Merkle inclusion proof is not evidence that validators reached consensus. A future CometBFT or equivalent integration must supply finality and persist the cross-block request index.

The separate version 1 `thunderbolt-storage` and `thunderbolt-node` path can verify evidence-free Invoice and Transfer proposals inside the same SQLite write transaction that selects the authoritative snapshot, pending Invoice, and Ledger time. The transaction persists the entry, evidence, snapshot, and retry mapping atomically. The shipped daemon starts without a Trusted Verifier, so normal event submission remains unavailable.

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
cargo build --locked --release
cargo test --workspace --all-features --locked --lib --bins --tests
```

The existing workspace contains:

```text
crates/
  thunderbolt-bitcoin/ Validated Bitcoin Core RPC and chain tracking library
  thunderbolt-ledger/  Signed proposal and executed-block contract for v2
  thunderbolt-holder/ Local Holder, Recipient, and threshold-Invoice engine
  thunderbolt-committee/ One-share committee member engine
  thunderbolt-verifier/ Trusted Invoice and Transfer verification bridge
  thunderbolt-keystore/ Transactional encrypted participant vault
  thunderbolt-core/    Proofs, Paillier operations, and public threshold
                       distribution primitives
  thunderbolt-protocol/ Version 1 and version 2 channel reducers
  thunderbolt-wire/    Version 1 proof messages and stable version 2 bindings
  thunderbolt-storage/ Atomic verified SQLite Ledger persistence
  thunderbolt-config/  Strict configuration and local token authorization
  thunderbolt-node/    Loopback Ledger API and Trusted Verifier injection
  thunderboltd/        Reference Ledger daemon
  thunderbolt-cli/     Operator control client
  bitcoin-utils/       Research-only legacy Bitcoin account utilities
  thunderbolt-eval/    Research benchmarks and regression harnesses
research/benchmarks/   Lightning, Groth16, and SP1 comparison harnesses
research/artifacts/    Published benchmark outputs and reproduction scripts
```

The default release build excludes `bitcoin-utils`, `thunderbolt-eval`, the old static two-key Taproot prototype, and the single-process committee fixture. Full workspace regression tests enable the research features explicitly so that those artifacts remain checked without entering release binaries.

## Quickstart

Build the release binaries, then initialize a no-clobber regtest instance:

```bash
cargo build --locked --release --package thunderboltd --package thunderbolt-cli

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

The Bitcoin backend has also passed the opt-in live gate against the official Bitcoin Core v31.1.0 release, including network and genesis checks, the exact 100-confirmation coinbase boundary, a one-block reorganization, and a graceful same-datadir restart. The harness is ignored and environment-gated, so this is measured release evidence rather than an automatic CI result. See [Testing](docs/testing.md).

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
- The current daemon uses authenticated loopback HTTP and the version 1 state machine. It has no configured production verifier, version 2 proposal or reducer path, ABCI service, quorum receipt, role service, or Bitcoin settlement path.
- The manual database backup is verified but not encrypted by the daemon. Protect it at the filesystem or volume layer.
- The RC wire codec enforces a 2048-bit Paillier modulus, while the accepted paper evaluates 3072-bit Paillier. The production parameter and wire version must be reconciled before mainnet approval.
- The Open ceremony still needs a reviewed DKG or provisioning protocol. Finalize still needs an `R_own` proof and audited combined-key Holder plus FROST signing under the fixed key `P`.
- Version 2 signed proposals and concurrent-Invoice reduction exist as standalone libraries. They have no durable cross-block request index, finality receipt, storage integration, or activation path in the shipped daemon.
- The concrete Holder and committee Keystore adapters require an independent authenticated rollback-checkpoint backend. Their retained histories still need compaction or epoch rotation for long-lived deployments.

The focused security milestone review found no unresolved Critical, High, or Medium code finding within the reviewed version 2 Ledger, reducer, Keystore, Holder-adapter, and committee-adapter boundaries at `6ca2c42`. This is not a system audit or production approval. See [Security milestone](docs/security-milestone-2026-08-21.md).

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
| [Ledger v2 contract](crates/thunderbolt-ledger/README.md) | Signed proposals, executed blocks, application hashes, Merkle proofs, and finality boundary |
| [Protocol v2 migration](crates/thunderbolt-protocol/docs/v2-migration.md) | Separate-history rules, concurrent Invoices, consensus time, and reducer limits |
| [Release process](docs/release-process.md) | RC policy, verification, signing, and promotion gates |
| [Production roadmap](docs/roadmap.md) | Protocol v2, multi-process regtest, cryptographic, and Ledger gates |
| [Testing](docs/testing.md) | Automated checks and the measured Bitcoin Core v31.1.0 live gate |
| [Security milestone](docs/security-milestone-2026-08-21.md) | Scoped review result, resolved items, and remaining production blockers |
| [Publication checklist](docs/publication-checklist.md) | Legal, security, history, and repository publication gates |
| [History sanitization](docs/history-sanitization.md) | Known historical secrets and generated build artifacts that must be removed before publication |
| [Core ZKP](CORE_ZKP.md) | Mathematical specification of the proof construction |
| [Research artifacts](research/artifacts/README.md) | Paper benchmark reproduction |

## Contributing

Start with [CONTRIBUTING.md](CONTRIBUTING.md), [GOVERNANCE.md](GOVERNANCE.md), and the [Code of Conduct](CODE_OF_CONDUCT.md). Protocol, cryptography, persistence, and signing changes need focused review and tests for invalid as well as valid inputs.

General questions and bug reports belong in the repository's public issues. Security reports follow [SECURITY.md](SECURITY.md).

## License

Bitcoin Thunderbolt is licensed under the [Apache License 2.0](LICENSE). See [NOTICE](NOTICE) for project and third-party attributions.
