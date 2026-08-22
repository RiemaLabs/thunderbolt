# Architecture

Bitcoin Thunderbolt uses a daemon and client layout familiar to Lightning node operators, but its protocol model is different. Thunderbolt transfers ownership of a fixed UTXO through a Threshold Committee and a shared Ledger. It does not route payments through a peer graph.

This document distinguishes the runnable `v1.0.0-rc.1` reference Ledger from the full protocol runtime. A component marked target is a release requirement, not a claim about the current daemon.

## Protocol roles

Holder
: The party that knows the current Holder secret. The role moves from one user to the next after a valid transfer.

Recipient
: The prospective next Holder. The Recipient creates an invoice and can retrieve the transfer credential later, so the current Holder and Recipient do not need to be online together.

Threshold Committee
: A set of `n` independent operators. Each operator holds one share of the complementary lock-key secret. At least `t` members must update their shares and participate in finalization.

Thunderbolt Ledger
: A shared append-only service. It orders entries within each channel and makes committed entries available. The Ledger authenticates entries but holds no Holder or committee secret.

Bitcoin Chain
: The settlement layer. The base protocol opens and finalizes a channel on chain while ownership transfers remain off chain.

## Current process layout

```text
operator
   |
thunderbolt-cli
   |
bearer-authenticated loopback HTTP, port 19736 by default
   |
thunderboltd, Ledger role only
   |
SQLite immutable events and materialized channel snapshots
```

### `thunderbolt-cli`

The client is a thin, stateless operator interface. It reads the endpoint and bearer-token file from configuration, sends JSON API requests, and prints structured results. It does not read the SQLite database directly.

### `thunderboltd`

The current daemon runs only the reference Ledger. Runtime validation requires `node.role = "ledger"` and rejects Holder or committee roles. It provides health, redacted configuration, channel and event reads, gated development event submission, database integrity, verified manual backup, and graceful stop.

The target runtime adds separate role processes:

- Wallet mode manages Holder secrets, invoices, transfers, channel state, and finalization requests.
- Committee mode stores one committee share, verifies committed events, applies refresh shares, and joins threshold signing.
- Ledger replicas provide an append-only event service under the production fault model.

The reference Ledger does not satisfy the paper's Byzantine fault model. A production committee must keep one share per independently administered instance, and the production Ledger must establish its ordering and availability guarantees independently.

## Landed library boundaries

The workspace contains role libraries, but no executable composes them into a Thunderbolt network yet.

`thunderbolt-holder`
: A local Holder and Recipient state engine. It creates the v1 single-committee Invoice and threshold Recipient-share plus VESS package, retains credentials after Transfer, and checks committed acknowledgements. `KeystoreSecretVault` is a concrete encrypted implementation of the engine's transactional vault with exact-checkpoint fencing and externally finalized receipt pruning. It has no network client, outbox, Ledger cursor, service loop, or trusted source for the public `DurableAcknowledgement` capability.

`thunderbolt-committee`
: A one-share committee member engine. It verifies the Recipient-share proof, its exact distribution binding, the committed Transfer, and an abstract Ledger receipt before updating its local Shamir share. `KeystoreCommitteeVault` stores engine and signing-session state through exact-checkpoint fenced transactions and can prune externally finalized receipts and idempotency records. The crate has no production rollback-floor backend, concrete quorum receipt, DKG, FROST aggregation, or Finalize path under `P`.

`thunderbolt-verifier`
: A narrow bridge from bounded public Invoice and Transfer artifacts to trusted verification evidence. It checks deployment, committee, channel, invoice, step, and prior-Ledger bindings. `thunderbolt-node` can inject it into the transaction-scoped append path. The shipped daemon does not supply one, and the verifier has no Open, Finalize, actor-signature, or Bitcoin policy implementation.

`thunderbolt-keystore`
: An encrypted transactional multi-record vault. `VaultCheckpoint` combines the revision with a digest of the exact encrypted file, so equal-revision forks differ. `RollbackFloorStore` provides atomic checkpoint CAS; all secret reads and callback outputs remain fenced until the checkpoint is anchored. Exact anchored backups can be restored, finalized receipts can be pruned under external request history, and nonce tombstones are never pruned. The repository provides no production rollback-floor implementation.

`thunderbolt-bitcoin`
: A fail-closed Bitcoin Core boundary for regtest, signet, and testnet3. It validates network and genesis, bounds RPC work, tracks a reorganization-aware chain cursor, enforces coinbase maturity, and checks funding and closing transactions. It passed the official Bitcoin Core v31.1.0 live regtest, reorganization, and same-datadir restart gate. It deliberately has no wallet or signing API.

### Bitcoin Core

The `thunderbolt-bitcoin` library provides the validated Bitcoin Core boundary, but no Bitcoin backend is connected to `thunderboltd` in this RC. The future runtime must persist its chain cursor and use the backend for funding state, transaction broadcast, fee estimation, confirmation tracking, mempool changes, and reorganizations.

## Stable version 2 binding

`thunderbolt-wire` provides `ChannelBindingV2` and `OperationBindingV2`. The stable channel context commits to protocol version and suite, Bitcoin network and exact genesis, the complete 36-byte funding outpoint, deployment ID, committee epoch and descriptor digest, and the anchor parameter-suite digest. Invoice ID and positive Transfer step remain operation inputs, so they do not change the stable channel `ctx_id`.

Version 2 now has a separate signed Ledger and reducer surface. It does not change any version 1 hash or behavior, and the shipped daemon still uses version 1.

## Standalone version 2 application contract

`thunderbolt-ledger` authenticates chain-scoped proposals with BIP340. A `SignedProposalV2` binds the Ledger chain ID, stable channel binding, sequence and predecessor, actor-scoped request digest, x-only actor key and derived participant ID, role, event kind, and bounded canonical event bytes.

Consensus supplies proposal order, positive height, positive block time, and the previous application hash. `PendingBlockV2` produces deterministic executed-entry metadata, an ordered Merkle root, and an incremental application hash. `ExecutedBlockV2::validate_successor` checks chain, next height, previous application hash, and monotonic consensus time. Merkle proofs authenticate executed entry metadata to that block commitment.

These values prove deterministic, self-consistent execution only. They do not prove that a validator quorum committed the block. The crate has no network, consensus engine, ABCI server, database, validator signatures, quorum certificate, trusted header chain, or durable cross-block `request_digest -> entry_hash` index.

`thunderbolt-protocol` has a separate version 2 reducer that consumes authenticated executed entries. It uses positive consensus block time, pins one Ledger chain, supports a bounded map of concurrent Invoices, consumes one selected Invoice by exact committed entry hash, invalidates other Invoices from the prior Holder step, and orders Finalize without allowing an unrelated Invoice to veto closure. Its `ExternalVerifierV2` hooks for Open, Invoice, Transfer, and Finalize are abstract. No production implementation exists.

The Ledger and reducer crates are not connected to `thunderboltd`, `thunderbolt-storage`, or a consensus runtime. They make no finality or deployed-runtime claim.

## Control plane and target protocol plane

The current control API is loopback HTTP on `[admin].bind_address` and `[admin].port`, with port `19736` by default. Runtime validation rejects remote binding and built-in TLS. Health routes are public; every other `/v1` route uses bearer-token scopes. `paths.socket_path` is reserved but is not a live Unix socket.

The target protocol plane connects Holder clients, Ledger replicas, and committee nodes. Transport authentication is required, but it is not enough by itself. Every protocol entry also needs a canonical signed digest so authentication survives storage and relay.

The two planes must use separate listeners, authorization policy, rate limits, and metrics.

## Version 1 transaction-scoped verification

The service-facing write path now has one atomic boundary:

```text
evidence-free Invoice or Transfer proposal
   |
authenticated HTTP identity check
   |
SQLite BEGIN IMMEDIATE
   |
deduplicate proposal and request key
   |
load authoritative snapshot, pending Invoice, and Ledger time
   |
injected Trusted Verifier
   |
reducer and one commit for entry, evidence, snapshot, and retry mapping
```

`SqliteStorage::append_verified_proposal` rejects client evidence and runs version 1 verification under the writer lock. `NodeServer::bind_with_verifier` and `from_listener_with_verifier` inject the version 1 Invoice and Transfer verifier. Open and Finalize fail closed even when one is supplied.

`thunderboltd` calls the ordinary `NodeServer::bind` path and has no configuration for a production verifier. Its normal submission path therefore remains unavailable. Development regtest may still use the explicit synthetic-evidence mode.

## Channel state machine

The implemented reducer advances in one direction:

```text
new -> open -> invoice pending -> transfer complete
       |            ^                  |
       |            +------------------+
       +---------------------> finalized
transfer complete -----------> finalized
```

The implemented events are Open, Invoice, Transfer, and Finalize. Each entry carries a channel identifier, sequence, previous-entry hash, idempotency key, actor, timestamp, and event payload. SQLite storage applies the reducer and commits the immutable entry and derived snapshot in one transaction.

The active version 1 event contract still needs:

- protocol version and Bitcoin network
- channel identifier, derived from the funding outpoint
- sequence number and previous event hash
- transfer step and committee epoch
- stable request identifier for idempotency
- actor public key and signature
- canonical payload

The reducer rejects duplicate invoice identifiers, skipped or repeated sequences, wrong actors, stale hashes, invalid lifecycle transitions, and idempotency conflicts. It requires verification attestations but does not run proof, Bitcoin, signature, or quorum verification itself.

The version 1 reducer permits one pending Invoice. The standalone version 2 reducer resolves that product-semantics gap with a bounded concurrent set, but no active runtime uses it.

## Storage boundary

The current Ledger database contains public protocol entries and materialized channel snapshots. It uses SQLite WAL, full synchronization, immutable-entry triggers, migration checksums, hash-chain replay, integrity checking, and no-clobber verified backup. It does not store Holder secrets, committee shares, decryption keys, or signing material.

The concrete Holder and committee adapters map engine state into independently keyed Keystore records. They use the exact external checkpoint for every read and write, withhold output until checkpoint CAS succeeds, fail closed on unresolved ambiguity, and support bounded pruning after external finalization.

The missing piece is the rollback-floor service itself. A production implementation must live in an independent authenticated trust domain. The repository also has no automatic recovery protocol for a process killed after local encrypted persistence but before external checkpoint advancement. Role runtimes still need outboxes, Ledger cursors, and settlement coordination. Holder history is loaded eagerly and grows append-only; the committee replay journal retains a 512 KiB state-record ceiling. Both need compaction or epoch rotation.

The current manual backup is verified but not encrypted by the daemon. Operators must protect the destination at the filesystem or volume layer. Production backups must be encrypted, versioned, and verified through a restore drill.

## Invariants

The implementation must preserve these protocol invariants at each accepted transfer:

1. The fixed Bitcoin lock key does not change.
2. The public Holder anchor matches the Holder secret in the accepted credential.
3. The committee update compensates for the Holder update.
4. A channel has one committed order and one accepted transition at each step.
5. The current Holder cannot forward or finalize until the required committee updates are durable.
6. A finalization signature is bound to the current channel state and exact Bitcoin transaction.

## Current implementation boundary

The current tree has the version 1 reference daemon and its atomic verified append, plus standalone version 2 binding, signed Ledger, and reducer libraries. It also contains the concrete Holder and committee Keystore adapters and the Bitcoin Core library. The default release build excludes the legacy settlement prototype and single-process committee fixtures. Research builds enable them explicitly for regression coverage.

The following remain release gates:

- reconcile the current 2048-bit Paillier wire parameter with the paper's 3072-bit evaluation parameter
- choose and implement the version 2 runtime and activation path; the shipped daemon remains version 1 and verifierless
- add an ABCI application, persistent version 2 channel state, and durable cross-block request index
- implement a production rollback-floor backend and killed-between-commit-and-floor recovery procedure
- add Holder and committee role daemons, outboxes, Ledger cursors, and settlement coordination
- replace raw Holder `DurableAcknowledgement` construction and the abstract committee receipt with authenticated finality capabilities
- specify and implement the Open DKG or provisioning ceremony
- add an `R_own` proof and combined-key Holder plus FROST Finalize path under `P`
- a Ledger that meets the required fault model
- an integrated Bitcoin Core settlement path
- authenticated protocol transport and a production local control transport
- Holder and committee daemon services with durable outboxes and Ledger consumers
- metrics and production observability
- full multi-process restart, replay, duplicate, out-of-order, quorum-loss, and reorganization tests
- compaction or epoch rotation for Holder history and the committee replay journal

The planned production Ledger recommendation is the standalone deterministic version 2 application replicated through CometBFT. This repository has no CometBFT dependency, ABCI application, configuration, deployment assets, quorum receipt, or integration tests. Validator governance, its relationship to the Threshold Committee, state synchronization, evidence handling, and recovery remain design work. Until those pieces exist and pass review, the only runnable Ledger is the version 1 single SQLite service.

See [Production roadmap](roadmap.md), [Publication checklist](publication-checklist.md), and [Release process](release-process.md) for the gates that prevent an RC from being labeled mainnet-ready.
