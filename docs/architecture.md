# Architecture

Bitcoin Thunderbolt separates protocol roles, consensus, local secret state, and operator control. Each process has one role and one durable identity.

## Roles

### Holder

The Holder controls the current ownership secret. It verifies an invoice, creates the transfer, stores the next credential state, and can initiate final settlement.

### Recipient

The Recipient creates an invoice with a fresh secret and encrypted refresh material. After the transfer and committee update finalize, the Recipient decrypts the credential and becomes the Holder.

### Committee member

Each committee process holds one share. It scans finalized Ledger blocks in order, verifies the invoice and transfer pair, updates its local share, and records the result before advancing its cursor. A process never loads another member's share.

### Thunderbolt Ledger

The Ledger orders signed protocol entries and materializes channel state. It holds no Holder or committee secret. The application is deterministic; CometBFT supplies replication and finality.

### Rollback floor

The rollback floor prevents a copied or restored participant vault from returning to an older accepted secret state. It runs in an independent trust domain and anchors exact process identities and checkpoints.

### Bitcoin Core

Bitcoin Core supplies funding, confirmation, mempool, reorganization, and settlement data. The Ledger never acts as a Bitcoin wallet.

## Process topology

```text
 operator CLI                   operator CLI
      |                              |
 owner-only Unix socket        owner-only Unix socket
      |                              |
 Holder daemon                 Committee daemon(s)
      |                              |
 encrypted vault               encrypted share vault
      |                              |
      +--------- rollback floor -----+
      |                              |
      +------ authenticated Ledger client ------+
                              |
                     CometBFT validator set
                              |
                     deterministic Ledger app
                              |
                            SQLite
                              |
                         Bitcoin Core
```

Administrative traffic never shares a listener with protocol or consensus traffic.

## Channel binding

Every channel is bound to:

- the Bitcoin network and genesis hash
- the complete funding outpoint
- the deployment identifier
- the committee epoch and descriptor
- the proof and anchor parameter suites
- the Ledger chain identifier

Each operation adds its own invoice, step, actor, predecessor, request, and event data. BIP340 signatures authenticate the actor and the canonical proposal body.

## Ledger stack

The Ledger stack has four layers:

1. `thunderbolt-ledger` defines signed proposals, executed entries, block commitments, application hashes, and Merkle proofs.
2. `thunderbolt-ledger-app` executes and persists deterministic blocks in SQLite.
3. `thunderbolt-ledger-abci` maps the application to CometBFT callbacks.
4. `thunderbolt-abci-server` provides bounded local framing, deadlines, connection limits, and fatal supervision.

`thunderbolt-cometbft-rpc` authenticates RPC peers with pinned TLS identities. `thunderbolt-cometbft-client` maintains the durable light-client root and finalized history. `thunderbolt-ledger-comet-client` combines those boundaries into typed Holder and committee capabilities.

An executed entry alone is not finality evidence. A role service receives a capability only after the block header, application hash, exact entry, inclusion proof, and configured trust policy all agree.

## Holder flow

The Holder service owns:

- the encrypted Holder vault
- a durable proposal outbox
- its finalized Ledger cursor
- request reconciliation after an ambiguous broadcast
- the Bitcoin settlement adapter
- the external rollback-floor client

The service writes the local transition and outbox atomically. It advances the external floor before releasing state-dependent output. On restart it reconciles the floor, Ledger history, and outbox before accepting new work.

## Committee flow

The committee service consumes complete finalized blocks, including empty blocks. It records its cursor, pending invoice evidence, matched transfer evidence, and share update in one transaction.

Only compact block commitments, exact entries, inclusion proofs, and durable finality capabilities enter committee storage. Full blocks and raw consensus receipts are transient. Exact Ledger replays preserve the first finalized occurrence and do not increment the refresh chain twice.

## Rollback-floor flow

The floor application accepts actor-signed compare-and-swap requests tied to the exact next height and previous application hash. It rejects a second request for the same identity in one block. CometBFT finality authorizes history compaction, and a chained external anchor authenticates the retained snapshot and bounded tail.

Holder and committee code depend on the floor through a narrow capability interface. They do not trust a local database row simply because it is well formed.

## Operator runtime

`thunderboltd` loads one strict TOML file, validates every public reference, binds the complete deployment identity, acquires the process lock, and exposes a local control socket. `thunderbolt-cli` supports status, blockers, redacted configuration, drain, and stop. It has no raw protocol mutation command.

The runtime keeps a bounded request ledger so an operator retry returns the same result. Shutdown, cancellation, dirty restart, and lost-client cases have explicit state transitions.

## Crash consistency

Durable transitions follow the same rule throughout the system:

1. Validate the complete request and current head.
2. Prepare the deterministic result without publishing authority.
3. Commit local state atomically.
4. Advance the independent checkpoint when required.
5. Reconcile ambiguous outcomes through exact readback.
6. Publish output only after all required durable checks pass.

Fatal storage or consensus ambiguity closes the affected process boundary. It is never converted into an ordinary success response.

## Current release boundary

Version 1.0 contains the role services, deterministic Ledger and floor applications, bounded ABCI server, authenticated CometBFT clients, encrypted storage, Bitcoin and proof backends, operator runtime, and packaged integration points. Deployment-specific role handlers, trust material, and threshold-signing providers are supplied at the operator boundary.
