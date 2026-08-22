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
: A local Holder and Recipient state engine. It creates the v1 single-committee Invoice and the threshold Recipient-share plus VESS package, retains old credentials after Transfer, checks committed acknowledgements, and stores private transitions through a transactional vault trait. The threshold Recipient proof uses the implemented `tb/share` transcript and does not claim to be the paper's exact `R_inv^thr` transcript. The crate has no network client, service loop, or `thunderboltd` integration.

`thunderbolt-committee`
: A one-share committee member engine. It verifies the Recipient-share proof, its exact binding to the threshold distribution, the committed Transfer, and an abstract Ledger receipt before updating only its local Shamir share. The update and replay-safe acknowledgement share one encrypted-vault revision. The crate defines the Ledger receipt and signer boundaries but has no concrete quorum-receipt verifier, DKG, FROST aggregation, or Finalize path under `P`.

`thunderbolt-verifier`
: A narrow bridge from bounded public Invoice and Transfer artifacts to trusted verification evidence. It checks deployment, committee, channel, invoice, step, and prior-Ledger bindings. `thunderbolt-node` can inject it into the transaction-scoped append path. The shipped daemon does not supply one, and the verifier has no Open, Finalize, actor-signature, or Bitcoin policy implementation.

`thunderbolt-keystore`
: An encrypted transactional multi-record vault for Holder or committee-member secrets. It authenticates deployment and committee scope, uses record versions and vault revisions for compare-and-swap updates, retains idempotency receipts, and turns consumed signing nonces into permanent tombstones. Committee open requires a minimum revision anchored outside the vault, and generic committee restore is forbidden. The daemon never opens the vault, and the role engines still need concrete adapters.

`thunderbolt-bitcoin`
: A fail-closed Bitcoin Core boundary for regtest, signet, and testnet3. It validates network and genesis, bounds RPC work, tracks a reorganization-aware chain cursor, enforces coinbase maturity, and checks funding and closing transactions. It passed the official Bitcoin Core v31.1.0 live regtest, reorganization, and same-datadir restart gate. It deliberately has no wallet or signing API.

### Bitcoin Core

The `thunderbolt-bitcoin` library provides the validated Bitcoin Core boundary, but no Bitcoin backend is connected to `thunderboltd` in this RC. The future runtime must persist its chain cursor and use the backend for funding state, transaction broadcast, fee estimation, confirmation tracking, mempool changes, and reorganizations.

## Stable version 2 binding

`thunderbolt-wire` provides `ChannelBindingV2` and `OperationBindingV2`. The stable channel context commits to protocol version and suite, Bitcoin network and exact genesis, the complete 36-byte funding outpoint, deployment ID, committee epoch and descriptor digest, and the anchor parameter-suite digest. Invoice ID and positive Transfer step remain operation inputs, so they do not change the stable channel `ctx_id`.

This binding is a landed codec primitive, not the active event protocol. Version 1 Invoice, Transfer, verifier, Holder, committee, and Ledger types still use the version 1 binding. Version 2 also lacks an actor-signed proposal envelope. Migration, golden vectors across every consumer, and activation policy remain release work.

## Control plane and target protocol plane

The current control API is loopback HTTP on `[admin].bind_address` and `[admin].port`, with port `19736` by default. Runtime validation rejects remote binding and built-in TLS. Health routes are public; every other `/v1` route uses bearer-token scopes. `paths.socket_path` is reserved but is not a live Unix socket.

The target protocol plane connects Holder clients, Ledger replicas, and committee nodes. Transport authentication is required, but it is not enough by itself. Every protocol entry also needs a canonical signed digest so authentication survives storage and relay.

The two planes must use separate listeners, authorization policy, rate limits, and metrics.

## Transaction-scoped verification

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

`SqliteStorage::append_verified_proposal` rejects client evidence and runs verification under the writer lock. `NodeServer::bind_with_verifier` and `from_listener_with_verifier` inject the Invoice and Transfer verifier. Open and Finalize fail closed even when one is supplied.

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

The version 1 reducer also permits only one pending Invoice. Protocol v2 must either preserve that as an explicit product restriction with its own analysis or adopt the paper's pending-Invoice set semantics.

## Storage boundary

The current Ledger database contains public protocol entries and materialized channel snapshots. It uses SQLite WAL, full synchronization, immutable-entry triggers, migration checksums, hash-chain replay, integrity checking, and no-clobber verified backup. It does not store Holder secrets, committee shares, decryption keys, or signing material.

The Keystore and role-engine vault traits establish the local encryption and transaction boundaries. The multi-record transaction can update independently keyed channel, Invoice, credential, committee-share, nonce, and adapter records together. The daemon still needs adapters that coordinate those secret records with Ledger cursors, acknowledgements, and outbound work. Committee processes must also persist and advance the externally trusted rollback floor after each share, nonce, or signing-state commit.

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

The current tree has the cryptographic proof implementation, stable version 2 binding primitives, a deterministic version 1 channel reducer, atomic verified Ledger storage, strict configuration and token authorization, a loopback Ledger daemon, a control CLI, and the Holder, committee, Trusted Verifier, Keystore, and Bitcoin Core libraries described above. The default release build excludes the legacy settlement prototype and single-process committee fixtures. Research builds enable them explicitly for regression coverage.

The following remain release gates:

- reconcile the current 2048-bit Paillier wire parameter with the paper's 3072-bit evaluation parameter
- configure a production verifier in the daemon and add Open, Finalize, Bitcoin, actor-signature, and quorum-receipt verification
- migrate the version 1 event and proof layers to the stable version 2 binding
- add durable Holder and committee runtime adapters, outboxes, Ledger cursors, migrations, and recovery tests
- specify and implement the Open DKG or provisioning ceremony
- add an `R_own` proof and combined-key Holder plus FROST Finalize path under `P`
- a Ledger that meets the required fault model
- an integrated Bitcoin Core settlement path
- authenticated protocol transport and a production local control transport
- Holder and committee daemon services with durable outboxes and Ledger consumers
- metrics and production observability
- full multi-process restart, replay, duplicate, out-of-order, quorum-loss, and reorganization tests

The planned production Ledger recommendation is a deterministic Thunderbolt application replicated through CometBFT. This repository has no CometBFT dependency, ABCI application, configuration, deployment assets, or tests. Validator governance, its relationship to the Threshold Committee, state synchronization, evidence handling, and recovery remain design work. Until those pieces exist and pass review, the only runnable Ledger is the single SQLite service.

See [Production roadmap](roadmap.md), [Publication checklist](publication-checklist.md), and [Release process](release-process.md) for the gates that prevent an RC from being labeled mainnet-ready.
