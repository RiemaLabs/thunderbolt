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

### Bitcoin Core

Bitcoin Core is the target production chain backend. No Bitcoin backend is connected to `thunderboltd` in this RC. The future runtime must use a validated backend for funding state, transaction broadcast, fee estimation, confirmation tracking, mempool changes, and reorganizations.

## Control plane and target protocol plane

The current control API is loopback HTTP on `[admin].bind_address` and `[admin].port`, with port `19736` by default. Runtime validation rejects remote binding and built-in TLS. Health routes are public; every other `/v1` route uses bearer-token scopes. `paths.socket_path` is reserved but is not a live Unix socket.

The target protocol plane connects Holder clients, Ledger replicas, and committee nodes. Transport authentication is required, but it is not enough by itself. Every protocol entry also needs a canonical signed digest so authentication survives storage and relay.

The two planes must use separate listeners, authorization policy, rate limits, and metrics.

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

The production event contract still needs:

- protocol version and Bitcoin network
- channel identifier, derived from the funding outpoint
- sequence number and previous event hash
- transfer step and committee epoch
- stable request identifier for idempotency
- actor public key and signature
- canonical payload

The reducer rejects duplicate invoice identifiers, skipped or repeated sequences, wrong actors, stale hashes, invalid lifecycle transitions, and idempotency conflicts. It requires verification attestations but does not run proof, Bitcoin, signature, or quorum verification itself.

## Storage boundary

The current Ledger database contains public protocol entries and materialized channel snapshots. It uses SQLite WAL, full synchronization, immutable-entry triggers, migration checksums, hash-chain replay, integrity checking, and no-clobber verified backup. It does not store Holder secrets, committee shares, decryption keys, or signing material.

Future Holder and committee databases need authenticated encryption at rest. Threshold-signing nonce state must be persisted before a partial signature leaves the process, and a crash must never make a nonce reusable.

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

The current tree has the cryptographic proof implementation, bounded wire types, a deterministic channel reducer, durable public Ledger storage, strict configuration and token authorization, a loopback Ledger daemon, a control CLI, research benchmarks, and regression tests. The proof benchmark path still creates all protocol participants in one process. Threshold timing and network behavior in the evaluation crate are simulations.

The following remain release gates:

- reconcile the current 2048-bit Paillier wire parameter with the paper's 3072-bit evaluation parameter
- integrate real proof, signature, Bitcoin, and quorum verification before Ledger submission
- bind network, deployment, committee epoch, and actor signatures into the event contract
- add durable encrypted Holder and committee state with migration and recovery tests
- one committee share per process
- threshold Open and Finalize signing with nonce-reuse protection
- a Ledger that meets the required fault model
- an integrated Bitcoin Core settlement path
- authenticated protocol transport and a production local control transport
- Holder and committee runtimes
- metrics and production observability
- restart, replay, duplicate, out-of-order, and reorganization tests

See [Publication checklist](publication-checklist.md) and [Release process](release-process.md) for the gates that prevent an RC from being labeled mainnet-ready.
