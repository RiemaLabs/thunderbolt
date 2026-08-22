# Thunderbolt signed rollback-floor application

`thunderbolt-floor-app` is the deterministic v2 application state machine for
an independent rollback-floor Ledger. It is not a local `RollbackFloorStore`
backend and does not grant consensus finality by itself.

## Authorization

Genesis fixes a bounded registry from the digest of each complete
`VaultIdentity` to one exact x-only BIP340 operator key. The registry and a
nonzero consensus-profile digest are hashed into the genesis digest and every
application hash. There is no runtime registry mutation, rotation, or recovery
API; adding governance requires a separately specified protocol version.

Every CAS wraps the canonical `FloorCasRequest` from `thunderbolt-floor` with
the registered actor key, a nonzero 32-byte audit/correlation nonce, one exact
target height, and the exact expected prior application hash. BIP340 signs the
domain-separated digest of all those fields, including the floor chain and full
vault identity. mTLS or transport identity is never treated as authorization.

A request is valid only for that one next application head. It cannot be moved
to a later block where a previously conflicting transition might become live,
so exact CAS idempotency requires no permanent nonce/result table. The nonce is
not a global uniqueness database. No block may contain two requests for the
same vault identity; therefore each result's `current` value is also that
identity's final checkpoint in the committed block state.

## Deterministic execution and storage

Consensus supplies positive height/time, prior app hash, and request order. The
application never reads a local clock. SQLite uses WAL, `synchronous=FULL`,
foreign keys, strict tables, immutable history triggers, and one immediate
transaction per block. Preview executes and rolls back; commit re-executes and
compares the exact block before committing. Exact latest-height replay is
accepted, while same-height forks and stale predecessors fail closed.
Production open rejects empty, relative, in-memory, URI/magic, symlink, and
non-file paths. It requires an absolute database file in an existing private
caller-managed directory, creates new files with private permissions, and uses
SQLite no-follow mode. It rejects link counts other than one and rechecks the
exact device/inode before every operation, preventing hardlink aliases from
creating divergent WAL/SHM namespaces. Non-Unix production open fails closed
until equivalent ownership/inode guarantees are implemented. Runtime
configuration remains responsible for checking owner-only ancestry and placing
the database on durable independent storage.
Historical state stores only the final changed leaf for each identity in a
block. Empty and conflict-only blocks add no state-history rows;
historical proofs resolve each identity's latest delta at or before the proved
height.

Hot-history retention is local maintenance, never a consensus input. Operators
can inspect retained block/result/delta counts against caller-selected policy.
Compaction starts from an exact application-created snapshot candidate and can
run only after an independent `FinalizedHistoryAnchorVerifier` authenticates
the chain, genesis/profile, height/time, prior and through app hashes, state
root, snapshot digest, prior-anchor chain, and committing header. This crate
ships no production verifier or local bypass. Verifier calls are historical,
pure, and repeatable by contract; they must not advance a mutable trust root
before local commit reconciliation.

Normal restart preflights absolute retained block, result, delta, encoded-byte,
and live-page byte bounds before replay allocation. Candidate and recovery
paths perform the same capped metadata/encoding preflight before loading a
snapshot. Oversized state returns recoverable
`CompactionRequired`. A recovery-only API authenticates any existing anchor,
builds an exact candidate without exposing checkpoints or execution, installs
a bounded externally verified prefix, and returns a normal application only
after the remaining tail passes bounded replay. Live consensus execution never
branches on local retention or compaction state.

The anchor and full registry-ordered snapshot are installed in the same
WAL/`FULL` transaction that prunes older blocks, results, and deltas. Exact
compaction retry performs durable readback, while a different fork fails.
The connection and anchor operation guards remain held through post-commit
integrity replay and the in-memory anchor update. Any ambiguous or failed
post-commit reconciliation poisons the handle before releasing those guards;
all subsequent reads, proofs, and writes require a cold authenticated reopen.
Ordinary open refuses a compacted database; restart must re-authenticate the
stored anchor externally and then replays only the retained tail. Pruned block,
result, and historical-state queries fail explicitly. State at the anchor is
available only through a separately anchor-bound inclusion/absence proof.

The app hash commits application version, floor chain, genesis/registry/profile,
prior app hash, exact block digest, height/time, ordered result root, and the
registry-ordered state root. Every registered floor key has a state leaf even
when its checkpoint is absent, giving bounded inclusion or explicit-absence
proofs. State-proof verification requires the configured genesis, exact
committed execution block, expected identity, and expected checkpoint or
absence. Ordered block results have separate bounded inclusion proofs whose
verification API requires the exact executed block and result claim. Neither
API permits validating a self-declared root and then substituting a different
claim. A stored committed block can be loaded as execution evidence after
restart, but that evidence is explicitly not a finality proof.
On every restart, integrity verification begins from genesis or an externally
authenticated anchor snapshot, streams the retained tail into one
registry-ordered in-memory state, and checks each exact persisted delta set.
Missing, extra, moved, orphaned, or conflicting blocks, results, and state
mappings are rejected. Retained results store the exact BIP340 signature;
restart reconstructs every signed request, verifies the immutable operator key,
and recomputes the complete block input digest before exposing state or proofs.

## Deployment boundary

Mainnet identities are rejected until an independent audit. The floor registry
uses the closed `thunderbolt-keystore` identity network domain, which contains
Regtest, Signet, Testnet3, and Mainnet only; Bitcoin Testnet4 is structurally
unrepresentable and therefore cannot be admitted accidentally. This matches the
current Holder, Committee, and runtime policy until the keystore gains a
distinct Testnet4 identity tag.

This crate does not implement CometBFT networking, quorum verification, a
permissive local floor, or a same-host trust shortcut. A finality verifier must
separately validate the adjacent committing header and application-state proof
before converting an executed result into a `FinalizedFloorResponse`. On
restart, the runtime must also reconcile the local last height/app hash with the
independently finalized consensus head before serving queries. Local signature
replay authenticates retained transitions; it does not prove tail completeness
or consensus finality by itself.
