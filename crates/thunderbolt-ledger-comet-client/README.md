# Thunderbolt finalized Ledger Comet client

`thunderbolt-ledger-comet-client` is the concrete boundary between the
Thunderbolt role services and CometBFT. It owns:

- one crash-safe `TrustCoordinator` database and independent checkpoint store;
- one authenticated P3 transport dedicated to trace acquisition; and
- a separate authenticated P3 transport for fixed Ledger broadcast and query
  operations.

`prepare_range` first fetches a P2 exact-count whole-block range from the current
primary without mutating trust state. It returns one bounded serializable,
authority-free `FinalityAdvanceIntentV2` per block. The caller must durably
retain these intents before invoking `finalize_prepared_range`; they supply the
exact independently retained execution needed by finality recovery. Finalization
then advances every block in order. Empty blocks are retained and finalized
rather than skipped. Each durable result rechecks chain, application version,
execution height/time, application hash, committing height, and coordinator
proof digest before an in-process capability is returned.

## Trust boundary

`HolderFinalityCapabilityV2` and `FinalizedBlockCapabilityV2` implement neither
`Serialize` nor `Deserialize`. They can only be constructed from coordinator
history that still matches the independent external checkpoint.

`HistoricalEntryReferenceV2` is deliberately different. It is a fixed 423-byte
authority-free locator, encoded as exactly 846 lowercase hexadecimal JSON
characters when serialized. It contains no raw trace, validator receipt,
provider label, TLS evidence, or authority flag. Deserializing it proves only
canonical shape. Every use must call `revalidate_reference`, which reloads and
validates the coordinator proof, request-first index, exact block entry, and
Merkle proof. Restart, history-epoch sealing, and source rotation preserve the
same static profile because it binds the complete allowed RPC roster. Each
reference separately binds its historical source version and proof digest.

`HistoricalBlockReferenceV2` provides the same provider-free, authority-free
handoff for a complete executed block, including a zero-entry block. Its sole
binary form is 291 bytes and its Serde form is exactly 582 lowercase hexadecimal
characters. It binds the client profile, coordinator identity, chain, source
configuration and application versions, execution height/time/application and
header hashes, adjacent committing height/header hash, and proof digest. It has
no entry index or raw receipt. `revalidate_block_reference` reloads the exact
block, summary, and proof from externally anchored coordinator history before
returning a private `FinalizedBlockCapabilityV2`.

An authenticated `broadcast_tx_sync` result is only CheckTx admission. Writes
are attempted once. `AmbiguousWrite` is never retried automatically; callers
reconcile only through `reconcile_submission`, which performs the complete
actor-request query and requires matching durable coordinator finality before
returning a capability.

ABCI query responses and TLS evidence do not establish finality. The client
uses the query only to locate deterministic application output, then derives
authority from the locally persisted and externally checkpointed
`TrustCoordinator` proof.

## Configuration

`LedgerCometClientConfig` accepts an identity-free coordinator policy, complete
allowed authenticated RPC peer roster, trace and Ledger body limits, and
bounded RPC/locator work. It mechanically hashes the chain, finality policy,
coordinator/history limits, full allowed-roster `RpcTransportProfileId`, and
every client limit into `ClientProfileIdV2`; that exact digest becomes the
durable `TrustCoordinatorIdentity`. There is no raw profile or coordinator-ID
constructor at this boundary, so policy drift fails during `open`, before any
reference or capability can be used. The RPC roster may contain extra
explicitly pinned peers only for a future consecutive source rotation.

Absence verification is capped compositionally by both block count and maximum
aggregate proof bytes, and runs on a blocking worker. Coordinator ownership is
removed from the live client during blocking or async trust mutations. If the
caller cancels while a checkpoint CAS or scan is pending, every subsequent
method returns `Poisoned`; the caller must drop and use an exact recovery/open
path. The wrapper exposes bootstrap, finality, source-rotation, and
history-epoch recovery. Finality recovery consumes the independently retained
execution intent; history recovery consumes the independently retained seal
intent.

There is no synchronous network facade, raw JSON-RPC method, role database
cursor, opaque self-asserted receipt, or default accepting finality verifier in
this crate. Holder and Committee trait adapters are intentionally a later
scoped migration.
