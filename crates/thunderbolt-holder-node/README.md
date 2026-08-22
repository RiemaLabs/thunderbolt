# Bitcoin Thunderbolt Holder node

`thunderbolt-holder-node` is the long-running Holder/Recipient role service. It
combines the private Holder engine and fenced encrypted keystore with a durable
SQLite outbox and runtime-neutral asynchronous Ledger boundaries.

The crate opens no TCP listener and implements no remote administration.
Applications should expose its local-control types only over owner-only local
IPC.

## Ledger and finality boundary

Proposal submission returns only `Accepted` or `AlreadyKnown`; neither status
claims finality. Finalized history uses complete globally contiguous
`ExecutedBlockV2` ranges. A range binds the immutable verifier profile,
coordinator identity, Ledger chain, exact start height and predecessor
application hash, every whole block in order, and the mandatory next height and
application hash. Zero-entry blocks are explicit. `None` never moves a cursor.

Finality uses an explicit crash-safe handoff:

1. `SignedV2LedgerClient::prepare_finalized_execution` returns a bounded,
   canonical, authority-free `FinalityRangeIntentV2` and does not mutate the
   finality coordinator.
2. The Holder database commits and reads back that exact intent before issuing
   a private-constructor `StagedFinalityRangeCapabilityV2`.
3. `FinalityVerifier::finalize_staged_range` may mutate only its configured
   coordinator after receiving that store-issued capability. It must commit and
   read back each transition before returning exact durable block capabilities.
4. After every asynchronous capability check succeeds, one SQLite transaction
   advances the global cursor and local channel history, finalizes matching
   outbox rows, persists the last block capability, and deletes the exact stage.

Cancellation before step 4 leaves the role cursor and outbox unchanged and the
canonical stage available for replay. If coordinator state may have advanced,
call `inspect_staged_finality_recovery` before normally opening the concrete
coordinator. Pass the returned `StagedFinalityRecoveryV2` to the asynchronous
`HolderRoleService::open`; open rechecks the full store/file/stage/intent binding
so an inspection/open race fails closed.

The configured `FinalityVerifierProfileId` and `FinalityCoordinatorId` are part
of the service domain, SQLite identity, every intent and durable capability, and
the global cursor. A non-genesis cursor retains the bounded authority-free
capability for its prior block. Open and every subsequent fetch asynchronously
revalidate that capability. Changing to a different or weaker verifier cannot
silently reuse the database.

## Durable local state

SQLite uses WAL mode with `synchronous=FULL`. The database must be an absolute,
normalized, owner-only regular file beneath audited Unix ancestry. Symlinks,
hardlinks, URI and in-memory paths, unsafe directory permissions, file
replacement, and duplicate process opens are rejected. A separate owner-only
role lock excludes another process. A persisted random store identity plus the
canonical path and device/inode identity prevents a copied or recreated file
from issuing a valid stage capability.

Every local command enters a bounded outbox before submission. Request digests
and command IDs are independently deduplicated, retries reuse the originally
stored signed proposal, exact Ledger replays are no-ops, and conflicting
duplicates fail closed. A dirty lifecycle marker reports crash recovery.

A legacy channel-only finality cursor cannot prove a globally contiguous block
position. Legacy databases with finality progress are rejected rather than
assigned a fabricated global cursor.

The committed Holder engine still implements the v1 proof-envelope domain. A
reviewed v2 Holder proof and identity bridge remains a release gate. Mainnet and
Testnet4 are disabled. Bundled Ledger, finality, Bitcoin settlement, and
threshold-signing implementations all fail closed and must be replaced before
those actions are enabled.
