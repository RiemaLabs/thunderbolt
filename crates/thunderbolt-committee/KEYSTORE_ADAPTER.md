# Committee keystore adapter

Review date: 2026-08-21

`KeystoreCommitteeVault` is the production storage adapter between the
one-member committee engine and `thunderbolt-keystore`. It owns both the raw
encrypted `Vault` handle and an independent `RollbackFloorStore` capability.
Neither is exposed, so another component cannot mutate the local file without
also winning the external checkpoint protocol.

## Identity and records

The authenticated `VaultIdentity` binds the Bitcoin network, shared derived
deployment ID, CommitteeMember role, deterministic member node ID, positive
committee epoch, and exact committee descriptor digest. Testnet4 is rejected
until the keystore has a distinct Testnet4 identity. Mainnet construction does
not itself authorize mainnet operation; the runtime policy must retain the
project-wide mainnet safety gate.

Each descriptor/member pair has one `AdapterState` engine record. Its versioned
envelope contains:

- descriptor and member identity;
- engine CAS revision;
- committed keystore revision;
- last canonical request digest; and
- the opaque engine payload.

Every mutation also inserts a separate, immutable idempotency record in the
same transaction. The request and transaction IDs are domain-separated hashes
over the complete vault identity, operation kind, prior/resulting engine
revisions, and canonical payload or nonce-operation digest. A reused identifier
with different bytes fails closed in the keystore.

## Checkpoint protocol

The external anchor is an exact `VaultCheckpoint` containing both revision and
encrypted-file state digest. Revision-only anchoring is insufficient because
two copied vault paths can produce different states at the same next revision.

Creation uses a restricted `RecoveryVault`, installs its exact revision-zero
checkpoint with `None -> checkpoint`, and only then unlocks secret records.
Normal open requires the file checkpoint to equal the external checkpoint
before the recovery handle exposes any private record.

Every read and write runs inside the keystore's fenced transaction callback.
Callback output is withheld until the encrypted replacement and exact external
checkpoint CAS both succeed. A replay carries no freshly recomputed output and
is therefore rejected by this adapter. No acknowledgement, nonce reservation,
state read, or successful engine CAS escapes before anchoring.

Normal open requires exact checkpoint equality. Generic `R = F + 1` recovery
is forbidden because `RecoveryVault` intentionally exposes no private
AdapterState before anchoring; advancing an unverified candidate could pin the
external checkpoint to an unrelated AEAD-valid fork. Any unresolved candidate
therefore fails closed for explicit operator/control-plane recovery.

## Nonce ordering

Nonce reservation and consumption use the keystore's immutable SessionNonce
collection. Reservation writes the nonce, state control record, and
idempotency record atomically, then anchors the resulting checkpoint before a
caller may publish a commitment. Consumption atomically tombstones the nonce,
updates the same control/idempotency records, and anchors the checkpoint before
return. A tombstone cannot be replaced or removed.

## Secret-flow review

- The adapter, engine record, idempotency buffers, and decoded record copies
  intentionally implement no broad serialization or logging interface.
- Engine plaintext stays in `VaultPlaintext` or `Zeroizing<Vec<u8>>` buffers.
  Moving an encoded buffer into `SecretValue` transfers its allocation directly;
  error paths zeroize both source and destination wrappers.
- Decrypted keystore views exist only inside fenced callbacks and are copied
  immediately into zeroizing allocations before parsing. The state record and
  every descriptor-bound idempotency record are validated before callback
  output or checkpoint advancement. No plaintext is written to temporary files,
  backups, checkpoint records, transaction IDs, or error strings.
- External checkpoints hash randomized authenticated ciphertext, not plaintext.
  Request IDs contain only cryptographic digests of high-entropy secret state.
- On any ambiguous keystore write, checkpoint mismatch, identity mismatch, or
  unreconciled floor result, the adapter drops the decrypted `Vault` and permits
  no further reads or writes.

## Operational limits

The keystore bounds one record to 512 KiB and retains at most 4,096 records and
transaction receipts. `prune_finalized_history` first prunes receipts through an
explicit externally finalized revision, then canonically removes the supplied
finalized idempotency-record set. The caller must retain durable request history;
nonce tombstones are never pruned.

The encrypted engine replay journal itself is not compacted. Reaching the
512 KiB state-record ceiling still requires epoch rotation or a future
proof-preserving journal compactor and remains a production liveness blocker.

A production `RollbackFloorStore` must live in an independent authenticated
trust domain such as an HSM-backed monotonic service or replicated control
plane. A sibling file beside the vault is not a production floor.
