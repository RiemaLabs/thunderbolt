# thunderbolt-storage

Durable node state for Bitcoin Thunderbolt. This crate keeps each public
protocol ledger entry and the channel snapshot derived from it in one SQLite
transaction.

## Guarantees

- per-channel, append-only ledger ordering enforced by the protocol reducer and
  immutable database rows;
- channel-scoped idempotency and lifetime invoice-ID uniqueness;
- WAL journaling, `synchronous=FULL`, foreign keys, and a bounded busy timeout;
- versioned, checksummed migrations and refusal of databases from newer or
  unrelated applications;
- transaction-scoped proposal verification after `BEGIN IMMEDIATE`, with the
  authoritative snapshot, exact pending Invoice head, and trusted ledger time;
- stable evidence-free proposal digests, atomic retry mappings, and verifier
  callbacks that are the only source of persisted verification evidence;
- keyset pagination bounded by both rows and serialized bytes, restart-safe
  reads, physical and protocol-level integrity checking; and
- verified online backups published with a no-clobber rename.

`append_verified_proposal` is the service-facing write path. It rejects any
client-supplied evidence before the callback, computes a stable proposal digest,
and deduplicates both that digest and the channel-scoped idempotency key under
the writer lock. The asserted actor is stored only for diagnostics and conflict
reporting. Exact retries return the original outcome; reuse of an idempotency
key for a different proposal fails before expensive verification. For a new
proposal, the callback runs inside that transaction and returns node-produced
evidence. A verifier error or write failure rolls back every related row.

`append_entry` remains available for trusted import and regression tooling. It
expects a fully verified entry and does not perform cryptographic verification.
Protocol evidence is public attestation data, not proof that those checks were
performed. Production request handlers should use `append_verified_proposal`.
This database must never contain signing keys, Paillier secret keys, committee
shares, API tokens, or other private node material.

```rust,no_run
use std::path::Path;
use thunderbolt_protocol::{LedgerEntry, VerificationEvidence};
use thunderbolt_storage::{SqliteStorage, VerifiedProposalContext};

#[derive(Debug)]
struct VerificationFailure;

fn verify(
    _context: VerifiedProposalContext<'_>,
) -> Result<Vec<VerificationEvidence>, VerificationFailure> {
    // Invoke the deployment's trusted verifier and return its evidence.
    unimplemented!()
}

fn persist_proposal(
    proposal: &LedgerEntry,
) -> Result<(), thunderbolt_storage::VerifiedAppendError<VerificationFailure>> {
    let storage = SqliteStorage::open(Path::new("thunderbolt.db"))?;
    storage.append_verified_proposal(proposal, verify)?;
    Ok(())
}
```
