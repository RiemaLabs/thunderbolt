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
- keyset pagination bounded by both rows and serialized bytes, restart-safe
  reads, physical and protocol-level integrity checking; and
- verified online backups published with a no-clobber rename.

`append_entry` expects an entry that has already passed the service's
authentication, authorization, and cryptographic proof/quorum verification.
Protocol evidence is public attestation data, not proof that those checks were
performed. This database must never contain signing keys, Paillier secret keys,
committee shares, API tokens, or other private node material.

```rust,no_run
use std::path::Path;
use thunderbolt_protocol::LedgerEntry;
use thunderbolt_storage::SqliteStorage;

fn persist_verified_entry(entry: &LedgerEntry) -> thunderbolt_storage::Result<()> {
    let storage = SqliteStorage::open(Path::new("thunderbolt.db"))?;
    storage.append_entry(entry)?;
    Ok(())
}
```
