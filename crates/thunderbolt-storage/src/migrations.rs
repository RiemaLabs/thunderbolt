use std::path::Path;

use rusqlite::{Connection, Transaction, TransactionBehavior};
use sha2::{Digest, Sha256};
use thunderbolt_protocol::ProtocolLimits;

use crate::error::{Result, StorageError};

pub(crate) const APPLICATION_ID: i64 = 0x5442_5354; // "TBST"
/// Latest SQLite schema version understood by this crate.
pub const CURRENT_SCHEMA_VERSION: i64 = 2;

const MIGRATION_1: &str = r#"
CREATE TABLE schema_migrations (
    version       INTEGER PRIMARY KEY,
    name          TEXT NOT NULL UNIQUE,
    checksum      BLOB NOT NULL CHECK (length(checksum) = 32),
    applied_at_ms INTEGER NOT NULL CHECK (applied_at_ms >= 0)
) STRICT;

CREATE TABLE storage_settings (
    singleton                   INTEGER PRIMARY KEY CHECK (singleton = 1),
    max_entries_per_channel     INTEGER NOT NULL CHECK (max_entries_per_channel > 0),
    max_verifications_per_event INTEGER NOT NULL CHECK (max_verifications_per_event > 0)
) STRICT;

CREATE TABLE ledger_entries (
    channel_id         TEXT NOT NULL CHECK (length(channel_id) BETWEEN 66 AND 75),
    sequence           INTEGER NOT NULL CHECK (sequence >= 0),
    entry_hash         BLOB NOT NULL CHECK (length(entry_hash) = 32),
    previous_entry_hash BLOB NOT NULL CHECK (length(previous_entry_hash) = 32),
    idempotency_key    TEXT NOT NULL CHECK (length(idempotency_key) BETWEEN 1 AND 128),
    created_invoice_id TEXT CHECK (created_invoice_id IS NULL OR length(created_invoice_id) BETWEEN 1 AND 128),
    protocol_version   INTEGER NOT NULL CHECK (protocol_version > 0 AND protocol_version <= 65535),
    occurred_at_ms     INTEGER NOT NULL CHECK (occurred_at_ms >= 0),
    entry_json         BLOB NOT NULL CHECK (length(entry_json) > 0),
    recorded_at_ms     INTEGER NOT NULL CHECK (recorded_at_ms >= 0),
    PRIMARY KEY (channel_id, sequence),
    UNIQUE (channel_id, entry_hash),
    UNIQUE (channel_id, sequence, entry_hash),
    UNIQUE (channel_id, idempotency_key),
    UNIQUE (channel_id, created_invoice_id),
    FOREIGN KEY (channel_id) REFERENCES channel_snapshots(channel_id)
        ON UPDATE RESTRICT ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED
) STRICT, WITHOUT ROWID;

CREATE TABLE channel_snapshots (
    channel_id       TEXT PRIMARY KEY NOT NULL CHECK (length(channel_id) BETWEEN 66 AND 75),
    head_sequence    INTEGER NOT NULL CHECK (head_sequence >= 0),
    head_entry_hash  BLOB NOT NULL CHECK (length(head_entry_hash) = 32),
    snapshot_json    BLOB NOT NULL CHECK (length(snapshot_json) > 0),
    created_at_ms    INTEGER NOT NULL CHECK (created_at_ms >= 0),
    updated_at_ms    INTEGER NOT NULL CHECK (updated_at_ms >= created_at_ms),
    FOREIGN KEY (channel_id, head_sequence, head_entry_hash)
        REFERENCES ledger_entries(channel_id, sequence, entry_hash)
        ON UPDATE RESTRICT ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED
) STRICT, WITHOUT ROWID;

CREATE INDEX ledger_entries_channel_sequence_idx
    ON ledger_entries(channel_id, sequence);

CREATE INDEX channels_updated_idx
    ON channel_snapshots(updated_at_ms, channel_id);

CREATE TRIGGER ledger_entries_no_update
BEFORE UPDATE ON ledger_entries
BEGIN
    SELECT RAISE(ABORT, 'Thunderbolt ledger entries are immutable');
END;

CREATE TRIGGER ledger_entries_no_delete
BEFORE DELETE ON ledger_entries
BEGIN
    SELECT RAISE(ABORT, 'Thunderbolt ledger entries are immutable');
END;

CREATE TRIGGER ledger_entries_no_replace_sequence
BEFORE INSERT ON ledger_entries
WHEN EXISTS (
    SELECT 1 FROM ledger_entries AS existing
    WHERE existing.channel_id = NEW.channel_id
      AND existing.sequence = NEW.sequence
)
BEGIN
    SELECT RAISE(ABORT, 'Thunderbolt ledger entries cannot be replaced');
END;

CREATE TRIGGER ledger_entries_no_replace_hash
BEFORE INSERT ON ledger_entries
WHEN EXISTS (
    SELECT 1 FROM ledger_entries AS existing
    WHERE existing.channel_id = NEW.channel_id
      AND existing.entry_hash = NEW.entry_hash
)
BEGIN
    SELECT RAISE(ABORT, 'Thunderbolt ledger entries cannot be replaced');
END;

CREATE TRIGGER ledger_entries_no_replace_idempotency
BEFORE INSERT ON ledger_entries
WHEN EXISTS (
    SELECT 1 FROM ledger_entries AS existing
    WHERE existing.channel_id = NEW.channel_id
      AND existing.idempotency_key = NEW.idempotency_key
)
BEGIN
    SELECT RAISE(ABORT, 'Thunderbolt ledger entries cannot be replaced');
END;

CREATE TRIGGER ledger_entries_no_replace_invoice
BEFORE INSERT ON ledger_entries
WHEN NEW.created_invoice_id IS NOT NULL AND EXISTS (
    SELECT 1 FROM ledger_entries AS existing
    WHERE existing.channel_id = NEW.channel_id
      AND existing.created_invoice_id = NEW.created_invoice_id
)
BEGIN
    SELECT RAISE(ABORT, 'Thunderbolt ledger entries cannot be replaced');
END;
"#;

const MIGRATION_2: &str = r#"
CREATE TABLE verification_evidence (
    channel_id     TEXT NOT NULL CHECK (length(channel_id) BETWEEN 66 AND 75),
    sequence       INTEGER NOT NULL CHECK (sequence >= 0),
    evidence_index INTEGER NOT NULL CHECK (evidence_index >= 0),
    evidence_json  BLOB NOT NULL CHECK (length(evidence_json) > 0),
    PRIMARY KEY (channel_id, sequence, evidence_index),
    FOREIGN KEY (channel_id, sequence)
        REFERENCES ledger_entries(channel_id, sequence)
        ON UPDATE RESTRICT ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED
) STRICT, WITHOUT ROWID;

CREATE TABLE verified_requests (
    proposal_digest BLOB PRIMARY KEY NOT NULL CHECK (length(proposal_digest) = 32),
    channel_id      TEXT NOT NULL CHECK (length(channel_id) BETWEEN 66 AND 75),
    actor_id        TEXT NOT NULL CHECK (length(actor_id) BETWEEN 1 AND 128),
    idempotency_key TEXT NOT NULL CHECK (length(idempotency_key) BETWEEN 1 AND 128),
    sequence        INTEGER NOT NULL CHECK (sequence >= 0),
    entry_hash      BLOB NOT NULL CHECK (length(entry_hash) = 32),
    snapshot_json   BLOB NOT NULL CHECK (length(snapshot_json) > 0),
    recorded_at_ms  INTEGER NOT NULL CHECK (recorded_at_ms >= 0),
    UNIQUE (channel_id, sequence),
    UNIQUE (channel_id, idempotency_key),
    FOREIGN KEY (channel_id, sequence, entry_hash)
        REFERENCES ledger_entries(channel_id, sequence, entry_hash)
        ON UPDATE RESTRICT ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED
) STRICT, WITHOUT ROWID;

CREATE INDEX verified_requests_channel_sequence_idx
    ON verified_requests(channel_id, sequence);

CREATE TRIGGER verification_evidence_no_update
BEFORE UPDATE ON verification_evidence
BEGIN
    SELECT RAISE(ABORT, 'Thunderbolt verification evidence is immutable');
END;

CREATE TRIGGER verification_evidence_no_delete
BEFORE DELETE ON verification_evidence
BEGIN
    SELECT RAISE(ABORT, 'Thunderbolt verification evidence is immutable');
END;

CREATE TRIGGER verification_evidence_no_replace
BEFORE INSERT ON verification_evidence
WHEN EXISTS (
    SELECT 1 FROM verification_evidence AS existing
    WHERE existing.channel_id = NEW.channel_id
      AND existing.sequence = NEW.sequence
      AND existing.evidence_index = NEW.evidence_index
)
BEGIN
    SELECT RAISE(ABORT, 'Thunderbolt verification evidence cannot be replaced');
END;

CREATE TRIGGER verified_requests_no_update
BEFORE UPDATE ON verified_requests
BEGIN
    SELECT RAISE(ABORT, 'Thunderbolt verified request mappings are immutable');
END;

CREATE TRIGGER verified_requests_no_delete
BEFORE DELETE ON verified_requests
BEGIN
    SELECT RAISE(ABORT, 'Thunderbolt verified request mappings are immutable');
END;

CREATE TRIGGER verified_requests_no_replace
BEFORE INSERT ON verified_requests
WHEN EXISTS (
    SELECT 1 FROM verified_requests AS existing
    WHERE existing.proposal_digest = NEW.proposal_digest
       OR (existing.channel_id = NEW.channel_id AND existing.sequence = NEW.sequence)
       OR (existing.channel_id = NEW.channel_id AND existing.idempotency_key = NEW.idempotency_key)
)
BEGIN
    SELECT RAISE(ABORT, 'Thunderbolt verified request mappings cannot be replaced');
END;
"#;

pub(crate) fn migrate(
    connection: &mut Connection,
    path: &Path,
    applied_at_ms: i64,
    limits: ProtocolLimits,
) -> Result<()> {
    // Metadata must be read only after the write lock is held. Otherwise two
    // processes opening a fresh database can both observe version zero and the
    // second process will attempt to reapply migration 1.
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let migration_result = inspect_and_apply(&transaction, path, applied_at_ms, limits);
    finish_transaction(transaction, migration_result)
}

fn inspect_and_apply(connection: &Connection, path: &Path, applied_at_ms: i64, limits: ProtocolLimits) -> Result<()> {
    let application_id: i64 = connection.pragma_query_value(None, "application_id", |row| row.get(0))?;
    let version: i64 = connection.pragma_query_value(None, "user_version", |row| row.get(0))?;

    if application_id != 0 && application_id != APPLICATION_ID {
        return Err(StorageError::WrongApplication {
            path: path.to_path_buf(),
            found: application_id,
        });
    }
    if version < 0 {
        return Err(StorageError::InvalidSchemaVersion { found: version });
    }
    if version > CURRENT_SCHEMA_VERSION {
        return Err(StorageError::UnsupportedSchema {
            found: version,
            supported: CURRENT_SCHEMA_VERSION,
        });
    }
    if version > 0 && application_id != APPLICATION_ID {
        return Err(StorageError::WrongApplication {
            path: path.to_path_buf(),
            found: application_id,
        });
    }
    if version == 0 && application_id == 0 {
        let has_user_objects: bool = connection.query_row(
            "SELECT EXISTS(
                 SELECT 1 FROM sqlite_schema
                 WHERE name NOT LIKE 'sqlite_%'
             )",
            [],
            |row| row.get(0),
        )?;
        if has_user_objects {
            return Err(StorageError::UnrecognizedDatabase(path.to_path_buf()));
        }
    }

    if version == CURRENT_SCHEMA_VERSION {
        verify_migration_checksums(connection)?;
        return verify_protocol_limits(connection, limits);
    }
    apply_pending(connection, version, applied_at_ms, limits)
}

pub(crate) fn validate_current(connection: &Connection, path: &Path, limits: ProtocolLimits) -> Result<()> {
    let application_id: i64 = connection.pragma_query_value(None, "application_id", |row| row.get(0))?;
    if application_id != APPLICATION_ID {
        return Err(StorageError::WrongApplication {
            path: path.to_path_buf(),
            found: application_id,
        });
    }
    let version: i64 = connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
    if version > CURRENT_SCHEMA_VERSION {
        return Err(StorageError::UnsupportedSchema {
            found: version,
            supported: CURRENT_SCHEMA_VERSION,
        });
    }
    if version != CURRENT_SCHEMA_VERSION {
        return Err(StorageError::CorruptData(format!(
            "backup schema version is {version}, expected {CURRENT_SCHEMA_VERSION}"
        )));
    }
    verify_migration_checksums(connection)?;
    verify_protocol_limits(connection, limits)
}

fn apply_pending(transaction: &Connection, version: i64, applied_at_ms: i64, limits: ProtocolLimits) -> Result<()> {
    if version > 0 {
        verify_migration_checksums_through(transaction, version)?;
    }
    if version == 0 {
        transaction.execute_batch(MIGRATION_1)?;
        let checksum = migration_checksum(MIGRATION_1);
        transaction.execute(
            "INSERT INTO schema_migrations(version, name, checksum, applied_at_ms) VALUES (?1, ?2, ?3, ?4)",
            (1_i64, "initial durable ledger", checksum.as_slice(), applied_at_ms),
        )?;
        transaction.pragma_update(None, "application_id", APPLICATION_ID)?;
        transaction.pragma_update(None, "user_version", 1_i64)?;
        transaction.execute(
            "INSERT INTO storage_settings(
                 singleton, max_entries_per_channel, max_verifications_per_event
             ) VALUES (1, ?1, ?2)",
            (
                i64::try_from(limits.max_entries_per_channel).map_err(|_| {
                    StorageError::InvalidInput("max_entries_per_channel exceeds SQLite INTEGER range".to_string())
                })?,
                i64::try_from(limits.max_verifications_per_event).map_err(|_| {
                    StorageError::InvalidInput("max_verifications_per_event exceeds SQLite INTEGER range".to_string())
                })?,
            ),
        )?;
    }
    if version < 2 {
        transaction.execute_batch(MIGRATION_2)?;
        let checksum = migration_checksum(MIGRATION_2);
        transaction.execute(
            "INSERT INTO schema_migrations(version, name, checksum, applied_at_ms) VALUES (?1, ?2, ?3, ?4)",
            (
                2_i64,
                "transaction-scoped verified append",
                checksum.as_slice(),
                applied_at_ms,
            ),
        )?;
        transaction.pragma_update(None, "user_version", 2_i64)?;
    }
    Ok(())
}

fn verify_protocol_limits(connection: &Connection, requested: ProtocolLimits) -> Result<()> {
    let (stored_entries, stored_verifications): (i64, i64) = connection.query_row(
        "SELECT max_entries_per_channel, max_verifications_per_event
         FROM storage_settings WHERE singleton = 1",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    let stored_entries = u64::try_from(stored_entries)
        .map_err(|_| StorageError::CorruptData("stored entry limit is negative".to_string()))?;
    let stored_verifications = usize::try_from(stored_verifications)
        .map_err(|_| StorageError::CorruptData("stored verification limit is negative".to_string()))?;
    if stored_entries != requested.max_entries_per_channel
        || stored_verifications != requested.max_verifications_per_event
    {
        return Err(StorageError::ProtocolLimitsMismatch {
            stored_entries,
            stored_verifications,
            requested_entries: requested.max_entries_per_channel,
            requested_verifications: requested.max_verifications_per_event,
        });
    }
    Ok(())
}

fn verify_migration_checksums(connection: &Connection) -> Result<()> {
    verify_migration_checksums_through(connection, CURRENT_SCHEMA_VERSION)
}

fn verify_migration_checksums_through(connection: &Connection, through_version: i64) -> Result<()> {
    let expected = [migration_checksum(MIGRATION_1), migration_checksum(MIGRATION_2)];
    let mut statement = connection.prepare("SELECT version, checksum FROM schema_migrations ORDER BY version")?;
    let mut rows = statement.query([])?;
    let mut found = 0_i64;
    while let Some(row) = rows.next()? {
        let version: i64 = row.get(0)?;
        let checksum: Vec<u8> = row.get(1)?;
        found += 1;
        let expected_checksum = usize::try_from(version - 1).ok().and_then(|index| expected.get(index));
        if version != found
            || version > through_version
            || expected_checksum.is_none_or(|value| checksum.as_slice() != value.as_slice())
        {
            return Err(StorageError::MigrationChecksumMismatch { version });
        }
    }
    if found != through_version {
        return Err(StorageError::MigrationChecksumMismatch {
            version: found.saturating_add(1),
        });
    }
    Ok(())
}

fn migration_checksum(sql: &str) -> [u8; 32] {
    Sha256::digest(sql.as_bytes()).into()
}

fn finish_transaction(transaction: Transaction<'_>, result: Result<()>) -> Result<()> {
    match result {
        Ok(()) => {
            transaction.commit()?;
            Ok(())
        }
        Err(operation_error) => match transaction.rollback() {
            Ok(()) => Err(operation_error),
            Err(rollback_error) => Err(StorageError::RollbackFailed {
                operation_error: operation_error.to_string(),
                rollback_error,
            }),
        },
    }
}
