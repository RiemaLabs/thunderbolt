use std::path::Path;

use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use sha2::{Digest as _, Sha256};
use thunderbolt_ledger::LedgerChainIdV2;
use thunderbolt_protocol::v2::ProtocolLimitsV2;

use crate::{ApplicationError, Result};

pub(crate) const APPLICATION_ID: i64 = 0x5442_4c41; // "TBLA"
/// Latest schema version understood by this crate.
pub const CURRENT_SCHEMA_VERSION: i64 = 1;

const MIGRATION_1: &str = r#"
CREATE TABLE schema_migrations (
    version  INTEGER PRIMARY KEY,
    name     TEXT NOT NULL UNIQUE,
    checksum BLOB NOT NULL CHECK (length(checksum) = 32)
) STRICT;

CREATE TABLE application_state (
    singleton                 INTEGER PRIMARY KEY CHECK (singleton = 1),
    application_version       INTEGER NOT NULL CHECK (application_version = 2),
    ledger_chain_id           TEXT NOT NULL,
    max_entries_per_channel   INTEGER NOT NULL CHECK (max_entries_per_channel >= 2),
    max_pending_invoices      INTEGER NOT NULL CHECK (max_pending_invoices > 0),
    max_invoice_ttl_ms        INTEGER NOT NULL CHECK (max_invoice_ttl_ms > 0),
    last_height               INTEGER NOT NULL CHECK (last_height >= 0),
    last_block_time_ms        INTEGER NOT NULL CHECK (last_block_time_ms >= 0),
    last_app_hash             BLOB NOT NULL CHECK (length(last_app_hash) = 32),
    last_block_json           BLOB
) STRICT;

CREATE TABLE blocks (
    height                    INTEGER PRIMARY KEY CHECK (height > 0),
    block_time_ms             INTEGER NOT NULL CHECK (block_time_ms > 0),
    previous_app_hash         BLOB NOT NULL CHECK (length(previous_app_hash) = 32),
    app_hash                  BLOB NOT NULL CHECK (length(app_hash) = 32),
    entry_count               INTEGER NOT NULL CHECK (entry_count >= 0),
    executed_block_json       BLOB NOT NULL CHECK (length(executed_block_json) > 0)
) STRICT;

CREATE TABLE executed_entries (
    height                    INTEGER NOT NULL CHECK (height > 0),
    block_index               INTEGER NOT NULL CHECK (block_index >= 0),
    channel_context_id        BLOB NOT NULL CHECK (length(channel_context_id) = 32),
    participant_id            BLOB NOT NULL CHECK (length(participant_id) = 32),
    request_digest            BLOB NOT NULL CHECK (length(request_digest) = 32),
    entry_hash                BLOB NOT NULL CHECK (length(entry_hash) = 32),
    disposition               INTEGER NOT NULL CHECK (disposition IN (1, 2)),
    canonical_event           BLOB NOT NULL CHECK (length(canonical_event) > 0),
    executed_entry_json       BLOB NOT NULL CHECK (length(executed_entry_json) > 0),
    state_hash_after          BLOB NOT NULL CHECK (length(state_hash_after) = 32),
    PRIMARY KEY (height, block_index)
) STRICT, WITHOUT ROWID;

CREATE TABLE request_index (
    channel_context_id        BLOB NOT NULL CHECK (length(channel_context_id) = 32),
    participant_id            BLOB NOT NULL CHECK (length(participant_id) = 32),
    request_digest            BLOB NOT NULL CHECK (length(request_digest) = 32),
    entry_hash                BLOB NOT NULL CHECK (length(entry_hash) = 32),
    first_height              INTEGER NOT NULL CHECK (first_height > 0),
    first_block_index         INTEGER NOT NULL CHECK (first_block_index >= 0),
    PRIMARY KEY (channel_context_id, participant_id, request_digest)
) STRICT, WITHOUT ROWID;

CREATE TABLE channel_snapshots (
    channel_context_id        BLOB PRIMARY KEY NOT NULL CHECK (length(channel_context_id) = 32),
    snapshot_json             BLOB NOT NULL CHECK (length(snapshot_json) > 0),
    state_hash                BLOB NOT NULL CHECK (length(state_hash) = 32),
    last_entry_json           BLOB NOT NULL CHECK (length(last_entry_json) > 0),
    updated_height            INTEGER NOT NULL CHECK (updated_height > 0),
    updated_block_index       INTEGER NOT NULL CHECK (updated_block_index >= 0)
) STRICT, WITHOUT ROWID;

CREATE TABLE invoice_history (
    channel_context_id        BLOB NOT NULL CHECK (length(channel_context_id) = 32),
    invoice_id                BLOB NOT NULL CHECK (length(invoice_id) > 0),
    entry_hash                BLOB NOT NULL CHECK (length(entry_hash) = 32),
    committed_height          INTEGER NOT NULL CHECK (committed_height > 0),
    committed_block_index     INTEGER NOT NULL CHECK (committed_block_index >= 0),
    PRIMARY KEY (channel_context_id, invoice_id)
) STRICT, WITHOUT ROWID;

CREATE INDEX executed_entries_channel_idx
    ON executed_entries(channel_context_id, height, block_index);
CREATE INDEX request_index_location_idx
    ON request_index(first_height, first_block_index);

CREATE TRIGGER blocks_no_update BEFORE UPDATE ON blocks
BEGIN SELECT RAISE(ABORT, 'executed blocks are immutable'); END;
CREATE TRIGGER blocks_no_delete BEFORE DELETE ON blocks
BEGIN SELECT RAISE(ABORT, 'executed blocks are immutable'); END;
CREATE TRIGGER executed_entries_no_update BEFORE UPDATE ON executed_entries
BEGIN SELECT RAISE(ABORT, 'executed entries are immutable'); END;
CREATE TRIGGER executed_entries_no_delete BEFORE DELETE ON executed_entries
BEGIN SELECT RAISE(ABORT, 'executed entries are immutable'); END;
CREATE TRIGGER request_index_no_update BEFORE UPDATE ON request_index
BEGIN SELECT RAISE(ABORT, 'request mappings are immutable'); END;
CREATE TRIGGER request_index_no_delete BEFORE DELETE ON request_index
BEGIN SELECT RAISE(ABORT, 'request mappings are immutable'); END;
CREATE TRIGGER invoice_history_no_update BEFORE UPDATE ON invoice_history
BEGIN SELECT RAISE(ABORT, 'invoice history is immutable'); END;
CREATE TRIGGER invoice_history_no_delete BEFORE DELETE ON invoice_history
BEGIN SELECT RAISE(ABORT, 'invoice history is immutable'); END;
"#;

pub(crate) fn migrate(
    connection: &mut Connection,
    path: &Path,
    chain_id: &LedgerChainIdV2,
    limits: ProtocolLimitsV2,
) -> Result<()> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let result = migrate_locked(&transaction, path, chain_id, limits);
    match result {
        Ok(()) => transaction.commit().map_err(ApplicationError::from),
        Err(error) => match transaction.rollback() {
            Ok(()) => Err(error),
            Err(rollback_error) => Err(ApplicationError::RollbackFailed {
                operation_error: error.to_string(),
                rollback_error,
            }),
        },
    }
}

fn migrate_locked(
    connection: &Connection,
    path: &Path,
    chain_id: &LedgerChainIdV2,
    limits: ProtocolLimitsV2,
) -> Result<()> {
    let application_id: i64 = connection.pragma_query_value(None, "application_id", |row| row.get(0))?;
    let version: i64 = connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
    if application_id != 0 && application_id != APPLICATION_ID {
        return Err(ApplicationError::WrongApplication {
            path: path.to_path_buf(),
            found: application_id,
        });
    }
    if version > CURRENT_SCHEMA_VERSION {
        return Err(ApplicationError::UnsupportedSchema {
            found: version,
            supported: CURRENT_SCHEMA_VERSION,
        });
    }
    if version > 0 && application_id != APPLICATION_ID {
        return Err(ApplicationError::WrongApplication {
            path: path.to_path_buf(),
            found: application_id,
        });
    }
    if version == 0 && application_id == 0 {
        let has_objects: bool = connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%')",
            [],
            |row| row.get(0),
        )?;
        if has_objects {
            return Err(ApplicationError::UnrecognizedDatabase(path.to_path_buf()));
        }
        connection.execute_batch(MIGRATION_1)?;
        connection.execute(
            "INSERT INTO schema_migrations(version, name, checksum) VALUES (1, ?1, ?2)",
            params![
                "initial v2 Ledger application",
                migration_checksum(MIGRATION_1).as_slice()
            ],
        )?;
        connection.execute(
            "INSERT INTO application_state(
                 singleton, application_version, ledger_chain_id, max_entries_per_channel,
                 max_pending_invoices, max_invoice_ttl_ms, last_height,
                 last_block_time_ms, last_app_hash, last_block_json
             ) VALUES (1, 2, ?1, ?2, ?3, ?4, 0, 0, zeroblob(32), NULL)",
            params![
                chain_id.as_str(),
                to_sql_u64("max_entries_per_channel", limits.max_entries_per_channel)?,
                to_sql_usize("max_pending_invoices", limits.max_pending_invoices)?,
                to_sql_u64("max_invoice_ttl_ms", limits.max_invoice_ttl_ms)?,
            ],
        )?;
        connection.pragma_update(None, "application_id", APPLICATION_ID)?;
        connection.pragma_update(None, "user_version", CURRENT_SCHEMA_VERSION)?;
    }
    verify_migration(connection)?;
    verify_configuration(connection, chain_id, limits)
}

pub(crate) fn verify_current(connection: &Connection) -> Result<()> {
    let application_id: i64 = connection.pragma_query_value(None, "application_id", |row| row.get(0))?;
    let version: i64 = connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
    if application_id != APPLICATION_ID {
        return Err(ApplicationError::CorruptData(
            "database application id changed".to_owned(),
        ));
    }
    if version != CURRENT_SCHEMA_VERSION {
        return Err(ApplicationError::UnsupportedSchema {
            found: version,
            supported: CURRENT_SCHEMA_VERSION,
        });
    }
    verify_migration(connection)
}

fn verify_migration(connection: &Connection) -> Result<()> {
    let checksum: Option<Vec<u8>> = connection
        .query_row(
            "SELECT checksum FROM schema_migrations WHERE version = 1 AND name = ?1",
            ["initial v2 Ledger application"],
            |row| row.get(0),
        )
        .optional()?;
    if checksum.as_deref() != Some(migration_checksum(MIGRATION_1).as_slice()) {
        return Err(ApplicationError::MigrationChecksumMismatch { version: 1 });
    }
    Ok(())
}

fn verify_configuration(connection: &Connection, chain_id: &LedgerChainIdV2, limits: ProtocolLimitsV2) -> Result<()> {
    let stored: (i64, String, i64, i64, i64) = connection.query_row(
        "SELECT application_version, ledger_chain_id, max_entries_per_channel,
                max_pending_invoices, max_invoice_ttl_ms
         FROM application_state WHERE singleton = 1",
        [],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)),
    )?;
    let requested = (
        chain_id.as_str(),
        to_sql_u64("max_entries_per_channel", limits.max_entries_per_channel)?,
        to_sql_usize("max_pending_invoices", limits.max_pending_invoices)?,
        to_sql_u64("max_invoice_ttl_ms", limits.max_invoice_ttl_ms)?,
    );
    if stored.0 != crate::APPLICATION_VERSION_V2 as i64
        || stored.1 != requested.0
        || stored.2 != requested.1
        || stored.3 != requested.2
        || stored.4 != requested.3
    {
        return Err(ApplicationError::ConfigurationMismatch);
    }
    Ok(())
}

fn migration_checksum(sql: &str) -> [u8; 32] {
    Sha256::digest(sql.as_bytes()).into()
}

fn to_sql_u64(label: &'static str, value: u64) -> Result<i64> {
    i64::try_from(value).map_err(|_| ApplicationError::IntegerRange(label))
}

fn to_sql_usize(label: &'static str, value: usize) -> Result<i64> {
    i64::try_from(value).map_err(|_| ApplicationError::IntegerRange(label))
}
