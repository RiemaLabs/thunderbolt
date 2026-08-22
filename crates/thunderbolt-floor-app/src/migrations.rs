use rusqlite::Connection;
use std::path::Path;

use crate::{FloorApplicationError, Result};

pub(crate) const APPLICATION_ID: i64 = 0x5442_4641; // TBFA
/// Current floor application schema.
pub const CURRENT_SCHEMA_VERSION: i64 = 1;

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS application_state (
    singleton              INTEGER PRIMARY KEY CHECK (singleton = 1),
    application_version    INTEGER NOT NULL CHECK (application_version = 2),
    chain_id               BLOB NOT NULL CHECK (length(chain_id) BETWEEN 1 AND 128),
    profile_digest         BLOB NOT NULL CHECK (length(profile_digest) = 32),
    registry_digest        BLOB NOT NULL CHECK (length(registry_digest) = 32),
    genesis_digest         BLOB NOT NULL CHECK (length(genesis_digest) = 32),
    last_height            INTEGER NOT NULL CHECK (last_height >= 0),
    last_block_time_ms     INTEGER NOT NULL CHECK (last_block_time_ms >= 0),
    last_app_hash          BLOB NOT NULL CHECK (length(last_app_hash) = 32)
) STRICT;

CREATE TABLE IF NOT EXISTS registry (
    ordinal                INTEGER NOT NULL UNIQUE CHECK (ordinal >= 0),
    identity_digest        BLOB PRIMARY KEY CHECK (length(identity_digest) = 32),
    network                INTEGER NOT NULL CHECK (network BETWEEN 1 AND 3),
    role                   INTEGER NOT NULL CHECK (role IN (1, 2)),
    node_id                BLOB NOT NULL CHECK (length(node_id) = 32),
    deployment_id          BLOB NOT NULL CHECK (length(deployment_id) = 32),
    committee_epoch        INTEGER NOT NULL CHECK (committee_epoch > 0),
    committee_descriptor   BLOB NOT NULL CHECK (length(committee_descriptor) = 32),
    operator_key           BLOB NOT NULL CHECK (length(operator_key) = 32)
) STRICT, WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS floor_state (
    identity_digest        BLOB PRIMARY KEY REFERENCES registry(identity_digest),
    revision               INTEGER CHECK (revision IS NULL OR revision >= 0),
    state_digest           BLOB CHECK (
        (revision IS NULL AND state_digest IS NULL) OR
        (revision IS NOT NULL AND length(state_digest) = 32)
    ),
    updated_height         INTEGER NOT NULL CHECK (updated_height >= 0),
    updated_block_index    INTEGER CHECK (updated_block_index IS NULL OR updated_block_index >= 0)
) STRICT, WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS blocks (
    height                 INTEGER PRIMARY KEY CHECK (height > 0),
    block_time_ms          INTEGER NOT NULL CHECK (block_time_ms > 0),
    previous_app_hash      BLOB NOT NULL CHECK (length(previous_app_hash) = 32),
    block_digest           BLOB NOT NULL CHECK (length(block_digest) = 32),
    result_root            BLOB NOT NULL CHECK (length(result_root) = 32),
    state_root             BLOB NOT NULL CHECK (length(state_root) = 32),
    app_hash               BLOB NOT NULL CHECK (length(app_hash) = 32),
    request_count          INTEGER NOT NULL CHECK (request_count BETWEEN 0 AND 1024)
) STRICT;

CREATE TABLE IF NOT EXISTS block_results (
    height                 INTEGER NOT NULL REFERENCES blocks(height),
    block_index            INTEGER NOT NULL CHECK (block_index >= 0),
    identity_digest        BLOB NOT NULL CHECK (length(identity_digest) = 32),
    actor_key              BLOB NOT NULL CHECK (length(actor_key) = 32),
    request_nonce          BLOB NOT NULL CHECK (length(request_nonce) = 32),
    request_digest         BLOB NOT NULL CHECK (length(request_digest) = 32),
    expected_revision      INTEGER,
    expected_digest        BLOB,
    next_revision          INTEGER NOT NULL CHECK (next_revision >= 0),
    next_digest            BLOB NOT NULL CHECK (length(next_digest) = 32),
    current_revision       INTEGER,
    current_digest         BLOB,
    disposition            INTEGER NOT NULL CHECK (disposition BETWEEN 1 AND 3),
    request_signature      BLOB NOT NULL CHECK (length(request_signature) = 64),
    result_digest          BLOB NOT NULL CHECK (length(result_digest) = 32),
    PRIMARY KEY (height, block_index)
) STRICT, WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS floor_state_history (
    height                 INTEGER NOT NULL REFERENCES blocks(height),
    identity_digest        BLOB NOT NULL REFERENCES registry(identity_digest),
    revision               INTEGER NOT NULL CHECK (revision >= 0),
    state_digest           BLOB NOT NULL CHECK (length(state_digest) = 32),
    PRIMARY KEY (identity_digest, height)
) STRICT, WITHOUT ROWID;

CREATE INDEX IF NOT EXISTS floor_state_history_by_height
ON floor_state_history(height, identity_digest);

CREATE TABLE IF NOT EXISTS history_anchor (
    singleton              INTEGER PRIMARY KEY CHECK (singleton = 1),
    chain_id               BLOB NOT NULL CHECK (length(chain_id) BETWEEN 1 AND 128),
    genesis_digest         BLOB NOT NULL CHECK (length(genesis_digest) = 32),
    profile_digest         BLOB NOT NULL CHECK (length(profile_digest) = 32),
    epoch                   INTEGER NOT NULL CHECK (epoch > 0),
    through_height          INTEGER NOT NULL CHECK (through_height > 0),
    through_time_ms         INTEGER NOT NULL CHECK (through_time_ms > 0),
    previous_app_hash       BLOB NOT NULL CHECK (length(previous_app_hash) = 32),
    through_app_hash        BLOB NOT NULL CHECK (length(through_app_hash) = 32),
    state_root              BLOB NOT NULL CHECK (length(state_root) = 32),
    snapshot_digest         BLOB NOT NULL CHECK (length(snapshot_digest) = 32),
    committing_header_hash  BLOB NOT NULL CHECK (length(committing_header_hash) = 32),
    prior_anchor_digest     BLOB CHECK (prior_anchor_digest IS NULL OR length(prior_anchor_digest) = 32),
    anchor_digest           BLOB NOT NULL CHECK (length(anchor_digest) = 32)
) STRICT;

CREATE TABLE IF NOT EXISTS history_anchor_snapshot (
    ordinal                INTEGER PRIMARY KEY CHECK (ordinal >= 0),
    identity_digest        BLOB NOT NULL UNIQUE REFERENCES registry(identity_digest),
    revision               INTEGER CHECK (revision IS NULL OR revision >= 0),
    state_digest           BLOB CHECK (
        (revision IS NULL AND state_digest IS NULL) OR
        (revision IS NOT NULL AND length(state_digest) = 32)
    )
) STRICT;

CREATE TABLE IF NOT EXISTS compaction_guard (
    singleton              INTEGER PRIMARY KEY CHECK (singleton = 1),
    active                 INTEGER NOT NULL CHECK (active IN (0, 1))
) STRICT;
INSERT OR IGNORE INTO compaction_guard VALUES (1, 0);

CREATE TRIGGER IF NOT EXISTS registry_no_update BEFORE UPDATE ON registry
BEGIN SELECT RAISE(ABORT, 'registry immutable'); END;
CREATE TRIGGER IF NOT EXISTS registry_no_delete BEFORE DELETE ON registry
BEGIN SELECT RAISE(ABORT, 'registry immutable'); END;
CREATE TRIGGER IF NOT EXISTS blocks_no_update BEFORE UPDATE ON blocks
BEGIN SELECT RAISE(ABORT, 'blocks immutable'); END;
CREATE TRIGGER IF NOT EXISTS blocks_no_delete BEFORE DELETE ON blocks
WHEN (SELECT active FROM compaction_guard WHERE singleton=1) = 0
BEGIN SELECT RAISE(ABORT, 'blocks immutable'); END;
CREATE TRIGGER IF NOT EXISTS results_no_update BEFORE UPDATE ON block_results
BEGIN SELECT RAISE(ABORT, 'results immutable'); END;
CREATE TRIGGER IF NOT EXISTS results_no_delete BEFORE DELETE ON block_results
WHEN (SELECT active FROM compaction_guard WHERE singleton=1) = 0
BEGIN SELECT RAISE(ABORT, 'results immutable'); END;
CREATE TRIGGER IF NOT EXISTS history_no_update BEFORE UPDATE ON floor_state_history
BEGIN SELECT RAISE(ABORT, 'state history immutable'); END;
CREATE TRIGGER IF NOT EXISTS history_no_delete BEFORE DELETE ON floor_state_history
WHEN (SELECT active FROM compaction_guard WHERE singleton=1) = 0
BEGIN SELECT RAISE(ABORT, 'state history immutable'); END;
"#;

pub(crate) fn migrate(connection: &Connection, path: &Path) -> Result<()> {
    let application_id: i64 = connection.pragma_query_value(None, "application_id", |row| row.get(0))?;
    let version: i64 = connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
    if (application_id != 0 && application_id != APPLICATION_ID) || version > CURRENT_SCHEMA_VERSION {
        return Err(FloorApplicationError::WrongDatabase {
            path: path.to_path_buf(),
        });
    }
    connection.execute_batch(SCHEMA)?;
    connection.pragma_update(None, "application_id", APPLICATION_ID)?;
    connection.pragma_update(None, "user_version", CURRENT_SCHEMA_VERSION)?;
    Ok(())
}
