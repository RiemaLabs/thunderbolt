use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};

use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use sha2::{Digest, Sha256};

use crate::types::{MAX_BUNDLE_BYTES, MAX_OUTBOX_BYTES};
use crate::{
    AcknowledgementRecord, FinalityDigest, IngestDisposition, LedgerCursor, NodeConfig, NodeError, OutboxItem,
    OutboxStatus, Result,
};

const APPLICATION_ID: i64 = 0x5442_434e; // TBCN
const SCHEMA_VERSION: i64 = 1;
type SettingsRow = (Vec<u8>, i64, Vec<u8>, i64, String, i64, i64);

pub(crate) struct StoredInbox {
    pub id: [u8; 32],
    pub bundle: Vec<u8>,
}

pub(crate) struct SqliteQueue {
    path: PathBuf,
    connection: Mutex<Connection>,
    max_inbox: u32,
    max_outbox: u32,
}

impl SqliteQueue {
    pub fn open(
        path: impl AsRef<Path>,
        config: &NodeConfig,
        deployment_id: &[u8],
        epoch: u64,
        descriptor_id: &[u8; 32],
        member_id: u32,
    ) -> Result<Self> {
        if path.as_ref().as_os_str().is_empty() {
            return Err(NodeError::InvalidConfiguration("database path is empty"));
        }
        let mut connection = Connection::open(path.as_ref())?;
        connection.pragma_update(None, "foreign_keys", true)?;
        connection.pragma_update(None, "journal_mode", "WAL")?;
        connection.pragma_update(None, "synchronous", "FULL")?;
        connection.busy_timeout(std::time::Duration::from_secs(5))?;
        let application_id: i64 = connection.pragma_query_value(None, "application_id", |row| row.get(0))?;
        let schema_version: i64 = connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
        if (application_id != 0 && application_id != APPLICATION_ID)
            || !(0..=SCHEMA_VERSION).contains(&schema_version)
            || (schema_version > 0 && application_id != APPLICATION_ID)
        {
            return Err(NodeError::CorruptState);
        }
        if application_id == 0
            && connection.query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%')",
                [],
                |row| row.get::<_, bool>(0),
            )?
        {
            return Err(NodeError::CorruptState);
        }
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        transaction.execute_batch(
            "CREATE TABLE IF NOT EXISTS node_settings(
                 singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                 deployment_id BLOB NOT NULL,
                 committee_epoch INTEGER NOT NULL CHECK(committee_epoch>0),
                 descriptor_id BLOB NOT NULL CHECK(length(descriptor_id)=32),
                 member_id INTEGER NOT NULL CHECK(member_id>0),
                 ledger_chain_id TEXT NOT NULL,
                 max_inbox INTEGER NOT NULL CHECK(max_inbox>0),
                 max_outbox INTEGER NOT NULL CHECK(max_outbox>0)
             ) STRICT;
             CREATE TABLE IF NOT EXISTS finalized_cursor(
                 singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                 block_height INTEGER NOT NULL CHECK(block_height>0),
                 block_index INTEGER NOT NULL CHECK(block_index>=0),
                 app_hash BLOB NOT NULL CHECK(length(app_hash)=32),
                 entry_hash BLOB NOT NULL CHECK(length(entry_hash)=32),
                 finality_digest BLOB NOT NULL CHECK(length(finality_digest)=32)
             ) STRICT;
             CREATE TABLE IF NOT EXISTS inbox(
                 ordinal INTEGER PRIMARY KEY AUTOINCREMENT,
                 item_id BLOB NOT NULL UNIQUE CHECK(length(item_id)=32),
                 request_digest BLOB NOT NULL UNIQUE CHECK(length(request_digest)=32),
                 bundle_digest BLOB NOT NULL CHECK(length(bundle_digest)=32),
                 bundle_json BLOB NOT NULL,
                 status INTEGER NOT NULL CHECK(status IN (0,1)),
                 ack_digest BLOB CHECK(ack_digest IS NULL OR length(ack_digest)=32)
             ) STRICT;
             CREATE TABLE IF NOT EXISTS outbox(
                 ordinal INTEGER PRIMARY KEY AUTOINCREMENT,
                 item_id BLOB NOT NULL UNIQUE CHECK(length(item_id)=32),
                 inbox_id BLOB NOT NULL UNIQUE CHECK(length(inbox_id)=32),
                 payload_json BLOB NOT NULL,
                 status INTEGER NOT NULL CHECK(status BETWEEN 0 AND 3),
                 attempts INTEGER NOT NULL CHECK(attempts>=0),
                 FOREIGN KEY(inbox_id) REFERENCES inbox(item_id)
             ) STRICT;",
        )?;
        transaction.pragma_update(None, "application_id", APPLICATION_ID)?;
        transaction.pragma_update(None, "user_version", SCHEMA_VERSION)?;
        let existing: Option<SettingsRow> = transaction
            .query_row(
                "SELECT deployment_id,committee_epoch,descriptor_id,member_id,ledger_chain_id,max_inbox,max_outbox
                 FROM node_settings WHERE singleton=1",
                [],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                        row.get(6)?,
                    ))
                },
            )
            .optional()?;
        let expected = (
            deployment_id,
            i64::try_from(epoch).map_err(|_| NodeError::NumericRange)?,
            descriptor_id.as_slice(),
            i64::from(member_id),
            config.ledger_chain_id.as_str(),
            i64::from(config.max_inbox_rows),
            i64::from(config.max_outbox_rows),
        );
        match existing {
            Some(row)
                if row.0.as_slice() == expected.0
                    && row.1 == expected.1
                    && row.2.as_slice() == expected.2
                    && row.3 == expected.3
                    && row.4 == expected.4
                    && row.5 == expected.5
                    && row.6 == expected.6 => {}
            Some(_) => return Err(NodeError::IdentityMismatch),
            None => {
                transaction.execute(
                    "INSERT INTO node_settings VALUES(1,?1,?2,?3,?4,?5,?6,?7)",
                    params![expected.0, expected.1, expected.2, expected.3, expected.4, expected.5, expected.6],
                )?;
            }
        }
        transaction.commit()?;
        Ok(Self {
            path: path.as_ref().to_path_buf(),
            connection: Mutex::new(connection),
            max_inbox: config.max_inbox_rows,
            max_outbox: config.max_outbox_rows,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn ingest(
        &self,
        item_id: [u8; 32],
        request_digest: [u8; 32],
        bundle: Vec<u8>,
        cursor: &LedgerCursor,
    ) -> Result<IngestDisposition> {
        if bundle.is_empty() || bundle.len() > MAX_BUNDLE_BYTES {
            return Err(NodeError::InvalidLedgerArtifact);
        }
        let bundle_digest: [u8; 32] = Sha256::digest(&bundle).into();
        let mut connection = self.lock()?;
        let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(existing) = tx
            .query_row(
                "SELECT bundle_digest FROM inbox WHERE item_id=?1",
                [item_id.as_slice()],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()?
        {
            return if existing.as_slice() == bundle_digest {
                tx.commit()?;
                Ok(IngestDisposition::Replay)
            } else {
                Err(NodeError::ReplayConflict)
            };
        }
        if tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM inbox WHERE request_digest=?1)",
            [request_digest.as_slice()],
            |row| row.get::<_, bool>(0),
        )? {
            return Err(NodeError::ReplayConflict);
        }
        let count: i64 = tx.query_row("SELECT count(*) FROM inbox", [], |row| row.get(0))?;
        if u32::try_from(count).map_err(|_| NodeError::CorruptState)? >= self.max_inbox {
            return Err(NodeError::QueueFull);
        }
        validate_cursor(&tx, cursor)?;
        tx.execute(
            "INSERT INTO inbox(item_id,request_digest,bundle_digest,bundle_json,status)
             VALUES(?1,?2,?3,?4,0)",
            params![
                item_id.as_slice(),
                request_digest.as_slice(),
                bundle_digest.as_slice(),
                bundle
            ],
        )?;
        tx.execute(
            "INSERT INTO finalized_cursor VALUES(1,?1,?2,?3,?4,?5)
             ON CONFLICT(singleton) DO UPDATE SET
               block_height=excluded.block_height,block_index=excluded.block_index,
               app_hash=excluded.app_hash,entry_hash=excluded.entry_hash,
               finality_digest=excluded.finality_digest",
            params![
                to_i64(cursor.block_height)?,
                i64::from(cursor.block_index),
                cursor.app_hash.as_bytes().as_slice(),
                cursor.entry_hash.as_bytes().as_slice(),
                cursor.finality_digest.as_bytes().as_slice()
            ],
        )?;
        tx.commit()?;
        Ok(IngestDisposition::Accepted)
    }

    pub fn next_pending(&self) -> Result<Option<StoredInbox>> {
        let connection = self.lock()?;
        connection
            .query_row(
                "SELECT item_id,bundle_json FROM inbox WHERE status=0 ORDER BY ordinal LIMIT 1",
                [],
                |row| {
                    let id: Vec<u8> = row.get(0)?;
                    let id = <[u8; 32]>::try_from(id.as_slice()).map_err(|_| rusqlite::Error::InvalidQuery)?;
                    Ok(StoredInbox {
                        id,
                        bundle: row.get(1)?,
                    })
                },
            )
            .optional()
            .map_err(NodeError::from)
    }

    pub fn mark_applied(&self, inbox_id: [u8; 32], acknowledgement: &AcknowledgementRecord) -> Result<()> {
        let payload = serde_json::to_vec(acknowledgement)?;
        if payload.len() > MAX_OUTBOX_BYTES {
            return Err(NodeError::CorruptState);
        }
        let outbox_id: [u8; 32] = Sha256::digest(
            [
                b"bitcoin-thunderbolt/committee-node/outbox/v1".as_slice(),
                inbox_id.as_slice(),
                acknowledgement.acknowledgement_digest.as_slice(),
            ]
            .concat(),
        )
        .into();
        let mut connection = self.lock()?;
        let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let count: i64 = tx.query_row("SELECT count(*) FROM outbox", [], |row| row.get(0))?;
        if u32::try_from(count).map_err(|_| NodeError::CorruptState)? >= self.max_outbox
            && !tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM outbox WHERE inbox_id=?1)",
                [inbox_id.as_slice()],
                |r| r.get::<_, bool>(0),
            )?
        {
            return Err(NodeError::QueueFull);
        }
        tx.execute(
            "INSERT INTO outbox(item_id,inbox_id,payload_json,status,attempts) VALUES(?1,?2,?3,0,0)
             ON CONFLICT(inbox_id) DO NOTHING",
            params![outbox_id.as_slice(), inbox_id.as_slice(), payload],
        )?;
        tx.execute(
            "UPDATE inbox SET status=1,ack_digest=?2 WHERE item_id=?1 AND status=0",
            params![inbox_id.as_slice(), acknowledgement.acknowledgement_digest.as_slice()],
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn cursor(&self) -> Result<Option<LedgerCursor>> {
        let connection = self.lock()?;
        connection.query_row(
            "SELECT block_height,block_index,app_hash,entry_hash,finality_digest FROM finalized_cursor WHERE singleton=1",
            [], cursor_row,
        ).optional().map_err(NodeError::from)
    }

    pub fn counts(&self) -> Result<(u32, u32)> {
        let connection = self.lock()?;
        let inbox: i64 = connection.query_row("SELECT count(*) FROM inbox WHERE status=0", [], |r| r.get(0))?;
        let outbox: i64 = connection.query_row("SELECT count(*) FROM outbox WHERE status!=2", [], |r| r.get(0))?;
        Ok((
            u32::try_from(inbox).map_err(|_| NodeError::CorruptState)?,
            u32::try_from(outbox).map_err(|_| NodeError::CorruptState)?,
        ))
    }

    pub fn list_outbox(&self, limit: u16) -> Result<Vec<OutboxItem>> {
        if limit == 0 || limit > 256 {
            return Err(NodeError::InvalidConfiguration("invalid outbox page"));
        }
        let connection = self.lock()?;
        let mut statement =
            connection.prepare("SELECT item_id,payload_json,status,attempts FROM outbox ORDER BY ordinal LIMIT ?1")?;
        let rows = statement.query_map([i64::from(limit)], |row| {
            let id: Vec<u8> = row.get(0)?;
            let id = <[u8; 32]>::try_from(id.as_slice()).map_err(|_| rusqlite::Error::InvalidQuery)?;
            let payload: Vec<u8> = row.get(1)?;
            let acknowledgement = serde_json::from_slice(&payload).map_err(|_| rusqlite::Error::InvalidQuery)?;
            let status = match row.get::<_, i64>(2)? {
                0 => OutboxStatus::AwaitingSignature,
                1 => OutboxStatus::Ready,
                2 => OutboxStatus::Delivered,
                _ => OutboxStatus::Failed,
            };
            Ok(OutboxItem {
                id,
                status,
                acknowledgement,
                signed_proposal: None,
                attempts: u32::try_from(row.get::<_, i64>(3)?).map_err(|_| rusqlite::Error::InvalidQuery)?,
            })
        })?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(NodeError::from)
    }

    pub fn retry_outbox(&self, id: [u8; 32]) -> Result<()> {
        let connection = self.lock()?;
        if connection.execute(
            "UPDATE outbox SET status=0 WHERE item_id=?1 AND status=3",
            [id.as_slice()],
        )? != 1
        {
            return Err(NodeError::InvalidConfiguration("outbox item is not retryable"));
        }
        Ok(())
    }

    fn lock(&self) -> Result<MutexGuard<'_, Connection>> {
        self.connection.lock().map_err(|_| NodeError::CorruptState)
    }
}

fn validate_cursor(tx: &rusqlite::Transaction<'_>, next: &LedgerCursor) -> Result<()> {
    let current=tx.query_row("SELECT block_height,block_index,app_hash,entry_hash,finality_digest FROM finalized_cursor WHERE singleton=1",[],cursor_row).optional()?;
    if let Some(current) = current {
        if next.block_height < current.block_height
            || (next.block_height == current.block_height
                && (next.app_hash != current.app_hash || next.block_index <= current.block_index))
        {
            return Err(NodeError::CursorConflict);
        }
    }
    Ok(())
}

fn cursor_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<LedgerCursor> {
    let height: i64 = row.get(0)?;
    let index: i64 = row.get(1)?;
    let app: Vec<u8> = row.get(2)?;
    let entry: Vec<u8> = row.get(3)?;
    let finality: Vec<u8> = row.get(4)?;
    Ok(LedgerCursor {
        block_height: u64::try_from(height).map_err(|_| rusqlite::Error::InvalidQuery)?,
        block_index: u32::try_from(index).map_err(|_| rusqlite::Error::InvalidQuery)?,
        app_hash: thunderbolt_ledger::AppHashV2::from_bytes(
            <[u8; 32]>::try_from(app.as_slice()).map_err(|_| rusqlite::Error::InvalidQuery)?,
        )
        .map_err(|_| rusqlite::Error::InvalidQuery)?,
        entry_hash: thunderbolt_ledger::EntryHashV2::from_bytes(
            <[u8; 32]>::try_from(entry.as_slice()).map_err(|_| rusqlite::Error::InvalidQuery)?,
        )
        .map_err(|_| rusqlite::Error::InvalidQuery)?,
        finality_digest: FinalityDigest::new(
            <[u8; 32]>::try_from(finality.as_slice()).map_err(|_| rusqlite::Error::InvalidQuery)?,
        ),
    })
}
fn to_i64(value: u64) -> Result<i64> {
    i64::try_from(value).map_err(|_| NodeError::NumericRange)
}
