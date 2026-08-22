use std::collections::BTreeSet;
#[cfg(unix)]
use std::fs::{File, OpenOptions};
#[cfg(not(unix))]
struct File;
use std::path::{Component, Path, PathBuf};
use std::sync::{Mutex, MutexGuard, OnceLock};

use rusqlite::{params, Connection, OpenFlags, OptionalExtension, TransactionBehavior};
use sha2::{Digest, Sha256};
use thunderbolt_ledger::AppHashV2;

use crate::types::{MAX_INBOX_RECORD_BYTES, MAX_OUTBOX_BYTES};
use crate::{
    AcknowledgementRecord, FinalityRangeIntentV2, LedgerCursor, NodeConfig, NodeError, OutboxItem, OutboxStatus,
    Result, StagedFinalityRangeCapabilityV2,
};

const APPLICATION_ID: i64 = 0x5442_434e; // TBCN
const SCHEMA_VERSION: i64 = 4;
type SettingsRow = (
    Vec<u8>,
    i64,
    Vec<u8>,
    i64,
    String,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    i64,
    i64,
);
type StagedFinalityRow = (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, i64);

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct DurableFileIdentity {
    device: u64,
    inode: u64,
}

static OPEN_DATABASES: OnceLock<Mutex<BTreeSet<DurableFileIdentity>>> = OnceLock::new();

struct ProcessFileLock(DurableFileIdentity);

impl ProcessFileLock {
    fn acquire(identity: DurableFileIdentity) -> Result<Self> {
        let mut open = OPEN_DATABASES
            .get_or_init(|| Mutex::new(BTreeSet::new()))
            .lock()
            .map_err(|_| NodeError::CorruptState)?;
        if !open.insert(identity) {
            return Err(NodeError::InvalidConfiguration(
                "database is already open in this process",
            ));
        }
        Ok(Self(identity))
    }
}

impl Drop for ProcessFileLock {
    fn drop(&mut self) {
        if let Ok(mut open) = OPEN_DATABASES.get_or_init(|| Mutex::new(BTreeSet::new())).lock() {
            open.remove(&self.0);
        }
    }
}

pub(crate) struct StoredInbox {
    pub id: [u8; 32],
    pub record: Vec<u8>,
}

pub(crate) struct StoredPendingInvoice {
    pub digest: [u8; 32],
    pub record: Vec<u8>,
}

pub(crate) struct PendingInvoiceWrite {
    pub entry_hash: [u8; 32],
    pub expires_at_ms: u64,
    pub record: Vec<u8>,
}

pub(crate) struct PendingInvoiceRemoval {
    pub entry_hash: [u8; 32],
    pub expected_digest: [u8; 32],
}

pub(crate) struct InboxWrite {
    pub item_id: [u8; 32],
    pub invoice_entry_hash: [u8; 32],
    pub request_digest: [u8; 32],
    pub record: Vec<u8>,
}

pub(crate) struct ScanCommit<'a> {
    pub expected_cursor: Option<&'a LedgerCursor>,
    pub next_cursor: &'a LedgerCursor,
    pub staged: &'a StagedFinalityRangeCapabilityV2,
    pub segment_digest: [u8; 32],
    pub expire_through_ms: u64,
    pub pending_writes: Vec<PendingInvoiceWrite>,
    pub pending_removals: Vec<PendingInvoiceRemoval>,
    pub inbox_writes: Vec<InboxWrite>,
}

pub(crate) enum ScanCommitOutcome {
    Applied { inbox_added: usize },
    Replayed,
}

pub(crate) struct SqliteQueue {
    path: PathBuf,
    file_identity: DurableFileIdentity,
    file_identity_digest: [u8; 32],
    _database_file: File,
    _process_lock: ProcessFileLock,
    connection: Mutex<Connection>,
    store_id: [u8; 32],
    max_inbox: u32,
    max_outbox: u32,
}

#[cfg(unix)]
fn prepare_durable_path(path: &Path) -> Result<(PathBuf, DurableFileIdentity, File)> {
    use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};

    let invalid = || NodeError::InvalidConfiguration("database path is not a durable owner-only file");
    let file_name = path.file_name().ok_or_else(&invalid)?;
    let magic = file_name.to_string_lossy();
    if !path.is_absolute()
        || path.as_os_str().is_empty()
        || magic == ":memory:"
        || magic.starts_with("file:")
        || magic.contains("mode=memory")
        || path
            .components()
            .any(|component| !matches!(component, Component::RootDir | Component::Normal(_)))
    {
        return Err(invalid());
    }
    reject_symlink_components(path)?;
    let parent = path.parent().ok_or_else(&invalid)?;
    let parent_metadata = std::fs::symlink_metadata(parent).map_err(|_| invalid())?;
    let effective_uid = rustix::process::geteuid().as_raw();
    if parent_metadata.file_type().is_symlink()
        || !parent_metadata.is_dir()
        || parent_metadata.uid() != effective_uid
        || parent_metadata.permissions().mode() & 0o077 != 0
        || parent_metadata.permissions().mode() & 0o300 != 0o300
    {
        return Err(invalid());
    }
    validate_safe_ancestors(parent, effective_uid)?;
    let canonical_parent = std::fs::canonicalize(parent).map_err(|_| invalid())?;
    let durable_path = canonical_parent.join(file_name);
    match std::fs::symlink_metadata(&durable_path) {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
                .open(&durable_path)
                .map_err(|_| invalid())?;
        }
        Err(_) => return Err(invalid()),
    }
    let before = std::fs::symlink_metadata(&durable_path).map_err(|_| invalid())?;
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(&durable_path)
        .map_err(|_| invalid())?;
    let after = file.metadata().map_err(|_| invalid())?;
    if before.file_type().is_symlink()
        || !before.is_file()
        || before.dev() != after.dev()
        || before.ino() != after.ino()
        || after.uid() != effective_uid
        || after.nlink() != 1
        || after.permissions().mode() & 0o600 != 0o600
        || after.permissions().mode() & 0o177 != 0
    {
        return Err(invalid());
    }
    Ok((
        durable_path,
        DurableFileIdentity {
            device: after.dev(),
            inode: after.ino(),
        },
        file,
    ))
}

#[cfg(not(unix))]
fn prepare_durable_path(_path: &Path) -> Result<(PathBuf, DurableFileIdentity, File)> {
    Err(NodeError::InvalidConfiguration(
        "durable database paths require Unix owner and inode semantics",
    ))
}

#[cfg(unix)]
fn reject_symlink_components(path: &Path) -> Result<()> {
    let mut current = PathBuf::new();
    for component in path.components() {
        match component {
            Component::RootDir => current.push(component.as_os_str()),
            Component::Normal(value) => {
                current.push(value);
                match std::fs::symlink_metadata(&current) {
                    Ok(metadata) if metadata.file_type().is_symlink() => {
                        return Err(NodeError::InvalidConfiguration("database path contains a symlink"));
                    }
                    Ok(_) => {}
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => break,
                    Err(_) => return Err(NodeError::InvalidConfiguration("database path cannot be audited")),
                }
            }
            Component::CurDir | Component::ParentDir | Component::Prefix(_) => {
                return Err(NodeError::InvalidConfiguration("database path is not normalized"));
            }
        }
    }
    Ok(())
}

#[cfg(unix)]
fn validate_safe_ancestors(path: &Path, effective_uid: u32) -> Result<()> {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    let canonical = std::fs::canonicalize(path)
        .map_err(|_| NodeError::InvalidConfiguration("database ancestry cannot be canonicalized"))?;
    for ancestor in canonical.ancestors() {
        let metadata = std::fs::symlink_metadata(ancestor)
            .map_err(|_| NodeError::InvalidConfiguration("database ancestry cannot be audited"))?;
        let mode = metadata.permissions().mode();
        if metadata.file_type().is_symlink()
            || !metadata.is_dir()
            || (metadata.uid() != 0 && metadata.uid() != effective_uid)
            || (mode & 0o022 != 0 && mode & 0o1000 == 0)
        {
            return Err(NodeError::InvalidConfiguration(
                "database ancestry is not owner controlled",
            ));
        }
    }
    Ok(())
}

fn configure_connection(connection: &Connection) -> Result<()> {
    connection.busy_timeout(std::time::Duration::from_secs(5))?;
    connection.pragma_update(None, "foreign_keys", "ON")?;
    connection.pragma_update(None, "journal_mode", "WAL")?;
    connection.pragma_update(None, "synchronous", "FULL")?;
    let foreign_keys: i64 = connection.pragma_query_value(None, "foreign_keys", |row| row.get(0))?;
    let journal_mode: String = connection.pragma_query_value(None, "journal_mode", |row| row.get(0))?;
    let synchronous: i64 = connection.pragma_query_value(None, "synchronous", |row| row.get(0))?;
    if foreign_keys != 1 || !journal_mode.eq_ignore_ascii_case("wal") || synchronous != 2 {
        return Err(NodeError::CorruptState);
    }
    Ok(())
}

fn random_store_id() -> Result<[u8; 32]> {
    let mut bytes = [0_u8; 32];
    getrandom::fill(&mut bytes).map_err(|_| NodeError::CorruptState)?;
    if bytes == [0; 32] {
        return Err(NodeError::CorruptState);
    }
    Ok(bytes)
}

#[cfg(unix)]
fn durable_file_identity_digest(path: &Path, identity: DurableFileIdentity) -> [u8; 32] {
    use std::os::unix::ffi::OsStrExt as _;

    let path_bytes = path.as_os_str().as_bytes();
    let mut hasher = Sha256::new();
    hasher.update(b"bitcoin-thunderbolt/committee-node/file-identity/v1");
    hasher.update(u64::try_from(path_bytes.len()).unwrap_or(u64::MAX).to_be_bytes());
    hasher.update(path_bytes);
    hasher.update(identity.device.to_be_bytes());
    hasher.update(identity.inode.to_be_bytes());
    hasher.finalize().into()
}

#[cfg(not(unix))]
fn durable_file_identity_digest(_path: &Path, _identity: DurableFileIdentity) -> [u8; 32] {
    [0; 32]
}

#[cfg(unix)]
fn verify_durable_file(path: &Path, expected: DurableFileIdentity) -> Result<()> {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    let metadata = std::fs::symlink_metadata(path)
        .map_err(|_| NodeError::InvalidConfiguration("database path changed after open"))?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.dev() != expected.device
        || metadata.ino() != expected.inode
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.nlink() != 1
        || metadata.permissions().mode() & 0o600 != 0o600
        || metadata.permissions().mode() & 0o177 != 0
    {
        return Err(NodeError::InvalidConfiguration("database identity changed after open"));
    }
    Ok(())
}

#[cfg(not(unix))]
fn verify_durable_file(_path: &Path, _expected: DurableFileIdentity) -> Result<()> {
    Err(NodeError::InvalidConfiguration(
        "durable database paths require Unix owner and inode semantics",
    ))
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
        let (path, file_identity, database_file) = prepare_durable_path(path.as_ref())?;
        let file_identity_digest = durable_file_identity_digest(&path, file_identity);
        let process_lock = ProcessFileLock::acquire(file_identity)?;
        let mut connection = Connection::open_with_flags(
            &path,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_CREATE
                | OpenFlags::SQLITE_OPEN_FULL_MUTEX
                | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )?;
        verify_durable_file(&path, file_identity)?;
        configure_connection(&connection)?;
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
        if matches!(schema_version, 1 | 2) {
            let legacy_rows: i64 = transaction.query_row(
                "SELECT (SELECT count(*) FROM inbox)+(SELECT count(*) FROM outbox)
                       +(SELECT count(*) FROM finalized_cursor)",
                [],
                |row| row.get(0),
            )?;
            if legacy_rows != 0 {
                return Err(NodeError::LegacyEvidenceRecords);
            }
        }
        if schema_version == 1 {
            transaction.execute_batch(
                "ALTER TABLE node_settings ADD COLUMN finality_verifier_profile BLOB
                   CHECK(finality_verifier_profile IS NULL OR length(finality_verifier_profile)=32);",
            )?;
            transaction.execute(
                "UPDATE node_settings SET finality_verifier_profile=?1 WHERE singleton=1",
                [config.finality_verifier_profile.as_bytes().as_slice()],
            )?;
        }
        let new_store_id = random_store_id()?;
        if schema_version == 3 {
            let legacy_rows: i64 = transaction.query_row(
                "SELECT (SELECT count(*) FROM finalized_cursor)
                       +(SELECT count(*) FROM pending_invoices)
                       +(SELECT count(*) FROM inbox)
                       +(SELECT count(*) FROM outbox)",
                [],
                |row| row.get(0),
            )?;
            if legacy_rows != 0 {
                return Err(NodeError::LegacyEvidenceRecords);
            }
        }
        if matches!(schema_version, 1..=3) {
            let has_coordinator: bool = transaction.query_row(
                "SELECT EXISTS(SELECT 1 FROM pragma_table_info('node_settings')
                               WHERE name='finality_coordinator_id')",
                [],
                |row| row.get(0),
            )?;
            let has_store_id: bool = transaction.query_row(
                "SELECT EXISTS(SELECT 1 FROM pragma_table_info('node_settings') WHERE name='store_id')",
                [],
                |row| row.get(0),
            )?;
            let has_file_identity: bool = transaction.query_row(
                "SELECT EXISTS(SELECT 1 FROM pragma_table_info('node_settings') WHERE name='file_identity')",
                [],
                |row| row.get(0),
            )?;
            if !has_coordinator {
                transaction.execute_batch(
                    "ALTER TABLE node_settings ADD COLUMN finality_coordinator_id BLOB
                       CHECK(finality_coordinator_id IS NULL OR length(finality_coordinator_id)=32);",
                )?;
            }
            if !has_store_id {
                transaction.execute_batch(
                    "ALTER TABLE node_settings ADD COLUMN store_id BLOB
                       CHECK(store_id IS NULL OR length(store_id)=32);",
                )?;
            }
            if !has_file_identity {
                transaction.execute_batch(
                    "ALTER TABLE node_settings ADD COLUMN file_identity BLOB
                       CHECK(file_identity IS NULL OR length(file_identity)=32);",
                )?;
            }
            transaction.execute(
                "UPDATE node_settings SET finality_coordinator_id=?1,store_id=?2,file_identity=?3 WHERE singleton=1",
                params![
                    config.finality_coordinator_id.as_bytes().as_slice(),
                    new_store_id.as_slice(),
                    file_identity_digest.as_slice()
                ],
            )?;
        }
        if matches!(schema_version, 1 | 2) {
            transaction.execute_batch("DROP TABLE outbox; DROP TABLE inbox; DROP TABLE finalized_cursor;")?;
        }
        transaction.execute_batch(
            "CREATE TABLE IF NOT EXISTS node_settings(
                 singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                 deployment_id BLOB NOT NULL,
                 committee_epoch INTEGER NOT NULL CHECK(committee_epoch>0),
                 descriptor_id BLOB NOT NULL CHECK(length(descriptor_id)=32),
                 member_id INTEGER NOT NULL CHECK(member_id>0),
                 ledger_chain_id TEXT NOT NULL,
                 finality_verifier_profile BLOB NOT NULL CHECK(length(finality_verifier_profile)=32),
                 finality_coordinator_id BLOB NOT NULL CHECK(length(finality_coordinator_id)=32),
                 store_id BLOB NOT NULL CHECK(length(store_id)=32),
                 file_identity BLOB NOT NULL CHECK(length(file_identity)=32),
                 max_inbox INTEGER NOT NULL CHECK(max_inbox>0),
                 max_outbox INTEGER NOT NULL CHECK(max_outbox>0)
             ) STRICT;
             CREATE TABLE IF NOT EXISTS finalized_cursor(
                 singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                 next_height INTEGER NOT NULL CHECK(next_height>1),
                 expected_previous_app_hash BLOB NOT NULL CHECK(length(expected_previous_app_hash)=32),
                 processed_refresh_count INTEGER NOT NULL CHECK(processed_refresh_count>=0),
                 last_refresh_entry_hash BLOB NOT NULL CHECK(length(last_refresh_entry_hash)=32),
                 finality_digest BLOB NOT NULL CHECK(length(finality_digest)=32),
                 finality_json BLOB NOT NULL CHECK(length(finality_json) BETWEEN 1 AND 524288)
             ) STRICT;
             CREATE TABLE IF NOT EXISTS pending_invoices(
                 entry_hash BLOB PRIMARY KEY CHECK(length(entry_hash)=32),
                 expires_at_ms INTEGER NOT NULL CHECK(expires_at_ms>0),
                 record_digest BLOB NOT NULL CHECK(length(record_digest)=32),
                 record_json BLOB NOT NULL CHECK(length(record_json) BETWEEN 1 AND 10485760)
             ) STRICT, WITHOUT ROWID;
             CREATE TABLE IF NOT EXISTS inbox(
                 ordinal INTEGER PRIMARY KEY AUTOINCREMENT,
                 item_id BLOB NOT NULL UNIQUE CHECK(length(item_id)=32),
                 invoice_entry_hash BLOB NOT NULL UNIQUE CHECK(length(invoice_entry_hash)=32),
                 request_digest BLOB NOT NULL UNIQUE CHECK(length(request_digest)=32),
                 record_digest BLOB NOT NULL CHECK(length(record_digest)=32),
                 record_json BLOB NOT NULL CHECK(length(record_json) BETWEEN 1 AND 10485760),
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
             ) STRICT;
             CREATE TABLE IF NOT EXISTS last_scan_commit(
                 singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                 start_cursor_digest BLOB NOT NULL CHECK(length(start_cursor_digest)=32),
                 end_cursor_digest BLOB NOT NULL CHECK(length(end_cursor_digest)=32),
                 segment_digest BLOB NOT NULL CHECK(length(segment_digest)=32)
             ) STRICT;
             CREATE TABLE IF NOT EXISTS staged_finality_range(
                 singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                 store_id BLOB NOT NULL CHECK(length(store_id)=32),
                 file_identity BLOB NOT NULL CHECK(length(file_identity)=32),
                 stage_digest BLOB NOT NULL CHECK(length(stage_digest)=32),
                 intent_digest BLOB NOT NULL CHECK(length(intent_digest)=32),
                 intent_json BLOB NOT NULL CHECK(length(intent_json) BETWEEN 1 AND 24117248)
             ) STRICT;",
        )?;
        transaction.pragma_update(None, "application_id", APPLICATION_ID)?;
        transaction.pragma_update(None, "user_version", SCHEMA_VERSION)?;
        let existing: Option<SettingsRow> = transaction
            .query_row(
                "SELECT deployment_id,committee_epoch,descriptor_id,member_id,ledger_chain_id,finality_verifier_profile,
                        finality_coordinator_id,store_id,file_identity,max_inbox,max_outbox
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
                        row.get(7)?,
                        row.get(8)?,
                        row.get(9)?,
                        row.get(10)?,
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
            config.finality_verifier_profile.as_bytes().as_slice(),
            config.finality_coordinator_id.as_bytes().as_slice(),
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
                    && row.5.as_slice() == expected.5
                    && row.6.as_slice() == expected.6
                    && row.7.len() == 32
                    && row.7.as_slice() != [0_u8; 32]
                    && row.8.as_slice() == file_identity_digest
                    && row.9 == expected.7
                    && row.10 == expected.8 => {}
            Some(_) => return Err(NodeError::IdentityMismatch),
            None => {
                transaction.execute(
                    "INSERT INTO node_settings VALUES(1,?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)",
                    params![
                        expected.0,
                        expected.1,
                        expected.2,
                        expected.3,
                        expected.4,
                        expected.5,
                        expected.6,
                        new_store_id.as_slice(),
                        file_identity_digest.as_slice(),
                        expected.7,
                        expected.8
                    ],
                )?;
            }
        }
        let store_id_bytes: Vec<u8> =
            transaction.query_row("SELECT store_id FROM node_settings WHERE singleton=1", [], |row| {
                row.get(0)
            })?;
        let store_id = <[u8; 32]>::try_from(store_id_bytes.as_slice()).map_err(|_| NodeError::CorruptState)?;
        if store_id == [0; 32] {
            return Err(NodeError::CorruptState);
        }
        transaction.commit()?;
        verify_durable_file(&path, file_identity)?;
        Ok(Self {
            path,
            file_identity,
            file_identity_digest,
            _database_file: database_file,
            _process_lock: process_lock,
            connection: Mutex::new(connection),
            store_id,
            max_inbox: config.max_inbox_rows,
            max_outbox: config.max_outbox_rows,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn staged_finality_range(&self) -> Result<Option<StagedFinalityRangeCapabilityV2>> {
        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
        let row: Option<StagedFinalityRow> = transaction
            .query_row(
                "SELECT store_id,file_identity,stage_digest,intent_digest,length(intent_json)
                 FROM staged_finality_range WHERE singleton=1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)),
            )
            .optional()?;
        let Some((stored_store, stored_file, stage_digest, intent_digest, encoded_len)) = row else {
            transaction.commit()?;
            return Ok(None);
        };
        if stored_store.as_slice() != self.store_id
            || stored_file.as_slice() != self.file_identity_digest
            || stage_digest.len() != 32
            || intent_digest.len() != 32
            || encoded_len <= 0
            || usize::try_from(encoded_len).map_err(|_| NodeError::CorruptState)?
                > crate::types::MAX_FINALITY_INTENT_BYTES
        {
            return Err(NodeError::CorruptState);
        }
        let bytes: Vec<u8> = transaction.query_row(
            "SELECT intent_json FROM staged_finality_range WHERE singleton=1",
            [],
            |row| row.get(0),
        )?;
        let digest: [u8; 32] = Sha256::digest(&bytes).into();
        if bytes.len() != usize::try_from(encoded_len).map_err(|_| NodeError::CorruptState)?
            || intent_digest.as_slice() != digest
        {
            return Err(NodeError::CorruptState);
        }
        let expected_stage = finality_stage_digest(self.store_id, self.file_identity_digest, &bytes);
        if stage_digest.as_slice() != expected_stage {
            return Err(NodeError::CorruptState);
        }
        let intent = FinalityRangeIntentV2::from_canonical_bytes(&bytes).map_err(|_| NodeError::CorruptState)?;
        let settings: (String, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) = transaction.query_row(
            "SELECT ledger_chain_id,finality_verifier_profile,finality_coordinator_id,store_id,file_identity
             FROM node_settings WHERE singleton=1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)),
        )?;
        let current = transaction
            .query_row(
                "SELECT next_height,expected_previous_app_hash,processed_refresh_count,last_refresh_entry_hash,
                        finality_digest,length(finality_json),finality_json
                 FROM finalized_cursor WHERE singleton=1",
                [],
                cursor_row,
            )
            .optional()?;
        if let Some(cursor) = current.as_ref() {
            validate_stored_cursor(cursor)?;
        }
        let expected_height = current.as_ref().map_or(1, |cursor| cursor.next_height);
        let expected_hash = current
            .as_ref()
            .map_or_else(AppHashV2::zero, |cursor| cursor.expected_previous_app_hash.clone());
        if settings.0 != intent.ledger_chain_id().as_str()
            || settings.1.as_slice() != intent.verifier_profile().as_bytes()
            || settings.2.as_slice() != intent.coordinator_id().as_bytes()
            || settings.3.as_slice() != self.store_id
            || settings.4.as_slice() != self.file_identity_digest
            || intent.start_height() != expected_height
            || intent.expected_previous_app_hash() != &expected_hash
        {
            return Err(NodeError::CorruptState);
        }
        transaction.commit()?;
        verify_durable_file(&self.path, self.file_identity)?;
        Ok(Some(StagedFinalityRangeCapabilityV2::from_store(
            self.store_id,
            self.file_identity_digest,
            expected_stage,
            intent,
        )?))
    }

    pub fn stage_finality_range(&self, intent: &FinalityRangeIntentV2) -> Result<StagedFinalityRangeCapabilityV2> {
        let bytes = intent.canonical_bytes()?;
        let intent_digest: [u8; 32] = Sha256::digest(&bytes).into();
        let stage_digest = finality_stage_digest(self.store_id, self.file_identity_digest, &bytes);
        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let settings: (String, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) = transaction.query_row(
            "SELECT ledger_chain_id,finality_verifier_profile,finality_coordinator_id,store_id,file_identity
             FROM node_settings WHERE singleton=1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)),
        )?;
        if settings.0 != intent.ledger_chain_id().as_str()
            || settings.1.as_slice() != intent.verifier_profile().as_bytes()
            || settings.2.as_slice() != intent.coordinator_id().as_bytes()
            || settings.3.as_slice() != self.store_id
            || settings.4.as_slice() != self.file_identity_digest
        {
            return Err(NodeError::IdentityMismatch);
        }
        let current = transaction
            .query_row(
                "SELECT next_height,expected_previous_app_hash,processed_refresh_count,last_refresh_entry_hash,
                        finality_digest,length(finality_json),finality_json
                 FROM finalized_cursor WHERE singleton=1",
                [],
                cursor_row,
            )
            .optional()?;
        if let Some(cursor) = current.as_ref() {
            validate_stored_cursor(cursor)?;
        }
        let expected_height = current.as_ref().map_or(1, |cursor| cursor.next_height);
        let expected_hash = current
            .as_ref()
            .map_or_else(AppHashV2::zero, |cursor| cursor.expected_previous_app_hash.clone());
        if intent.start_height() != expected_height || intent.expected_previous_app_hash() != &expected_hash {
            return Err(NodeError::CursorConflict);
        }
        let existing: Option<(Vec<u8>, Vec<u8>)> = transaction
            .query_row(
                "SELECT stage_digest,intent_digest FROM staged_finality_range WHERE singleton=1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        match existing {
            Some((stored_stage, stored_intent))
                if stored_stage.as_slice() == stage_digest && stored_intent.as_slice() == intent_digest => {}
            Some(_) => return Err(NodeError::CursorConflict),
            None => {
                transaction.execute(
                    "INSERT INTO staged_finality_range(singleton,store_id,file_identity,stage_digest,intent_digest,intent_json)
                     VALUES(1,?1,?2,?3,?4,?5)",
                    params![
                        self.store_id.as_slice(),
                        self.file_identity_digest.as_slice(),
                        stage_digest.as_slice(),
                        intent_digest.as_slice(),
                        bytes
                    ],
                )?;
            }
        }
        transaction.commit()?;
        drop(connection);
        let staged = self.staged_finality_range()?.ok_or(NodeError::CorruptState)?;
        if staged.stage_digest() != &stage_digest || staged.intent() != intent {
            return Err(NodeError::CorruptState);
        }
        Ok(staged)
    }

    pub fn pending_invoice(&self, entry_hash: [u8; 32]) -> Result<Option<StoredPendingInvoice>> {
        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
        let metadata = transaction
            .query_row(
                "SELECT record_digest,length(record_json) FROM pending_invoices WHERE entry_hash=?1",
                [entry_hash.as_slice()],
                |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, i64>(1)?)),
            )
            .optional()?;
        let Some((digest, encoded_len)) = metadata else {
            transaction.commit()?;
            return Ok(None);
        };
        if digest.len() != 32
            || encoded_len <= 0
            || usize::try_from(encoded_len).map_err(|_| NodeError::CorruptState)? > MAX_INBOX_RECORD_BYTES
        {
            return Err(NodeError::CorruptState);
        }
        let record: Vec<u8> = transaction.query_row(
            "SELECT record_json FROM pending_invoices WHERE entry_hash=?1",
            [entry_hash.as_slice()],
            |row| row.get(0),
        )?;
        let digest = <[u8; 32]>::try_from(digest.as_slice()).map_err(|_| NodeError::CorruptState)?;
        if record.len() != usize::try_from(encoded_len).map_err(|_| NodeError::CorruptState)?
            || Sha256::digest(&record).as_slice() != digest
        {
            return Err(NodeError::CorruptState);
        }
        transaction.commit()?;
        Ok(Some(StoredPendingInvoice { digest, record }))
    }

    pub fn inbox_by_transfer(&self, entry_hash: [u8; 32]) -> Result<Option<StoredInbox>> {
        self.inbox_by_key(0, entry_hash)
    }

    pub fn inbox_by_invoice(&self, entry_hash: [u8; 32]) -> Result<Option<StoredInbox>> {
        self.inbox_by_key(1, entry_hash)
    }

    fn inbox_by_key(&self, selector: i64, entry_hash: [u8; 32]) -> Result<Option<StoredInbox>> {
        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
        let metadata = transaction
            .query_row(
                "SELECT item_id,record_digest,length(record_json) FROM inbox
                 WHERE (?1=0 AND item_id=?2) OR (?1=1 AND invoice_entry_hash=?2)",
                params![selector, entry_hash.as_slice()],
                |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, i64>(2)?,
                    ))
                },
            )
            .optional()?;
        let Some((id, digest, encoded_len)) = metadata else {
            transaction.commit()?;
            return Ok(None);
        };
        if id.len() != 32
            || digest.len() != 32
            || encoded_len <= 0
            || usize::try_from(encoded_len).map_err(|_| NodeError::CorruptState)? > MAX_INBOX_RECORD_BYTES
        {
            return Err(NodeError::CorruptState);
        }
        let record: Vec<u8> = transaction.query_row(
            "SELECT record_json FROM inbox WHERE item_id=?1",
            [id.as_slice()],
            |row| row.get(0),
        )?;
        if record.len() != usize::try_from(encoded_len).map_err(|_| NodeError::CorruptState)?
            || digest.as_slice() != Sha256::digest(&record).as_slice()
        {
            return Err(NodeError::CorruptState);
        }
        transaction.commit()?;
        Ok(Some(StoredInbox {
            id: <[u8; 32]>::try_from(id.as_slice()).map_err(|_| NodeError::CorruptState)?,
            record,
        }))
    }

    pub fn commit_scan(&self, commit: ScanCommit<'_>) -> Result<ScanCommitOutcome> {
        if commit.segment_digest == [0; 32]
            || commit.staged.store_id != self.store_id
            || commit.staged.file_identity != self.file_identity_digest
            || commit.staged.stage_digest == [0; 32]
        {
            return Err(NodeError::InvalidLedgerArtifact);
        }
        for record in commit
            .pending_writes
            .iter()
            .map(|write| &write.record)
            .chain(commit.inbox_writes.iter().map(|write| &write.record))
        {
            if record.is_empty() || record.len() > MAX_INBOX_RECORD_BYTES {
                return Err(NodeError::InvalidLedgerArtifact);
            }
        }
        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let current = transaction
            .query_row(
                "SELECT next_height,expected_previous_app_hash,processed_refresh_count,last_refresh_entry_hash,finality_digest,length(finality_json),finality_json FROM finalized_cursor WHERE singleton=1",
                [],
                cursor_row,
            )
            .optional()?;
        if let Some(cursor) = current.as_ref() {
            validate_stored_cursor(cursor)?;
        }
        validate_stored_cursor(commit.next_cursor)?;
        let staged_row: Option<(Vec<u8>, Vec<u8>, Vec<u8>)> = transaction
            .query_row(
                "SELECT store_id,file_identity,stage_digest FROM staged_finality_range WHERE singleton=1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?;
        if staged_row
            .as_ref()
            .is_some_and(|row| row.0.as_slice() != self.store_id || row.1.as_slice() != self.file_identity_digest)
        {
            return Err(NodeError::CorruptState);
        }
        let staged_digest = staged_row.as_ref().map(|row| &row.2);
        let staged_intent = commit.staged.intent();
        let expected_start_height = commit.expected_cursor.map_or(1, |cursor| cursor.next_height);
        let expected_start_hash = commit
            .expected_cursor
            .map_or_else(AppHashV2::zero, |cursor| cursor.expected_previous_app_hash.clone());
        if staged_intent.start_height() != expected_start_height
            || staged_intent.expected_previous_app_hash() != &expected_start_hash
            || staged_intent.next_height() != commit.next_cursor.next_height
            || staged_intent.next_expected_previous_app_hash() != &commit.next_cursor.expected_previous_app_hash
            || commit.next_cursor.last_finality.block_height() != staged_intent.next_height().saturating_sub(1)
            || commit.next_cursor.last_finality.app_hash() != staged_intent.next_expected_previous_app_hash()
        {
            return Err(NodeError::CursorConflict);
        }
        let start_digest = cursor_digest(commit.expected_cursor);
        let end_digest = cursor_digest(Some(commit.next_cursor));
        if current.as_ref() == Some(commit.next_cursor) {
            if staged_digest.is_some() {
                return Err(NodeError::CorruptState);
            }
            let replay: Option<(Vec<u8>, Vec<u8>, Vec<u8>)> = transaction
                .query_row(
                    "SELECT start_cursor_digest,end_cursor_digest,segment_digest FROM last_scan_commit WHERE singleton=1",
                    [],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .optional()?;
            if replay.as_ref().is_some_and(|row| {
                row.0.as_slice() == start_digest
                    && row.1.as_slice() == end_digest
                    && row.2.as_slice() == commit.segment_digest
            }) {
                transaction.commit()?;
                verify_durable_file(&self.path, self.file_identity)?;
                return Ok(ScanCommitOutcome::Replayed);
            }
            return Err(NodeError::CursorConflict);
        }
        if current.as_ref() != commit.expected_cursor {
            return Err(NodeError::CursorConflict);
        }
        if staged_digest.map(Vec::as_slice) != Some(commit.staged.stage_digest.as_slice()) {
            return Err(NodeError::CursorConflict);
        }

        for removal in &commit.pending_removals {
            if transaction.execute(
                "DELETE FROM pending_invoices WHERE entry_hash=?1 AND record_digest=?2",
                params![removal.entry_hash.as_slice(), removal.expected_digest.as_slice()],
            )? != 1
            {
                return Err(NodeError::ReplayConflict);
            }
        }
        transaction.execute(
            "DELETE FROM pending_invoices WHERE expires_at_ms<=?1",
            [to_i64(commit.expire_through_ms)?],
        )?;
        for write in &commit.pending_writes {
            let digest: [u8; 32] = Sha256::digest(&write.record).into();
            let existing: Option<Vec<u8>> = transaction
                .query_row(
                    "SELECT record_digest FROM pending_invoices WHERE entry_hash=?1",
                    [write.entry_hash.as_slice()],
                    |row| row.get(0),
                )
                .optional()?;
            match existing {
                Some(existing) if existing.as_slice() == digest => {}
                Some(_) => return Err(NodeError::ReplayConflict),
                None => {
                    let count: i64 =
                        transaction.query_row("SELECT count(*) FROM pending_invoices", [], |row| row.get(0))?;
                    if u32::try_from(count).map_err(|_| NodeError::CorruptState)? >= self.max_inbox {
                        return Err(NodeError::QueueFull);
                    }
                    transaction.execute(
                        "INSERT INTO pending_invoices VALUES(?1,?2,?3,?4)",
                        params![
                            write.entry_hash.as_slice(),
                            to_i64(write.expires_at_ms)?,
                            digest.as_slice(),
                            &write.record
                        ],
                    )?;
                }
            }
        }
        let mut inbox_added = 0_usize;
        for write in &commit.inbox_writes {
            let digest: [u8; 32] = Sha256::digest(&write.record).into();
            let existing: Option<Vec<u8>> = transaction
                .query_row(
                    "SELECT record_digest FROM inbox WHERE item_id=?1",
                    [write.item_id.as_slice()],
                    |row| row.get(0),
                )
                .optional()?;
            match existing {
                Some(existing) if existing.as_slice() == digest => {}
                Some(_) => return Err(NodeError::ReplayConflict),
                None => {
                    if transaction.query_row(
                        "SELECT EXISTS(SELECT 1 FROM inbox WHERE request_digest=?1)",
                        [write.request_digest.as_slice()],
                        |row| row.get::<_, bool>(0),
                    )? {
                        return Err(NodeError::ReplayConflict);
                    }
                    let count: i64 = transaction.query_row("SELECT count(*) FROM inbox", [], |row| row.get(0))?;
                    if u32::try_from(count).map_err(|_| NodeError::CorruptState)? >= self.max_inbox {
                        return Err(NodeError::QueueFull);
                    }
                    transaction.execute(
                        "INSERT INTO inbox(item_id,invoice_entry_hash,request_digest,record_digest,record_json,status) VALUES(?1,?2,?3,?4,?5,0)",
                        params![write.item_id.as_slice(), write.invoice_entry_hash.as_slice(), write.request_digest.as_slice(), digest.as_slice(), &write.record],
                    )?;
                    inbox_added = inbox_added.checked_add(1).ok_or(NodeError::NumericRange)?;
                }
            }
        }
        let finality_json = serde_json::to_vec(&commit.next_cursor.last_finality)?;
        if transaction.execute(
            "DELETE FROM staged_finality_range
             WHERE singleton=1 AND store_id=?1 AND file_identity=?2 AND stage_digest=?3",
            params![
                self.store_id.as_slice(),
                self.file_identity_digest.as_slice(),
                commit.staged.stage_digest.as_slice()
            ],
        )? != 1
        {
            return Err(NodeError::CursorConflict);
        }
        transaction.execute(
            "INSERT INTO finalized_cursor VALUES(1,?1,?2,?3,?4,?5,?6)
             ON CONFLICT(singleton) DO UPDATE SET next_height=excluded.next_height,
             expected_previous_app_hash=excluded.expected_previous_app_hash,
             processed_refresh_count=excluded.processed_refresh_count,
             last_refresh_entry_hash=excluded.last_refresh_entry_hash,
             finality_digest=excluded.finality_digest,
             finality_json=excluded.finality_json",
            params![
                to_i64(commit.next_cursor.next_height)?,
                commit.next_cursor.expected_previous_app_hash.as_bytes().as_slice(),
                to_i64(commit.next_cursor.processed_refresh_count)?,
                commit.next_cursor.last_refresh_entry_hash.as_bytes().as_slice(),
                commit.next_cursor.last_finality.verifier_digest().as_bytes().as_slice(),
                finality_json,
            ],
        )?;
        transaction.execute(
            "INSERT INTO last_scan_commit VALUES(1,?1,?2,?3) ON CONFLICT(singleton) DO UPDATE SET
             start_cursor_digest=excluded.start_cursor_digest,end_cursor_digest=excluded.end_cursor_digest,
             segment_digest=excluded.segment_digest",
            params![
                start_digest.as_slice(),
                end_digest.as_slice(),
                commit.segment_digest.as_slice()
            ],
        )?;
        let commit_result = transaction.commit();
        let exact = scan_commit_matches(
            &connection,
            commit.next_cursor,
            start_digest,
            end_digest,
            commit.segment_digest,
        )?;
        if !exact {
            return match commit_result {
                Ok(()) => Err(NodeError::CorruptState),
                Err(error) => Err(NodeError::Sqlite(error)),
            };
        }
        verify_durable_file(&self.path, self.file_identity)?;
        Ok(ScanCommitOutcome::Applied { inbox_added })
    }

    pub fn next_pending(&self) -> Result<Option<StoredInbox>> {
        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let metadata = transaction
            .query_row(
                "SELECT item_id,record_digest,length(record_json) FROM inbox WHERE status=0 ORDER BY ordinal LIMIT 1",
                [],
                |row| {
                    let id: Vec<u8> = row.get(0)?;
                    let id = <[u8; 32]>::try_from(id.as_slice()).map_err(|_| rusqlite::Error::InvalidQuery)?;
                    Ok((id, row.get::<_, Vec<u8>>(1)?, row.get::<_, i64>(2)?))
                },
            )
            .optional()
            .map_err(NodeError::from)?;
        let Some((id, expected, encoded_len)) = metadata else {
            transaction.commit()?;
            return Ok(None);
        };
        if encoded_len <= 0
            || usize::try_from(encoded_len).map_err(|_| NodeError::CorruptState)? > MAX_INBOX_RECORD_BYTES
            || expected.len() != 32
        {
            return Err(NodeError::CorruptState);
        }
        let record: Vec<u8> = transaction.query_row(
            "SELECT record_json FROM inbox WHERE item_id=?1",
            [id.as_slice()],
            |row| row.get(0),
        )?;
        if record.len() != usize::try_from(encoded_len).map_err(|_| NodeError::CorruptState)?
            || expected.as_slice() != Sha256::digest(&record).as_slice()
        {
            return Err(NodeError::CorruptState);
        }
        transaction.commit()?;
        Ok(Some(StoredInbox { id, record }))
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
        let existing_inbox: Option<(i64, Option<Vec<u8>>)> = tx
            .query_row(
                "SELECT status,ack_digest FROM inbox WHERE item_id=?1",
                [inbox_id.as_slice()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        let Some((inbox_status, inbox_ack)) = existing_inbox else {
            return Err(NodeError::CorruptState);
        };
        if inbox_ack
            .as_ref()
            .is_some_and(|digest| digest.as_slice() != acknowledgement.acknowledgement_digest)
        {
            return Err(NodeError::ReplayConflict);
        }
        if let Some((existing_id, existing_payload)) = tx
            .query_row(
                "SELECT item_id,payload_json FROM outbox WHERE inbox_id=?1",
                [inbox_id.as_slice()],
                |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?)),
            )
            .optional()?
        {
            if existing_id.as_slice() != outbox_id || existing_payload != payload || inbox_status != 1 {
                return Err(NodeError::ReplayConflict);
            }
            tx.commit()?;
            return Ok(());
        }
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
            "INSERT INTO outbox(item_id,inbox_id,payload_json,status,attempts) VALUES(?1,?2,?3,0,0)",
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
        let cursor = connection
            .query_row(
                "SELECT next_height,expected_previous_app_hash,processed_refresh_count,last_refresh_entry_hash,finality_digest,length(finality_json),finality_json FROM finalized_cursor WHERE singleton=1",
                [],
                cursor_row,
            )
            .optional()
            .map_err(NodeError::from)?;
        if let Some(cursor) = cursor.as_ref() {
            validate_stored_cursor(cursor)?;
        }
        Ok(cursor)
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
        verify_durable_file(&self.path, self.file_identity)?;
        self.connection.lock().map_err(|_| NodeError::CorruptState)
    }
}

fn scan_commit_matches(
    connection: &Connection,
    expected_cursor: &LedgerCursor,
    start_digest: [u8; 32],
    end_digest: [u8; 32],
    segment_digest: [u8; 32],
) -> Result<bool> {
    let cursor = connection
        .query_row(
            "SELECT next_height,expected_previous_app_hash,processed_refresh_count,last_refresh_entry_hash,finality_digest,length(finality_json),finality_json FROM finalized_cursor WHERE singleton=1",
            [],
            cursor_row,
        )
        .optional()?;
    let receipt: Option<(Vec<u8>, Vec<u8>, Vec<u8>)> = connection
        .query_row(
            "SELECT start_cursor_digest,end_cursor_digest,segment_digest FROM last_scan_commit WHERE singleton=1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()?;
    let staged_exists: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM staged_finality_range WHERE singleton=1)",
        [],
        |row| row.get(0),
    )?;
    Ok(cursor.as_ref() == Some(expected_cursor)
        && !staged_exists
        && receipt.is_some_and(|row| {
            row.0.as_slice() == start_digest && row.1.as_slice() == end_digest && row.2.as_slice() == segment_digest
        }))
}

fn cursor_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<LedgerCursor> {
    let next_height: i64 = row.get(0)?;
    let previous: Vec<u8> = row.get(1)?;
    let refresh_count: i64 = row.get(2)?;
    let last_refresh: Vec<u8> = row.get(3)?;
    let finality_digest: Vec<u8> = row.get(4)?;
    let finality_len: i64 = row.get(5)?;
    if !(1..=524_288).contains(&finality_len) {
        return Err(rusqlite::Error::InvalidQuery);
    }
    let finality_json: Vec<u8> = row.get(6)?;
    if i64::try_from(finality_json.len()).map_err(|_| rusqlite::Error::InvalidQuery)? != finality_len {
        return Err(rusqlite::Error::InvalidQuery);
    }
    let last_finality: crate::DurableBlockFinalityCapability =
        serde_json::from_slice(&finality_json).map_err(|_| rusqlite::Error::InvalidQuery)?;
    if serde_json::to_vec(&last_finality).map_err(|_| rusqlite::Error::InvalidQuery)? != finality_json
        || last_finality.verifier_digest().as_bytes()
            != &<[u8; 32]>::try_from(finality_digest.as_slice()).map_err(|_| rusqlite::Error::InvalidQuery)?
    {
        return Err(rusqlite::Error::InvalidQuery);
    }
    Ok(LedgerCursor {
        next_height: u64::try_from(next_height).map_err(|_| rusqlite::Error::InvalidQuery)?,
        expected_previous_app_hash: thunderbolt_ledger::AppHashV2::from_bytes(
            <[u8; 32]>::try_from(previous.as_slice()).map_err(|_| rusqlite::Error::InvalidQuery)?,
        )
        .map_err(|_| rusqlite::Error::InvalidQuery)?,
        processed_refresh_count: u64::try_from(refresh_count).map_err(|_| rusqlite::Error::InvalidQuery)?,
        last_refresh_entry_hash: thunderbolt_ledger::EntryHashV2::from_bytes(
            <[u8; 32]>::try_from(last_refresh.as_slice()).map_err(|_| rusqlite::Error::InvalidQuery)?,
        )
        .map_err(|_| rusqlite::Error::InvalidQuery)?,
        last_finality,
    })
}

fn cursor_digest(cursor: Option<&LedgerCursor>) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"bitcoin-thunderbolt/committee-node/global-cursor/v2");
    match cursor {
        Some(cursor) => {
            hasher.update([1]);
            hasher.update(cursor.next_height.to_be_bytes());
            hasher.update(cursor.expected_previous_app_hash.as_bytes());
            hasher.update(cursor.processed_refresh_count.to_be_bytes());
            hasher.update(cursor.last_refresh_entry_hash.as_bytes());
            hasher.update(cursor.last_finality.verifier_profile().as_bytes());
            hasher.update(cursor.last_finality.coordinator_id().as_bytes());
            hasher.update(cursor.last_finality.ledger_chain_id().as_bytes());
            hasher.update(cursor.last_finality.block_height().to_be_bytes());
            hasher.update(cursor.last_finality.app_hash().as_bytes());
            hasher.update(cursor.last_finality.verifier_digest().as_bytes());
            hasher.update((cursor.last_finality.attestation().len() as u64).to_be_bytes());
            hasher.update(cursor.last_finality.attestation());
        }
        None => hasher.update([0]),
    }
    hasher.finalize().into()
}

fn finality_stage_digest(store_id: [u8; 32], file_identity: [u8; 32], intent_bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"bitcoin-thunderbolt/committee-node/staged-finality/v1");
    hasher.update(store_id);
    hasher.update(file_identity);
    hasher.update(u64::try_from(intent_bytes.len()).unwrap_or(u64::MAX).to_be_bytes());
    hasher.update(intent_bytes);
    hasher.finalize().into()
}

fn validate_stored_cursor(cursor: &LedgerCursor) -> Result<()> {
    if cursor.next_height < 2
        || cursor.expected_previous_app_hash.is_zero()
        || cursor.last_finality.validate_shape().is_err()
        || cursor.last_finality.block_height() != cursor.next_height.saturating_sub(1)
        || cursor.last_finality.app_hash() != &cursor.expected_previous_app_hash
        || (cursor.processed_refresh_count == 0) != cursor.last_refresh_entry_hash.is_zero()
    {
        return Err(NodeError::CorruptState);
    }
    Ok(())
}

fn to_i64(value: u64) -> Result<i64> {
    i64::try_from(value).map_err(|_| NodeError::NumericRange)
}
