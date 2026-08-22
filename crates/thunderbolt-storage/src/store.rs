use std::collections::BTreeSet;
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use rusqlite::backup::Backup;
use rusqlite::{
    params, Connection, ErrorCode, OpenFlags, OptionalExtension, Row, Rows, Transaction, TransactionBehavior,
};
use sha2::{Digest as _, Sha256};
use tempfile::NamedTempFile;
use thunderbolt_protocol::{
    ApplyDisposition, ChannelEvent, ChannelId, ChannelReducer, ChannelSnapshot, EntryHash, HistoryContext,
    IdempotencyKey, LedgerEntry, ProtocolLimits, VerificationEvidence,
};

use crate::error::{Result, StorageError, VerifiedAppendError, VerifiedRequestConflict};
use crate::migrations;

/// Recommended page size for operator-facing reads.
pub const DEFAULT_PAGE_LIMIT: usize = 100;
/// Hard maximum accepted by channel and ledger list operations.
pub const MAX_PAGE_LIMIT: usize = 256;
/// Hard serialized-byte budget for one channel or ledger page.
pub const MAX_PAGE_BYTES: usize = 16 * 1024 * 1024;
const DEFAULT_BUSY_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_BUSY_TIMEOUT: Duration = Duration::from_secs(60);
const BACKUP_PAGES_PER_STEP: i32 = 128;
const BACKUP_STEP_PAUSE: Duration = Duration::from_millis(5);
const PROPOSAL_DIGEST_DOMAIN: &[u8] = b"thunderbolt/verified-proposal/v1\0";

/// Connection durability, lock-wait, and protocol resource limits.
#[derive(Clone, Debug)]
pub struct StorageOptions {
    /// Maximum time to wait for another SQLite writer, capped at 60 seconds.
    pub busy_timeout: Duration,
    /// Reduction policy persisted on first open and required on every reopen.
    pub protocol_limits: ProtocolLimits,
}

impl Default for StorageOptions {
    fn default() -> Self {
        Self {
            busy_timeout: DEFAULT_BUSY_TIMEOUT,
            protocol_limits: ProtocolLimits::default(),
        }
    }
}

/// Result of an atomic ledger append.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AppendOutcome {
    pub sequence: u64,
    pub entry_hash: EntryHash,
    pub snapshot: ChannelSnapshot,
    /// True when the exact entry was already committed under its key.
    pub replayed: bool,
}

/// Stable SHA-256 commitment to an evidence-free ledger proposal.
///
/// Verification evidence is deliberately excluded so retries remain stable
/// across verifier execution and process restarts.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProposalDigest([u8; 32]);

impl ProposalDigest {
    /// Computes the domain-separated digest of a proposal that contains no
    /// client-supplied verification evidence.
    pub fn from_proposal(proposal: &LedgerEntry) -> Result<Self> {
        ensure_unverified_proposal(proposal)?;
        Ok(proposal_digest_unchecked(proposal))
    }

    /// Returns the committed digest bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for ProposalDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// Result of a transaction-scoped verified append.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedAppendOutcome {
    /// Stable evidence-free proposal digest used for request deduplication.
    pub proposal_digest: ProposalDigest,
    /// Committed channel-local sequence.
    pub sequence: u64,
    /// Canonical hash of the entry after node evidence was installed.
    pub entry_hash: EntryHash,
    /// Exact post-transition snapshot recorded with the request mapping.
    pub snapshot: ChannelSnapshot,
    /// True when this proposal digest was already committed atomically.
    pub replayed: bool,
}

/// Immutable state exposed to the trusted verification callback.
///
/// The context exists only while the SQLite `BEGIN IMMEDIATE` transaction and
/// writer lock are held. Callbacks must not re-enter the same storage handle.
#[derive(Debug)]
pub struct VerifiedProposalContext<'a> {
    proposal: &'a LedgerEntry,
    snapshot: Option<&'a ChannelSnapshot>,
    pending_invoice_head: Option<&'a LedgerEntry>,
    ledger_time_ms: u64,
}

impl<'a> VerifiedProposalContext<'a> {
    /// Returns the exact evidence-free proposal being evaluated.
    pub const fn proposal(&self) -> &'a LedgerEntry {
        self.proposal
    }

    /// Returns the authoritative channel snapshot read under the writer lock.
    pub const fn snapshot(&self) -> Option<&'a ChannelSnapshot> {
        self.snapshot
    }

    /// Returns the immutable pending Invoice head referenced by a Transfer.
    pub const fn pending_invoice_head(&self) -> Option<&'a LedgerEntry> {
        self.pending_invoice_head
    }

    /// Returns the trusted ledger timestamp sampled under the writer lock.
    pub const fn ledger_time_ms(&self) -> u64 {
        self.ledger_time_ms
    }
}

/// Counts returned after both SQLite and protocol-level checks pass.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IntegrityReport {
    pub channels_checked: usize,
    pub entries_checked: usize,
}

/// Thread-safe access to one durable Thunderbolt SQLite database.
pub struct SqliteStorage {
    path: PathBuf,
    connection: Mutex<Connection>,
    backup_connection: Mutex<Connection>,
    reducer: ChannelReducer,
}

impl fmt::Debug for SqliteStorage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SqliteStorage")
            .field("path", &self.path)
            .field("protocol_limits", &self.reducer.limits())
            .finish_non_exhaustive()
    }
}

impl SqliteStorage {
    /// Opens or creates a database, applies migrations, and enables WAL with
    /// full synchronous durability and foreign-key enforcement.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        Self::open_with_options(path, StorageOptions::default())
    }

    /// Opens with explicit busy-timeout and protocol reduction limits.
    pub fn open_with_options(path: impl AsRef<Path>, options: StorageOptions) -> Result<Self> {
        let path = path.as_ref();
        validate_database_path(path)?;
        if options.busy_timeout.is_zero() || options.busy_timeout > MAX_BUSY_TIMEOUT {
            return Err(StorageError::InvalidInput(
                "busy timeout must be greater than zero and no more than 60 seconds".to_string(),
            ));
        }
        let reducer = ChannelReducer::new(options.protocol_limits)?;
        if i64::try_from(reducer.limits().max_entries_per_channel).is_err() {
            return Err(StorageError::InvalidInput(
                "max_entries_per_channel exceeds SQLite INTEGER range".to_string(),
            ));
        }
        let flags =
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE | OpenFlags::SQLITE_OPEN_FULL_MUTEX;
        let mut connection = Connection::open_with_flags(path, flags)?;
        connection.busy_timeout(options.busy_timeout)?;
        connection.pragma_update(None, "foreign_keys", true)?;
        migrations::migrate(&mut connection, path, now_unix_millis()?, reducer.limits())?;
        configure_durability(&connection, options.busy_timeout)?;
        let backup_flags = OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_FULL_MUTEX;
        let backup_connection = Connection::open_with_flags(path, backup_flags)?;
        configure_backup_source(&backup_connection, path, options.busy_timeout, reducer.limits())?;
        Ok(Self {
            path: path.to_path_buf(),
            connection: Mutex::new(connection),
            backup_connection: Mutex::new(backup_connection),
            reducer,
        })
    }

    /// Returns the database path used to open both live SQLite connections.
    pub fn database_path(&self) -> &Path {
        &self.path
    }

    /// Validates and atomically appends an entry together with its reduced
    /// channel snapshot. Sequence zero creates the channel.
    ///
    /// The reducer checks verification attestations but does not perform the
    /// cryptography they describe. Callers must authenticate the actor and
    /// verify every proof/quorum before invoking this method.
    pub fn append_entry(&self, entry: &LedgerEntry) -> Result<AppendOutcome> {
        let prepared = PreparedEntry::new(entry)?;
        let mut connection = self.lock_connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let operation = append_in_transaction(&transaction, &self.reducer, &self.path, entry, &prepared);
        finish_transaction(transaction, operation)
    }

    /// Verifies and appends an evidence-free proposal under one writer-locked
    /// SQLite transaction.
    ///
    /// The proposal digest and channel-scoped idempotency key are checked
    /// before the callback. An exact committed retry returns its stored outcome
    /// without invoking `verify`; reuse of that key by a different proposal is
    /// a conflict. For a new proposal, storage loads the
    /// authoritative snapshot and, for a Transfer, its referenced immutable
    /// pending Invoice head. It then samples trusted ledger time and invokes
    /// `verify` while the `BEGIN IMMEDIATE` lock is still held. Only evidence
    /// returned by that callback is installed.
    ///
    /// Verifier rejection, reduction failure, or any persistence failure rolls
    /// back the entry, evidence rows, snapshot, and proposal mapping together.
    pub fn append_verified_proposal<F, E>(
        &self,
        proposal: &LedgerEntry,
        verify: F,
    ) -> std::result::Result<VerifiedAppendOutcome, VerifiedAppendError<E>>
    where
        F: FnOnce(VerifiedProposalContext<'_>) -> std::result::Result<Vec<VerificationEvidence>, E>,
    {
        let proposal_digest = ProposalDigest::from_proposal(proposal)?;
        let mut connection = self.lock_connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(StorageError::from)?;
        let operation = append_verified_in_transaction(
            &transaction,
            &self.reducer,
            &self.path,
            proposal,
            proposal_digest,
            verify,
        );
        finish_verified_transaction(transaction, operation)
    }

    /// Returns the latest materialized snapshot for a channel.
    pub fn get_channel(&self, channel_id: &ChannelId) -> Result<Option<ChannelSnapshot>> {
        let connection = self.lock_connection()?;
        load_channel(&connection, &channel_id.to_string())
    }

    /// Lists channels in stable identifier order using a keyset cursor.
    pub fn list_channels(&self, after: Option<&ChannelId>, limit: usize) -> Result<Vec<ChannelSnapshot>> {
        let limit = validate_page_limit(limit)?;
        let connection = self.lock_connection()?;
        match after {
            Some(after) => {
                let mut statement = connection.prepare(
                    "SELECT length(snapshot_json), snapshot_json FROM channel_snapshots
                     WHERE channel_id > ?1
                     ORDER BY channel_id ASC LIMIT ?2",
                )?;
                let mut rows = statement.query(params![after.to_string(), limit])?;
                collect_json_page(&mut rows, "channel snapshot")
            }
            None => {
                let mut statement = connection.prepare(
                    "SELECT length(snapshot_json), snapshot_json FROM channel_snapshots
                     ORDER BY channel_id ASC LIMIT ?1",
                )?;
                let mut rows = statement.query([limit])?;
                collect_json_page(&mut rows, "channel snapshot")
            }
        }
    }

    /// Returns one immutable ledger entry by its channel-local sequence.
    pub fn get_entry(&self, channel_id: &ChannelId, sequence: u64) -> Result<Option<LedgerEntry>> {
        let sequence = to_sql_integer("sequence", sequence)?;
        let connection = self.lock_connection()?;
        load_entry(&connection, &channel_id.to_string(), sequence)
    }

    /// Lists entries in ascending order. `None` starts at sequence zero;
    /// otherwise the cursor itself is excluded.
    pub fn list_entries(
        &self,
        channel_id: &ChannelId,
        after_sequence: Option<u64>,
        limit: usize,
    ) -> Result<Vec<LedgerEntry>> {
        let limit = validate_page_limit(limit)?;
        let connection = self.lock_connection()?;
        match after_sequence {
            Some(after_sequence) => {
                let after_sequence = to_sql_integer("after_sequence", after_sequence)?;
                let mut statement = connection.prepare(
                    "SELECT length(entry_json), entry_json FROM ledger_entries
                     WHERE channel_id = ?1 AND sequence > ?2
                     ORDER BY sequence ASC LIMIT ?3",
                )?;
                let mut rows = statement.query(params![channel_id.to_string(), after_sequence, limit])?;
                collect_json_page(&mut rows, "ledger entry")
            }
            None => {
                let mut statement = connection.prepare(
                    "SELECT length(entry_json), entry_json FROM ledger_entries
                     WHERE channel_id = ?1
                     ORDER BY sequence ASC LIMIT ?2",
                )?;
                let mut rows = statement.query(params![channel_id.to_string(), limit])?;
                collect_json_page(&mut rows, "ledger entry")
            }
        }
    }

    /// Finds the entry already bound to a channel-scoped idempotency key.
    pub fn find_entry_by_idempotency_key(
        &self,
        channel_id: &ChannelId,
        key: &IdempotencyKey,
    ) -> Result<Option<LedgerEntry>> {
        let connection = self.lock_connection()?;
        connection
            .query_row(
                "SELECT entry_json FROM ledger_entries
                 WHERE channel_id = ?1 AND idempotency_key = ?2",
                params![channel_id.to_string(), key.to_string()],
                deserialize_entry_row,
            )
            .optional()
            .map_err(StorageError::from)
    }

    /// Finds an entry by its canonical hash within a channel.
    pub fn get_entry_by_hash(&self, channel_id: &ChannelId, hash: &EntryHash) -> Result<Option<LedgerEntry>> {
        let connection = self.lock_connection()?;
        connection
            .query_row(
                "SELECT entry_json FROM ledger_entries
                 WHERE channel_id = ?1 AND entry_hash = ?2",
                params![channel_id.to_string(), hash.as_bytes().as_slice()],
                deserialize_entry_row,
            )
            .optional()
            .map_err(StorageError::from)
    }

    /// Checks SQLite pages and foreign keys, validates every indexed protocol
    /// field, then replays every ledger through the protocol reducer.
    pub fn integrity_check(&self) -> Result<IntegrityReport> {
        let mut connection = self.lock_connection()?;
        integrity_check_connection(&mut connection, &self.reducer, &self.path)
    }

    /// Creates a verified online backup at a path that must not exist.
    pub fn backup_to(&self, destination: impl AsRef<Path>) -> Result<IntegrityReport> {
        let destination = destination.as_ref();
        validate_database_path(destination)?;
        let parent = destination
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let temporary = NamedTempFile::new_in(parent).map_err(|source| StorageError::Io {
            operation: "create temporary backup",
            path: parent.to_path_buf(),
            source,
        })?;

        let report = self.copy_and_verify_backup(temporary.path())?;
        temporary.as_file().sync_all().map_err(|source| StorageError::Io {
            operation: "flush temporary backup",
            path: temporary.path().to_path_buf(),
            source,
        })?;
        match temporary.persist_noclobber(destination) {
            Ok(_) => {}
            Err(error) if error.error.kind() == std::io::ErrorKind::AlreadyExists => {
                return Err(StorageError::BackupDestinationExists(destination.to_path_buf()));
            }
            Err(error) => {
                return Err(StorageError::Io {
                    operation: "install backup",
                    path: destination.to_path_buf(),
                    source: error.error,
                });
            }
        }
        sync_parent_directory(parent, destination)?;
        Ok(report)
    }

    fn copy_and_verify_backup(&self, temporary_path: &Path) -> Result<IntegrityReport> {
        let flags = OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_FULL_MUTEX;
        let mut destination_connection = Connection::open_with_flags(temporary_path, flags)?;
        {
            let source_connection = self.lock_backup_connection()?;
            let backup = Backup::new(&source_connection, &mut destination_connection)?;
            backup.run_to_completion(BACKUP_PAGES_PER_STEP, BACKUP_STEP_PAUSE, None)?;
        }
        let report = integrity_check_connection(&mut destination_connection, &self.reducer, temporary_path)?;
        destination_connection.close().map_err(|(_, error)| error)?;
        Ok(report)
    }

    fn lock_connection(&self) -> Result<MutexGuard<'_, Connection>> {
        self.connection.lock().map_err(|_| StorageError::LockPoisoned)
    }

    fn lock_backup_connection(&self) -> Result<MutexGuard<'_, Connection>> {
        self.backup_connection.lock().map_err(|_| StorageError::LockPoisoned)
    }
}

struct PreparedEntry {
    channel_id: String,
    sequence: u64,
    sequence_sql: i64,
    entry_hash: EntryHash,
    previous_entry_hash: [u8; 32],
    idempotency_key: String,
    created_invoice_id: Option<String>,
    protocol_version: i64,
    occurred_at_ms: i64,
    entry_json: Vec<u8>,
}

impl PreparedEntry {
    fn new(entry: &LedgerEntry) -> Result<Self> {
        Ok(Self {
            channel_id: entry.channel_id.to_string(),
            sequence: entry.sequence,
            sequence_sql: to_sql_integer("entry sequence", entry.sequence)?,
            entry_hash: entry.entry_hash(),
            previous_entry_hash: entry.previous_entry_hash.to_bytes(),
            idempotency_key: entry.idempotency_key.to_string(),
            created_invoice_id: entry.created_invoice_id().map(ToString::to_string),
            protocol_version: i64::from(entry.protocol_version),
            occurred_at_ms: to_sql_integer("occurred_at_ms", entry.occurred_at_ms)?,
            entry_json: serde_json::to_vec(entry)?,
        })
    }
}

fn append_in_transaction(
    transaction: &Transaction<'_>,
    reducer: &ChannelReducer,
    path: &Path,
    entry: &LedgerEntry,
    prepared: &PreparedEntry,
) -> Result<AppendOutcome> {
    migrations::validate_current(transaction, path, reducer.limits())?;
    let current = load_channel(transaction, &prepared.channel_id)?;
    // Sample trusted ledger time only after BEGIN IMMEDIATE has acquired the
    // writer lock and immediately before reduction. Time spent waiting behind
    // another request or process must count toward expiry decisions.
    let recorded_at_ms = now_unix_millis()?;
    reduce_and_persist(transaction, reducer, entry, prepared, current.as_ref(), recorded_at_ms)
}

fn append_verified_in_transaction<F, E>(
    transaction: &Transaction<'_>,
    reducer: &ChannelReducer,
    path: &Path,
    proposal: &LedgerEntry,
    proposal_digest: ProposalDigest,
    verify: F,
) -> std::result::Result<VerifiedAppendOutcome, VerifiedAppendError<E>>
where
    F: FnOnce(VerifiedProposalContext<'_>) -> std::result::Result<Vec<VerificationEvidence>, E>,
{
    migrations::validate_current(transaction, path, reducer.limits())?;
    if let Some(replay) = load_verified_replay(transaction, proposal_digest, proposal)? {
        return Ok(replay);
    }
    reject_verified_request_key_conflict(transaction, proposal_digest, proposal)?;

    let channel_id = proposal.channel_id.to_string();
    let current = load_channel(transaction, &channel_id)?;
    let pending_invoice_head = load_referenced_pending_invoice(transaction, current.as_ref(), proposal)?;
    // This sample occurs after BEGIN IMMEDIATE, request deduplication, and all
    // authoritative state reads. The exact value is reused by verification,
    // reduction, evidence persistence, and the request mapping.
    let recorded_at_ms = now_unix_millis()?;
    let ledger_time_ms = from_sql_integer("recorded_at_ms", recorded_at_ms)?;
    let evidence = verify(VerifiedProposalContext {
        proposal,
        snapshot: current.as_ref(),
        pending_invoice_head: pending_invoice_head.as_ref(),
        ledger_time_ms,
    })
    .map_err(VerifiedAppendError::Verification)?;
    let evidence_limit = reducer.limits().max_verifications_per_event;
    if evidence.len() > evidence_limit {
        return Err(StorageError::VerifierEvidenceLimitExceeded {
            limit: evidence_limit,
            found: evidence.len(),
        }
        .into());
    }

    let mut verified_entry = proposal.clone();
    install_verification_evidence(&mut verified_entry, evidence);
    let prepared = PreparedEntry::new(&verified_entry)?;
    let outcome = reduce_and_persist(
        transaction,
        reducer,
        &verified_entry,
        &prepared,
        current.as_ref(),
        recorded_at_ms,
    )?;
    if outcome.replayed {
        return Err(StorageError::MissingVerifiedRequestMapping.into());
    }

    persist_verification_evidence(transaction, &prepared, &verified_entry)?;
    let snapshot_json = serde_json::to_vec(&outcome.snapshot).map_err(StorageError::from)?;
    transaction
        .execute(
            "INSERT INTO verified_requests(
             proposal_digest, channel_id, actor_id, idempotency_key, sequence,
             entry_hash, snapshot_json, recorded_at_ms
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                proposal_digest.as_bytes().as_slice(),
                &prepared.channel_id,
                proposal.actor.participant_id.to_string(),
                &prepared.idempotency_key,
                prepared.sequence_sql,
                prepared.entry_hash.as_bytes().as_slice(),
                snapshot_json,
                recorded_at_ms,
            ],
        )
        .map_err(StorageError::from)?;

    Ok(VerifiedAppendOutcome {
        proposal_digest,
        sequence: outcome.sequence,
        entry_hash: outcome.entry_hash,
        snapshot: outcome.snapshot,
        replayed: false,
    })
}

fn reduce_and_persist(
    transaction: &Transaction<'_>,
    reducer: &ChannelReducer,
    entry: &LedgerEntry,
    prepared: &PreparedEntry,
    current: Option<&ChannelSnapshot>,
    recorded_at_ms: i64,
) -> Result<AppendOutcome> {
    let existing_idempotency_hash = lookup_idempotency_hash(transaction, prepared)?;
    let invoice_id_already_used = invoice_id_already_used(transaction, prepared)?;
    let history = HistoryContext {
        existing_idempotency_hash,
        invoice_id_already_used,
        ledger_time_ms: from_sql_integer("recorded_at_ms", recorded_at_ms)?,
    };
    let reduction = reducer.apply(current, entry, history)?;
    match reduction.disposition {
        ApplyDisposition::Replay => {
            return Ok(AppendOutcome {
                sequence: prepared.sequence,
                entry_hash: prepared.entry_hash,
                snapshot: reduction.snapshot,
                replayed: true,
            });
        }
        ApplyDisposition::Applied => {}
    }

    let snapshot_json = serde_json::to_vec(&reduction.snapshot)?;
    transaction.execute(
        "INSERT INTO ledger_entries(
             channel_id, sequence, entry_hash, previous_entry_hash, idempotency_key,
             created_invoice_id, protocol_version, occurred_at_ms, entry_json, recorded_at_ms
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        params![
            &prepared.channel_id,
            prepared.sequence_sql,
            prepared.entry_hash.as_bytes().as_slice(),
            prepared.previous_entry_hash.as_slice(),
            &prepared.idempotency_key,
            &prepared.created_invoice_id,
            prepared.protocol_version,
            prepared.occurred_at_ms,
            &prepared.entry_json,
            recorded_at_ms,
        ],
    )?;
    if current.is_none() {
        transaction.execute(
            "INSERT INTO channel_snapshots(
                 channel_id, head_sequence, head_entry_hash, snapshot_json, created_at_ms, updated_at_ms
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?5)",
            params![
                &prepared.channel_id,
                prepared.sequence_sql,
                prepared.entry_hash.as_bytes().as_slice(),
                &snapshot_json,
                recorded_at_ms,
            ],
        )?;
    } else {
        let previous_sequence = prepared.sequence.checked_sub(1).ok_or_else(|| {
            StorageError::CorruptData("reducer applied sequence zero to an existing channel".to_string())
        })?;
        let changed = transaction.execute(
            "UPDATE channel_snapshots
             SET head_sequence = ?2, head_entry_hash = ?3, snapshot_json = ?4,
                 updated_at_ms = max(updated_at_ms, ?5)
             WHERE channel_id = ?1 AND head_sequence = ?6",
            params![
                &prepared.channel_id,
                prepared.sequence_sql,
                prepared.entry_hash.as_bytes().as_slice(),
                &snapshot_json,
                recorded_at_ms,
                to_sql_integer("previous sequence", previous_sequence)?,
            ],
        )?;
        if changed != 1 {
            return Err(StorageError::SequenceConflict {
                channel_id: prepared.channel_id.clone(),
                expected: previous_sequence,
                actual: current.map(|snapshot| snapshot.last_sequence).unwrap_or(0),
            });
        }
    }
    Ok(AppendOutcome {
        sequence: prepared.sequence,
        entry_hash: prepared.entry_hash,
        snapshot: reduction.snapshot,
        replayed: false,
    })
}

fn ensure_unverified_proposal(proposal: &LedgerEntry) -> Result<()> {
    if proposal.event.verification().is_empty() {
        Ok(())
    } else {
        Err(StorageError::ClientVerificationEvidence)
    }
}

fn proposal_digest_unchecked(proposal: &LedgerEntry) -> ProposalDigest {
    let canonical = proposal.canonical_bytes();
    let mut hasher = Sha256::new();
    hasher.update(PROPOSAL_DIGEST_DOMAIN);
    hasher.update((canonical.len() as u64).to_be_bytes());
    hasher.update(canonical);
    ProposalDigest(hasher.finalize().into())
}

fn install_verification_evidence(entry: &mut LedgerEntry, evidence: Vec<VerificationEvidence>) {
    match &mut entry.event {
        ChannelEvent::Open(event) => event.verification = evidence,
        ChannelEvent::Invoice(event) => event.verification = evidence,
        ChannelEvent::Transfer(event) => event.verification = evidence,
        ChannelEvent::Finalize(event) => event.verification = evidence,
    }
}

fn load_referenced_pending_invoice(
    transaction: &Transaction<'_>,
    current: Option<&ChannelSnapshot>,
    proposal: &LedgerEntry,
) -> Result<Option<LedgerEntry>> {
    let ChannelEvent::Transfer(transfer) = &proposal.event else {
        return Ok(None);
    };
    let requested_invoice_id = transfer.invoice_id.to_string();
    let snapshot = current.ok_or_else(|| StorageError::PendingInvoiceReference {
        invoice_id: requested_invoice_id.clone(),
    })?;
    let pending = snapshot
        .pending_invoice
        .as_ref()
        .filter(|pending| pending.invoice_id == transfer.invoice_id)
        .ok_or_else(|| StorageError::PendingInvoiceReference {
            invoice_id: requested_invoice_id.clone(),
        })?;
    let invoice_entry = transaction
        .query_row(
            "SELECT entry_json FROM ledger_entries
             WHERE channel_id = ?1 AND created_invoice_id = ?2",
            params![proposal.channel_id.to_string(), requested_invoice_id],
            deserialize_entry_row,
        )
        .optional()?
        .ok_or_else(|| {
            StorageError::CorruptData("pending invoice snapshot has no immutable ledger entry".to_string())
        })?;
    let ChannelEvent::Invoice(invoice) = &invoice_entry.event else {
        return Err(StorageError::CorruptData(
            "created invoice index refers to a non-Invoice event".to_string(),
        ));
    };
    if invoice_entry.channel_id != snapshot.channel_id
        || invoice_entry.sequence != snapshot.last_sequence
        || invoice_entry.entry_hash() != snapshot.head_hash
        || invoice.invoice_id != pending.invoice_id
        || invoice.recipient != pending.recipient
        || invoice.expires_at_ms != pending.expires_at_ms
    {
        return Err(StorageError::CorruptData(
            "pending invoice entry differs from the authoritative snapshot head".to_string(),
        ));
    }
    Ok(Some(invoice_entry))
}

fn persist_verification_evidence(
    transaction: &Transaction<'_>,
    prepared: &PreparedEntry,
    entry: &LedgerEntry,
) -> Result<()> {
    for (index, evidence) in entry.event.verification().iter().enumerate() {
        let index = i64::try_from(index)
            .map_err(|_| StorageError::InvalidInput("verification evidence index is too large".to_string()))?;
        let evidence_json = serde_json::to_vec(evidence)?;
        transaction.execute(
            "INSERT INTO verification_evidence(channel_id, sequence, evidence_index, evidence_json)
             VALUES (?1, ?2, ?3, ?4)",
            params![&prepared.channel_id, prepared.sequence_sql, index, evidence_json,],
        )?;
    }
    Ok(())
}

fn reject_verified_request_key_conflict(
    transaction: &Connection,
    proposal_digest: ProposalDigest,
    proposal: &LedgerEntry,
) -> Result<()> {
    let channel_id = proposal.channel_id.to_string();
    let idempotency_key = proposal.idempotency_key.to_string();
    let existing = transaction
        .query_row(
            "SELECT proposal_digest, actor_id FROM verified_requests
             WHERE channel_id = ?1 AND idempotency_key = ?2",
            params![&channel_id, &idempotency_key],
            |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, String>(1)?)),
        )
        .optional()?;
    if let Some((existing_digest, existing_actor_id)) = existing {
        let existing_digest: [u8; 32] = existing_digest
            .try_into()
            .map_err(|_| StorageError::CorruptData("verified request proposal digest is not 32 bytes".to_string()))?;
        let existing_digest = ProposalDigest(existing_digest);
        if existing_digest == proposal_digest {
            return Err(StorageError::InvalidVerifiedReplay(
                "exact proposal mapping exists but could not be loaded".to_string(),
            ));
        }
        return Err(verified_request_conflict(
            proposal,
            existing_actor_id,
            existing_digest,
            proposal_digest,
        ));
    }

    // Databases upgraded from schema v1 and trusted imports can contain a
    // ledger idempotency key without a schema-v2 request mapping. Detect that
    // before verifier execution so lost-response recovery cannot trigger
    // repeated expensive proof verification.
    let existing_entry = transaction
        .query_row(
            "SELECT entry_json FROM ledger_entries
             WHERE channel_id = ?1 AND idempotency_key = ?2",
            params![&channel_id, &idempotency_key],
            deserialize_entry_row,
        )
        .optional()?;
    let Some(existing_entry) = existing_entry else {
        return Ok(());
    };
    let existing_actor_id = existing_entry.actor.participant_id.to_string();
    let mut existing_proposal = existing_entry;
    install_verification_evidence(&mut existing_proposal, Vec::new());
    let existing_digest = proposal_digest_unchecked(&existing_proposal);
    if existing_digest == proposal_digest {
        return Err(StorageError::MissingVerifiedRequestMapping);
    }
    Err(verified_request_conflict(
        proposal,
        existing_actor_id,
        existing_digest,
        proposal_digest,
    ))
}

fn verified_request_conflict(
    proposal: &LedgerEntry,
    existing_actor_id: String,
    existing_digest: ProposalDigest,
    proposed_digest: ProposalDigest,
) -> StorageError {
    StorageError::VerifiedRequestConflict(Box::new(VerifiedRequestConflict {
        channel_id: proposal.channel_id.to_string(),
        idempotency_key: proposal.idempotency_key.to_string(),
        existing_actor_id,
        proposed_actor_id: proposal.actor.participant_id.to_string(),
        existing_digest: existing_digest.to_string(),
        proposed_digest: proposed_digest.to_string(),
    }))
}

fn load_verified_replay(
    transaction: &Connection,
    proposal_digest: ProposalDigest,
    proposal: &LedgerEntry,
) -> Result<Option<VerifiedAppendOutcome>> {
    let row = transaction
        .query_row(
            "SELECT request.channel_id, request.actor_id, request.idempotency_key,
                    request.sequence, request.entry_hash,
                    request.snapshot_json, request.recorded_at_ms, entry.entry_json,
                    entry.recorded_at_ms
             FROM verified_requests AS request
             JOIN ledger_entries AS entry
               ON entry.channel_id = request.channel_id
              AND entry.sequence = request.sequence
              AND entry.entry_hash = request.entry_hash
             WHERE request.proposal_digest = ?1",
            [proposal_digest.as_bytes().as_slice()],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, Vec<u8>>(4)?,
                    row.get::<_, Vec<u8>>(5)?,
                    row.get::<_, i64>(6)?,
                    row.get::<_, Vec<u8>>(7)?,
                    row.get::<_, i64>(8)?,
                ))
            },
        )
        .optional()?;
    let Some((
        channel_id,
        actor_id,
        idempotency_key,
        sequence_sql,
        entry_hash,
        snapshot_json,
        request_time,
        entry_json,
        entry_time,
    )) = row
    else {
        return Ok(None);
    };
    if request_time != entry_time {
        return Err(StorageError::InvalidVerifiedReplay(
            "request and ledger timestamps differ".to_string(),
        ));
    }

    let sequence = from_sql_integer("verified request sequence", sequence_sql)?;
    let entry_hash = entry_hash_from_blob("verified request entry hash", entry_hash)?;
    let entry: LedgerEntry = deserialize_protocol_json(&entry_json, "verified request entry")?;
    let snapshot: ChannelSnapshot = deserialize_protocol_json(&snapshot_json, "verified request snapshot")?;
    snapshot.validate()?;

    let mut stored_proposal = entry.clone();
    install_verification_evidence(&mut stored_proposal, Vec::new());
    if stored_proposal != *proposal
        || proposal_digest_unchecked(&stored_proposal) != proposal_digest
        || channel_id != proposal.channel_id.to_string()
        || actor_id != proposal.actor.participant_id.to_string()
        || idempotency_key != proposal.idempotency_key.to_string()
        || sequence != entry.sequence
        || entry_hash != entry.entry_hash()
        || snapshot.channel_id != proposal.channel_id
        || snapshot.last_sequence != sequence
        || snapshot.head_hash != entry_hash
        || snapshot.last_occurred_at_ms != from_sql_integer("verified request time", request_time)?
    {
        return Err(StorageError::InvalidVerifiedReplay(
            "proposal mapping does not match its immutable entry and snapshot".to_string(),
        ));
    }
    let stored_evidence = load_verification_evidence(transaction, &channel_id, sequence_sql)?;
    if stored_evidence != entry.event.verification() {
        return Err(StorageError::InvalidVerifiedReplay(
            "stored evidence rows differ from the immutable entry".to_string(),
        ));
    }

    Ok(Some(VerifiedAppendOutcome {
        proposal_digest,
        sequence,
        entry_hash,
        snapshot,
        replayed: true,
    }))
}

fn load_verification_evidence(
    connection: &Connection,
    channel_id: &str,
    sequence: i64,
) -> Result<Vec<VerificationEvidence>> {
    let mut statement = connection.prepare(
        "SELECT evidence_index, evidence_json FROM verification_evidence
         WHERE channel_id = ?1 AND sequence = ?2 ORDER BY evidence_index",
    )?;
    let mut rows = statement.query(params![channel_id, sequence])?;
    let mut evidence = Vec::new();
    while let Some(row) = rows.next()? {
        let stored_index: i64 = row.get(0)?;
        let expected_index = i64::try_from(evidence.len())
            .map_err(|_| StorageError::CorruptData("verification evidence index overflow".to_string()))?;
        if stored_index != expected_index {
            return Err(StorageError::CorruptData(
                "verification evidence indices are not contiguous".to_string(),
            ));
        }
        let bytes: Vec<u8> = row.get(1)?;
        evidence.push(deserialize_protocol_json(&bytes, "verification evidence")?);
    }
    Ok(evidence)
}

fn lookup_idempotency_hash(transaction: &Transaction<'_>, prepared: &PreparedEntry) -> Result<Option<EntryHash>> {
    let bytes = transaction
        .query_row(
            "SELECT entry_hash FROM ledger_entries
             WHERE channel_id = ?1 AND idempotency_key = ?2",
            params![&prepared.channel_id, &prepared.idempotency_key],
            |row| row.get::<_, Vec<u8>>(0),
        )
        .optional()?;
    bytes
        .map(|value| entry_hash_from_blob("idempotency entry hash", value))
        .transpose()
}

fn invoice_id_already_used(transaction: &Transaction<'_>, prepared: &PreparedEntry) -> Result<bool> {
    let Some(invoice_id) = prepared.created_invoice_id.as_ref() else {
        return Ok(false);
    };
    transaction
        .query_row(
            "SELECT EXISTS(
                 SELECT 1 FROM ledger_entries WHERE channel_id = ?1 AND created_invoice_id = ?2
             )",
            params![&prepared.channel_id, invoice_id],
            |row| row.get(0),
        )
        .map_err(StorageError::from)
}

fn finish_transaction<T>(transaction: Transaction<'_>, operation: Result<T>) -> Result<T> {
    match operation {
        Ok(value) => {
            transaction.commit()?;
            Ok(value)
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

fn finish_verified_transaction<T, E>(
    transaction: Transaction<'_>,
    operation: std::result::Result<T, VerifiedAppendError<E>>,
) -> std::result::Result<T, VerifiedAppendError<E>> {
    match operation {
        Ok(value) => {
            transaction
                .commit()
                .map_err(StorageError::from)
                .map_err(VerifiedAppendError::Storage)?;
            Ok(value)
        }
        Err(operation_error) => match transaction.rollback() {
            Ok(()) => Err(operation_error),
            Err(rollback_error) => {
                let operation_error = match operation_error {
                    VerifiedAppendError::Storage(error) => error.to_string(),
                    VerifiedAppendError::Verification(_) => "proposal verification failed".to_string(),
                };
                Err(VerifiedAppendError::Storage(StorageError::RollbackFailed {
                    operation_error,
                    rollback_error,
                }))
            }
        },
    }
}

fn configure_durability(connection: &Connection, expected_busy_timeout: Duration) -> Result<()> {
    enable_wal(connection, expected_busy_timeout)?;
    connection.pragma_update(None, "synchronous", "FULL")?;
    connection.pragma_update(None, "foreign_keys", true)?;
    connection.pragma_update(None, "wal_autocheckpoint", 1_000_i64)?;
    connection.pragma_update(None, "trusted_schema", false)?;
    let foreign_keys: i64 = connection.pragma_query_value(None, "foreign_keys", |row| row.get(0))?;
    let synchronous: i64 = connection.pragma_query_value(None, "synchronous", |row| row.get(0))?;
    let busy_timeout_ms: i64 = connection.pragma_query_value(None, "busy_timeout", |row| row.get(0))?;
    let expected_busy_timeout_ms = i64::try_from(expected_busy_timeout.as_millis())
        .map_err(|_| StorageError::InvalidInput("busy timeout is too large".to_string()))?;
    if foreign_keys != 1 || synchronous != 2 || busy_timeout_ms != expected_busy_timeout_ms {
        return Err(StorageError::InvalidInput(
            "SQLite refused required foreign-key, FULL synchronous, or busy-timeout settings".to_string(),
        ));
    }
    Ok(())
}

fn enable_wal(connection: &Connection, timeout: Duration) -> Result<()> {
    let started = Instant::now();
    loop {
        match connection.query_row("PRAGMA journal_mode = WAL", [], |row| row.get::<_, String>(0)) {
            Ok(mode) if mode.eq_ignore_ascii_case("wal") => return Ok(()),
            Ok(mode) if started.elapsed() >= timeout => {
                return Err(StorageError::InvalidInput(format!(
                    "SQLite refused WAL journal mode and selected {mode}"
                )));
            }
            Ok(_) => {}
            Err(error) if is_lock_contention(&error) && started.elapsed() < timeout => {}
            Err(error) => return Err(StorageError::Database(error)),
        }

        let remaining = timeout.saturating_sub(started.elapsed());
        std::thread::sleep(remaining.min(Duration::from_millis(10)));
    }
}

fn is_lock_contention(error: &rusqlite::Error) -> bool {
    matches!(
        error,
        rusqlite::Error::SqliteFailure(details, _)
            if matches!(details.code, ErrorCode::DatabaseBusy | ErrorCode::DatabaseLocked)
    )
}

fn configure_backup_source(
    connection: &Connection,
    path: &Path,
    busy_timeout: Duration,
    limits: ProtocolLimits,
) -> Result<()> {
    connection.busy_timeout(busy_timeout)?;
    connection.pragma_update(None, "foreign_keys", true)?;
    connection.pragma_update(None, "trusted_schema", false)?;
    connection.pragma_update(None, "query_only", true)?;
    let journal_mode: String = connection.pragma_query_value(None, "journal_mode", |row| row.get(0))?;
    if !journal_mode.eq_ignore_ascii_case("wal") {
        return Err(StorageError::InvalidInput(format!(
            "backup source is not in WAL journal mode: {journal_mode}"
        )));
    }
    migrations::validate_current(connection, path, limits)
}

fn integrity_check_connection(
    connection: &mut Connection,
    reducer: &ChannelReducer,
    path: &Path,
) -> Result<IntegrityReport> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
    let operation = integrity_check_snapshot(&transaction, reducer, path);
    finish_transaction(transaction, operation)
}

fn integrity_check_snapshot(connection: &Connection, reducer: &ChannelReducer, path: &Path) -> Result<IntegrityReport> {
    migrations::validate_current(connection, path, reducer.limits())?;
    let mut failures = sqlite_integrity_failures(connection)?;
    let mut channels_checked = 0usize;
    let mut entries_checked = 0usize;
    let mut statement = connection.prepare(
        "SELECT channel_id, head_sequence, head_entry_hash, snapshot_json
         FROM channel_snapshots ORDER BY channel_id",
    )?;
    let mut rows = statement.query([])?;
    while let Some(row) = rows.next()? {
        channels_checked += 1;
        if let Err(error) = validate_channel_row(row, connection, reducer, &mut entries_checked) {
            failures.push(error.to_string());
        }
    }
    drop(rows);
    drop(statement);
    if let Err(error) = validate_verified_request_records(connection) {
        failures.push(error.to_string());
    }
    if failures.is_empty() {
        Ok(IntegrityReport {
            channels_checked,
            entries_checked,
        })
    } else {
        Err(StorageError::IntegrityCheckFailed(failures))
    }
}

fn validate_verified_request_records(connection: &Connection) -> Result<()> {
    let orphaned_evidence: bool = connection.query_row(
        "SELECT EXISTS(
             SELECT 1 FROM verification_evidence AS evidence
             LEFT JOIN verified_requests AS request
               ON request.channel_id = evidence.channel_id
              AND request.sequence = evidence.sequence
             WHERE request.proposal_digest IS NULL
         )",
        [],
        |row| row.get(0),
    )?;
    if orphaned_evidence {
        return Err(StorageError::CorruptData(
            "verification evidence exists without a verified request mapping".to_string(),
        ));
    }

    let mut statement = connection.prepare("SELECT proposal_digest FROM verified_requests ORDER BY proposal_digest")?;
    let digests = statement
        .query_map([], |row| row.get::<_, Vec<u8>>(0))?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    for digest in digests {
        let digest: [u8; 32] = digest
            .try_into()
            .map_err(|_| StorageError::CorruptData("verified proposal digest is not 32 bytes".to_string()))?;
        let digest = ProposalDigest(digest);
        let entry_json: Vec<u8> = connection.query_row(
            "SELECT entry.entry_json
             FROM verified_requests AS request
             JOIN ledger_entries AS entry
               ON entry.channel_id = request.channel_id
              AND entry.sequence = request.sequence
              AND entry.entry_hash = request.entry_hash
             WHERE request.proposal_digest = ?1",
            [digest.as_bytes().as_slice()],
            |row| row.get(0),
        )?;
        let mut proposal: LedgerEntry = deserialize_protocol_json(&entry_json, "verified request entry")?;
        install_verification_evidence(&mut proposal, Vec::new());
        if load_verified_replay(connection, digest, &proposal)?.is_none() {
            return Err(StorageError::CorruptData(
                "verified request disappeared from a stable integrity snapshot".to_string(),
            ));
        }
    }
    Ok(())
}

fn sqlite_integrity_failures(connection: &Connection) -> Result<Vec<String>> {
    let mut failures = Vec::new();
    let mut statement = connection.prepare("PRAGMA integrity_check")?;
    for row in statement.query_map([], |row| row.get::<_, String>(0))? {
        let message = row?;
        if message != "ok" {
            failures.push(message);
        }
    }
    let mut statement = connection.prepare("PRAGMA foreign_key_check")?;
    let mut rows = statement.query([])?;
    while let Some(row) = rows.next()? {
        let table: String = row.get(0)?;
        let row_id: Option<i64> = row.get(1)?;
        let parent: String = row.get(2)?;
        let constraint: i64 = row.get(3)?;
        failures.push(format!(
            "foreign key violation in {table} row {row_id:?}, parent {parent}, constraint {constraint}"
        ));
    }
    Ok(failures)
}

fn validate_channel_row(
    row: &Row<'_>,
    connection: &Connection,
    reducer: &ChannelReducer,
    entries_checked: &mut usize,
) -> Result<()> {
    let indexed_channel_id: String = row.get(0)?;
    let indexed_head_sequence = from_sql_integer("channel head sequence", row.get(1)?)?;
    let indexed_head_hash: Vec<u8> = row.get(2)?;
    let snapshot_json: Vec<u8> = row.get(3)?;
    let snapshot: ChannelSnapshot = deserialize_protocol_json(&snapshot_json, "channel snapshot")?;
    if snapshot.channel_id.to_string() != indexed_channel_id
        || snapshot.last_sequence != indexed_head_sequence
        || snapshot.head_hash.as_bytes().as_slice() != indexed_head_hash
    {
        return Err(StorageError::CorruptData(format!(
            "channel {indexed_channel_id} snapshot differs from its indexed head"
        )));
    }
    let replayed = replay_channel(connection, reducer, &indexed_channel_id, entries_checked)?;
    if replayed != snapshot {
        return Err(StorageError::CorruptData(format!(
            "channel {indexed_channel_id} snapshot differs from replayed ledger state"
        )));
    }
    Ok(())
}

fn replay_channel(
    connection: &Connection,
    reducer: &ChannelReducer,
    channel_id: &str,
    entries_checked: &mut usize,
) -> Result<ChannelSnapshot> {
    let mut statement = connection.prepare(
        "SELECT sequence, entry_hash, previous_entry_hash, idempotency_key,
                created_invoice_id, protocol_version, occurred_at_ms, recorded_at_ms, entry_json
         FROM ledger_entries WHERE channel_id = ?1 ORDER BY sequence",
    )?;
    let mut rows = statement.query([channel_id])?;
    let mut current: Option<ChannelSnapshot> = None;
    let mut idempotency_keys = BTreeSet::new();
    let mut invoice_ids = BTreeSet::new();
    while let Some(row) = rows.next()? {
        *entries_checked += 1;
        let indexed_sequence = from_sql_integer("ledger sequence", row.get(0)?)?;
        let indexed_hash: Vec<u8> = row.get(1)?;
        let indexed_previous_hash: Vec<u8> = row.get(2)?;
        let indexed_idempotency_key: String = row.get(3)?;
        let indexed_invoice_id: Option<String> = row.get(4)?;
        let indexed_protocol_version: i64 = row.get(5)?;
        let indexed_occurred_at_ms = from_sql_integer("occurred_at_ms", row.get(6)?)?;
        let indexed_recorded_at_ms = from_sql_integer("recorded_at_ms", row.get(7)?)?;
        let entry_json: Vec<u8> = row.get(8)?;
        let entry: LedgerEntry = deserialize_protocol_json(&entry_json, "ledger entry")?;
        if entry.channel_id.to_string() != channel_id
            || entry.sequence != indexed_sequence
            || entry.entry_hash().as_bytes().as_slice() != indexed_hash
            || entry.previous_entry_hash.as_bytes().as_slice() != indexed_previous_hash
            || entry.idempotency_key.to_string() != indexed_idempotency_key
            || entry.created_invoice_id().map(ToString::to_string) != indexed_invoice_id
            || i64::from(entry.protocol_version) != indexed_protocol_version
            || entry.occurred_at_ms != indexed_occurred_at_ms
        {
            return Err(StorageError::CorruptData(format!(
                "channel {channel_id} entry {indexed_sequence} differs from its indexed columns"
            )));
        }
        if !idempotency_keys.insert(indexed_idempotency_key) {
            return Err(StorageError::CorruptData(format!(
                "channel {channel_id} repeats an idempotency key"
            )));
        }
        if let Some(invoice_id) = indexed_invoice_id {
            if !invoice_ids.insert(invoice_id) {
                return Err(StorageError::CorruptData(format!(
                    "channel {channel_id} repeats an invoice id"
                )));
            }
        }
        let reduction = reducer.apply(
            current.as_ref(),
            &entry,
            HistoryContext {
                existing_idempotency_hash: None,
                invoice_id_already_used: false,
                ledger_time_ms: indexed_recorded_at_ms,
            },
        )?;
        if reduction.disposition != ApplyDisposition::Applied {
            return Err(StorageError::CorruptData(format!(
                "channel {channel_id} persisted a replay at sequence {indexed_sequence}"
            )));
        }
        current = Some(reduction.snapshot);
    }
    current.ok_or_else(|| StorageError::CorruptData(format!("channel {channel_id} has no ledger entries")))
}

fn load_channel(connection: &Connection, channel_id: &str) -> Result<Option<ChannelSnapshot>> {
    let bytes = connection
        .query_row(
            "SELECT snapshot_json FROM channel_snapshots WHERE channel_id = ?1",
            [channel_id],
            |row| row.get::<_, Vec<u8>>(0),
        )
        .optional()?;
    bytes
        .map(|value| deserialize_protocol_json(&value, "channel snapshot"))
        .transpose()
}

fn load_entry(connection: &Connection, channel_id: &str, sequence: i64) -> Result<Option<LedgerEntry>> {
    let bytes = connection
        .query_row(
            "SELECT entry_json FROM ledger_entries WHERE channel_id = ?1 AND sequence = ?2",
            params![channel_id, sequence],
            |row| row.get::<_, Vec<u8>>(0),
        )
        .optional()?;
    bytes
        .map(|value| deserialize_protocol_json(&value, "ledger entry"))
        .transpose()
}

fn deserialize_entry_row(row: &Row<'_>) -> rusqlite::Result<LedgerEntry> {
    deserialize_json_row(row)
}

fn deserialize_json_row<T: serde::de::DeserializeOwned>(row: &Row<'_>) -> rusqlite::Result<T> {
    let bytes: Vec<u8> = row.get(0)?;
    serde_json::from_slice(&bytes).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(bytes.len(), rusqlite::types::Type::Blob, Box::new(error))
    })
}

fn deserialize_protocol_json<T: serde::de::DeserializeOwned>(bytes: &[u8], label: &str) -> Result<T> {
    serde_json::from_slice(bytes).map_err(|error| StorageError::CorruptData(format!("invalid {label} JSON: {error}")))
}

fn collect_json_page<T: serde::de::DeserializeOwned>(rows: &mut Rows<'_>, kind: &'static str) -> Result<Vec<T>> {
    let mut items = Vec::new();
    let mut bytes_used = 0usize;
    while let Some(row) = rows.next()? {
        let serialized_size = row.get::<_, i64>(0)?;
        let serialized_size = usize::try_from(serialized_size)
            .map_err(|_| StorageError::CorruptData(format!("{kind} has a negative serialized size")))?;
        if serialized_size > MAX_PAGE_BYTES {
            return Err(StorageError::PageItemTooLarge {
                kind,
                bytes: serialized_size,
                limit: MAX_PAGE_BYTES,
            });
        }
        let next_size = bytes_used
            .checked_add(serialized_size)
            .ok_or_else(|| StorageError::CorruptData(format!("{kind} page size overflow")))?;
        if next_size > MAX_PAGE_BYTES {
            return Err(StorageError::PageByteBudgetExceeded {
                kind,
                limit: MAX_PAGE_BYTES,
            });
        }

        let serialized: Vec<u8> = row.get(1)?;
        if serialized.len() != serialized_size {
            return Err(StorageError::CorruptData(format!(
                "{kind} length changed while reading a stable page"
            )));
        }
        items.push(deserialize_protocol_json(&serialized, kind)?);
        bytes_used = next_size;
    }
    Ok(items)
}

fn entry_hash_from_blob(label: &str, bytes: Vec<u8>) -> Result<EntryHash> {
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| StorageError::CorruptData(format!("{label} is not 32 bytes")))?;
    Ok(EntryHash::from_bytes(bytes))
}

fn validate_page_limit(limit: usize) -> Result<i64> {
    if !(1..=MAX_PAGE_LIMIT).contains(&limit) {
        return Err(StorageError::InvalidInput(format!(
            "page limit must be between 1 and {MAX_PAGE_LIMIT}"
        )));
    }
    i64::try_from(limit).map_err(|_| StorageError::InvalidInput("page limit is too large".to_string()))
}

fn validate_database_path(path: &Path) -> Result<()> {
    if path.as_os_str().is_empty() {
        return Err(StorageError::InvalidInput(
            "database path must not be empty".to_string(),
        ));
    }
    if path.is_dir() {
        return Err(StorageError::InvalidInput(format!(
            "database path is a directory: {}",
            path.display()
        )));
    }
    Ok(())
}

#[cfg(unix)]
fn sync_parent_directory(parent: &Path, published_path: &Path) -> Result<()> {
    std::fs::File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|source| StorageError::BackupPublishedButDirectorySyncFailed {
            path: published_path.to_path_buf(),
            source,
        })
}

#[cfg(not(unix))]
fn sync_parent_directory(_parent: &Path, _published_path: &Path) -> Result<()> {
    // Windows does not expose a portable directory fsync through std. The file
    // itself has already been sync_all'd before the no-clobber persist.
    Ok(())
}

fn now_unix_millis() -> Result<i64> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| StorageError::InvalidSystemClock)?;
    i64::try_from(duration.as_millis()).map_err(|_| StorageError::InvalidSystemClock)
}

fn to_sql_integer(label: &str, value: u64) -> Result<i64> {
    i64::try_from(value).map_err(|_| StorageError::InvalidInput(format!("{label} exceeds SQLite INTEGER range")))
}

fn from_sql_integer(label: &str, value: i64) -> Result<u64> {
    u64::try_from(value).map_err(|_| StorageError::CorruptData(format!("{label} is negative")))
}

#[cfg(test)]
mod private_tests {
    use super::*;
    use std::sync::{mpsc, Arc};
    use tempfile::TempDir;

    #[test]
    fn page_limits_are_bounded() {
        assert!(validate_page_limit(1).is_ok());
        assert!(validate_page_limit(MAX_PAGE_LIMIT).is_ok());
        assert!(validate_page_limit(0).is_err());
        assert!(validate_page_limit(MAX_PAGE_LIMIT + 1).is_err());
    }

    #[test]
    fn sqlite_storage_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<SqliteStorage>();
    }

    #[test]
    fn required_pragmas_and_schema_survive_reopen() {
        let directory = TempDir::new().expect("temporary directory");
        let path = directory.path().join("node.db");
        for _ in 0..2 {
            let storage = SqliteStorage::open(&path).expect("open storage");
            let connection = storage.lock_connection().expect("lock connection");
            let journal: String = connection
                .pragma_query_value(None, "journal_mode", |row| row.get(0))
                .expect("journal mode");
            let foreign_keys: i64 = connection
                .pragma_query_value(None, "foreign_keys", |row| row.get(0))
                .expect("foreign keys");
            let synchronous: i64 = connection
                .pragma_query_value(None, "synchronous", |row| row.get(0))
                .expect("synchronous");
            let busy_timeout: i64 = connection
                .pragma_query_value(None, "busy_timeout", |row| row.get(0))
                .expect("busy timeout");
            let application_id: i64 = connection
                .pragma_query_value(None, "application_id", |row| row.get(0))
                .expect("application id");
            let user_version: i64 = connection
                .pragma_query_value(None, "user_version", |row| row.get(0))
                .expect("user version");
            assert_eq!(journal, "wal");
            assert_eq!(foreign_keys, 1);
            assert_eq!(synchronous, 2);
            assert_eq!(busy_timeout, 5_000);
            assert_eq!(application_id, migrations::APPLICATION_ID);
            assert_eq!(user_version, migrations::CURRENT_SCHEMA_VERSION);
        }
    }

    #[test]
    fn online_backup_does_not_take_the_request_connection_mutex() {
        let directory = TempDir::new().expect("temporary directory");
        let path = directory.path().join("node.db");
        let destination = directory.path().join("backup.db");
        let storage = Arc::new(SqliteStorage::open(&path).expect("open storage"));
        let request_connection = storage.lock_connection().expect("hold request connection");
        let (sender, receiver) = mpsc::channel();
        let backup_storage = Arc::clone(&storage);
        let handle = std::thread::spawn(move || {
            let result = backup_storage.backup_to(destination);
            sender.send(result).expect("send backup result");
        });

        let result = receiver
            .recv_timeout(Duration::from_secs(2))
            .expect("backup should not wait for request mutex");
        result.expect("online backup");
        drop(request_connection);
        handle.join().expect("join backup thread");
    }
}
