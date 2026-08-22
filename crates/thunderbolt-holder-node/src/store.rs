use std::collections::{BTreeMap, BTreeSet};
#[cfg(unix)]
use std::fs::{File, OpenOptions};
#[cfg(not(unix))]
struct File;
use std::path::{Component, Path, PathBuf};
use std::sync::{Mutex, OnceLock};

use rusqlite::{params, Connection, OpenFlags, OptionalExtension, Transaction, TransactionBehavior};
use sha2::{Digest as _, Sha256};
use thunderbolt_ledger::{AppHashV2, ChannelContextIdV2, EntryHashV2, RequestDigestV2};

use crate::config::{HolderNodeConfig, RetryPolicy, MAX_COMMAND_ROWS, MAX_OUTBOX_ROWS, MAX_PROPOSAL_BYTES};
use crate::types::{
    CommandId, FinalizedBlockCursor, FinalizedChannelCursor, LifecycleState, OutboxRecord, OutboxStatus,
    QueueDisposition,
};
use crate::{
    FinalityCoordinatorId, FinalityRangeIntentV2, FinalityVerifierProfileId, FinalizedRangeCapabilityV2,
    HolderNodeError, Result, ServiceStatus, StagedFinalityRangeCapabilityV2, StagedFinalityRecoveryV2,
};

const APPLICATION_ID: i64 = 0x5442_484e; // TBHN
const SCHEMA_VERSION: i64 = 3;
const MAX_DURABLE_FINALITY_JSON_BYTES: usize = 512 * 1024;
type ServiceIdentityRow = (
    i64,
    String,
    Vec<u8>,
    Option<Vec<u8>>,
    Option<Vec<u8>>,
    Option<Vec<u8>>,
    Option<Vec<u8>>,
);
type CursorStorageRow = (Vec<u8>, Vec<u8>, i64, Vec<u8>, Option<i64>, Option<i64>);
type StageStorageRow = (Vec<u8>, Vec<u8>, Vec<u8>, i64, i64);
type ExistingIdentityRow = (i64, String, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>);

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct DurableFileIdentity {
    device: u64,
    inode: u64,
}

impl DurableFileIdentity {
    fn digest(self, path: &Path) -> Result<[u8; 32]> {
        #[cfg(unix)]
        use std::os::unix::ffi::OsStrExt as _;

        let mut hasher = Sha256::new();
        hasher.update(b"bitcoin-thunderbolt/holder-node/durable-file/v1");
        #[cfg(unix)]
        let path_bytes = path.as_os_str().as_bytes();
        #[cfg(not(unix))]
        let path_bytes = path.as_os_str().to_string_lossy().as_bytes();
        hasher.update(
            u64::try_from(path_bytes.len())
                .map_err(|_| HolderNodeError::OutOfRange)?
                .to_be_bytes(),
        );
        hasher.update(path_bytes);
        hasher.update(self.device.to_be_bytes());
        hasher.update(self.inode.to_be_bytes());
        Ok(hasher.finalize().into())
    }
}

static OPEN_DATABASES: OnceLock<Mutex<BTreeSet<DurableFileIdentity>>> = OnceLock::new();

struct ProcessFileLock(DurableFileIdentity);

impl ProcessFileLock {
    fn acquire(identity: DurableFileIdentity) -> Result<Self> {
        let mut open = OPEN_DATABASES
            .get_or_init(|| Mutex::new(BTreeSet::new()))
            .lock()
            .map_err(|_| HolderNodeError::StorageUnavailable)?;
        if !open.insert(identity) {
            return Err(HolderNodeError::StorageUnavailable);
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

pub(crate) struct FinalizedUpdate {
    pub cursor: FinalizedChannelCursor,
    pub previous_entry_hash: EntryHashV2,
    pub request_digest: RequestDigestV2,
    pub proposal_digest: [u8; 32],
    pub finality_digest: [u8; 32],
}

pub(crate) struct RuntimeStore {
    path: PathBuf,
    file_identity: DurableFileIdentity,
    file_identity_digest: [u8; 32],
    store_identity: [u8; 32],
    _database_file: File,
    _role_lock: File,
    _process_lock: ProcessFileLock,
    connection: Connection,
    chain: thunderbolt_ledger::LedgerChainIdV2,
    verifier_profile: FinalityVerifierProfileId,
    coordinator_id: FinalityCoordinatorId,
    service_domain: [u8; 32],
}

impl RuntimeStore {
    pub(crate) fn open(
        path: &Path,
        config: &HolderNodeConfig,
        service_domain: &[u8; 32],
        legacy_service_domain: &[u8; 32],
        expected_recovery: Option<&StagedFinalityRecoveryV2>,
    ) -> Result<Self> {
        let (path, file_identity, database_file) = prepare_durable_path(path, true)?;
        let role_lock = open_role_lock(&path)?;
        let process_lock = ProcessFileLock::acquire(file_identity)?;
        let mut connection = Connection::open_with_flags(
            &path,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_CREATE
                | OpenFlags::SQLITE_OPEN_FULL_MUTEX
                | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )?;
        verify_durable_file(&path, file_identity)?;
        configure_connection(&connection, config)?;
        let file_identity_digest = file_identity.digest(&path)?;
        let store_identity = initialize_schema(
            &mut connection,
            config,
            service_domain,
            legacy_service_domain,
            &file_identity_digest,
        )?;
        let store = Self {
            path,
            file_identity,
            file_identity_digest,
            store_identity,
            _database_file: database_file,
            _role_lock: role_lock,
            _process_lock: process_lock,
            connection,
            chain: config.ledger_chain_id().clone(),
            verifier_profile: config.finality_verifier_profile(),
            coordinator_id: config.finality_coordinator_id(),
            service_domain: *service_domain,
        };
        store.verify_identity()?;
        let actual_recovery = store.staged_finality()?.as_ref().map(StagedFinalityRecoveryV2::new);
        if actual_recovery.as_ref() != expected_recovery {
            return Err(HolderNodeError::FinalityConflict);
        }
        let _ = store.execution_cursor()?;
        Ok(store)
    }

    pub(crate) fn inspect_staged_recovery(
        path: &Path,
        config: &HolderNodeConfig,
        service_domain: &[u8; 32],
    ) -> Result<Option<StagedFinalityRecoveryV2>> {
        let (path, file_identity, database_file) = prepare_durable_path(path, false)?;
        let connection = Connection::open_with_flags(
            &path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_FULL_MUTEX | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )?;
        verify_durable_file(&path, file_identity)?;
        let file_identity_digest = file_identity.digest(&path)?;
        validate_existing_identity(&connection, config, service_domain, &file_identity_digest)?;
        let store_identity = load_store_identity(&connection)?;
        let staged = read_staged(&connection, store_identity, file_identity_digest)?;
        drop(connection);
        drop(database_file);
        verify_durable_file(&path, file_identity)?;
        Ok(staged.as_ref().map(StagedFinalityRecoveryV2::new))
    }

    fn verify_identity(&self) -> Result<()> {
        verify_durable_file(&self.path, self.file_identity)?;
        validate_existing_identity_values(
            &self.connection,
            &self.chain,
            self.verifier_profile,
            self.coordinator_id,
            &self.store_identity,
            &self.file_identity_digest,
            &self.service_domain,
        )
    }

    pub(crate) fn begin_run(&mut self) -> Result<(u64, bool)> {
        self.verify_identity()?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (active, generation): (i64, i64) = transaction.query_row(
            "SELECT active, run_generation FROM service_meta WHERE singleton = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        let next = generation.checked_add(1).ok_or(HolderNodeError::OutOfRange)?;
        transaction.execute(
            "UPDATE service_meta SET active = 1, lifecycle = ?1, run_generation = ?2 WHERE singleton = 1",
            params![lifecycle_code(LifecycleState::Running), next],
        )?;
        transaction.commit()?;
        self.verify_identity()?;
        Ok((
            u64::try_from(next).map_err(|_| HolderNodeError::StorageCorrupt)?,
            active == 1,
        ))
    }

    pub(crate) fn stored_lifecycle(&self) -> Result<LifecycleState> {
        self.verify_identity()?;
        let code: i64 =
            self.connection
                .query_row("SELECT lifecycle FROM service_meta WHERE singleton = 1", [], |row| {
                    row.get(0)
                })?;
        lifecycle_from_code(code)
    }

    pub(crate) fn set_lifecycle(&mut self, lifecycle: LifecycleState, active: bool) -> Result<()> {
        self.verify_identity()?;
        self.connection.execute(
            "UPDATE service_meta SET lifecycle = ?1, active = ?2 WHERE singleton = 1",
            params![lifecycle_code(lifecycle), i64::from(active)],
        )?;
        self.verify_identity()
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn queue(
        &mut self,
        command_id: CommandId,
        request_digest: &RequestDigestV2,
        channel_context_id: &ChannelContextIdV2,
        sequence: u64,
        proposal_digest: &[u8; 32],
        proposal_bytes: &[u8],
        now_ms: u64,
    ) -> Result<QueueDisposition> {
        self.verify_identity()?;
        if proposal_bytes.is_empty() || proposal_bytes.len() > MAX_PROPOSAL_BYTES || now_ms == 0 {
            return Err(HolderNodeError::InvalidRequest("proposal or timestamp outside bounds"));
        }
        let sequence = to_i64(sequence)?;
        let now = to_i64(now_ms)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some((stored_request, stored_digest)) = transaction
            .query_row(
                "SELECT request_digest, proposal_digest FROM command_dedup WHERE command_id = ?1",
                [command_id.as_bytes().as_slice()],
                |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?)),
            )
            .optional()?
        {
            if stored_request.as_slice() == request_digest.as_bytes() && stored_digest.as_slice() == proposal_digest {
                transaction.commit()?;
                return Ok(QueueDisposition::AlreadyQueued);
            }
            return Err(HolderNodeError::IdempotencyConflict);
        }
        let command_count: i64 = transaction.query_row("SELECT COUNT(*) FROM command_dedup", [], |row| row.get(0))?;
        if usize::try_from(command_count).map_err(|_| HolderNodeError::StorageCorrupt)? >= MAX_COMMAND_ROWS {
            return Err(HolderNodeError::OutboxCapacity);
        }
        if let Some(stored_digest) = transaction
            .query_row(
                "SELECT proposal_digest FROM outbox WHERE request_digest = ?1",
                [request_digest.as_bytes().as_slice()],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()?
        {
            if stored_digest.as_slice() != proposal_digest {
                return Err(HolderNodeError::IdempotencyConflict);
            }
            transaction.execute(
                "INSERT INTO command_dedup(command_id, request_digest, proposal_digest) VALUES(?1, ?2, ?3)",
                params![
                    command_id.as_bytes().as_slice(),
                    request_digest.as_bytes().as_slice(),
                    proposal_digest
                ],
            )?;
            transaction.commit()?;
            return Ok(QueueDisposition::AlreadyQueued);
        }
        let count: i64 = transaction.query_row("SELECT COUNT(*) FROM outbox", [], |row| row.get(0))?;
        if usize::try_from(count).map_err(|_| HolderNodeError::StorageCorrupt)? >= MAX_OUTBOX_ROWS {
            return Err(HolderNodeError::OutboxCapacity);
        }
        transaction.execute(
            "INSERT INTO outbox(request_digest, channel_context_id, sequence, proposal_bytes, proposal_digest,
                                status, attempts, next_attempt_ms, created_at_ms, updated_at_ms)
             VALUES(?1, ?2, ?3, ?4, ?5, ?6, 0, ?7, ?7, ?7)",
            params![
                request_digest.as_bytes().as_slice(),
                channel_context_id.as_bytes().as_slice(),
                sequence,
                proposal_bytes,
                proposal_digest,
                OutboxStatus::Queued.code(),
                now,
            ],
        )?;
        transaction.execute(
            "INSERT INTO command_dedup(command_id, request_digest, proposal_digest) VALUES(?1, ?2, ?3)",
            params![
                command_id.as_bytes().as_slice(),
                request_digest.as_bytes().as_slice(),
                proposal_digest
            ],
        )?;
        transaction.commit()?;
        self.verify_identity()?;
        Ok(QueueDisposition::Queued)
    }

    pub(crate) fn due(&self, now_ms: u64, limit: usize) -> Result<Vec<OutboxRecord>> {
        self.verify_identity()?;
        let now = to_i64(now_ms)?;
        let limit = i64::try_from(limit).map_err(|_| HolderNodeError::OutOfRange)?;
        let mut statement = self.connection.prepare(
            "SELECT request_digest, proposal_bytes FROM outbox
             WHERE status IN (0,1) AND next_attempt_ms <= ?1
             ORDER BY next_attempt_ms, channel_context_id, sequence LIMIT ?2",
        )?;
        let rows = statement.query_map(params![now, limit], |row| {
            Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?))
        })?;
        let mut records = Vec::new();
        for row in rows {
            let (request, proposal_bytes) = row?;
            if proposal_bytes.is_empty() || proposal_bytes.len() > MAX_PROPOSAL_BYTES {
                return Err(HolderNodeError::StorageCorrupt);
            }
            records.push(OutboxRecord {
                request_digest: RequestDigestV2::from_bytes(request)?,
                proposal_bytes,
            });
        }
        Ok(records)
    }

    pub(crate) fn record_submission(
        &mut self,
        request: &RequestDigestV2,
        now_ms: u64,
        accepted: bool,
        retry: RetryPolicy,
    ) -> Result<OutboxStatus> {
        self.verify_identity()?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (status, attempts): (i64, i64) = transaction.query_row(
            "SELECT status, attempts FROM outbox WHERE request_digest = ?1",
            [request.as_bytes().as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        let current = OutboxStatus::from_code(status)?;
        if current == OutboxStatus::Finalized {
            transaction.commit()?;
            return Ok(current);
        }
        let attempts = u32::try_from(attempts)
            .map_err(|_| HolderNodeError::StorageCorrupt)?
            .checked_add(1)
            .ok_or(HolderNodeError::OutOfRange)?;
        let next_status = if accepted {
            OutboxStatus::Submitted
        } else if attempts >= retry.maximum_attempts {
            OutboxStatus::RetryExhausted
        } else {
            OutboxStatus::Queued
        };
        let next_attempt = now_ms
            .checked_add(retry.delay_after(attempts))
            .ok_or(HolderNodeError::OutOfRange)?;
        transaction.execute(
            "UPDATE outbox SET status = ?1, attempts = ?2, next_attempt_ms = ?3, updated_at_ms = ?4
             WHERE request_digest = ?5",
            params![
                next_status.code(),
                i64::from(attempts),
                to_i64(next_attempt)?,
                to_i64(now_ms)?,
                request.as_bytes().as_slice(),
            ],
        )?;
        transaction.commit()?;
        self.verify_identity()?;
        Ok(next_status)
    }

    pub(crate) fn retry(&mut self, command_id: CommandId, now_ms: u64) -> Result<()> {
        self.verify_identity()?;
        let changed = self.connection.execute(
            "UPDATE outbox SET status = ?1, attempts = 0, next_attempt_ms = ?2, updated_at_ms = ?2
             WHERE request_digest = (SELECT request_digest FROM command_dedup WHERE command_id = ?3)
               AND status != ?4",
            params![
                OutboxStatus::Queued.code(),
                to_i64(now_ms)?,
                command_id.as_bytes().as_slice(),
                OutboxStatus::Finalized.code(),
            ],
        )?;
        if changed == 0 {
            return Err(HolderNodeError::InvalidRequest(
                "command is unknown or already finalized",
            ));
        }
        self.verify_identity()
    }

    pub(crate) fn channels(&self) -> Result<Vec<ChannelContextIdV2>> {
        self.verify_identity()?;
        let mut statement = self
            .connection
            .prepare("SELECT DISTINCT channel_context_id FROM outbox ORDER BY channel_context_id")?;
        let rows = statement.query_map([], |row| row.get::<_, Vec<u8>>(0))?;
        let mut channels = Vec::new();
        for row in rows {
            channels.push(ChannelContextIdV2::from_bytes(row?)?);
        }
        Ok(channels)
    }

    pub(crate) fn execution_cursor(&self) -> Result<FinalizedBlockCursor> {
        self.verify_identity()?;
        read_execution_cursor(
            &self.connection,
            &self.chain,
            self.verifier_profile,
            self.coordinator_id,
        )
    }

    pub(crate) fn channel_cursor(&self, channel: &ChannelContextIdV2) -> Result<Option<FinalizedChannelCursor>> {
        self.verify_identity()?;
        self.connection
            .query_row(
                "SELECT sequence, entry_hash FROM finalized_heads WHERE channel_context_id = ?1",
                [channel.as_bytes().as_slice()],
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, Vec<u8>>(1)?)),
            )
            .optional()?
            .map(|(sequence, entry_hash)| {
                Ok(FinalizedChannelCursor::new(
                    channel.clone(),
                    u64::try_from(sequence).map_err(|_| HolderNodeError::StorageCorrupt)?,
                    EntryHashV2::from_bytes(entry_hash)?,
                ))
            })
            .transpose()
    }

    pub(crate) fn staged_finality(&self) -> Result<Option<StagedFinalityRangeCapabilityV2>> {
        self.verify_identity()?;
        read_staged(&self.connection, self.store_identity, self.file_identity_digest)
    }

    pub(crate) fn stage_finality_intent(
        &mut self,
        intent: FinalityRangeIntentV2,
    ) -> Result<StagedFinalityRangeCapabilityV2> {
        self.verify_identity()?;
        validate_intent_at_cursor(&intent, &self.execution_cursor()?)?;
        let capability =
            StagedFinalityRangeCapabilityV2::issue(self.store_identity, self.file_identity_digest, intent)?;
        let encoded = capability.intent().canonical_bytes()?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(existing) = read_staged(&transaction, self.store_identity, self.file_identity_digest)? {
            if existing != capability {
                return Err(HolderNodeError::FinalityConflict);
            }
            transaction.commit()?;
        } else {
            transaction.execute(
                "INSERT INTO staged_finality_range(singleton, store_identity, file_identity, stage_digest,
                                                    intent_length, intent_json)
                 VALUES(1, ?1, ?2, ?3, ?4, ?5)",
                params![
                    self.store_identity.as_slice(),
                    self.file_identity_digest.as_slice(),
                    capability.stage_digest().as_slice(),
                    i64::try_from(encoded.len()).map_err(|_| HolderNodeError::OutOfRange)?,
                    encoded,
                ],
            )?;
            transaction.commit()?;
        }
        self.verify_identity()?;
        let readback = self.staged_finality()?.ok_or(HolderNodeError::StorageCorrupt)?;
        if readback != capability {
            return Err(HolderNodeError::StorageCorrupt);
        }
        Ok(readback)
    }

    pub(crate) fn complete_staged_finality(
        &mut self,
        staged: &StagedFinalityRangeCapabilityV2,
        finalized: FinalizedRangeCapabilityV2,
        updates: &[FinalizedUpdate],
    ) -> Result<(usize, usize)> {
        self.verify_identity()?;
        if staged.store_identity() != &self.store_identity
            || staged.file_identity() != &self.file_identity_digest
            || finalized.stage_digest() != staged.stage_digest()
        {
            return Err(HolderNodeError::FinalityConflict);
        }
        let finalized_blocks = finalized.into_blocks();
        let last_finality = finalized_blocks
            .last()
            .cloned()
            .ok_or(HolderNodeError::FinalityConflict)?;
        let next_cursor = FinalizedBlockCursor::new(
            self.verifier_profile,
            self.coordinator_id,
            self.chain.clone(),
            staged.intent().next_height(),
            staged.intent().next_expected_previous_app_hash().clone(),
            Some(last_finality),
        )?;
        let expected_cursor = self.execution_cursor()?;
        validate_intent_at_cursor(staged.intent(), &expected_cursor)?;
        let finality_json = serde_json::to_vec(next_cursor.last_finality().ok_or(HolderNodeError::FinalityConflict)?)
            .map_err(|_| HolderNodeError::StorageCorrupt)?;
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let stored_stage = read_staged(&transaction, self.store_identity, self.file_identity_digest)?
            .ok_or(HolderNodeError::FinalityConflict)?;
        if &stored_stage != staged {
            return Err(HolderNodeError::FinalityConflict);
        }
        let current = read_execution_cursor(&transaction, &self.chain, self.verifier_profile, self.coordinator_id)?;
        if current != expected_cursor {
            return Err(HolderNodeError::FinalityConflict);
        }
        let (finalized_count, unrelated) = apply_channel_updates(&transaction, updates)?;
        let changed = transaction.execute(
            "UPDATE finalized_execution_cursor
             SET next_height=?1, expected_previous_app_hash=?2, last_finality_length=?3, last_finality_json=?4
             WHERE singleton=1 AND verifier_profile=?5 AND coordinator_id=?6
               AND next_height=?7 AND expected_previous_app_hash=?8",
            params![
                to_i64(next_cursor.next_height())?,
                next_cursor.expected_previous_app_hash().as_bytes().as_slice(),
                i64::try_from(finality_json.len()).map_err(|_| HolderNodeError::OutOfRange)?,
                finality_json,
                self.verifier_profile.as_bytes().as_slice(),
                self.coordinator_id.as_bytes().as_slice(),
                to_i64(expected_cursor.next_height())?,
                expected_cursor.expected_previous_app_hash().as_bytes().as_slice(),
            ],
        )?;
        if changed != 1 {
            return Err(HolderNodeError::FinalityConflict);
        }
        let deleted = transaction.execute(
            "DELETE FROM staged_finality_range
             WHERE singleton=1 AND store_identity=?1 AND file_identity=?2 AND stage_digest=?3",
            params![
                self.store_identity.as_slice(),
                self.file_identity_digest.as_slice(),
                staged.stage_digest().as_slice(),
            ],
        )?;
        if deleted != 1 {
            return Err(HolderNodeError::FinalityConflict);
        }
        transaction.commit()?;
        self.verify_identity()?;
        if self.execution_cursor()? != next_cursor || self.staged_finality()?.is_some() {
            return Err(HolderNodeError::StorageCorrupt);
        }
        Ok((finalized_count, unrelated))
    }

    pub(crate) fn status(&self, lifecycle: LifecycleState, recovered: bool, generation: u64) -> Result<ServiceStatus> {
        self.verify_identity()?;
        let mut counts = [0_usize; 4];
        let mut statement = self
            .connection
            .prepare("SELECT status, COUNT(*) FROM outbox GROUP BY status")?;
        let rows = statement.query_map([], |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)))?;
        for row in rows {
            let (status, count) = row?;
            let index = usize::try_from(status).map_err(|_| HolderNodeError::StorageCorrupt)?;
            *counts.get_mut(index).ok_or(HolderNodeError::StorageCorrupt)? =
                usize::try_from(count).map_err(|_| HolderNodeError::StorageCorrupt)?;
        }
        let finalized_channels: i64 = self
            .connection
            .query_row("SELECT COUNT(*) FROM finalized_heads", [], |row| row.get(0))?;
        let staged = self.staged_finality()?;
        Ok(ServiceStatus {
            lifecycle,
            recovered_unclean_shutdown: recovered,
            run_generation: generation,
            outbox_queued: counts[0],
            outbox_submitted: counts[1],
            outbox_finalized: counts[2],
            outbox_retry_exhausted: counts[3],
            finalized_channels: usize::try_from(finalized_channels).map_err(|_| HolderNodeError::StorageCorrupt)?,
            finalized_block_cursor: self.execution_cursor()?,
            staged_finality_range: staged.map(|value| *value.stage_digest()),
        })
    }
}

fn validate_intent_at_cursor(intent: &FinalityRangeIntentV2, cursor: &FinalizedBlockCursor) -> Result<()> {
    if intent.verifier_profile() != cursor.verifier_profile()
        || intent.coordinator_id() != cursor.coordinator_id()
        || intent.ledger_chain_id() != cursor.ledger_chain_id()
        || intent.start_height() != cursor.next_height()
        || intent.expected_previous_app_hash() != cursor.expected_previous_app_hash()
    {
        return Err(HolderNodeError::FinalityConflict);
    }
    Ok(())
}

fn apply_channel_updates(transaction: &Transaction<'_>, updates: &[FinalizedUpdate]) -> Result<(usize, usize)> {
    let mut channel_heads = BTreeMap::<ChannelContextIdV2, Option<(u64, EntryHashV2)>>::new();
    let mut finalized = 0_usize;
    let mut unrelated = 0_usize;
    for update in updates {
        let channel = update.cursor.channel_context_id.clone();
        if !channel_heads.contains_key(&channel) {
            let stored = transaction
                .query_row(
                    "SELECT sequence, entry_hash FROM finalized_heads WHERE channel_context_id=?1",
                    [channel.as_bytes().as_slice()],
                    |row| Ok((row.get::<_, i64>(0)?, row.get::<_, Vec<u8>>(1)?)),
                )
                .optional()?
                .map(|(sequence, hash)| -> Result<(u64, EntryHashV2)> {
                    Ok((
                        u64::try_from(sequence).map_err(|_| HolderNodeError::StorageCorrupt)?,
                        EntryHashV2::from_bytes(hash).map_err(|_| HolderNodeError::StorageCorrupt)?,
                    ))
                })
                .transpose()?;
            channel_heads.insert(channel.clone(), stored);
        }
        let existing_entry = transaction
            .query_row(
                "SELECT entry_hash FROM finalized_channel_entries
                 WHERE channel_context_id=?1 AND sequence=?2",
                params![channel.as_bytes().as_slice(), to_i64(update.cursor.sequence)?],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()?;
        let replay = if let Some(stored_hash) = existing_entry {
            if stored_hash.as_slice() != update.cursor.entry_hash.as_bytes() {
                return Err(HolderNodeError::FinalityConflict);
            }
            true
        } else {
            let prior = channel_heads.get(&channel).ok_or(HolderNodeError::StorageCorrupt)?;
            let (expected_sequence, expected_hash) = match prior {
                None => (0, EntryHashV2::zero()),
                Some((sequence, hash)) => (
                    sequence.checked_add(1).ok_or(HolderNodeError::FinalityConflict)?,
                    hash.clone(),
                ),
            };
            if update.cursor.sequence != expected_sequence || update.previous_entry_hash != expected_hash {
                return Err(HolderNodeError::FinalityConflict);
            }
            false
        };
        if let Some((stored, status)) = transaction
            .query_row(
                "SELECT proposal_digest, status FROM outbox WHERE request_digest=?1",
                [update.request_digest.as_bytes().as_slice()],
                |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, i64>(1)?)),
            )
            .optional()?
        {
            if stored.as_slice() != update.proposal_digest {
                return Err(HolderNodeError::FinalityConflict);
            }
            if OutboxStatus::from_code(status)? != OutboxStatus::Finalized {
                transaction.execute(
                    "UPDATE outbox SET status=?1, finalized_sequence=?2, finality_digest=?3
                     WHERE request_digest=?4",
                    params![
                        OutboxStatus::Finalized.code(),
                        to_i64(update.cursor.sequence)?,
                        update.finality_digest.as_slice(),
                        update.request_digest.as_bytes().as_slice(),
                    ],
                )?;
                finalized = finalized.saturating_add(1);
            }
        } else {
            unrelated = unrelated.saturating_add(1);
        }
        if !replay {
            transaction.execute(
                "INSERT INTO finalized_channel_entries(channel_context_id, sequence, entry_hash) VALUES(?1,?2,?3)",
                params![
                    channel.as_bytes().as_slice(),
                    to_i64(update.cursor.sequence)?,
                    update.cursor.entry_hash.as_bytes().as_slice()
                ],
            )?;
            transaction.execute(
                "INSERT INTO finalized_heads(channel_context_id, sequence, entry_hash) VALUES(?1,?2,?3)
                 ON CONFLICT(channel_context_id) DO UPDATE
                 SET sequence=excluded.sequence, entry_hash=excluded.entry_hash",
                params![
                    channel.as_bytes().as_slice(),
                    to_i64(update.cursor.sequence)?,
                    update.cursor.entry_hash.as_bytes().as_slice()
                ],
            )?;
            channel_heads.insert(
                channel,
                Some((update.cursor.sequence, update.cursor.entry_hash.clone())),
            );
        }
    }
    Ok((finalized, unrelated))
}

fn initialize_schema(
    connection: &mut Connection,
    config: &HolderNodeConfig,
    service_domain: &[u8; 32],
    legacy_service_domain: &[u8; 32],
    file_identity: &[u8; 32],
) -> Result<[u8; 32]> {
    let application_id: i64 = connection.pragma_query_value(None, "application_id", |row| row.get(0))?;
    let user_version: i64 = connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
    if (application_id != 0 && application_id != APPLICATION_ID)
        || !(0..=SCHEMA_VERSION).contains(&user_version)
        || (user_version > 0 && application_id != APPLICATION_ID)
    {
        return Err(HolderNodeError::StorageCorrupt);
    }
    let has_schema: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%')",
        [],
        |row| row.get(0),
    )?;
    let has_meta: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type='table' AND name='service_meta')",
        [],
        |row| row.get(0),
    )?;
    if has_schema && !has_meta {
        return Err(HolderNodeError::StorageCorrupt);
    }
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    if has_meta {
        let legacy_version: i64 =
            transaction.query_row("SELECT schema_version FROM service_meta WHERE singleton=1", [], |row| {
                row.get(0)
            })?;
        if matches!(legacy_version, 1 | 2) {
            let finalized_count: i64 =
                transaction.query_row("SELECT COUNT(*) FROM finalized_heads", [], |row| row.get(0))?;
            let finalized_outbox: i64 =
                transaction.query_row("SELECT COUNT(*) FROM outbox WHERE status=2", [], |row| row.get(0))?;
            let has_channel_entries: bool = transaction.query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type='table' AND name='finalized_channel_entries')",
                [],
                |row| row.get(0),
            )?;
            let channel_entries = if has_channel_entries {
                transaction.query_row("SELECT COUNT(*) FROM finalized_channel_entries", [], |row| row.get(0))?
            } else {
                0_i64
            };
            let has_stage_table: bool = transaction.query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type='table' AND name='staged_finality_range')",
                [],
                |row| row.get(0),
            )?;
            let staged_ranges = if has_stage_table {
                transaction.query_row("SELECT COUNT(*) FROM staged_finality_range", [], |row| row.get(0))?
            } else {
                0_i64
            };
            if finalized_count != 0 || finalized_outbox != 0 || channel_entries != 0 || staged_ranges != 0 {
                return Err(HolderNodeError::StorageCorrupt);
            }
            if legacy_version == 2 {
                let (next_height, previous): (i64, Vec<u8>) = transaction.query_row(
                    "SELECT next_height,expected_previous_app_hash
                     FROM finalized_execution_cursor WHERE singleton=1",
                    [],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )?;
                if next_height != 1 || fixed32(previous)? != [0; 32] {
                    return Err(HolderNodeError::StorageCorrupt);
                }
                let mut cursor_columns = transaction.prepare("PRAGMA table_info(finalized_execution_cursor)")?;
                let names = cursor_columns.query_map([], |row| row.get::<_, String>(1))?;
                let mut has_last_finality = false;
                for name in names {
                    if name? == "last_finality_json" {
                        has_last_finality = true;
                    }
                }
                drop(cursor_columns);
                if has_last_finality {
                    let retained_capability: i64 = transaction.query_row(
                        "SELECT COUNT(*) FROM finalized_execution_cursor
                         WHERE last_finality_json IS NOT NULL OR last_finality_length IS NOT NULL",
                        [],
                        |row| row.get(0),
                    )?;
                    if retained_capability != 0 {
                        return Err(HolderNodeError::StorageCorrupt);
                    }
                }
            }
            transaction.execute_batch("DROP TABLE IF EXISTS finalized_execution_cursor;")?;
        }
    }
    create_tables(&transaction)?;
    ensure_identity_columns(&transaction)?;
    let existing: Option<ServiceIdentityRow> = transaction
        .query_row(
            "SELECT schema_version, ledger_chain_id, service_domain, finality_verifier_profile,
                        finality_coordinator_id, store_identity, file_identity
                 FROM service_meta WHERE singleton=1",
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
    let store_identity = match existing {
        None => {
            let random = sqlite_random_identity(&transaction)?;
            transaction.execute(
                "INSERT INTO service_meta(singleton,schema_version,ledger_chain_id,service_domain,
                                          finality_verifier_profile,finality_coordinator_id,store_identity,
                                          file_identity,active,lifecycle,run_generation)
                 VALUES(1,?1,?2,?3,?4,?5,?6,?7,0,?8,0)",
                params![
                    SCHEMA_VERSION,
                    config.ledger_chain_id().as_str(),
                    service_domain.as_slice(),
                    config.finality_verifier_profile().as_bytes().as_slice(),
                    config.finality_coordinator_id().as_bytes().as_slice(),
                    random.as_slice(),
                    file_identity.as_slice(),
                    lifecycle_code(LifecycleState::Created),
                ],
            )?;
            insert_genesis_cursor(&transaction, config)?;
            random
        }
        Some((version, chain, domain, profile, coordinator, store, persisted_file)) if version == SCHEMA_VERSION => {
            let profile = fixed32(profile.ok_or(HolderNodeError::StorageCorrupt)?)?;
            let coordinator = fixed32(coordinator.ok_or(HolderNodeError::StorageCorrupt)?)?;
            let store = fixed32(store.ok_or(HolderNodeError::StorageCorrupt)?)?;
            let persisted_file = fixed32(persisted_file.ok_or(HolderNodeError::StorageCorrupt)?)?;
            if chain != config.ledger_chain_id().as_str()
                || domain.as_slice() != service_domain
                || profile != *config.finality_verifier_profile().as_bytes()
                || coordinator != *config.finality_coordinator_id().as_bytes()
                || store == [0; 32]
                || persisted_file != *file_identity
            {
                return Err(HolderNodeError::StorageCorrupt);
            }
            store
        }
        Some((1 | 2, chain, domain, _, _, _, _)) => {
            let finalized_count: i64 =
                transaction.query_row("SELECT COUNT(*) FROM finalized_heads", [], |row| row.get(0))?;
            if chain != config.ledger_chain_id().as_str()
                || (domain.as_slice() != service_domain && domain.as_slice() != legacy_service_domain)
                || finalized_count != 0
            {
                return Err(HolderNodeError::StorageCorrupt);
            }
            let random = sqlite_random_identity(&transaction)?;
            transaction.execute(
                "UPDATE service_meta SET schema_version=?1, service_domain=?2, finality_verifier_profile=?3,
                         finality_coordinator_id=?4, store_identity=?5, file_identity=?6 WHERE singleton=1",
                params![
                    SCHEMA_VERSION,
                    service_domain.as_slice(),
                    config.finality_verifier_profile().as_bytes().as_slice(),
                    config.finality_coordinator_id().as_bytes().as_slice(),
                    random.as_slice(),
                    file_identity.as_slice(),
                ],
            )?;
            transaction.execute("DELETE FROM finalized_execution_cursor", [])?;
            transaction.execute("DELETE FROM staged_finality_range", [])?;
            insert_genesis_cursor(&transaction, config)?;
            random
        }
        Some(_) => return Err(HolderNodeError::StorageCorrupt),
    };
    transaction.pragma_update(None, "application_id", APPLICATION_ID)?;
    transaction.pragma_update(None, "user_version", SCHEMA_VERSION)?;
    transaction.commit()?;
    validate_existing_identity_values(
        connection,
        config.ledger_chain_id(),
        config.finality_verifier_profile(),
        config.finality_coordinator_id(),
        &store_identity,
        file_identity,
        service_domain,
    )?;
    Ok(store_identity)
}

fn create_tables(connection: &Connection) -> Result<()> {
    connection.execute_batch(
        "CREATE TABLE IF NOT EXISTS service_meta(
             singleton INTEGER PRIMARY KEY CHECK(singleton=1),
             schema_version INTEGER NOT NULL,
             ledger_chain_id TEXT NOT NULL,
             service_domain BLOB NOT NULL CHECK(length(service_domain)=32),
             finality_verifier_profile BLOB CHECK(finality_verifier_profile IS NULL OR length(finality_verifier_profile)=32),
             finality_coordinator_id BLOB CHECK(finality_coordinator_id IS NULL OR length(finality_coordinator_id)=32),
             store_identity BLOB CHECK(store_identity IS NULL OR length(store_identity)=32),
             file_identity BLOB CHECK(file_identity IS NULL OR length(file_identity)=32),
             active INTEGER NOT NULL CHECK(active IN(0,1)),
             lifecycle INTEGER NOT NULL,
             run_generation INTEGER NOT NULL
         );
         CREATE TABLE IF NOT EXISTS outbox(
             request_digest BLOB PRIMARY KEY CHECK(length(request_digest)=32),
             channel_context_id BLOB NOT NULL CHECK(length(channel_context_id)=32),
             sequence INTEGER NOT NULL CHECK(sequence>=0), proposal_bytes BLOB NOT NULL,
             proposal_digest BLOB NOT NULL CHECK(length(proposal_digest)=32),
             status INTEGER NOT NULL CHECK(status BETWEEN 0 AND 3), attempts INTEGER NOT NULL CHECK(attempts>=0),
             next_attempt_ms INTEGER NOT NULL CHECK(next_attempt_ms>=0), created_at_ms INTEGER NOT NULL CHECK(created_at_ms>0),
             updated_at_ms INTEGER NOT NULL CHECK(updated_at_ms>0), finalized_sequence INTEGER, finality_digest BLOB,
             CHECK(length(proposal_bytes)>0), CHECK(finality_digest IS NULL OR length(finality_digest)=32)
         );
         CREATE INDEX IF NOT EXISTS outbox_due_idx ON outbox(status,next_attempt_ms,channel_context_id,sequence);
         CREATE TABLE IF NOT EXISTS command_dedup(
             command_id BLOB PRIMARY KEY CHECK(length(command_id)=32),
             request_digest BLOB NOT NULL REFERENCES outbox(request_digest) ON DELETE CASCADE,
             proposal_digest BLOB NOT NULL CHECK(length(proposal_digest)=32)
         );
         CREATE TABLE IF NOT EXISTS finalized_heads(
             channel_context_id BLOB PRIMARY KEY CHECK(length(channel_context_id)=32),
             sequence INTEGER NOT NULL CHECK(sequence>=0), entry_hash BLOB NOT NULL CHECK(length(entry_hash)=32)
         );
         CREATE TABLE IF NOT EXISTS finalized_channel_entries(
             channel_context_id BLOB NOT NULL CHECK(length(channel_context_id)=32),
             sequence INTEGER NOT NULL CHECK(sequence>=0), entry_hash BLOB NOT NULL CHECK(length(entry_hash)=32),
             PRIMARY KEY(channel_context_id,sequence)
         );
         CREATE TABLE IF NOT EXISTS finalized_execution_cursor(
             singleton INTEGER PRIMARY KEY CHECK(singleton=1),
             verifier_profile BLOB NOT NULL CHECK(length(verifier_profile)=32),
             coordinator_id BLOB NOT NULL CHECK(length(coordinator_id)=32),
             next_height INTEGER NOT NULL CHECK(next_height>0),
             expected_previous_app_hash BLOB NOT NULL CHECK(length(expected_previous_app_hash)=32),
             last_finality_length INTEGER,
             last_finality_json BLOB,
             CHECK((last_finality_length IS NULL AND last_finality_json IS NULL) OR
                   (last_finality_length BETWEEN 1 AND 524288 AND last_finality_length=length(last_finality_json)))
         );
         CREATE TABLE IF NOT EXISTS staged_finality_range(
             singleton INTEGER PRIMARY KEY CHECK(singleton=1), store_identity BLOB NOT NULL CHECK(length(store_identity)=32),
             file_identity BLOB NOT NULL CHECK(length(file_identity)=32), stage_digest BLOB NOT NULL CHECK(length(stage_digest)=32),
             intent_length INTEGER NOT NULL CHECK(intent_length>0), intent_json BLOB NOT NULL,
             CHECK(intent_length=length(intent_json))
         );",
    )?;
    Ok(())
}

fn ensure_identity_columns(connection: &Connection) -> Result<()> {
    let mut statement = connection.prepare("PRAGMA table_info(service_meta)")?;
    let rows = statement.query_map([], |row| row.get::<_, String>(1))?;
    let mut columns = BTreeSet::new();
    for row in rows {
        columns.insert(row?);
    }
    for (name, declaration) in [
        ("finality_verifier_profile", "BLOB"),
        ("finality_coordinator_id", "BLOB"),
        ("store_identity", "BLOB"),
        ("file_identity", "BLOB"),
    ] {
        if !columns.contains(name) {
            connection.execute_batch(&format!("ALTER TABLE service_meta ADD COLUMN {name} {declaration};"))?;
        }
    }
    Ok(())
}

fn insert_genesis_cursor(connection: &Connection, config: &HolderNodeConfig) -> Result<()> {
    let genesis = crate::FinalizedBlockCursor::genesis(
        config.finality_verifier_profile(),
        config.finality_coordinator_id(),
        config.ledger_chain_id().clone(),
    )?;
    connection.execute(
        "INSERT INTO finalized_execution_cursor(singleton,verifier_profile,coordinator_id,next_height,expected_previous_app_hash,
                                                 last_finality_length,last_finality_json)
         VALUES(1,?1,?2,?3,?4,NULL,NULL)",
        params![
            genesis.verifier_profile().as_bytes().as_slice(),
            genesis.coordinator_id().as_bytes().as_slice(),
            to_i64(genesis.next_height())?,
            genesis.expected_previous_app_hash().as_bytes().as_slice()
        ],
    )?;
    Ok(())
}

fn sqlite_random_identity(connection: &Connection) -> Result<[u8; 32]> {
    for _ in 0..4 {
        let value: Vec<u8> = connection.query_row("SELECT randomblob(32)", [], |row| row.get(0))?;
        let fixed = fixed32(value)?;
        if fixed != [0; 32] {
            return Ok(fixed);
        }
    }
    Err(HolderNodeError::StorageUnavailable)
}

fn read_execution_cursor(
    connection: &Connection,
    chain: &thunderbolt_ledger::LedgerChainIdV2,
    profile: FinalityVerifierProfileId,
    coordinator: FinalityCoordinatorId,
) -> Result<FinalizedBlockCursor> {
    let (stored_profile, stored_coordinator, next_height, previous, finality_length, actual_length): CursorStorageRow =
        connection.query_row(
            "SELECT verifier_profile,coordinator_id,next_height,expected_previous_app_hash,
                    last_finality_length,length(last_finality_json)
             FROM finalized_execution_cursor WHERE singleton=1",
            [],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                ))
            },
        )?;
    if fixed32(stored_profile)? != *profile.as_bytes() || fixed32(stored_coordinator)? != *coordinator.as_bytes() {
        return Err(HolderNodeError::StorageCorrupt);
    }
    let last_finality = match (finality_length, actual_length) {
        (None, None) => None,
        (Some(length), Some(actual)) => {
            let length = usize::try_from(length).map_err(|_| HolderNodeError::StorageCorrupt)?;
            if length == 0
                || length > MAX_DURABLE_FINALITY_JSON_BYTES
                || i64::try_from(length).map_err(|_| HolderNodeError::StorageCorrupt)? != actual
            {
                return Err(HolderNodeError::StorageCorrupt);
            }
            let json: Vec<u8> = connection.query_row(
                "SELECT last_finality_json FROM finalized_execution_cursor WHERE singleton=1",
                [],
                |row| row.get(0),
            )?;
            if json.len() != length {
                return Err(HolderNodeError::StorageCorrupt);
            }
            let capability: crate::DurableBlockFinalityCapabilityV2 =
                serde_json::from_slice(&json).map_err(|_| HolderNodeError::StorageCorrupt)?;
            if serde_json::to_vec(&capability).map_err(|_| HolderNodeError::StorageCorrupt)? != json {
                return Err(HolderNodeError::StorageCorrupt);
            }
            Some(capability)
        }
        _ => return Err(HolderNodeError::StorageCorrupt),
    };
    FinalizedBlockCursor::new(
        profile,
        coordinator,
        chain.clone(),
        u64::try_from(next_height).map_err(|_| HolderNodeError::StorageCorrupt)?,
        AppHashV2::from_bytes(previous).map_err(|_| HolderNodeError::StorageCorrupt)?,
        last_finality,
    )
    .map_err(|_| HolderNodeError::StorageCorrupt)
}

fn read_staged(
    connection: &Connection,
    store_identity: [u8; 32],
    file_identity: [u8; 32],
) -> Result<Option<StagedFinalityRangeCapabilityV2>> {
    let row: Option<StageStorageRow> = connection
        .query_row(
            "SELECT store_identity,file_identity,stage_digest,intent_length,length(intent_json)
             FROM staged_finality_range WHERE singleton=1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)),
        )
        .optional()?;
    let Some((stored_store, stored_file, stored_digest, length, actual_length)) = row else {
        return Ok(None);
    };
    let length = usize::try_from(length).map_err(|_| HolderNodeError::StorageCorrupt)?;
    if fixed32(stored_store)? != store_identity
        || fixed32(stored_file)? != file_identity
        || length == 0
        || length > crate::MAX_FINALITY_SEGMENT_BYTES
        || i64::try_from(length).map_err(|_| HolderNodeError::StorageCorrupt)? != actual_length
    {
        return Err(HolderNodeError::StorageCorrupt);
    }
    let json: Vec<u8> = connection.query_row(
        "SELECT intent_json FROM staged_finality_range WHERE singleton=1",
        [],
        |row| row.get(0),
    )?;
    if json.len() != length {
        return Err(HolderNodeError::StorageCorrupt);
    }
    let intent: FinalityRangeIntentV2 = serde_json::from_slice(&json).map_err(|_| HolderNodeError::StorageCorrupt)?;
    if intent.canonical_bytes()? != json {
        return Err(HolderNodeError::StorageCorrupt);
    }
    let capability = StagedFinalityRangeCapabilityV2::issue(store_identity, file_identity, intent)?;
    if capability.stage_digest().as_slice() != fixed32(stored_digest)?.as_slice() {
        return Err(HolderNodeError::StorageCorrupt);
    }
    Ok(Some(capability))
}

fn validate_existing_identity(
    connection: &Connection,
    config: &HolderNodeConfig,
    service_domain: &[u8; 32],
    file_identity: &[u8; 32],
) -> Result<()> {
    let (version, chain, domain, profile, coordinator, store, persisted_file): ExistingIdentityRow = connection
        .query_row(
            "SELECT schema_version,ledger_chain_id,service_domain,finality_verifier_profile,
                    finality_coordinator_id,store_identity,file_identity FROM service_meta WHERE singleton=1",
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
        )?;
    let store = fixed32(store)?;
    if version != SCHEMA_VERSION
        || chain != config.ledger_chain_id().as_str()
        || domain.as_slice() != service_domain
        || fixed32(profile)? != *config.finality_verifier_profile().as_bytes()
        || fixed32(coordinator)? != *config.finality_coordinator_id().as_bytes()
        || store == [0; 32]
        || fixed32(persisted_file)? != *file_identity
    {
        return Err(HolderNodeError::StorageCorrupt);
    }
    Ok(())
}

fn load_store_identity(connection: &Connection) -> Result<[u8; 32]> {
    fixed32(
        connection.query_row("SELECT store_identity FROM service_meta WHERE singleton=1", [], |row| {
            row.get(0)
        })?,
    )
}

fn validate_existing_identity_values(
    connection: &Connection,
    chain: &thunderbolt_ledger::LedgerChainIdV2,
    profile: FinalityVerifierProfileId,
    coordinator: FinalityCoordinatorId,
    store_identity: &[u8; 32],
    file_identity: &[u8; 32],
    service_domain: &[u8; 32],
) -> Result<()> {
    let (version, stored_chain, stored_domain, stored_profile, stored_coordinator, stored_store, stored_file): ExistingIdentityRow = connection.query_row(
        "SELECT schema_version,ledger_chain_id,service_domain,finality_verifier_profile,
                finality_coordinator_id,store_identity,file_identity
             FROM service_meta WHERE singleton=1",
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
    )?;
    if version != SCHEMA_VERSION
        || stored_chain != chain.as_str()
        || stored_domain.as_slice() != service_domain
        || fixed32(stored_profile)? != *profile.as_bytes()
        || fixed32(stored_coordinator)? != *coordinator.as_bytes()
        || fixed32(stored_store)? != *store_identity
        || fixed32(stored_file)? != *file_identity
        || *store_identity == [0; 32]
    {
        return Err(HolderNodeError::StorageCorrupt);
    }
    Ok(())
}

#[cfg(unix)]
fn prepare_durable_path(path: &Path, create: bool) -> Result<(PathBuf, DurableFileIdentity, File)> {
    use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};

    let invalid = || HolderNodeError::InvalidConfiguration("database path is not a durable owner-only file");
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
        Err(error) if error.kind() == std::io::ErrorKind::NotFound && create => {
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
        .write(create)
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

#[cfg(unix)]
fn open_role_lock(database_path: &Path) -> Result<File> {
    use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};

    let invalid = || HolderNodeError::InvalidConfiguration("role lock is not a durable owner-only file");
    let lock_path = database_path.with_extension("holder-node.lock");
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(&lock_path)
        .map_err(|_| invalid())?;
    let metadata = lock.metadata().map_err(|_| invalid())?;
    let path_metadata = std::fs::symlink_metadata(&lock_path).map_err(|_| invalid())?;
    if path_metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.dev() != path_metadata.dev()
        || metadata.ino() != path_metadata.ino()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.nlink() != 1
        || metadata.permissions().mode() & 0o600 != 0o600
        || metadata.permissions().mode() & 0o177 != 0
    {
        return Err(invalid());
    }
    lock.try_lock().map_err(|_| HolderNodeError::StorageUnavailable)?;
    Ok(lock)
}

#[cfg(not(unix))]
fn open_role_lock(_database_path: &Path) -> Result<File> {
    Err(HolderNodeError::InvalidConfiguration(
        "durable role locks require Unix owner and inode semantics",
    ))
}

#[cfg(not(unix))]
fn prepare_durable_path(_path: &Path, _create: bool) -> Result<(PathBuf, DurableFileIdentity, File)> {
    Err(HolderNodeError::InvalidConfiguration(
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
                        return Err(HolderNodeError::InvalidConfiguration(
                            "database path contains a symlink",
                        ));
                    }
                    Ok(_) => {}
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => break,
                    Err(_) => {
                        return Err(HolderNodeError::InvalidConfiguration("database path cannot be audited"));
                    }
                }
            }
            Component::CurDir | Component::ParentDir | Component::Prefix(_) => {
                return Err(HolderNodeError::InvalidConfiguration("database path is not normalized"));
            }
        }
    }
    Ok(())
}

#[cfg(unix)]
fn validate_safe_ancestors(path: &Path, effective_uid: u32) -> Result<()> {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    let canonical = std::fs::canonicalize(path)
        .map_err(|_| HolderNodeError::InvalidConfiguration("database ancestry cannot be canonicalized"))?;
    for ancestor in canonical.ancestors() {
        let metadata = std::fs::symlink_metadata(ancestor)
            .map_err(|_| HolderNodeError::InvalidConfiguration("database ancestry cannot be audited"))?;
        let mode = metadata.permissions().mode();
        if metadata.file_type().is_symlink()
            || !metadata.is_dir()
            || (metadata.uid() != 0 && metadata.uid() != effective_uid)
            || (mode & 0o022 != 0 && mode & 0o1000 == 0)
        {
            return Err(HolderNodeError::InvalidConfiguration(
                "database ancestry is not owner controlled",
            ));
        }
    }
    Ok(())
}

#[cfg(unix)]
fn verify_durable_file(path: &Path, expected: DurableFileIdentity) -> Result<()> {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    let metadata = std::fs::symlink_metadata(path)
        .map_err(|_| HolderNodeError::InvalidConfiguration("database path changed after open"))?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.dev() != expected.device
        || metadata.ino() != expected.inode
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.nlink() != 1
        || metadata.permissions().mode() & 0o600 != 0o600
        || metadata.permissions().mode() & 0o177 != 0
    {
        return Err(HolderNodeError::InvalidConfiguration(
            "database identity changed after open",
        ));
    }
    Ok(())
}

#[cfg(not(unix))]
fn verify_durable_file(_path: &Path, _expected: DurableFileIdentity) -> Result<()> {
    Err(HolderNodeError::InvalidConfiguration(
        "durable database paths require Unix owner and inode semantics",
    ))
}

fn configure_connection(connection: &Connection, config: &HolderNodeConfig) -> Result<()> {
    connection.busy_timeout(config.busy_timeout())?;
    connection.pragma_update(None, "foreign_keys", "ON")?;
    connection.pragma_update(None, "journal_mode", "WAL")?;
    connection.pragma_update(None, "synchronous", "FULL")?;
    let foreign_keys: i64 = connection.pragma_query_value(None, "foreign_keys", |row| row.get(0))?;
    let journal_mode: String = connection.pragma_query_value(None, "journal_mode", |row| row.get(0))?;
    let synchronous: i64 = connection.pragma_query_value(None, "synchronous", |row| row.get(0))?;
    if foreign_keys != 1 || !journal_mode.eq_ignore_ascii_case("wal") || synchronous != 2 {
        return Err(HolderNodeError::StorageUnavailable);
    }
    Ok(())
}

fn lifecycle_code(lifecycle: LifecycleState) -> i64 {
    match lifecycle {
        LifecycleState::Created => 0,
        LifecycleState::Running => 1,
        LifecycleState::Draining => 2,
        LifecycleState::Stopped => 3,
        LifecycleState::Faulted => 4,
    }
}

fn lifecycle_from_code(code: i64) -> Result<LifecycleState> {
    match code {
        0 => Ok(LifecycleState::Created),
        1 => Ok(LifecycleState::Running),
        2 => Ok(LifecycleState::Draining),
        3 => Ok(LifecycleState::Stopped),
        4 => Ok(LifecycleState::Faulted),
        _ => Err(HolderNodeError::StorageCorrupt),
    }
}

fn fixed32(bytes: Vec<u8>) -> Result<[u8; 32]> {
    bytes.try_into().map_err(|_| HolderNodeError::StorageCorrupt)
}

fn to_i64(value: u64) -> Result<i64> {
    i64::try_from(value).map_err(|_| HolderNodeError::OutOfRange)
}
