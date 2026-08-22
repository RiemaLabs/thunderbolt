use std::path::Path;
use std::{fs::File, fs::OpenOptions};

#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use thunderbolt_ledger::{ChannelContextIdV2, EntryHashV2, RequestDigestV2};

use crate::config::{HolderNodeConfig, RetryPolicy, MAX_COMMAND_ROWS, MAX_OUTBOX_ROWS, MAX_PROPOSAL_BYTES};
use crate::types::{CommandId, FinalizedCursor, LifecycleState, OutboxRecord, OutboxStatus, QueueDisposition};
use crate::{HolderNodeError, Result, ServiceStatus};

const SCHEMA_VERSION: i64 = 1;

pub(crate) struct FinalizedUpdate {
    pub cursor: FinalizedCursor,
    pub request_digest: RequestDigestV2,
    pub proposal_digest: [u8; 32],
    pub finality_digest: [u8; 32],
}

pub(crate) struct RuntimeStore {
    connection: Connection,
    _lock: File,
}

impl RuntimeStore {
    pub(crate) fn open(path: &Path, config: &HolderNodeConfig, service_domain: &[u8; 32]) -> Result<Self> {
        if path.as_os_str().is_empty() || path.parent().is_none() {
            return Err(HolderNodeError::InvalidConfiguration("invalid SQLite path"));
        }
        let lock_path = path.with_extension("holder-node.lock");
        if std::fs::symlink_metadata(path).is_ok_and(|metadata| metadata.file_type().is_symlink())
            || std::fs::symlink_metadata(&lock_path).is_ok_and(|metadata| metadata.file_type().is_symlink())
        {
            return Err(HolderNodeError::StorageUnavailable);
        }
        let mut lock_options = OpenOptions::new();
        lock_options.read(true).write(true).create(true);
        #[cfg(unix)]
        lock_options.mode(0o600);
        let lock = lock_options
            .open(&lock_path)
            .map_err(|_| HolderNodeError::StorageUnavailable)?;
        lock.try_lock().map_err(|_| HolderNodeError::StorageUnavailable)?;
        #[cfg(unix)]
        lock.set_permissions(std::fs::Permissions::from_mode(0o600))
            .map_err(|_| HolderNodeError::StorageUnavailable)?;
        let connection = Connection::open(path)?;
        #[cfg(unix)]
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .map_err(|_| HolderNodeError::StorageUnavailable)?;
        connection.busy_timeout(config.busy_timeout())?;
        connection.pragma_update(None, "journal_mode", "WAL")?;
        connection.pragma_update(None, "synchronous", "FULL")?;
        connection.pragma_update(None, "foreign_keys", "ON")?;
        connection.execute_batch(
            "CREATE TABLE IF NOT EXISTS service_meta (
                 singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                 schema_version INTEGER NOT NULL,
                 ledger_chain_id TEXT NOT NULL,
                 service_domain BLOB NOT NULL CHECK (length(service_domain) = 32),
                 active INTEGER NOT NULL CHECK (active IN (0,1)),
                 lifecycle INTEGER NOT NULL,
                 run_generation INTEGER NOT NULL
             );
             CREATE TABLE IF NOT EXISTS outbox (
                 request_digest BLOB PRIMARY KEY CHECK (length(request_digest) = 32),
                 channel_context_id BLOB NOT NULL CHECK (length(channel_context_id) = 32),
                 sequence INTEGER NOT NULL CHECK (sequence >= 0),
                 proposal_bytes BLOB NOT NULL,
                 proposal_digest BLOB NOT NULL CHECK (length(proposal_digest) = 32),
                 status INTEGER NOT NULL CHECK (status BETWEEN 0 AND 3),
                 attempts INTEGER NOT NULL CHECK (attempts >= 0),
                 next_attempt_ms INTEGER NOT NULL CHECK (next_attempt_ms >= 0),
                 created_at_ms INTEGER NOT NULL CHECK (created_at_ms > 0),
                 updated_at_ms INTEGER NOT NULL CHECK (updated_at_ms > 0),
                 finalized_sequence INTEGER,
                 finality_digest BLOB,
                 CHECK (length(proposal_bytes) > 0),
                 CHECK (finality_digest IS NULL OR length(finality_digest) = 32)
             );
             CREATE INDEX IF NOT EXISTS outbox_due_idx
                 ON outbox(status, next_attempt_ms, channel_context_id, sequence);
             CREATE TABLE IF NOT EXISTS command_dedup (
                 command_id BLOB PRIMARY KEY CHECK (length(command_id) = 32),
                 request_digest BLOB NOT NULL REFERENCES outbox(request_digest) ON DELETE CASCADE,
                 proposal_digest BLOB NOT NULL CHECK (length(proposal_digest) = 32)
             );
             CREATE TABLE IF NOT EXISTS finalized_heads (
                 channel_context_id BLOB PRIMARY KEY CHECK (length(channel_context_id) = 32),
                 sequence INTEGER NOT NULL CHECK (sequence >= 0),
                 entry_hash BLOB NOT NULL CHECK (length(entry_hash) = 32)
             );",
        )?;
        let existing: Option<(i64, String, Vec<u8>)> = connection
            .query_row(
                "SELECT schema_version, ledger_chain_id, service_domain FROM service_meta WHERE singleton = 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?;
        match existing {
            None => {
                connection.execute(
                    "INSERT INTO service_meta(singleton, schema_version, ledger_chain_id, service_domain,
                                              active, lifecycle, run_generation)
                     VALUES(1, ?1, ?2, ?3, 0, ?4, 0)",
                    params![
                        SCHEMA_VERSION,
                        config.ledger_chain_id().as_str(),
                        service_domain.as_slice(),
                        lifecycle_code(LifecycleState::Created)
                    ],
                )?;
            }
            Some((version, chain, stored_domain))
                if version == SCHEMA_VERSION
                    && chain == config.ledger_chain_id().as_str()
                    && stored_domain.as_slice() == service_domain => {}
            Some(_) => return Err(HolderNodeError::StorageCorrupt),
        }
        Ok(Self {
            connection,
            _lock: lock,
        })
    }

    pub(crate) fn begin_run(&mut self) -> Result<(u64, bool)> {
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
        Ok((
            u64::try_from(next).map_err(|_| HolderNodeError::StorageCorrupt)?,
            active == 1,
        ))
    }

    pub(crate) fn stored_lifecycle(&self) -> Result<LifecycleState> {
        let code: i64 =
            self.connection
                .query_row("SELECT lifecycle FROM service_meta WHERE singleton = 1", [], |row| {
                    row.get(0)
                })?;
        lifecycle_from_code(code)
    }

    pub(crate) fn set_lifecycle(&mut self, lifecycle: LifecycleState, active: bool) -> Result<()> {
        self.connection.execute(
            "UPDATE service_meta SET lifecycle = ?1, active = ?2 WHERE singleton = 1",
            params![lifecycle_code(lifecycle), i64::from(active)],
        )?;
        Ok(())
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
        Ok(QueueDisposition::Queued)
    }

    pub(crate) fn due(&self, now_ms: u64, limit: usize) -> Result<Vec<OutboxRecord>> {
        let now = to_i64(now_ms)?;
        let limit = i64::try_from(limit).map_err(|_| HolderNodeError::OutOfRange)?;
        let mut statement = self.connection.prepare(
            "SELECT request_digest, proposal_bytes
             FROM outbox
             WHERE status IN (0,1) AND next_attempt_ms <= ?1
             ORDER BY next_attempt_ms, channel_context_id, sequence
             LIMIT ?2",
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
        Ok(next_status)
    }

    pub(crate) fn retry(&mut self, command_id: CommandId, now_ms: u64) -> Result<()> {
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
        Ok(())
    }

    pub(crate) fn channels(&self) -> Result<Vec<ChannelContextIdV2>> {
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

    pub(crate) fn cursor(&self, channel: &ChannelContextIdV2) -> Result<Option<FinalizedCursor>> {
        self.connection
            .query_row(
                "SELECT sequence, entry_hash FROM finalized_heads WHERE channel_context_id = ?1",
                [channel.as_bytes().as_slice()],
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, Vec<u8>>(1)?)),
            )
            .optional()?
            .map(|(sequence, entry_hash)| {
                Ok(FinalizedCursor::new(
                    channel.clone(),
                    u64::try_from(sequence).map_err(|_| HolderNodeError::StorageCorrupt)?,
                    EntryHashV2::from_bytes(entry_hash)?,
                ))
            })
            .transpose()
    }

    pub(crate) fn apply_finalized_page(
        &mut self,
        channel: &ChannelContextIdV2,
        expected: Option<&FinalizedCursor>,
        updates: &[FinalizedUpdate],
    ) -> Result<(usize, usize)> {
        if updates.is_empty() {
            return Ok((0, 0));
        }
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let current = transaction
            .query_row(
                "SELECT sequence, entry_hash FROM finalized_heads WHERE channel_context_id = ?1",
                [channel.as_bytes().as_slice()],
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, Vec<u8>>(1)?)),
            )
            .optional()?;
        if !cursor_matches(current.as_ref(), expected)? {
            return Err(HolderNodeError::FinalityConflict);
        }
        let mut prior_sequence = expected.map(|cursor| cursor.sequence);
        let mut prior_hash = expected.map(|cursor| cursor.entry_hash.clone());
        let mut finalized = 0_usize;
        let mut unrelated = 0_usize;
        for update in updates {
            if &update.cursor.channel_context_id != channel {
                return Err(HolderNodeError::FinalityConflict);
            }
            let expected_sequence = match prior_sequence {
                None => 0,
                Some(sequence) => sequence.checked_add(1).ok_or(HolderNodeError::FinalityConflict)?,
            };
            if update.cursor.sequence != expected_sequence {
                return Err(HolderNodeError::FinalityConflict);
            }
            prior_sequence = Some(update.cursor.sequence);
            prior_hash = Some(update.cursor.entry_hash.clone());
            if let Some(stored) = transaction
                .query_row(
                    "SELECT proposal_digest FROM outbox WHERE request_digest = ?1",
                    [update.request_digest.as_bytes().as_slice()],
                    |row| row.get::<_, Vec<u8>>(0),
                )
                .optional()?
            {
                if stored.as_slice() != update.proposal_digest {
                    return Err(HolderNodeError::FinalityConflict);
                }
                transaction.execute(
                    "UPDATE outbox SET status = ?1, finalized_sequence = ?2, finality_digest = ?3
                     WHERE request_digest = ?4",
                    params![
                        OutboxStatus::Finalized.code(),
                        to_i64(update.cursor.sequence)?,
                        update.finality_digest.as_slice(),
                        update.request_digest.as_bytes().as_slice(),
                    ],
                )?;
                finalized = finalized.saturating_add(1);
            } else {
                unrelated = unrelated.saturating_add(1);
            }
        }
        let final_sequence = prior_sequence.ok_or(HolderNodeError::FinalityConflict)?;
        let final_hash = prior_hash.ok_or(HolderNodeError::FinalityConflict)?;
        transaction.execute(
            "INSERT INTO finalized_heads(channel_context_id, sequence, entry_hash) VALUES(?1, ?2, ?3)
             ON CONFLICT(channel_context_id) DO UPDATE SET sequence = excluded.sequence, entry_hash = excluded.entry_hash",
            params![channel.as_bytes().as_slice(), to_i64(final_sequence)?, final_hash.as_bytes().as_slice()],
        )?;
        transaction.commit()?;
        Ok((finalized, unrelated))
    }

    pub(crate) fn status(&self, lifecycle: LifecycleState, recovered: bool, generation: u64) -> Result<ServiceStatus> {
        let mut counts = [0_usize; 4];
        let mut statement = self
            .connection
            .prepare("SELECT status, COUNT(*) FROM outbox GROUP BY status")?;
        let rows = statement.query_map([], |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)))?;
        for row in rows {
            let (status, count) = row?;
            let index = usize::try_from(status).map_err(|_| HolderNodeError::StorageCorrupt)?;
            let slot = counts.get_mut(index).ok_or(HolderNodeError::StorageCorrupt)?;
            *slot = usize::try_from(count).map_err(|_| HolderNodeError::StorageCorrupt)?;
        }
        let finalized_channels: i64 = self
            .connection
            .query_row("SELECT COUNT(*) FROM finalized_heads", [], |row| row.get(0))?;
        Ok(ServiceStatus {
            lifecycle,
            recovered_unclean_shutdown: recovered,
            run_generation: generation,
            outbox_queued: counts[0],
            outbox_submitted: counts[1],
            outbox_finalized: counts[2],
            outbox_retry_exhausted: counts[3],
            finalized_channels: usize::try_from(finalized_channels).map_err(|_| HolderNodeError::StorageCorrupt)?,
        })
    }
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

fn to_i64(value: u64) -> Result<i64> {
    i64::try_from(value).map_err(|_| HolderNodeError::OutOfRange)
}

fn cursor_matches(stored: Option<&(i64, Vec<u8>)>, expected: Option<&FinalizedCursor>) -> Result<bool> {
    match (stored, expected) {
        (None, None) => Ok(true),
        (Some((sequence, hash)), Some(expected)) => Ok(u64::try_from(*sequence)
            .map_err(|_| HolderNodeError::StorageCorrupt)?
            == expected.sequence
            && hash.as_slice() == expected.entry_hash.as_bytes()),
        _ => Ok(false),
    }
}
