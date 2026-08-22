use std::collections::BTreeMap;
#[cfg(unix)]
use std::fs::{self, OpenOptions};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, MutexGuard};
use std::time::Duration;

use rusqlite::{params, Connection, OpenFlags, OptionalExtension, Row, Transaction, TransactionBehavior};
use thunderbolt_floor::{FloorCasRequest, VaultCheckpoint};
use thunderbolt_keystore::{Network, VaultRevision, VaultRole, VaultStateDigest};

use crate::history::{digest_snapshot, HistoryAnchorCandidateInput, StoredHistoryAnchor};
use crate::merkle::{anchor_state_proof, result_proof, result_root, state_proof, state_root};
use crate::migrations;
use crate::types::{ExecutedFloorResultInput, StoredFloorBlock};
use crate::{
    ActorRequestDigest, ActorRequestNonce, ExecutedFloorBlock, ExecutedFloorResult, FinalizedHistoryAnchor,
    FinalizedHistoryAnchorVerifier, FloorAnchorStateProof, FloorAppHash, FloorApplicationError, FloorApplicationStatus,
    FloorBlockDigest, FloorBlockExecutionOutcome, FloorBlockInput, FloorCasAuthorization, FloorCasDisposition,
    FloorGenesis, FloorOperatorKey, FloorResultDigest, FloorResultProof, FloorResultRoot, FloorStateProof,
    FloorStateRoot, GenesisDigest, HistoryAnchorCandidate, HistoryAnchorDigest, HistoryCompactionError,
    HistoryOpenError, HistoryRetentionPolicy, HistorySnapshotDigest, HistoryUsage, PreparedFloorBlock, Result,
    SignedFloorCasRequest, VaultIdentityDigest, FLOOR_APPLICATION_VERSION_V2, MAX_BLOCK_REQUESTS, MAX_REGISTRY_ENTRIES,
    MAX_RESTART_LIVE_BYTES, MAX_RESTART_TAIL_BLOCKS, MAX_RESTART_TAIL_RESULTS, MAX_RESTART_TAIL_STATE_DELTAS,
};

const DEFAULT_BUSY_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, Clone, Copy)]
struct RestartTailLimits {
    blocks: u64,
    results: u64,
    state_deltas: u64,
    live_bytes: u64,
    encoded_bytes: u64,
}

const PRODUCTION_RESTART_LIMITS: RestartTailLimits = RestartTailLimits {
    blocks: MAX_RESTART_TAIL_BLOCKS,
    results: MAX_RESTART_TAIL_RESULTS,
    state_deltas: MAX_RESTART_TAIL_STATE_DELTAS,
    live_bytes: MAX_RESTART_LIVE_BYTES,
    encoded_bytes: MAX_RESTART_LIVE_BYTES,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DurableFileIdentity {
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
}

struct StoredRegistryRow {
    identity_digest: Vec<u8>,
    network: i64,
    role: i64,
    node_id: Vec<u8>,
    deployment_id: Vec<u8>,
    committee_epoch: i64,
    committee_descriptor: Vec<u8>,
    operator_key: Vec<u8>,
}

struct LoadedBlockResults {
    time: u64,
    results: Vec<ExecutedFloorResult>,
    signatures: Vec<[u8; 64]>,
}

/// Crash-safe deterministic floor application.
pub struct FloorApplication {
    path: PathBuf,
    file_identity: DurableFileIdentity,
    genesis: FloorGenesis,
    poisoned: AtomicBool,
    trusted_anchor: Mutex<Option<FinalizedHistoryAnchor>>,
    connection: Mutex<Connection>,
}

impl FloorApplication {
    /// Opens or initializes one SQLite floor application.
    pub fn open(path: impl AsRef<Path>, genesis: FloorGenesis) -> Result<Self> {
        let (path, file_identity) = prepare_durable_path(path.as_ref())?;
        let connection = Connection::open_with_flags(
            &path,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_CREATE
                | OpenFlags::SQLITE_OPEN_FULL_MUTEX
                | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )
        .map_err(FloorApplicationError::from)?;
        configure(&connection)?;
        migrations::migrate(&connection, &path)?;
        initialize_or_verify(&connection, &genesis)?;
        if load_history_anchor(&connection)?.is_some() {
            return Err(FloorApplicationError::ExternalHistoryAnchorRequired);
        }
        let application = Self {
            path,
            file_identity,
            genesis,
            poisoned: AtomicBool::new(false),
            trusted_anchor: Mutex::new(None),
            connection: Mutex::new(connection),
        };
        application.verify_integrity()?;
        Ok(application)
    }

    /// Reopens a compacted database after independently authenticating its exact stored anchor.
    pub fn open_with_history_anchor<V>(
        path: impl AsRef<Path>,
        genesis: FloorGenesis,
        proof: &V::Proof,
        verifier: &V,
    ) -> std::result::Result<Self, HistoryOpenError<V::Error>>
    where
        V: FinalizedHistoryAnchorVerifier,
    {
        let (path, file_identity) = prepare_durable_path(path.as_ref())?;
        let connection = Connection::open_with_flags(
            &path,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_CREATE
                | OpenFlags::SQLITE_OPEN_FULL_MUTEX
                | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )
        .map_err(FloorApplicationError::from)?;
        configure(&connection)?;
        migrations::migrate(&connection, &path)?;
        initialize_or_verify(&connection, &genesis)?;
        let anchor = load_history_anchor(&connection)?.ok_or(FloorApplicationError::HistoryAnchorMismatch)?;
        verify_anchor_binding(&connection, &genesis, &anchor)?;
        verifier
            .verify_stored_anchor(&anchor, proof)
            .map_err(HistoryOpenError::Verifier)?;
        let application = Self {
            path,
            file_identity,
            genesis,
            poisoned: AtomicBool::new(false),
            trusted_anchor: Mutex::new(Some(anchor)),
            connection: Mutex::new(connection),
        };
        application.verify_integrity()?;
        Ok(application)
    }

    /// Builds a recovery-only anchor candidate without replaying an oversized retained tail.
    pub fn recovery_history_anchor_candidate<V>(
        path: impl AsRef<Path>,
        genesis: FloorGenesis,
        through_height: u64,
        stored_anchor_proof: Option<&V::Proof>,
        verifier: &V,
    ) -> std::result::Result<HistoryAnchorCandidate, HistoryOpenError<V::Error>>
    where
        V: FinalizedHistoryAnchorVerifier,
    {
        let (path, _file_identity) = prepare_durable_path(path.as_ref())?;
        let connection = Connection::open_with_flags(
            &path,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_CREATE
                | OpenFlags::SQLITE_OPEN_FULL_MUTEX
                | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )
        .map_err(FloorApplicationError::from)?;
        configure(&connection)?;
        migrations::migrate(&connection, &path)?;
        initialize_or_verify(&connection, &genesis)?;
        let prior_anchor = load_history_anchor(&connection)?;
        match (prior_anchor.as_ref(), stored_anchor_proof) {
            (Some(anchor), Some(proof)) => {
                verify_anchor_binding(&connection, &genesis, anchor)?;
                verifier
                    .verify_stored_anchor(anchor, proof)
                    .map_err(HistoryOpenError::Verifier)?;
            }
            (None, None) => {}
            _ => return Err(FloorApplicationError::ExternalHistoryAnchorRequired.into()),
        }
        let candidate = build_bounded_history_anchor_candidate(
            &connection,
            &genesis,
            prior_anchor.as_ref(),
            through_height,
            PRODUCTION_RESTART_LIMITS,
        )?;
        Ok(candidate)
    }

    /// Recovers an oversized database by externally authenticating and compacting a bounded prefix.
    ///
    /// This path exposes no checkpoints, proofs, or execution API until the new
    /// anchor is committed and the retained tail passes bounded restart replay.
    pub fn recover_and_compact_history<V>(
        path: impl AsRef<Path>,
        genesis: FloorGenesis,
        candidate: HistoryAnchorCandidate,
        stored_anchor_proof: Option<&V::Proof>,
        candidate_proof: &V::Proof,
        verifier: &V,
    ) -> std::result::Result<(Self, FinalizedHistoryAnchor), HistoryOpenError<V::Error>>
    where
        V: FinalizedHistoryAnchorVerifier,
    {
        let (path, file_identity) = prepare_durable_path(path.as_ref())?;
        let mut connection = Connection::open_with_flags(
            &path,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_CREATE
                | OpenFlags::SQLITE_OPEN_FULL_MUTEX
                | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )
        .map_err(FloorApplicationError::from)?;
        configure(&connection)?;
        migrations::migrate(&connection, &path)?;
        initialize_or_verify(&connection, &genesis)?;
        let prior_anchor = load_history_anchor(&connection)?;
        match (prior_anchor.as_ref(), stored_anchor_proof) {
            (Some(anchor), Some(proof)) => {
                verify_anchor_binding(&connection, &genesis, anchor)?;
                verifier
                    .verify_stored_anchor(anchor, proof)
                    .map_err(HistoryOpenError::Verifier)?;
            }
            (None, None) => {}
            _ => return Err(FloorApplicationError::ExternalHistoryAnchorRequired.into()),
        }

        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(FloorApplicationError::from)?;
        let exact = build_bounded_history_anchor_candidate(
            &transaction,
            &genesis,
            prior_anchor.as_ref(),
            candidate.through_height(),
            PRODUCTION_RESTART_LIMITS,
        )?;
        if exact != candidate {
            return rollback_error(transaction, FloorApplicationError::HistoryAnchorMismatch)
                .map_err(HistoryOpenError::Application);
        }
        let committing_header_hash = verifier
            .finalize_candidate(&candidate, candidate_proof)
            .map_err(HistoryOpenError::Verifier)?;
        let finalized = FinalizedHistoryAnchor::finalize(&candidate, committing_header_hash)?;
        install_history_anchor(&transaction, &finalized, &candidate.snapshot)?;
        if let Err(error) = transaction.commit() {
            if load_history_anchor(&connection)?.as_ref() != Some(&finalized)
                || load_anchor_snapshot(&connection)? != candidate.snapshot
                || has_history_through(&connection, finalized.through_height())?
            {
                return Err(FloorApplicationError::Database(error).into());
            }
        }
        let application = Self {
            path,
            file_identity,
            genesis,
            poisoned: AtomicBool::new(false),
            trusted_anchor: Mutex::new(Some(finalized.clone())),
            connection: Mutex::new(connection),
        };
        application.verify_integrity()?;
        Ok((application, finalized))
    }

    /// Returns the immutable genesis configuration.
    pub const fn genesis(&self) -> &FloorGenesis {
        &self.genesis
    }

    /// Returns the SQLite database path.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Returns current durable application head.
    pub fn status(&self) -> Result<FloorApplicationStatus> {
        let connection = self.lock()?;
        load_status(&connection)
    }

    /// Returns the externally authenticated local-history anchor, if installed.
    pub fn finalized_history_anchor(&self) -> Result<Option<FinalizedHistoryAnchor>> {
        self.anchor()
    }

    /// Reports local retained-history usage without changing consensus execution.
    pub fn history_usage(&self, policy: HistoryRetentionPolicy) -> Result<HistoryUsage> {
        let anchor_height = self.anchor()?.map_or(0, |anchor| anchor.through_height());
        let connection = self.lock()?;
        let mut usage = load_history_usage(&connection, anchor_height)?;
        usage.compaction_recommended = usage.retained_blocks >= policy.preferred_blocks()
            || usage.retained_results >= policy.preferred_results()
            || usage.retained_state_deltas >= policy.preferred_state_deltas()
            || usage.retained_live_bytes >= policy.preferred_live_bytes();
        Ok(usage)
    }

    /// Builds an exact state snapshot candidate for external finality verification.
    pub fn history_anchor_candidate(&self, through_height: u64) -> Result<HistoryAnchorCandidate> {
        let anchor = self.anchor()?;
        let connection = self.lock()?;
        build_bounded_history_anchor_candidate(
            &connection,
            &self.genesis,
            anchor.as_ref(),
            through_height,
            PRODUCTION_RESTART_LIMITS,
        )
    }

    /// Installs an externally finalized local-history anchor and prunes through it atomically.
    ///
    /// Consensus execution never depends on whether or when this local operation runs.
    pub fn compact_history<V>(
        &self,
        candidate: HistoryAnchorCandidate,
        proof: &V::Proof,
        verifier: &V,
    ) -> std::result::Result<FinalizedHistoryAnchor, HistoryCompactionError<V::Error>>
    where
        V: FinalizedHistoryAnchorVerifier,
    {
        self.ensure_healthy()?;
        let mut trusted_anchor = self
            .trusted_anchor
            .lock()
            .map_err(|_| FloorApplicationError::CorruptState("history anchor mutex poisoned"))?;
        if let Some(installed) = trusted_anchor
            .as_ref()
            .filter(|anchor| anchor.matches_candidate(&candidate))
            .cloned()
        {
            let connection = self.lock()?;
            let exact = (|| -> Result<bool> {
                Ok(load_history_anchor(&connection)?.as_ref() == Some(&installed)
                    && load_anchor_snapshot(&connection)? == candidate.snapshot
                    && !has_history_through(&connection, installed.through_height())?)
            })();
            match exact {
                Ok(true) => {}
                Ok(false) => {
                    self.poison();
                    return Err(FloorApplicationError::HistoryAnchorMismatch.into());
                }
                Err(error) => {
                    self.poison();
                    return Err(error.into());
                }
            }
            if let Err(error) = verify_integrity_locked(&connection, &self.genesis, Some(&installed))
                .and_then(|()| verify_durable_file_identity(&self.path, self.file_identity))
            {
                self.poison();
                return Err(error.into());
            }
            return Ok(installed);
        }
        if trusted_anchor.as_ref().map(FinalizedHistoryAnchor::anchor_digest) != candidate.prior_anchor_digest() {
            return Err(FloorApplicationError::HistoryAnchorMismatch.into());
        }
        let mut connection = self.lock()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(FloorApplicationError::from)?;
        let exact = build_bounded_history_anchor_candidate(
            &transaction,
            &self.genesis,
            trusted_anchor.as_ref(),
            candidate.through_height(),
            PRODUCTION_RESTART_LIMITS,
        )?;
        if exact != candidate {
            return rollback_error(transaction, FloorApplicationError::HistoryAnchorMismatch)
                .map_err(HistoryCompactionError::Application);
        }
        let committing_header_hash = verifier
            .finalize_candidate(&candidate, proof)
            .map_err(HistoryCompactionError::Verifier)?;
        let finalized = FinalizedHistoryAnchor::finalize(&candidate, committing_header_hash)?;
        install_history_anchor(&transaction, &finalized, &candidate.snapshot)?;
        match transaction.commit() {
            Ok(()) => {}
            Err(error) => {
                let reconciled = (|| -> Result<bool> {
                    Ok(load_history_anchor(&connection)?.as_ref() == Some(&finalized)
                        && load_anchor_snapshot(&connection)? == candidate.snapshot
                        && !has_history_through(&connection, finalized.through_height())?)
                })();
                match reconciled {
                    Ok(true) => {}
                    Ok(false) => {
                        self.poison();
                        return Err(HistoryCompactionError::Application(FloorApplicationError::Database(
                            error,
                        )));
                    }
                    Err(reconciliation) => {
                        self.poison();
                        return Err(reconciliation.into());
                    }
                }
            }
        }
        if let Err(error) = verify_integrity_locked(&connection, &self.genesis, Some(&finalized))
            .and_then(|()| verify_durable_file_identity(&self.path, self.file_identity))
        {
            self.poison();
            return Err(error.into());
        }
        *trusted_anchor = Some(finalized.clone());
        Ok(finalized)
    }

    /// Loads internally checked execution evidence for a committed height.
    ///
    /// This is application evidence only. It does not prove consensus finality;
    /// callers must still validate the independent committing header.
    pub fn committed_block(&self, height: u64) -> Result<ExecutedFloorBlock> {
        if height == 0 {
            return Err(FloorApplicationError::InvalidInput("committed block height"));
        }
        reject_pruned_height(self.anchor()?.as_ref(), height)?;
        let connection = self.lock()?;
        let block = load_block(&connection, &self.genesis, height)?;
        let state = load_state_at_height(&connection, height)?;
        verify_state_entries(&self.genesis, &state)?;
        if result_root(height, block.block_time_ms(), block.results())? != block.result_root()
            || state_root(&state)? != block.state_root()
            || block.recompute_app_hash() != block.app_hash()
        {
            return Err(FloorApplicationError::CorruptState("committed block evidence"));
        }
        Ok(block)
    }

    /// Executes a rollback-only deterministic preview.
    pub fn preview_block(&self, input: FloorBlockInput) -> Result<PreparedFloorBlock> {
        let anchor = self.anchor()?;
        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let outcome = execute_locked(&transaction, &self.genesis, anchor.as_ref(), &input)?;
        transaction.rollback()?;
        Ok(PreparedFloorBlock {
            input,
            block: outcome.block().clone(),
        })
    }

    /// Re-executes and atomically commits an exact preview.
    pub fn commit_prepared_block(&self, prepared: PreparedFloorBlock) -> Result<FloorBlockExecutionOutcome> {
        let anchor = self.anchor()?;
        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let operation = execute_locked(&transaction, &self.genesis, anchor.as_ref(), &prepared.input);
        match operation {
            Ok(outcome) if outcome.block() == &prepared.block => {
                transaction.commit()?;
                Ok(outcome)
            }
            Ok(_) => rollback_error(transaction, FloorApplicationError::PreparedMismatch),
            Err(error) => rollback_error(transaction, error),
        }
    }

    /// Atomically executes one consensus-ordered block.
    pub fn execute_block(&self, input: &FloorBlockInput) -> Result<FloorBlockExecutionOutcome> {
        let anchor = self.anchor()?;
        let mut connection = self.lock()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        match execute_locked(&transaction, &self.genesis, anchor.as_ref(), input) {
            Ok(outcome) => {
                transaction.commit()?;
                Ok(outcome)
            }
            Err(error) => rollback_error(transaction, error),
        }
    }

    /// Reads the current checkpoint for one authorized identity.
    pub fn checkpoint(&self, identity_digest: VaultIdentityDigest) -> Result<Option<VaultCheckpoint>> {
        if self.genesis.entry(identity_digest).is_none() {
            return Err(FloorApplicationError::UnauthorizedActor);
        }
        let connection = self.lock()?;
        load_checkpoint(&connection, identity_digest)
    }

    /// Builds a registry-ordered inclusion/absence proof at the current head.
    pub fn state_proof(&self, identity_digest: VaultIdentityDigest) -> Result<FloorStateProof> {
        let anchor = self.anchor()?;
        let connection = self.lock()?;
        let status = load_status(&connection)?;
        if status.last_height == 0 {
            return Err(FloorApplicationError::InvalidInput(
                "state proof requires a committed block",
            ));
        }
        reject_pruned_height(anchor.as_ref(), status.last_height)?;
        let entries = load_all_state(&connection)?;
        verify_state_entries(&self.genesis, &entries)?;
        let index = self
            .genesis
            .entries()
            .iter()
            .position(|entry| entry.identity_digest() == identity_digest)
            .ok_or(FloorApplicationError::UnauthorizedActor)?;
        state_proof(status.last_height, status.last_block_time_ms, &entries, index)
    }

    /// Builds a registry-ordered state proof at a committed height.
    pub fn state_proof_at(&self, height: u64, identity_digest: VaultIdentityDigest) -> Result<FloorStateProof> {
        reject_pruned_height(self.anchor()?.as_ref(), height)?;
        let connection = self.lock()?;
        let block = load_block(&connection, &self.genesis, height)?;
        let entries = load_state_at_height(&connection, height)?;
        verify_state_entries(&self.genesis, &entries)?;
        let index = self
            .genesis
            .entries()
            .iter()
            .position(|entry| entry.identity_digest() == identity_digest)
            .ok_or(FloorApplicationError::UnauthorizedActor)?;
        state_proof(height, block.block_time_ms(), &entries, index)
    }

    /// Builds a present/absent state proof at the externally authenticated anchor snapshot.
    pub fn anchor_state_proof(&self, identity_digest: VaultIdentityDigest) -> Result<FloorAnchorStateProof> {
        let anchor = self.anchor()?.ok_or(FloorApplicationError::InvalidInput(
            "anchor state proof requires compacted history",
        ))?;
        let connection = self.lock()?;
        let snapshot = verify_anchor_binding(&connection, &self.genesis, &anchor)?;
        let index = self
            .genesis
            .entries()
            .iter()
            .position(|entry| entry.identity_digest() == identity_digest)
            .ok_or(FloorApplicationError::UnauthorizedActor)?;
        anchor_state_proof(&anchor, &snapshot, index)
    }

    /// Builds an ordered result proof for a committed block index.
    pub fn result_proof(&self, height: u64, block_index: usize) -> Result<FloorResultProof> {
        reject_pruned_height(self.anchor()?.as_ref(), height)?;
        let connection = self.lock()?;
        let block = load_block(&connection, &self.genesis, height)?;
        result_proof(height, block.block_time_ms(), block.results(), block_index)
    }

    /// Replays integrity checks over genesis, roots, app hashes, and the head.
    pub fn verify_integrity(&self) -> Result<()> {
        let trusted_anchor = self.anchor()?;
        let connection = self.lock()?;
        verify_integrity_locked(&connection, &self.genesis, trusted_anchor.as_ref())
    }

    fn lock(&self) -> Result<MutexGuard<'_, Connection>> {
        self.ensure_healthy()?;
        verify_durable_file_identity(&self.path, self.file_identity)?;
        let connection = self
            .connection
            .lock()
            .map_err(|_| FloorApplicationError::CorruptState("database mutex poisoned"))?;
        self.ensure_healthy()?;
        verify_durable_file_identity(&self.path, self.file_identity)?;
        Ok(connection)
    }

    fn anchor(&self) -> Result<Option<FinalizedHistoryAnchor>> {
        self.ensure_healthy()?;
        verify_durable_file_identity(&self.path, self.file_identity)?;
        let anchor = self
            .trusted_anchor
            .lock()
            .map_err(|_| FloorApplicationError::CorruptState("history anchor mutex poisoned"))?;
        self.ensure_healthy()?;
        verify_durable_file_identity(&self.path, self.file_identity)?;
        Ok(anchor.clone())
    }

    fn ensure_healthy(&self) -> Result<()> {
        if self.poisoned.load(Ordering::Acquire) {
            return Err(FloorApplicationError::Poisoned);
        }
        Ok(())
    }

    fn poison(&self) {
        self.poisoned.store(true, Ordering::Release);
    }
}

fn verify_integrity_locked(
    connection: &Connection,
    genesis: &FloorGenesis,
    trusted_anchor: Option<&FinalizedHistoryAnchor>,
) -> Result<()> {
    verify_genesis_rows(connection, genesis)?;
    let status = load_status(connection)?;
    let stored_anchor = load_history_anchor(connection)?;
    if stored_anchor.as_ref() != trusted_anchor {
        return Err(if stored_anchor.is_some() {
            FloorApplicationError::ExternalHistoryAnchorRequired
        } else {
            FloorApplicationError::HistoryAnchorMismatch
        });
    }
    let (guard_active, snapshot_rows): (i64, i64) = connection.query_row(
        "SELECT (SELECT active FROM compaction_guard WHERE singleton=1),(SELECT COUNT(*) FROM history_anchor_snapshot)",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    if guard_active != 0 || (trusted_anchor.is_none() && snapshot_rows != 0) {
        return Err(FloorApplicationError::CorruptState("history compaction metadata"));
    }
    let restart_base = trusted_anchor.map_or(0, FinalizedHistoryAnchor::through_height);
    preflight_restart_tail(connection, restart_base, PRODUCTION_RESTART_LIMITS)?;
    let (base_height, mut previous_time, mut previous, mut replayed_state) = if let Some(anchor) = trusted_anchor {
        let snapshot = verify_anchor_binding(connection, genesis, anchor)?;
        (
            anchor.through_height(),
            anchor.through_time_ms(),
            anchor.through_app_hash(),
            snapshot,
        )
    } else {
        (
            0,
            0,
            FloorAppHash::new([0; 32]),
            genesis
                .entries()
                .iter()
                .map(|entry| (entry.identity_digest(), None))
                .collect::<Vec<_>>(),
        )
    };
    verify_relational_shape(connection, &status, base_height)?;
    let state_positions = replayed_state
        .iter()
        .enumerate()
        .map(|(index, (identity, _))| (*identity, index))
        .collect::<BTreeMap<_, _>>();
    let mut replayed_state_root = state_root(&replayed_state)?;
    let first_retained = base_height
        .checked_add(1)
        .ok_or(FloorApplicationError::CorruptState("history anchor height"))?;
    for height in first_retained..=status.last_height {
        let block = load_block(connection, genesis, height)?;
        if block.previous_app_hash() != previous || block.block_time_ms() < previous_time {
            return Err(FloorApplicationError::CorruptState("block continuity"));
        }
        let expected_deltas = replay_block_state(genesis, &state_positions, &mut replayed_state, &block)?;
        if load_state_deltas(connection, height)? != expected_deltas {
            return Err(FloorApplicationError::CorruptState("state delta history"));
        }
        if !expected_deltas.is_empty() {
            replayed_state_root = state_root(&replayed_state)?;
        }
        if result_root(height, block.block_time_ms(), block.results())? != block.result_root()
            || replayed_state_root != block.state_root()
            || block.recompute_app_hash() != block.app_hash()
        {
            return Err(FloorApplicationError::CorruptState("block commitment"));
        }
        previous = block.app_hash();
        previous_time = block.block_time_ms();
    }
    if previous != status.last_app_hash || previous_time != status.last_block_time_ms {
        return Err(FloorApplicationError::CorruptState("application head"));
    }
    let entries = load_all_state(connection)?;
    verify_state_entries(genesis, &entries)?;
    if entries != replayed_state {
        return Err(FloorApplicationError::CorruptState("current floor state"));
    }
    let current_root = state_root(&entries)?;
    if status.last_height > base_height {
        let block = load_block(connection, genesis, status.last_height)?;
        if block.state_root() != current_root {
            return Err(FloorApplicationError::CorruptState("state root"));
        }
    } else if trusted_anchor.is_some_and(|anchor| anchor.state_root() != current_root) {
        return Err(FloorApplicationError::CorruptState("anchor state root"));
    }
    Ok(())
}

#[cfg(unix)]
fn prepare_durable_path(path: &Path) -> Result<(PathBuf, DurableFileIdentity)> {
    let invalid = || FloorApplicationError::InvalidStoragePath {
        path: path.to_path_buf(),
    };
    let file_name = path.file_name().ok_or_else(&invalid)?;
    let magic = file_name.to_string_lossy();
    if !path.is_absolute()
        || path.as_os_str().is_empty()
        || magic == ":memory:"
        || magic.starts_with("file:")
        || magic.contains("mode=memory")
    {
        return Err(invalid());
    }
    let parent = path.parent().ok_or_else(&invalid)?;
    let parent_metadata = fs::symlink_metadata(parent).map_err(|_| invalid())?;
    if parent_metadata.file_type().is_symlink() || !parent_metadata.is_dir() || !private_directory(&parent_metadata) {
        return Err(invalid());
    }
    let canonical_parent = fs::canonicalize(parent).map_err(|_| invalid())?;
    let durable_path = canonical_parent.join(file_name);
    let metadata = match fs::symlink_metadata(&durable_path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() || !private_file(&metadata) => {
            return Err(invalid());
        }
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            create_private_file(&durable_path).map_err(|_| invalid())?;
            fs::symlink_metadata(&durable_path).map_err(|_| invalid())?
        }
        Err(_) => return Err(invalid()),
    };
    let identity = durable_file_identity(&metadata).ok_or_else(&invalid)?;
    Ok((durable_path, identity))
}

#[cfg(not(unix))]
fn prepare_durable_path(path: &Path) -> Result<(PathBuf, DurableFileIdentity)> {
    Err(FloorApplicationError::InvalidStoragePath {
        path: path.to_path_buf(),
    })
}

fn reject_pruned_height(anchor: Option<&FinalizedHistoryAnchor>, height: u64) -> Result<()> {
    if let Some(anchor) = anchor.filter(|anchor| height <= anchor.through_height()) {
        return Err(FloorApplicationError::HistoryPruned {
            requested_height: height,
            earliest_available: anchor
                .through_height()
                .checked_add(1)
                .ok_or(FloorApplicationError::CorruptState("history anchor height"))?,
            anchor_height: anchor.through_height(),
        });
    }
    Ok(())
}

#[cfg(unix)]
fn create_private_file(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::OpenOptionsExt;

    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map(drop)
}

#[cfg(unix)]
fn private_directory(metadata: &fs::Metadata) -> bool {
    use std::os::unix::fs::PermissionsExt;

    let mode = metadata.permissions().mode();
    mode & 0o077 == 0 && mode & 0o300 == 0o300
}

#[cfg(unix)]
fn private_file(metadata: &fs::Metadata) -> bool {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    metadata.permissions().mode() & 0o077 == 0 && metadata.nlink() == 1
}

#[cfg(unix)]
fn durable_file_identity(metadata: &fs::Metadata) -> Option<DurableFileIdentity> {
    use std::os::unix::fs::MetadataExt;

    (metadata.is_file() && metadata.nlink() == 1).then_some(DurableFileIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    })
}

#[cfg(unix)]
fn verify_durable_file_identity(path: &Path, expected: DurableFileIdentity) -> Result<()> {
    let metadata = fs::symlink_metadata(path).map_err(|_| FloorApplicationError::InvalidStoragePath {
        path: path.to_path_buf(),
    })?;
    if metadata.file_type().is_symlink()
        || durable_file_identity(&metadata) != Some(expected)
        || !private_file(&metadata)
    {
        return Err(FloorApplicationError::InvalidStoragePath {
            path: path.to_path_buf(),
        });
    }
    Ok(())
}

#[cfg(not(unix))]
fn verify_durable_file_identity(path: &Path, _expected: DurableFileIdentity) -> Result<()> {
    Err(FloorApplicationError::InvalidStoragePath {
        path: path.to_path_buf(),
    })
}

fn configure(connection: &Connection) -> Result<()> {
    connection.busy_timeout(DEFAULT_BUSY_TIMEOUT)?;
    connection.pragma_update(None, "foreign_keys", "ON")?;
    connection.pragma_update(None, "journal_mode", "WAL")?;
    connection.pragma_update(None, "synchronous", "FULL")?;
    let foreign_keys: i64 = connection.pragma_query_value(None, "foreign_keys", |row| row.get(0))?;
    let journal_mode: String = connection.pragma_query_value(None, "journal_mode", |row| row.get(0))?;
    let synchronous: i64 = connection.pragma_query_value(None, "synchronous", |row| row.get(0))?;
    if foreign_keys != 1 || !journal_mode.eq_ignore_ascii_case("wal") || synchronous != 2 {
        return Err(FloorApplicationError::CorruptState("SQLite durability pragmas"));
    }
    Ok(())
}

fn initialize_or_verify(connection: &Connection, genesis: &FloorGenesis) -> Result<()> {
    let exists: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM application_state WHERE singleton = 1)",
        [],
        |row| row.get(0),
    )?;
    if exists {
        return verify_genesis_rows(connection, genesis);
    }
    let transaction = connection.unchecked_transaction()?;
    transaction.execute(
        "INSERT INTO application_state VALUES (1, ?1, ?2, ?3, ?4, ?5, 0, 0, ?6)",
        params![
            to_i64(FLOOR_APPLICATION_VERSION_V2)?,
            genesis.chain_id().as_bytes(),
            genesis.profile_digest(),
            genesis.registry_digest().as_bytes(),
            genesis.genesis_digest().as_bytes(),
            [0_u8; 32],
        ],
    )?;
    for (ordinal, entry) in genesis.entries().iter().enumerate() {
        let identity = entry.identity();
        transaction.execute(
            "INSERT INTO registry VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                i64::try_from(ordinal).map_err(|_| FloorApplicationError::InvalidInput("registry ordinal"))?,
                entry.identity_digest().as_bytes(),
                network_tag(identity.network()),
                role_tag(identity.role()),
                identity.node_id().as_bytes(),
                identity.deployment().deployment_id().as_bytes(),
                to_i64(identity.deployment().committee_epoch())?,
                identity.deployment().committee_descriptor().as_bytes(),
                entry.operator_key().as_bytes(),
            ],
        )?;
        transaction.execute(
            "INSERT INTO floor_state VALUES (?1, NULL, NULL, 0, NULL)",
            params![entry.identity_digest().as_bytes()],
        )?;
    }
    transaction.commit()?;
    Ok(())
}

fn verify_genesis_rows(connection: &Connection, genesis: &FloorGenesis) -> Result<()> {
    let stored = connection.query_row(
        "SELECT application_version, chain_id, profile_digest, registry_digest, genesis_digest FROM application_state WHERE singleton = 1",
        [],
        |row| Ok((row.get::<_, i64>(0)?, row.get::<_, Vec<u8>>(1)?, row.get::<_, Vec<u8>>(2)?, row.get::<_, Vec<u8>>(3)?, row.get::<_, Vec<u8>>(4)?)),
    )?;
    if stored.0 != to_i64(FLOOR_APPLICATION_VERSION_V2)?
        || stored.1 != genesis.chain_id().as_bytes()
        || stored.2 != genesis.profile_digest()
        || stored.3 != genesis.registry_digest().as_bytes()
        || stored.4 != genesis.genesis_digest().as_bytes()
    {
        return Err(FloorApplicationError::GenesisMismatch);
    }
    let registry_limit =
        i64::try_from(MAX_REGISTRY_ENTRIES + 1).map_err(|_| FloorApplicationError::InvalidInput("registry bound"))?;
    let registry_rows: i64 = connection.query_row(
        "SELECT COUNT(*) FROM (SELECT 1 FROM registry LIMIT ?1)",
        params![registry_limit],
        |row| row.get(0),
    )?;
    if registry_rows
        != i64::try_from(genesis.entries().len()).map_err(|_| FloorApplicationError::InvalidInput("registry count"))?
        || from_i64(registry_rows)? > MAX_REGISTRY_ENTRIES as u64
    {
        return Err(FloorApplicationError::GenesisMismatch);
    }
    let mut statement = connection.prepare(
        "SELECT identity_digest,network,role,node_id,deployment_id,committee_epoch,committee_descriptor,operator_key FROM registry ORDER BY ordinal LIMIT ?1",
    )?;
    let rows = statement
        .query_map(params![registry_decode_limit()?], |row| {
            Ok(StoredRegistryRow {
                identity_digest: row.get(0)?,
                network: row.get(1)?,
                role: row.get(2)?,
                node_id: row.get(3)?,
                deployment_id: row.get(4)?,
                committee_epoch: row.get(5)?,
                committee_descriptor: row.get(6)?,
                operator_key: row.get(7)?,
            })
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    if rows.len() != genesis.entries().len()
        || rows.iter().zip(genesis.entries()).any(|(stored, entry)| {
            let identity = entry.identity();
            stored.identity_digest.as_slice() != entry.identity_digest().as_bytes()
                || stored.network != network_tag(identity.network())
                || stored.role != role_tag(identity.role())
                || stored.node_id.as_slice() != identity.node_id().as_bytes()
                || stored.deployment_id.as_slice() != identity.deployment().deployment_id().as_bytes()
                || u64::try_from(stored.committee_epoch).ok() != Some(identity.deployment().committee_epoch())
                || stored.committee_descriptor.as_slice() != identity.deployment().committee_descriptor().as_bytes()
                || stored.operator_key.as_slice() != entry.operator_key().as_bytes()
        })
    {
        return Err(FloorApplicationError::GenesisMismatch);
    }
    Ok(())
}

fn verify_state_entries(
    genesis: &FloorGenesis,
    entries: &[(VaultIdentityDigest, Option<VaultCheckpoint>)],
) -> Result<()> {
    if entries.len() != genesis.entries().len()
        || entries
            .iter()
            .zip(genesis.entries())
            .any(|((identity, _), registry)| *identity != registry.identity_digest())
    {
        return Err(FloorApplicationError::CorruptState("floor state registry"));
    }
    Ok(())
}

fn verify_relational_shape(connection: &Connection, status: &FloorApplicationStatus, anchor_height: u64) -> Result<()> {
    let last_height = to_i64(status.last_height)?;
    let anchor_height = to_i64(anchor_height)?;
    if anchor_height > last_height {
        return Err(FloorApplicationError::CorruptState("anchor height range"));
    }
    let (block_count, minimum_height, maximum_height): (i64, Option<i64>, Option<i64>) =
        connection.query_row("SELECT COUNT(*),MIN(height),MAX(height) FROM blocks", [], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?))
        })?;
    let expected_blocks = last_height - anchor_height;
    let block_shape_matches = if expected_blocks == 0 {
        block_count == 0 && minimum_height.is_none() && maximum_height.is_none()
    } else {
        block_count == expected_blocks
            && minimum_height == Some(anchor_height + 1)
            && maximum_height == Some(last_height)
    };
    if !block_shape_matches {
        return Err(FloorApplicationError::CorruptState("block height range"));
    }

    let (result_count, expected_result_count): (i64, i64) = connection.query_row(
        "SELECT (SELECT COUNT(*) FROM block_results),COALESCE((SELECT SUM(request_count) FROM blocks),0)",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    let invalid_results: i64 = connection.query_row(
        "SELECT COUNT(*) FROM block_results br LEFT JOIN blocks b ON b.height=br.height LEFT JOIN registry r ON r.identity_digest=br.identity_digest WHERE b.height IS NULL OR r.identity_digest IS NULL OR br.height<=?1 OR br.height>?2 OR br.block_index<0 OR br.block_index>=b.request_count OR br.actor_key<>r.operator_key",
        params![anchor_height, last_height],
        |row| row.get(0),
    )?;
    if result_count != expected_result_count || invalid_results != 0 {
        return Err(FloorApplicationError::CorruptState("block result shape"));
    }

    let invalid_deltas: i64 = connection.query_row(
        "SELECT COUNT(*) FROM floor_state_history h LEFT JOIN blocks b ON b.height=h.height LEFT JOIN registry r ON r.identity_digest=h.identity_digest WHERE b.height IS NULL OR r.identity_digest IS NULL OR h.height<=?1 OR h.height>?2",
        params![anchor_height, last_height],
        |row| row.get(0),
    )?;
    if invalid_deltas != 0 {
        return Err(FloorApplicationError::CorruptState("state delta shape"));
    }

    Ok(())
}

fn replay_block_state(
    genesis: &FloorGenesis,
    positions: &BTreeMap<VaultIdentityDigest, usize>,
    state: &mut [(VaultIdentityDigest, Option<VaultCheckpoint>)],
    block: &ExecutedFloorBlock,
) -> Result<BTreeMap<VaultIdentityDigest, VaultCheckpoint>> {
    let mut deltas = BTreeMap::new();
    for result in block.results() {
        verify_result_authorization(genesis, block, result)?;
        let position = positions
            .get(&result.identity_digest())
            .copied()
            .ok_or(FloorApplicationError::CorruptState("result identity"))?;
        let current = state[position].1;
        match result.disposition() {
            FloorCasDisposition::Applied if current == result.expected() && result.current() == Some(result.next()) => {
                state[position].1 = Some(result.next());
                deltas.insert(result.identity_digest(), result.next());
            }
            FloorCasDisposition::AlreadyCurrent if current == Some(result.next()) && result.current() == current => {}
            FloorCasDisposition::Conflict
                if current != result.expected() && current != Some(result.next()) && result.current() == current => {}
            _ => return Err(FloorApplicationError::CorruptState("CAS result semantics")),
        }
    }
    Ok(deltas)
}

fn verify_result_authorization(
    genesis: &FloorGenesis,
    block: &ExecutedFloorBlock,
    result: &ExecutedFloorResult,
) -> Result<()> {
    let registry = genesis
        .entry(result.identity_digest())
        .ok_or(FloorApplicationError::CorruptState("result registry identity"))?;
    if registry.operator_key() != result.actor_key() {
        return Err(FloorApplicationError::CorruptState("result actor"));
    }
    let cas = FloorCasRequest::new(
        genesis.chain_id(),
        registry.identity(),
        result.expected(),
        result.next(),
    )
    .map_err(|_| FloorApplicationError::CorruptState("result CAS transition"))?;
    let authorization = FloorCasAuthorization::new(
        cas,
        result.actor_key(),
        result.nonce(),
        block.height(),
        block.previous_app_hash(),
    )
    .map_err(|_| FloorApplicationError::CorruptState("result authorization"))?;
    if authorization.request_digest() != result.request_digest() {
        return Err(FloorApplicationError::CorruptState("result request digest"));
    }
    Ok(())
}

fn execute_locked(
    connection: &Transaction<'_>,
    genesis: &FloorGenesis,
    anchor: Option<&FinalizedHistoryAnchor>,
    input: &FloorBlockInput,
) -> Result<FloorBlockExecutionOutcome> {
    let status = load_status(connection)?;
    if input.chain_id() != genesis.chain_id() {
        return Err(FloorApplicationError::BlockContinuity);
    }
    if input.height() == status.last_height && input.height() > 0 {
        reject_pruned_height(anchor, input.height())?;
        let block = load_block(connection, genesis, input.height())?;
        if block.block_digest() != input.block_digest() {
            return Err(FloorApplicationError::BlockFork);
        }
        return Ok(FloorBlockExecutionOutcome::new(block, true));
    }
    if input.height()
        != status
            .last_height
            .checked_add(1)
            .ok_or(FloorApplicationError::BlockContinuity)?
        || input.previous_app_hash() != status.last_app_hash
        || (status.last_height > 0 && input.block_time_ms() < status.last_block_time_ms)
    {
        return Err(FloorApplicationError::BlockContinuity);
    }

    let mut results = Vec::with_capacity(input.requests().len());
    for (index, request) in input.requests().iter().enumerate() {
        results.push(execute_request(connection, genesis, input, index, request)?);
    }
    let state_deltas = result_state_deltas(&results);
    let state_root = if state_deltas.is_empty() {
        load_previous_state_root(connection, genesis, anchor, status.last_height)?
    } else {
        let state = load_all_state(connection)?;
        verify_state_entries(genesis, &state)?;
        state_root(&state)?
    };
    let result_root = result_root(input.height(), input.block_time_ms(), &results)?;
    let block = ExecutedFloorBlock::new(input, genesis.genesis_digest(), result_root, state_root, results);
    insert_block(connection, &block, input.requests())?;
    insert_state_history(connection, block.height(), &state_deltas)?;
    connection.execute(
        "UPDATE application_state SET last_height=?1, last_block_time_ms=?2, last_app_hash=?3 WHERE singleton=1",
        params![
            to_i64(block.height())?,
            to_i64(block.block_time_ms())?,
            block.app_hash().as_bytes()
        ],
    )?;
    Ok(FloorBlockExecutionOutcome::new(block, false))
}

fn execute_request(
    connection: &Transaction<'_>,
    genesis: &FloorGenesis,
    input: &FloorBlockInput,
    index: usize,
    request: &SignedFloorCasRequest,
) -> Result<ExecutedFloorResult> {
    request.verify()?;
    let authorization = request.authorization();
    let identity_digest = crate::types::digest_identity(authorization.cas().identity());
    let registry = genesis
        .entry(identity_digest)
        .ok_or(FloorApplicationError::UnauthorizedActor)?;
    if registry.operator_key() != authorization.actor_key() || registry.identity() != authorization.cas().identity() {
        return Err(FloorApplicationError::UnauthorizedActor);
    }
    if authorization.target_height() != input.height()
        || authorization.expected_previous_app_hash() != input.previous_app_hash()
    {
        return Err(FloorApplicationError::InvalidInput("request head mismatch"));
    }

    let current = load_checkpoint(connection, identity_digest)?;
    let expected = authorization.cas().expected();
    let next = authorization.cas().next();
    let disposition = if current == Some(next) {
        FloorCasDisposition::AlreadyCurrent
    } else if current == expected {
        let updated = connection.execute(
            "UPDATE floor_state SET revision=?1, state_digest=?2, updated_height=?3, updated_block_index=?4 WHERE identity_digest=?5",
            params![to_i64(next.revision().get())?, next.state_digest().as_bytes(), to_i64(input.height())?, i64::try_from(index).map_err(|_| FloorApplicationError::InvalidInput("block index"))?, identity_digest.as_bytes()],
        )?;
        if updated != 1 {
            return Err(FloorApplicationError::CorruptState("floor state update"));
        }
        FloorCasDisposition::Applied
    } else {
        FloorCasDisposition::Conflict
    };
    let current_after = if disposition == FloorCasDisposition::Applied {
        Some(next)
    } else {
        current
    };
    let result = ExecutedFloorResult::new(ExecutedFloorResultInput {
        identity_digest,
        actor_key: authorization.actor_key(),
        nonce: authorization.nonce(),
        request_digest: authorization.request_digest(),
        expected,
        next,
        current: current_after,
        disposition,
    });
    Ok(result)
}

fn insert_block(
    connection: &Transaction<'_>,
    block: &ExecutedFloorBlock,
    requests: &[SignedFloorCasRequest],
) -> Result<()> {
    if requests.len() != block.results().len() {
        return Err(FloorApplicationError::CorruptState("signed result count"));
    }
    connection.execute(
        "INSERT INTO blocks VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
        params![
            to_i64(block.height())?,
            to_i64(block.block_time_ms())?,
            block.previous_app_hash().as_bytes(),
            block.block_digest().as_bytes(),
            block.result_root().as_bytes(),
            block.state_root().as_bytes(),
            block.app_hash().as_bytes(),
            i64::try_from(block.results().len()).map_err(|_| FloorApplicationError::InvalidInput("result count"))?
        ],
    )?;
    for (index, (result, request)) in block.results().iter().zip(requests).enumerate() {
        let (expected_revision, expected_digest) = checkpoint_columns(result.expected())?;
        let (current_revision, current_digest) = checkpoint_columns(result.current())?;
        connection.execute(
            "INSERT INTO block_results VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15)",
            params![
                to_i64(block.height())?,
                i64::try_from(index).map_err(|_| FloorApplicationError::InvalidInput("result index"))?,
                result.identity_digest().as_bytes(),
                result.actor_key().as_bytes(),
                result.nonce().as_bytes(),
                result.request_digest().as_bytes(),
                expected_revision,
                expected_digest,
                to_i64(result.next().revision().get())?,
                result.next().state_digest().as_bytes(),
                current_revision,
                current_digest,
                disposition_tag(result.disposition()),
                request.signature(),
                result.result_digest().as_bytes()
            ],
        )?;
    }
    Ok(())
}

fn insert_state_history(
    connection: &Transaction<'_>,
    height: u64,
    deltas: &BTreeMap<VaultIdentityDigest, VaultCheckpoint>,
) -> Result<()> {
    for (identity, checkpoint) in deltas {
        connection.execute(
            "INSERT INTO floor_state_history VALUES (?1,?2,?3,?4)",
            params![
                to_i64(height)?,
                identity.as_bytes(),
                to_i64(checkpoint.revision().get())?,
                checkpoint.state_digest().as_bytes()
            ],
        )?;
    }
    Ok(())
}

fn result_state_deltas(results: &[ExecutedFloorResult]) -> BTreeMap<VaultIdentityDigest, VaultCheckpoint> {
    results
        .iter()
        .filter(|result| result.disposition() == FloorCasDisposition::Applied)
        .map(|result| (result.identity_digest(), result.next()))
        .collect()
}

fn load_status(connection: &Connection) -> Result<FloorApplicationStatus> {
    connection.query_row(
        "SELECT last_height,last_block_time_ms,last_app_hash,genesis_digest FROM application_state WHERE singleton=1",
        [],
        |row| {
            Ok(FloorApplicationStatus {
                last_height: from_i64(row.get(0)?)?,
                last_block_time_ms: from_i64(row.get(1)?)?,
                last_app_hash: FloorAppHash::new(array32(row.get(2)?)?),
                genesis_digest: GenesisDigest::new(array32(row.get(3)?)?),
            })
        },
    ).map_err(FloorApplicationError::from)
}

fn load_history_anchor(connection: &Connection) -> Result<Option<FinalizedHistoryAnchor>> {
    preflight_anchor_encoding(connection)?;
    connection
        .query_row(
            "SELECT chain_id,genesis_digest,profile_digest,epoch,through_height,through_time_ms,previous_app_hash,through_app_hash,state_root,snapshot_digest,committing_header_hash,prior_anchor_digest,anchor_digest FROM history_anchor WHERE singleton=1",
            [],
            |row| {
                let chain_id = thunderbolt_floor::FloorLedgerChainId::new(row.get(0)?)
                    .map_err(|_| rusqlite::Error::InvalidQuery)?;
                let prior = row
                    .get::<_, Option<Vec<u8>>>(11)?
                    .map(array32)
                    .transpose()?
                    .map(HistoryAnchorDigest::new);
                FinalizedHistoryAnchor::from_stored(StoredHistoryAnchor {
                    chain_id,
                    genesis_digest: GenesisDigest::new(array32(row.get(1)?)?),
                    profile_digest: array32(row.get(2)?)?,
                    epoch: from_i64(row.get(3)?)?,
                    through_height: from_i64(row.get(4)?)?,
                    through_time_ms: from_i64(row.get(5)?)?,
                    previous_app_hash: FloorAppHash::new(array32(row.get(6)?)?),
                    through_app_hash: FloorAppHash::new(array32(row.get(7)?)?),
                    state_root: FloorStateRoot::new(array32(row.get(8)?)?),
                    snapshot_digest: HistorySnapshotDigest::new(array32(row.get(9)?)?),
                    committing_header_hash: array32(row.get(10)?)?,
                    prior_anchor_digest: prior,
                    anchor_digest: HistoryAnchorDigest::new(array32(row.get(12)?)?),
                })
                .map_err(to_sql_error)
            },
        )
        .optional()
        .map_err(FloorApplicationError::from)
}

fn load_anchor_snapshot(connection: &Connection) -> Result<Vec<(VaultIdentityDigest, Option<VaultCheckpoint>)>> {
    preflight_anchor_encoding(connection)?;
    let mut statement = connection.prepare(
        "SELECT ordinal,identity_digest,revision,state_digest FROM history_anchor_snapshot ORDER BY ordinal LIMIT ?1",
    )?;
    let rows = statement
        .query_map(params![registry_decode_limit()?], |row| {
            Ok((
                usize_from_i64(row.get(0)?)?,
                VaultIdentityDigest::new(array32(row.get(1)?)?),
                decode_checkpoint(row.get(2)?, row.get(3)?).map_err(to_sql_error)?,
            ))
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let mut snapshot = Vec::with_capacity(rows.len());
    for (expected, (ordinal, identity, checkpoint)) in rows.into_iter().enumerate() {
        if ordinal != expected {
            return Err(FloorApplicationError::CorruptState("anchor snapshot ordinal"));
        }
        snapshot.push((identity, checkpoint));
    }
    Ok(snapshot)
}

fn preflight_anchor_encoding(connection: &Connection) -> Result<()> {
    let anchor_rows: i64 = connection.query_row("SELECT COUNT(*) FROM history_anchor LIMIT 2", [], |row| row.get(0))?;
    if anchor_rows > 1 {
        return Err(FloorApplicationError::CorruptState("history anchor row count"));
    }
    let invalid_anchor: i64 = connection.query_row(
        "SELECT COUNT(*) FROM history_anchor WHERE length(chain_id) NOT BETWEEN 1 AND 128 OR length(genesis_digest)<>32 OR length(profile_digest)<>32 OR length(previous_app_hash)<>32 OR length(through_app_hash)<>32 OR length(state_root)<>32 OR length(snapshot_digest)<>32 OR length(committing_header_hash)<>32 OR (prior_anchor_digest IS NOT NULL AND length(prior_anchor_digest)<>32) OR length(anchor_digest)<>32",
        [],
        |row| row.get(0),
    )?;
    if invalid_anchor != 0 {
        return Err(FloorApplicationError::CorruptState("history anchor encoding"));
    }
    let snapshot_limit = i64::try_from(MAX_REGISTRY_ENTRIES + 1)
        .map_err(|_| FloorApplicationError::InvalidInput("anchor snapshot bound"))?;
    let (snapshot_rows, encoded_bytes): (i64, i64) = connection.query_row(
        "SELECT COUNT(*),COALESCE(SUM(encoded),0) FROM (SELECT length(identity_digest)+COALESCE(length(state_digest),0)+16 AS encoded FROM history_anchor_snapshot LIMIT ?1)",
        params![snapshot_limit],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    let maximum_bytes = u64::try_from(MAX_REGISTRY_ENTRIES)
        .ok()
        .and_then(|count| count.checked_mul(80))
        .ok_or(FloorApplicationError::InvalidInput("anchor snapshot byte bound"))?;
    if from_i64(snapshot_rows)? > MAX_REGISTRY_ENTRIES as u64 || from_i64(encoded_bytes)? > maximum_bytes {
        return Err(FloorApplicationError::CorruptState("anchor snapshot encoding"));
    }
    Ok(())
}

fn verify_anchor_binding(
    connection: &Connection,
    genesis: &FloorGenesis,
    anchor: &FinalizedHistoryAnchor,
) -> Result<Vec<(VaultIdentityDigest, Option<VaultCheckpoint>)>> {
    if anchor.chain_id() != genesis.chain_id()
        || anchor.genesis_digest() != genesis.genesis_digest()
        || anchor.profile_digest() != genesis.profile_digest()
    {
        return Err(FloorApplicationError::HistoryAnchorMismatch);
    }
    let snapshot = load_anchor_snapshot(connection)?;
    verify_state_entries(genesis, &snapshot)?;
    if digest_snapshot(&snapshot) != anchor.snapshot_digest() || state_root(&snapshot)? != anchor.state_root() {
        return Err(FloorApplicationError::HistoryAnchorMismatch);
    }
    let status = load_status(connection)?;
    if anchor.through_height() > status.last_height
        || (anchor.through_height() == status.last_height
            && (anchor.through_time_ms() != status.last_block_time_ms
                || anchor.through_app_hash() != status.last_app_hash))
    {
        return Err(FloorApplicationError::HistoryAnchorMismatch);
    }
    Ok(snapshot)
}

fn build_history_anchor_candidate(
    connection: &Connection,
    genesis: &FloorGenesis,
    prior_anchor: Option<&FinalizedHistoryAnchor>,
    through_height: u64,
) -> Result<HistoryAnchorCandidate> {
    let status = load_status(connection)?;
    let prior_height = prior_anchor.map_or(0, FinalizedHistoryAnchor::through_height);
    if through_height <= prior_height || through_height > status.last_height {
        return Err(FloorApplicationError::InvalidInput("history anchor height"));
    }
    let block = load_block(connection, genesis, through_height)?;
    let snapshot = load_state_at_height(connection, through_height)?;
    verify_state_entries(genesis, &snapshot)?;
    if state_root(&snapshot)? != block.state_root() || block.recompute_app_hash() != block.app_hash() {
        return Err(FloorApplicationError::HistoryAnchorMismatch);
    }
    HistoryAnchorCandidate::new(HistoryAnchorCandidateInput {
        chain_id: genesis.chain_id().clone(),
        genesis_digest: genesis.genesis_digest(),
        profile_digest: *genesis.profile_digest(),
        epoch: prior_anchor
            .map_or(0, FinalizedHistoryAnchor::epoch)
            .checked_add(1)
            .ok_or(FloorApplicationError::InvalidInput("history anchor epoch"))?,
        through_height,
        through_time_ms: block.block_time_ms(),
        previous_app_hash: block.previous_app_hash(),
        through_app_hash: block.app_hash(),
        state_root: block.state_root(),
        prior_anchor_digest: prior_anchor.map(FinalizedHistoryAnchor::anchor_digest),
        snapshot,
    })
}

fn build_bounded_history_anchor_candidate(
    connection: &Connection,
    genesis: &FloorGenesis,
    prior_anchor: Option<&FinalizedHistoryAnchor>,
    through_height: u64,
    limits: RestartTailLimits,
) -> Result<HistoryAnchorCandidate> {
    preflight_then_build(
        connection,
        prior_anchor.map_or(0, FinalizedHistoryAnchor::through_height),
        through_height,
        limits,
        || build_history_anchor_candidate(connection, genesis, prior_anchor, through_height),
    )
}

fn preflight_then_build<T>(
    connection: &Connection,
    after_height: u64,
    through_height: u64,
    limits: RestartTailLimits,
    build: impl FnOnce() -> Result<T>,
) -> Result<T> {
    preflight_compaction_range(connection, after_height, through_height, limits)?;
    build()
}

fn install_history_anchor(
    transaction: &Transaction<'_>,
    anchor: &FinalizedHistoryAnchor,
    snapshot: &[(VaultIdentityDigest, Option<VaultCheckpoint>)],
) -> Result<()> {
    transaction.execute("DELETE FROM history_anchor_snapshot", [])?;
    transaction.execute("DELETE FROM history_anchor", [])?;
    transaction.execute(
        "INSERT INTO history_anchor VALUES (1,?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13)",
        params![
            anchor.chain_id().as_bytes(),
            anchor.genesis_digest().as_bytes(),
            anchor.profile_digest(),
            to_i64(anchor.epoch())?,
            to_i64(anchor.through_height())?,
            to_i64(anchor.through_time_ms())?,
            anchor.previous_app_hash().as_bytes(),
            anchor.through_app_hash().as_bytes(),
            anchor.state_root().as_bytes(),
            anchor.snapshot_digest().as_bytes(),
            anchor.committing_header_hash(),
            anchor.prior_anchor_digest().map(|digest| digest.as_bytes().to_vec()),
            anchor.anchor_digest().as_bytes(),
        ],
    )?;
    for (ordinal, (identity, checkpoint)) in snapshot.iter().enumerate() {
        let (revision, digest) = checkpoint_columns(*checkpoint)?;
        transaction.execute(
            "INSERT INTO history_anchor_snapshot VALUES (?1,?2,?3,?4)",
            params![
                i64::try_from(ordinal).map_err(|_| FloorApplicationError::InvalidInput("anchor snapshot ordinal"))?,
                identity.as_bytes(),
                revision,
                digest,
            ],
        )?;
    }
    transaction.execute("UPDATE compaction_guard SET active=1 WHERE singleton=1", [])?;
    transaction.execute(
        "DELETE FROM block_results WHERE height<=?1",
        params![to_i64(anchor.through_height())?],
    )?;
    transaction.execute(
        "DELETE FROM floor_state_history WHERE height<=?1",
        params![to_i64(anchor.through_height())?],
    )?;
    transaction.execute(
        "DELETE FROM blocks WHERE height<=?1",
        params![to_i64(anchor.through_height())?],
    )?;
    transaction.execute("UPDATE compaction_guard SET active=0 WHERE singleton=1", [])?;
    Ok(())
}

fn has_history_through(connection: &Connection, height: u64) -> Result<bool> {
    connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM blocks WHERE height<=?1) OR EXISTS(SELECT 1 FROM block_results WHERE height<=?1) OR EXISTS(SELECT 1 FROM floor_state_history WHERE height<=?1)",
            params![to_i64(height)?],
            |row| row.get(0),
        )
        .map_err(FloorApplicationError::from)
}

fn load_history_usage(connection: &Connection, anchor_height: u64) -> Result<HistoryUsage> {
    let (blocks, results, deltas): (i64, i64, i64) = connection.query_row(
        "SELECT (SELECT COUNT(*) FROM blocks),(SELECT COUNT(*) FROM block_results),(SELECT COUNT(*) FROM floor_state_history)",
        [],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?;
    let live_bytes = sqlite_live_bytes(connection)?;
    Ok(HistoryUsage {
        anchor_height,
        retained_blocks: from_i64(blocks)?,
        retained_results: from_i64(results)?,
        retained_state_deltas: from_i64(deltas)?,
        retained_live_bytes: live_bytes,
        compaction_recommended: false,
    })
}

fn sqlite_live_bytes(connection: &Connection) -> Result<u64> {
    let page_count: i64 = connection.pragma_query_value(None, "page_count", |row| row.get(0))?;
    let freelist_count: i64 = connection.pragma_query_value(None, "freelist_count", |row| row.get(0))?;
    let page_size: i64 = connection.pragma_query_value(None, "page_size", |row| row.get(0))?;
    let live_pages = page_count
        .checked_sub(freelist_count)
        .ok_or(FloorApplicationError::CorruptState("SQLite live page count"))?;
    let live_bytes = live_pages
        .checked_mul(page_size)
        .ok_or(FloorApplicationError::CorruptState("SQLite live byte count"))?;
    from_i64(live_bytes).map_err(FloorApplicationError::from)
}

fn preflight_restart_tail(
    connection: &Connection,
    anchor_height: u64,
    limits: RestartTailLimits,
) -> Result<HistoryUsage> {
    let measure = capped_tail_measure(connection, limits)?;
    if measure.blocks > limits.blocks
        || measure.results > limits.results
        || measure.state_deltas > limits.state_deltas
        || measure.live_bytes > limits.live_bytes
        || measure.encoded_bytes > limits.encoded_bytes
    {
        return Err(FloorApplicationError::CompactionRequired {
            retained_blocks: measure.blocks,
            retained_results: measure.results,
            retained_state_deltas: measure.state_deltas,
            retained_live_bytes: measure.live_bytes,
        });
    }
    Ok(HistoryUsage {
        anchor_height,
        retained_blocks: measure.blocks,
        retained_results: measure.results,
        retained_state_deltas: measure.state_deltas,
        retained_live_bytes: measure.live_bytes,
        compaction_recommended: false,
    })
}

#[derive(Debug, Clone, Copy)]
struct TailMeasure {
    blocks: u64,
    results: u64,
    state_deltas: u64,
    live_bytes: u64,
    encoded_bytes: u64,
}

fn capped_tail_measure(connection: &Connection, limits: RestartTailLimits) -> Result<TailMeasure> {
    let block_limit = to_i64(
        limits
            .blocks
            .checked_add(1)
            .ok_or(FloorApplicationError::InvalidInput("block preflight bound"))?,
    )?;
    let result_limit = to_i64(
        limits
            .results
            .checked_add(1)
            .ok_or(FloorApplicationError::InvalidInput("result preflight bound"))?,
    )?;
    let delta_limit = to_i64(
        limits
            .state_deltas
            .checked_add(1)
            .ok_or(FloorApplicationError::InvalidInput("delta preflight bound"))?,
    )?;
    let (blocks, block_bytes): (i64, i64) = connection.query_row(
        "SELECT COUNT(*),COALESCE(SUM(encoded),0) FROM (SELECT length(previous_app_hash)+length(block_digest)+length(result_root)+length(state_root)+length(app_hash)+24 AS encoded FROM blocks LIMIT ?1)",
        params![block_limit],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    let (results, result_bytes): (i64, i64) = connection.query_row(
        "SELECT COUNT(*),COALESCE(SUM(encoded),0) FROM (SELECT length(identity_digest)+length(actor_key)+length(request_nonce)+length(request_digest)+COALESCE(length(expected_digest),0)+length(next_digest)+COALESCE(length(current_digest),0)+length(request_signature)+length(result_digest)+48 AS encoded FROM block_results LIMIT ?1)",
        params![result_limit],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    let (state_deltas, delta_bytes): (i64, i64) = connection.query_row(
        "SELECT COUNT(*),COALESCE(SUM(encoded),0) FROM (SELECT length(identity_digest)+length(state_digest)+16 AS encoded FROM floor_state_history LIMIT ?1)",
        params![delta_limit],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    let block_bytes = from_i64(block_bytes)?;
    let result_bytes = from_i64(result_bytes)?;
    let delta_bytes = from_i64(delta_bytes)?;
    let encoded_bytes = block_bytes
        .checked_add(result_bytes)
        .and_then(|value| value.checked_add(delta_bytes))
        .ok_or(FloorApplicationError::CorruptState("encoded history byte count"))?;
    Ok(TailMeasure {
        blocks: from_i64(blocks)?,
        results: from_i64(results)?,
        state_deltas: from_i64(state_deltas)?,
        live_bytes: sqlite_live_bytes(connection)?,
        encoded_bytes,
    })
}

fn preflight_compaction_range(
    connection: &Connection,
    after_height: u64,
    through_height: u64,
    limits: RestartTailLimits,
) -> Result<()> {
    if through_height <= after_height {
        return Err(FloorApplicationError::InvalidInput("compaction height range"));
    }
    let block_limit = to_i64(limits.blocks.saturating_add(1))?;
    let result_limit = to_i64(limits.results.saturating_add(1))?;
    let delta_limit = to_i64(limits.state_deltas.saturating_add(1))?;
    let after = to_i64(after_height)?;
    let through = to_i64(through_height)?;
    let (blocks, block_bytes): (i64, i64) = connection.query_row(
        "SELECT COUNT(*),COALESCE(SUM(encoded),0) FROM (SELECT length(previous_app_hash)+length(block_digest)+length(result_root)+length(state_root)+length(app_hash)+24 AS encoded FROM blocks WHERE height>?1 AND height<=?2 LIMIT ?3)",
        params![after, through, block_limit],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    let (results, result_bytes): (i64, i64) = connection.query_row(
        "SELECT COUNT(*),COALESCE(SUM(encoded),0) FROM (SELECT length(identity_digest)+length(actor_key)+length(request_nonce)+length(request_digest)+COALESCE(length(expected_digest),0)+length(next_digest)+COALESCE(length(current_digest),0)+length(request_signature)+length(result_digest)+48 AS encoded FROM block_results WHERE height>?1 AND height<=?2 LIMIT ?3)",
        params![after, through, result_limit],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    let (deltas, delta_bytes): (i64, i64) = connection.query_row(
        "SELECT COUNT(*),COALESCE(SUM(encoded),0) FROM (SELECT length(identity_digest)+length(state_digest)+16 AS encoded FROM floor_state_history WHERE height>?1 AND height<=?2 LIMIT ?3)",
        params![after, through, delta_limit],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    let blocks = from_i64(blocks)?;
    let results = from_i64(results)?;
    let deltas = from_i64(deltas)?;
    let block_bytes = from_i64(block_bytes)?;
    let result_bytes = from_i64(result_bytes)?;
    let delta_bytes = from_i64(delta_bytes)?;
    let encoded_bytes = block_bytes
        .checked_add(result_bytes)
        .and_then(|value| value.checked_add(delta_bytes))
        .ok_or(FloorApplicationError::CorruptState("compaction encoded bytes"))?;
    let live_bytes = sqlite_live_bytes(connection)?;
    if blocks > limits.blocks
        || results > limits.results
        || deltas > limits.state_deltas
        || encoded_bytes > limits.encoded_bytes
    {
        return Err(FloorApplicationError::CompactionRequired {
            retained_blocks: blocks,
            retained_results: results,
            retained_state_deltas: deltas,
            retained_live_bytes: live_bytes,
        });
    }
    Ok(())
}

fn load_previous_state_root(
    connection: &Connection,
    genesis: &FloorGenesis,
    anchor: Option<&FinalizedHistoryAnchor>,
    last_height: u64,
) -> Result<FloorStateRoot> {
    if last_height == 0 {
        let initial = genesis
            .entries()
            .iter()
            .map(|entry| (entry.identity_digest(), None))
            .collect::<Vec<_>>();
        return state_root(&initial);
    }
    if let Some(anchor) = anchor.filter(|anchor| anchor.through_height() == last_height) {
        return Ok(anchor.state_root());
    }
    connection
        .query_row(
            "SELECT state_root FROM blocks WHERE height=?1",
            params![to_i64(last_height)?],
            |row| Ok(FloorStateRoot::new(array32(row.get(0)?)?)),
        )
        .map_err(FloorApplicationError::from)
}

fn load_checkpoint(connection: &Connection, identity: VaultIdentityDigest) -> Result<Option<VaultCheckpoint>> {
    let row = connection
        .query_row(
            "SELECT revision,state_digest FROM floor_state WHERE identity_digest=?1",
            params![identity.as_bytes()],
            |row| Ok((row.get::<_, Option<i64>>(0)?, row.get::<_, Option<Vec<u8>>>(1)?)),
        )
        .optional()?;
    row.ok_or(FloorApplicationError::UnauthorizedActor)
        .and_then(|(revision, digest)| decode_checkpoint(revision, digest))
}

fn load_all_state(connection: &Connection) -> Result<Vec<(VaultIdentityDigest, Option<VaultCheckpoint>)>> {
    let mut statement = connection.prepare(
        "SELECT r.identity_digest,s.revision,s.state_digest FROM registry r JOIN floor_state s USING(identity_digest) ORDER BY r.ordinal LIMIT ?1",
    )?;
    let rows = statement
        .query_map(params![registry_decode_limit()?], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, Option<i64>>(1)?,
                row.get::<_, Option<Vec<u8>>>(2)?,
            ))
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    rows.into_iter()
        .map(|(identity, revision, digest)| {
            Ok((
                VaultIdentityDigest::new(array32(identity)?),
                decode_checkpoint(revision, digest)?,
            ))
        })
        .collect()
}

fn load_state_at_height(
    connection: &Connection,
    height: u64,
) -> Result<Vec<(VaultIdentityDigest, Option<VaultCheckpoint>)>> {
    let stored_height = to_i64(height)?;
    let anchor_height = connection
        .query_row(
            "SELECT through_height FROM history_anchor WHERE singleton=1",
            [],
            |row| row.get::<_, i64>(0),
        )
        .optional()?
        .map(from_i64)
        .transpose()?;
    if let Some(anchor_height) = anchor_height {
        if height < anchor_height {
            return Err(FloorApplicationError::HistoryPruned {
                requested_height: height,
                earliest_available: anchor_height
                    .checked_add(1)
                    .ok_or(FloorApplicationError::CorruptState("history anchor height"))?,
                anchor_height,
            });
        }
        if height == anchor_height {
            return load_anchor_snapshot(connection);
        }
    }
    let exists: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM blocks WHERE height=?1)",
        params![stored_height],
        |row| row.get(0),
    )?;
    if !exists {
        return Err(FloorApplicationError::CorruptState("missing state history block"));
    }
    let mut statement = connection.prepare(
        "SELECT r.identity_digest,CASE WHEN h.height IS NULL THEN a.revision ELSE h.revision END,CASE WHEN h.height IS NULL THEN a.state_digest ELSE h.state_digest END FROM registry r LEFT JOIN history_anchor_snapshot a ON a.identity_digest=r.identity_digest LEFT JOIN floor_state_history h ON h.identity_digest=r.identity_digest AND h.height=(SELECT MAX(h2.height) FROM floor_state_history h2 WHERE h2.identity_digest=r.identity_digest AND h2.height<=?1) ORDER BY r.ordinal LIMIT ?2",
    )?;
    let rows = statement
        .query_map(params![stored_height, registry_decode_limit()?], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, Option<i64>>(1)?,
                row.get::<_, Option<Vec<u8>>>(2)?,
            ))
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    rows.into_iter()
        .map(|(identity, revision, digest)| {
            Ok((
                VaultIdentityDigest::new(array32(identity)?),
                decode_checkpoint(revision, digest)?,
            ))
        })
        .collect()
}

fn load_state_deltas(connection: &Connection, height: u64) -> Result<BTreeMap<VaultIdentityDigest, VaultCheckpoint>> {
    let mut statement = connection.prepare(
        "SELECT identity_digest,revision,state_digest FROM floor_state_history WHERE height=?1 ORDER BY identity_digest LIMIT ?2",
    )?;
    let rows = statement
        .query_map(params![to_i64(height)?, registry_decode_limit()?], |row| {
            let identity = VaultIdentityDigest::new(array32(row.get(0)?)?);
            let checkpoint = decode_checkpoint(Some(row.get(1)?), Some(row.get(2)?))
                .map_err(to_sql_error)?
                .ok_or_else(|| to_sql_error(FloorApplicationError::CorruptState("state delta")))?;
            Ok((identity, checkpoint))
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let mut deltas = BTreeMap::new();
    for (identity, checkpoint) in rows {
        if deltas.insert(identity, checkpoint).is_some() {
            return Err(FloorApplicationError::CorruptState("duplicate state delta"));
        }
    }
    if deltas.len() > MAX_REGISTRY_ENTRIES {
        return Err(FloorApplicationError::CorruptState("state delta bound"));
    }
    Ok(deltas)
}

fn load_results_for_height(connection: &Connection, height: u64) -> Result<LoadedBlockResults> {
    let time: i64 = connection.query_row(
        "SELECT block_time_ms FROM blocks WHERE height=?1",
        params![to_i64(height)?],
        |row| row.get(0),
    )?;
    let mut statement = connection.prepare(
        "SELECT block_index,identity_digest,actor_key,request_nonce,request_digest,expected_revision,expected_digest,next_revision,next_digest,current_revision,current_digest,disposition,request_signature,result_digest FROM block_results WHERE height=?1 ORDER BY block_index LIMIT ?2",
    )?;
    let rows = statement
        .query_map(
            params![
                to_i64(height)?,
                i64::try_from(MAX_BLOCK_REQUESTS + 1)
                    .map_err(|_| FloorApplicationError::InvalidInput("result decode bound"))?
            ],
            |row| {
                let block_index = usize_from_i64(row.get(0)?)?;
                let identity = VaultIdentityDigest::new(array32(row.get(1)?)?);
                let actor = FloorOperatorKey::new(array32(row.get(2)?)?).map_err(to_sql_error)?;
                let nonce = ActorRequestNonce::new(array32(row.get(3)?)?).map_err(to_sql_error)?;
                let result = decode_result_row_offset(row, identity, actor, nonce, 4, 13)?;
                let signature = array64(row.get(12)?)?;
                Ok((block_index, result, signature))
            },
        )?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let mut results = Vec::with_capacity(rows.len());
    let mut signatures = Vec::with_capacity(rows.len());
    for (expected_index, (stored_index, result, signature)) in rows.into_iter().enumerate() {
        if expected_index != stored_index {
            return Err(FloorApplicationError::CorruptState("result index"));
        }
        results.push(result);
        signatures.push(signature);
    }
    Ok(LoadedBlockResults {
        time: from_i64(time)?,
        results,
        signatures,
    })
}

fn load_block(connection: &Connection, genesis: &FloorGenesis, height: u64) -> Result<ExecutedFloorBlock> {
    let row = connection.query_row(
        "SELECT block_time_ms,previous_app_hash,block_digest,result_root,state_root,app_hash,request_count FROM blocks WHERE height=?1",
        params![to_i64(height)?],
        |row| Ok((row.get::<_, i64>(0)?, row.get::<_, Vec<u8>>(1)?, row.get::<_, Vec<u8>>(2)?, row.get::<_, Vec<u8>>(3)?, row.get::<_, Vec<u8>>(4)?, row.get::<_, Vec<u8>>(5)?, row.get::<_, i64>(6)?)),
    )?;
    let stored_result_count = usize_from_i64(row.6)?;
    if stored_result_count > MAX_BLOCK_REQUESTS {
        return Err(FloorApplicationError::CorruptState("stored result bound"));
    }
    let loaded = load_results_for_height(connection, height)?;
    if loaded.time != from_i64(row.0)? {
        return Err(FloorApplicationError::CorruptState("result block time"));
    }
    if loaded.results.len() != stored_result_count {
        return Err(FloorApplicationError::CorruptState("result count"));
    }
    let previous_app_hash = FloorAppHash::new(array32(row.1)?);
    let mut signed_requests = Vec::with_capacity(loaded.results.len());
    for (result, signature) in loaded.results.iter().zip(&loaded.signatures) {
        let registry = genesis
            .entry(result.identity_digest())
            .ok_or(FloorApplicationError::CorruptState("result registry identity"))?;
        if registry.operator_key() != result.actor_key() {
            return Err(FloorApplicationError::CorruptState("stored result actor"));
        }
        let cas = FloorCasRequest::new(
            genesis.chain_id(),
            registry.identity(),
            result.expected(),
            result.next(),
        )
        .map_err(|_| FloorApplicationError::CorruptState("stored signed CAS"))?;
        let authorization =
            FloorCasAuthorization::new(cas, result.actor_key(), result.nonce(), height, previous_app_hash)
                .map_err(|_| FloorApplicationError::CorruptState("stored authorization"))?;
        if authorization.request_digest() != result.request_digest() {
            return Err(FloorApplicationError::CorruptState("stored request digest"));
        }
        signed_requests.push(
            authorization
                .authorize(*signature)
                .map_err(|_| FloorApplicationError::CorruptState("stored request signature"))?,
        );
    }
    let input = FloorBlockInput::new(
        genesis.chain_id().clone(),
        height,
        loaded.time,
        previous_app_hash,
        signed_requests,
    )
    .map_err(|_| FloorApplicationError::CorruptState("stored block input"))?;
    let stored_block_digest = FloorBlockDigest::new(array32(row.2)?);
    if input.block_digest() != stored_block_digest {
        return Err(FloorApplicationError::CorruptState("stored block digest"));
    }
    Ok(ExecutedFloorBlock::from_stored(StoredFloorBlock {
        chain_id: genesis.chain_id().clone(),
        genesis_digest: genesis.genesis_digest(),
        height,
        block_time_ms: loaded.time,
        previous_app_hash,
        block_digest: stored_block_digest,
        result_root: FloorResultRoot::new(array32(row.3)?),
        state_root: FloorStateRoot::new(array32(row.4)?),
        app_hash: FloorAppHash::new(array32(row.5)?),
        results: loaded.results,
    }))
}

fn decode_result_row_offset(
    row: &Row<'_>,
    identity: VaultIdentityDigest,
    actor: FloorOperatorKey,
    nonce: ActorRequestNonce,
    offset: usize,
    stored_digest_index: usize,
) -> rusqlite::Result<ExecutedFloorResult> {
    let request_digest = ActorRequestDigest::new(array32(row.get(offset)?)?);
    let expected = decode_checkpoint(row.get(offset + 1)?, row.get(offset + 2)?).map_err(to_sql_error)?;
    let next = decode_checkpoint(Some(row.get(offset + 3)?), Some(row.get(offset + 4)?))
        .map_err(to_sql_error)?
        .ok_or_else(|| to_sql_error(FloorApplicationError::CorruptState("next checkpoint")))?;
    let current = decode_checkpoint(row.get(offset + 5)?, row.get(offset + 6)?).map_err(to_sql_error)?;
    let disposition = decode_disposition(row.get(offset + 7)?).map_err(to_sql_error)?;
    let stored_digest = FloorResultDigest::new(array32(row.get(stored_digest_index)?)?);
    let result = ExecutedFloorResult::new(ExecutedFloorResultInput {
        identity_digest: identity,
        actor_key: actor,
        nonce,
        request_digest,
        expected,
        next,
        current,
        disposition,
    });
    if result.result_digest() != stored_digest {
        return Err(to_sql_error(FloorApplicationError::CorruptState("result digest")));
    }
    Ok(result)
}

fn checkpoint_columns(checkpoint: Option<VaultCheckpoint>) -> Result<(Option<i64>, Option<Vec<u8>>)> {
    checkpoint
        .map(|checkpoint| {
            Ok((
                Some(to_i64(checkpoint.revision().get())?),
                Some(checkpoint.state_digest().as_bytes().to_vec()),
            ))
        })
        .unwrap_or(Ok((None, None)))
}

fn decode_checkpoint(revision: Option<i64>, digest: Option<Vec<u8>>) -> Result<Option<VaultCheckpoint>> {
    match (revision, digest) {
        (None, None) => Ok(None),
        (Some(revision), Some(digest)) => Ok(Some(VaultCheckpoint::new(
            VaultRevision::new(from_i64(revision)?),
            VaultStateDigest::new(array32(digest)?),
        ))),
        _ => Err(FloorApplicationError::CorruptState("checkpoint columns")),
    }
}

fn disposition_tag(disposition: FloorCasDisposition) -> i64 {
    match disposition {
        FloorCasDisposition::Applied => 1,
        FloorCasDisposition::AlreadyCurrent => 2,
        FloorCasDisposition::Conflict => 3,
    }
}

fn decode_disposition(tag: i64) -> Result<FloorCasDisposition> {
    match tag {
        1 => Ok(FloorCasDisposition::Applied),
        2 => Ok(FloorCasDisposition::AlreadyCurrent),
        3 => Ok(FloorCasDisposition::Conflict),
        _ => Err(FloorApplicationError::CorruptState("CAS disposition")),
    }
}

fn rollback_error<T>(transaction: Transaction<'_>, error: FloorApplicationError) -> Result<T> {
    match transaction.rollback() {
        Ok(()) => Err(error),
        Err(rollback) => Err(FloorApplicationError::RollbackFailed {
            operation: error.to_string(),
            rollback,
        }),
    }
}

fn to_i64(value: u64) -> Result<i64> {
    i64::try_from(value).map_err(|_| FloorApplicationError::InvalidInput("integer exceeds SQLite range"))
}

fn registry_decode_limit() -> Result<i64> {
    i64::try_from(MAX_REGISTRY_ENTRIES + 1).map_err(|_| FloorApplicationError::InvalidInput("registry decode bound"))
}

fn from_i64(value: i64) -> rusqlite::Result<u64> {
    u64::try_from(value).map_err(|_| rusqlite::Error::IntegralValueOutOfRange(0, value))
}

fn usize_from_i64(value: i64) -> rusqlite::Result<usize> {
    usize::try_from(from_i64(value)?).map_err(|_| rusqlite::Error::IntegralValueOutOfRange(0, value))
}

fn array32(bytes: Vec<u8>) -> rusqlite::Result<[u8; 32]> {
    <[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| rusqlite::Error::InvalidQuery)
}

fn array64(bytes: Vec<u8>) -> rusqlite::Result<[u8; 64]> {
    <[u8; 64]>::try_from(bytes.as_slice()).map_err(|_| rusqlite::Error::InvalidQuery)
}

fn to_sql_error(error: FloorApplicationError) -> rusqlite::Error {
    rusqlite::Error::ToSqlConversionFailure(Box::new(error))
}

fn network_tag(network: Network) -> i64 {
    match network {
        Network::Regtest => 1,
        Network::Signet => 2,
        Network::Testnet => 3,
        Network::Mainnet => 4,
    }
}

fn role_tag(role: VaultRole) -> i64 {
    match role {
        VaultRole::Holder => 1,
        VaultRole::CommitteeMember => 2,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    fn oversized_history_connection() -> Connection {
        let connection = Connection::open_in_memory().expect("memory database");
        connection
            .execute_batch(
                "CREATE TABLE blocks(height INTEGER,previous_app_hash BLOB,block_digest BLOB,result_root BLOB,state_root BLOB,app_hash BLOB); CREATE TABLE block_results(height INTEGER,identity_digest BLOB,actor_key BLOB,request_nonce BLOB,request_digest BLOB,expected_digest BLOB,next_digest BLOB,current_digest BLOB,request_signature BLOB,result_digest BLOB); CREATE TABLE floor_state_history(height INTEGER,identity_digest BLOB,state_digest BLOB); INSERT INTO blocks VALUES (1,zeroblob(32),zeroblob(32),zeroblob(32),zeroblob(32),zeroblob(32)),(2,zeroblob(32),zeroblob(32),zeroblob(32),zeroblob(32),zeroblob(32));",
            )
            .expect("history shape");
        connection
    }

    #[test]
    fn restart_preflight_rejects_oversized_tail_before_replay() {
        let connection = oversized_history_connection();
        let error = preflight_restart_tail(
            &connection,
            0,
            RestartTailLimits {
                blocks: 1,
                results: 10,
                state_deltas: 10,
                live_bytes: u64::MAX,
                encoded_bytes: u64::MAX,
            },
        )
        .expect_err("oversized tail rejects");
        assert!(matches!(
            error,
            FloorApplicationError::CompactionRequired { retained_blocks: 2, .. }
        ));
    }

    #[test]
    fn oversized_prefix_rejects_before_snapshot_builder_runs() {
        let connection = oversized_history_connection();
        let builder_ran = Cell::new(false);
        let error = preflight_then_build(
            &connection,
            0,
            2,
            RestartTailLimits {
                blocks: 1,
                results: 10,
                state_deltas: 10,
                live_bytes: u64::MAX,
                encoded_bytes: u64::MAX,
            },
            || {
                builder_ran.set(true);
                Ok(())
            },
        )
        .expect_err("oversized prefix rejects");
        assert!(matches!(error, FloorApplicationError::CompactionRequired { .. }));
        assert!(!builder_ran.get());
    }
}
