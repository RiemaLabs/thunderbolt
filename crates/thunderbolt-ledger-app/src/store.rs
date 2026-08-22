use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};
use std::time::Duration;

use rusqlite::{params, Connection, OpenFlags, OptionalExtension, Transaction, TransactionBehavior};
use thunderbolt_ledger::{
    AppHashV2, ChannelContextIdV2, EntryHashV2, EntryMerkleProofV2, ExecutedBlockV2, ExecutedEntryMetadataV2,
    ExecutedEntryV2, LedgerChainIdV2, ParticipantIdV2, PendingBlockV2, RequestDigestV2, SignedProposalV2,
    MAX_BLOCK_ENTRIES, MAX_BLOCK_EVENT_BYTES,
};
use thunderbolt_protocol::v2::{
    ApplyDispositionV2, ChannelBindingV2, ChannelEventV2, ChannelSnapshotV2, ExternalVerifierV2, HistoryContextV2,
    ProtocolLimitsV2, StateHashV2, V2Reducer,
};

use crate::migrations;
use crate::{ApplicationError, Result, APPLICATION_VERSION_V2};

const DEFAULT_BUSY_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_BUSY_TIMEOUT: Duration = Duration::from_secs(60);
const DISPOSITION_APPLIED: i64 = 1;
const DISPOSITION_REPLAYED: i64 = 2;

/// Marker for deterministic proof verification used by the v2 application.
///
/// The underlying protocol trait receives typed authenticated entries and
/// immutable prior state. It returns only success or rejection; there is no
/// client-supplied evidence channel.
pub trait LedgerApplicationVerifierV2: ExternalVerifierV2 {}

impl<T: ExternalVerifierV2> LedgerApplicationVerifierV2 for T {}

/// Durable application settings fixed when a database is created.
#[derive(Debug, Clone)]
pub struct ApplicationOptions {
    /// Maximum SQLite lock wait, bounded to 60 seconds.
    pub busy_timeout: Duration,
    /// Deterministic version 2 reducer limits.
    pub protocol_limits: ProtocolLimitsV2,
    /// Immutable consensus-profile digest. ABCI deployments must set this to a
    /// digest covering verifier identity, deployment descriptor, reducer
    /// limits, and adapter resource policy.
    pub consensus_profile_digest: Option<[u8; 32]>,
}

impl Default for ApplicationOptions {
    fn default() -> Self {
        Self {
            busy_timeout: DEFAULT_BUSY_TIMEOUT,
            protocol_limits: ProtocolLimitsV2::default(),
            consensus_profile_digest: None,
        }
    }
}

/// One consensus-ordered block proposed to the application.
///
/// Height, time, prior application hash, and order must come from consensus.
/// This type has no local-clock constructor and carries no finality evidence.
#[derive(Clone, Debug)]
pub struct BlockInputV2 {
    ledger_chain_id: LedgerChainIdV2,
    height: u64,
    block_time_ms: u64,
    previous_app_hash: AppHashV2,
    proposals: Vec<SignedProposalV2>,
}

impl BlockInputV2 {
    /// Validates bounded block shape without running signature or proof checks.
    pub fn new(
        ledger_chain_id: LedgerChainIdV2,
        height: u64,
        block_time_ms: u64,
        previous_app_hash: AppHashV2,
        proposals: Vec<SignedProposalV2>,
    ) -> Result<Self> {
        let _ = PendingBlockV2::new(
            ledger_chain_id.clone(),
            height,
            block_time_ms,
            previous_app_hash.clone(),
        )?;
        if proposals.len() > MAX_BLOCK_ENTRIES {
            return Err(ApplicationError::InvalidOptions(
                "block proposal count exceeds the Ledger bound",
            ));
        }
        let event_bytes = proposals.iter().try_fold(0_usize, |total, proposal| {
            total
                .checked_add(proposal.body().event().as_bytes().len())
                .ok_or(ApplicationError::InvalidOptions("block event byte count overflow"))
        })?;
        if event_bytes > MAX_BLOCK_EVENT_BYTES {
            return Err(ApplicationError::InvalidOptions(
                "block event bytes exceed the Ledger bound",
            ));
        }
        Ok(Self {
            ledger_chain_id,
            height,
            block_time_ms,
            previous_app_hash,
            proposals,
        })
    }

    /// Returns the consensus Ledger chain ID.
    pub const fn ledger_chain_id(&self) -> &LedgerChainIdV2 {
        &self.ledger_chain_id
    }

    /// Returns the positive consensus height.
    pub const fn height(&self) -> u64 {
        self.height
    }

    /// Returns the positive consensus block time in Unix milliseconds.
    pub const fn block_time_ms(&self) -> u64 {
        self.block_time_ms
    }

    /// Returns the prior committed application hash.
    pub const fn previous_app_hash(&self) -> &AppHashV2 {
        &self.previous_app_hash
    }

    /// Returns signed proposals in consensus order.
    pub fn proposals(&self) -> &[SignedProposalV2] {
        &self.proposals
    }
}

/// Current durable application head, suitable for a future ABCI `Info` reply.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApplicationStatusV2 {
    application_version: u64,
    ledger_chain_id: LedgerChainIdV2,
    last_height: u64,
    last_block_time_ms: u64,
    last_app_hash: AppHashV2,
}

impl ApplicationStatusV2 {
    /// Returns the application version pinned by the v2 finality profile.
    pub const fn application_version(&self) -> u64 {
        self.application_version
    }

    /// Returns the configured consensus chain ID.
    pub const fn ledger_chain_id(&self) -> &LedgerChainIdV2 {
        &self.ledger_chain_id
    }

    /// Returns the last atomically executed height, or zero before InitChain.
    pub const fn last_height(&self) -> u64 {
        self.last_height
    }

    /// Returns the last consensus block time, or zero before the first block.
    pub const fn last_block_time_ms(&self) -> u64 {
        self.last_block_time_ms
    }

    /// Returns the application hash produced after `last_height`.
    ///
    /// In CometBFT this value is committed in the header at height
    /// `last_height + 1`.
    pub const fn last_app_hash(&self) -> &AppHashV2 {
        &self.last_app_hash
    }
}

/// Result of one atomic block execution or exact committed-block replay.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockExecutionOutcomeV2 {
    block: ExecutedBlockV2,
    replayed_block: bool,
    applied_entries: usize,
    replayed_entries: usize,
}

/// Bounded block input and exact outcome produced by rollback-only execution.
///
/// Values can only be created by [`LedgerApplication::preview_block`]. A later
/// commit re-runs the normal transaction path and compares the deterministic
/// block and disposition counts before allowing SQLite to commit.
#[derive(Clone, Debug)]
pub struct PreparedBlockV2 {
    input: BlockInputV2,
    outcome: BlockExecutionOutcomeV2,
}

impl PreparedBlockV2 {
    /// Returns the exact consensus input validated by the preview.
    pub const fn input(&self) -> &BlockInputV2 {
        &self.input
    }

    /// Returns the exact rollback-only execution outcome.
    pub const fn outcome(&self) -> &BlockExecutionOutcomeV2 {
        &self.outcome
    }
}

impl BlockExecutionOutcomeV2 {
    /// Returns deterministic execution output without promoting it to finality.
    pub const fn block(&self) -> &ExecutedBlockV2 {
        &self.block
    }

    /// Reports an exact retry of the already committed height.
    pub const fn replayed_block(&self) -> bool {
        self.replayed_block
    }

    /// Returns newly applied protocol transitions in the block.
    pub const fn applied_entries(&self) -> usize {
        self.applied_entries
    }

    /// Returns exact actor-request replays included in the block.
    pub const fn replayed_entries(&self) -> usize {
        self.replayed_entries
    }

    /// Returns the app hash that a future CometBFT header at `H + 1` commits
    /// after this application executes consensus height `H`.
    pub const fn app_hash_for_next_header(&self) -> &AppHashV2 {
        self.block.app_hash()
    }
}

/// Durable actor-scoped request mapping.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredRequestV2 {
    channel_context_id: ChannelContextIdV2,
    participant_id: ParticipantIdV2,
    request_digest: RequestDigestV2,
    entry_hash: EntryHashV2,
    first_height: u64,
    first_block_index: u32,
}

/// One channel lookup and the exact durable head observed in the same SQLite
/// read transaction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChannelHeadReadV2 {
    status: ApplicationStatusV2,
    channel: Option<ChannelSnapshotV2>,
}

impl ChannelHeadReadV2 {
    /// Returns the exact durable head paired with the lookup.
    pub const fn status(&self) -> &ApplicationStatusV2 {
        &self.status
    }

    /// Returns the channel snapshot present at that head, if any.
    pub const fn channel(&self) -> Option<&ChannelSnapshotV2> {
        self.channel.as_ref()
    }
}

/// One actor-request lookup and the exact durable head observed in the same
/// SQLite read transaction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RequestHeadReadV2 {
    status: ApplicationStatusV2,
    request: Option<StoredRequestV2>,
}

impl RequestHeadReadV2 {
    /// Returns the exact durable head paired with the lookup.
    pub const fn status(&self) -> &ApplicationStatusV2 {
        &self.status
    }

    /// Returns the request mapping present at that head, if any.
    pub const fn request(&self) -> Option<&StoredRequestV2> {
        self.request.as_ref()
    }
}

impl StoredRequestV2 {
    /// Returns the stable channel context.
    pub const fn channel_context_id(&self) -> &ChannelContextIdV2 {
        &self.channel_context_id
    }

    /// Returns the actor identity derived from its BIP340 key.
    pub const fn participant_id(&self) -> &ParticipantIdV2 {
        &self.participant_id
    }

    /// Returns the actor-scoped request digest.
    pub const fn request_digest(&self) -> &RequestDigestV2 {
        &self.request_digest
    }

    /// Returns the immutable entry hash named by this request.
    pub const fn entry_hash(&self) -> &EntryHashV2 {
        &self.entry_hash
    }

    /// Returns the first executed height for this request.
    pub const fn first_height(&self) -> u64 {
        self.first_height
    }

    /// Returns the first block position for this request.
    pub const fn first_block_index(&self) -> u32 {
        self.first_block_index
    }
}

/// Counts returned after durable structural integrity checks pass.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IntegrityReportV2 {
    /// Executed blocks checked.
    pub blocks: usize,
    /// Executed entries checked.
    pub entries: usize,
    /// Channel snapshots checked.
    pub channels: usize,
    /// Actor request mappings checked.
    pub requests: usize,
    /// Lifetime Invoice identifiers checked.
    pub invoices: usize,
}

/// Thread-safe, crash-safe v2 Ledger application.
pub struct LedgerApplication {
    path: PathBuf,
    chain_id: LedgerChainIdV2,
    reducer: V2Reducer,
    consensus_profile_digest: Option<[u8; 32]>,
    connection: Mutex<Connection>,
}

impl fmt::Debug for LedgerApplication {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LedgerApplication")
            .field("path", &self.path)
            .field("chain_id", &self.chain_id)
            .field("protocol_limits", &self.reducer.limits())
            .finish_non_exhaustive()
    }
}

impl LedgerApplication {
    /// Opens or creates one chain-scoped application database.
    pub fn open(path: impl AsRef<Path>, chain_id: LedgerChainIdV2, options: ApplicationOptions) -> Result<Self> {
        if options.busy_timeout.is_zero() || options.busy_timeout > MAX_BUSY_TIMEOUT {
            return Err(ApplicationError::InvalidOptions(
                "busy timeout must be positive and no more than 60 seconds",
            ));
        }
        let reducer = V2Reducer::new(chain_id.clone(), options.protocol_limits)?;
        let path = path.as_ref().to_path_buf();
        let flags =
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE | OpenFlags::SQLITE_OPEN_FULL_MUTEX;
        let mut connection = Connection::open_with_flags(&path, flags)?;
        connection.busy_timeout(options.busy_timeout)?;
        connection.pragma_update(None, "foreign_keys", true)?;
        migrations::migrate(
            &mut connection,
            &path,
            &chain_id,
            options.protocol_limits,
            options.consensus_profile_digest,
        )?;
        configure_durability(&connection, options.busy_timeout)?;
        validate_head(&connection, &chain_id)?;
        Ok(Self {
            path,
            chain_id,
            reducer,
            consensus_profile_digest: options.consensus_profile_digest,
            connection: Mutex::new(connection),
        })
    }

    /// Returns the configured application version.
    pub const fn application_version(&self) -> u64 {
        APPLICATION_VERSION_V2
    }

    /// Returns the configured Ledger chain ID.
    pub const fn ledger_chain_id(&self) -> &LedgerChainIdV2 {
        &self.chain_id
    }

    /// Returns the reducer limits bound into the durable application identity.
    pub const fn protocol_limits(&self) -> ProtocolLimitsV2 {
        self.reducer.limits()
    }

    /// Returns the immutable consensus-profile digest, if this application was
    /// created for a consensus adapter.
    pub const fn consensus_profile_digest(&self) -> Option<&[u8; 32]> {
        self.consensus_profile_digest.as_ref()
    }

    /// Returns the current durable execution head.
    pub fn status(&self) -> Result<ApplicationStatusV2> {
        let connection = self.lock_connection()?;
        load_head(&connection).map(|head| head.status)
    }

    /// Atomically verifies, reduces, executes, and persists one ordered block.
    ///
    /// The application reserves every new actor request inside the SQLite
    /// writer transaction before BIP340 and external proof verification. Any
    /// later rejection rolls the reservation and every block effect back.
    pub fn apply_block<V: LedgerApplicationVerifierV2>(
        &self,
        input: BlockInputV2,
        verifier: &V,
    ) -> Result<BlockExecutionOutcomeV2> {
        let mut connection = self.lock_connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let result = apply_block_locked(&transaction, &self.reducer, &self.chain_id, input, verifier);
        finish_transaction(transaction, result)
    }

    /// Executes the exact normal block path inside a rollback-only transaction.
    ///
    /// This performs request reservation, signatures, external proof hooks,
    /// reduction, every SQLite write, and deterministic block construction. It
    /// always rolls the transaction back, including after success, and returns
    /// a bounded prepared value that cannot be constructed by callers.
    pub fn preview_block<V: LedgerApplicationVerifierV2>(
        &self,
        input: BlockInputV2,
        verifier: &V,
    ) -> Result<PreparedBlockV2> {
        let mut connection = self.lock_connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let saved_input = input.clone();
        let result = apply_block_locked(&transaction, &self.reducer, &self.chain_id, input, verifier).map(|outcome| {
            PreparedBlockV2 {
                input: saved_input,
                outcome,
            }
        });
        rollback_preview(transaction, result)
    }

    /// Atomically previews one next-height mempool candidate against the exact
    /// current durable head.
    ///
    /// The synthetic admission time is the current committed time, or one
    /// millisecond for an empty genesis head. Final proposal processing must
    /// still repeat verification at the actual consensus time. Head loading,
    /// input construction, reservation, reduction, and rollback all occur
    /// under one SQLite writer transaction, so a concurrent commit cannot race
    /// the admission check.
    pub fn preview_next_block_for_admission<V: LedgerApplicationVerifierV2>(
        &self,
        proposals: Vec<SignedProposalV2>,
        verifier: &V,
    ) -> Result<PreparedBlockV2> {
        let mut connection = self.lock_connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let result = (|| {
            let head = load_head(&transaction)?;
            let height = head
                .status
                .last_height()
                .checked_add(1)
                .ok_or(ApplicationError::IntegerRange("admission block height"))?;
            let input = BlockInputV2::new(
                self.chain_id.clone(),
                height,
                head.status.last_block_time_ms().max(1),
                head.status.last_app_hash().clone(),
                proposals,
            )?;
            let saved_input = input.clone();
            let outcome = apply_block_locked(&transaction, &self.reducer, &self.chain_id, input, verifier)?;
            Ok(PreparedBlockV2 {
                input: saved_input,
                outcome,
            })
        })();
        rollback_preview(transaction, result)
    }

    /// Re-executes and atomically commits one rollback-only prepared block.
    ///
    /// The transaction is committed only if its deterministic executed block,
    /// application hash, and applied/replayed counts match the preview. Exact
    /// replay of a block already committed before a lost response is accepted;
    /// the replay marker itself is not application state.
    pub fn commit_prepared_block<V: LedgerApplicationVerifierV2>(
        &self,
        prepared: PreparedBlockV2,
        verifier: &V,
    ) -> Result<BlockExecutionOutcomeV2> {
        let mut connection = self.lock_connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let expected = prepared.outcome;
        let result = apply_block_locked(&transaction, &self.reducer, &self.chain_id, prepared.input, verifier)
            .and_then(|actual| {
                if actual.block() != expected.block()
                    || actual.applied_entries() != expected.applied_entries()
                    || actual.replayed_entries() != expected.replayed_entries()
                {
                    return Err(ApplicationError::PreparedBlockMismatch);
                }
                Ok(actual)
            });
        finish_transaction(transaction, result)
    }

    /// Loads one deterministic executed block by height.
    pub fn block(&self, height: u64) -> Result<Option<ExecutedBlockV2>> {
        let height = to_sql_u64("block height", height)?;
        let connection = self.lock_connection()?;
        load_block(&connection, height)
    }

    /// Loads one materialized channel snapshot by stable binding.
    pub fn channel(&self, binding: &ChannelBindingV2) -> Result<Option<ChannelSnapshotV2>> {
        let context = ChannelContextIdV2::from_bytes(binding.context_id()?)?;
        self.channel_by_context(&context)
    }

    /// Loads one materialized channel snapshot by context ID.
    pub fn channel_by_context(&self, context: &ChannelContextIdV2) -> Result<Option<ChannelSnapshotV2>> {
        let connection = self.lock_connection()?;
        load_channel(&connection, context.as_bytes()).map(|loaded| loaded.map(|channel| channel.snapshot))
    }

    /// Loads one channel and its exact durable head in a single rollback-only
    /// SQLite read transaction.
    pub fn channel_at_head(&self, context: &ChannelContextIdV2) -> Result<ChannelHeadReadV2> {
        let mut connection = self.lock_connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
        let result = (|| {
            let status = load_status(&transaction)?;
            let channel = load_channel(&transaction, context.as_bytes())?.map(|loaded| loaded.snapshot);
            Ok(ChannelHeadReadV2 { status, channel })
        })();
        rollback_preview(transaction, result)
    }

    /// Loads one durable actor-scoped request mapping.
    pub fn request(
        &self,
        channel: &ChannelContextIdV2,
        participant: &ParticipantIdV2,
        request: &RequestDigestV2,
    ) -> Result<Option<StoredRequestV2>> {
        let connection = self.lock_connection()?;
        load_request(
            &connection,
            channel.as_bytes(),
            participant.as_bytes(),
            request.as_bytes(),
        )
    }

    /// Loads one actor request and its exact durable head in a single
    /// rollback-only SQLite read transaction.
    pub fn request_at_head(
        &self,
        channel: &ChannelContextIdV2,
        participant: &ParticipantIdV2,
        request: &RequestDigestV2,
    ) -> Result<RequestHeadReadV2> {
        let mut connection = self.lock_connection()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
        let result = (|| {
            let status = load_status(&transaction)?;
            let request = load_request(
                &transaction,
                channel.as_bytes(),
                participant.as_bytes(),
                request.as_bytes(),
            )?;
            Ok(RequestHeadReadV2 { status, request })
        })();
        rollback_preview(transaction, result)
    }

    /// Generates an ordered inclusion proof from a stored executed block.
    ///
    /// The proof is execution evidence only and carries no consensus receipt.
    pub fn entry_proof(&self, height: u64, block_index: usize) -> Result<EntryMerkleProofV2> {
        let block = self
            .block(height)?
            .ok_or_else(|| ApplicationError::CorruptData(format!("executed block {height} does not exist")))?;
        block.entry_proof(block_index).map_err(ApplicationError::from)
    }

    /// Checks schema metadata, executed-block continuity, and durable indexes.
    ///
    /// This does not re-run external proof verification and is not a finality
    /// check.
    pub fn integrity_check(&self) -> Result<IntegrityReportV2> {
        let connection = self.lock_connection()?;
        integrity_check_locked(&connection, &self.chain_id)
    }

    fn lock_connection(&self) -> Result<MutexGuard<'_, Connection>> {
        self.connection.lock().map_err(|_| ApplicationError::LockPoisoned)
    }
}

#[derive(Debug)]
struct DurableHead {
    status: ApplicationStatusV2,
    last_block: Option<ExecutedBlockV2>,
}

#[derive(Debug, Clone)]
struct LoadedChannel {
    snapshot: ChannelSnapshotV2,
    metadata: ExecutedEntryMetadataV2,
}

#[derive(Debug)]
struct WorkingChannel {
    snapshot: Option<ChannelSnapshotV2>,
    metadata: Option<ExecutedEntryMetadataV2>,
    seen: bool,
    replay_seen: bool,
    last_applied_index: Option<usize>,
}

#[derive(Debug)]
struct StagedEntry {
    event: ChannelEventV2,
    snapshot_after: ChannelSnapshotV2,
    disposition: ApplyDispositionV2,
}

fn apply_block_locked<V: LedgerApplicationVerifierV2>(
    transaction: &Transaction<'_>,
    reducer: &V2Reducer,
    chain_id: &LedgerChainIdV2,
    input: BlockInputV2,
    verifier: &V,
) -> Result<BlockExecutionOutcomeV2> {
    migrations::verify_current(transaction)?;
    if input.ledger_chain_id() != chain_id {
        return Err(ApplicationError::LedgerChainMismatch);
    }
    let head = load_head(transaction)?;
    if input.height() == head.status.last_height() && input.height() > 0 {
        let existing = head
            .last_block
            .ok_or_else(|| ApplicationError::CorruptData("application head has no executed block".to_owned()))?;
        if block_matches_input(&existing, &input) {
            let (applied_entries, replayed_entries) = load_disposition_counts(transaction, input.height())?;
            return Ok(BlockExecutionOutcomeV2 {
                block: existing,
                replayed_block: true,
                applied_entries,
                replayed_entries,
            });
        }
        return Err(ApplicationError::BlockConflict { height: input.height() });
    }
    if input.height() < head.status.last_height() {
        return Err(ApplicationError::StaleHeight {
            current: head.status.last_height(),
            found: input.height(),
        });
    }
    let expected_height = head
        .status
        .last_height()
        .checked_add(1)
        .ok_or(ApplicationError::IntegerRange("block height"))?;
    if input.height() != expected_height {
        return Err(ApplicationError::HeightGap {
            expected: expected_height,
            found: input.height(),
        });
    }
    if input.previous_app_hash() != head.status.last_app_hash() {
        return Err(ApplicationError::AppHashMismatch);
    }
    if input.block_time_ms() < head.status.last_block_time_ms() {
        return Err(ApplicationError::BlockTimeRegression {
            previous_ms: head.status.last_block_time_ms(),
            proposed_ms: input.block_time_ms(),
        });
    }

    let mut pending = PendingBlockV2::new(
        input.ledger_chain_id.clone(),
        input.height,
        input.block_time_ms,
        input.previous_app_hash.clone(),
    )?;
    pending.validate_previous_block_time(if head.status.last_height() == 0 {
        None
    } else {
        Some(head.status.last_block_time_ms())
    })?;
    if let Some(previous) = head.last_block.as_ref() {
        pending.validate_successor(previous)?;
    }

    let mut channels: BTreeMap<Vec<u8>, WorkingChannel> = BTreeMap::new();
    let mut staged = Vec::with_capacity(input.proposals.len());
    for (index, proposal) in input.proposals.iter().enumerate() {
        let body = proposal.body();
        body.validate_chain_id(chain_id)?;
        let channel_context = ChannelContextIdV2::from_bytes(body.channel().context_id()?)?;
        let participant = body.participant_id()?;
        let request_digest = body.request_id().digest().clone();
        let entry_hash = body.entry_hash()?;
        let existing_request = lookup_request_hash(
            transaction,
            channel_context.as_bytes(),
            participant.as_bytes(),
            request_digest.as_bytes(),
        )?;
        if existing_request
            .as_ref()
            .is_some_and(|existing| existing != &entry_hash)
        {
            return Err(ApplicationError::RequestConflict);
        }
        if existing_request.is_none() {
            insert_request_mapping(
                transaction,
                &channel_context,
                &participant,
                &request_digest,
                &entry_hash,
                input.height(),
                index,
            )?;
        }

        let key = channel_context.as_bytes().to_vec();
        if !channels.contains_key(&key) {
            let loaded = load_channel(transaction, channel_context.as_bytes())?;
            channels.insert(
                key.clone(),
                WorkingChannel {
                    snapshot: loaded.as_ref().map(|value| value.snapshot.clone()),
                    metadata: loaded.map(|value| value.metadata),
                    seen: false,
                    replay_seen: false,
                    last_applied_index: None,
                },
            );
        }
        let working = channels
            .get_mut(&key)
            .ok_or_else(|| ApplicationError::CorruptData("working channel disappeared".to_owned()))?;
        let exact_replay = existing_request.is_some();
        if working.seen && (working.replay_seen || exact_replay) {
            return Err(ApplicationError::MixedReplayChain);
        }
        if !working.seen && !exact_replay {
            body.validate_predecessor(working.metadata.as_ref())?;
        }
        working.seen = true;
        working.replay_seen |= exact_replay;

        // Request reservation above intentionally precedes both signature and
        // operation-specific proof verification. A rejection rolls it back.
        proposal.verify()?;
        pending.push(proposal.clone())?;
        let event = ChannelEventV2::from_canonical_bytes(body.event().as_bytes())?;
        let consensus = thunderbolt_protocol::v2::ConsensusEntryV2::from_pending_block(&pending, index, &event)?;
        let invoice_used = match event.created_invoice_id() {
            Some(invoice_id) => invoice_id_used(transaction, channel_context.as_bytes(), invoice_id.as_bytes())?,
            None => false,
        };
        let history = HistoryContextV2::new(existing_request.clone(), invoice_used);
        let reduction = reducer.apply(working.snapshot.as_ref(), &consensus, history, verifier)?;
        if reduction.disposition == ApplyDispositionV2::Applied {
            if exact_replay {
                return Err(ApplicationError::CorruptData(
                    "durable request mapping reduced as a new entry".to_owned(),
                ));
            }
            if let Some(invoice_id) = event.created_invoice_id() {
                insert_invoice_history(
                    transaction,
                    channel_context.as_bytes(),
                    invoice_id.as_bytes(),
                    &entry_hash,
                    input.height(),
                    index,
                )?;
            }
            working.snapshot = Some(reduction.snapshot.clone());
            working.last_applied_index = Some(index);
        } else if !exact_replay {
            return Err(ApplicationError::CorruptData(
                "fresh request mapping reduced as a replay".to_owned(),
            ));
        }
        staged.push(StagedEntry {
            event,
            snapshot_after: reduction.snapshot,
            disposition: reduction.disposition,
        });
    }

    let executed = pending.execute()?;
    if executed.entries().len() != staged.len() {
        return Err(ApplicationError::CorruptData(
            "executed entry count differs from reduced entry count".to_owned(),
        ));
    }
    persist_block(transaction, &executed)?;
    let mut applied_entries = 0_usize;
    let mut replayed_entries = 0_usize;
    for (index, stage) in staged.iter().enumerate() {
        let executed_entry = executed
            .entries()
            .get(index)
            .ok_or_else(|| ApplicationError::CorruptData("executed entry index disappeared".to_owned()))?;
        persist_entry(transaction, executed_entry, stage)?;
        match stage.disposition {
            ApplyDispositionV2::Applied => applied_entries = applied_entries.saturating_add(1),
            ApplyDispositionV2::Replay => replayed_entries = replayed_entries.saturating_add(1),
        }
    }
    for (key, working) in channels {
        let Some(index) = working.last_applied_index else {
            continue;
        };
        let snapshot = working
            .snapshot
            .ok_or_else(|| ApplicationError::CorruptData("applied channel has no snapshot".to_owned()))?;
        let executed_entry = executed
            .entries()
            .get(index)
            .ok_or_else(|| ApplicationError::CorruptData("channel metadata index disappeared".to_owned()))?;
        persist_channel(transaction, &key, &snapshot, executed_entry)?;
    }
    update_head(transaction, &executed)?;
    Ok(BlockExecutionOutcomeV2 {
        block: executed,
        replayed_block: false,
        applied_entries,
        replayed_entries,
    })
}

fn block_matches_input(block: &ExecutedBlockV2, input: &BlockInputV2) -> bool {
    block.ledger_chain_id() == input.ledger_chain_id()
        && block.height() == input.height()
        && block.block_time_ms() == input.block_time_ms()
        && block.previous_app_hash() == input.previous_app_hash()
        && block.entries().len() == input.proposals().len()
        && block
            .entries()
            .iter()
            .zip(input.proposals())
            .all(|(entry, proposal)| entry.proposal() == proposal)
}

fn load_status(connection: &Connection) -> Result<ApplicationStatusV2> {
    let row: (i64, String, i64, i64, Vec<u8>) = connection.query_row(
        "SELECT application_version, ledger_chain_id, last_height,
                last_block_time_ms, last_app_hash
         FROM application_state WHERE singleton = 1",
        [],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)),
    )?;
    let application_version =
        u64::try_from(row.0).map_err(|_| ApplicationError::CorruptData("negative application version".to_owned()))?;
    if application_version != APPLICATION_VERSION_V2 {
        return Err(ApplicationError::CorruptData(
            "stored application version changed".to_owned(),
        ));
    }
    Ok(ApplicationStatusV2 {
        application_version,
        ledger_chain_id: durable_value("stored Ledger chain id", LedgerChainIdV2::new(row.1))?,
        last_height: from_sql_u64("last height", row.2)?,
        last_block_time_ms: from_sql_u64("last block time", row.3)?,
        last_app_hash: durable_value(
            "stored last application hash",
            AppHashV2::from_bytes(blob_32("last app hash", row.4)?),
        )?,
    })
}

fn load_head(connection: &Connection) -> Result<DurableHead> {
    let status = load_status(connection)?;
    let last_block = if status.last_height() == 0 {
        None
    } else {
        load_block(connection, to_sql_u64("last height", status.last_height())?)?
            .ok_or_else(|| ApplicationError::CorruptData("application head block is missing".to_owned()))?
            .into()
    };
    let head = DurableHead { status, last_block };
    validate_loaded_head(&head)?;
    Ok(head)
}

fn load_block(connection: &Connection, height: i64) -> Result<Option<ExecutedBlockV2>> {
    let bytes: Option<Vec<u8>> = connection
        .query_row(
            "SELECT executed_block_json FROM blocks WHERE height = ?1",
            [height],
            |row| row.get(0),
        )
        .optional()?;
    bytes.map(|value| decode_json(&value, "executed block")).transpose()
}

fn load_channel(connection: &Connection, context: &[u8; 32]) -> Result<Option<LoadedChannel>> {
    let row: Option<(Vec<u8>, Vec<u8>)> = connection
        .query_row(
            "SELECT snapshot_json, last_entry_json
             FROM channel_snapshots WHERE channel_context_id = ?1",
            [context.as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    row.map(|(snapshot, executed_entry)| {
        let snapshot: ChannelSnapshotV2 = decode_json(&snapshot, "channel snapshot")?;
        durable_value("stored channel snapshot", snapshot.validate())?;
        let executed_entry: ExecutedEntryV2 = decode_json(&executed_entry, "executed entry")?;
        Ok(LoadedChannel {
            snapshot,
            metadata: executed_entry.metadata().clone(),
        })
    })
    .transpose()
}

fn load_request(
    connection: &Connection,
    channel: &[u8; 32],
    participant: &[u8; 32],
    request: &[u8; 32],
) -> Result<Option<StoredRequestV2>> {
    let row: Option<(Vec<u8>, i64, i64)> = connection
        .query_row(
            "SELECT entry_hash, first_height, first_block_index
             FROM request_index
             WHERE channel_context_id = ?1 AND participant_id = ?2 AND request_digest = ?3",
            params![channel.as_slice(), participant.as_slice(), request.as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()?;
    row.map(|(entry_hash, height, index)| {
        Ok(StoredRequestV2 {
            channel_context_id: durable_value(
                "stored request channel context",
                ChannelContextIdV2::from_bytes(channel),
            )?,
            participant_id: durable_value("stored request participant", ParticipantIdV2::from_bytes(participant))?,
            request_digest: durable_value("stored request digest", RequestDigestV2::from_bytes(request))?,
            entry_hash: durable_value(
                "stored request entry hash",
                EntryHashV2::from_bytes(blob_32("request entry hash", entry_hash)?),
            )?,
            first_height: from_sql_u64("request height", height)?,
            first_block_index: from_sql_u32("request block index", index)?,
        })
    })
    .transpose()
}

fn lookup_request_hash(
    connection: &Connection,
    channel: &[u8; 32],
    participant: &[u8; 32],
    request: &[u8; 32],
) -> Result<Option<EntryHashV2>> {
    let bytes: Option<Vec<u8>> = connection
        .query_row(
            "SELECT entry_hash FROM request_index
             WHERE channel_context_id = ?1 AND participant_id = ?2 AND request_digest = ?3",
            params![channel.as_slice(), participant.as_slice(), request.as_slice()],
            |row| row.get(0),
        )
        .optional()?;
    bytes
        .map(|value| {
            durable_value(
                "stored request entry hash",
                EntryHashV2::from_bytes(blob_32("request entry hash", value)?),
            )
        })
        .transpose()
}

fn insert_request_mapping(
    connection: &Connection,
    channel: &ChannelContextIdV2,
    participant: &ParticipantIdV2,
    request: &RequestDigestV2,
    entry_hash: &EntryHashV2,
    height: u64,
    index: usize,
) -> Result<()> {
    connection.execute(
        "INSERT INTO request_index(
             channel_context_id, participant_id, request_digest, entry_hash,
             first_height, first_block_index
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            channel.as_bytes().as_slice(),
            participant.as_bytes().as_slice(),
            request.as_bytes().as_slice(),
            entry_hash.as_bytes().as_slice(),
            to_sql_u64("request height", height)?,
            to_sql_usize("request block index", index)?,
        ],
    )?;
    Ok(())
}

fn invoice_id_used(connection: &Connection, channel: &[u8; 32], invoice_id: &[u8]) -> Result<bool> {
    connection
        .query_row(
            "SELECT EXISTS(
                 SELECT 1 FROM invoice_history
                 WHERE channel_context_id = ?1 AND invoice_id = ?2
             )",
            params![channel.as_slice(), invoice_id],
            |row| row.get(0),
        )
        .map_err(ApplicationError::from)
}

fn insert_invoice_history(
    connection: &Connection,
    channel: &[u8; 32],
    invoice_id: &[u8],
    entry_hash: &EntryHashV2,
    height: u64,
    index: usize,
) -> Result<()> {
    connection.execute(
        "INSERT INTO invoice_history(
             channel_context_id, invoice_id, entry_hash,
             committed_height, committed_block_index
         ) VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            channel.as_slice(),
            invoice_id,
            entry_hash.as_bytes().as_slice(),
            to_sql_u64("Invoice height", height)?,
            to_sql_usize("Invoice block index", index)?,
        ],
    )?;
    Ok(())
}

fn persist_block(connection: &Connection, block: &ExecutedBlockV2) -> Result<()> {
    let block_json = serde_json::to_vec(block)?;
    connection.execute(
        "INSERT INTO blocks(
             height, block_time_ms, previous_app_hash, app_hash,
             entry_count, executed_block_json
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            to_sql_u64("block height", block.height())?,
            to_sql_u64("block time", block.block_time_ms())?,
            block.previous_app_hash().as_bytes().as_slice(),
            block.app_hash().as_bytes().as_slice(),
            to_sql_usize("block entry count", block.entries().len())?,
            block_json,
        ],
    )?;
    Ok(())
}

fn persist_entry(connection: &Connection, entry: &ExecutedEntryV2, stage: &StagedEntry) -> Result<()> {
    let metadata = entry.metadata();
    let state_hash = stage.snapshot_after.state_hash()?;
    let disposition = match stage.disposition {
        ApplyDispositionV2::Applied => DISPOSITION_APPLIED,
        ApplyDispositionV2::Replay => DISPOSITION_REPLAYED,
    };
    connection.execute(
        "INSERT INTO executed_entries(
             height, block_index, channel_context_id, participant_id,
             request_digest, entry_hash, disposition, canonical_event,
             executed_entry_json, state_hash_after
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        params![
            to_sql_u64("entry height", metadata.block_height())?,
            i64::from(metadata.block_index()),
            metadata.channel_context_id().as_bytes().as_slice(),
            metadata.participant_id().as_bytes().as_slice(),
            metadata.request_digest().as_bytes().as_slice(),
            metadata.entry_hash().as_bytes().as_slice(),
            disposition,
            stage.event.canonical_bytes()?,
            serde_json::to_vec(entry)?,
            state_hash.as_bytes().as_slice(),
        ],
    )?;
    Ok(())
}

fn persist_channel(
    connection: &Connection,
    context: &[u8],
    snapshot: &ChannelSnapshotV2,
    executed_entry: &ExecutedEntryV2,
) -> Result<()> {
    let metadata = executed_entry.metadata();
    let state_hash = snapshot.state_hash()?;
    connection.execute(
        "INSERT INTO channel_snapshots(
             channel_context_id, snapshot_json, state_hash, last_entry_json,
             updated_height, updated_block_index
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)
         ON CONFLICT(channel_context_id) DO UPDATE SET
             snapshot_json = excluded.snapshot_json,
             state_hash = excluded.state_hash,
             last_entry_json = excluded.last_entry_json,
             updated_height = excluded.updated_height,
             updated_block_index = excluded.updated_block_index",
        params![
            context,
            serde_json::to_vec(snapshot)?,
            state_hash.as_bytes().as_slice(),
            serde_json::to_vec(executed_entry)?,
            to_sql_u64("channel height", metadata.block_height())?,
            i64::from(metadata.block_index()),
        ],
    )?;
    Ok(())
}

fn update_head(connection: &Connection, block: &ExecutedBlockV2) -> Result<()> {
    let changed = connection.execute(
        "UPDATE application_state SET
             last_height = ?1,
             last_block_time_ms = ?2,
             last_app_hash = ?3,
             last_block_json = ?4
         WHERE singleton = 1 AND last_height = ?5",
        params![
            to_sql_u64("head height", block.height())?,
            to_sql_u64("head block time", block.block_time_ms())?,
            block.app_hash().as_bytes().as_slice(),
            serde_json::to_vec(block)?,
            to_sql_u64("previous head height", block.height().saturating_sub(1))?,
        ],
    )?;
    if changed != 1 {
        return Err(ApplicationError::CorruptData(
            "application head changed during locked execution".to_owned(),
        ));
    }
    Ok(())
}

fn load_disposition_counts(connection: &Connection, height: u64) -> Result<(usize, usize)> {
    let row: (i64, i64) = connection.query_row(
        "SELECT
             COALESCE(SUM(CASE WHEN disposition = 1 THEN 1 ELSE 0 END), 0),
             COALESCE(SUM(CASE WHEN disposition = 2 THEN 1 ELSE 0 END), 0)
         FROM executed_entries WHERE height = ?1",
        [to_sql_u64("block height", height)?],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    Ok((
        from_sql_usize("applied entry count", row.0)?,
        from_sql_usize("replayed entry count", row.1)?,
    ))
}

fn validate_head(connection: &Connection, chain_id: &LedgerChainIdV2) -> Result<()> {
    let head = load_head(connection)?;
    if head.status.ledger_chain_id() != chain_id {
        return Err(ApplicationError::ConfigurationMismatch);
    }
    Ok(())
}

fn validate_loaded_head(head: &DurableHead) -> Result<()> {
    match (head.status.last_height(), head.last_block.as_ref()) {
        (0, None) if head.status.last_block_time_ms() == 0 && head.status.last_app_hash().is_zero() => Ok(()),
        (0, _) => Err(ApplicationError::CorruptData(
            "genesis application state has block data".to_owned(),
        )),
        (_, Some(block))
            if block.height() == head.status.last_height()
                && block.block_time_ms() == head.status.last_block_time_ms()
                && block.app_hash() == head.status.last_app_hash() =>
        {
            Ok(())
        }
        _ => Err(ApplicationError::CorruptData(
            "application head does not match its last executed block".to_owned(),
        )),
    }
}

fn integrity_check_locked(connection: &Connection, chain_id: &LedgerChainIdV2) -> Result<IntegrityReportV2> {
    migrations::verify_current(connection)?;
    let integrity: String = connection.pragma_query_value(None, "integrity_check", |row| row.get(0))?;
    if integrity != "ok" {
        return Err(ApplicationError::CorruptData(format!(
            "SQLite integrity check returned {integrity}"
        )));
    }
    let mut previous: Option<ExecutedBlockV2> = None;
    let mut expected_entries: BTreeMap<(u64, u32), ExecutedEntryV2> = BTreeMap::new();
    let mut blocks = 0_usize;
    let mut entries = 0_usize;
    let mut statement = connection.prepare("SELECT executed_block_json FROM blocks ORDER BY height")?;
    let mut rows = statement.query([])?;
    while let Some(row) = rows.next()? {
        let bytes: Vec<u8> = row.get(0)?;
        let block: ExecutedBlockV2 = decode_json(&bytes, "executed block")?;
        block.validate_chain_id(chain_id)?;
        match previous.as_ref() {
            Some(parent) => block.validate_successor(parent)?,
            None if block.height() == 1 && block.previous_app_hash().is_zero() => {}
            None => {
                return Err(ApplicationError::CorruptData(
                    "first stored block is not height one".to_owned(),
                ));
            }
        }
        for entry in block.entries() {
            let key = (entry.metadata().block_height(), entry.metadata().block_index());
            if expected_entries.insert(key, entry.clone()).is_some() {
                return Err(ApplicationError::CorruptData(
                    "two stored blocks repeat one executed position".to_owned(),
                ));
            }
        }
        entries = entries.saturating_add(block.entries().len());
        blocks = blocks.saturating_add(1);
        previous = Some(block);
    }
    validate_head(connection, chain_id)?;
    let stored_entries = table_count(connection, "executed_entries")?;
    if stored_entries != entries {
        return Err(ApplicationError::CorruptData(
            "executed entry rows differ from stored blocks".to_owned(),
        ));
    }
    validate_entry_rows(connection, &mut expected_entries)?;
    if !expected_entries.is_empty() {
        return Err(ApplicationError::CorruptData(
            "stored blocks contain entries missing from the entry index".to_owned(),
        ));
    }
    let channels = table_count(connection, "channel_snapshots")?;
    validate_channel_rows(connection)?;
    let requests = table_count(connection, "request_index")?;
    validate_request_rows(connection)?;
    let invoices = table_count(connection, "invoice_history")?;
    validate_invoice_rows(connection)?;
    Ok(IntegrityReportV2 {
        blocks,
        entries,
        channels,
        requests,
        invoices,
    })
}

fn validate_entry_rows(connection: &Connection, expected: &mut BTreeMap<(u64, u32), ExecutedEntryV2>) -> Result<()> {
    let mut statement = connection.prepare(
        "SELECT height, block_index, disposition, canonical_event,
                executed_entry_json, state_hash_after
         FROM executed_entries ORDER BY height, block_index",
    )?;
    let rows = statement.query_map([], |row| {
        Ok((
            row.get::<_, i64>(0)?,
            row.get::<_, i64>(1)?,
            row.get::<_, i64>(2)?,
            row.get::<_, Vec<u8>>(3)?,
            row.get::<_, Vec<u8>>(4)?,
            row.get::<_, Vec<u8>>(5)?,
        ))
    })?;
    for row in rows {
        let (height, index, disposition, event_bytes, entry_bytes, state_hash) = row?;
        if !matches!(disposition, DISPOSITION_APPLIED | DISPOSITION_REPLAYED) {
            return Err(ApplicationError::CorruptData(
                "executed entry has an invalid disposition".to_owned(),
            ));
        }
        let key = (
            from_sql_u64("executed entry height", height)?,
            from_sql_u32("executed block index", index)?,
        );
        let expected_entry = expected.remove(&key).ok_or_else(|| {
            ApplicationError::CorruptData("entry index contains a position absent from its block".to_owned())
        })?;
        let entry: ExecutedEntryV2 = decode_json(&entry_bytes, "executed entry")?;
        if entry != expected_entry {
            return Err(ApplicationError::CorruptData(
                "entry index differs from the executed block".to_owned(),
            ));
        }
        let event = ChannelEventV2::from_canonical_bytes(&event_bytes)?;
        let _ = thunderbolt_protocol::v2::AuthenticatedEntryV2::from_signed(entry.proposal(), &event)?;
        let _ = StateHashV2::from_bytes(blob_32("entry state hash", state_hash)?);
    }
    Ok(())
}

fn validate_channel_rows(connection: &Connection) -> Result<()> {
    let mut statement = connection.prepare(
        "SELECT channel_context_id, snapshot_json, state_hash, last_entry_json
         FROM channel_snapshots ORDER BY channel_context_id",
    )?;
    let rows = statement.query_map([], |row| {
        Ok((
            row.get::<_, Vec<u8>>(0)?,
            row.get::<_, Vec<u8>>(1)?,
            row.get::<_, Vec<u8>>(2)?,
            row.get::<_, Vec<u8>>(3)?,
        ))
    })?;
    for row in rows {
        let (context, snapshot, state_hash, executed_entry) = row?;
        let snapshot: ChannelSnapshotV2 = decode_json(&snapshot, "channel snapshot")?;
        snapshot.validate()?;
        let expected_context = snapshot.binding.context_id()?;
        if context.as_slice() != expected_context {
            return Err(ApplicationError::CorruptData(
                "snapshot context index differs from its binding".to_owned(),
            ));
        }
        let expected_hash = snapshot.state_hash()?;
        if state_hash.as_slice() != expected_hash.as_bytes() {
            return Err(ApplicationError::CorruptData(
                "snapshot state hash index differs from its bytes".to_owned(),
            ));
        }
        let executed_entry: ExecutedEntryV2 = decode_json(&executed_entry, "executed entry")?;
        let metadata = executed_entry.metadata();
        if metadata.channel_context_id().as_bytes() != &expected_context
            || metadata.entry_hash() != &snapshot.head_entry_hash
        {
            return Err(ApplicationError::CorruptData(
                "snapshot metadata differs from its channel head".to_owned(),
            ));
        }
    }
    Ok(())
}

fn validate_request_rows(connection: &Connection) -> Result<()> {
    let invalid: bool = connection.query_row(
        "SELECT EXISTS(
             SELECT 1 FROM request_index AS requests
             LEFT JOIN executed_entries AS entries
               ON entries.height = requests.first_height
              AND entries.block_index = requests.first_block_index
             WHERE entries.entry_hash IS NULL
                OR entries.channel_context_id != requests.channel_context_id
                OR entries.participant_id != requests.participant_id
                OR entries.request_digest != requests.request_digest
                OR entries.entry_hash != requests.entry_hash
         )",
        [],
        |row| row.get(0),
    )?;
    if invalid {
        return Err(ApplicationError::CorruptData(
            "request mapping does not match its first executed entry".to_owned(),
        ));
    }
    Ok(())
}

fn validate_invoice_rows(connection: &Connection) -> Result<()> {
    let mut statement = connection.prepare(
        "SELECT history.channel_context_id, history.invoice_id, history.entry_hash,
                entries.channel_context_id, entries.entry_hash, entries.canonical_event
         FROM invoice_history AS history
         LEFT JOIN executed_entries AS entries
           ON entries.height = history.committed_height
          AND entries.block_index = history.committed_block_index
         ORDER BY history.channel_context_id, history.invoice_id",
    )?;
    let rows = statement.query_map([], |row| {
        Ok((
            row.get::<_, Vec<u8>>(0)?,
            row.get::<_, Vec<u8>>(1)?,
            row.get::<_, Vec<u8>>(2)?,
            row.get::<_, Option<Vec<u8>>>(3)?,
            row.get::<_, Option<Vec<u8>>>(4)?,
            row.get::<_, Option<Vec<u8>>>(5)?,
        ))
    })?;
    for row in rows {
        let (channel, invoice_id, entry_hash, indexed_channel, indexed_hash, event_bytes) = row?;
        if indexed_channel.as_deref() != Some(channel.as_slice())
            || indexed_hash.as_deref() != Some(entry_hash.as_slice())
        {
            return Err(ApplicationError::CorruptData(
                "Invoice history does not match its executed entry".to_owned(),
            ));
        }
        let event_bytes = event_bytes
            .ok_or_else(|| ApplicationError::CorruptData("Invoice history points to a missing event".to_owned()))?;
        let event = ChannelEventV2::from_canonical_bytes(event_bytes)?;
        let ChannelEventV2::Invoice(event) = event else {
            return Err(ApplicationError::CorruptData(
                "Invoice history points to a non-Invoice event".to_owned(),
            ));
        };
        if event.invoice_id.as_bytes() != invoice_id {
            return Err(ApplicationError::CorruptData(
                "Invoice history identifier differs from event bytes".to_owned(),
            ));
        }
    }
    Ok(())
}

fn table_count(connection: &Connection, table: &'static str) -> Result<usize> {
    let sql = match table {
        "executed_entries" => "SELECT COUNT(*) FROM executed_entries",
        "channel_snapshots" => "SELECT COUNT(*) FROM channel_snapshots",
        "request_index" => "SELECT COUNT(*) FROM request_index",
        "invoice_history" => "SELECT COUNT(*) FROM invoice_history",
        _ => return Err(ApplicationError::CorruptData("unknown integrity table".to_owned())),
    };
    let count: i64 = connection.query_row(sql, [], |row| row.get(0))?;
    from_sql_usize("table row count", count)
}

fn configure_durability(connection: &Connection, busy_timeout: Duration) -> Result<()> {
    let mode: String = connection.pragma_query_value(None, "journal_mode", |row| row.get(0))?;
    if !mode.eq_ignore_ascii_case("wal") {
        let selected: String = connection.query_row("PRAGMA journal_mode = WAL", [], |row| row.get(0))?;
        if !selected.eq_ignore_ascii_case("wal") {
            return Err(ApplicationError::InvalidOptions("SQLite refused WAL mode"));
        }
    }
    connection.pragma_update(None, "synchronous", "FULL")?;
    connection.pragma_update(None, "foreign_keys", true)?;
    connection.pragma_update(None, "trusted_schema", false)?;
    connection.pragma_update(None, "wal_autocheckpoint", 1_000_i64)?;
    let expected_timeout = i64::try_from(busy_timeout.as_millis())
        .map_err(|_| ApplicationError::InvalidOptions("busy timeout exceeds SQLite range"))?;
    let actual_timeout: i64 = connection.pragma_query_value(None, "busy_timeout", |row| row.get(0))?;
    if actual_timeout != expected_timeout {
        return Err(ApplicationError::InvalidOptions(
            "SQLite busy timeout differs from configuration",
        ));
    }
    Ok(())
}

fn finish_transaction<T>(transaction: Transaction<'_>, result: Result<T>) -> Result<T> {
    match result {
        Ok(value) => {
            transaction.commit()?;
            Ok(value)
        }
        Err(error) => match transaction.rollback() {
            Ok(()) => Err(error),
            Err(rollback_error) => Err(ApplicationError::RollbackFailed {
                operation_error: error.to_string(),
                rollback_error,
            }),
        },
    }
}

fn rollback_preview<T>(transaction: Transaction<'_>, result: Result<T>) -> Result<T> {
    match transaction.rollback() {
        Ok(()) => result,
        Err(rollback_error) => Err(ApplicationError::RollbackFailed {
            operation_error: match result {
                Ok(_) => "rollback-only preview succeeded".to_owned(),
                Err(error) => error.to_string(),
            },
            rollback_error,
        }),
    }
}

fn decode_json<T: serde::de::DeserializeOwned>(bytes: &[u8], label: &str) -> Result<T> {
    serde_json::from_slice(bytes)
        .map_err(|error| ApplicationError::CorruptData(format!("invalid {label} JSON: {error}")))
}

fn durable_value<T, E: std::fmt::Display>(label: &str, value: std::result::Result<T, E>) -> Result<T> {
    value.map_err(|error| ApplicationError::CorruptData(format!("{label} is invalid: {error}")))
}

fn blob_32(label: &str, value: Vec<u8>) -> Result<[u8; 32]> {
    value
        .try_into()
        .map_err(|_| ApplicationError::CorruptData(format!("{label} is not 32 bytes")))
}

fn to_sql_u64(label: &'static str, value: u64) -> Result<i64> {
    i64::try_from(value).map_err(|_| ApplicationError::IntegerRange(label))
}

fn to_sql_usize(label: &'static str, value: usize) -> Result<i64> {
    i64::try_from(value).map_err(|_| ApplicationError::IntegerRange(label))
}

fn from_sql_u64(label: &str, value: i64) -> Result<u64> {
    u64::try_from(value).map_err(|_| ApplicationError::CorruptData(format!("{label} is negative")))
}

fn from_sql_u32(label: &str, value: i64) -> Result<u32> {
    u32::try_from(value).map_err(|_| ApplicationError::CorruptData(format!("{label} is outside u32")))
}

fn from_sql_usize(label: &str, value: i64) -> Result<usize> {
    usize::try_from(value).map_err(|_| ApplicationError::CorruptData(format!("{label} is negative")))
}
