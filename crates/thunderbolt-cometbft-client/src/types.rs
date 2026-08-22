use core::fmt;
use core::future::Future;
use core::pin::Pin;
use core::time::Duration;
use std::time::Instant;

use tendermint::node::Id as NodeId;
use tendermint_light_client_verifier::types::LightBlock;
use thiserror::Error;
use thunderbolt_cometbft::{FinalityError, FinalityPolicy, PinnedTrustRoot, MAX_WITNESSES};
use thunderbolt_ledger::{AppHashV2, ExecutedBlockV2, LedgerChainIdV2, RequestDigestV2, MAX_BLOCK_ENTRIES};
use tokio::io::AsyncRead;

/// Maximum accepted encoded size of one fetched primary or witness trace.
pub const MAX_TRACE_ENCODED_BYTES: usize = 16 * 1024 * 1024;
/// Maximum accepted encoded size of one complete persisted proof bundle.
pub const MAX_PROOF_BUNDLE_BYTES: usize = 64 * 1024 * 1024;
/// Maximum accepted encoded deterministic execution output.
pub const MAX_EXECUTION_ENCODED_BYTES: usize = 32 * 1024 * 1024;
/// Maximum transitions sealed by one history epoch.
pub const MAX_HISTORY_EPOCH_TRANSITIONS: usize = 256;
/// Maximum proof bytes processed by one history epoch.
pub const MAX_HISTORY_EPOCH_PROOF_BYTES: usize = 256 * 1024 * 1024;
/// Maximum executed request mappings processed by one history epoch.
pub const MAX_HISTORY_EPOCH_REQUESTS: usize = 65_536;
pub(crate) const MAX_BUSY_TIMEOUT: Duration = Duration::from_secs(60);
pub(crate) const MIN_OPERATION_TIMEOUT: Duration = Duration::from_millis(100);
pub(crate) const MAX_OPERATION_TIMEOUT: Duration = Duration::from_secs(120);
pub(crate) const PROOF_ENCODING_OVERHEAD: usize = 64 * 1024;

/// Fail-closed coordinator errors.
#[derive(Debug, Error)]
pub enum CoordinatorError {
    /// A static operator configuration violates a safety bound.
    #[error("invalid trust-coordinator configuration: {0}")]
    InvalidConfiguration(&'static str),
    /// An update request or fetched value is malformed or outside its bound.
    #[error("invalid trust-coordinator input: {0}")]
    InvalidInput(&'static str),
    /// The configured transport could not fetch an exact bounded trace.
    #[error("authenticated trace transport failed")]
    Transport,
    /// The trusted authenticator rejected a peer session or trace binding.
    #[error("trace peer authentication failed")]
    Authentication,
    /// The pinned trust root is no longer inside its trusting period.
    #[error("the pinned CometBFT trust root is expired")]
    ExpiredTrustRoot,
    /// The CometBFT proof did not establish finality for the execution output.
    #[error(transparent)]
    Finality(#[from] FinalityError),
    /// A request or height was reused with different immutable content.
    #[error("idempotency conflict")]
    IdempotencyConflict,
    /// The requested source rotation is stale, skips a version, or conflicts.
    #[error("source configuration version conflict")]
    ConfigurationConflict,
    /// A configured capacity bound was reached.
    #[error("trust-coordinator capacity reached")]
    Capacity,
    /// A new mutation would exceed the configured unsealed-history work bound.
    /// Seal the prepared history epoch, then retry the mutation.
    #[error("history epoch seal required before another trust-state mutation")]
    HistorySealRequired,
    /// The SQLite database or its lock could not be opened safely.
    #[error("trust-coordinator storage is unavailable")]
    StorageUnavailable,
    /// Durable state failed a structural or cryptographic-integrity check.
    #[error("trust-coordinator storage is corrupt: {0}")]
    StorageCorrupt(&'static str),
    /// A SQLite operation failed before a commit was attempted.
    #[error("trust-coordinator storage operation failed")]
    Storage(#[source] rusqlite::Error),
    /// SQLite reported a commit failure whose durable outcome is not knowable
    /// from the current process. Drop and reopen the coordinator before retrying.
    #[error("trust-coordinator commit outcome is ambiguous; reopen required")]
    AmbiguousCommit,
    /// This handle observed an ambiguous commit and is intentionally unusable.
    #[error("trust-coordinator handle is poisoned; reopen required")]
    Poisoned,
    /// The independent rollback checkpoint store was unavailable or its result
    /// was ambiguous. Drop and reopen before retrying.
    #[error("external trust checkpoint outcome is ambiguous; reopen required")]
    CheckpointUnavailable,
    /// The independently anchored checkpoint belongs to another database fork
    /// or is ahead of this local copy.
    #[error("external trust checkpoint conflicts with the local database")]
    CheckpointConflict,
    /// A bounded trace/authentication operation exceeded its configured deadline.
    #[error("trace acquisition or authentication deadline elapsed")]
    DeadlineExceeded,
}

/// Stable operator-provisioned identity for one trust coordinator.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TrustCoordinatorIdentity([u8; 32]);

impl TrustCoordinatorIdentity {
    /// Constructs a nonzero identity shared by the database and independent checkpoint store.
    pub fn new(bytes: [u8; 32]) -> Result<Self, CoordinatorError> {
        if bytes == [0_u8; 32] {
            return Err(CoordinatorError::InvalidConfiguration(
                "trust coordinator identity must be nonzero",
            ));
        }
        Ok(Self(bytes))
    }

    /// Returns the exact identity bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Exact independently anchored generation and logical trust-state digest.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TrustCheckpoint {
    generation: u64,
    state_digest: [u8; 32],
}

impl TrustCheckpoint {
    /// Constructs a checkpoint value for a checkpoint-store implementation.
    pub const fn new(generation: u64, state_digest: [u8; 32]) -> Self {
        Self {
            generation,
            state_digest,
        }
    }

    /// Returns the monotonic database generation.
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Returns the exact logical state digest at that generation.
    pub const fn state_digest(&self) -> &[u8; 32] {
        &self.state_digest
    }
}

/// Result of an atomic independent checkpoint compare-and-swap.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TrustCheckpointCasOutcome {
    /// The expected checkpoint was atomically replaced.
    Advanced,
    /// The exact candidate was already current.
    AlreadyCurrent,
    /// Another checkpoint (or no checkpoint) is current.
    Conflict(Option<TrustCheckpoint>),
}

/// Independent rollback/fork checkpoint boundary.
///
/// A production implementation must durably and atomically key CAS operations
/// by the full [`TrustCoordinatorIdentity`] in a trust domain independent of the
/// SQLite path. This crate provides no local-file or permissive implementation.
pub trait TrustCheckpointStore: Send + Sync {
    /// Store-specific error.
    type Error;

    /// Loads the currently anchored exact checkpoint.
    fn load_checkpoint<'a>(
        &'a self,
        identity: TrustCoordinatorIdentity,
    ) -> CheckpointFuture<'a, Option<TrustCheckpoint>, Self::Error>;

    /// Atomically advances `expected` to `next`, or reports the conflicting current value.
    fn compare_and_swap_checkpoint<'a>(
        &'a self,
        identity: TrustCoordinatorIdentity,
        expected: Option<TrustCheckpoint>,
        next: TrustCheckpoint,
    ) -> CheckpointFuture<'a, TrustCheckpointCasOutcome, Self::Error>;
}

/// Boxed cancellable future returned by an independent checkpoint store.
pub type CheckpointFuture<'a, T, E> = Pin<Box<dyn Future<Output = std::result::Result<T, E>> + Send + 'a>>;

impl From<rusqlite::Error> for CoordinatorError {
    fn from(error: rusqlite::Error) -> Self {
        Self::Storage(error)
    }
}

/// Primary or zero-based witness position in an authenticated fetch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SourceRole {
    /// The configured primary RPC source.
    Primary,
    /// One independently configured witness source.
    Witness(u8),
}

/// Immutable identity expected from an authenticated transport session.
///
/// `transport_binding` is an operator-provisioned digest of the authenticated
/// endpoint identity, such as an mTLS SPKI hash. It is never derived from a
/// `LightBlock.provider` field.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct PeerIdentity {
    transport_binding: [u8; 32],
    node_id: NodeId,
}

impl PeerIdentity {
    /// Constructs one exact endpoint and CometBFT node-identity pin.
    pub fn new(transport_binding: [u8; 32], node_id: NodeId) -> Result<Self, CoordinatorError> {
        if transport_binding == [0_u8; 32] || node_id.as_bytes().iter().all(|byte| *byte == 0) {
            return Err(CoordinatorError::InvalidConfiguration(
                "peer identity pins must be nonzero",
            ));
        }
        Ok(Self {
            transport_binding,
            node_id,
        })
    }

    /// Returns the exact authenticated transport-identity digest.
    pub const fn transport_binding(&self) -> &[u8; 32] {
        &self.transport_binding
    }

    /// Returns the exact expected CometBFT node id.
    pub const fn node_id(&self) -> NodeId {
        self.node_id
    }
}

impl fmt::Debug for PeerIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PeerIdentity")
            .field("transport_binding", &self.transport_binding)
            .field("node_id", &self.node_id)
            .finish()
    }
}

/// Explicitly versioned primary and witness identity roster.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SourceConfiguration {
    version: u64,
    primary: PeerIdentity,
    witnesses: Vec<PeerIdentity>,
}

impl SourceConfiguration {
    /// Constructs a nonempty, distinct source roster.
    pub fn new(version: u64, primary: PeerIdentity, witnesses: Vec<PeerIdentity>) -> Result<Self, CoordinatorError> {
        if version == 0 {
            return Err(CoordinatorError::InvalidConfiguration(
                "source configuration version must be positive",
            ));
        }
        if witnesses.is_empty() || witnesses.len() > MAX_WITNESSES {
            return Err(CoordinatorError::InvalidConfiguration(
                "witness count is outside the supported bound",
            ));
        }
        let mut identities = Vec::with_capacity(witnesses.len() + 1);
        identities.push(&primary);
        identities.extend(witnesses.iter());
        for (index, identity) in identities.iter().enumerate() {
            if identities
                .iter()
                .skip(index + 1)
                .any(|other| identity.node_id == other.node_id || identity.transport_binding == other.transport_binding)
            {
                return Err(CoordinatorError::InvalidConfiguration(
                    "primary and witness identities must be distinct",
                ));
            }
        }
        Ok(Self {
            version,
            primary,
            witnesses,
        })
    }

    /// Returns the positive operator-controlled configuration version.
    pub const fn version(&self) -> u64 {
        self.version
    }

    /// Returns the configured primary identity.
    pub const fn primary(&self) -> &PeerIdentity {
        &self.primary
    }

    /// Returns the ordered, independently authenticated witness identities.
    pub fn witnesses(&self) -> &[PeerIdentity] {
        &self.witnesses
    }

    pub(crate) fn validate_policy(&self, policy: FinalityPolicy) -> Result<(), CoordinatorError> {
        if self.witnesses.len() < policy.min_witnesses() || self.witnesses.len() > policy.max_witnesses() {
            return Err(CoordinatorError::InvalidConfiguration(
                "source roster does not satisfy the finality policy",
            ));
        }
        Ok(())
    }
}

/// Immutable coordinator configuration that must match durable state on open.
#[derive(Clone, Debug)]
pub struct CoordinatorConfig {
    identity: TrustCoordinatorIdentity,
    ledger_chain_id: LedgerChainIdV2,
    policy: FinalityPolicy,
    sources: SourceConfiguration,
    busy_timeout: Duration,
    limits: CoordinatorLimits,
    history_limits: HistoryEpochLimits,
}

/// Bounded synchronous work budget for one externally anchored history epoch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HistoryEpochLimits {
    max_transitions: usize,
    max_proof_bytes: usize,
    max_requests: usize,
}

impl HistoryEpochLimits {
    /// Constructs a compositional history-seal budget.
    pub fn new(max_transitions: usize, max_proof_bytes: usize, max_requests: usize) -> Result<Self, CoordinatorError> {
        if max_transitions == 0 || max_transitions > MAX_HISTORY_EPOCH_TRANSITIONS {
            return Err(CoordinatorError::InvalidConfiguration(
                "history epoch transition limit is outside the supported bound",
            ));
        }
        if max_proof_bytes == 0 || max_proof_bytes > MAX_HISTORY_EPOCH_PROOF_BYTES {
            return Err(CoordinatorError::InvalidConfiguration(
                "history epoch proof-byte limit is outside the supported bound",
            ));
        }
        if !(MAX_BLOCK_ENTRIES..=MAX_HISTORY_EPOCH_REQUESTS).contains(&max_requests) {
            return Err(CoordinatorError::InvalidConfiguration(
                "history epoch request limit is outside the supported bound",
            ));
        }
        Ok(Self {
            max_transitions,
            max_proof_bytes,
            max_requests,
        })
    }

    /// Returns the maximum transitions processed in one seal.
    pub const fn max_transitions(&self) -> usize {
        self.max_transitions
    }

    /// Returns the maximum aggregate proof bytes processed in one seal.
    pub const fn max_proof_bytes(&self) -> usize {
        self.max_proof_bytes
    }

    /// Returns the maximum aggregate request mappings processed in one seal.
    pub const fn max_requests(&self) -> usize {
        self.max_requests
    }
}

/// Compositional byte and deadline limits for one trust update.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CoordinatorLimits {
    max_trace_encoded_bytes: usize,
    max_execution_encoded_bytes: usize,
    max_proof_bundle_bytes: usize,
    operation_timeout: Duration,
}

impl CoordinatorLimits {
    /// Constructs limits whose worst-case root, primary, witness, execution,
    /// and encoding overhead fit the complete proof-bundle cap.
    pub fn new(
        max_trace_encoded_bytes: usize,
        max_execution_encoded_bytes: usize,
        max_proof_bundle_bytes: usize,
        operation_timeout: Duration,
        witness_count: usize,
    ) -> Result<Self, CoordinatorError> {
        if max_trace_encoded_bytes == 0 || max_trace_encoded_bytes > MAX_TRACE_ENCODED_BYTES {
            return Err(CoordinatorError::InvalidConfiguration(
                "trace byte limit is outside the supported bound",
            ));
        }
        if max_execution_encoded_bytes == 0 || max_execution_encoded_bytes > MAX_EXECUTION_ENCODED_BYTES {
            return Err(CoordinatorError::InvalidConfiguration(
                "execution byte limit is outside the supported bound",
            ));
        }
        if max_proof_bundle_bytes == 0 || max_proof_bundle_bytes > MAX_PROOF_BUNDLE_BYTES {
            return Err(CoordinatorError::InvalidConfiguration(
                "proof-bundle byte limit is outside the supported bound",
            ));
        }
        if !(MIN_OPERATION_TIMEOUT..=MAX_OPERATION_TIMEOUT).contains(&operation_timeout) {
            return Err(CoordinatorError::InvalidConfiguration(
                "trace operation timeout is outside the supported bound",
            ));
        }
        let trace_count = witness_count
            .checked_add(2)
            .ok_or(CoordinatorError::InvalidConfiguration("trace-count budget overflows"))?;
        let required = max_trace_encoded_bytes
            .checked_mul(trace_count)
            .and_then(|bytes| bytes.checked_add(max_execution_encoded_bytes))
            .and_then(|bytes| bytes.checked_add(PROOF_ENCODING_OVERHEAD))
            .ok_or(CoordinatorError::InvalidConfiguration(
                "aggregate proof-bundle budget overflows",
            ))?;
        if required > max_proof_bundle_bytes {
            return Err(CoordinatorError::InvalidConfiguration(
                "proof-bundle limit cannot contain configured root, traces, and execution",
            ));
        }
        Ok(Self {
            max_trace_encoded_bytes,
            max_execution_encoded_bytes,
            max_proof_bundle_bytes,
            operation_timeout,
        })
    }

    /// Returns the per-trace encoded-byte limit.
    pub const fn max_trace_encoded_bytes(&self) -> usize {
        self.max_trace_encoded_bytes
    }

    /// Returns the encoded execution-output limit.
    pub const fn max_execution_encoded_bytes(&self) -> usize {
        self.max_execution_encoded_bytes
    }

    /// Returns the complete proof-bundle limit.
    pub const fn max_proof_bundle_bytes(&self) -> usize {
        self.max_proof_bundle_bytes
    }

    /// Returns the total deadline for all fetch and authentication work.
    pub const fn operation_timeout(&self) -> Duration {
        self.operation_timeout
    }
}

impl CoordinatorConfig {
    /// Constructs bounded local trust-coordinator configuration.
    pub fn new(
        identity: TrustCoordinatorIdentity,
        ledger_chain_id: LedgerChainIdV2,
        policy: FinalityPolicy,
        sources: SourceConfiguration,
        busy_timeout: Duration,
        limits: CoordinatorLimits,
        history_limits: HistoryEpochLimits,
    ) -> Result<Self, CoordinatorError> {
        sources.validate_policy(policy)?;
        if busy_timeout.is_zero() || busy_timeout > MAX_BUSY_TIMEOUT {
            return Err(CoordinatorError::InvalidConfiguration(
                "SQLite busy timeout is outside the supported bound",
            ));
        }
        if limits
            != CoordinatorLimits::new(
                limits.max_trace_encoded_bytes(),
                limits.max_execution_encoded_bytes(),
                limits.max_proof_bundle_bytes(),
                limits.operation_timeout(),
                sources.witnesses().len(),
            )?
        {
            return Err(CoordinatorError::InvalidConfiguration("resource limits differ"));
        }
        if history_limits.max_proof_bytes() < limits.max_proof_bundle_bytes() {
            return Err(CoordinatorError::InvalidConfiguration(
                "history epoch cannot contain one maximum proof bundle",
            ));
        }
        Ok(Self {
            identity,
            ledger_chain_id,
            policy,
            sources,
            busy_timeout,
            limits,
            history_limits,
        })
    }

    /// Returns the independently checkpointed coordinator identity.
    pub const fn identity(&self) -> TrustCoordinatorIdentity {
        self.identity
    }

    /// Returns the only accepted Ledger chain id.
    pub const fn ledger_chain_id(&self) -> &LedgerChainIdV2 {
        &self.ledger_chain_id
    }

    /// Returns the immutable CometBFT verification policy.
    pub const fn policy(&self) -> FinalityPolicy {
        self.policy
    }

    /// Returns the exact current source roster expected on disk.
    pub const fn sources(&self) -> &SourceConfiguration {
        &self.sources
    }

    /// Returns the bounded SQLite lock wait.
    pub const fn busy_timeout(&self) -> Duration {
        self.busy_timeout
    }

    /// Returns the maximum encoded bytes accepted for one trace.
    pub const fn max_trace_encoded_bytes(&self) -> usize {
        self.limits.max_trace_encoded_bytes
    }

    /// Returns the maximum encoded deterministic execution size.
    pub const fn max_execution_encoded_bytes(&self) -> usize {
        self.limits.max_execution_encoded_bytes
    }

    /// Returns the maximum bytes accepted for one persisted proof bundle.
    pub const fn max_proof_bundle_bytes(&self) -> usize {
        self.limits.max_proof_bundle_bytes
    }

    /// Returns the total deadline for trace fetch and authentication.
    pub const fn operation_timeout(&self) -> Duration {
        self.limits.operation_timeout
    }

    /// Returns the bounded synchronous history-seal work budget.
    pub const fn history_limits(&self) -> HistoryEpochLimits {
        self.history_limits
    }

    pub(crate) fn with_sources(&self, sources: SourceConfiguration) -> Result<Self, CoordinatorError> {
        sources.validate_policy(self.policy)?;
        CoordinatorLimits::new(
            self.limits.max_trace_encoded_bytes,
            self.limits.max_execution_encoded_bytes,
            self.limits.max_proof_bundle_bytes,
            self.limits.operation_timeout,
            sources.witnesses().len(),
        )?;
        Ok(Self {
            identity: self.identity,
            ledger_chain_id: self.ledger_chain_id.clone(),
            policy: self.policy,
            sources,
            busy_timeout: self.busy_timeout,
            limits: self.limits,
            history_limits: self.history_limits,
        })
    }
}

/// Exact bounded request presented to a configured trace transport.
#[derive(Clone, Debug)]
pub struct TraceFetchRequest {
    ledger_chain_id: LedgerChainIdV2,
    config_version: u64,
    role: SourceRole,
    first_height: u64,
    last_height: u64,
    max_blocks: usize,
    max_encoded_bytes: usize,
    deadline: Instant,
}

impl TraceFetchRequest {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        ledger_chain_id: LedgerChainIdV2,
        config_version: u64,
        role: SourceRole,
        first_height: u64,
        last_height: u64,
        max_blocks: usize,
        max_encoded_bytes: usize,
        deadline: Instant,
    ) -> Self {
        Self {
            ledger_chain_id,
            config_version,
            role,
            first_height,
            last_height,
            max_blocks,
            max_encoded_bytes,
            deadline,
        }
    }

    /// Returns the exact expected Ledger chain id.
    pub const fn ledger_chain_id(&self) -> &LedgerChainIdV2 {
        &self.ledger_chain_id
    }

    /// Returns the source-roster version authorizing this fetch.
    pub const fn config_version(&self) -> u64 {
        self.config_version
    }

    /// Returns whether the requested peer is the primary or a witness.
    pub const fn role(&self) -> SourceRole {
        self.role
    }

    /// Returns the first required adjacent height.
    pub const fn first_height(&self) -> u64 {
        self.first_height
    }

    /// Returns the final required committing height.
    pub const fn last_height(&self) -> u64 {
        self.last_height
    }

    /// Returns the exact decoded block-count limit.
    pub const fn max_blocks(&self) -> usize {
        self.max_blocks
    }

    /// Returns the raw encoded-body limit that transport must enforce before decoding.
    pub const fn max_encoded_bytes(&self) -> usize {
        self.max_encoded_bytes
    }

    /// Returns the absolute monotonic deadline shared by this update.
    pub const fn deadline(&self) -> Instant {
        self.deadline
    }
}

/// One decoded trace plus opaque evidence from its authenticated transport session.
///
/// The transport must enforce `TraceFetchRequest::max_encoded_bytes` on the raw
/// response before decoding and report the exact raw byte count here. The
/// coordinator independently bounds both this value and its own re-encoding.
pub struct FetchedTrace<B, E> {
    body: B,
    evidence: E,
}

impl<B, E> FetchedTrace<B, E> {
    /// Packages an undecoded streaming response for coordinator-bounded reading.
    pub fn new(body: B, evidence: E) -> Self {
        Self { body, evidence }
    }

    pub(crate) fn into_parts(self) -> (B, E) {
        (self.body, self.evidence)
    }
}

/// Transport boundary for obtaining bounded primary and witness traces.
///
/// Implementations must authenticate neither by caller labels nor by
/// `LightBlock.provider`. They must apply the raw response limit before decode.
/// This crate intentionally provides no implementation.
pub trait TraceTransport: Send + Sync {
    /// Opaque transport-session evidence passed to the trusted authenticator.
    type Evidence: Send + Sync;
    /// Undecoded response body. Dropping it must cancel further reads.
    type Body: AsyncRead + Unpin + Send;
    /// Transport-specific error.
    type Error;

    /// Fetches one exact trace from the configured endpoint identity.
    fn fetch<'a>(
        &'a self,
        peer: &'a PeerIdentity,
        request: &'a TraceFetchRequest,
    ) -> TraceFuture<'a, FetchedTrace<Self::Body, Self::Evidence>, Self::Error>;
}

/// Boxed cancellable future returned by a trace transport.
pub type TraceFuture<'a, T, E> = Pin<Box<dyn Future<Output = std::result::Result<T, E>> + Send + 'a>>;

/// Exact trace and request metadata presented to a trusted peer authenticator.
#[derive(Clone, Copy, Debug)]
pub struct AuthenticationContext<'a> {
    request: &'a TraceFetchRequest,
    blocks: &'a [LightBlock],
    trace_digest: [u8; 32],
    encoded_bytes: usize,
}

impl<'a> AuthenticationContext<'a> {
    pub(crate) const fn new(
        request: &'a TraceFetchRequest,
        blocks: &'a [LightBlock],
        trace_digest: [u8; 32],
        encoded_bytes: usize,
    ) -> Self {
        Self {
            request,
            blocks,
            trace_digest,
            encoded_bytes,
        }
    }

    /// Returns the exact fetch request being authenticated.
    pub const fn request(&self) -> &'a TraceFetchRequest {
        self.request
    }

    /// Returns the exact decoded trace being authorized.
    pub const fn blocks(&self) -> &'a [LightBlock] {
        self.blocks
    }

    /// Returns the coordinator-computed digest of the exact decoded trace.
    pub const fn trace_digest(&self) -> &[u8; 32] {
        &self.trace_digest
    }

    /// Returns the transport-reported raw encoded size.
    pub const fn encoded_bytes(&self) -> usize {
        self.encoded_bytes
    }
}

/// Trusted boundary that binds transport evidence to an exact configured peer
/// and trace. A successful return authorizes the coordinator to bind the
/// configured CometBFT node id into the one-use verifier capability.
///
/// This crate intentionally provides no implementation.
pub trait TracePeerAuthenticator<E>: Send + Sync {
    /// Authenticator-specific error.
    type Error;

    /// Authenticates one session and exact trace against `expected`.
    fn authenticate<'a>(
        &'a self,
        expected: &'a PeerIdentity,
        context: AuthenticationContext<'a>,
        evidence: &'a E,
    ) -> TraceFuture<'a, (), Self::Error>;
}

/// Durable summary derived from a verified in-process CometBFT receipt.
///
/// This type intentionally implements neither `Serialize` nor `Deserialize`.
/// It can only be obtained from a successful coordinator update or validated
/// immutable historical lookup.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FinalitySummary {
    pub(crate) ledger_chain_id: LedgerChainIdV2,
    pub(crate) application_version: u64,
    pub(crate) config_version: u64,
    pub(crate) execution_height: u64,
    pub(crate) execution_block_time_ms: u64,
    pub(crate) application_hash: AppHashV2,
    pub(crate) execution_header_hash: [u8; 32],
    pub(crate) committing_height: u64,
    pub(crate) committing_header_hash: [u8; 32],
    pub(crate) primary_peer_id: NodeId,
    pub(crate) witness_peer_ids: Vec<NodeId>,
}

impl FinalitySummary {
    /// Returns the verified Ledger chain id.
    pub const fn ledger_chain_id(&self) -> &LedgerChainIdV2 {
        &self.ledger_chain_id
    }

    /// Returns the verified ABCI application version.
    pub const fn application_version(&self) -> u64 {
        self.application_version
    }

    /// Returns the source-roster version used for verification.
    pub const fn config_version(&self) -> u64 {
        self.config_version
    }

    /// Returns the finalized execution height.
    pub const fn execution_height(&self) -> u64 {
        self.execution_height
    }

    /// Returns the execution time bound to the signed header.
    pub const fn execution_block_time_ms(&self) -> u64 {
        self.execution_block_time_ms
    }

    /// Returns the finalized Thunderbolt application hash.
    pub const fn application_hash(&self) -> &AppHashV2 {
        &self.application_hash
    }

    /// Returns the signed execution-header hash.
    pub const fn execution_header_hash(&self) -> &[u8; 32] {
        &self.execution_header_hash
    }

    /// Returns the header height that commits the application hash.
    pub const fn committing_height(&self) -> u64 {
        self.committing_height
    }

    /// Returns the signed committing-header hash.
    pub const fn committing_header_hash(&self) -> &[u8; 32] {
        &self.committing_header_hash
    }

    /// Returns the authenticated primary CometBFT node id.
    pub const fn primary_peer_id(&self) -> NodeId {
        self.primary_peer_id
    }

    /// Returns the distinct authenticated witness node ids.
    pub fn witness_peer_ids(&self) -> &[NodeId] {
        &self.witness_peer_ids
    }
}

/// Complete public evidence durably retained for one finality decision.
///
/// The fields are private and this API has no deserializer. Persisted decoding
/// is an internal bounded operation followed by full cross-field validation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FinalityProofBundle {
    pub(crate) config_version: u64,
    pub(crate) trusted_root: LightBlock,
    pub(crate) primary_trace: Vec<LightBlock>,
    pub(crate) witness_traces: Vec<Vec<LightBlock>>,
    pub(crate) execution: ExecutedBlockV2,
}

impl FinalityProofBundle {
    /// Returns the source-roster version used for this proof.
    pub const fn config_version(&self) -> u64 {
        self.config_version
    }

    /// Returns the exact trust root from which verification started.
    pub const fn trusted_root(&self) -> &LightBlock {
        &self.trusted_root
    }

    /// Returns the authenticated primary adjacent trace.
    pub fn primary_trace(&self) -> &[LightBlock] {
        &self.primary_trace
    }

    /// Returns the independently authenticated witness traces.
    pub fn witness_traces(&self) -> &[Vec<LightBlock>] {
        &self.witness_traces
    }

    /// Returns the deterministically recomputed execution output.
    pub const fn execution(&self) -> &ExecutedBlockV2 {
        &self.execution
    }
}

/// Immutable historical finality result for one execution height.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HistoricalFinality {
    pub(crate) summary: FinalitySummary,
    pub(crate) proof: FinalityProofBundle,
    pub(crate) proof_digest: [u8; 32],
}

impl HistoricalFinality {
    /// Returns the non-serializable receipt-derived summary.
    pub const fn summary(&self) -> &FinalitySummary {
        &self.summary
    }

    /// Returns the complete locally persisted proof bundle.
    pub const fn proof(&self) -> &FinalityProofBundle {
        &self.proof
    }

    /// Returns the local integrity digest covering proof, summary, roster, and roots.
    pub const fn proof_digest(&self) -> &[u8; 32] {
        &self.proof_digest
    }
}

/// Immutable historical finality result for one executed Ledger request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HistoricalRequestFinality {
    pub(crate) request_digest: RequestDigestV2,
    pub(crate) block_index: u32,
    pub(crate) finality: HistoricalFinality,
}

impl HistoricalRequestFinality {
    /// Returns the exact executed request digest.
    pub const fn request_digest(&self) -> &RequestDigestV2 {
        &self.request_digest
    }

    /// Returns the exact zero-based entry index within the finalized block.
    pub const fn block_index(&self) -> u32 {
        self.block_index
    }

    /// Returns the immutable block-finality proof and summary.
    pub const fn finality(&self) -> &HistoricalFinality {
        &self.finality
    }
}

/// Outcome of a finality update attempt.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AdvanceOutcome {
    /// Verification and its next root were newly committed.
    Applied(HistoricalFinality),
    /// The exact execution had already been durably verified.
    Replayed(HistoricalFinality),
}

/// Outcome of an explicit source-roster rotation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RotationOutcome {
    /// A consecutive new roster version was durably installed.
    Applied,
    /// The exact roster version and contents were already current.
    AlreadyCurrent,
}

/// Outcome of sealing a bounded immutable history epoch into the external
/// checkpoint chain.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HistorySealOutcome {
    /// A bounded generation interval and its request-index mappings were sealed.
    Sealed {
        /// First non-manifest checkpoint generation covered.
        first_generation: u64,
        /// Last non-manifest checkpoint generation covered.
        last_generation: u64,
    },
    /// Every current non-manifest transition was already sealed.
    NothingToSeal,
}

/// Independently retainable intent for one exact history-epoch seal.
///
/// This value is not itself proof of durability. Before calling the seal or
/// recovery method, the operator must persist its canonical bytes outside the
/// candidate SQLite database. Recovery compares every field and the recomputed
/// manifest before advancing the external checkpoint.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HistorySealIntent {
    pub(crate) identity: TrustCoordinatorIdentity,
    pub(crate) expected_checkpoint: TrustCheckpoint,
    pub(crate) first_generation: u64,
    pub(crate) last_generation: u64,
    pub(crate) manifest_digest: [u8; 32],
}

impl HistorySealIntent {
    /// Encodes the fixed-width canonical intent for independent durable storage.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut output = Vec::with_capacity(128);
        output.extend_from_slice(b"TBHSI001");
        output.extend_from_slice(self.identity.as_bytes());
        output.extend_from_slice(&self.expected_checkpoint.generation().to_be_bytes());
        output.extend_from_slice(self.expected_checkpoint.state_digest());
        output.extend_from_slice(&self.first_generation.to_be_bytes());
        output.extend_from_slice(&self.last_generation.to_be_bytes());
        output.extend_from_slice(&self.manifest_digest);
        output
    }

    /// Decodes a canonical intent previously retained by the operator.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, CoordinatorError> {
        if bytes.len() != 128 || bytes.get(..8) != Some(b"TBHSI001".as_slice()) {
            return Err(CoordinatorError::InvalidInput(
                "history seal intent encoding is invalid",
            ));
        }
        let identity = TrustCoordinatorIdentity::new(copy_fixed::<32>(bytes, 8)?)?;
        let expected_generation = u64::from_be_bytes(copy_fixed::<8>(bytes, 40)?);
        let expected_checkpoint = TrustCheckpoint::new(expected_generation, copy_fixed::<32>(bytes, 48)?);
        let first_generation = u64::from_be_bytes(copy_fixed::<8>(bytes, 80)?);
        let last_generation = u64::from_be_bytes(copy_fixed::<8>(bytes, 88)?);
        let manifest_digest = copy_fixed::<32>(bytes, 96)?;
        if last_generation < first_generation || manifest_digest == [0_u8; 32] {
            return Err(CoordinatorError::InvalidInput("history seal intent fields are invalid"));
        }
        Ok(Self {
            identity,
            expected_checkpoint,
            first_generation,
            last_generation,
            manifest_digest,
        })
    }

    /// Returns the coordinator identity bound into the intent.
    pub const fn identity(&self) -> TrustCoordinatorIdentity {
        self.identity
    }

    /// Returns the exact external checkpoint expected before sealing.
    pub const fn expected_checkpoint(&self) -> TrustCheckpoint {
        self.expected_checkpoint
    }

    /// Returns the first covered generation.
    pub const fn first_generation(&self) -> u64 {
        self.first_generation
    }

    /// Returns the last covered generation.
    pub const fn last_generation(&self) -> u64 {
        self.last_generation
    }

    /// Returns the exact manifest digest to commit and externally anchor.
    pub const fn manifest_digest(&self) -> &[u8; 32] {
        &self.manifest_digest
    }
}

fn copy_fixed<const N: usize>(bytes: &[u8], offset: usize) -> Result<[u8; N], CoordinatorError> {
    let end = offset
        .checked_add(N)
        .ok_or(CoordinatorError::InvalidInput("fixed field offset overflows"))?;
    bytes
        .get(offset..end)
        .and_then(|slice| slice.try_into().ok())
        .ok_or(CoordinatorError::InvalidInput("fixed field is truncated"))
}

/// Non-serializable view of the coordinator's current durable trust root.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CurrentTrustRoot {
    pub(crate) height: u64,
    pub(crate) header_hash: [u8; 32],
    pub(crate) config_version: u64,
}

impl CurrentTrustRoot {
    /// Returns the current trusted CometBFT height.
    pub const fn height(&self) -> u64 {
        self.height
    }

    /// Returns the exact current trusted header hash.
    pub const fn header_hash(&self) -> &[u8; 32] {
        &self.header_hash
    }

    /// Returns the current source configuration version.
    pub const fn config_version(&self) -> u64 {
        self.config_version
    }
}

pub(crate) fn validate_root(root: &PinnedTrustRoot, config: &CoordinatorConfig) -> Result<(), CoordinatorError> {
    if root.ledger_chain_id() != config.ledger_chain_id()
        || root.policy() != config.policy()
        || root.application_version() != thunderbolt_cometbft::THUNDERBOLT_APP_VERSION_V2
    {
        return Err(CoordinatorError::InvalidConfiguration(
            "pinned root does not match chain, application, or policy",
        ));
    }
    Ok(())
}
