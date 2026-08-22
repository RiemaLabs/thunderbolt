use std::path::Path;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use futures_util::stream::{FuturesUnordered, StreamExt as _};
use serde_json::to_vec;
use sha2::{Digest, Sha256};
use tendermint_light_client_verifier::types::LightBlock;
use thunderbolt_cometbft::{
    AuthenticatedTrace, FinalityVerifier, PinnedTrustRoot, TraceAuthenticationCapability, TraceAuthenticationRequest,
    TraceRole, TraceSourceAuthenticator,
};
use thunderbolt_ledger::{ExecutedBlockV2, RequestDigestV2};
use tokio::io::AsyncReadExt as _;

use crate::storage::{
    execution_digest, source_configuration_digest, DurableStore, PreparedUpdate, StoredHead, OPERATION_BOOTSTRAP,
    OPERATION_FINALITY, OPERATION_ROTATION,
};
use crate::types::{
    validate_root, AdvanceOutcome, AuthenticationContext, CoordinatorConfig, CoordinatorError, CurrentTrustRoot,
    FetchedTrace, FinalityProofBundle, FinalitySummary, HistoricalFinality, HistoricalRequestFinality,
    HistorySealIntent, HistorySealOutcome, PeerIdentity, RotationOutcome, SourceConfiguration, SourceRole,
    TraceFetchRequest, TracePeerAuthenticator, TraceTransport, TrustCheckpoint, TrustCheckpointCasOutcome,
    TrustCheckpointStore,
};
use crate::Result;

const TRACE_DOMAIN: &[u8] = b"bitcoin-thunderbolt/cometbft-client/trace/v1";

/// Crash-safe owner of one pinned CometBFT root and authenticated source roster.
///
/// The coordinator contains no network implementation. A daemon supplies a
/// deadline-aware [`TraceTransport`], a trusted [`TracePeerAuthenticator`], and
/// an independent [`TrustCheckpointStore`]. The handle must be dropped and
/// explicitly recovered after an ambiguous SQLite or checkpoint outcome.
pub struct TrustCoordinator<T, A, S> {
    store: DurableStore,
    head: StoredHead,
    config: CoordinatorConfig,
    transport: T,
    authenticator: A,
    checkpoint_store: S,
    poisoned: bool,
    #[cfg(test)]
    fault: Option<FaultPoint>,
}

struct PreparedBinding {
    role: SourceRole,
    first_height: u64,
    last_height: u64,
    trace_digest: [u8; 32],
    node_id: tendermint::node::Id,
}

struct PreparedAuthenticator {
    ledger_chain_id: thunderbolt_ledger::LedgerChainIdV2,
    bindings: Vec<PreparedBinding>,
}

impl TraceSourceAuthenticator for PreparedAuthenticator {
    type Error = ();

    fn authenticate<'a>(
        &self,
        request: TraceAuthenticationRequest<'a>,
        capability: TraceAuthenticationCapability<'a>,
    ) -> std::result::Result<AuthenticatedTrace<'a>, Self::Error> {
        let requested_role = match request.role() {
            TraceRole::Primary => SourceRole::Primary,
            TraceRole::Witness(index) => SourceRole::Witness(index),
        };
        let digest = trace_digest(request.blocks()).map_err(|_| ())?;
        let binding = self
            .bindings
            .iter()
            .find(|candidate| candidate.role == requested_role)
            .ok_or(())?;
        if request.ledger_chain_id() != &self.ledger_chain_id
            || request.first_height() != binding.first_height
            || request.last_height() != binding.last_height
            || digest != binding.trace_digest
        {
            return Err(());
        }
        Ok(capability.bind(binding.node_id))
    }
}

struct AuthenticatedFetch {
    blocks: Vec<LightBlock>,
    binding: PreparedBinding,
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FaultPoint {
    BeforePersistence,
    AfterCommit,
}

impl<T, A, S> TrustCoordinator<T, A, S>
where
    T: TraceTransport,
    A: TracePeerAuthenticator<T::Evidence>,
    S: TrustCheckpointStore,
{
    /// Creates a new durable coordinator from an independently reviewed initial pin.
    ///
    /// Creation prevalidates all bounded inputs and initializes only a new or
    /// transactionally empty owner-private database. It never repurposes a
    /// nonempty database. Use [`Self::recover_bootstrap`] only when SQLite may
    /// have committed but the independent checkpoint CAS was not acknowledged.
    pub async fn create(
        path: impl AsRef<Path>,
        config: CoordinatorConfig,
        initial_root: PinnedTrustRoot,
        transport: T,
        authenticator: A,
        checkpoint_store: S,
    ) -> Result<Self> {
        validate_root(&initial_root, &config)?;
        let (store, head) = DurableStore::create(path.as_ref(), &config, &initial_root)?;
        anchor_transition(&checkpoint_store, &config, None, head.checkpoint).await?;
        Ok(Self::from_parts(
            store,
            head,
            config,
            transport,
            authenticator,
            checkpoint_store,
        ))
    }

    /// Opens an existing coordinator only when chain, policy, and the complete
    /// current source roster exactly match operator configuration.
    pub async fn open(
        path: impl AsRef<Path>,
        config: CoordinatorConfig,
        transport: T,
        authenticator: A,
        checkpoint_store: S,
    ) -> Result<Self> {
        let (store, head) = DurableStore::open(path.as_ref(), &config)?;
        require_exact_checkpoint(&checkpoint_store, &config, &head).await?;
        Ok(Self::from_parts(
            store,
            head,
            config,
            transport,
            authenticator,
            checkpoint_store,
        ))
    }

    /// Recovers a bootstrap whose SQLite commit completed before its independent
    /// checkpoint CAS. The caller must supply the exact original operator pin.
    pub async fn recover_bootstrap(
        path: impl AsRef<Path>,
        config: CoordinatorConfig,
        initial_root: &PinnedTrustRoot,
        transport: T,
        authenticator: A,
        checkpoint_store: S,
    ) -> Result<Self> {
        validate_root(initial_root, &config)?;
        let (store, head) = DurableStore::open(path.as_ref(), &config)?;
        if head.operation_kind != OPERATION_BOOTSTRAP
            || head.checkpoint.generation() != 0
            || head.prior_checkpoint.is_some()
            || head.root.height() != initial_root.height()
            || head.root.header_hash() != initial_root.header_hash()
            || head.root.light_block() != initial_root.light_block()
        {
            return Err(CoordinatorError::CheckpointConflict);
        }
        recover_transition(&checkpoint_store, &config, &head).await?;
        Ok(Self::from_parts(
            store,
            head,
            config,
            transport,
            authenticator,
            checkpoint_store,
        ))
    }

    /// Recovers one finality update whose SQLite commit completed before its
    /// independent checkpoint CAS. `expected_execution` must come from durable
    /// caller request history, not from the candidate database.
    pub async fn recover_finality(
        path: impl AsRef<Path>,
        config: CoordinatorConfig,
        expected_execution: &ExecutedBlockV2,
        transport: T,
        authenticator: A,
        checkpoint_store: S,
    ) -> Result<Self> {
        let (store, head) = DurableStore::open(path.as_ref(), &config)?;
        let historical = store
            .historical_by_height(&config, expected_execution.height())?
            .ok_or(CoordinatorError::CheckpointConflict)?;
        let intended_operation = store.finality_checkpoint_operation_digest(&config, expected_execution.height())?;
        if head.operation_kind != OPERATION_FINALITY
            || head.prior_checkpoint.is_none()
            || head.operation_digest != intended_operation
            || execution_digest(historical.proof().execution())? != execution_digest(expected_execution)?
        {
            return Err(CoordinatorError::CheckpointConflict);
        }
        require_prior_checkpoint(&checkpoint_store, &config, &head).await?;
        let prior_root = store.pending_prior_root(&config, expected_execution.height())?;
        reverify_pending_finality(&transport, &authenticator, &config, &prior_root, &historical, &head).await?;
        recover_transition(&checkpoint_store, &config, &head).await?;
        Ok(Self::from_parts(
            store,
            head,
            config,
            transport,
            authenticator,
            checkpoint_store,
        ))
    }

    /// Recovers one explicitly intended consecutive source rotation whose
    /// SQLite commit completed before its independent checkpoint CAS.
    pub async fn recover_rotation(
        path: impl AsRef<Path>,
        config: CoordinatorConfig,
        expected_previous_version: u64,
        transport: T,
        authenticator: A,
        checkpoint_store: S,
    ) -> Result<Self> {
        let (store, head) = DurableStore::open(path.as_ref(), &config)?;
        if head.operation_kind != OPERATION_ROTATION
            || head.prior_checkpoint.is_none()
            || expected_previous_version.checked_add(1) != Some(config.sources().version())
            || source_configuration_digest(config.sources())? != head.operation_digest
        {
            return Err(CoordinatorError::CheckpointConflict);
        }
        recover_transition(&checkpoint_store, &config, &head).await?;
        Ok(Self::from_parts(
            store,
            head,
            config,
            transport,
            authenticator,
            checkpoint_store,
        ))
    }

    /// Recovers one prepared history seal whose SQLite commit completed before
    /// its external checkpoint CAS. The exact canonical `intent` must have been
    /// retained independently before the seal began.
    pub fn recover_history_epoch(
        path: impl AsRef<Path>,
        config: CoordinatorConfig,
        intent: &HistorySealIntent,
        transport: T,
        authenticator: A,
        checkpoint_store: S,
    ) -> Result<impl std::future::Future<Output = Result<Self>>> {
        let (store, head) = DurableStore::open(path.as_ref(), &config)?;
        store.validate_pending_history_intent(&config, &head, intent)?;
        Ok(async move {
            require_prior_checkpoint(&checkpoint_store, &config, &head).await?;
            recover_transition(&checkpoint_store, &config, &head).await?;
            Ok(Self::from_parts(
                store,
                head,
                config,
                transport,
                authenticator,
                checkpoint_store,
            ))
        })
    }

    fn from_parts(
        store: DurableStore,
        head: StoredHead,
        config: CoordinatorConfig,
        transport: T,
        authenticator: A,
        checkpoint_store: S,
    ) -> Self {
        Self {
            store,
            head,
            config,
            transport,
            authenticator,
            checkpoint_store,
            poisoned: false,
            #[cfg(test)]
            fault: None,
        }
    }

    /// Returns a non-serializable view of the exact current durable root.
    pub fn current_trust_root(&self) -> Result<CurrentTrustRoot> {
        self.ensure_usable()?;
        Ok(CurrentTrustRoot {
            height: self.head.root.height(),
            header_hash: *self.head.root.header_hash(),
            config_version: self.config.sources().version(),
        })
    }

    /// Returns the exact current authenticated source roster.
    pub fn source_configuration(&self) -> Result<&SourceConfiguration> {
        self.ensure_usable()?;
        Ok(self.config.sources())
    }

    /// Fetches, authenticates, verifies, and atomically commits finality for one
    /// deterministic execution output.
    ///
    /// An exact already-committed execution is returned without fetching or
    /// advancing trust. Reusing the same height with different execution bytes
    /// is a conflict. Submission or RPC success is never treated as finality.
    pub async fn advance(&mut self, execution: &ExecutedBlockV2) -> Result<AdvanceOutcome> {
        self.ensure_usable()?;
        execution
            .validate_chain_id(self.config.ledger_chain_id())
            .map_err(|_| CoordinatorError::InvalidInput("execution Ledger chain id differs"))?;
        let execution_bytes = serde_json::to_vec(execution)
            .map_err(|_| CoordinatorError::InvalidInput("execution output cannot be encoded"))?;
        if execution_bytes.is_empty() || execution_bytes.len() > self.config.max_execution_encoded_bytes() {
            return Err(CoordinatorError::InvalidInput(
                "execution output exceeds its encoded-byte bound",
            ));
        }
        if let Some(existing) = self.store.historical_by_height(&self.config, execution.height())? {
            if execution_digest(existing.proof().execution())? == execution_digest(execution)? {
                return Ok(AdvanceOutcome::Replayed(existing));
            }
            return Err(CoordinatorError::IdempotencyConflict);
        }
        if self.head.root.height() > execution.height() {
            return Err(CoordinatorError::InvalidInput(
                "execution height is behind the current trust root",
            ));
        }
        self.store
            .require_update_capacity(&self.config, execution.entries().len())?;
        ensure_root_live(&self.head.root, self.config.policy())?;
        let committing_height = execution
            .height()
            .checked_add(1)
            .ok_or(CoordinatorError::InvalidInput("execution height cannot advance"))?;
        let first_height = self
            .head
            .root
            .height()
            .checked_add(1)
            .ok_or(CoordinatorError::InvalidInput("trust-root height cannot advance"))?;
        let expected_blocks = committing_height
            .checked_sub(self.head.root.height())
            .and_then(|distance| usize::try_from(distance).ok())
            .ok_or(CoordinatorError::InvalidInput(
                "trace distance does not fit this platform",
            ))?;
        if expected_blocks == 0 || expected_blocks > self.config.policy().max_adjacent_headers() {
            return Err(CoordinatorError::InvalidInput(
                "trace distance is outside the configured bound",
            ));
        }
        let deadline = Instant::now().checked_add(self.config.operation_timeout()).ok_or(
            CoordinatorError::InvalidConfiguration("trace operation deadline overflows"),
        )?;

        let primary_peer = self.config.sources().primary().clone();
        let primary = fetch_and_authenticate(
            &self.transport,
            &self.authenticator,
            &self.config,
            &primary_peer,
            SourceRole::Primary,
            first_height,
            committing_height,
            expected_blocks,
            deadline,
        )
        .await?;
        let witness_peers = self.config.sources().witnesses().to_vec();
        let mut pending_witnesses = FuturesUnordered::new();
        for (index, peer) in witness_peers.iter().enumerate() {
            let index = u8::try_from(index)
                .map_err(|_| CoordinatorError::InvalidConfiguration("witness index does not fit u8"))?;
            pending_witnesses.push(fetch_and_authenticate(
                &self.transport,
                &self.authenticator,
                &self.config,
                peer,
                SourceRole::Witness(index),
                first_height,
                committing_height,
                expected_blocks,
                deadline,
            ));
        }
        let mut witnesses = Vec::with_capacity(self.config.policy().min_witnesses());
        while let Some(result) = pending_witnesses.next().await {
            if let Ok(mut witness) = result {
                let compact_index = u8::try_from(witnesses.len())
                    .map_err(|_| CoordinatorError::InvalidConfiguration("witness index does not fit u8"))?;
                witness.binding.role = SourceRole::Witness(compact_index);
                witnesses.push(witness);
                if witnesses.len() == self.config.policy().min_witnesses() {
                    break;
                }
            }
        }
        if witnesses.len() < self.config.policy().min_witnesses() {
            return Err(CoordinatorError::Transport);
        }

        let mut bindings = Vec::with_capacity(witnesses.len() + 1);
        bindings.push(primary.binding);
        bindings.extend(witnesses.iter().map(|witness| PreparedBinding {
            role: witness.binding.role,
            first_height: witness.binding.first_height,
            last_height: witness.binding.last_height,
            trace_digest: witness.binding.trace_digest,
            node_id: witness.binding.node_id,
        }));
        let prepared_authenticator = PreparedAuthenticator {
            ledger_chain_id: self.config.ledger_chain_id().clone(),
            bindings,
        };
        let verifier = FinalityVerifier::new(
            self.config.ledger_chain_id().clone(),
            self.config.policy(),
            prepared_authenticator,
        );
        let witness_refs = witnesses
            .iter()
            .map(|witness| witness.blocks.as_slice())
            .collect::<Vec<_>>();
        let verified = verifier.verify_execution(&self.head.root, &primary.blocks, &witness_refs, execution)?;
        let summary = summary_from_receipt(verified.receipt(), self.config.sources().version());
        validate_receipt_sources(&summary, self.config.sources())?;
        let (_, next_root) = verified.into_parts();
        let bundle = FinalityProofBundle {
            config_version: self.config.sources().version(),
            trusted_root: self.head.root.light_block().clone(),
            primary_trace: primary.blocks,
            witness_traces: witnesses.into_iter().map(|witness| witness.blocks).collect(),
            execution: execution.clone(),
        };
        #[cfg(test)]
        if self.fault == Some(FaultPoint::BeforePersistence) {
            self.fault = None;
            return Err(CoordinatorError::StorageUnavailable);
        }
        let result = self.store.commit_update(
            &self.config,
            &self.head,
            PreparedUpdate {
                bundle,
                summary,
                next_root,
            },
        );
        let (historical, next_head) = match result {
            Ok(applied) => applied,
            Err(CoordinatorError::AmbiguousCommit) => {
                self.poisoned = true;
                return Err(CoordinatorError::AmbiguousCommit);
            }
            Err(error) => return Err(error),
        };
        #[cfg(test)]
        if self.fault == Some(FaultPoint::AfterCommit) {
            self.fault = None;
            self.poisoned = true;
            return Err(CoordinatorError::AmbiguousCommit);
        }
        if let Err(error) = anchor_transition(
            &self.checkpoint_store,
            &self.config,
            Some(self.head.checkpoint),
            next_head.checkpoint,
        )
        .await
        {
            self.poisoned = true;
            return Err(error);
        }
        self.head = next_head;
        Ok(AdvanceOutcome::Applied(historical))
    }

    /// Returns a validated historical proof by execution height without
    /// fetching, authenticating, or advancing the current trust root.
    pub fn historical_by_height(&self, execution_height: u64) -> Result<Option<HistoricalFinality>> {
        self.ensure_usable()?;
        self.store.historical_by_height(&self.config, execution_height)
    }

    /// Returns a validated historical proof for an exact executed Ledger request
    /// without fetching, authenticating, or advancing the current trust root.
    pub fn historical_by_request(&self, request_digest: &RequestDigestV2) -> Result<Option<HistoricalRequestFinality>> {
        self.ensure_usable()?;
        self.store.historical_by_request(&self.config, request_digest)
    }

    /// Atomically rotates to one exact consecutive source-roster version.
    ///
    /// This local operator action does not fetch headers and never changes the
    /// pinned trust root. On an ambiguous commit, reopen with the intended next
    /// configuration first; if that exact open fails, reopen with the prior one.
    pub async fn rotate_sources(
        &mut self,
        expected_current_version: u64,
        next: SourceConfiguration,
    ) -> Result<RotationOutcome> {
        self.ensure_usable()?;
        if expected_current_version != self.config.sources().version() {
            return Err(CoordinatorError::ConfigurationConflict);
        }
        let prospective_config = self.config.with_sources(next.clone())?;
        let (outcome, next_head) = match self.store.rotate_sources(&self.config, &self.head, &next) {
            Ok(value) => value,
            Err(CoordinatorError::AmbiguousCommit) => {
                self.poisoned = true;
                return Err(CoordinatorError::AmbiguousCommit);
            }
            Err(error) => return Err(error),
        };
        if outcome == RotationOutcome::Applied {
            if let Err(error) = anchor_transition(
                &self.checkpoint_store,
                &self.config,
                Some(self.head.checkpoint),
                next_head.checkpoint,
            )
            .await
            {
                self.poisoned = true;
                return Err(error);
            }
            self.config = prospective_config;
            self.head = next_head;
        }
        Ok(outcome)
    }

    /// Prepares one bounded history seal intent without mutating SQLite or the
    /// external checkpoint. The caller must independently persist the returned
    /// canonical intent before calling [`Self::seal_history_epoch`].
    ///
    /// This bounded but synchronous planning pass should run on the daemon's
    /// blocking worker, not an async reactor thread.
    pub fn prepare_history_epoch(&mut self) -> Result<Option<HistorySealIntent>> {
        self.ensure_usable()?;
        self.store.prepare_history_manifest(&self.config, &self.head)
    }

    /// Seals one epoch within its configured transition, aggregate proof-byte,
    /// and request-mapping limits into the exact independently retained
    /// `intent`, then anchors that manifest through the independent checkpoint
    /// CAS. Absolute maxima are 256 transitions, 256 MiB, and 65,536 requests.
    ///
    /// Full proof rows remain immutable and queryable. Regularly sealing epochs
    /// bounds restart and historical ancestry work without deleting evidence.
    pub fn seal_history_epoch<'a>(
        &'a mut self,
        intent: &HistorySealIntent,
    ) -> Result<impl std::future::Future<Output = Result<HistorySealOutcome>> + 'a> {
        self.ensure_usable()?;
        let (outcome, next_head) = match self.store.seal_history_manifest(&self.config, &self.head, intent) {
            Ok(value) => value,
            Err(CoordinatorError::AmbiguousCommit) => {
                self.poisoned = true;
                return Err(CoordinatorError::AmbiguousCommit);
            }
            Err(error) => return Err(error),
        };
        self.poisoned = matches!(outcome, HistorySealOutcome::Sealed { .. });
        #[cfg(test)]
        if self.fault == Some(FaultPoint::AfterCommit) {
            self.fault = None;
            return Err(CoordinatorError::AmbiguousCommit);
        }
        Ok(async move {
            if matches!(outcome, HistorySealOutcome::Sealed { .. }) {
                anchor_transition(
                    &self.checkpoint_store,
                    &self.config,
                    Some(self.head.checkpoint),
                    next_head.checkpoint,
                )
                .await?;
                self.head = next_head;
                self.poisoned = false;
            }
            Ok(outcome)
        })
    }

    fn ensure_usable(&self) -> Result<()> {
        if self.poisoned {
            Err(CoordinatorError::Poisoned)
        } else {
            Ok(())
        }
    }

    #[cfg(test)]
    pub(crate) fn inject_fault(&mut self, fault: FaultPoint) {
        self.fault = Some(fault);
    }
}

#[allow(clippy::too_many_arguments)]
async fn fetch_and_authenticate<T, A>(
    transport: &T,
    authenticator: &A,
    config: &CoordinatorConfig,
    peer: &PeerIdentity,
    role: SourceRole,
    first_height: u64,
    last_height: u64,
    expected_blocks: usize,
    deadline: Instant,
) -> Result<AuthenticatedFetch>
where
    T: TraceTransport,
    A: TracePeerAuthenticator<T::Evidence>,
{
    let request = TraceFetchRequest::new(
        config.ledger_chain_id().clone(),
        config.sources().version(),
        role,
        first_height,
        last_height,
        expected_blocks,
        config.max_trace_encoded_bytes(),
        deadline,
    );
    let fetch_timeout = remaining(deadline)?;
    let fetched: FetchedTrace<T::Body, T::Evidence> =
        tokio::time::timeout(fetch_timeout, transport.fetch(peer, &request))
            .await
            .map_err(|_| CoordinatorError::DeadlineExceeded)?
            .map_err(|_| CoordinatorError::Transport)?;
    let (body, evidence) = fetched.into_parts();
    let read_limit = u64::try_from(request.max_encoded_bytes())
        .map_err(|_| CoordinatorError::InvalidConfiguration("trace byte limit does not fit u64"))?
        .checked_add(1)
        .ok_or(CoordinatorError::InvalidConfiguration("trace read limit overflows"))?;
    let mut encoded = Vec::with_capacity(request.max_encoded_bytes().min(64 * 1024));
    let mut bounded_body = body.take(read_limit);
    let read_timeout = remaining(deadline)?;
    tokio::time::timeout(read_timeout, bounded_body.read_to_end(&mut encoded))
        .await
        .map_err(|_| CoordinatorError::DeadlineExceeded)?
        .map_err(|_| CoordinatorError::Transport)?;
    if encoded.is_empty() || encoded.len() > request.max_encoded_bytes() {
        return Err(CoordinatorError::InvalidInput("raw trace body exceeds its byte bound"));
    }
    let blocks: Vec<LightBlock> = serde_json::from_slice(&encoded)
        .map_err(|_| CoordinatorError::InvalidInput("fetched trace cannot be decoded"))?;
    if blocks.len() != expected_blocks || blocks.is_empty() || blocks.len() > request.max_blocks() {
        return Err(CoordinatorError::InvalidInput("fetched trace count differs"));
    }
    let reencoded = to_vec(&blocks).map_err(|_| CoordinatorError::InvalidInput("fetched trace cannot be encoded"))?;
    if reencoded.is_empty() || reencoded.len() > request.max_encoded_bytes() {
        return Err(CoordinatorError::InvalidInput(
            "decoded trace re-encoding exceeds its byte bound",
        ));
    }
    let digest = trace_digest_from_bytes(&reencoded);
    let authentication_timeout = remaining(deadline)?;
    tokio::time::timeout(
        authentication_timeout,
        authenticator.authenticate(
            peer,
            AuthenticationContext::new(&request, &blocks, digest, encoded.len()),
            &evidence,
        ),
    )
    .await
    .map_err(|_| CoordinatorError::DeadlineExceeded)?
    .map_err(|_| CoordinatorError::Authentication)?;
    Ok(AuthenticatedFetch {
        blocks,
        binding: PreparedBinding {
            role,
            first_height,
            last_height,
            trace_digest: digest,
            node_id: peer.node_id(),
        },
    })
}

fn remaining(deadline: Instant) -> Result<std::time::Duration> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|remaining| !remaining.is_zero())
        .ok_or(CoordinatorError::DeadlineExceeded)
}

fn trace_digest(blocks: &[LightBlock]) -> Result<[u8; 32]> {
    let encoded =
        to_vec(blocks).map_err(|_| CoordinatorError::InvalidInput("trace cannot be encoded for authentication"))?;
    Ok(trace_digest_from_bytes(&encoded))
}

fn trace_digest_from_bytes(encoded: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(u64::try_from(TRACE_DOMAIN.len()).unwrap_or(u64::MAX).to_be_bytes());
    hasher.update(TRACE_DOMAIN);
    hasher.update(u64::try_from(encoded.len()).unwrap_or(u64::MAX).to_be_bytes());
    hasher.update(encoded);
    hasher.finalize().into()
}

fn summary_from_receipt(
    receipt: &thunderbolt_cometbft::CometBftFinalityReceipt,
    config_version: u64,
) -> FinalitySummary {
    FinalitySummary {
        ledger_chain_id: receipt.ledger_chain_id().clone(),
        application_version: receipt.application_version(),
        config_version,
        execution_height: receipt.execution_height(),
        execution_block_time_ms: receipt.execution_block_time_ms(),
        application_hash: receipt.application_hash().clone(),
        execution_header_hash: *receipt.execution_header_hash(),
        committing_height: receipt.committing_height(),
        committing_header_hash: *receipt.committing_header_hash(),
        primary_peer_id: receipt.primary_peer_id(),
        witness_peer_ids: receipt.witness_peer_ids().to_vec(),
    }
}

fn validate_receipt_sources(summary: &FinalitySummary, sources: &SourceConfiguration) -> Result<()> {
    if summary.primary_peer_id() != sources.primary().node_id()
        || summary.witness_peer_ids().is_empty()
        || summary.witness_peer_ids().len() > sources.witnesses().len()
    {
        return Err(CoordinatorError::Authentication);
    }
    let mut seen = std::collections::BTreeSet::new();
    for witness in summary.witness_peer_ids() {
        if !seen.insert(*witness)
            || !sources
                .witnesses()
                .iter()
                .any(|expected| expected.node_id() == *witness)
        {
            return Err(CoordinatorError::Authentication);
        }
    }
    Ok(())
}

async fn reverify_pending_finality<T, A>(
    transport: &T,
    authenticator: &A,
    config: &CoordinatorConfig,
    prior_root: &PinnedTrustRoot,
    local: &HistoricalFinality,
    head: &StoredHead,
) -> Result<()>
where
    T: TraceTransport,
    A: TracePeerAuthenticator<T::Evidence>,
{
    ensure_root_live(prior_root, config.policy())?;
    let execution = local.proof().execution();
    let committing_height = execution
        .height()
        .checked_add(1)
        .ok_or(CoordinatorError::CheckpointConflict)?;
    let first_height = prior_root
        .height()
        .checked_add(1)
        .ok_or(CoordinatorError::CheckpointConflict)?;
    let expected_blocks = committing_height
        .checked_sub(prior_root.height())
        .and_then(|distance| usize::try_from(distance).ok())
        .ok_or(CoordinatorError::CheckpointConflict)?;
    let deadline = Instant::now()
        .checked_add(config.operation_timeout())
        .ok_or(CoordinatorError::DeadlineExceeded)?;
    let primary = fetch_and_authenticate(
        transport,
        authenticator,
        config,
        config.sources().primary(),
        SourceRole::Primary,
        first_height,
        committing_height,
        expected_blocks,
        deadline,
    )
    .await?;
    let mut witnesses = Vec::with_capacity(local.summary().witness_peer_ids().len());
    for (compact_index, node_id) in local.summary().witness_peer_ids().iter().enumerate() {
        let (configured_index, peer) = config
            .sources()
            .witnesses()
            .iter()
            .enumerate()
            .find(|(_, candidate)| candidate.node_id() == *node_id)
            .ok_or(CoordinatorError::Authentication)?;
        let configured_index = u8::try_from(configured_index)
            .map_err(|_| CoordinatorError::InvalidConfiguration("witness index does not fit u8"))?;
        let mut witness = fetch_and_authenticate(
            transport,
            authenticator,
            config,
            peer,
            SourceRole::Witness(configured_index),
            first_height,
            committing_height,
            expected_blocks,
            deadline,
        )
        .await?;
        witness.binding.role = SourceRole::Witness(
            u8::try_from(compact_index)
                .map_err(|_| CoordinatorError::InvalidConfiguration("witness index does not fit u8"))?,
        );
        witnesses.push(witness);
    }
    let mut bindings = Vec::with_capacity(witnesses.len() + 1);
    bindings.push(primary.binding);
    bindings.extend(witnesses.iter().map(|witness| PreparedBinding {
        role: witness.binding.role,
        first_height: witness.binding.first_height,
        last_height: witness.binding.last_height,
        trace_digest: witness.binding.trace_digest,
        node_id: witness.binding.node_id,
    }));
    let verifier = FinalityVerifier::new(
        config.ledger_chain_id().clone(),
        config.policy(),
        PreparedAuthenticator {
            ledger_chain_id: config.ledger_chain_id().clone(),
            bindings,
        },
    );
    let witness_refs = witnesses
        .iter()
        .map(|witness| witness.blocks.as_slice())
        .collect::<Vec<_>>();
    let verified = verifier.verify_execution(prior_root, &primary.blocks, &witness_refs, execution)?;
    let live_summary = summary_from_receipt(verified.receipt(), config.sources().version());
    if &live_summary != local.summary()
        || verified.next_trust_root().height() != head.root.height()
        || verified.next_trust_root().header_hash() != head.root.header_hash()
        || !same_trace_without_provider(local.proof().primary_trace(), &primary.blocks)
        || local.proof().witness_traces().len() != witnesses.len()
        || !local
            .proof()
            .witness_traces()
            .iter()
            .zip(&witnesses)
            .all(|(stored, live)| same_trace_without_provider(stored, &live.blocks))
    {
        return Err(CoordinatorError::CheckpointConflict);
    }
    Ok(())
}

fn same_trace_without_provider(left: &[LightBlock], right: &[LightBlock]) -> bool {
    left.len() == right.len()
        && left.iter().zip(right).all(|(left_block, right_block)| {
            left_block.signed_header == right_block.signed_header
                && left_block.validators == right_block.validators
                && left_block.next_validators == right_block.next_validators
        })
}

async fn require_prior_checkpoint<S: TrustCheckpointStore>(
    store: &S,
    config: &CoordinatorConfig,
    head: &StoredHead,
) -> Result<()> {
    let anchored = tokio::time::timeout(config.operation_timeout(), store.load_checkpoint(config.identity()))
        .await
        .map_err(|_| CoordinatorError::DeadlineExceeded)?
        .map_err(|_| CoordinatorError::CheckpointUnavailable)?;
    if anchored == head.prior_checkpoint {
        Ok(())
    } else {
        Err(CoordinatorError::CheckpointConflict)
    }
}

async fn require_exact_checkpoint<S: TrustCheckpointStore>(
    store: &S,
    config: &CoordinatorConfig,
    head: &StoredHead,
) -> Result<()> {
    let anchored = tokio::time::timeout(config.operation_timeout(), store.load_checkpoint(config.identity()))
        .await
        .map_err(|_| CoordinatorError::DeadlineExceeded)?
        .map_err(|_| CoordinatorError::CheckpointUnavailable)?;
    if anchored == Some(head.checkpoint) {
        return Ok(());
    }
    Err(CoordinatorError::CheckpointConflict)
}

async fn recover_transition<S: TrustCheckpointStore>(
    store: &S,
    config: &CoordinatorConfig,
    head: &StoredHead,
) -> Result<()> {
    let anchored = tokio::time::timeout(config.operation_timeout(), store.load_checkpoint(config.identity()))
        .await
        .map_err(|_| CoordinatorError::DeadlineExceeded)?
        .map_err(|_| CoordinatorError::CheckpointUnavailable)?;
    if anchored == Some(head.checkpoint) {
        return Ok(());
    }
    if anchored != head.prior_checkpoint {
        return Err(CoordinatorError::CheckpointConflict);
    }
    anchor_transition(store, config, head.prior_checkpoint, head.checkpoint).await
}

async fn anchor_transition<S: TrustCheckpointStore>(
    store: &S,
    config: &CoordinatorConfig,
    expected: Option<TrustCheckpoint>,
    next: TrustCheckpoint,
) -> Result<()> {
    match tokio::time::timeout(
        config.operation_timeout(),
        store.compare_and_swap_checkpoint(config.identity(), expected, next),
    )
    .await
    .map_err(|_| CoordinatorError::DeadlineExceeded)?
    .map_err(|_| CoordinatorError::CheckpointUnavailable)?
    {
        TrustCheckpointCasOutcome::Advanced | TrustCheckpointCasOutcome::AlreadyCurrent => Ok(()),
        TrustCheckpointCasOutcome::Conflict(current) if current == Some(next) => Ok(()),
        TrustCheckpointCasOutcome::Conflict(_) => Err(CoordinatorError::CheckpointConflict),
    }
}

fn ensure_root_live(root: &PinnedTrustRoot, policy: thunderbolt_cometbft::FinalityPolicy) -> Result<()> {
    let root_nanos = root.light_block().signed_header.header.time.unix_timestamp_nanos();
    if root_nanos <= 0 {
        return Err(CoordinatorError::ExpiredTrustRoot);
    }
    let trusting_nanos = i128::try_from(policy.trusting_period().as_nanos())
        .map_err(|_| CoordinatorError::InvalidConfiguration("trusting period does not fit i128"))?;
    let expires_at = root_nanos
        .checked_add(trusting_nanos)
        .ok_or(CoordinatorError::ExpiredTrustRoot)?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| CoordinatorError::ExpiredTrustRoot)?;
    let now_nanos = i128::try_from(now.as_nanos()).map_err(|_| CoordinatorError::ExpiredTrustRoot)?;
    if expires_at <= now_nanos {
        return Err(CoordinatorError::ExpiredTrustRoot);
    }
    Ok(())
}
