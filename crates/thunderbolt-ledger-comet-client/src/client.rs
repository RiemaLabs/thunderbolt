use std::path::Path;

use serde::{Deserialize, Serialize};
use thunderbolt_cometbft::PinnedTrustRoot;
use thunderbolt_cometbft_client::{
    AdvanceOutcome, CurrentTrustRoot, HistoricalFinality, HistorySealIntent, HistorySealOutcome, PeerIdentity,
    RotationOutcome, SourceConfiguration, TrustCheckpointStore, TrustCoordinator,
};
use thunderbolt_cometbft_rpc::{
    AuthenticatedBroadcastTxSyncV2, CometBftRpcTransport, LedgerAbciQueryV2, RpcPeerAuthenticator, RpcTransportError,
};
use thunderbolt_ledger::{
    ChannelContextIdV2, EntryHashV2, ExecutedBlockV2, LedgerChainIdV2, ParticipantIdV2, RequestDigestV2,
    SignedProposalV2, MAX_BLOCK_ENTRIES,
};
use thunderbolt_ledger_rpc::{EntryLocationRequestV2, ExecutionRangeRequestV2, RpcRequestV2, RpcResponseV2};

use crate::types::{
    FinalizedAbsenceCapabilityV2, HistoricalBlockReferenceV2, HistoricalEntryReferenceV2, PreparedExecutionRangeV2,
};
use crate::{
    ClientError, FinalizedBlockCapabilityV2, FinalizedExecutionSummaryV2, FinalizedFirstLocationV2, FinalizedRangeV2,
    HolderFinalityCapabilityV2, LedgerCometClientConfig, LedgerCometClientLimits, ReconciledSubmissionV2, Result,
};

const ABCI_NOT_FOUND_CODE: u32 = 4;

type ConcreteCoordinator<S> = TrustCoordinator<CometBftRpcTransport, RpcPeerAuthenticator, S>;

/// Concrete crash-safe finalized Ledger client.
pub struct LedgerCometClient<S>
where
    S: TrustCheckpointStore,
{
    coordinator: Option<ConcreteCoordinator<S>>,
    ledger_rpc: CometBftRpcTransport,
    coordinator_identity: thunderbolt_cometbft_client::TrustCoordinatorIdentity,
    ledger_chain_id: LedgerChainIdV2,
    profile_id: crate::ClientProfileIdV2,
    limits: LedgerCometClientLimits,
    max_execution_encoded_bytes: usize,
    allowed_peers: Vec<PeerIdentity>,
}

impl<S> LedgerCometClient<S>
where
    S: TrustCheckpointStore + 'static,
{
    /// Creates and independently anchors a new trust coordinator before use.
    pub async fn create(
        path: impl AsRef<Path>,
        config: LedgerCometClientConfig,
        initial_root: PinnedTrustRoot,
        checkpoint_store: S,
    ) -> Result<Self> {
        let (coordinator_transport, ledger_rpc) = build_transports(&config)?;
        let coordinator = TrustCoordinator::create(
            path,
            config.coordinator().clone(),
            initial_root,
            coordinator_transport,
            RpcPeerAuthenticator,
            checkpoint_store,
        )
        .await?;
        Ok(Self::from_parts(coordinator, ledger_rpc, &config))
    }

    /// Opens only an exact externally checkpointed coordinator and matching profile.
    pub async fn open(path: impl AsRef<Path>, config: LedgerCometClientConfig, checkpoint_store: S) -> Result<Self> {
        let (coordinator_transport, ledger_rpc) = build_transports(&config)?;
        let coordinator = TrustCoordinator::open(
            path,
            config.coordinator().clone(),
            coordinator_transport,
            RpcPeerAuthenticator,
            checkpoint_store,
        )
        .await?;
        Ok(Self::from_parts(coordinator, ledger_rpc, &config))
    }

    /// Recovers a bootstrap whose coordinator SQLite commit preceded checkpoint anchoring.
    pub async fn recover_bootstrap(
        path: impl AsRef<Path>,
        config: LedgerCometClientConfig,
        initial_root: &PinnedTrustRoot,
        checkpoint_store: S,
    ) -> Result<Self> {
        let (coordinator_transport, ledger_rpc) = build_transports(&config)?;
        let coordinator = TrustCoordinator::recover_bootstrap(
            path,
            config.coordinator().clone(),
            initial_root,
            coordinator_transport,
            RpcPeerAuthenticator,
            checkpoint_store,
        )
        .await?;
        Ok(Self::from_parts(coordinator, ledger_rpc, &config))
    }

    /// Recovers a latest finality transition only after live trace reauthentication.
    pub async fn recover_finality(
        path: impl AsRef<Path>,
        config: LedgerCometClientConfig,
        expected_execution: &ExecutedBlockV2,
        checkpoint_store: S,
    ) -> Result<Self> {
        let (coordinator_transport, ledger_rpc) = build_transports(&config)?;
        let coordinator = TrustCoordinator::recover_finality(
            path,
            config.coordinator().clone(),
            expected_execution,
            coordinator_transport,
            RpcPeerAuthenticator,
            checkpoint_store,
        )
        .await?;
        Ok(Self::from_parts(coordinator, ledger_rpc, &config))
    }

    /// Recovers an explicitly intended consecutive source rotation after its
    /// SQLite commit but before external checkpoint acknowledgement.
    pub async fn recover_rotation(
        path: impl AsRef<Path>,
        config: LedgerCometClientConfig,
        expected_previous_version: u64,
        checkpoint_store: S,
    ) -> Result<Self> {
        let (coordinator_transport, ledger_rpc) = build_transports(&config)?;
        let coordinator = TrustCoordinator::recover_rotation(
            path,
            config.coordinator().clone(),
            expected_previous_version,
            coordinator_transport,
            RpcPeerAuthenticator,
            checkpoint_store,
        )
        .await?;
        Ok(Self::from_parts(coordinator, ledger_rpc, &config))
    }

    /// Recovers one latest history seal only from its independently retained intent.
    pub async fn recover_history_epoch(
        path: impl AsRef<Path>,
        config: LedgerCometClientConfig,
        intent: &HistorySealIntent,
        checkpoint_store: S,
    ) -> Result<Self> {
        let (coordinator_transport, ledger_rpc) = build_transports(&config)?;
        let recovery = TrustCoordinator::recover_history_epoch(
            path,
            config.coordinator().clone(),
            intent,
            coordinator_transport,
            RpcPeerAuthenticator,
            checkpoint_store,
        )?;
        let coordinator = recovery.await?;
        Ok(Self::from_parts(coordinator, ledger_rpc, &config))
    }

    fn from_parts(
        coordinator: ConcreteCoordinator<S>,
        ledger_rpc: CometBftRpcTransport,
        config: &LedgerCometClientConfig,
    ) -> Self {
        Self {
            coordinator: Some(coordinator),
            ledger_rpc,
            coordinator_identity: config.coordinator().identity(),
            ledger_chain_id: config.coordinator().ledger_chain_id().clone(),
            profile_id: config.profile_id(),
            limits: config.limits(),
            max_execution_encoded_bytes: config.coordinator().max_execution_encoded_bytes(),
            allowed_peers: config
                .rpc()
                .peers()
                .iter()
                .map(|peer| peer.identity().clone())
                .collect(),
        }
    }

    pub(crate) const fn profile_id(&self) -> crate::ClientProfileIdV2 {
        self.profile_id
    }

    pub(crate) const fn coordinator_identity(&self) -> thunderbolt_cometbft_client::TrustCoordinatorIdentity {
        self.coordinator_identity
    }

    pub(crate) const fn ledger_chain_id(&self) -> &LedgerChainIdV2 {
        &self.ledger_chain_id
    }

    pub(crate) const fn max_execution_encoded_bytes(&self) -> usize {
        self.max_execution_encoded_bytes
    }

    /// Returns the exact current durable light-client root.
    pub fn current_trust_root(&self) -> Result<CurrentTrustRoot> {
        Ok(self.coordinator()?.current_trust_root()?)
    }

    /// Returns the current authenticated source roster.
    pub fn source_configuration(&self) -> Result<&SourceConfiguration> {
        Ok(self.coordinator()?.source_configuration()?)
    }

    /// Fetches and validates an exact P2 range without mutating trust state.
    /// Callers must durably retain every returned intent before finalization.
    pub async fn prepare_range(&self, request: &ExecutionRangeRequestV2) -> Result<PreparedExecutionRangeV2> {
        if request.block_count() > self.limits.max_range_blocks()
            || request.cursor().ledger_chain_id() != self.ledger_chain_id()
        {
            return Err(ClientError::Capacity);
        }
        let root = self.coordinator()?.current_trust_root()?;
        if request.cursor().next_height() > root.height() {
            return Err(ClientError::BindingMismatch);
        }
        let primary = self.current_primary()?;
        let query = LedgerAbciQueryV2::execution_range(request.clone());
        let response = self
            .ledger_rpc
            .abci_query(&primary, &self.ledger_chain_id, &query, self.limits.rpc_timeout())
            .await?;
        let rpc_request = RpcRequestV2::ExecutionRange(request.clone());
        let decoded =
            RpcResponseV2::from_canonical_bytes_for(response.value(), &rpc_request).map_err(|_| ClientError::Codec)?;
        let RpcResponseV2::ExecutionRange(range) = decoded.response() else {
            return Err(ClientError::BindingMismatch);
        };
        PreparedExecutionRangeV2::from_staged_blocks(
            self.profile_id(),
            self.coordinator_identity(),
            range.blocks().to_vec(),
            range.next_cursor().clone(),
            self.max_execution_encoded_bytes(),
        )
    }

    /// Finalizes a prepared range after its authority-free intents have been durably retained.
    pub async fn finalize_prepared_range(&mut self, prepared: &PreparedExecutionRangeV2) -> Result<FinalizedRangeV2> {
        if prepared.intents.is_empty() || prepared.intents.len() > usize::from(self.limits.max_range_blocks()) {
            return Err(ClientError::Capacity);
        }
        let mut finalized = Vec::with_capacity(prepared.intents.len());
        for intent in &prepared.intents {
            if intent.profile_id != *self.profile_id.as_bytes()
                || intent.coordinator_identity != *self.coordinator_identity.as_bytes()
                || intent.execution.ledger_chain_id() != &self.ledger_chain_id
            {
                return Err(ClientError::BindingMismatch);
            }
            let historical = match self.advance_cancellation_safe(intent.execution.clone()).await? {
                AdvanceOutcome::Applied(historical) | AdvanceOutcome::Replayed(historical) => historical,
            };
            validate_historical(&historical, &intent.execution, &self.ledger_chain_id)?;
            finalized.push(block_capability(
                self.profile_id,
                self.coordinator_identity,
                &self.ledger_chain_id,
                historical,
            )?);
        }
        Ok(FinalizedRangeV2 {
            blocks: finalized,
            next_cursor: prepared.next_cursor.clone(),
        })
    }

    /// Returns a freshly revalidated private capability for one complete finalized block.
    ///
    /// Empty executed blocks are first-class and return a capability with an
    /// empty ordered entry list.
    pub fn finalized_block(&self, execution_height: u64) -> Result<FinalizedBlockCapabilityV2> {
        let historical = self
            .coordinator()?
            .historical_by_height(execution_height)?
            .ok_or(ClientError::HistoryUnavailable)?;
        block_capability(
            self.profile_id,
            self.coordinator_identity,
            &self.ledger_chain_id,
            historical,
        )
    }

    /// Revalidates an authority-free whole-block reference against externally
    /// anchored coordinator history on every invocation.
    pub fn revalidate_block_reference(
        &self,
        reference: &HistoricalBlockReferenceV2,
    ) -> Result<FinalizedBlockCapabilityV2> {
        if reference.profile_id != self.profile_id
            || reference.coordinator_identity != self.coordinator_identity
            || reference.ledger_chain_id != self.ledger_chain_id
        {
            return Err(ClientError::BindingMismatch);
        }
        let capability = self.finalized_block(reference.execution_height)?;
        if capability.reference != *reference {
            return Err(ClientError::BindingMismatch);
        }
        Ok(capability)
    }

    /// Returns a revalidated private capability for one finalized block entry.
    pub fn finalized_entry(&self, execution_height: u64, block_index: u32) -> Result<HolderFinalityCapabilityV2> {
        let coordinator = self.coordinator()?;
        let historical = coordinator
            .historical_by_height(execution_height)?
            .ok_or(ClientError::HistoryUnavailable)?;
        entry_capability(
            coordinator,
            self.profile_id,
            self.coordinator_identity,
            &self.ledger_chain_id,
            historical,
            block_index,
        )
    }

    /// Revalidates an authority-free reference against the externally anchored
    /// coordinator database on every invocation.
    pub fn revalidate_reference(&self, reference: &HistoricalEntryReferenceV2) -> Result<HolderFinalityCapabilityV2> {
        if reference.profile_id != self.profile_id
            || reference.coordinator_identity != self.coordinator_identity
            || reference.ledger_chain_id != self.ledger_chain_id
        {
            return Err(ClientError::BindingMismatch);
        }
        let capability = self.finalized_entry(reference.execution_height, reference.block_index)?;
        if capability.reference != *reference {
            return Err(ClientError::BindingMismatch);
        }
        Ok(capability)
    }

    /// Authenticates the P2 first-location result against finalized coordinator
    /// history. An absence requires a bounded scan of every retained finalized
    /// block from height one through the exact checkpoint.
    pub async fn finalized_first_location(
        &mut self,
        request: &EntryLocationRequestV2,
    ) -> Result<FinalizedFirstLocationV2> {
        if request.ledger_chain_id() != &self.ledger_chain_id {
            return Err(ClientError::BindingMismatch);
        }
        let through = self
            .coordinator()?
            .historical_by_height(request.through_height())?
            .ok_or(ClientError::HistoryUnavailable)?;
        validate_historical(&through, through.proof().execution(), &self.ledger_chain_id)?;
        if through.summary().application_hash() != request.expected_through_app_hash() {
            return Err(ClientError::BindingMismatch);
        }
        let primary = self.current_primary()?;
        let query = LedgerAbciQueryV2::entry_location(request.clone());
        let response = self
            .ledger_rpc
            .abci_query(&primary, &self.ledger_chain_id, &query, self.limits.rpc_timeout())
            .await?;
        let rpc_request = RpcRequestV2::EntryLocation(request.clone());
        let decoded =
            RpcResponseV2::from_canonical_bytes_for(response.value(), &rpc_request).map_err(|_| ClientError::Codec)?;
        let RpcResponseV2::EntryLocation(location) = decoded.response() else {
            return Err(ClientError::BindingMismatch);
        };
        if let Some(location) = location.location() {
            let capability = self.finalized_entry(location.height(), location.block_index())?;
            if capability.reference.channel_context_id != *request.channel_context_id()
                || capability.reference.entry_hash != *request.entry_hash()
                || capability.reference.execution_height > request.through_height()
            {
                return Err(ClientError::BindingMismatch);
            }
            let first = self
                .coordinator()?
                .historical_by_request(capability.reference.request_digest())?
                .ok_or(ClientError::HistoryUnavailable)?;
            if first.finality().summary().execution_height() != location.height()
                || first.block_index() != location.block_index()
            {
                return Err(ClientError::BindingMismatch);
            }
            return Ok(FinalizedFirstLocationV2::Found(Box::new(capability)));
        }

        if request.through_height() > u64::from(self.limits.max_locator_scan_blocks()) {
            return Err(ClientError::Capacity);
        }
        let coordinator = self.coordinator.take().ok_or(ClientError::Poisoned)?;
        let chain = self.ledger_chain_id.clone();
        let channel = request.channel_context_id().clone();
        let entry_hash = request.entry_hash().clone();
        let through_height = request.through_height();
        let joined = tokio::task::spawn_blocking(move || {
            let result = scan_finalized_absence(&coordinator, &chain, &channel, &entry_hash, through_height);
            (coordinator, result)
        })
        .await;
        let (coordinator, scan_result) = joined.map_err(|_| ClientError::Poisoned)?;
        self.coordinator = Some(coordinator);
        scan_result?;
        Ok(FinalizedFirstLocationV2::Absent(Box::new(
            FinalizedAbsenceCapabilityV2 {
                profile_id: self.profile_id,
                channel_context_id: request.channel_context_id().clone(),
                entry_hash: request.entry_hash().clone(),
                through_summary: FinalizedExecutionSummaryV2::from_finality(through.summary()),
            },
        )))
    }

    /// Performs one one-shot P3 submission. This method never retries a write.
    pub async fn broadcast(&self, proposal: &SignedProposalV2) -> Result<AuthenticatedBroadcastTxSyncV2> {
        let primary = self.current_primary()?;
        Ok(self
            .ledger_rpc
            .broadcast_tx_sync(&primary, &self.ledger_chain_id, proposal, self.limits.rpc_timeout())
            .await?)
    }

    /// Reconciles a one-shot or ambiguous submission only through the exact
    /// actor-request query and already durable coordinator finality.
    pub async fn reconcile_submission(
        &self,
        proposal: &SignedProposalV2,
        at_height: u64,
    ) -> Result<ReconciledSubmissionV2> {
        proposal.verify().map_err(|_| ClientError::BindingMismatch)?;
        proposal
            .body()
            .validate_chain_id(&self.ledger_chain_id)
            .map_err(|_| ClientError::BindingMismatch)?;
        let through = self
            .coordinator()?
            .historical_by_height(at_height)?
            .ok_or(ClientError::HistoryUnavailable)?;
        validate_historical(&through, through.proof().execution(), &self.ledger_chain_id)?;
        let channel = ChannelContextIdV2::from_bytes(
            proposal
                .body()
                .channel()
                .context_id()
                .map_err(|_| ClientError::BindingMismatch)?,
        )
        .map_err(|_| ClientError::BindingMismatch)?;
        let participant = proposal
            .body()
            .participant_id()
            .map_err(|_| ClientError::BindingMismatch)?;
        let request_digest = proposal.body().request_id().digest().clone();
        let query =
            LedgerAbciQueryV2::request(channel.clone(), participant.clone(), request_digest.clone(), at_height)?;
        let primary = self.current_primary()?;
        let response = match self
            .ledger_rpc
            .abci_query(&primary, &self.ledger_chain_id, &query, self.limits.rpc_timeout())
            .await
        {
            Ok(response) => response,
            Err(RpcTransportError::AbciQueryRejected { code }) if code == ABCI_NOT_FOUND_CODE => {
                if self.coordinator()?.historical_by_request(&request_digest)?.is_some() {
                    return Err(ClientError::BindingMismatch);
                }
                return Ok(ReconciledSubmissionV2::Unknown);
            }
            Err(error) => return Err(error.into()),
        };
        let mapping: RequestQueryValue = decode_canonical(response.value())?;
        let entry_hash = proposal.body().entry_hash().map_err(|_| ClientError::BindingMismatch)?;
        if mapping.channel_context_id != channel
            || mapping.participant_id != participant
            || mapping.request_digest != request_digest
            || mapping.entry_hash != entry_hash
            || mapping.first_height == 0
            || mapping.first_height > at_height
            || usize::try_from(mapping.first_block_index).map_or(true, |index| index >= MAX_BLOCK_ENTRIES)
        {
            return Err(ClientError::BindingMismatch);
        }
        let first = self
            .coordinator()?
            .historical_by_request(&request_digest)?
            .ok_or(ClientError::HistoryUnavailable)?;
        if first.finality().summary().execution_height() != mapping.first_height
            || first.block_index() != mapping.first_block_index
        {
            return Err(ClientError::BindingMismatch);
        }
        let capability = self.finalized_entry(mapping.first_height, mapping.first_block_index)?;
        if capability.entry.metadata().request_digest() != &request_digest
            || capability.entry.metadata().entry_hash() != &entry_hash
        {
            return Err(ClientError::BindingMismatch);
        }
        Ok(ReconciledSubmissionV2::Finalized(Box::new(capability)))
    }

    /// Rotates to one consecutive source roster already present in the pinned
    /// allowed RPC peer set. References retain their historical source version
    /// while the static client profile continues to bind the full allowed roster.
    pub async fn rotate_sources(
        &mut self,
        expected_current_version: u64,
        next: SourceConfiguration,
    ) -> Result<RotationOutcome> {
        if !source_is_allowed(&self.allowed_peers, next.primary())
            || next
                .witnesses()
                .iter()
                .any(|peer| !source_is_allowed(&self.allowed_peers, peer))
        {
            return Err(ClientError::InvalidConfiguration(
                "rotated source is absent from the pinned RPC roster",
            ));
        }
        self.rotate_cancellation_safe(expected_current_version, next).await
    }

    /// Prepares a bounded authority-free history-seal intent for external retention.
    pub fn prepare_history_epoch(&mut self) -> Result<Option<HistorySealIntent>> {
        Ok(self.coordinator_mut()?.prepare_history_epoch()?)
    }

    /// Seals one independently retained history intent and anchors its checkpoint.
    pub async fn seal_history_epoch(&mut self, intent: &HistorySealIntent) -> Result<HistorySealOutcome> {
        let seal = self.coordinator_mut()?.seal_history_epoch(intent)?;
        Ok(seal.await?)
    }

    fn current_primary(&self) -> Result<PeerIdentity> {
        Ok(self.coordinator()?.source_configuration()?.primary().clone())
    }

    fn coordinator(&self) -> Result<&ConcreteCoordinator<S>> {
        self.coordinator.as_ref().ok_or(ClientError::Poisoned)
    }

    fn coordinator_mut(&mut self) -> Result<&mut ConcreteCoordinator<S>> {
        self.coordinator.as_mut().ok_or(ClientError::Poisoned)
    }

    async fn advance_cancellation_safe(&mut self, execution: ExecutedBlockV2) -> Result<AdvanceOutcome> {
        let mut coordinator = self.coordinator.take().ok_or(ClientError::Poisoned)?;
        let outcome = coordinator.advance(&execution).await;
        self.coordinator = Some(coordinator);
        Ok(outcome?)
    }

    async fn rotate_cancellation_safe(
        &mut self,
        expected_current_version: u64,
        next: SourceConfiguration,
    ) -> Result<RotationOutcome> {
        let mut coordinator = self.coordinator.take().ok_or(ClientError::Poisoned)?;
        let outcome = coordinator.rotate_sources(expected_current_version, next).await;
        self.coordinator = Some(coordinator);
        Ok(outcome?)
    }
}

fn build_transports(config: &LedgerCometClientConfig) -> Result<(CometBftRpcTransport, CometBftRpcTransport)> {
    let coordinator = CometBftRpcTransport::new(config.rpc().clone())?;
    let ledger = CometBftRpcTransport::new(config.rpc().clone())?;
    Ok((coordinator, ledger))
}

fn source_is_allowed(allowed: &[PeerIdentity], source: &PeerIdentity) -> bool {
    allowed.iter().any(|peer| peer == source)
}

fn scan_finalized_absence<S>(
    coordinator: &ConcreteCoordinator<S>,
    expected_chain: &LedgerChainIdV2,
    channel: &ChannelContextIdV2,
    entry_hash: &EntryHashV2,
    through_height: u64,
) -> Result<()>
where
    S: TrustCheckpointStore,
{
    for height in 1..=through_height {
        let historical = coordinator
            .historical_by_height(height)?
            .ok_or(ClientError::HistoryUnavailable)?;
        validate_historical(&historical, historical.proof().execution(), expected_chain)?;
        if historical.proof().execution().entries().iter().any(|entry| {
            entry.metadata().channel_context_id() == channel && entry.metadata().entry_hash() == entry_hash
        }) {
            return Err(ClientError::BindingMismatch);
        }
    }
    Ok(())
}

fn validate_historical(
    historical: &HistoricalFinality,
    execution: &ExecutedBlockV2,
    expected_chain: &LedgerChainIdV2,
) -> Result<()> {
    let summary = historical.summary();
    execution
        .validate_chain_id(expected_chain)
        .map_err(|_| ClientError::BindingMismatch)?;
    if historical.proof().execution() != execution
        || historical.proof().config_version() != summary.config_version()
        || summary.ledger_chain_id() != expected_chain
        || summary.application_version() != 2
        || summary.execution_height() != execution.height()
        || summary.execution_block_time_ms() != execution.block_time_ms()
        || summary.application_hash() != execution.app_hash()
        || summary.committing_height() != execution.height().checked_add(1).ok_or(ClientError::BindingMismatch)?
        || historical.proof_digest() == &[0_u8; 32]
    {
        return Err(ClientError::BindingMismatch);
    }
    Ok(())
}

fn block_capability(
    profile_id: crate::ClientProfileIdV2,
    coordinator_identity: thunderbolt_cometbft_client::TrustCoordinatorIdentity,
    expected_chain: &LedgerChainIdV2,
    historical: HistoricalFinality,
) -> Result<FinalizedBlockCapabilityV2> {
    validate_historical(&historical, historical.proof().execution(), expected_chain)?;
    let reference = HistoricalBlockReferenceV2::from_finality(
        profile_id,
        coordinator_identity,
        historical.summary(),
        *historical.proof_digest(),
    )?;
    Ok(FinalizedBlockCapabilityV2 {
        reference,
        summary: FinalizedExecutionSummaryV2::from_finality(historical.summary()),
        block: historical.proof().execution().clone(),
    })
}

fn entry_capability<S>(
    coordinator: &ConcreteCoordinator<S>,
    profile_id: crate::ClientProfileIdV2,
    coordinator_identity: thunderbolt_cometbft_client::TrustCoordinatorIdentity,
    expected_chain: &LedgerChainIdV2,
    historical: HistoricalFinality,
    block_index: u32,
) -> Result<HolderFinalityCapabilityV2>
where
    S: TrustCheckpointStore,
{
    validate_historical(&historical, historical.proof().execution(), expected_chain)?;
    let index = usize::try_from(block_index).map_err(|_| ClientError::BindingMismatch)?;
    let entry = historical
        .proof()
        .execution()
        .entries()
        .get(index)
        .cloned()
        .ok_or(ClientError::BindingMismatch)?;
    let proof = historical
        .proof()
        .execution()
        .entry_proof(index)
        .map_err(|_| ClientError::BindingMismatch)?;
    proof
        .verify(entry.metadata(), historical.proof().execution())
        .map_err(|_| ClientError::BindingMismatch)?;
    let first = coordinator
        .historical_by_request(entry.metadata().request_digest())?
        .ok_or(ClientError::HistoryUnavailable)?;
    validate_historical(first.finality(), first.finality().proof().execution(), expected_chain)?;
    let first_entry = first
        .finality()
        .proof()
        .execution()
        .entries()
        .get(usize::try_from(first.block_index()).map_err(|_| ClientError::BindingMismatch)?)
        .ok_or(ClientError::BindingMismatch)?;
    if first_entry.metadata().channel_context_id() != entry.metadata().channel_context_id()
        || first_entry.metadata().participant_id() != entry.metadata().participant_id()
        || first_entry.metadata().request_digest() != entry.metadata().request_digest()
        || first_entry.metadata().entry_hash() != entry.metadata().entry_hash()
        || first.finality().summary().execution_height() > historical.summary().execution_height()
    {
        return Err(ClientError::BindingMismatch);
    }
    let reference = HistoricalEntryReferenceV2::from_finality(
        profile_id,
        coordinator_identity,
        historical.summary(),
        entry.metadata(),
        *historical.proof_digest(),
    )?;
    Ok(HolderFinalityCapabilityV2 {
        reference,
        summary: FinalizedExecutionSummaryV2::from_finality(historical.summary()),
        entry,
        inclusion_proof: proof,
    })
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RequestQueryValue {
    channel_context_id: ChannelContextIdV2,
    participant_id: ParticipantIdV2,
    request_digest: RequestDigestV2,
    entry_hash: EntryHashV2,
    first_height: u64,
    first_block_index: u32,
}

fn decode_canonical<T>(bytes: &[u8]) -> Result<T>
where
    T: for<'de> Deserialize<'de> + Serialize,
{
    let value: T = serde_json::from_slice(bytes).map_err(|_| ClientError::Codec)?;
    if serde_json::to_vec(&value).map_err(|_| ClientError::Codec)? != bytes {
        return Err(ClientError::Codec);
    }
    Ok(value)
}
