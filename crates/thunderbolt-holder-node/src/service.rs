use std::collections::BTreeMap;
use std::path::Path;

use sha2::{Digest as _, Sha256};
use thunderbolt_holder::{HolderEngine, HolderIdentity, KeystoreSecretVault};
use thunderbolt_keystore::RollbackFloorStore;
use thunderbolt_ledger::{ActorKeyAlgorithmV2, ExecutedEntryV2, ProposalBodyV2, SignedProposalV2};
use thunderbolt_protocol::v2::ChannelEventV2;
use thunderbolt_wire::ValidateWire as _;

use crate::capabilities::{
    BitcoinSettlement, SettlementArtifacts, SettlementIntent, ThresholdAction, ThresholdArtifacts, ThresholdSigner,
};
use crate::config::HolderNodeConfig;
use crate::ledger::{ActorSigner, FinalityVerifier, SignedV2LedgerClient};
use crate::store::{FinalizedUpdate, RuntimeStore};
use crate::types::{channel_context_id, event_kind};
use crate::{
    HolderNodeError, LifecycleState, QueueProposalRequest, QueuedProposal, Result, RunReport, ServiceStatus,
    StagedFinalityRangeCapabilityV2, StagedFinalityRecoveryV2,
};

/// Long-running Holder/Recipient role service.
///
/// The contained Holder engine still uses the committed v1 proof envelopes;
/// this service does not wrap those bytes as v2 proof artifacts. A reviewed v2
/// proof bridge remains required before automating invoice/transfer creation.
pub struct HolderRoleService<F, L, V, A, B, T>
where
    F: RollbackFloorStore,
    L: SignedV2LedgerClient,
    V: FinalityVerifier,
    A: ActorSigner,
    B: BitcoinSettlement,
    T: ThresholdSigner,
{
    holder: HolderEngine<KeystoreSecretVault<F>>,
    ledger: L,
    finality: V,
    actor_signer: A,
    bitcoin: B,
    threshold: T,
    store: RuntimeStore,
    config: HolderNodeConfig,
    lifecycle: LifecycleState,
    recovered_unclean: bool,
    run_generation: u64,
}

/// Inspects the exact committed role-side recovery handoff before a concrete
/// finality coordinator is normally opened.
pub fn inspect_staged_finality_recovery(
    database_path: impl AsRef<Path>,
    config: &HolderNodeConfig,
    holder_identity: &HolderIdentity,
    actor_public_key: &thunderbolt_ledger::ActorPublicKeyV2,
) -> Result<Option<StagedFinalityRecoveryV2>> {
    let service_domain = service_domain_digest(config, holder_identity, actor_public_key);
    RuntimeStore::inspect_staged_recovery(database_path.as_ref(), config, &service_domain)
}

impl<F, L, V, A, B, T> HolderRoleService<F, L, V, A, B, T>
where
    F: RollbackFloorStore,
    L: SignedV2LedgerClient,
    V: FinalityVerifier,
    A: ActorSigner,
    B: BitcoinSettlement,
    T: ThresholdSigner,
{
    #[allow(clippy::too_many_arguments)]
    pub async fn open(
        mut holder: HolderEngine<KeystoreSecretVault<F>>,
        ledger: L,
        finality: V,
        actor_signer: A,
        bitcoin: B,
        threshold: T,
        database_path: impl AsRef<Path>,
        config: HolderNodeConfig,
        expected_recovery: Option<&StagedFinalityRecoveryV2>,
    ) -> Result<Self> {
        let holder_identity = holder.identity()?;
        let actor_public_key = actor_signer.public_key().map_err(|_| HolderNodeError::ActorSigning)?;
        require_finality_identity(&config, &finality)?;
        let service_domain = service_domain_digest(&config, &holder_identity, actor_public_key);
        let legacy_service_domain = legacy_service_domain_digest(&config, &holder_identity, actor_public_key);
        let store = RuntimeStore::open(
            database_path.as_ref(),
            &config,
            &service_domain,
            &legacy_service_domain,
            expected_recovery,
        )?;
        revalidate_cursor(&finality, &config, &store.execution_cursor()?).await?;
        let persisted_lifecycle = store.stored_lifecycle()?;
        let lifecycle = if persisted_lifecycle == LifecycleState::Faulted {
            LifecycleState::Faulted
        } else {
            LifecycleState::Created
        };
        Ok(Self {
            holder,
            ledger,
            finality,
            actor_signer,
            bitcoin,
            threshold,
            store,
            config,
            lifecycle,
            recovered_unclean: false,
            run_generation: 0,
        })
    }

    pub fn start(&mut self) -> Result<()> {
        if !matches!(self.lifecycle, LifecycleState::Created | LifecycleState::Stopped) {
            return Err(HolderNodeError::InvalidLifecycle);
        }
        let (generation, recovered) = self.store.begin_run()?;
        self.run_generation = generation;
        self.recovered_unclean = recovered;
        self.lifecycle = LifecycleState::Running;
        Ok(())
    }

    pub fn begin_draining(&mut self) -> Result<()> {
        if self.lifecycle != LifecycleState::Running {
            return Err(HolderNodeError::InvalidLifecycle);
        }
        self.store.set_lifecycle(LifecycleState::Draining, true)?;
        self.lifecycle = LifecycleState::Draining;
        Ok(())
    }

    pub fn stop(&mut self) -> Result<()> {
        if self.lifecycle != LifecycleState::Draining {
            return Err(HolderNodeError::InvalidLifecycle);
        }
        self.store.set_lifecycle(LifecycleState::Stopped, false)?;
        self.lifecycle = LifecycleState::Stopped;
        Ok(())
    }

    /// Explicit operator acknowledgement required before restarting a faulted
    /// service instance.
    pub fn acknowledge_fault(&mut self) -> Result<()> {
        if self.lifecycle != LifecycleState::Faulted {
            return Err(HolderNodeError::InvalidLifecycle);
        }
        self.store.set_lifecycle(LifecycleState::Stopped, false)?;
        self.lifecycle = LifecycleState::Stopped;
        Ok(())
    }

    pub fn holder_identity(&mut self) -> Result<HolderIdentity> {
        self.holder.identity().map_err(HolderNodeError::from)
    }

    pub fn status(&self) -> Result<ServiceStatus> {
        self.store
            .status(self.lifecycle, self.recovered_unclean, self.run_generation)
    }

    pub fn queue_proposal(&mut self, request: QueueProposalRequest) -> Result<QueuedProposal> {
        if self.lifecycle != LifecycleState::Running {
            return Err(HolderNodeError::InvalidLifecycle);
        }
        if request.now_ms == 0
            || !self.config.deployment().matches(&request.channel)
            || matches!(
                request.channel.network,
                bitcoin::Network::Bitcoin | bitcoin::Network::Testnet4
            )
            || !role_authorized_for_event(request.actor_role, &request.event)
        {
            return Err(HolderNodeError::InvalidRequest(
                "proposal is outside Holder role policy",
            ));
        }
        request
            .channel
            .validate_wire()
            .map_err(|_| HolderNodeError::InvalidProposal)?;
        let event = thunderbolt_ledger::CanonicalEventV2::from_bytes(request.event.canonical_bytes()?)?;
        let body = ProposalBodyV2::new(
            self.config.ledger_chain_id().clone(),
            request.channel.clone(),
            request.sequence,
            request.previous_entry_hash,
            request.request_nonce,
            ActorKeyAlgorithmV2::Bip340V1,
            self.actor_signer
                .public_key()
                .map_err(|_| HolderNodeError::ActorSigning)?
                .clone(),
            request.actor_role,
            event_kind(&request.event),
            event,
        )?;
        let proposal_digest = body.proposal_digest()?;
        let signature = self
            .actor_signer
            .sign(&proposal_digest)
            .map_err(|_| HolderNodeError::ActorSigning)?;
        let proposal = SignedProposalV2::new(body, signature)?;
        let request_digest = proposal.body().request_id().digest().clone();
        let entry_hash = proposal.body().entry_hash()?;
        let channel_id = channel_context_id(proposal.body().channel())?;
        let proposal_bytes = serde_json::to_vec(&proposal).map_err(|_| HolderNodeError::InvalidProposal)?;
        let disposition = self.store.queue(
            request.command_id,
            &request_digest,
            &channel_id,
            request.sequence,
            proposal_digest.as_bytes(),
            &proposal_bytes,
            request.now_ms,
        )?;
        Ok(QueuedProposal {
            disposition,
            request_digest,
            entry_hash,
        })
    }

    pub fn retry_command(&mut self, command_id: crate::CommandId, now_ms: u64) -> Result<()> {
        if !matches!(self.lifecycle, LifecycleState::Running | LifecycleState::Draining) || now_ms == 0 {
            return Err(HolderNodeError::InvalidLifecycle);
        }
        self.store.retry(command_id, now_ms)
    }

    pub async fn run_once(&mut self, now_ms: u64) -> Result<RunReport> {
        if !matches!(self.lifecycle, LifecycleState::Running | LifecycleState::Draining) || now_ms == 0 {
            return Err(HolderNodeError::InvalidLifecycle);
        }
        require_finality_identity(&self.config, &self.finality)?;
        if !self.ledger.is_available() {
            return Err(HolderNodeError::CapabilityUnavailable);
        }
        let mut report = RunReport::default();

        // Resolve a committed role-side stage before any unrelated network
        // work. A coordinator recovery can replay this exact intent after a
        // cancellation without moving the Holder cursor twice.
        let cursor = self.store.execution_cursor()?;
        revalidate_cursor(&self.finality, &self.config, &cursor).await?;
        if let Some(staged) = self.store.staged_finality()? {
            report.finalized = self.finalize_staged(staged).await?;
        }

        for record in self.store.due(now_ms, self.config.submit_batch())? {
            let proposal: SignedProposalV2 =
                serde_json::from_slice(&record.proposal_bytes).map_err(|_| HolderNodeError::StorageCorrupt)?;
            proposal.verify().map_err(|_| HolderNodeError::StorageCorrupt)?;
            // No local mutation occurs while submission is pending. If this
            // future is cancelled after the remote side accepted the request,
            // the durable queued proposal is replayed byte-for-byte next run.
            let accepted = self.ledger.submit(&proposal).await.is_ok();
            let status = self
                .store
                .record_submission(&record.request_digest, now_ms, accepted, self.config.retry())?;
            if accepted {
                report.submitted = report.submitted.saturating_add(1);
            } else {
                report.submit_failures = report.submit_failures.saturating_add(1);
                if status == crate::OutboxStatus::RetryExhausted {
                    continue;
                }
            }
        }

        let cursor = self.store.execution_cursor()?;
        revalidate_cursor(&self.finality, &self.config, &cursor).await?;
        let Some(intent) = self
            .ledger
            .prepare_finalized_execution(
                &cursor,
                self.config.finality_batch(),
                self.config.finality_verifier_profile(),
                self.config.finality_coordinator_id(),
            )
            .await
            .map_err(|_| HolderNodeError::LedgerPoll)?
        else {
            return Ok(report);
        };
        if intent.blocks().len() > self.config.finality_batch()
            || intent.verifier_profile() != self.config.finality_verifier_profile()
            || intent.coordinator_id() != self.config.finality_coordinator_id()
            || intent.ledger_chain_id() != self.config.ledger_chain_id()
            || intent.start_height() != cursor.next_height()
            || intent.expected_previous_app_hash() != cursor.expected_previous_app_hash()
        {
            return self.fail(HolderNodeError::FinalityConflict);
        }
        // This synchronous call commits and reads back the canonical intent.
        // Only the returned private-constructor capability authorizes the
        // coordinator mutation below.
        let staged = match self.store.stage_finality_intent(intent) {
            Ok(staged) => staged,
            Err(error @ HolderNodeError::FinalityConflict) => return self.fail(error),
            Err(error) => return Err(error),
        };
        report.finalized = report.finalized.saturating_add(self.finalize_staged(staged).await?);
        Ok(report)
    }

    async fn finalize_staged(&mut self, staged: StagedFinalityRangeCapabilityV2) -> Result<usize> {
        let cursor = self.store.execution_cursor()?;
        if staged.intent().verifier_profile() != self.config.finality_verifier_profile()
            || staged.intent().coordinator_id() != self.config.finality_coordinator_id()
            || staged.intent().ledger_chain_id() != self.config.ledger_chain_id()
            || staged.intent().start_height() != cursor.next_height()
            || staged.intent().expected_previous_app_hash() != cursor.expected_previous_app_hash()
        {
            return self.fail(HolderNodeError::FinalityConflict);
        }
        let finalized = match self.finality.finalize_staged_range(&staged).await {
            Ok(finalized) => finalized,
            Err(_) => return Err(HolderNodeError::FinalityConflict),
        };
        if finalized.stage_digest() != staged.stage_digest()
            || finalized.blocks().len() != staged.intent().blocks().len()
        {
            return self.fail(HolderNodeError::FinalityConflict);
        }
        for capability in finalized.blocks() {
            if self.finality.revalidate_durable_capability(capability).await.is_err() {
                return self.fail(HolderNodeError::FinalityConflict);
            }
        }

        let channels = self.store.channels()?;
        let mut channel_heads = BTreeMap::new();
        for channel in channels {
            channel_heads.insert(*channel.as_bytes(), self.store.channel_cursor(&channel)?);
        }
        let mut updates = Vec::new();
        for (block, capability) in staged.intent().blocks().iter().zip(finalized.blocks()) {
            if capability.verifier_profile() != self.config.finality_verifier_profile()
                || capability.coordinator_id() != self.config.finality_coordinator_id()
                || capability.ledger_chain_id() != self.config.ledger_chain_id()
                || capability.block_height() != block.height()
                || capability.app_hash() != block.app_hash()
            {
                return self.fail(HolderNodeError::FinalityConflict);
            }
            for entry in block.entries() {
                let channel = match channel_context_id(entry.proposal().body().channel()) {
                    Ok(channel) => channel,
                    Err(_) => return self.fail(HolderNodeError::FinalityConflict),
                };
                let key = *channel.as_bytes();
                let Some(prior) = channel_heads.get_mut(&key) else {
                    continue;
                };
                let update =
                    match self.validate_entry(&channel, prior.as_ref(), entry, capability.verifier_digest().as_bytes())
                    {
                        Ok(update) => update,
                        Err(error) => return self.fail(error),
                    };
                let is_new_head = prior.as_ref().is_none_or(|head| update.cursor.sequence > head.sequence);
                if is_new_head {
                    *prior = Some(update.cursor.clone());
                }
                updates.push(update);
            }
        }
        let (finalized_count, _unrelated) = match self.store.complete_staged_finality(&staged, finalized, &updates) {
            Ok(value) => value,
            Err(error @ HolderNodeError::FinalityConflict) => return self.fail(error),
            Err(error) => return Err(error),
        };
        Ok(finalized_count)
    }

    fn validate_entry(
        &self,
        channel: &thunderbolt_ledger::ChannelContextIdV2,
        prior: Option<&crate::types::FinalizedChannelCursor>,
        entry: &ExecutedEntryV2,
        finality_digest: &[u8; 32],
    ) -> Result<FinalizedUpdate> {
        let proposal = entry.proposal();
        proposal.verify().map_err(|_| HolderNodeError::FinalityConflict)?;
        proposal
            .body()
            .validate_chain_id(self.config.ledger_chain_id())
            .map_err(|_| HolderNodeError::FinalityConflict)?;
        let body = proposal.body();
        let body_channel = channel_context_id(body.channel())?;
        let cursor = crate::types::FinalizedChannelCursor::new(channel.clone(), body.sequence(), body.entry_hash()?);
        if &body_channel != channel
            || &cursor.channel_context_id != channel
            || entry.metadata().channel_context_id() != channel
            || entry.metadata().sequence() != body.sequence()
            || entry.metadata().entry_hash() != &cursor.entry_hash
        {
            return Err(HolderNodeError::FinalityConflict);
        }
        match prior {
            None if body.sequence() == 0 && body.previous_entry_hash().is_zero() => {}
            Some(prior)
                if prior.sequence.checked_add(1) == Some(body.sequence())
                    && body.previous_entry_hash() == &prior.entry_hash => {}
            Some(prior) if body.sequence() <= prior.sequence => {
                if body.sequence() == prior.sequence && cursor.entry_hash != prior.entry_hash {
                    return Err(HolderNodeError::FinalityConflict);
                }
            }
            _ => return Err(HolderNodeError::FinalityConflict),
        }
        ChannelEventV2::from_canonical_bytes(body.event().as_bytes())?;
        Ok(FinalizedUpdate {
            cursor,
            previous_entry_hash: body.previous_entry_hash().clone(),
            request_digest: body.request_id().digest().clone(),
            proposal_digest: *body.proposal_digest()?.as_bytes(),
            finality_digest: *finality_digest,
        })
    }

    pub fn prepare_settlement(&mut self, intent: &SettlementIntent) -> Result<SettlementArtifacts> {
        self.bitcoin
            .prepare(intent)
            .map_err(|_| HolderNodeError::CapabilityUnavailable)?
            .validate()
            .map_err(|_| HolderNodeError::CapabilityUnavailable)
    }

    pub fn threshold_sign(&mut self, action: &ThresholdAction) -> Result<ThresholdArtifacts> {
        self.threshold
            .sign(action)
            .map_err(|_| HolderNodeError::CapabilityUnavailable)?
            .validate()
            .map_err(|_| HolderNodeError::CapabilityUnavailable)
    }

    pub async fn handle_local(&mut self, request: crate::LocalControlRequest) -> Result<crate::LocalControlResponse> {
        use crate::{LocalControlRequest as Request, LocalControlResponse as Response};
        match request {
            Request::Status => self.status().map(Box::new).map(Response::Status),
            Request::QueueProposal(request) => self.queue_proposal(*request).map(Response::Queued),
            Request::RunOnce { now_ms } => self.run_once(now_ms).await.map(Response::Run),
            Request::Retry { command_id, now_ms } => {
                self.retry_command(command_id, now_ms)?;
                Ok(Response::Accepted)
            }
            Request::BeginDraining => {
                self.begin_draining()?;
                Ok(Response::Accepted)
            }
            Request::Stop => {
                self.stop()?;
                Ok(Response::Accepted)
            }
            Request::AcknowledgeFault => {
                self.acknowledge_fault()?;
                Ok(Response::Accepted)
            }
        }
    }

    fn fail<X>(&mut self, error: HolderNodeError) -> Result<X> {
        let _ = self.store.set_lifecycle(LifecycleState::Faulted, false);
        self.lifecycle = LifecycleState::Faulted;
        Err(error)
    }
}

fn role_authorized_for_event(role: thunderbolt_ledger::ActorRoleV2, event: &ChannelEventV2) -> bool {
    match event {
        ChannelEventV2::Invoice(_) => role == thunderbolt_ledger::ActorRoleV2::Recipient,
        ChannelEventV2::Open(_) | ChannelEventV2::Transfer(_) | ChannelEventV2::Finalize(_) => {
            role == thunderbolt_ledger::ActorRoleV2::Holder
        }
    }
}

fn require_finality_identity<V: FinalityVerifier>(config: &HolderNodeConfig, finality: &V) -> Result<()> {
    if !finality.is_available() {
        return Err(HolderNodeError::CapabilityUnavailable);
    }
    if finality.profile_id() != config.finality_verifier_profile()
        || finality.coordinator_id() != config.finality_coordinator_id()
    {
        return Err(HolderNodeError::FinalityConflict);
    }
    Ok(())
}

async fn revalidate_cursor<V: FinalityVerifier>(
    finality: &V,
    config: &HolderNodeConfig,
    cursor: &crate::FinalizedBlockCursor,
) -> Result<()> {
    require_finality_identity(config, finality)?;
    if cursor.verifier_profile() != config.finality_verifier_profile()
        || cursor.coordinator_id() != config.finality_coordinator_id()
        || cursor.ledger_chain_id() != config.ledger_chain_id()
    {
        return Err(HolderNodeError::FinalityConflict);
    }
    if let Some(capability) = cursor.last_finality() {
        finality
            .revalidate_durable_capability(capability)
            .await
            .map_err(|_| HolderNodeError::FinalityConflict)?;
        if capability.verifier_profile() != cursor.verifier_profile()
            || capability.coordinator_id() != cursor.coordinator_id()
            || capability.ledger_chain_id() != cursor.ledger_chain_id()
            || capability.block_height().checked_add(1) != Some(cursor.next_height())
            || capability.app_hash() != cursor.expected_previous_app_hash()
        {
            return Err(HolderNodeError::FinalityConflict);
        }
    } else if cursor.next_height() != 1 || !cursor.expected_previous_app_hash().is_zero() {
        return Err(HolderNodeError::FinalityConflict);
    }
    Ok(())
}

fn service_domain_digest(
    config: &HolderNodeConfig,
    holder: &HolderIdentity,
    actor_key: &thunderbolt_ledger::ActorPublicKeyV2,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"bitcoin-thunderbolt/holder-node/service-domain/v2");
    append_domain(&mut hasher, config.ledger_chain_id().as_bytes());
    hasher.update(config.finality_verifier_profile().as_bytes());
    hasher.update(config.finality_coordinator_id().as_bytes());
    hasher.update(config.deployment().digest());
    append_domain(&mut hasher, actor_key.as_bytes());
    append_domain(&mut hasher, holder.participant_id().as_str().as_bytes());
    append_domain(&mut hasher, holder.public_key());
    hasher.finalize().into()
}

fn legacy_service_domain_digest(
    config: &HolderNodeConfig,
    holder: &HolderIdentity,
    actor_key: &thunderbolt_ledger::ActorPublicKeyV2,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"bitcoin-thunderbolt/holder-node/service-domain/v1");
    append_domain(&mut hasher, config.ledger_chain_id().as_bytes());
    hasher.update(config.deployment().digest());
    append_domain(&mut hasher, actor_key.as_bytes());
    append_domain(&mut hasher, holder.participant_id().as_str().as_bytes());
    append_domain(&mut hasher, holder.public_key());
    hasher.finalize().into()
}

fn append_domain(hasher: &mut Sha256, value: &[u8]) {
    hasher.update((value.len() as u64).to_be_bytes());
    hasher.update(value);
}
