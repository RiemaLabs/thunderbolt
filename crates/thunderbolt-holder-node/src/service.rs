use std::path::Path;

use sha2::{Digest as _, Sha256};
use thunderbolt_holder::{HolderEngine, HolderIdentity, KeystoreSecretVault};
use thunderbolt_keystore::RollbackFloorStore;
use thunderbolt_ledger::{ActorKeyAlgorithmV2, ProposalBodyV2, SignedProposalV2};
use thunderbolt_protocol::v2::ChannelEventV2;
use thunderbolt_wire::ValidateWire as _;

use crate::capabilities::{
    BitcoinSettlement, SettlementArtifacts, SettlementIntent, ThresholdAction, ThresholdArtifacts, ThresholdSigner,
};
use crate::config::HolderNodeConfig;
use crate::ledger::{ActorSigner, FinalityVerifier, SignedV2LedgerClient, TrustedLedgerReceipt};
use crate::store::{FinalizedUpdate, RuntimeStore};
use crate::types::{channel_context_id, event_kind};
use crate::{HolderNodeError, LifecycleState, QueueProposalRequest, QueuedProposal, Result, RunReport, ServiceStatus};

/// Long-running Holder/Recipient role service.
///
/// The contained Holder engine still uses the committed v1 proof envelopes;
/// this service does not wrap those bytes as v2 proof artifacts. A reviewed v2
/// proof bridge remains required before automating invoice/transfer creation.
pub struct HolderRoleService<F, L, V, A, B, T>
where
    F: RollbackFloorStore,
    L: SignedV2LedgerClient,
    V: FinalityVerifier<L::FinalityCandidate>,
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

impl<F, L, V, A, B, T> HolderRoleService<F, L, V, A, B, T>
where
    F: RollbackFloorStore,
    L: SignedV2LedgerClient,
    V: FinalityVerifier<L::FinalityCandidate>,
    A: ActorSigner,
    B: BitcoinSettlement,
    T: ThresholdSigner,
{
    #[allow(clippy::too_many_arguments)]
    pub fn open(
        mut holder: HolderEngine<KeystoreSecretVault<F>>,
        ledger: L,
        finality: V,
        actor_signer: A,
        bitcoin: B,
        threshold: T,
        database_path: impl AsRef<Path>,
        config: HolderNodeConfig,
    ) -> Result<Self> {
        let holder_identity = holder.identity()?;
        let actor_public_key = actor_signer.public_key().map_err(|_| HolderNodeError::ActorSigning)?;
        let service_domain = service_domain_digest(&config, &holder_identity, actor_public_key);
        let store = RuntimeStore::open(database_path.as_ref(), &config, &service_domain)?;
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

    pub fn run_once(&mut self, now_ms: u64) -> Result<RunReport> {
        if !matches!(self.lifecycle, LifecycleState::Running | LifecycleState::Draining) || now_ms == 0 {
            return Err(HolderNodeError::InvalidLifecycle);
        }
        let mut report = RunReport::default();
        for record in self.store.due(now_ms, self.config.submit_batch())? {
            let proposal: SignedProposalV2 =
                serde_json::from_slice(&record.proposal_bytes).map_err(|_| HolderNodeError::StorageCorrupt)?;
            proposal.verify().map_err(|_| HolderNodeError::StorageCorrupt)?;
            let accepted = self.ledger.submit(&proposal).is_ok();
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

        for channel in self.store.channels()? {
            let cursor = self.store.cursor(&channel)?;
            let candidates = self
                .ledger
                .finalized_history(&channel, cursor.as_ref(), self.config.finality_batch())
                .map_err(|_| HolderNodeError::LedgerPoll)?;
            if candidates.len() > self.config.finality_batch() {
                return self.fail(HolderNodeError::FinalityConflict);
            }
            let mut updates = Vec::with_capacity(candidates.len());
            let mut prior = cursor.clone();
            for candidate in candidates {
                let receipt = match self.finality.verify(self.config.ledger_chain_id(), candidate) {
                    Ok(receipt) => receipt,
                    Err(_) => return self.fail(HolderNodeError::FinalityConflict),
                };
                let update = match self.validate_receipt(&channel, prior.as_ref(), &receipt) {
                    Ok(update) => update,
                    Err(error) => return self.fail(error),
                };
                prior = Some(update.cursor.clone());
                updates.push(update);
            }
            let (finalized, _unrelated) = match self.store.apply_finalized_page(&channel, cursor.as_ref(), &updates) {
                Ok(value) => value,
                Err(error @ HolderNodeError::FinalityConflict) => return self.fail(error),
                Err(error) => return Err(error),
            };
            report.finalized = report.finalized.saturating_add(finalized);
        }
        Ok(report)
    }

    fn validate_receipt<R: TrustedLedgerReceipt>(
        &self,
        channel: &thunderbolt_ledger::ChannelContextIdV2,
        prior: Option<&crate::FinalizedCursor>,
        receipt: &R,
    ) -> Result<FinalizedUpdate> {
        let proposal = receipt.signed_proposal();
        proposal.verify().map_err(|_| HolderNodeError::FinalityConflict)?;
        proposal
            .body()
            .validate_chain_id(self.config.ledger_chain_id())
            .map_err(|_| HolderNodeError::FinalityConflict)?;
        let body = proposal.body();
        let body_channel = channel_context_id(body.channel())?;
        let cursor = receipt.cursor();
        if &body_channel != channel
            || &cursor.channel_context_id != channel
            || cursor.sequence != body.sequence()
            || cursor.entry_hash != body.entry_hash()?
            || receipt.finality_digest() == &[0_u8; 32]
            || receipt.request_digest() != body.request_id().digest()
            || receipt.event_digest() != &body.event().digest()?
        {
            return Err(HolderNodeError::FinalityConflict);
        }
        match prior {
            None if body.sequence() == 0 && body.previous_entry_hash().is_zero() => {}
            Some(prior)
                if prior.sequence.checked_add(1) == Some(body.sequence())
                    && body.previous_entry_hash() == &prior.entry_hash => {}
            _ => return Err(HolderNodeError::FinalityConflict),
        }
        ChannelEventV2::from_canonical_bytes(body.event().as_bytes())?;
        Ok(FinalizedUpdate {
            cursor,
            request_digest: body.request_id().digest().clone(),
            proposal_digest: *body.proposal_digest()?.as_bytes(),
            finality_digest: *receipt.finality_digest(),
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

    pub fn handle_local(&mut self, request: crate::LocalControlRequest) -> Result<crate::LocalControlResponse> {
        use crate::{LocalControlRequest as Request, LocalControlResponse as Response};
        match request {
            Request::Status => self.status().map(Response::Status),
            Request::QueueProposal(request) => self.queue_proposal(*request).map(Response::Queued),
            Request::RunOnce { now_ms } => self.run_once(now_ms).map(Response::Run),
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

fn service_domain_digest(
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
