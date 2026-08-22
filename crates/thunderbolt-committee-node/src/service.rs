use std::path::Path;

use serde::de::DeserializeOwned;
use serde::Serialize;
use thunderbolt_committee::{CommittedTransfer, CommitteeMemberEngine, KeystoreCommitteeVault};
use thunderbolt_ledger::{ActorRoleV2, EventKindV2};
use thunderbolt_protocol::v2::ChannelEventV2;
use thunderbolt_protocol::EntryHash;
use thunderbolt_wire::{to_json_vec, CanonicalDigest, PublicMessageV1};

use crate::storage::SqliteQueue;
use crate::traits::CommitteeRuntime;
use crate::{
    AcknowledgementRecord, ControlRequest, ControlResponse, FinalizedRefreshBundleV2, IngestDisposition, LedgerCursor,
    LedgerFinalityVerifier, NodeConfig, NodeError, NodeStatus, ProcessDisposition, Result, SignedV2LedgerClient,
};

pub type FencedCommitteeNode<F> = CommitteeNode<CommitteeMemberEngine<KeystoreCommitteeVault<F>>>;

pub struct CommitteeNode<R> {
    runtime: R,
    queue: SqliteQueue,
    config: NodeConfig,
    #[cfg(test)]
    crash_after_runtime_once: bool,
}

impl<R> CommitteeNode<R>
where
    R: CommitteeRuntime,
{
    pub fn open(path: impl AsRef<Path>, runtime: R, config: NodeConfig) -> Result<Self> {
        let descriptor = runtime.descriptor();
        NodeConfig::validate_network(descriptor.network())?;
        let queue = SqliteQueue::open(
            path,
            &config,
            descriptor.deployment_id(),
            descriptor.epoch().get(),
            descriptor.id().as_bytes(),
            runtime.member_id().get(),
        )?;
        Ok(Self {
            runtime,
            queue,
            config,
            #[cfg(test)]
            crash_after_runtime_once: false,
        })
    }

    pub fn database_path(&self) -> &Path {
        self.queue.path()
    }

    pub fn poll<C, V>(&mut self, client: &mut C, finality: &V) -> Result<usize>
    where
        C: SignedV2LedgerClient,
        V: LedgerFinalityVerifier<C::Receipt>,
    {
        require_verifier_profile(&self.config, finality)?;
        let cursor = self.queue.cursor()?;
        let bundles = client
            .fetch_finalized_refreshes(cursor.as_ref(), self.config.fetch_batch_size)
            .map_err(|_| NodeError::FinalityRejected)?;
        let mut prepared = bundles
            .into_iter()
            .map(|bundle| prepare_bundle(self.runtime.descriptor(), &self.config, &bundle, finality))
            .collect::<Result<Vec<_>>>()?;
        prepared.sort_by_key(|item| item.record.finality.refresh_ordinal());
        let mut accepted = 0_usize;
        for item in prepared {
            if self.ingest_prepared(item)? == IngestDisposition::Accepted {
                accepted = accepted.checked_add(1).ok_or(NodeError::NumericRange)?;
            }
        }
        Ok(accepted)
    }

    pub fn ingest<T, V>(&self, bundle: FinalizedRefreshBundleV2<T>, finality: &V) -> Result<IngestDisposition>
    where
        T: Clone + Serialize + DeserializeOwned,
        V: LedgerFinalityVerifier<T>,
    {
        require_verifier_profile(&self.config, finality)?;
        let validated = prepare_bundle(self.runtime.descriptor(), &self.config, &bundle, finality)?;
        self.ingest_prepared(validated)
    }

    fn ingest_prepared(&self, validated: ValidatedBundle) -> Result<IngestDisposition> {
        let encoded = serde_json::to_vec(&validated.record)?;
        self.queue.ingest(
            validated.transfer_entry_hash,
            validated.request_digest,
            encoded,
            &validated.cursor,
        )
    }

    pub fn process_next<T, V>(&mut self, finality: &V) -> Result<ProcessDisposition>
    where
        T: Clone + Serialize + DeserializeOwned,
        V: LedgerFinalityVerifier<T>,
    {
        require_verifier_profile(&self.config, finality)?;
        let Some(stored) = self.queue.next_pending()? else {
            return Ok(ProcessDisposition::Idle);
        };
        let record: crate::VerifiedRefreshRecordV2 = serde_json::from_slice(&stored.bundle)?;
        let validated = validate_verified_record(self.runtime.descriptor(), &self.config, record)?;
        finality
            .verify_durable_capability(&validated.record.finality)
            .map_err(|_| NodeError::FinalityRejected)?;
        let acknowledgement = self.runtime.apply_refresh(&validated.record, validated.commitment)?;
        #[cfg(test)]
        if self.crash_after_runtime_once {
            self.crash_after_runtime_once = false;
            return Err(NodeError::InjectedCrash);
        }
        let record = AcknowledgementRecord {
            event_id: *acknowledgement.event_id().as_bytes(),
            descriptor_id: *acknowledgement.descriptor_id().as_bytes(),
            epoch: acknowledgement.epoch().get(),
            member_id: acknowledgement.member_id().get(),
            durable_revision: acknowledgement.durable_revision(),
            acknowledgement_digest: *acknowledgement.acknowledgement_digest(),
        };
        self.queue.mark_applied(stored.id, &record)?;
        Ok(if acknowledgement.durable_revision() == 0 {
            ProcessDisposition::Replay
        } else {
            ProcessDisposition::Applied
        })
    }

    pub fn control(&self, request: ControlRequest, finality_available: bool) -> Result<ControlResponse> {
        match request {
            ControlRequest::Status => {
                let (inbox_pending, outbox_pending) = self.queue.counts()?;
                Ok(ControlResponse::Status(NodeStatus {
                    member_id: self.runtime.member_id().get(),
                    committee_epoch: self.runtime.descriptor().epoch().get(),
                    descriptor_id: *self.runtime.descriptor().id().as_bytes(),
                    inbox_pending,
                    outbox_pending,
                    cursor: self.queue.cursor()?,
                    signing_available: false,
                    finality_available,
                }))
            }
            ControlRequest::ListOutbox { limit } => Ok(ControlResponse::Outbox(self.queue.list_outbox(limit)?)),
            ControlRequest::RetryOutbox { id } => {
                self.queue.retry_outbox(id)?;
                Ok(ControlResponse::Retried { id })
            }
        }
    }

    pub fn into_runtime(self) -> R {
        self.runtime
    }

    #[cfg(test)]
    #[allow(dead_code)]
    pub(crate) fn inject_crash_after_runtime_once(&mut self) {
        self.crash_after_runtime_once = true;
    }
}

struct ValidatedBundle {
    record: crate::VerifiedRefreshRecordV2,
    commitment: CommittedTransfer,
    cursor: LedgerCursor,
    transfer_entry_hash: [u8; 32],
    request_digest: [u8; 32],
}

fn prepare_bundle<T, V>(
    descriptor: &thunderbolt_committee::CommitteeDescriptor,
    config: &NodeConfig,
    bundle: &FinalizedRefreshBundleV2<T>,
    finality: &V,
) -> Result<ValidatedBundle>
where
    V: LedgerFinalityVerifier<T>,
{
    let invoice = crate::ExecutedEntryEvidenceV2::from(&bundle.invoice);
    let transfer = crate::ExecutedEntryEvidenceV2::from(&bundle.transfer);
    validate_executed_entry(&invoice, &config.ledger_chain_id)?;
    validate_executed_entry(&transfer, &config.ledger_chain_id)?;
    let capability = finality
        .verify_finalized_refresh(&bundle.invoice, &bundle.transfer)
        .map_err(|_| NodeError::FinalityRejected)?;
    let record = crate::VerifiedRefreshRecordV2 {
        invoice,
        transfer,
        recipient_share: bundle.recipient_share.clone(),
        threshold_distribution: bundle.threshold_distribution.clone(),
        transfer_proof: bundle.transfer_proof.clone(),
        finality: capability,
    };
    validate_verified_record(descriptor, config, record)
}

fn validate_verified_record(
    descriptor: &thunderbolt_committee::CommitteeDescriptor,
    config: &NodeConfig,
    record: crate::VerifiedRefreshRecordV2,
) -> Result<ValidatedBundle> {
    let invoice_entry = validate_executed_entry(&record.invoice, &config.ledger_chain_id)?;
    let transfer_entry = validate_executed_entry(&record.transfer, &config.ledger_chain_id)?;
    validate_capability(&record, invoice_entry, transfer_entry, config)?;
    let invoice_body = invoice_entry.proposal().body();
    let transfer_body = transfer_entry.proposal().body();
    if invoice_body.actor_role() != ActorRoleV2::Recipient
        || transfer_body.actor_role() != ActorRoleV2::Holder
        || invoice_body.event_kind() != EventKindV2::Invoice
        || transfer_body.event_kind() != EventKindV2::Transfer
        || invoice_body.channel() != transfer_body.channel()
    {
        return Err(NodeError::RefreshBindingMismatch);
    }
    validate_channel(descriptor, invoice_body.channel())?;
    let invoice_event = ChannelEventV2::from_canonical_bytes(invoice_body.event().as_bytes())
        .map_err(|_| NodeError::InvalidLedgerArtifact)?;
    let transfer_event = ChannelEventV2::from_canonical_bytes(transfer_body.event().as_bytes())
        .map_err(|_| NodeError::InvalidLedgerArtifact)?;
    let (ChannelEventV2::Invoice(invoice), ChannelEventV2::Transfer(transfer)) = (invoice_event, transfer_event) else {
        return Err(NodeError::RefreshBindingMismatch);
    };
    if transfer.invoice_entry_hash.as_bytes() != invoice_entry.metadata().entry_hash().as_bytes()
        || transfer.invoice_id.as_bytes() != invoice.invoice_id.as_bytes()
    {
        return Err(NodeError::RefreshBindingMismatch);
    }
    let stable = invoice_body.channel();
    if record.threshold_distribution.binding.network != stable.network
        || record.threshold_distribution.binding.deployment_id.as_bytes() != stable.deployment_id.as_bytes()
        || record.threshold_distribution.binding.committee_epoch != stable.committee_epoch
        || record.threshold_distribution.binding.channel_id.as_bytes() != stable.funding_outpoint.canonical_bytes()
        || record.threshold_distribution.binding.invoice_id.as_bytes() != invoice.invoice_id.as_bytes()
    {
        return Err(NodeError::RefreshBindingMismatch);
    }
    let recipient_json = to_json_vec(&PublicMessageV1::Share(record.recipient_share.clone()))
        .map_err(|_| NodeError::RefreshBindingMismatch)?;
    let threshold_json = to_json_vec(&PublicMessageV1::ThresholdRefresh(
        record.threshold_distribution.clone(),
    ))
    .map_err(|_| NodeError::RefreshBindingMismatch)?;
    let transfer_json = to_json_vec(&PublicMessageV1::Transfer(record.transfer_proof.clone()))
        .map_err(|_| NodeError::RefreshBindingMismatch)?;
    if invoice.invoice_proof.as_bytes() != recipient_json
        || invoice.committee_package.as_bytes() != threshold_json
        || transfer.transfer_proof.as_bytes() != transfer_json
    {
        return Err(NodeError::RefreshBindingMismatch);
    }
    let transfer_metadata = transfer_entry.metadata();
    let cursor = LedgerCursor {
        refresh_ordinal: record.finality.refresh_ordinal(),
        previous_refresh_entry_hash: record.finality.previous_refresh_entry_hash().clone(),
        block_height: transfer_metadata.block_height(),
        block_index: transfer_metadata.block_index(),
        app_hash: record.transfer.block.app_hash().clone(),
        entry_hash: transfer_metadata.entry_hash().clone(),
        finality_digest: record.finality.verifier_digest(),
    };
    let commitment = CommittedTransfer::new(
        record
            .recipient_share
            .canonical_digest()
            .map_err(|_| NodeError::RefreshBindingMismatch)?,
        record
            .threshold_distribution
            .canonical_digest()
            .map_err(|_| NodeError::RefreshBindingMismatch)?,
        record
            .transfer_proof
            .canonical_digest()
            .map_err(|_| NodeError::RefreshBindingMismatch)?,
        EntryHash::from_bytes(*invoice_entry.metadata().entry_hash().as_bytes()),
        EntryHash::from_bytes(*transfer_metadata.entry_hash().as_bytes()),
        EntryHash::from_bytes(*transfer_metadata.entry_hash().as_bytes()),
        transfer_metadata.sequence(),
        record
            .transfer_proof
            .binding
            .step
            .ok_or(NodeError::RefreshBindingMismatch)?,
    )
    .map_err(|_| NodeError::RefreshBindingMismatch)?;
    let transfer_entry_hash = *transfer_metadata.entry_hash().as_bytes();
    let request_digest = *transfer_metadata.request_digest().as_bytes();
    Ok(ValidatedBundle {
        record,
        commitment,
        cursor,
        transfer_entry_hash,
        request_digest,
    })
}

fn validate_executed_entry<'a>(
    item: &'a crate::ExecutedEntryEvidenceV2,
    chain_id: &thunderbolt_ledger::LedgerChainIdV2,
) -> Result<&'a thunderbolt_ledger::ExecutedEntryV2> {
    item.block
        .validate_chain_id(chain_id)
        .map_err(|_| NodeError::InvalidLedgerArtifact)?;
    let entry = item.entry()?;
    entry
        .proposal()
        .verify()
        .map_err(|_| NodeError::InvalidLedgerArtifact)?;
    item.inclusion_proof
        .verify(entry.metadata(), &item.block)
        .map_err(|_| NodeError::InvalidLedgerArtifact)?;
    Ok(entry)
}

fn validate_capability(
    record: &crate::VerifiedRefreshRecordV2,
    invoice: &thunderbolt_ledger::ExecutedEntryV2,
    transfer: &thunderbolt_ledger::ExecutedEntryV2,
    config: &NodeConfig,
) -> Result<()> {
    let capability = &record.finality;
    capability.validate_shape()?;
    if capability.ledger_chain_id() != &config.ledger_chain_id
        || capability.verifier_profile() != config.finality_verifier_profile
        || capability.invoice_height() != invoice.metadata().block_height()
        || capability.invoice_index() != invoice.metadata().block_index()
        || capability.invoice_entry_hash() != invoice.metadata().entry_hash()
        || capability.transfer_height() != transfer.metadata().block_height()
        || capability.transfer_index() != transfer.metadata().block_index()
        || capability.transfer_entry_hash() != transfer.metadata().entry_hash()
        || capability.transfer_app_hash() != record.transfer.block.app_hash()
        || (capability.invoice_height(), capability.invoice_index())
            >= (capability.transfer_height(), capability.transfer_index())
        || invoice.metadata().sequence() >= transfer.metadata().sequence()
    {
        return Err(NodeError::FinalityRejected);
    }
    Ok(())
}

fn require_verifier_profile<T, V>(config: &NodeConfig, verifier: &V) -> Result<()>
where
    V: LedgerFinalityVerifier<T>,
{
    if verifier.profile_id() == config.finality_verifier_profile {
        Ok(())
    } else {
        Err(NodeError::FinalityRejected)
    }
}

fn validate_channel(
    descriptor: &thunderbolt_committee::CommitteeDescriptor,
    binding: &thunderbolt_wire::ChannelBindingV2,
) -> Result<()> {
    if binding.network != descriptor.network()
        || binding.deployment_id.as_bytes() != descriptor.deployment_id()
        || binding.committee_epoch != descriptor.epoch().get()
        || binding.committee_descriptor_digest.as_bytes() != descriptor.id().as_bytes()
    {
        return Err(NodeError::RefreshBindingMismatch);
    }
    NodeConfig::validate_network(binding.network)
}
