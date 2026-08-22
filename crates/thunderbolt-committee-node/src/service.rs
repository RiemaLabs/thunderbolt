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
    AcknowledgementRecord, ControlRequest, ControlResponse, FinalityDigest, FinalizedEntryV2, FinalizedRefreshBundleV2,
    IngestDisposition, LedgerCursor, LedgerFinalityVerifier, NodeConfig, NodeError, NodeStatus, ProcessDisposition,
    Result, SignedV2LedgerClient,
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
        let cursor = self.queue.cursor()?;
        let bundles = client
            .fetch_finalized_refreshes(cursor.as_ref(), self.config.fetch_batch_size)
            .map_err(|_| NodeError::FinalityRejected)?;
        let mut accepted = 0_usize;
        for bundle in bundles {
            if self.ingest(bundle, finality)? == IngestDisposition::Accepted {
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
        let validated = validate_bundle(self.runtime.descriptor(), &self.config, &bundle, finality)?;
        let encoded = serde_json::to_vec(&bundle)?;
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
        let Some(stored) = self.queue.next_pending()? else {
            return Ok(ProcessDisposition::Idle);
        };
        let bundle: FinalizedRefreshBundleV2<T> = serde_json::from_slice(&stored.bundle)?;
        let validated = validate_bundle(self.runtime.descriptor(), &self.config, &bundle, finality)?;
        let acknowledgement = self.runtime.apply_refresh(&bundle, validated.commitment)?;
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
    commitment: CommittedTransfer,
    cursor: LedgerCursor,
    transfer_entry_hash: [u8; 32],
    request_digest: [u8; 32],
}

fn validate_bundle<T, V>(
    descriptor: &thunderbolt_committee::CommitteeDescriptor,
    config: &NodeConfig,
    bundle: &FinalizedRefreshBundleV2<T>,
    finality: &V,
) -> Result<ValidatedBundle>
where
    V: LedgerFinalityVerifier<T>,
{
    let (invoice_entry, invoice_finality) =
        validate_finalized_entry(&bundle.invoice, &config.ledger_chain_id, finality)?;
    let (transfer_entry, transfer_finality) =
        validate_finalized_entry(&bundle.transfer, &config.ledger_chain_id, finality)?;
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
    if bundle.threshold_distribution.binding.network != stable.network
        || bundle.threshold_distribution.binding.deployment_id.as_bytes() != stable.deployment_id.as_bytes()
        || bundle.threshold_distribution.binding.committee_epoch != stable.committee_epoch
        || bundle.threshold_distribution.binding.channel_id.as_bytes() != stable.funding_outpoint.canonical_bytes()
        || bundle.threshold_distribution.binding.invoice_id.as_bytes() != invoice.invoice_id.as_bytes()
    {
        return Err(NodeError::RefreshBindingMismatch);
    }
    let recipient_json = to_json_vec(&PublicMessageV1::Share(bundle.recipient_share.clone()))
        .map_err(|_| NodeError::RefreshBindingMismatch)?;
    let threshold_json = to_json_vec(&PublicMessageV1::ThresholdRefresh(
        bundle.threshold_distribution.clone(),
    ))
    .map_err(|_| NodeError::RefreshBindingMismatch)?;
    let transfer_json = to_json_vec(&PublicMessageV1::Transfer(bundle.transfer_proof.clone()))
        .map_err(|_| NodeError::RefreshBindingMismatch)?;
    if invoice.invoice_proof.as_bytes() != recipient_json
        || invoice.committee_package.as_bytes() != threshold_json
        || transfer.transfer_proof.as_bytes() != transfer_json
    {
        return Err(NodeError::RefreshBindingMismatch);
    }
    let transfer_metadata = transfer_entry.metadata();
    let cursor = LedgerCursor {
        block_height: transfer_metadata.block_height(),
        block_index: transfer_metadata.block_index(),
        app_hash: bundle.transfer.block.app_hash().clone(),
        entry_hash: transfer_metadata.entry_hash().clone(),
        finality_digest: transfer_finality,
    };
    let commitment = CommittedTransfer::new(
        bundle
            .recipient_share
            .canonical_digest()
            .map_err(|_| NodeError::RefreshBindingMismatch)?,
        bundle
            .threshold_distribution
            .canonical_digest()
            .map_err(|_| NodeError::RefreshBindingMismatch)?,
        bundle
            .transfer_proof
            .canonical_digest()
            .map_err(|_| NodeError::RefreshBindingMismatch)?,
        EntryHash::from_bytes(*invoice_entry.metadata().entry_hash().as_bytes()),
        EntryHash::from_bytes(*transfer_metadata.entry_hash().as_bytes()),
        EntryHash::from_bytes(*transfer_metadata.entry_hash().as_bytes()),
        transfer_metadata.sequence(),
        bundle
            .transfer_proof
            .binding
            .step
            .ok_or(NodeError::RefreshBindingMismatch)?,
    )
    .map_err(|_| NodeError::RefreshBindingMismatch)?;
    let _ = invoice_finality;
    Ok(ValidatedBundle {
        commitment,
        cursor,
        transfer_entry_hash: *transfer_metadata.entry_hash().as_bytes(),
        request_digest: *transfer_metadata.request_digest().as_bytes(),
    })
}

fn validate_finalized_entry<'a, T, V>(
    item: &'a FinalizedEntryV2<T>,
    chain_id: &thunderbolt_ledger::LedgerChainIdV2,
    finality: &V,
) -> Result<(&'a thunderbolt_ledger::ExecutedEntryV2, FinalityDigest)>
where
    V: LedgerFinalityVerifier<T>,
{
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
    let digest = finality
        .verify_finality(&item.block, entry, &item.inclusion_proof, &item.receipt)
        .map_err(|_| NodeError::FinalityRejected)?;
    Ok((entry, digest))
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
