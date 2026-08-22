use std::collections::BTreeMap;
use std::io::Write as _;
use std::path::Path;

use serde::de::DeserializeOwned;
use serde::Serialize;
use sha2::{Digest as _, Sha256};
use thunderbolt_committee::{CommittedTransfer, CommitteeMemberEngine, KeystoreCommitteeVault};
use thunderbolt_ledger::{ActorRoleV2, AppHashV2, EntryHashV2, EventKindV2, ExecutedBlockCommitmentV2};
use thunderbolt_protocol::v2::ChannelEventV2;
use thunderbolt_protocol::EntryHash;
use thunderbolt_wire::{
    validate_threshold_package_v2, CanonicalDigest, OperationBindingV2, PublicMessageV2, RecipientShareEnvelopeV2,
    ThresholdEnvelopeV2,
};

use crate::storage::{
    InboxWrite, PendingInvoiceRemoval, PendingInvoiceWrite, ScanCommit, ScanCommitOutcome, SqliteQueue,
};
use crate::traits::CommitteeRuntime;
use crate::{
    ControlRequest, ControlResponse, FinalizedExecutionSegmentV2, LedgerCursor, LedgerFinalityVerifier, NodeConfig,
    NodeError, NodeStatus, ProcessDisposition, RefreshBlockCommitmentsV2, Result, SignedV2LedgerClient,
    VerifiedV2Refresh,
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
        require_runtime_available(&self.runtime)?;
        require_verifier_profile(&self.config, finality)?;
        let cursor = self.queue.cursor()?;
        validate_cursor_finality(cursor.as_ref(), &self.config, finality)?;
        let Some(segment) = client
            .fetch_contiguous_finalized_segment(cursor.as_ref(), self.config.fetch_batch_size)
            .map_err(|_| NodeError::FinalityRejected)?
        else {
            return Ok(0);
        };
        self.ingest_segment(segment, finality)
    }

    pub fn ingest_segment<T, V>(&self, segment: FinalizedExecutionSegmentV2<T>, finality: &V) -> Result<usize>
    where
        T: Clone + Serialize + DeserializeOwned,
        V: LedgerFinalityVerifier<T>,
    {
        require_runtime_available(&self.runtime)?;
        require_verifier_profile(&self.config, finality)?;
        let current = self.queue.cursor()?;
        validate_cursor_finality(current.as_ref(), &self.config, finality)?;
        let Some(prepared) = prepare_segment(
            &self.queue,
            &self.runtime,
            self.runtime.descriptor(),
            self.runtime.member_id(),
            &self.config,
            current.as_ref(),
            &segment,
            finality,
        )?
        else {
            return Ok(0);
        };
        match self.queue.commit_scan(ScanCommit {
            expected_cursor: current.as_ref(),
            next_cursor: &prepared.next_cursor,
            segment_digest: prepared.segment_digest,
            expire_through_ms: prepared.expire_through_ms,
            pending_writes: prepared.pending_writes,
            pending_removals: prepared.pending_removals,
            inbox_writes: prepared.inbox_writes,
        })? {
            ScanCommitOutcome::Applied { inbox_added } => Ok(inbox_added),
            ScanCommitOutcome::Replayed => Ok(0),
        }
    }

    pub fn process_next<T, V>(&mut self, finality: &V) -> Result<ProcessDisposition>
    where
        T: Clone + Serialize + DeserializeOwned,
        V: LedgerFinalityVerifier<T>,
    {
        require_runtime_available(&self.runtime)?;
        require_verifier_profile(&self.config, finality)?;
        let Some(stored) = self.queue.next_pending()? else {
            return Ok(ProcessDisposition::Idle);
        };
        let record: crate::VerifiedRefreshRecordV2 = serde_json::from_slice(&stored.record)?;
        if serde_json::to_vec(&record)? != stored.record {
            return Err(NodeError::CorruptState);
        }
        let validated = validate_compact_record(
            self.runtime.descriptor(),
            self.runtime.member_id(),
            &self.config,
            record,
            finality,
        )?;
        let runtime_outcome = self.runtime.apply_verified_refresh(&validated.refresh)?;
        validate_runtime_outcome(
            self.runtime.descriptor(),
            self.runtime.member_id(),
            validated.expected_event_id,
            &runtime_outcome,
        )?;
        #[cfg(test)]
        if self.crash_after_runtime_once {
            self.crash_after_runtime_once = false;
            return Err(NodeError::InjectedCrash);
        }
        self.queue.mark_applied(stored.id, &runtime_outcome.acknowledgement)?;
        Ok(if runtime_outcome.replay {
            ProcessDisposition::Replay
        } else {
            ProcessDisposition::Applied
        })
    }

    pub fn control(&self, request: ControlRequest, finality_available: bool) -> Result<ControlResponse> {
        match request {
            ControlRequest::Status => {
                let (inbox_pending, outbox_pending) = self.queue.counts()?;
                Ok(ControlResponse::Status(Box::new(NodeStatus {
                    member_id: self.runtime.member_id().get(),
                    committee_epoch: self.runtime.descriptor().epoch().get(),
                    descriptor_id: *self.runtime.descriptor().id().as_bytes(),
                    inbox_pending,
                    outbox_pending,
                    cursor: self.queue.cursor()?,
                    signing_available: false,
                    finality_available,
                    v2_runtime_available: self.runtime.is_v2_available(),
                })))
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

struct PreparedSegment {
    next_cursor: LedgerCursor,
    segment_digest: [u8; 32],
    expire_through_ms: u64,
    pending_writes: Vec<PendingInvoiceWrite>,
    pending_removals: Vec<PendingInvoiceRemoval>,
    inbox_writes: Vec<InboxWrite>,
}

struct CompactValidation {
    refresh: VerifiedV2Refresh,
    expected_event_id: [u8; 32],
}

type SemanticLocation = ([u8; 32], (u64, u32));

#[allow(clippy::too_many_arguments)]
fn prepare_segment<T, V, R>(
    queue: &SqliteQueue,
    runtime: &R,
    descriptor: &thunderbolt_committee::CommitteeDescriptor,
    member_id: thunderbolt_committee::CommitteeMemberId,
    config: &NodeConfig,
    current: Option<&LedgerCursor>,
    segment: &FinalizedExecutionSegmentV2<T>,
    finality: &V,
) -> Result<Option<PreparedSegment>>
where
    T: Clone + Serialize + DeserializeOwned,
    V: LedgerFinalityVerifier<T>,
    R: CommitteeRuntime,
{
    if segment.blocks.len() > usize::from(config.fetch_batch_size)
        || bounded_json_len(segment, crate::types::MAX_SCAN_SEGMENT_BYTES).is_err()
        || segment.ledger_chain_id != config.ledger_chain_id
    {
        return Err(NodeError::InvalidLedgerArtifact);
    }
    let expected_start = current.map_or(1, |cursor| cursor.next_height);
    let expected_previous = current.map_or_else(AppHashV2::zero, |cursor| cursor.expected_previous_app_hash.clone());
    if segment.start_height != expected_start || segment.expected_previous_app_hash != expected_previous {
        return Err(NodeError::CursorConflict);
    }
    validate_segment_head(segment)?;
    if segment.blocks.is_empty() {
        return Err(NodeError::InvalidLedgerArtifact);
    }

    let mut next_height = expected_start;
    let mut previous_app_hash = expected_previous;
    let mut processed_refresh_count = current.map_or(0, |cursor| cursor.processed_refresh_count);
    let mut last_refresh_entry_hash =
        current.map_or_else(EntryHashV2::zero, |cursor| cursor.last_refresh_entry_hash.clone());
    let total_entries = segment.blocks.iter().try_fold(0_usize, |total, block| {
        total
            .checked_add(block.block.entries().len())
            .ok_or(NodeError::NumericRange)
    })?;
    if segment.occurrences.len() > total_entries {
        return Err(NodeError::InvalidLedgerArtifact);
    }
    let mut occurrences = BTreeMap::new();
    for occurrence in &segment.occurrences {
        if occurrences
            .insert((occurrence.observed_height, occurrence.observed_index), occurrence)
            .is_some()
        {
            return Err(NodeError::ReplayConflict);
        }
    }
    let mut pending_new: BTreeMap<[u8; 32], (crate::types::PendingInvoiceRecordV2, Vec<u8>)> = BTreeMap::new();
    let mut seen_invoice_semantics = BTreeMap::new();
    let mut seen_transfer_semantics = BTreeMap::new();
    let mut pending_removals = Vec::new();
    let mut inbox_writes = Vec::new();
    let mut last_finality = None;
    let mut expire_through_ms = 0_u64;

    for finalized in &segment.blocks {
        let block = &finalized.block;
        block
            .validate_chain_id(&config.ledger_chain_id)
            .map_err(|_| NodeError::InvalidLedgerArtifact)?;
        if block.height() != next_height || block.previous_app_hash() != &previous_app_hash {
            return Err(NodeError::CursorConflict);
        }
        let block_finality = finality
            .verify_finalized_block(finalized)
            .map_err(|_| NodeError::FinalityRejected)?;
        validate_block_finality(config, block, &block_finality)?;
        let commitment =
            ExecutedBlockCommitmentV2::from_executed_block(block).map_err(|_| NodeError::InvalidLedgerArtifact)?;
        for (index, entry) in block.entries().iter().enumerate() {
            entry
                .proposal()
                .verify()
                .map_err(|_| NodeError::InvalidLedgerArtifact)?;
            let body = entry.proposal().body();
            if !channel_matches_descriptor(descriptor, body.channel()) {
                continue;
            }
            let event = ChannelEventV2::from_canonical_bytes(body.event().as_bytes())
                .map_err(|_| NodeError::InvalidLedgerArtifact)?;
            let evidence = crate::ExecutedEntryEvidenceV2 {
                entry: entry.clone(),
                inclusion_proof: block.entry_proof(index).map_err(|_| NodeError::InvalidLedgerArtifact)?,
            };
            match event {
                ChannelEventV2::Invoice(invoice)
                    if body.actor_role() == ActorRoleV2::Recipient && body.event_kind() == EventKindV2::Invoice =>
                {
                    let occurrence = verify_occurrence(
                        finality,
                        occurrences
                            .remove(&(entry.metadata().block_height(), entry.metadata().block_index()))
                            .ok_or(NodeError::InvalidLedgerArtifact)?,
                        entry,
                        config,
                        segment.next_height.saturating_sub(1),
                        &segment.next_expected_previous_app_hash,
                    )?;
                    let entry_hash = *entry.metadata().entry_hash().as_bytes();
                    let semantic_digest = entry_semantic_digest(entry)?;
                    let first_position = (occurrence.first_height, occurrence.first_index);
                    if occurrence.kind == crate::EntryOccurrenceKindV2::Replay {
                        let known = if let Some(known) = seen_invoice_semantics.get(&entry_hash) {
                            Some(*known)
                        } else if let Some((pending, _)) = pending_new.get(&entry_hash) {
                            Some((
                                pending.semantic_digest,
                                (
                                    pending.invoice.entry.metadata().block_height(),
                                    pending.invoice.entry.metadata().block_index(),
                                ),
                            ))
                        } else {
                            stored_invoice_semantic(queue, entry_hash, descriptor, member_id, config, finality)?
                        };
                        if known.is_some_and(|known| known != (semantic_digest, first_position)) {
                            return Err(NodeError::ReplayConflict);
                        }
                        seen_invoice_semantics.insert(entry_hash, (semantic_digest, first_position));
                        continue;
                    }
                    if seen_invoice_semantics.contains_key(&entry_hash)
                        || pending_new.contains_key(&entry_hash)
                        || queue.pending_invoice(entry_hash)?.is_some()
                        || queue.inbox_by_invoice(entry_hash)?.is_some()
                    {
                        return Err(NodeError::ReplayConflict);
                    }
                    let pending = crate::types::PendingInvoiceRecordV2 {
                        commitment: commitment.clone(),
                        invoice: evidence,
                        semantic_digest,
                        finality: block_finality.clone(),
                        expires_at_ms: invoice.expires_at_ms,
                    };
                    validate_pending_invoice(descriptor, member_id, config, &pending)?;
                    let encoded = serde_json::to_vec(&pending)?;
                    if encoded.len() > crate::MAX_INBOX_RECORD_BYTES {
                        return Err(NodeError::InvalidLedgerArtifact);
                    }
                    seen_invoice_semantics.insert(entry_hash, (semantic_digest, first_position));
                    pending_new.insert(entry_hash, (pending, encoded));
                }
                ChannelEventV2::Transfer(transfer)
                    if body.actor_role() == ActorRoleV2::Holder && body.event_kind() == EventKindV2::Transfer =>
                {
                    let occurrence = verify_occurrence(
                        finality,
                        occurrences
                            .remove(&(entry.metadata().block_height(), entry.metadata().block_index()))
                            .ok_or(NodeError::InvalidLedgerArtifact)?,
                        entry,
                        config,
                        segment.next_height.saturating_sub(1),
                        &segment.next_expected_previous_app_hash,
                    )?;
                    let transfer_hash = *entry.metadata().entry_hash().as_bytes();
                    let transfer_semantic_digest = entry_semantic_digest(entry)?;
                    let first_position = (occurrence.first_height, occurrence.first_index);
                    if occurrence.kind == crate::EntryOccurrenceKindV2::Replay {
                        let known = if let Some(known) = seen_transfer_semantics.get(&transfer_hash) {
                            Some(*known)
                        } else {
                            stored_transfer_semantic(queue, transfer_hash, descriptor, member_id, config, finality)?
                        };
                        if known.is_some_and(|known| known != (transfer_semantic_digest, first_position)) {
                            return Err(NodeError::ReplayConflict);
                        }
                        seen_transfer_semantics.insert(transfer_hash, (transfer_semantic_digest, first_position));
                        continue;
                    }
                    if seen_transfer_semantics.contains_key(&transfer_hash)
                        || queue.inbox_by_transfer(transfer_hash)?.is_some()
                    {
                        return Err(NodeError::ReplayConflict);
                    }
                    let invoice_hash = *transfer.invoice_entry_hash.as_bytes();
                    let (pending, expected_digest) = if let Some((pending, _)) = pending_new.remove(&invoice_hash) {
                        (pending, None)
                    } else {
                        let stored = queue
                            .pending_invoice(invoice_hash)?
                            .ok_or(NodeError::RefreshBindingMismatch)?;
                        let pending: crate::types::PendingInvoiceRecordV2 = serde_json::from_slice(&stored.record)?;
                        if serde_json::to_vec(&pending)? != stored.record {
                            return Err(NodeError::CorruptState);
                        }
                        finality
                            .verify_durable_capability(&pending.finality)
                            .map_err(|_| NodeError::FinalityRejected)?;
                        (pending, Some(stored.digest))
                    };
                    if pending.expires_at_ms <= block.block_time_ms() {
                        return Err(NodeError::RefreshBindingMismatch);
                    }
                    let blocks = RefreshBlockCommitmentsV2::new(pending.commitment.clone(), commitment.clone());
                    let finality_capability = crate::DurableFinalityCapability::new(
                        &blocks,
                        pending.finality.clone(),
                        block_finality.clone(),
                    )?;
                    let record = crate::VerifiedRefreshRecordV2 {
                        blocks,
                        invoice: pending.invoice,
                        transfer: evidence,
                        invoice_semantic_digest: pending.semantic_digest,
                        transfer_semantic_digest,
                        finality: finality_capability,
                    };
                    let validated = validate_compact_record(descriptor, member_id, config, record.clone(), finality)?;
                    runtime.validate_verified_refresh(&validated.refresh)?;
                    let encoded = serde_json::to_vec(&record)?;
                    if encoded.len() > crate::MAX_INBOX_RECORD_BYTES {
                        return Err(NodeError::InvalidLedgerArtifact);
                    }
                    processed_refresh_count = processed_refresh_count.checked_add(1).ok_or(NodeError::NumericRange)?;
                    last_refresh_entry_hash = entry.metadata().entry_hash().clone();
                    seen_transfer_semantics.insert(transfer_hash, (transfer_semantic_digest, first_position));
                    inbox_writes.push(InboxWrite {
                        item_id: transfer_hash,
                        invoice_entry_hash: invoice_hash,
                        request_digest: *entry.metadata().request_digest().as_bytes(),
                        record: encoded,
                    });
                    if let Some(expected_digest) = expected_digest {
                        pending_removals.push(PendingInvoiceRemoval {
                            entry_hash: invoice_hash,
                            expected_digest,
                        });
                    }
                }
                ChannelEventV2::Invoice(_) | ChannelEventV2::Transfer(_) => {
                    return Err(NodeError::RefreshBindingMismatch);
                }
                _ => {}
            }
        }
        expire_through_ms = block.block_time_ms();
        pending_new.retain(|_, (pending, _)| pending.expires_at_ms > expire_through_ms);
        previous_app_hash = block.app_hash().clone();
        next_height = next_height.checked_add(1).ok_or(NodeError::NumericRange)?;
        last_finality = Some(block_finality);
    }
    if !occurrences.is_empty() {
        return Err(NodeError::InvalidLedgerArtifact);
    }
    validate_segment_end(segment, next_height, &previous_app_hash)?;
    let last_finality = last_finality.ok_or(NodeError::InvalidLedgerArtifact)?;
    let next_cursor = LedgerCursor {
        next_height,
        expected_previous_app_hash: previous_app_hash,
        processed_refresh_count,
        last_refresh_entry_hash,
        last_finality,
    };
    let pending_writes = pending_new
        .into_iter()
        .map(|(entry_hash, (pending, record))| PendingInvoiceWrite {
            entry_hash,
            expires_at_ms: pending.expires_at_ms,
            record,
        })
        .collect::<Vec<_>>();
    let segment_digest =
        prepared_segment_digest(current, &next_cursor, &pending_writes, &pending_removals, &inbox_writes);
    Ok(Some(PreparedSegment {
        next_cursor,
        segment_digest,
        expire_through_ms,
        pending_writes,
        pending_removals,
        inbox_writes,
    }))
}

struct BoundedJsonCounter {
    length: usize,
    maximum: usize,
}

impl std::io::Write for BoundedJsonCounter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let next = self
            .length
            .checked_add(bytes.len())
            .ok_or_else(|| std::io::Error::other("JSON length overflow"))?;
        if next > self.maximum {
            return Err(std::io::Error::other("JSON exceeds configured bound"));
        }
        self.length = next;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn bounded_json_len<T: Serialize>(value: &T, maximum: usize) -> Result<usize> {
    let mut counter = BoundedJsonCounter { length: 0, maximum };
    serde_json::to_writer(&mut counter, value).map_err(|_| NodeError::InvalidLedgerArtifact)?;
    counter.flush().map_err(|_| NodeError::InvalidLedgerArtifact)?;
    Ok(counter.length)
}

fn validate_segment_head<T>(segment: &FinalizedExecutionSegmentV2<T>) -> Result<()> {
    if segment.start_height == 0
        || segment.blocks.is_empty()
        || segment.blocks.len() > usize::from(crate::types::MAX_BATCH_ITEMS)
    {
        return Err(NodeError::InvalidLedgerArtifact);
    }
    Ok(())
}

fn validate_segment_end<T>(
    segment: &FinalizedExecutionSegmentV2<T>,
    next_height: u64,
    previous: &AppHashV2,
) -> Result<()> {
    if segment.next_height != next_height || &segment.next_expected_previous_app_hash != previous {
        return Err(NodeError::CursorConflict);
    }
    Ok(())
}

fn validate_block_finality(
    config: &NodeConfig,
    block: &thunderbolt_ledger::ExecutedBlockV2,
    capability: &crate::DurableBlockFinalityCapability,
) -> Result<()> {
    capability.validate_shape()?;
    if capability.verifier_profile() != config.finality_verifier_profile
        || capability.ledger_chain_id() != &config.ledger_chain_id
        || capability.block_height() != block.height()
        || capability.app_hash() != block.app_hash()
    {
        return Err(NodeError::FinalityRejected);
    }
    Ok(())
}

fn channel_matches_descriptor(
    descriptor: &thunderbolt_committee::CommitteeDescriptor,
    binding: &thunderbolt_wire::ChannelBindingV2,
) -> bool {
    binding.network == descriptor.network()
        && binding.deployment_id.as_bytes() == descriptor.deployment_id()
        && binding.committee_epoch == descriptor.epoch().get()
        && binding.committee_descriptor_digest.as_bytes() == descriptor.id().as_bytes()
}

fn prepared_segment_digest(
    current: Option<&LedgerCursor>,
    next: &LedgerCursor,
    pending_writes: &[PendingInvoiceWrite],
    pending_removals: &[PendingInvoiceRemoval],
    inbox_writes: &[InboxWrite],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"bitcoin-thunderbolt/committee-node/prepared-segment/v2");
    append_cursor_digest(&mut hasher, current);
    append_cursor_digest(&mut hasher, Some(next));
    for write in pending_writes {
        hasher.update(write.entry_hash);
        hasher.update(write.expires_at_ms.to_be_bytes());
        hasher.update(Sha256::digest(&write.record));
    }
    for removal in pending_removals {
        hasher.update(removal.entry_hash);
        hasher.update(removal.expected_digest);
    }
    for write in inbox_writes {
        hasher.update(write.item_id);
        hasher.update(write.request_digest);
        hasher.update(Sha256::digest(&write.record));
    }
    hasher.finalize().into()
}

fn append_cursor_digest(hasher: &mut Sha256, cursor: Option<&LedgerCursor>) {
    match cursor {
        Some(cursor) => {
            hasher.update([1]);
            hasher.update(cursor.next_height.to_be_bytes());
            hasher.update(cursor.expected_previous_app_hash.as_bytes());
            hasher.update(cursor.processed_refresh_count.to_be_bytes());
            hasher.update(cursor.last_refresh_entry_hash.as_bytes());
            hasher.update(cursor.last_finality.verifier_profile().as_bytes());
            hasher.update(cursor.last_finality.ledger_chain_id().as_bytes());
            hasher.update(cursor.last_finality.block_height().to_be_bytes());
            hasher.update(cursor.last_finality.app_hash().as_bytes());
            hasher.update(cursor.last_finality.verifier_digest().as_bytes());
            hasher.update((cursor.last_finality.attestation().len() as u64).to_be_bytes());
            hasher.update(cursor.last_finality.attestation());
        }
        None => hasher.update([0]),
    }
}

fn verify_occurrence<T, V>(
    finality: &V,
    occurrence: &crate::FinalizedEntryOccurrenceV2<T>,
    entry: &thunderbolt_ledger::ExecutedEntryV2,
    config: &NodeConfig,
    expected_through_height: u64,
    expected_through_app_hash: &AppHashV2,
) -> Result<crate::VerifiedEntryOccurrenceV2>
where
    V: LedgerFinalityVerifier<T>,
{
    let verified = finality
        .verify_entry_occurrence(occurrence)
        .map_err(|_| NodeError::FinalityRejected)?;
    let metadata = entry.metadata();
    let semantic_digest = entry_semantic_digest(entry)?;
    let first_position = (verified.first_height, verified.first_index);
    let observed_position = (metadata.block_height(), metadata.block_index());
    let kind_matches = match verified.kind {
        crate::EntryOccurrenceKindV2::First => first_position == observed_position,
        crate::EntryOccurrenceKindV2::Replay => first_position < observed_position,
    };
    if verified.verifier_profile != config.finality_verifier_profile
        || verified.verifier_digest.as_bytes() == &[0; 32]
        || verified.ledger_chain_id != config.ledger_chain_id
        || verified.channel_context_id != *metadata.channel_context_id()
        || verified.entry_hash != *metadata.entry_hash()
        || verified.semantic_digest != semantic_digest
        || verified.observed_height != metadata.block_height()
        || verified.observed_index != metadata.block_index()
        || verified.through_height < metadata.block_height()
        || verified.through_height != expected_through_height
        || &verified.expected_through_app_hash != expected_through_app_hash
        || !kind_matches
        || occurrence.kind != verified.kind
        || occurrence.ledger_chain_id != verified.ledger_chain_id
        || occurrence.channel_context_id != verified.channel_context_id
        || occurrence.entry_hash != verified.entry_hash
        || occurrence.semantic_digest != verified.semantic_digest
        || occurrence.observed_height != verified.observed_height
        || occurrence.observed_index != verified.observed_index
        || occurrence.first_height != verified.first_height
        || occurrence.first_index != verified.first_index
        || occurrence.through_height != verified.through_height
        || occurrence.expected_through_app_hash != verified.expected_through_app_hash
    {
        return Err(NodeError::FinalityRejected);
    }
    Ok(verified)
}

fn stored_invoice_semantic<T, V>(
    queue: &SqliteQueue,
    entry_hash: [u8; 32],
    descriptor: &thunderbolt_committee::CommitteeDescriptor,
    member_id: thunderbolt_committee::CommitteeMemberId,
    config: &NodeConfig,
    finality: &V,
) -> Result<Option<SemanticLocation>>
where
    V: LedgerFinalityVerifier<T>,
{
    if let Some(stored) = queue.pending_invoice(entry_hash)? {
        let pending: crate::types::PendingInvoiceRecordV2 = serde_json::from_slice(&stored.record)?;
        if serde_json::to_vec(&pending)? != stored.record {
            return Err(NodeError::CorruptState);
        }
        finality
            .verify_durable_capability(&pending.finality)
            .map_err(|_| NodeError::FinalityRejected)?;
        validate_pending_invoice(descriptor, member_id, config, &pending)?;
        return Ok(Some((
            pending.semantic_digest,
            (
                pending.invoice.entry.metadata().block_height(),
                pending.invoice.entry.metadata().block_index(),
            ),
        )));
    }
    let Some(stored) = queue.inbox_by_invoice(entry_hash)? else {
        return Ok(None);
    };
    let record: crate::VerifiedRefreshRecordV2 = serde_json::from_slice(&stored.record)?;
    if serde_json::to_vec(&record)? != stored.record {
        return Err(NodeError::CorruptState);
    }
    let semantic = record.invoice_semantic_digest;
    let position = (
        record.invoice.entry.metadata().block_height(),
        record.invoice.entry.metadata().block_index(),
    );
    validate_compact_record(descriptor, member_id, config, record, finality)?;
    Ok(Some((semantic, position)))
}

fn stored_transfer_semantic<T, V>(
    queue: &SqliteQueue,
    entry_hash: [u8; 32],
    descriptor: &thunderbolt_committee::CommitteeDescriptor,
    member_id: thunderbolt_committee::CommitteeMemberId,
    config: &NodeConfig,
    finality: &V,
) -> Result<Option<SemanticLocation>>
where
    V: LedgerFinalityVerifier<T>,
{
    let Some(stored) = queue.inbox_by_transfer(entry_hash)? else {
        return Ok(None);
    };
    let record: crate::VerifiedRefreshRecordV2 = serde_json::from_slice(&stored.record)?;
    if serde_json::to_vec(&record)? != stored.record {
        return Err(NodeError::CorruptState);
    }
    let semantic = record.transfer_semantic_digest;
    let position = (
        record.transfer.entry.metadata().block_height(),
        record.transfer.entry.metadata().block_index(),
    );
    validate_compact_record(descriptor, member_id, config, record, finality)?;
    Ok(Some((semantic, position)))
}

struct ParsedInvoiceArtifacts {
    event: thunderbolt_protocol::v2::InvoiceEventV2,
    recipient: RecipientShareEnvelopeV2,
    threshold: ThresholdEnvelopeV2,
}

fn validate_pending_invoice(
    descriptor: &thunderbolt_committee::CommitteeDescriptor,
    member_id: thunderbolt_committee::CommitteeMemberId,
    config: &NodeConfig,
    pending: &crate::types::PendingInvoiceRecordV2,
) -> Result<ParsedInvoiceArtifacts> {
    validate_compact_entry(&pending.invoice, &pending.commitment, &config.ledger_chain_id)?;
    if pending.semantic_digest != entry_semantic_digest(&pending.invoice.entry)? {
        return Err(NodeError::ReplayConflict);
    }
    validate_block_capability_commitment(config, &pending.finality, &pending.commitment)?;
    let body = pending.invoice.entry.proposal().body();
    if body.actor_role() != ActorRoleV2::Recipient
        || body.event_kind() != EventKindV2::Invoice
        || !channel_matches_descriptor(descriptor, body.channel())
    {
        return Err(NodeError::RefreshBindingMismatch);
    }
    let ChannelEventV2::Invoice(event) =
        ChannelEventV2::from_canonical_bytes(body.event().as_bytes()).map_err(|_| NodeError::InvalidLedgerArtifact)?
    else {
        return Err(NodeError::RefreshBindingMismatch);
    };
    if event.expires_at_ms != pending.expires_at_ms {
        return Err(NodeError::RefreshBindingMismatch);
    }
    let recipient =
        match PublicMessageV2::decode(event.invoice_proof.as_bytes()).map_err(|_| NodeError::RefreshBindingMismatch)? {
            PublicMessageV2::RecipientShare(value) => value,
            _ => return Err(NodeError::RefreshBindingMismatch),
        };
    let threshold = match PublicMessageV2::decode(event.committee_package.as_bytes())
        .map_err(|_| NodeError::RefreshBindingMismatch)?
    {
        PublicMessageV2::ThresholdRefresh(value) => value,
        _ => return Err(NodeError::RefreshBindingMismatch),
    };
    validate_threshold_package_v2(&recipient, &threshold).map_err(|_| NodeError::RefreshBindingMismatch)?;
    let expected_step = event
        .holder_step
        .checked_add(1)
        .ok_or(NodeError::RefreshBindingMismatch)?;
    let descriptor_ids = descriptor
        .members()
        .iter()
        .map(|member| member.id().get())
        .collect::<Vec<_>>();
    let roster_ids = threshold
        .package
        .roster
        .members
        .iter()
        .map(|member| member.member_id)
        .collect::<Vec<_>>();
    let OperationBindingV2::Invoice { channel, invoice_id } = &recipient.binding else {
        return Err(NodeError::RefreshBindingMismatch);
    };
    if channel != body.channel()
        || invoice_id != &event.invoice_id
        || threshold.binding != recipient.binding
        || threshold.package.expected_transfer_step != expected_step
        || threshold.package.roster.threshold != descriptor.threshold()
        || descriptor_ids != roster_ids
        || !roster_ids.contains(&member_id.get())
        || threshold.distribution.anchor_base.as_bytes() != descriptor.anchor_base().serialize()
        || recipient.statement.recipient_key.as_bytes() != event.recipient_encryption_key.as_bytes()
        || recipient.statement.committed_point.as_bytes() != event.public_delta.as_bytes()
        || recipient.statement.ciphertext.as_bytes() != event.recipient_ciphertext.as_bytes()
    {
        return Err(NodeError::RefreshBindingMismatch);
    }
    Ok(ParsedInvoiceArtifacts {
        event,
        recipient,
        threshold,
    })
}

fn validate_compact_record<T, V>(
    descriptor: &thunderbolt_committee::CommitteeDescriptor,
    member_id: thunderbolt_committee::CommitteeMemberId,
    config: &NodeConfig,
    record: crate::VerifiedRefreshRecordV2,
    finality: &V,
) -> Result<CompactValidation>
where
    V: LedgerFinalityVerifier<T>,
{
    record.blocks.validate_canonical()?;
    record.finality.validate_canonical(&record.blocks)?;
    finality
        .verify_durable_capability(record.finality.invoice())
        .map_err(|_| NodeError::FinalityRejected)?;
    if record.finality.transfer() != record.finality.invoice() {
        finality
            .verify_durable_capability(record.finality.transfer())
            .map_err(|_| NodeError::FinalityRejected)?;
    }
    validate_block_capability_commitment(config, record.finality.invoice(), record.blocks.invoice())?;
    validate_block_capability_commitment(config, record.finality.transfer(), record.blocks.transfer())?;
    let pending = crate::types::PendingInvoiceRecordV2 {
        commitment: record.blocks.invoice().clone(),
        invoice: record.invoice.clone(),
        semantic_digest: record.invoice_semantic_digest,
        finality: record.finality.invoice().clone(),
        expires_at_ms: invoice_expiry(&record.invoice)?,
    };
    let parsed_invoice = validate_pending_invoice(descriptor, member_id, config, &pending)?;
    if record.transfer_semantic_digest != entry_semantic_digest(&record.transfer.entry)? {
        return Err(NodeError::ReplayConflict);
    }
    validate_compact_entry(&record.transfer, record.blocks.transfer(), &config.ledger_chain_id)?;
    let transfer_body = record.transfer.entry.proposal().body();
    if transfer_body.actor_role() != ActorRoleV2::Holder
        || transfer_body.event_kind() != EventKindV2::Transfer
        || transfer_body.channel() != pending.invoice.entry.proposal().body().channel()
    {
        return Err(NodeError::RefreshBindingMismatch);
    }
    let ChannelEventV2::Transfer(transfer_event) =
        ChannelEventV2::from_canonical_bytes(transfer_body.event().as_bytes())
            .map_err(|_| NodeError::InvalidLedgerArtifact)?
    else {
        return Err(NodeError::RefreshBindingMismatch);
    };
    let transfer_proof = match PublicMessageV2::decode(transfer_event.transfer_proof.as_bytes())
        .map_err(|_| NodeError::RefreshBindingMismatch)?
    {
        PublicMessageV2::Transfer(value) => value,
        _ => return Err(NodeError::RefreshBindingMismatch),
    };
    let expected_step = parsed_invoice
        .event
        .holder_step
        .checked_add(1)
        .ok_or(NodeError::RefreshBindingMismatch)?;
    let OperationBindingV2::Transfer {
        channel,
        invoice_id,
        step,
    } = &transfer_proof.binding
    else {
        return Err(NodeError::RefreshBindingMismatch);
    };
    if channel != transfer_body.channel()
        || invoice_id != &parsed_invoice.event.invoice_id
        || *step != expected_step
        || transfer_event.invoice_id != parsed_invoice.event.invoice_id
        || transfer_event.invoice_entry_hash != *record.invoice.entry.metadata().entry_hash()
        || transfer_proof.statement.anchor_base != parsed_invoice.threshold.distribution.anchor_base
        || transfer_proof.statement.recipient_key != parsed_invoice.recipient.statement.recipient_key
        || transfer_proof.statement.invoice_ciphertext != parsed_invoice.recipient.statement.ciphertext
        || transfer_proof.anchor_transition.delta != parsed_invoice.threshold.distribution.delta
        || transfer_proof.anchor_transition.next_anchor.as_bytes() != transfer_event.next_holder_anchor.as_bytes()
        || transfer_proof.statement.next_holder_ciphertext.as_bytes()
            != transfer_event.next_holder_ciphertext.as_bytes()
        || (
            record.invoice.entry.metadata().block_height(),
            record.invoice.entry.metadata().block_index(),
        ) >= (
            record.transfer.entry.metadata().block_height(),
            record.transfer.entry.metadata().block_index(),
        )
        || record.invoice.entry.metadata().sequence() >= record.transfer.entry.metadata().sequence()
    {
        return Err(NodeError::RefreshBindingMismatch);
    }
    let commitment = CommittedTransfer::new(
        parsed_invoice
            .recipient
            .canonical_digest()
            .map_err(|_| NodeError::RefreshBindingMismatch)?,
        parsed_invoice
            .threshold
            .canonical_digest()
            .map_err(|_| NodeError::RefreshBindingMismatch)?,
        transfer_proof
            .canonical_digest()
            .map_err(|_| NodeError::RefreshBindingMismatch)?,
        EntryHash::from_bytes(*record.invoice.entry.metadata().entry_hash().as_bytes()),
        EntryHash::from_bytes(*record.transfer.entry.metadata().entry_hash().as_bytes()),
        EntryHash::from_bytes(*record.blocks.transfer().app_hash().as_bytes()),
        record.transfer.entry.metadata().sequence(),
        *step,
    )
    .map_err(|_| NodeError::RefreshBindingMismatch)?;
    Ok(CompactValidation {
        expected_event_id: refresh_event_id(commitment),
        refresh: VerifiedV2Refresh {
            recipient_share: parsed_invoice.recipient,
            threshold_distribution: parsed_invoice.threshold,
            transfer_proof,
            commitment,
        },
    })
}

fn invoice_expiry(evidence: &crate::ExecutedEntryEvidenceV2) -> Result<u64> {
    let ChannelEventV2::Invoice(invoice) =
        ChannelEventV2::from_canonical_bytes(evidence.entry.proposal().body().event().as_bytes())
            .map_err(|_| NodeError::InvalidLedgerArtifact)?
    else {
        return Err(NodeError::RefreshBindingMismatch);
    };
    Ok(invoice.expires_at_ms)
}

fn entry_semantic_digest(entry: &thunderbolt_ledger::ExecutedEntryV2) -> Result<[u8; 32]> {
    let bytes = entry
        .proposal()
        .body()
        .canonical_bytes()
        .map_err(|_| NodeError::InvalidLedgerArtifact)?;
    let mut hasher = Sha256::new();
    hasher.update(b"bitcoin-thunderbolt/committee-node/entry-semantic/v2");
    hasher.update(
        u64::try_from(bytes.len())
            .map_err(|_| NodeError::NumericRange)?
            .to_be_bytes(),
    );
    hasher.update(bytes);
    Ok(hasher.finalize().into())
}

fn validate_compact_entry(
    evidence: &crate::ExecutedEntryEvidenceV2,
    commitment: &thunderbolt_ledger::ExecutedBlockCommitmentV2,
    chain_id: &thunderbolt_ledger::LedgerChainIdV2,
) -> Result<()> {
    commitment
        .validate_chain_id(chain_id)
        .map_err(|_| NodeError::InvalidLedgerArtifact)?;
    evidence
        .entry
        .proposal()
        .verify()
        .map_err(|_| NodeError::InvalidLedgerArtifact)?;
    evidence
        .inclusion_proof
        .verify_entry_against_commitment(&evidence.entry, commitment)
        .map_err(|_| NodeError::InvalidLedgerArtifact)
}

fn validate_block_capability_commitment(
    config: &NodeConfig,
    capability: &crate::DurableBlockFinalityCapability,
    commitment: &thunderbolt_ledger::ExecutedBlockCommitmentV2,
) -> Result<()> {
    capability.validate_shape()?;
    if capability.verifier_profile() != config.finality_verifier_profile
        || capability.ledger_chain_id() != &config.ledger_chain_id
        || capability.block_height() != commitment.height()
        || capability.app_hash() != commitment.app_hash()
    {
        return Err(NodeError::FinalityRejected);
    }
    Ok(())
}

fn refresh_event_id(commitment: CommittedTransfer) -> [u8; 32] {
    let mut hasher = Sha256::new();
    let domain = b"bitcoin-thunderbolt/committee-refresh-event/v2";
    hasher.update((domain.len() as u64).to_be_bytes());
    hasher.update(domain);
    hasher.update(commitment.recipient_share_digest());
    hasher.update(commitment.threshold_refresh_digest());
    hasher.update(commitment.transfer_digest());
    hasher.update(commitment.invoice_entry_hash().as_bytes());
    hasher.update(commitment.transfer_entry_hash().as_bytes());
    hasher.update(commitment.transfer_sequence().to_be_bytes());
    hasher.update(commitment.transfer_step().to_be_bytes());
    hasher.finalize().into()
}

fn validate_runtime_outcome(
    descriptor: &thunderbolt_committee::CommitteeDescriptor,
    member_id: thunderbolt_committee::CommitteeMemberId,
    expected_event_id: [u8; 32],
    outcome: &crate::RuntimeRefreshOutcome,
) -> Result<()> {
    let acknowledgement = &outcome.acknowledgement;
    if acknowledgement.event_id != expected_event_id
        || acknowledgement.descriptor_id != *descriptor.id().as_bytes()
        || acknowledgement.epoch != descriptor.epoch().get()
        || acknowledgement.member_id != member_id.get()
        || acknowledgement.durable_revision == 0
        || acknowledgement.acknowledgement_digest == [0; 32]
    {
        return Err(NodeError::Runtime(
            "v2 runtime acknowledgement binding mismatch".to_owned(),
        ));
    }
    Ok(())
}

fn require_runtime_available<R: CommitteeRuntime>(runtime: &R) -> Result<()> {
    if runtime.is_v2_available() {
        Ok(())
    } else {
        Err(NodeError::V2RuntimeUnavailable)
    }
}

fn validate_cursor_finality<T, V>(cursor: Option<&LedgerCursor>, config: &NodeConfig, finality: &V) -> Result<()>
where
    V: LedgerFinalityVerifier<T>,
{
    let Some(cursor) = cursor else {
        return Ok(());
    };
    finality
        .verify_durable_capability(&cursor.last_finality)
        .map_err(|_| NodeError::FinalityRejected)?;
    if cursor.last_finality.verifier_profile() != config.finality_verifier_profile
        || cursor.last_finality.ledger_chain_id() != &config.ledger_chain_id
        || cursor.last_finality.block_height() != cursor.next_height.saturating_sub(1)
        || cursor.last_finality.app_hash() != &cursor.expected_previous_app_hash
    {
        return Err(NodeError::FinalityRejected);
    }
    Ok(())
}

fn require_verifier_profile<T, V>(config: &NodeConfig, verifier: &V) -> Result<()>
where
    V: LedgerFinalityVerifier<T>,
{
    if verifier.is_available() && verifier.profile_id() == config.finality_verifier_profile {
        Ok(())
    } else {
        Err(NodeError::FinalityRejected)
    }
}
