use core::fmt;

use bitcoin::Network;
use serde::{Deserialize, Serialize};
use std::io;
use thunderbolt_ledger::{
    AppHashV2, EntryHashV2, EntryMerkleProofV2, ExecutedBlockCommitmentV2, ExecutedBlockV2, ExecutedEntryV2,
    LedgerChainIdV2, SignedProposalV2,
};
use thunderbolt_wire::{RecipientShareEnvelopeV2, ThresholdEnvelopeV2, TransferEnvelopeV2};

use crate::{NodeError, Result};

pub const MAX_QUEUE_ROWS: u32 = 100_000;
pub const MAX_BATCH_ITEMS: u16 = 64;
/// Maximum aggregate canonical JSON bytes in one transient contiguous scan.
pub const MAX_SCAN_SEGMENT_BYTES: usize = 23 * 1024 * 1024;
/// Absolute canonical JSON bound for one compact durable inbox record.
///
/// Two maximum-sized signed proposals require at most eight MiB of hex JSON;
/// commitments, proofs, finality metadata, and framing fit in the remaining
/// measured headroom.
pub const MAX_INBOX_RECORD_BYTES: usize = 10 * 1024 * 1024;
pub const MAX_OUTBOX_BYTES: usize = 64 * 1024;
pub const MAX_FINALITY_ATTESTATION_BYTES: usize = 64 * 1024;
/// Maximum canonical authority-free staged finality range bytes.
pub const MAX_FINALITY_INTENT_BYTES: usize = MAX_SCAN_SEGMENT_BYTES;

/// Transport-only result of submitting one exact signed proposal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SubmissionStatus {
    /// The authenticated transport admitted the exact proposal.
    Accepted,
    /// Exact request reconciliation found the proposal already finalized.
    AlreadyKnown,
}

#[derive(Clone, Debug)]
pub struct NodeConfig {
    pub(crate) ledger_chain_id: LedgerChainIdV2,
    pub(crate) finality_verifier_profile: FinalityVerifierProfileId,
    pub(crate) finality_coordinator_id: FinalityCoordinatorId,
    pub(crate) max_inbox_rows: u32,
    pub(crate) max_outbox_rows: u32,
    pub(crate) fetch_batch_size: u16,
}

impl NodeConfig {
    pub fn new(
        ledger_chain_id: LedgerChainIdV2,
        finality_verifier_profile: FinalityVerifierProfileId,
        finality_coordinator_id: FinalityCoordinatorId,
        max_inbox_rows: u32,
        max_outbox_rows: u32,
        fetch_batch_size: u16,
    ) -> Result<Self> {
        if finality_verifier_profile == FinalityVerifierProfileId::DISABLED
            || finality_coordinator_id == FinalityCoordinatorId::DISABLED
            || max_inbox_rows == 0
            || max_outbox_rows == 0
            || max_inbox_rows > MAX_QUEUE_ROWS
            || max_outbox_rows > MAX_QUEUE_ROWS
            || fetch_batch_size == 0
            || fetch_batch_size > MAX_BATCH_ITEMS
        {
            return Err(NodeError::InvalidConfiguration(
                "finality identity, queue, or batch bound is invalid",
            ));
        }
        Ok(Self {
            ledger_chain_id,
            finality_verifier_profile,
            finality_coordinator_id,
            max_inbox_rows,
            max_outbox_rows,
            fetch_batch_size,
        })
    }

    pub fn validate_network(network: Network) -> Result<()> {
        match network {
            Network::Regtest | Network::Signet | Network::Testnet => Ok(()),
            Network::Bitcoin | Network::Testnet4 => Err(NodeError::InvalidConfiguration(
                "mainnet and Testnet4 Committee services are disabled",
            )),
        }
    }

    pub const fn ledger_chain_id(&self) -> &LedgerChainIdV2 {
        &self.ledger_chain_id
    }

    pub const fn finality_verifier_profile(&self) -> FinalityVerifierProfileId {
        self.finality_verifier_profile
    }

    pub const fn finality_coordinator_id(&self) -> FinalityCoordinatorId {
        self.finality_coordinator_id
    }

    pub const fn max_inbox_rows(&self) -> u32 {
        self.max_inbox_rows
    }

    pub const fn max_outbox_rows(&self) -> u32 {
        self.max_outbox_rows
    }

    pub const fn fetch_batch_size(&self) -> u16 {
        self.fetch_batch_size
    }
}

/// Immutable identity of the finality app version, trust policy, authenticator
/// domain, and attestation verification key.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct FinalityVerifierProfileId([u8; 32]);

impl FinalityVerifierProfileId {
    pub const DISABLED: Self = Self([0xff; 32]);
    pub fn new(bytes: [u8; 32]) -> Result<Self> {
        if bytes == [0; 32] {
            Err(NodeError::InvalidConfiguration(
                "finality verifier profile must be nonzero",
            ))
        } else {
            Ok(Self(bytes))
        }
    }
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Immutable identity of the crash-safe finality coordinator and its database.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct FinalityCoordinatorId([u8; 32]);

impl FinalityCoordinatorId {
    pub const DISABLED: Self = Self([0xff; 32]);

    pub fn new(bytes: [u8; 32]) -> Result<Self> {
        if bytes == [0; 32] {
            Err(NodeError::InvalidConfiguration(
                "finality coordinator identity must be nonzero",
            ))
        } else {
            Ok(Self(bytes))
        }
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct FinalityDigest([u8; 32]);

impl FinalityDigest {
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Authority-free exact execution range that must be durably staged before
/// any light-client trust transition may begin.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FinalityRangeIntentV2 {
    verifier_profile: FinalityVerifierProfileId,
    coordinator_id: FinalityCoordinatorId,
    ledger_chain_id: LedgerChainIdV2,
    start_height: u64,
    expected_previous_app_hash: AppHashV2,
    blocks: Vec<ExecutedBlockV2>,
    next_height: u64,
    next_expected_previous_app_hash: AppHashV2,
}

impl fmt::Debug for FinalityRangeIntentV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FinalityRangeIntentV2")
            .field("verifier_profile", &self.verifier_profile)
            .field("coordinator_id", &self.coordinator_id)
            .field("ledger_chain_id", &self.ledger_chain_id)
            .field("start_height", &self.start_height)
            .field("block_count", &self.blocks.len())
            .field("next_height", &self.next_height)
            .field("authority", &"none")
            .finish()
    }
}

impl FinalityRangeIntentV2 {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        verifier_profile: FinalityVerifierProfileId,
        coordinator_id: FinalityCoordinatorId,
        ledger_chain_id: LedgerChainIdV2,
        start_height: u64,
        expected_previous_app_hash: AppHashV2,
        blocks: Vec<ExecutedBlockV2>,
        next_height: u64,
        next_expected_previous_app_hash: AppHashV2,
    ) -> Result<Self> {
        let intent = Self {
            verifier_profile,
            coordinator_id,
            ledger_chain_id,
            start_height,
            expected_previous_app_hash,
            blocks,
            next_height,
            next_expected_previous_app_hash,
        };
        intent.validate()?;
        let _ = intent.canonical_bytes()?;
        Ok(intent)
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        let mut writer = BoundedIntentWriter::new(MAX_FINALITY_INTENT_BYTES);
        serde_json::to_writer(&mut writer, self).map_err(|_| NodeError::InvalidLedgerArtifact)?;
        Ok(writer.into_bytes())
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.is_empty() || bytes.len() > MAX_FINALITY_INTENT_BYTES {
            return Err(NodeError::InvalidLedgerArtifact);
        }
        let intent: Self = serde_json::from_slice(bytes).map_err(|_| NodeError::InvalidLedgerArtifact)?;
        intent.validate()?;
        if intent.canonical_bytes()? != bytes {
            return Err(NodeError::InvalidLedgerArtifact);
        }
        Ok(intent)
    }

    fn validate(&self) -> Result<()> {
        if self.start_height == 0
            || self.blocks.is_empty()
            || self.blocks.len() > usize::from(MAX_BATCH_ITEMS)
            || self.blocks[0].height() != self.start_height
            || self.blocks[0].previous_app_hash() != &self.expected_previous_app_hash
            || self.blocks[0].ledger_chain_id() != &self.ledger_chain_id
        {
            return Err(NodeError::InvalidLedgerArtifact);
        }
        if self.start_height == 1 {
            self.blocks[0]
                .validate_previous_block_time(None)
                .map_err(|_| NodeError::InvalidLedgerArtifact)?;
        }
        for pair in self.blocks.windows(2) {
            pair[1]
                .validate_successor(&pair[0])
                .map_err(|_| NodeError::InvalidLedgerArtifact)?;
        }
        if self
            .blocks
            .iter()
            .any(|block| block.ledger_chain_id() != &self.ledger_chain_id)
        {
            return Err(NodeError::InvalidLedgerArtifact);
        }
        let last = self.blocks.last().ok_or(NodeError::InvalidLedgerArtifact)?;
        let expected_next = self
            .start_height
            .checked_add(u64::try_from(self.blocks.len()).map_err(|_| NodeError::NumericRange)?)
            .ok_or(NodeError::NumericRange)?;
        if self.next_height != expected_next || &self.next_expected_previous_app_hash != last.app_hash() {
            return Err(NodeError::InvalidLedgerArtifact);
        }
        Ok(())
    }

    pub const fn verifier_profile(&self) -> FinalityVerifierProfileId {
        self.verifier_profile
    }

    pub const fn coordinator_id(&self) -> FinalityCoordinatorId {
        self.coordinator_id
    }

    pub const fn ledger_chain_id(&self) -> &LedgerChainIdV2 {
        &self.ledger_chain_id
    }

    pub const fn start_height(&self) -> u64 {
        self.start_height
    }

    pub const fn expected_previous_app_hash(&self) -> &AppHashV2 {
        &self.expected_previous_app_hash
    }

    pub fn blocks(&self) -> &[ExecutedBlockV2] {
        &self.blocks
    }

    pub const fn next_height(&self) -> u64 {
        self.next_height
    }

    pub const fn next_expected_previous_app_hash(&self) -> &AppHashV2 {
        &self.next_expected_previous_app_hash
    }
}

struct BoundedIntentWriter {
    bytes: Vec<u8>,
    remaining: usize,
}

impl BoundedIntentWriter {
    fn new(limit: usize) -> Self {
        Self {
            bytes: Vec::new(),
            remaining: limit,
        }
    }

    fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

impl io::Write for BoundedIntentWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > self.remaining {
            return Err(io::Error::other("finality intent exceeds its bound"));
        }
        self.bytes.extend_from_slice(bytes);
        self.remaining -= bytes.len();
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Store-issued proof that an exact authority-free finality range was durably
/// committed and read back before external trust state may advance.
#[derive(Clone, PartialEq, Eq)]
pub struct StagedFinalityRangeCapabilityV2 {
    pub(crate) store_id: [u8; 32],
    pub(crate) file_identity: [u8; 32],
    pub(crate) stage_digest: [u8; 32],
    pub(crate) intent: FinalityRangeIntentV2,
}

impl fmt::Debug for StagedFinalityRangeCapabilityV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StagedFinalityRangeCapabilityV2")
            .field("stage_digest", &self.stage_digest)
            .field("intent", &self.intent)
            .field("durability", &"role store committed and read back")
            .finish_non_exhaustive()
    }
}

impl StagedFinalityRangeCapabilityV2 {
    pub(crate) fn from_store(
        store_id: [u8; 32],
        file_identity: [u8; 32],
        stage_digest: [u8; 32],
        intent: FinalityRangeIntentV2,
    ) -> Result<Self> {
        if store_id == [0; 32] || file_identity == [0; 32] || stage_digest == [0; 32] {
            return Err(NodeError::CorruptState);
        }
        Ok(Self {
            store_id,
            file_identity,
            stage_digest,
            intent,
        })
    }

    pub const fn stage_digest(&self) -> &[u8; 32] {
        &self.stage_digest
    }

    pub const fn intent(&self) -> &FinalityRangeIntentV2 {
        &self.intent
    }
}

/// Verified startup view of one unresolved role-owned finality range.
#[derive(Clone, PartialEq, Eq)]
pub struct StagedFinalityRecoveryV2 {
    store_id: [u8; 32],
    file_identity: [u8; 32],
    stage_digest: [u8; 32],
    intent: FinalityRangeIntentV2,
}

impl fmt::Debug for StagedFinalityRecoveryV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StagedFinalityRecoveryV2")
            .field("stage_digest", &self.stage_digest)
            .field("intent", &self.intent)
            .finish_non_exhaustive()
    }
}

impl StagedFinalityRecoveryV2 {
    pub(crate) fn from_staged(staged: &StagedFinalityRangeCapabilityV2) -> Self {
        Self {
            store_id: staged.store_id,
            file_identity: staged.file_identity,
            stage_digest: staged.stage_digest,
            intent: staged.intent.clone(),
        }
    }

    pub const fn store_id(&self) -> &[u8; 32] {
        &self.store_id
    }

    pub const fn file_identity(&self) -> &[u8; 32] {
        &self.file_identity
    }

    pub const fn stage_digest(&self) -> &[u8; 32] {
        &self.stage_digest
    }

    pub const fn intent(&self) -> &FinalityRangeIntentV2 {
        &self.intent
    }
}

/// Locator classification for one relevant finalized execution.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EntryOccurrenceKindV2 {
    First,
    Replay,
}

/// Finality-authenticated first-location capability with no raw receipt.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedEntryOccurrenceV2 {
    pub kind: EntryOccurrenceKindV2,
    pub ledger_chain_id: LedgerChainIdV2,
    pub channel_context_id: thunderbolt_ledger::ChannelContextIdV2,
    pub entry_hash: EntryHashV2,
    pub semantic_digest: [u8; 32],
    pub observed_height: u64,
    pub observed_index: u32,
    pub first_height: u64,
    pub first_index: u32,
    pub through_height: u64,
    pub expected_through_app_hash: AppHashV2,
    pub verifier_profile: FinalityVerifierProfileId,
    pub coordinator_id: FinalityCoordinatorId,
    pub verifier_digest: FinalityDigest,
}

/// One complete finalized execution block and its bounded provider-free durable
/// finality capability.
#[derive(Clone)]
pub struct FinalizedBlockV2 {
    pub block: ExecutedBlockV2,
    pub finality: DurableBlockFinalityCapability,
}

impl fmt::Debug for FinalizedBlockV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FinalizedBlockV2")
            .field("height", &self.block.height())
            .field("entry_count", &self.block.entries().len())
            .field("app_hash", self.block.app_hash())
            .field("finality", &self.finality)
            .finish()
    }
}

/// Trusted result of finalizing one exact store-issued staged range.
#[derive(Clone)]
pub struct FinalizedRangeCapabilityV2 {
    stage_digest: [u8; 32],
    ledger_chain_id: LedgerChainIdV2,
    start_height: u64,
    expected_previous_app_hash: AppHashV2,
    blocks: Vec<FinalizedBlockV2>,
    occurrences: Vec<VerifiedEntryOccurrenceV2>,
    next_height: u64,
    next_expected_previous_app_hash: AppHashV2,
}

impl fmt::Debug for FinalizedRangeCapabilityV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FinalizedRangeCapabilityV2")
            .field("stage_digest", &self.stage_digest)
            .field("ledger_chain_id", &self.ledger_chain_id)
            .field("start_height", &self.start_height)
            .field("block_count", &self.blocks.len())
            .field("occurrence_count", &self.occurrences.len())
            .field("next_height", &self.next_height)
            .finish_non_exhaustive()
    }
}

impl FinalizedRangeCapabilityV2 {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        staged: &StagedFinalityRangeCapabilityV2,
        blocks: Vec<FinalizedBlockV2>,
        occurrences: Vec<VerifiedEntryOccurrenceV2>,
    ) -> Result<Self> {
        let intent = staged.intent();
        if blocks.len() != intent.blocks().len()
            || blocks
                .iter()
                .zip(intent.blocks())
                .any(|(finalized, expected)| &finalized.block != expected)
        {
            return Err(NodeError::FinalityRejected);
        }
        let result = Self {
            stage_digest: *staged.stage_digest(),
            ledger_chain_id: intent.ledger_chain_id().clone(),
            start_height: intent.start_height(),
            expected_previous_app_hash: intent.expected_previous_app_hash().clone(),
            blocks,
            occurrences,
            next_height: intent.next_height(),
            next_expected_previous_app_hash: intent.next_expected_previous_app_hash().clone(),
        };
        if result.stage_digest == [0; 32]
            || result.blocks.is_empty()
            || result.blocks.iter().any(|block| {
                block.block.ledger_chain_id() != &result.ledger_chain_id
                    || block.finality.validate_shape().is_err()
                    || block.finality.verifier_profile() != intent.verifier_profile()
                    || block.finality.coordinator_id() != intent.coordinator_id()
                    || block.finality.ledger_chain_id() != &result.ledger_chain_id
                    || block.finality.block_height() != block.block.height()
                    || block.finality.app_hash() != block.block.app_hash()
            })
            || result.occurrences.iter().any(|occurrence| {
                occurrence.verifier_profile != intent.verifier_profile()
                    || occurrence.coordinator_id != intent.coordinator_id()
                    || occurrence.ledger_chain_id != result.ledger_chain_id
                    || occurrence.through_height != result.next_height.saturating_sub(1)
                    || occurrence.expected_through_app_hash != result.next_expected_previous_app_hash
                    || occurrence.verifier_digest.as_bytes() == &[0; 32]
            })
        {
            return Err(NodeError::FinalityRejected);
        }
        Ok(result)
    }

    pub const fn stage_digest(&self) -> &[u8; 32] {
        &self.stage_digest
    }

    pub const fn ledger_chain_id(&self) -> &LedgerChainIdV2 {
        &self.ledger_chain_id
    }

    pub const fn start_height(&self) -> u64 {
        self.start_height
    }

    pub const fn expected_previous_app_hash(&self) -> &AppHashV2 {
        &self.expected_previous_app_hash
    }

    pub fn blocks(&self) -> &[FinalizedBlockV2] {
        &self.blocks
    }

    pub fn occurrences(&self) -> &[VerifiedEntryOccurrenceV2] {
        &self.occurrences
    }

    pub const fn next_height(&self) -> u64 {
        self.next_height
    }

    pub const fn next_expected_previous_app_hash(&self) -> &AppHashV2 {
        &self.next_expected_previous_app_hash
    }
}

/// Deduplicated compact block commitments for one Invoice/Transfer pair.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "layout", rename_all = "snake_case", deny_unknown_fields)]
pub enum RefreshBlockCommitmentsV2 {
    /// Both entries are included in one executed block.
    Shared {
        /// Exact compact commitment shared by both inclusion proofs.
        commitment: ExecutedBlockCommitmentV2,
    },
    /// Entries are included in distinct executed blocks.
    Distinct {
        /// Invoice block commitment.
        invoice: ExecutedBlockCommitmentV2,
        /// Transfer block commitment.
        transfer: ExecutedBlockCommitmentV2,
    },
}

impl fmt::Debug for DurableBlockFinalityCapability {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DurableBlockFinalityCapability")
            .field("verifier_profile", &self.verifier_profile)
            .field("coordinator_id", &self.coordinator_id)
            .field("ledger_chain_id", &self.ledger_chain_id)
            .field("block_height", &self.block_height)
            .field("app_hash", &self.app_hash)
            .field("verifier_digest", &self.verifier_digest)
            .field("attestation", &"[provider-free bounded capability]")
            .finish()
    }
}

impl RefreshBlockCommitmentsV2 {
    /// Canonicalizes equal commitments into the shared representation.
    pub fn new(invoice: ExecutedBlockCommitmentV2, transfer: ExecutedBlockCommitmentV2) -> Self {
        if invoice == transfer {
            Self::Shared { commitment: invoice }
        } else {
            Self::Distinct { invoice, transfer }
        }
    }

    /// Returns the Invoice block commitment.
    pub const fn invoice(&self) -> &ExecutedBlockCommitmentV2 {
        match self {
            Self::Shared { commitment } => commitment,
            Self::Distinct { invoice, .. } => invoice,
        }
    }

    /// Returns the Transfer block commitment.
    pub const fn transfer(&self) -> &ExecutedBlockCommitmentV2 {
        match self {
            Self::Shared { commitment } => commitment,
            Self::Distinct { transfer, .. } => transfer,
        }
    }

    pub(crate) fn validate_canonical(&self) -> Result<()> {
        self.invoice()
            .validate()
            .map_err(|_| NodeError::InvalidLedgerArtifact)?;
        self.transfer()
            .validate()
            .map_err(|_| NodeError::InvalidLedgerArtifact)?;
        if matches!(self, Self::Distinct { invoice, transfer } if invoice == transfer) {
            return Err(NodeError::InvalidLedgerArtifact);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutedEntryEvidenceV2 {
    pub entry: ExecutedEntryV2,
    pub inclusion_proof: EntryMerkleProofV2,
}

impl ExecutedEntryEvidenceV2 {
    pub const fn entry(&self) -> &ExecutedEntryV2 {
        &self.entry
    }
}

/// Bounded, verifier-authenticated summary of one complete finalized block.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DurableBlockFinalityCapability {
    verifier_profile: FinalityVerifierProfileId,
    coordinator_id: FinalityCoordinatorId,
    ledger_chain_id: LedgerChainIdV2,
    block_height: u64,
    app_hash: AppHashV2,
    verifier_digest: FinalityDigest,
    attestation: Vec<u8>,
}

impl DurableBlockFinalityCapability {
    pub fn new(
        verifier_profile: FinalityVerifierProfileId,
        coordinator_id: FinalityCoordinatorId,
        ledger_chain_id: LedgerChainIdV2,
        block_height: u64,
        app_hash: AppHashV2,
        verifier_digest: FinalityDigest,
        attestation: Vec<u8>,
    ) -> Result<Self> {
        let capability = Self {
            verifier_profile,
            coordinator_id,
            ledger_chain_id,
            block_height,
            app_hash,
            verifier_digest,
            attestation,
        };
        capability.validate_shape()?;
        Ok(capability)
    }
    pub const fn verifier_profile(&self) -> FinalityVerifierProfileId {
        self.verifier_profile
    }
    pub const fn coordinator_id(&self) -> FinalityCoordinatorId {
        self.coordinator_id
    }
    pub(crate) fn validate_shape(&self) -> Result<()> {
        if self.block_height == 0
            || self.attestation.is_empty()
            || self.attestation.len() > MAX_FINALITY_ATTESTATION_BYTES
            || self.app_hash.is_zero()
            || self.verifier_digest.as_bytes() == &[0; 32]
        {
            Err(NodeError::FinalityRejected)
        } else {
            Ok(())
        }
    }
    pub fn ledger_chain_id(&self) -> &LedgerChainIdV2 {
        &self.ledger_chain_id
    }
    pub const fn block_height(&self) -> u64 {
        self.block_height
    }
    pub const fn app_hash(&self) -> &AppHashV2 {
        &self.app_hash
    }
    pub const fn verifier_digest(&self) -> FinalityDigest {
        self.verifier_digest
    }
    pub fn attestation(&self) -> &[u8] {
        &self.attestation
    }
}

/// Deduplicated durable finality attestations for a compact refresh pair.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "layout", rename_all = "snake_case", deny_unknown_fields)]
pub enum DurableFinalityCapability {
    Shared {
        block: DurableBlockFinalityCapability,
    },
    Distinct {
        invoice: DurableBlockFinalityCapability,
        transfer: DurableBlockFinalityCapability,
    },
}

impl DurableFinalityCapability {
    pub fn new(
        blocks: &RefreshBlockCommitmentsV2,
        invoice: DurableBlockFinalityCapability,
        transfer: DurableBlockFinalityCapability,
    ) -> Result<Self> {
        invoice.validate_shape()?;
        transfer.validate_shape()?;
        let value = match blocks {
            RefreshBlockCommitmentsV2::Shared { .. } if invoice == transfer => Self::Shared { block: invoice },
            RefreshBlockCommitmentsV2::Distinct { .. } if invoice != transfer => Self::Distinct { invoice, transfer },
            _ => return Err(NodeError::FinalityRejected),
        };
        Ok(value)
    }

    pub const fn invoice(&self) -> &DurableBlockFinalityCapability {
        match self {
            Self::Shared { block } => block,
            Self::Distinct { invoice, .. } => invoice,
        }
    }

    pub const fn transfer(&self) -> &DurableBlockFinalityCapability {
        match self {
            Self::Shared { block } => block,
            Self::Distinct { transfer, .. } => transfer,
        }
    }

    pub(crate) fn validate_canonical(&self, blocks: &RefreshBlockCommitmentsV2) -> Result<()> {
        self.invoice().validate_shape()?;
        self.transfer().validate_shape()?;
        if matches!(
            (self, blocks),
            (Self::Shared { .. }, RefreshBlockCommitmentsV2::Shared { .. })
        ) || matches!((self, blocks), (Self::Distinct { invoice, transfer }, RefreshBlockCommitmentsV2::Distinct { .. }) if invoice != transfer)
        {
            Ok(())
        } else {
            Err(NodeError::FinalityRejected)
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifiedRefreshRecordV2 {
    pub blocks: RefreshBlockCommitmentsV2,
    pub invoice: ExecutedEntryEvidenceV2,
    pub transfer: ExecutedEntryEvidenceV2,
    #[serde(with = "semantic_digest_serde")]
    pub invoice_semantic_digest: [u8; 32],
    #[serde(with = "semantic_digest_serde")]
    pub transfer_semantic_digest: [u8; 32],
    pub finality: DurableFinalityCapability,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PendingInvoiceRecordV2 {
    pub commitment: ExecutedBlockCommitmentV2,
    pub invoice: ExecutedEntryEvidenceV2,
    #[serde(with = "semantic_digest_serde")]
    pub semantic_digest: [u8; 32],
    pub finality: DurableBlockFinalityCapability,
    pub expires_at_ms: u64,
}

/// Exact v2 artifacts parsed from authenticated Ledger events and cross-bound
/// to compact finalized execution evidence.
///
/// Fields are private so callers cannot mint this capability from transport
/// JSON. This capability does not claim proof validity or private-key/roster
/// compatibility; the trusted runtime must establish both before mutation.
#[derive(Clone, Debug)]
pub struct VerifiedV2Refresh {
    pub(crate) recipient_share: RecipientShareEnvelopeV2,
    pub(crate) threshold_distribution: ThresholdEnvelopeV2,
    pub(crate) transfer_proof: TransferEnvelopeV2,
    pub(crate) commitment: thunderbolt_committee::CommittedTransfer,
}

impl VerifiedV2Refresh {
    /// Returns the exact Recipient share proof from the committed Invoice.
    pub const fn recipient_share(&self) -> &RecipientShareEnvelopeV2 {
        &self.recipient_share
    }

    /// Returns the exact Committee threshold distribution from the Invoice.
    pub const fn threshold_distribution(&self) -> &ThresholdEnvelopeV2 {
        &self.threshold_distribution
    }

    /// Returns the exact Transfer proof from the consuming Transfer.
    pub const fn transfer_proof(&self) -> &TransferEnvelopeV2 {
        &self.transfer_proof
    }

    /// Returns the exact finality-bound event identity used for durable replay.
    pub const fn commitment(&self) -> thunderbolt_committee::CommittedTransfer {
        self.commitment
    }
}

/// Trusted private-runtime result. It contains only public acknowledgement
/// metadata and an explicit replay disposition, never share or nonce material.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuntimeRefreshOutcome {
    pub acknowledgement: AcknowledgementRecord,
    pub replay: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LedgerCursor {
    pub next_height: u64,
    pub expected_previous_app_hash: AppHashV2,
    pub processed_refresh_count: u64,
    pub last_refresh_entry_hash: EntryHashV2,
    pub last_finality: DurableBlockFinalityCapability,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProcessDisposition {
    Idle,
    Applied,
    Replay,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OutboxStatus {
    AwaitingSignature,
    Ready,
    Delivered,
    Failed,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AcknowledgementRecord {
    pub event_id: [u8; 32],
    pub descriptor_id: [u8; 32],
    pub epoch: u64,
    pub member_id: u32,
    pub durable_revision: u64,
    pub acknowledgement_digest: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutboxItem {
    pub id: [u8; 32],
    pub status: OutboxStatus,
    pub acknowledgement: AcknowledgementRecord,
    pub signed_proposal: Option<SignedProposalV2>,
    pub attempts: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NodeStatus {
    pub member_id: u32,
    pub committee_epoch: u64,
    pub descriptor_id: [u8; 32],
    pub inbox_pending: u32,
    pub outbox_pending: u32,
    pub cursor: Option<LedgerCursor>,
    pub signing_available: bool,
    pub finality_available: bool,
    pub v2_runtime_available: bool,
}

#[derive(Clone, Debug)]
pub enum ControlRequest {
    Status,
    ListOutbox { limit: u16 },
    RetryOutbox { id: [u8; 32] },
}

#[derive(Clone, Debug)]
pub enum ControlResponse {
    Status(Box<NodeStatus>),
    Outbox(Vec<OutboxItem>),
    Retried { id: [u8; 32] },
}

mod semantic_digest_serde {
    use serde::{Deserialize as _, Deserializer, Serializer};

    pub fn serialize<S>(value: &[u8; 32], serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut encoded = String::with_capacity(64);
        for byte in value {
            encoded.push(char::from(HEX[usize::from(byte >> 4)]));
            encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
        serializer.serialize_str(&encoded)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> std::result::Result<[u8; 32], D::Error>
    where
        D: Deserializer<'de>,
    {
        let encoded = String::deserialize(deserializer)?;
        if encoded.len() != 64
            || !encoded
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            return Err(serde::de::Error::custom(
                "semantic digest is not canonical lowercase hex",
            ));
        }
        let mut output = [0_u8; 32];
        for (index, pair) in encoded.as_bytes().chunks_exact(2).enumerate() {
            let high = nibble(pair[0]).ok_or_else(|| serde::de::Error::custom("semantic digest hex"))?;
            let low = nibble(pair[1]).ok_or_else(|| serde::de::Error::custom("semantic digest hex"))?;
            output[index] = (high << 4) | low;
        }
        Ok(output)
    }

    fn nibble(value: u8) -> Option<u8> {
        match value {
            b'0'..=b'9' => Some(value - b'0'),
            b'a'..=b'f' => Some(value - b'a' + 10),
            _ => None,
        }
    }
}
