use bitcoin::Network;
use serde::{Deserialize, Serialize};
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

#[derive(Clone, Debug)]
pub struct NodeConfig {
    pub(crate) ledger_chain_id: LedgerChainIdV2,
    pub(crate) finality_verifier_profile: FinalityVerifierProfileId,
    pub(crate) max_inbox_rows: u32,
    pub(crate) max_outbox_rows: u32,
    pub(crate) fetch_batch_size: u16,
}

impl NodeConfig {
    pub fn new(
        ledger_chain_id: LedgerChainIdV2,
        finality_verifier_profile: FinalityVerifierProfileId,
        max_inbox_rows: u32,
        max_outbox_rows: u32,
        fetch_batch_size: u16,
    ) -> Result<Self> {
        if max_inbox_rows == 0
            || max_outbox_rows == 0
            || max_inbox_rows > MAX_QUEUE_ROWS
            || max_outbox_rows > MAX_QUEUE_ROWS
            || fetch_batch_size == 0
            || fetch_batch_size > MAX_BATCH_ITEMS
        {
            return Err(NodeError::InvalidConfiguration("queue or batch bound is invalid"));
        }
        Ok(Self {
            ledger_chain_id,
            finality_verifier_profile,
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

/// One complete finalized executed block in a transient contiguous scan.
#[derive(Clone, Debug, Serialize)]
#[serde(bound(serialize = "R: Serialize"), deny_unknown_fields)]
pub struct FinalizedExecutedBlockV2<R> {
    /// Full execution value used transiently to prove that no block entry was skipped.
    pub block: ExecutedBlockV2,
    /// Opaque consensus receipt authenticated before the scan cursor advances.
    pub receipt: R,
}

/// Bounded whole-block page beginning at one exact durable global cursor.
#[derive(Clone, Debug, Serialize)]
#[serde(bound(serialize = "R: Serialize"), deny_unknown_fields)]
pub struct FinalizedExecutionSegmentV2<R> {
    pub ledger_chain_id: LedgerChainIdV2,
    pub start_height: u64,
    pub expected_previous_app_hash: AppHashV2,
    pub blocks: Vec<FinalizedExecutedBlockV2<R>>,
    pub occurrences: Vec<FinalizedEntryOccurrenceV2<R>>,
    pub next_height: u64,
    pub next_expected_previous_app_hash: AppHashV2,
}

/// Locator classification for one relevant finalized execution.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EntryOccurrenceKindV2 {
    First,
    Replay,
}

/// Transient exact first-location result and its finality receipt.
#[derive(Clone, Debug, Serialize)]
#[serde(bound(serialize = "R: Serialize"), deny_unknown_fields)]
pub struct FinalizedEntryOccurrenceV2<R> {
    pub kind: EntryOccurrenceKindV2,
    pub ledger_chain_id: LedgerChainIdV2,
    pub channel_context_id: thunderbolt_ledger::ChannelContextIdV2,
    pub entry_hash: EntryHashV2,
    #[serde(with = "semantic_digest_serde")]
    pub semantic_digest: [u8; 32],
    pub observed_height: u64,
    pub observed_index: u32,
    pub first_height: u64,
    pub first_index: u32,
    pub through_height: u64,
    pub expected_through_app_hash: AppHashV2,
    pub receipt: R,
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
    pub verifier_digest: FinalityDigest,
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
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DurableBlockFinalityCapability {
    verifier_profile: FinalityVerifierProfileId,
    ledger_chain_id: LedgerChainIdV2,
    block_height: u64,
    app_hash: AppHashV2,
    verifier_digest: FinalityDigest,
    attestation: Vec<u8>,
}

impl DurableBlockFinalityCapability {
    pub fn new(
        verifier_profile: FinalityVerifierProfileId,
        ledger_chain_id: LedgerChainIdV2,
        block_height: u64,
        app_hash: AppHashV2,
        verifier_digest: FinalityDigest,
        attestation: Vec<u8>,
    ) -> Result<Self> {
        let capability = Self {
            verifier_profile,
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
