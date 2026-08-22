use bitcoin::Network;
use serde::{Deserialize, Serialize};
use thunderbolt_ledger::{
    AppHashV2, EntryHashV2, EntryMerkleProofV2, ExecutedBlockV2, LedgerChainIdV2, SignedProposalV2,
};
use thunderbolt_wire::{ShareEnvelopeV1, ThresholdEnvelopeV1, TransferEnvelopeV1};

use crate::{NodeError, Result};

pub const MAX_QUEUE_ROWS: u32 = 100_000;
pub const MAX_BATCH_ITEMS: u16 = 256;
pub const MAX_BUNDLE_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_OUTBOX_BYTES: usize = 64 * 1024;
pub const MAX_FINALITY_ATTESTATION_BYTES: usize = 64 * 1024;

#[derive(Clone, Debug)]
pub struct NodeConfig {
    pub ledger_chain_id: LedgerChainIdV2,
    pub finality_verifier_profile: FinalityVerifierProfileId,
    pub max_inbox_rows: u32,
    pub max_outbox_rows: u32,
    pub fetch_batch_size: u16,
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

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(bound(serialize = "R: Serialize", deserialize = "R: Deserialize<'de>"))]
pub struct FinalizedEntryV2<R> {
    pub block: ExecutedBlockV2,
    pub inclusion_proof: EntryMerkleProofV2,
    pub entry_index: u32,
    pub receipt: R,
}

impl<R> FinalizedEntryV2<R> {
    pub fn entry(&self) -> Result<&thunderbolt_ledger::ExecutedEntryV2> {
        self.block
            .entries()
            .get(usize::try_from(self.entry_index).map_err(|_| NodeError::NumericRange)?)
            .ok_or(NodeError::InvalidLedgerArtifact)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(bound(serialize = "R: Serialize", deserialize = "R: Deserialize<'de>"))]
pub struct FinalizedRefreshBundleV2<R> {
    pub invoice: FinalizedEntryV2<R>,
    pub transfer: FinalizedEntryV2<R>,
    pub recipient_share: ShareEnvelopeV1,
    pub threshold_distribution: ThresholdEnvelopeV1,
    pub transfer_proof: TransferEnvelopeV1,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExecutedEntryEvidenceV2 {
    pub block: ExecutedBlockV2,
    pub inclusion_proof: EntryMerkleProofV2,
    pub entry_index: u32,
}

impl<R> From<&FinalizedEntryV2<R>> for ExecutedEntryEvidenceV2 {
    fn from(value: &FinalizedEntryV2<R>) -> Self {
        Self {
            block: value.block.clone(),
            inclusion_proof: value.inclusion_proof.clone(),
            entry_index: value.entry_index,
        }
    }
}

impl ExecutedEntryEvidenceV2 {
    pub fn entry(&self) -> Result<&thunderbolt_ledger::ExecutedEntryV2> {
        self.block
            .entries()
            .get(usize::try_from(self.entry_index).map_err(|_| NodeError::NumericRange)?)
            .ok_or(NodeError::InvalidLedgerArtifact)
    }
}

/// Bounded, verifier-authenticated summary of one finalized refresh pair.
///
/// `refresh_ordinal` and `previous_refresh_entry_hash` must come from Ledger
/// application state committed by `transfer_app_hash`, never RPC metadata.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DurableFinalityCapability {
    verifier_profile: FinalityVerifierProfileId,
    ledger_chain_id: LedgerChainIdV2,
    invoice_height: u64,
    invoice_index: u32,
    invoice_entry_hash: EntryHashV2,
    transfer_height: u64,
    transfer_index: u32,
    transfer_entry_hash: EntryHashV2,
    transfer_app_hash: AppHashV2,
    refresh_ordinal: u64,
    previous_refresh_entry_hash: EntryHashV2,
    verifier_digest: FinalityDigest,
    attestation: Vec<u8>,
}

impl DurableFinalityCapability {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        verifier_profile: FinalityVerifierProfileId,
        ledger_chain_id: LedgerChainIdV2,
        invoice_height: u64,
        invoice_index: u32,
        invoice_entry_hash: EntryHashV2,
        transfer_height: u64,
        transfer_index: u32,
        transfer_entry_hash: EntryHashV2,
        transfer_app_hash: AppHashV2,
        refresh_ordinal: u64,
        previous_refresh_entry_hash: EntryHashV2,
        verifier_digest: FinalityDigest,
        attestation: Vec<u8>,
    ) -> Result<Self> {
        let capability = Self {
            verifier_profile,
            ledger_chain_id,
            invoice_height,
            invoice_index,
            invoice_entry_hash,
            transfer_height,
            transfer_index,
            transfer_entry_hash,
            transfer_app_hash,
            refresh_ordinal,
            previous_refresh_entry_hash,
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
        if self.invoice_height == 0
            || self.transfer_height == 0
            || self.refresh_ordinal == 0
            || self.attestation.is_empty()
            || self.attestation.len() > MAX_FINALITY_ATTESTATION_BYTES
            || (self.invoice_height, self.invoice_index) >= (self.transfer_height, self.transfer_index)
        {
            Err(NodeError::FinalityRejected)
        } else {
            Ok(())
        }
    }
    pub fn ledger_chain_id(&self) -> &LedgerChainIdV2 {
        &self.ledger_chain_id
    }
    pub const fn invoice_height(&self) -> u64 {
        self.invoice_height
    }
    pub const fn invoice_index(&self) -> u32 {
        self.invoice_index
    }
    pub const fn invoice_entry_hash(&self) -> &EntryHashV2 {
        &self.invoice_entry_hash
    }
    pub const fn transfer_height(&self) -> u64 {
        self.transfer_height
    }
    pub const fn transfer_index(&self) -> u32 {
        self.transfer_index
    }
    pub const fn transfer_entry_hash(&self) -> &EntryHashV2 {
        &self.transfer_entry_hash
    }
    pub const fn transfer_app_hash(&self) -> &AppHashV2 {
        &self.transfer_app_hash
    }
    pub const fn refresh_ordinal(&self) -> u64 {
        self.refresh_ordinal
    }
    pub const fn previous_refresh_entry_hash(&self) -> &EntryHashV2 {
        &self.previous_refresh_entry_hash
    }
    pub const fn verifier_digest(&self) -> FinalityDigest {
        self.verifier_digest
    }
    pub fn attestation(&self) -> &[u8] {
        &self.attestation
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VerifiedRefreshRecordV2 {
    pub invoice: ExecutedEntryEvidenceV2,
    pub transfer: ExecutedEntryEvidenceV2,
    pub recipient_share: ShareEnvelopeV1,
    pub threshold_distribution: ThresholdEnvelopeV1,
    pub transfer_proof: TransferEnvelopeV1,
    pub finality: DurableFinalityCapability,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LedgerCursor {
    pub refresh_ordinal: u64,
    pub previous_refresh_entry_hash: EntryHashV2,
    pub block_height: u64,
    pub block_index: u32,
    pub app_hash: AppHashV2,
    pub entry_hash: EntryHashV2,
    pub finality_digest: FinalityDigest,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IngestDisposition {
    Accepted,
    Replay,
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
}

#[derive(Clone, Debug)]
pub enum ControlRequest {
    Status,
    ListOutbox { limit: u16 },
    RetryOutbox { id: [u8; 32] },
}

#[derive(Clone, Debug)]
pub enum ControlResponse {
    Status(NodeStatus),
    Outbox(Vec<OutboxItem>),
    Retried { id: [u8; 32] },
}
