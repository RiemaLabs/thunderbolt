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

#[derive(Clone, Debug)]
pub struct NodeConfig {
    pub ledger_chain_id: LedgerChainIdV2,
    pub max_inbox_rows: u32,
    pub max_outbox_rows: u32,
    pub fetch_batch_size: u16,
}

impl NodeConfig {
    pub fn new(
        ledger_chain_id: LedgerChainIdV2,
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

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LedgerCursor {
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
