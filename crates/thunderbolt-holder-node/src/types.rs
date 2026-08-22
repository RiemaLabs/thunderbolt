use core::fmt;

use serde::{Deserialize, Serialize};
use thunderbolt_ledger::{
    ActorRoleV2, ChannelContextIdV2, ClientRequestNonceV2, EntryHashV2, EventKindV2, RequestDigestV2,
};
use thunderbolt_protocol::v2::{ChannelBindingV2, ChannelEventV2};

/// Caller-generated local idempotency key.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct CommandId([u8; 32]);

impl CommandId {
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for CommandId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CommandId(")?;
        for byte in self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        formatter.write_str(")")
    }
}

/// Monotonic finalized head for one exact Ledger/channel scope.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FinalizedCursor {
    pub channel_context_id: ChannelContextIdV2,
    pub sequence: u64,
    pub entry_hash: EntryHashV2,
}

impl FinalizedCursor {
    pub fn new(channel_context_id: ChannelContextIdV2, sequence: u64, entry_hash: EntryHashV2) -> Self {
        Self {
            channel_context_id,
            sequence,
            entry_hash,
        }
    }
}

/// Explicit service lifecycle state.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LifecycleState {
    Created,
    Running,
    Draining,
    Stopped,
    Faulted,
}

/// Durable outbox state.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OutboxStatus {
    Queued,
    Submitted,
    Finalized,
    RetryExhausted,
}

impl OutboxStatus {
    pub(crate) const fn code(self) -> i64 {
        match self {
            Self::Queued => 0,
            Self::Submitted => 1,
            Self::Finalized => 2,
            Self::RetryExhausted => 3,
        }
    }

    pub(crate) fn from_code(code: i64) -> crate::Result<Self> {
        match code {
            0 => Ok(Self::Queued),
            1 => Ok(Self::Submitted),
            2 => Ok(Self::Finalized),
            3 => Ok(Self::RetryExhausted),
            _ => Err(crate::HolderNodeError::StorageCorrupt),
        }
    }
}

/// Local command used to construct, sign, and enqueue one v2 proposal.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QueueProposalRequest {
    pub command_id: CommandId,
    pub channel: ChannelBindingV2,
    pub sequence: u64,
    pub previous_entry_hash: EntryHashV2,
    pub request_nonce: ClientRequestNonceV2,
    pub actor_role: ActorRoleV2,
    pub event: ChannelEventV2,
    pub now_ms: u64,
}

/// Result of durable queue insertion.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QueueDisposition {
    Queued,
    AlreadyQueued,
}

/// Public queue result.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QueuedProposal {
    pub disposition: QueueDisposition,
    pub request_digest: RequestDigestV2,
    pub entry_hash: EntryHashV2,
}

/// One service-loop report.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunReport {
    pub submitted: usize,
    pub submit_failures: usize,
    pub finalized: usize,
}

/// Local, secret-free runtime status.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceStatus {
    pub lifecycle: LifecycleState,
    pub recovered_unclean_shutdown: bool,
    pub run_generation: u64,
    pub outbox_queued: usize,
    pub outbox_submitted: usize,
    pub outbox_finalized: usize,
    pub outbox_retry_exhausted: usize,
    pub finalized_channels: usize,
}

/// Internal durable outbox row.
pub(crate) struct OutboxRecord {
    pub request_digest: RequestDigestV2,
    pub proposal_bytes: Vec<u8>,
}

pub(crate) fn channel_context_id(channel: &ChannelBindingV2) -> crate::Result<ChannelContextIdV2> {
    let context = channel
        .context_id()
        .map_err(|_| crate::HolderNodeError::InvalidProposal)?;
    ChannelContextIdV2::from_bytes(context).map_err(crate::HolderNodeError::from)
}

pub(crate) fn event_kind(event: &ChannelEventV2) -> EventKindV2 {
    event.kind()
}
