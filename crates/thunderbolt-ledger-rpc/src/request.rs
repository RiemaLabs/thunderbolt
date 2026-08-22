use serde::{Deserialize, Serialize};
use thunderbolt_ledger::{
    AppHashV2, ChannelContextIdV2, LedgerChainIdV2, ParticipantIdV2, RequestDigestV2, SignedProposalV2,
    MAX_BLOCK_ENTRIES,
};

use crate::{Result, RollbackFloorCasRequestV2, RpcCodecError};

/// Maximum number of executed metadata records returned in one history page.
pub const MAX_HISTORY_PAGE_ENTRIES: u16 = 64;
/// Maximum whole executed blocks in one globally contiguous range page.
pub const MAX_EXECUTION_RANGE_BLOCKS: u16 = 64;
/// Maximum canonical JSON bytes occupied by the block array in one range page.
pub const MAX_EXECUTION_RANGE_ENCODED_BYTES: u32 = 23 * 1024 * 1024;

/// Request to admit one exact actor-signed proposal into the Ledger mempool.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SubmitProposalRequestV2 {
    ledger_chain_id: LedgerChainIdV2,
    signed_proposal: SignedProposalV2,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SubmitProposalRequestInput {
    ledger_chain_id: LedgerChainIdV2,
    signed_proposal: SignedProposalV2,
}

impl SubmitProposalRequestV2 {
    /// Constructs a request and verifies signature, chain, and embedded deployment binding.
    pub fn new(ledger_chain_id: LedgerChainIdV2, signed_proposal: SignedProposalV2) -> Result<Self> {
        let request = Self {
            ledger_chain_id,
            signed_proposal,
        };
        request.validate()?;
        Ok(request)
    }

    /// Returns the exact consensus chain.
    pub const fn ledger_chain_id(&self) -> &LedgerChainIdV2 {
        &self.ledger_chain_id
    }

    /// Returns the exact signed proposal.
    pub const fn signed_proposal(&self) -> &SignedProposalV2 {
        &self.signed_proposal
    }

    pub(crate) fn validate(&self) -> Result<()> {
        self.signed_proposal.verify()?;
        if self.signed_proposal.body().ledger_chain_id() != &self.ledger_chain_id {
            return Err(RpcCodecError::BindingMismatch(
                "submit chain differs from the actor-signed proposal chain",
            ));
        }
        Ok(())
    }
}

/// Request for the materialized state of one stable channel context.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ChannelStatusRequestV2 {
    ledger_chain_id: LedgerChainIdV2,
    channel_context_id: ChannelContextIdV2,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ChannelStatusRequestInput {
    ledger_chain_id: LedgerChainIdV2,
    channel_context_id: ChannelContextIdV2,
}

impl ChannelStatusRequestV2 {
    /// Constructs an exact chain- and context-bound query.
    #[must_use]
    pub const fn new(ledger_chain_id: LedgerChainIdV2, channel_context_id: ChannelContextIdV2) -> Self {
        Self {
            ledger_chain_id,
            channel_context_id,
        }
    }

    /// Returns the exact consensus chain.
    pub const fn ledger_chain_id(&self) -> &LedgerChainIdV2 {
        &self.ledger_chain_id
    }

    /// Returns the stable context, which commits the complete deployment binding.
    pub const fn channel_context_id(&self) -> &ChannelContextIdV2 {
        &self.channel_context_id
    }
}

/// Complete authenticated key for looking up an idempotent actor request.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RequestStatusRequestV2 {
    ledger_chain_id: LedgerChainIdV2,
    channel_context_id: ChannelContextIdV2,
    participant_id: ParticipantIdV2,
    request_digest: RequestDigestV2,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RequestStatusRequestInput {
    ledger_chain_id: LedgerChainIdV2,
    channel_context_id: ChannelContextIdV2,
    participant_id: ParticipantIdV2,
    request_digest: RequestDigestV2,
}

impl RequestStatusRequestV2 {
    /// Constructs an exact chain-, channel-, participant-, and request-bound query.
    #[must_use]
    pub const fn new(
        ledger_chain_id: LedgerChainIdV2,
        channel_context_id: ChannelContextIdV2,
        participant_id: ParticipantIdV2,
        request_digest: RequestDigestV2,
    ) -> Self {
        Self {
            ledger_chain_id,
            channel_context_id,
            participant_id,
            request_digest,
        }
    }

    /// Returns the exact consensus chain.
    pub const fn ledger_chain_id(&self) -> &LedgerChainIdV2 {
        &self.ledger_chain_id
    }

    /// Returns the stable channel context.
    pub const fn channel_context_id(&self) -> &ChannelContextIdV2 {
        &self.channel_context_id
    }

    /// Returns the participant derived from the original authenticated actor key.
    pub const fn participant_id(&self) -> &ParticipantIdV2 {
        &self.participant_id
    }

    /// Returns the original channel- and actor-scoped request digest.
    pub const fn request_digest(&self) -> &RequestDigestV2 {
        &self.request_digest
    }
}

/// Exact continuation cursor between whole globally ordered executed blocks.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionRangeCursorV2 {
    ledger_chain_id: LedgerChainIdV2,
    next_height: u64,
    expected_previous_app_hash: AppHashV2,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ExecutionRangeCursorInput {
    ledger_chain_id: LedgerChainIdV2,
    next_height: u64,
    expected_previous_app_hash: AppHashV2,
}

impl ExecutionRangeCursorInput {
    fn into_cursor(self) -> Result<ExecutionRangeCursorV2> {
        ExecutionRangeCursorV2::new(self.ledger_chain_id, self.next_height, self.expected_previous_app_hash)
    }
}

impl ExecutionRangeCursorV2 {
    /// Constructs a chain-bound cursor. Height one alone uses the zero predecessor hash.
    pub fn new(
        ledger_chain_id: LedgerChainIdV2,
        next_height: u64,
        expected_previous_app_hash: AppHashV2,
    ) -> Result<Self> {
        if next_height == 0
            || next_height > i64::MAX as u64
            || (next_height == 1) != expected_previous_app_hash.is_zero()
        {
            return Err(RpcCodecError::InvalidField("execution range cursor is invalid"));
        }
        Ok(Self {
            ledger_chain_id,
            next_height,
            expected_previous_app_hash,
        })
    }

    /// Returns the exact Ledger chain.
    pub const fn ledger_chain_id(&self) -> &LedgerChainIdV2 {
        &self.ledger_chain_id
    }

    /// Returns the next whole execution height.
    pub const fn next_height(&self) -> u64 {
        self.next_height
    }

    /// Returns the exact application hash immediately before `next_height`.
    pub const fn expected_previous_app_hash(&self) -> &AppHashV2 {
        &self.expected_previous_app_hash
    }
}

/// Bounded request for whole globally contiguous executed blocks.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionRangeRequestV2 {
    cursor: ExecutionRangeCursorV2,
    block_count: u16,
    max_encoded_bytes: u32,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ExecutionRangeRequestInput {
    cursor: ExecutionRangeCursorInput,
    block_count: u16,
    max_encoded_bytes: u32,
}

impl ExecutionRangeRequestV2 {
    /// Constructs a positive count- and byte-bounded range request.
    pub fn new(cursor: ExecutionRangeCursorV2, block_count: u16, max_encoded_bytes: u32) -> Result<Self> {
        let through_height = cursor
            .next_height()
            .checked_add(u64::from(block_count).saturating_sub(1));
        if block_count == 0
            || block_count > MAX_EXECUTION_RANGE_BLOCKS
            || !(2..=MAX_EXECUTION_RANGE_ENCODED_BYTES).contains(&max_encoded_bytes)
            || through_height.is_none_or(|height| height >= i64::MAX as u64)
        {
            return Err(RpcCodecError::InvalidField("execution range bound is invalid"));
        }
        Ok(Self {
            cursor,
            block_count,
            max_encoded_bytes,
        })
    }

    /// Returns the exact start cursor.
    pub const fn cursor(&self) -> &ExecutionRangeCursorV2 {
        &self.cursor
    }

    /// Returns the exact whole-block count.
    pub const fn block_count(&self) -> u16 {
        self.block_count
    }

    /// Returns the maximum canonical block-array byte count.
    pub const fn max_encoded_bytes(&self) -> u32 {
        self.max_encoded_bytes
    }
}

/// Exact channel-and-entry key for immutable first-location lookup.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EntryLocationRequestV2 {
    ledger_chain_id: LedgerChainIdV2,
    channel_context_id: ChannelContextIdV2,
    entry_hash: thunderbolt_ledger::EntryHashV2,
    through_height: u64,
    expected_through_app_hash: AppHashV2,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EntryLocationRequestInput {
    ledger_chain_id: LedgerChainIdV2,
    channel_context_id: ChannelContextIdV2,
    entry_hash: thunderbolt_ledger::EntryHashV2,
    through_height: u64,
    expected_through_app_hash: AppHashV2,
}

impl EntryLocationRequestV2 {
    /// Constructs a complete immutable entry locator key.
    pub fn new(
        ledger_chain_id: LedgerChainIdV2,
        channel_context_id: ChannelContextIdV2,
        entry_hash: thunderbolt_ledger::EntryHashV2,
        through_height: u64,
        expected_through_app_hash: AppHashV2,
    ) -> Result<Self> {
        if through_height == 0 || through_height > i64::MAX as u64 || expected_through_app_hash.is_zero() {
            return Err(RpcCodecError::InvalidField("entry location checkpoint is invalid"));
        }
        Ok(Self {
            ledger_chain_id,
            channel_context_id,
            entry_hash,
            through_height,
            expected_through_app_hash,
        })
    }

    /// Returns the exact Ledger chain.
    pub const fn ledger_chain_id(&self) -> &LedgerChainIdV2 {
        &self.ledger_chain_id
    }

    /// Returns the stable channel context.
    pub const fn channel_context_id(&self) -> &ChannelContextIdV2 {
        &self.channel_context_id
    }

    /// Returns the exact deterministic entry hash.
    pub const fn entry_hash(&self) -> &thunderbolt_ledger::EntryHashV2 {
        &self.entry_hash
    }

    /// Returns the inclusive durable height at which the lookup is meaningful.
    pub const fn through_height(&self) -> u64 {
        self.through_height
    }

    /// Returns the exact durable app hash at `through_height`.
    pub const fn expected_through_app_hash(&self) -> &AppHashV2 {
        &self.expected_through_app_hash
    }
}

/// Opaque continuation position in the deterministic global execution order.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HistoryCursorV2 {
    ledger_chain_id: LedgerChainIdV2,
    next_height: u64,
    next_block_index: u32,
    previous_app_hash: AppHashV2,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HistoryCursorInput {
    ledger_chain_id: LedgerChainIdV2,
    next_height: u64,
    next_block_index: u32,
    previous_app_hash: AppHashV2,
}

impl HistoryCursorInput {
    fn into_cursor(self) -> Result<HistoryCursorV2> {
        HistoryCursorV2::new(
            self.ledger_chain_id,
            self.next_height,
            self.next_block_index,
            self.previous_app_hash,
        )
    }
}

impl HistoryCursorV2 {
    /// Constructs a bounded cursor. Height one/index zero must use the zero app hash.
    pub fn new(
        ledger_chain_id: LedgerChainIdV2,
        next_height: u64,
        next_block_index: u32,
        previous_app_hash: AppHashV2,
    ) -> Result<Self> {
        if next_height == 0 || usize::try_from(next_block_index).map_or(true, |index| index >= MAX_BLOCK_ENTRIES) {
            return Err(RpcCodecError::InvalidField(
                "history cursor position is outside block bounds",
            ));
        }
        if (next_height == 1) != previous_app_hash.is_zero() {
            return Err(RpcCodecError::InvalidField(
                "history cursor previous app hash does not match genesis position",
            ));
        }
        Ok(Self {
            ledger_chain_id,
            next_height,
            next_block_index,
            previous_app_hash,
        })
    }

    /// Returns the consensus chain.
    pub const fn ledger_chain_id(&self) -> &LedgerChainIdV2 {
        &self.ledger_chain_id
    }

    /// Returns the next block height to inspect.
    pub const fn next_height(&self) -> u64 {
        self.next_height
    }

    /// Returns the next zero-based position within that block.
    pub const fn next_block_index(&self) -> u32 {
        self.next_block_index
    }

    /// Returns the exact application hash preceding `next_height`.
    pub const fn previous_app_hash(&self) -> &AppHashV2 {
        &self.previous_app_hash
    }
}

/// Validated page-size bound for history queries.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct HistoryPageLimitV2(u16);

impl HistoryPageLimitV2 {
    /// Constructs a positive page size under the protocol maximum.
    pub fn new(value: u16) -> Result<Self> {
        if value == 0 || value > MAX_HISTORY_PAGE_ENTRIES {
            return Err(RpcCodecError::InvalidField("history page limit is outside bounds"));
        }
        Ok(Self(value))
    }

    /// Returns the numeric page size.
    pub const fn get(self) -> u16 {
        self.0
    }
}

/// Request for a bounded page of executed entry metadata.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HistoryRequestV2 {
    channel_context_id: ChannelContextIdV2,
    cursor: HistoryCursorV2,
    limit: HistoryPageLimitV2,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HistoryRequestInput {
    channel_context_id: ChannelContextIdV2,
    cursor: HistoryCursorInput,
    limit: u16,
}

impl HistoryRequestV2 {
    /// Constructs a context-bound history query from an exact execution cursor.
    #[must_use]
    pub const fn new(
        channel_context_id: ChannelContextIdV2,
        cursor: HistoryCursorV2,
        limit: HistoryPageLimitV2,
    ) -> Self {
        Self {
            channel_context_id,
            cursor,
            limit,
        }
    }

    /// Returns the stable channel context.
    pub const fn channel_context_id(&self) -> &ChannelContextIdV2 {
        &self.channel_context_id
    }

    /// Returns the exact execution cursor.
    pub const fn cursor(&self) -> &HistoryCursorV2 {
        &self.cursor
    }

    /// Returns the bounded page size.
    pub const fn limit(&self) -> HistoryPageLimitV2 {
        self.limit
    }
}

pub(crate) fn decode_submit_request_value(value: serde_json::Value) -> Result<SubmitProposalRequestV2> {
    let input: SubmitProposalRequestInput = serde_json::from_value(value).map_err(RpcCodecError::InvalidEnvelope)?;
    SubmitProposalRequestV2::new(input.ledger_chain_id, input.signed_proposal)
}

pub(crate) fn decode_channel_status_request_value(value: serde_json::Value) -> Result<ChannelStatusRequestV2> {
    let input: ChannelStatusRequestInput = serde_json::from_value(value).map_err(RpcCodecError::InvalidEnvelope)?;
    Ok(ChannelStatusRequestV2::new(
        input.ledger_chain_id,
        input.channel_context_id,
    ))
}

pub(crate) fn decode_request_status_request_value(value: serde_json::Value) -> Result<RequestStatusRequestV2> {
    let input: RequestStatusRequestInput = serde_json::from_value(value).map_err(RpcCodecError::InvalidEnvelope)?;
    Ok(RequestStatusRequestV2::new(
        input.ledger_chain_id,
        input.channel_context_id,
        input.participant_id,
        input.request_digest,
    ))
}

pub(crate) fn decode_history_request_value(value: serde_json::Value) -> Result<HistoryRequestV2> {
    let input: HistoryRequestInput = serde_json::from_value(value).map_err(RpcCodecError::InvalidEnvelope)?;
    Ok(HistoryRequestV2::new(
        input.channel_context_id,
        input.cursor.into_cursor()?,
        HistoryPageLimitV2::new(input.limit)?,
    ))
}

pub(crate) fn decode_history_cursor_value(value: serde_json::Value) -> Result<HistoryCursorV2> {
    let input: HistoryCursorInput = serde_json::from_value(value).map_err(RpcCodecError::InvalidEnvelope)?;
    input.into_cursor()
}

pub(crate) fn decode_execution_range_request_value(value: serde_json::Value) -> Result<ExecutionRangeRequestV2> {
    let input: ExecutionRangeRequestInput = serde_json::from_value(value).map_err(RpcCodecError::InvalidEnvelope)?;
    ExecutionRangeRequestV2::new(input.cursor.into_cursor()?, input.block_count, input.max_encoded_bytes)
}

pub(crate) fn decode_execution_range_cursor_value(value: serde_json::Value) -> Result<ExecutionRangeCursorV2> {
    let input: ExecutionRangeCursorInput = serde_json::from_value(value).map_err(RpcCodecError::InvalidEnvelope)?;
    input.into_cursor()
}

pub(crate) fn decode_entry_location_request_value(value: serde_json::Value) -> Result<EntryLocationRequestV2> {
    let input: EntryLocationRequestInput = serde_json::from_value(value).map_err(RpcCodecError::InvalidEnvelope)?;
    EntryLocationRequestV2::new(
        input.ledger_chain_id,
        input.channel_context_id,
        input.entry_hash,
        input.through_height,
        input.expected_through_app_hash,
    )
}

/// One method in the version-two transport-neutral Ledger control plane.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "method", content = "params", rename_all = "snake_case")]
pub enum RpcRequestV2 {
    /// Admit one actor-signed proposal.
    SubmitProposal(SubmitProposalRequestV2),
    /// Query one materialized channel head.
    ChannelStatus(ChannelStatusRequestV2),
    /// Query one authenticated idempotency key.
    RequestStatus(RequestStatusRequestV2),
    /// Page through deterministic executed metadata.
    History(HistoryRequestV2),
    /// Read whole globally contiguous executed blocks.
    ExecutionRange(ExecutionRangeRequestV2),
    /// Locate the immutable first occurrence of one exact channel entry.
    EntryLocation(EntryLocationRequestV2),
    /// Submit one exact rollback-floor checkpoint CAS.
    RollbackFloorCas(RollbackFloorCasRequestV2),
}

impl RpcRequestV2 {
    pub(crate) fn validate(&self) -> Result<()> {
        match self {
            Self::SubmitProposal(request) => request.validate(),
            Self::ChannelStatus(_)
            | Self::RequestStatus(_)
            | Self::History(_)
            | Self::ExecutionRange(_)
            | Self::EntryLocation(_) => Ok(()),
            Self::RollbackFloorCas(request) => request.validate(),
        }
    }
}
