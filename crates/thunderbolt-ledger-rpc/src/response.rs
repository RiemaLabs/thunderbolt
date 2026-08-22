use std::error::Error;

use serde::de::{Error as _, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use thunderbolt_ledger::{
    ActorRoleV2, EntryHashV2, EntryMerkleProofV2, EventDigestV2, EventKindV2, ExecutedBlockV2, ExecutedEntryMetadataV2,
    ExecutedEntryV2, LedgerChainIdV2, ParticipantIdV2, ProposalDigestV2, RequestDigestV2, MAX_BLOCK_ENTRIES,
};
use thunderbolt_protocol::v2::StateHashV2;
use thunderbolt_wire::ChannelBindingV2;

use crate::{
    ChannelStatusRequestV2, HistoryCursorV2, HistoryRequestV2, OpaqueConsensusReceiptV2, RequestStatusRequestV2,
    Result, RpcCodecError, RpcRequestDigestV2, RpcRequestV2, SnapshotBytesV2, SubmitProposalRequestV2,
    TransportAcceptanceIdV2, MAX_HISTORY_PAGE_ENTRIES,
};

/// Fixed rejection reasons returned by deterministic admission policy.
///
/// Transport failures and timeouts are not rejection values and must remain
/// errors in the concrete transport adapter.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdmissionRejectionV2 {
    /// Proposal does not extend the committed per-channel predecessor.
    InvalidPredecessor,
    /// Request digest was already used for a different proposal.
    ConflictingRequest,
    /// Deterministic block or mempool resource limits were reached.
    CapacityExceeded,
    /// Authenticated actor role is not authorized for this transition.
    UnauthorizedTransition,
}

/// Transport admission result. It never means executed or finalized.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum AdmissionStatusV2 {
    /// The transport admitted the proposal for possible consensus ordering.
    Accepted {
        /// Opaque admission identifier for support and retry correlation.
        acceptance_id: TransportAcceptanceIdV2,
    },
    /// The exact logical request was already admitted or executed.
    AlreadyKnown,
    /// Deterministic admission rejected the proposal.
    Rejected {
        /// Stable machine-readable reason without free-form text.
        reason: AdmissionRejectionV2,
    },
}

/// Response to one signed-proposal submission.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SubmitProposalResponseV2 {
    proposal_digest: ProposalDigestV2,
    entry_hash: EntryHashV2,
    request_digest: RequestDigestV2,
    admission_status: AdmissionStatusV2,
}

impl SubmitProposalResponseV2 {
    /// Derives all identifiers from the exact signed request.
    pub fn new(request: &SubmitProposalRequestV2, admission_status: AdmissionStatusV2) -> Result<Self> {
        request.signed_proposal().verify()?;
        Ok(Self {
            proposal_digest: request.signed_proposal().body().proposal_digest()?,
            entry_hash: request.signed_proposal().body().entry_hash()?,
            request_digest: request.signed_proposal().body().request_id().digest().clone(),
            admission_status,
        })
    }

    /// Returns the actor-authenticated proposal digest.
    pub const fn proposal_digest(&self) -> &ProposalDigestV2 {
        &self.proposal_digest
    }

    /// Returns the deterministic entry hash.
    pub const fn entry_hash(&self) -> &EntryHashV2 {
        &self.entry_hash
    }

    /// Returns the original idempotency digest.
    pub const fn request_digest(&self) -> &RequestDigestV2 {
        &self.request_digest
    }

    /// Returns transport admission, not execution or finality.
    pub const fn admission_status(&self) -> &AdmissionStatusV2 {
        &self.admission_status
    }

    /// Checks this response against the exact submitted proposal.
    pub fn validate_for(&self, request: &SubmitProposalRequestV2) -> Result<()> {
        let expected = Self::new(request, self.admission_status.clone())?;
        if self != &expected {
            return Err(RpcCodecError::BindingMismatch(
                "submission response identifiers differ from the signed proposal",
            ));
        }
        Ok(())
    }
}

/// Availability of an external consensus receipt for a state or entry.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", content = "receipt", rename_all = "snake_case")]
pub enum FinalityStatusV2 {
    /// Only local deterministic execution is available.
    Unfinalized,
    /// An opaque receipt is available and still requires external verification.
    ReceiptAvailable(OpaqueConsensusReceiptV2),
}

/// Deterministic location and head hash of one materialized channel state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChannelExecutionPositionV2 {
    executed_height: u64,
    block_index: u32,
    entry_hash: EntryHashV2,
}

impl ChannelExecutionPositionV2 {
    /// Constructs a positive height, bounded block index, and exact head hash.
    pub fn new(executed_height: u64, block_index: u32, entry_hash: EntryHashV2) -> Result<Self> {
        if executed_height == 0 || usize::try_from(block_index).map_or(true, |index| index >= MAX_BLOCK_ENTRIES) {
            return Err(RpcCodecError::InvalidField(
                "channel status execution position is invalid",
            ));
        }
        Ok(Self {
            executed_height,
            block_index,
            entry_hash,
        })
    }

    /// Returns the execution height.
    pub const fn executed_height(&self) -> u64 {
        self.executed_height
    }

    /// Returns the zero-based block position.
    pub const fn block_index(&self) -> u32 {
        self.block_index
    }

    /// Returns the exact materialized channel head hash.
    pub const fn entry_hash(&self) -> &EntryHashV2 {
        &self.entry_hash
    }
}

/// Materialized channel-status response at one deterministic execution position.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ChannelStatusResponseV2 {
    channel_context_id: thunderbolt_ledger::ChannelContextIdV2,
    channel_binding: ChannelBindingV2,
    executed_height: u64,
    block_index: u32,
    entry_hash: EntryHashV2,
    state_hash: StateHashV2,
    snapshot_bytes: SnapshotBytesV2,
    finality_status: FinalityStatusV2,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ChannelStatusResponseInput {
    channel_context_id: thunderbolt_ledger::ChannelContextIdV2,
    channel_binding: ChannelBindingV2,
    executed_height: u64,
    block_index: u32,
    entry_hash: EntryHashV2,
    state_hash: StateHashV2,
    snapshot_bytes: SnapshotBytesV2,
    finality_status: FinalityStatusV2,
}

impl<'de> Deserialize<'de> for ChannelStatusResponseV2 {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let input = ChannelStatusResponseInput::deserialize(deserializer)?;
        Self::from_input(input).map_err(serde::de::Error::custom)
    }
}

impl ChannelStatusResponseV2 {
    /// Constructs a status response bound to the exact channel-status query.
    pub fn new(
        request: &ChannelStatusRequestV2,
        channel_binding: ChannelBindingV2,
        execution: ChannelExecutionPositionV2,
        state_hash: StateHashV2,
        snapshot_bytes: SnapshotBytesV2,
        finality_status: FinalityStatusV2,
    ) -> Result<Self> {
        let response = Self::from_input(ChannelStatusResponseInput {
            channel_context_id: request.channel_context_id().clone(),
            channel_binding,
            executed_height: execution.executed_height,
            block_index: execution.block_index,
            entry_hash: execution.entry_hash,
            state_hash,
            snapshot_bytes,
            finality_status,
        })?;
        response.validate_for(request)?;
        Ok(response)
    }

    fn from_input(input: ChannelStatusResponseInput) -> Result<Self> {
        ChannelExecutionPositionV2::new(input.executed_height, input.block_index, input.entry_hash.clone())?;
        if input.snapshot_bytes.state_hash() != input.state_hash {
            return Err(RpcCodecError::BindingMismatch(
                "channel status hash differs from canonical snapshot bytes",
            ));
        }
        let snapshot = input.snapshot_bytes.decode(&input.channel_binding)?;
        if input.channel_binding.context_id()? != *input.channel_context_id.as_bytes()
            || snapshot.head_entry_hash != input.entry_hash
        {
            return Err(RpcCodecError::BindingMismatch(
                "channel binding context or snapshot head differs from the response",
            ));
        }
        Ok(Self {
            channel_context_id: input.channel_context_id,
            channel_binding: input.channel_binding,
            executed_height: input.executed_height,
            block_index: input.block_index,
            entry_hash: input.entry_hash,
            state_hash: input.state_hash,
            snapshot_bytes: input.snapshot_bytes,
            finality_status: input.finality_status,
        })
    }

    /// Returns the stable channel context correlated to the query.
    pub const fn channel_context_id(&self) -> &thunderbolt_ledger::ChannelContextIdV2 {
        &self.channel_context_id
    }

    /// Returns the complete deployment and funding binding committed by the snapshot.
    pub const fn channel_binding(&self) -> &ChannelBindingV2 {
        &self.channel_binding
    }

    /// Returns the execution height.
    pub const fn executed_height(&self) -> u64 {
        self.executed_height
    }

    /// Returns the zero-based block position.
    pub const fn block_index(&self) -> u32 {
        self.block_index
    }

    /// Returns the exact materialized channel head hash.
    pub const fn entry_hash(&self) -> &EntryHashV2 {
        &self.entry_hash
    }

    /// Returns the hash of the exact snapshot bytes.
    pub const fn state_hash(&self) -> StateHashV2 {
        self.state_hash
    }

    /// Returns the bounded versioned snapshot bytes.
    pub const fn snapshot_bytes(&self) -> &SnapshotBytesV2 {
        &self.snapshot_bytes
    }

    /// Returns whether only execution or an unverified receipt is available.
    pub const fn finality_status(&self) -> &FinalityStatusV2 {
        &self.finality_status
    }

    /// Checks the snapshot's embedded Ledger chain against the exact query.
    pub fn validate_for(&self, request: &ChannelStatusRequestV2) -> Result<()> {
        if &self.channel_context_id != request.channel_context_id()
            || self.channel_binding.context_id()? != *request.channel_context_id().as_bytes()
        {
            return Err(RpcCodecError::BindingMismatch(
                "channel status context or snapshot chain differs from the query",
            ));
        }
        let snapshot = self.snapshot_bytes.decode(&self.channel_binding)?;
        if snapshot.ledger_chain_id != *request.ledger_chain_id() || snapshot.head_entry_hash != self.entry_hash {
            return Err(RpcCodecError::BindingMismatch(
                "decoded snapshot chain or head differs from the query response",
            ));
        }
        Ok(())
    }
}

/// Exact finality-carrying entry material returned by a finalized lookup.
///
/// Deserialization recomputes the deterministic block and verifies exact entry
/// equality and its ordered Merkle proof. Those checks still do not establish
/// consensus finality.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FinalizedEntryBundleV2 {
    block: ExecutedBlockV2,
    entry: ExecutedEntryV2,
    proof: EntryMerkleProofV2,
    consensus_receipt: OpaqueConsensusReceiptV2,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FinalizedEntryBundleInput {
    block: ExecutedBlockV2,
    entry: ExecutedEntryV2,
    proof: EntryMerkleProofV2,
    consensus_receipt: OpaqueConsensusReceiptV2,
}

impl<'de> Deserialize<'de> for FinalizedEntryBundleV2 {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let input = FinalizedEntryBundleInput::deserialize(deserializer)?;
        Self::new(input.block, input.entry, input.proof, input.consensus_receipt).map_err(serde::de::Error::custom)
    }
}

impl FinalizedEntryBundleV2 {
    /// Constructs and deterministically validates a finality-carrying bundle.
    pub fn new(
        block: ExecutedBlockV2,
        entry: ExecutedEntryV2,
        proof: EntryMerkleProofV2,
        consensus_receipt: OpaqueConsensusReceiptV2,
    ) -> Result<Self> {
        let index = usize::try_from(entry.metadata().block_index())
            .map_err(|_| RpcCodecError::InvalidField("entry index does not fit usize"))?;
        if block.entries().get(index) != Some(&entry) {
            return Err(RpcCodecError::BindingMismatch(
                "finalized entry is not the exact entry at its block index",
            ));
        }
        proof.verify(entry.metadata(), &block)?;
        Ok(Self {
            block,
            entry,
            proof,
            consensus_receipt,
        })
    }

    /// Returns the deterministic execution output, not a finality capability.
    pub const fn block(&self) -> &ExecutedBlockV2 {
        &self.block
    }

    /// Returns the exact entry duplicated from the checked block position.
    pub const fn entry(&self) -> &ExecutedEntryV2 {
        &self.entry
    }

    /// Returns the deterministic ordered-Merkle proof.
    pub const fn proof(&self) -> &EntryMerkleProofV2 {
        &self.proof
    }

    /// Returns opaque consensus bytes, which are untrusted until verified.
    pub const fn consensus_receipt(&self) -> &OpaqueConsensusReceiptV2 {
        &self.consensus_receipt
    }

    /// Invokes the configured external verifier and returns a capability only on success.
    pub fn verify_finality<'a, V>(
        &'a self,
        verifier: &V,
    ) -> std::result::Result<VerifiedFinalizedEntryV2<'a>, FinalityCapabilityError<V::Error>>
    where
        V: ExternalFinalityVerifierV2,
    {
        if verifier.profile_id() != self.consensus_receipt.verifier_profile_id() {
            return Err(FinalityCapabilityError::ProfileMismatch);
        }
        verifier
            .verify(&self.block, &self.entry, &self.proof, &self.consensus_receipt)
            .map_err(FinalityCapabilityError::Verifier)?;
        Ok(VerifiedFinalizedEntryV2 { bundle: self })
    }
}

/// Failure while converting an opaque receipt into a finality capability.
#[derive(Debug, thiserror::Error)]
pub enum FinalityCapabilityError<E>
where
    E: Error + 'static,
{
    /// Receipt and verifier were configured for different trust profiles.
    #[error("consensus receipt verifier profile mismatch")]
    ProfileMismatch,
    /// The correctly profiled external verifier rejected the receipt.
    #[error("external finality verification failed")]
    Verifier(#[source] E),
}

/// External trust boundary for consensus and application-inclusion receipts.
///
/// A production implementation must bind the configured chain and trust root,
/// validator quorum or light-client header continuity, height, time, app hash,
/// application version two, exact entry metadata, and the supplied Merkle proof.
pub trait ExternalFinalityVerifierV2: Send + Sync {
    /// Non-secret verification error.
    type Error: Error + Send + Sync + 'static;

    /// Returns the exact trust-root and verification-policy profile accepted by this verifier.
    fn profile_id(&self) -> crate::FinalityVerifierProfileIdV2;

    /// Verifies an opaque receipt against all deterministic bundle components.
    fn verify(
        &self,
        block: &ExecutedBlockV2,
        entry: &ExecutedEntryV2,
        proof: &EntryMerkleProofV2,
        receipt: &OpaqueConsensusReceiptV2,
    ) -> std::result::Result<(), Self::Error>;
}

/// Borrowed capability proving that a configured external verifier accepted a bundle.
pub struct VerifiedFinalizedEntryV2<'a> {
    bundle: &'a FinalizedEntryBundleV2,
}

impl<'a> VerifiedFinalizedEntryV2<'a> {
    /// Returns the exact bundle accepted by the external verifier.
    pub const fn bundle(&self) -> &'a FinalizedEntryBundleV2 {
        self.bundle
    }
}

/// Lifecycle result for one authenticated actor request key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum RequestLifecycleV2 {
    /// No matching admission or committed request was observed.
    Unknown,
    /// The transport admitted the request but execution is not known.
    Admitted {
        /// Opaque transport-admission identifier.
        acceptance_id: TransportAcceptanceIdV2,
    },
    /// Deterministic execution is available but no finality receipt is carried.
    Executed {
        /// Exact deterministic metadata, including entry hash and block location.
        metadata: Box<ExecutedMetadataRecordV2>,
    },
    /// Deterministic execution plus an externally verifiable receipt is available.
    FinalityReceiptAvailable {
        /// Exact block, entry, Merkle proof, and opaque consensus receipt.
        bundle: Box<FinalizedEntryBundleV2>,
    },
}

/// Response to a complete authenticated request-status key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RequestStatusResponseV2 {
    ledger_chain_id: LedgerChainIdV2,
    channel_context_id: thunderbolt_ledger::ChannelContextIdV2,
    participant_id: ParticipantIdV2,
    request_digest: RequestDigestV2,
    lifecycle: RequestLifecycleV2,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RequestStatusResponseInput {
    ledger_chain_id: LedgerChainIdV2,
    channel_context_id: thunderbolt_ledger::ChannelContextIdV2,
    participant_id: ParticipantIdV2,
    request_digest: RequestDigestV2,
    lifecycle: RequestLifecycleV2,
}

impl<'de> Deserialize<'de> for RequestStatusResponseV2 {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let input = RequestStatusResponseInput::deserialize(deserializer)?;
        let request = RequestStatusRequestV2::new(
            input.ledger_chain_id,
            input.channel_context_id,
            input.participant_id,
            input.request_digest,
        );
        Self::new(&request, input.lifecycle).map_err(serde::de::Error::custom)
    }
}

impl RequestStatusResponseV2 {
    /// Constructs a lifecycle response bound to the complete authenticated query key.
    pub fn new(request: &RequestStatusRequestV2, lifecycle: RequestLifecycleV2) -> Result<Self> {
        let response = Self {
            ledger_chain_id: request.ledger_chain_id().clone(),
            channel_context_id: request.channel_context_id().clone(),
            participant_id: request.participant_id().clone(),
            request_digest: request.request_digest().clone(),
            lifecycle,
        };
        response.validate_for(request)?;
        Ok(response)
    }

    /// Returns the current observed lifecycle.
    pub const fn lifecycle(&self) -> &RequestLifecycleV2 {
        &self.lifecycle
    }

    /// Checks every executed identifier against the complete query key.
    pub fn validate_for(&self, request: &RequestStatusRequestV2) -> Result<()> {
        if &self.ledger_chain_id != request.ledger_chain_id()
            || &self.channel_context_id != request.channel_context_id()
            || &self.participant_id != request.participant_id()
            || &self.request_digest != request.request_digest()
        {
            return Err(RpcCodecError::BindingMismatch(
                "request-status response key differs from the complete query key",
            ));
        }
        let metadata = match &self.lifecycle {
            RequestLifecycleV2::Unknown | RequestLifecycleV2::Admitted { .. } => return Ok(()),
            RequestLifecycleV2::Executed { metadata } => {
                metadata.validate()?;
                return validate_record_key(metadata, request);
            }
            RequestLifecycleV2::FinalityReceiptAvailable { bundle } => bundle.entry().metadata(),
        };
        validate_metadata_key(metadata, request)?;
        Ok(())
    }

    pub(crate) fn validate_shape(&self) -> Result<()> {
        let request = RequestStatusRequestV2::new(
            self.ledger_chain_id.clone(),
            self.channel_context_id.clone(),
            self.participant_id.clone(),
            self.request_digest.clone(),
        );
        self.validate_for(&request)
    }
}

/// Transport projection of deterministic executed-entry metadata.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutedMetadataRecordV2 {
    /// Positive block height.
    pub block_height: u64,
    /// Positive trusted consensus time in Unix milliseconds.
    pub block_time_ms: u64,
    /// Zero-based position in the block.
    pub block_index: u32,
    /// Exact Ledger chain.
    pub ledger_chain_id: LedgerChainIdV2,
    /// Stable channel context.
    pub channel_context_id: thunderbolt_ledger::ChannelContextIdV2,
    /// Per-channel sequence.
    pub sequence: u64,
    /// Exact prior per-channel entry hash.
    pub previous_entry_hash: EntryHashV2,
    /// Actor-authenticated proposal digest.
    pub proposal_digest: ProposalDigestV2,
    /// Deterministic entry hash.
    pub entry_hash: EntryHashV2,
    /// Channel- and actor-scoped request digest.
    pub request_digest: RequestDigestV2,
    /// Participant derived from the actor key.
    pub participant_id: ParticipantIdV2,
    /// Authenticated typed actor role.
    pub actor_role: ActorRoleV2,
    /// Permanent event kind.
    pub event_kind: EventKindV2,
    /// Digest of the canonical public event bytes.
    pub event_digest: EventDigestV2,
}

impl ExecutedMetadataRecordV2 {
    /// Copies one query projection from recomputed deterministic metadata.
    #[must_use]
    pub fn from_metadata(metadata: &ExecutedEntryMetadataV2) -> Self {
        Self {
            block_height: metadata.block_height(),
            block_time_ms: metadata.block_time_ms(),
            block_index: metadata.block_index(),
            ledger_chain_id: metadata.ledger_chain_id().clone(),
            channel_context_id: metadata.channel_context_id().clone(),
            sequence: metadata.sequence(),
            previous_entry_hash: metadata.previous_entry_hash().clone(),
            proposal_digest: metadata.proposal_digest().clone(),
            entry_hash: metadata.entry_hash().clone(),
            request_digest: metadata.request_digest().clone(),
            participant_id: metadata.participant_id().clone(),
            actor_role: metadata.actor_role(),
            event_kind: metadata.event_kind(),
            event_digest: metadata.event_digest().clone(),
        }
    }

    pub(crate) fn validate(&self) -> Result<()> {
        if self.block_height == 0
            || self.block_time_ms == 0
            || usize::try_from(self.block_index).map_or(true, |index| index >= MAX_BLOCK_ENTRIES)
        {
            return Err(RpcCodecError::InvalidField(
                "executed metadata position or time is invalid",
            ));
        }
        if (self.sequence == 0) != self.previous_entry_hash.is_zero()
            || (self.sequence == 0) != (self.event_kind == EventKindV2::Open)
        {
            return Err(RpcCodecError::InvalidField(
                "executed metadata channel-chain shape is invalid",
            ));
        }
        Ok(())
    }
}

/// Bounded page of deterministic metadata and its exact continuation cursor.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HistoryResponseV2 {
    request_digest: RpcRequestDigestV2,
    entries: Vec<ExecutedMetadataRecordV2>,
    next_cursor: Option<HistoryCursorV2>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HistoryResponseInput {
    request_digest: RpcRequestDigestV2,
    entries: BoundedMetadataList,
    next_cursor: Option<HistoryCursorV2>,
}

struct BoundedMetadataList(Vec<ExecutedMetadataRecordV2>);

struct MetadataListVisitor;

impl<'de> Visitor<'de> for MetadataListVisitor {
    type Value = BoundedMetadataList;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "at most {MAX_HISTORY_PAGE_ENTRIES} executed metadata records"
        )
    }

    fn visit_seq<A>(self, mut sequence: A) -> std::result::Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        if sequence
            .size_hint()
            .is_some_and(|size| size > usize::from(MAX_HISTORY_PAGE_ENTRIES))
        {
            return Err(A::Error::custom("history page exceeds entry bound"));
        }
        let mut entries = Vec::with_capacity(
            sequence
                .size_hint()
                .unwrap_or_default()
                .min(usize::from(MAX_HISTORY_PAGE_ENTRIES)),
        );
        while let Some(entry) = sequence.next_element::<ExecutedMetadataRecordV2>()? {
            if entries.len() == usize::from(MAX_HISTORY_PAGE_ENTRIES) {
                return Err(A::Error::custom("history page exceeds entry bound"));
            }
            entry.validate().map_err(A::Error::custom)?;
            entries.push(entry);
        }
        Ok(BoundedMetadataList(entries))
    }
}

impl<'de> Deserialize<'de> for BoundedMetadataList {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_seq(MetadataListVisitor)
    }
}

impl<'de> Deserialize<'de> for HistoryResponseV2 {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let input = HistoryResponseInput::deserialize(deserializer)?;
        Ok(Self {
            request_digest: input.request_digest,
            entries: input.entries.0,
            next_cursor: input.next_cursor,
        })
    }
}

impl HistoryResponseV2 {
    /// Constructs and validates a bounded page against its exact request.
    pub fn new(
        request: &HistoryRequestV2,
        entries: Vec<ExecutedMetadataRecordV2>,
        next_cursor: Option<HistoryCursorV2>,
    ) -> Result<Self> {
        let request_digest = RpcRequestV2::History(request.clone()).request_digest()?;
        let response = Self {
            request_digest,
            entries,
            next_cursor,
        };
        response.validate_for(request)?;
        Ok(response)
    }

    /// Returns the digest of the complete correlated history request.
    pub const fn request_digest(&self) -> RpcRequestDigestV2 {
        self.request_digest
    }

    /// Returns the ordered deterministic metadata projection.
    pub fn entries(&self) -> &[ExecutedMetadataRecordV2] {
        &self.entries
    }

    /// Returns the next global execution cursor, or `None` at the observed tip.
    pub const fn next_cursor(&self) -> Option<&HistoryCursorV2> {
        self.next_cursor.as_ref()
    }

    /// Validates chain, channel, bounds, order, and forward cursor progress.
    pub fn validate_for(&self, request: &HistoryRequestV2) -> Result<()> {
        let expected_request_digest = RpcRequestV2::History(request.clone()).request_digest()?;
        if self.request_digest != expected_request_digest {
            return Err(RpcCodecError::BindingMismatch(
                "history response digest differs from the complete query",
            ));
        }
        if self.entries.len() > usize::from(request.limit().get())
            || self.entries.len() > usize::from(MAX_HISTORY_PAGE_ENTRIES)
        {
            return Err(RpcCodecError::InvalidField(
                "history response exceeds requested page limit",
            ));
        }
        let mut previous_position = None;
        for entry in &self.entries {
            entry.validate()?;
            if &entry.ledger_chain_id != request.cursor().ledger_chain_id()
                || &entry.channel_context_id != request.channel_context_id()
            {
                return Err(RpcCodecError::BindingMismatch(
                    "history metadata differs from query chain or channel",
                ));
            }
            let position = (entry.block_height, entry.block_index);
            if position < (request.cursor().next_height(), request.cursor().next_block_index())
                || previous_position.is_some_and(|previous| position <= previous)
            {
                return Err(RpcCodecError::InvalidField(
                    "history metadata is not in strict cursor order",
                ));
            }
            previous_position = Some(position);
        }
        if let Some(cursor) = &self.next_cursor {
            if cursor.ledger_chain_id() != request.cursor().ledger_chain_id()
                || (cursor.next_height(), cursor.next_block_index())
                    <= (request.cursor().next_height(), request.cursor().next_block_index())
                || previous_position
                    .is_some_and(|position| (cursor.next_height(), cursor.next_block_index()) <= position)
            {
                return Err(RpcCodecError::InvalidField(
                    "history continuation cursor did not advance",
                ));
            }
        }
        Ok(())
    }
}

/// One response in the version-two transport-neutral Ledger control plane.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "method", content = "result", rename_all = "snake_case")]
pub enum RpcResponseV2 {
    /// Proposal admission result.
    SubmitProposal(SubmitProposalResponseV2),
    /// Materialized channel head.
    ChannelStatus(Box<ChannelStatusResponseV2>),
    /// Authenticated request lifecycle.
    RequestStatus(Box<RequestStatusResponseV2>),
    /// Bounded deterministic metadata page.
    History(HistoryResponseV2),
    /// Rollback-floor CAS transport/result response.
    RollbackFloorCas(crate::RollbackFloorCasResponseV2),
}

impl RpcResponseV2 {
    /// Validates method correlation and every binding available from the exact request.
    pub fn validate_for(&self, request: &RpcRequestV2) -> Result<()> {
        match (self, request) {
            (Self::SubmitProposal(response), RpcRequestV2::SubmitProposal(request)) => response.validate_for(request),
            (Self::ChannelStatus(response), RpcRequestV2::ChannelStatus(request)) => response.validate_for(request),
            (Self::RequestStatus(response), RpcRequestV2::RequestStatus(request)) => response.validate_for(request),
            (Self::History(response), RpcRequestV2::History(request)) => response.validate_for(request),
            (Self::RollbackFloorCas(response), RpcRequestV2::RollbackFloorCas(request)) => {
                response.validate_for(request.request())
            }
            _ => Err(RpcCodecError::BindingMismatch(
                "RPC response method differs from the correlated request method",
            )),
        }
    }

    pub(crate) fn validate(&self) -> Result<()> {
        match self {
            Self::SubmitProposal(_) | Self::ChannelStatus(_) => Ok(()),
            Self::RequestStatus(response) => response.validate_shape(),
            Self::History(response) => {
                for entry in &response.entries {
                    entry.validate()?;
                }
                Ok(())
            }
            Self::RollbackFloorCas(response) => response.validate(),
        }
    }
}

fn validate_metadata_key(metadata: &ExecutedEntryMetadataV2, request: &RequestStatusRequestV2) -> Result<()> {
    if metadata.ledger_chain_id() != request.ledger_chain_id()
        || metadata.channel_context_id() != request.channel_context_id()
        || metadata.participant_id() != request.participant_id()
        || metadata.request_digest() != request.request_digest()
    {
        return Err(RpcCodecError::BindingMismatch(
            "executed request metadata differs from the complete status key",
        ));
    }
    Ok(())
}

fn validate_record_key(metadata: &ExecutedMetadataRecordV2, request: &RequestStatusRequestV2) -> Result<()> {
    if &metadata.ledger_chain_id != request.ledger_chain_id()
        || &metadata.channel_context_id != request.channel_context_id()
        || &metadata.participant_id != request.participant_id()
        || &metadata.request_digest != request.request_digest()
    {
        return Err(RpcCodecError::BindingMismatch(
            "executed request projection differs from the complete status key",
        ));
    }
    Ok(())
}
