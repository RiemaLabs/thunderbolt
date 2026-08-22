use std::error::Error;

use serde::de::DeserializeOwned;
use serde::Serialize;
use thunderbolt_committee::{CommitteeMemberEngine, CommitteeVault};
use thunderbolt_ledger::{ActorSignatureV2, ProposalBodyV2, SignedProposalV2};

use crate::{
    DurableBlockFinalityCapability, FinalityVerifierProfileId, FinalizedEntryOccurrenceV2, FinalizedExecutedBlockV2,
    FinalizedExecutionSegmentV2, LedgerCursor, NodeError, Result, RuntimeRefreshOutcome, VerifiedEntryOccurrenceV2,
    VerifiedV2Refresh,
};

/// Trusted consensus boundary for one complete deterministic executed block.
///
/// Implementations authenticate the exact chain, height, application hash, and
/// complete executed block through a trusted header or validator quorum. They
/// never assign refresh ordinals or claim filtered-result completeness. The
/// service derives its local refresh chain only from whole-block continuity.
/// This crate provides no accepting production implementation.
pub trait LedgerFinalityVerifier<R> {
    type Error: Error + Send + Sync + 'static;
    fn profile_id(&self) -> FinalityVerifierProfileId;
    fn verify_finalized_block(
        &self,
        block: &FinalizedExecutedBlockV2<R>,
    ) -> std::result::Result<DurableBlockFinalityCapability, Self::Error>;
    /// Authenticates an exact request-bound first-location lookup at the stated
    /// finalized `(through_height, through_app_hash)` checkpoint. The returned
    /// capability must bind every field, the canonical current-entry semantic
    /// digest, and equality with the canonical entry at the authenticated first
    /// location. It must distinguish first execution from an exact later
    /// replay; a locator response alone is not sufficient.
    fn verify_entry_occurrence(
        &self,
        occurrence: &FinalizedEntryOccurrenceV2<R>,
    ) -> std::result::Result<VerifiedEntryOccurrenceV2, Self::Error>;
    /// Verifies the bounded persisted attestation without consulting mutable
    /// light-client state or requiring the original raw consensus receipt. The
    /// authenticated attestation must cover the exact profile, chain, block
    /// height, and application hash; accepting shape-valid JSON alone is unsafe.
    fn verify_durable_capability(
        &self,
        capability: &DurableBlockFinalityCapability,
    ) -> std::result::Result<(), Self::Error>;
    fn is_available(&self) -> bool {
        true
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct DisabledFinalityVerifier;

impl<R> LedgerFinalityVerifier<R> for DisabledFinalityVerifier {
    type Error = NodeError;
    fn profile_id(&self) -> FinalityVerifierProfileId {
        FinalityVerifierProfileId::DISABLED
    }
    fn verify_finalized_block(
        &self,
        _block: &FinalizedExecutedBlockV2<R>,
    ) -> std::result::Result<DurableBlockFinalityCapability, Self::Error> {
        Err(NodeError::FinalityUnavailable)
    }
    fn verify_entry_occurrence(
        &self,
        _occurrence: &FinalizedEntryOccurrenceV2<R>,
    ) -> std::result::Result<VerifiedEntryOccurrenceV2, Self::Error> {
        Err(NodeError::FinalityUnavailable)
    }
    fn verify_durable_capability(
        &self,
        _capability: &DurableBlockFinalityCapability,
    ) -> std::result::Result<(), Self::Error> {
        Err(NodeError::FinalityUnavailable)
    }
    fn is_available(&self) -> bool {
        false
    }
}

/// Transport for complete contiguous finalized whole-block pages.
///
/// `None` cursor means the exact genesis locator `(height=1, previous_app_hash=0)`.
/// Returning `None` means no new complete finalized range is available. A
/// returned segment must come from a request-correlated execution-range page;
/// locators and filtered history responses are insufficient.
pub trait SignedV2LedgerClient {
    type Receipt: Clone + Serialize + DeserializeOwned;
    type Error: Error + Send + Sync + 'static;
    fn fetch_contiguous_finalized_segment(
        &mut self,
        cursor: Option<&LedgerCursor>,
        max_blocks: u16,
    ) -> std::result::Result<Option<FinalizedExecutionSegmentV2<Self::Receipt>>, Self::Error>;
    fn submit_signed_proposal(
        &mut self,
        proposal: &SignedProposalV2,
    ) -> std::result::Result<Self::Receipt, Self::Error>;
}

/// External BIP340 signer boundary. The service never receives a secret key.
///
/// No current protocol-v2 application event authorizes the Committee role, so
/// this hook is fail-closed unless a future version adds such an event.
pub trait SignedV2ProposalSigner {
    type Error: Error + Send + Sync + 'static;
    fn sign(&mut self, body: &ProposalBodyV2) -> std::result::Result<ActorSignatureV2, Self::Error>;
    fn is_available(&self) -> bool {
        true
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct DisabledProposalSigner;
impl SignedV2ProposalSigner for DisabledProposalSigner {
    type Error = NodeError;
    fn sign(&mut self, _body: &ProposalBodyV2) -> std::result::Result<ActorSignatureV2, Self::Error> {
        Err(NodeError::SigningUnavailable)
    }
    fn is_available(&self) -> bool {
        false
    }
}

/// Narrow trusted protocol-v2 private-runtime boundary used by the role service.
///
/// Implementations must verify the v2 proofs with the mandatory production
/// profile, bind the exact roster keys to the provisioned descriptor/member,
/// update exactly one member share crash-safely, and return only public
/// acknowledgement metadata. This crate ships no accepting implementation
/// until the reviewed Paillier/core-v2/Committee engine migration lands.
pub trait CommitteeRuntime {
    fn descriptor(&self) -> &thunderbolt_committee::CommitteeDescriptor;
    fn member_id(&self) -> thunderbolt_committee::CommitteeMemberId;
    fn validate_verified_refresh(&self, refresh: &VerifiedV2Refresh) -> Result<()>;
    fn apply_verified_refresh(&mut self, refresh: &VerifiedV2Refresh) -> Result<RuntimeRefreshOutcome>;
    fn is_v2_available(&self) -> bool {
        true
    }
}

impl<V> CommitteeRuntime for CommitteeMemberEngine<V>
where
    V: CommitteeVault,
{
    fn descriptor(&self) -> &thunderbolt_committee::CommitteeDescriptor {
        self.descriptor()
    }
    fn member_id(&self) -> thunderbolt_committee::CommitteeMemberId {
        self.state().member_id()
    }
    fn validate_verified_refresh(&self, _refresh: &VerifiedV2Refresh) -> Result<()> {
        Err(NodeError::V2RuntimeUnavailable)
    }
    fn apply_verified_refresh(&mut self, _refresh: &VerifiedV2Refresh) -> Result<RuntimeRefreshOutcome> {
        Err(NodeError::V2RuntimeUnavailable)
    }
    fn is_v2_available(&self) -> bool {
        false
    }
}
