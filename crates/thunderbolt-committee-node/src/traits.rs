use std::error::Error;
use std::future::Future;
use std::pin::Pin;

use thunderbolt_committee::{CommitteeMemberEngine, CommitteeVault};
use thunderbolt_ledger::{ActorSignatureV2, ProposalBodyV2, SignedProposalV2};

use crate::{
    DurableBlockFinalityCapability, FinalityCoordinatorId, FinalityRangeIntentV2, FinalityVerifierProfileId,
    FinalizedRangeCapabilityV2, LedgerCursor, NodeError, Result, RuntimeRefreshOutcome,
    StagedFinalityRangeCapabilityV2, SubmissionStatus, VerifiedV2Refresh,
};

/// Trusted consensus boundary for one complete deterministic executed block.
///
/// Implementations authenticate the exact chain, height, application hash, and
/// complete executed block through a trusted header or validator quorum. They
/// never assign refresh ordinals or claim filtered-result completeness. The
/// service derives its local refresh chain only from whole-block continuity.
/// Every method is asynchronous because historically repeatable verification
/// may consult a crash-safe light-client store. Cancellation must not expose an
/// unanchored capability. The service durably stages authority-free execution
/// intent first, but performs no cursor, inbox, or private-runtime mutation
/// until finalization has completed. This crate provides no accepting
/// production implementation.
pub trait LedgerFinalityVerifier: Send + Sync {
    type Error: Error + Send + Sync + 'static;
    fn profile_id(&self) -> FinalityVerifierProfileId;
    fn coordinator_id(&self) -> FinalityCoordinatorId;
    /// Finalizes only a role-store-issued staged range. Implementations must
    /// replay an already finalized prefix exactly and must retain no provider
    /// metadata in the returned capability.
    fn finalize_staged_range<'a>(
        &'a mut self,
        staged: &'a StagedFinalityRangeCapabilityV2,
    ) -> LedgerFuture<'a, FinalizedRangeCapabilityV2, Self::Error>;
    /// Revalidates the bounded persisted attestation against historically
    /// repeatable trusted state without requiring the original raw consensus
    /// receipt. The authenticated attestation must cover the exact profile,
    /// chain, block height, and application hash; accepting shape-valid JSON
    /// alone is unsafe.
    fn verify_durable_capability<'a>(
        &'a self,
        capability: &'a DurableBlockFinalityCapability,
    ) -> LedgerFuture<'a, (), Self::Error>;
    fn is_available(&self) -> bool {
        true
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct DisabledFinalityVerifier;

impl LedgerFinalityVerifier for DisabledFinalityVerifier {
    type Error = NodeError;
    fn profile_id(&self) -> FinalityVerifierProfileId {
        FinalityVerifierProfileId::DISABLED
    }
    fn coordinator_id(&self) -> FinalityCoordinatorId {
        FinalityCoordinatorId::DISABLED
    }
    fn finalize_staged_range<'a>(
        &'a mut self,
        _staged: &'a StagedFinalityRangeCapabilityV2,
    ) -> LedgerFuture<'a, FinalizedRangeCapabilityV2, Self::Error> {
        Box::pin(async { Err(NodeError::FinalityUnavailable) })
    }
    fn verify_durable_capability<'a>(
        &'a self,
        _capability: &'a DurableBlockFinalityCapability,
    ) -> LedgerFuture<'a, (), Self::Error> {
        Box::pin(async { Err(NodeError::FinalityUnavailable) })
    }
    fn is_available(&self) -> bool {
        false
    }
}

/// Transport for complete contiguous authority-free whole-block intents.
///
/// `None` cursor means the exact genesis locator `(height=1, previous_app_hash=0)`.
/// Returning `None` means no new complete execution range is available. A
/// returned intent must come from a request-correlated execution-range page;
/// locators and filtered history responses are insufficient. Preparing never
/// grants finality or mutates coordinator trust state.
pub trait SignedV2LedgerClient: Send {
    type Error: Error + Send + Sync + 'static;
    fn profile_id(&self) -> FinalityVerifierProfileId;
    fn coordinator_id(&self) -> FinalityCoordinatorId;
    fn prepare_finalized_execution<'a>(
        &'a mut self,
        cursor: Option<&'a LedgerCursor>,
        max_blocks: u16,
    ) -> LedgerFuture<'a, Option<FinalityRangeIntentV2>, Self::Error>;
    fn submit_signed_proposal<'a>(
        &'a mut self,
        proposal: &'a SignedProposalV2,
    ) -> LedgerFuture<'a, SubmissionStatus, Self::Error>;
    fn is_available(&self) -> bool {
        true
    }
}

/// Boxed cancellable future returned by a Committee Ledger transport.
pub type LedgerFuture<'a, T, E> = Pin<Box<dyn Future<Output = std::result::Result<T, E>> + Send + 'a>>;

/// Signed-v2 Ledger client that always fails closed.
#[derive(Clone, Copy, Debug, Default)]
pub struct DisabledSignedV2LedgerClient;

impl SignedV2LedgerClient for DisabledSignedV2LedgerClient {
    type Error = NodeError;

    fn profile_id(&self) -> FinalityVerifierProfileId {
        FinalityVerifierProfileId::DISABLED
    }

    fn coordinator_id(&self) -> FinalityCoordinatorId {
        FinalityCoordinatorId::DISABLED
    }

    fn prepare_finalized_execution<'a>(
        &'a mut self,
        _cursor: Option<&'a LedgerCursor>,
        _max_blocks: u16,
    ) -> LedgerFuture<'a, Option<FinalityRangeIntentV2>, Self::Error> {
        Box::pin(async { Err(NodeError::FinalityUnavailable) })
    }

    fn submit_signed_proposal<'a>(
        &'a mut self,
        _proposal: &'a SignedProposalV2,
    ) -> LedgerFuture<'a, SubmissionStatus, Self::Error> {
        Box::pin(async { Err(NodeError::FinalityUnavailable) })
    }

    fn is_available(&self) -> bool {
        false
    }
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
