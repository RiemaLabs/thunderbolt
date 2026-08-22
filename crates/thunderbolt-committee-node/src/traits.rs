use std::error::Error;

use serde::de::DeserializeOwned;
use serde::Serialize;
use thunderbolt_committee::{
    CommittedTransfer, CommitteeMemberEngine, CommitteeVault, LedgerCommitmentVerifier, UpdateAcknowledgement,
};
use thunderbolt_ledger::{ActorSignatureV2, ProposalBodyV2, SignedProposalV2};

use crate::{
    DurableFinalityCapability, FinalityVerifierProfileId, FinalizedEntryV2, FinalizedRefreshBundleV2, LedgerCursor,
    NodeError, Result, VerifiedRefreshRecordV2,
};

/// Trusted consensus boundary for an otherwise deterministic execution entry.
///
/// Implementations must prove both entries share one finalized ancestry and
/// bind the receipt to chain id, block positions, exact app hash, entry hashes,
/// inclusion proofs, and an authenticated trusted header or validator quorum.
/// The refresh ordinal and previous-refresh hash must come from application
/// state committed by that app hash. This crate provides no accepting implementation.
pub trait LedgerFinalityVerifier<R> {
    type Error: Error + Send + Sync + 'static;
    fn profile_id(&self) -> FinalityVerifierProfileId;
    fn verify_finalized_refresh(
        &self,
        invoice: &FinalizedEntryV2<R>,
        transfer: &FinalizedEntryV2<R>,
    ) -> std::result::Result<DurableFinalityCapability, Self::Error>;
    /// Verifies the bounded persisted attestation without consulting mutable
    /// light-client state or requiring the original raw consensus receipt. The
    /// authenticated attestation must cover every public capability field,
    /// including both entry hashes/positions, transfer app hash, ordinal, and
    /// prior-refresh hash; accepting shape-valid JSON alone is unsafe.
    fn verify_durable_capability(&self, capability: &DurableFinalityCapability)
        -> std::result::Result<(), Self::Error>;
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
    fn verify_finalized_refresh(
        &self,
        _invoice: &FinalizedEntryV2<R>,
        _transfer: &FinalizedEntryV2<R>,
    ) -> std::result::Result<DurableFinalityCapability, Self::Error> {
        Err(NodeError::FinalityUnavailable)
    }
    fn verify_durable_capability(
        &self,
        _capability: &DurableFinalityCapability,
    ) -> std::result::Result<(), Self::Error> {
        Err(NodeError::FinalityUnavailable)
    }
    fn is_available(&self) -> bool {
        false
    }
}

/// Transport for exact signed-v2 proposals and externally finalized bundles.
pub trait SignedV2LedgerClient {
    type Receipt: Clone + Serialize + DeserializeOwned;
    type Error: Error + Send + Sync + 'static;
    fn fetch_finalized_refreshes(
        &mut self,
        after: Option<&LedgerCursor>,
        limit: u16,
    ) -> std::result::Result<Vec<FinalizedRefreshBundleV2<Self::Receipt>>, Self::Error>;
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

/// Minimal private one-member engine boundary used by the role service.
pub trait CommitteeRuntime {
    fn descriptor(&self) -> &thunderbolt_committee::CommitteeDescriptor;
    fn member_id(&self) -> thunderbolt_committee::CommitteeMemberId;
    fn apply_refresh(
        &mut self,
        bundle: &VerifiedRefreshRecordV2,
        commitment: CommittedTransfer,
    ) -> Result<UpdateAcknowledgement>;
}

struct ExactCommitmentVerifier(CommittedTransfer);
impl LedgerCommitmentVerifier for ExactCommitmentVerifier {
    type Receipt = ();
    type Error = NodeError;
    fn verify_committed(&self, _receipt: &()) -> std::result::Result<CommittedTransfer, Self::Error> {
        Ok(self.0)
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
    fn apply_refresh(
        &mut self,
        bundle: &VerifiedRefreshRecordV2,
        commitment: CommittedTransfer,
    ) -> Result<UpdateAcknowledgement> {
        self.apply_committed_refresh(
            &bundle.recipient_share,
            &bundle.threshold_distribution,
            &bundle.transfer_proof,
            &ExactCommitmentVerifier(commitment),
            &(),
        )
        .map_err(|error| NodeError::Runtime(error.to_string()))
    }
}
