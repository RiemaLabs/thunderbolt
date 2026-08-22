use std::error::Error;

use serde::de::DeserializeOwned;
use serde::Serialize;
use thunderbolt_committee::{
    CommittedTransfer, CommitteeMemberEngine, CommitteeVault, LedgerCommitmentVerifier, UpdateAcknowledgement,
};
use thunderbolt_ledger::{
    ActorSignatureV2, EntryMerkleProofV2, ExecutedBlockV2, ExecutedEntryV2, ProposalBodyV2, SignedProposalV2,
};

use crate::{FinalityDigest, FinalizedRefreshBundleV2, LedgerCursor, NodeError, Result};

/// Trusted consensus boundary for an otherwise deterministic execution entry.
///
/// Implementations must bind the receipt to chain id, block height, exact app
/// hash, entry metadata/hash, inclusion proof, and an authenticated trusted
/// header or validator quorum. This crate provides no accepting implementation.
pub trait LedgerFinalityVerifier<R> {
    type Error: Error + Send + Sync + 'static;
    fn verify_finality(
        &self,
        block: &ExecutedBlockV2,
        entry: &ExecutedEntryV2,
        inclusion: &EntryMerkleProofV2,
        receipt: &R,
    ) -> std::result::Result<FinalityDigest, Self::Error>;
    fn is_available(&self) -> bool {
        true
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct DisabledFinalityVerifier;

impl<R> LedgerFinalityVerifier<R> for DisabledFinalityVerifier {
    type Error = NodeError;
    fn verify_finality(
        &self,
        _block: &ExecutedBlockV2,
        _entry: &ExecutedEntryV2,
        _inclusion: &EntryMerkleProofV2,
        _receipt: &R,
    ) -> std::result::Result<FinalityDigest, Self::Error> {
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
        bundle: &FinalizedRefreshBundleV2<impl Serialize>,
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
        bundle: &FinalizedRefreshBundleV2<impl Serialize>,
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
