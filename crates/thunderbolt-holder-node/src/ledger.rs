use thunderbolt_ledger::{
    ActorPublicKeyV2, ActorSignatureV2, ChannelContextIdV2, EventDigestV2, LedgerChainIdV2, ProposalDigestV2,
    RequestDigestV2, SignedProposalV2,
};

use crate::FinalizedCursor;

/// External actor-signing boundary. Secret keys never enter this crate.
pub trait ActorSigner {
    type Error: std::error::Error + Send + Sync + 'static;

    fn public_key(&self) -> std::result::Result<&ActorPublicKeyV2, Self::Error>;
    fn sign(&mut self, digest: &ProposalDigestV2) -> std::result::Result<ActorSignatureV2, Self::Error>;
}

/// Actor signer that always fails closed.
#[derive(Clone, Copy, Debug, Default)]
pub struct UnavailableActorSigner;

impl ActorSigner for UnavailableActorSigner {
    type Error = crate::CapabilityError;

    fn public_key(&self) -> std::result::Result<&ActorPublicKeyV2, Self::Error> {
        Err(crate::CapabilityError::Unavailable)
    }

    fn sign(&mut self, _digest: &ProposalDigestV2) -> std::result::Result<ActorSignatureV2, Self::Error> {
        Err(crate::CapabilityError::Unavailable)
    }
}

/// Submission result from a signed-v2 Ledger client.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SubmissionStatus {
    Accepted,
    AlreadyKnown,
}

/// Raw signed-v2 Ledger transport. Poll results are not final until the
/// separately supplied finality verifier issues a trusted receipt.
///
/// `finalized_history` must be historically repeatable after crashes. If the
/// client advances a monotonic light-client root while fetching candidates,
/// that root must be durable before return and must continue to verify the same
/// historical page until the Holder cursor commits.
pub trait SignedV2LedgerClient {
    type Error: std::error::Error + Send + Sync + 'static;
    type FinalityCandidate: Send + 'static;

    fn submit(&mut self, proposal: &SignedProposalV2) -> std::result::Result<SubmissionStatus, Self::Error>;

    fn finalized_history(
        &mut self,
        channel: &ChannelContextIdV2,
        after: Option<&FinalizedCursor>,
        limit: usize,
    ) -> std::result::Result<Vec<Self::FinalityCandidate>, Self::Error>;
}

/// Trusted finality capability produced by a quorum/light-client verifier.
///
/// Implementations are a security boundary. The acknowledgement must be
/// derived from the finalized, application-verified statement; it must never
/// be synthesized from an HTTP acceptance response or execution-only block.
pub trait TrustedLedgerReceipt: Clone + Send + Sync + 'static {
    fn cursor(&self) -> FinalizedCursor;
    fn signed_proposal(&self) -> &SignedProposalV2;
    fn finality_digest(&self) -> &[u8; 32];
    fn request_digest(&self) -> &RequestDigestV2;
    fn event_digest(&self) -> &EventDigestV2;
}

/// Converts an untrusted Ledger candidate into a typed finality capability.
pub trait FinalityVerifier<C> {
    type Error: std::error::Error + Send + Sync + 'static;
    type Receipt: TrustedLedgerReceipt;

    /// Pure, historically repeatable verification. Implementations must not
    /// advance or persist a trust root here; any monotonic light-client update
    /// must already be durable before the candidate is exposed.
    fn verify(&self, expected_chain: &LedgerChainIdV2, candidate: C)
        -> std::result::Result<Self::Receipt, Self::Error>;
}
