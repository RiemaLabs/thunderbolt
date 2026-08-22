use std::future::Future;
use std::pin::Pin;

use thunderbolt_ledger::{ActorPublicKeyV2, ActorSignatureV2, ProposalDigestV2, SignedProposalV2};

use crate::{
    CapabilityError, DurableBlockFinalityCapabilityV2, FinalityCoordinatorId, FinalityRangeIntentV2,
    FinalityVerifierProfileId, FinalizedBlockCursor, FinalizedRangeCapabilityV2, StagedFinalityRangeCapabilityV2,
};

/// Boxed cancellable future returned by a Holder Ledger capability.
pub type LedgerFuture<'a, T, E> = Pin<Box<dyn Future<Output = std::result::Result<T, E>> + Send + 'a>>;

/// External actor-signing boundary. Secret keys never enter this crate.
pub trait ActorSigner: Send {
    type Error: std::error::Error + Send + Sync + 'static;

    fn public_key(&self) -> std::result::Result<&ActorPublicKeyV2, Self::Error>;
    fn sign(&mut self, digest: &ProposalDigestV2) -> std::result::Result<ActorSignatureV2, Self::Error>;
}

/// Actor signer that always fails closed.
#[derive(Clone, Copy, Debug, Default)]
pub struct UnavailableActorSigner;

impl ActorSigner for UnavailableActorSigner {
    type Error = CapabilityError;

    fn public_key(&self) -> std::result::Result<&ActorPublicKeyV2, Self::Error> {
        Err(CapabilityError::Unavailable)
    }

    fn sign(&mut self, _digest: &ProposalDigestV2) -> std::result::Result<ActorSignatureV2, Self::Error> {
        Err(CapabilityError::Unavailable)
    }
}

/// Admission result from a signed-v2 Ledger client. This never claims finality.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SubmissionStatus {
    Accepted,
    AlreadyKnown,
}

/// Transport for proposal admission and authority-free finalized execution intents.
///
/// `prepare_finalized_execution` must not mutate a finality coordinator. It
/// returns a bounded canonical range that the Holder durably stages before a
/// separate verifier receives store-issued authority to finalize it. `None`
/// means no new finalized block and never advances a cursor.
pub trait SignedV2LedgerClient: Send {
    type Error: std::error::Error + Send + Sync + 'static;

    fn submit<'a>(&'a mut self, proposal: &'a SignedProposalV2) -> LedgerFuture<'a, SubmissionStatus, Self::Error>;

    fn prepare_finalized_execution<'a>(
        &'a mut self,
        cursor: &'a FinalizedBlockCursor,
        max_blocks: usize,
        verifier_profile: FinalityVerifierProfileId,
        coordinator_id: FinalityCoordinatorId,
    ) -> LedgerFuture<'a, Option<FinalityRangeIntentV2>, Self::Error>;

    fn is_available(&self) -> bool {
        true
    }
}

/// Crash-safe finality coordinator boundary.
///
/// `finalize_staged_range` may mutate coordinator trust state only after it
/// receives the private-constructor capability issued by committed Holder
/// storage. It must commit and read back every transition before returning the
/// exact durable range capabilities. If cancellation makes the coordinator
/// transition ambiguous, retry/recovery with the same staged intent must be
/// historically repeatable. `revalidate_durable_capability` authenticates a
/// persisted authority-free attestation without raw provider metadata.
pub trait FinalityVerifier: Send + Sync {
    type Error: std::error::Error + Send + Sync + 'static;

    fn profile_id(&self) -> FinalityVerifierProfileId;
    fn coordinator_id(&self) -> FinalityCoordinatorId;

    fn finalize_staged_range<'a>(
        &'a mut self,
        staged: &'a StagedFinalityRangeCapabilityV2,
    ) -> LedgerFuture<'a, FinalizedRangeCapabilityV2, Self::Error>;

    fn revalidate_durable_capability<'a>(
        &'a self,
        capability: &'a DurableBlockFinalityCapabilityV2,
    ) -> LedgerFuture<'a, (), Self::Error>;

    fn is_available(&self) -> bool {
        true
    }
}

/// Signed-v2 Ledger capability that always fails closed.
#[derive(Clone, Copy, Debug, Default)]
pub struct UnavailableSignedV2LedgerClient;

impl SignedV2LedgerClient for UnavailableSignedV2LedgerClient {
    type Error = CapabilityError;

    fn submit<'a>(&'a mut self, _proposal: &'a SignedProposalV2) -> LedgerFuture<'a, SubmissionStatus, Self::Error> {
        Box::pin(async { Err(CapabilityError::Unavailable) })
    }

    fn prepare_finalized_execution<'a>(
        &'a mut self,
        _cursor: &'a FinalizedBlockCursor,
        _max_blocks: usize,
        _verifier_profile: FinalityVerifierProfileId,
        _coordinator_id: FinalityCoordinatorId,
    ) -> LedgerFuture<'a, Option<FinalityRangeIntentV2>, Self::Error> {
        Box::pin(async { Err(CapabilityError::Unavailable) })
    }

    fn is_available(&self) -> bool {
        false
    }
}

/// Finality coordinator capability that always fails closed.
#[derive(Clone, Copy, Debug, Default)]
pub struct UnavailableFinalityVerifier;

impl FinalityVerifier for UnavailableFinalityVerifier {
    type Error = CapabilityError;

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
        Box::pin(async { Err(CapabilityError::Unavailable) })
    }

    fn revalidate_durable_capability<'a>(
        &'a self,
        _capability: &'a DurableBlockFinalityCapabilityV2,
    ) -> LedgerFuture<'a, (), Self::Error> {
        Box::pin(async { Err(CapabilityError::Unavailable) })
    }

    fn is_available(&self) -> bool {
        false
    }
}
