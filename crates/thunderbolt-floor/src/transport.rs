use std::error::Error;
use std::marker::PhantomData;

use thunderbolt_keystore::VaultIdentity;

use crate::{
    FinalizedFloorResponse, FinalizedFloorResult, FloorCasRequest, FloorFinalityAnchor, FloorReadRequest,
    FloorRequestDigest,
};

/// Opaque transport response that has not established consensus finality.
///
/// Possessing this value grants no authority. In particular, a locally
/// executed Thunderbolt block is not sufficient; the configured verifier must
/// validate a quorum certificate or trusted light-client proof.
pub struct UnverifiedLedgerResponse<R>(R);

impl<R> UnverifiedLedgerResponse<R> {
    /// Wraps an opaque receipt returned by a transport implementation.
    #[must_use]
    pub const fn new(receipt: R) -> Self {
        Self(receipt)
    }

    /// Consumes the wrapper at the finality-verifier boundary.
    #[must_use]
    pub fn into_receipt(self) -> R {
        self.0
    }
}

/// Unverified result of submitting an atomic floor compare-and-swap.
pub enum UnverifiedCasSubmission<R, A> {
    /// The transport returned an unverified execution/finality receipt.
    Response(UnverifiedLedgerResponse<R>),
    /// Submission may have committed; resolution must use this opaque token.
    Ambiguous(A),
}

/// One-use capability supplied only during finality verification.
///
/// `FinalizedFloorResponse` has no public constructor. A verifier can produce
/// it only by consuming this capability while handling an unverified receipt.
pub struct FinalityVerifierCapability<'a> {
    _marker: PhantomData<&'a mut ()>,
}

impl<'a> FinalityVerifierCapability<'a> {
    pub(crate) const fn new() -> Self {
        Self { _marker: PhantomData }
    }

    /// Finalizes claims after the verifier has checked consensus and inclusion.
    #[must_use]
    pub fn finalize(
        self,
        request_digest: FloorRequestDigest,
        identity: VaultIdentity,
        result: FinalizedFloorResult,
        finality: FloorFinalityAnchor,
    ) -> FinalizedFloorResponse {
        FinalizedFloorResponse::new(request_digest, identity, result, finality)
    }
}

/// Authenticated Ledger transport without any finality authority.
///
/// Implementations own RPC framing, mutual authentication, deadlines, and
/// retry policy. They must never turn an uncertain submission into a clean
/// transport error: uncertainty is returned as `Ambiguous` with a token that
/// `resolve_ambiguous_cas` can resolve causally.
pub trait LedgerFloorTransport: Send + Sync {
    /// Opaque Ledger receipt verified by `LedgerFinalityVerifier`.
    type Receipt;
    /// Opaque token identifying one potentially committed CAS submission.
    type AmbiguousCas;
    /// Non-secret transport error.
    type Error: Error + Send + Sync + 'static;

    /// Reads the current floor and returns an unverified finalized-state receipt.
    fn read_checkpoint(
        &self,
        request: &FloorReadRequest,
    ) -> std::result::Result<UnverifiedLedgerResponse<Self::Receipt>, Self::Error>;

    /// Submits one atomic CAS or returns an explicit ambiguity token.
    fn compare_and_swap(
        &self,
        request: &FloorCasRequest,
    ) -> std::result::Result<UnverifiedCasSubmission<Self::Receipt, Self::AmbiguousCas>, Self::Error>;

    /// Resolves one ambiguous submission with a causally ordered receipt.
    ///
    /// The returned receipt must prove the finalized result of this exact CAS,
    /// not merely a read that could have finalized before the pending write.
    fn resolve_ambiguous_cas(
        &self,
        request: &FloorCasRequest,
        ambiguity: Self::AmbiguousCas,
    ) -> std::result::Result<UnverifiedLedgerResponse<Self::Receipt>, Self::Error>;
}

/// Trust boundary for consensus-final floor receipts.
///
/// A production implementation owns pinned validator/trust-root state and must
/// validate quorum or light-client continuity, the configured consensus chain,
/// an execution height/time and app hash, the adjacent committing header, an
/// application-state inclusion proof against that app hash, and the exact floor
/// state-machine result. Returning a merely self-consistent `ExecutedBlockV2`
/// is forbidden. The verifier must maintain a monotonic trusted header and
/// reject receipts older than the latest trusted/finalized state, including an
/// otherwise valid historical receipt for the same request digest.
pub trait LedgerFinalityVerifier<R>: Send + Sync {
    /// Non-secret verification error.
    type Error: Error + Send + Sync + 'static;

    /// Verifies an opaque transport receipt into finalized floor claims.
    fn verify(
        &self,
        response: UnverifiedLedgerResponse<R>,
        capability: FinalityVerifierCapability<'_>,
    ) -> std::result::Result<FinalizedFloorResponse, Self::Error>;
}
