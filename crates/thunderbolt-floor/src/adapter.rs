use thunderbolt_keystore::{CheckpointCasOutcome, RollbackFloorStore, VaultCheckpoint, VaultIdentity};

use crate::{
    FinalityVerifierCapability, FinalizedFloorResponse, FinalizedFloorResult, FloorCasRequest, FloorLedgerChainId,
    FloorReadRequest, FloorRequestDigest, LedgerFinalityVerifier, LedgerFloorStoreError, LedgerFloorTransport,
    UnverifiedCasSubmission, UnverifiedLedgerResponse,
};

/// Ledger-backed exact checkpoint store with explicit transport and finality trust boundaries.
pub struct LedgerRollbackFloorStore<T, V> {
    transport: T,
    verifier: V,
    chain_id: FloorLedgerChainId,
}

impl<T, V> LedgerRollbackFloorStore<T, V> {
    /// Constructs an adapter pinned to one independent consensus chain.
    #[must_use]
    pub const fn new(transport: T, verifier: V, chain_id: FloorLedgerChainId) -> Self {
        Self {
            transport,
            verifier,
            chain_id,
        }
    }

    /// Returns the pinned floor Ledger chain identifier.
    #[must_use]
    pub const fn chain_id(&self) -> &FloorLedgerChainId {
        &self.chain_id
    }

    /// Borrows the transport implementation.
    #[must_use]
    pub const fn transport(&self) -> &T {
        &self.transport
    }

    /// Borrows the consensus-finality verifier.
    #[must_use]
    pub const fn verifier(&self) -> &V {
        &self.verifier
    }
}

impl<T, V> RollbackFloorStore for LedgerRollbackFloorStore<T, V>
where
    T: LedgerFloorTransport,
    V: LedgerFinalityVerifier<T::Receipt>,
{
    type Error = LedgerFloorStoreError<T::Error, V::Error>;

    fn load_checkpoint(&self, identity: VaultIdentity) -> std::result::Result<Option<VaultCheckpoint>, Self::Error> {
        let request = FloorReadRequest::new(&self.chain_id, identity);
        let response = self
            .transport
            .read_checkpoint(&request)
            .map_err(|error| LedgerFloorStoreError::Transport(Box::new(error)))?;
        let finalized = self.verify(response, request.digest(), identity)?;
        match finalized.result() {
            FinalizedFloorResult::Read { current } => Ok(current),
            FinalizedFloorResult::CompareAndSwap { .. } => Err(LedgerFloorStoreError::ResponseMismatch(
                "read request returned a CAS result",
            )),
        }
    }

    fn compare_and_swap_checkpoint(
        &self,
        identity: VaultIdentity,
        expected: Option<VaultCheckpoint>,
        next: VaultCheckpoint,
    ) -> std::result::Result<CheckpointCasOutcome, Self::Error> {
        let request =
            FloorCasRequest::new(&self.chain_id, identity, expected, next).map_err(LedgerFloorStoreError::Contract)?;
        let response = match self
            .transport
            .compare_and_swap(&request)
            .map_err(|error| LedgerFloorStoreError::Transport(Box::new(error)))?
        {
            UnverifiedCasSubmission::Response(response) => response,
            UnverifiedCasSubmission::Ambiguous(ambiguity) => self
                .transport
                .resolve_ambiguous_cas(&request, ambiguity)
                .map_err(|error| LedgerFloorStoreError::AmbiguousResolution(Box::new(error)))?,
        };
        let finalized = self.verify(response, request.digest(), identity)?;
        match finalized.result() {
            FinalizedFloorResult::Read { .. } => Err(LedgerFloorStoreError::ResponseMismatch(
                "CAS request returned a read result",
            )),
            FinalizedFloorResult::CompareAndSwap { current, applied } => {
                if applied && current != Some(next) {
                    return Err(LedgerFloorStoreError::ResponseMismatch(
                        "applied CAS did not finalize its exact candidate",
                    ));
                }
                if current == Some(next) {
                    if applied {
                        Ok(CheckpointCasOutcome::Advanced)
                    } else {
                        Ok(CheckpointCasOutcome::AlreadyCurrent)
                    }
                } else {
                    Ok(CheckpointCasOutcome::Conflict(current))
                }
            }
        }
    }
}

impl<T, V> LedgerRollbackFloorStore<T, V>
where
    T: LedgerFloorTransport,
    V: LedgerFinalityVerifier<T::Receipt>,
{
    fn verify(
        &self,
        response: UnverifiedLedgerResponse<T::Receipt>,
        request_digest: FloorRequestDigest,
        identity: VaultIdentity,
    ) -> std::result::Result<FinalizedFloorResponse, LedgerFloorStoreError<T::Error, V::Error>> {
        let finalized = self
            .verifier
            .verify(response, FinalityVerifierCapability::new())
            .map_err(|error| LedgerFloorStoreError::Finality(Box::new(error)))?;
        if finalized.finality().chain_id() != &self.chain_id {
            return Err(LedgerFloorStoreError::ResponseMismatch(
                "finality receipt belongs to a different consensus chain",
            ));
        }
        if finalized.request_digest() != request_digest {
            return Err(LedgerFloorStoreError::ResponseMismatch(
                "finality receipt does not bind the exact request digest",
            ));
        }
        if finalized.identity() != identity {
            return Err(LedgerFloorStoreError::ResponseMismatch(
                "finality receipt does not bind the complete vault identity",
            ));
        }
        Ok(finalized)
    }
}
