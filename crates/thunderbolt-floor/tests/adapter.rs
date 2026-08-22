use std::collections::VecDeque;
use std::error::Error;
use std::fmt;
use std::sync::Mutex;

use proptest::prelude::*;
use thunderbolt_floor::{
    CheckpointCasOutcome, FinalityVerifierCapability, FinalizedFloorResponse, FinalizedFloorResult, FloorCasRequest,
    FloorFinalityAnchor, FloorLedgerChainId, FloorReadRequest, FloorRequestDigest, LedgerFinalityVerifier,
    LedgerFloorStoreError, LedgerFloorTransport, LedgerRollbackFloorStore, RollbackFloorStore, UnverifiedCasSubmission,
    UnverifiedLedgerResponse, VaultCheckpoint, VaultIdentity,
};
use thunderbolt_keystore::{
    CommitteeDescriptorDigest, DeploymentBinding, DeploymentId, Network, NodeId, VaultRevision, VaultRole,
    VaultStateDigest,
};

#[derive(Debug)]
struct TestError(&'static str);

impl fmt::Display for TestError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.0)
    }
}

impl Error for TestError {}

#[derive(Clone, Copy)]
enum SubmitMode {
    Normal,
    AmbiguousApplied,
    AmbiguousRejected,
}

struct TestReceipt {
    request_digest: FloorRequestDigest,
    identity: VaultIdentity,
    result: FinalizedFloorResult,
    finality: FloorFinalityAnchor,
}

struct Ambiguity(TestReceipt);

struct TestTransport {
    chain_id: FloorLedgerChainId,
    state: Mutex<Option<VaultCheckpoint>>,
    modes: Mutex<VecDeque<SubmitMode>>,
    corrupt_identity: Mutex<Option<VaultIdentity>>,
}

impl TestTransport {
    fn new(chain_id: FloorLedgerChainId) -> Self {
        Self {
            chain_id,
            state: Mutex::new(None),
            modes: Mutex::new(VecDeque::new()),
            corrupt_identity: Mutex::new(None),
        }
    }

    fn push_mode(&self, mode: SubmitMode) {
        self.modes.lock().expect("test mode lock").push_back(mode);
    }

    fn corrupt_next_identity(&self, identity: VaultIdentity) {
        *self.corrupt_identity.lock().expect("test identity lock") = Some(identity);
    }

    fn identity_for(&self, requested: VaultIdentity) -> VaultIdentity {
        self.corrupt_identity
            .lock()
            .expect("test identity lock")
            .take()
            .unwrap_or(requested)
    }

    fn anchor(&self, height: u64) -> FloorFinalityAnchor {
        FloorFinalityAnchor::new(self.chain_id.clone(), height, 1_800_000_000_000, [0xa1; 32], [0xa2; 32])
            .expect("valid test finality anchor")
    }
}

impl LedgerFloorTransport for TestTransport {
    type Receipt = TestReceipt;
    type AmbiguousCas = Ambiguity;
    type Error = TestError;

    fn read_checkpoint(
        &self,
        request: &FloorReadRequest,
    ) -> Result<UnverifiedLedgerResponse<Self::Receipt>, Self::Error> {
        let current = *self.state.lock().map_err(|_| TestError("state lock"))?;
        Ok(UnverifiedLedgerResponse::new(TestReceipt {
            request_digest: request.digest(),
            identity: self.identity_for(request.identity()),
            result: FinalizedFloorResult::Read { current },
            finality: self.anchor(1),
        }))
    }

    fn compare_and_swap(
        &self,
        request: &FloorCasRequest,
    ) -> Result<UnverifiedCasSubmission<Self::Receipt, Self::AmbiguousCas>, Self::Error> {
        let mode = self
            .modes
            .lock()
            .map_err(|_| TestError("mode lock"))?
            .pop_front()
            .unwrap_or(SubmitMode::Normal);
        let mut state = self.state.lock().map_err(|_| TestError("state lock"))?;
        let applied = *state == request.expected() && !matches!(mode, SubmitMode::AmbiguousRejected);
        if applied {
            *state = Some(request.next());
        }
        let response = TestReceipt {
            request_digest: request.digest(),
            identity: self.identity_for(request.identity()),
            result: FinalizedFloorResult::CompareAndSwap {
                current: *state,
                applied,
            },
            finality: self.anchor(2),
        };
        if matches!(mode, SubmitMode::Normal) {
            Ok(UnverifiedCasSubmission::Response(UnverifiedLedgerResponse::new(
                response,
            )))
        } else {
            Ok(UnverifiedCasSubmission::Ambiguous(Ambiguity(response)))
        }
    }

    fn resolve_ambiguous_cas(
        &self,
        _request: &FloorCasRequest,
        ambiguity: Self::AmbiguousCas,
    ) -> Result<UnverifiedLedgerResponse<Self::Receipt>, Self::Error> {
        Ok(UnverifiedLedgerResponse::new(ambiguity.0))
    }
}

struct TestVerifier;

impl LedgerFinalityVerifier<TestReceipt> for TestVerifier {
    type Error = TestError;

    fn verify(
        &self,
        response: UnverifiedLedgerResponse<TestReceipt>,
        capability: FinalityVerifierCapability<'_>,
    ) -> Result<FinalizedFloorResponse, Self::Error> {
        let receipt = response.into_receipt();
        Ok(capability.finalize(
            receipt.request_digest,
            receipt.identity,
            receipt.result,
            receipt.finality,
        ))
    }
}

struct RejectVerifier;

impl LedgerFinalityVerifier<TestReceipt> for RejectVerifier {
    type Error = TestError;

    fn verify(
        &self,
        _response: UnverifiedLedgerResponse<TestReceipt>,
        _capability: FinalityVerifierCapability<'_>,
    ) -> Result<FinalizedFloorResponse, Self::Error> {
        Err(TestError("untrusted finality"))
    }
}

fn identity(node_byte: u8) -> VaultIdentity {
    let deployment = DeploymentBinding::new(
        DeploymentId::new([0xb1; 32]).expect("deployment"),
        3,
        CommitteeDescriptorDigest::new([0xb2; 32]).expect("descriptor"),
    )
    .expect("binding");
    VaultIdentity::new(
        Network::Signet,
        VaultRole::CommitteeMember,
        NodeId::new([node_byte; 32]),
        deployment,
    )
}

fn checkpoint(revision: u64, byte: u8) -> VaultCheckpoint {
    VaultCheckpoint::new(VaultRevision::new(revision), VaultStateDigest::new([byte; 32]))
}

#[test]
fn finalized_cas_is_exact_idempotent_and_fork_detecting() -> Result<(), Box<dyn Error>> {
    let chain_id = FloorLedgerChainId::new(b"thunderbolt-floor-test".to_vec())?;
    let store = LedgerRollbackFloorStore::new(TestTransport::new(chain_id.clone()), TestVerifier, chain_id);
    let identity = identity(0xc1);
    let initial = checkpoint(0, 0xc2);
    let next = checkpoint(1, 0xc3);
    let fork = checkpoint(1, 0xc4);

    assert_eq!(store.load_checkpoint(identity)?, None);
    assert_eq!(
        store.compare_and_swap_checkpoint(identity, None, initial)?,
        CheckpointCasOutcome::Advanced
    );
    assert_eq!(
        store.compare_and_swap_checkpoint(identity, None, initial)?,
        CheckpointCasOutcome::AlreadyCurrent
    );
    assert_eq!(
        store.compare_and_swap_checkpoint(identity, Some(initial), next)?,
        CheckpointCasOutcome::Advanced
    );
    assert_eq!(
        store.compare_and_swap_checkpoint(identity, Some(initial), fork)?,
        CheckpointCasOutcome::Conflict(Some(next))
    );
    Ok(())
}

#[test]
fn ambiguous_submission_resolves_applied_and_rejected_outcomes() -> Result<(), Box<dyn Error>> {
    let chain_id = FloorLedgerChainId::new(b"thunderbolt-floor-ambiguous".to_vec())?;
    let transport = TestTransport::new(chain_id.clone());
    transport.push_mode(SubmitMode::AmbiguousApplied);
    transport.push_mode(SubmitMode::AmbiguousRejected);
    let store = LedgerRollbackFloorStore::new(transport, TestVerifier, chain_id);
    let identity = identity(0xd1);
    let initial = checkpoint(0, 0xd2);
    let next = checkpoint(1, 0xd3);

    assert_eq!(
        store.compare_and_swap_checkpoint(identity, None, initial)?,
        CheckpointCasOutcome::Advanced
    );
    assert_eq!(
        store.compare_and_swap_checkpoint(identity, Some(initial), next)?,
        CheckpointCasOutcome::Conflict(Some(initial))
    );
    Ok(())
}

#[test]
fn finalized_response_must_bind_complete_identity() -> Result<(), Box<dyn Error>> {
    let chain_id = FloorLedgerChainId::new(b"thunderbolt-floor-binding".to_vec())?;
    let transport = TestTransport::new(chain_id.clone());
    transport.corrupt_next_identity(identity(0xe2));
    let store = LedgerRollbackFloorStore::new(transport, TestVerifier, chain_id);
    let error = store
        .load_checkpoint(identity(0xe1))
        .expect_err("mismatched finalized identity must fail");
    assert!(matches!(error, LedgerFloorStoreError::ResponseMismatch(_)));
    Ok(())
}

#[test]
fn unverified_or_wrong_chain_receipts_fail_closed() -> Result<(), Box<dyn Error>> {
    let receipt_chain = FloorLedgerChainId::new(b"floor-receipt-chain".to_vec())?;
    let configured_chain = FloorLedgerChainId::new(b"floor-configured-chain".to_vec())?;
    let rejected = LedgerRollbackFloorStore::new(
        TestTransport::new(receipt_chain.clone()),
        RejectVerifier,
        receipt_chain.clone(),
    );
    assert!(matches!(
        rejected.load_checkpoint(identity(0xe3)),
        Err(LedgerFloorStoreError::Finality(_))
    ));

    let wrong_chain = LedgerRollbackFloorStore::new(TestTransport::new(receipt_chain), TestVerifier, configured_chain);
    assert!(matches!(
        wrong_chain.load_checkpoint(identity(0xe4)),
        Err(LedgerFloorStoreError::ResponseMismatch(_))
    ));
    Ok(())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn ambiguous_resolution_and_same_revision_forks_fail_closed(
        initial_byte in any::<u8>(),
        next_byte in any::<u8>(),
        fork_byte in any::<u8>(),
        ambiguity_applies in any::<bool>(),
    ) {
        let next_byte = if next_byte == initial_byte { next_byte ^ 1 } else { next_byte };
        let fork_byte = if fork_byte == next_byte { fork_byte ^ 0x80 } else { fork_byte };
        let chain_id = FloorLedgerChainId::new(b"thunderbolt-floor-property".to_vec())?;
        let transport = TestTransport::new(chain_id.clone());
        transport.push_mode(if ambiguity_applies {
            SubmitMode::AmbiguousApplied
        } else {
            SubmitMode::AmbiguousRejected
        });
        let store = LedgerRollbackFloorStore::new(transport, TestVerifier, chain_id);
        let identity = identity(0xf1);
        let initial = checkpoint(0, initial_byte);
        let next = checkpoint(1, next_byte);
        let fork = checkpoint(1, fork_byte);
        prop_assert_eq!(
            store.compare_and_swap_checkpoint(identity, None, initial)?,
            if ambiguity_applies {
                CheckpointCasOutcome::Advanced
            } else {
                CheckpointCasOutcome::Conflict(None)
            }
        );
        if !ambiguity_applies {
            prop_assert_eq!(store.load_checkpoint(identity)?, None);
            return Ok(());
        }

        prop_assert_eq!(
            store.compare_and_swap_checkpoint(identity, Some(initial), next)?,
            CheckpointCasOutcome::Advanced
        );
        prop_assert_eq!(
            store.compare_and_swap_checkpoint(identity, Some(initial), fork)?,
            CheckpointCasOutcome::Conflict(Some(next))
        );
    }
}
