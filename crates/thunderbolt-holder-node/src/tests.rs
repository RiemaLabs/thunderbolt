use std::collections::BTreeMap;
use std::error::Error;
use std::future::{pending, Future};
use std::path::Path;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Wake, Waker};
use std::time::Duration;

use bitcoin::Network;
use secp256k1::{Keypair, Secp256k1, SecretKey};
use sha2::{Digest as _, Sha256};
use tempfile::TempDir;
use thunderbolt_holder::{holder_keystore_identity, HolderEngine, HolderIdentity, KeystoreSecretVault};
use thunderbolt_keystore::{
    CheckpointCasOutcome, CommitteeDescriptorDigest, KdfParams, NodeId, Password, RollbackFloorStore, VaultCheckpoint,
    VaultIdentity, MIN_ARGON2_ITERATIONS, MIN_ARGON2_MEMORY_KIB,
};
use thunderbolt_ledger::{
    ActorPublicKeyV2, ActorRoleV2, ActorSignatureV2, AppHashV2, ClientRequestNonceV2, EntryHashV2, ExecutedBlockV2,
    LedgerChainIdV2, PendingBlockV2, ProposalDigestV2, SignedProposalV2,
};
use thunderbolt_protocol::v2::ArtifactV2;
use thunderbolt_protocol::v2::{ChannelEventV2, OpenEventV2};
use thunderbolt_wire::{
    AnchorParameterSuiteIdV2, BitcoinGenesisHashV2, ChannelBindingV2, CommitteeDescriptorDigestV2, FundingOutpointV2,
    ProtocolSuiteIdV2,
};

use super::*;

#[derive(Clone, Default)]
struct TestFloor {
    state: Arc<Mutex<Option<(VaultIdentity, VaultCheckpoint)>>>,
}

#[derive(Debug, thiserror::Error)]
#[error("test floor failure")]
struct TestFloorError;

impl RollbackFloorStore for TestFloor {
    type Error = TestFloorError;

    fn load_checkpoint(&self, identity: VaultIdentity) -> std::result::Result<Option<VaultCheckpoint>, Self::Error> {
        let state = self.state.lock().map_err(|_| TestFloorError)?;
        Ok(state
            .as_ref()
            .and_then(|(stored, checkpoint)| (*stored == identity).then_some(*checkpoint)))
    }

    fn compare_and_swap_checkpoint(
        &self,
        identity: VaultIdentity,
        expected: Option<VaultCheckpoint>,
        next: VaultCheckpoint,
    ) -> std::result::Result<CheckpointCasOutcome, Self::Error> {
        let mut state = self.state.lock().map_err(|_| TestFloorError)?;
        if state.as_ref().is_some_and(|(stored, _)| *stored != identity) {
            return Ok(CheckpointCasOutcome::Conflict(None));
        }
        let current = state.as_ref().map(|(_, checkpoint)| *checkpoint);
        if current == Some(next) {
            return Ok(CheckpointCasOutcome::AlreadyCurrent);
        }
        let valid = match (current, expected) {
            (None, None) => next.revision().get() == 0,
            (Some(current), Some(expected)) if current == expected => current
                .revision()
                .get()
                .checked_add(1)
                .is_some_and(|revision| revision == next.revision().get()),
            _ => false,
        };
        if !valid {
            return Ok(CheckpointCasOutcome::Conflict(current));
        }
        *state = Some((identity, next));
        Ok(CheckpointCasOutcome::Advanced)
    }
}

#[derive(Debug, thiserror::Error)]
#[error("mock signer failure")]
struct MockSignerError;

struct MockSigner {
    keypair: Keypair,
    public_key: ActorPublicKeyV2,
}

impl MockSigner {
    fn new(tag: u8) -> std::result::Result<Self, Box<dyn Error>> {
        let secret = SecretKey::from_byte_array([tag; 32])?;
        let keypair = Keypair::from_secret_key(&Secp256k1::signing_only(), &secret);
        let (public, _) = keypair.x_only_public_key();
        Ok(Self {
            keypair,
            public_key: ActorPublicKeyV2::from_bytes(public.serialize())?,
        })
    }
}

impl ActorSigner for MockSigner {
    type Error = MockSignerError;

    fn public_key(&self) -> std::result::Result<&ActorPublicKeyV2, Self::Error> {
        Ok(&self.public_key)
    }

    fn sign(&mut self, digest: &ProposalDigestV2) -> std::result::Result<ActorSignatureV2, Self::Error> {
        let signature = Secp256k1::signing_only().sign_schnorr_no_aux_rand(digest.as_bytes(), &self.keypair);
        ActorSignatureV2::from_bytes(signature.to_byte_array()).map_err(|_| MockSignerError)
    }
}

#[derive(Debug, thiserror::Error)]
#[error("mock Ledger failure")]
struct MockLedgerError;

#[derive(Default)]
struct MockLedgerState {
    submitted: BTreeMap<[u8; 32], SignedProposalV2>,
    blocks: Vec<ExecutedBlockV2>,
    pending_submit_after_accept_once: bool,
    pending_prepare_once: bool,
}

#[derive(Clone, Default)]
struct MockLedger {
    state: Arc<Mutex<MockLedgerState>>,
}

impl MockLedger {
    fn pending_submit_after_accept_once(&self) -> std::result::Result<(), MockLedgerError> {
        self.state
            .lock()
            .map_err(|_| MockLedgerError)?
            .pending_submit_after_accept_once = true;
        Ok(())
    }

    fn pending_prepare_once(&self) -> std::result::Result<(), MockLedgerError> {
        self.state.lock().map_err(|_| MockLedgerError)?.pending_prepare_once = true;
        Ok(())
    }

    fn submitted_request(
        &self,
        request: &thunderbolt_ledger::RequestDigestV2,
    ) -> std::result::Result<SignedProposalV2, MockLedgerError> {
        self.state
            .lock()
            .map_err(|_| MockLedgerError)?
            .submitted
            .get(request.as_bytes())
            .cloned()
            .ok_or(MockLedgerError)
    }

    fn push_block(&self, block: ExecutedBlockV2) -> std::result::Result<(), MockLedgerError> {
        self.state.lock().map_err(|_| MockLedgerError)?.blocks.push(block);
        Ok(())
    }
}

impl SignedV2LedgerClient for MockLedger {
    type Error = MockLedgerError;

    fn submit<'a>(&'a mut self, proposal: &'a SignedProposalV2) -> LedgerFuture<'a, SubmissionStatus, Self::Error> {
        let state = self.state.lock();
        let Ok(mut state) = state else {
            return Box::pin(async { Err(MockLedgerError) });
        };
        let request = *proposal.body().request_id().digest().as_bytes();
        let status = if let Some(existing) = state.submitted.get(&request) {
            if existing != proposal {
                return Box::pin(async { Err(MockLedgerError) });
            }
            SubmissionStatus::AlreadyKnown
        } else {
            state.submitted.insert(request, proposal.clone());
            SubmissionStatus::Accepted
        };
        if state.pending_submit_after_accept_once {
            state.pending_submit_after_accept_once = false;
            return Box::pin(pending());
        }
        Box::pin(async move { Ok(status) })
    }

    fn prepare_finalized_execution<'a>(
        &'a mut self,
        cursor: &'a FinalizedBlockCursor,
        max_blocks: usize,
        verifier_profile: FinalityVerifierProfileId,
        coordinator_id: FinalityCoordinatorId,
    ) -> LedgerFuture<'a, Option<FinalityRangeIntentV2>, Self::Error> {
        let state = self.state.lock();
        let Ok(mut state) = state else {
            return Box::pin(async { Err(MockLedgerError) });
        };
        if state.pending_prepare_once {
            state.pending_prepare_once = false;
            return Box::pin(pending());
        }
        let Some(position) = state
            .blocks
            .iter()
            .position(|block| block.height() == cursor.next_height())
        else {
            return Box::pin(async { Ok(None) });
        };
        let blocks = state.blocks[position..]
            .iter()
            .take(max_blocks)
            .cloned()
            .collect::<Vec<_>>();
        let Some(last) = blocks.last() else {
            return Box::pin(async { Err(MockLedgerError) });
        };
        let next_height = last.height().saturating_add(1);
        let next_app_hash = last.app_hash().clone();
        let intent = FinalityRangeIntentV2::new(
            verifier_profile,
            coordinator_id,
            cursor.ledger_chain_id().clone(),
            cursor.next_height(),
            cursor.expected_previous_app_hash().clone(),
            blocks,
            next_height,
            next_app_hash,
        )
        .map_err(|_| MockLedgerError);
        Box::pin(async move { intent.map(Some) })
    }
}

#[derive(Default)]
struct MockFinalityState {
    committed: BTreeMap<[u8; 32], Vec<DurableBlockFinalityCapabilityV2>>,
    pending_before_commit_once: bool,
    pending_after_first_commit_once: bool,
    reject_revalidation: bool,
    finalize_calls: usize,
}

#[derive(Clone)]
struct MockFinalityVerifier {
    profile: FinalityVerifierProfileId,
    coordinator: FinalityCoordinatorId,
    state: Arc<Mutex<MockFinalityState>>,
}

impl MockFinalityVerifier {
    fn new(profile: FinalityVerifierProfileId, coordinator: FinalityCoordinatorId) -> Self {
        Self {
            profile,
            coordinator,
            state: Arc::new(Mutex::new(MockFinalityState::default())),
        }
    }

    fn pending_before_commit_once(&self) -> std::result::Result<(), MockLedgerError> {
        self.state
            .lock()
            .map_err(|_| MockLedgerError)?
            .pending_before_commit_once = true;
        Ok(())
    }

    fn pending_after_first_commit_once(&self) -> std::result::Result<(), MockLedgerError> {
        self.state
            .lock()
            .map_err(|_| MockLedgerError)?
            .pending_after_first_commit_once = true;
        Ok(())
    }

    fn reject_revalidation(&self, reject: bool) -> std::result::Result<(), MockLedgerError> {
        self.state.lock().map_err(|_| MockLedgerError)?.reject_revalidation = reject;
        Ok(())
    }

    fn committed_count(&self, stage: &[u8; 32]) -> std::result::Result<usize, MockLedgerError> {
        Ok(self
            .state
            .lock()
            .map_err(|_| MockLedgerError)?
            .committed
            .get(stage)
            .map_or(0, Vec::len))
    }
}

impl FinalityVerifier for MockFinalityVerifier {
    type Error = MockLedgerError;

    fn profile_id(&self) -> FinalityVerifierProfileId {
        self.profile
    }

    fn coordinator_id(&self) -> FinalityCoordinatorId {
        self.coordinator
    }

    fn finalize_staged_range<'a>(
        &'a mut self,
        staged: &'a StagedFinalityRangeCapabilityV2,
    ) -> LedgerFuture<'a, FinalizedRangeCapabilityV2, Self::Error> {
        let state = self.state.lock();
        let Ok(mut state) = state else {
            return Box::pin(async { Err(MockLedgerError) });
        };
        state.finalize_calls = state.finalize_calls.saturating_add(1);
        if staged.intent().verifier_profile() != self.profile || staged.intent().coordinator_id() != self.coordinator {
            return Box::pin(async { Err(MockLedgerError) });
        }
        if state.pending_before_commit_once {
            state.pending_before_commit_once = false;
            return Box::pin(pending());
        }
        let mut capabilities = state.committed.get(staged.stage_digest()).cloned().unwrap_or_default();
        while capabilities.len() < staged.intent().blocks().len() {
            let index = capabilities.len();
            let block = match staged.intent().blocks().get(index) {
                Some(block) => block,
                None => return Box::pin(async { Err(MockLedgerError) }),
            };
            let capability = match mock_capability(self.profile, self.coordinator, staged.stage_digest(), block) {
                Ok(capability) => capability,
                Err(_) => return Box::pin(async { Err(MockLedgerError) }),
            };
            capabilities.push(capability);
            state.committed.insert(*staged.stage_digest(), capabilities.clone());
            if state.pending_after_first_commit_once && capabilities.len() == 1 {
                state.pending_after_first_commit_once = false;
                return Box::pin(pending());
            }
        }
        let finalized = FinalizedRangeCapabilityV2::new(staged, capabilities).map_err(|_| MockLedgerError);
        Box::pin(async move { finalized })
    }

    fn revalidate_durable_capability<'a>(
        &'a self,
        capability: &'a DurableBlockFinalityCapabilityV2,
    ) -> LedgerFuture<'a, (), Self::Error> {
        let state = self.state.lock();
        let Ok(state) = state else {
            return Box::pin(async { Err(MockLedgerError) });
        };
        let valid = !state.reject_revalidation
            && capability.verifier_profile() == self.profile
            && capability.coordinator_id() == self.coordinator
            && capability.verifier_digest().as_bytes() == &mock_capability_digest(capability);
        Box::pin(async move { valid.then_some(()).ok_or(MockLedgerError) })
    }
}

fn mock_capability(
    profile: FinalityVerifierProfileId,
    coordinator: FinalityCoordinatorId,
    stage_digest: &[u8; 32],
    block: &ExecutedBlockV2,
) -> Result<DurableBlockFinalityCapabilityV2> {
    let mut attestation = Vec::with_capacity(72);
    attestation.extend_from_slice(stage_digest);
    attestation.extend_from_slice(&block.height().to_be_bytes());
    attestation.extend_from_slice(block.app_hash().as_bytes());
    let prototype = DurableBlockFinalityCapabilityV2::new(
        profile,
        coordinator,
        block.ledger_chain_id().clone(),
        block.height(),
        block.app_hash().clone(),
        FinalityDigestV2::new([0x01; 32])?,
        attestation.clone(),
    )?;
    DurableBlockFinalityCapabilityV2::new(
        profile,
        coordinator,
        block.ledger_chain_id().clone(),
        block.height(),
        block.app_hash().clone(),
        FinalityDigestV2::new(mock_capability_digest(&prototype))?,
        attestation,
    )
}

fn mock_capability_digest(capability: &DurableBlockFinalityCapabilityV2) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"holder-node/mock-finality/v1");
    hasher.update(capability.verifier_profile().as_bytes());
    hasher.update(capability.coordinator_id().as_bytes());
    hasher.update(capability.ledger_chain_id().as_bytes());
    hasher.update(capability.block_height().to_be_bytes());
    hasher.update(capability.app_hash().as_bytes());
    hasher.update((capability.attestation().len() as u64).to_be_bytes());
    hasher.update(capability.attestation());
    hasher.finalize().into()
}

type TestService = HolderRoleService<
    TestFloor,
    MockLedger,
    MockFinalityVerifier,
    MockSigner,
    UnavailableBitcoinSettlement,
    UnavailableThresholdSigner,
>;

fn profile(tag: u8) -> Result<FinalityVerifierProfileId> {
    FinalityVerifierProfileId::new([tag; 32])
}

fn coordinator(tag: u8) -> Result<FinalityCoordinatorId> {
    FinalityCoordinatorId::new([tag; 32])
}

fn password() -> std::result::Result<Password, Box<dyn Error>> {
    Ok(Password::from_bytes(b"holder node test password".to_vec())?)
}

fn params() -> std::result::Result<KdfParams, Box<dyn Error>> {
    Ok(KdfParams::new(MIN_ARGON2_MEMORY_KIB, MIN_ARGON2_ITERATIONS, 1)?)
}

fn vault_identity(tag: u8) -> std::result::Result<VaultIdentity, Box<dyn Error>> {
    Ok(holder_keystore_identity(
        Network::Regtest,
        b"holder-node-test",
        7,
        CommitteeDescriptorDigest::new([0x44; 32])?,
        NodeId::new([tag; 32]),
    )?)
}

fn holder_engine(
    path: &Path,
    tag: u8,
    floor: TestFloor,
    create: bool,
) -> std::result::Result<HolderEngine<KeystoreSecretVault<TestFloor>>, Box<dyn Error>> {
    let adapter = if create {
        KeystoreSecretVault::create(path, vault_identity(tag)?, password()?, params()?, floor)?
    } else {
        KeystoreSecretVault::open_with_floor_store(path, vault_identity(tag)?, password()?, floor)?
    };
    let mut holder = HolderEngine::new(adapter);
    if create {
        let _ = holder.initialize()?;
    }
    Ok(holder)
}

fn ledger_chain() -> std::result::Result<LedgerChainIdV2, Box<dyn Error>> {
    Ok(LedgerChainIdV2::new("holder-node-regtest")?)
}

fn config_with(
    verifier_profile: FinalityVerifierProfileId,
    coordinator_id: FinalityCoordinatorId,
) -> std::result::Result<HolderNodeConfig, Box<dyn Error>> {
    Ok(HolderNodeConfig::new(
        Network::Regtest,
        ledger_chain()?,
        verifier_profile,
        coordinator_id,
        HolderDeploymentPolicy::from_channel(&channel(5)?)?,
        RetryPolicy {
            initial_delay_ms: 10,
            maximum_delay_ms: 100,
            maximum_attempts: 3,
        },
        8,
        8,
        Duration::from_secs(1),
    )?)
}

fn config() -> std::result::Result<HolderNodeConfig, Box<dyn Error>> {
    config_with(profile(0x91)?, coordinator(0x92)?)
}

fn channel(tag: u8) -> std::result::Result<ChannelBindingV2, Box<dyn Error>> {
    Ok(ChannelBindingV2::new(
        ProtocolSuiteIdV2::from_bytes([0x11; 32])?,
        Network::Regtest,
        BitcoinGenesisHashV2::for_network(Network::Regtest)?,
        b"holder-node-test",
        FundingOutpointV2::new([tag; 32], u32::from(tag))?,
        7,
        CommitteeDescriptorDigestV2::from_bytes([0x22; 32])?,
        AnchorParameterSuiteIdV2::from_bytes([0x33; 32])?,
    )?)
}

fn queue_request(
    command_tag: u8,
    nonce_tag: u8,
    now_ms: u64,
) -> std::result::Result<QueueProposalRequest, Box<dyn Error>> {
    Ok(QueueProposalRequest {
        command_id: CommandId::from_bytes([command_tag; 32]),
        channel: channel(5)?,
        sequence: 0,
        previous_entry_hash: EntryHashV2::zero(),
        request_nonce: ClientRequestNonceV2::from_bytes([nonce_tag; 16])?,
        actor_role: ActorRoleV2::Holder,
        event: ChannelEventV2::Open(OpenEventV2 {
            committee_member_count: 3,
            committee_threshold: 2,
            capacity_sat: 50_000,
            lock_key: ArtifactV2::new(vec![0x41; 33])?,
            initial_holder_anchor: ArtifactV2::new(vec![0x42; 33])?,
            initial_holder_ciphertext: ArtifactV2::new(vec![0x43; 64])?,
            open_proof: ArtifactV2::new(vec![0x44; 64])?,
        }),
        now_ms,
    })
}

#[allow(clippy::too_many_arguments)]
fn create_service_at(
    directory: &TempDir,
    database_path: &Path,
    floor: TestFloor,
    ledger: MockLedger,
    verifier: MockFinalityVerifier,
    create_vault: bool,
    node_config: HolderNodeConfig,
    expected_recovery: Option<&StagedFinalityRecoveryV2>,
) -> std::result::Result<TestService, Box<dyn Error>> {
    let durable_database_path = std::fs::canonicalize(database_path.parent().ok_or("database path has no parent")?)?
        .join(database_path.file_name().ok_or("database path has no file name")?);
    Ok(block_on(HolderRoleService::open(
        holder_engine(&directory.path().join("holder.vault"), 0x51, floor, create_vault)?,
        ledger,
        verifier,
        MockSigner::new(0x21)?,
        UnavailableBitcoinSettlement,
        UnavailableThresholdSigner,
        durable_database_path,
        node_config,
        expected_recovery,
    ))?)
}

fn create_service(
    directory: &TempDir,
    floor: TestFloor,
    ledger: MockLedger,
    verifier: MockFinalityVerifier,
    create_vault: bool,
    expected_recovery: Option<&StagedFinalityRecoveryV2>,
) -> std::result::Result<TestService, Box<dyn Error>> {
    create_service_at(
        directory,
        &durable_database_path(directory, "holder-node.db")?,
        floor,
        ledger,
        verifier,
        create_vault,
        config()?,
        expected_recovery,
    )
}

fn recovery_identity(
    directory: &TempDir,
    floor: TestFloor,
) -> std::result::Result<(HolderIdentity, ActorPublicKeyV2), Box<dyn Error>> {
    let mut holder = holder_engine(&directory.path().join("holder.vault"), 0x51, floor, false)?;
    let identity = holder.identity()?;
    let signer = MockSigner::new(0x21)?;
    Ok((identity, signer.public_key))
}

fn inspect_recovery(
    directory: &TempDir,
    floor: TestFloor,
) -> std::result::Result<Option<StagedFinalityRecoveryV2>, Box<dyn Error>> {
    let (identity, actor_key) = recovery_identity(directory, floor)?;
    Ok(inspect_staged_finality_recovery(
        durable_database_path(directory, "holder-node.db")?,
        &config()?,
        &identity,
        &actor_key,
    )?)
}

fn durable_database_path(
    directory: &TempDir,
    file_name: &str,
) -> std::result::Result<std::path::PathBuf, Box<dyn Error>> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(std::fs::canonicalize(directory.path())?.join(file_name))
}

fn block(
    height: u64,
    block_time_ms: u64,
    previous: AppHashV2,
    proposals: Vec<SignedProposalV2>,
) -> std::result::Result<ExecutedBlockV2, Box<dyn Error>> {
    let mut pending = PendingBlockV2::new(ledger_chain()?, height, block_time_ms, previous)?;
    for proposal in proposals {
        pending.push(proposal)?;
    }
    Ok(pending.execute()?)
}

#[derive(Debug)]
struct TestWake;

impl Wake for TestWake {
    fn wake(self: Arc<Self>) {}
}

fn test_waker() -> Waker {
    Waker::from(Arc::new(TestWake))
}

fn block_on<F: Future>(future: F) -> F::Output {
    let mut future = Box::pin(future);
    let waker = test_waker();
    let mut context = Context::from_waker(&waker);
    loop {
        match future.as_mut().poll(&mut context) {
            Poll::Ready(output) => return output,
            Poll::Pending => std::thread::yield_now(),
        }
    }
}

fn assert_pending<F: Future>(future: Pin<&mut F>) {
    let waker = test_waker();
    let mut context = Context::from_waker(&waker);
    assert!(matches!(future.poll(&mut context), Poll::Pending));
}

#[test]
fn configuration_and_missing_capabilities_fail_closed() -> std::result::Result<(), Box<dyn Error>> {
    assert!(FinalityVerifierProfileId::new([0; 32]).is_err());
    assert!(FinalityCoordinatorId::new([0; 32]).is_err());
    assert!(config_with(FinalityVerifierProfileId::DISABLED, coordinator(1)?).is_err());
    assert!(!UnavailableSignedV2LedgerClient.is_available());
    assert!(!UnavailableFinalityVerifier.is_available());

    let directory = TempDir::new()?;
    let result = block_on(HolderRoleService::open(
        holder_engine(&directory.path().join("holder.vault"), 0x51, TestFloor::default(), true)?,
        UnavailableSignedV2LedgerClient,
        UnavailableFinalityVerifier,
        MockSigner::new(0x21)?,
        UnavailableBitcoinSettlement,
        UnavailableThresholdSigner,
        directory.path().join("holder-node.db"),
        config()?,
        None,
    ));
    assert!(matches!(result, Err(HolderNodeError::CapabilityUnavailable)));
    Ok(())
}

#[test]
fn cancellation_after_stage_commit_restarts_from_exact_handoff() -> std::result::Result<(), Box<dyn Error>> {
    let directory = TempDir::new()?;
    let floor = TestFloor::default();
    let ledger = MockLedger::default();
    let verifier = MockFinalityVerifier::new(profile(0x91)?, coordinator(0x92)?);
    let mut service = create_service(&directory, floor.clone(), ledger.clone(), verifier.clone(), true, None)?;
    service.start()?;
    let queued = service.queue_proposal(queue_request(0x11, 0x12, 1_000)?)?;
    let _ = block_on(service.run_once(1_000))?;
    let proposal = ledger.submitted_request(&queued.request_digest)?;
    ledger.push_block(block(1, 2_000, AppHashV2::zero(), vec![proposal])?)?;
    verifier.pending_before_commit_once()?;

    let mut run = Box::pin(service.run_once(1_001));
    assert_pending(run.as_mut());
    drop(run);
    let status = service.status()?;
    assert_eq!(status.finalized_block_cursor.next_height(), 1);
    assert_eq!(status.outbox_submitted, 1);
    assert!(status.staged_finality_range.is_some());
    drop(service);

    let recovery = inspect_recovery(&directory, floor.clone())?.ok_or("missing recovery handoff")?;
    assert_eq!(recovery.intent().start_height(), 1);
    assert_eq!(recovery.intent().blocks().len(), 1);
    let mut service = create_service(&directory, floor, ledger, verifier, false, Some(&recovery))?;
    service.start()?;
    assert!(service.status()?.recovered_unclean_shutdown);
    assert_eq!(block_on(service.run_once(1_002))?.finalized, 1);
    let status = service.status()?;
    assert_eq!(status.finalized_block_cursor.next_height(), 2);
    assert!(status.staged_finality_range.is_none());
    assert_eq!(status.outbox_finalized, 1);
    Ok(())
}

#[test]
fn partial_coordinator_commit_cancels_without_partial_role_progress() -> std::result::Result<(), Box<dyn Error>> {
    let directory = TempDir::new()?;
    let floor = TestFloor::default();
    let ledger = MockLedger::default();
    let verifier = MockFinalityVerifier::new(profile(0x91)?, coordinator(0x92)?);
    let mut service = create_service(&directory, floor.clone(), ledger.clone(), verifier.clone(), true, None)?;
    service.start()?;
    let first = block(1, 3_000, AppHashV2::zero(), Vec::new())?;
    let second = block(2, 3_001, first.app_hash().clone(), Vec::new())?;
    ledger.push_block(first)?;
    ledger.push_block(second.clone())?;
    verifier.pending_after_first_commit_once()?;

    let mut run = Box::pin(service.run_once(2_000));
    assert_pending(run.as_mut());
    drop(run);
    let status = service.status()?;
    let stage_digest = status.staged_finality_range.ok_or("missing staged range")?;
    assert_eq!(verifier.committed_count(&stage_digest)?, 1);
    assert_eq!(status.finalized_block_cursor.next_height(), 1);
    drop(service);

    let recovery = inspect_recovery(&directory, floor.clone())?.ok_or("missing recovery handoff")?;
    assert_eq!(recovery.intent().blocks().len(), 2);
    assert_eq!(recovery.intent().next_height(), 3);
    let mut service = create_service(&directory, floor, ledger, verifier.clone(), false, Some(&recovery))?;
    service.start()?;
    assert_eq!(block_on(service.run_once(2_001))?.finalized, 0);
    let status = service.status()?;
    assert_eq!(status.finalized_block_cursor.next_height(), 3);
    assert_eq!(
        status.finalized_block_cursor.expected_previous_app_hash(),
        second.app_hash()
    );
    assert_eq!(
        status
            .finalized_block_cursor
            .last_finality()
            .map(|value| value.block_height()),
        Some(2)
    );
    assert!(status.staged_finality_range.is_none());
    assert_eq!(verifier.committed_count(recovery.stage_digest())?, 2);
    Ok(())
}

#[test]
fn stale_inspection_handoff_fails_open_toctou_check() -> std::result::Result<(), Box<dyn Error>> {
    let directory = TempDir::new()?;
    let floor = TestFloor::default();
    let ledger = MockLedger::default();
    let verifier = MockFinalityVerifier::new(profile(0x91)?, coordinator(0x92)?);
    let mut service = create_service(&directory, floor.clone(), ledger.clone(), verifier.clone(), true, None)?;
    service.start()?;
    ledger.push_block(block(1, 4_000, AppHashV2::zero(), Vec::new())?)?;
    verifier.pending_before_commit_once()?;
    let mut run = Box::pin(service.run_once(3_000));
    assert_pending(run.as_mut());
    drop(run);
    drop(service);
    let recovery = inspect_recovery(&directory, floor.clone())?.ok_or("missing handoff")?;

    let replacement_block = block(1, 4_001, AppHashV2::zero(), Vec::new())?;
    let replacement = FinalityRangeIntentV2::new(
        profile(0x91)?,
        coordinator(0x92)?,
        ledger_chain()?,
        1,
        AppHashV2::zero(),
        vec![replacement_block.clone()],
        2,
        replacement_block.app_hash().clone(),
    )?;
    let replacement_json = replacement.canonical_bytes()?;
    let mut stage_hasher = Sha256::new();
    stage_hasher.update(b"bitcoin-thunderbolt/holder/staged-finality-range/v2");
    stage_hasher.update(recovery.store_identity());
    stage_hasher.update(recovery.file_identity());
    stage_hasher.update((replacement_json.len() as u64).to_be_bytes());
    stage_hasher.update(&replacement_json);
    let replacement_digest: [u8; 32] = stage_hasher.finalize().into();
    let connection = rusqlite::Connection::open(durable_database_path(&directory, "holder-node.db")?)?;
    connection.execute(
        "UPDATE staged_finality_range
         SET stage_digest=?1,intent_length=?2,intent_json=?3 WHERE singleton=1",
        rusqlite::params![
            replacement_digest.as_slice(),
            i64::try_from(replacement_json.len())?,
            replacement_json,
        ],
    )?;
    drop(connection);
    assert!(create_service(&directory, floor, ledger, verifier, false, Some(&recovery),).is_err());
    Ok(())
}

#[test]
fn remote_submission_cancellation_replays_after_restart() -> std::result::Result<(), Box<dyn Error>> {
    let directory = TempDir::new()?;
    let floor = TestFloor::default();
    let ledger = MockLedger::default();
    let verifier = MockFinalityVerifier::new(profile(0x91)?, coordinator(0x92)?);
    let mut service = create_service(&directory, floor.clone(), ledger.clone(), verifier.clone(), true, None)?;
    service.start()?;
    let _ = service.queue_proposal(queue_request(0x21, 0x22, 4_000)?)?;
    ledger.pending_submit_after_accept_once()?;
    let mut run = Box::pin(service.run_once(4_000));
    assert_pending(run.as_mut());
    drop(run);
    assert_eq!(service.status()?.outbox_queued, 1);
    drop(service);

    let mut service = create_service(&directory, floor, ledger, verifier, false, None)?;
    service.start()?;
    assert_eq!(block_on(service.run_once(4_001))?.submitted, 1);
    assert_eq!(service.status()?.outbox_submitted, 1);
    Ok(())
}

#[test]
fn prepare_cancellation_and_none_page_never_move_cursor() -> std::result::Result<(), Box<dyn Error>> {
    let directory = TempDir::new()?;
    let ledger = MockLedger::default();
    let verifier = MockFinalityVerifier::new(profile(0x91)?, coordinator(0x92)?);
    let mut service = create_service(&directory, TestFloor::default(), ledger.clone(), verifier, true, None)?;
    service.start()?;
    assert_eq!(block_on(service.run_once(5_000))?.finalized, 0);
    assert_eq!(service.status()?.finalized_block_cursor.next_height(), 1);
    ledger.push_block(block(1, 5_000, AppHashV2::zero(), Vec::new())?)?;
    ledger.pending_prepare_once()?;
    let mut run = Box::pin(service.run_once(5_001));
    assert_pending(run.as_mut());
    drop(run);
    assert_eq!(service.status()?.finalized_block_cursor.next_height(), 1);
    assert!(service.status()?.staged_finality_range.is_none());
    assert_eq!(block_on(service.run_once(5_002))?.finalized, 0);
    assert_eq!(service.status()?.finalized_block_cursor.next_height(), 2);
    Ok(())
}

#[test]
fn verifier_profile_drift_and_weaker_revalidation_are_rejected() -> std::result::Result<(), Box<dyn Error>> {
    let directory = TempDir::new()?;
    let floor = TestFloor::default();
    let ledger = MockLedger::default();
    let verifier = MockFinalityVerifier::new(profile(0x91)?, coordinator(0x92)?);
    let mut service = create_service(&directory, floor.clone(), ledger.clone(), verifier.clone(), true, None)?;
    service.start()?;
    ledger.push_block(block(1, 6_000, AppHashV2::zero(), Vec::new())?)?;
    let _ = block_on(service.run_once(6_000))?;
    verifier.reject_revalidation(true)?;
    assert!(matches!(
        block_on(service.run_once(6_001)),
        Err(HolderNodeError::FinalityConflict)
    ));
    assert_eq!(service.status()?.finalized_block_cursor.next_height(), 2);
    verifier.reject_revalidation(false)?;
    drop(service);

    let drifted = MockFinalityVerifier::new(profile(0x93)?, coordinator(0x92)?);
    assert!(create_service(&directory, floor.clone(), ledger.clone(), drifted, false, None,).is_err());

    verifier.reject_revalidation(true)?;
    assert!(create_service(&directory, floor, ledger, verifier, false, None).is_err());
    Ok(())
}

#[test]
fn copied_database_cannot_reissue_store_capability() -> std::result::Result<(), Box<dyn Error>> {
    let directory = TempDir::new()?;
    let floor = TestFloor::default();
    let ledger = MockLedger::default();
    let verifier = MockFinalityVerifier::new(profile(0x91)?, coordinator(0x92)?);
    let service = create_service(&directory, floor.clone(), ledger.clone(), verifier.clone(), true, None)?;
    drop(service);
    let copied = durable_database_path(&directory, "copied-holder-node.db")?;
    std::fs::copy(durable_database_path(&directory, "holder-node.db")?, &copied)?;
    assert!(create_service_at(
        &directory,
        &copied,
        floor.clone(),
        ledger.clone(),
        verifier.clone(),
        false,
        config()?,
        None,
    )
    .is_err());
    let hardlink = durable_database_path(&directory, "hardlinked-holder-node.db")?;
    std::fs::hard_link(durable_database_path(&directory, "holder-node.db")?, &hardlink)?;
    assert!(create_service_at(&directory, &hardlink, floor, ledger, verifier, false, config()?, None,).is_err());
    Ok(())
}

#[test]
fn advanced_empty_block_v2_cursor_is_not_rolled_back_by_migration() -> std::result::Result<(), Box<dyn Error>> {
    let directory = TempDir::new()?;
    let floor = TestFloor::default();
    let ledger = MockLedger::default();
    let verifier = MockFinalityVerifier::new(profile(0x91)?, coordinator(0x92)?);
    let service = create_service(&directory, floor.clone(), ledger.clone(), verifier.clone(), true, None)?;
    drop(service);

    let connection = rusqlite::Connection::open(durable_database_path(&directory, "holder-node.db")?)?;
    connection.execute("UPDATE service_meta SET schema_version=2 WHERE singleton=1", [])?;
    connection.pragma_update(None, "user_version", 2)?;
    connection.execute(
        "UPDATE finalized_execution_cursor
         SET next_height=2,expected_previous_app_hash=?1,last_finality_length=NULL,last_finality_json=NULL
         WHERE singleton=1",
        [[0x44_u8; 32].as_slice()],
    )?;
    drop(connection);

    assert!(create_service(&directory, floor, ledger, verifier, false, None).is_err());
    Ok(())
}

#[test]
fn persisted_capability_tamper_is_rejected_on_async_open() -> std::result::Result<(), Box<dyn Error>> {
    let directory = TempDir::new()?;
    let floor = TestFloor::default();
    let ledger = MockLedger::default();
    let verifier = MockFinalityVerifier::new(profile(0x91)?, coordinator(0x92)?);
    let mut service = create_service(&directory, floor.clone(), ledger.clone(), verifier.clone(), true, None)?;
    service.start()?;
    ledger.push_block(block(1, 7_000, AppHashV2::zero(), Vec::new())?)?;
    let _ = block_on(service.run_once(7_000))?;
    drop(service);

    let connection = rusqlite::Connection::open(durable_database_path(&directory, "holder-node.db")?)?;
    let json: Vec<u8> = connection.query_row(
        "SELECT last_finality_json FROM finalized_execution_cursor WHERE singleton=1",
        [],
        |row| row.get(0),
    )?;
    let mut value: serde_json::Value = serde_json::from_slice(&json)?;
    let attestation = value
        .get_mut("attestation")
        .and_then(serde_json::Value::as_array_mut)
        .ok_or("missing attestation")?;
    let first = attestation.first_mut().ok_or("empty attestation")?;
    let original = first.as_u64().ok_or("attestation byte is not an integer")?;
    *first = serde_json::Value::from((original + 1) % 256);
    let capability: DurableBlockFinalityCapabilityV2 = serde_json::from_value(value)?;
    let tampered = serde_json::to_vec(&capability)?;
    connection.execute(
        "UPDATE finalized_execution_cursor SET last_finality_length=?1,last_finality_json=?2 WHERE singleton=1",
        rusqlite::params![i64::try_from(tampered.len())?, tampered],
    )?;
    drop(connection);
    assert!(create_service(&directory, floor, ledger, verifier, false, None).is_err());
    Ok(())
}

#[test]
fn exact_replay_is_noop_and_conflicting_duplicate_rolls_back() -> std::result::Result<(), Box<dyn Error>> {
    let directory = TempDir::new()?;
    let ledger = MockLedger::default();
    let verifier = MockFinalityVerifier::new(profile(0x91)?, coordinator(0x92)?);
    let mut service = create_service(&directory, TestFloor::default(), ledger.clone(), verifier, true, None)?;
    service.start()?;
    let queued = service.queue_proposal(queue_request(0x31, 0x32, 8_000)?)?;
    let _ = block_on(service.run_once(8_000))?;
    let proposal = ledger.submitted_request(&queued.request_digest)?;
    let first = block(1, 8_000, AppHashV2::zero(), vec![proposal.clone()])?;
    ledger.push_block(first.clone())?;
    assert_eq!(block_on(service.run_once(8_001))?.finalized, 1);
    let replay = block(2, 8_001, first.app_hash().clone(), vec![proposal])?;
    ledger.push_block(replay)?;
    assert_eq!(block_on(service.run_once(8_002))?.finalized, 0);
    assert_eq!(service.status()?.finalized_block_cursor.next_height(), 3);

    let conflicting = service.queue_proposal(queue_request(0x33, 0x34, 8_003)?)?;
    let _ = block_on(service.run_once(8_003))?;
    let proposal = ledger.submitted_request(&conflicting.request_digest)?;
    let prior = service
        .status()?
        .finalized_block_cursor
        .expected_previous_app_hash()
        .clone();
    ledger.push_block(block(3, 8_002, prior, vec![proposal])?)?;
    assert!(matches!(
        block_on(service.run_once(8_004)),
        Err(HolderNodeError::FinalityConflict)
    ));
    assert_eq!(service.status()?.finalized_block_cursor.next_height(), 3);
    Ok(())
}

#[test]
fn recovery_and_cursor_codecs_reject_tampering() -> std::result::Result<(), Box<dyn Error>> {
    let start = FinalizedBlockCursor::genesis(profile(0x91)?, coordinator(0x92)?, ledger_chain()?)?;
    let executed = block(1, 9_000, AppHashV2::zero(), Vec::new())?;
    let intent = FinalityRangeIntentV2::new(
        profile(0x91)?,
        coordinator(0x92)?,
        ledger_chain()?,
        1,
        AppHashV2::zero(),
        vec![executed.clone()],
        2,
        executed.app_hash().clone(),
    )?;
    let encoded = serde_json::to_vec(&intent)?;
    assert_eq!(serde_json::from_slice::<FinalityRangeIntentV2>(&encoded)?, intent);
    let encoded_cursor = serde_json::to_vec(&start)?;
    assert_eq!(serde_json::from_slice::<FinalizedBlockCursor>(&encoded_cursor)?, start);
    let mut value = serde_json::to_value(&intent)?;
    value["next_height"] = serde_json::Value::from(3_u64);
    assert!(serde_json::from_value::<FinalityRangeIntentV2>(value).is_err());
    Ok(())
}

#[test]
fn lifecycle_local_control_and_role_capabilities_remain_fail_closed() -> std::result::Result<(), Box<dyn Error>> {
    let directory = TempDir::new()?;
    let floor = TestFloor::default();
    let ledger = MockLedger::default();
    let verifier = MockFinalityVerifier::new(profile(0x91)?, coordinator(0x92)?);
    let mut service = create_service(&directory, floor.clone(), ledger.clone(), verifier.clone(), true, None)?;
    service.start()?;
    assert!(matches!(
        block_on(service.handle_local(LocalControlRequest::Status))?,
        LocalControlResponse::Status(_)
    ));
    assert!(service
        .prepare_settlement(&SettlementIntent {
            channel: channel(7)?,
            current_entry_hash: EntryHashV2::from_bytes([0x55; 32])?,
            expected_holder_anchor: vec![0x56; 33],
        })
        .is_err());
    assert!(service
        .threshold_sign(&ThresholdAction {
            channel: channel(7)?,
            entry_hash: EntryHashV2::from_bytes([0x57; 32])?,
            message_digest: [0x58; 32],
        })
        .is_err());
    service.begin_draining()?;
    service.stop()?;
    drop(service);
    let mut service = create_service(&directory, floor, ledger, verifier, false, None)?;
    service.start()?;
    assert!(!service.status()?.recovered_unclean_shutdown);
    Ok(())
}
