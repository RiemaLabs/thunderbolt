use std::collections::BTreeMap;
use std::error::Error;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bitcoin::Network;
use secp256k1::{Keypair, Secp256k1, SecretKey};
use tempfile::TempDir;
use thunderbolt_holder::{holder_keystore_identity, HolderEngine, KeystoreSecretVault};
use thunderbolt_keystore::{
    CheckpointCasOutcome, CommitteeDescriptorDigest, KdfParams, NodeId, Password, RollbackFloorStore, VaultCheckpoint,
    VaultIdentity, MIN_ARGON2_ITERATIONS, MIN_ARGON2_MEMORY_KIB,
};
use thunderbolt_ledger::{
    ActorPublicKeyV2, ActorRoleV2, ActorSignatureV2, ClientRequestNonceV2, EntryHashV2, ProposalDigestV2,
    SignedProposalV2,
};
use thunderbolt_protocol::v2::{ChannelEventV2, OpenEventV2};
use thunderbolt_protocol::Artifact;
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

#[derive(Clone)]
struct MockReceipt {
    cursor: FinalizedCursor,
    proposal: SignedProposalV2,
    finality_digest: [u8; 32],
    request_digest: thunderbolt_ledger::RequestDigestV2,
    event_digest: thunderbolt_ledger::EventDigestV2,
}

impl TrustedLedgerReceipt for MockReceipt {
    fn cursor(&self) -> FinalizedCursor {
        self.cursor.clone()
    }
    fn signed_proposal(&self) -> &SignedProposalV2 {
        &self.proposal
    }
    fn finality_digest(&self) -> &[u8; 32] {
        &self.finality_digest
    }
    fn request_digest(&self) -> &thunderbolt_ledger::RequestDigestV2 {
        &self.request_digest
    }
    fn event_digest(&self) -> &thunderbolt_ledger::EventDigestV2 {
        &self.event_digest
    }
}

#[derive(Clone)]
struct MockCandidate {
    receipt: MockReceipt,
    valid: bool,
}

#[derive(Default)]
struct MockLedgerState {
    submitted: BTreeMap<[u8; 32], SignedProposalV2>,
    candidates: Vec<MockCandidate>,
    fail_submissions: bool,
    return_duplicates: bool,
}

#[derive(Clone, Default)]
struct MockLedger {
    state: Arc<Mutex<MockLedgerState>>,
}

#[derive(Debug, thiserror::Error)]
#[error("mock Ledger failure")]
struct MockLedgerError;

impl MockLedger {
    fn set_fail_submissions(&self, fail: bool) -> std::result::Result<(), MockLedgerError> {
        self.state.lock().map_err(|_| MockLedgerError)?.fail_submissions = fail;
        Ok(())
    }
    fn submitted(&self) -> std::result::Result<SignedProposalV2, MockLedgerError> {
        self.state
            .lock()
            .map_err(|_| MockLedgerError)?
            .submitted
            .values()
            .next()
            .cloned()
            .ok_or(MockLedgerError)
    }
    fn push_receipt(&self, receipt: MockReceipt) -> std::result::Result<(), MockLedgerError> {
        self.state
            .lock()
            .map_err(|_| MockLedgerError)?
            .candidates
            .push(MockCandidate { receipt, valid: true });
        Ok(())
    }
    fn return_duplicates(&self, enabled: bool) -> std::result::Result<(), MockLedgerError> {
        self.state.lock().map_err(|_| MockLedgerError)?.return_duplicates = enabled;
        Ok(())
    }
}

impl SignedV2LedgerClient for MockLedger {
    type Error = MockLedgerError;
    type FinalityCandidate = MockCandidate;

    fn submit(&mut self, proposal: &SignedProposalV2) -> std::result::Result<SubmissionStatus, Self::Error> {
        let mut state = self.state.lock().map_err(|_| MockLedgerError)?;
        if state.fail_submissions {
            return Err(MockLedgerError);
        }
        let request = *proposal.body().request_id().digest().as_bytes();
        if let Some(existing) = state.submitted.get(&request) {
            return if existing == proposal {
                Ok(SubmissionStatus::AlreadyKnown)
            } else {
                Err(MockLedgerError)
            };
        }
        state.submitted.insert(request, proposal.clone());
        Ok(SubmissionStatus::Accepted)
    }

    fn finalized_history(
        &mut self,
        channel: &thunderbolt_ledger::ChannelContextIdV2,
        after: Option<&FinalizedCursor>,
        limit: usize,
    ) -> std::result::Result<Vec<Self::FinalityCandidate>, Self::Error> {
        let state = self.state.lock().map_err(|_| MockLedgerError)?;
        Ok(state
            .candidates
            .iter()
            .filter(|candidate| {
                &candidate.receipt.cursor.channel_context_id == channel
                    && (state.return_duplicates
                        || after.is_none_or(|cursor| candidate.receipt.cursor.sequence > cursor.sequence))
            })
            .take(limit)
            .cloned()
            .collect())
    }
}

#[derive(Default)]
struct MockFinalityVerifier;

impl FinalityVerifier<MockCandidate> for MockFinalityVerifier {
    type Error = MockLedgerError;
    type Receipt = MockReceipt;

    fn verify(
        &self,
        expected_chain: &thunderbolt_ledger::LedgerChainIdV2,
        candidate: MockCandidate,
    ) -> std::result::Result<Self::Receipt, Self::Error> {
        (candidate.valid && candidate.receipt.proposal.body().ledger_chain_id() == expected_chain)
            .then_some(candidate.receipt)
            .ok_or(MockLedgerError)
    }
}

type TestService = HolderRoleService<
    TestFloor,
    MockLedger,
    MockFinalityVerifier,
    MockSigner,
    UnavailableBitcoinSettlement,
    UnavailableThresholdSigner,
>;

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

fn config(network: Network) -> std::result::Result<HolderNodeConfig, Box<dyn Error>> {
    Ok(HolderNodeConfig::new(
        network,
        thunderbolt_ledger::LedgerChainIdV2::new("holder-node-regtest")?,
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
            lock_key: Artifact::new(vec![0x41; 33])?,
            initial_holder_anchor: Artifact::new(vec![0x42; 33])?,
            initial_holder_ciphertext: Artifact::new(vec![0x43; 64])?,
            open_proof: Artifact::new(vec![0x44; 64])?,
        }),
        now_ms,
    })
}

fn create_service(
    directory: &TempDir,
    floor: TestFloor,
    ledger: MockLedger,
    create_vault: bool,
) -> std::result::Result<TestService, Box<dyn Error>> {
    Ok(HolderRoleService::open(
        holder_engine(&directory.path().join("holder.vault"), 0x51, floor, create_vault)?,
        ledger,
        MockFinalityVerifier,
        MockSigner::new(0x21)?,
        UnavailableBitcoinSettlement,
        UnavailableThresholdSigner,
        directory.path().join("holder-node.db"),
        config(Network::Regtest)?,
    )?)
}

fn receipt(proposal: SignedProposalV2) -> std::result::Result<MockReceipt, Box<dyn Error>> {
    let channel = thunderbolt_ledger::ChannelContextIdV2::from_bytes(proposal.body().channel().context_id()?)?;
    let sequence = proposal.body().sequence();
    let entry_hash = proposal.body().entry_hash()?;
    let request_digest = proposal.body().request_id().digest().clone();
    let event_digest = proposal.body().event().digest()?;
    Ok(MockReceipt {
        cursor: FinalizedCursor::new(channel, sequence, entry_hash),
        proposal,
        finality_digest: [0xf1; 32],
        request_digest,
        event_digest,
    })
}

#[test]
fn configuration_rejects_mainnet_and_testnet4() -> std::result::Result<(), Box<dyn Error>> {
    assert!(config(Network::Bitcoin).is_err());
    assert!(config(Network::Testnet4).is_err());
    assert!(config(Network::Regtest).is_ok());
    let unavailable = UnavailableActorSigner;
    assert!(unavailable.public_key().is_err());
    Ok(())
}

#[test]
fn outbox_crash_restart_retry_finality_and_conflicts() -> std::result::Result<(), Box<dyn Error>> {
    let directory = TempDir::new()?;
    let floor = TestFloor::default();
    let ledger = MockLedger::default();
    ledger.set_fail_submissions(true)?;
    let mut service = create_service(&directory, floor.clone(), ledger.clone(), true)?;
    service.start()?;
    let request = queue_request(1, 2, 1_000)?;
    let mut wrong_role = request.clone();
    wrong_role.command_id = CommandId::from_bytes([9; 32]);
    wrong_role.actor_role = ActorRoleV2::Recipient;
    assert!(matches!(
        service.queue_proposal(wrong_role),
        Err(HolderNodeError::InvalidRequest(_))
    ));
    assert_eq!(
        service.queue_proposal(request.clone())?.disposition,
        QueueDisposition::Queued
    );
    assert_eq!(
        service.queue_proposal(request.clone())?.disposition,
        QueueDisposition::AlreadyQueued
    );
    let mut alias = request.clone();
    alias.command_id = CommandId::from_bytes([3; 32]);
    assert_eq!(
        service.queue_proposal(alias)?.disposition,
        QueueDisposition::AlreadyQueued
    );
    let mut conflict = request;
    conflict.request_nonce = ClientRequestNonceV2::from_bytes([4; 16])?;
    assert!(matches!(
        service.queue_proposal(conflict),
        Err(HolderNodeError::IdempotencyConflict)
    ));
    assert_eq!(service.run_once(1_000)?.submit_failures, 1);
    drop(service);

    ledger.set_fail_submissions(false)?;
    let mut service = create_service(&directory, floor.clone(), ledger.clone(), false)?;
    service.start()?;
    assert!(service.status()?.recovered_unclean_shutdown);
    assert_eq!(service.run_once(1_020)?.submitted, 1);
    let proposal = ledger.submitted()?;
    ledger.push_receipt(receipt(proposal)?)?;
    assert_eq!(service.run_once(1_021)?.finalized, 1);
    let status = service.status()?;
    assert_eq!(status.outbox_finalized, 1);
    assert_eq!(status.finalized_channels, 1);

    ledger.return_duplicates(true)?;
    assert!(matches!(
        service.run_once(1_022),
        Err(HolderNodeError::FinalityConflict)
    ));
    assert_eq!(service.status()?.lifecycle, LifecycleState::Faulted);
    drop(service);
    let mut service = create_service(&directory, floor, ledger, false)?;
    assert_eq!(service.status()?.lifecycle, LifecycleState::Faulted);
    assert!(matches!(service.start(), Err(HolderNodeError::InvalidLifecycle)));
    service.acknowledge_fault()?;
    service.start()?;
    Ok(())
}

#[test]
fn database_rejects_a_different_actor_identity() -> std::result::Result<(), Box<dyn Error>> {
    let directory = TempDir::new()?;
    let floor = TestFloor::default();
    let ledger = MockLedger::default();
    drop(create_service(&directory, floor.clone(), ledger.clone(), true)?);
    let result = HolderRoleService::open(
        holder_engine(&directory.path().join("holder.vault"), 0x51, floor.clone(), false)?,
        ledger,
        MockFinalityVerifier,
        MockSigner::new(0x22)?,
        UnavailableBitcoinSettlement,
        UnavailableThresholdSigner,
        directory.path().join("holder-node.db"),
        config(Network::Regtest)?,
    );
    assert!(matches!(result, Err(HolderNodeError::StorageCorrupt)));

    let alternate_channel = ChannelBindingV2::new(
        ProtocolSuiteIdV2::from_bytes([0x12; 32])?,
        Network::Regtest,
        BitcoinGenesisHashV2::for_network(Network::Regtest)?,
        b"other-holder-deployment",
        FundingOutpointV2::new([0x13; 32], 1)?,
        8,
        CommitteeDescriptorDigestV2::from_bytes([0x23; 32])?,
        AnchorParameterSuiteIdV2::from_bytes([0x34; 32])?,
    )?;
    let alternate_config = HolderNodeConfig::new(
        Network::Regtest,
        thunderbolt_ledger::LedgerChainIdV2::new("holder-node-regtest")?,
        HolderDeploymentPolicy::from_channel(&alternate_channel)?,
        RetryPolicy::default(),
        8,
        8,
        Duration::from_secs(1),
    )?;
    let result = HolderRoleService::open(
        holder_engine(&directory.path().join("holder.vault"), 0x51, floor, false)?,
        MockLedger::default(),
        MockFinalityVerifier,
        MockSigner::new(0x21)?,
        UnavailableBitcoinSettlement,
        UnavailableThresholdSigner,
        directory.path().join("holder-node.db"),
        alternate_config,
    );
    assert!(matches!(result, Err(HolderNodeError::StorageCorrupt)));
    Ok(())
}

#[test]
fn receipt_digest_mismatch_faults_without_finalizing() -> std::result::Result<(), Box<dyn Error>> {
    let directory = TempDir::new()?;
    let floor = TestFloor::default();
    let ledger = MockLedger::default();
    let mut service = create_service(&directory, floor, ledger.clone(), true)?;
    service.start()?;
    let _ = service.queue_proposal(queue_request(0x31, 0x32, 2_000)?)?;
    assert_eq!(service.run_once(2_000)?.submitted, 1);
    let proposal = ledger.submitted()?;
    let mut invalid = receipt(proposal)?;
    invalid.event_digest = thunderbolt_ledger::EventDigestV2::from_bytes([0x33; 32])?;
    ledger.push_receipt(invalid)?;
    assert!(matches!(
        service.run_once(2_001),
        Err(HolderNodeError::FinalityConflict)
    ));
    let status = service.status()?;
    assert_eq!(status.lifecycle, LifecycleState::Faulted);
    assert_eq!(status.outbox_finalized, 0);
    assert_eq!(status.outbox_submitted, 1);
    Ok(())
}

#[test]
fn clean_lifecycle_local_control_and_missing_capabilities_fail_closed() -> std::result::Result<(), Box<dyn Error>> {
    let directory = TempDir::new()?;
    let floor = TestFloor::default();
    let ledger = MockLedger::default();
    let mut service = create_service(&directory, floor.clone(), ledger.clone(), true)?;
    service.start()?;
    assert!(matches!(
        service.handle_local(LocalControlRequest::Status)?,
        LocalControlResponse::Status(_)
    ));
    assert!(matches!(
        service.prepare_settlement(&SettlementIntent {
            channel: channel(7)?,
            current_entry_hash: EntryHashV2::from_bytes([0x55; 32])?,
            expected_holder_anchor: vec![0x56; 33],
        }),
        Err(HolderNodeError::CapabilityUnavailable)
    ));
    assert!(matches!(
        service.threshold_sign(&ThresholdAction {
            channel: channel(7)?,
            entry_hash: EntryHashV2::from_bytes([0x57; 32])?,
            message_digest: [0x58; 32],
        }),
        Err(HolderNodeError::CapabilityUnavailable)
    ));
    service.begin_draining()?;
    service.stop()?;
    drop(service);

    let mut service = create_service(&directory, floor, ledger, false)?;
    service.start()?;
    assert!(!service.status()?.recovered_unclean_shutdown);
    Ok(())
}
