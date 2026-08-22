use core::time::Duration;
use std::error::Error;
use std::io::Cursor;
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use bitcoin::Network;
use ed25519_consensus::SigningKey;
use rusqlite::Connection;
use secp256k1::{Keypair, Secp256k1, SecretKey};
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use tendermint::block::parts::Header as PartSetHeader;
use tendermint::block::signed_header::SignedHeader;
use tendermint::block::{self, Commit, CommitSig, Header, Round};
use tendermint::chain;
use tendermint::hash::Hash;
use tendermint::node::Id as NodeId;
use tendermint::public_key::PublicKey;
use tendermint::signature::Signature;
use tendermint::validator::{Info as ValidatorInfo, Set as ValidatorSet};
use tendermint::vote::{self, Power, SignedVote, ValidatorIndex, Vote};
use tendermint::{AppHash, Time};
use tendermint_light_client_verifier::types::LightBlock;
use thunderbolt_cometbft::{FinalityPolicy, PinnedTrustRoot, THUNDERBOLT_APP_VERSION_V2};
use thunderbolt_ledger::{
    ActorKeyAlgorithmV2, ActorPublicKeyV2, ActorRoleV2, ActorSignatureV2, AppHashV2, CanonicalEventV2,
    ClientRequestNonceV2, EntryHashV2, EventKindV2, ExecutedBlockV2, LedgerChainIdV2, PendingBlockV2, ProposalBodyV2,
    RequestDigestV2, SignedProposalV2,
};
use thunderbolt_wire::{
    AnchorParameterSuiteIdV2, BitcoinGenesisHashV2, ChannelBindingV2, CommitteeDescriptorDigestV2, FundingOutpointV2,
    ProtocolSuiteIdV2,
};

use crate::coordinator::FaultPoint;
use crate::{
    AdvanceOutcome, AuthenticationContext, CheckpointFuture, CoordinatorConfig, CoordinatorError, CoordinatorLimits,
    FetchedTrace, HistoryEpochLimits, HistorySealOutcome, PeerIdentity, RotationOutcome, SourceConfiguration,
    SourceRole, TraceFetchRequest, TraceFuture, TracePeerAuthenticator, TraceTransport, TrustCheckpoint,
    TrustCheckpointCasOutcome, TrustCheckpointStore, TrustCoordinator, TrustCoordinatorIdentity,
};

const CHAIN_ID: &str = "thunderbolt-client-regtest-2";
const PRIMARY_NODE: &str = "2222222222222222222222222222222222222222";
const WITNESS_NODE: &str = "3333333333333333333333333333333333333333";

struct Fixture {
    config: CoordinatorConfig,
    root: PinnedTrustRoot,
    primary: Vec<LightBlock>,
    witness: Vec<LightBlock>,
    execution: ExecutedBlockV2,
    replay_primary: Vec<LightBlock>,
    replay_witness: Vec<LightBlock>,
    replay_execution: ExecutedBlockV2,
    request_digest: RequestDigestV2,
}

#[derive(Clone, Copy)]
enum TransportMode {
    Normal,
    WrongWitnessEvidence,
    TamperedWitness,
    Oversize,
    Hang,
    FailFirstWitness,
}

struct Evidence {
    binding: [u8; 32],
    role: SourceRole,
    first_height: u64,
    last_height: u64,
    trace_hash: [u8; 32],
}

struct MockTransport {
    primary: Vec<LightBlock>,
    witness: Vec<LightBlock>,
    replay_primary: Vec<LightBlock>,
    replay_witness: Vec<LightBlock>,
    calls: Arc<AtomicUsize>,
    mode: TransportMode,
}

impl TraceTransport for MockTransport {
    type Evidence = Evidence;
    type Body = Cursor<Vec<u8>>;
    type Error = &'static str;

    fn fetch<'a>(
        &'a self,
        peer: &'a PeerIdentity,
        request: &'a TraceFetchRequest,
    ) -> TraceFuture<'a, FetchedTrace<Self::Body, Self::Evidence>, Self::Error> {
        Box::pin(async move {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if matches!(self.mode, TransportMode::Hang) {
                return std::future::pending().await;
            }
            if matches!(self.mode, TransportMode::FailFirstWitness) && request.role() == SourceRole::Witness(0) {
                return Err("injected optional witness outage");
            }
            let replay = request.first_height() > 2;
            let mut blocks = match (request.role(), replay) {
                (SourceRole::Primary, false) => self.primary.clone(),
                (SourceRole::Witness(_), false) => self.witness.clone(),
                (SourceRole::Primary, true) => self.replay_primary.clone(),
                (SourceRole::Witness(_), true) => self.replay_witness.clone(),
            };
            if matches!(self.mode, TransportMode::TamperedWitness) && matches!(request.role(), SourceRole::Witness(_)) {
                blocks[0].signed_header.header.app_hash =
                    AppHash::try_from(vec![0x5a_u8; 32]).map_err(|_| "invalid test app hash")?;
            }
            let encoded = serde_json::to_vec(&blocks).map_err(|_| "encoding")?;
            let binding = if matches!(self.mode, TransportMode::WrongWitnessEvidence)
                && matches!(request.role(), SourceRole::Witness(_))
            {
                [0xa1_u8; 32]
            } else {
                *peer.transport_binding()
            };
            let evidence = Evidence {
                binding,
                role: request.role(),
                first_height: request.first_height(),
                last_height: request.last_height(),
                trace_hash: Sha256::digest(&encoded).into(),
            };
            let body = if matches!(self.mode, TransportMode::Oversize) {
                vec![0_u8; request.max_encoded_bytes() + 1]
            } else {
                encoded
            };
            Ok(FetchedTrace::new(Cursor::new(body), evidence))
        })
    }
}

#[derive(Clone, Copy)]
struct MockAuthenticator;

impl TracePeerAuthenticator<Evidence> for MockAuthenticator {
    type Error = &'static str;

    fn authenticate<'a>(
        &'a self,
        expected: &'a PeerIdentity,
        context: AuthenticationContext<'a>,
        evidence: &'a Evidence,
    ) -> TraceFuture<'a, (), Self::Error> {
        Box::pin(async move {
            let encoded = serde_json::to_vec(context.blocks()).map_err(|_| "encoding")?;
            let trace_hash: [u8; 32] = Sha256::digest(encoded).into();
            if evidence.binding != *expected.transport_binding()
                || evidence.role != context.request().role()
                || evidence.first_height != context.request().first_height()
                || evidence.last_height != context.request().last_height()
                || evidence.trace_hash != trace_hash
                || context.trace_digest() == &[0_u8; 32]
                || context.encoded_bytes() == 0
            {
                return Err("session evidence differs");
            }
            Ok(())
        })
    }
}

#[derive(Clone, Default)]
struct MemoryCheckpointStore {
    state: Arc<Mutex<Option<(TrustCoordinatorIdentity, TrustCheckpoint)>>>,
}

impl TrustCheckpointStore for MemoryCheckpointStore {
    type Error = &'static str;

    fn load_checkpoint<'a>(
        &'a self,
        identity: TrustCoordinatorIdentity,
    ) -> CheckpointFuture<'a, Option<TrustCheckpoint>, Self::Error> {
        Box::pin(async move {
            let state = self.state.lock().map_err(|_| "checkpoint lock poisoned")?;
            match *state {
                Some((stored_identity, checkpoint)) if stored_identity == identity => Ok(Some(checkpoint)),
                Some(_) => Err("checkpoint identity differs"),
                None => Ok(None),
            }
        })
    }

    fn compare_and_swap_checkpoint<'a>(
        &'a self,
        identity: TrustCoordinatorIdentity,
        expected: Option<TrustCheckpoint>,
        next: TrustCheckpoint,
    ) -> CheckpointFuture<'a, TrustCheckpointCasOutcome, Self::Error> {
        Box::pin(async move {
            let mut state = self.state.lock().map_err(|_| "checkpoint lock poisoned")?;
            let current = match *state {
                Some((stored_identity, checkpoint)) if stored_identity == identity => Some(checkpoint),
                Some(_) => return Err("checkpoint identity differs"),
                None => None,
            };
            if current == Some(next) {
                return Ok(TrustCheckpointCasOutcome::AlreadyCurrent);
            }
            if current != expected {
                return Ok(TrustCheckpointCasOutcome::Conflict(current));
            }
            *state = Some((identity, next));
            Ok(TrustCheckpointCasOutcome::Advanced)
        })
    }
}

#[derive(Clone)]
struct FailOnceCheckpointStore {
    inner: MemoryCheckpointStore,
    fail_next_cas: Arc<AtomicBool>,
}

impl FailOnceCheckpointStore {
    fn new() -> Self {
        Self {
            inner: MemoryCheckpointStore::default(),
            fail_next_cas: Arc::new(AtomicBool::new(true)),
        }
    }

    fn ready() -> Self {
        Self {
            inner: MemoryCheckpointStore::default(),
            fail_next_cas: Arc::new(AtomicBool::new(false)),
        }
    }

    fn fail_next(&self) {
        self.fail_next_cas.store(true, Ordering::SeqCst);
    }
}

impl TrustCheckpointStore for FailOnceCheckpointStore {
    type Error = &'static str;

    fn load_checkpoint<'a>(
        &'a self,
        identity: TrustCoordinatorIdentity,
    ) -> CheckpointFuture<'a, Option<TrustCheckpoint>, Self::Error> {
        self.inner.load_checkpoint(identity)
    }

    fn compare_and_swap_checkpoint<'a>(
        &'a self,
        identity: TrustCoordinatorIdentity,
        expected: Option<TrustCheckpoint>,
        next: TrustCheckpoint,
    ) -> CheckpointFuture<'a, TrustCheckpointCasOutcome, Self::Error> {
        Box::pin(async move {
            if self.fail_next_cas.swap(false, Ordering::SeqCst) {
                return Err("injected ambiguous checkpoint failure");
            }
            self.inner.compare_and_swap_checkpoint(identity, expected, next).await
        })
    }
}

#[derive(Clone, Copy)]
struct HangingCheckpointStore;

impl TrustCheckpointStore for HangingCheckpointStore {
    type Error = &'static str;

    fn load_checkpoint<'a>(
        &'a self,
        _identity: TrustCoordinatorIdentity,
    ) -> CheckpointFuture<'a, Option<TrustCheckpoint>, Self::Error> {
        Box::pin(std::future::pending())
    }

    fn compare_and_swap_checkpoint<'a>(
        &'a self,
        _identity: TrustCoordinatorIdentity,
        _expected: Option<TrustCheckpoint>,
        _next: TrustCheckpoint,
    ) -> CheckpointFuture<'a, TrustCheckpointCasOutcome, Self::Error> {
        Box::pin(std::future::pending())
    }
}

fn transport(fixture: &Fixture, calls: Arc<AtomicUsize>, mode: TransportMode) -> MockTransport {
    MockTransport {
        primary: fixture.primary.clone(),
        witness: fixture.witness.clone(),
        replay_primary: fixture.replay_primary.clone(),
        replay_witness: fixture.replay_witness.clone(),
        calls,
        mode,
    }
}

fn private_directory() -> std::result::Result<TempDir, Box<dyn Error>> {
    let directory = TempDir::new()?;
    #[cfg(unix)]
    std::fs::set_permissions(
        directory.path(),
        <std::fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o700),
    )?;
    Ok(directory)
}

type TestCoordinator = TrustCoordinator<MockTransport, MockAuthenticator, MemoryCheckpointStore>;

async fn create_coordinator(
    path: &std::path::Path,
    fixture: &Fixture,
    calls: Arc<AtomicUsize>,
    mode: TransportMode,
    checkpoints: MemoryCheckpointStore,
) -> std::result::Result<TestCoordinator, CoordinatorError> {
    TrustCoordinator::create(
        path,
        fixture.config.clone(),
        fixture.root.clone(),
        transport(fixture, calls, mode),
        MockAuthenticator,
        checkpoints,
    )
    .await
}

async fn open_coordinator(
    path: &std::path::Path,
    fixture: &Fixture,
    config: CoordinatorConfig,
    calls: Arc<AtomicUsize>,
    mode: TransportMode,
    checkpoints: MemoryCheckpointStore,
) -> std::result::Result<TestCoordinator, CoordinatorError> {
    TrustCoordinator::open(
        path,
        config,
        transport(fixture, calls, mode),
        MockAuthenticator,
        checkpoints,
    )
    .await
}

fn peer(binding: u8, node: &str) -> std::result::Result<PeerIdentity, Box<dyn Error>> {
    Ok(PeerIdentity::new([binding; 32], NodeId::from_str(node)?)?)
}

fn sources(
    version: u64,
    primary_binding: u8,
    primary_node: &str,
    witness_binding: u8,
    witness_node: &str,
) -> std::result::Result<SourceConfiguration, Box<dyn Error>> {
    Ok(SourceConfiguration::new(
        version,
        peer(primary_binding, primary_node)?,
        vec![peer(witness_binding, witness_node)?],
    )?)
}

fn fixture(root_age_seconds: u64, trusting_period_seconds: u64) -> std::result::Result<Fixture, Box<dyn Error>> {
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let base = now.checked_sub(root_age_seconds).ok_or("test clock too near epoch")?;
    let base_i64 = i64::try_from(base)?;
    let chain_id = LedgerChainIdV2::new(CHAIN_ID)?;
    let zero = AppHashV2::zero();
    let first_time_ms = base.checked_mul(1_000).ok_or("time overflow")?;
    let first_execution = PendingBlockV2::new(chain_id.clone(), 1, first_time_ms, zero.clone())?.execute()?;
    let second_time_ms = first_time_ms.checked_add(10_000).ok_or("time overflow")?;
    let proposal = signed_open(chain_id.clone())?;
    let request_digest = proposal.body().request_id().digest().clone();
    let mut pending = PendingBlockV2::new(chain_id.clone(), 2, second_time_ms, first_execution.app_hash().clone())?;
    pending.push(proposal.clone())?;
    let execution = pending.execute()?;
    let third_time_ms = second_time_ms.checked_add(10_000).ok_or("time overflow")?;
    let mut replay_pending = PendingBlockV2::new(chain_id.clone(), 3, third_time_ms, execution.app_hash().clone())?;
    replay_pending.push(proposal)?;
    let replay_execution = replay_pending.execute()?;

    let seeds = validator_seeds();
    let validators = validator_set(&seeds)?;
    let header_one = build_header(
        &validators,
        1,
        Time::from_unix_timestamp(base_i64, 0)?,
        None,
        zero.as_bytes(),
    )?;
    let header_one_hash = header_one.hash();
    let header_two = build_header(
        &validators,
        2,
        Time::from_unix_timestamp(base_i64 + 10, 0)?,
        Some(header_one_hash),
        first_execution.app_hash().as_bytes(),
    )?;
    let header_two_hash = header_two.hash();
    let header_three = build_header(
        &validators,
        3,
        Time::from_unix_timestamp(base_i64 + 20, 0)?,
        Some(header_two_hash),
        execution.app_hash().as_bytes(),
    )?;
    let header_three_hash = header_three.hash();
    let header_four = build_header(
        &validators,
        4,
        Time::from_unix_timestamp(base_i64 + 30, 0)?,
        Some(header_three_hash),
        replay_execution.app_hash().as_bytes(),
    )?;
    let root_block = light_block(
        header_one,
        &validators,
        &seeds,
        "1111111111111111111111111111111111111111",
    )?;
    let primary = vec![
        light_block(
            header_two.clone(),
            &validators,
            &seeds,
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        )?,
        light_block(
            header_three.clone(),
            &validators,
            &seeds,
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        )?,
    ];
    let witness = vec![
        light_block(
            header_two,
            &validators,
            &seeds,
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        )?,
        light_block(
            header_three,
            &validators,
            &seeds,
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        )?,
    ];
    let replay_primary = vec![light_block(
        header_four.clone(),
        &validators,
        &seeds,
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    )?];
    let replay_witness = vec![light_block(
        header_four,
        &validators,
        &seeds,
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    )?];
    let policy = FinalityPolicy::new(
        Duration::from_secs(trusting_period_seconds),
        Duration::from_secs(30),
        4,
        8,
        1,
        2,
    )?;
    let pinned_hash = sha256_header_hash(&root_block)?;
    let root = PinnedTrustRoot::new(root_block, &chain_id, 1, pinned_hash, policy)?;
    let limits = CoordinatorLimits::new(2 * 1024 * 1024, 1024 * 1024, 8 * 1024 * 1024, Duration::from_secs(2), 1)?;
    let config = CoordinatorConfig::new(
        TrustCoordinatorIdentity::new([0x91; 32])?,
        chain_id,
        policy,
        sources(1, 0xa1, PRIMARY_NODE, 0xb1, WITNESS_NODE)?,
        Duration::from_secs(2),
        limits,
        HistoryEpochLimits::new(64, 64 * 1024 * 1024, 4_096)?,
    )?;
    Ok(Fixture {
        config,
        root,
        primary,
        witness,
        execution,
        replay_primary,
        replay_witness,
        replay_execution,
        request_digest,
    })
}

fn validator_seeds() -> [[u8; 32]; 4] {
    [[1_u8; 32], [2_u8; 32], [3_u8; 32], [4_u8; 32]]
}

fn validator_set(seeds: &[[u8; 32]]) -> std::result::Result<ValidatorSet, Box<dyn Error>> {
    let mut validators = Vec::with_capacity(seeds.len());
    for seed in seeds {
        let signing_key = tendermint::private_key::Ed25519::try_from(seed.as_slice())?;
        validators.push(ValidatorInfo::new(
            PublicKey::from(signing_key.verification_key()),
            Power::try_from(1_u64)?,
        ));
    }
    Ok(ValidatorSet::without_proposer(validators))
}

fn build_header(
    validators: &ValidatorSet,
    height: u64,
    time: Time,
    last_header_hash: Option<Hash>,
    state_app_hash: &[u8; 32],
) -> std::result::Result<Header, Box<dyn Error>> {
    let validator_hash = validators.hash();
    Ok(Header {
        version: block::header::Version {
            block: 11,
            app: THUNDERBOLT_APP_VERSION_V2,
        },
        chain_id: chain::Id::from_str(CHAIN_ID)?,
        height: block::Height::try_from(height)?,
        time,
        last_block_id: last_header_hash.map(|hash| block::Id {
            hash,
            part_set_header: PartSetHeader::default(),
        }),
        last_commit_hash: None,
        data_hash: None,
        validators_hash: validator_hash,
        next_validators_hash: validator_hash,
        consensus_hash: validator_hash,
        app_hash: AppHash::try_from(state_app_hash.to_vec())?,
        last_results_hash: None,
        evidence_hash: None,
        proposer_address: validators.validators()[0].address,
    })
}

fn sign_commit(
    header: &Header,
    validators: &ValidatorSet,
    seeds: &[[u8; 32]],
) -> std::result::Result<Commit, Box<dyn Error>> {
    let header_hash = header.hash();
    let block_id = block::Id {
        hash: header_hash,
        part_set_header: PartSetHeader::new(1, header_hash)?,
    };
    let round = Round::try_from(1_u32)?;
    let mut signatures = Vec::with_capacity(validators.validators().len());
    for (index, validator) in validators.validators().iter().enumerate() {
        let seed = seeds
            .iter()
            .find(|seed| {
                tendermint::private_key::Ed25519::try_from(seed.as_slice())
                    .is_ok_and(|key| validator.address == tendermint::account::Id::from(key.verification_key()))
            })
            .ok_or("validator seed is missing")?;
        let vote = Vote {
            vote_type: vote::Type::Precommit,
            height: header.height,
            round,
            block_id: Some(block_id),
            timestamp: Some(header.time),
            validator_address: validator.address,
            validator_index: ValidatorIndex::try_from(u32::try_from(index)?)?,
            signature: Signature::new(vec![0_u8; 64])?,
            extension: Vec::new(),
            extension_signature: None,
        };
        let sign_bytes = SignedVote::from_vote(vote, header.chain_id.clone())
            .ok_or("test vote cannot be signed")?
            .sign_bytes();
        let signing_key = SigningKey::from(*seed);
        signatures.push(CommitSig::BlockIdFlagCommit {
            validator_address: validator.address,
            timestamp: header.time,
            signature: Some(signing_key.sign(&sign_bytes).into()),
        });
    }
    Ok(Commit {
        height: header.height,
        round,
        block_id,
        signatures,
    })
}

fn light_block(
    header: Header,
    validators: &ValidatorSet,
    seeds: &[[u8; 32]],
    provider: &str,
) -> std::result::Result<LightBlock, Box<dyn Error>> {
    let commit = sign_commit(&header, validators, seeds)?;
    let signed_header = SignedHeader::new(header, commit)?;
    Ok(LightBlock::new(
        signed_header,
        validators.clone(),
        validators.clone(),
        NodeId::from_str(provider)?,
    ))
}

fn sha256_header_hash(block: &LightBlock) -> std::result::Result<[u8; 32], Box<dyn Error>> {
    match block.signed_header.header.hash() {
        Hash::Sha256(bytes) => Ok(bytes),
        Hash::None => Err("header hash is empty".into()),
    }
}

fn signed_open(chain_id: LedgerChainIdV2) -> std::result::Result<SignedProposalV2, Box<dyn Error>> {
    let mut secret_bytes = [0_u8; 32];
    secret_bytes[31] = 7;
    let secret = SecretKey::from_byte_array(secret_bytes)?;
    let keypair = Keypair::from_secret_key(&Secp256k1::signing_only(), &secret);
    let (public, _) = keypair.x_only_public_key();
    let channel = ChannelBindingV2::new(
        ProtocolSuiteIdV2::from_bytes([0x11; 32])?,
        Network::Regtest,
        BitcoinGenesisHashV2::for_network(Network::Regtest)?,
        b"cometbft-client-tests",
        FundingOutpointV2::new([0x44; 32], 2)?,
        1,
        CommitteeDescriptorDigestV2::from_bytes([0x22; 32])?,
        AnchorParameterSuiteIdV2::from_bytes([0x33; 32])?,
    )?;
    let body = ProposalBodyV2::new(
        chain_id,
        channel,
        0,
        EntryHashV2::zero(),
        ClientRequestNonceV2::from_bytes([0x55; 16])?,
        ActorKeyAlgorithmV2::Bip340V1,
        ActorPublicKeyV2::from_bytes(public.serialize())?,
        ActorRoleV2::Holder,
        EventKindV2::Open,
        CanonicalEventV2::from_bytes([0x66])?,
    )?;
    let signature = Secp256k1::signing_only().sign_schnorr_no_aux_rand(body.proposal_digest()?.as_bytes(), &keypair);
    Ok(SignedProposalV2::new(
        body,
        ActorSignatureV2::from_bytes(signature.to_byte_array())?,
    )?)
}

#[tokio::test(flavor = "current_thread")]
async fn update_restart_and_immutable_history_are_exact() -> std::result::Result<(), Box<dyn Error>> {
    let directory = private_directory()?;
    let path = directory.path().join("trust.sqlite");
    let fixture = fixture(30, 600)?;
    let calls = Arc::new(AtomicUsize::new(0));
    let checkpoints = MemoryCheckpointStore::default();
    let mut coordinator = create_coordinator(
        &path,
        &fixture,
        Arc::clone(&calls),
        TransportMode::Normal,
        checkpoints.clone(),
    )
    .await?;
    let applied = coordinator.advance(&fixture.execution).await?;
    let AdvanceOutcome::Applied(finality) = applied else {
        return Err("expected applied update".into());
    };
    assert_eq!(finality.summary().execution_height(), 2);
    assert_eq!(coordinator.current_trust_root()?.height(), 3);
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    drop(coordinator);

    let mut reopened = open_coordinator(
        &path,
        &fixture,
        fixture.config.clone(),
        Arc::clone(&calls),
        TransportMode::Normal,
        checkpoints,
    )
    .await?;
    let before = reopened.current_trust_root()?;
    let by_height = reopened.historical_by_height(2)?.ok_or("missing height proof")?;
    let by_request = reopened
        .historical_by_request(&fixture.request_digest)?
        .ok_or("missing request proof")?;
    assert_eq!(by_request.block_index(), 0);
    assert_eq!(by_request.finality().proof_digest(), by_height.proof_digest());
    assert_eq!(reopened.current_trust_root()?, before);
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    assert!(matches!(
        reopened.advance(&fixture.execution).await?,
        AdvanceOutcome::Replayed(_)
    ));
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn crash_before_persistence_leaves_no_partial_update() -> std::result::Result<(), Box<dyn Error>> {
    let directory = private_directory()?;
    let path = directory.path().join("before.sqlite");
    let fixture = fixture(30, 600)?;
    let calls = Arc::new(AtomicUsize::new(0));
    let checkpoints = MemoryCheckpointStore::default();
    let mut coordinator = create_coordinator(
        &path,
        &fixture,
        Arc::clone(&calls),
        TransportMode::Normal,
        checkpoints.clone(),
    )
    .await?;
    coordinator.inject_fault(FaultPoint::BeforePersistence);
    assert!(matches!(
        coordinator.advance(&fixture.execution).await,
        Err(CoordinatorError::StorageUnavailable)
    ));
    assert_eq!(coordinator.current_trust_root()?.height(), 1);
    drop(coordinator);
    let mut reopened = open_coordinator(
        &path,
        &fixture,
        fixture.config.clone(),
        calls,
        TransportMode::Normal,
        checkpoints,
    )
    .await?;
    assert!(reopened.historical_by_height(2)?.is_none());
    assert!(matches!(
        reopened.advance(&fixture.execution).await?,
        AdvanceOutcome::Applied(_)
    ));
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn ambiguous_post_commit_requires_reopen_then_replays() -> std::result::Result<(), Box<dyn Error>> {
    let directory = private_directory()?;
    let path = directory.path().join("ambiguous.sqlite");
    let fixture = fixture(30, 600)?;
    let calls = Arc::new(AtomicUsize::new(0));
    let checkpoints = MemoryCheckpointStore::default();
    let mut coordinator = create_coordinator(
        &path,
        &fixture,
        Arc::clone(&calls),
        TransportMode::Normal,
        checkpoints.clone(),
    )
    .await?;
    coordinator.inject_fault(FaultPoint::AfterCommit);
    assert!(matches!(
        coordinator.advance(&fixture.execution).await,
        Err(CoordinatorError::AmbiguousCommit)
    ));
    assert!(matches!(
        coordinator.current_trust_root(),
        Err(CoordinatorError::Poisoned)
    ));
    drop(coordinator);
    assert!(matches!(
        open_coordinator(
            &path,
            &fixture,
            fixture.config.clone(),
            Arc::clone(&calls),
            TransportMode::Normal,
            checkpoints.clone(),
        )
        .await,
        Err(CoordinatorError::CheckpointConflict)
    ));
    let mut reopened = TrustCoordinator::recover_finality(
        &path,
        fixture.config.clone(),
        &fixture.execution,
        transport(&fixture, Arc::clone(&calls), TransportMode::Normal),
        MockAuthenticator,
        checkpoints,
    )
    .await?;
    assert_eq!(reopened.current_trust_root()?.height(), 3);
    let calls_before = calls.load(Ordering::SeqCst);
    assert!(matches!(
        reopened.advance(&fixture.execution).await?,
        AdvanceOutcome::Replayed(_)
    ));
    assert_eq!(calls.load(Ordering::SeqCst), calls_before);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn forged_latest_candidate_cannot_recover_from_execution_intent() -> std::result::Result<(), Box<dyn Error>> {
    let directory = private_directory()?;
    let path = directory.path().join("forged-recovery.sqlite");
    let fixture = fixture(30, 600)?;
    let checkpoints = MemoryCheckpointStore::default();
    let mut coordinator = create_coordinator(
        &path,
        &fixture,
        Arc::new(AtomicUsize::new(0)),
        TransportMode::Normal,
        checkpoints.clone(),
    )
    .await?;
    coordinator.inject_fault(FaultPoint::AfterCommit);
    assert!(matches!(
        coordinator.advance(&fixture.execution).await,
        Err(CoordinatorError::AmbiguousCommit)
    ));
    drop(coordinator);

    let mut forged_header = fixture.primary[1].signed_header.header.clone();
    forged_header.app_hash = AppHash::try_from(vec![0x7b_u8; 32])?;
    let forged = light_block(
        forged_header,
        &fixture.primary[1].validators,
        &validator_seeds(),
        "9999999999999999999999999999999999999999",
    )?;
    crate::storage::forge_latest_committing_block_for_test(&path, &fixture.config, &forged)?;
    assert!(matches!(
        TrustCoordinator::recover_finality(
            &path,
            fixture.config.clone(),
            &fixture.execution,
            transport(&fixture, Arc::new(AtomicUsize::new(0)), TransportMode::Normal),
            MockAuthenticator,
            checkpoints,
        )
        .await,
        Err(CoordinatorError::CheckpointConflict)
    ));
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn same_height_conflict_is_rejected_without_fetch() -> std::result::Result<(), Box<dyn Error>> {
    let directory = private_directory()?;
    let path = directory.path().join("conflict.sqlite");
    let fixture = fixture(30, 600)?;
    let calls = Arc::new(AtomicUsize::new(0));
    let mut coordinator = create_coordinator(
        &path,
        &fixture,
        Arc::clone(&calls),
        TransportMode::Normal,
        MemoryCheckpointStore::default(),
    )
    .await?;
    coordinator.advance(&fixture.execution).await?;
    let first_execution = PendingBlockV2::new(
        fixture.config.ledger_chain_id().clone(),
        1,
        fixture.execution.block_time_ms() - 10_000,
        AppHashV2::zero(),
    )?
    .execute()?;
    let conflicting = PendingBlockV2::new(
        fixture.config.ledger_chain_id().clone(),
        2,
        fixture.execution.block_time_ms(),
        first_execution.app_hash().clone(),
    )?
    .execute()?;
    let calls_before = calls.load(Ordering::SeqCst);
    assert!(matches!(
        coordinator.advance(&conflicting).await,
        Err(CoordinatorError::IdempotencyConflict)
    ));
    assert_eq!(calls.load(Ordering::SeqCst), calls_before);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn exact_request_replay_advances_root_and_retains_first_location() -> std::result::Result<(), Box<dyn Error>> {
    let directory = private_directory()?;
    let path = directory.path().join("request-replay.sqlite");
    let fixture = fixture(30, 600)?;
    let calls = Arc::new(AtomicUsize::new(0));
    let checkpoints = MemoryCheckpointStore::default();
    let mut coordinator = create_coordinator(
        &path,
        &fixture,
        Arc::clone(&calls),
        TransportMode::Normal,
        checkpoints.clone(),
    )
    .await?;
    assert!(matches!(
        coordinator.advance(&fixture.execution).await?,
        AdvanceOutcome::Applied(_)
    ));
    assert!(matches!(
        coordinator.advance(&fixture.replay_execution).await?,
        AdvanceOutcome::Applied(_)
    ));
    assert_eq!(coordinator.current_trust_root()?.height(), 4);
    assert_eq!(calls.load(Ordering::SeqCst), 4);
    assert_eq!(
        coordinator
            .historical_by_height(3)?
            .ok_or("missing replay block finality")?
            .summary()
            .execution_height(),
        3
    );
    let first = coordinator
        .historical_by_request(&fixture.request_digest)?
        .ok_or("missing first request location")?;
    assert_eq!(first.finality().summary().execution_height(), 2);
    assert_eq!(first.block_index(), 0);
    drop(coordinator);

    let reopened = open_coordinator(
        &path,
        &fixture,
        fixture.config.clone(),
        calls,
        TransportMode::Normal,
        checkpoints,
    )
    .await?;
    assert_eq!(reopened.current_trust_root()?.height(), 4);
    assert_eq!(
        reopened
            .historical_by_request(&fixture.request_digest)?
            .ok_or("missing first request after restart")?
            .finality()
            .summary()
            .execution_height(),
        2
    );
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn cross_peer_evidence_and_tampered_witness_fail_closed() -> std::result::Result<(), Box<dyn Error>> {
    for (name, mode) in [
        ("cross-peer.sqlite", TransportMode::WrongWitnessEvidence),
        ("tampered-witness.sqlite", TransportMode::TamperedWitness),
    ] {
        let directory = private_directory()?;
        let path = directory.path().join(name);
        let fixture = fixture(30, 600)?;
        let mut coordinator = create_coordinator(
            &path,
            &fixture,
            Arc::new(AtomicUsize::new(0)),
            mode,
            MemoryCheckpointStore::default(),
        )
        .await?;
        assert!(coordinator.advance(&fixture.execution).await.is_err());
        assert_eq!(coordinator.current_trust_root()?.height(), 1);
        assert!(coordinator.historical_by_height(2)?.is_none());
    }
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn optional_witness_outage_still_uses_authenticated_quorum() -> std::result::Result<(), Box<dyn Error>> {
    let directory = private_directory()?;
    let path = directory.path().join("witness-subset.sqlite");
    let mut fixture = fixture(30, 600)?;
    let expanded = SourceConfiguration::new(
        1,
        fixture.config.sources().primary().clone(),
        vec![
            fixture.config.sources().witnesses()[0].clone(),
            peer(0xc1, "4444444444444444444444444444444444444444")?,
        ],
    )?;
    let limits = CoordinatorLimits::new(1024 * 1024, 1024 * 1024, 8 * 1024 * 1024, Duration::from_secs(2), 2)?;
    fixture.config = CoordinatorConfig::new(
        fixture.config.identity(),
        fixture.config.ledger_chain_id().clone(),
        fixture.config.policy(),
        expanded,
        fixture.config.busy_timeout(),
        limits,
        fixture.config.history_limits(),
    )?;
    let checkpoints = MemoryCheckpointStore::default();
    let mut coordinator = create_coordinator(
        &path,
        &fixture,
        Arc::new(AtomicUsize::new(0)),
        TransportMode::FailFirstWitness,
        checkpoints.clone(),
    )
    .await?;
    let applied = coordinator.advance(&fixture.execution).await?;
    let AdvanceOutcome::Applied(finality) = applied else {
        return Err("expected witness-subset update".into());
    };
    assert_eq!(finality.summary().witness_peer_ids().len(), 1);
    assert_eq!(
        finality.summary().witness_peer_ids()[0],
        NodeId::from_str("4444444444444444444444444444444444444444")?
    );
    drop(coordinator);
    let reopened = open_coordinator(
        &path,
        &fixture,
        fixture.config.clone(),
        Arc::new(AtomicUsize::new(0)),
        TransportMode::Normal,
        checkpoints,
    )
    .await?;
    assert_eq!(
        reopened
            .historical_by_height(2)?
            .ok_or("missing subset history")?
            .summary()
            .witness_peer_ids()
            .len(),
        1
    );
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn trace_raw_size_is_enforced_before_authentication() -> std::result::Result<(), Box<dyn Error>> {
    let directory = private_directory()?;
    let path = directory.path().join("oversize.sqlite");
    let fixture = fixture(30, 600)?;
    let mut coordinator = create_coordinator(
        &path,
        &fixture,
        Arc::new(AtomicUsize::new(0)),
        TransportMode::Oversize,
        MemoryCheckpointStore::default(),
    )
    .await?;
    assert!(matches!(
        coordinator.advance(&fixture.execution).await,
        Err(CoordinatorError::InvalidInput(_))
    ));
    assert_eq!(coordinator.current_trust_root()?.height(), 1);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn hung_transport_is_cancelled_at_the_shared_deadline() -> std::result::Result<(), Box<dyn Error>> {
    let directory = private_directory()?;
    let path = directory.path().join("deadline.sqlite");
    let mut fixture = fixture(30, 600)?;
    let limits = CoordinatorLimits::new(
        fixture.config.max_trace_encoded_bytes(),
        fixture.config.max_execution_encoded_bytes(),
        fixture.config.max_proof_bundle_bytes(),
        Duration::from_millis(100),
        fixture.config.sources().witnesses().len(),
    )?;
    fixture.config = CoordinatorConfig::new(
        fixture.config.identity(),
        fixture.config.ledger_chain_id().clone(),
        fixture.config.policy(),
        fixture.config.sources().clone(),
        fixture.config.busy_timeout(),
        limits,
        fixture.config.history_limits(),
    )?;
    let calls = Arc::new(AtomicUsize::new(0));
    let mut coordinator = create_coordinator(
        &path,
        &fixture,
        Arc::clone(&calls),
        TransportMode::Hang,
        MemoryCheckpointStore::default(),
    )
    .await?;
    assert!(matches!(
        coordinator.advance(&fixture.execution).await,
        Err(CoordinatorError::DeadlineExceeded)
    ));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(coordinator.current_trust_root()?.height(), 1);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn ambiguous_rolled_back_bootstrap_is_retryable() -> std::result::Result<(), Box<dyn Error>> {
    let directory = private_directory()?;
    let path = directory.path().join("bootstrap-retry.sqlite");
    let fixture = fixture(30, 600)?;
    let checkpoints = MemoryCheckpointStore::default();
    crate::storage::inject_bootstrap_ambiguous_rollback_once();
    assert!(matches!(
        create_coordinator(
            &path,
            &fixture,
            Arc::new(AtomicUsize::new(0)),
            TransportMode::Normal,
            checkpoints.clone(),
        )
        .await,
        Err(CoordinatorError::AmbiguousCommit)
    ));
    let coordinator = create_coordinator(
        &path,
        &fixture,
        Arc::new(AtomicUsize::new(0)),
        TransportMode::Normal,
        checkpoints,
    )
    .await?;
    assert_eq!(coordinator.current_trust_root()?.height(), 1);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn committed_bootstrap_requires_explicit_pin_recovery() -> std::result::Result<(), Box<dyn Error>> {
    let directory = private_directory()?;
    let path = directory.path().join("bootstrap-checkpoint.sqlite");
    let fixture = fixture(30, 600)?;
    let checkpoints = FailOnceCheckpointStore::new();
    assert!(matches!(
        TrustCoordinator::create(
            &path,
            fixture.config.clone(),
            fixture.root.clone(),
            transport(&fixture, Arc::new(AtomicUsize::new(0)), TransportMode::Normal),
            MockAuthenticator,
            checkpoints.clone(),
        )
        .await,
        Err(CoordinatorError::CheckpointUnavailable)
    ));
    assert!(matches!(
        TrustCoordinator::open(
            &path,
            fixture.config.clone(),
            transport(&fixture, Arc::new(AtomicUsize::new(0)), TransportMode::Normal),
            MockAuthenticator,
            checkpoints.clone(),
        )
        .await,
        Err(CoordinatorError::CheckpointConflict)
    ));
    let recovered = TrustCoordinator::recover_bootstrap(
        &path,
        fixture.config.clone(),
        &fixture.root,
        transport(&fixture, Arc::new(AtomicUsize::new(0)), TransportMode::Normal),
        MockAuthenticator,
        checkpoints,
    )
    .await?;
    assert_eq!(recovered.current_trust_root()?.height(), 1);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn checkpoint_backend_is_cancelled_at_deadline() -> std::result::Result<(), Box<dyn Error>> {
    let directory = private_directory()?;
    let path = directory.path().join("checkpoint-deadline.sqlite");
    let mut fixture = fixture(30, 600)?;
    let limits = CoordinatorLimits::new(
        fixture.config.max_trace_encoded_bytes(),
        fixture.config.max_execution_encoded_bytes(),
        fixture.config.max_proof_bundle_bytes(),
        Duration::from_millis(100),
        fixture.config.sources().witnesses().len(),
    )?;
    fixture.config = CoordinatorConfig::new(
        fixture.config.identity(),
        fixture.config.ledger_chain_id().clone(),
        fixture.config.policy(),
        fixture.config.sources().clone(),
        fixture.config.busy_timeout(),
        limits,
        fixture.config.history_limits(),
    )?;
    assert!(matches!(
        TrustCoordinator::create(
            &path,
            fixture.config.clone(),
            fixture.root.clone(),
            transport(&fixture, Arc::new(AtomicUsize::new(0)), TransportMode::Normal),
            MockAuthenticator,
            HangingCheckpointStore,
        )
        .await,
        Err(CoordinatorError::DeadlineExceeded)
    ));
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn persisted_bundle_tamper_is_detected_on_historical_read() -> std::result::Result<(), Box<dyn Error>> {
    let directory = private_directory()?;
    let path = directory.path().join("tamper.sqlite");
    let fixture = fixture(30, 600)?;
    let checkpoints = MemoryCheckpointStore::default();
    let mut coordinator = create_coordinator(
        &path,
        &fixture,
        Arc::new(AtomicUsize::new(0)),
        TransportMode::Normal,
        checkpoints.clone(),
    )
    .await?;
    coordinator.advance(&fixture.execution).await?;
    drop(coordinator);
    let connection = Connection::open(&path)?;
    let mut proof: Vec<u8> = connection.query_row(
        "SELECT proof_bundle_json FROM finality_updates WHERE execution_height = 2",
        [],
        |row| row.get(0),
    )?;
    proof[0] ^= 1;
    connection.execute(
        "UPDATE finality_updates SET proof_bundle_json = ?1 WHERE execution_height = 2",
        [proof],
    )?;
    drop(connection);
    assert!(matches!(
        open_coordinator(
            &path,
            &fixture,
            fixture.config.clone(),
            Arc::new(AtomicUsize::new(0)),
            TransportMode::Normal,
            checkpoints,
        )
        .await,
        Err(CoordinatorError::StorageCorrupt(_))
    ));
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn recomputed_local_history_cannot_cross_external_checkpoint() -> std::result::Result<(), Box<dyn Error>> {
    let directory = private_directory()?;
    let path = directory.path().join("recomputed-history.sqlite");
    let fixture = fixture(30, 600)?;
    let checkpoints = MemoryCheckpointStore::default();
    let mut coordinator = create_coordinator(
        &path,
        &fixture,
        Arc::new(AtomicUsize::new(0)),
        TransportMode::Normal,
        checkpoints.clone(),
    )
    .await?;
    coordinator.advance(&fixture.execution).await?;
    coordinator.advance(&fixture.replay_execution).await?;
    drop(coordinator);
    crate::storage::rewrite_old_proof_and_local_checkpoint_chain_for_test(&path, &fixture.config)?;
    assert!(matches!(
        open_coordinator(
            &path,
            &fixture,
            fixture.config.clone(),
            Arc::new(AtomicUsize::new(0)),
            TransportMode::Normal,
            checkpoints,
        )
        .await,
        Err(CoordinatorError::CheckpointConflict)
    ));
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn externally_anchored_epoch_preserves_first_request_index() -> std::result::Result<(), Box<dyn Error>> {
    let directory = private_directory()?;
    let path = directory.path().join("history-epoch.sqlite");
    let fixture = fixture(30, 600)?;
    let checkpoints = MemoryCheckpointStore::default();
    let mut coordinator = create_coordinator(
        &path,
        &fixture,
        Arc::new(AtomicUsize::new(0)),
        TransportMode::Normal,
        checkpoints.clone(),
    )
    .await?;
    coordinator.advance(&fixture.execution).await?;
    coordinator.advance(&fixture.replay_execution).await?;
    let intent = coordinator
        .prepare_history_epoch()?
        .ok_or("history seal intent is missing")?;
    let restored_intent = crate::HistorySealIntent::from_canonical_bytes(&intent.canonical_bytes())?;
    assert_eq!(
        coordinator.seal_history_epoch(&restored_intent)?.await?,
        HistorySealOutcome::Sealed {
            first_generation: 0,
            last_generation: 2,
        }
    );
    assert!(coordinator.prepare_history_epoch()?.is_none());
    drop(coordinator);

    let connection = Connection::open(&path)?;
    connection.execute(
        "DELETE FROM request_index WHERE request_digest = ?1",
        [fixture.request_digest.as_bytes().as_slice()],
    )?;
    drop(connection);
    let reopened = open_coordinator(
        &path,
        &fixture,
        fixture.config.clone(),
        Arc::new(AtomicUsize::new(0)),
        TransportMode::Normal,
        checkpoints,
    )
    .await?;
    let archived = reopened
        .historical_by_request(&fixture.request_digest)?
        .ok_or("manifest request index is missing")?;
    assert_eq!(archived.finality().summary().execution_height(), 2);
    assert_eq!(archived.block_index(), 0);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn history_epoch_stops_at_configured_transition_bound() -> std::result::Result<(), Box<dyn Error>> {
    let directory = private_directory()?;
    let path = directory.path().join("history-bounds.sqlite");
    let mut fixture = fixture(30, 600)?;
    fixture.config = CoordinatorConfig::new(
        fixture.config.identity(),
        fixture.config.ledger_chain_id().clone(),
        fixture.config.policy(),
        fixture.config.sources().clone(),
        fixture.config.busy_timeout(),
        CoordinatorLimits::new(
            fixture.config.max_trace_encoded_bytes(),
            fixture.config.max_execution_encoded_bytes(),
            fixture.config.max_proof_bundle_bytes(),
            fixture.config.operation_timeout(),
            fixture.config.sources().witnesses().len(),
        )?,
        HistoryEpochLimits::new(2, fixture.config.max_proof_bundle_bytes(), 1_024)?,
    )?;
    let checkpoints = MemoryCheckpointStore::default();
    let mut coordinator = create_coordinator(
        &path,
        &fixture,
        Arc::new(AtomicUsize::new(0)),
        TransportMode::Normal,
        checkpoints,
    )
    .await?;
    coordinator.advance(&fixture.execution).await?;
    assert!(matches!(
        coordinator.advance(&fixture.replay_execution).await,
        Err(CoordinatorError::HistorySealRequired)
    ));
    let first = coordinator
        .prepare_history_epoch()?
        .ok_or("first bounded history intent is missing")?;
    assert_eq!(first.first_generation(), 0);
    assert_eq!(first.last_generation(), 1);
    coordinator.seal_history_epoch(&first)?.await?;
    coordinator.advance(&fixture.replay_execution).await?;
    let second = coordinator
        .prepare_history_epoch()?
        .ok_or("second bounded history intent is missing")?;
    assert_eq!(second.first_generation(), 3);
    assert_eq!(second.last_generation(), 3);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn later_epoch_planning_does_not_revisit_sealed_proofs() -> std::result::Result<(), Box<dyn Error>> {
    let directory = private_directory()?;
    let path = directory.path().join("history-tail-only.sqlite");
    let fixture = fixture(30, 600)?;
    let checkpoints = MemoryCheckpointStore::default();
    let mut coordinator = create_coordinator(
        &path,
        &fixture,
        Arc::new(AtomicUsize::new(0)),
        TransportMode::Normal,
        checkpoints,
    )
    .await?;
    coordinator.advance(&fixture.execution).await?;
    let first = coordinator
        .prepare_history_epoch()?
        .ok_or("first epoch intent is missing")?;
    coordinator.seal_history_epoch(&first)?.await?;

    let connection = Connection::open(&path)?;
    let mut old_bundle: Vec<u8> = connection.query_row(
        "SELECT proof_bundle_json FROM finality_updates WHERE execution_height = 2",
        [],
        |row| row.get(0),
    )?;
    old_bundle.push(b' ');
    connection.execute(
        "UPDATE finality_updates SET proof_bundle_json = ?1 WHERE execution_height = 2",
        [old_bundle],
    )?;
    drop(connection);

    coordinator.advance(&fixture.replay_execution).await?;
    let second = coordinator
        .prepare_history_epoch()?
        .ok_or("tail epoch intent is missing")?;
    assert_eq!(second.first_generation(), 3);
    assert_eq!(second.last_generation(), 3);
    assert!(matches!(
        coordinator.historical_by_height(2),
        Err(CoordinatorError::StorageCorrupt(_))
    ));
    Ok(())
}

#[test]
fn history_epoch_limits_are_compositional() -> std::result::Result<(), Box<dyn Error>> {
    assert!(HistoryEpochLimits::new(1, 1, 1_024).is_ok());
    assert!(HistoryEpochLimits::new(0, 1, 1_024).is_err());
    assert!(HistoryEpochLimits::new(1, 1, 1_023).is_err());
    let fixture = fixture(30, 600)?;
    let too_small = HistoryEpochLimits::new(1, fixture.config.max_proof_bundle_bytes() - 1, 1_024)?;
    assert!(CoordinatorConfig::new(
        fixture.config.identity(),
        fixture.config.ledger_chain_id().clone(),
        fixture.config.policy(),
        fixture.config.sources().clone(),
        fixture.config.busy_timeout(),
        CoordinatorLimits::new(
            fixture.config.max_trace_encoded_bytes(),
            fixture.config.max_execution_encoded_bytes(),
            fixture.config.max_proof_bundle_bytes(),
            fixture.config.operation_timeout(),
            fixture.config.sources().witnesses().len(),
        )?,
        too_small,
    )
    .is_err());
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn seal_rejects_request_index_moved_to_exact_replay() -> std::result::Result<(), Box<dyn Error>> {
    let directory = private_directory()?;
    let path = directory.path().join("history-index-tamper.sqlite");
    let fixture = fixture(30, 600)?;
    let checkpoints = MemoryCheckpointStore::default();
    let mut coordinator = create_coordinator(
        &path,
        &fixture,
        Arc::new(AtomicUsize::new(0)),
        TransportMode::Normal,
        checkpoints,
    )
    .await?;
    coordinator.advance(&fixture.execution).await?;
    coordinator.advance(&fixture.replay_execution).await?;
    let connection = Connection::open(&path)?;
    connection.execute(
        "UPDATE request_index SET execution_height = 3, block_index = 0 WHERE request_digest = ?1",
        [fixture.request_digest.as_bytes().as_slice()],
    )?;
    drop(connection);
    assert!(matches!(
        coordinator.prepare_history_epoch(),
        Err(CoordinatorError::StorageCorrupt(_) | CoordinatorError::IdempotencyConflict)
    ));
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn history_epoch_pre_cas_failure_recovers_from_exact_intent() -> std::result::Result<(), Box<dyn Error>> {
    let directory = private_directory()?;
    let path = directory.path().join("history-pre-cas.sqlite");
    let fixture = fixture(30, 600)?;
    let checkpoints = FailOnceCheckpointStore::ready();
    let mut coordinator = TrustCoordinator::create(
        &path,
        fixture.config.clone(),
        fixture.root.clone(),
        transport(&fixture, Arc::new(AtomicUsize::new(0)), TransportMode::Normal),
        MockAuthenticator,
        checkpoints.clone(),
    )
    .await?;
    coordinator.advance(&fixture.execution).await?;
    let intent = coordinator
        .prepare_history_epoch()?
        .ok_or("history intent is missing")?;
    checkpoints.fail_next();
    assert!(matches!(
        coordinator.seal_history_epoch(&intent)?.await,
        Err(CoordinatorError::CheckpointUnavailable)
    ));
    drop(coordinator);
    assert!(matches!(
        TrustCoordinator::open(
            &path,
            fixture.config.clone(),
            transport(&fixture, Arc::new(AtomicUsize::new(0)), TransportMode::Normal),
            MockAuthenticator,
            checkpoints.clone(),
        )
        .await,
        Err(CoordinatorError::CheckpointConflict)
    ));
    let recovered = TrustCoordinator::recover_history_epoch(
        &path,
        fixture.config.clone(),
        &intent,
        transport(&fixture, Arc::new(AtomicUsize::new(0)), TransportMode::Normal),
        MockAuthenticator,
        checkpoints,
    )?
    .await?;
    assert_eq!(recovered.current_trust_root()?.height(), 3);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn history_epoch_ambiguous_commit_recovers_from_exact_intent() -> std::result::Result<(), Box<dyn Error>> {
    let directory = private_directory()?;
    let path = directory.path().join("history-ambiguous.sqlite");
    let fixture = fixture(30, 600)?;
    let checkpoints = MemoryCheckpointStore::default();
    let mut coordinator = create_coordinator(
        &path,
        &fixture,
        Arc::new(AtomicUsize::new(0)),
        TransportMode::Normal,
        checkpoints.clone(),
    )
    .await?;
    coordinator.advance(&fixture.execution).await?;
    let intent = coordinator
        .prepare_history_epoch()?
        .ok_or("history intent is missing")?;
    coordinator.inject_fault(FaultPoint::AfterCommit);
    assert!(matches!(
        coordinator.seal_history_epoch(&intent),
        Err(CoordinatorError::AmbiguousCommit)
    ));
    drop(coordinator);
    let recovered = TrustCoordinator::recover_history_epoch(
        &path,
        fixture.config.clone(),
        &intent,
        transport(&fixture, Arc::new(AtomicUsize::new(0)), TransportMode::Normal),
        MockAuthenticator,
        checkpoints,
    )?
    .await?;
    assert_eq!(recovered.current_trust_root()?.height(), 3);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn expired_root_fails_before_any_fetch() -> std::result::Result<(), Box<dyn Error>> {
    let directory = private_directory()?;
    let path = directory.path().join("expired.sqlite");
    let fixture = fixture(300, 60)?;
    let calls = Arc::new(AtomicUsize::new(0));
    let mut coordinator = create_coordinator(
        &path,
        &fixture,
        Arc::clone(&calls),
        TransportMode::Normal,
        MemoryCheckpointStore::default(),
    )
    .await?;
    assert!(matches!(
        coordinator.advance(&fixture.execution).await,
        Err(CoordinatorError::ExpiredTrustRoot)
    ));
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn witness_rotation_requires_exact_consecutive_version_and_restart_pin() -> std::result::Result<(), Box<dyn Error>>
{
    let directory = private_directory()?;
    let path = directory.path().join("rotation.sqlite");
    let fixture = fixture(30, 600)?;
    let next = sources(
        2,
        0xc1,
        "4444444444444444444444444444444444444444",
        0xd1,
        "5555555555555555555555555555555555555555",
    )?;
    let checkpoints = MemoryCheckpointStore::default();
    let mut coordinator = create_coordinator(
        &path,
        &fixture,
        Arc::new(AtomicUsize::new(0)),
        TransportMode::Normal,
        checkpoints.clone(),
    )
    .await?;
    assert_eq!(
        coordinator.rotate_sources(1, next.clone()).await?,
        RotationOutcome::Applied
    );
    assert_eq!(coordinator.current_trust_root()?.height(), 1);
    assert_eq!(coordinator.current_trust_root()?.config_version(), 2);
    assert_eq!(
        coordinator.rotate_sources(2, next.clone()).await?,
        RotationOutcome::AlreadyCurrent
    );
    let skipped = sources(
        4,
        0xe1,
        "6666666666666666666666666666666666666666",
        0xf1,
        "7777777777777777777777777777777777777777",
    )?;
    assert!(matches!(
        coordinator.rotate_sources(2, skipped).await,
        Err(CoordinatorError::ConfigurationConflict)
    ));
    drop(coordinator);
    assert!(matches!(
        open_coordinator(
            &path,
            &fixture,
            fixture.config.clone(),
            Arc::new(AtomicUsize::new(0)),
            TransportMode::Normal,
            checkpoints.clone(),
        )
        .await,
        Err(CoordinatorError::StorageCorrupt(_))
    ));
    let next_config = fixture.config.with_sources(next)?;
    let reopened = open_coordinator(
        &path,
        &fixture,
        next_config,
        Arc::new(AtomicUsize::new(0)),
        TransportMode::Normal,
        checkpoints,
    )
    .await?;
    assert_eq!(reopened.current_trust_root()?.config_version(), 2);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn witness_expansion_that_exceeds_bundle_budget_is_rejected() -> std::result::Result<(), Box<dyn Error>> {
    let directory = private_directory()?;
    let path = directory.path().join("rotation-budget.sqlite");
    let fixture = fixture(30, 600)?;
    let expanded = SourceConfiguration::new(
        2,
        peer(0xc1, "4444444444444444444444444444444444444444")?,
        vec![
            peer(0xd1, "5555555555555555555555555555555555555555")?,
            peer(0xe1, "6666666666666666666666666666666666666666")?,
        ],
    )?;
    let mut coordinator = create_coordinator(
        &path,
        &fixture,
        Arc::new(AtomicUsize::new(0)),
        TransportMode::Normal,
        MemoryCheckpointStore::default(),
    )
    .await?;
    assert!(matches!(
        coordinator.rotate_sources(1, expanded).await,
        Err(CoordinatorError::InvalidConfiguration(_))
    ));
    assert_eq!(coordinator.source_configuration()?.version(), 1);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn conflicting_second_engine_is_locked_out() -> std::result::Result<(), Box<dyn Error>> {
    let directory = private_directory()?;
    let path = directory.path().join("locked.sqlite");
    let fixture = fixture(30, 600)?;
    let checkpoints = MemoryCheckpointStore::default();
    let _first = create_coordinator(
        &path,
        &fixture,
        Arc::new(AtomicUsize::new(0)),
        TransportMode::Normal,
        checkpoints.clone(),
    )
    .await?;
    assert!(matches!(
        open_coordinator(
            &path,
            &fixture,
            fixture.config.clone(),
            Arc::new(AtomicUsize::new(0)),
            TransportMode::Normal,
            checkpoints,
        )
        .await,
        Err(CoordinatorError::StorageUnavailable)
    ));
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn copied_database_fork_loses_external_checkpoint_cas() -> std::result::Result<(), Box<dyn Error>> {
    let directory = private_directory()?;
    let first_path = directory.path().join("fork-a.sqlite");
    let copied_path = directory.path().join("fork-b.sqlite");
    let fixture = fixture(30, 600)?;
    let checkpoints = MemoryCheckpointStore::default();
    let initial = create_coordinator(
        &first_path,
        &fixture,
        Arc::new(AtomicUsize::new(0)),
        TransportMode::Normal,
        checkpoints.clone(),
    )
    .await?;
    drop(initial);
    std::fs::copy(&first_path, &copied_path)?;

    let first_sources = sources(
        2,
        0xc1,
        "4444444444444444444444444444444444444444",
        0xd1,
        "5555555555555555555555555555555555555555",
    )?;
    let copied_sources = sources(
        2,
        0xe1,
        "6666666666666666666666666666666666666666",
        0xf1,
        "7777777777777777777777777777777777777777",
    )?;
    let mut first = open_coordinator(
        &first_path,
        &fixture,
        fixture.config.clone(),
        Arc::new(AtomicUsize::new(0)),
        TransportMode::Normal,
        checkpoints.clone(),
    )
    .await?;
    let mut copied = open_coordinator(
        &copied_path,
        &fixture,
        fixture.config.clone(),
        Arc::new(AtomicUsize::new(0)),
        TransportMode::Normal,
        checkpoints.clone(),
    )
    .await?;
    assert_eq!(
        first.rotate_sources(1, first_sources.clone()).await?,
        RotationOutcome::Applied
    );
    assert!(matches!(
        copied.rotate_sources(1, copied_sources.clone()).await,
        Err(CoordinatorError::CheckpointConflict)
    ));
    assert!(matches!(copied.current_trust_root(), Err(CoordinatorError::Poisoned)));
    drop(first);
    drop(copied);

    let first_config = fixture.config.with_sources(first_sources)?;
    let reopened = open_coordinator(
        &first_path,
        &fixture,
        first_config,
        Arc::new(AtomicUsize::new(0)),
        TransportMode::Normal,
        checkpoints.clone(),
    )
    .await?;
    assert_eq!(reopened.current_trust_root()?.config_version(), 2);
    drop(reopened);
    let copied_config = fixture.config.with_sources(copied_sources)?;
    assert!(matches!(
        open_coordinator(
            &copied_path,
            &fixture,
            copied_config,
            Arc::new(AtomicUsize::new(0)),
            TransportMode::Normal,
            checkpoints,
        )
        .await,
        Err(CoordinatorError::CheckpointConflict)
    ));
    Ok(())
}

#[test]
fn duplicate_peer_identity_is_rejected_at_configuration() -> std::result::Result<(), Box<dyn Error>> {
    let same = peer(0xa1, PRIMARY_NODE)?;
    assert!(matches!(
        SourceConfiguration::new(1, same.clone(), vec![same]),
        Err(CoordinatorError::InvalidConfiguration(_))
    ));
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn create_never_repurposes_an_existing_database() -> std::result::Result<(), Box<dyn Error>> {
    let directory = private_directory()?;
    let path = directory.path().join("unrelated.sqlite");
    let unrelated = Connection::open(&path)?;
    unrelated.execute("CREATE TABLE unrelated(value INTEGER NOT NULL)", [])?;
    unrelated.execute("INSERT INTO unrelated(value) VALUES(7)", [])?;
    drop(unrelated);
    let fixture = fixture(30, 600)?;
    assert!(matches!(
        create_coordinator(
            &path,
            &fixture,
            Arc::new(AtomicUsize::new(0)),
            TransportMode::Normal,
            MemoryCheckpointStore::default(),
        )
        .await,
        Err(CoordinatorError::StorageUnavailable)
    ));
    let unrelated = Connection::open(&path)?;
    let value: i64 = unrelated.query_row("SELECT value FROM unrelated", [], |row| row.get(0))?;
    assert_eq!(value, 7);
    let coordinator_tables: i64 = unrelated.query_row(
        "SELECT COUNT(*) FROM sqlite_schema WHERE name = 'coordinator_meta'",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(coordinator_tables, 0);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn invalid_bootstrap_is_rejected_before_filesystem_mutation() -> std::result::Result<(), Box<dyn Error>> {
    let directory = private_directory()?;
    let path = directory.path().join("prevalidated.sqlite");
    let mut fixture = fixture(30, 600)?;
    let limits = CoordinatorLimits::new(1_024, 512 * 1_024, 1_024 * 1_024, Duration::from_secs(1), 1)?;
    fixture.config = CoordinatorConfig::new(
        fixture.config.identity(),
        fixture.config.ledger_chain_id().clone(),
        fixture.config.policy(),
        fixture.config.sources().clone(),
        fixture.config.busy_timeout(),
        limits,
        fixture.config.history_limits(),
    )?;
    assert!(matches!(
        create_coordinator(
            &path,
            &fixture,
            Arc::new(AtomicUsize::new(0)),
            TransportMode::Normal,
            MemoryCheckpointStore::default(),
        )
        .await,
        Err(CoordinatorError::InvalidInput(_))
    ));
    assert!(!path.exists());
    assert!(!path.with_extension("cometbft-client.lock").exists());
    Ok(())
}
