use core::time::Duration;
use std::str::FromStr;

use ed25519_consensus::SigningKey;
use proptest::prelude::*;
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
use thunderbolt_ledger::{AppHashV2, ExecutedBlockV2, LedgerChainIdV2, PendingBlockV2};

use super::{sha256_header_hash, FinalityError, FinalityPolicy, FinalityVerifier, PinnedTrustRoot};
use super::{
    AuthenticatedTrace, TraceAuthenticationCapability, TraceAuthenticationRequest, TraceRole, TraceSourceAuthenticator,
    THUNDERBOLT_APP_VERSION_V2,
};

const CHAIN_ID: &str = "thunderbolt-regtest-2";
const BASE_TIME_SECONDS: i64 = 1_700_000_000;

struct Fixture {
    verifier: FinalityVerifier<TestAuthenticator>,
    root: PinnedTrustRoot,
    trace: Vec<LightBlock>,
    witness_trace: Vec<LightBlock>,
    execution: ExecutedBlockV2,
    now: Time,
}

#[derive(Clone, Debug)]
struct TestAuthenticator {
    duplicate_witness: bool,
}

impl TestAuthenticator {
    const fn distinct() -> Self {
        Self {
            duplicate_witness: false,
        }
    }

    const fn duplicate() -> Self {
        Self {
            duplicate_witness: true,
        }
    }
}

impl TraceSourceAuthenticator for TestAuthenticator {
    type Error = &'static str;

    fn authenticate<'a>(
        &self,
        request: TraceAuthenticationRequest<'a>,
        capability: TraceAuthenticationCapability<'a>,
    ) -> Result<AuthenticatedTrace<'a>, Self::Error> {
        if request.ledger_chain_id().as_str() != CHAIN_ID
            || request.blocks().is_empty()
            || request.first_height() > request.last_height()
        {
            return Err("invalid test authentication request");
        }
        let peer = match request.role() {
            TraceRole::Primary => "2222222222222222222222222222222222222222",
            TraceRole::Witness(_) if self.duplicate_witness => "2222222222222222222222222222222222222222",
            TraceRole::Witness(index) => match index {
                0 => "3333333333333333333333333333333333333333",
                1 => "4444444444444444444444444444444444444444",
                _ => return Err("unsupported test witness"),
            },
        };
        Ok(capability.bind(NodeId::from_str(peer).unwrap()))
    }
}

fn validator_seeds() -> [[u8; 32]; 4] {
    [[1_u8; 32], [2_u8; 32], [3_u8; 32], [4_u8; 32]]
}

fn app_hash(bytes: &[u8; 32]) -> AppHash {
    AppHash::try_from(bytes.to_vec()).unwrap()
}

fn validator_set(seeds: &[[u8; 32]]) -> ValidatorSet {
    let validators = seeds
        .iter()
        .map(|seed| {
            let signing_key = tendermint::private_key::Ed25519::try_from(seed.as_slice()).unwrap();
            ValidatorInfo::new(
                PublicKey::from(signing_key.verification_key()),
                Power::try_from(1_u64).unwrap(),
            )
        })
        .collect();
    ValidatorSet::without_proposer(validators)
}

fn build_header(
    validators: &ValidatorSet,
    height: u64,
    time: Time,
    last_header_hash: Option<Hash>,
    state_app_hash: &[u8; 32],
) -> Header {
    let validator_hash = validators.hash();
    Header {
        version: block::header::Version {
            block: 11,
            app: THUNDERBOLT_APP_VERSION_V2,
        },
        chain_id: chain::Id::from_str(CHAIN_ID).unwrap(),
        height: block::Height::try_from(height).unwrap(),
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
        app_hash: app_hash(state_app_hash),
        last_results_hash: None,
        evidence_hash: None,
        proposer_address: validators.validators()[0].address,
    }
}

fn sign_commit(header: &Header, validators: &ValidatorSet, seeds: &[[u8; 32]]) -> Commit {
    let header_hash = header.hash();
    let block_id = block::Id {
        hash: header_hash,
        part_set_header: PartSetHeader::new(1, header_hash).unwrap(),
    };
    let round = Round::try_from(1_u32).unwrap();
    let signatures = validators
        .validators()
        .iter()
        .enumerate()
        .map(|(index, validator)| {
            let seed = seeds
                .iter()
                .find(|seed| {
                    let key = tendermint::private_key::Ed25519::try_from(seed.as_slice()).unwrap();
                    validator.address == tendermint::account::Id::from(key.verification_key())
                })
                .unwrap();
            let dummy_signature = Signature::new(vec![0_u8; 64]).unwrap();
            let vote = Vote {
                vote_type: vote::Type::Precommit,
                height: header.height,
                round,
                block_id: Some(block_id),
                timestamp: Some(header.time),
                validator_address: validator.address,
                validator_index: ValidatorIndex::try_from(u32::try_from(index).unwrap()).unwrap(),
                signature: dummy_signature,
                extension: Vec::new(),
                extension_signature: None,
            };
            let sign_bytes = SignedVote::from_vote(vote, header.chain_id.clone())
                .unwrap()
                .sign_bytes();
            let signing_key = SigningKey::from(*seed);
            CommitSig::BlockIdFlagCommit {
                validator_address: validator.address,
                timestamp: header.time,
                signature: Some(signing_key.sign(&sign_bytes).into()),
            }
        })
        .collect();
    Commit {
        height: header.height,
        round,
        block_id,
        signatures,
    }
}

fn generate_light_block(header: Header, validators: &ValidatorSet, seeds: &[[u8; 32]], provider: &str) -> LightBlock {
    let commit = sign_commit(&header, validators, seeds);
    let signed_header = SignedHeader::new(header, commit).unwrap();
    let provider = NodeId::from_str(provider).unwrap();
    LightBlock::new(signed_header, validators.clone(), validators.clone(), provider)
}

fn build_fixture(committing_app_hash: Option<[u8; 32]>) -> Fixture {
    let chain_id = LedgerChainIdV2::new(CHAIN_ID).unwrap();
    let zero = AppHashV2::zero();
    let first_time_ms = u64::try_from(BASE_TIME_SECONDS).unwrap() * 1_000;
    let first_execution = PendingBlockV2::new(chain_id.clone(), 1, first_time_ms, zero.clone())
        .unwrap()
        .execute()
        .unwrap();
    let second_time_ms = first_time_ms + 10_000;
    let execution = PendingBlockV2::new(chain_id.clone(), 2, second_time_ms, first_execution.app_hash().clone())
        .unwrap()
        .execute()
        .unwrap();

    let seeds = validator_seeds();
    let validators = validator_set(&seeds);
    let header_one = build_header(
        &validators,
        1,
        Time::from_unix_timestamp(BASE_TIME_SECONDS, 0).unwrap(),
        None,
        zero.as_bytes(),
    );
    let header_one_hash = header_one.hash();
    let header_two = build_header(
        &validators,
        2,
        Time::from_unix_timestamp(BASE_TIME_SECONDS + 10, 0).unwrap(),
        Some(header_one_hash),
        first_execution.app_hash().as_bytes(),
    );
    let header_two_hash = header_two.hash();
    let committed = committing_app_hash.unwrap_or_else(|| *execution.app_hash().as_bytes());
    let header_three = build_header(
        &validators,
        3,
        Time::from_unix_timestamp(BASE_TIME_SECONDS + 20, 0).unwrap(),
        Some(header_two_hash),
        &committed,
    );

    let trusted_light_block = generate_light_block(
        header_one,
        &validators,
        &seeds,
        "1111111111111111111111111111111111111111",
    );
    let trace = vec![
        generate_light_block(
            header_two.clone(),
            &validators,
            &seeds,
            "2222222222222222222222222222222222222222",
        ),
        generate_light_block(
            header_three.clone(),
            &validators,
            &seeds,
            "2222222222222222222222222222222222222222",
        ),
    ];
    let witness_trace = vec![
        generate_light_block(
            header_two,
            &validators,
            &seeds,
            "3333333333333333333333333333333333333333",
        ),
        generate_light_block(
            header_three,
            &validators,
            &seeds,
            "3333333333333333333333333333333333333333",
        ),
    ];
    let policy = FinalityPolicy::new(Duration::from_secs(60), Duration::from_secs(1), 4, 8, 1, 2).unwrap();
    let pinned_hash = sha256_header_hash(&trusted_light_block.signed_header.header).unwrap();
    let root = PinnedTrustRoot::new(trusted_light_block, &chain_id, 1, pinned_hash, policy).unwrap();
    let verifier = FinalityVerifier::new(chain_id, policy, TestAuthenticator::distinct());
    Fixture {
        verifier,
        root,
        trace,
        witness_trace,
        execution,
        now: Time::from_unix_timestamp(BASE_TIME_SECONDS + 30, 0).unwrap(),
    }
}

#[test]
fn adjacent_quorum_headers_bind_the_execution_app_hash_one_height_later() {
    let fixture = build_fixture(None);
    let update = fixture
        .verifier
        .verify_execution_at(
            &fixture.root,
            &fixture.trace,
            &[fixture.witness_trace.as_slice()],
            &fixture.execution,
            fixture.now,
        )
        .unwrap();
    let receipt = update.receipt();
    assert_eq!(receipt.ledger_chain_id().as_str(), CHAIN_ID);
    assert_eq!(receipt.application_version(), THUNDERBOLT_APP_VERSION_V2);
    assert_eq!(receipt.execution_height(), 2);
    assert_eq!(receipt.execution_block_time_ms(), fixture.execution.block_time_ms());
    assert_eq!(receipt.application_hash(), fixture.execution.app_hash());
    assert_eq!(receipt.committing_height(), 3);
    assert_eq!(receipt.witness_peer_ids().len(), 1);
    assert_ne!(receipt.primary_peer_id(), receipt.witness_peer_ids()[0]);
    assert_eq!(update.next_trust_root().height(), 3);
    assert_ne!(receipt.execution_header_hash(), receipt.committing_header_hash());
}

#[test]
fn execution_is_not_final_without_the_next_signed_header() {
    let fixture = build_fixture(None);
    let error = fixture
        .verifier
        .verify_execution_at(
            &fixture.root,
            &fixture.trace[..1],
            &[&fixture.witness_trace[..1]],
            &fixture.execution,
            fixture.now,
        )
        .unwrap_err();
    assert!(matches!(error, FinalityError::InvalidTrace(_)));
}

#[test]
fn wrong_operator_pin_is_rejected() {
    let fixture = build_fixture(None);
    let mut wrong = *fixture.root.header_hash();
    wrong[0] ^= 1;
    let error = PinnedTrustRoot::new(
        fixture.root.light_block().clone(),
        fixture.verifier.ledger_chain_id(),
        fixture.root.height(),
        wrong,
        fixture.verifier.policy(),
    )
    .unwrap_err();
    assert!(matches!(error, FinalityError::InvalidTrustRoot(_)));
}

#[test]
fn wrong_abci_application_version_is_rejected_at_the_pin() {
    let fixture = build_fixture(None);
    let mut wrong_block = fixture.root.light_block().clone();
    wrong_block.signed_header.header.version.app = THUNDERBOLT_APP_VERSION_V2 + 1;
    let wrong_hash = sha256_header_hash(&wrong_block.signed_header.header).unwrap();
    let error = PinnedTrustRoot::new(
        wrong_block,
        fixture.verifier.ledger_chain_id(),
        fixture.root.height(),
        wrong_hash,
        fixture.verifier.policy(),
    )
    .unwrap_err();
    assert!(matches!(error, FinalityError::InvalidTrustRoot(_)));
}

#[test]
fn an_already_verified_execution_header_can_be_the_trust_root() {
    let fixture = build_fixture(None);
    let execution_root_block = fixture.trace[0].clone();
    let execution_root_hash = sha256_header_hash(&execution_root_block.signed_header.header).unwrap();
    let execution_root = PinnedTrustRoot::new(
        execution_root_block,
        fixture.verifier.ledger_chain_id(),
        2,
        execution_root_hash,
        fixture.verifier.policy(),
    )
    .unwrap();
    let update = fixture
        .verifier
        .verify_execution_at(
            &execution_root,
            &fixture.trace[1..],
            &[&fixture.witness_trace[1..]],
            &fixture.execution,
            fixture.now,
        )
        .unwrap();
    assert_eq!(update.receipt().execution_height(), 2);
    assert_eq!(update.next_trust_root().height(), 3);
}

#[test]
fn execution_time_must_match_the_signed_height_header() {
    let fixture = build_fixture(None);
    let wrong_time_execution = PendingBlockV2::new(
        fixture.verifier.ledger_chain_id().clone(),
        fixture.execution.height(),
        fixture.execution.block_time_ms() + 1,
        fixture.execution.previous_app_hash().clone(),
    )
    .unwrap()
    .execute()
    .unwrap();
    let error = fixture
        .verifier
        .verify_execution_at(
            &fixture.root,
            &fixture.trace,
            &[fixture.witness_trace.as_slice()],
            &wrong_time_execution,
            fixture.now,
        )
        .unwrap_err();
    assert!(matches!(error, FinalityError::ExecutionBinding(_)));
}

#[test]
fn execution_previous_app_hash_must_match_the_signed_height_header() {
    let fixture = build_fixture(None);
    let mut wrong_previous = [9_u8; 32];
    if wrong_previous == *fixture.execution.previous_app_hash().as_bytes() {
        wrong_previous[0] ^= 1;
    }
    let wrong_previous_execution = PendingBlockV2::new(
        fixture.verifier.ledger_chain_id().clone(),
        fixture.execution.height(),
        fixture.execution.block_time_ms(),
        AppHashV2::from_bytes(wrong_previous).unwrap(),
    )
    .unwrap()
    .execute()
    .unwrap();
    let error = fixture
        .verifier
        .verify_execution_at(
            &fixture.root,
            &fixture.trace,
            &[fixture.witness_trace.as_slice()],
            &wrong_previous_execution,
            fixture.now,
        )
        .unwrap_err();
    assert!(matches!(error, FinalityError::ExecutionBinding(_)));
}

#[test]
fn broken_header_predecessor_is_rejected_before_receipt_creation() {
    let mut fixture = build_fixture(None);
    let wrong_hash = fixture.trace[0].signed_header.header.validators_hash;
    fixture.trace[1]
        .signed_header
        .header
        .last_block_id
        .as_mut()
        .unwrap()
        .hash = wrong_hash;
    let error = fixture
        .verifier
        .verify_execution_at(
            &fixture.root,
            &fixture.trace,
            &[fixture.witness_trace.as_slice()],
            &fixture.execution,
            fixture.now,
        )
        .unwrap_err();
    assert!(matches!(error, FinalityError::InvalidTrace(_)));
}

#[test]
fn missing_quorum_signature_is_rejected() {
    use tendermint::block::CommitSig;

    let mut fixture = build_fixture(None);
    fixture.trace[1].signed_header.commit.signatures[1] = CommitSig::BlockIdFlagAbsent;
    fixture.trace[1].signed_header.commit.signatures[2] = CommitSig::BlockIdFlagAbsent;
    let error = fixture
        .verifier
        .verify_execution_at(
            &fixture.root,
            &fixture.trace,
            &[fixture.witness_trace.as_slice()],
            &fixture.execution,
            fixture.now,
        )
        .unwrap_err();
    assert!(matches!(error, FinalityError::LightClientVerification));
}

#[test]
fn validator_address_public_key_mismatch_is_rejected_before_vote_tally() {
    let mut fixture = build_fixture(None);
    fixture.trace[0].validators.validators[0].address = fixture.trace[0].validators.validators[1].address;
    let error = fixture
        .verifier
        .verify_execution_at(
            &fixture.root,
            &fixture.trace,
            &[fixture.witness_trace.as_slice()],
            &fixture.execution,
            fixture.now,
        )
        .unwrap_err();
    assert!(matches!(error, FinalityError::InvalidTrace(_)));
}

#[test]
fn non_thunderbolt_app_hash_width_is_rejected_before_crypto() {
    let mut fixture = build_fixture(None);
    fixture.trace[0].signed_header.header.app_hash = AppHash::try_from(vec![7_u8; 31]).unwrap();
    let error = fixture
        .verifier
        .verify_execution_at(
            &fixture.root,
            &fixture.trace,
            &[fixture.witness_trace.as_slice()],
            &fixture.execution,
            fixture.now,
        )
        .unwrap_err();
    assert!(matches!(error, FinalityError::InvalidTrace(_)));
}

#[test]
fn signature_vector_must_match_the_bounded_validator_set() {
    let mut fixture = build_fixture(None);
    fixture.trace[0]
        .signed_header
        .commit
        .signatures
        .push(CommitSig::BlockIdFlagAbsent);
    let error = fixture
        .verifier
        .verify_execution_at(
            &fixture.root,
            &fixture.trace,
            &[fixture.witness_trace.as_slice()],
            &fixture.execution,
            fixture.now,
        )
        .unwrap_err();
    assert!(matches!(error, FinalityError::InvalidTrace(_)));
}

#[test]
fn policy_rejects_an_excessive_signature_work_product() {
    let error = FinalityPolicy::new(Duration::from_secs(60), Duration::from_secs(1), 64, 2_048, 1, 4).unwrap_err();
    assert!(matches!(error, FinalityError::InvalidPolicy(_)));
}

#[test]
fn public_verification_uses_current_system_time_and_rejects_expired_roots() {
    let fixture = build_fixture(None);
    let error = fixture
        .verifier
        .verify_execution(
            &fixture.root,
            &fixture.trace,
            &[fixture.witness_trace.as_slice()],
            &fixture.execution,
        )
        .unwrap_err();
    assert!(matches!(error, FinalityError::LightClientVerification));
}

#[test]
fn primary_only_verification_cannot_create_a_finality_receipt() {
    let fixture = build_fixture(None);
    let error = fixture
        .verifier
        .verify_execution_at(&fixture.root, &fixture.trace, &[], &fixture.execution, fixture.now)
        .unwrap_err();
    assert!(matches!(error, FinalityError::WitnessVerification(_)));
}

#[test]
fn a_distinct_valid_but_conflicting_witness_chain_is_rejected() {
    let fixture = build_fixture(None);
    let mut wrong = *fixture.execution.app_hash().as_bytes();
    wrong[0] ^= 1;
    let conflicting = build_fixture(Some(wrong));
    let error = fixture
        .verifier
        .verify_execution_at(
            &fixture.root,
            &fixture.trace,
            &[conflicting.witness_trace.as_slice()],
            &fixture.execution,
            fixture.now,
        )
        .unwrap_err();
    assert!(matches!(error, FinalityError::WitnessVerification(_)));
}

#[test]
fn a_second_claim_from_the_primary_provider_is_not_a_witness() {
    let fixture = build_fixture(None);
    let verifier = FinalityVerifier::new(
        fixture.verifier.ledger_chain_id().clone(),
        fixture.verifier.policy(),
        TestAuthenticator::duplicate(),
    );
    let error = verifier
        .verify_execution_at(
            &fixture.root,
            &fixture.trace,
            &[fixture.trace.as_slice()],
            &fixture.execution,
            fixture.now,
        )
        .unwrap_err();
    assert!(matches!(error, FinalityError::WitnessVerification(_)));
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(96))]

    #[test]
    fn any_distinct_signed_committing_app_hash_is_rejected(candidate in any::<[u8; 32]>()) {
        let valid = build_fixture(None);
        prop_assume!(candidate != *valid.execution.app_hash().as_bytes());
        let fixture = build_fixture(Some(candidate));
        let result = fixture.verifier.verify_execution_at(
            &fixture.root,
            &fixture.trace,
            &[fixture.witness_trace.as_slice()],
            &fixture.execution,
            fixture.now,
        );
        prop_assert!(matches!(result, Err(FinalityError::ExecutionBinding(_))));
    }
}
