use std::error::Error;
use std::fs;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::PathBuf;
use std::sync::{Arc, Barrier};

use bytes::Bytes;
use proptest::prelude::*;
use rusqlite::Connection;
use secp256k1::{Keypair, Secp256k1, SecretKey, XOnlyPublicKey};
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use tendermint_abci::Application;
use tendermint_proto::google::protobuf::Timestamp;
use tendermint_proto::v0_38::abci::{
    response_offer_snapshot, response_process_proposal, response_verify_vote_extension, CheckTxType, CommitInfo,
    RequestCheckTx, RequestExtendVote, RequestFinalizeBlock, RequestInfo, RequestInitChain, RequestOfferSnapshot,
    RequestPrepareProposal, RequestProcessProposal, RequestQuery, RequestVerifyVoteExtension, ValidatorUpdate,
};
use tendermint_proto::v0_38::crypto::{public_key, PublicKey};
use thunderbolt_floor::{FloorCasRequest, FloorLedgerChainId, VaultCheckpoint};
use thunderbolt_floor_app::{
    ActorRequestNonce, FloorAppHash, FloorApplication, FloorCasAuthorization, FloorGenesis, FloorOperatorKey,
    RegistryEntry,
};
use thunderbolt_keystore::{
    CommitteeDescriptorDigest, DeploymentBinding, DeploymentId, Network, NodeId, VaultIdentity, VaultRevision,
    VaultRole, VaultStateDigest,
};

use crate::app::expected_consensus_parameters;
use crate::*;

type TestResult<T> = std::result::Result<T, Box<dyn Error>>;

#[derive(Clone, Copy)]
struct PanicFatal;

impl FatalAbciHandler for PanicFatal {
    fn terminate(&self, failure: FatalAbciFailure) -> ! {
        std::panic::resume_unwind(Box::new(failure))
    }
}

struct Fixture {
    _directory: TempDir,
    path: PathBuf,
    genesis: FloorGenesis,
    validators: FloorValidatorGenesisV2,
    identities: [VaultIdentity; 2],
    keys: [Keypair; 2],
}

impl Fixture {
    fn new() -> TestResult<Self> {
        let directory = private_temp_dir()?;
        let path = directory.path().join("floor.sqlite");
        let chain_id = FloorLedgerChainId::new(b"floor-abci-test".to_vec())?;
        let validators = validator_genesis()?;
        let profile = FloorConsensusProfileV2::derive(&chain_id, &validators)?;
        let keys = [keypair(1)?, keypair(2)?];
        let identities = [identity(0x41)?, identity(0x42)?];
        let entries = identities
            .iter()
            .zip(&keys)
            .map(|(identity, key)| Ok(RegistryEntry::new(*identity, operator_key(key)?)?))
            .collect::<TestResult<Vec<_>>>()?;
        let genesis = FloorGenesis::new(chain_id, *profile.as_bytes(), entries)?;
        Ok(Self {
            _directory: directory,
            path,
            genesis,
            validators,
            identities,
            keys,
        })
    }

    fn adapter(&self) -> TestResult<ThunderboltFloorAbci<PanicFatal>> {
        let application = FloorApplication::open(&self.path, self.genesis.clone())?;
        Ok(ThunderboltFloorAbci::new(
            application,
            self.validators.clone(),
            PanicFatal,
        )?)
    }
}

fn private_temp_dir() -> std::io::Result<TempDir> {
    let directory = TempDir::new()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))?;
    }
    Ok(directory)
}

fn validator_genesis() -> TestResult<FloorValidatorGenesisV2> {
    let mut key = [0x66; 32];
    key[0] = 0x58;
    Ok(FloorValidatorGenesisV2::new(vec![ValidatorUpdate {
        pub_key: Some(PublicKey {
            sum: Some(public_key::Sum::Ed25519(key.to_vec())),
        }),
        power: 10,
    }])?)
}

fn keypair(byte: u8) -> TestResult<Keypair> {
    let secret = SecretKey::from_byte_array([byte; 32])?;
    Ok(Keypair::from_secret_key(&Secp256k1::new(), &secret))
}

fn operator_key(keypair: &Keypair) -> TestResult<FloorOperatorKey> {
    let (public, _) = XOnlyPublicKey::from_keypair(keypair);
    Ok(FloorOperatorKey::new(public.serialize())?)
}

fn identity(node: u8) -> TestResult<VaultIdentity> {
    Ok(VaultIdentity::new(
        Network::Regtest,
        VaultRole::CommitteeMember,
        NodeId::new([node; 32]),
        DeploymentBinding::new(
            DeploymentId::new([0x51; 32])?,
            7,
            CommitteeDescriptorDigest::new([0x52; 32])?,
        )?,
    ))
}

fn checkpoint(revision: u64, byte: u8) -> VaultCheckpoint {
    VaultCheckpoint::new(VaultRevision::new(revision), VaultStateDigest::new([byte; 32]))
}

fn signed_tx(
    fixture: &Fixture,
    participant: usize,
    nonce: u8,
    expected: Option<VaultCheckpoint>,
    next: VaultCheckpoint,
    target_height: u64,
    previous: FloorAppHash,
) -> TestResult<Vec<u8>> {
    let cas = FloorCasRequest::new(
        fixture.genesis.chain_id(),
        fixture.identities[participant],
        expected,
        next,
    )?;
    let authorization = FloorCasAuthorization::new(
        cas,
        operator_key(&fixture.keys[participant])?,
        ActorRequestNonce::new([nonce; 32])?,
        target_height,
        previous,
    )?;
    let signature = Secp256k1::signing_only()
        .sign_schnorr_no_aux_rand(authorization.request_digest().as_bytes(), &fixture.keys[participant])
        .to_byte_array();
    Ok(encode_signed_cas(&authorization.authorize(signature)?)?)
}

fn timestamp(ms: u64) -> Timestamp {
    Timestamp {
        seconds: i64::try_from(ms / 1_000).unwrap_or(i64::MAX),
        nanos: i32::try_from((ms % 1_000) * 1_000_000).unwrap_or(0),
    }
}

fn prepare(height: i64, time_ms: u64, txs: Vec<Bytes>) -> RequestPrepareProposal {
    RequestPrepareProposal {
        max_tx_bytes: i64::try_from(MAX_BLOCK_TRANSACTION_BYTES).unwrap_or(0),
        txs,
        local_last_commit: None,
        misbehavior: Vec::new(),
        height,
        time: Some(timestamp(time_ms)),
        next_validators_hash: vec![0x61; 32].into(),
        proposer_address: vec![0x62; 20].into(),
    }
}

fn finalize(height: i64, time_ms: u64, txs: Vec<Bytes>) -> RequestFinalizeBlock {
    RequestFinalizeBlock {
        txs,
        decided_last_commit: Some(CommitInfo::default()),
        misbehavior: Vec::new(),
        hash: vec![u8::try_from(height).unwrap_or(0); 32].into(),
        height,
        time: Some(timestamp(time_ms)),
        next_validators_hash: vec![0x61; 32].into(),
        proposer_address: vec![0x62; 20].into(),
    }
}

fn process(request: &RequestFinalizeBlock) -> RequestProcessProposal {
    RequestProcessProposal {
        txs: request.txs.clone(),
        proposed_last_commit: request.decided_last_commit.clone(),
        misbehavior: request.misbehavior.clone(),
        hash: request.hash.clone(),
        height: request.height,
        time: request.time,
        next_validators_hash: request.next_validators_hash.clone(),
        proposer_address: request.proposer_address.clone(),
    }
}

fn init_request(fixture: &Fixture) -> TestResult<RequestInitChain> {
    let profile = FloorConsensusProfileV2::derive(fixture.genesis.chain_id(), &fixture.validators)?;
    Ok(RequestInitChain {
        time: Some(timestamp(1_000)),
        chain_id: "floor-abci-test".to_owned(),
        consensus_params: Some(expected_consensus_parameters()),
        validators: fixture.validators.validators().to_vec(),
        app_state_bytes: profile.genesis_app_state_bytes(&fixture.genesis)?.into(),
        initial_height: 1,
    })
}

#[test]
fn codec_round_trip_and_canonical_width() -> TestResult<()> {
    let fixture = Fixture::new()?;
    let tx = signed_tx(
        &fixture,
        0,
        3,
        Some(checkpoint(0, 0x71)),
        checkpoint(1, 0x72),
        9,
        FloorAppHash::new([0x73; 32]),
    )?;
    assert!((MIN_TRANSACTION_BYTES..=MAX_TRANSACTION_BYTES).contains(&tx.len()));
    assert_eq!(&tx[..8], FLOOR_TRANSACTION_MAGIC);
    let golden_digest: [u8; 32] = Sha256::digest(&tx).into();
    assert_eq!(
        golden_digest,
        [
            0x8e, 0xcf, 0xf3, 0x28, 0xcc, 0x41, 0xd4, 0x28, 0x48, 0xdb, 0xf7, 0xd5, 0x84, 0x5f, 0xe7, 0x51, 0xd0, 0x9c,
            0x5c, 0xb7, 0x10, 0x18, 0xbe, 0xb9, 0x90, 0xb8, 0x38, 0x9d, 0x51, 0xac, 0x3b, 0x42,
        ]
    );
    let decoded = decode_signed_cas(&tx)?;
    assert_eq!(encode_signed_cas(&decoded)?, tx);
    let maximum_chain = FloorLedgerChainId::new(vec![b'x'; 128])?;
    let maximum_cas = FloorCasRequest::new(
        &maximum_chain,
        fixture.identities[0],
        Some(checkpoint(0, 0x81)),
        checkpoint(1, 0x82),
    )?;
    let maximum_authorization = FloorCasAuthorization::new(
        maximum_cas,
        operator_key(&fixture.keys[0])?,
        ActorRequestNonce::new([0x83; 32])?,
        2,
        FloorAppHash::new([0x84; 32]),
    )?;
    let maximum_signature = Secp256k1::signing_only()
        .sign_schnorr_no_aux_rand(maximum_authorization.request_digest().as_bytes(), &fixture.keys[0])
        .to_byte_array();
    assert_eq!(
        encode_signed_cas(&maximum_authorization.authorize(maximum_signature)?)?.len(),
        MAX_TRANSACTION_BYTES
    );
    let mut trailing = tx.clone();
    trailing.push(0);
    assert!(decode_signed_cas(&trailing).is_err());
    let mut tampered = tx;
    tampered[20] ^= 1;
    assert!(decode_signed_cas(&tampered).is_err());
    Ok(())
}

#[test]
fn info_and_init_pin_profile_validators_and_resources() -> TestResult<()> {
    assert!(FloorValidatorGenesisV2::new(Vec::new()).is_err());
    assert!(FloorValidatorGenesisV2::new(vec![ValidatorUpdate {
        pub_key: Some(PublicKey {
            sum: Some(public_key::Sum::Secp256k1(vec![0x22; 33])),
        }),
        power: 1,
    }])
    .is_err());
    let fixture = Fixture::new()?;
    let adapter = fixture.adapter()?;
    let info = adapter.try_info(RequestInfo::default())?;
    assert_eq!(info.app_version, 2);
    assert_eq!(info.last_block_height, 0);
    let response = adapter.try_init_chain(init_request(&fixture)?)?;
    assert_eq!(response.consensus_params, Some(expected_consensus_parameters()));
    let mut wrong = init_request(&fixture)?;
    wrong.app_state_bytes = vec![0; 144].into();
    assert!(adapter.try_init_chain(wrong).is_err());
    let mut wrong = init_request(&fixture)?;
    wrong.validators[0].power += 1;
    assert!(adapter.try_init_chain(wrong).is_err());
    let mut wrong = init_request(&fixture)?;
    let Some(block) = wrong.consensus_params.as_mut().and_then(|params| params.block.as_mut()) else {
        return Err("missing test block parameters".into());
    };
    block.max_bytes -= 1;
    assert!(adapter.try_init_chain(wrong).is_err());
    let mut wrong = init_request(&fixture)?;
    if let Some(abci) = wrong.consensus_params.as_mut().and_then(|params| params.abci.as_mut()) {
        abci.vote_extensions_enable_height = 1;
    } else {
        return Err("missing test ABCI parameters".into());
    }
    assert!(adapter.try_init_chain(wrong).is_err());

    let wrong_directory = private_temp_dir()?;
    let wrong_entries = fixture
        .identities
        .iter()
        .zip(&fixture.keys)
        .map(|(identity, key)| Ok(RegistryEntry::new(*identity, operator_key(key)?)?))
        .collect::<TestResult<Vec<_>>>()?;
    let wrong_genesis = FloorGenesis::new(fixture.genesis.chain_id().clone(), [0xaa; 32], wrong_entries)?;
    let wrong_application = FloorApplication::open(wrong_directory.path().join("wrong-profile.sqlite"), wrong_genesis)?;
    assert!(ThunderboltFloorAbci::new(wrong_application, fixture.validators.clone(), PanicFatal,).is_err());
    for (index, chain_bytes) in [vec![b'x'; 51], b"invalid chain".to_vec()].into_iter().enumerate() {
        let chain = FloorLedgerChainId::new(chain_bytes)?;
        let profile = FloorConsensusProfileV2::derive(&chain, &fixture.validators)?;
        let entries = fixture
            .identities
            .iter()
            .zip(&fixture.keys)
            .map(|(identity, key)| Ok(RegistryEntry::new(*identity, operator_key(key)?)?))
            .collect::<TestResult<Vec<_>>>()?;
        let genesis = FloorGenesis::new(chain, *profile.as_bytes(), entries)?;
        let application = FloorApplication::open(
            wrong_directory.path().join(format!("bad-chain-{index}.sqlite")),
            genesis,
        )?;
        assert!(ThunderboltFloorAbci::new(application, fixture.validators.clone(), PanicFatal).is_err());
    }
    Ok(())
}

#[test]
fn check_tx_is_exact_head_scoped_and_identity_deduplicated() -> TestResult<()> {
    let fixture = Fixture::new()?;
    let adapter = fixture.adapter()?;
    let tx = signed_tx(&fixture, 0, 4, None, checkpoint(0, 0x74), 1, FloorAppHash::new([0; 32]))?;
    adapter.try_check_tx(RequestCheckTx {
        tx: tx.clone().into(),
        r#type: CheckTxType::New as i32,
    })?;
    adapter.try_check_tx(RequestCheckTx {
        tx: tx.clone().into(),
        r#type: CheckTxType::Recheck as i32,
    })?;
    let conflict = signed_tx(&fixture, 0, 5, None, checkpoint(0, 0x75), 1, FloorAppHash::new([0; 32]))?;
    assert!(adapter
        .try_check_tx(RequestCheckTx {
            tx: conflict.into(),
            r#type: CheckTxType::New as i32,
        })
        .is_err());
    let other = signed_tx(&fixture, 1, 6, None, checkpoint(0, 0x76), 1, FloorAppHash::new([0; 32]))?;
    adapter.try_check_tx(RequestCheckTx {
        tx: other.into(),
        r#type: CheckTxType::New as i32,
    })?;
    adapter.try_finalize_block(finalize(1, 1_000, vec![tx.clone().into()]))?;
    adapter.try_commit()?;
    assert!(adapter
        .try_check_tx(RequestCheckTx {
            tx: tx.into(),
            r#type: CheckTxType::Recheck as i32,
        })
        .is_err());
    Ok(())
}

#[test]
fn concurrent_check_tx_allows_only_one_identity_request_per_head() -> TestResult<()> {
    let fixture = Fixture::new()?;
    let adapter = Arc::new(fixture.adapter()?);
    let first = signed_tx(
        &fixture,
        0,
        15,
        None,
        checkpoint(0, 0xa1),
        1,
        FloorAppHash::new([0; 32]),
    )?;
    let second = signed_tx(
        &fixture,
        0,
        16,
        None,
        checkpoint(0, 0xa2),
        1,
        FloorAppHash::new([0; 32]),
    )?;
    let barrier = Arc::new(Barrier::new(3));
    let first_thread = {
        let adapter = Arc::clone(&adapter);
        let barrier = Arc::clone(&barrier);
        std::thread::spawn(move || {
            barrier.wait();
            adapter
                .try_check_tx(RequestCheckTx {
                    tx: first.into(),
                    r#type: CheckTxType::New as i32,
                })
                .is_ok()
        })
    };
    let second_thread = {
        let adapter = Arc::clone(&adapter);
        let barrier = Arc::clone(&barrier);
        std::thread::spawn(move || {
            barrier.wait();
            adapter
                .try_check_tx(RequestCheckTx {
                    tx: second.into(),
                    r#type: CheckTxType::New as i32,
                })
                .is_ok()
        })
    };
    barrier.wait();
    let first_ok = first_thread.join().map_err(|_| "first CheckTx thread panicked")?;
    let second_ok = second_thread.join().map_err(|_| "second CheckTx thread panicked")?;
    assert_ne!(first_ok, second_ok);
    Ok(())
}

#[test]
fn rotating_prepare_scan_surfaces_identity_after_duplicate_window() -> TestResult<()> {
    let fixture = Fixture::new()?;
    let adapter = fixture.adapter()?;
    let first = Bytes::from(signed_tx(
        &fixture,
        0,
        7,
        None,
        checkpoint(0, 0x77),
        1,
        FloorAppHash::new([0; 32]),
    )?);
    let second = Bytes::from(signed_tx(
        &fixture,
        1,
        8,
        None,
        checkpoint(0, 0x78),
        1,
        FloorAppHash::new([0; 32]),
    )?);
    let mut txs = vec![first.clone(); MAX_PREPARE_SCAN_TRANSACTIONS];
    txs.push(second.clone());
    let first_round = adapter.try_prepare_proposal(prepare(1, 1_000, txs.clone()))?;
    assert_eq!(first_round.txs, vec![first]);
    let second_round = adapter.try_prepare_proposal(prepare(1, 1_000, txs))?;
    assert_eq!(second_round.txs, vec![second]);
    Ok(())
}

#[test]
fn process_rejects_conflict_duplicate_identity_and_stale_head() -> TestResult<()> {
    let fixture = Fixture::new()?;
    let adapter = fixture.adapter()?;
    let conflict = Bytes::from(signed_tx(
        &fixture,
        0,
        12,
        Some(checkpoint(0, 0x99)),
        checkpoint(1, 0x9a),
        1,
        FloorAppHash::new([0; 32]),
    )?);
    assert!(adapter
        .try_process_proposal(process(&finalize(1, 1_000, vec![conflict])))
        .is_err());

    let first = Bytes::from(signed_tx(
        &fixture,
        0,
        13,
        None,
        checkpoint(0, 0x9b),
        1,
        FloorAppHash::new([0; 32]),
    )?);
    let second = Bytes::from(signed_tx(
        &fixture,
        0,
        14,
        None,
        checkpoint(0, 0x9c),
        1,
        FloorAppHash::new([0; 32]),
    )?);
    assert!(adapter
        .try_process_proposal(process(&finalize(1, 1_000, vec![first.clone(), second])))
        .is_err());
    adapter.try_finalize_block(finalize(1, 1_000, vec![first.clone()]))?;
    adapter.try_commit()?;
    assert!(adapter
        .try_process_proposal(process(&finalize(2, 2_000, vec![first])))
        .is_err());
    assert!(adapter
        .try_process_proposal(process(&finalize(
            2,
            2_000,
            vec![Bytes::from_static(b"x"); thunderbolt_floor_app::MAX_BLOCK_REQUESTS + 1],
        )))
        .is_err());
    Ok(())
}

#[test]
fn finalize_is_preview_and_commit_is_only_durable_path_with_queries() -> TestResult<()> {
    let fixture = Fixture::new()?;
    let adapter = fixture.adapter()?;
    let tx = Bytes::from(signed_tx(
        &fixture,
        0,
        9,
        None,
        checkpoint(0, 0x79),
        1,
        FloorAppHash::new([0; 32]),
    )?);
    let decided = finalize(1, 1_000, vec![tx]);
    let processed = adapter.try_process_proposal(process(&decided))?;
    assert_eq!(
        processed.status,
        response_process_proposal::ProposalStatus::Accept as i32
    );
    let finalized = adapter.try_finalize_block(decided.clone())?;
    assert_eq!(adapter.try_finalize_block(decided)?, finalized);
    assert_eq!(adapter.try_info(RequestInfo::default())?.last_block_height, 0);
    assert_eq!(finalized.tx_results.len(), 1);
    adapter.try_commit()?;
    assert_eq!(adapter.try_info(RequestInfo::default())?.last_block_height, 1);

    let status = adapter.try_query(RequestQuery {
        data: Bytes::new(),
        path: QUERY_STATUS_PATH.to_owned(),
        height: 1,
        prove: false,
    })?;
    assert!(std::str::from_utf8(&status.value)?.contains("\"execution_only\":true"));
    assert!(std::str::from_utf8(&status.value)?.contains("\"consensus_finality\":false"));
    for request in [
        RequestQuery {
            data: 1_u64.to_be_bytes().to_vec().into(),
            path: QUERY_BLOCK_PATH.to_owned(),
            height: 1,
            prove: false,
        },
        RequestQuery {
            data: [1_u64.to_be_bytes().as_slice(), 0_u32.to_be_bytes().as_slice()]
                .concat()
                .into(),
            path: QUERY_RESULT_PROOF_PATH.to_owned(),
            height: 1,
            prove: false,
        },
        RequestQuery {
            data: [
                1_u64.to_be_bytes().as_slice(),
                fixture.genesis.entries()[0].identity_digest().as_bytes(),
            ]
            .concat()
            .into(),
            path: QUERY_STATE_PROOF_PATH.to_owned(),
            height: 1,
            prove: false,
        },
        RequestQuery {
            data: fixture.genesis.entries()[0]
                .identity_digest()
                .as_bytes()
                .to_vec()
                .into(),
            path: QUERY_CHECKPOINT_PATH.to_owned(),
            height: 1,
            prove: false,
        },
    ] {
        let response = adapter.try_query(request)?;
        assert_eq!(response.code, 0);
        assert!(std::str::from_utf8(&response.value)?.contains("\"execution_only\":true"));
    }
    assert!(adapter
        .try_query(RequestQuery {
            data: Bytes::new(),
            path: "/thunderbolt/floor/v2/history-anchor".to_owned(),
            height: 0,
            prove: false,
        })
        .is_err());
    assert!(adapter
        .try_query(RequestQuery {
            data: Bytes::new(),
            path: QUERY_STATUS_PATH.to_owned(),
            height: 1,
            prove: true,
        })
        .is_err());
    Ok(())
}

#[test]
fn crash_before_and_after_commit_reconcile_through_info() -> TestResult<()> {
    let fixture = Fixture::new()?;
    let tx = Bytes::from(signed_tx(
        &fixture,
        0,
        10,
        None,
        checkpoint(0, 0x7a),
        1,
        FloorAppHash::new([0; 32]),
    )?);
    let decided = finalize(1, 1_000, vec![tx.clone()]);
    let adapter = fixture.adapter()?;
    adapter.try_finalize_block(decided.clone())?;
    drop(adapter);
    let restarted = fixture.adapter()?;
    assert_eq!(restarted.try_info(RequestInfo::default())?.last_block_height, 0);
    restarted.try_finalize_block(decided.clone())?;
    restarted.fail_after_next_commit_for_test();
    assert!(matches!(
        restarted.try_commit(),
        Err(FloorAbciError::PostCommitAmbiguous)
    ));
    drop(restarted);
    let recovered = fixture.adapter()?;
    assert_eq!(recovered.try_info(RequestInfo::default())?.last_block_height, 1);
    recovered.try_finalize_block(decided)?;
    recovered.try_commit()?;
    assert_eq!(recovered.try_info(RequestInfo::default())?.last_block_height, 1);
    Ok(())
}

#[test]
fn fatal_commit_and_corrupt_query_never_return_success() -> TestResult<()> {
    let fixture = Fixture::new()?;
    let adapter = fixture.adapter()?;
    let clone = adapter.clone();
    let failure = match catch_unwind(AssertUnwindSafe(|| adapter.commit())) {
        Ok(_) => return Err("Commit returned instead of invoking fatal handler".into()),
        Err(failure) => failure,
    };
    let failure = failure.downcast::<FatalAbciFailure>().map_err(|_| "fatal payload")?;
    assert_eq!(failure.stage(), FatalAbciStage::Commit);
    assert!(matches!(
        clone.try_info(RequestInfo::default()),
        Err(FloorAbciError::Faulted)
    ));

    let fixture = Fixture::new()?;
    let adapter = fixture.adapter()?;
    let tx = Bytes::from(signed_tx(
        &fixture,
        0,
        11,
        None,
        checkpoint(0, 0x7b),
        1,
        FloorAppHash::new([0; 32]),
    )?);
    adapter.try_finalize_block(finalize(1, 1_000, vec![tx]))?;
    adapter.try_commit()?;
    let connection = Connection::open(&fixture.path)?;
    connection
        .execute_batch("DROP TRIGGER results_no_update; UPDATE block_results SET request_signature=zeroblob(64);")?;
    drop(connection);
    let failure = match catch_unwind(AssertUnwindSafe(|| {
        adapter.query(RequestQuery {
            data: 1_u64.to_be_bytes().to_vec().into(),
            path: QUERY_BLOCK_PATH.to_owned(),
            height: 1,
            prove: false,
        })
    })) {
        Ok(_) => return Err("corrupt query returned instead of invoking fatal handler".into()),
        Err(failure) => failure,
    };
    let failure = failure.downcast::<FatalAbciFailure>().map_err(|_| "fatal payload")?;
    assert_eq!(failure.stage(), FatalAbciStage::Query);
    Ok(())
}

#[test]
fn snapshots_and_vote_extensions_are_disabled() -> TestResult<()> {
    let fixture = Fixture::new()?;
    let adapter = fixture.adapter()?;
    assert!(adapter.list_snapshots().snapshots.is_empty());
    assert_eq!(
        adapter.offer_snapshot(RequestOfferSnapshot::default()).result,
        response_offer_snapshot::Result::Abort as i32
    );
    assert!(adapter
        .extend_vote(RequestExtendVote::default())
        .vote_extension
        .is_empty());
    assert_eq!(
        adapter
            .verify_vote_extension(RequestVerifyVoteExtension {
                vote_extension: vec![1].into(),
                ..RequestVerifyVoteExtension::default()
            })
            .status,
        response_verify_vote_extension::VerifyStatus::Reject as i32
    );
    Ok(())
}

fn prop_result<T>(result: TestResult<T>) -> std::result::Result<T, proptest::test_runner::TestCaseError> {
    result.map_err(|error| proptest::test_runner::TestCaseError::fail(error.to_string()))
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn arbitrary_transaction_bytes_never_panic(bytes in prop::collection::vec(any::<u8>(), 0..700)) {
        let _ = decode_signed_cas(&bytes);
    }

    #[test]
    fn valid_transactions_round_trip(nonce in 1_u8..=255, digest in any::<u8>()) {
        let fixture = prop_result(Fixture::new())?;
        let tx = prop_result(signed_tx(
            &fixture,
            0,
            nonce,
            None,
            checkpoint(0, digest),
            1,
            FloorAppHash::new([0; 32]),
        ))?;
        let decoded = decode_signed_cas(&tx)?;
        prop_assert_eq!(encode_signed_cas(&decoded)?, tx);
    }

    #[test]
    fn oversized_checktx_frames_fail_without_panic(extra in 1_usize..1024) {
        let fixture = prop_result(Fixture::new())?;
        let adapter = prop_result(fixture.adapter())?;
        let request = RequestCheckTx {
            tx: vec![0_u8; MAX_TRANSACTION_BYTES + extra].into(),
            r#type: CheckTxType::New as i32,
        };
        prop_assert!(adapter.try_check_tx(request).is_err());
    }
}
