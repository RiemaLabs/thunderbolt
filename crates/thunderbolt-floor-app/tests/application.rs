#![cfg(unix)]

use std::cell::Cell;
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{mpsc, Arc, Barrier};
use std::time::Duration;

use proptest::prelude::*;
use rusqlite::Connection;
use secp256k1::{Keypair, Secp256k1, SecretKey, XOnlyPublicKey};
use tempfile::TempDir;
use thunderbolt_floor::{FloorCasRequest, FloorLedgerChainId, VaultCheckpoint};
use thunderbolt_floor_app::{
    ActorRequestNonce, FinalizedHistoryAnchor, FinalizedHistoryAnchorVerifier, FloorAppHash, FloorApplication,
    FloorApplicationError, FloorBlockInput, FloorCasAuthorization, FloorCasDisposition, FloorGenesis, FloorOperatorKey,
    HistoryAnchorCandidate, HistoryOpenError, HistoryRetentionPolicy, RegistryEntry, SignedFloorCasRequest,
};

#[derive(Debug)]
struct TestFinalityError;

impl std::fmt::Display for TestFinalityError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("test finality mismatch")
    }
}

impl Error for TestFinalityError {}

struct TestFinalityVerifier;

impl FinalizedHistoryAnchorVerifier for TestFinalityVerifier {
    type Proof = [u8; 32];
    type Error = TestFinalityError;

    fn finalize_candidate(
        &self,
        candidate: &HistoryAnchorCandidate,
        proof: &Self::Proof,
    ) -> std::result::Result<[u8; 32], Self::Error> {
        if proof != candidate.candidate_digest() {
            return Err(TestFinalityError);
        }
        Ok([0xd1; 32])
    }

    fn verify_stored_anchor(
        &self,
        anchor: &FinalizedHistoryAnchor,
        proof: &Self::Proof,
    ) -> std::result::Result<(), Self::Error> {
        if proof != anchor.anchor_digest().as_bytes() {
            return Err(TestFinalityError);
        }
        Ok(())
    }
}

struct StatefulFinalityVerifier {
    finalize_calls: Cell<u32>,
}

struct BarrierFinalityVerifier {
    entered: Arc<Barrier>,
    release: Arc<Barrier>,
}

impl FinalizedHistoryAnchorVerifier for BarrierFinalityVerifier {
    type Proof = [u8; 32];
    type Error = TestFinalityError;

    fn finalize_candidate(
        &self,
        candidate: &HistoryAnchorCandidate,
        proof: &Self::Proof,
    ) -> std::result::Result<[u8; 32], Self::Error> {
        if proof != candidate.candidate_digest() {
            return Err(TestFinalityError);
        }
        self.entered.wait();
        self.release.wait();
        Ok([0xd3; 32])
    }

    fn verify_stored_anchor(
        &self,
        _anchor: &FinalizedHistoryAnchor,
        _proof: &Self::Proof,
    ) -> std::result::Result<(), Self::Error> {
        Ok(())
    }
}

impl FinalizedHistoryAnchorVerifier for StatefulFinalityVerifier {
    type Proof = [u8; 32];
    type Error = TestFinalityError;

    fn finalize_candidate(
        &self,
        _candidate: &HistoryAnchorCandidate,
        _proof: &Self::Proof,
    ) -> std::result::Result<[u8; 32], Self::Error> {
        self.finalize_calls.set(self.finalize_calls.get() + 1);
        Ok([0xd2; 32])
    }

    fn verify_stored_anchor(
        &self,
        _anchor: &FinalizedHistoryAnchor,
        _proof: &Self::Proof,
    ) -> std::result::Result<(), Self::Error> {
        Ok(())
    }
}
use thunderbolt_keystore::{
    CheckpointCasOutcome, CommitteeDescriptorDigest, DeploymentBinding, DeploymentId, Network, NodeId, VaultIdentity,
    VaultRevision, VaultRole, VaultStateDigest,
};

fn keypair(byte: u8) -> Keypair {
    let secret = SecretKey::from_byte_array([byte; 32]).expect("test secret key");
    Keypair::from_secret_key(&Secp256k1::new(), &secret)
}

fn operator_key(keypair: &Keypair) -> FloorOperatorKey {
    let (public_key, _) = XOnlyPublicKey::from_keypair(keypair);
    FloorOperatorKey::new(public_key.serialize()).expect("operator key")
}

fn identity(node: u8, network: Network) -> VaultIdentity {
    VaultIdentity::new(
        network,
        VaultRole::CommitteeMember,
        NodeId::new([node; 32]),
        DeploymentBinding::new(
            DeploymentId::new([0x41; 32]).expect("deployment"),
            7,
            CommitteeDescriptorDigest::new([0x42; 32]).expect("descriptor"),
        )
        .expect("binding"),
    )
}

fn checkpoint(revision: u64, byte: u8) -> VaultCheckpoint {
    VaultCheckpoint::new(VaultRevision::new(revision), VaultStateDigest::new([byte; 32]))
}

fn chain_id() -> FloorLedgerChainId {
    FloorLedgerChainId::new(b"floor-app-test".to_vec()).expect("chain")
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

fn make_genesis(entries: &[(VaultIdentity, &Keypair)], profile: u8) -> FloorGenesis {
    FloorGenesis::new(
        chain_id(),
        [profile; 32],
        entries
            .iter()
            .map(|(identity, keypair)| RegistryEntry::new(*identity, operator_key(keypair)).expect("entry"))
            .collect(),
    )
    .expect("genesis")
}

fn signed_request(
    identity: VaultIdentity,
    keypair: &Keypair,
    nonce: u8,
    expected: Option<VaultCheckpoint>,
    next: VaultCheckpoint,
    target_height: u64,
    expected_previous_app_hash: FloorAppHash,
) -> SignedFloorCasRequest {
    let cas = FloorCasRequest::new(&chain_id(), identity, expected, next).expect("CAS");
    let authorization = FloorCasAuthorization::new(
        cas,
        operator_key(keypair),
        ActorRequestNonce::new([nonce; 32]).expect("nonce"),
        target_height,
        expected_previous_app_hash,
    )
    .expect("authorization");
    let signature = Secp256k1::signing_only()
        .sign_schnorr_no_aux_rand(authorization.request_digest().as_bytes(), keypair)
        .to_byte_array();
    authorization.authorize(signature).expect("signature")
}

fn block(height: u64, time: u64, previous: FloorAppHash, requests: Vec<SignedFloorCasRequest>) -> FloorBlockInput {
    FloorBlockInput::new(chain_id(), height, time, previous, requests).expect("block")
}

fn seed_single_result(path: &Path) -> Result<FloorGenesis, Box<dyn Error>> {
    let operator = keypair(10);
    let identity = identity(0x59, Network::Regtest);
    let genesis = make_genesis(&[(identity, &operator)], 0x67);
    let application = FloorApplication::open(path, genesis.clone())?;
    application.execute_block(&block(
        1,
        6_000,
        FloorAppHash::new([0; 32]),
        vec![signed_request(
            identity,
            &operator,
            31,
            None,
            checkpoint(0, 0x91),
            1,
            FloorAppHash::new([0; 32]),
        )],
    ))?;
    drop(application);
    Ok(genesis)
}

#[test]
fn signed_cas_block_replay_conflict_and_restart_round_trip() -> Result<(), Box<dyn Error>> {
    let directory = private_temp_dir()?;
    let path = directory.path().join("floor.sqlite");
    let operator = keypair(1);
    let identity = identity(0x51, Network::Signet);
    let genesis = make_genesis(&[(identity, &operator)], 0x61);
    let app = FloorApplication::open(&path, genesis.clone())?;
    let initial = checkpoint(0, 0x71);
    let request = signed_request(identity, &operator, 1, None, initial, 1, FloorAppHash::new([0; 32]));
    let input = block(1, 1_000, FloorAppHash::new([0; 32]), vec![request]);
    let first = app.execute_block(&input)?;
    assert_eq!(first.block().results()[0].disposition(), FloorCasDisposition::Applied);
    assert_eq!(app.checkpoint(genesis.entries()[0].identity_digest())?, Some(initial));
    assert!(app.execute_block(&input)?.replayed_block());

    let fork = checkpoint(1, 0x72);
    let conflict = signed_request(
        identity,
        &operator,
        2,
        Some(checkpoint(0, 0x79)),
        fork,
        2,
        first.block().app_hash(),
    );
    let second = app.execute_block(&block(2, 1_002, first.block().app_hash(), vec![conflict]))?;
    assert_eq!(second.block().results()[0].disposition(), FloorCasDisposition::Conflict);
    drop(app);

    let reopened = FloorApplication::open(&path, genesis.clone())?;
    assert_eq!(reopened.status()?.last_height, 2);
    assert_eq!(
        reopened.checkpoint(genesis.entries()[0].identity_digest())?,
        Some(initial)
    );
    reopened.verify_integrity()?;
    Ok(())
}

#[test]
fn cross_head_replay_is_rejected_and_old_copy_cannot_reanchor() -> Result<(), Box<dyn Error>> {
    let directory = private_temp_dir()?;
    let operator = keypair(13);
    let identity = identity(0x5c, Network::Signet);
    let genesis = make_genesis(&[(identity, &operator)], 0x6a);
    let path = directory.path().join("cross-head.sqlite");
    let application = FloorApplication::open(&path, genesis.clone())?;
    let c0 = checkpoint(0, 0xa0);
    let c1 = checkpoint(1, 0xa1);
    let c2 = checkpoint(2, 0xa2);
    let first_request = signed_request(identity, &operator, 50, None, c0, 1, FloorAppHash::new([0; 32]));
    let first = application.execute_block(&block(
        1,
        9_000,
        FloorAppHash::new([0; 32]),
        vec![first_request.clone()],
    ))?;
    let future = signed_request(identity, &operator, 51, Some(c1), c2, 2, first.block().app_hash());
    let future_conflict =
        application.execute_block(&block(2, 9_001, first.block().app_hash(), vec![future.clone()]))?;
    assert_eq!(
        future_conflict.block().results()[0].disposition(),
        FloorCasDisposition::Conflict
    );
    let second = application.execute_block(&block(
        3,
        9_002,
        future_conflict.block().app_hash(),
        vec![signed_request(
            identity,
            &operator,
            52,
            Some(c0),
            c1,
            3,
            future_conflict.block().app_hash(),
        )],
    ))?;
    assert!(matches!(
        FloorBlockInput::new(chain_id(), 4, 9_003, second.block().app_hash(), vec![future]),
        Err(FloorApplicationError::InvalidInput("request head mismatch"))
    ));
    let third = application.execute_block(&block(
        4,
        9_003,
        second.block().app_hash(),
        vec![signed_request(
            identity,
            &operator,
            53,
            Some(c1),
            c2,
            4,
            second.block().app_hash(),
        )],
    ))?;
    assert!(matches!(
        FloorBlockInput::new(chain_id(), 5, 9_004, third.block().app_hash(), vec![first_request]),
        Err(FloorApplicationError::InvalidInput("request head mismatch"))
    ));
    let old_copy = signed_request(identity, &operator, 54, None, c0, 5, third.block().app_hash());
    let rejected = application.execute_block(&block(5, 9_004, third.block().app_hash(), vec![old_copy]))?;
    let result = &rejected.block().results()[0];
    assert_eq!(result.next(), c0);
    assert_eq!(result.current(), Some(c2));
    assert_eq!(result.disposition(), FloorCasDisposition::Conflict);
    let adapter_outcome = match result.disposition() {
        FloorCasDisposition::Applied => CheckpointCasOutcome::Advanced,
        FloorCasDisposition::AlreadyCurrent => CheckpointCasOutcome::AlreadyCurrent,
        FloorCasDisposition::Conflict => CheckpointCasOutcome::Conflict(result.current()),
    };
    assert_eq!(adapter_outcome, CheckpointCasOutcome::Conflict(Some(c2)));
    assert_eq!(
        application.checkpoint(genesis.entries()[0].identity_digest())?,
        Some(c2)
    );
    drop(application);
    FloorApplication::open(&path, genesis)?.verify_integrity()?;
    Ok(())
}

#[test]
fn wrong_key_tamper_nonce_reuse_and_block_failure_are_atomic() -> Result<(), Box<dyn Error>> {
    let directory = private_temp_dir()?;
    let path = directory.path().join("atomic.sqlite");
    let authorized = keypair(2);
    let attacker = keypair(3);
    let second_authorized = keypair(15);
    let first_identity = identity(0x52, Network::Regtest);
    let second_identity = identity(0x5e, Network::Regtest);
    let genesis = make_genesis(
        &[(first_identity, &authorized), (second_identity, &second_authorized)],
        0x62,
    );
    let app = FloorApplication::open(&path, genesis.clone())?;
    let good = signed_request(
        first_identity,
        &authorized,
        4,
        None,
        checkpoint(0, 0x73),
        1,
        FloorAppHash::new([0; 32]),
    );
    let wrong = signed_request(
        second_identity,
        &attacker,
        5,
        None,
        checkpoint(0, 0x74),
        1,
        FloorAppHash::new([0; 32]),
    );
    let result = app.execute_block(&block(1, 2_000, FloorAppHash::new([0; 32]), vec![good, wrong]));
    assert!(matches!(result, Err(FloorApplicationError::UnauthorizedActor)));
    assert_eq!(app.status()?.last_height, 0);
    assert_eq!(app.checkpoint(genesis.entries()[0].identity_digest())?, None);

    let cas = FloorCasRequest::new(&chain_id(), first_identity, None, checkpoint(0, 0x75))?;
    let authorization = FloorCasAuthorization::new(
        cas,
        operator_key(&authorized),
        ActorRequestNonce::new([9; 32])?,
        1,
        FloorAppHash::new([0; 32]),
    )?;
    let mut signature = Secp256k1::signing_only()
        .sign_schnorr_no_aux_rand(authorization.request_digest().as_bytes(), &authorized)
        .to_byte_array();
    signature[0] ^= 1;
    assert!(matches!(
        authorization.authorize(signature),
        Err(FloorApplicationError::InvalidSignature)
    ));

    let first = signed_request(
        first_identity,
        &authorized,
        10,
        None,
        checkpoint(0, 0x76),
        1,
        FloorAppHash::new([0; 32]),
    );
    let applied = app.execute_block(&block(1, 2_001, FloorAppHash::new([0; 32]), vec![first]))?;
    let reused = signed_request(
        first_identity,
        &authorized,
        10,
        Some(checkpoint(0, 0x76)),
        checkpoint(1, 0x77),
        2,
        applied.block().app_hash(),
    );
    let reused = app.execute_block(&block(2, 2_002, applied.block().app_hash(), vec![reused]))?;
    assert_eq!(reused.block().results()[0].disposition(), FloorCasDisposition::Applied);
    assert_eq!(app.status()?.last_height, 2);
    Ok(())
}

#[test]
fn preview_commit_proofs_fork_rollback_and_genesis_mismatch() -> Result<(), Box<dyn Error>> {
    let directory = private_temp_dir()?;
    let path = directory.path().join("preview.sqlite");
    let first_key = keypair(4);
    let second_key = keypair(5);
    let first_identity = identity(0x53, Network::Signet);
    let second_identity = identity(0x54, Network::Signet);
    let genesis = make_genesis(&[(first_identity, &first_key), (second_identity, &second_key)], 0x63);
    let app = FloorApplication::open(&path, genesis.clone())?;
    let request = signed_request(
        first_identity,
        &first_key,
        11,
        None,
        checkpoint(0, 0x78),
        1,
        FloorAppHash::new([0; 32]),
    );
    let input = block(1, 3_000, FloorAppHash::new([0; 32]), vec![request]);
    let prepared = app.preview_block(input.clone())?;
    assert_eq!(app.status()?.last_height, 0);
    let committed = app.commit_prepared_block(prepared)?;
    assert_eq!(committed.block().height(), 1);

    let first_digest = genesis
        .entries()
        .iter()
        .find(|entry| entry.identity() == first_identity)
        .ok_or("missing first identity")?
        .identity_digest();
    let second_digest = genesis
        .entries()
        .iter()
        .find(|entry| entry.identity() == second_identity)
        .ok_or("missing second identity")?
        .identity_digest();
    let present = app.state_proof_at(1, first_digest)?;
    present.verify(committed.block(), &genesis, first_digest, Some(checkpoint(0, 0x78)))?;
    assert!(present.checkpoint().is_some());
    let absent = app.state_proof_at(1, second_digest)?;
    absent.verify(committed.block(), &genesis, second_digest, None)?;
    assert!(absent.checkpoint().is_none());
    assert!(present
        .verify(committed.block(), &genesis, second_digest, Some(checkpoint(0, 0x78)))
        .is_err());
    assert!(present.verify(committed.block(), &genesis, first_digest, None).is_err());
    assert!(absent
        .verify(committed.block(), &genesis, second_digest, Some(checkpoint(0, 0x78)))
        .is_err());
    assert_eq!(app.committed_block(1)?, *committed.block());
    let result_proof = app.result_proof(1, 0)?;
    result_proof.verify(committed.block(), &committed.block().results()[0])?;

    let exact = app.execute_block(&input)?;
    assert!(exact.replayed_block());
    let different = block(1, 3_001, FloorAppHash::new([0; 32]), Vec::new());
    assert!(matches!(
        app.execute_block(&different),
        Err(FloorApplicationError::BlockFork)
    ));
    let stale = block(2, 3_002, FloorAppHash::new([0; 32]), Vec::new());
    assert!(matches!(
        app.execute_block(&stale),
        Err(FloorApplicationError::BlockContinuity)
    ));

    drop(app);
    let mismatched = make_genesis(&[(first_identity, &first_key), (second_identity, &second_key)], 0x64);
    assert!(matches!(
        FloorApplication::open(&path, mismatched),
        Err(FloorApplicationError::GenesisMismatch)
    ));
    let mismatched_registry = make_genesis(&[(first_identity, &second_key), (second_identity, &second_key)], 0x63);
    assert!(matches!(
        FloorApplication::open(&path, mismatched_registry),
        Err(FloorApplicationError::GenesisMismatch)
    ));
    Ok(())
}

#[test]
fn registry_network_policy_matches_keystore_identity_domain() {
    let operator = keypair(6);
    for network in [Network::Regtest, Network::Signet, Network::Testnet] {
        assert!(RegistryEntry::new(identity(0x55, network), operator_key(&operator)).is_ok());
    }
    assert!(matches!(
        RegistryEntry::new(identity(0x55, Network::Mainnet), operator_key(&operator)),
        Err(FloorApplicationError::MainnetDisabled)
    ));
}

#[test]
#[cfg(unix)]
fn production_open_requires_a_persistent_private_absolute_file() -> Result<(), Box<dyn Error>> {
    let directory = private_temp_dir()?;
    let operator = keypair(14);
    let identity = identity(0x5d, Network::Regtest);
    let genesis = make_genesis(&[(identity, &operator)], 0x6b);
    for rejected in [
        PathBuf::new(),
        PathBuf::from(":memory:"),
        PathBuf::from("file:floor.sqlite?mode=memory"),
        PathBuf::from("relative-floor.sqlite"),
        directory.path().join(":memory:"),
        directory.path().join("file:floor.sqlite"),
        directory.path().join("missing").join("floor.sqlite"),
    ] {
        assert!(matches!(
            FloorApplication::open(rejected, genesis.clone()),
            Err(FloorApplicationError::InvalidStoragePath { .. })
        ));
    }
    assert!(matches!(
        FloorApplication::open(directory.path(), genesis.clone()),
        Err(FloorApplicationError::InvalidStoragePath { .. })
    ));

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let insecure = directory.path().join("insecure");
        fs::create_dir(&insecure)?;
        fs::set_permissions(&insecure, fs::Permissions::from_mode(0o755))?;
        assert!(matches!(
            FloorApplication::open(insecure.join("floor.sqlite"), genesis.clone()),
            Err(FloorApplicationError::InvalidStoragePath { .. })
        ));
    }

    let path = directory.path().join("persistent.sqlite");
    let application = FloorApplication::open(&path, genesis.clone())?;
    assert!(path.is_file());
    drop(application);
    let reopened = FloorApplication::open(&path, genesis.clone())?;
    reopened.verify_integrity()?;
    #[cfg(unix)]
    {
        let alias = directory.path().join("hardlink.sqlite");
        fs::hard_link(&path, &alias)?;
        assert!(matches!(
            reopened.status(),
            Err(FloorApplicationError::InvalidStoragePath { .. })
        ));
        drop(reopened);
        assert!(matches!(
            FloorApplication::open(&path, genesis),
            Err(FloorApplicationError::InvalidStoragePath { .. })
        ));
    }
    #[cfg(not(unix))]
    drop(reopened);
    Ok(())
}

#[test]
fn consensus_order_changes_result_root_and_app_hash() -> Result<(), Box<dyn Error>> {
    let first_directory = private_temp_dir()?;
    let second_directory = private_temp_dir()?;
    let first_key = keypair(7);
    let second_key = keypair(8);
    let first_identity = identity(0x56, Network::Signet);
    let second_identity = identity(0x57, Network::Signet);
    let genesis = make_genesis(&[(first_identity, &first_key), (second_identity, &second_key)], 0x65);
    let first_request = signed_request(
        first_identity,
        &first_key,
        20,
        None,
        checkpoint(0, 0x81),
        1,
        FloorAppHash::new([0; 32]),
    );
    let second_request = signed_request(
        second_identity,
        &second_key,
        21,
        None,
        checkpoint(0, 0x82),
        1,
        FloorAppHash::new([0; 32]),
    );
    let first_app = FloorApplication::open(first_directory.path().join("floor.sqlite"), genesis.clone())?;
    let second_app = FloorApplication::open(second_directory.path().join("floor.sqlite"), genesis)?;
    let first = first_app.execute_block(&block(
        1,
        4_000,
        FloorAppHash::new([0; 32]),
        vec![first_request.clone(), second_request.clone()],
    ))?;
    let second = second_app.execute_block(&block(
        1,
        4_000,
        FloorAppHash::new([0; 32]),
        vec![second_request, first_request],
    ))?;
    assert_ne!(first.block().result_root(), second.block().result_root());
    assert_ne!(first.block().app_hash(), second.block().app_hash());
    let proof = first_app.result_proof(1, 0)?;
    proof.verify(first.block(), &first.block().results()[0])?;
    assert!(proof.verify(first.block(), &first.block().results()[1]).is_err());
    assert!(proof.verify(second.block(), &second.block().results()[0]).is_err());
    Ok(())
}

#[test]
fn restart_rejects_head_time_hidden_block_and_orphan_result() -> Result<(), Box<dyn Error>> {
    let time_directory = private_temp_dir()?;
    let time_path = time_directory.path().join("head-time.sqlite");
    let time_genesis = seed_single_result(&time_path)?;
    let connection = Connection::open(&time_path)?;
    connection.execute(
        "UPDATE application_state SET last_block_time_ms=last_block_time_ms+1 WHERE singleton=1",
        [],
    )?;
    drop(connection);
    assert!(FloorApplication::open(&time_path, time_genesis).is_err());

    let block_directory = private_temp_dir()?;
    let block_path = block_directory.path().join("hidden-block.sqlite");
    let block_genesis = seed_single_result(&block_path)?;
    let connection = Connection::open(&block_path)?;
    connection.execute(
        "INSERT INTO blocks VALUES (2,6001,zeroblob(32),zeroblob(32),zeroblob(32),zeroblob(32),zeroblob(32),0)",
        [],
    )?;
    drop(connection);
    assert!(FloorApplication::open(&block_path, block_genesis).is_err());

    let result_directory = private_temp_dir()?;
    let result_path = result_directory.path().join("orphan-result.sqlite");
    let result_genesis = seed_single_result(&result_path)?;
    let connection = Connection::open(&result_path)?;
    connection.pragma_update(None, "foreign_keys", "OFF")?;
    connection.execute(
        "INSERT INTO block_results SELECT 99,block_index,identity_digest,actor_key,request_nonce,request_digest,expected_revision,expected_digest,next_revision,next_digest,current_revision,current_digest,disposition,request_signature,result_digest FROM block_results WHERE height=1",
        [],
    )?;
    drop(connection);
    assert!(FloorApplication::open(&result_path, result_genesis).is_err());

    let registry_directory = private_temp_dir()?;
    let registry_path = registry_directory.path().join("registry.sqlite");
    let registry_genesis = seed_single_result(&registry_path)?;
    let connection = Connection::open(&registry_path)?;
    connection.execute_batch("DROP TRIGGER registry_no_update; UPDATE registry SET node_id=zeroblob(32);")?;
    drop(connection);
    assert!(FloorApplication::open(&registry_path, registry_genesis).is_err());

    let signature_directory = private_temp_dir()?;
    let signature_path = signature_directory.path().join("signature.sqlite");
    let signature_genesis = seed_single_result(&signature_path)?;
    let connection = Connection::open(&signature_path)?;
    connection
        .execute_batch("DROP TRIGGER results_no_update; UPDATE block_results SET request_signature=zeroblob(64);")?;
    drop(connection);
    assert!(FloorApplication::open(&signature_path, signature_genesis).is_err());
    Ok(())
}

#[test]
fn empty_blocks_do_not_grow_state_delta_history() -> Result<(), Box<dyn Error>> {
    let directory = private_temp_dir()?;
    let path = directory.path().join("empty-blocks.sqlite");
    let operator = keypair(11);
    let identity = identity(0x5a, Network::Regtest);
    let genesis = make_genesis(&[(identity, &operator)], 0x68);
    let application = FloorApplication::open(&path, genesis.clone())?;
    let mut previous = FloorAppHash::new([0; 32]);
    let mut state_root = None;
    for height in 1..=32 {
        let outcome = application.execute_block(&block(height, 7_000 + height, previous, Vec::new()))?;
        if let Some(expected) = state_root {
            assert_eq!(outcome.block().state_root(), expected);
        } else {
            state_root = Some(outcome.block().state_root());
        }
        previous = outcome.block().app_hash();
    }
    let connection = Connection::open(&path)?;
    let history_rows: i64 = connection.query_row("SELECT COUNT(*) FROM floor_state_history", [], |row| row.get(0))?;
    assert_eq!(history_rows, 0);
    drop(connection);
    drop(application);
    let reopened = FloorApplication::open(&path, genesis)?;
    assert_eq!(reopened.status()?.last_height, 32);
    Ok(())
}

#[test]
fn delta_history_tracks_sequential_changes_and_rejects_same_identity_blocks() -> Result<(), Box<dyn Error>> {
    let directory = private_temp_dir()?;
    let path = directory.path().join("deltas.sqlite");
    let operator = keypair(12);
    let identity = identity(0x5b, Network::Signet);
    let genesis = make_genesis(&[(identity, &operator)], 0x69);
    let identity_digest = genesis.entries()[0].identity_digest();
    let application = FloorApplication::open(&path, genesis.clone())?;

    let empty = application.execute_block(&block(1, 8_000, FloorAppHash::new([0; 32]), Vec::new()))?;
    let initial_checkpoint = checkpoint(0, 0x94);
    let advanced_checkpoint = checkpoint(1, 0x95);
    let initial = signed_request(
        identity,
        &operator,
        40,
        None,
        initial_checkpoint,
        2,
        empty.block().app_hash(),
    );
    let same_block_advance = signed_request(
        identity,
        &operator,
        41,
        Some(initial_checkpoint),
        advanced_checkpoint,
        2,
        empty.block().app_hash(),
    );
    assert!(matches!(
        FloorBlockInput::new(
            chain_id(),
            2,
            8_001,
            empty.block().app_hash(),
            vec![initial.clone(), same_block_advance]
        ),
        Err(FloorApplicationError::InvalidInput("duplicate identity in block"))
    ));
    let initialized = application.execute_block(&block(2, 8_001, empty.block().app_hash(), vec![initial]))?;
    let advance = signed_request(
        identity,
        &operator,
        42,
        Some(initial_checkpoint),
        advanced_checkpoint,
        3,
        initialized.block().app_hash(),
    );
    let changed = application.execute_block(&block(3, 8_002, initialized.block().app_hash(), vec![advance]))?;
    let final_empty = application.execute_block(&block(4, 8_003, changed.block().app_hash(), Vec::new()))?;
    assert_eq!(final_empty.block().state_root(), changed.block().state_root());

    let before = application.state_proof_at(1, identity_digest)?;
    before.verify(empty.block(), &genesis, identity_digest, None)?;
    assert_eq!(before.checkpoint(), None);
    let initialized_proof = application.state_proof_at(2, identity_digest)?;
    initialized_proof.verify(initialized.block(), &genesis, identity_digest, Some(initial_checkpoint))?;
    for (height, block) in [(3, changed.block()), (4, final_empty.block())] {
        let proof = application.state_proof_at(height, identity_digest)?;
        proof.verify(block, &genesis, identity_digest, Some(advanced_checkpoint))?;
        assert_eq!(proof.checkpoint(), Some(advanced_checkpoint));
    }
    let changed_proof = application.state_proof_at(3, identity_digest)?;
    assert!(changed_proof
        .verify(
            final_empty.block(),
            &genesis,
            identity_digest,
            Some(advanced_checkpoint)
        )
        .is_err());
    let connection = Connection::open(&path)?;
    let history_rows: i64 = connection.query_row("SELECT COUNT(*) FROM floor_state_history", [], |row| row.get(0))?;
    assert_eq!(history_rows, 2);
    drop(connection);
    drop(application);

    let reopened = FloorApplication::open(&path, genesis.clone())?;
    reopened.verify_integrity()?;
    drop(reopened);
    let connection = Connection::open(&path)?;
    connection
        .execute_batch("DROP TRIGGER history_no_update; UPDATE floor_state_history SET state_digest = zeroblob(32);")?;
    drop(connection);
    assert!(FloorApplication::open(&path, genesis).is_err());
    Ok(())
}

#[test]
fn compaction_rechecks_before_verifier_and_retry_does_not_mask_tail_corruption() -> Result<(), Box<dyn Error>> {
    let first_directory = private_temp_dir()?;
    let second_directory = private_temp_dir()?;
    let first_path = first_directory.path().join("first.sqlite");
    let second_path = second_directory.path().join("second.sqlite");
    let operator = keypair(18);
    let identity = identity(0x62, Network::Regtest);
    let first_genesis = make_genesis(&[(identity, &operator)], 0x6d);
    let second_genesis = make_genesis(&[(identity, &operator)], 0x6e);
    let first_app = FloorApplication::open(&first_path, first_genesis)?;
    let second_app = FloorApplication::open(&second_path, second_genesis)?;
    let c0 = checkpoint(0, 0xc0);
    let c1 = checkpoint(1, 0xc1);
    let first = first_app.execute_block(&block(
        1,
        11_000,
        FloorAppHash::new([0; 32]),
        vec![signed_request(
            identity,
            &operator,
            70,
            None,
            c0,
            1,
            FloorAppHash::new([0; 32]),
        )],
    ))?;
    let second_input = block(
        2,
        11_001,
        first.block().app_hash(),
        vec![signed_request(
            identity,
            &operator,
            71,
            Some(c0),
            c1,
            2,
            first.block().app_hash(),
        )],
    );
    first_app.execute_block(&second_input)?;
    second_app.execute_block(&block(
        1,
        11_000,
        FloorAppHash::new([0; 32]),
        vec![signed_request(
            identity,
            &operator,
            72,
            None,
            checkpoint(0, 0xcf),
            1,
            FloorAppHash::new([0; 32]),
        )],
    ))?;
    let candidate = first_app.history_anchor_candidate(1)?;
    let stateful = StatefulFinalityVerifier {
        finalize_calls: Cell::new(0),
    };
    assert!(second_app
        .compact_history(candidate.clone(), &[0; 32], &stateful)
        .is_err());
    assert_eq!(stateful.finalize_calls.get(), 0);

    let proof = *candidate.candidate_digest();
    first_app.compact_history(candidate.clone(), &proof, &TestFinalityVerifier)?;
    let connection = Connection::open(&first_path)?;
    connection.execute_batch(
        "DROP TRIGGER results_no_update; UPDATE block_results SET request_signature=zeroblob(64) WHERE height=2;",
    )?;
    drop(connection);
    assert!(first_app
        .compact_history(candidate, &proof, &TestFinalityVerifier)
        .is_err());
    assert!(matches!(first_app.status(), Err(FloorApplicationError::Poisoned)));
    assert!(matches!(
        first_app.checkpoint(first_app.genesis().entries()[0].identity_digest()),
        Err(FloorApplicationError::Poisoned)
    ));
    assert!(matches!(
        first_app.committed_block(2),
        Err(FloorApplicationError::Poisoned)
    ));
    assert!(matches!(
        first_app.execute_block(&second_input),
        Err(FloorApplicationError::Poisoned)
    ));
    assert!(matches!(
        first_app.finalized_history_anchor(),
        Err(FloorApplicationError::Poisoned)
    ));
    Ok(())
}

#[test]
fn compaction_blocks_concurrent_state_output_until_postcommit_verification() -> Result<(), Box<dyn Error>> {
    let directory = private_temp_dir()?;
    let path = directory.path().join("concurrent-compaction.sqlite");
    let operator = keypair(20);
    let identity = identity(0x64, Network::Regtest);
    let genesis = make_genesis(&[(identity, &operator)], 0x70);
    let identity_digest = genesis.entries()[0].identity_digest();
    let application = Arc::new(FloorApplication::open(&path, genesis)?);
    let checkpoint = checkpoint(0, 0xe0);
    application.execute_block(&block(
        1,
        13_000,
        FloorAppHash::new([0; 32]),
        vec![signed_request(
            identity,
            &operator,
            90,
            None,
            checkpoint,
            1,
            FloorAppHash::new([0; 32]),
        )],
    ))?;
    let candidate = application.history_anchor_candidate(1)?;
    let proof = *candidate.candidate_digest();
    let entered = Arc::new(Barrier::new(2));
    let release = Arc::new(Barrier::new(2));
    let compactor = {
        let application = Arc::clone(&application);
        let entered = Arc::clone(&entered);
        let release = Arc::clone(&release);
        std::thread::spawn(move || {
            application
                .compact_history(candidate, &proof, &BarrierFinalityVerifier { entered, release })
                .is_ok()
        })
    };
    entered.wait();
    let (sender, receiver) = mpsc::channel();
    let reader = {
        let application = Arc::clone(&application);
        std::thread::spawn(move || {
            let value = application.checkpoint(identity_digest).ok().flatten();
            sender.send(value).expect("reader result");
        })
    };
    assert!(matches!(
        receiver.recv_timeout(Duration::from_millis(100)),
        Err(mpsc::RecvTimeoutError::Timeout)
    ));
    release.wait();
    assert!(compactor.join().expect("compactor join"));
    assert_eq!(receiver.recv_timeout(Duration::from_secs(2))?, Some(checkpoint));
    reader.join().expect("reader join");
    Ok(())
}

#[test]
fn queued_status_and_anchor_reads_fail_after_compaction_poisons() -> Result<(), Box<dyn Error>> {
    let directory = private_temp_dir()?;
    let path = directory.path().join("poisoned-waiters.sqlite");
    let operator = keypair(21);
    let identity = identity(0x65, Network::Regtest);
    let genesis = make_genesis(&[(identity, &operator)], 0x71);
    let application = Arc::new(FloorApplication::open(&path, genesis)?);
    let c0 = checkpoint(0, 0xe1);
    let c1 = checkpoint(1, 0xe2);
    let first = application.execute_block(&block(
        1,
        14_000,
        FloorAppHash::new([0; 32]),
        vec![signed_request(
            identity,
            &operator,
            91,
            None,
            c0,
            1,
            FloorAppHash::new([0; 32]),
        )],
    ))?;
    application.execute_block(&block(
        2,
        14_001,
        first.block().app_hash(),
        vec![signed_request(
            identity,
            &operator,
            92,
            Some(c0),
            c1,
            2,
            first.block().app_hash(),
        )],
    ))?;
    let candidate = application.history_anchor_candidate(1)?;
    let proof = *candidate.candidate_digest();
    let connection = Connection::open(&path)?;
    connection.execute_batch(
        "DROP TRIGGER results_no_update; UPDATE block_results SET request_signature=zeroblob(64) WHERE height=2;",
    )?;
    drop(connection);

    let entered = Arc::new(Barrier::new(2));
    let release = Arc::new(Barrier::new(2));
    let compactor = {
        let application = Arc::clone(&application);
        let entered = Arc::clone(&entered);
        let release = Arc::clone(&release);
        std::thread::spawn(move || {
            application
                .compact_history(candidate, &proof, &BarrierFinalityVerifier { entered, release })
                .is_ok()
        })
    };
    entered.wait();
    let (status_sender, status_receiver) = mpsc::channel();
    let status_reader = {
        let application = Arc::clone(&application);
        std::thread::spawn(move || {
            status_sender
                .send(matches!(application.status(), Err(FloorApplicationError::Poisoned)))
                .expect("status result");
        })
    };
    let (anchor_sender, anchor_receiver) = mpsc::channel();
    let anchor_reader = {
        let application = Arc::clone(&application);
        std::thread::spawn(move || {
            anchor_sender
                .send(matches!(
                    application.finalized_history_anchor(),
                    Err(FloorApplicationError::Poisoned)
                ))
                .expect("anchor result");
        })
    };
    assert!(matches!(
        status_receiver.recv_timeout(Duration::from_millis(100)),
        Err(mpsc::RecvTimeoutError::Timeout)
    ));
    assert!(matches!(
        anchor_receiver.recv_timeout(Duration::from_millis(100)),
        Err(mpsc::RecvTimeoutError::Timeout)
    ));
    release.wait();
    assert!(!compactor.join().expect("compactor join"));
    assert!(status_receiver.recv_timeout(Duration::from_secs(2))?);
    assert!(anchor_receiver.recv_timeout(Duration::from_secs(2))?);
    status_reader.join().expect("status reader join");
    anchor_reader.join().expect("anchor reader join");
    Ok(())
}

#[test]
fn recovery_only_path_compacts_before_exposing_oversized_state() -> Result<(), Box<dyn Error>> {
    let directory = private_temp_dir()?;
    let path = directory.path().join("recovery.sqlite");
    let operator = keypair(19);
    let identity = identity(0x63, Network::Regtest);
    let genesis = make_genesis(&[(identity, &operator)], 0x6f);
    let identity_digest = genesis.entries()[0].identity_digest();
    let application = FloorApplication::open(&path, genesis.clone())?;
    let c0 = checkpoint(0, 0xd0);
    let c1 = checkpoint(1, 0xd1);
    let first = application.execute_block(&block(
        1,
        12_000,
        FloorAppHash::new([0; 32]),
        vec![signed_request(
            identity,
            &operator,
            80,
            None,
            c0,
            1,
            FloorAppHash::new([0; 32]),
        )],
    ))?;
    let second = application.execute_block(&block(
        2,
        12_001,
        first.block().app_hash(),
        vec![signed_request(
            identity,
            &operator,
            81,
            Some(c0),
            c1,
            2,
            first.block().app_hash(),
        )],
    ))?;
    application.execute_block(&block(3, 12_002, second.block().app_hash(), Vec::new()))?;
    drop(application);

    let candidate =
        FloorApplication::recovery_history_anchor_candidate(&path, genesis.clone(), 2, None, &TestFinalityVerifier)?;
    let proof = *candidate.candidate_digest();
    let (recovered, anchor) =
        FloorApplication::recover_and_compact_history(&path, genesis, candidate, None, &proof, &TestFinalityVerifier)?;
    assert_eq!(anchor.through_height(), 2);
    assert_eq!(
        recovered
            .history_usage(HistoryRetentionPolicy::new(2, 2, 2, u64::MAX)?)?
            .retained_blocks,
        1
    );
    assert_eq!(recovered.checkpoint(identity_digest)?, Some(c1));
    recovered.verify_integrity()?;
    Ok(())
}

#[test]
fn finalized_anchor_compacts_history_and_bounds_restart_tail() -> Result<(), Box<dyn Error>> {
    let directory = private_temp_dir()?;
    let path = directory.path().join("compacted.sqlite");
    let first_key = keypair(16);
    let second_key = keypair(17);
    let first_identity = identity(0x60, Network::Signet);
    let second_identity = identity(0x61, Network::Signet);
    let genesis = make_genesis(&[(first_identity, &first_key), (second_identity, &second_key)], 0x6c);
    let first_digest = genesis
        .entries()
        .iter()
        .find(|entry| entry.identity() == first_identity)
        .ok_or("first identity")?
        .identity_digest();
    let second_digest = genesis
        .entries()
        .iter()
        .find(|entry| entry.identity() == second_identity)
        .ok_or("second identity")?
        .identity_digest();
    let application = FloorApplication::open(&path, genesis.clone())?;
    let c0 = checkpoint(0, 0xb0);
    let c1 = checkpoint(1, 0xb1);
    let first = application.execute_block(&block(
        1,
        10_000,
        FloorAppHash::new([0; 32]),
        vec![signed_request(
            first_identity,
            &first_key,
            60,
            None,
            c0,
            1,
            FloorAppHash::new([0; 32]),
        )],
    ))?;
    let second = application.execute_block(&block(2, 10_001, first.block().app_hash(), Vec::new()))?;
    let third = application.execute_block(&block(
        3,
        10_002,
        second.block().app_hash(),
        vec![signed_request(
            first_identity,
            &first_key,
            61,
            Some(c0),
            c1,
            3,
            second.block().app_hash(),
        )],
    ))?;
    let second_checkpoint = checkpoint(0, 0xb2);
    let fourth = application.execute_block(&block(
        4,
        10_003,
        third.block().app_hash(),
        vec![signed_request(
            second_identity,
            &second_key,
            62,
            None,
            second_checkpoint,
            4,
            third.block().app_hash(),
        )],
    ))?;
    let fifth = application.execute_block(&block(5, 10_004, fourth.block().app_hash(), Vec::new()))?;
    let policy = HistoryRetentionPolicy::new(3, 3, 3, u64::MAX)?;
    assert!(application.history_usage(policy)?.compaction_recommended);

    let candidate = application.history_anchor_candidate(3)?;
    let candidate_proof = *candidate.candidate_digest();
    let retry_candidate = candidate.clone();
    let anchor = application.compact_history(candidate, &candidate_proof, &TestFinalityVerifier)?;
    assert_eq!(
        application.compact_history(retry_candidate, &candidate_proof, &TestFinalityVerifier)?,
        anchor
    );
    assert_eq!(anchor.through_height(), 3);
    assert_eq!(anchor.prior_anchor_digest(), None);
    let usage = application.history_usage(policy)?;
    assert_eq!(usage.anchor_height, 3);
    assert_eq!(usage.retained_blocks, 2);
    assert_eq!(usage.retained_results, 1);
    assert_eq!(usage.retained_state_deltas, 1);
    assert!(!usage.compaction_recommended);
    for height in [1, 2, 3] {
        assert!(matches!(
            application.committed_block(height),
            Err(FloorApplicationError::HistoryPruned { anchor_height: 3, .. })
        ));
    }
    assert!(matches!(
        application.result_proof(3, 0),
        Err(FloorApplicationError::HistoryPruned { .. })
    ));
    assert!(matches!(
        application.state_proof_at(2, first_digest),
        Err(FloorApplicationError::HistoryPruned { .. })
    ));
    let anchor_proof = application.anchor_state_proof(first_digest)?;
    anchor_proof.verify(&anchor, &genesis, first_digest, Some(c1))?;
    assert!(anchor_proof.verify(&anchor, &genesis, second_digest, None).is_err());
    application.committed_block(4)?;
    let tail_proof = application.state_proof_at(4, second_digest)?;
    tail_proof.verify(fourth.block(), &genesis, second_digest, Some(second_checkpoint))?;
    application.verify_integrity()?;
    assert_eq!(fifth.block().height(), 5);
    drop(application);

    assert!(matches!(
        FloorApplication::open(&path, genesis.clone()),
        Err(FloorApplicationError::ExternalHistoryAnchorRequired)
    ));
    assert!(matches!(
        FloorApplication::open_with_history_anchor(&path, genesis.clone(), &[0; 32], &TestFinalityVerifier),
        Err(HistoryOpenError::Verifier(_))
    ));
    let anchor_proof = *anchor.anchor_digest().as_bytes();
    let reopened =
        FloorApplication::open_with_history_anchor(&path, genesis.clone(), &anchor_proof, &TestFinalityVerifier)?;
    assert_eq!(reopened.status()?.last_height, 5);
    assert_eq!(reopened.checkpoint(first_digest)?, Some(c1));
    assert_eq!(reopened.checkpoint(second_digest)?, Some(second_checkpoint));
    reopened.verify_integrity()?;
    let status = reopened.status()?;
    reopened.execute_block(&block(6, 10_005, status.last_app_hash, Vec::new()))?;
    let second_candidate = reopened.history_anchor_candidate(6)?;
    assert_eq!(second_candidate.prior_anchor_digest(), Some(anchor.anchor_digest()));
    assert_eq!(second_candidate.epoch(), 2);
    let second_candidate_proof = *second_candidate.candidate_digest();
    let second_anchor = reopened.compact_history(second_candidate, &second_candidate_proof, &TestFinalityVerifier)?;
    assert_eq!(second_anchor.through_height(), 6);
    assert_eq!(reopened.history_usage(policy)?.retained_blocks, 0);
    drop(reopened);
    let anchor_proof = *second_anchor.anchor_digest().as_bytes();
    let reopened =
        FloorApplication::open_with_history_anchor(&path, genesis.clone(), &anchor_proof, &TestFinalityVerifier)?;
    assert_eq!(reopened.status()?.last_height, 6);
    reopened.verify_integrity()?;
    let status = reopened.status()?;
    reopened.execute_block(&block(7, 10_006, status.last_app_hash, Vec::new()))?;
    drop(reopened);
    let connection = Connection::open(&path)?;
    connection.execute(
        "UPDATE history_anchor_snapshot SET state_digest=zeroblob(32) WHERE revision IS NOT NULL",
        [],
    )?;
    drop(connection);
    assert!(matches!(
        FloorApplication::open_with_history_anchor(&path, genesis, &anchor_proof, &TestFinalityVerifier,),
        Err(HistoryOpenError::Application(
            FloorApplicationError::HistoryAnchorMismatch
        ))
    ));
    Ok(())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(16))]

    #[test]
    fn identical_consensus_inputs_produce_identical_blocks(nonce in 1_u8..=255, digest_byte in any::<u8>()) {
        let first_directory = private_temp_dir()?;
        let second_directory = private_temp_dir()?;
        let operator = keypair(9);
        let identity = identity(0x58, Network::Regtest);
        let genesis = make_genesis(&[(identity, &operator)], 0x66);
        let request = signed_request(
            identity,
            &operator,
            nonce,
            None,
            checkpoint(0, digest_byte),
            1,
            FloorAppHash::new([0; 32]),
        );
        let input = block(1, 5_000, FloorAppHash::new([0; 32]), vec![request]);
        let first = FloorApplication::open(first_directory.path().join("floor.sqlite"), genesis.clone())?;
        let second = FloorApplication::open(second_directory.path().join("floor.sqlite"), genesis)?;
        let first_block = first.execute_block(&input)?;
        let second_block = second.execute_block(&input)?;
        prop_assert_eq!(first_block.block(), second_block.block());
    }
}
