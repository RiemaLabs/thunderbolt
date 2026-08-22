#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::sync::{Arc, Barrier};
use std::thread;

use bitcoin::Network;
use bytes::Bytes;
use proptest::prelude::*;
use secp256k1::{Keypair, Secp256k1, SecretKey};
use tempfile::TempDir;
use tendermint_abci::Application;
use tendermint_proto::google::protobuf::Timestamp;
use tendermint_proto::v0_38::abci::{
    response_apply_snapshot_chunk, response_offer_snapshot, response_process_proposal, response_verify_vote_extension,
    CommitInfo, RequestApplySnapshotChunk, RequestCheckTx, RequestExtendVote, RequestFinalizeBlock, RequestInfo,
    RequestInitChain, RequestLoadSnapshotChunk, RequestOfferSnapshot, RequestPrepareProposal, RequestProcessProposal,
    RequestQuery, RequestVerifyVoteExtension,
};
use tendermint_proto::v0_38::types::{AbciParams, ConsensusParams, VersionParams};
use thunderbolt_ledger::{
    ActorKeyAlgorithmV2, ActorPublicKeyV2, ActorRoleV2, ActorSignatureV2, CanonicalEventV2, ChannelContextIdV2,
    ClientRequestNonceV2, EntryHashV2, LedgerChainIdV2, ProposalBodyV2, SignedProposalV2, MAX_BLOCK_ENTRIES,
};
use thunderbolt_ledger_app::{ApplicationOptions, LedgerApplication};
use thunderbolt_protocol::v2::{
    ChannelEventV2, ExternalVerifierV2, FinalizeVerificationRequestV2, InvoiceVerificationRequestV2, OpenEventV2,
    OpenVerificationRequestV2, TransferVerificationRequestV2,
};
use thunderbolt_protocol::Artifact;
use thunderbolt_wire::{
    AnchorParameterSuiteIdV2, BitcoinGenesisHashV2, ChannelBindingV2, CommitteeDescriptorDigestV2, FundingOutpointV2,
    ProtocolSuiteIdV2,
};

use super::*;

const CHAIN_ID: &str = "thunderbolt-abci-regtest-1";

#[derive(Debug, Default)]
struct AcceptAll;

impl ExternalVerifierV2 for AcceptAll {
    type Error = ();

    fn verify_open(&self, _request: OpenVerificationRequestV2<'_>) -> std::result::Result<(), Self::Error> {
        Ok(())
    }

    fn verify_invoice(&self, _request: InvoiceVerificationRequestV2<'_>) -> std::result::Result<(), Self::Error> {
        Ok(())
    }

    fn verify_transfer(&self, _request: TransferVerificationRequestV2<'_>) -> std::result::Result<(), Self::Error> {
        Ok(())
    }

    fn verify_finalize(&self, _request: FinalizeVerificationRequestV2<'_>) -> std::result::Result<(), Self::Error> {
        Ok(())
    }
}

fn chain_id() -> LedgerChainIdV2 {
    LedgerChainIdV2::new(CHAIN_ID).expect("test chain id")
}

fn binding(channel_byte: u8) -> ChannelBindingV2 {
    let mut txid = [channel_byte; 32];
    txid[0] |= 1;
    ChannelBindingV2::new(
        ProtocolSuiteIdV2::from_bytes([0x11; 32]).expect("protocol suite"),
        Network::Regtest,
        BitcoinGenesisHashV2::for_network(Network::Regtest).expect("genesis"),
        b"ledger-abci-tests",
        FundingOutpointV2::new(txid, u32::from(channel_byte)).expect("funding outpoint"),
        1,
        CommitteeDescriptorDigestV2::from_bytes([0x22; 32]).expect("committee"),
        AnchorParameterSuiteIdV2::from_bytes([0x33; 32]).expect("anchor suite"),
    )
    .expect("binding")
}

fn open_event() -> ChannelEventV2 {
    ChannelEventV2::Open(OpenEventV2 {
        committee_member_count: 3,
        committee_threshold: 2,
        capacity_sat: 1_000_000,
        lock_key: Artifact::new([1]).expect("artifact"),
        initial_holder_anchor: Artifact::new([2]).expect("artifact"),
        initial_holder_ciphertext: Artifact::new([3]).expect("artifact"),
        open_proof: Artifact::new([4]).expect("artifact"),
    })
}

fn keypair(index: u64) -> Keypair {
    let mut secret = [0_u8; 32];
    secret[24..].copy_from_slice(&index.max(1).to_be_bytes());
    let secret = SecretKey::from_byte_array(secret).expect("secret key");
    Keypair::from_secret_key(&Secp256k1::signing_only(), &secret)
}

fn signed_open(channel_byte: u8, actor: u64) -> SignedProposalV2 {
    let keypair = keypair(actor);
    let (public, _) = keypair.x_only_public_key();
    let event = open_event();
    let body = ProposalBodyV2::new(
        chain_id(),
        binding(channel_byte),
        0,
        EntryHashV2::zero(),
        ClientRequestNonceV2::from_bytes([channel_byte; 16]).expect("request nonce"),
        ActorKeyAlgorithmV2::Bip340V1,
        ActorPublicKeyV2::from_bytes(public.serialize()).expect("public key"),
        ActorRoleV2::Holder,
        event.kind(),
        CanonicalEventV2::from_bytes(event.canonical_bytes().expect("event bytes")).expect("canonical event"),
    )
    .expect("proposal body");
    let digest = body.proposal_digest().expect("proposal digest");
    let signature = Secp256k1::signing_only().sign_schnorr_no_aux_rand(digest.as_bytes(), &keypair);
    SignedProposalV2::new(
        body,
        ActorSignatureV2::from_bytes(signature.to_byte_array()).expect("signature"),
    )
    .expect("signed proposal")
}

fn transaction(proposal: &SignedProposalV2) -> Bytes {
    serde_json::to_vec(proposal).expect("canonical transaction").into()
}

fn timestamp(milliseconds: u64) -> Timestamp {
    Timestamp {
        seconds: i64::try_from(milliseconds / 1_000).expect("seconds"),
        nanos: i32::try_from((milliseconds % 1_000) * 1_000_000).expect("nanos"),
    }
}

fn commit_info(height: i64) -> Option<CommitInfo> {
    (height > 1).then_some(CommitInfo {
        round: 0,
        votes: Vec::new(),
    })
}

fn process_request(txs: Vec<Bytes>, height: i64, time_ms: u64) -> RequestProcessProposal {
    RequestProcessProposal {
        txs,
        proposed_last_commit: commit_info(height),
        misbehavior: Vec::new(),
        hash: vec![0x44; 32].into(),
        height,
        time: Some(timestamp(time_ms)),
        next_validators_hash: vec![0x55; 32].into(),
        proposer_address: vec![0x66; 20].into(),
    }
}

fn finalize_request(txs: Vec<Bytes>, height: i64, time_ms: u64) -> RequestFinalizeBlock {
    RequestFinalizeBlock {
        txs,
        decided_last_commit: commit_info(height),
        misbehavior: Vec::new(),
        hash: vec![0x44; 32].into(),
        height,
        time: Some(timestamp(time_ms)),
        next_validators_hash: vec![0x55; 32].into(),
        proposer_address: vec![0x66; 20].into(),
    }
}

fn adapter(directory: &TempDir) -> Result<ThunderboltLedgerAbci<AcceptAll>> {
    let application = LedgerApplication::open(
        directory.path().join("ledger-abci.sqlite3"),
        chain_id(),
        ApplicationOptions::default(),
    )?;
    ThunderboltLedgerAbci::new(application, AcceptAll)
}

#[test]
fn info_and_init_chain_pin_chain_and_application_version() -> Result<()> {
    let directory = TempDir::new().map_err(|_| AbciAdapterError::InvalidRequest("tempdir"))?;
    let app = adapter(&directory)?;
    let info = app.info(RequestInfo::default());
    assert_eq!(info.data, APPLICATION_NAME);
    assert_eq!(info.app_version, APPLICATION_VERSION);
    assert_eq!(info.last_block_height, 0);
    assert_eq!(info.last_block_app_hash.as_ref(), &[0_u8; 32]);

    let response = app.init_chain(RequestInitChain {
        chain_id: CHAIN_ID.to_owned(),
        initial_height: 1,
        consensus_params: Some(ConsensusParams {
            version: Some(VersionParams {
                app: APPLICATION_VERSION,
            }),
            abci: Some(AbciParams {
                vote_extensions_enable_height: 0,
            }),
            ..ConsensusParams::default()
        }),
        ..RequestInitChain::default()
    });
    assert_eq!(response.app_hash.as_ref(), &[0_u8; 32]);
    assert_eq!(
        response
            .consensus_params
            .and_then(|parameters| parameters.version)
            .map(|version| version.app),
        Some(APPLICATION_VERSION)
    );
    assert!(matches!(
        app.try_init_chain(RequestInitChain {
            chain_id: "wrong-chain".to_owned(),
            initial_height: 1,
            ..RequestInitChain::default()
        }),
        Err(AbciAdapterError::InvalidRequest(_))
    ));
    Ok(())
}

#[test]
fn check_prepare_and_process_preserve_order_without_mutation() -> Result<()> {
    let directory = TempDir::new().map_err(|_| AbciAdapterError::InvalidRequest("tempdir"))?;
    let app = adapter(&directory)?;
    let first = transaction(&signed_open(1, 1));
    let second = transaction(&signed_open(2, 2));
    let checked = app.check_tx(RequestCheckTx {
        tx: first.clone(),
        r#type: 0,
    });
    assert_eq!(checked.code, OK_CODE);
    assert_eq!(checked.data.len(), 32);

    let prepared = app.prepare_proposal(RequestPrepareProposal {
        max_tx_bytes: i64::try_from(first.len()).expect("budget"),
        txs: vec![Bytes::from_static(b"not-json"), first.clone(), second.clone()],
        height: 1,
        time: Some(timestamp(1_000)),
        next_validators_hash: vec![0x55; 32].into(),
        proposer_address: vec![0x66; 20].into(),
        ..RequestPrepareProposal::default()
    });
    assert_eq!(prepared.txs, vec![first.clone()]);

    let processed = app.process_proposal(process_request(vec![first, second], 1, 1_000));
    assert_eq!(
        processed.status,
        response_process_proposal::ProposalStatus::Accept as i32
    );
    assert_eq!(app.info(RequestInfo::default()).last_block_height, 0);
    Ok(())
}

#[test]
fn finalize_stages_and_commit_alone_advances_the_durable_head() -> Result<()> {
    let directory = TempDir::new().map_err(|_| AbciAdapterError::InvalidRequest("tempdir"))?;
    let app = adapter(&directory)?;
    let request = finalize_request(vec![transaction(&signed_open(3, 3))], 1, 1_000);
    let finalized = app.finalize_block(request.clone());
    assert_eq!(finalized.app_hash.len(), 32);
    assert_eq!(finalized.tx_results.len(), 1);
    assert_eq!(finalized.tx_results[0].code, OK_CODE);
    assert_eq!(app.info(RequestInfo::default()).last_block_height, 0);

    let repeated = app.finalize_block(request);
    assert_eq!(repeated, finalized);
    let _ = app.commit();
    let info = app.info(RequestInfo::default());
    assert_eq!(info.last_block_height, 1);
    assert_eq!(info.last_block_app_hash, finalized.app_hash);
    assert_eq!(app.commit().retain_height, 0);
    assert_eq!(app.info(RequestInfo::default()).last_block_height, 1);
    Ok(())
}

#[test]
fn crash_handshake_replays_before_or_after_commit() -> Result<()> {
    let directory = TempDir::new().map_err(|_| AbciAdapterError::InvalidRequest("tempdir"))?;
    let request = finalize_request(vec![transaction(&signed_open(4, 4))], 1, 2_000);
    let staged_hash = {
        let app = adapter(&directory)?;
        let finalized = app.finalize_block(request.clone());
        assert_eq!(app.info(RequestInfo::default()).last_block_height, 0);
        finalized.app_hash
    };

    {
        let restarted = adapter(&directory)?;
        assert_eq!(restarted.info(RequestInfo::default()).last_block_height, 0);
        let replayed = restarted.finalize_block(request.clone());
        assert_eq!(replayed.app_hash, staged_hash);
        let _ = restarted.commit();
    }

    {
        let restarted = adapter(&directory)?;
        let info = restarted.info(RequestInfo::default());
        assert_eq!(info.last_block_height, 1);
        assert_eq!(info.last_block_app_hash, staged_hash);
        let replayed = restarted.finalize_block(request);
        assert_eq!(replayed.app_hash, staged_hash);
        let _ = restarted.commit();
        assert_eq!(restarted.info(RequestInfo::default()).last_block_height, 1);
    }
    Ok(())
}

#[test]
fn invalid_decided_block_fails_closed_without_committing() -> Result<()> {
    let directory = TempDir::new().map_err(|_| AbciAdapterError::InvalidRequest("tempdir"))?;
    let app = adapter(&directory)?;
    let invalid = Bytes::from_static(b"invalid");
    let processed = app.process_proposal(process_request(vec![invalid.clone()], 1, 1_000));
    assert_eq!(
        processed.status,
        response_process_proposal::ProposalStatus::Reject as i32
    );
    let finalized = app.finalize_block(finalize_request(vec![invalid], 1, 1_000));
    assert!(finalized.app_hash.is_empty());
    assert_eq!(finalized.tx_results.len(), 1);
    assert_ne!(finalized.tx_results[0].code, OK_CODE);
    let _ = app.commit();
    assert_eq!(app.try_info(RequestInfo::default())?.last_block_height, 0);
    Ok(())
}

#[test]
fn h_result_is_the_app_hash_reported_for_header_h_plus_one() -> Result<()> {
    let directory = TempDir::new().map_err(|_| AbciAdapterError::InvalidRequest("tempdir"))?;
    let app = adapter(&directory)?;
    let first = app.finalize_block(finalize_request(vec![transaction(&signed_open(5, 5))], 1, 1_000));
    let first_hash = first.app_hash.clone();
    let _ = app.commit();
    assert_eq!(app.info(RequestInfo::default()).last_block_app_hash, first_hash);

    let second = app.finalize_block(finalize_request(Vec::new(), 2, 1_001));
    assert_eq!(second.app_hash.len(), 32);
    assert_ne!(second.app_hash, first_hash);
    assert_eq!(app.info(RequestInfo::default()).last_block_height, 1);
    let _ = app.commit();
    assert_eq!(app.info(RequestInfo::default()).last_block_height, 2);
    assert_eq!(app.info(RequestInfo::default()).last_block_app_hash, second.app_hash);
    Ok(())
}

#[test]
fn bounded_queries_return_status_block_channel_request_and_execution_proof() -> Result<()> {
    let directory = TempDir::new().map_err(|_| AbciAdapterError::InvalidRequest("tempdir"))?;
    let app = adapter(&directory)?;
    let proposal = signed_open(6, 6);
    let body = proposal.body().clone();
    let finalized = app.finalize_block(finalize_request(vec![transaction(&proposal)], 1, 3_000));
    assert_eq!(finalized.app_hash.len(), 32);
    let _ = app.commit();

    let status = app.query(RequestQuery {
        path: QUERY_STATUS_PATH.to_owned(),
        ..RequestQuery::default()
    });
    assert_eq!(status.code, OK_CODE);
    assert_eq!(status.height, 1);
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&status.value)?["last_height"],
        1
    );

    let block = app.query(RequestQuery {
        data: 1_u64.to_be_bytes().to_vec().into(),
        path: QUERY_BLOCK_PATH.to_owned(),
        height: 1,
        ..RequestQuery::default()
    });
    assert_eq!(block.code, OK_CODE);
    assert_eq!(serde_json::from_slice::<serde_json::Value>(&block.value)?["height"], 1);

    let context = ChannelContextIdV2::from_bytes(body.channel().context_id().expect("context"))?;
    let channel = app.query(RequestQuery {
        data: context.as_bytes().to_vec().into(),
        path: QUERY_CHANNEL_PATH.to_owned(),
        ..RequestQuery::default()
    });
    assert_eq!(channel.code, OK_CODE);
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&channel.value)?["committed_application_height"],
        1
    );

    let participant = body.participant_id()?;
    let mut request_key = Vec::with_capacity(96);
    request_key.extend_from_slice(context.as_bytes());
    request_key.extend_from_slice(participant.as_bytes());
    request_key.extend_from_slice(body.request_id().digest().as_bytes());
    let request = app.query(RequestQuery {
        data: request_key.into(),
        path: QUERY_REQUEST_PATH.to_owned(),
        ..RequestQuery::default()
    });
    assert_eq!(request.code, OK_CODE);
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&request.value)?["first_height"],
        1
    );

    let mut proof_key = Vec::with_capacity(12);
    proof_key.extend_from_slice(&1_u64.to_be_bytes());
    proof_key.extend_from_slice(&0_u32.to_be_bytes());
    let proof = app.query(RequestQuery {
        data: proof_key.into(),
        path: QUERY_PROOF_PATH.to_owned(),
        prove: true,
        ..RequestQuery::default()
    });
    assert_eq!(proof.code, OK_CODE);
    assert!(proof.proof_ops.is_none());
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&proof.value)?["execution_only"],
        true
    );
    Ok(())
}

#[test]
fn cloned_connections_share_staging_and_serialize_concurrent_previews() -> Result<()> {
    let directory = TempDir::new().map_err(|_| AbciAdapterError::InvalidRequest("tempdir"))?;
    let app = adapter(&directory)?;
    let tx = transaction(&signed_open(7, 7));
    let barrier = Arc::new(Barrier::new(3));
    let first_app = app.clone();
    let first_barrier = Arc::clone(&barrier);
    let first_tx = tx.clone();
    let first = thread::spawn(move || {
        first_barrier.wait();
        first_app.process_proposal(process_request(vec![first_tx], 1, 4_000))
    });
    let second_app = app.clone();
    let second_barrier = Arc::clone(&barrier);
    let second_tx = tx.clone();
    let second = thread::spawn(move || {
        second_barrier.wait();
        second_app.process_proposal(process_request(vec![second_tx], 1, 4_000))
    });
    barrier.wait();
    assert_eq!(
        first.join().expect("first connection").status,
        response_process_proposal::ProposalStatus::Accept as i32
    );
    assert_eq!(
        second.join().expect("second connection").status,
        response_process_proposal::ProposalStatus::Accept as i32
    );
    assert_eq!(app.info(RequestInfo::default()).last_block_height, 0);

    let finalized = app.clone().finalize_block(finalize_request(vec![tx], 1, 4_000));
    assert_eq!(finalized.app_hash.len(), 32);
    let _ = app.clone().commit();
    assert_eq!(app.info(RequestInfo::default()).last_block_height, 1);
    Ok(())
}

#[test]
fn snapshots_and_vote_extensions_fail_closed() -> Result<()> {
    let directory = TempDir::new().map_err(|_| AbciAdapterError::InvalidRequest("tempdir"))?;
    let app = adapter(&directory)?;
    assert!(app.list_snapshots().snapshots.is_empty());
    assert_eq!(
        app.offer_snapshot(RequestOfferSnapshot::default()).result,
        response_offer_snapshot::Result::Abort as i32
    );
    assert!(app
        .load_snapshot_chunk(RequestLoadSnapshotChunk::default())
        .chunk
        .is_empty());
    assert_eq!(
        app.apply_snapshot_chunk(RequestApplySnapshotChunk::default()).result,
        response_apply_snapshot_chunk::Result::Abort as i32
    );
    assert!(app.extend_vote(RequestExtendVote::default()).vote_extension.is_empty());
    assert_eq!(
        app.verify_vote_extension(RequestVerifyVoteExtension::default()).status,
        response_verify_vote_extension::VerifyStatus::Reject as i32
    );
    Ok(())
}

#[test]
fn explicit_oversize_requests_fail_without_panicking_or_allocating_unbounded_results() -> Result<()> {
    let directory = TempDir::new().map_err(|_| AbciAdapterError::InvalidRequest("tempdir"))?;
    let app = adapter(&directory)?;
    let oversized = vec![0_u8; MAX_TRANSACTION_BYTES + 1];
    assert_ne!(
        app.check_tx(RequestCheckTx {
            tx: oversized.into(),
            r#type: 0,
        })
        .code,
        OK_CODE
    );
    let finalized = app.finalize_block(finalize_request(vec![Bytes::new(); MAX_BLOCK_ENTRIES + 1], 1, 1_000));
    assert!(finalized.app_hash.is_empty());
    assert_eq!(finalized.tx_results.len(), MAX_BLOCK_ENTRIES);
    Ok(())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn arbitrary_bounded_transaction_and_query_bytes_never_panic(
        transaction_bytes in prop::collection::vec(any::<u8>(), 0..4096),
        query_bytes in prop::collection::vec(any::<u8>(), 0..256),
        path in ".{0,80}",
    ) {
        let directory = TempDir::new().expect("tempdir");
        let app = adapter(&directory).expect("adapter");
        let _ = app.check_tx(RequestCheckTx {
            tx: transaction_bytes.into(),
            r#type: 0,
        });
        let response = app.query(RequestQuery {
            data: query_bytes.into(),
            path,
            height: 0,
            prove: false,
        });
        prop_assert!(response.code <= 7);
        prop_assert!(response.value.len() <= MAX_QUERY_RESPONSE_BYTES);
    }
}
