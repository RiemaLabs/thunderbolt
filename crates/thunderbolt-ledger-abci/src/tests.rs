#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::Duration;

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
    ClientRequestNonceV2, EntryHashV2, LedgerChainIdV2, ProposalBodyV2, SignedProposalV2, EVENT_BYTES_MAX,
    MAX_BLOCK_ENTRIES,
};
use thunderbolt_ledger_app::{ApplicationOptions, LedgerApplication};
use thunderbolt_ledger_rpc::{RpcRequestV2, MAX_EXECUTION_RANGE_ENCODED_BYTES};
use thunderbolt_protocol::v2::{
    ArtifactV2, ChannelEventV2, ExternalVerifierV2, FinalizeVerificationRequestV2, InvoiceEventV2,
    InvoiceVerificationRequestV2, OpenEventV2, OpenVerificationRequestV2, TransferVerificationRequestV2,
};
use thunderbolt_wire::{
    AnchorParameterSuiteIdV2, BitcoinGenesisHashV2, ChannelBindingV2, CommitteeDescriptorDigestV2, FundingOutpointV2,
    HexBytes, ProtocolSuiteIdV2,
};

use super::*;

const CHAIN_ID: &str = "thunderbolt-abci-regtest-1";

#[derive(Debug, Default)]
struct AcceptAll;

#[derive(Debug, Default)]
struct RejectPoison;

#[derive(Clone, Copy, Debug, Default)]
struct PanicFatal;

#[derive(Debug)]
struct ToggleVerifier {
    reject_contextual: Arc<AtomicBool>,
}

impl FatalAbciHandler for PanicFatal {
    fn terminate(&self, failure: FatalAbciFailure) -> ! {
        std::panic::panic_any(failure)
    }
}

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

impl ExternalVerifierV2 for RejectPoison {
    type Error = ();

    fn verify_open(&self, request: OpenVerificationRequestV2<'_>) -> std::result::Result<(), Self::Error> {
        if request.event.open_proof.as_bytes() == [0xff] {
            Err(())
        } else {
            Ok(())
        }
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

impl StaticAdmissionVerifierV2 for AcceptAll {
    type Error = ();

    fn verifier_profile_id(&self) -> [u8; 32] {
        [0x41; 32]
    }

    fn deployment_descriptor(&self) -> [u8; 32] {
        [0x51; 32]
    }

    fn verify_static(&self, _request: StaticAdmissionRequestV2<'_>) -> std::result::Result<(), Self::Error> {
        Ok(())
    }
}

impl StaticAdmissionVerifierV2 for RejectPoison {
    type Error = ();

    fn verifier_profile_id(&self) -> [u8; 32] {
        [0x42; 32]
    }

    fn deployment_descriptor(&self) -> [u8; 32] {
        [0x51; 32]
    }

    fn verify_static(&self, request: StaticAdmissionRequestV2<'_>) -> std::result::Result<(), Self::Error> {
        match request.event() {
            ChannelEventV2::Open(event) if event.open_proof.as_bytes() == [0xff] => Err(()),
            _ => Ok(()),
        }
    }
}

impl ExternalVerifierV2 for ToggleVerifier {
    type Error = ();

    fn verify_open(&self, _request: OpenVerificationRequestV2<'_>) -> std::result::Result<(), Self::Error> {
        if self.reject_contextual.load(Ordering::SeqCst) {
            Err(())
        } else {
            Ok(())
        }
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

impl StaticAdmissionVerifierV2 for ToggleVerifier {
    type Error = ();

    fn verifier_profile_id(&self) -> [u8; 32] {
        [0x43; 32]
    }

    fn deployment_descriptor(&self) -> [u8; 32] {
        [0x51; 32]
    }

    fn verify_static(&self, _request: StaticAdmissionRequestV2<'_>) -> std::result::Result<(), Self::Error> {
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
        lock_key: ArtifactV2::new([1]).expect("artifact"),
        initial_holder_anchor: ArtifactV2::new([2]).expect("artifact"),
        initial_holder_ciphertext: ArtifactV2::new([3]).expect("artifact"),
        open_proof: ArtifactV2::new([4]).expect("artifact"),
    })
}

fn keypair(index: u64) -> Keypair {
    let mut secret = [0_u8; 32];
    secret[24..].copy_from_slice(&index.max(1).to_be_bytes());
    let secret = SecretKey::from_byte_array(secret).expect("secret key");
    Keypair::from_secret_key(&Secp256k1::signing_only(), &secret)
}

fn signed_open(channel_byte: u8, actor: u64) -> SignedProposalV2 {
    signed_open_custom(channel_byte, actor, 0, [channel_byte; 16], 4)
}

fn signed_open_with_proof(channel_byte: u8, actor: u64, proof_byte: u8) -> SignedProposalV2 {
    signed_open_custom(channel_byte, actor, 0, [channel_byte; 16], proof_byte)
}

fn signed_open_custom(
    channel_byte: u8,
    actor: u64,
    sequence: u64,
    request_nonce: [u8; 16],
    proof_byte: u8,
) -> SignedProposalV2 {
    let keypair = keypair(actor);
    let (public, _) = keypair.x_only_public_key();
    let mut event = open_event();
    let ChannelEventV2::Open(open) = &mut event else {
        panic!("Open test event changed variant");
    };
    open.open_proof = ArtifactV2::new([proof_byte]).expect("artifact");
    let body = ProposalBodyV2::new(
        chain_id(),
        binding(channel_byte),
        sequence,
        EntryHashV2::zero(),
        ClientRequestNonceV2::from_bytes(request_nonce).expect("request nonce"),
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

fn signed_absent_channel_invoice(request_index: u32) -> SignedProposalV2 {
    let actor = 40_u64;
    let keypair = keypair(actor);
    let (public, _) = keypair.x_only_public_key();
    let event = ChannelEventV2::Invoice(InvoiceEventV2 {
        invoice_id: HexBytes::from_bytes("invoice id", request_index.to_be_bytes()).expect("invoice id"),
        holder_step: 0,
        recipient_encryption_key: ArtifactV2::new([5]).expect("artifact"),
        public_delta: ArtifactV2::new([6]).expect("artifact"),
        recipient_ciphertext: ArtifactV2::new([7]).expect("artifact"),
        committee_package: ArtifactV2::new([8]).expect("artifact"),
        invoice_proof: ArtifactV2::new([9]).expect("artifact"),
        expires_at_ms: 10_000,
    });
    let mut nonce = [0_u8; 16];
    nonce[0] = 1;
    nonce[12..].copy_from_slice(&request_index.to_be_bytes());
    let body = ProposalBodyV2::new(
        chain_id(),
        binding(40),
        1,
        EntryHashV2::from_bytes([0x77; 32]).expect("predecessor"),
        ClientRequestNonceV2::from_bytes(nonce).expect("request nonce"),
        ActorKeyAlgorithmV2::Bip340V1,
        ActorPublicKeyV2::from_bytes(public.serialize()).expect("public key"),
        ActorRoleV2::Recipient,
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

fn signed_invoice_after_open(open: &SignedProposalV2, request_index: u32, expires_at_ms: u64) -> SignedProposalV2 {
    let actor = 60_u64;
    let keypair = keypair(actor);
    let (public, _) = keypair.x_only_public_key();
    let event = ChannelEventV2::Invoice(InvoiceEventV2 {
        invoice_id: HexBytes::from_bytes("invoice id", request_index.to_be_bytes()).expect("invoice id"),
        holder_step: 0,
        recipient_encryption_key: ArtifactV2::new([5]).expect("artifact"),
        public_delta: ArtifactV2::new([6]).expect("artifact"),
        recipient_ciphertext: ArtifactV2::new([7]).expect("artifact"),
        committee_package: ArtifactV2::new([8]).expect("artifact"),
        invoice_proof: ArtifactV2::new([9]).expect("artifact"),
        expires_at_ms,
    });
    let mut nonce = [0_u8; 16];
    nonce[0] = 1;
    nonce[12..].copy_from_slice(&request_index.to_be_bytes());
    let body = ProposalBodyV2::new(
        chain_id(),
        open.body().channel().clone(),
        1,
        open.body().entry_hash().expect("Open entry hash"),
        ClientRequestNonceV2::from_bytes(nonce).expect("request nonce"),
        ActorKeyAlgorithmV2::Bip340V1,
        ActorPublicKeyV2::from_bytes(public.serialize()).expect("public key"),
        ActorRoleV2::Recipient,
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

fn resign(proposal: &SignedProposalV2, actor: u64, nonce: u32) -> SignedProposalV2 {
    let body = proposal.body().clone();
    let digest = body.proposal_digest().expect("proposal digest");
    let mut auxiliary = [0_u8; 32];
    auxiliary[28..].copy_from_slice(&nonce.to_be_bytes());
    let signature =
        Secp256k1::signing_only().sign_schnorr_with_aux_rand(digest.as_bytes(), &keypair(actor), &auxiliary);
    SignedProposalV2::new(
        body,
        ActorSignatureV2::from_bytes(signature.to_byte_array()).expect("signature"),
    )
    .expect("resigned proposal")
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

fn adapter(directory: &TempDir) -> Result<ThunderboltLedgerAbci<AcceptAll, PanicFatal>> {
    adapter_with(directory, AcceptAll)
}

fn adapter_with<V>(directory: &TempDir, verifier: V) -> Result<ThunderboltLedgerAbci<V, PanicFatal>>
where
    V: LedgerApplicationVerifierV2 + StaticAdmissionVerifierV2 + Send + Sync + 'static,
{
    let limits = thunderbolt_protocol::v2::ProtocolLimitsV2::default();
    let profile = ConsensusProfileV2::from_verifier(&chain_id(), limits, &verifier)?;
    let application = LedgerApplication::open(
        directory.path().join("ledger-abci.sqlite3"),
        chain_id(),
        ApplicationOptions {
            protocol_limits: limits,
            consensus_profile_digest: Some(*profile.as_bytes()),
            ..ApplicationOptions::default()
        },
    )?;
    ThunderboltLedgerAbci::new(application, verifier, PanicFatal)
}

fn capture_fatal<T>(action: impl FnOnce() -> T) -> FatalAbciFailure {
    let payload = match catch_unwind(AssertUnwindSafe(action)) {
        Ok(_) => panic!("fatal handler returned"),
        Err(payload) => payload,
    };
    *payload.downcast::<FatalAbciFailure>().expect("fatal handler payload")
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
        app_state_bytes: app.consensus_profile().genesis_app_state_bytes()?.into(),
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
            app_state_bytes: app.consensus_profile().genesis_app_state_bytes()?.into(),
            ..RequestInitChain::default()
        }),
        Err(AbciAdapterError::InvalidRequest(_))
    ));
    assert!(matches!(
        app.try_init_chain(RequestInitChain {
            chain_id: CHAIN_ID.to_owned(),
            initial_height: 1,
            app_state_bytes: b"wrong-profile".to_vec().into(),
            ..RequestInitChain::default()
        }),
        Err(AbciAdapterError::InvalidRequest(_))
    ));
    assert!(matches!(
        app.try_init_chain(RequestInitChain {
            chain_id: CHAIN_ID.to_owned(),
            initial_height: 1,
            app_state_bytes: app.consensus_profile().genesis_app_state_bytes()?.into(),
            validators: vec![Default::default(); MAX_COMMIT_VOTES + 1],
            ..RequestInitChain::default()
        }),
        Err(AbciAdapterError::InvalidRequest(_))
    ));
    Ok(())
}

#[test]
fn consensus_profile_has_a_golden_digest_and_changes_with_identity_or_limits() -> Result<()> {
    let limits = thunderbolt_protocol::v2::ProtocolLimitsV2::default();
    let profile = ConsensusProfileV2::from_verifier(&chain_id(), limits, &AcceptAll)?;
    assert_eq!(
        profile.as_bytes(),
        &[
            0x8a, 0x46, 0x38, 0x64, 0x7d, 0x2e, 0x2a, 0x96, 0x9c, 0xb9, 0x04, 0xbf, 0x7f, 0x46, 0x09, 0x6d, 0x25, 0xf1,
            0x0d, 0xaf, 0x60, 0xa8, 0x3f, 0xf7, 0x76, 0xef, 0xcc, 0xbb, 0xe3, 0xe2, 0x94, 0x7a,
        ]
    );
    assert_ne!(
        profile,
        ConsensusProfileV2::from_verifier(&chain_id(), limits, &RejectPoison)?
    );
    assert_ne!(
        profile,
        ConsensusProfileV2::from_verifier(
            &chain_id(),
            thunderbolt_protocol::v2::ProtocolLimitsV2::new(
                limits.max_entries_per_channel + 1,
                limits.max_pending_invoices,
                limits.max_invoice_ttl_ms,
            )
            .expect("mutated limits"),
            &AcceptAll,
        )?
    );
    assert_ne!(
        profile,
        ConsensusProfileV2::from_verifier(&LedgerChainIdV2::new("different-profile-chain")?, limits, &AcceptAll,)?
    );
    let mut resource_values = compiled_resource_profile_values();
    resource_values[COMPILED_RETAINED_STATE_INDEX] = resource_values[COMPILED_RETAINED_STATE_INDEX]
        .checked_add(1)
        .ok_or(AbciAdapterError::InvalidRequest("test resource value overflows"))?;
    let changed_retained_budget = ConsensusProfileV2 {
        digest: consensus_profile_digest(
            &chain_id(),
            limits,
            AcceptAll.verifier_profile_id(),
            AcceptAll.deployment_descriptor(),
            &resource_values,
        )?,
    };
    assert_ne!(profile, changed_retained_budget);
    Ok(())
}

#[test]
fn compiled_resource_limits_are_closed_across_events_transactions_and_blocks() -> Result<()> {
    validate_compiled_resource_limits()?;
    assert_eq!(MAX_TRANSACTION_BYTES, MAX_SIGNED_PROPOSAL_JSON_BYTES);
    assert_eq!(
        EVENT_BYTES_MAX * 2 + SIGNED_PROPOSAL_RPC_METADATA_ALLOWANCE_BYTES,
        MAX_SIGNED_PROPOSAL_JSON_BYTES
    );
    assert_eq!(
        MAX_RETAINED_CHANNEL_STATE_BYTES_V2 + SNAPSHOT_CANONICAL_FRAMING_ALLOWANCE_BYTES_V2,
        MAX_CANONICAL_SNAPSHOT_BYTES_V2
    );
    assert_eq!(
        MAX_RETAINED_CHANNEL_STATE_BYTES_V2 * 2 + SNAPSHOT_QUERY_JSON_METADATA_ALLOWANCE_BYTES,
        MAX_QUERY_RESPONSE_BYTES
    );
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
fn prepare_charges_all_scanned_values_and_skips_nonfitting_front_value() -> Result<()> {
    let directory = TempDir::new().map_err(|_| AbciAdapterError::InvalidRequest("tempdir"))?;
    let app = adapter(&directory)?;
    let valid = transaction(&signed_open(32, 32));
    let nonfitting = Bytes::from(vec![0x7b; valid.len() + 1]);
    let prepared = app.prepare_proposal(RequestPrepareProposal {
        max_tx_bytes: i64::try_from(valid.len()).expect("budget"),
        txs: vec![nonfitting, valid.clone()],
        height: 1,
        time: Some(timestamp(1_000)),
        next_validators_hash: vec![0x55; 32].into(),
        proposer_address: vec![0x66; 20].into(),
        ..RequestPrepareProposal::default()
    });
    assert_eq!(prepared.txs, vec![valid.clone()]);

    let mut exhausted = vec![Bytes::from_static(b"x"); MAX_PREPARE_SCAN_TRANSACTIONS];
    exhausted.push(valid);
    let bounded = app.prepare_proposal(RequestPrepareProposal {
        max_tx_bytes: i64::try_from(MAX_BLOCK_TRANSACTION_BYTES).expect("budget"),
        txs: exhausted,
        height: 1,
        time: Some(timestamp(1_000)),
        next_validators_hash: vec![0x55; 32].into(),
        proposer_address: vec![0x66; 20].into(),
        ..RequestPrepareProposal::default()
    });
    assert!(bounded.txs.is_empty());
    Ok(())
}

#[test]
fn fairness_cursor_is_explicitly_process_local_and_resets_on_restart() -> Result<()> {
    let directory = TempDir::new().map_err(|_| AbciAdapterError::InvalidRequest("tempdir"))?;
    let app = adapter(&directory)?;
    *app.inner.prepare_cursor.lock().expect("cursor") = 123;
    drop(app);
    let restarted = adapter(&directory)?;
    assert_eq!(*restarted.inner.prepare_cursor.lock().expect("cursor"), 0);
    Ok(())
}

#[test]
fn contextual_checktx_writer_contention_terminates_instead_of_succeeding() -> Result<()> {
    let directory = TempDir::new().map_err(|_| AbciAdapterError::InvalidRequest("tempdir"))?;
    let path = directory.path().join("contended.sqlite3");
    let limits = thunderbolt_protocol::v2::ProtocolLimitsV2::default();
    let profile = ConsensusProfileV2::from_verifier(&chain_id(), limits, &AcceptAll)?;
    let application = LedgerApplication::open(
        &path,
        chain_id(),
        ApplicationOptions {
            busy_timeout: Duration::from_millis(25),
            protocol_limits: limits,
            consensus_profile_digest: Some(*profile.as_bytes()),
        },
    )?;
    let app = ThunderboltLedgerAbci::new(application, AcceptAll, PanicFatal)?;
    let external = rusqlite::Connection::open(path).map_err(thunderbolt_ledger_app::ApplicationError::from)?;
    external
        .execute_batch("BEGIN IMMEDIATE")
        .map_err(thunderbolt_ledger_app::ApplicationError::from)?;
    let failure = capture_fatal(|| {
        app.check_tx(RequestCheckTx {
            tx: transaction(&signed_open(42, 42)),
            r#type: 0,
        })
    });
    assert_eq!(failure.stage(), FatalAbciStage::CheckTx);
    external
        .execute_batch("ROLLBACK")
        .map_err(thunderbolt_ledger_app::ApplicationError::from)?;
    Ok(())
}

#[test]
fn logical_request_dedupes_distinct_signatures_and_recheck_evicts_after_commit() -> Result<()> {
    let directory = TempDir::new().map_err(|_| AbciAdapterError::InvalidRequest("tempdir"))?;
    let app = adapter(&directory)?;
    let proposal = signed_open(30, 30);
    let admitted = transaction(&proposal);
    assert_eq!(
        app.check_tx(RequestCheckTx {
            tx: admitted.clone(),
            r#type: 0,
        })
        .code,
        OK_CODE
    );
    assert_eq!(
        app.check_tx(RequestCheckTx {
            tx: admitted.clone(),
            r#type: 1,
        })
        .code,
        OK_CODE
    );
    for nonce in 1..=u32::try_from(MAX_PREPARE_PREVIEW_WORK + 1).expect("bounded nonce") {
        assert_ne!(
            app.check_tx(RequestCheckTx {
                tx: transaction(&resign(&proposal, 30, nonce)),
                r#type: 0,
            })
            .code,
            OK_CODE
        );
    }

    let prepared = app.prepare_proposal(RequestPrepareProposal {
        max_tx_bytes: i64::try_from(admitted.len()).expect("budget"),
        txs: vec![admitted.clone()],
        height: 1,
        time: Some(timestamp(1_000)),
        next_validators_hash: vec![0x55; 32].into(),
        proposer_address: vec![0x66; 20].into(),
        ..RequestPrepareProposal::default()
    });
    assert_eq!(prepared.txs, vec![admitted.clone()]);
    let finalized = app.finalize_block(finalize_request(prepared.txs, 1, 1_000));
    assert_eq!(finalized.tx_results.len(), 1);
    let _ = app.commit();
    assert_ne!(
        app.check_tx(RequestCheckTx {
            tx: admitted,
            r#type: 1,
        })
        .code,
        OK_CODE
    );
    for nonce in 1..=u32::try_from(MAX_PREPARE_PREVIEW_WORK + 1).expect("bounded nonce") {
        assert_ne!(
            app.check_tx(RequestCheckTx {
                tx: transaction(&resign(&proposal, 30, nonce)),
                r#type: 1,
            })
            .code,
            OK_CODE
        );
    }
    Ok(())
}

#[test]
fn proposer_skips_poison_proof_and_valid_transaction_still_progresses() -> Result<()> {
    let directory = TempDir::new().map_err(|_| AbciAdapterError::InvalidRequest("tempdir"))?;
    let app = adapter_with(&directory, RejectPoison)?;
    let poison = transaction(&signed_open_with_proof(20, 20, 0xff));
    let valid = transaction(&signed_open(21, 21));
    for check_type in [0, 1] {
        for _ in 0..=MAX_PREPARE_PREVIEW_WORK {
            assert_ne!(
                app.check_tx(RequestCheckTx {
                    tx: poison.clone(),
                    r#type: check_type,
                })
                .code,
                OK_CODE
            );
        }
    }
    let prepared = app.prepare_proposal(RequestPrepareProposal {
        max_tx_bytes: i64::try_from(valid.len()).expect("budget"),
        txs: vec![valid.clone()],
        height: 1,
        time: Some(timestamp(1_000)),
        next_validators_hash: vec![0x55; 32].into(),
        proposer_address: vec![0x66; 20].into(),
        ..RequestPrepareProposal::default()
    });
    assert_eq!(prepared.txs, vec![valid.clone()]);
    assert_eq!(
        app.process_proposal(process_request(prepared.txs.clone(), 1, 1_000))
            .status,
        response_process_proposal::ProposalStatus::Accept as i32
    );
    let finalized = app.finalize_block(finalize_request(prepared.txs, 1, 1_000));
    assert_eq!(finalized.tx_results.len(), 1);
    assert_eq!(finalized.tx_results[0].code, OK_CODE);
    let _ = app.commit();
    assert_eq!(app.info(RequestInfo::default()).last_block_height, 1);
    assert_ne!(app.check_tx(RequestCheckTx { tx: valid, r#type: 1 }).code, OK_CODE);
    Ok(())
}

#[test]
fn contextual_check_evicts_full_invalid_prefix_and_valid_request_progresses() -> Result<()> {
    let directory = TempDir::new().map_err(|_| AbciAdapterError::InvalidRequest("tempdir"))?;
    let app = adapter(&directory)?;
    for index in 0..u32::try_from(MAX_PREPARE_SCAN_TRANSACTIONS).expect("scan count") {
        let invalid = transaction(&signed_absent_channel_invoice(index));
        assert_ne!(app.check_tx(RequestCheckTx { tx: invalid, r#type: 0 }).code, OK_CODE);
    }

    let valid = transaction(&signed_open(41, 41));
    assert_eq!(
        app.check_tx(RequestCheckTx {
            tx: valid.clone(),
            r#type: 0,
        })
        .code,
        OK_CODE
    );
    let prepared = app.prepare_proposal(RequestPrepareProposal {
        max_tx_bytes: i64::try_from(valid.len()).expect("budget"),
        txs: vec![valid.clone()],
        height: 1,
        time: Some(timestamp(1_000)),
        next_validators_hash: vec![0x55; 32].into(),
        proposer_address: vec![0x66; 20].into(),
        ..RequestPrepareProposal::default()
    });
    assert_eq!(prepared.txs, vec![valid]);
    Ok(())
}

#[test]
fn rotating_prepare_window_cannot_hide_valid_suffix_behind_near_expiry_prefix() -> Result<()> {
    let directory = TempDir::new().map_err(|_| AbciAdapterError::InvalidRequest("tempdir"))?;
    let app = adapter(&directory)?;
    let open = signed_open(60, 61);
    let _ = app.try_finalize_block(finalize_request(vec![transaction(&open)], 1, 1_000))?;
    let _ = app.try_commit()?;

    let mut transactions = Vec::with_capacity(MAX_PREPARE_SCAN_TRANSACTIONS + 1);
    for index in 0..u32::try_from(MAX_PREPARE_SCAN_TRANSACTIONS).expect("scan count") {
        let expiring = transaction(&signed_invoice_after_open(&open, index, 1_001));
        if index == 0 {
            assert_eq!(
                app.check_tx(RequestCheckTx {
                    tx: expiring.clone(),
                    r#type: 0,
                })
                .code,
                OK_CODE
            );
        }
        transactions.push(expiring);
    }
    let valid = transaction(&signed_open(61, 62));
    transactions.push(valid.clone());
    let request = RequestPrepareProposal {
        max_tx_bytes: i64::try_from(MAX_BLOCK_TRANSACTION_BYTES).expect("budget"),
        txs: transactions,
        height: 2,
        time: Some(timestamp(1_001)),
        next_validators_hash: vec![0x55; 32].into(),
        proposer_address: vec![0x66; 20].into(),
        ..RequestPrepareProposal::default()
    };
    assert!(app.prepare_proposal(request.clone()).txs.is_empty());
    let second_round = app.prepare_proposal(request);
    assert_eq!(second_round.txs, vec![valid]);
    assert_eq!(
        app.process_proposal(process_request(second_round.txs, 2, 1_001)).status,
        response_process_proposal::ProposalStatus::Accept as i32
    );
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
    Ok(())
}

#[test]
fn every_missing_or_duplicate_commit_fails_closed() -> Result<()> {
    let directory = TempDir::new().map_err(|_| AbciAdapterError::InvalidRequest("tempdir"))?;
    let app = adapter(&directory)?;
    assert!(matches!(app.try_commit(), Err(AbciAdapterError::MissingStagedBlock)));
    assert_eq!(app.try_info(RequestInfo::default())?.last_block_height, 0);

    let finalized = app.try_finalize_block(finalize_request(Vec::new(), 1, 1_000))?;
    assert_eq!(finalized.app_hash.len(), 32);
    let _ = app.try_commit()?;
    let committed = app.try_info(RequestInfo::default())?;
    assert!(matches!(app.try_commit(), Err(AbciAdapterError::MissingStagedBlock)));
    assert_eq!(app.try_info(RequestInfo::default())?, committed);

    let reopened = adapter(&directory)?;
    assert!(matches!(
        reopened.try_commit(),
        Err(AbciAdapterError::MissingStagedBlock)
    ));
    assert_eq!(reopened.try_info(RequestInfo::default())?, committed);
    Ok(())
}

#[test]
fn precommit_reverification_failure_terminates_before_response() -> Result<()> {
    let directory = TempDir::new().map_err(|_| AbciAdapterError::InvalidRequest("tempdir"))?;
    let rejection = Arc::new(AtomicBool::new(false));
    let app = adapter_with(
        &directory,
        ToggleVerifier {
            reject_contextual: Arc::clone(&rejection),
        },
    )?;
    let finalized = app.finalize_block(finalize_request(vec![transaction(&signed_open(31, 31))], 1, 1_000));
    assert_eq!(finalized.app_hash.len(), 32);
    rejection.store(true, Ordering::SeqCst);
    let failure = capture_fatal(|| app.commit());
    assert_eq!(failure.stage(), FatalAbciStage::Commit);
    assert_eq!(app.try_info(RequestInfo::default())?.last_block_height, 0);
    Ok(())
}

#[test]
fn postcommit_ambiguity_terminates_and_restart_resolves_durable_head() -> Result<()> {
    let directory = TempDir::new().map_err(|_| AbciAdapterError::InvalidRequest("tempdir"))?;
    let app = adapter(&directory)?;
    let finalized = app.finalize_block(finalize_request(Vec::new(), 1, 1_000));
    assert_eq!(finalized.app_hash.len(), 32);
    app.fail_after_next_commit_for_test();
    let failure = capture_fatal(|| app.commit());
    assert_eq!(failure.stage(), FatalAbciStage::Commit);
    drop(app);

    let restarted = adapter(&directory)?;
    assert_eq!(restarted.try_info(RequestInfo::default())?.last_block_height, 1);
    Ok(())
}

#[test]
fn info_storage_failure_terminates_instead_of_returning_height_zero() -> Result<()> {
    let directory = TempDir::new().map_err(|_| AbciAdapterError::InvalidRequest("tempdir"))?;
    let path = directory.path().join("ledger-abci.sqlite3");
    let app = adapter(&directory)?;
    let external = rusqlite::Connection::open(path).map_err(thunderbolt_ledger_app::ApplicationError::from)?;
    external
        .execute_batch("DROP TABLE application_state")
        .map_err(thunderbolt_ledger_app::ApplicationError::from)?;
    let failure = capture_fatal(|| app.info(RequestInfo::default()));
    assert_eq!(failure.stage(), FatalAbciStage::Info);
    Ok(())
}

#[test]
fn semantically_invalid_stored_snapshot_terminates_query() -> Result<()> {
    let directory = TempDir::new().map_err(|_| AbciAdapterError::InvalidRequest("tempdir"))?;
    let path = directory.path().join("ledger-abci.sqlite3");
    let app = adapter(&directory)?;
    let proposal = signed_open(50, 50);
    let context = ChannelContextIdV2::from_bytes(proposal.body().channel().context_id().expect("context"))?;
    let _ = app.try_finalize_block(finalize_request(vec![transaction(&proposal)], 1, 1_000))?;
    let _ = app.try_commit()?;
    let external = rusqlite::Connection::open(path).map_err(thunderbolt_ledger_app::ApplicationError::from)?;
    let bytes: Vec<u8> = external
        .query_row(
            "SELECT snapshot_json FROM channel_snapshots WHERE channel_context_id = ?1",
            [context.as_bytes().as_slice()],
            |row| row.get(0),
        )
        .map_err(thunderbolt_ledger_app::ApplicationError::from)?;
    let mut value: serde_json::Value = serde_json::from_slice(&bytes)?;
    value["capacity_sat"] = serde_json::Value::from(0_u64);
    external
        .execute(
            "UPDATE channel_snapshots SET snapshot_json = ?1 WHERE channel_context_id = ?2",
            rusqlite::params![serde_json::to_vec(&value)?, context.as_bytes().as_slice()],
        )
        .map_err(thunderbolt_ledger_app::ApplicationError::from)?;
    let failure = capture_fatal(|| {
        app.query(RequestQuery {
            data: context.as_bytes().to_vec().into(),
            path: QUERY_CHANNEL_PATH.to_owned(),
            ..RequestQuery::default()
        })
    });
    assert_eq!(failure.stage(), FatalAbciStage::Query);
    Ok(())
}

#[test]
fn malformed_stored_request_terminates_query_and_checktx() -> Result<()> {
    for check_path in [false, true] {
        let directory = TempDir::new().map_err(|_| AbciAdapterError::InvalidRequest("tempdir"))?;
        let path = directory.path().join("ledger-abci.sqlite3");
        let app = adapter(&directory)?;
        let proposal = signed_open(51, 51);
        let context = ChannelContextIdV2::from_bytes(proposal.body().channel().context_id().expect("context"))?;
        let participant = proposal.body().participant_id()?;
        let request_digest = proposal.body().request_id().digest().clone();
        let transaction = transaction(&proposal);
        let _ = app.try_finalize_block(finalize_request(vec![transaction.clone()], 1, 1_000))?;
        let _ = app.try_commit()?;
        let external = rusqlite::Connection::open(path).map_err(thunderbolt_ledger_app::ApplicationError::from)?;
        external
            .execute_batch(
                "PRAGMA ignore_check_constraints = ON;
                 DROP TRIGGER request_index_no_update;",
            )
            .map_err(thunderbolt_ledger_app::ApplicationError::from)?;
        external
            .execute(
                "UPDATE request_index SET entry_hash = x'01'
                 WHERE channel_context_id = ?1 AND participant_id = ?2 AND request_digest = ?3",
                rusqlite::params![
                    context.as_bytes().as_slice(),
                    participant.as_bytes().as_slice(),
                    request_digest.as_bytes().as_slice(),
                ],
            )
            .map_err(thunderbolt_ledger_app::ApplicationError::from)?;
        let failure = if check_path {
            capture_fatal(|| {
                app.check_tx(RequestCheckTx {
                    tx: transaction,
                    r#type: 1,
                })
            })
        } else {
            let mut key = Vec::with_capacity(96);
            key.extend_from_slice(context.as_bytes());
            key.extend_from_slice(participant.as_bytes());
            key.extend_from_slice(request_digest.as_bytes());
            capture_fatal(|| {
                app.query(RequestQuery {
                    data: key.into(),
                    path: QUERY_REQUEST_PATH.to_owned(),
                    ..RequestQuery::default()
                })
            })
        };
        assert_eq!(
            failure.stage(),
            if check_path {
                FatalAbciStage::CheckTx
            } else {
                FatalAbciStage::Query
            }
        );
    }
    Ok(())
}

#[test]
fn installed_verifier_must_match_the_durable_consensus_profile() -> Result<()> {
    let directory = TempDir::new().map_err(|_| AbciAdapterError::InvalidRequest("tempdir"))?;
    let path = directory.path().join("profile-mismatch.sqlite3");
    let limits = thunderbolt_protocol::v2::ProtocolLimitsV2::default();
    let expected = ConsensusProfileV2::from_verifier(&chain_id(), limits, &AcceptAll)?;
    let application = LedgerApplication::open(
        path,
        chain_id(),
        ApplicationOptions {
            protocol_limits: limits,
            consensus_profile_digest: Some(*expected.as_bytes()),
            ..ApplicationOptions::default()
        },
    )?;
    assert!(matches!(
        ThunderboltLedgerAbci::new(application, RejectPoison, PanicFatal),
        Err(AbciAdapterError::InvalidRequest(_))
    ));
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
    let failure = capture_fatal(|| app.finalize_block(finalize_request(vec![invalid], 1, 1_000)));
    assert_eq!(failure.stage(), FatalAbciStage::FinalizeBlock);
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
        data: proof_key.clone().into(),
        path: QUERY_PROOF_PATH.to_owned(),
        prove: false,
        ..RequestQuery::default()
    });
    assert_eq!(proof.code, OK_CODE);
    assert!(proof.proof_ops.is_none());
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&proof.value)?["execution_only"],
        true
    );
    let confused = app.query(RequestQuery {
        data: proof_key.into(),
        path: QUERY_PROOF_PATH.to_owned(),
        prove: true,
        ..RequestQuery::default()
    });
    assert_ne!(confused.code, OK_CODE);
    assert!(confused.proof_ops.is_none());
    Ok(())
}

#[test]
fn channel_query_never_pairs_a_new_object_with_an_old_head() -> Result<()> {
    let directory = TempDir::new().map_err(|_| AbciAdapterError::InvalidRequest("tempdir"))?;
    let app = adapter(&directory)?;
    let proposal = signed_open(33, 33);
    let context = ChannelContextIdV2::from_bytes(proposal.body().channel().context_id().expect("context"))?;
    let query = RequestQuery {
        data: context.as_bytes().to_vec().into(),
        path: QUERY_CHANNEL_PATH.to_owned(),
        ..RequestQuery::default()
    };
    let _ = app.try_finalize_block(finalize_request(vec![transaction(&proposal)], 1, 1_000))?;
    let committer = app.clone();
    let handle = thread::spawn(move || committer.try_commit());
    for _ in 0..128 {
        match app.try_query(query.clone()) {
            Ok(response) => {
                let value: serde_json::Value = serde_json::from_slice(&response.value)?;
                assert_eq!(value["committed_application_height"], 1);
            }
            Err(AbciAdapterError::NotFound("channel")) => {}
            Err(error) => return Err(error),
        }
    }
    let _ = handle
        .join()
        .map_err(|_| AbciAdapterError::InvalidRequest("commit thread panicked"))??;
    Ok(())
}

#[test]
fn bounded_json_writer_stops_before_exceeding_its_limit() {
    let mut writer = BoundedJsonWriter::new(8);
    assert!(serde_json::to_writer(&mut writer, &vec![0_u8; 64]).is_err());
    assert!(writer.exceeded);
    assert!(writer.bytes.len() <= 8);
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
        response_verify_vote_extension::VerifyStatus::Accept as i32
    );
    assert_eq!(
        app.verify_vote_extension(RequestVerifyVoteExtension {
            vote_extension: Bytes::from_static(b"unsupported"),
            ..RequestVerifyVoteExtension::default()
        })
        .status,
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
    let failure =
        capture_fatal(|| app.finalize_block(finalize_request(vec![Bytes::new(); MAX_BLOCK_ENTRIES + 1], 1, 1_000)));
    assert_eq!(failure.stage(), FatalAbciStage::FinalizeBlock);
    Ok(())
}

#[test]
fn exact_maximum_event_fits_the_abci_transaction_boundary() -> Result<()> {
    let mut event = open_event();
    let baseline = event
        .canonical_bytes()
        .map_err(thunderbolt_ledger_app::ApplicationError::from)?
        .len();
    let ChannelEventV2::Open(open) = &mut event else {
        return Err(AbciAdapterError::InvalidRequest("test event is not Open"));
    };
    let proof_len = open
        .open_proof
        .as_bytes()
        .len()
        .checked_add(EVENT_BYTES_MAX - baseline)
        .ok_or(AbciAdapterError::InvalidRequest("test event capacity overflows"))?;
    open.open_proof = ArtifactV2::new(vec![0x5a; proof_len])
        .map_err(|_| AbciAdapterError::InvalidRequest("test proof exceeds artifact bound"))?;
    let event_bytes = event
        .canonical_bytes()
        .map_err(thunderbolt_ledger_app::ApplicationError::from)?;
    assert_eq!(event_bytes.len(), EVENT_BYTES_MAX);

    let keypair = keypair(91);
    let (public, _) = keypair.x_only_public_key();
    let body = ProposalBodyV2::new(
        chain_id(),
        binding(91),
        0,
        EntryHashV2::zero(),
        ClientRequestNonceV2::from_bytes([0x91; 64])?,
        ActorKeyAlgorithmV2::Bip340V1,
        ActorPublicKeyV2::from_bytes(public.serialize())?,
        ActorRoleV2::Holder,
        event.kind(),
        CanonicalEventV2::from_bytes(event_bytes)?,
    )?;
    let signature = Secp256k1::signing_only().sign_schnorr_no_aux_rand(body.proposal_digest()?.as_bytes(), &keypair);
    let proposal = SignedProposalV2::new(body, ActorSignatureV2::from_bytes(signature.to_byte_array())?)?;
    let transaction = transaction(&proposal);
    assert!(transaction.len() <= MAX_TRANSACTION_BYTES);

    let directory = TempDir::new().map_err(|_| AbciAdapterError::InvalidRequest("tempdir"))?;
    let app = adapter(&directory)?;
    assert_eq!(
        app.check_tx(RequestCheckTx {
            tx: transaction,
            r#type: 0,
        })
        .code,
        OK_CODE
    );
    Ok(())
}

#[test]
fn exact_execution_range_and_first_location_queries_are_bounded_and_correlated() -> Result<()> {
    let directory = TempDir::new().map_err(|_| AbciAdapterError::InvalidRequest("tempdir"))?;
    let app = adapter(&directory)?;
    let proposal = signed_open(92, 92);
    let body = proposal.body().clone();
    let first = app.finalize_block(finalize_request(vec![transaction(&proposal)], 1, 10_000));
    let first_hash = AppHashV2::from_bytes(first.app_hash.as_ref())?;
    let _ = app.commit();
    let second = app.finalize_block(finalize_request(Vec::new(), 2, 10_001));
    let second_hash = AppHashV2::from_bytes(second.app_hash.as_ref())?;
    let _ = app.commit();
    let third = app.finalize_block(finalize_request(vec![transaction(&proposal)], 3, 10_002));
    let third_hash = AppHashV2::from_bytes(third.app_hash.as_ref())?;
    let _ = app.commit();

    let range_request = ExecutionRangeRequestV2::new(
        ExecutionRangeCursorV2::new(chain_id(), 1, AppHashV2::zero())
            .map_err(|_| AbciAdapterError::InvalidRequest("range cursor"))?,
        3,
        MAX_EXECUTION_RANGE_ENCODED_BYTES,
    )
    .map_err(|_| AbciAdapterError::InvalidRequest("range request"))?;
    let mut range_key = Vec::with_capacity(46);
    range_key.extend_from_slice(&1_u64.to_be_bytes());
    range_key.extend_from_slice(AppHashV2::zero().as_bytes());
    range_key.extend_from_slice(&3_u16.to_be_bytes());
    range_key.extend_from_slice(&MAX_EXECUTION_RANGE_ENCODED_BYTES.to_be_bytes());
    let range = app.query(RequestQuery {
        data: range_key.clone().into(),
        path: QUERY_EXECUTION_RANGE_PATH.to_owned(),
        height: 3,
        ..RequestQuery::default()
    });
    assert_eq!(range.code, OK_CODE);
    assert_eq!(range.height, 3);
    assert!(range.proof_ops.is_none());
    let decoded = RpcResponseV2::from_canonical_bytes_for(&range.value, &RpcRequestV2::ExecutionRange(range_request))
        .map_err(|_| AbciAdapterError::InvalidRequest("range response"))?;
    let RpcResponseV2::ExecutionRange(range) = decoded.response() else {
        return Err(AbciAdapterError::InvalidRequest("range response method"));
    };
    assert_eq!(
        range
            .blocks()
            .iter()
            .map(thunderbolt_ledger::ExecutedBlockV2::height)
            .collect::<Vec<_>>(),
        vec![1, 2, 3]
    );
    assert!(range.blocks()[1].entries().is_empty());
    assert_eq!(range.next_cursor().next_height(), 4);
    assert_eq!(range.next_cursor().expected_previous_app_hash(), &third_hash);

    assert_ne!(
        app.query(RequestQuery {
            data: range_key.clone().into(),
            path: QUERY_EXECUTION_RANGE_PATH.to_owned(),
            height: 2,
            ..RequestQuery::default()
        })
        .code,
        OK_CODE
    );
    assert_ne!(
        app.query(RequestQuery {
            data: range_key.clone().into(),
            path: QUERY_EXECUTION_RANGE_PATH.to_owned(),
            height: 3,
            prove: true,
        })
        .code,
        OK_CODE
    );
    range_key[40..42].copy_from_slice(&0_u16.to_be_bytes());
    assert_ne!(
        app.query(RequestQuery {
            data: range_key.into(),
            path: QUERY_EXECUTION_RANGE_PATH.to_owned(),
            height: 3,
            ..RequestQuery::default()
        })
        .code,
        OK_CODE
    );

    let channel = ChannelContextIdV2::from_bytes(
        body.channel()
            .context_id()
            .map_err(|_| AbciAdapterError::InvalidRequest("channel context"))?,
    )?;
    let entry_hash = body.entry_hash()?;
    let location_request =
        EntryLocationRequestV2::new(chain_id(), channel.clone(), entry_hash.clone(), 2, second_hash.clone())
            .map_err(|_| AbciAdapterError::InvalidRequest("location request"))?;
    let mut location_key = Vec::with_capacity(104);
    location_key.extend_from_slice(channel.as_bytes());
    location_key.extend_from_slice(entry_hash.as_bytes());
    location_key.extend_from_slice(&2_u64.to_be_bytes());
    location_key.extend_from_slice(second_hash.as_bytes());
    let location = app.query(RequestQuery {
        data: location_key.clone().into(),
        path: QUERY_ENTRY_LOCATION_PATH.to_owned(),
        height: 2,
        ..RequestQuery::default()
    });
    assert_eq!(location.code, OK_CODE);
    let decoded =
        RpcResponseV2::from_canonical_bytes_for(&location.value, &RpcRequestV2::EntryLocation(location_request))
            .map_err(|_| AbciAdapterError::InvalidRequest("location response"))?;
    let RpcResponseV2::EntryLocation(location) = decoded.response() else {
        return Err(AbciAdapterError::InvalidRequest("location response method"));
    };
    assert_eq!(
        location
            .location()
            .ok_or(AbciAdapterError::NotFound("location"))?
            .height(),
        1
    );

    location_key[72..104].copy_from_slice(first_hash.as_bytes());
    assert_ne!(
        app.query(RequestQuery {
            data: location_key.clone().into(),
            path: QUERY_ENTRY_LOCATION_PATH.to_owned(),
            height: 2,
            ..RequestQuery::default()
        })
        .code,
        OK_CODE
    );
    assert_ne!(
        app.query(RequestQuery {
            data: location_key.into(),
            path: QUERY_ENTRY_LOCATION_PATH.to_owned(),
            height: 2,
            prove: true,
        })
        .code,
        OK_CODE
    );
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
