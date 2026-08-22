#![allow(dead_code, clippy::expect_used, clippy::unwrap_used)]

use std::collections::BTreeMap;

use bitcoin::Network;
use secp256k1::{Keypair, Secp256k1, SecretKey};
use thunderbolt_floor::{FloorCasRequest, FloorLedgerChainId};
use thunderbolt_keystore::{
    CommitteeDescriptorDigest, DeploymentBinding, DeploymentId as VaultDeploymentId, Network as VaultNetwork, NodeId,
    VaultCheckpoint, VaultIdentity, VaultRevision, VaultRole, VaultStateDigest,
};
use thunderbolt_ledger::{
    ActorKeyAlgorithmV2, ActorPublicKeyV2, ActorRoleV2, ActorSignatureV2, AppHashV2, CanonicalEventV2,
    ClientRequestNonceV2, ExecutedBlockV2, LedgerChainIdV2, PendingBlockV2, ProposalBodyV2, SignedProposalV2,
};
use thunderbolt_protocol::v2::{ChannelPhaseV2, ChannelSnapshotV2, PROTOCOL_VERSION_V2};
use thunderbolt_protocol::Artifact;
use thunderbolt_wire::{
    AnchorParameterSuiteIdV2, BitcoinGenesisHashV2, ChannelBindingV2, CommitteeDescriptorDigestV2, FundingOutpointV2,
    ProtocolSuiteIdV2,
};

pub fn ledger_chain() -> LedgerChainIdV2 {
    LedgerChainIdV2::new("thunderbolt-regtest-v2").expect("chain")
}

pub fn channel_binding(discriminator: u8) -> ChannelBindingV2 {
    let mut txid = [discriminator.max(1); 32];
    txid[31] = discriminator.max(1);
    ChannelBindingV2::new(
        ProtocolSuiteIdV2::from_bytes([0x11; 32]).expect("suite"),
        Network::Regtest,
        BitcoinGenesisHashV2::for_network(Network::Regtest).expect("genesis"),
        b"deployment-regtest-v2",
        FundingOutpointV2::new(txid, u32::from(discriminator)).expect("outpoint"),
        1,
        CommitteeDescriptorDigestV2::from_bytes([0x22; 32]).expect("committee"),
        AnchorParameterSuiteIdV2::from_bytes([0x33; 32]).expect("anchor suite"),
    )
    .expect("binding")
}

pub fn signed_open(discriminator: u8) -> SignedProposalV2 {
    let secp = Secp256k1::new();
    let mut secret_bytes = [0_u8; 32];
    secret_bytes[31] = discriminator.max(1);
    let secret = SecretKey::from_byte_array(secret_bytes).expect("secret");
    let keypair = Keypair::from_secret_key(&secp, &secret);
    let (public_key, _) = keypair.x_only_public_key();
    let mut nonce = [0x44; 16];
    nonce[15] = discriminator;
    let body = ProposalBodyV2::new(
        ledger_chain(),
        channel_binding(discriminator),
        0,
        thunderbolt_ledger::EntryHashV2::zero(),
        ClientRequestNonceV2::from_bytes(nonce).expect("nonce"),
        ActorKeyAlgorithmV2::Bip340V1,
        ActorPublicKeyV2::from_bytes(public_key.serialize()).expect("public key"),
        ActorRoleV2::Holder,
        thunderbolt_ledger::EventKindV2::Open,
        CanonicalEventV2::from_bytes([0x01, discriminator.max(1)]).expect("event"),
    )
    .expect("body");
    let signature = secp.sign_schnorr_no_aux_rand(body.proposal_digest().expect("digest").as_bytes(), &keypair);
    SignedProposalV2::new(
        body,
        ActorSignatureV2::from_bytes(signature.as_ref()).expect("signature"),
    )
    .expect("signed proposal")
}

pub fn executed_block(discriminator: u8) -> ExecutedBlockV2 {
    let mut pending = PendingBlockV2::new(ledger_chain(), 1, 1_700_000_000_000, AppHashV2::zero()).expect("pending");
    pending.push(signed_open(discriminator)).expect("push");
    pending.execute().expect("execute")
}

pub fn snapshot(discriminator: u8) -> ChannelSnapshotV2 {
    let proposal = signed_open(discriminator);
    let participant = proposal.body().participant_id().expect("participant");
    let entry_hash = proposal.body().entry_hash().expect("entry hash");
    let snapshot = ChannelSnapshotV2 {
        protocol_version: PROTOCOL_VERSION_V2,
        ledger_chain_id: ledger_chain(),
        binding: proposal.body().channel().clone(),
        phase: ChannelPhaseV2::Active,
        capacity_sat: 50_000,
        committee_member_count: 3,
        committee_threshold: 2,
        lock_key: Artifact::new([0x51; 33]).expect("lock key"),
        current_holder: participant,
        current_holder_anchor: Artifact::new([0x52; 33]).expect("anchor"),
        current_holder_ciphertext: Artifact::new([0x53; 64]).expect("ciphertext"),
        transfers_completed: 0,
        pending_invoices: BTreeMap::new(),
        last_consumed_invoice_id: None,
        last_sequence: 0,
        head_entry_hash: entry_hash,
        opened_at_ms: 1_700_000_000_000,
        last_block_time_ms: 1_700_000_000_000,
        finalized_at_ms: None,
    };
    snapshot.validate().expect("snapshot");
    snapshot
}

pub fn floor_request(discriminator: u8) -> FloorCasRequest {
    let chain = FloorLedgerChainId::new(b"thunderbolt-floor-regtest-v1".to_vec()).expect("floor chain");
    let deployment_id =
        VaultDeploymentId::derive(VaultNetwork::Regtest, b"deployment-regtest-v2").expect("vault deployment");
    let deployment = DeploymentBinding::new(
        deployment_id,
        1,
        CommitteeDescriptorDigest::new([0x22; 32]).expect("descriptor"),
    )
    .expect("deployment");
    let identity = VaultIdentity::new(
        VaultNetwork::Regtest,
        VaultRole::Holder,
        NodeId::new([discriminator.max(1); 32]),
        deployment,
    );
    let next = VaultCheckpoint::new(VaultRevision::new(0), VaultStateDigest::new([discriminator.max(1); 32]));
    FloorCasRequest::new(&chain, identity, None, next).expect("floor CAS")
}
