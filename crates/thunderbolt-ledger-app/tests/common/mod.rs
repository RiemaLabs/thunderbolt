#![allow(dead_code, clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use bitcoin::Network;
use secp256k1::{Keypair, Secp256k1, SecretKey};
use thunderbolt_ledger::{
    ActorKeyAlgorithmV2, ActorPublicKeyV2, ActorRoleV2, ActorSignatureV2, AppHashV2, CanonicalEventV2,
    ClientRequestNonceV2, EntryHashV2, LedgerChainIdV2, ProposalBodyV2, SignedProposalV2,
};
use thunderbolt_protocol::v2::{
    ArtifactV2, ChannelEventV2, ChannelSnapshotV2, FinalizeEventV2, InvoiceEventV2, OpenEventV2, TransferEventV2,
};
use thunderbolt_wire::{
    AnchorParameterSuiteIdV2, BitcoinGenesisHashV2, ChannelBindingV2, CommitteeDescriptorDigestV2, FundingOutpointV2,
    HexBytes, ProtocolSuiteIdV2,
};

pub const TEST_CHAIN_ID: &str = "thunderbolt-app-regtest-1";

pub fn chain_id() -> LedgerChainIdV2 {
    LedgerChainIdV2::new(TEST_CHAIN_ID).expect("test chain id")
}

pub fn artifact(byte: u8) -> ArtifactV2 {
    ArtifactV2::new([byte]).expect("bounded public artifact")
}

pub fn invoice_id(index: u32) -> thunderbolt_protocol::v2::InvoiceIdV2 {
    HexBytes::from_bytes("test invoice id", index.to_be_bytes()).expect("bounded invoice id")
}

pub fn binding(channel_byte: u8) -> ChannelBindingV2 {
    let mut txid = [channel_byte; 32];
    txid[0] |= 1;
    ChannelBindingV2::new(
        ProtocolSuiteIdV2::from_bytes([0x11; 32]).expect("protocol suite"),
        Network::Regtest,
        BitcoinGenesisHashV2::for_network(Network::Regtest).expect("regtest genesis"),
        b"ledger-app-tests",
        FundingOutpointV2::new(txid, u32::from(channel_byte)).expect("funding outpoint"),
        1,
        CommitteeDescriptorDigestV2::from_bytes([0x22; 32]).expect("committee descriptor"),
        AnchorParameterSuiteIdV2::from_bytes([0x33; 32]).expect("anchor suite"),
    )
    .expect("stable channel binding")
}

pub fn keypair(index: u64) -> Keypair {
    let mut secret = [0_u8; 32];
    secret[24..].copy_from_slice(&index.max(1).to_be_bytes());
    let secret = SecretKey::from_byte_array(secret).expect("bounded test secret");
    Keypair::from_secret_key(&Secp256k1::signing_only(), &secret)
}

fn actor_public_key(keypair: &Keypair) -> ActorPublicKeyV2 {
    let (public, _) = keypair.x_only_public_key();
    ActorPublicKeyV2::from_bytes(public.serialize()).expect("actor public key")
}

pub fn proposal(
    binding: ChannelBindingV2,
    event: &ChannelEventV2,
    sequence: u64,
    previous: EntryHashV2,
    actor_index: u64,
    role: ActorRoleV2,
    nonce: [u8; 16],
) -> SignedProposalV2 {
    let keypair = keypair(actor_index);
    let body = ProposalBodyV2::new(
        chain_id(),
        binding,
        sequence,
        previous,
        ClientRequestNonceV2::from_bytes(nonce).expect("request nonce"),
        ActorKeyAlgorithmV2::Bip340V1,
        actor_public_key(&keypair),
        role,
        event.kind(),
        CanonicalEventV2::from_bytes(event.canonical_bytes().expect("canonical event")).expect("bounded event"),
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

pub fn open_event() -> ChannelEventV2 {
    ChannelEventV2::Open(OpenEventV2 {
        committee_member_count: 3,
        committee_threshold: 2,
        capacity_sat: 1_000_000,
        lock_key: artifact(1),
        initial_holder_anchor: artifact(2),
        initial_holder_ciphertext: artifact(3),
        open_proof: artifact(4),
    })
}

pub fn invoice_event(index: u32, holder_step: u64, expires_at_ms: u64) -> ChannelEventV2 {
    ChannelEventV2::Invoice(InvoiceEventV2 {
        invoice_id: invoice_id(index),
        holder_step,
        recipient_encryption_key: artifact(5),
        public_delta: artifact(6),
        recipient_ciphertext: artifact(7),
        committee_package: artifact(8),
        invoice_proof: artifact(9),
        expires_at_ms,
    })
}

pub fn transfer_event(snapshot: &ChannelSnapshotV2, index: u32) -> ChannelEventV2 {
    let invoice = snapshot
        .pending_invoices
        .get(&invoice_id(index))
        .expect("pending invoice");
    ChannelEventV2::Transfer(TransferEventV2 {
        invoice_id: invoice_id(index),
        invoice_entry_hash: invoice.committed_entry_hash.clone(),
        next_holder_anchor: artifact(10),
        next_holder_ciphertext: artifact(11),
        transfer_proof: artifact(12),
    })
}

#[allow(dead_code)]
pub fn finalize_event(byte: u8) -> ChannelEventV2 {
    ChannelEventV2::Finalize(FinalizeEventV2 {
        closing_txid: [byte; 32],
        closing_transaction: artifact(15),
        ownership_proof: artifact(13),
        committee_attestation: artifact(14),
    })
}

pub fn zero_app_hash() -> AppHashV2 {
    AppHashV2::zero()
}
