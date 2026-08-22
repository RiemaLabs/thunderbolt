use bitcoin::Network;
use secp256k1::{Keypair, Secp256k1, SecretKey};
use thunderbolt_ledger::{
    ActorKeyAlgorithmV2, ActorPublicKeyV2, ActorRoleV2, ActorSignatureV2, CanonicalEventV2, ClientRequestNonceV2,
    EntryHashV2, EventKindV2, LedgerChainIdV2, ProposalBodyV2, SignedProposalV2,
};
use thunderbolt_wire::{
    AnchorParameterSuiteIdV2, BitcoinGenesisHashV2, ChannelBindingV2, CommitteeDescriptorDigestV2, FundingOutpointV2,
    ProtocolSuiteIdV2,
};

pub fn nonzero(mut bytes: [u8; 32]) -> [u8; 32] {
    bytes[0] |= 1;
    bytes
}

pub fn actor_keypair(secret_index: u64) -> Keypair {
    let mut bytes = [0_u8; 32];
    bytes[24..].copy_from_slice(&secret_index.max(1).to_be_bytes());
    let secret = SecretKey::from_byte_array(bytes).expect("bounded nonzero test secret");
    Keypair::from_secret_key(&Secp256k1::signing_only(), &secret)
}

pub fn actor_public_key(keypair: &Keypair) -> ActorPublicKeyV2 {
    let (public_key, _) = keypair.x_only_public_key();
    ActorPublicKeyV2::from_bytes(public_key.serialize()).expect("test actor public key")
}

pub fn channel(txid: [u8; 32], vout: u32, epoch: u64) -> ChannelBindingV2 {
    ChannelBindingV2::new(
        ProtocolSuiteIdV2::from_bytes([0x11; 32]).expect("protocol suite"),
        Network::Regtest,
        BitcoinGenesisHashV2::for_network(Network::Regtest).expect("regtest genesis"),
        b"test-deployment",
        FundingOutpointV2::new(nonzero(txid), vout).expect("funding outpoint"),
        epoch.max(1),
        CommitteeDescriptorDigestV2::from_bytes([0x22; 32]).expect("committee descriptor"),
        AnchorParameterSuiteIdV2::from_bytes([0x33; 32]).expect("anchor suite"),
    )
    .expect("stable channel binding")
}

#[allow(clippy::too_many_arguments)]
pub fn signed_open(
    chain_id: &str,
    txid: [u8; 32],
    vout: u32,
    epoch: u64,
    secret_index: u64,
    role: ActorRoleV2,
    nonce: Vec<u8>,
    event: Vec<u8>,
) -> SignedProposalV2 {
    let keypair = actor_keypair(secret_index);
    let body = ProposalBodyV2::new(
        LedgerChainIdV2::new(chain_id).expect("test chain id"),
        channel(txid, vout, epoch),
        0,
        EntryHashV2::zero(),
        ClientRequestNonceV2::from_bytes(nonce).expect("test request nonce"),
        ActorKeyAlgorithmV2::Bip340V1,
        actor_public_key(&keypair),
        role,
        EventKindV2::Open,
        CanonicalEventV2::from_bytes(event).expect("test event"),
    )
    .expect("test proposal body");
    sign(body, &keypair)
}

pub fn sign(body: ProposalBodyV2, keypair: &Keypair) -> SignedProposalV2 {
    let digest = body.proposal_digest().expect("test proposal digest");
    let signature = Secp256k1::signing_only().sign_schnorr_no_aux_rand(digest.as_bytes(), keypair);
    SignedProposalV2::new(
        body,
        ActorSignatureV2::from_bytes(signature.to_byte_array()).expect("test actor signature"),
    )
    .expect("valid signed test proposal")
}
