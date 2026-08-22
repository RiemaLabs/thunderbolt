mod common;

use serde_json::Value;
use thunderbolt_ledger::{
    entry_merkle_root_v2, ActorKeyAlgorithmV2, ActorRoleV2, AppHashV2, CanonicalEventV2, ClientRequestNonceV2,
    EntryHashV2, EventKindV2, FinalizedBlockV2, LedgerChainIdV2, PendingBlockV2, ProposalBodyV2, EVENT_BYTES_MAX,
    LEDGER_CHAIN_ID_MAX,
};

use common::{actor_keypair, actor_public_key, channel, sign, signed_open};

#[test]
fn chain_ids_are_bounded_canonical_and_cluster_specific() {
    assert!(LedgerChainIdV2::new("thunderbolt-regtest-1").is_ok());
    assert!(LedgerChainIdV2::new("a").is_ok());
    assert!(LedgerChainIdV2::new("a".repeat(LEDGER_CHAIN_ID_MAX)).is_ok());
    for invalid in ["", "-chain", "chain-", "chain/id", "chain id", "雷"] {
        assert!(LedgerChainIdV2::new(invalid).is_err(), "accepted {invalid:?}");
    }
    assert!(LedgerChainIdV2::new("a".repeat(LEDGER_CHAIN_ID_MAX + 1)).is_err());

    let first = signed_open("tb-a", [1; 32], 0, 1, 1, ActorRoleV2::Holder, vec![1; 16], vec![1]);
    let second = signed_open("tb-b", [1; 32], 0, 1, 1, ActorRoleV2::Holder, vec![1; 16], vec![1]);
    assert_ne!(first.body().request_id().digest(), second.body().request_id().digest());
    assert_ne!(
        first.body().proposal_digest().expect("first digest"),
        second.body().proposal_digest().expect("second digest")
    );
    assert!(first
        .body()
        .validate_chain_id(&LedgerChainIdV2::new("tb-b").expect("chain id"))
        .is_err());
}

#[test]
fn actor_identity_is_derived_from_the_bip340_key() {
    let first = signed_open(
        "tb-identity",
        [1; 32],
        0,
        1,
        1,
        ActorRoleV2::Holder,
        vec![1; 16],
        vec![1],
    );
    let same_key_other_role = signed_open(
        "tb-identity",
        [2; 32],
        0,
        1,
        1,
        ActorRoleV2::Recipient,
        vec![2; 16],
        vec![2],
    );
    let other_key = signed_open(
        "tb-identity",
        [3; 32],
        0,
        1,
        2,
        ActorRoleV2::Holder,
        vec![3; 16],
        vec![3],
    );

    assert_eq!(
        first.body().participant_id().expect("participant"),
        same_key_other_role.body().participant_id().expect("participant")
    );
    assert_ne!(
        first.body().participant_id().expect("participant"),
        other_key.body().participant_id().expect("participant")
    );
    let view = first.verified_view().expect("verified capability");
    assert_eq!(
        view.participant_id(),
        &first.body().participant_id().expect("participant")
    );
    assert_eq!(view.actor_role(), ActorRoleV2::Holder);
    assert_eq!(view.event().as_bytes(), &[1]);
}

#[test]
fn opening_and_successor_chain_shape_is_fail_closed() {
    let keypair = actor_keypair(7);
    let chain_id = LedgerChainIdV2::new("tb-chain").expect("chain id");
    let binding = channel([9; 32], 2, 3);

    assert!(ProposalBodyV2::new(
        chain_id.clone(),
        binding.clone(),
        0,
        EntryHashV2::from_bytes([1; 32]).expect("hash"),
        ClientRequestNonceV2::from_bytes([1; 16]).expect("nonce"),
        ActorKeyAlgorithmV2::Bip340V1,
        actor_public_key(&keypair),
        ActorRoleV2::Holder,
        EventKindV2::Open,
        CanonicalEventV2::from_bytes([1]).expect("event"),
    )
    .is_err());
    assert!(ProposalBodyV2::new(
        chain_id.clone(),
        binding.clone(),
        1,
        EntryHashV2::zero(),
        ClientRequestNonceV2::from_bytes([1; 16]).expect("nonce"),
        ActorKeyAlgorithmV2::Bip340V1,
        actor_public_key(&keypair),
        ActorRoleV2::Recipient,
        EventKindV2::Invoice,
        CanonicalEventV2::from_bytes([1]).expect("event"),
    )
    .is_err());

    let open = signed_open(
        chain_id.as_str(),
        [9; 32],
        2,
        3,
        7,
        ActorRoleV2::Holder,
        vec![1; 16],
        vec![1],
    );
    let mut first_block = PendingBlockV2::new(chain_id.clone(), 1, 100, AppHashV2::zero()).expect("first block");
    first_block.push(open.clone()).expect("opening proposal");
    let first_block = first_block.finalize().expect("first finalized block");
    let predecessor = first_block.entries()[0].metadata();

    let invoice_body = ProposalBodyV2::new(
        chain_id.clone(),
        binding,
        1,
        open.body().entry_hash().expect("opening entry hash"),
        ClientRequestNonceV2::from_bytes([2; 16]).expect("nonce"),
        ActorKeyAlgorithmV2::Bip340V1,
        actor_public_key(&keypair),
        ActorRoleV2::Recipient,
        EventKindV2::Invoice,
        CanonicalEventV2::from_bytes([2]).expect("event"),
    )
    .expect("invoice body");
    invoice_body
        .validate_predecessor(Some(predecessor))
        .expect("valid predecessor");
    let invoice = sign(invoice_body, &keypair);

    let mut second_block = PendingBlockV2::new(chain_id, 2, 100, first_block.app_hash().clone()).expect("second block");
    second_block
        .validate_previous_block_time(Some(first_block.block_time_ms()))
        .expect("non-decreasing consensus time");
    second_block.push(invoice).expect("invoice proposal");
}

#[test]
fn event_and_block_bounds_are_enforced_before_commitment() {
    assert!(CanonicalEventV2::from_bytes(Vec::<u8>::new()).is_err());
    assert!(CanonicalEventV2::from_bytes(vec![0; EVENT_BYTES_MAX]).is_ok());
    assert!(CanonicalEventV2::from_bytes(vec![0; EVENT_BYTES_MAX + 1]).is_err());

    let proposal = signed_open("tb-bounds", [1; 32], 0, 1, 1, ActorRoleV2::Holder, vec![1; 16], vec![1]);
    let mut block = PendingBlockV2::new(
        LedgerChainIdV2::new("tb-bounds").expect("chain id"),
        1,
        1,
        AppHashV2::zero(),
    )
    .expect("block");
    block.push(proposal.clone()).expect("first request");
    assert!(block.push(proposal).is_err());
}

#[test]
fn consensus_time_is_external_positive_and_monotonic() {
    let chain_id = LedgerChainIdV2::new("tb-time").expect("chain id");
    assert!(PendingBlockV2::new(chain_id.clone(), 1, 0, AppHashV2::zero()).is_err());
    let first = PendingBlockV2::new(chain_id.clone(), 1, 100, AppHashV2::zero()).expect("first block");
    first
        .validate_previous_block_time(None)
        .expect("genesis has no prior time");
    assert!(first.validate_previous_block_time(Some(99)).is_err());

    let first = first.finalize().expect("empty first block");
    let second = PendingBlockV2::new(chain_id, 2, 100, first.app_hash().clone()).expect("second block");
    second
        .validate_previous_block_time(Some(100))
        .expect("same truncated millisecond is monotonic");
    assert!(second.validate_previous_block_time(Some(101)).is_err());
    assert!(second.validate_previous_block_time(None).is_err());
}

#[test]
fn finalized_block_serde_recomputes_metadata_root_time_and_app_hash() {
    let proposal = signed_open("tb-serde", [1; 32], 0, 1, 1, ActorRoleV2::Holder, vec![1; 16], vec![1]);
    let mut block = PendingBlockV2::new(
        LedgerChainIdV2::new("tb-serde").expect("chain id"),
        1,
        123,
        AppHashV2::zero(),
    )
    .expect("block");
    block.push(proposal).expect("proposal");
    let block = block.finalize().expect("finalized block");

    let mut value = serde_json::to_value(&block).expect("block value");
    value["block_time_ms"] = Value::from(124);
    assert!(serde_json::from_value::<FinalizedBlockV2>(value).is_err());

    let mut value = serde_json::to_value(&block).expect("block value");
    value["entry_merkle_root"] = Value::String("00".repeat(32));
    assert!(serde_json::from_value::<FinalizedBlockV2>(value).is_err());

    let mut value = serde_json::to_value(&block).expect("block value");
    value
        .as_object_mut()
        .expect("block object")
        .insert("unknown".to_owned(), Value::Bool(true));
    assert!(serde_json::from_value::<FinalizedBlockV2>(value).is_err());
}

#[test]
fn empty_block_has_a_defined_merkle_root_and_application_hash() {
    let empty_root = entry_merkle_root_v2(&[]).expect("empty root");
    let block = PendingBlockV2::new(
        LedgerChainIdV2::new("tb-empty").expect("chain id"),
        1,
        7,
        AppHashV2::zero(),
    )
    .expect("empty pending block")
    .finalize()
    .expect("empty finalized block");
    assert!(block.entries().is_empty());
    assert_eq!(block.entry_merkle_root(), &empty_root);
    assert!(!block.app_hash().is_zero());
}
