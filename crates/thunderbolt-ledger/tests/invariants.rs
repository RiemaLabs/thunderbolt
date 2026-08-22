mod common;

use serde_json::Value;
use thunderbolt_ledger::{
    compute_app_hash_v2, entry_merkle_root_v2, ActorKeyAlgorithmV2, ActorRoleV2, AppHashV2, CanonicalEventV2,
    ClientRequestNonceV2, EntryHashV2, EntryMerkleRootV2, EventKindV2, ExecutedBlockCommitmentV2, ExecutedBlockV2,
    LedgerChainIdV2, LedgerContractError, PendingBlockV2, ProposalBodyV2, EVENT_BYTES_MAX, LEDGER_CHAIN_ID_MAX,
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
    let first_block = first_block.execute().expect("first executed block");
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

    let first = first.execute().expect("empty first block");
    let second = PendingBlockV2::new(chain_id, 2, 100, first.app_hash().clone()).expect("second block");
    second
        .validate_previous_block_time(Some(100))
        .expect("same truncated millisecond is monotonic");
    assert!(second.validate_previous_block_time(Some(101)).is_err());
    assert!(second.validate_previous_block_time(None).is_err());
}

#[test]
fn successor_validation_binds_chain_height_app_hash_and_time() {
    let chain_id = LedgerChainIdV2::new("tb-successor").expect("chain id");
    let previous = PendingBlockV2::new(chain_id.clone(), 1, 100, AppHashV2::zero())
        .expect("first pending block")
        .execute()
        .expect("first execution");

    let correct =
        PendingBlockV2::new(chain_id.clone(), 2, 100, previous.app_hash().clone()).expect("correct successor");
    correct
        .validate_successor(&previous)
        .expect("exact successor continuity");
    let correct = correct.execute().expect("second execution");
    correct
        .validate_successor(&previous)
        .expect("executed successor continuity");

    let wrong_chain = PendingBlockV2::new(
        LedgerChainIdV2::new("tb-other").expect("other chain"),
        2,
        100,
        previous.app_hash().clone(),
    )
    .expect("shape-valid other chain");
    assert!(wrong_chain.validate_successor(&previous).is_err());

    let wrong_height =
        PendingBlockV2::new(chain_id.clone(), 3, 100, previous.app_hash().clone()).expect("shape-valid height gap");
    assert!(wrong_height.validate_successor(&previous).is_err());

    let wrong_hash = PendingBlockV2::new(
        chain_id.clone(),
        2,
        100,
        AppHashV2::from_bytes([0x99; 32]).expect("nonzero app hash"),
    )
    .expect("shape-valid wrong hash");
    assert!(wrong_hash.validate_successor(&previous).is_err());

    let backwards_time =
        PendingBlockV2::new(chain_id, 2, 99, previous.app_hash().clone()).expect("shape-valid backwards time");
    assert!(backwards_time.validate_successor(&previous).is_err());
}

#[test]
fn executed_block_serde_recomputes_metadata_root_time_and_app_hash() {
    let proposal = signed_open("tb-serde", [1; 32], 0, 1, 1, ActorRoleV2::Holder, vec![1; 16], vec![1]);
    let mut block = PendingBlockV2::new(
        LedgerChainIdV2::new("tb-serde").expect("chain id"),
        1,
        123,
        AppHashV2::zero(),
    )
    .expect("block");
    block.push(proposal).expect("proposal");
    let block = block.execute().expect("executed block");

    let mut value = serde_json::to_value(&block).expect("block value");
    value["block_time_ms"] = Value::from(124);
    assert!(serde_json::from_value::<ExecutedBlockV2>(value).is_err());

    let mut value = serde_json::to_value(&block).expect("block value");
    value["entry_merkle_root"] = Value::String("00".repeat(32));
    assert!(serde_json::from_value::<ExecutedBlockV2>(value).is_err());

    let mut value = serde_json::to_value(&block).expect("block value");
    value
        .as_object_mut()
        .expect("block object")
        .insert("unknown".to_owned(), Value::Bool(true));
    assert!(serde_json::from_value::<ExecutedBlockV2>(value).is_err());
}

#[test]
fn compact_commitment_verifies_exact_metadata_and_entry_without_full_block() {
    let first = signed_open(
        "tb-commitment",
        [1; 32],
        0,
        1,
        1,
        ActorRoleV2::Holder,
        vec![1; 16],
        vec![1],
    );
    let second = signed_open(
        "tb-commitment",
        [2; 32],
        1,
        1,
        2,
        ActorRoleV2::Recipient,
        vec![2; 16],
        vec![2],
    );
    let mut pending = PendingBlockV2::new(
        LedgerChainIdV2::new("tb-commitment").expect("chain"),
        1,
        123,
        AppHashV2::zero(),
    )
    .expect("pending block");
    pending.push(first).expect("first");
    pending.push(second).expect("second");
    let block = pending.execute().expect("executed block");
    let commitment = block.commitment().expect("compact commitment");
    assert_eq!(commitment.ledger_chain_id(), block.ledger_chain_id());
    assert_eq!(commitment.height(), block.height());
    assert_eq!(commitment.block_time_ms(), block.block_time_ms());
    assert_eq!(commitment.previous_app_hash(), block.previous_app_hash());
    assert_eq!(commitment.entry_count(), 2);
    assert_eq!(commitment.entry_merkle_root(), block.entry_merkle_root());
    assert_eq!(commitment.app_hash(), block.app_hash());

    let encoded = serde_json::to_vec(&commitment).expect("commitment JSON");
    let decoded: ExecutedBlockCommitmentV2 = serde_json::from_slice(&encoded).expect("commitment decode");
    assert_eq!(decoded, commitment);
    let proof = block.entry_proof(0).expect("entry proof");
    proof
        .verify_against_commitment(block.entries()[0].metadata(), &commitment)
        .expect("metadata inclusion");
    proof
        .verify_entry_against_commitment(&block.entries()[0], &commitment)
        .expect("entry inclusion");
    assert!(proof
        .verify_entry_against_commitment(&block.entries()[1], &commitment)
        .is_err());
    assert!(commitment
        .validate_chain_id(&LedgerChainIdV2::new("tb-other").expect("other chain"))
        .is_err());
}

#[test]
fn commitment_and_proof_reject_wrong_count_root_app_chain_time_and_index() {
    let proposal = signed_open("tb-scope", [7; 32], 0, 1, 7, ActorRoleV2::Holder, vec![7; 16], vec![7]);
    let mut pending = PendingBlockV2::new(
        LedgerChainIdV2::new("tb-scope").expect("chain"),
        1,
        777,
        AppHashV2::zero(),
    )
    .expect("pending");
    pending.push(proposal).expect("proposal");
    let block = pending.execute().expect("block");
    let commitment = block.commitment().expect("commitment");
    let proof = block.entry_proof(0).expect("proof");
    let metadata = block.entries()[0].metadata();

    let wrong_scope_block = PendingBlockV2::new(commitment.ledger_chain_id().clone(), 1, 778, AppHashV2::zero())
        .expect("wrong-scope pending block")
        .execute()
        .expect("wrong-scope block");
    assert!(matches!(
        proof.verify(metadata, &wrong_scope_block),
        Err(LedgerContractError::InvalidMerkleProof {
            reason: "proof scope does not match executed block"
        })
    ));

    let other_proposal = signed_open(
        "tb-scope",
        [8; 32],
        1,
        1,
        8,
        ActorRoleV2::Recipient,
        vec![8; 16],
        vec![8],
    );
    let mut wrong_root_pending = PendingBlockV2::new(
        commitment.ledger_chain_id().clone(),
        commitment.height(),
        commitment.block_time_ms(),
        commitment.previous_app_hash().clone(),
    )
    .expect("wrong-root pending block");
    wrong_root_pending.push(other_proposal).expect("other proposal");
    let wrong_root_block = wrong_root_pending.execute().expect("wrong-root block");
    assert!(matches!(
        proof.verify(metadata, &wrong_root_block),
        Err(LedgerContractError::InvalidMerkleProof {
            reason: "inclusion path does not reconstruct the executed block Merkle root"
        })
    ));

    let wrong_count = commitment_with(
        commitment.ledger_chain_id().clone(),
        commitment.height(),
        commitment.block_time_ms(),
        commitment.previous_app_hash().clone(),
        2,
        commitment.entry_merkle_root().clone(),
    );
    assert!(proof.verify_against_commitment(metadata, &wrong_count).is_err());

    let wrong_root_value = EntryMerkleRootV2::from_bytes([0x99; 32]).expect("root");
    let wrong_root = commitment_with(
        commitment.ledger_chain_id().clone(),
        commitment.height(),
        commitment.block_time_ms(),
        commitment.previous_app_hash().clone(),
        commitment.entry_count(),
        wrong_root_value,
    );
    assert!(proof.verify_against_commitment(metadata, &wrong_root).is_err());

    let other_chain = LedgerChainIdV2::new("tb-other").expect("other chain");
    let wrong_chain = commitment_with(
        other_chain,
        commitment.height(),
        commitment.block_time_ms(),
        commitment.previous_app_hash().clone(),
        commitment.entry_count(),
        commitment.entry_merkle_root().clone(),
    );
    assert!(proof.verify_against_commitment(metadata, &wrong_chain).is_err());

    let wrong_height = commitment_with(
        commitment.ledger_chain_id().clone(),
        2,
        commitment.block_time_ms(),
        AppHashV2::from_bytes([0x11; 32]).expect("prior app hash"),
        commitment.entry_count(),
        commitment.entry_merkle_root().clone(),
    );
    assert!(proof.verify_against_commitment(metadata, &wrong_height).is_err());

    let wrong_time = commitment_with(
        commitment.ledger_chain_id().clone(),
        commitment.height(),
        commitment.block_time_ms() + 1,
        commitment.previous_app_hash().clone(),
        commitment.entry_count(),
        commitment.entry_merkle_root().clone(),
    );
    assert!(proof.verify_against_commitment(metadata, &wrong_time).is_err());
    let expected_digest = commitment.canonical_digest().expect("commitment digest");
    for changed in [&wrong_count, &wrong_root, &wrong_chain, &wrong_height, &wrong_time] {
        assert_ne!(changed.canonical_digest().expect("changed digest"), expected_digest);
    }

    let mut bad_app = serde_json::to_value(&commitment).expect("commitment value");
    mutate_first_hex_nibble(&mut bad_app["app_hash"]);
    assert!(serde_json::from_value::<ExecutedBlockCommitmentV2>(bad_app).is_err());

    let mut bad_index = serde_json::to_value(&proof).expect("proof value");
    bad_index["leaf_index"] = Value::from(1);
    assert!(serde_json::from_value::<thunderbolt_ledger::EntryMerkleProofV2>(bad_index).is_err());
}

fn mutate_first_hex_nibble(value: &mut Value) {
    let encoded = value.as_str().expect("hex string");
    let replacement = if encoded.starts_with('0') { '1' } else { '0' };
    let mut mutated = encoded.to_owned();
    mutated.replace_range(..1, &replacement.to_string());
    *value = Value::String(mutated);
}

fn commitment_with(
    chain: LedgerChainIdV2,
    height: u64,
    block_time_ms: u64,
    previous_app_hash: AppHashV2,
    entry_count: u32,
    root: EntryMerkleRootV2,
) -> ExecutedBlockCommitmentV2 {
    let app_hash = compute_app_hash_v2(&chain, &previous_app_hash, height, block_time_ms, entry_count, &root)
        .expect("self-consistent app hash");
    ExecutedBlockCommitmentV2::new(
        chain,
        height,
        block_time_ms,
        previous_app_hash,
        entry_count,
        root,
        app_hash,
    )
    .expect("self-consistent commitment")
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
    .execute()
    .expect("empty executed block");
    assert!(block.entries().is_empty());
    assert_eq!(block.entry_merkle_root(), &empty_root);
    assert!(!block.app_hash().is_zero());
    let commitment = block.commitment().expect("empty commitment");
    assert_eq!(commitment.entry_count(), 0);
    assert_eq!(commitment.entry_merkle_root(), &empty_root);
    let wrong_root = EntryMerkleRootV2::from_bytes([0x44; 32]).expect("wrong empty root");
    let wrong_app = compute_app_hash_v2(
        commitment.ledger_chain_id(),
        commitment.previous_app_hash(),
        commitment.height(),
        commitment.block_time_ms(),
        0,
        &wrong_root,
    )
    .expect("shape-valid wrong empty app hash");
    assert!(ExecutedBlockCommitmentV2::new(
        commitment.ledger_chain_id().clone(),
        commitment.height(),
        commitment.block_time_ms(),
        commitment.previous_app_hash().clone(),
        0,
        wrong_root,
        wrong_app,
    )
    .is_err());
}
