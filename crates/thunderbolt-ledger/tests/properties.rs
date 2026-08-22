mod common;

use proptest::prelude::*;
use serde_json::Value;
use thunderbolt_ledger::{
    ActorRoleV2, AppHashV2, EntryMerkleProofV2, ExecutedBlockV2, LedgerChainIdV2, PendingBlockV2, SignedProposalV2,
};

use common::signed_open;

fn role_strategy() -> impl Strategy<Value = ActorRoleV2> {
    prop_oneof![
        Just(ActorRoleV2::Holder),
        Just(ActorRoleV2::Recipient),
        Just(ActorRoleV2::Committee),
        Just(ActorRoleV2::LedgerOperator),
    ]
}

fn signed_proposal_strategy() -> impl Strategy<Value = SignedProposalV2> {
    (
        "[a-z0-9]{1,20}",
        any::<[u8; 32]>(),
        any::<u32>(),
        1_u64..=u64::MAX,
        1_u64..=u64::MAX,
        role_strategy(),
        prop::collection::vec(any::<u8>(), 16..=64),
        prop::collection::vec(any::<u8>(), 1..=1_024),
    )
        .prop_map(|(suffix, txid, vout, epoch, secret, role, mut nonce, event)| {
            nonce[0] |= 1;
            signed_open(&format!("tb-{suffix}"), txid, vout, epoch, secret, role, nonce, event)
        })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(96))]

    #[test]
    fn signed_proposal_and_executed_block_serde_round_trip(
        proposal in signed_proposal_strategy(),
        block_time_ms in 1_u64..=u64::MAX,
    ) {
        let compact = serde_json::to_vec(&proposal).expect("proposal JSON");
        let value: Value = serde_json::from_slice(&compact).expect("proposal value");
        let pretty = serde_json::to_vec_pretty(&value).expect("pretty proposal JSON");
        let decoded: SignedProposalV2 = serde_json::from_slice(&pretty).expect("validated proposal decode");
        prop_assert_eq!(&decoded, &proposal);
        decoded.verify()?;

        let chain_id = proposal.body().ledger_chain_id().clone();
        let mut pending = PendingBlockV2::new(chain_id, 1, block_time_ms, AppHashV2::zero())?;
        pending.push(proposal)?;
        let executed = pending.execute()?;
        let encoded = serde_json::to_vec(&executed).expect("executed block JSON");
        let decoded: ExecutedBlockV2 = serde_json::from_slice(&encoded).expect("validated block decode");
        prop_assert_eq!(decoded, executed);
    }

    #[test]
    fn signed_proposal_rejects_canonical_field_tampering(
        proposal in signed_proposal_strategy(),
        target in 0_u8..5,
    ) {
        let mut value = serde_json::to_value(&proposal).expect("proposal value");
        match target {
            0 => {
                let chain_id = value["body"]["ledger_chain_id"].as_str().expect("chain id");
                value["body"]["ledger_chain_id"] = Value::String(format!("{chain_id}x"));
            }
            1 => mutate_first_hex_nibble(&mut value["body"]["event"]),
            2 => {
                let role = value["body"]["actor_role"].as_str().expect("actor role");
                value["body"]["actor_role"] = Value::String(
                    if role == "holder" { "recipient" } else { "holder" }.to_owned(),
                );
            }
            3 => mutate_first_hex_nibble(&mut value["body"]["request_id"]["digest"]),
            _ => value["body"]["protocol_version"] = Value::from(1),
        }
        let encoded = serde_json::to_vec(&value).expect("tampered proposal JSON");
        prop_assert!(serde_json::from_slice::<SignedProposalV2>(&encoded).is_err());
    }

    #[test]
    fn block_merkle_root_and_app_hash_commit_consensus_order(
        chain_suffix in "[a-z0-9]{1,20}",
        payloads in prop::collection::vec(prop::collection::vec(any::<u8>(), 1..=128), 2..=12),
        block_time_ms in 1_u64..=u64::MAX,
    ) {
        let chain_text = format!("tb-{chain_suffix}");
        let chain_id = LedgerChainIdV2::new(&chain_text)?;
        let mut proposals = Vec::with_capacity(payloads.len());
        for (index, payload) in payloads.into_iter().enumerate() {
            let discriminator = u64::try_from(index).expect("small property-test index") + 1;
            let mut txid = [0_u8; 32];
            txid[24..].copy_from_slice(&discriminator.to_be_bytes());
            let mut nonce = vec![0x44; 16];
            nonce[8..].copy_from_slice(&discriminator.to_be_bytes());
            proposals.push(signed_open(
                &chain_text,
                txid,
                u32::try_from(index).expect("small property-test index"),
                1,
                discriminator,
                ActorRoleV2::Holder,
                nonce,
                payload,
            ));
        }

        let mut forward = PendingBlockV2::new(chain_id.clone(), 1, block_time_ms, AppHashV2::zero())?;
        for proposal in &proposals {
            forward.push(proposal.clone())?;
        }
        let forward = forward.execute()?;

        let mut reverse = PendingBlockV2::new(chain_id, 1, block_time_ms, AppHashV2::zero())?;
        for proposal in proposals.iter().rev() {
            reverse.push(proposal.clone())?;
        }
        let reverse = reverse.execute()?;

        prop_assert_ne!(forward.entry_merkle_root(), reverse.entry_merkle_root());
        prop_assert_ne!(forward.app_hash(), reverse.app_hash());
    }

    #[test]
    fn ordered_merkle_inclusion_proofs_round_trip_and_reject_tampering(
        chain_suffix in "[a-z0-9]{1,20}",
        payloads in prop::collection::vec(prop::collection::vec(any::<u8>(), 1..=128), 2..=12),
        requested_index in any::<usize>(),
        tamper_target in 0_u8..4,
        block_time_ms in 1_u64..=u64::MAX,
    ) {
        let chain_text = format!("tb-{chain_suffix}");
        let chain_id = LedgerChainIdV2::new(&chain_text)?;
        let mut pending = PendingBlockV2::new(chain_id, 1, block_time_ms, AppHashV2::zero())?;
        for (index, payload) in payloads.iter().enumerate() {
            let discriminator = u64::try_from(index).expect("small property-test index") + 1;
            let mut txid = [0_u8; 32];
            txid[24..].copy_from_slice(&discriminator.to_be_bytes());
            let mut nonce = vec![0x77; 16];
            nonce[8..].copy_from_slice(&discriminator.to_be_bytes());
            pending.push(signed_open(
                &chain_text,
                txid,
                u32::try_from(index).expect("small property-test index"),
                1,
                discriminator,
                ActorRoleV2::Holder,
                nonce,
                payload.clone(),
            ))?;
        }
        let executed = pending.execute()?;
        let leaf_index = requested_index % executed.entries().len();
        let metadata = executed.entries()[leaf_index].metadata();
        let proof = executed.entry_proof(leaf_index)?;
        proof.verify(metadata, &executed)?;

        let encoded = serde_json::to_vec(&proof).expect("proof JSON");
        let decoded: EntryMerkleProofV2 = serde_json::from_slice(&encoded).expect("proof decode");
        prop_assert_eq!(&decoded, &proof);
        decoded.verify(metadata, &executed)?;

        let mut value = serde_json::to_value(&proof).expect("proof value");
        match tamper_target {
            0 => mutate_first_hex_nibble(&mut value["siblings"][0]["hash"]),
            1 => {
                let side = value["siblings"][0]["side"].as_str().expect("sibling side");
                value["siblings"][0]["side"] = Value::String(
                    if side == "left" { "right" } else { "left" }.to_owned(),
                );
            }
            2 => {
                let other = (leaf_index + 1) % executed.entries().len();
                value["leaf_index"] = Value::from(u64::try_from(other).expect("small property-test index"));
            }
            _ => value["leaf_count"] = Value::from(1),
        }
        if let Ok(tampered) = serde_json::from_value::<EntryMerkleProofV2>(value) {
            prop_assert!(tampered.verify(metadata, &executed).is_err());
        }

        let other = (leaf_index + 1) % executed.entries().len();
        prop_assert!(proof.verify(executed.entries()[other].metadata(), &executed).is_err());
    }
}

fn mutate_first_hex_nibble(value: &mut Value) {
    let encoded = value.as_str().expect("hex string");
    let replacement = if encoded.starts_with('0') { '1' } else { '0' };
    let mut mutated = encoded.to_owned();
    mutated.replace_range(..1, &replacement.to_string());
    *value = Value::String(mutated);
}
