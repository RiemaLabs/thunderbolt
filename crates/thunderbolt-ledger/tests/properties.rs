mod common;

use proptest::prelude::*;
use serde_json::Value;
use thunderbolt_ledger::{ActorRoleV2, AppHashV2, FinalizedBlockV2, LedgerChainIdV2, PendingBlockV2, SignedProposalV2};

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
    fn signed_proposal_and_finalized_block_serde_round_trip(
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
        let finalized = pending.finalize()?;
        let encoded = serde_json::to_vec(&finalized).expect("finalized block JSON");
        let decoded: FinalizedBlockV2 = serde_json::from_slice(&encoded).expect("validated block decode");
        prop_assert_eq!(decoded, finalized);
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
        let forward = forward.finalize()?;

        let mut reverse = PendingBlockV2::new(chain_id, 1, block_time_ms, AppHashV2::zero())?;
        for proposal in proposals.iter().rev() {
            reverse.push(proposal.clone())?;
        }
        let reverse = reverse.finalize()?;

        prop_assert_ne!(forward.entry_merkle_root(), reverse.entry_merkle_root());
        prop_assert_ne!(forward.app_hash(), reverse.app_hash());
    }
}

fn mutate_first_hex_nibble(value: &mut Value) {
    let encoded = value.as_str().expect("hex string");
    let replacement = if encoded.starts_with('0') { '1' } else { '0' };
    let mut mutated = encoded.to_owned();
    mutated.replace_range(..1, &replacement.to_string());
    *value = Value::String(mutated);
}
