mod common;

use proptest::prelude::*;
use thunderbolt_ledger::{AppHashV2, ChannelContextIdV2, LedgerChainIdV2, ParticipantIdV2, RequestDigestV2};
use thunderbolt_ledger_rpc::{
    AmbiguityTokenV2, ChannelStatusRequestV2, ChannelStatusResponseV2, FinalityStatusV2, HistoryCursorV2,
    HistoryPageLimitV2, HistoryRequestV2, RequestLifecycleV2, RequestStatusRequestV2, RequestStatusResponseV2,
    RollbackFloorCasResponseV2, RollbackFloorCasStatusV2, RpcRequestV2, RpcResponseV2, SnapshotBytesV2,
};

fn fail(error: impl std::fmt::Display) -> TestCaseError {
    TestCaseError::fail(error.to_string())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(96))]

    #[test]
    fn compact_finality_round_trips_and_app_hash_tamper_fails(
        discriminator in 1_u8..=250,
        profile_byte in 1_u8..=255,
        receipt in prop::collection::vec(any::<u8>(), 1..=512),
        bit in 0_u8..8,
    ) {
        let bundle = common::finalized_bundle(discriminator, profile_byte, receipt);
        let metadata = bundle.entry().metadata();
        let query = RequestStatusRequestV2::new(
            metadata.ledger_chain_id().clone(),
            metadata.channel_context_id().clone(),
            metadata.participant_id().clone(),
            metadata.request_digest().clone(),
        );
        let response = RpcResponseV2::RequestStatus(Box::new(
            RequestStatusResponseV2::new(
                &query,
                RequestLifecycleV2::FinalityReceiptAvailable {
                    bundle: Box::new(bundle),
                },
            ).map_err(fail)?,
        ));
        let encoded = response.to_canonical_bytes().map_err(fail)?;
        let rpc_request = RpcRequestV2::RequestStatus(query);
        let correlated = RpcResponseV2::from_canonical_bytes_for(&encoded, &rpc_request).map_err(fail)?;
        prop_assert_eq!(correlated.response(), &response);

        let mut value: serde_json::Value = serde_json::from_slice(&encoded).map_err(fail)?;
        let app_hash = value["response"]["result"]["lifecycle"]["bundle"]["commitment"]["app_hash"]
            .as_str()
            .ok_or_else(|| TestCaseError::fail("missing compact commitment app hash"))?;
        let mut app_hash = hex::decode(app_hash).map_err(fail)?;
        app_hash[0] ^= 1_u8 << bit;
        value["response"]["result"]["lifecycle"]["bundle"]["commitment"]["app_hash"] =
            serde_json::Value::String(hex::encode(app_hash));
        let tampered = serde_json::to_vec(&value).map_err(fail)?;
        prop_assert!(RpcResponseV2::from_canonical_bytes_for(tampered, &rpc_request).is_err());
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(128))]

    #[test]
    fn complete_request_status_keys_round_trip(
        suffix in "[a-z0-9]{1,20}",
        context in any::<[u8; 32]>(),
        participant in any::<[u8; 32]>(),
        request in any::<[u8; 32]>(),
    ) {
        let query = RpcRequestV2::RequestStatus(RequestStatusRequestV2::new(
            LedgerChainIdV2::new(format!("tb{suffix}")).map_err(fail)?,
            ChannelContextIdV2::from_bytes(context).map_err(fail)?,
            ParticipantIdV2::from_bytes(participant).map_err(fail)?,
            RequestDigestV2::from_bytes(request).map_err(fail)?,
        ));
        let encoded = query.to_canonical_bytes().map_err(fail)?;
        let decoded = RpcRequestV2::from_canonical_bytes(&encoded).map_err(fail)?;
        prop_assert_eq!(&decoded, &query);
        prop_assert_eq!(decoded.to_canonical_bytes().map_err(fail)?, encoded);
    }

    #[test]
    fn canonical_decoder_rejects_equivalent_whitespace(
        suffix in "[a-z0-9]{1,20}",
        context in any::<[u8; 32]>(),
        prefix in any::<bool>(),
    ) {
        let query = RpcRequestV2::ChannelStatus(ChannelStatusRequestV2::new(
            LedgerChainIdV2::new(format!("tb{suffix}")).map_err(fail)?,
            ChannelContextIdV2::from_bytes(context).map_err(fail)?,
        ));
        let canonical = query.to_canonical_bytes().map_err(fail)?;
        let mut changed = Vec::with_capacity(canonical.len() + 1);
        if prefix {
            changed.push(b' ');
            changed.extend_from_slice(&canonical);
        } else {
            changed.extend_from_slice(&canonical);
            changed.push(b'\n');
        }
        prop_assert!(RpcRequestV2::from_canonical_bytes(changed).is_err());
    }

    #[test]
    fn non_genesis_history_cursors_round_trip(
        suffix in "[a-z0-9]{1,20}",
        height in 2_u64..1_000_000,
        index in 0_u32..1024,
        mut previous in any::<[u8; 32]>(),
    ) {
        if previous == [0_u8; 32] {
            previous[0] = 1;
        }
        let cursor = HistoryCursorV2::new(
            LedgerChainIdV2::new(format!("tb{suffix}")).map_err(fail)?,
            height,
            index,
            AppHashV2::from_bytes(previous).map_err(fail)?,
        ).map_err(fail)?;
        let request = RpcRequestV2::History(HistoryRequestV2::new(
            ChannelContextIdV2::from_bytes([0x81; 32]).map_err(fail)?,
            cursor,
            HistoryPageLimitV2::new(1).map_err(fail)?,
        ));
        let encoded = request.to_canonical_bytes().map_err(fail)?;
        prop_assert_eq!(RpcRequestV2::from_canonical_bytes(encoded).map_err(fail)?, request);
    }

    #[test]
    fn ambiguity_tokens_remain_bounded_and_round_trip(bytes in prop::collection::vec(any::<u8>(), 16..=256)) {
        let request = common::floor_request(12);
        let response = RpcResponseV2::RollbackFloorCas(
            RollbackFloorCasResponseV2::new(
                &request,
                RollbackFloorCasStatusV2::Ambiguous {
                    token: AmbiguityTokenV2::new(bytes).map_err(fail)?,
                },
            ).map_err(fail)?,
        );
        let encoded = response.to_canonical_bytes().map_err(fail)?;
        let rpc_request = RpcRequestV2::RollbackFloorCas(
            thunderbolt_ledger_rpc::RollbackFloorCasRequestV2::new(request),
        );
        let correlated = RpcResponseV2::from_canonical_bytes_for(&encoded, &rpc_request).map_err(fail)?;
        prop_assert_eq!(correlated.response(), &response);
    }

    #[test]
    fn any_snapshot_payload_tamper_breaks_bound_state_hash(offset in any::<usize>(), bit in 0_u8..8) {
        let snapshot = common::snapshot(13);
        let bytes = SnapshotBytesV2::from_snapshot(&snapshot).map_err(fail)?;
        let query = ChannelStatusRequestV2::new(
            common::ledger_chain(),
            ChannelContextIdV2::from_bytes(snapshot.binding.context_id().map_err(fail)?).map_err(fail)?,
        );
        let response = RpcResponseV2::ChannelStatus(Box::new(ChannelStatusResponseV2::new(
            &query,
            snapshot.binding.clone(),
            thunderbolt_ledger_rpc::ChannelExecutionPositionV2::new(1, 0, snapshot.head_entry_hash).map_err(fail)?,
            bytes.state_hash(),
            bytes,
            FinalityStatusV2::Unfinalized,
        ).map_err(fail)?));
        let encoded = response.to_canonical_bytes().map_err(fail)?;
        let mut value: serde_json::Value = serde_json::from_slice(&encoded).map_err(fail)?;
        let snapshot_hex = value["response"]["result"]["snapshot_bytes"]
            .as_str()
            .ok_or_else(|| TestCaseError::fail("missing snapshot bytes"))?;
        let mut snapshot_bytes = hex::decode(snapshot_hex).map_err(fail)?;
        let header = 8 + b"bitcoin-thunderbolt/protocol-state/v2".len() + 4;
        let index = header + (offset % (snapshot_bytes.len() - header));
        snapshot_bytes[index] ^= 1_u8 << bit;
        value["response"]["result"]["snapshot_bytes"] = serde_json::Value::String(hex::encode(snapshot_bytes));
        let tampered = serde_json::to_vec(&value).map_err(fail)?;
        prop_assert!(RpcResponseV2::from_canonical_bytes_for(
            tampered,
            &RpcRequestV2::ChannelStatus(query),
        )
        .is_err());
    }
}
