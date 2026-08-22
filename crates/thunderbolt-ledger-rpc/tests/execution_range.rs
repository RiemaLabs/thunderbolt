mod common;

use proptest::prelude::*;
use thunderbolt_ledger::{AppHashV2, EntryHashV2, ExecutedBlockV2, LedgerChainIdV2, PendingBlockV2};
use thunderbolt_ledger_rpc::{
    EntryLocationRequestV2, EntryLocationResponseV2, ExecutionLocationV2, ExecutionRangeCursorV2,
    ExecutionRangeRequestV2, ExecutionRangeResponseV2, RpcRequestV2, RpcResponseV2, MAX_EXECUTION_RANGE_BLOCKS,
    MAX_EXECUTION_RANGE_ENCODED_BYTES,
};

fn contiguous_blocks(count: u16) -> Result<Vec<ExecutedBlockV2>, Box<dyn std::error::Error>> {
    let mut blocks = Vec::with_capacity(usize::from(count));
    let first = common::executed_block(41);
    let mut previous = first.app_hash().clone();
    blocks.push(first);
    for height in 2..=u64::from(count) {
        let block =
            PendingBlockV2::new(common::ledger_chain(), height, 1_700_000_000_000 + height, previous)?.execute()?;
        previous = block.app_hash().clone();
        blocks.push(block);
    }
    Ok(blocks)
}

fn range_request(count: u16) -> Result<ExecutionRangeRequestV2, Box<dyn std::error::Error>> {
    Ok(ExecutionRangeRequestV2::new(
        ExecutionRangeCursorV2::new(common::ledger_chain(), 1, AppHashV2::zero())?,
        count,
        MAX_EXECUTION_RANGE_ENCODED_BYTES,
    )?)
}

fn range_response(count: u16) -> Result<(RpcRequestV2, RpcResponseV2), Box<dyn std::error::Error>> {
    let request = range_request(count)?;
    let blocks = contiguous_blocks(count)?;
    let last = blocks.last().ok_or("nonempty range")?;
    let next = ExecutionRangeCursorV2::new(common::ledger_chain(), u64::from(count) + 1, last.app_hash().clone())?;
    let response = RpcResponseV2::ExecutionRange(ExecutionRangeResponseV2::new(&request, blocks, next)?);
    Ok((RpcRequestV2::ExecutionRange(request), response))
}

fn correlated_rejects(value: serde_json::Value, request: &RpcRequestV2) {
    let bytes = serde_json::to_vec(&value).expect("bounded test JSON");
    assert!(RpcResponseV2::from_canonical_bytes_for(bytes, request).is_err());
}

#[test]
fn whole_range_round_trip_preserves_empty_blocks_and_exact_continuation() -> Result<(), Box<dyn std::error::Error>> {
    let (request, response) = range_response(4)?;
    let RpcResponseV2::ExecutionRange(range) = &response else {
        return Err("range response variant".into());
    };
    assert_eq!(
        range.blocks().iter().map(ExecutedBlockV2::height).collect::<Vec<_>>(),
        vec![1, 2, 3, 4]
    );
    assert!(range.blocks()[1..].iter().all(|block| block.entries().is_empty()));
    assert_eq!(range.next_cursor().next_height(), 5);

    let encoded = response.to_canonical_bytes()?;
    let decoded = RpcResponseV2::from_canonical_bytes_for(&encoded, &request)?;
    assert_eq!(decoded.response(), &response);
    Ok(())
}

#[test]
fn range_response_rejects_empty_reordered_regressing_and_wrong_continuation_pages(
) -> Result<(), Box<dyn std::error::Error>> {
    let (request, response) = range_response(3)?;
    let encoded = response.to_canonical_bytes()?;
    let value: serde_json::Value = serde_json::from_slice(&encoded)?;

    let mut empty = value.clone();
    empty["response"]["result"]["blocks"] = serde_json::json!([]);
    correlated_rejects(empty, &request);

    let mut reordered = value.clone();
    reordered["response"]["result"]["blocks"]
        .as_array_mut()
        .ok_or("blocks array")?
        .swap(0, 1);
    correlated_rejects(reordered, &request);

    let mut duplicate = value.clone();
    let first = duplicate["response"]["result"]["blocks"][0].clone();
    duplicate["response"]["result"]["blocks"][1] = first;
    correlated_rejects(duplicate, &request);

    let mut continuation = value.clone();
    continuation["response"]["result"]["next_cursor"]["next_height"] = serde_json::json!(9);
    correlated_rejects(continuation, &request);

    let first = common::executed_block(41);
    let regressing = PendingBlockV2::new(
        common::ledger_chain(),
        2,
        first.block_time_ms() - 1,
        first.app_hash().clone(),
    )?
    .execute()?;
    let range = range_request(2)?;
    let next = ExecutionRangeCursorV2::new(common::ledger_chain(), 3, regressing.app_hash().clone())?;
    assert!(ExecutionRangeResponseV2::new(&range, vec![first, regressing], next).is_err());
    Ok(())
}

#[test]
fn every_range_request_field_and_response_binding_is_correlated() -> Result<(), Box<dyn std::error::Error>> {
    let (request, response) = range_response(3)?;
    let encoded = response.to_canonical_bytes()?;
    let RpcRequestV2::ExecutionRange(base) = &request else {
        return Err("range request variant".into());
    };
    let blocks = contiguous_blocks(3)?;
    let alternate_requests = [
        RpcRequestV2::ExecutionRange(ExecutionRangeRequestV2::new(
            ExecutionRangeCursorV2::new(LedgerChainIdV2::new("other-chain")?, 1, AppHashV2::zero())?,
            base.block_count(),
            base.max_encoded_bytes(),
        )?),
        RpcRequestV2::ExecutionRange(ExecutionRangeRequestV2::new(
            ExecutionRangeCursorV2::new(common::ledger_chain(), 2, blocks[0].app_hash().clone())?,
            base.block_count(),
            base.max_encoded_bytes(),
        )?),
        RpcRequestV2::ExecutionRange(ExecutionRangeRequestV2::new(
            ExecutionRangeCursorV2::new(common::ledger_chain(), 2, AppHashV2::from_bytes([0x77; 32])?)?,
            base.block_count(),
            base.max_encoded_bytes(),
        )?),
        RpcRequestV2::ExecutionRange(ExecutionRangeRequestV2::new(
            base.cursor().clone(),
            2,
            base.max_encoded_bytes(),
        )?),
        RpcRequestV2::ExecutionRange(ExecutionRangeRequestV2::new(
            base.cursor().clone(),
            base.block_count(),
            base.max_encoded_bytes() - 1,
        )?),
    ];
    for alternate in alternate_requests {
        assert!(RpcResponseV2::from_canonical_bytes_for(&encoded, &alternate).is_err());
    }

    let mut digest = serde_json::from_slice::<serde_json::Value>(&encoded)?;
    digest["response"]["result"]["request_digest"] = serde_json::json!("11".repeat(32));
    correlated_rejects(digest, &request);
    let mut version = serde_json::from_slice::<serde_json::Value>(&encoded)?;
    version["response"]["result"]["application_version"] = serde_json::json!(3);
    correlated_rejects(version, &request);
    Ok(())
}

#[test]
fn bounded_decoder_rejects_cap_plus_one_blocks() -> Result<(), Box<dyn std::error::Error>> {
    let (request, response) = range_response(MAX_EXECUTION_RANGE_BLOCKS)?;
    let mut value: serde_json::Value = serde_json::from_slice(&response.to_canonical_bytes()?)?;
    let blocks = value["response"]["result"]["blocks"]
        .as_array_mut()
        .ok_or("blocks array")?;
    blocks.push(blocks[0].clone());
    correlated_rejects(value, &request);
    Ok(())
}

#[test]
fn range_constructors_reject_empty_oversize_and_unrepresentable_pages() -> Result<(), Box<dyn std::error::Error>> {
    let genesis = ExecutionRangeCursorV2::new(common::ledger_chain(), 1, AppHashV2::zero())?;
    assert!(ExecutionRangeRequestV2::new(genesis.clone(), 0, MAX_EXECUTION_RANGE_ENCODED_BYTES,).is_err());
    assert!(ExecutionRangeRequestV2::new(
        genesis.clone(),
        MAX_EXECUTION_RANGE_BLOCKS + 1,
        MAX_EXECUTION_RANGE_ENCODED_BYTES,
    )
    .is_err());
    assert!(ExecutionRangeRequestV2::new(genesis, 1, MAX_EXECUTION_RANGE_ENCODED_BYTES + 1,).is_err());
    let terminal = ExecutionRangeCursorV2::new(
        common::ledger_chain(),
        i64::MAX as u64,
        AppHashV2::from_bytes([0x71; 32])?,
    )?;
    assert!(ExecutionRangeRequestV2::new(terminal, 1, MAX_EXECUTION_RANGE_ENCODED_BYTES,).is_err());
    Ok(())
}

#[test]
fn location_none_and_some_are_bound_to_exact_historical_checkpoint() -> Result<(), Box<dyn std::error::Error>> {
    let block = common::executed_block(52);
    let metadata = block.entries()[0].metadata();
    let request = EntryLocationRequestV2::new(
        common::ledger_chain(),
        metadata.channel_context_id().clone(),
        metadata.entry_hash().clone(),
        1,
        block.app_hash().clone(),
    )?;
    let none = RpcResponseV2::EntryLocation(EntryLocationResponseV2::new(&request, None)?);
    let some = RpcResponseV2::EntryLocation(EntryLocationResponseV2::new(
        &request,
        Some(ExecutionLocationV2::new(1, 0)?),
    )?);
    let rpc_request = RpcRequestV2::EntryLocation(request.clone());
    assert_eq!(
        RpcResponseV2::from_canonical_bytes_for(none.to_canonical_bytes()?, &rpc_request)?.response(),
        &none
    );
    assert_eq!(
        RpcResponseV2::from_canonical_bytes_for(some.to_canonical_bytes()?, &rpc_request)?.response(),
        &some
    );

    let later = PendingBlockV2::new(
        common::ledger_chain(),
        2,
        block.block_time_ms() + 1,
        block.app_hash().clone(),
    )?
    .execute()?;
    let changed = [
        EntryLocationRequestV2::new(
            LedgerChainIdV2::new("other-chain")?,
            request.channel_context_id().clone(),
            request.entry_hash().clone(),
            request.through_height(),
            request.expected_through_app_hash().clone(),
        )?,
        EntryLocationRequestV2::new(
            common::ledger_chain(),
            thunderbolt_ledger::ChannelContextIdV2::from_bytes([0x61; 32])?,
            request.entry_hash().clone(),
            request.through_height(),
            request.expected_through_app_hash().clone(),
        )?,
        EntryLocationRequestV2::new(
            common::ledger_chain(),
            request.channel_context_id().clone(),
            EntryHashV2::from_bytes([0x62; 32])?,
            request.through_height(),
            request.expected_through_app_hash().clone(),
        )?,
        EntryLocationRequestV2::new(
            common::ledger_chain(),
            request.channel_context_id().clone(),
            request.entry_hash().clone(),
            2,
            later.app_hash().clone(),
        )?,
        EntryLocationRequestV2::new(
            common::ledger_chain(),
            request.channel_context_id().clone(),
            request.entry_hash().clone(),
            request.through_height(),
            AppHashV2::from_bytes([0x63; 32])?,
        )?,
    ];
    let encoded = none.to_canonical_bytes()?;
    for changed in changed {
        assert!(RpcResponseV2::from_canonical_bytes_for(&encoded, &RpcRequestV2::EntryLocation(changed),).is_err());
    }
    Ok(())
}

fn fail(error: impl std::fmt::Display) -> TestCaseError {
    TestCaseError::fail(error.to_string())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn any_bounded_whole_block_count_round_trips_exactly(count in 1_u16..=MAX_EXECUTION_RANGE_BLOCKS) {
        let request = range_request(count).map_err(fail)?;
        let blocks = contiguous_blocks(count).map_err(fail)?;
        let last = blocks.last().ok_or_else(|| TestCaseError::fail("nonempty range"))?;
        let next = ExecutionRangeCursorV2::new(
            common::ledger_chain(),
            u64::from(count) + 1,
            last.app_hash().clone(),
        ).map_err(fail)?;
        let response = RpcResponseV2::ExecutionRange(
            ExecutionRangeResponseV2::new(&request, blocks, next).map_err(fail)?
        );
        let encoded = response.to_canonical_bytes().map_err(fail)?;
        let decoded = RpcResponseV2::from_canonical_bytes_for(
            &encoded,
            &RpcRequestV2::ExecutionRange(request),
        ).map_err(fail)?;
        prop_assert_eq!(decoded.response(), &response);
    }
}
