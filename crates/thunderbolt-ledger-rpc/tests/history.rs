mod common;

use thunderbolt_ledger_rpc::{
    ExecutedMetadataRecordV2, HistoryCursorV2, HistoryPageLimitV2, HistoryRequestV2, HistoryResponseV2,
};

#[test]
fn history_page_binds_chain_channel_order_and_forward_cursor() -> Result<(), Box<dyn std::error::Error>> {
    let block = common::executed_block(15);
    let metadata = ExecutedMetadataRecordV2::from_metadata(block.entries()[0].metadata());
    let request = HistoryRequestV2::new(
        metadata.channel_context_id.clone(),
        HistoryCursorV2::new(common::ledger_chain(), 1, 0, thunderbolt_ledger::AppHashV2::zero())?,
        HistoryPageLimitV2::new(4)?,
    );
    let next = HistoryCursorV2::new(common::ledger_chain(), 2, 0, block.app_hash().clone())?;
    let response = HistoryResponseV2::new(&request, vec![metadata.clone()], Some(next))?;
    response.validate_for(&request)?;

    let wrong_channel = HistoryRequestV2::new(
        thunderbolt_ledger::ChannelContextIdV2::from_bytes([0xef; 32])?,
        request.cursor().clone(),
        request.limit(),
    );
    assert!(response.validate_for(&wrong_channel).is_err());

    assert!(HistoryResponseV2::new(&request, vec![metadata.clone(), metadata], None).is_err());
    Ok(())
}

#[test]
fn history_page_enforces_requested_limit_and_cursor_progress() -> Result<(), Box<dyn std::error::Error>> {
    let block = common::executed_block(16);
    let metadata = ExecutedMetadataRecordV2::from_metadata(block.entries()[0].metadata());
    let cursor = HistoryCursorV2::new(common::ledger_chain(), 1, 0, thunderbolt_ledger::AppHashV2::zero())?;
    let request = HistoryRequestV2::new(
        metadata.channel_context_id.clone(),
        cursor.clone(),
        HistoryPageLimitV2::new(1)?,
    );

    assert!(HistoryResponseV2::new(&request, vec![metadata], Some(cursor)).is_err());

    let empty = HistoryResponseV2::new(&request, Vec::new(), None)?;
    let replay_target = HistoryRequestV2::new(
        request.channel_context_id().clone(),
        request.cursor().clone(),
        HistoryPageLimitV2::new(2)?,
    );
    assert!(empty.validate_for(&replay_target).is_err());
    Ok(())
}
