mod common;

use thunderbolt_keystore::CheckpointCasOutcome;
use thunderbolt_ledger_rpc::{
    AdmissionStatusV2, AmbiguityTokenV2, ChannelStatusRequestV2, ChannelStatusResponseV2, FinalityStatusV2,
    HistoryCursorV2, HistoryPageLimitV2, HistoryRequestV2, HistoryResponseV2, RequestLifecycleV2,
    RequestStatusRequestV2, RequestStatusResponseV2, RollbackFloorCasRequestV2, RollbackFloorCasResponseV2,
    RollbackFloorCasStatusV2, RpcRequestV2, RpcResponseV2, SnapshotBytesV2, SubmitProposalRequestV2,
    SubmitProposalResponseV2, TransportAcceptanceIdV2,
};

#[test]
fn every_request_variant_round_trips_canonically() -> Result<(), Box<dyn std::error::Error>> {
    let proposal = common::signed_open(7);
    let channel_context = thunderbolt_ledger::ChannelContextIdV2::from_bytes(proposal.body().channel().context_id()?)?;
    let participant = proposal.body().participant_id()?;
    let request_digest = proposal.body().request_id().digest().clone();
    let chain = common::ledger_chain();
    let requests = vec![
        RpcRequestV2::SubmitProposal(SubmitProposalRequestV2::new(chain.clone(), proposal)?),
        RpcRequestV2::ChannelStatus(ChannelStatusRequestV2::new(chain.clone(), channel_context.clone())),
        RpcRequestV2::RequestStatus(RequestStatusRequestV2::new(
            chain.clone(),
            channel_context.clone(),
            participant,
            request_digest,
        )),
        RpcRequestV2::History(HistoryRequestV2::new(
            channel_context,
            HistoryCursorV2::new(chain, 1, 0, thunderbolt_ledger::AppHashV2::zero())?,
            HistoryPageLimitV2::new(16)?,
        )),
        RpcRequestV2::RollbackFloorCas(RollbackFloorCasRequestV2::new(common::floor_request(7))),
    ];

    for request in requests {
        let encoded = request.to_canonical_bytes()?;
        assert_eq!(RpcRequestV2::from_canonical_bytes(&encoded)?, request);
        assert_eq!(request.to_canonical_bytes()?, encoded);
    }
    Ok(())
}

#[test]
fn representative_responses_round_trip_canonically() -> Result<(), Box<dyn std::error::Error>> {
    let proposal_request = SubmitProposalRequestV2::new(common::ledger_chain(), common::signed_open(9))?;
    let submit = RpcResponseV2::SubmitProposal(SubmitProposalResponseV2::new(
        &proposal_request,
        AdmissionStatusV2::Accepted {
            acceptance_id: TransportAcceptanceIdV2::from_bytes([0x91; 32])?,
        },
    )?);

    let snapshot = common::snapshot(9);
    let snapshot_bytes = SnapshotBytesV2::from_snapshot(&snapshot)?;
    let channel_query = ChannelStatusRequestV2::new(
        common::ledger_chain(),
        thunderbolt_ledger::ChannelContextIdV2::from_bytes(snapshot.binding.context_id()?)?,
    );
    let channel = RpcResponseV2::ChannelStatus(Box::new(ChannelStatusResponseV2::new(
        &channel_query,
        snapshot.binding.clone(),
        thunderbolt_ledger_rpc::ChannelExecutionPositionV2::new(1, 0, snapshot.head_entry_hash.clone())?,
        snapshot_bytes.state_hash(),
        snapshot_bytes,
        FinalityStatusV2::Unfinalized,
    )?));

    let executed = common::executed_block(9);
    let metadata = executed.entries()[0].metadata();
    let status_query = RequestStatusRequestV2::new(
        metadata.ledger_chain_id().clone(),
        metadata.channel_context_id().clone(),
        metadata.participant_id().clone(),
        metadata.request_digest().clone(),
    );
    let request_status = RpcResponseV2::RequestStatus(Box::new(RequestStatusResponseV2::new(
        &status_query,
        RequestLifecycleV2::Executed {
            metadata: Box::new(thunderbolt_ledger_rpc::ExecutedMetadataRecordV2::from_metadata(
                metadata,
            )),
        },
    )?));

    let history = RpcResponseV2::History(HistoryResponseV2::new(
        &HistoryRequestV2::new(
            thunderbolt_ledger::ChannelContextIdV2::from_bytes(
                proposal_request.signed_proposal().body().channel().context_id()?,
            )?,
            HistoryCursorV2::new(common::ledger_chain(), 1, 0, thunderbolt_ledger::AppHashV2::zero())?,
            HistoryPageLimitV2::new(4)?,
        ),
        Vec::new(),
        None,
    )?);

    let floor_request = common::floor_request(9);
    let floor = RpcResponseV2::RollbackFloorCas(RollbackFloorCasResponseV2::new(
        &floor_request,
        RollbackFloorCasStatusV2::Ambiguous {
            token: AmbiguityTokenV2::new(vec![0x92; 16])?,
        },
    )?);

    for response in [submit, channel, request_status, history, floor] {
        let encoded = response.to_canonical_bytes()?;
        assert_eq!(RpcResponseV2::from_canonical_bytes(&encoded)?, response);
        assert_eq!(response.to_canonical_bytes()?, encoded);
    }
    Ok(())
}

#[test]
fn finalized_floor_outcome_round_trips_under_separate_profile() -> Result<(), Box<dyn std::error::Error>> {
    let request = common::floor_request(10);
    let response = RpcResponseV2::RollbackFloorCas(RollbackFloorCasResponseV2::new(
        &request,
        RollbackFloorCasStatusV2::FinalityReceiptAvailable {
            outcome: CheckpointCasOutcome::AlreadyCurrent,
            consensus_receipt: thunderbolt_ledger_rpc::OpaqueConsensusReceiptV2::new(
                thunderbolt_ledger_rpc::FinalityVerifierProfileIdV2::from_bytes([0x71; 32])?,
                vec![0x72; 48],
            )?,
        },
    )?);
    let encoded = response.to_canonical_bytes()?;
    assert_eq!(RpcResponseV2::from_canonical_bytes(&encoded)?, response);
    Ok(())
}

#[test]
fn channel_response_checks_embedded_chain() -> Result<(), Box<dyn std::error::Error>> {
    let proposal = common::signed_open(3);
    let context = thunderbolt_ledger::ChannelContextIdV2::from_bytes(proposal.body().channel().context_id()?)?;
    let response_snapshot = common::snapshot(3);
    let snapshot_bytes = SnapshotBytesV2::from_snapshot(&response_snapshot)?;
    let request = ChannelStatusRequestV2::new(common::ledger_chain(), context);
    let response = ChannelStatusResponseV2::new(
        &request,
        response_snapshot.binding.clone(),
        thunderbolt_ledger_rpc::ChannelExecutionPositionV2::new(1, 0, response_snapshot.head_entry_hash)?,
        snapshot_bytes.state_hash(),
        snapshot_bytes,
        FinalityStatusV2::Unfinalized,
    )?;
    response.validate_for(&request)?;
    assert!(response
        .validate_for(&ChannelStatusRequestV2::new(
            thunderbolt_ledger::LedgerChainIdV2::new("other-chain")?,
            thunderbolt_ledger::ChannelContextIdV2::from_bytes([0x55; 32])?,
        ))
        .is_err());

    let other_snapshot = common::snapshot(4);
    let other_bytes = SnapshotBytesV2::from_snapshot(&other_snapshot)?;
    assert!(ChannelStatusResponseV2::new(
        &request,
        other_snapshot.binding,
        thunderbolt_ledger_rpc::ChannelExecutionPositionV2::new(1, 0, other_snapshot.head_entry_hash)?,
        other_bytes.state_hash(),
        other_bytes,
        FinalityStatusV2::Unfinalized,
    )
    .is_err());
    Ok(())
}

#[test]
fn channel_response_rejects_trailing_snapshot_bytes_and_wrong_head() -> Result<(), Box<dyn std::error::Error>> {
    let snapshot = common::snapshot(5);
    let request = ChannelStatusRequestV2::new(
        common::ledger_chain(),
        thunderbolt_ledger::ChannelContextIdV2::from_bytes(snapshot.binding.context_id()?)?,
    );
    let mut trailing = snapshot.canonical_bytes()?;
    trailing.push(0);
    let trailing = SnapshotBytesV2::from_canonical_bytes(trailing)?;
    assert!(ChannelStatusResponseV2::new(
        &request,
        snapshot.binding.clone(),
        thunderbolt_ledger_rpc::ChannelExecutionPositionV2::new(1, 0, snapshot.head_entry_hash.clone())?,
        trailing.state_hash(),
        trailing,
        FinalityStatusV2::Unfinalized,
    )
    .is_err());

    let canonical = SnapshotBytesV2::from_snapshot(&snapshot)?;
    assert!(ChannelStatusResponseV2::new(
        &request,
        snapshot.binding,
        thunderbolt_ledger_rpc::ChannelExecutionPositionV2::new(
            1,
            0,
            thunderbolt_ledger::EntryHashV2::from_bytes([0xfa; 32])?,
        )?,
        canonical.state_hash(),
        canonical,
        FinalityStatusV2::Unfinalized,
    )
    .is_err());
    Ok(())
}
