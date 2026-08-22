mod common;

use thunderbolt_ledger_rpc::{
    AdmissionRejectionV2, AdmissionStatusV2, ChannelStatusRequestV2, HistoryCursorV2, RequestLifecycleV2,
    RequestStatusRequestV2, RequestStatusResponseV2, RollbackFloorCasRequestV2, RpcCodecError, RpcRequestV2,
    RpcResponseV2, SubmitProposalRequestV2, SubmitProposalResponseV2, MAX_RPC_REQUEST_BYTES, MAX_RPC_RESPONSE_BYTES,
};

#[test]
fn noncanonical_unknown_and_future_version_envelopes_are_rejected() -> Result<(), Box<dyn std::error::Error>> {
    let request = RpcRequestV2::ChannelStatus(ChannelStatusRequestV2::new(
        common::ledger_chain(),
        thunderbolt_ledger::ChannelContextIdV2::from_bytes([0x11; 32])?,
    ));
    let canonical = request.to_canonical_bytes()?;

    let mut spaced = Vec::with_capacity(canonical.len() + 1);
    spaced.push(b' ');
    spaced.extend_from_slice(&canonical);
    assert!(matches!(
        RpcRequestV2::from_canonical_bytes(spaced),
        Err(RpcCodecError::NonCanonical)
    ));

    let mut value: serde_json::Value = serde_json::from_slice(&canonical)?;
    value["unexpected"] = true.into();
    assert!(RpcRequestV2::from_canonical_bytes(serde_json::to_vec(&value)?).is_err());

    let canonical_text = String::from_utf8(canonical.clone())?;
    let duplicate_version = format!("{{\"api_version\":2,{}", &canonical_text[1..]);
    assert!(RpcRequestV2::from_canonical_bytes(duplicate_version).is_err());

    let mut value: serde_json::Value = serde_json::from_slice(&canonical)?;
    value["api_version"] = 3.into();
    assert!(matches!(
        RpcRequestV2::from_canonical_bytes(serde_json::to_vec(&value)?),
        Err(RpcCodecError::UnsupportedVersion { found: 3 })
    ));
    Ok(())
}

#[test]
fn oversized_request_is_rejected_before_parsing() {
    let oversized = vec![b' '; MAX_RPC_REQUEST_BYTES + 1];
    assert!(matches!(
        RpcRequestV2::from_canonical_bytes(oversized),
        Err(RpcCodecError::BodyTooLarge {
            direction: "request",
            limit: MAX_RPC_REQUEST_BYTES,
        })
    ));
}

#[test]
fn oversized_escaped_response_is_rejected_before_json_parsing() -> Result<(), Box<dyn std::error::Error>> {
    let request = RpcRequestV2::ChannelStatus(ChannelStatusRequestV2::new(
        common::ledger_chain(),
        thunderbolt_ledger::ChannelContextIdV2::from_bytes([0x77; 32])?,
    ));
    let mut oversized = b"{\"api_version\":2,\"response\":\"".to_vec();
    oversized.extend_from_slice("\\u0061".repeat(MAX_RPC_RESPONSE_BYTES / 6 + 1).as_bytes());
    assert!(matches!(
        RpcResponseV2::from_canonical_bytes_for(oversized, &request),
        Err(RpcCodecError::BodyTooLarge {
            direction: "response",
            limit: MAX_RPC_RESPONSE_BYTES,
        })
    ));
    Ok(())
}

#[test]
fn submit_request_and_response_are_bound_to_signed_identifiers() -> Result<(), Box<dyn std::error::Error>> {
    let proposal = common::signed_open(7);
    assert!(SubmitProposalRequestV2::new(
        thunderbolt_ledger::LedgerChainIdV2::new("wrong-chain")?,
        proposal.clone(),
    )
    .is_err());

    let request = SubmitProposalRequestV2::new(common::ledger_chain(), proposal)?;
    let response = SubmitProposalResponseV2::new(
        &request,
        AdmissionStatusV2::Rejected {
            reason: AdmissionRejectionV2::InvalidPredecessor,
        },
    )?;
    response.validate_for(&request)?;

    let other = SubmitProposalRequestV2::new(common::ledger_chain(), common::signed_open(8))?;
    assert!(response.validate_for(&other).is_err());
    Ok(())
}

#[test]
fn floor_digest_chain_and_transition_tamper_fail_closed() -> Result<(), Box<dyn std::error::Error>> {
    let request = RpcRequestV2::RollbackFloorCas(RollbackFloorCasRequestV2::new(common::floor_request(5)));
    let encoded = request.to_canonical_bytes()?;

    let mut value: serde_json::Value = serde_json::from_slice(&encoded)?;
    let digest = value["request"]["params"]["request_digest"].as_str().ok_or("digest")?;
    value["request"]["params"]["request_digest"] = serde_json::Value::String(format!(
        "{}{}",
        if &digest[..2] == "00" { "01" } else { "00" },
        &digest[2..]
    ));
    assert!(RpcRequestV2::from_canonical_bytes(serde_json::to_vec(&value)?).is_err());

    let mut value: serde_json::Value = serde_json::from_slice(&encoded)?;
    let canonical = value["request"]["params"]["canonical_request"]
        .as_str()
        .ok_or("canonical")?;
    let mut bytes = hex::decode(canonical)?;
    let domain_len = u64::from_be_bytes(bytes[..8].try_into()?);
    let chain_length_offset = 8 + usize::try_from(domain_len)?;
    let chain_start = chain_length_offset + 8;
    bytes[chain_start] ^= 1;
    value["request"]["params"]["canonical_request"] = serde_json::Value::String(hex::encode(bytes));
    assert!(RpcRequestV2::from_canonical_bytes(serde_json::to_vec(&value)?).is_err());
    Ok(())
}

#[test]
fn cursor_rejects_zero_height_and_genesis_hash_mismatch() -> Result<(), Box<dyn std::error::Error>> {
    assert!(HistoryCursorV2::new(common::ledger_chain(), 0, 0, thunderbolt_ledger::AppHashV2::zero()).is_err());
    assert!(HistoryCursorV2::new(
        common::ledger_chain(),
        1,
        0,
        thunderbolt_ledger::AppHashV2::from_bytes([1; 32])?,
    )
    .is_err());
    assert!(HistoryCursorV2::new(common::ledger_chain(), 2, 0, thunderbolt_ledger::AppHashV2::zero()).is_err());
    Ok(())
}

#[test]
fn uppercase_fixed_hex_is_not_canonical() -> Result<(), Box<dyn std::error::Error>> {
    let request = SubmitProposalRequestV2::new(common::ledger_chain(), common::signed_open(3))?;
    let response = RpcResponseV2::SubmitProposal(SubmitProposalResponseV2::new(
        &request,
        AdmissionStatusV2::AlreadyKnown,
    )?);
    let mut value: serde_json::Value = serde_json::from_slice(&response.to_canonical_bytes()?)?;
    let entry_hash = value["response"]["result"]["entry_hash"].as_str().ok_or("entry hash")?;
    value["response"]["result"]["entry_hash"] = serde_json::Value::String(entry_hash.to_uppercase());
    assert!(RpcResponseV2::from_canonical_bytes_for(
        serde_json::to_vec(&value)?,
        &RpcRequestV2::SubmitProposal(request),
    )
    .is_err());
    Ok(())
}

#[test]
fn unknown_status_cannot_be_replayed_across_complete_request_keys() -> Result<(), Box<dyn std::error::Error>> {
    let proposal = common::signed_open(14);
    let original = RequestStatusRequestV2::new(
        common::ledger_chain(),
        thunderbolt_ledger::ChannelContextIdV2::from_bytes(proposal.body().channel().context_id()?)?,
        proposal.body().participant_id()?,
        proposal.body().request_id().digest().clone(),
    );
    let response = RequestStatusResponseV2::new(&original, RequestLifecycleV2::Unknown)?;
    response.validate_for(&original)?;

    let other = RequestStatusRequestV2::new(
        common::ledger_chain(),
        original.channel_context_id().clone(),
        thunderbolt_ledger::ParticipantIdV2::from_bytes([0xee; 32])?,
        original.request_digest().clone(),
    );
    assert!(response.validate_for(&other).is_err());
    let encoded = RpcResponseV2::RequestStatus(Box::new(response.clone())).to_canonical_bytes()?;
    assert!(RpcResponseV2::from_canonical_bytes_for(&encoded, &RpcRequestV2::RequestStatus(original.clone()),).is_ok());
    assert!(RpcResponseV2::from_canonical_bytes_for(&encoded, &RpcRequestV2::RequestStatus(other),).is_err());
    assert!(RpcResponseV2::from_canonical_bytes_for(
        encoded,
        &RpcRequestV2::ChannelStatus(ChannelStatusRequestV2::new(
            common::ledger_chain(),
            original.channel_context_id().clone(),
        )),
    )
    .is_err());
    Ok(())
}
