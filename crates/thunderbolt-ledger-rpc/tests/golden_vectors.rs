mod common;

use sha2::{Digest as _, Sha256};
use thunderbolt_ledger::{ChannelContextIdV2, LedgerChainIdV2, ParticipantIdV2, RequestDigestV2};
use thunderbolt_ledger_rpc::{
    ChannelStatusRequestV2, RequestLifecycleV2, RequestStatusRequestV2, RequestStatusResponseV2, RpcRequestV2,
    RpcResponseV2,
};

const CHANNEL_STATUS_REQUEST_HEX: &str = "7b226170695f76657273696f6e223a322c2272657175657374223a7b226d6574686f64223a226368616e6e656c5f737461747573222c22706172616d73223a7b226c65646765725f636861696e5f6964223a2274622d726567746573742d32222c226368616e6e656c5f636f6e746578745f6964223a2231313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131227d7d7d";
const CHANNEL_STATUS_REQUEST_DIGEST_HEX: &str = "ebb46fd439de0699a98ab0fadc1e126dd7baf5a1c553ddceb632ec1fdd2c8742";
const UNKNOWN_REQUEST_STATUS_RESPONSE_HEX: &str = "7b226170695f76657273696f6e223a322c22726573706f6e7365223a7b226d6574686f64223a22726571756573745f737461747573222c22726573756c74223a7b226c65646765725f636861696e5f6964223a2274622d726567746573742d32222c226368616e6e656c5f636f6e746578745f6964223a2231313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131313131222c227061727469636970616e745f6964223a2232323232323232323232323232323232323232323232323232323232323232323232323232323232323232323232323232323232323232323232323232323232222c22726571756573745f646967657374223a2233333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333222c226c6966656379636c65223a7b22737461747573223a22756e6b6e6f776e227d7d7d7d";
const COMPACT_FINALITY_RESPONSE_BYTES: usize = 3_183;
const COMPACT_FINALITY_RESPONSE_SHA256: &str = "a674056e0e20890faa8b34270320c8350c83f581dc5679b9aea93f043fdc2a1a";

#[test]
fn channel_status_request_and_digest_are_stable() -> Result<(), Box<dyn std::error::Error>> {
    let request = RpcRequestV2::ChannelStatus(ChannelStatusRequestV2::new(
        LedgerChainIdV2::new("tb-regtest-2")?,
        ChannelContextIdV2::from_bytes([0x11; 32])?,
    ));
    assert_eq!(request.to_canonical_bytes()?, hex::decode(CHANNEL_STATUS_REQUEST_HEX)?);
    assert_eq!(request.request_digest()?.to_hex(), CHANNEL_STATUS_REQUEST_DIGEST_HEX);
    Ok(())
}

#[test]
fn compact_finalized_request_status_response_is_stable() -> Result<(), Box<dyn std::error::Error>> {
    let bundle = common::finalized_bundle(9, 0x91, vec![0x92; 48]);
    let metadata = bundle.entry().metadata();
    let request = RequestStatusRequestV2::new(
        metadata.ledger_chain_id().clone(),
        metadata.channel_context_id().clone(),
        metadata.participant_id().clone(),
        metadata.request_digest().clone(),
    );
    let response = RpcResponseV2::RequestStatus(Box::new(RequestStatusResponseV2::new(
        &request,
        RequestLifecycleV2::FinalityReceiptAvailable {
            bundle: Box::new(bundle),
        },
    )?));
    let encoded = response.to_canonical_bytes()?;
    assert_eq!(encoded.len(), COMPACT_FINALITY_RESPONSE_BYTES);
    assert_eq!(hex::encode(Sha256::digest(&encoded)), COMPACT_FINALITY_RESPONSE_SHA256);
    let value: serde_json::Value = serde_json::from_slice(&encoded)?;
    let encoded_bundle = &value["response"]["result"]["lifecycle"]["bundle"];
    assert!(encoded_bundle.get("commitment").is_some());
    assert!(encoded_bundle.get("block").is_none());
    let correlated = RpcResponseV2::from_canonical_bytes_for(&encoded, &RpcRequestV2::RequestStatus(request))?;
    assert_eq!(correlated.response(), &response);
    Ok(())
}

#[test]
fn unknown_request_status_response_is_stable() -> Result<(), Box<dyn std::error::Error>> {
    let request = RequestStatusRequestV2::new(
        LedgerChainIdV2::new("tb-regtest-2")?,
        ChannelContextIdV2::from_bytes([0x11; 32])?,
        ParticipantIdV2::from_bytes([0x22; 32])?,
        RequestDigestV2::from_bytes([0x33; 32])?,
    );
    let response = RpcResponseV2::RequestStatus(Box::new(RequestStatusResponseV2::new(
        &request,
        RequestLifecycleV2::Unknown,
    )?));
    assert_eq!(
        response.to_canonical_bytes()?,
        hex::decode(UNKNOWN_REQUEST_STATUS_RESPONSE_HEX)?
    );
    Ok(())
}
