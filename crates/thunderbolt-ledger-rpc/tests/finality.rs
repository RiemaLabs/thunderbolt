mod common;

use std::fmt;

use thunderbolt_ledger_rpc::{
    ExternalFinalityVerifierV2, FinalityVerifierProfileIdV2, FinalizedEntryBundleV2, OpaqueConsensusReceiptV2,
    RequestLifecycleV2, RequestStatusRequestV2, RequestStatusResponseV2,
};

#[derive(Debug)]
struct Rejected;

impl fmt::Display for Rejected {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("rejected test receipt")
    }
}

impl std::error::Error for Rejected {}

struct Verifier {
    accept: bool,
    profile_byte: u8,
}

impl ExternalFinalityVerifierV2 for Verifier {
    type Error = Rejected;

    fn profile_id(&self) -> FinalityVerifierProfileIdV2 {
        FinalityVerifierProfileIdV2::from_bytes([self.profile_byte; 32]).expect("test profile")
    }

    fn verify(
        &self,
        block: &thunderbolt_ledger::ExecutedBlockV2,
        entry: &thunderbolt_ledger::ExecutedEntryV2,
        proof: &thunderbolt_ledger::EntryMerkleProofV2,
        receipt: &OpaqueConsensusReceiptV2,
    ) -> Result<(), Self::Error> {
        if self.accept
            && block.entries().get(entry.metadata().block_index() as usize) == Some(entry)
            && proof.leaf_index() == entry.metadata().block_index()
            && receipt.as_bytes() == b"test quorum and app-inclusion receipt"
        {
            Ok(())
        } else {
            Err(Rejected)
        }
    }
}

fn bundle(discriminator: u8) -> Result<FinalizedEntryBundleV2, Box<dyn std::error::Error>> {
    let block = common::executed_block(discriminator);
    let entry = block.entries()[0].clone();
    let proof = block.entry_proof(0)?;
    let receipt = OpaqueConsensusReceiptV2::new(
        FinalityVerifierProfileIdV2::from_bytes([0xa1; 32])?,
        b"test quorum and app-inclusion receipt".to_vec(),
    )?;
    Ok(FinalizedEntryBundleV2::new(block, entry, proof, receipt)?)
}

#[test]
fn only_external_verifier_issues_finality_capability() -> Result<(), Box<dyn std::error::Error>> {
    let bundle = bundle(4)?;
    assert!(bundle
        .verify_finality(&Verifier {
            accept: false,
            profile_byte: 0xa1,
        })
        .is_err());
    assert!(bundle
        .verify_finality(&Verifier {
            accept: true,
            profile_byte: 0xa2,
        })
        .is_err());
    let verified = bundle.verify_finality(&Verifier {
        accept: true,
        profile_byte: 0xa1,
    })?;
    assert_eq!(verified.bundle(), &bundle);
    Ok(())
}

#[test]
fn bundle_rejects_entry_from_another_block() -> Result<(), Box<dyn std::error::Error>> {
    let block = common::executed_block(4);
    let other = common::executed_block(5);
    let proof = block.entry_proof(0)?;
    let receipt = OpaqueConsensusReceiptV2::new(FinalityVerifierProfileIdV2::from_bytes([0xa2; 32])?, vec![0x45; 32])?;
    assert!(FinalizedEntryBundleV2::new(block, other.entries()[0].clone(), proof, receipt).is_err());
    Ok(())
}

#[test]
fn finalized_request_status_binds_complete_query_key() -> Result<(), Box<dyn std::error::Error>> {
    let bundle = bundle(6)?;
    let metadata = bundle.entry().metadata();
    let request = RequestStatusRequestV2::new(
        metadata.ledger_chain_id().clone(),
        metadata.channel_context_id().clone(),
        metadata.participant_id().clone(),
        metadata.request_digest().clone(),
    );
    let response = RequestStatusResponseV2::new(
        &request,
        RequestLifecycleV2::FinalityReceiptAvailable {
            bundle: Box::new(bundle.clone()),
        },
    )?;
    response.validate_for(&request)?;

    let wrong = RequestStatusRequestV2::new(
        metadata.ledger_chain_id().clone(),
        metadata.channel_context_id().clone(),
        thunderbolt_ledger::ParticipantIdV2::from_bytes([0xfe; 32])?,
        metadata.request_digest().clone(),
    );
    assert!(response.validate_for(&wrong).is_err());
    Ok(())
}

#[test]
fn tampered_block_or_merkle_proof_fails_decode() -> Result<(), Box<dyn std::error::Error>> {
    let bundle = bundle(8)?;
    let metadata = bundle.entry().metadata();
    let query = RequestStatusRequestV2::new(
        metadata.ledger_chain_id().clone(),
        metadata.channel_context_id().clone(),
        metadata.participant_id().clone(),
        metadata.request_digest().clone(),
    );
    let response = thunderbolt_ledger_rpc::RpcResponseV2::RequestStatus(Box::new(RequestStatusResponseV2::new(
        &query,
        RequestLifecycleV2::FinalityReceiptAvailable {
            bundle: Box::new(bundle),
        },
    )?));
    let encoded = response.to_canonical_bytes()?;
    let mut value: serde_json::Value = serde_json::from_slice(&encoded)?;
    value["response"]["result"]["lifecycle"]["bundle"]["proof"]["leaf_index"] = 1.into();
    let tampered = serde_json::to_vec(&value)?;
    let rpc_request = thunderbolt_ledger_rpc::RpcRequestV2::RequestStatus(query.clone());
    assert!(thunderbolt_ledger_rpc::RpcResponseV2::from_canonical_bytes_for(tampered, &rpc_request).is_err());

    let mut value: serde_json::Value = serde_json::from_slice(&encoded)?;
    value["response"]["result"]["lifecycle"]["bundle"]["block"]["app_hash"] =
        serde_json::Value::String("ff".repeat(32));
    let tampered = serde_json::to_vec(&value)?;
    assert!(thunderbolt_ledger_rpc::RpcResponseV2::from_canonical_bytes_for(tampered, &rpc_request).is_err());
    Ok(())
}
