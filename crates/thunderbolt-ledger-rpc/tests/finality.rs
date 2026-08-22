mod common;

use std::fmt;

use serde_json::json;
use thunderbolt_ledger::{
    compute_app_hash_v2, ChannelContextIdV2, EntryMerkleRootV2, ExecutedBlockCommitmentV2, LedgerChainIdV2,
    ParticipantIdV2, RequestDigestV2,
};
use thunderbolt_ledger_rpc::{
    ExternalFinalityVerifierV2, FinalityVerifierProfileIdV2, FinalizedEntryBundleV2, OpaqueConsensusReceiptV2,
    RequestLifecycleV2, RequestStatusRequestV2, RequestStatusResponseV2, RpcRequestV2, RpcResponseV2,
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
        commitment: &thunderbolt_ledger::ExecutedBlockCommitmentV2,
        entry: &thunderbolt_ledger::ExecutedEntryV2,
        proof: &thunderbolt_ledger::EntryMerkleProofV2,
        receipt: &OpaqueConsensusReceiptV2,
    ) -> Result<(), Self::Error> {
        if self.accept
            && proof.verify_entry_against_commitment(entry, commitment).is_ok()
            && receipt.as_bytes() == receipt_bytes(commitment)
        {
            Ok(())
        } else {
            Err(Rejected)
        }
    }
}

fn bundle(discriminator: u8) -> Result<FinalizedEntryBundleV2, Box<dyn std::error::Error>> {
    let block = common::executed_block(discriminator);
    let commitment = block.commitment()?;
    let entry = block.entries()[0].clone();
    let proof = block.entry_proof(0)?;
    let receipt = OpaqueConsensusReceiptV2::new(
        FinalityVerifierProfileIdV2::from_bytes([0xa1; 32])?,
        receipt_bytes(&commitment),
    )?;
    Ok(FinalizedEntryBundleV2::new(commitment, entry, proof, receipt)?)
}

fn receipt_bytes(commitment: &thunderbolt_ledger::ExecutedBlockCommitmentV2) -> Vec<u8> {
    [
        b"test quorum and app-inclusion receipt".as_slice(),
        commitment.app_hash().as_bytes(),
    ]
    .concat()
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
fn external_verifier_rejects_receipt_bound_to_another_app_hash() -> Result<(), Box<dyn std::error::Error>> {
    let block = common::executed_block(4);
    let commitment = block.commitment()?;
    let other_commitment = common::executed_block(5).commitment()?;
    let entry = block.entries()[0].clone();
    let proof = block.entry_proof(0)?;
    let receipt = OpaqueConsensusReceiptV2::new(
        FinalityVerifierProfileIdV2::from_bytes([0xa1; 32])?,
        receipt_bytes(&other_commitment),
    )?;
    let bundle = FinalizedEntryBundleV2::new(commitment, entry, proof, receipt)?;

    assert!(bundle
        .verify_finality(&Verifier {
            accept: true,
            profile_byte: 0xa1,
        })
        .is_err());
    Ok(())
}

#[test]
fn bundle_rejects_entry_from_another_block() -> Result<(), Box<dyn std::error::Error>> {
    let block = common::executed_block(4);
    let other = common::executed_block(5);
    let commitment = block.commitment()?;
    let proof = block.entry_proof(0)?;
    let receipt = OpaqueConsensusReceiptV2::new(FinalityVerifierProfileIdV2::from_bytes([0xa2; 32])?, vec![0x45; 32])?;
    assert!(FinalizedEntryBundleV2::new(commitment, other.entries()[0].clone(), proof, receipt).is_err());
    Ok(())
}

#[test]
fn bundle_rejects_self_consistent_wrong_commitment_scope() -> Result<(), Box<dyn std::error::Error>> {
    let block = common::executed_block(5);
    let base = block.commitment()?;
    let entry = block.entries()[0].clone();
    let proof = block.entry_proof(0)?;
    let wrong_chain = LedgerChainIdV2::new("wrong-ledger")?;
    let wrong_root = EntryMerkleRootV2::from_bytes([0x7b; 32])?;
    let commitments = [
        rebuild_commitment(
            &base,
            wrong_chain,
            base.block_time_ms(),
            base.entry_count(),
            base.entry_merkle_root().clone(),
        )?,
        rebuild_commitment(
            &base,
            base.ledger_chain_id().clone(),
            base.block_time_ms() + 1,
            base.entry_count(),
            base.entry_merkle_root().clone(),
        )?,
        rebuild_commitment(
            &base,
            base.ledger_chain_id().clone(),
            base.block_time_ms(),
            base.entry_count() + 1,
            base.entry_merkle_root().clone(),
        )?,
        rebuild_commitment(
            &base,
            base.ledger_chain_id().clone(),
            base.block_time_ms(),
            base.entry_count(),
            wrong_root,
        )?,
    ];
    for commitment in commitments {
        let receipt =
            OpaqueConsensusReceiptV2::new(FinalityVerifierProfileIdV2::from_bytes([0xa2; 32])?, vec![0x45; 32])?;
        assert!(FinalizedEntryBundleV2::new(commitment, entry.clone(), proof.clone(), receipt).is_err());
    }
    Ok(())
}

fn rebuild_commitment(
    base: &ExecutedBlockCommitmentV2,
    ledger_chain_id: LedgerChainIdV2,
    block_time_ms: u64,
    entry_count: u32,
    entry_merkle_root: EntryMerkleRootV2,
) -> Result<ExecutedBlockCommitmentV2, Box<dyn std::error::Error>> {
    let app_hash = compute_app_hash_v2(
        &ledger_chain_id,
        base.previous_app_hash(),
        base.height(),
        block_time_ms,
        entry_count,
        &entry_merkle_root,
    )?;
    Ok(ExecutedBlockCommitmentV2::new(
        ledger_chain_id,
        base.height(),
        block_time_ms,
        base.previous_app_hash().clone(),
        entry_count,
        entry_merkle_root,
        app_hash,
    )?)
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
    let encoded = RpcResponseV2::RequestStatus(Box::new(response)).to_canonical_bytes()?;
    let exact = RpcRequestV2::RequestStatus(request.clone());
    assert!(RpcResponseV2::from_canonical_bytes_for(&encoded, &exact).is_ok());

    let wrong_requests = [
        RequestStatusRequestV2::new(
            LedgerChainIdV2::new("wrong-ledger")?,
            metadata.channel_context_id().clone(),
            metadata.participant_id().clone(),
            metadata.request_digest().clone(),
        ),
        RequestStatusRequestV2::new(
            metadata.ledger_chain_id().clone(),
            ChannelContextIdV2::from_bytes([0xfd; 32])?,
            metadata.participant_id().clone(),
            metadata.request_digest().clone(),
        ),
        RequestStatusRequestV2::new(
            metadata.ledger_chain_id().clone(),
            metadata.channel_context_id().clone(),
            ParticipantIdV2::from_bytes([0xfe; 32])?,
            metadata.request_digest().clone(),
        ),
        RequestStatusRequestV2::new(
            metadata.ledger_chain_id().clone(),
            metadata.channel_context_id().clone(),
            metadata.participant_id().clone(),
            RequestDigestV2::from_bytes([0xfc; 32])?,
        ),
    ];
    for wrong in wrong_requests {
        assert!(RpcResponseV2::from_canonical_bytes_for(&encoded, &RpcRequestV2::RequestStatus(wrong)).is_err());
    }
    Ok(())
}

#[test]
fn tampered_commitment_entry_or_merkle_proof_fails_decode() -> Result<(), Box<dyn std::error::Error>> {
    let bundle = bundle(8)?;
    let metadata = bundle.entry().metadata();
    let query = RequestStatusRequestV2::new(
        metadata.ledger_chain_id().clone(),
        metadata.channel_context_id().clone(),
        metadata.participant_id().clone(),
        metadata.request_digest().clone(),
    );
    let response = RpcResponseV2::RequestStatus(Box::new(RequestStatusResponseV2::new(
        &query,
        RequestLifecycleV2::FinalityReceiptAvailable {
            bundle: Box::new(bundle),
        },
    )?));
    let encoded = response.to_canonical_bytes()?;
    let rpc_request = RpcRequestV2::RequestStatus(query);
    let cases = [
        (
            "/response/result/lifecycle/bundle/commitment/ledger_chain_id",
            json!("wrong-ledger"),
        ),
        ("/response/result/lifecycle/bundle/commitment/height", json!(2)),
        ("/response/result/lifecycle/bundle/commitment/block_time_ms", json!(1)),
        ("/response/result/lifecycle/bundle/commitment/entry_count", json!(2)),
        (
            "/response/result/lifecycle/bundle/commitment/entry_merkle_root",
            json!("ff".repeat(32)),
        ),
        (
            "/response/result/lifecycle/bundle/commitment/app_hash",
            json!("ff".repeat(32)),
        ),
        (
            "/response/result/lifecycle/bundle/entry/metadata/block_time_ms",
            json!(1),
        ),
        ("/response/result/lifecycle/bundle/proof/leaf_index", json!(1)),
    ];
    for (pointer, replacement) in cases {
        assert_json_tamper_rejected(&encoded, &rpc_request, pointer, replacement)?;
    }
    Ok(())
}

fn assert_json_tamper_rejected(
    encoded: &[u8],
    request: &RpcRequestV2,
    pointer: &str,
    replacement: serde_json::Value,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut value: serde_json::Value = serde_json::from_slice(encoded)?;
    let field = value
        .pointer_mut(pointer)
        .ok_or_else(|| std::io::Error::other(format!("missing test field {pointer}")))?;
    *field = replacement;
    let tampered = serde_json::to_vec(&value)?;
    assert!(RpcResponseV2::from_canonical_bytes_for(tampered, request).is_err());
    Ok(())
}
