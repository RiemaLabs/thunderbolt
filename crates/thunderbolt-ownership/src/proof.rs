use secp::{MaybeScalar, Scalar};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::{
    types::{FinalizeContextData, OwnershipWireStatementV2},
    FinalizeSigningContext, OwnershipEnvelopeV2, OwnershipError, OwnershipProofV2, OwnershipWitness, Result,
    VerifiedOwnership, OWNERSHIP_PROOF_VERSION,
};

/// Proves knowledge of exactly `x` such that the trusted context's `X = xH`.
///
/// All other context fields provide stronger domain separation only.
pub fn prove_ownership(context: &FinalizeSigningContext, witness: &OwnershipWitness) -> Result<OwnershipEnvelopeV2> {
    let nonce = random_scalar()?;
    let proof = prove_with_scalar(&context.data, witness, nonce)?;
    OwnershipEnvelopeV2::from_parts(OwnershipWireStatementV2::from_trusted(&context.data), proof)
}

/// Verifies the ownership equation only after requiring an exact match with a
/// context independently derived from authenticated Ledger state.
///
/// This is the only function that returns [`VerifiedOwnership`]. It proves no
/// closing-transaction validity, Committee authorization, or threshold
/// signature.
pub fn verify_ownership(
    expected: &FinalizeSigningContext,
    envelope: &OwnershipEnvelopeV2,
) -> Result<VerifiedOwnership> {
    if envelope.statement != OwnershipWireStatementV2::from_trusted(&expected.data) {
        return Err(OwnershipError::ContextMismatch);
    }
    verify_equation(&expected.data, envelope.proof())?;
    Ok(VerifiedOwnership {
        statement_digest: expected.data.statement_digest()?,
        snapshot_state_hash: expected.data.snapshot_state_hash,
        channel_context_id: expected.data.channel_context_id,
        step: expected.data.step,
        holder_participant: expected.data.holder_participant.clone(),
        holder_key: expected.data.holder_key.clone(),
        anchor_suite_id: expected.data.channel.anchor_parameter_suite_id.clone(),
        fixed_lock_key: expected.data.fixed_lock_key,
        anchor_base: expected.data.anchor_base,
        current_anchor: expected.data.current_anchor,
        closing_digest: expected.data.closing_digest,
    })
}

fn verify_equation(context: &FinalizeContextData, proof: &OwnershipProofV2) -> Result<()> {
    if proof.version != OWNERSHIP_PROOF_VERSION {
        return Err(OwnershipError::UnsupportedVersion);
    }
    let response = proof.response()?;
    let challenge = challenge(context, proof.commitment)?;
    let lhs = context.anchor_base * response;
    let rhs = proof.commitment + context.current_anchor * challenge;
    if lhs != rhs {
        return Err(OwnershipError::InvalidProof);
    }
    Ok(())
}

fn prove_with_scalar(
    context: &FinalizeContextData,
    witness: &OwnershipWitness,
    nonce: Scalar,
) -> Result<OwnershipProofV2> {
    let witness = witness.scalar()?;
    if context.anchor_base * witness != context.current_anchor {
        return Err(OwnershipError::WitnessMismatch);
    }
    let commitment = context.anchor_base * nonce;
    let challenge = challenge(context, commitment)?;
    let response = MaybeScalar::Valid(nonce) + challenge * witness;
    Ok(OwnershipProofV2 {
        version: OWNERSHIP_PROOF_VERSION,
        commitment,
        response: response.serialize(),
    })
}

fn challenge(context: &FinalizeContextData, commitment: secp::Point) -> Result<MaybeScalar> {
    let encoded = crate::codec::encode_transcript_context(context)?;
    let mut hasher = Sha256::new();
    hasher.update(b"bitcoin-thunderbolt/ownership-proof/v2");
    hasher.update(OWNERSHIP_PROOF_VERSION.to_be_bytes());
    hasher.update(u64::try_from(encoded.len()).unwrap_or(u64::MAX).to_be_bytes());
    hasher.update(encoded);
    hasher.update(commitment.serialize());
    Ok(MaybeScalar::reduce_from(&<[u8; 32]>::from(hasher.finalize())))
}

fn random_scalar() -> Result<Scalar> {
    let mut bytes = Zeroizing::new([0_u8; 32]);
    loop {
        getrandom::fill(bytes.as_mut()).map_err(|_| OwnershipError::RandomnessUnavailable)?;
        if let Ok(scalar) = Scalar::from_slice(bytes.as_ref()) {
            return Ok(scalar);
        }
    }
}

#[cfg(test)]
pub(crate) fn prove_context_with_nonce_bytes(
    context: FinalizeContextData,
    witness: &OwnershipWitness,
    nonce: [u8; 32],
) -> Result<OwnershipEnvelopeV2> {
    let nonce = Scalar::from_slice(&nonce).map_err(|_| OwnershipError::InvalidWitness)?;
    let proof = prove_with_scalar(&context, witness, nonce)?;
    let statement = OwnershipWireStatementV2::from_trusted(&context);
    OwnershipEnvelopeV2::from_parts(statement, proof)
}
