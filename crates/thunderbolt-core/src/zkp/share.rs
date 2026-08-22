use libpaillier::{unknown_order::BigNumber, Ciphertext, EncryptionKey, Nonce};
use secp::Point;

use crate::paillier::{
    add_ciphertexts, build_response_lhs, combine_response_nonce, compose_ciphertext, exponentiate_ciphertext,
    random_nonce_in_group, validate_ciphertext, validate_nonce, validate_plaintext, validate_protocol_encryption_key,
};
use crate::zkp::transcript::ProofTranscript;
use crate::zkp::types::{
    random_commitment_scalar, reduce_big_number_mod_curve_order, scalar_to_big_number, IntegerResponse, ProofContext,
    ProofTag,
};
use crate::{Result, ThunderboltError};

#[derive(Clone, Debug)]
pub struct ShareEncryptionStatement {
    pub context: ProofContext,
    pub anchor_base: Point,
    pub recipient_key: EncryptionKey,
    pub member_id: u32,
    pub committed_point: Point,
    pub ciphertext: Ciphertext,
}

#[derive(Clone, Debug)]
pub struct ShareEncryptionWitness {
    pub secret: secp::Scalar,
    pub nonce: Nonce,
}

#[derive(Clone, Debug)]
pub struct ShareEncryptionProof {
    pub a_point: Point,
    pub a_ciphertext: Ciphertext,
    pub z: BigNumber,
    pub tau: Nonce,
}

fn share_challenge(
    statement: &ShareEncryptionStatement,
    a_point: &Point,
    a_ciphertext: &Ciphertext,
) -> crate::zkp::types::ChallengeValue {
    let mut transcript = ProofTranscript::new(ProofTag::ShareEncryption);
    transcript.append_context(&statement.context);
    transcript.append_point(b"H", &statement.anchor_base);
    transcript.append_key(b"pk_i", &statement.recipient_key);
    transcript.append_u32(b"member_id", statement.member_id);
    transcript.append_point(b"S_i", &statement.committed_point);
    transcript.append_ciphertext(b"ct_i", &statement.ciphertext);
    transcript.append_point(b"A_S", a_point);
    transcript.append_ciphertext(b"A_ct", a_ciphertext);
    transcript.challenge()
}

fn validate_statement(statement: &ShareEncryptionStatement) -> Result<()> {
    statement.context.expect_invoice()?;
    validate_protocol_encryption_key(&statement.recipient_key)?;
    validate_ciphertext(&statement.recipient_key, &statement.ciphertext)?;
    Ok(())
}

pub fn prove_share_encryption(
    statement: &ShareEncryptionStatement,
    witness: &ShareEncryptionWitness,
) -> Result<ShareEncryptionProof> {
    validate_statement(statement)?;
    validate_nonce(&statement.recipient_key, &witness.nonce)?;

    let secret_bn = scalar_to_big_number(witness.secret);
    validate_plaintext(&statement.recipient_key, &secret_bn)?;

    let expected_point = statement.anchor_base * witness.secret;
    if expected_point != statement.committed_point {
        return Err(ThunderboltError::InvalidParameter(
            "share witness does not open the committed elliptic-curve point".to_string(),
        ));
    }

    let expected_ciphertext = compose_ciphertext(&statement.recipient_key, &secret_bn, &witness.nonce)?;
    if expected_ciphertext != statement.ciphertext {
        return Err(ThunderboltError::InvalidParameter(
            "share witness does not open the Paillier ciphertext".to_string(),
        ));
    }

    let alpha_bn = random_commitment_scalar();
    let alpha_scalar = reduce_big_number_mod_curve_order(&alpha_bn)?
        .not_zero()
        .map_err(|_| ThunderboltError::CryptographicError("commitment scalar reduced to zero mod q".to_string()))?;
    let beta = random_nonce_in_group(&statement.recipient_key);
    let a_point = statement.anchor_base * alpha_scalar;
    let a_ciphertext = compose_ciphertext(&statement.recipient_key, &alpha_bn, &beta)?;

    let challenge = share_challenge(statement, &a_point, &a_ciphertext);
    let response = IntegerResponse::from_linear_relation(&alpha_bn, challenge.integer(), witness.secret)?;
    let tau = combine_response_nonce(&statement.recipient_key, &beta, &witness.nonce, challenge.integer())?;

    Ok(ShareEncryptionProof {
        a_point,
        a_ciphertext,
        z: response.integer().clone(),
        tau,
    })
}

pub fn verify_share_encryption(statement: &ShareEncryptionStatement, proof: &ShareEncryptionProof) -> Result<()> {
    validate_statement(statement)?;
    validate_ciphertext(&statement.recipient_key, &proof.a_ciphertext)?;
    validate_nonce(&statement.recipient_key, &proof.tau)?;

    let challenge = share_challenge(statement, &proof.a_point, &proof.a_ciphertext);
    let response = IntegerResponse::new(proof.z.clone())?;

    let lhs_ec = statement.anchor_base * response.scalar_mod_q();
    let rhs_ec = proof.a_point + statement.committed_point * challenge.scalar();
    if lhs_ec != rhs_ec {
        return Err(ThunderboltError::InvalidProof(
            "share-encryption EC equation failed".to_string(),
        ));
    }

    let lhs_ciphertext = build_response_lhs(&statement.recipient_key, response.integer(), &proof.tau)?;
    let rhs_ciphertext = add_ciphertexts(
        &statement.recipient_key,
        &proof.a_ciphertext,
        &exponentiate_ciphertext(&statement.recipient_key, &statement.ciphertext, challenge.integer())?,
    )?;
    if lhs_ciphertext != rhs_ciphertext {
        return Err(ThunderboltError::InvalidProof(
            "share-encryption Paillier equation failed".to_string(),
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::paillier::{decrypt_to_big_number, encrypt_plaintext};
    use libpaillier::DecryptionKey;

    fn scalar_from_u8(value: u8) -> secp::Scalar {
        let mut bytes = [0u8; 32];
        bytes[31] = value;
        secp::Scalar::from_slice(&bytes).unwrap()
    }

    #[test]
    fn share_encryption_round_trips() {
        let sk = DecryptionKey::random().unwrap();
        let pk = EncryptionKey::from(&sk);
        let anchor_base = scalar_from_u8(11).base_point_mul();
        let secret = scalar_from_u8(7);
        let nonce = random_nonce_in_group(&pk);
        let ciphertext = encrypt_plaintext(&pk, &scalar_to_big_number(secret), &nonce).unwrap();
        let statement = ShareEncryptionStatement {
            context: ProofContext::invoice(b"ctx", b"invoice"),
            anchor_base,
            recipient_key: pk.clone(),
            member_id: 1,
            committed_point: anchor_base * secret,
            ciphertext: ciphertext.clone(),
        };
        let witness = ShareEncryptionWitness { secret, nonce };

        let proof = prove_share_encryption(&statement, &witness).unwrap();
        verify_share_encryption(&statement, &proof).unwrap();
        assert_eq!(
            decrypt_to_big_number(&sk, &ciphertext).unwrap(),
            scalar_to_big_number(secret)
        );
    }

    #[test]
    fn share_encryption_rejects_member_binding_changes() {
        let sk = DecryptionKey::random().unwrap();
        let pk = EncryptionKey::from(&sk);
        let anchor_base = scalar_from_u8(13).base_point_mul();
        let secret = scalar_from_u8(9);
        let nonce = random_nonce_in_group(&pk);
        let statement = ShareEncryptionStatement {
            context: ProofContext::invoice(b"ctx", b"invoice"),
            anchor_base,
            recipient_key: pk.clone(),
            member_id: 2,
            committed_point: anchor_base * secret,
            ciphertext: compose_ciphertext(&pk, &scalar_to_big_number(secret), &nonce).unwrap(),
        };
        let proof = prove_share_encryption(&statement, &ShareEncryptionWitness { secret, nonce }).unwrap();

        let tampered = ShareEncryptionStatement {
            member_id: 3,
            ..statement
        };
        assert!(verify_share_encryption(&tampered, &proof).is_err());
    }
}
