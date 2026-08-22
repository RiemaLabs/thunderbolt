use libpaillier::{unknown_order::BigNumber, Ciphertext, EncryptionKey, Nonce};
use secp::{Point, Scalar};

use crate::paillier::{
    add_ciphertexts, build_response_lhs, combine_response_nonce, compose_ciphertext, encrypt_plaintext,
    exponentiate_ciphertext, random_nonce_in_group, validate_ciphertext, validate_nonce, validate_plaintext,
    validate_protocol_encryption_key,
};
use crate::zkp::transcript::ProofTranscript;
use crate::zkp::types::{
    random_commitment_scalar, reduce_big_number_mod_curve_order, scalar_to_big_number, IntegerResponse, ProofContext,
    ProofTag,
};
use crate::{Result, ThunderboltError};

#[derive(Clone, Debug)]
pub struct InvoiceStatement {
    pub context: ProofContext,
    pub anchor_base: Point,
    pub bob_key: EncryptionKey,
    pub committee_key: EncryptionKey,
    pub delta: Point,
    pub bob_ciphertext: Ciphertext,
    pub committee_ciphertext: Ciphertext,
}

#[derive(Clone, Debug)]
pub struct InvoiceWitness {
    pub refresh: Scalar,
    pub bob_nonce: Nonce,
    pub committee_nonce: Nonce,
}

#[derive(Clone, Debug)]
pub struct InvoiceProof {
    pub a_delta: Point,
    pub a_bob: Ciphertext,
    pub a_committee: Ciphertext,
    pub z: BigNumber,
    pub tau_bob: Nonce,
    pub tau_committee: Nonce,
}

fn validate_statement(statement: &InvoiceStatement) -> Result<()> {
    statement.context.expect_invoice()?;
    validate_protocol_encryption_key(&statement.bob_key)?;
    validate_protocol_encryption_key(&statement.committee_key)?;
    validate_ciphertext(&statement.bob_key, &statement.bob_ciphertext)?;
    validate_ciphertext(&statement.committee_key, &statement.committee_ciphertext)?;
    Ok(())
}

fn invoice_challenge(
    statement: &InvoiceStatement,
    a_delta: &Point,
    a_bob: &Ciphertext,
    a_committee: &Ciphertext,
) -> crate::zkp::types::ChallengeValue {
    let mut transcript = ProofTranscript::new(ProofTag::Invoice);
    transcript.append_context(&statement.context);
    transcript.append_point(b"H", &statement.anchor_base);
    transcript.append_key(b"pk_B", &statement.bob_key);
    transcript.append_key(b"pk_C", &statement.committee_key);
    transcript.append_point(b"D_s", &statement.delta);
    transcript.append_ciphertext(b"ct_B", &statement.bob_ciphertext);
    transcript.append_ciphertext(b"ct_C", &statement.committee_ciphertext);
    transcript.append_point(b"A_D", a_delta);
    transcript.append_ciphertext(b"A_B", a_bob);
    transcript.append_ciphertext(b"A_C", a_committee);
    transcript.challenge()
}

pub fn prove_invoice(statement: &InvoiceStatement, witness: &InvoiceWitness) -> Result<InvoiceProof> {
    validate_statement(statement)?;
    validate_nonce(&statement.bob_key, &witness.bob_nonce)?;
    validate_nonce(&statement.committee_key, &witness.committee_nonce)?;

    let refresh = scalar_to_big_number(witness.refresh);
    validate_plaintext(&statement.bob_key, &refresh)?;
    validate_plaintext(&statement.committee_key, &refresh)?;

    let expected_delta = statement.anchor_base * witness.refresh;
    if expected_delta != statement.delta {
        return Err(ThunderboltError::InvalidParameter(
            "invoice witness does not open the public delta D_s".to_string(),
        ));
    }

    let expected_bob = encrypt_plaintext(&statement.bob_key, &refresh, &witness.bob_nonce)?;
    if expected_bob != statement.bob_ciphertext {
        return Err(ThunderboltError::InvalidParameter(
            "invoice witness does not open Bob's ciphertext".to_string(),
        ));
    }

    let expected_committee = encrypt_plaintext(&statement.committee_key, &refresh, &witness.committee_nonce)?;
    if expected_committee != statement.committee_ciphertext {
        return Err(ThunderboltError::InvalidParameter(
            "invoice witness does not open the committee ciphertext".to_string(),
        ));
    }

    let alpha_bn = random_commitment_scalar();
    let alpha_scalar = reduce_big_number_mod_curve_order(&alpha_bn)?
        .not_zero()
        .map_err(|_| ThunderboltError::CryptographicError("commitment scalar reduced to zero mod q".to_string()))?;
    let beta_bob = random_nonce_in_group(&statement.bob_key);
    let beta_committee = random_nonce_in_group(&statement.committee_key);

    let a_delta = statement.anchor_base * alpha_scalar;
    let a_bob = compose_ciphertext(&statement.bob_key, &alpha_bn, &beta_bob)?;
    let a_committee = compose_ciphertext(&statement.committee_key, &alpha_bn, &beta_committee)?;

    let challenge = invoice_challenge(statement, &a_delta, &a_bob, &a_committee);
    let response = IntegerResponse::from_linear_relation(&alpha_bn, challenge.integer(), witness.refresh)?;
    let tau_bob = combine_response_nonce(&statement.bob_key, &beta_bob, &witness.bob_nonce, challenge.integer())?;
    let tau_committee = combine_response_nonce(
        &statement.committee_key,
        &beta_committee,
        &witness.committee_nonce,
        challenge.integer(),
    )?;

    Ok(InvoiceProof {
        a_delta,
        a_bob,
        a_committee,
        z: response.integer().clone(),
        tau_bob,
        tau_committee,
    })
}

pub fn verify_invoice(statement: &InvoiceStatement, proof: &InvoiceProof) -> Result<()> {
    validate_statement(statement)?;
    validate_ciphertext(&statement.bob_key, &proof.a_bob)?;
    validate_ciphertext(&statement.committee_key, &proof.a_committee)?;
    validate_nonce(&statement.bob_key, &proof.tau_bob)?;
    validate_nonce(&statement.committee_key, &proof.tau_committee)?;

    let challenge = invoice_challenge(statement, &proof.a_delta, &proof.a_bob, &proof.a_committee);
    let response = IntegerResponse::new(proof.z.clone())?;

    let lhs_ec = statement.anchor_base * response.scalar_mod_q();
    let rhs_ec = proof.a_delta + statement.delta * challenge.scalar();
    if lhs_ec != rhs_ec {
        return Err(ThunderboltError::InvalidProof(
            "invoice EC equation zH = A_D + cD_s failed".to_string(),
        ));
    }

    let lhs_bob = build_response_lhs(&statement.bob_key, response.integer(), &proof.tau_bob)?;
    let rhs_bob = add_ciphertexts(
        &statement.bob_key,
        &proof.a_bob,
        &exponentiate_ciphertext(&statement.bob_key, &statement.bob_ciphertext, challenge.integer())?,
    )?;
    if lhs_bob != rhs_bob {
        return Err(ThunderboltError::InvalidProof(
            "invoice Bob Paillier equation failed".to_string(),
        ));
    }

    let lhs_committee = build_response_lhs(&statement.committee_key, response.integer(), &proof.tau_committee)?;
    let rhs_committee = add_ciphertexts(
        &statement.committee_key,
        &proof.a_committee,
        &exponentiate_ciphertext(
            &statement.committee_key,
            &statement.committee_ciphertext,
            challenge.integer(),
        )?,
    )?;
    if lhs_committee != rhs_committee {
        return Err(ThunderboltError::InvalidProof(
            "invoice committee Paillier equation failed".to_string(),
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::paillier::{decrypt_to_big_number, random_nonce_in_group};
    use libpaillier::DecryptionKey;

    fn scalar_from_u8(value: u8) -> Scalar {
        let mut bytes = [0u8; 32];
        bytes[31] = value;
        Scalar::from_slice(&bytes).unwrap()
    }

    #[test]
    fn invoice_round_trips() {
        let bob_sk = DecryptionKey::random().unwrap();
        let bob_key = EncryptionKey::from(&bob_sk);
        let committee_sk = DecryptionKey::random().unwrap();
        let committee_key = EncryptionKey::from(&committee_sk);

        let anchor_base = scalar_from_u8(41).base_point_mul();
        let refresh = scalar_from_u8(7);
        let refresh_bn = scalar_to_big_number(refresh);
        let bob_nonce = random_nonce_in_group(&bob_key);
        let committee_nonce = random_nonce_in_group(&committee_key);
        let bob_ciphertext = encrypt_plaintext(&bob_key, &refresh_bn, &bob_nonce).unwrap();
        let committee_ciphertext = encrypt_plaintext(&committee_key, &refresh_bn, &committee_nonce).unwrap();
        let statement = InvoiceStatement {
            context: ProofContext::invoice(b"ctx", b"invoice"),
            anchor_base,
            bob_key: bob_key.clone(),
            committee_key: committee_key.clone(),
            delta: anchor_base * refresh,
            bob_ciphertext: bob_ciphertext.clone(),
            committee_ciphertext: committee_ciphertext.clone(),
        };
        let witness = InvoiceWitness {
            refresh,
            bob_nonce,
            committee_nonce,
        };

        let proof = prove_invoice(&statement, &witness).unwrap();
        verify_invoice(&statement, &proof).unwrap();
        assert_eq!(decrypt_to_big_number(&bob_sk, &bob_ciphertext).unwrap(), refresh_bn);
    }

    #[test]
    fn invoice_rejects_wrong_domain_binding() {
        let bob_sk = DecryptionKey::random().unwrap();
        let bob_key = EncryptionKey::from(&bob_sk);
        let committee_sk = DecryptionKey::random().unwrap();
        let committee_key = EncryptionKey::from(&committee_sk);

        let anchor_base = scalar_from_u8(29).base_point_mul();
        let refresh = scalar_from_u8(5);
        let refresh_bn = scalar_to_big_number(refresh);
        let bob_nonce = random_nonce_in_group(&bob_key);
        let committee_nonce = random_nonce_in_group(&committee_key);
        let statement = InvoiceStatement {
            context: ProofContext::invoice(b"ctx", b"invoice"),
            anchor_base,
            bob_key: bob_key.clone(),
            committee_key: committee_key.clone(),
            delta: anchor_base * refresh,
            bob_ciphertext: encrypt_plaintext(&bob_key, &refresh_bn, &bob_nonce).unwrap(),
            committee_ciphertext: encrypt_plaintext(&committee_key, &refresh_bn, &committee_nonce).unwrap(),
        };
        let witness = InvoiceWitness {
            refresh,
            bob_nonce,
            committee_nonce,
        };

        let proof = prove_invoice(&statement, &witness).unwrap();
        verify_invoice(&statement, &proof).unwrap();

        let tampered = InvoiceStatement {
            context: ProofContext::invoice(b"other-ctx", b"invoice"),
            ..statement.clone()
        };
        assert!(verify_invoice(&tampered, &proof).is_err());
    }

    #[test]
    fn invoice_rejects_mismatched_committee_ciphertext() {
        let bob_sk = DecryptionKey::random().unwrap();
        let bob_key = EncryptionKey::from(&bob_sk);
        let committee_sk = DecryptionKey::random().unwrap();
        let committee_key = EncryptionKey::from(&committee_sk);

        let anchor_base = scalar_from_u8(23).base_point_mul();
        let refresh = scalar_from_u8(8);
        let refresh_bn = scalar_to_big_number(refresh);
        let bob_nonce = random_nonce_in_group(&bob_key);
        let committee_nonce = random_nonce_in_group(&committee_key);
        let statement = InvoiceStatement {
            context: ProofContext::invoice(b"ctx", b"invoice"),
            anchor_base,
            bob_key: bob_key.clone(),
            committee_key: committee_key.clone(),
            delta: anchor_base * refresh,
            bob_ciphertext: encrypt_plaintext(&bob_key, &refresh_bn, &bob_nonce).unwrap(),
            committee_ciphertext: encrypt_plaintext(&committee_key, &refresh_bn, &committee_nonce).unwrap(),
        };
        let witness = InvoiceWitness {
            refresh,
            bob_nonce,
            committee_nonce,
        };
        let proof = prove_invoice(&statement, &witness).unwrap();

        let wrong_refresh = scalar_to_big_number(scalar_from_u8(9));
        let wrong_nonce = random_nonce_in_group(&committee_key);
        let tampered = InvoiceStatement {
            committee_ciphertext: encrypt_plaintext(&committee_key, &wrong_refresh, &wrong_nonce).unwrap(),
            ..statement.clone()
        };
        assert!(verify_invoice(&tampered, &proof).is_err());
    }
}
