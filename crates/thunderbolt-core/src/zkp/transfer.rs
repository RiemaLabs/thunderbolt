use bitcoin::key::rand::thread_rng;
use libpaillier::{unknown_order::BigNumber, Ciphertext, EncryptionKey, Nonce};
use secp::{MaybePoint, Point, Scalar};

use crate::paillier::{
    add_ciphertexts, build_response_lhs, combine_response_nonce, compose_ciphertext, encrypt_plaintext,
    exponentiate_ciphertext, random_nonce_in_group, subtract_ciphertexts, validate_ciphertext, validate_nonce,
    validate_plaintext,
};
use crate::zkp::transcript::ProofTranscript;
use crate::zkp::types::{scalar_to_big_number, IntegerResponse, ProofContext, ProofTag};
use crate::{Result, ThunderboltError};

#[derive(Clone, Debug)]
pub struct TransferStatement {
    pub context: ProofContext,
    pub anchor_base: Point,
    pub bob_key: EncryptionKey,
    pub current_anchor: Point,
    pub invoice_ciphertext: Ciphertext,
    pub next_holder_ciphertext: Ciphertext,
}

#[derive(Clone, Debug)]
pub struct TransferWitness {
    pub holder_secret: Scalar,
    pub holder_nonce: Nonce,
}

#[derive(Clone, Debug)]
pub struct TransferProof {
    pub a_anchor: Point,
    pub a_ciphertext: Ciphertext,
    pub z: BigNumber,
    pub tau: Nonce,
}

fn validate_statement(statement: &TransferStatement) -> Result<()> {
    statement.context.expect_transfer()?;
    validate_ciphertext(&statement.bob_key, &statement.invoice_ciphertext)?;
    validate_ciphertext(&statement.bob_key, &statement.next_holder_ciphertext)?;
    Ok(())
}

fn transfer_challenge(
    statement: &TransferStatement,
    a_anchor: &Point,
    a_ciphertext: &Ciphertext,
) -> crate::zkp::types::ChallengeValue {
    let mut transcript = ProofTranscript::new(ProofTag::Transfer);
    transcript.append_context(&statement.context);
    transcript.append_point(b"H", &statement.anchor_base);
    transcript.append_key(b"pk_B", &statement.bob_key);
    transcript.append_point(b"X_s", &statement.current_anchor);
    transcript.append_ciphertext(b"ct_B", &statement.invoice_ciphertext);
    transcript.append_ciphertext(b"T_next", &statement.next_holder_ciphertext);
    transcript.append_point(b"A_X", a_anchor);
    transcript.append_ciphertext(b"A_T", a_ciphertext);
    transcript.challenge()
}

pub fn prove_transfer(statement: &TransferStatement, witness: &TransferWitness) -> Result<TransferProof> {
    validate_statement(statement)?;
    validate_nonce(&statement.bob_key, &witness.holder_nonce)?;

    let holder_secret = scalar_to_big_number(witness.holder_secret);
    validate_plaintext(&statement.bob_key, &holder_secret)?;

    let expected_anchor = statement.anchor_base * witness.holder_secret;
    if expected_anchor != statement.current_anchor {
        return Err(ThunderboltError::InvalidParameter(
            "transfer witness does not open the current anchor X_s".to_string(),
        ));
    }

    let holder_component = encrypt_plaintext(&statement.bob_key, &holder_secret, &witness.holder_nonce)?;
    let expected_next = add_ciphertexts(&statement.bob_key, &holder_component, &statement.invoice_ciphertext)?;
    if expected_next != statement.next_holder_ciphertext {
        return Err(ThunderboltError::InvalidParameter(
            "transfer witness does not open T_{s+1} ⊖ ct_B".to_string(),
        ));
    }

    let alpha = Scalar::random(&mut thread_rng());
    let alpha_bn = scalar_to_big_number(alpha);
    let beta = random_nonce_in_group(&statement.bob_key);

    let a_anchor = statement.anchor_base * alpha;
    let a_ciphertext = compose_ciphertext(&statement.bob_key, &alpha_bn, &beta)?;

    let challenge = transfer_challenge(statement, &a_anchor, &a_ciphertext);
    let response = IntegerResponse::from_linear_relation(alpha, challenge.integer(), witness.holder_secret)?;
    let tau = combine_response_nonce(&statement.bob_key, &beta, &witness.holder_nonce, challenge.integer())?;

    Ok(TransferProof {
        a_anchor,
        a_ciphertext,
        z: response.integer().clone(),
        tau,
    })
}

pub fn verify_transfer(statement: &TransferStatement, proof: &TransferProof) -> Result<()> {
    validate_statement(statement)?;
    validate_ciphertext(&statement.bob_key, &proof.a_ciphertext)?;
    validate_nonce(&statement.bob_key, &proof.tau)?;

    let challenge = transfer_challenge(statement, &proof.a_anchor, &proof.a_ciphertext);
    let response = IntegerResponse::new(proof.z.clone())?;

    let lhs_ec = statement.anchor_base * response.scalar_mod_q();
    let rhs_ec = proof.a_anchor + statement.current_anchor * challenge.scalar();
    if lhs_ec != rhs_ec {
        return Err(ThunderboltError::InvalidProof(
            "transfer EC equation zH = A_X + cX_s failed".to_string(),
        ));
    }

    let offset_ciphertext = subtract_ciphertexts(
        &statement.bob_key,
        &statement.next_holder_ciphertext,
        &statement.invoice_ciphertext,
    )?;
    let lhs_ciphertext = build_response_lhs(&statement.bob_key, response.integer(), &proof.tau)?;
    let rhs_ciphertext = add_ciphertexts(
        &statement.bob_key,
        &proof.a_ciphertext,
        &exponentiate_ciphertext(&statement.bob_key, &offset_ciphertext, challenge.integer())?,
    )?;
    if lhs_ciphertext != rhs_ciphertext {
        return Err(ThunderboltError::InvalidProof(
            "transfer Paillier equation failed".to_string(),
        ));
    }

    Ok(())
}

pub fn verify_anchor_transition(current_anchor: &Point, delta: &Point, next_anchor: &Point) -> Result<()> {
    let expected_next = *current_anchor + *delta;
    if expected_next != MaybePoint::Valid(*next_anchor) {
        return Err(ThunderboltError::InvalidStateTransition(
            "anchor transition X_{s+1} = X_s + D_s failed".to_string(),
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
    fn transfer_round_trips() {
        let bob_sk = DecryptionKey::random().unwrap();
        let bob_key = EncryptionKey::from(&bob_sk);
        let anchor_base = scalar_from_u8(37).base_point_mul();
        let holder_secret = scalar_from_u8(11);
        let refresh = scalar_from_u8(5);
        let holder_bn = scalar_to_big_number(holder_secret);
        let refresh_bn = scalar_to_big_number(refresh);
        let invoice_nonce = random_nonce_in_group(&bob_key);
        let holder_nonce = random_nonce_in_group(&bob_key);
        let invoice_ciphertext = encrypt_plaintext(&bob_key, &refresh_bn, &invoice_nonce).unwrap();
        let holder_component = encrypt_plaintext(&bob_key, &holder_bn, &holder_nonce).unwrap();
        let next_holder_ciphertext = add_ciphertexts(&bob_key, &holder_component, &invoice_ciphertext).unwrap();
        let statement = TransferStatement {
            context: ProofContext::transfer(b"ctx", 1, b"invoice"),
            anchor_base,
            bob_key: bob_key.clone(),
            current_anchor: anchor_base * holder_secret,
            invoice_ciphertext: invoice_ciphertext.clone(),
            next_holder_ciphertext: next_holder_ciphertext.clone(),
        };
        let witness = TransferWitness {
            holder_secret,
            holder_nonce,
        };

        let proof = prove_transfer(&statement, &witness).unwrap();
        verify_transfer(&statement, &proof).unwrap();
        let decrypted = decrypt_to_big_number(&bob_sk, &next_holder_ciphertext).unwrap();
        assert_eq!(decrypted, holder_bn + refresh_bn);
    }

    #[test]
    fn transfer_rejects_step_binding_changes() {
        let bob_sk = DecryptionKey::random().unwrap();
        let bob_key = EncryptionKey::from(&bob_sk);
        let anchor_base = scalar_from_u8(31).base_point_mul();
        let holder_secret = scalar_from_u8(9);
        let refresh = scalar_from_u8(4);
        let holder_bn = scalar_to_big_number(holder_secret);
        let refresh_bn = scalar_to_big_number(refresh);
        let invoice_nonce = random_nonce_in_group(&bob_key);
        let holder_nonce = random_nonce_in_group(&bob_key);
        let invoice_ciphertext = encrypt_plaintext(&bob_key, &refresh_bn, &invoice_nonce).unwrap();
        let holder_component = encrypt_plaintext(&bob_key, &holder_bn, &holder_nonce).unwrap();
        let next_holder_ciphertext = add_ciphertexts(&bob_key, &holder_component, &invoice_ciphertext).unwrap();
        let statement = TransferStatement {
            context: ProofContext::transfer(b"ctx", 1, b"invoice"),
            anchor_base,
            bob_key: bob_key.clone(),
            current_anchor: anchor_base * holder_secret,
            invoice_ciphertext,
            next_holder_ciphertext,
        };
        let witness = TransferWitness {
            holder_secret,
            holder_nonce,
        };
        let proof = prove_transfer(&statement, &witness).unwrap();
        verify_transfer(&statement, &proof).unwrap();

        let tampered = TransferStatement {
            context: ProofContext::transfer(b"ctx", 2, b"invoice"),
            ..statement.clone()
        };
        assert!(verify_transfer(&tampered, &proof).is_err());
    }

    #[test]
    fn anchor_transition_is_a_separate_public_check() {
        let anchor_base = scalar_from_u8(19).base_point_mul();
        let current = anchor_base * scalar_from_u8(3);
        let delta = anchor_base * scalar_from_u8(5);
        let next = (current + delta).unwrap();

        verify_anchor_transition(&current, &delta, &next).unwrap();
        assert!(verify_anchor_transition(&current, &delta, &current).is_err());
    }
}
