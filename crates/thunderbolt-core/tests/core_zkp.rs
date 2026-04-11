use libpaillier::{unknown_order::BigNumber, DecryptionKey, EncryptionKey};
use secp::Scalar;
use thunderbolt_core::paillier::{
    add_ciphertexts, decrypt_to_big_number, encrypt_plaintext, random_nonce_in_group, subtract_ciphertexts,
};
use thunderbolt_core::zkp::{
    prove_invoice, prove_transfer, verify_anchor_transition, verify_invoice, verify_transfer, InvoiceStatement,
    InvoiceWitness, ProofContext, TransferStatement, TransferWitness,
};

fn scalar_from_u8(value: u8) -> Scalar {
    let mut bytes = [0u8; 32];
    bytes[31] = value;
    Scalar::from_slice(&bytes).unwrap()
}

fn scalar_bn(scalar: Scalar) -> BigNumber {
    BigNumber::from_slice(scalar.serialize())
}

#[test]
fn invoice_and_transfer_flow_round_trips() {
    let bob_sk = DecryptionKey::random().unwrap();
    let bob_key = EncryptionKey::from(&bob_sk);
    let committee_sk = DecryptionKey::random().unwrap();
    let committee_key = EncryptionKey::from(&committee_sk);

    let anchor_base = scalar_from_u8(42).base_point_mul();
    let refresh = scalar_from_u8(7);
    let holder_secret = scalar_from_u8(11);
    let refresh_bn = scalar_bn(refresh);
    let holder_bn = scalar_bn(holder_secret);

    let bob_invoice_nonce = random_nonce_in_group(&bob_key);
    let committee_invoice_nonce = random_nonce_in_group(&committee_key);
    let invoice_statement = InvoiceStatement {
        context: ProofContext::invoice(b"ctx-1", b"invoice-1"),
        anchor_base,
        bob_key: bob_key.clone(),
        committee_key: committee_key.clone(),
        delta: anchor_base * refresh,
        bob_ciphertext: encrypt_plaintext(&bob_key, &refresh_bn, &bob_invoice_nonce).unwrap(),
        committee_ciphertext: encrypt_plaintext(&committee_key, &refresh_bn, &committee_invoice_nonce).unwrap(),
    };
    let invoice_witness = InvoiceWitness {
        refresh,
        bob_nonce: bob_invoice_nonce,
        committee_nonce: committee_invoice_nonce,
    };
    let invoice_proof = prove_invoice(&invoice_statement, &invoice_witness).unwrap();
    verify_invoice(&invoice_statement, &invoice_proof).unwrap();

    let holder_nonce = random_nonce_in_group(&bob_key);
    let current_anchor = anchor_base * holder_secret;
    let holder_component = encrypt_plaintext(&bob_key, &holder_bn, &holder_nonce).unwrap();
    let next_holder_ciphertext =
        add_ciphertexts(&bob_key, &holder_component, &invoice_statement.bob_ciphertext).unwrap();
    let transfer_statement = TransferStatement {
        context: ProofContext::transfer(b"ctx-1", 1, b"invoice-1"),
        anchor_base,
        bob_key: bob_key.clone(),
        current_anchor,
        invoice_ciphertext: invoice_statement.bob_ciphertext.clone(),
        next_holder_ciphertext: next_holder_ciphertext.clone(),
    };
    let transfer_witness = TransferWitness {
        holder_secret,
        holder_nonce,
    };
    let transfer_proof = prove_transfer(&transfer_statement, &transfer_witness).unwrap();
    verify_transfer(&transfer_statement, &transfer_proof).unwrap();

    let next_anchor = (current_anchor + invoice_statement.delta).unwrap();
    verify_anchor_transition(&current_anchor, &invoice_statement.delta, &next_anchor).unwrap();

    let decrypted = decrypt_to_big_number(&bob_sk, &next_holder_ciphertext).unwrap();
    assert_eq!(decrypted, holder_bn + refresh_bn);
}

#[test]
fn invoice_verification_fails_when_bound_identifier_changes() {
    let bob_sk = DecryptionKey::random().unwrap();
    let bob_key = EncryptionKey::from(&bob_sk);
    let committee_sk = DecryptionKey::random().unwrap();
    let committee_key = EncryptionKey::from(&committee_sk);

    let anchor_base = scalar_from_u8(17).base_point_mul();
    let refresh = scalar_from_u8(3);
    let refresh_bn = scalar_bn(refresh);
    let bob_nonce = random_nonce_in_group(&bob_key);
    let committee_nonce = random_nonce_in_group(&committee_key);
    let statement = InvoiceStatement {
        context: ProofContext::invoice(b"ctx-2", b"invoice-9"),
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

    let changed_ctx = InvoiceStatement {
        context: ProofContext::invoice(b"ctx-3", b"invoice-9"),
        ..statement.clone()
    };
    assert!(verify_invoice(&changed_ctx, &proof).is_err());

    let changed_inv_id = InvoiceStatement {
        context: ProofContext::invoice(b"ctx-2", b"invoice-10"),
        ..statement
    };
    assert!(verify_invoice(&changed_inv_id, &proof).is_err());
}

#[test]
fn transfer_verification_fails_when_step_or_ciphertext_binding_changes() {
    let bob_sk = DecryptionKey::random().unwrap();
    let bob_key = EncryptionKey::from(&bob_sk);

    let anchor_base = scalar_from_u8(25).base_point_mul();
    let refresh = scalar_from_u8(6);
    let holder_secret = scalar_from_u8(9);
    let refresh_bn = scalar_bn(refresh);
    let holder_bn = scalar_bn(holder_secret);
    let invoice_nonce = random_nonce_in_group(&bob_key);
    let holder_nonce = random_nonce_in_group(&bob_key);
    let invoice_ciphertext = encrypt_plaintext(&bob_key, &refresh_bn, &invoice_nonce).unwrap();
    let holder_component = encrypt_plaintext(&bob_key, &holder_bn, &holder_nonce).unwrap();
    let next_holder_ciphertext = add_ciphertexts(&bob_key, &holder_component, &invoice_ciphertext).unwrap();
    let statement = TransferStatement {
        context: ProofContext::transfer(b"ctx-4", 4, b"invoice-22"),
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

    let changed_step = TransferStatement {
        context: ProofContext::transfer(b"ctx-4", 5, b"invoice-22"),
        ..statement.clone()
    };
    assert!(verify_transfer(&changed_step, &proof).is_err());

    let tampered_ciphertext = add_ciphertexts(&bob_key, &next_holder_ciphertext, &invoice_ciphertext).unwrap();
    let changed_ciphertext = TransferStatement {
        next_holder_ciphertext: tampered_ciphertext,
        ..statement
    };
    assert!(verify_transfer(&changed_ciphertext, &proof).is_err());
}

#[test]
fn malformed_paillier_ciphertext_is_rejected() {
    let bob_sk = DecryptionKey::random().unwrap();
    let bob_key = EncryptionKey::from(&bob_sk);
    let nonce = random_nonce_in_group(&bob_key);
    let ciphertext = encrypt_plaintext(&bob_key, &BigNumber::from(12u32), &nonce).unwrap();

    assert!(subtract_ciphertexts(&bob_key, &ciphertext, &BigNumber::zero()).is_err());
}
