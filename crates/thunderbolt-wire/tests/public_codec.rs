use bitcoin::Network;
use libpaillier::{DecryptionKey, EncryptionKey};
use secp::Scalar;
use thunderbolt_core::paillier::{add_ciphertexts, encrypt_plaintext, random_nonce_in_group};
use thunderbolt_core::threshold::{create_threshold_refresh_distribution, ThresholdMemberPublicKey};
use thunderbolt_core::zkp::types::scalar_to_big_number;
use thunderbolt_core::zkp::{
    prove_invoice, prove_share_encryption, prove_transfer, InvoiceStatement, InvoiceWitness, ShareEncryptionStatement,
    ShareEncryptionWitness, TransferStatement, TransferWitness,
};
use thunderbolt_wire::{
    from_json_slice, to_json_vec, BindingContext, CanonicalDigest, CanonicalInteger, ChannelId, HexBytes,
    InvoiceEnvelopeV1, PointHex, PublicMessageV1, ShareEnvelopeV1, ShareStatementV1, ThresholdEnvelopeV1,
    TransferEnvelopeV1, ValidateWire, WireError, MAX_DEPLOYMENT_ID_BYTES, MAX_WIRE_MESSAGE_BYTES,
    PAILLIER_MODULUS_BYTES,
};

fn scalar(value: u8) -> Scalar {
    let mut bytes = [0u8; 32];
    bytes[31] = value;
    Scalar::from_slice(&bytes).expect("test scalar is in range")
}

#[test]
fn public_messages_round_trip_verify_and_reject_tampering() {
    let bob_secret_key = DecryptionKey::random().expect("generate Bob Paillier key");
    let bob_key = EncryptionKey::from(&bob_secret_key);
    let committee_secret_key = DecryptionKey::random().expect("generate committee Paillier key");
    let committee_key = EncryptionKey::from(&committee_secret_key);
    assert_eq!(bob_key.to_bytes().len(), PAILLIER_MODULUS_BYTES);
    assert_eq!(committee_key.to_bytes().len(), PAILLIER_MODULUS_BYTES);

    let invoice_binding =
        BindingContext::invoice(Network::Regtest, b"local-deployment", 7, b"channel-42", b"invoice-9")
            .expect("valid binding");
    let anchor_base = scalar(41).base_point_mul();
    let refresh = scalar(7);
    let refresh_integer = scalar_to_big_number(refresh);
    let bob_nonce = random_nonce_in_group(&bob_key);
    let committee_nonce = random_nonce_in_group(&committee_key);
    let invoice_statement = InvoiceStatement {
        context: invoice_binding.proof_context().expect("invoice proof context"),
        anchor_base,
        bob_key: bob_key.clone(),
        committee_key: committee_key.clone(),
        delta: anchor_base * refresh,
        bob_ciphertext: encrypt_plaintext(&bob_key, &refresh_integer, &bob_nonce).expect("Bob ciphertext"),
        committee_ciphertext: encrypt_plaintext(&committee_key, &refresh_integer, &committee_nonce)
            .expect("committee ciphertext"),
    };
    let invoice_proof = prove_invoice(
        &invoice_statement,
        &InvoiceWitness {
            refresh,
            bob_nonce,
            committee_nonce,
        },
    )
    .expect("invoice proof");
    let invoice = InvoiceEnvelopeV1::from_core(invoice_binding.clone(), &invoice_statement, &invoice_proof)
        .expect("invoice wire conversion");
    invoice.verify().expect("wire invoice verifies");

    let compact = to_json_vec(&invoice).expect("compact JSON");
    let compact_text = std::str::from_utf8(&compact).expect("JSON is UTF-8");
    for forbidden_field in [
        "witness",
        "decryption_key",
        "holder_secret",
        "refresh_share",
        "updated_share",
        "committee_share",
    ] {
        assert!(!compact_text.contains(forbidden_field));
    }
    let json_value: serde_json::Value = serde_json::from_slice(&compact).expect("JSON value");
    let pretty = serde_json::to_vec_pretty(&json_value).expect("pretty JSON");
    let compact_roundtrip: InvoiceEnvelopeV1 = from_json_slice(&compact).expect("compact decode");
    let pretty_roundtrip: InvoiceEnvelopeV1 = from_json_slice(&pretty).expect("pretty decode");
    assert_eq!(compact_roundtrip, invoice);
    assert_eq!(pretty_roundtrip, invoice);
    assert_eq!(
        compact_roundtrip.canonical_digest().expect("digest"),
        invoice.canonical_digest().expect("digest")
    );
    assert_eq!(
        pretty_roundtrip.canonical_digest().expect("digest"),
        invoice.canonical_digest().expect("digest")
    );

    let share_secret = scalar(13);
    let share_nonce = random_nonce_in_group(&bob_key);
    let share_statement = ShareEncryptionStatement {
        context: invoice_binding.proof_context().expect("share proof context"),
        anchor_base,
        recipient_key: bob_key.clone(),
        member_id: 1,
        committed_point: anchor_base * share_secret,
        ciphertext: encrypt_plaintext(&bob_key, &scalar_to_big_number(share_secret), &share_nonce)
            .expect("share ciphertext"),
    };
    let share_proof = prove_share_encryption(
        &share_statement,
        &ShareEncryptionWitness {
            secret: share_secret,
            nonce: share_nonce,
        },
    )
    .expect("share proof");
    let share = ShareEnvelopeV1::from_core(invoice_binding.clone(), &share_statement, &share_proof)
        .expect("share wire conversion");
    share.verify().expect("wire share verifies");
    let share_roundtrip: PublicMessageV1 =
        from_json_slice(&to_json_vec(&PublicMessageV1::Share(share.clone())).expect("share JSON"))
            .expect("share roundtrip");
    assert_eq!(share_roundtrip, PublicMessageV1::Share(share));

    let distribution = create_threshold_refresh_distribution(
        invoice_binding.proof_context().expect("threshold proof context"),
        anchor_base,
        2,
        refresh,
        &[
            ThresholdMemberPublicKey {
                member_id: 1,
                encryption_key: bob_key.clone(),
            },
            ThresholdMemberPublicKey {
                member_id: 2,
                encryption_key: committee_key.clone(),
            },
        ],
    )
    .expect("threshold distribution");
    let threshold =
        ThresholdEnvelopeV1::from_core(invoice_binding.clone(), &distribution).expect("threshold wire conversion");
    threshold.verify().expect("wire threshold distribution verifies");
    let threshold_json = to_json_vec(&threshold).expect("threshold JSON");
    let threshold_roundtrip: ThresholdEnvelopeV1 = from_json_slice(&threshold_json).expect("threshold roundtrip");
    assert_eq!(threshold_roundtrip, threshold);

    let transfer_binding =
        BindingContext::transfer(Network::Regtest, b"local-deployment", 7, b"channel-42", b"invoice-9", 1)
            .expect("transfer binding");
    let holder_secret = scalar(11);
    let holder_nonce = random_nonce_in_group(&bob_key);
    let holder_component =
        encrypt_plaintext(&bob_key, &scalar_to_big_number(holder_secret), &holder_nonce).expect("holder ciphertext");
    let next_holder_ciphertext = add_ciphertexts(&bob_key, &holder_component, &invoice_statement.bob_ciphertext)
        .expect("next-holder ciphertext");
    let current_anchor = anchor_base * holder_secret;
    let next_anchor = (current_anchor + invoice_statement.delta)
        .into_option()
        .expect("test transition is finite");
    let transfer_statement = TransferStatement {
        context: transfer_binding.proof_context().expect("transfer proof context"),
        anchor_base,
        bob_key,
        current_anchor,
        invoice_ciphertext: invoice_statement.bob_ciphertext.clone(),
        next_holder_ciphertext,
    };
    let transfer_proof = prove_transfer(
        &transfer_statement,
        &TransferWitness {
            holder_secret,
            holder_nonce,
        },
    )
    .expect("transfer proof");
    let transfer = TransferEnvelopeV1::from_core(
        transfer_binding,
        &transfer_statement,
        &transfer_proof,
        &invoice_statement.delta,
        &next_anchor,
    )
    .expect("transfer wire conversion");
    transfer.verify().expect("wire transfer and anchor transition verify");
    let transfer_roundtrip: TransferEnvelopeV1 =
        from_json_slice(&to_json_vec(&transfer).expect("transfer JSON")).expect("transfer roundtrip");
    assert_eq!(transfer_roundtrip, transfer);

    let mut changed_binding = invoice.clone();
    changed_binding.binding.channel_id =
        ChannelId::from_bytes("channel_id", b"different-channel").expect("bounded channel");
    assert!(changed_binding.verify().is_err());
    assert_ne!(
        changed_binding.canonical_digest().expect("changed digest"),
        invoice.canonical_digest().expect("original digest")
    );

    let mut changed_proof = invoice.clone();
    changed_proof.proof.a_delta =
        PointHex::from_bytes("invoice.proof.a_delta", scalar(99).base_point_mul().serialize()).expect("valid point");
    assert!(changed_proof.verify().is_err());

    let mut changed_transition = transfer.clone();
    changed_transition.anchor_transition.next_anchor =
        PointHex::from_bytes("next_anchor", scalar(87).base_point_mul().serialize()).expect("valid point");
    assert!(changed_transition.verify().is_err());

    let mut reordered_threshold = threshold;
    reordered_threshold.distribution.encrypted_shares.reverse();
    assert!(reordered_threshold.validate_wire().is_err());
}

#[test]
fn codec_rejects_oversize_noncanonical_and_invalid_crypto_encodings() {
    let oversized = vec![b' '; MAX_WIRE_MESSAGE_BYTES + 1];
    assert!(matches!(
        from_json_slice::<BindingContext>(&oversized),
        Err(WireError::MessageTooLarge { .. })
    ));

    assert!(HexBytes::<1, MAX_DEPLOYMENT_ID_BYTES>::from_bytes(
        "deployment_id",
        vec![0u8; MAX_DEPLOYMENT_ID_BYTES + 1]
    )
    .is_err());
    assert!(HexBytes::<1, 4>::from_hex("identifier", "AA").is_err());
    assert!(HexBytes::<1, 4>::from_hex("identifier", "a").is_err());
    assert!(CanonicalInteger::<4>::from_hex("integer", "0001").is_err());

    let point = PointHex::from_bytes("point", [0u8; 33]).expect("correct byte width");
    let even_key = HexBytes::<PAILLIER_MODULUS_BYTES, PAILLIER_MODULUS_BYTES>::from_bytes(
        "key",
        vec![2u8; PAILLIER_MODULUS_BYTES],
    )
    .expect("correct key width");
    let invalid_statement = ShareStatementV1 {
        anchor_base: point.clone(),
        recipient_key: even_key,
        member_id: 1,
        committed_point: point,
        ciphertext: CanonicalInteger::from_bytes("ciphertext", [1u8]).expect("canonical integer"),
    };
    assert!(invalid_statement.validate_wire().is_err());
}

#[test]
fn binding_accepts_full_outpoints_and_protocol_invoice_ids_without_truncation() {
    assert!(BindingContext::invoice(
        Network::Regtest,
        b"deployment",
        1,
        [0x11; thunderbolt_wire::MAX_CHANNEL_ID_BYTES],
        [0x22; thunderbolt_wire::MAX_INVOICE_ID_BYTES],
    )
    .is_ok());
    assert!(BindingContext::invoice(
        Network::Regtest,
        b"deployment",
        1,
        [0x11; thunderbolt_wire::MAX_CHANNEL_ID_BYTES + 1],
        b"invoice",
    )
    .is_err());
    assert!(BindingContext::invoice(
        Network::Regtest,
        b"deployment",
        1,
        b"channel",
        [0x22; thunderbolt_wire::MAX_INVOICE_ID_BYTES + 1],
    )
    .is_err());
}
