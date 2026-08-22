mod support;

use std::panic::{catch_unwind, AssertUnwindSafe};

use thunderbolt_core::zkp::production::{CertifiedKeyResolver3072, PublicKey3072, RawPublicKey3072};
use thunderbolt_core::{Result as CoreResult, ThunderboltError};
use thunderbolt_wire::{
    decode_public_message_v2, from_json_slice, threshold_invoice_package_digest_v2, to_json_vec,
    validate_threshold_package_v2, CanonicalDigest, InvoiceEnvelopeV2, PublicMessageV1, PublicMessageV2,
    ThresholdPackageBindingV2, ValidateWire, WireError, MAX_COMMITTEE_MEMBERS, MAX_WIRE_MESSAGE_BYTES,
    PAILLIER_V2_CIPHERTEXT_BYTES,
};

use support::{invoice, modulus, point, raw_hex, threshold_pair, transfer};

#[test]
fn every_v2_message_round_trips_only_as_canonical_json() {
    let invoice = invoice(3);
    let transfer = transfer(4);
    let (recipient, threshold) = threshold_pair(5, 3, 2);
    validate_threshold_package_v2(&recipient, &threshold).expect("threshold pair");
    let package_digest = threshold_invoice_package_digest_v2(&recipient, &threshold).expect("package digest");
    assert_ne!(package_digest, [0_u8; 32]);

    let messages = [
        PublicMessageV2::Invoice(invoice),
        PublicMessageV2::Transfer(transfer),
        PublicMessageV2::RecipientShare(recipient),
        PublicMessageV2::ThresholdRefresh(threshold),
    ];
    for message in messages {
        let encoded = to_json_vec(&message).expect("canonical JSON");
        let decoded = decode_public_message_v2(&encoded).expect("canonical decode");
        assert_eq!(decoded, message);
        assert_eq!(
            decoded.canonical_digest().expect("decoded digest"),
            message.canonical_digest().expect("digest")
        );

        let value: serde_json::Value = serde_json::from_slice(&encoded).expect("JSON value");
        let pretty = serde_json::to_vec_pretty(&value).expect("pretty JSON");
        assert!(matches!(
            decode_public_message_v2(&pretty),
            Err(WireError::InvalidMessage {
                message: "protocol v2 JSON",
                ..
            })
        ));
    }
}

#[test]
fn proof_context_fields_have_golden_vectors() {
    let invoice = invoice(3);
    let transfer = transfer(4);
    let (recipient, threshold) = threshold_pair(5, 3, 2);
    let invoice_context = invoice.proof_context().expect("Invoice context");
    let transfer_context = transfer.proof_context().expect("Transfer context");
    let recipient_context = recipient.proof_context().expect("Recipient context");
    let threshold_context = threshold.proof_context().expect("threshold context");
    assert_eq!(recipient_context, threshold_context);
    assert_eq!(
        hex::encode(invoice_context.ctx_id()),
        "25d79602e97498c9f5f31dc992473d4c4b45a0b600e0bcb06a6e4621834db19e"
    );
    assert_eq!(
        hex::encode(transfer_context.ctx_id()),
        "fcfbe3a9b39be810a1ec0abcdba85d3dee82a4f82bd5f4c314e74b6e3d9b4a18"
    );
    assert_eq!(
        hex::encode(recipient_context.ctx_id()),
        "5bba67ba1a65b7f34bb76cf051edd385cd1017c27a63704536ffc8f8bd83fcb8"
    );
}

#[test]
fn v2_core_ingress_requires_authenticated_keys_without_panicking_or_falling_back() {
    struct RejectingResolver;

    impl CertifiedKeyResolver3072 for RejectingResolver {
        fn resolve_certified_key(
            &self,
            _raw: &RawPublicKey3072,
            _expected_role: thunderbolt_core::zkp::CertifiedKeyRole3072,
        ) -> CoreResult<PublicKey3072> {
            Err(ThunderboltError::InvalidParameter(
                "test resolver has no authenticated certified key".to_string(),
            ))
        }
    }

    let invoice = invoice(11);
    let outcome = catch_unwind(AssertUnwindSafe(|| invoice.to_core_with_keys(&RejectingResolver)));
    let error = outcome
        .expect("raw v2 ingress must not panic")
        .expect_err("unauthenticated raw key must fail closed");
    assert_registry_gate(error);

    let transfer = transfer(12);
    let outcome = catch_unwind(AssertUnwindSafe(|| transfer.verify_with_keys(&RejectingResolver)));
    let error = outcome
        .expect("v2 transfer verification must not panic")
        .expect_err("unauthenticated transfer key must fail closed");
    assert_registry_gate(error);

    let (recipient, threshold) = threshold_pair(13, 2, 2);
    let recipient_error = recipient
        .to_core_with_keys(&RejectingResolver)
        .expect_err("Recipient ingress must require authenticated keys");
    assert_registry_gate(recipient_error);
    assert!(matches!(threshold.verify(), Err(WireError::InvalidMessage { .. })));
}

#[test]
fn malformed_cross_profile_and_nested_deserialization_are_sealed() {
    let oversized_document = vec![b' '; MAX_WIRE_MESSAGE_BYTES + 1];
    assert!(matches!(
        decode_public_message_v2(&oversized_document),
        Err(WireError::MessageTooLarge { .. })
    ));

    let invoice = invoice(21);
    let encoded = to_json_vec(&invoice).expect("invoice JSON");
    let mut value: serde_json::Value = serde_json::from_slice(&encoded).expect("invoice value");

    value["paillier_profile"] = serde_json::Value::String("legacy_rc_2048_v1".to_owned());
    assert!(decode_invoice_value(value.clone()).is_err());

    let mut missing_profile: serde_json::Value = serde_json::from_slice(&encoded).expect("invoice value");
    missing_profile
        .as_object_mut()
        .expect("invoice object")
        .remove("paillier_profile");
    assert!(decode_invoice_value(missing_profile).is_err());

    let mut zero_step: serde_json::Value = serde_json::from_slice(&encoded).expect("invoice value");
    zero_step["expected_transfer_step"] = serde_json::json!(0);
    assert!(decode_invoice_value(zero_step).is_err());

    let mut statement = serde_json::to_value(&invoice.statement).expect("statement value");
    statement["anchor_base"] = serde_json::Value::String("00".repeat(33));
    assert!(decode_invoice_statement_value(&invoice, statement).is_err());

    let mut statement = serde_json::to_value(&invoice.statement).expect("statement value");
    statement["recipient_key"] = serde_json::Value::String("40".repeat(383));
    assert!(decode_invoice_statement_value(&invoice, statement).is_err());

    let mut statement = serde_json::to_value(&invoice.statement).expect("statement value");
    statement["recipient_key"] = serde_json::Value::String("20".repeat(384));
    assert!(decode_invoice_statement_value(&invoice, statement).is_err());

    let mut statement = serde_json::to_value(&invoice.statement).expect("statement value");
    let mut short_modulus = vec![0_u8; 384];
    short_modulus[0] = 0x40;
    short_modulus[383] = 1;
    statement["recipient_key"] = serde_json::Value::String(hex::encode(short_modulus));
    assert!(decode_invoice_statement_value(&invoice, statement).is_err());

    let mut statement = serde_json::to_value(&invoice.statement).expect("statement value");
    statement["unexpected"] = serde_json::json!(true);
    assert!(decode_invoice_statement_value(&invoice, statement).is_err());

    let v2_message = PublicMessageV2::Invoice(invoice);
    let v2_json = to_json_vec(&v2_message).expect("v2 message");
    assert!(from_json_slice::<PublicMessageV1>(&v2_json).is_err());

    let oversized = raw_hex::<PAILLIER_V2_CIPHERTEXT_BYTES>(1);
    assert_eq!(oversized.as_bytes().len(), PAILLIER_V2_CIPHERTEXT_BYTES);
    assert!(thunderbolt_wire::PaillierCiphertextBytesV2::from_bytes(
        "oversized ciphertext",
        vec![1_u8; PAILLIER_V2_CIPHERTEXT_BYTES + 1],
    )
    .is_err());
}

#[test]
fn operation_step_roster_and_package_tampering_changes_or_invalidates_binding() {
    let original = invoice(31);
    let original_digest = original.canonical_digest().expect("invoice digest");
    let mut changed_step = original.clone();
    changed_step.expected_transfer_step += 1;
    assert_ne!(
        changed_step.canonical_digest().expect("changed digest"),
        original_digest
    );
    assert_ne!(
        changed_step.proof_context().expect("changed proof context").ctx_id(),
        original.proof_context().expect("original proof context").ctx_id()
    );

    let original_transfer = transfer(32);
    let transfer_digest = original_transfer.canonical_digest().expect("transfer digest");
    let mut changed_transfer = original_transfer.clone();
    if let thunderbolt_wire::OperationBindingV2::Transfer { step, .. } = &mut changed_transfer.binding {
        *step += 1;
    }
    assert_ne!(
        changed_transfer.canonical_digest().expect("changed transfer digest"),
        transfer_digest
    );
    assert_ne!(
        changed_transfer
            .proof_context()
            .expect("changed proof context")
            .ctx_id(),
        original_transfer
            .proof_context()
            .expect("original proof context")
            .ctx_id()
    );

    let (recipient, threshold) = threshold_pair(33, 3, 2);
    assert_eq!(
        recipient.proof_context().expect("Recipient proof context"),
        threshold.proof_context().expect("threshold proof context")
    );
    assert_ne!(
        recipient.proof_context().expect("package proof context").ctx_id(),
        recipient
            .binding
            .proof_context()
            .expect("base operation context")
            .ctx_id()
    );
    let mut changed_invoice = recipient.clone();
    changed_invoice.binding =
        thunderbolt_wire::OperationBindingV2::invoice(changed_invoice.binding.channel().clone(), [0xee; 32])
            .expect("changed invoice binding");
    assert!(changed_invoice.validate_wire().is_err());

    let mut changed_roster = recipient.clone();
    changed_roster.package.roster.members[0].encryption_key = modulus(99);
    assert!(changed_roster.validate_wire().is_err());

    let changed_package = ThresholdPackageBindingV2::new(
        &recipient.binding,
        recipient.package.expected_transfer_step + 1,
        recipient.package.roster.clone(),
    )
    .expect("changed package");
    let mut rebound_recipient = recipient.clone();
    rebound_recipient.package = changed_package;
    assert_ne!(
        rebound_recipient
            .proof_context()
            .expect("changed package context")
            .ctx_id(),
        recipient.proof_context().expect("original package context").ctx_id()
    );

    let mut changed_distribution = threshold.clone();
    changed_distribution.distribution.encrypted_shares[0].encryption_key = modulus(98);
    assert!(changed_distribution.validate_wire().is_err());

    let mut changed_point = threshold.clone();
    changed_point.distribution.delta = point(99);
    changed_point.distribution.polynomial_commitments[0] = point(99);
    assert!(validate_threshold_package_v2(&recipient, &changed_point).is_err());

    let (_, other_threshold) = threshold_pair(34, 3, 2);
    assert!(validate_threshold_package_v2(&recipient, &other_threshold).is_err());
}

#[test]
fn maximum_roster_round_trips_and_next_member_is_rejected_during_nested_decode() {
    let (_, threshold) = threshold_pair(41, MAX_COMMITTEE_MEMBERS, 1);
    threshold.validate_wire().expect("maximum roster validates");
    let encoded = to_json_vec(&threshold).expect("maximum roster JSON");
    assert!(encoded.len() <= MAX_WIRE_MESSAGE_BYTES);
    let message = PublicMessageV2::ThresholdRefresh(threshold.clone());
    let encoded = to_json_vec(&message).expect("maximum roster message JSON");
    let decoded = decode_public_message_v2(&encoded).expect("maximum roster decode");
    assert_eq!(decoded, message);

    let mut value = serde_json::to_value(&threshold).expect("threshold value");
    let members = value["package"]["roster"]["members"]
        .as_array_mut()
        .expect("member array");
    members.push(members[0].clone());
    assert!(decode_threshold_value(value).is_err());
}

#[test]
fn maximum_topology_transport_sizes_are_locked_and_activation_is_blocked() {
    let (recipient, threshold) = maximum_threshold_pair();
    let recipient_json = to_json_vec(&PublicMessageV2::RecipientShare(recipient.clone())).expect("recipient JSON");
    let threshold_json = to_json_vec(&PublicMessageV2::ThresholdRefresh(threshold.clone())).expect("threshold JSON");
    let event_len = invoice_event_len(
        thunderbolt_wire::MAX_INVOICE_ID_BYTES,
        recipient_json.len(),
        threshold_json.len(),
    );
    let (signed_proposal_len, rpc_request_len) = proposal_transport_lengths(event_len, recipient.binding.channel());
    assert_eq!(recipient_json.len(), 212_661);
    assert_eq!(threshold_json.len(), 1_491_757);
    assert_eq!(event_len, 1_705_843);
    assert_eq!(signed_proposal_len, 3_413_182);
    assert_eq!(rpc_request_len, 3_413_339);

    assert!(recipient_json.len() <= MAX_WIRE_MESSAGE_BYTES);
    assert!(threshold_json.len() <= MAX_WIRE_MESSAGE_BYTES);
    assert!(threshold_json.len() > 1_048_576);
    assert!(event_len > 256 * 1024);
    assert!(signed_proposal_len > 2 * 1024 * 1024);
    assert!(rpc_request_len > 2 * 1024 * 1024);
}

fn maximum_threshold_pair() -> (
    thunderbolt_wire::RecipientShareEnvelopeV2,
    thunderbolt_wire::ThresholdEnvelopeV2,
) {
    let (mut recipient, mut threshold) = threshold_pair(51, MAX_COMMITTEE_MEMBERS, MAX_COMMITTEE_MEMBERS as u32);
    let mut channel = recipient.binding.channel().clone();
    channel.deployment_id =
        thunderbolt_wire::DeploymentId::from_bytes("deployment_id", [0xff; thunderbolt_wire::MAX_DEPLOYMENT_ID_BYTES])
            .expect("maximum deployment id");
    channel.committee_epoch = u64::MAX;
    channel.funding_outpoint =
        thunderbolt_wire::FundingOutpointV2::new([0xdd; 32], u32::MAX).expect("maximum funding vout");
    let operation =
        thunderbolt_wire::OperationBindingV2::invoice(channel, [0xee; thunderbolt_wire::MAX_INVOICE_ID_BYTES])
            .expect("maximum invoice operation");
    let package = ThresholdPackageBindingV2::new(&operation, u64::MAX, recipient.package.roster.clone())
        .expect("maximum package binding");
    recipient.binding = operation.clone();
    recipient.package = package.clone();
    threshold.binding = operation;
    threshold.package = package;
    (recipient, threshold)
}

fn invoice_event_len(invoice_id_len: usize, recipient_json_len: usize, threshold_json_len: usize) -> usize {
    let mut length = 8 + b"bitcoin-thunderbolt/protocol-event/v2".len() + 3;
    length += 8 + invoice_id_len;
    length += 16;
    for artifact_len in [
        thunderbolt_wire::PAILLIER_V2_MODULUS_BYTES,
        33,
        thunderbolt_wire::PAILLIER_V2_CIPHERTEXT_BYTES,
        threshold_json_len,
        recipient_json_len,
    ] {
        length += 8 + artifact_len;
    }
    length
}

fn proposal_transport_lengths(event_len: usize, channel: &thunderbolt_wire::ChannelBindingV2) -> (usize, usize) {
    let ledger_chain_id = "a".repeat(50);
    let signed_proposal = serde_json::json!({
        "body": {
            "protocol_version": 2,
            "ledger_chain_id": ledger_chain_id,
            "channel": channel,
            "sequence": u64::MAX,
            "previous_entry_hash": "ff".repeat(32),
            "request_id": {
                "nonce": "ff".repeat(64),
                "digest": "ff".repeat(32),
            },
            "actor_key_algorithm": "bip340_v1",
            "actor_public_key": "ff".repeat(32),
            "actor_role": "recipient",
            "event_kind": "invoice",
            "event": "ff".repeat(event_len),
        },
        "signature": "ff".repeat(64),
    });
    let signed_proposal_len = serde_json::to_vec(&signed_proposal)
        .expect("signed proposal size model")
        .len();
    let request = serde_json::json!({
        "api_version": 2,
        "request": {
            "method": "submit_proposal",
            "params": {
                "ledger_chain_id": "a".repeat(50),
                "signed_proposal": signed_proposal,
            }
        }
    });
    let rpc_request_len = serde_json::to_vec(&request).expect("RPC size model").len();
    (signed_proposal_len, rpc_request_len)
}

fn decode_invoice_value(payload: serde_json::Value) -> thunderbolt_wire::Result<PublicMessageV2> {
    let message = serde_json::json!({"message_type": "invoice", "payload": payload});
    decode_public_message_v2(&serde_json::to_vec(&message)?)
}

fn decode_invoice_statement_value(
    invoice: &InvoiceEnvelopeV2,
    statement: serde_json::Value,
) -> thunderbolt_wire::Result<PublicMessageV2> {
    let mut payload = serde_json::to_value(invoice)?;
    payload["statement"] = statement;
    decode_invoice_value(payload)
}

fn decode_threshold_value(payload: serde_json::Value) -> thunderbolt_wire::Result<PublicMessageV2> {
    let message = serde_json::json!({"message_type": "threshold_refresh", "payload": payload});
    decode_public_message_v2(&serde_json::to_vec(&message)?)
}

fn assert_registry_gate(error: WireError) {
    match error {
        WireError::Core { source, .. } => {
            let message = source.to_string();
            assert!(message.contains("authenticated certified key"));
        }
        other => panic!("expected certified-key registry gate, got {other}"),
    }
}
