mod support;

use bitcoin::Network;
use proptest::prelude::*;
use thunderbolt_protocol::{Artifact, ChannelEvent};
use thunderbolt_verifier::{decode_bounded_message, BindingField, VerifierError, VerifierErrorCode};
use thunderbolt_wire::{
    to_json_vec, ChannelId as WireChannelId, DeploymentId, InvoiceId as WireInvoiceId, PublicMessageV1,
    MAX_WIRE_MESSAGE_BYTES,
};

use support::{replace_invoice_proof, single_fixture, INVOICE_LEDGER_TIME, TRANSFER_LEDGER_TIME};

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn prop_bounded_json_roundtrip_ignores_only_json_whitespace(
        leading in 0_usize..64,
        trailing in 0_usize..64,
    ) {
        let fixture = single_fixture();
        let compact = to_json_vec(&fixture.invoice_message).expect("fixture encodes");
        let mut encoded = vec![b' '; leading];
        encoded.extend_from_slice(&compact);
        encoded.extend(std::iter::repeat_n(b'\n', trailing));

        let decoded = decode_bounded_message(&encoded).expect("bounded whitespace is valid JSON");
        prop_assert_eq!(decoded, fixture.invoice_message.clone());
    }

    #[test]
    fn prop_public_field_tamper_is_never_accepted(field in 0_u8..4, mask in 1_u8..=u8::MAX) {
        let fixture = single_fixture();
        let mut entry = fixture.invoice_entry.clone();
        let ChannelEvent::Invoice(event) = &mut entry.event else {
            unreachable!("fixture event type is fixed")
        };
        let target = match field {
            0 => &mut event.recipient_encryption_key,
            1 => &mut event.public_delta,
            2 => &mut event.recipient_ciphertext,
            _ => &mut event.committee_package,
        };
        let mut bytes = target.as_bytes().to_vec();
        bytes[0] ^= mask;
        *target = Artifact::new(bytes).expect("tampered artifact remains bounded");

        let result = fixture.verifier.verify_invoice(
            &entry,
            &fixture.open_snapshot,
            INVOICE_LEDGER_TIME,
        );
        prop_assert!(result.is_err());
    }

    #[test]
    fn prop_each_trusted_invoice_binding_mismatch_is_rejected(field in 0_u8..5) {
        let fixture = single_fixture();
        let PublicMessageV1::Invoice(mut envelope) = fixture.invoice_message.clone() else {
            unreachable!("fixture message type is fixed")
        };
        let expected = match field {
            0 => {
                envelope.binding.network = Network::Signet;
                BindingField::Network
            }
            1 => {
                envelope.binding.deployment_id = DeploymentId::from_bytes("deployment_id", b"other-deployment")
                    .expect("bounded deployment id");
                BindingField::DeploymentId
            }
            2 => {
                envelope.binding.committee_epoch += 1;
                BindingField::CommitteeEpoch
            }
            3 => {
                envelope.binding.channel_id = WireChannelId::from_bytes("channel_id", [0x55; 36])
                    .expect("bounded channel id");
                BindingField::ChannelId
            }
            _ => {
                envelope.binding.invoice_id = WireInvoiceId::from_bytes("invoice_id", b"other-invoice")
                    .expect("bounded invoice id");
                BindingField::InvoiceId
            }
        };
        let mut entry = fixture.invoice_entry.clone();
        replace_invoice_proof(&mut entry, &PublicMessageV1::Invoice(envelope));

        let error = fixture.verifier.verify_invoice(
            &entry,
            &fixture.open_snapshot,
            INVOICE_LEDGER_TIME,
        ).expect_err("binding mismatch must fail before proof acceptance");
        let rejected_expected_field =
            matches!(error, VerifierError::BindingMismatch { field } if field == expected);
        prop_assert!(rejected_expected_field);
    }

    #[test]
    fn prop_transfer_step_mismatch_is_rejected(delta in 1_u64..1_000) {
        let fixture = single_fixture();
        let PublicMessageV1::Transfer(mut envelope) = fixture.transfer_message.clone() else {
            unreachable!("fixture message type is fixed")
        };
        envelope.binding.step = Some(1_u64.saturating_add(delta));
        let mut entry = fixture.transfer_entry.clone();
        let ChannelEvent::Transfer(event) = &mut entry.event else {
            unreachable!("fixture event type is fixed")
        };
        event.transfer_proof = Artifact::new(
            to_json_vec(&PublicMessageV1::Transfer(envelope)).expect("structurally valid transfer JSON")
        ).expect("bounded transfer artifact");

        let error = fixture.verifier.verify_transfer(
            &entry,
            &fixture.invoice_snapshot,
            &fixture.committed_invoice,
            TRANSFER_LEDGER_TIME,
        ).expect_err("step mismatch must fail");
        let rejected_step = matches!(
            error,
            VerifierError::BindingMismatch {
                field: BindingField::Step,
            }
        );
        prop_assert!(rejected_step);
    }

    #[test]
    fn prop_oversize_input_always_hits_existing_wire_limit(extra in 1_usize..1_024) {
        let encoded = vec![b' '; MAX_WIRE_MESSAGE_BYTES + extra];
        let error = decode_bounded_message(&encoded).expect_err("oversize input must fail before JSON parsing");
        prop_assert_eq!(error.code(), VerifierErrorCode::ArtifactDecode);
        let hit_wire_limit = matches!(
            error,
            VerifierError::ArtifactDecode {
                source: thunderbolt_wire::WireError::MessageTooLarge { .. },
                ..
            }
        );
        prop_assert!(hit_wire_limit);
    }
}
