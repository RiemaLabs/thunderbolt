mod support;

use proptest::prelude::*;
use thunderbolt_wire::{decode_public_message_v2, to_json_vec, CanonicalDigest, PublicMessageV2, ValidateWire};

use support::{invoice, replace_binding};

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 96,
        failure_persistence: None,
        ..ProptestConfig::default()
    })]

    #[test]
    fn v2_invoice_codec_round_trips_and_authenticates_operation_fields(
        deployment in prop::collection::vec(any::<u8>(), 1..=64),
        invoice_id in prop::collection::vec(any::<u8>(), 1..=128),
        expected_step in 1_u64..=u64::MAX,
        seed in 1_u8..=250,
    ) {
        let mut envelope = invoice(seed);
        replace_binding(&mut envelope, deployment, invoice_id);
        envelope.expected_transfer_step = expected_step;
        envelope.validate_wire()?;

        let message = PublicMessageV2::Invoice(envelope.clone());
        let encoded = to_json_vec(&message)?;
        let decoded = decode_public_message_v2(&encoded)?;
        prop_assert_eq!(&decoded, &message);
        prop_assert_eq!(decoded.canonical_digest()?, message.canonical_digest()?);

        let mut changed = envelope;
        changed.expected_transfer_step = if expected_step == u64::MAX { 1 } else { expected_step + 1 };
        prop_assert_ne!(changed.canonical_digest()?, message.canonical_digest()?);
    }

    #[test]
    fn arbitrary_bytes_never_panic_the_v2_public_decoder(
        bytes in prop::collection::vec(any::<u8>(), 0..=16_384),
    ) {
        let _ = decode_public_message_v2(&bytes);
    }
}
