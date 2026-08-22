mod support;

use std::sync::OnceLock;

use thunderbolt_core::zkp::{
    CertifiedKeyResolver3072, CertifiedKeyRole3072, InvoiceProver3072, PublicKey3072, RawPublicKey3072,
    SecretScalar3072, ShareEncryptionProver3072, TransferProver3072,
};
use thunderbolt_core::{Result as CoreResult, ThunderboltError};
use thunderbolt_paillier::{OfflineKeyGenerator, SecretKey3072};
use thunderbolt_wire::{
    decode_public_message_v2, to_json_vec, InvoiceEnvelopeV2, OperationBindingV2, PaillierModulusBytesV2,
    PublicMessageV2, RecipientShareEnvelopeV2, ThresholdPackageBindingV2, ThresholdRosterMemberV2, ThresholdRosterV2,
    TransferEnvelopeV2, ValidateWire, RECIPIENT_SHARE_MEMBER_ID,
};
use zeroize::Zeroizing;

use support::channel;

fn test_key() -> &'static SecretKey3072 {
    static KEY: OnceLock<SecretKey3072> = OnceLock::new();
    KEY.get_or_init(|| {
        OfflineKeyGenerator
            .generate()
            .expect("offline test-only Paillier key generation")
    })
}

fn secret(value: u64) -> SecretScalar3072 {
    let mut bytes = Zeroizing::new([0_u8; 32]);
    bytes[24..].copy_from_slice(&value.to_be_bytes());
    SecretScalar3072::from_bytes(bytes).expect("small secret scalar")
}

struct ExactResolver(PublicKey3072);

impl CertifiedKeyResolver3072 for ExactResolver {
    fn resolve_certified_key(&self, raw: &RawPublicKey3072, _role: CertifiedKeyRole3072) -> CoreResult<PublicKey3072> {
        if raw.to_bytes() == self.0.to_bytes() {
            Ok(self.0.clone())
        } else {
            Err(ThunderboltError::InvalidParameter(
                "test key is absent from the certified resolver".to_string(),
            ))
        }
    }
}

#[test]
fn prove_wire_resolve_and_verify_all_defined_production_relations() {
    let key = test_key().public_key();
    let registry = ExactResolver(key.clone());
    let anchor_base = secp::Scalar::one().base_point_mul();
    let channel = channel(71, b"production-wire");
    let invoice_binding = OperationBindingV2::invoice(channel.clone(), [0x71; 32]).expect("invoice binding");
    let invoice_context = InvoiceEnvelopeV2::proof_context_for(&invoice_binding, 1).expect("invoice context");
    let (invoice_statement, invoice_proof) =
        InvoiceProver3072::prepare(invoice_context, anchor_base, key, key, secret(7))
            .expect("invoice preparation")
            .prove()
            .expect("invoice proof");
    let invoice = InvoiceEnvelopeV2::from_core(invoice_binding.clone(), 1, &invoice_statement, &invoice_proof)
        .expect("invoice wire egress");
    let encoded = to_json_vec(&PublicMessageV2::Invoice(invoice.clone())).expect("invoice JSON");
    let decoded = decode_public_message_v2(&encoded).expect("invoice decode");
    decoded
        .verify_with_keys(&registry)
        .expect("decoded invoice verification");
    let (decoded_statement, _) = invoice.to_core_with_keys(&registry).expect("invoice core ingress");
    assert_eq!(
        decoded_statement.recipient_ciphertext,
        invoice_statement.recipient_ciphertext
    );

    let transfer_binding = OperationBindingV2::transfer(channel.clone(), [0x71; 32], 1).expect("transfer binding");
    let transfer_context = TransferEnvelopeV2::proof_context_for(&transfer_binding).expect("transfer context");
    let (transfer_statement, transfer_proof) = TransferProver3072::prepare(
        transfer_context,
        anchor_base,
        key,
        invoice_statement.recipient_ciphertext.clone(),
        secret(11),
    )
    .expect("transfer preparation")
    .prove()
    .expect("transfer proof");
    let next_anchor = (transfer_statement.current_anchor + invoice_statement.delta)
        .not_inf()
        .expect("next anchor");
    let transfer = TransferEnvelopeV2::from_core(
        transfer_binding,
        &transfer_statement,
        &transfer_proof,
        &invoice_statement.delta,
        &next_anchor,
    )
    .expect("transfer wire egress");
    let encoded = to_json_vec(&PublicMessageV2::Transfer(transfer)).expect("transfer JSON");
    decode_public_message_v2(&encoded)
        .expect("transfer decode")
        .verify_with_keys(&registry)
        .expect("decoded transfer verification");

    let roster = ThresholdRosterV2::new(
        1,
        vec![ThresholdRosterMemberV2 {
            member_id: 1,
            encryption_key: PaillierModulusBytesV2::from_bytes("test roster key", key.to_bytes())
                .expect("fixed key width"),
        }],
    )
    .expect("roster");
    let package = ThresholdPackageBindingV2::new(&invoice_binding, 1, roster).expect("package");
    let share_context = package.proof_context(&invoice_binding).expect("share context");
    let (share_statement, share_proof) =
        ShareEncryptionProver3072::prepare(share_context, anchor_base, key, RECIPIENT_SHARE_MEMBER_ID, secret(13))
            .expect("share preparation")
            .prove()
            .expect("share proof");
    let share = RecipientShareEnvelopeV2::from_core(invoice_binding, package, &share_statement, &share_proof)
        .expect("share wire egress");
    let encoded = to_json_vec(&PublicMessageV2::RecipientShare(share)).expect("share JSON");
    decode_public_message_v2(&encoded)
        .expect("share decode")
        .verify_with_keys(&registry)
        .expect("decoded share verification");
}

#[test]
fn changed_context_or_substituting_resolver_is_rejected() {
    struct SubstitutingResolver(PublicKey3072);

    impl CertifiedKeyResolver3072 for SubstitutingResolver {
        fn resolve_certified_key(
            &self,
            _raw: &RawPublicKey3072,
            _role: CertifiedKeyRole3072,
        ) -> CoreResult<PublicKey3072> {
            Ok(self.0.clone())
        }
    }

    let key = test_key().public_key();
    let registry = ExactResolver(key.clone());
    let anchor_base = secp::Scalar::one().base_point_mul();
    let binding = OperationBindingV2::invoice(channel(72, b"production-wire"), [0x72; 32]).expect("binding");
    let context = InvoiceEnvelopeV2::proof_context_for(&binding, 1).expect("context");
    let (statement, proof) = InvoiceProver3072::prepare(context, anchor_base, key, key, secret(17))
        .expect("prepare")
        .prove()
        .expect("prove");
    let invoice = InvoiceEnvelopeV2::from_core(binding, 1, &statement, &proof).expect("wire invoice");

    let mut changed_context = invoice.clone();
    changed_context.binding =
        OperationBindingV2::invoice(changed_context.binding.channel().clone(), [0x73; 32]).expect("changed binding");
    assert!(changed_context.verify_with_keys(&registry).is_err());

    let mut substituted = invoice;
    let mut raw = key.to_bytes();
    raw[1] ^= 1;
    substituted.statement.recipient_key =
        PaillierModulusBytesV2::from_bytes("substituted raw key", raw).expect("raw fixed key");
    substituted
        .validate_wire()
        .expect("structured raw key remains wire-valid");
    let error = substituted
        .to_core_with_keys(&SubstitutingResolver(key.clone()))
        .expect_err("resolver substitution must fail exact-byte match");
    assert!(error.to_string().contains("different modulus"));
}
