use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::{Mutex, OnceLock};

use libpaillier::{unknown_order::BigNumber, DecryptionKey, EncryptionKey};
use proptest::prelude::*;
use secp::Scalar;
use thunderbolt_core::paillier::{
    decode_ciphertext_with_profile, decode_nonce_with_profile, encrypt_plaintext, random_nonce_in_group,
    validate_ciphertext_with_profile, validate_nonce_with_profile, validate_paillier_backend,
    validate_protocol_encryption_key_with_profile, PaillierAccount, PaillierAccountLocal, PaillierModulusProfile,
};
use thunderbolt_core::threshold::{
    create_threshold_refresh_distribution, create_threshold_refresh_distribution_with_profile,
    verify_threshold_refresh_distribution, verify_threshold_refresh_distribution_with_profile,
    ThresholdMemberPublicKey, ThresholdRefreshDistribution,
};
use thunderbolt_core::zkp::{
    prove_invoice, prove_invoice_with_profile, prove_share_encryption, prove_share_encryption_with_profile,
    prove_transfer, prove_transfer_with_profile, verify_invoice, verify_invoice_with_profile, verify_share_encryption,
    verify_share_encryption_with_profile, verify_transfer, verify_transfer_with_profile, InvoiceProof,
    InvoiceStatement, InvoiceWitness, ProofContext, ShareEncryptionProof, ShareEncryptionStatement,
    ShareEncryptionWitness, TransferProof, TransferStatement, TransferWitness,
};

const LEGACY: PaillierModulusProfile = PaillierModulusProfile::LegacyRc2048V1;
const PRODUCTION: PaillierModulusProfile = PaillierModulusProfile::ProtocolV2Production3072;

fn scalar(value: u8) -> Scalar {
    let mut bytes = [0_u8; 32];
    bytes[31] = value;
    Scalar::from_slice(&bytes).expect("small nonzero scalar")
}

fn scalar_bn(value: Scalar) -> BigNumber {
    BigNumber::from_slice(value.serialize())
}

fn legacy_key() -> &'static EncryptionKey {
    static KEY: OnceLock<EncryptionKey> = OnceLock::new();
    KEY.get_or_init(|| {
        let secret = DecryptionKey::random().expect("legacy Paillier keygen");
        EncryptionKey::from(&secret)
    })
}

fn legacy_account() -> &'static Mutex<PaillierAccountLocal> {
    static ACCOUNT: OnceLock<Mutex<PaillierAccountLocal>> = OnceLock::new();
    ACCOUNT.get_or_init(|| Mutex::new(PaillierAccountLocal::new_with_profile(LEGACY).expect("legacy profile account")))
}

#[test]
fn legacy_profile_paths_interoperate_with_unchanged_v1_paths() {
    let key = legacy_key().clone();
    let anchor_base = scalar(41).base_point_mul();
    let refresh = scalar(7);
    let holder_secret = scalar(11);
    let refresh_bn = scalar_bn(refresh);
    let holder_bn = scalar_bn(holder_secret);

    let invoice_nonce = random_nonce_in_group(&key);
    let committee_nonce = random_nonce_in_group(&key);
    let invoice_statement = InvoiceStatement {
        context: ProofContext::invoice(b"profile-ctx", b"profile-invoice"),
        anchor_base,
        bob_key: key.clone(),
        committee_key: key.clone(),
        delta: anchor_base * refresh,
        bob_ciphertext: encrypt_plaintext(&key, &refresh_bn, &invoice_nonce).expect("invoice ciphertext"),
        committee_ciphertext: encrypt_plaintext(&key, &refresh_bn, &committee_nonce).expect("committee ciphertext"),
    };
    let invoice_witness = InvoiceWitness {
        refresh,
        bob_nonce: invoice_nonce,
        committee_nonce,
    };
    let legacy_invoice = prove_invoice(&invoice_statement, &invoice_witness).expect("legacy invoice proof");
    verify_invoice_with_profile(LEGACY, &invoice_statement, &legacy_invoice).expect("profile verifies v1 invoice");
    let profile_invoice =
        prove_invoice_with_profile(LEGACY, &invoice_statement, &invoice_witness).expect("profile invoice proof");
    verify_invoice(&invoice_statement, &profile_invoice).expect("v1 verifies profile invoice");

    let holder_nonce = random_nonce_in_group(&key);
    let holder_ciphertext = encrypt_plaintext(&key, &holder_bn, &holder_nonce).expect("holder ciphertext");
    let next_holder_ciphertext =
        thunderbolt_core::paillier::add_ciphertexts(&key, &holder_ciphertext, &invoice_statement.bob_ciphertext)
            .expect("next ciphertext");
    let transfer_statement = TransferStatement {
        context: ProofContext::transfer(b"profile-ctx", 1, b"profile-invoice"),
        anchor_base,
        bob_key: key.clone(),
        current_anchor: anchor_base * holder_secret,
        invoice_ciphertext: invoice_statement.bob_ciphertext.clone(),
        next_holder_ciphertext,
    };
    let transfer_witness = TransferWitness {
        holder_secret,
        holder_nonce,
    };
    let legacy_transfer = prove_transfer(&transfer_statement, &transfer_witness).expect("legacy transfer proof");
    verify_transfer_with_profile(LEGACY, &transfer_statement, &legacy_transfer).expect("profile verifies v1 transfer");
    let profile_transfer =
        prove_transfer_with_profile(LEGACY, &transfer_statement, &transfer_witness).expect("profile transfer proof");
    verify_transfer(&transfer_statement, &profile_transfer).expect("v1 verifies profile transfer");

    let share_secret = scalar(13);
    let share_nonce = random_nonce_in_group(&key);
    let share_statement = ShareEncryptionStatement {
        context: ProofContext::invoice(b"profile-ctx", b"profile-share"),
        anchor_base,
        recipient_key: key.clone(),
        member_id: 1,
        committed_point: anchor_base * share_secret,
        ciphertext: encrypt_plaintext(&key, &scalar_bn(share_secret), &share_nonce).expect("share ciphertext"),
    };
    let share_witness = ShareEncryptionWitness {
        secret: share_secret,
        nonce: share_nonce,
    };
    let legacy_share = prove_share_encryption(&share_statement, &share_witness).expect("legacy share proof");
    verify_share_encryption_with_profile(LEGACY, &share_statement, &legacy_share).expect("profile verifies v1 share");
    let profile_share =
        prove_share_encryption_with_profile(LEGACY, &share_statement, &share_witness).expect("profile share proof");
    verify_share_encryption(&share_statement, &profile_share).expect("v1 verifies profile share");

    let recipients = [ThresholdMemberPublicKey {
        member_id: 1,
        encryption_key: key,
    }];
    let distribution = create_threshold_refresh_distribution(
        ProofContext::invoice(b"profile-ctx", b"profile-threshold"),
        anchor_base,
        1,
        refresh,
        &recipients,
    )
    .expect("legacy threshold distribution");
    verify_threshold_refresh_distribution_with_profile(LEGACY, &distribution).expect("profile verifies v1 threshold");
    let profile_distribution = create_threshold_refresh_distribution_with_profile(
        LEGACY,
        ProofContext::invoice(b"profile-ctx", b"profile-threshold-2"),
        anchor_base,
        1,
        refresh,
        &recipients,
    )
    .expect("profile threshold distribution");
    verify_threshold_refresh_distribution(&profile_distribution).expect("v1 verifies profile threshold");
}

#[test]
fn production_profile_is_fail_closed_without_panicking() {
    assert_eq!(PRODUCTION.modulus_bytes(), 384);
    assert_eq!(PRODUCTION.nonce_bytes(), 384);
    assert_eq!(PRODUCTION.ciphertext_bytes(), 768);
    assert!(validate_paillier_backend(PRODUCTION).is_err());

    let account = catch_unwind(AssertUnwindSafe(|| PaillierAccountLocal::new_with_profile(PRODUCTION)));
    assert!(matches!(account, Ok(Err(_))));

    let key = legacy_key();
    let key_validation = catch_unwind(AssertUnwindSafe(|| {
        validate_protocol_encryption_key_with_profile(PRODUCTION, key)
    }));
    assert!(matches!(key_validation, Ok(Err(_))));

    let anchor_base = scalar(17).base_point_mul();
    let one = BigNumber::one();
    let invoice_statement = InvoiceStatement {
        context: ProofContext::invoice(b"blocked", b"invoice"),
        anchor_base,
        bob_key: key.clone(),
        committee_key: key.clone(),
        delta: anchor_base,
        bob_ciphertext: one.clone(),
        committee_ciphertext: one.clone(),
    };
    let invoice_witness = InvoiceWitness {
        refresh: scalar(1),
        bob_nonce: one.clone(),
        committee_nonce: one.clone(),
    };
    let invoice_proof = InvoiceProof {
        a_delta: anchor_base,
        a_bob: one.clone(),
        a_committee: one.clone(),
        z: one.clone(),
        tau_bob: one.clone(),
        tau_committee: one.clone(),
    };
    let transfer_statement = TransferStatement {
        context: ProofContext::transfer(b"blocked", 1, b"invoice"),
        anchor_base,
        bob_key: key.clone(),
        current_anchor: anchor_base,
        invoice_ciphertext: one.clone(),
        next_holder_ciphertext: one.clone(),
    };
    let transfer_witness = TransferWitness {
        holder_secret: scalar(1),
        holder_nonce: one.clone(),
    };
    let transfer_proof = TransferProof {
        a_anchor: anchor_base,
        a_ciphertext: one.clone(),
        z: one.clone(),
        tau: one.clone(),
    };
    let share_statement = ShareEncryptionStatement {
        context: ProofContext::invoice(b"blocked", b"share"),
        anchor_base,
        recipient_key: key.clone(),
        member_id: 1,
        committed_point: anchor_base,
        ciphertext: one.clone(),
    };
    let share_witness = ShareEncryptionWitness {
        secret: scalar(1),
        nonce: one.clone(),
    };
    let share_proof = ShareEncryptionProof {
        a_point: anchor_base,
        a_ciphertext: one.clone(),
        z: one,
        tau: BigNumber::one(),
    };
    let distribution = ThresholdRefreshDistribution {
        context: ProofContext::invoice(b"blocked", b"threshold"),
        anchor_base,
        threshold: 0,
        delta: anchor_base,
        polynomial_commitments: Vec::new(),
        encrypted_shares: Vec::new(),
    };
    let proof_paths = catch_unwind(AssertUnwindSafe(|| {
        assert!(prove_invoice_with_profile(PRODUCTION, &invoice_statement, &invoice_witness).is_err());
        assert!(verify_invoice_with_profile(PRODUCTION, &invoice_statement, &invoice_proof).is_err());
        assert!(prove_transfer_with_profile(PRODUCTION, &transfer_statement, &transfer_witness).is_err());
        assert!(verify_transfer_with_profile(PRODUCTION, &transfer_statement, &transfer_proof).is_err());
        assert!(prove_share_encryption_with_profile(PRODUCTION, &share_statement, &share_witness).is_err());
        assert!(verify_share_encryption_with_profile(PRODUCTION, &share_statement, &share_proof).is_err());
        assert!(create_threshold_refresh_distribution_with_profile(
            PRODUCTION,
            ProofContext::invoice(b"blocked", b"new-threshold"),
            anchor_base,
            1,
            scalar(1),
            &[],
        )
        .is_err());
        assert!(verify_threshold_refresh_distribution_with_profile(PRODUCTION, &distribution).is_err());
    }));
    assert!(proof_paths.is_ok(), "unsupported proof paths must not panic");
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(32))]

    #[test]
    fn profile_width_decoders_reject_short_inputs_without_panicking(value in 0_u64..=u64::MAX) {
        let key = legacy_key();
        let short = value.to_be_bytes();
        let nonce = catch_unwind(AssertUnwindSafe(|| decode_nonce_with_profile(LEGACY, key, &short)));
        let ciphertext = catch_unwind(AssertUnwindSafe(|| {
            decode_ciphertext_with_profile(LEGACY, key, &short)
        }));
        prop_assert!(matches!(nonce, Ok(Err(_))));
        prop_assert!(matches!(ciphertext, Ok(Err(_))));
    }

    #[test]
    fn legacy_account_outputs_always_validate(plaintext in prop::collection::vec(any::<u8>(), 0..=64)) {
        let account = legacy_account().lock().expect("legacy account lock");
        let (ciphertext, nonce) = account.encrypt(&plaintext)?;
        validate_nonce_with_profile(account.profile(), account.public_key(), &nonce)?;
        validate_ciphertext_with_profile(account.profile(), account.public_key(), &ciphertext)?;
    }
}
