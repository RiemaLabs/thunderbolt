use std::sync::OnceLock;

use chacha20::ChaCha20Rng;
use crypto_bigint::U1536;
use crypto_primes::{is_prime, Flavor};
use num_bigint::BigUint;
use num_traits::One as _;
use proptest::prelude::*;
use rand_core::SeedableRng;
use sha2::{Digest as _, Sha256};
use static_assertions::{assert_impl_all, assert_not_impl_any};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::types::EncryptionNonce3072;
use crate::{
    Ciphertext3072, Encryption3072, OfflineKeyGenerator, PaillierError, ProofOpeningResponse3072, PublicExponent3072,
    PublicKey3072, RawPublicKey3072, SecretKey3072, SecretKeyBytes3072, SecretPlaintext3072, SecretPlaintextBytes3072,
    CIPHERTEXT_BYTES, MODULUS_BYTES, PRIME_BYTES, SECRET_KEY_BYTES,
};

assert_not_impl_any!(SecretKey3072: Clone, core::fmt::Debug);
assert_not_impl_any!(EncryptionNonce3072: Clone, core::fmt::Debug);
assert_not_impl_any!(Encryption3072: Clone, core::fmt::Debug);
assert_not_impl_any!(SecretPlaintext3072: Clone, core::fmt::Debug);
assert_not_impl_any!(SecretPlaintextBytes3072: Clone, core::fmt::Debug);
assert_not_impl_any!(SecretKeyBytes3072: Clone, core::fmt::Debug);
assert_impl_all!(SecretKey3072: Zeroize, ZeroizeOnDrop, Send, Sync);
assert_impl_all!(EncryptionNonce3072: Zeroize, ZeroizeOnDrop, Send, Sync);
assert_impl_all!(Encryption3072: Zeroize, ZeroizeOnDrop, Send, Sync);
assert_impl_all!(SecretPlaintext3072: Zeroize, ZeroizeOnDrop, Send, Sync);
assert_impl_all!(SecretPlaintextBytes3072: Zeroize, ZeroizeOnDrop, Send, Sync);
assert_impl_all!(SecretKeyBytes3072: Zeroize, ZeroizeOnDrop, Send, Sync);
assert_impl_all!(PublicKey3072: Clone, core::fmt::Debug, Send, Sync);
assert_impl_all!(Ciphertext3072: Clone, core::fmt::Debug, Send, Sync);
assert_impl_all!(ProofOpeningResponse3072: Clone, core::fmt::Debug, Send, Sync);
assert_impl_all!(ChaCha20Rng: ZeroizeOnDrop);

pub(crate) fn secret_key() -> &'static SecretKey3072 {
    static KEY: OnceLock<SecretKey3072> = OnceLock::new();
    KEY.get_or_init(|| {
        let mut key_rng = ChaCha20Rng::from_seed([0x41; 32]);
        OfflineKeyGenerator
            .generate_with_rng_for_test(&mut key_rng)
            .expect("deterministic offline key generation")
    })
}

fn second_secret_key() -> &'static SecretKey3072 {
    static KEY: OnceLock<SecretKey3072> = OnceLock::new();
    KEY.get_or_init(|| {
        let mut key_rng = ChaCha20Rng::from_seed([0x42; 32]);
        OfflineKeyGenerator
            .generate_with_rng_for_test(&mut key_rng)
            .expect("second deterministic offline key generation")
    })
}

#[test]
fn deterministic_kat_and_homomorphic_operations_round_trip() {
    let secret_key = secret_key();
    let public_key = secret_key.public_key();

    let left = small_plaintext(public_key, 7);
    let right = small_plaintext(public_key, 11);
    let mut nonce_rng = ChaCha20Rng::from_seed([0x52; 32]);
    let left_encryption = public_key
        .encrypt_with_rng_for_test(&left, &mut nonce_rng)
        .expect("left encryption");
    let right_encryption = public_key
        .encrypt_with_rng_for_test(&right, &mut nonce_rng)
        .expect("right encryption");

    assert_secret_u64(
        &secret_key
            .decrypt(left_encryption.ciphertext())
            .expect("left decryption"),
        7,
    );

    let sum = public_key
        .add(left_encryption.ciphertext(), right_encryption.ciphertext())
        .expect("homomorphic addition");
    assert_secret_u64(&secret_key.decrypt(&sum).expect("sum decryption"), 18);

    let recovered_left = public_key
        .subtract(&sum, right_encryption.ciphertext())
        .expect("homomorphic subtraction");
    assert_secret_u64(&secret_key.decrypt(&recovered_left).expect("recovered decryption"), 7);

    let exponent = PublicExponent3072::from_bytes([3_u8]).expect("public exponent");
    let tripled = public_key
        .exponentiate(left_encryption.ciphertext(), &exponent)
        .expect("homomorphic scalar multiplication");
    assert_secret_u64(&secret_key.decrypt(&tripled).expect("tripled decryption"), 21);

    let encoded_key = secret_key.to_secret_record();
    let expected_key = fixture_record_bytes();
    assert_eq!(encoded_key.as_ref(), expected_key.as_slice());
    assert_eq!(
        hex::encode(Sha256::digest(public_key.to_bytes())),
        "0d284aa383468b76ace48cd70bd7a47d87ec45c19213ca8749e03512d0c550aa"
    );
    assert_eq!(
        hex::encode(Sha256::digest(left_encryption.ciphertext().to_bytes())),
        "dc0b65e6fa0668831b9c93c7dad03189539a669c3d322f0bb053b49d110ee856"
    );
    assert_eq!(
        hex::encode(Sha256::digest(
            left_encryption.nonce_for_test().to_secret_bytes().as_ref()
        )),
        "92d96a3f42c24752b91df779f3b3fb06fc62a64dd29f88c7dd446e57641fdcdc"
    );
    let restored = SecretKey3072::from_secret_record(encoded_key).expect("secret-key restore");
    assert_eq!(restored.public_key().to_bytes(), public_key.to_bytes());
}

#[test]
fn arithmetic_and_consuming_proof_openings_match_num_bigint() {
    let public_key = secret_key().public_key();
    let n = BigUint::from_bytes_be(&public_key.to_bytes());
    let nn = &n * &n;
    let generator = &n + BigUint::one();

    let plaintext = small_plaintext(public_key, 23);
    let nonce = local_nonce(public_key, 17);
    let ciphertext = public_key
        .compose_with_nonce_for_test(&plaintext, &nonce)
        .expect("deterministic encryption");
    assert_eq!(
        public_key
            .ciphertext_from_bytes(ciphertext.to_bytes())
            .expect("ciphertext codec"),
        ciphertext
    );
    let expected = (generator.modpow(&BigUint::from(23_u8), &nn) * BigUint::from(17_u8).modpow(&n, &nn)) % &nn;
    assert_eq!(BigUint::from_bytes_be(&ciphertext.to_bytes()), expected);

    let other_plaintext = small_plaintext(public_key, 29);
    let other_nonce = local_nonce(public_key, 19);
    let other = public_key
        .compose_with_nonce_for_test(&other_plaintext, &other_nonce)
        .expect("other deterministic encryption");
    let sum = public_key.add(&ciphertext, &other).expect("ciphertext addition");
    let reference_sum =
        (BigUint::from_bytes_be(&ciphertext.to_bytes()) * BigUint::from_bytes_be(&other.to_bytes())) % &nn;
    assert_eq!(BigUint::from_bytes_be(&sum.to_bytes()), reference_sum);

    let challenge = PublicExponent3072::from_bytes([7_u8]).expect("challenge");
    let statement_opening = public_key
        .opening_with_nonce_for_test(&plaintext, local_nonce(public_key, 5))
        .expect("statement opening");
    let commitment_opening = public_key
        .opening_with_nonce_for_test(&small_plaintext(public_key, 31), local_nonce(public_key, 3))
        .expect("commitment opening");
    let material = public_key
        .consume_proof_openings(statement_opening, commitment_opening, &challenge)
        .expect("response nonce");
    let expected_tau = (BigUint::from(3_u8) * BigUint::from(5_u8).modpow(&BigUint::from(7_u8), &n)) % &n;
    assert_eq!(
        BigUint::from_bytes_be(&material.response_nonce().to_bytes()),
        expected_tau
    );
    assert_eq!(
        public_key
            .proof_nonce_from_bytes(material.response_nonce().to_bytes())
            .expect("proof nonce codec"),
        *material.response_nonce()
    );

    let response = PublicExponent3072::from_bytes([11_u8]).expect("response");
    let lhs = public_key
        .response_lhs(&response, material.response_nonce())
        .expect("response lhs");
    let expected_lhs = (generator.modpow(&BigUint::from(11_u8), &nn) * expected_tau.modpow(&n, &nn)) % &nn;
    assert_eq!(BigUint::from_bytes_be(&lhs.to_bytes()), expected_lhs);
}

#[test]
fn former_same_nonce_api_would_reveal_plaintext_difference() {
    let public_key = secret_key().public_key();
    let n = BigUint::from_bytes_be(&public_key.to_bytes());
    let reused_nonce = local_nonce(public_key, 17);
    let high = public_key
        .compose_with_nonce_for_test(&small_plaintext(public_key, 19), &reused_nonce)
        .expect("test-only first composition");
    let low = public_key
        .compose_with_nonce_for_test(&small_plaintext(public_key, 7), &reused_nonce)
        .expect("test-only reused composition");

    let public_ratio = public_key.subtract(&high, &low).expect("public ciphertext ratio");
    let ratio = BigUint::from_bytes_be(&public_ratio.to_bytes());
    let leaked_difference = ((ratio - BigUint::one()) / &n) % &n;
    assert_eq!(leaked_difference, BigUint::from(12_u8));
}

#[test]
fn exact_key_bindings_reject_cross_key_use_before_arithmetic() {
    let first_key = secret_key();
    let second_key = second_secret_key();
    let first_public = first_key.public_key();
    let second_public = second_key.public_key();

    let first_plaintext = small_plaintext(first_public, 9);
    assert!(matches!(
        second_public.encrypt(&first_plaintext),
        Err(PaillierError::WrongPublicKey {
            field: "secret plaintext"
        })
    ));

    let mut first_rng = ChaCha20Rng::from_seed([0x71; 32]);
    let mut second_rng = ChaCha20Rng::from_seed([0x72; 32]);
    let first_opening = first_public
        .encrypt_with_rng_for_test(&first_plaintext, &mut first_rng)
        .expect("first opening");
    let second_opening = second_public
        .encrypt_with_rng_for_test(&small_plaintext(second_public, 13), &mut second_rng)
        .expect("second opening");
    let first_ciphertext = first_opening.ciphertext().clone();
    let challenge = PublicExponent3072::from_bytes([5_u8]).expect("challenge");
    assert!(matches!(
        first_public.consume_proof_openings(first_opening, second_opening, &challenge),
        Err(PaillierError::WrongPublicKey {
            field: "commitment opening"
        })
    ));
    assert!(matches!(
        second_key.decrypt(&first_ciphertext),
        Err(PaillierError::WrongPublicKey { field: "ciphertext" })
    ));
}

#[test]
fn fixed_width_codecs_arithmetic_boundaries_and_zeroization_fail_closed() {
    let secret_key = secret_key();
    let public_key = secret_key.public_key();
    let raw = public_key.to_raw();
    assert_eq!(raw.to_bytes().len(), MODULUS_BYTES);
    assert_eq!(RawPublicKey3072::from_bytes(raw.to_bytes()).expect("raw key"), raw);

    assert!(RawPublicKey3072::from_bytes([0_u8; MODULUS_BYTES - 1]).is_err());
    let mut missing_top_bit = raw.to_bytes();
    missing_top_bit[0] &= 0x7f;
    assert!(RawPublicKey3072::from_bytes(missing_top_bit).is_err());
    let mut even = raw.to_bytes();
    even[MODULUS_BYTES - 1] &= 0xfe;
    assert!(RawPublicKey3072::from_bytes(even).is_err());

    assert!(public_key.ciphertext_from_bytes([0_u8; CIPHERTEXT_BYTES]).is_err());
    let n = BigUint::from_bytes_be(&public_key.to_bytes());
    let nn = &n * &n;
    assert!(public_key
        .ciphertext_from_bytes(fixed_public_bytes::<CIPHERTEXT_BYTES>(&nn))
        .is_err());
    assert!(public_key
        .ciphertext_from_bytes(fixed_public_bytes::<CIPHERTEXT_BYTES>(&n))
        .is_err());
    assert!(public_key.proof_nonce_from_bytes([0_u8; MODULUS_BYTES]).is_err());
    assert!(public_key.proof_nonce_from_bytes(public_key.to_bytes()).is_err());

    let n_plaintext = SecretPlaintextBytes3072::new(Zeroizing::new(public_key.to_bytes()));
    assert!(public_key.plaintext_from_secret_bytes(n_plaintext).is_err());
    let n_minus_one = secret_plaintext_bytes_from_biguint(&(n.clone() - BigUint::one()));
    let max_plaintext = public_key
        .plaintext_from_secret_bytes(n_minus_one)
        .expect("N - 1 plaintext");
    let wrapped = public_key
        .add(
            &public_key
                .compose_with_nonce_for_test(&max_plaintext, &local_nonce(public_key, 17))
                .expect("N - 1 ciphertext"),
            &public_key
                .compose_with_nonce_for_test(&small_plaintext(public_key, 1), &local_nonce(public_key, 19))
                .expect("one ciphertext"),
        )
        .expect("plaintext wrap");
    assert_secret_u64(&secret_key.decrypt(&wrapped).expect("wrapped decryption"), 0);

    let one = local_nonce(public_key, 1);
    let one_bytes = one.to_secret_bytes();
    assert!(one_bytes[..MODULUS_BYTES - 1].iter().all(|byte| *byte == 0));
    assert_eq!(one_bytes[MODULUS_BYTES - 1], 1);

    let debug_key = format!("{public_key:?}");
    assert!(debug_key.contains("fingerprint"));
    assert!(!debug_key.contains(&hex::encode(public_key.to_bytes())));

    let caller_owned = vec![0x5a; SECRET_KEY_BYTES];
    let mut owned_record = SecretKeyBytes3072::copy_from_slice(&caller_owned).expect("owned secret record");
    owned_record.zeroize();
    assert!(owned_record.as_ref().iter().all(|byte| *byte == 0));
    assert!(caller_owned.iter().all(|byte| *byte == 0x5a));

    let mut zeroized_nonce = local_nonce(public_key, 1);
    zeroized_nonce.zeroize();
    assert!(zeroized_nonce.to_secret_bytes().iter().all(|byte| *byte == 0));
    let mut zeroized_plaintext = small_plaintext(public_key, 9);
    zeroized_plaintext.zeroize();
    assert!(zeroized_plaintext.to_secret_bytes().iter().all(|byte| *byte == 0));

    let mut rng = ChaCha20Rng::from_seed([0x5f; 32]);
    let mut encryption = public_key
        .encrypt_with_rng_for_test(&small_plaintext(public_key, 10), &mut rng)
        .expect("encryption to zeroize");
    encryption.zeroize();
    assert!(encryption
        .nonce_for_test()
        .to_secret_bytes()
        .iter()
        .all(|byte| *byte == 0));
}

#[test]
fn secret_record_validation_hits_targeted_failure_classes() {
    let fixture = fixture_record_bytes();

    let mut wrong_version = fixture;
    wrong_version[9] = 2;
    assert!(SecretKey3072::from_secret_record(secret_record(wrong_version)).is_err());

    let mut equal_factors = fixture;
    equal_factors.copy_within(10..10 + PRIME_BYTES, 10 + PRIME_BYTES);
    assert!(matches!(
        SecretKey3072::from_secret_record(secret_record(equal_factors)),
        Err(PaillierError::InvalidSecretKey {
            reason: "p and q must be distinct"
        })
    ));

    let mut composite_factor = fixture;
    composite_factor[10 + PRIME_BYTES..].fill(0);
    composite_factor[10 + PRIME_BYTES] = 0xc0;
    composite_factor[SECRET_KEY_BYTES - 1] = 3;
    assert!(matches!(
        SecretKey3072::from_secret_record(secret_record(composite_factor)),
        Err(PaillierError::InvalidSecretKey { .. })
    ));

    let mut short_factor = fixture;
    short_factor[10] &= 0x7f;
    assert!(SecretKey3072::from_secret_record(secret_record(short_factor)).is_err());

    let p = U1536::from_be_slice(&fixture[10..10 + PRIME_BYTES]);
    let close_q = next_probable_prime(p.wrapping_add(&U1536::from(2_u8)));
    let mut close_factors = fixture;
    close_factors[10 + PRIME_BYTES..].copy_from_slice(close_q.to_be_bytes().as_ref());
    assert!(matches!(
        SecretKey3072::from_secret_record(secret_record(close_factors)),
        Err(PaillierError::InvalidSecretKey {
            reason: "secret factors are too close for the production RSA-style key profile"
        })
    ));

    let low_q = next_probable_prime(U1536::ONE.wrapping_shl(1535).wrapping_add(&U1536::ONE));
    let mut short_product = fixture;
    short_product[10 + PRIME_BYTES..].copy_from_slice(low_q.to_be_bytes().as_ref());
    assert!(matches!(
        SecretKey3072::from_secret_record(secret_record(short_product)),
        Err(PaillierError::InvalidModulus { .. })
    ));
}

#[test]
fn sampled_nonces_are_fixed_width_distinct_units() {
    let public_key = secret_key().public_key();
    let mut rng = ChaCha20Rng::from_seed([0x63; 32]);
    let mut seen = std::collections::BTreeSet::new();
    for _ in 0..128 {
        let nonce = public_key.sample_nonce_for_test(&mut rng);
        let bytes = nonce.to_secret_bytes();
        public_key
            .proof_nonce_from_bytes(bytes.as_ref())
            .expect("sampled nonce is in Z_N*");
        assert!(seen.insert(*bytes));
    }
}

#[test]
fn deterministic_nonce_sample_has_no_low_nibble_bias_regression() {
    const SAMPLES: usize = 4096;
    let public_key = secret_key().public_key();
    let mut rng = ChaCha20Rng::from_seed([0x64; 32]);
    let mut counts = [0_usize; 16];
    let mut saw_leading_zero = false;
    for _ in 0..SAMPLES {
        let nonce = public_key.sample_nonce_for_test(&mut rng);
        let bytes = nonce.to_secret_bytes();
        saw_leading_zero |= bytes[0] == 0;
        counts[usize::from(bytes[MODULUS_BYTES - 1] & 0x0f)] += 1;
    }
    let expected = SAMPLES as f64 / counts.len() as f64;
    let chi_squared = counts
        .iter()
        .map(|count| {
            let delta = *count as f64 - expected;
            delta * delta / expected
        })
        .sum::<f64>();
    assert!(chi_squared < 40.0, "low-nibble chi-squared regression: {chi_squared}");
    assert!(counts.iter().all(|count| (190..=330).contains(count)));
    assert!(saw_leading_zero, "fixed-width nonce sampling lost leading-zero values");
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 128,
        failure_persistence: None,
        ..ProptestConfig::default()
    })]

    #[test]
    fn plaintext_codec_round_trips_with_fixed_padding(bytes in any::<[u8; 32]>()) {
        let public_key = secret_key().public_key();
        let input = SecretPlaintextBytes3072::left_pad(Zeroizing::new(bytes))?;
        let plaintext = public_key.plaintext_from_secret_bytes(input)?;
        let encoded = plaintext.to_secret_bytes();
        prop_assert!(encoded[..MODULUS_BYTES - 32].iter().all(|byte| *byte == 0));
        prop_assert_eq!(&encoded[MODULUS_BYTES - 32..], &bytes);
    }

    #[test]
    fn arbitrary_exact_secret_plaintexts_never_panic(bytes in any::<[u8; MODULUS_BYTES]>()) {
        let input = SecretPlaintextBytes3072::new(Zeroizing::new(bytes));
        let _ = secret_key().public_key().plaintext_from_secret_bytes(input);
    }

    #[test]
    fn arbitrary_raw_modulus_bytes_never_panic(bytes in any::<[u8; MODULUS_BYTES]>()) {
        let _ = RawPublicKey3072::from_bytes(bytes);
    }

    #[test]
    fn malformed_variable_length_inputs_never_panic(bytes in prop::collection::vec(any::<u8>(), 0..=800)) {
        let _ = RawPublicKey3072::from_bytes(&bytes);
        let _ = SecretKey3072::from_borrowed_secret_bytes(&bytes);
        let _ = PublicExponent3072::from_bytes(&bytes);
    }
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 16,
        failure_persistence: None,
        ..ProptestConfig::default()
    })]

    #[test]
    fn randomized_encryption_inverse_and_homomorphic_laws_match_oracle(
        left_value in any::<u16>(),
        right_value in any::<u16>(),
        left_nonce in 1_u16..=u16::MAX,
        right_nonce in 1_u16..=u16::MAX,
    ) {
        let public_key = secret_key().public_key();
        let n = BigUint::from_bytes_be(&public_key.to_bytes());
        let nn = &n * &n;
        let generator = &n + BigUint::one();
        let left_plaintext = small_plaintext(public_key, u64::from(left_value));
        let right_plaintext = small_plaintext(public_key, u64::from(right_value));
        let left = public_key.compose_with_nonce_for_test(
            &left_plaintext,
            &local_nonce(public_key, u64::from(left_nonce)),
        )?;
        let right = public_key.compose_with_nonce_for_test(
            &right_plaintext,
            &local_nonce(public_key, u64::from(right_nonce)),
        )?;
        let expected = (generator.modpow(&BigUint::from(left_value), &nn)
            * BigUint::from(left_nonce).modpow(&n, &nn)) % &nn;
        prop_assert_eq!(BigUint::from_bytes_be(&left.to_bytes()), expected);
        let decrypted_left = secret_key().decrypt(&left)?.to_secret_bytes();
        let expected_left = left_plaintext.to_secret_bytes();
        prop_assert_eq!(decrypted_left.as_ref(), expected_left.as_ref());
        prop_assert_eq!(public_key.ciphertext_from_bytes(left.to_bytes())?, left.clone());

        let sum_lr = public_key.add(&left, &right)?;
        let sum_rl = public_key.add(&right, &left)?;
        prop_assert_eq!(&sum_lr, &sum_rl);
        let expected_sum = u64::from(left_value) + u64::from(right_value);
        let decrypted_sum = secret_key().decrypt(&sum_lr)?.to_secret_bytes();
        let expected_sum = small_plaintext(public_key, expected_sum).to_secret_bytes();
        prop_assert_eq!(decrypted_sum.as_ref(), expected_sum.as_ref());
        prop_assert_eq!(public_key.subtract(&sum_lr, &right)?, left);
    }
}

fn small_plaintext(public_key: &PublicKey3072, value: u64) -> SecretPlaintext3072 {
    public_key
        .plaintext_from_secret_bytes(
            SecretPlaintextBytes3072::left_pad(Zeroizing::new(value.to_be_bytes()))
                .expect("fixed-width small plaintext input"),
        )
        .expect("small plaintext is below N")
}

fn local_nonce(public_key: &PublicKey3072, value: u64) -> EncryptionNonce3072 {
    let mut bytes = Zeroizing::new([0_u8; MODULUS_BYTES]);
    bytes[MODULUS_BYTES - 8..].copy_from_slice(&value.to_be_bytes());
    public_key
        .encryption_nonce_from_secret_bytes_for_test(bytes)
        .expect("small fixture nonce is invertible")
}

fn assert_secret_u64(plaintext: &SecretPlaintext3072, expected: u64) {
    let encoded = plaintext.to_secret_bytes();
    assert!(encoded[..MODULUS_BYTES - 8].iter().all(|byte| *byte == 0));
    assert_eq!(&encoded[MODULUS_BYTES - 8..], &expected.to_be_bytes());
}

fn secret_plaintext_bytes_from_biguint(value: &BigUint) -> SecretPlaintextBytes3072 {
    let encoded = Zeroizing::new(value.to_bytes_be());
    let mut padded = Zeroizing::new([0_u8; MODULUS_BYTES]);
    padded[MODULUS_BYTES - encoded.len()..].copy_from_slice(encoded.as_ref());
    SecretPlaintextBytes3072::new(padded)
}

fn fixed_public_bytes<const N: usize>(value: &BigUint) -> [u8; N] {
    let encoded = value.to_bytes_be();
    let mut padded = [0_u8; N];
    padded[N - encoded.len()..].copy_from_slice(&encoded);
    padded
}

fn fixture_record_bytes() -> [u8; SECRET_KEY_BYTES] {
    let decoded = hex::decode(include_str!("../tests/fixtures/secret_key_v1.hex").trim()).expect("key fixture hex");
    <[u8; SECRET_KEY_BYTES]>::try_from(decoded).expect("fixed-size key fixture")
}

fn secret_record(bytes: [u8; SECRET_KEY_BYTES]) -> SecretKeyBytes3072 {
    SecretKeyBytes3072::new(Zeroizing::new(bytes))
}

fn next_probable_prime(mut candidate: U1536) -> U1536 {
    if !bool::from(candidate.is_odd()) {
        candidate = candidate.wrapping_add(&U1536::ONE);
    }
    loop {
        if is_prime(Flavor::Any, &candidate) {
            return candidate;
        }
        candidate = candidate.wrapping_add(&U1536::from(2_u8));
    }
}
