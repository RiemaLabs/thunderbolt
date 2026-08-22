use crate::{Result, ThunderboltError};
use libpaillier::{unknown_order::BigNumber, Ciphertext, DecryptionKey, EncryptionKey, Nonce};
use zeroize::Zeroize;

/// Canonical modulus width of the legacy v1 Paillier profile.
///
/// This constant remains unchanged for compatibility. New code selects a
/// closed [`PaillierModulusProfile`] instead of changing this value.
pub const PAILLIER_MODULUS_BYTES: usize = 256;
const MIN_PAILLIER_MODULUS_BITS: usize = PAILLIER_MODULUS_BYTES * 8 - 1;
const MAX_PAILLIER_MODULUS_BITS: usize = PAILLIER_MODULUS_BYTES * 8;

/// Closed, wire-versioned Paillier modulus profiles.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PaillierModulusProfile {
    /// Release-candidate/v1 profile with a 2048-bit modulus.
    LegacyRc2048V1 = 1,
    /// Protocol-v2 production profile evaluated by the accepted paper.
    ProtocolV2Production3072 = 2,
}

impl PaillierModulusProfile {
    /// Returns the exact canonical modulus width.
    #[must_use]
    pub const fn modulus_bytes(self) -> usize {
        match self {
            Self::LegacyRc2048V1 => PAILLIER_MODULUS_BYTES,
            Self::ProtocolV2Production3072 => 384,
        }
    }

    /// Returns the exact canonical ciphertext width.
    #[must_use]
    pub const fn ciphertext_bytes(self) -> usize {
        self.modulus_bytes() * 2
    }

    /// Returns the exact canonical nonce width.
    #[must_use]
    pub const fn nonce_bytes(self) -> usize {
        self.modulus_bytes()
    }

    const fn minimum_modulus_bits(self) -> usize {
        self.modulus_bytes() * 8 - 1
    }

    const fn maximum_modulus_bits(self) -> usize {
        self.modulus_bytes() * 8
    }
}

/// Rejects profiles unsupported by the compiled arbitrary-precision backend.
///
/// libpaillier's current default backend cannot represent a 3072-bit modulus
/// squared and panics during key construction. Rejecting here keeps every v2
/// entry point fail-closed before statement-controlled arithmetic.
pub fn validate_paillier_backend(profile: PaillierModulusProfile) -> Result<()> {
    match profile {
        PaillierModulusProfile::LegacyRc2048V1 => Ok(()),
        PaillierModulusProfile::ProtocolV2Production3072 => {
            Err(ThunderboltError::CryptographicError(
                "3072-bit Paillier requires an approved arbitrary-precision backend; the compiled fixed-width backend is unsupported"
                    .to_string(),
            ))
        }
    }
}

/// Generates a decryption key for one of the closed parameter profiles.
///
/// No bit-count argument is accepted: callers must select a wire-versioned
/// profile. The backend gate runs before prime generation.
pub fn generate_decryption_key_with_profile(profile: PaillierModulusProfile) -> Result<DecryptionKey> {
    validate_paillier_backend(profile)?;
    match profile {
        PaillierModulusProfile::LegacyRc2048V1 => DecryptionKey::random().ok_or_else(|| {
            ThunderboltError::CryptographicError("failed to generate a Paillier decryption key".to_string())
        }),
        PaillierModulusProfile::ProtocolV2Production3072 => Err(ThunderboltError::CryptographicError(
            "3072-bit Paillier key generation is disabled for the compiled fixed-width backend".to_string(),
        )),
    }
}

pub trait PaillierAccount {
    /// Encrypts with fresh CSPRNG-sampled randomness.
    ///
    /// Callers do not supply nonces because reusing or predicting a Paillier
    /// nonce breaks semantic security.
    fn encrypt(&self, secret: &[u8]) -> Result<(Ciphertext, Nonce)>;
    fn decrypt(&self, ciphertext: &Ciphertext) -> Option<Vec<u8>>;
}

pub struct PaillierAccountLocal {
    profile: PaillierModulusProfile,
    public_key: EncryptionKey,
    private_key: DecryptionKey,
}

impl PaillierAccount for PaillierAccountLocal {
    fn encrypt(&self, secret: &[u8]) -> Result<(Ciphertext, Nonce)> {
        match self.profile {
            PaillierModulusProfile::LegacyRc2048V1 => {
                let plaintext = BigNumber::from_slice(secret);
                let nonce = random_nonce_in_group(&self.public_key);
                let ciphertext = encrypt_plaintext(&self.public_key, &plaintext, &nonce)?;
                Ok((ciphertext, nonce))
            }
            PaillierModulusProfile::ProtocolV2Production3072 => {
                validate_paillier_backend(self.profile)?;
                let plaintext = BigNumber::from_slice(secret);
                let nonce = random_nonce_in_group_with_profile(self.profile, &self.public_key)?;
                let ciphertext = encrypt_plaintext_with_profile(self.profile, &self.public_key, &plaintext, &nonce)?;
                Ok((ciphertext, nonce))
            }
        }
    }

    fn decrypt(&self, ciphertext: &Ciphertext) -> Option<Vec<u8>> {
        match self.profile {
            PaillierModulusProfile::LegacyRc2048V1 => self.private_key.decrypt(ciphertext),
            PaillierModulusProfile::ProtocolV2Production3072 => {
                decrypt_to_big_number_with_profile(self.profile, &self.private_key, ciphertext)
                    .ok()
                    .map(|plaintext| plaintext.to_bytes())
            }
        }
    }
}

impl PaillierAccountLocal {
    /// Generates a legacy v1 2048-bit account.
    ///
    /// Protocol-v2 integrations must use `new_with_profile` and must not fall
    /// back to this constructor when the production profile is unavailable.
    pub fn new() -> Option<Self> {
        let private_key = DecryptionKey::random()?;
        let public_key = EncryptionKey::from(&private_key);
        Some(Self {
            profile: PaillierModulusProfile::LegacyRc2048V1,
            public_key,
            private_key,
        })
    }

    /// Generates a local account using an approved, closed parameter profile.
    pub fn new_with_profile(profile: PaillierModulusProfile) -> Result<Self> {
        let private_key = generate_decryption_key_with_profile(profile)?;
        Self::from_decryption_key_with_profile(profile, private_key)
    }

    /// Constructs a local account from persisted key material after checking
    /// that it belongs to the selected closed profile.
    pub fn from_decryption_key_with_profile(
        profile: PaillierModulusProfile,
        private_key: DecryptionKey,
    ) -> Result<Self> {
        validate_paillier_backend(profile)?;
        let public_key = EncryptionKey::from(&private_key);
        validate_protocol_encryption_key_with_profile(profile, &public_key)?;
        Ok(Self {
            profile,
            public_key,
            private_key,
        })
    }

    /// Returns the immutable parameter profile for this account.
    #[must_use]
    pub const fn profile(&self) -> PaillierModulusProfile {
        self.profile
    }

    pub fn public_key(&self) -> &EncryptionKey {
        &self.public_key
    }

    pub fn decrypt_big_number(&self, ciphertext: &Ciphertext) -> Result<BigNumber> {
        match self.profile {
            PaillierModulusProfile::LegacyRc2048V1 => decrypt_to_big_number(&self.private_key, ciphertext),
            PaillierModulusProfile::ProtocolV2Production3072 => {
                decrypt_to_big_number_with_profile(self.profile, &self.private_key, ciphertext)
            }
        }
    }
}

fn ensure_non_negative(label: &str, value: &BigNumber) -> Result<()> {
    if value < &BigNumber::zero() {
        return Err(ThunderboltError::OutOfRange(format!("{label} must be non-negative")));
    }

    Ok(())
}

/// Validates a legacy v1 2048-bit key.
///
/// Protocol-v2 code must use `validate_protocol_encryption_key_with_profile`.
/// This rejects attacker-sized keys before any GCD or modular exponentiation.
pub fn validate_protocol_encryption_key(pk: &EncryptionKey) -> Result<()> {
    let bits = pk.n().bit_length();
    if !(MIN_PAILLIER_MODULUS_BITS..=MAX_PAILLIER_MODULUS_BITS).contains(&bits)
        || pk.to_bytes().len() != PAILLIER_MODULUS_BYTES
        || pk.n().is_zero()
        || (pk.n() % BigNumber::from(2u32)).is_zero()
    {
        return Err(ThunderboltError::InvalidParameter(format!(
            "Paillier modulus must use the {MAX_PAILLIER_MODULUS_BITS}-bit legacy v1 parameter"
        )));
    }
    Ok(())
}

pub fn validate_plaintext(pk: &EncryptionKey, plaintext: &BigNumber) -> Result<()> {
    ensure_non_negative("Paillier plaintext", plaintext)?;

    if plaintext >= pk.n() {
        return Err(ThunderboltError::OutOfRange(
            "Paillier plaintext must be smaller than the Paillier modulus".to_string(),
        ));
    }

    Ok(())
}

pub fn validate_nonce(pk: &EncryptionKey, nonce: &Nonce) -> Result<()> {
    ensure_non_negative("Paillier nonce", nonce)?;

    if nonce.is_zero() || nonce >= pk.n() {
        return Err(ThunderboltError::InvalidNonce(
            "Paillier nonce must lie in the range [1, N)".to_string(),
        ));
    }

    if nonce.gcd(pk.n()) != BigNumber::one() {
        return Err(ThunderboltError::InvalidNonce(
            "Paillier nonce must lie in Z_N* (be invertible modulo N)".to_string(),
        ));
    }

    Ok(())
}

pub fn validate_ciphertext(pk: &EncryptionKey, ciphertext: &Ciphertext) -> Result<()> {
    ensure_non_negative("Paillier ciphertext", ciphertext)?;

    if ciphertext.is_zero() || ciphertext >= pk.nn() {
        return Err(ThunderboltError::InvalidCiphertext(
            "Paillier ciphertext must lie in the range [1, N^2)".to_string(),
        ));
    }

    if ciphertext.gcd(pk.nn()) != BigNumber::one() {
        return Err(ThunderboltError::InvalidCiphertext(
            "Paillier ciphertext must be invertible modulo N^2".to_string(),
        ));
    }

    Ok(())
}

/// Validates that a key belongs to the selected closed profile.
pub fn validate_protocol_encryption_key_with_profile(
    profile: PaillierModulusProfile,
    pk: &EncryptionKey,
) -> Result<()> {
    validate_paillier_backend(profile)?;

    let bits = pk.n().bit_length();
    if pk.to_bytes().len() != profile.modulus_bytes()
        || !(profile.minimum_modulus_bits()..=profile.maximum_modulus_bits()).contains(&bits)
    {
        return Err(ThunderboltError::InvalidParameter(format!(
            "Paillier modulus does not match profile {profile:?}"
        )));
    }

    if pk.n().is_zero() || (pk.n() % BigNumber::from(2u32)).is_zero() {
        return Err(ThunderboltError::InvalidParameter(
            "Paillier modulus must be a positive odd integer".to_string(),
        ));
    }

    Ok(())
}

/// Decodes an exact-width public key after checking backend support first.
///
/// On the compiled backend, a 384-byte v2 input is rejected before constructing
/// `BigNumber` or `EncryptionKey`, avoiding libpaillier's known `N^2` panic.
pub fn decode_encryption_key_with_profile(profile: PaillierModulusProfile, encoded: &[u8]) -> Result<EncryptionKey> {
    validate_paillier_backend(profile)?;
    if encoded.len() != profile.modulus_bytes() {
        return Err(ThunderboltError::InvalidParameter(format!(
            "Paillier modulus encoding must be exactly {} bytes for profile {profile:?}",
            profile.modulus_bytes()
        )));
    }
    let key = EncryptionKey::from_n(BigNumber::from_slice(encoded));
    validate_protocol_encryption_key_with_profile(profile, &key)?;
    Ok(key)
}

/// Encodes a validated public key at its exact profile width.
pub fn encode_encryption_key_with_profile(profile: PaillierModulusProfile, key: &EncryptionKey) -> Result<Vec<u8>> {
    validate_protocol_encryption_key_with_profile(profile, key)?;
    left_pad_profile_value(key.to_bytes(), profile.modulus_bytes(), "Paillier modulus")
}

/// Validates a plaintext under the selected closed profile.
pub fn validate_plaintext_with_profile(
    profile: PaillierModulusProfile,
    pk: &EncryptionKey,
    plaintext: &BigNumber,
) -> Result<()> {
    validate_protocol_encryption_key_with_profile(profile, pk)?;
    validate_plaintext(pk, plaintext)
}

/// Validates a nonce under the selected closed profile.
///
/// This validates the numerical group element without conditioning randomness
/// on its minimal integer encoding. Exact transport width is enforced by
/// [`decode_nonce_with_profile`].
pub fn validate_nonce_with_profile(profile: PaillierModulusProfile, pk: &EncryptionKey, nonce: &Nonce) -> Result<()> {
    validate_protocol_encryption_key_with_profile(profile, pk)?;
    ensure_non_negative("Paillier nonce", nonce)?;
    if nonce.is_zero() || nonce >= pk.n() {
        return Err(ThunderboltError::InvalidNonce(
            "Paillier nonce must lie in the range [1, N)".to_string(),
        ));
    }
    if nonce.gcd(pk.n()) != BigNumber::one() {
        return Err(ThunderboltError::InvalidNonce(
            "Paillier nonce must lie in Z_N* (be invertible modulo N)".to_string(),
        ));
    }

    Ok(())
}

/// Decodes an exact-width nonce before running numerical group validation.
pub fn decode_nonce_with_profile(profile: PaillierModulusProfile, pk: &EncryptionKey, encoded: &[u8]) -> Result<Nonce> {
    validate_paillier_backend(profile)?;
    validate_protocol_encryption_key_with_profile(profile, pk)?;
    if encoded.len() != profile.nonce_bytes() {
        return Err(ThunderboltError::InvalidNonce(format!(
            "Paillier nonce encoding must be exactly {} bytes for profile {profile:?}",
            profile.nonce_bytes()
        )));
    }
    let nonce = BigNumber::from_slice(encoded);
    validate_nonce_with_profile(profile, pk, &nonce)?;
    Ok(nonce)
}

/// Left-pads a uniformly sampled valid nonce to its exact transport width.
pub fn encode_nonce_with_profile(
    profile: PaillierModulusProfile,
    pk: &EncryptionKey,
    nonce: &Nonce,
) -> Result<Vec<u8>> {
    validate_nonce_with_profile(profile, pk, nonce)?;
    left_pad_profile_value(nonce.to_bytes(), profile.nonce_bytes(), "Paillier nonce")
}

/// Validates a ciphertext under the selected closed profile.
///
/// This validates the numerical group element without conditioning ciphertext
/// distribution on its minimal integer encoding. Exact transport width is
/// enforced by [`decode_ciphertext_with_profile`].
pub fn validate_ciphertext_with_profile(
    profile: PaillierModulusProfile,
    pk: &EncryptionKey,
    ciphertext: &Ciphertext,
) -> Result<()> {
    validate_protocol_encryption_key_with_profile(profile, pk)?;
    ensure_non_negative("Paillier ciphertext", ciphertext)?;
    if ciphertext.is_zero() || ciphertext >= pk.nn() {
        return Err(ThunderboltError::InvalidCiphertext(
            "Paillier ciphertext must lie in the range [1, N^2)".to_string(),
        ));
    }
    if ciphertext.gcd(pk.nn()) != BigNumber::one() {
        return Err(ThunderboltError::InvalidCiphertext(
            "Paillier ciphertext must be invertible modulo N^2".to_string(),
        ));
    }

    Ok(())
}

/// Decodes an exact-width ciphertext before running numerical group validation.
pub fn decode_ciphertext_with_profile(
    profile: PaillierModulusProfile,
    pk: &EncryptionKey,
    encoded: &[u8],
) -> Result<Ciphertext> {
    validate_paillier_backend(profile)?;
    validate_protocol_encryption_key_with_profile(profile, pk)?;
    if encoded.len() != profile.ciphertext_bytes() {
        return Err(ThunderboltError::InvalidCiphertext(format!(
            "Paillier ciphertext encoding must be exactly {} bytes for profile {profile:?}",
            profile.ciphertext_bytes()
        )));
    }
    let ciphertext = BigNumber::from_slice(encoded);
    validate_ciphertext_with_profile(profile, pk, &ciphertext)?;
    Ok(ciphertext)
}

/// Left-pads a valid ciphertext to its exact transport width.
pub fn encode_ciphertext_with_profile(
    profile: PaillierModulusProfile,
    pk: &EncryptionKey,
    ciphertext: &Ciphertext,
) -> Result<Vec<u8>> {
    validate_ciphertext_with_profile(profile, pk, ciphertext)?;
    left_pad_profile_value(ciphertext.to_bytes(), profile.ciphertext_bytes(), "Paillier ciphertext")
}

fn left_pad_profile_value(mut bytes: Vec<u8>, width: usize, label: &str) -> Result<Vec<u8>> {
    if bytes.len() > width {
        return Err(ThunderboltError::OutOfRange(format!(
            "{label} exceeds the {width}-byte profile width"
        )));
    }
    if bytes.len() == width {
        return Ok(bytes);
    }
    let mut encoded = vec![0_u8; width];
    let offset = width - bytes.len();
    encoded[offset..].copy_from_slice(&bytes);
    bytes.zeroize();
    Ok(encoded)
}

pub fn paillier_generator(pk: &EncryptionKey) -> BigNumber {
    pk.n() + BigNumber::one()
}

/// Samples a nonce for the legacy unprofiled compatibility API.
pub fn random_nonce_in_group(pk: &EncryptionKey) -> Nonce {
    loop {
        let candidate = Nonce::random(pk.n());
        if validate_nonce(pk, &candidate).is_ok() {
            return candidate;
        }
    }
}

pub fn compose_ciphertext(pk: &EncryptionKey, exponent: &BigNumber, nonce: &Nonce) -> Result<Ciphertext> {
    ensure_non_negative("Paillier exponent", exponent)?;
    validate_nonce(pk, nonce)?;

    let generator = paillier_generator(pk);
    let g_term = generator.modpow(exponent, pk.nn());
    let n_term = nonce.modpow(pk.n(), pk.nn());

    Ok(g_term.modmul(&n_term, pk.nn()))
}

/// Encrypts through the legacy unprofiled compatibility API.
pub fn encrypt_plaintext(pk: &EncryptionKey, plaintext: &BigNumber, nonce: &Nonce) -> Result<Ciphertext> {
    validate_plaintext(pk, plaintext)?;
    compose_ciphertext(pk, plaintext, nonce)
}

pub fn decrypt_to_big_number(sk: &DecryptionKey, ciphertext: &Ciphertext) -> Result<BigNumber> {
    sk.decrypt(ciphertext)
        .map(|bytes| BigNumber::from_slice(bytes.as_slice()))
        .ok_or_else(|| {
            ThunderboltError::CryptographicError(
                "failed to decrypt Paillier ciphertext with the supplied key".to_string(),
            )
        })
}

pub fn add_ciphertexts(pk: &EncryptionKey, left: &Ciphertext, right: &Ciphertext) -> Result<Ciphertext> {
    validate_ciphertext(pk, left)?;
    validate_ciphertext(pk, right)?;

    Ok(left.modmul(right, pk.nn()))
}

pub fn invert_ciphertext(pk: &EncryptionKey, ciphertext: &Ciphertext) -> Result<Ciphertext> {
    validate_ciphertext(pk, ciphertext)?;

    ciphertext.invert(pk.nn()).ok_or_else(|| {
        ThunderboltError::InvalidCiphertext("Paillier ciphertext is not invertible modulo N^2".to_string())
    })
}

pub fn subtract_ciphertexts(pk: &EncryptionKey, minuend: &Ciphertext, subtrahend: &Ciphertext) -> Result<Ciphertext> {
    let inverse = invert_ciphertext(pk, subtrahend)?;
    add_ciphertexts(pk, minuend, &inverse)
}

pub fn exponentiate_ciphertext(
    pk: &EncryptionKey,
    ciphertext: &Ciphertext,
    exponent: &BigNumber,
) -> Result<Ciphertext> {
    validate_ciphertext(pk, ciphertext)?;
    ensure_non_negative("ciphertext exponent", exponent)?;

    Ok(ciphertext.modpow(exponent, pk.nn()))
}

pub fn combine_response_nonce(
    pk: &EncryptionKey,
    commitment_nonce: &Nonce,
    witness_nonce: &Nonce,
    challenge: &BigNumber,
) -> Result<Nonce> {
    validate_nonce(pk, commitment_nonce)?;
    validate_nonce(pk, witness_nonce)?;
    ensure_non_negative("Fiat-Shamir challenge", challenge)?;

    let witness_term = witness_nonce.modpow(challenge, pk.n());
    let response = commitment_nonce.modmul(&witness_term, pk.n());

    validate_nonce(pk, &response)?;
    Ok(response)
}

pub fn build_response_lhs(pk: &EncryptionKey, z: &BigNumber, tau: &Nonce) -> Result<Ciphertext> {
    compose_ciphertext(pk, z, tau)
}

/// Returns the Paillier generator after checking the selected profile.
pub fn paillier_generator_with_profile(profile: PaillierModulusProfile, pk: &EncryptionKey) -> Result<BigNumber> {
    validate_protocol_encryption_key_with_profile(profile, pk)?;
    Ok(paillier_generator(pk))
}

/// Samples a canonical, invertible nonce for the selected profile.
pub fn random_nonce_in_group_with_profile(profile: PaillierModulusProfile, pk: &EncryptionKey) -> Result<Nonce> {
    validate_protocol_encryption_key_with_profile(profile, pk)?;
    Ok(random_nonce_in_group(pk))
}

/// Composes a Paillier ciphertext under the selected profile.
pub fn compose_ciphertext_with_profile(
    profile: PaillierModulusProfile,
    pk: &EncryptionKey,
    exponent: &BigNumber,
    nonce: &Nonce,
) -> Result<Ciphertext> {
    validate_paillier_backend(profile)?;
    validate_protocol_encryption_key_with_profile(profile, pk)?;
    ensure_non_negative("Paillier exponent", exponent)?;
    validate_nonce_with_profile(profile, pk, nonce)?;

    let generator = paillier_generator(pk);
    let g_term = generator.modpow(exponent, pk.nn());
    let n_term = nonce.modpow(pk.n(), pk.nn());
    let ciphertext = g_term.modmul(&n_term, pk.nn());
    validate_ciphertext_with_profile(profile, pk, &ciphertext)?;
    Ok(ciphertext)
}

/// Encrypts a plaintext under the selected profile and supplied nonce.
pub fn encrypt_plaintext_with_profile(
    profile: PaillierModulusProfile,
    pk: &EncryptionKey,
    plaintext: &BigNumber,
    nonce: &Nonce,
) -> Result<Ciphertext> {
    validate_plaintext_with_profile(profile, pk, plaintext)?;
    compose_ciphertext_with_profile(profile, pk, plaintext, nonce)
}

/// Adds two ciphertexts under the selected profile.
pub fn add_ciphertexts_with_profile(
    profile: PaillierModulusProfile,
    pk: &EncryptionKey,
    left: &Ciphertext,
    right: &Ciphertext,
) -> Result<Ciphertext> {
    validate_paillier_backend(profile)?;
    validate_ciphertext_with_profile(profile, pk, left)?;
    validate_ciphertext_with_profile(profile, pk, right)?;
    let ciphertext = left.modmul(right, pk.nn());
    validate_ciphertext_with_profile(profile, pk, &ciphertext)?;
    Ok(ciphertext)
}

/// Inverts a ciphertext under the selected profile.
pub fn invert_ciphertext_with_profile(
    profile: PaillierModulusProfile,
    pk: &EncryptionKey,
    ciphertext: &Ciphertext,
) -> Result<Ciphertext> {
    validate_paillier_backend(profile)?;
    validate_ciphertext_with_profile(profile, pk, ciphertext)?;
    let inverse = ciphertext.invert(pk.nn()).ok_or_else(|| {
        ThunderboltError::InvalidCiphertext("Paillier ciphertext is not invertible modulo N^2".to_string())
    })?;
    validate_ciphertext_with_profile(profile, pk, &inverse)?;
    Ok(inverse)
}

/// Subtracts two ciphertexts under the selected profile.
pub fn subtract_ciphertexts_with_profile(
    profile: PaillierModulusProfile,
    pk: &EncryptionKey,
    minuend: &Ciphertext,
    subtrahend: &Ciphertext,
) -> Result<Ciphertext> {
    validate_paillier_backend(profile)?;
    let inverse = invert_ciphertext_with_profile(profile, pk, subtrahend)?;
    add_ciphertexts_with_profile(profile, pk, minuend, &inverse)
}

/// Exponentiates a ciphertext under the selected profile.
pub fn exponentiate_ciphertext_with_profile(
    profile: PaillierModulusProfile,
    pk: &EncryptionKey,
    ciphertext: &Ciphertext,
    exponent: &BigNumber,
) -> Result<Ciphertext> {
    validate_paillier_backend(profile)?;
    validate_ciphertext_with_profile(profile, pk, ciphertext)?;
    ensure_non_negative("ciphertext exponent", exponent)?;
    let result = ciphertext.modpow(exponent, pk.nn());
    validate_ciphertext_with_profile(profile, pk, &result)?;
    Ok(result)
}

/// Combines proof-response nonces under the selected profile.
pub fn combine_response_nonce_with_profile(
    profile: PaillierModulusProfile,
    pk: &EncryptionKey,
    commitment_nonce: &Nonce,
    witness_nonce: &Nonce,
    challenge: &BigNumber,
) -> Result<Nonce> {
    validate_paillier_backend(profile)?;
    validate_nonce_with_profile(profile, pk, commitment_nonce)?;
    validate_nonce_with_profile(profile, pk, witness_nonce)?;
    ensure_non_negative("Fiat-Shamir challenge", challenge)?;

    let witness_term = witness_nonce.modpow(challenge, pk.n());
    let response = commitment_nonce.modmul(&witness_term, pk.n());
    validate_nonce_with_profile(profile, pk, &response)?;
    Ok(response)
}

/// Builds the left-hand side of a proof response under the selected profile.
pub fn build_response_lhs_with_profile(
    profile: PaillierModulusProfile,
    pk: &EncryptionKey,
    z: &BigNumber,
    tau: &Nonce,
) -> Result<Ciphertext> {
    compose_ciphertext_with_profile(profile, pk, z, tau)
}

/// Decrypts after checking the key and ciphertext against the selected profile.
pub fn decrypt_to_big_number_with_profile(
    profile: PaillierModulusProfile,
    sk: &DecryptionKey,
    ciphertext: &Ciphertext,
) -> Result<BigNumber> {
    validate_paillier_backend(profile)?;
    let pk = EncryptionKey::from(sk);
    validate_protocol_encryption_key_with_profile(profile, &pk)?;
    validate_ciphertext_with_profile(profile, &pk, ciphertext)?;
    decrypt_to_big_number(sk, ciphertext)
}

#[cfg(test)]
mod tests {
    use std::panic::{catch_unwind, AssertUnwindSafe};

    use zeroize::Zeroize;

    use super::*;

    fn small_test_key() -> (EncryptionKey, DecryptionKey) {
        let mut p = BigNumber::prime(256);
        let mut q = BigNumber::prime(256);
        while p == q {
            q = BigNumber::prime(256);
        }
        let sk = DecryptionKey::with_primes_unchecked(&p, &q).unwrap();
        p.zeroize();
        q.zeroize();
        let pk = EncryptionKey::from(&sk);
        (pk, sk)
    }

    #[test]
    fn encrypts_and_decrypts_zero_plaintext() {
        let (pk, sk) = small_test_key();
        let nonce = random_nonce_in_group(&pk);
        let ciphertext = encrypt_plaintext(&pk, &BigNumber::zero(), &nonce).unwrap();
        let plaintext = decrypt_to_big_number(&sk, &ciphertext).unwrap();

        assert!(plaintext.is_zero());
    }

    #[test]
    fn rejects_non_invertible_ciphertexts() {
        let (pk, _) = small_test_key();
        let nonce = random_nonce_in_group(&pk);
        let plaintext = BigNumber::from(9u32);
        let ciphertext = encrypt_plaintext(&pk, &plaintext, &nonce).unwrap();

        let invalid_ciphertext = BigNumber::zero();
        assert!(subtract_ciphertexts(&pk, &ciphertext, &invalid_ciphertext).is_err());
    }

    #[test]
    fn rejects_wrong_sized_protocol_keys_before_expensive_verification() {
        let small = EncryptionKey::from_n(BigNumber::from(17u32));
        assert!(validate_protocol_encryption_key(&small).is_err());

        let oversized = EncryptionKey::from_n((BigNumber::one() << 4096) + BigNumber::one());
        assert!(validate_protocol_encryption_key(&oversized).is_err());
    }

    #[test]
    fn profiles_have_stable_versions_and_exact_widths() {
        assert_eq!(PaillierModulusProfile::LegacyRc2048V1 as u8, 1);
        assert_eq!(PaillierModulusProfile::LegacyRc2048V1.modulus_bytes(), 256);
        assert_eq!(PaillierModulusProfile::LegacyRc2048V1.nonce_bytes(), 256);
        assert_eq!(PaillierModulusProfile::LegacyRc2048V1.ciphertext_bytes(), 512);

        assert_eq!(PaillierModulusProfile::ProtocolV2Production3072 as u8, 2);
        assert_eq!(PaillierModulusProfile::ProtocolV2Production3072.modulus_bytes(), 384);
        assert_eq!(PaillierModulusProfile::ProtocolV2Production3072.nonce_bytes(), 384);
        assert_eq!(PaillierModulusProfile::ProtocolV2Production3072.ciphertext_bytes(), 768);
    }

    #[test]
    fn production_profile_fails_closed_before_backend_arithmetic() {
        let profile = PaillierModulusProfile::ProtocolV2Production3072;
        let (pk, sk) = small_test_key();
        let value = BigNumber::one();

        let result = catch_unwind(AssertUnwindSafe(|| {
            assert!(validate_paillier_backend(profile).is_err());
            assert!(validate_protocol_encryption_key_with_profile(profile, &pk).is_err());
            assert!(validate_nonce_with_profile(profile, &pk, &value).is_err());
            assert!(validate_ciphertext_with_profile(profile, &pk, &value).is_err());
            assert!(random_nonce_in_group_with_profile(profile, &pk).is_err());
            assert!(compose_ciphertext_with_profile(profile, &pk, &value, &value).is_err());
            assert!(encrypt_plaintext_with_profile(profile, &pk, &value, &value).is_err());
            assert!(add_ciphertexts_with_profile(profile, &pk, &value, &value).is_err());
            assert!(exponentiate_ciphertext_with_profile(profile, &pk, &value, &value).is_err());
            assert!(combine_response_nonce_with_profile(profile, &pk, &value, &value, &value).is_err());
            assert!(build_response_lhs_with_profile(profile, &pk, &value, &value).is_err());
            assert!(decrypt_to_big_number_with_profile(profile, &sk, &value).is_err());
            assert!(generate_decryption_key_with_profile(profile).is_err());
            assert!(PaillierAccountLocal::new_with_profile(profile).is_err());
            assert!(decode_encryption_key_with_profile(profile, &[0xff; 384]).is_err());
            assert!(decode_nonce_with_profile(profile, &pk, &[0xff; 384]).is_err());
            assert!(decode_ciphertext_with_profile(profile, &pk, &[0xff; 768]).is_err());
        }));

        assert!(result.is_ok(), "unsupported v2 calls must not panic");
    }

    #[test]
    fn fixed_width_codecs_pad_short_valid_group_elements() {
        let account = PaillierAccountLocal::new_with_profile(PaillierModulusProfile::LegacyRc2048V1).unwrap();
        let short_but_valid = BigNumber::one();

        validate_nonce_with_profile(account.profile(), account.public_key(), &short_but_valid).unwrap();
        validate_ciphertext_with_profile(account.profile(), account.public_key(), &short_but_valid).unwrap();

        let nonce_bytes = encode_nonce_with_profile(account.profile(), account.public_key(), &short_but_valid).unwrap();
        assert_eq!(nonce_bytes.len(), account.profile().nonce_bytes());
        assert_eq!(
            decode_nonce_with_profile(account.profile(), account.public_key(), &nonce_bytes).unwrap(),
            short_but_valid
        );
        assert!(decode_nonce_with_profile(account.profile(), account.public_key(), &nonce_bytes[1..]).is_err());

        let ciphertext_bytes =
            encode_ciphertext_with_profile(account.profile(), account.public_key(), &BigNumber::one()).unwrap();
        assert_eq!(ciphertext_bytes.len(), account.profile().ciphertext_bytes());
        assert_eq!(
            decode_ciphertext_with_profile(account.profile(), account.public_key(), &ciphertext_bytes).unwrap(),
            BigNumber::one()
        );
        assert!(
            decode_ciphertext_with_profile(account.profile(), account.public_key(), &ciphertext_bytes[1..]).is_err()
        );
    }

    #[test]
    fn legacy_account_outputs_validate_and_round_trip_through_fixed_width_codec() {
        let account = PaillierAccountLocal::new_with_profile(PaillierModulusProfile::LegacyRc2048V1).unwrap();
        let plaintext = BigNumber::from(42u32);

        let (ciphertext, nonce) = account.encrypt(&plaintext.to_bytes()).unwrap();
        validate_nonce_with_profile(account.profile(), account.public_key(), &nonce).unwrap();
        validate_ciphertext_with_profile(account.profile(), account.public_key(), &ciphertext).unwrap();
        let encoded = encode_ciphertext_with_profile(account.profile(), account.public_key(), &ciphertext).unwrap();
        let decoded = decode_ciphertext_with_profile(account.profile(), account.public_key(), &encoded).unwrap();

        assert_eq!(
            decrypt_to_big_number_with_profile(account.profile(), &account.private_key, &decoded).unwrap(),
            plaintext
        );
    }
}
