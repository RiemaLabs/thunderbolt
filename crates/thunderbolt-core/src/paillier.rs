use crate::{Result, ThunderboltError};
use libpaillier::{unknown_order::BigNumber, Ciphertext, DecryptionKey, EncryptionKey, Nonce};

/// The current RC uses 2048-bit Paillier moduli. The accepted paper evaluates
/// 3072-bit Paillier; changing this constant requires a wire-version change.
pub const PAILLIER_MODULUS_BYTES: usize = 256;
const MIN_PAILLIER_MODULUS_BITS: usize = PAILLIER_MODULUS_BYTES * 8 - 1;
const MAX_PAILLIER_MODULUS_BITS: usize = PAILLIER_MODULUS_BYTES * 8;

pub trait PaillierAccount {
    /// Encrypts with fresh CSPRNG-sampled randomness.
    ///
    /// Callers do not supply nonces because reusing or predicting a Paillier
    /// nonce breaks semantic security.
    fn encrypt(&self, secret: &[u8]) -> Result<(Ciphertext, Nonce)>;
    fn decrypt(&self, ciphertext: &Ciphertext) -> Option<Vec<u8>>;
}

pub struct PaillierAccountLocal {
    public_key: EncryptionKey,
    private_key: DecryptionKey,
}

impl PaillierAccount for PaillierAccountLocal {
    fn encrypt(&self, secret: &[u8]) -> Result<(Ciphertext, Nonce)> {
        let plaintext = BigNumber::from_slice(secret);
        let nonce = random_nonce_in_group(&self.public_key);
        let ciphertext = encrypt_plaintext(&self.public_key, &plaintext, &nonce)?;
        Ok((ciphertext, nonce))
    }

    fn decrypt(&self, ciphertext: &Ciphertext) -> Option<Vec<u8>> {
        self.private_key.decrypt(ciphertext)
    }
}

impl PaillierAccountLocal {
    pub fn new() -> Option<Self> {
        let private_key = DecryptionKey::random()?;
        let public_key = EncryptionKey::from(&private_key);
        Some(Self {
            public_key,
            private_key,
        })
    }

    pub fn public_key(&self) -> &EncryptionKey {
        &self.public_key
    }

    pub fn decrypt_big_number(&self, ciphertext: &Ciphertext) -> Result<BigNumber> {
        decrypt_to_big_number(&self.private_key, ciphertext)
    }
}

fn ensure_non_negative(label: &str, value: &BigNumber) -> Result<()> {
    if value < &BigNumber::zero() {
        return Err(ThunderboltError::OutOfRange(format!("{label} must be non-negative")));
    }

    Ok(())
}

/// Rejects attacker-sized keys before any GCD or modular exponentiation.
pub fn validate_protocol_encryption_key(pk: &EncryptionKey) -> Result<()> {
    let bits = pk.n().bit_length();
    if !(MIN_PAILLIER_MODULUS_BITS..=MAX_PAILLIER_MODULUS_BITS).contains(&bits)
        || pk.to_bytes().len() != PAILLIER_MODULUS_BYTES
        || pk.n().is_zero()
        || (pk.n() % BigNumber::from(2u32)).is_zero()
    {
        return Err(ThunderboltError::InvalidParameter(format!(
            "Paillier modulus must use the {MAX_PAILLIER_MODULUS_BITS}-bit RC parameter"
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

pub fn paillier_generator(pk: &EncryptionKey) -> BigNumber {
    pk.n() + BigNumber::one()
}

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

#[cfg(test)]
mod tests {
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
}
