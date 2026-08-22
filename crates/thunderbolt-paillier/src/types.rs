use core::fmt;

use crypto_bigint::{Encoding, Limb, Uint, U1536, U3072, U6144};
use sha2::{Digest as _, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::{PaillierError, Result};

pub const PRIME_BYTES: usize = 192;
pub const MODULUS_BYTES: usize = 384;
pub const CIPHERTEXT_BYTES: usize = 768;
pub const SECRET_KEY_BYTES: usize = 8 + 2 + PRIME_BYTES * 2;

pub(crate) type Prime = U1536;
pub(crate) type Modulus = U3072;
pub(crate) type Wide = U6144;

/// Consuming, zeroizing wrapper for the versioned Paillier secret-key record.
///
/// This type intentionally implements neither `Clone` nor `Debug`.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecretKeyBytes3072(Zeroizing<[u8; SECRET_KEY_BYTES]>);

impl SecretKeyBytes3072 {
    /// Takes ownership of one exact secret-key record.
    #[must_use]
    pub fn new(bytes: Zeroizing<[u8; SECRET_KEY_BYTES]>) -> Self {
        Self(bytes)
    }

    /// Copies a borrowed record into immediately zeroizing ownership. This
    /// cannot erase the caller's original buffer.
    pub fn copy_from_slice(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != SECRET_KEY_BYTES {
            return Err(PaillierError::InvalidLength {
                field: "secret key record",
                expected: SECRET_KEY_BYTES,
                actual: bytes.len(),
            });
        }
        let mut owned = Zeroizing::new([0_u8; SECRET_KEY_BYTES]);
        owned.copy_from_slice(bytes);
        Ok(Self::new(owned))
    }
}

impl AsRef<[u8]> for SecretKeyBytes3072 {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

/// Public Paillier ciphertext modulo one exact certified key's `N^2`.
#[derive(Clone, PartialEq, Eq)]
pub struct Ciphertext3072 {
    pub(crate) value: Wide,
    pub(crate) key_modulus: [u8; MODULUS_BYTES],
}

impl Ciphertext3072 {
    /// Returns the exact 768-byte big-endian transport encoding.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; CIPHERTEXT_BYTES] {
        uint_to_array(&self.value)
    }

    /// Returns a short non-secret fingerprint suitable for diagnostics.
    #[must_use]
    pub fn fingerprint(&self) -> [u8; 8] {
        fingerprint(&self.to_bytes())
    }
}

impl fmt::Debug for Ciphertext3072 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Ciphertext3072")
            .field("fingerprint", &HexFingerprint(self.fingerprint()))
            .finish_non_exhaustive()
    }
}

/// Public response nonce in one exact certified key's `Z_N*`.
#[derive(Clone, PartialEq, Eq)]
pub struct ProofNonce3072 {
    pub(crate) value: Modulus,
    pub(crate) key_modulus: [u8; MODULUS_BYTES],
}

impl ProofNonce3072 {
    /// Returns the exact 384-byte big-endian transport encoding.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; MODULUS_BYTES] {
        uint_to_array(&self.value)
    }
}

impl fmt::Debug for ProofNonce3072 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProofNonce3072")
            .field("fingerprint", &HexFingerprint(fingerprint(&self.to_bytes())))
            .finish_non_exhaustive()
    }
}

/// Public non-negative exponent bounded by the Paillier plaintext width.
#[derive(Clone, PartialEq, Eq)]
pub struct PublicExponent3072(pub(crate) Modulus);

impl PublicExponent3072 {
    /// Parses a non-empty big-endian integer of at most 384 bytes.
    pub fn from_bytes(bytes: impl AsRef<[u8]>) -> Result<Self> {
        parse_modulus_width("public exponent", bytes.as_ref()).map(Self)
    }

    /// Returns the exact padded 384-byte encoding.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; MODULUS_BYTES] {
        uint_to_array(&self.0)
    }
}

impl fmt::Debug for PublicExponent3072 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PublicExponent3072")
            .field("bit_width", &MODULUS_BYTES.saturating_mul(8))
            .finish_non_exhaustive()
    }
}

/// Consuming exact-width plaintext input.
///
/// This type intentionally implements neither `Clone` nor `Debug`. Construct
/// it from an already-zeroizing source so the caller does not retain an
/// unmanaged secret copy.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecretPlaintextBytes3072(Zeroizing<[u8; MODULUS_BYTES]>);

impl SecretPlaintextBytes3072 {
    /// Takes ownership of an exact 384-byte, big-endian plaintext candidate.
    #[must_use]
    pub fn new(bytes: Zeroizing<[u8; MODULUS_BYTES]>) -> Self {
        Self(bytes)
    }

    /// Left-pads a consuming, zeroizing short input to the exact protocol
    /// width. The input length is public and must be in `1..=384`.
    pub fn left_pad<const N: usize>(bytes: Zeroizing<[u8; N]>) -> Result<Self> {
        if N == 0 || N > MODULUS_BYTES {
            return Err(PaillierError::InvalidLength {
                field: "secret plaintext input",
                expected: MODULUS_BYTES,
                actual: N,
            });
        }
        let mut padded = Zeroizing::new([0_u8; MODULUS_BYTES]);
        padded[MODULUS_BYTES - N..].copy_from_slice(bytes.as_ref());
        Ok(Self::new(padded))
    }

    pub(crate) fn expose(&self) -> &[u8; MODULUS_BYTES] {
        &self.0
    }
}

/// Secret encryption randomness in one exact certified key's `Z_N*`.
///
/// This type intentionally implements neither `Clone` nor `Debug`.
#[derive(Zeroize, ZeroizeOnDrop)]
pub(crate) struct EncryptionNonce3072 {
    value: Modulus,
    #[zeroize(skip)]
    key_modulus: [u8; MODULUS_BYTES],
}

impl EncryptionNonce3072 {
    pub(crate) fn new(value: Modulus, key_modulus: [u8; MODULUS_BYTES]) -> Self {
        Self { value, key_modulus }
    }

    pub(crate) fn expose(&self) -> &Modulus {
        &self.value
    }

    pub(crate) fn is_bound_to(&self, key_modulus: &[u8; MODULUS_BYTES]) -> bool {
        self.key_modulus == *key_modulus
    }

    /// Test-only evidence for fixed-width sampling and deterministic vectors.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn to_secret_bytes(&self) -> Zeroizing<[u8; MODULUS_BYTES]> {
        secret_modulus_to_array(&self.value)
    }
}

/// Validated secret plaintext integer in `[0, N)`, bound to one exact key.
///
/// This type intentionally implements neither `Clone` nor `Debug`.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecretPlaintext3072 {
    value: Modulus,
    #[zeroize(skip)]
    key_modulus: [u8; MODULUS_BYTES],
}

impl SecretPlaintext3072 {
    pub(crate) fn new(value: Modulus, key_modulus: [u8; MODULUS_BYTES]) -> Self {
        Self { value, key_modulus }
    }

    pub(crate) fn expose(&self) -> &Modulus {
        &self.value
    }

    pub(crate) fn is_bound_to(&self, key_modulus: &[u8; MODULUS_BYTES]) -> bool {
        self.key_modulus == *key_modulus
    }

    /// Returns the only online secret encoding: an exact 384-byte padded
    /// value. Narrower extraction is deliberately left to a later reviewed
    /// protocol adapter.
    #[must_use]
    pub fn to_secret_bytes(&self) -> Zeroizing<[u8; MODULUS_BYTES]> {
        secret_modulus_to_array(&self.value)
    }
}

pub(crate) fn parse_prime(bytes: &[u8]) -> Result<Prime> {
    if bytes.len() != PRIME_BYTES {
        return Err(PaillierError::InvalidLength {
            field: "secret prime",
            expected: PRIME_BYTES,
            actual: bytes.len(),
        });
    }
    Ok(Prime::from_be_slice(bytes))
}

pub(crate) fn parse_modulus_exact(bytes: &[u8]) -> Result<Modulus> {
    if bytes.len() != MODULUS_BYTES {
        return Err(PaillierError::InvalidLength {
            field: "public modulus",
            expected: MODULUS_BYTES,
            actual: bytes.len(),
        });
    }
    Ok(Modulus::from_be_slice(bytes))
}

pub(crate) fn parse_wide_exact(bytes: &[u8]) -> Result<Wide> {
    if bytes.len() != CIPHERTEXT_BYTES {
        return Err(PaillierError::InvalidLength {
            field: "ciphertext",
            expected: CIPHERTEXT_BYTES,
            actual: bytes.len(),
        });
    }
    Ok(Wide::from_be_slice(bytes))
}

fn parse_modulus_width(field: &'static str, bytes: &[u8]) -> Result<Modulus> {
    if bytes.is_empty() || bytes.len() > MODULUS_BYTES {
        return Err(PaillierError::InvalidLength {
            field,
            expected: MODULUS_BYTES,
            actual: bytes.len(),
        });
    }
    let mut padded = Zeroizing::new([0_u8; MODULUS_BYTES]);
    let offset = MODULUS_BYTES - bytes.len();
    padded[offset..].copy_from_slice(bytes);
    Ok(Modulus::from_be_slice(padded.as_ref()))
}

pub(crate) fn uint_to_array<T, const N: usize>(value: &T) -> [u8; N]
where
    T: Encoding,
    T::Repr: AsRef<[u8]>,
{
    let encoded = value.to_be_bytes();
    let mut output = [0_u8; N];
    output.copy_from_slice(encoded.as_ref());
    output
}

fn secret_uint_to_array<const LIMBS: usize, const N: usize>(value: &Uint<LIMBS>) -> Zeroizing<[u8; N]> {
    let mut output = Zeroizing::new([0_u8; N]);
    for (destination, word) in output.chunks_exact_mut(Limb::BYTES).zip(value.as_words().iter().rev()) {
        let encoded_word = Zeroizing::new(word.to_be_bytes());
        for (byte, encoded) in destination.iter_mut().zip(encoded_word.iter()) {
            *byte = *encoded;
        }
    }
    output
}

pub(crate) fn secret_prime_to_array(value: &Prime) -> Zeroizing<[u8; PRIME_BYTES]> {
    secret_uint_to_array(value)
}

fn secret_modulus_to_array(value: &Modulus) -> Zeroizing<[u8; MODULUS_BYTES]> {
    secret_uint_to_array(value)
}

fn fingerprint(bytes: &[u8]) -> [u8; 8] {
    let digest = Sha256::digest(bytes);
    let mut output = [0_u8; 8];
    output.copy_from_slice(&digest[..8]);
    output
}

struct HexFingerprint([u8; 8]);

impl fmt::Debug for HexFingerprint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}
