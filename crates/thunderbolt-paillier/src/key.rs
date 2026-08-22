use core::fmt;

use chacha20::ChaCha20Rng;
use crypto_bigint::modular::{FixedMontyForm, FixedMontyParams};
use crypto_bigint::{CtEq, CtLt, Odd, RandomMod, U3072, U6144};
use crypto_primes::{
    fips::{self, FipsOptions},
    hazmat::{SetBits, SmallFactorsSieveFactory},
    sieve_and_find, Flavor,
};
use rand_core::{CryptoRng, SeedableRng};
use sha2::{Digest as _, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::types::{
    parse_modulus_exact, parse_prime, parse_wide_exact, secret_prime_to_array, uint_to_array, Ciphertext3072,
    EncryptionNonce3072, Modulus, Prime, ProofNonce3072, PublicExponent3072, SecretKeyBytes3072, SecretPlaintext3072,
    SecretPlaintextBytes3072, Wide, MODULUS_BYTES, PRIME_BYTES, SECRET_KEY_BYTES,
};
use crate::{
    CertifiedPublicKeyRecord3072, ExpectedPublicKeyCertificate3072, PaillierError, Result,
    TrustedProvisioningAuthority3072,
};

const SECRET_KEY_MAGIC: &[u8; 8] = b"TBP3SK01";
const SECRET_KEY_VERSION: u16 = 1;
const MODULUS_BITS: u32 = 3072;
const MIN_PRIME_DISTANCE_BITS: u32 = 1536 - 100;

type ModulusParams = FixedMontyParams<{ U3072::LIMBS }>;
type WideParams = FixedMontyParams<{ U6144::LIMBS }>;

/// Structurally valid raw modulus that has not crossed the protocol's
/// authenticated key-validity boundary.
#[derive(Clone, PartialEq, Eq)]
pub struct RawPublicKey3072([u8; MODULUS_BYTES]);

impl RawPublicKey3072 {
    /// Parses an exact, odd, 3072-bit modulus. This does not certify that the
    /// value is a product of two distinct primes or meets the VEDL conditions.
    pub fn from_bytes(bytes: impl AsRef<[u8]>) -> Result<Self> {
        let bytes = bytes.as_ref();
        if bytes.len() != MODULUS_BYTES {
            return Err(PaillierError::InvalidLength {
                field: "raw public modulus",
                expected: MODULUS_BYTES,
                actual: bytes.len(),
            });
        }
        if bytes.first().is_none_or(|first| first & 0x80 == 0) {
            return Err(PaillierError::InvalidModulus {
                reason: "the modulus must have exact 3072-bit width",
            });
        }
        if bytes.last().is_none_or(|last| last & 1 == 0) {
            return Err(PaillierError::InvalidModulus {
                reason: "the modulus must be odd",
            });
        }
        let mut encoded = [0_u8; MODULUS_BYTES];
        encoded.copy_from_slice(bytes);
        Ok(Self(encoded))
    }

    /// Returns the exact 384-byte modulus.
    #[must_use]
    pub const fn to_bytes(&self) -> [u8; MODULUS_BYTES] {
        self.0
    }
}

impl fmt::Debug for RawPublicKey3072 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RawPublicKey3072")
            .field("fingerprint", &Fingerprint::new(&self.0))
            .finish_non_exhaustive()
    }
}

/// Certified production Paillier public key.
///
/// Stage A creates this type only from a locally validated secret key. A later
/// integration must add the reviewed authenticated registry/certificate path;
/// raw network moduli deliberately cannot be promoted here.
#[derive(Clone, PartialEq, Eq)]
pub struct PublicKey3072 {
    n: Odd<Modulus>,
    n_squared: Odd<Wide>,
    n_params: ModulusParams,
    n_squared_params: WideParams,
}

impl PublicKey3072 {
    fn from_modulus(n: Modulus) -> Result<Self> {
        if !bool::from(n.bit(MODULUS_BITS - 1)) {
            return Err(PaillierError::InvalidModulus {
                reason: "the modulus must have exact 3072-bit width",
            });
        }
        let n = Odd::new(n).into_option().ok_or(PaillierError::InvalidModulus {
            reason: "the modulus must be odd",
        })?;
        let n_squared_value: Wide = n.as_ref().concatenating_square();
        let n_squared = Odd::new(n_squared_value)
            .into_option()
            .ok_or(PaillierError::ArithmeticInvariant {
                reason: "the square of an odd modulus was not odd",
            })?;
        let n_params = ModulusParams::new(n);
        let n_squared_params = WideParams::new(n_squared);
        Ok(Self {
            n,
            n_squared,
            n_params,
            n_squared_params,
        })
    }

    /// Reconstructs a remote public key from a persisted, signed provisioning
    /// certificate without loading either prime factor.
    ///
    /// The trusted authority attests that offline provisioning validated the
    /// two distinct 1536-bit factors, exact product width, factor-distance
    /// policy, and fixed `g = N + 1` suite. Signature verification and every
    /// expected deployment/epoch/role/subject/policy/serial comparison happen
    /// before the raw modulus reaches arithmetic construction.
    pub fn from_certificate(
        record: &CertifiedPublicKeyRecord3072,
        authority: &TrustedProvisioningAuthority3072,
        expected: &ExpectedPublicKeyCertificate3072,
    ) -> Result<Self> {
        authority.verify(record, expected)?;
        let modulus = parse_modulus_exact(&record.body().modulus().to_bytes())?;
        Self::from_modulus(modulus)
    }

    /// Returns the exact public modulus.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; MODULUS_BYTES] {
        uint_to_array(self.n.as_ref())
    }

    /// Returns the untrusted transport form for publication.
    #[must_use]
    pub fn to_raw(&self) -> RawPublicKey3072 {
        RawPublicKey3072(self.to_bytes())
    }

    /// Returns a short public fingerprint suitable for diagnostics.
    #[must_use]
    pub fn fingerprint(&self) -> [u8; 8] {
        Fingerprint::bytes(&self.to_bytes())
    }

    /// Parses and validates a public ciphertext under this certified key.
    pub fn ciphertext_from_bytes(&self, bytes: impl AsRef<[u8]>) -> Result<Ciphertext3072> {
        let ciphertext = parse_wide_exact(bytes.as_ref())?;
        self.validate_ciphertext_value(&ciphertext)?;
        Ok(Ciphertext3072 {
            value: ciphertext,
            key_modulus: self.to_bytes(),
        })
    }

    /// Revalidates a public ciphertext's exact-key binding and group
    /// membership before transport or protocol use.
    pub fn validate_ciphertext(&self, ciphertext: &Ciphertext3072) -> Result<()> {
        self.ensure_ciphertext_key(ciphertext, "ciphertext")?;
        self.validate_ciphertext_value(&ciphertext.value)
    }

    /// Parses and validates a public proof nonce under this certified key.
    pub fn proof_nonce_from_bytes(&self, bytes: impl AsRef<[u8]>) -> Result<ProofNonce3072> {
        let nonce = parse_modulus_exact(bytes.as_ref())?;
        self.validate_nonce_value(&nonce)?;
        Ok(ProofNonce3072 {
            value: nonce,
            key_modulus: self.to_bytes(),
        })
    }

    /// Revalidates a public proof nonce's exact-key binding and membership in
    /// `Z_N*` before transport or protocol use.
    pub fn validate_proof_nonce(&self, nonce: &ProofNonce3072) -> Result<()> {
        self.ensure_proof_nonce_key(nonce)?;
        self.validate_nonce_value(&nonce.value)
    }

    /// Consumes and validates an exact-width secret plaintext under this key.
    /// The returned semantic type cannot be used with another modulus.
    pub fn plaintext_from_secret_bytes(&self, bytes: SecretPlaintextBytes3072) -> Result<SecretPlaintext3072> {
        let plaintext = Zeroizing::new(parse_modulus_exact(bytes.expose())?);
        if !bool::from(plaintext.ct_lt(self.n.as_ref())) {
            return Err(PaillierError::InvalidPlaintext {
                reason: "plaintext must be smaller than N",
            });
        }
        Ok(SecretPlaintext3072::new(*plaintext, self.to_bytes()))
    }

    #[cfg(test)]
    pub(crate) fn encryption_nonce_from_secret_bytes_for_test(
        &self,
        bytes: Zeroizing<[u8; MODULUS_BYTES]>,
    ) -> Result<EncryptionNonce3072> {
        let nonce = parse_modulus_exact(bytes.as_ref())?;
        self.validate_nonce_value(&nonce)?;
        Ok(EncryptionNonce3072::new(nonce, self.to_bytes()))
    }

    fn sample_nonce<R>(&self, rng: &mut R) -> EncryptionNonce3072
    where
        R: CryptoRng + ?Sized,
    {
        loop {
            let candidate = Zeroizing::new(Modulus::random_mod_vartime(rng, self.n.as_nz_ref()));
            let form = Zeroizing::new(FixedMontyForm::new(&candidate, &self.n_params));
            let invertible = form.invert().is_some() & candidate.is_nonzero();
            if bool::from(invertible) {
                return EncryptionNonce3072::new(*candidate, self.to_bytes());
            }
        }
    }

    #[cfg(test)]
    pub(crate) fn sample_nonce_for_test<R>(&self, rng: &mut R) -> EncryptionNonce3072
    where
        R: CryptoRng + ?Sized,
    {
        self.sample_nonce(rng)
    }

    fn encrypt_with_rng_inner<R>(&self, plaintext: &SecretPlaintext3072, rng: &mut R) -> Result<Encryption3072>
    where
        R: CryptoRng + ?Sized,
    {
        self.ensure_plaintext_key(plaintext)?;
        let nonce = self.sample_nonce(rng);
        let ciphertext = self.compose_ciphertext(plaintext, &nonce)?;
        Ok(Encryption3072 {
            key_modulus: self.to_bytes(),
            ciphertext,
            nonce,
        })
    }

    #[cfg(test)]
    pub(crate) fn encrypt_with_rng_for_test<R>(
        &self,
        plaintext: &SecretPlaintext3072,
        rng: &mut R,
    ) -> Result<Encryption3072>
    where
        R: CryptoRng + ?Sized,
    {
        self.encrypt_with_rng_inner(plaintext, rng)
    }

    /// Encrypts with fresh operating-system-seeded randomness.
    ///
    /// Production callers cannot provide or restore a nonce. The non-cloneable
    /// opening returned here is consumed when proof-opening material is built.
    pub fn encrypt(&self, plaintext: &SecretPlaintext3072) -> Result<Encryption3072> {
        self.ensure_plaintext_key(plaintext)?;
        let mut rng = system_rng()?;
        self.encrypt_with_rng_inner(plaintext, &mut rng)
    }

    fn compose_ciphertext(
        &self,
        plaintext: &SecretPlaintext3072,
        nonce: &EncryptionNonce3072,
    ) -> Result<Ciphertext3072> {
        self.ensure_plaintext_key(plaintext)?;
        self.ensure_nonce_key(nonce, "encryption nonce")?;
        self.validate_nonce_value(nonce.expose())?;

        let generator = self.generator_wide();
        let generator_term = Zeroizing::new(
            self.wide_form(&generator)
                .pow_bounded_exp(plaintext.expose(), MODULUS_BITS),
        );
        let nonce_wide = Zeroizing::new(nonce.expose().resize::<{ U6144::LIMBS }>());
        let nonce_term = Zeroizing::new(
            self.wide_form(&nonce_wide)
                .pow_bounded_exp(self.n.as_ref(), MODULUS_BITS),
        );
        Ok(Ciphertext3072 {
            value: generator_term.mul(&nonce_term).retrieve(),
            key_modulus: self.to_bytes(),
        })
    }

    #[cfg(test)]
    pub(crate) fn compose_with_nonce_for_test(
        &self,
        plaintext: &SecretPlaintext3072,
        nonce: &EncryptionNonce3072,
    ) -> Result<Ciphertext3072> {
        self.compose_ciphertext(plaintext, nonce)
    }

    #[cfg(test)]
    pub(crate) fn opening_with_nonce_for_test(
        &self,
        plaintext: &SecretPlaintext3072,
        nonce: EncryptionNonce3072,
    ) -> Result<Encryption3072> {
        let ciphertext = self.compose_ciphertext(plaintext, &nonce)?;
        Ok(Encryption3072 {
            key_modulus: self.to_bytes(),
            ciphertext,
            nonce,
        })
    }

    #[cfg(test)]
    pub(crate) fn opening_for_timing_test(
        &self,
        fixed_ciphertext: &Ciphertext3072,
        nonce: EncryptionNonce3072,
    ) -> Result<Encryption3072> {
        self.ensure_ciphertext_key(fixed_ciphertext, "timing ciphertext")?;
        self.ensure_nonce_key(&nonce, "timing nonce")?;
        self.validate_nonce_value(nonce.expose())?;
        Ok(Encryption3072 {
            key_modulus: self.to_bytes(),
            ciphertext: fixed_ciphertext.clone(),
            nonce,
        })
    }

    /// Adds two encrypted plaintexts homomorphically.
    pub fn add(&self, left: &Ciphertext3072, right: &Ciphertext3072) -> Result<Ciphertext3072> {
        self.ensure_ciphertext_key(left, "left ciphertext")?;
        self.ensure_ciphertext_key(right, "right ciphertext")?;
        self.validate_ciphertext_value(&left.value)?;
        self.validate_ciphertext_value(&right.value)?;
        Ok(Ciphertext3072 {
            value: self
                .wide_form(&left.value)
                .mul(&self.wide_form(&right.value))
                .retrieve(),
            key_modulus: self.to_bytes(),
        })
    }

    /// Subtracts one encrypted plaintext homomorphically.
    pub fn subtract(&self, minuend: &Ciphertext3072, subtrahend: &Ciphertext3072) -> Result<Ciphertext3072> {
        self.ensure_ciphertext_key(minuend, "minuend ciphertext")?;
        self.ensure_ciphertext_key(subtrahend, "subtrahend ciphertext")?;
        self.validate_ciphertext_value(&minuend.value)?;
        self.validate_ciphertext_value(&subtrahend.value)?;
        let inverse =
            self.wide_form(&subtrahend.value)
                .invert()
                .into_option()
                .ok_or(PaillierError::InvalidCiphertext {
                    reason: "ciphertext is not invertible modulo N^2",
                })?;
        Ok(Ciphertext3072 {
            value: self.wide_form(&minuend.value).mul(&inverse).retrieve(),
            key_modulus: self.to_bytes(),
        })
    }

    /// Raises a ciphertext to a public exponent.
    pub fn exponentiate(&self, ciphertext: &Ciphertext3072, exponent: &PublicExponent3072) -> Result<Ciphertext3072> {
        self.ensure_ciphertext_key(ciphertext, "ciphertext")?;
        self.validate_ciphertext_value(&ciphertext.value)?;
        Ok(Ciphertext3072 {
            value: self
                .wide_form(&ciphertext.value)
                .pow_bounded_exp(&exponent.0, MODULUS_BITS)
                .retrieve(),
            key_modulus: self.to_bytes(),
        })
    }

    /// Consumes two one-use openings and computes
    /// `tau = beta * rho^challenge mod N`.
    ///
    /// Both exact full-modulus bindings are checked before arithmetic. The
    /// statement and commitment ciphertexts are returned with the public
    /// response nonce; neither secret opening can be reused afterward.
    pub fn consume_proof_openings(
        &self,
        statement_opening: Encryption3072,
        commitment_opening: Encryption3072,
        challenge: &PublicExponent3072,
    ) -> Result<ProofOpeningResponse3072> {
        self.ensure_opening_key(&statement_opening, "statement opening")?;
        self.ensure_opening_key(&commitment_opening, "commitment opening")?;
        self.validate_nonce_value(commitment_opening.nonce.expose())?;
        self.validate_nonce_value(statement_opening.nonce.expose())?;
        let witness_term = Zeroizing::new(
            self.modulus_form(statement_opening.nonce.expose())
                .pow_bounded_exp(&challenge.0, MODULUS_BITS),
        );
        let response = Zeroizing::new(
            self.modulus_form(commitment_opening.nonce.expose())
                .mul(&witness_term)
                .retrieve(),
        );
        self.validate_nonce_value(&response)?;
        Ok(ProofOpeningResponse3072 {
            statement_ciphertext: statement_opening.ciphertext.clone(),
            commitment_ciphertext: commitment_opening.ciphertext.clone(),
            response_nonce: ProofNonce3072 {
                value: *response,
                key_modulus: self.to_bytes(),
            },
        })
    }

    /// Builds `g^z * tau^N mod N^2` for a public proof response.
    pub fn response_lhs(&self, response: &PublicExponent3072, nonce: &ProofNonce3072) -> Result<Ciphertext3072> {
        self.ensure_proof_nonce_key(nonce)?;
        self.validate_nonce_value(&nonce.value)?;
        let generator_term = Zeroizing::new(
            self.wide_form(&self.generator_wide())
                .pow_bounded_exp(&response.0, MODULUS_BITS),
        );
        let nonce_wide = Zeroizing::new(nonce.value.resize::<{ U6144::LIMBS }>());
        let nonce_term = Zeroizing::new(
            self.wide_form(&nonce_wide)
                .pow_bounded_exp(self.n.as_ref(), MODULUS_BITS),
        );
        Ok(Ciphertext3072 {
            value: generator_term.mul(&nonce_term).retrieve(),
            key_modulus: self.to_bytes(),
        })
    }

    fn ensure_plaintext_key(&self, plaintext: &SecretPlaintext3072) -> Result<()> {
        if !plaintext.is_bound_to(&self.to_bytes()) {
            return Err(PaillierError::WrongPublicKey {
                field: "secret plaintext",
            });
        }
        Ok(())
    }

    fn ensure_nonce_key(&self, nonce: &EncryptionNonce3072, field: &'static str) -> Result<()> {
        if !nonce.is_bound_to(&self.to_bytes()) {
            return Err(PaillierError::WrongPublicKey { field });
        }
        Ok(())
    }

    fn ensure_ciphertext_key(&self, ciphertext: &Ciphertext3072, field: &'static str) -> Result<()> {
        if ciphertext.key_modulus != self.to_bytes() {
            return Err(PaillierError::WrongPublicKey { field });
        }
        Ok(())
    }

    fn ensure_proof_nonce_key(&self, nonce: &ProofNonce3072) -> Result<()> {
        if nonce.key_modulus != self.to_bytes() {
            return Err(PaillierError::WrongPublicKey {
                field: "proof response nonce",
            });
        }
        Ok(())
    }

    fn ensure_opening_key(&self, opening: &Encryption3072, field: &'static str) -> Result<()> {
        if opening.key_modulus != self.to_bytes() {
            return Err(PaillierError::WrongPublicKey { field });
        }
        self.ensure_ciphertext_key(&opening.ciphertext, field)?;
        self.ensure_nonce_key(&opening.nonce, field)
    }

    fn validate_nonce_value(&self, nonce: &Modulus) -> Result<()> {
        let in_range = nonce.is_nonzero() & nonce.ct_lt(self.n.as_ref());
        let form = Zeroizing::new(self.modulus_form(nonce));
        let invertible = form.invert().is_some();
        if !bool::from(in_range & invertible) {
            return Err(PaillierError::InvalidNonce {
                reason: "nonce must lie in Z_N*",
            });
        }
        Ok(())
    }

    fn validate_ciphertext_value(&self, ciphertext: &Wide) -> Result<()> {
        let in_range = ciphertext.is_nonzero() & ciphertext.ct_lt(self.n_squared.as_ref());
        let invertible = self.wide_form(ciphertext).invert().is_some();
        if !bool::from(in_range & invertible) {
            return Err(PaillierError::InvalidCiphertext {
                reason: "ciphertext must lie in Z_(N^2)*",
            });
        }
        Ok(())
    }

    fn generator_wide(&self) -> Wide {
        self.n.as_ref().resize::<{ U6144::LIMBS }>().wrapping_add(&Wide::ONE)
    }

    fn modulus_form(&self, value: &Modulus) -> FixedMontyForm<{ U3072::LIMBS }> {
        FixedMontyForm::new(value, &self.n_params)
    }

    fn wide_form(&self, value: &Wide) -> FixedMontyForm<{ U6144::LIMBS }> {
        FixedMontyForm::new(value, &self.n_squared_params)
    }
}

impl fmt::Debug for PublicKey3072 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PublicKey3072")
            .field("fingerprint", &Fingerprint(self.fingerprint()))
            .finish_non_exhaustive()
    }
}

/// Ciphertext together with its secret opening nonce.
///
/// This type intentionally implements neither `Clone` nor `Debug`.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Encryption3072 {
    #[zeroize(skip)]
    key_modulus: [u8; MODULUS_BYTES],
    #[zeroize(skip)]
    ciphertext: Ciphertext3072,
    nonce: EncryptionNonce3072,
}

impl Encryption3072 {
    /// Borrows the public ciphertext.
    #[must_use]
    pub const fn ciphertext(&self) -> &Ciphertext3072 {
        &self.ciphertext
    }

    #[cfg(test)]
    pub(crate) const fn nonce_for_test(&self) -> &EncryptionNonce3072 {
        &self.nonce
    }
}

/// Public material recovered by consuming a statement opening and a fresh
/// proof-commitment opening under the same exact key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProofOpeningResponse3072 {
    statement_ciphertext: Ciphertext3072,
    commitment_ciphertext: Ciphertext3072,
    response_nonce: ProofNonce3072,
}

impl ProofOpeningResponse3072 {
    /// Returns the statement ciphertext whose witness opening was consumed.
    #[must_use]
    pub const fn statement_ciphertext(&self) -> &Ciphertext3072 {
        &self.statement_ciphertext
    }

    /// Returns the fresh proof-commitment ciphertext whose opening was
    /// consumed.
    #[must_use]
    pub const fn commitment_ciphertext(&self) -> &Ciphertext3072 {
        &self.commitment_ciphertext
    }

    /// Returns `tau = beta * rho^challenge mod N`.
    #[must_use]
    pub const fn response_nonce(&self) -> &ProofNonce3072 {
        &self.response_nonce
    }
}

/// Validated Paillier secret key generated from two distinct 1536-bit primes.
///
/// This type intentionally implements neither `Clone` nor `Debug`.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecretKey3072 {
    p: Prime,
    q: Prime,
    lambda: Modulus,
    mu: Modulus,
    #[zeroize(skip)]
    public_key: PublicKey3072,
}

impl SecretKey3072 {
    fn from_primes(p: Zeroizing<Prime>, q: Zeroizing<Prime>) -> Result<Self> {
        if p.ct_eq(&q).into() {
            return Err(PaillierError::InvalidSecretKey {
                reason: "p and q must be distinct",
            });
        }
        if !bool::from(p.bit(1535) & q.bit(1535) & p.is_odd() & q.is_odd()) {
            return Err(PaillierError::InvalidSecretKey {
                reason: "secret factors must be odd 1536-bit integers",
            });
        }
        let distance = if bool::from(p.ct_lt(&q)) {
            Zeroizing::new(q.wrapping_sub(&p))
        } else {
            Zeroizing::new(p.wrapping_sub(&q))
        };
        let minimum_distance = Zeroizing::new(Prime::ONE.wrapping_shl(MIN_PRIME_DISTANCE_BITS));
        if !bool::from(minimum_distance.ct_lt(&distance)) {
            return Err(PaillierError::InvalidSecretKey {
                reason: "secret factors are too close for the production RSA-style key profile",
            });
        }

        let n: Modulus = p.concatenating_mul(&*q);
        let public_key = PublicKey3072::from_modulus(n)?;
        let p_minus_one = Zeroizing::new(p.wrapping_sub(&Prime::ONE));
        let q_minus_one = Zeroizing::new(q.wrapping_sub(&Prime::ONE));
        let lambda = Zeroizing::new(p_minus_one.lcm(&q_minus_one));
        if bool::from(lambda.is_zero()) {
            return Err(PaillierError::ArithmeticInvariant {
                reason: "Carmichael exponent was zero",
            });
        }

        let generator = public_key.generator_wide();
        let powered = Zeroizing::new(
            public_key
                .wide_form(&generator)
                .pow_bounded_exp(&lambda, MODULUS_BITS)
                .retrieve(),
        );
        let l_value = Zeroizing::new(exact_l(&powered, public_key.n.as_ref())?);
        let mu = Zeroizing::new(
            public_key
                .modulus_form(&l_value)
                .invert()
                .into_option()
                .ok_or(PaillierError::ArithmeticInvariant {
                    reason: "L(g^lambda) was not invertible modulo N",
                })?
                .retrieve(),
        );

        Ok(Self {
            p: *p,
            q: *q,
            lambda: *lambda,
            mu: *mu,
            public_key,
        })
    }

    /// Restores an authenticated generator record and revalidates its factors.
    /// FIPS 186-5 probable-prime validation is intentionally offline and
    /// variable-time, with a false-accept target below `2^-128`.
    pub fn from_secret_record(record: SecretKeyBytes3072) -> Result<Self> {
        let bytes = record.as_ref();
        if bytes.len() != SECRET_KEY_BYTES {
            return Err(PaillierError::InvalidLength {
                field: "secret key record",
                expected: SECRET_KEY_BYTES,
                actual: bytes.len(),
            });
        }
        if bytes.get(..8) != Some(SECRET_KEY_MAGIC) {
            return Err(PaillierError::InvalidSecretKey {
                reason: "secret key magic is invalid",
            });
        }
        let version = bytes
            .get(8..10)
            .and_then(|slice| <[u8; 2]>::try_from(slice).ok())
            .map(u16::from_be_bytes)
            .ok_or(PaillierError::InvalidSecretKey {
                reason: "secret key version is missing",
            })?;
        if version != SECRET_KEY_VERSION {
            return Err(PaillierError::InvalidSecretKey {
                reason: "secret key version is unsupported",
            });
        }
        let p = Zeroizing::new(parse_prime(bytes.get(10..10 + PRIME_BYTES).ok_or(
            PaillierError::InvalidSecretKey {
                reason: "secret key p is missing",
            },
        )?)?);
        let q = Zeroizing::new(parse_prime(bytes.get(10 + PRIME_BYTES..).ok_or(
            PaillierError::InvalidSecretKey {
                reason: "secret key q is missing",
            },
        )?)?);
        validate_prime_pair(&p, &q)?;
        Self::from_primes(p, q)
    }

    /// Borrowed compatibility adapter. The input is copied immediately into a
    /// consuming zeroizing record, but this function cannot wipe the caller's
    /// original buffer. Prefer [`Self::from_secret_record`].
    pub fn from_borrowed_secret_bytes(bytes: &[u8]) -> Result<Self> {
        Self::from_secret_record(SecretKeyBytes3072::copy_from_slice(bytes)?)
    }

    /// Returns a zeroizing, versioned fixed-width record containing the two
    /// secret prime factors. Persist only inside the encrypted keystore.
    #[must_use]
    pub fn to_secret_record(&self) -> SecretKeyBytes3072 {
        let mut bytes = Zeroizing::new([0_u8; SECRET_KEY_BYTES]);
        bytes[..8].copy_from_slice(SECRET_KEY_MAGIC);
        bytes[8..10].copy_from_slice(&SECRET_KEY_VERSION.to_be_bytes());
        let p = secret_prime_to_array(&self.p);
        let q = secret_prime_to_array(&self.q);
        bytes[10..10 + PRIME_BYTES].copy_from_slice(p.as_ref());
        bytes[10 + PRIME_BYTES..].copy_from_slice(q.as_ref());
        SecretKeyBytes3072::new(bytes)
    }

    /// Returns the certified public key derived from the validated factors.
    #[must_use]
    pub fn public_key(&self) -> &PublicKey3072 {
        &self.public_key
    }

    /// Decrypts to an exact fixed-width secret plaintext.
    pub fn decrypt(&self, ciphertext: &Ciphertext3072) -> Result<SecretPlaintext3072> {
        self.public_key.ensure_ciphertext_key(ciphertext, "ciphertext")?;
        self.public_key.validate_ciphertext_value(&ciphertext.value)?;
        let powered = Zeroizing::new(
            self.public_key
                .wide_form(&ciphertext.value)
                .pow_bounded_exp(&self.lambda, MODULUS_BITS)
                .retrieve(),
        );
        let l_value = Zeroizing::new(exact_l(&powered, self.public_key.n.as_ref())?);
        let plaintext = Zeroizing::new(
            self.public_key
                .modulus_form(&l_value)
                .mul(&self.public_key.modulus_form(&self.mu))
                .retrieve(),
        );
        Ok(SecretPlaintext3072::new(*plaintext, self.public_key.to_bytes()))
    }

    #[cfg(test)]
    pub(crate) fn decryption_key_for_timing_test(&self, class: u8) -> Result<Self> {
        if class == 0 {
            return Ok(Self {
                p: self.p,
                q: self.q,
                lambda: self.lambda,
                mu: self.mu,
                public_key: self.public_key.clone(),
            });
        }
        if class != 1 {
            return Err(PaillierError::ArithmeticInvariant {
                reason: "the timing-test decryption-key class must be zero or one",
            });
        }
        let lambda = Zeroizing::new(self.lambda.wrapping_add(&self.lambda));
        if !bool::from(lambda.is_nonzero() & lambda.ct_lt(self.public_key.n.as_ref())) {
            return Err(PaillierError::ArithmeticInvariant {
                reason: "the doubled timing-test Carmichael exponent exceeded N",
            });
        }
        let mu = Zeroizing::new(
            self.public_key
                .modulus_form(&lambda)
                .invert()
                .into_option()
                .ok_or(PaillierError::ArithmeticInvariant {
                    reason: "the doubled timing-test Carmichael exponent was not invertible",
                })?
                .retrieve(),
        );
        Ok(Self {
            p: self.p,
            q: self.q,
            lambda: *lambda,
            mu: *mu,
            public_key: self.public_key.clone(),
        })
    }
}

/// Explicit offline-only key generator.
#[derive(Debug, Default)]
pub struct OfflineKeyGenerator;

impl OfflineKeyGenerator {
    /// Seeds a zeroizing ChaCha20 CSPRNG from the operating system, then runs
    /// variable-time prime search entirely in the caller's provisioning flow.
    pub fn generate(&self) -> Result<SecretKey3072> {
        let mut rng = system_rng()?;
        self.generate_with_rng_inner(&mut rng)
    }

    fn generate_with_rng_inner<R>(&self, rng: &mut R) -> Result<SecretKey3072>
    where
        R: CryptoRng + ?Sized,
    {
        loop {
            let p = generate_prime(rng)?;
            let q = generate_prime(rng)?;
            match SecretKey3072::from_primes(p, q) {
                Ok(key) => return Ok(key),
                Err(PaillierError::InvalidModulus { .. }) | Err(PaillierError::InvalidSecretKey { .. }) => continue,
                Err(error) => return Err(error),
            }
        }
    }

    #[cfg(test)]
    pub(crate) fn generate_with_rng_for_test<R>(&self, rng: &mut R) -> Result<SecretKey3072>
    where
        R: CryptoRng + ?Sized,
    {
        self.generate_with_rng_inner(rng)
    }
}

fn generate_prime<R>(rng: &mut R) -> Result<Zeroizing<Prime>>
where
    R: CryptoRng + ?Sized,
{
    let factory = SmallFactorsSieveFactory::<Prime>::new(Flavor::Any, (PRIME_BYTES * 8) as u32, SetBits::Msb)
        .map_err(|_| PaillierError::KeyGenerationFailed)?;
    let primality = fips_options()?;
    sieve_and_find(rng, factory, |rng, candidate| {
        fips::is_prime(rng, Flavor::Any, candidate, primality)
    })
    .map_err(|_| PaillierError::KeyGenerationFailed)?
    .map(Zeroizing::new)
    .ok_or(PaillierError::KeyGenerationFailed)
}

fn validate_prime_pair(p: &Prime, q: &Prime) -> Result<()> {
    let mut rng = system_rng()?;
    let primality = fips_options()?;
    if !fips::is_prime(&mut rng, Flavor::Any, p, primality) || !fips::is_prime(&mut rng, Flavor::Any, q, primality) {
        return Err(PaillierError::InvalidSecretKey {
            reason: "secret factors failed FIPS 186-5 probable-prime validation",
        });
    }
    Ok(())
}

fn fips_options() -> Result<FipsOptions> {
    FipsOptions::with_error_bound((PRIME_BYTES * 8) as u32, 128)
        .map(FipsOptions::with_lucas_test)
        .map(FipsOptions::with_trial_division_test)
        .ok_or(PaillierError::KeyGenerationFailed)
}

fn exact_l(value: &Wide, modulus: &Modulus) -> Result<Modulus> {
    let numerator = Zeroizing::new(value.wrapping_sub(&Wide::ONE));
    let remainder = Zeroizing::new(numerator.checked_rem(modulus).into_option().ok_or(
        PaillierError::ArithmeticInvariant {
            reason: "L denominator was zero",
        },
    )?);
    if !bool::from(remainder.is_zero()) {
        return Err(PaillierError::ArithmeticInvariant {
            reason: "L numerator was not divisible by N",
        });
    }
    numerator
        .checked_div(modulus)
        .and_then(|quotient| quotient.resize_checked::<{ U3072::LIMBS }>())
        .into_option()
        .ok_or(PaillierError::ArithmeticInvariant {
            reason: "L quotient exceeded the plaintext width",
        })
}

fn system_rng() -> Result<ChaCha20Rng> {
    let mut seed = Zeroizing::new([0_u8; 32]);
    getrandom::fill(seed.as_mut()).map_err(|_| PaillierError::EntropyUnavailable)?;
    Ok(ChaCha20Rng::from_seed(*seed))
}

struct Fingerprint([u8; 8]);

impl Fingerprint {
    fn new(bytes: &[u8]) -> Self {
        Self(Self::bytes(bytes))
    }

    fn bytes(bytes: &[u8]) -> [u8; 8] {
        let digest = Sha256::digest(bytes);
        let mut output = [0_u8; 8];
        output.copy_from_slice(&digest[..8]);
        output
    }
}

impl fmt::Debug for Fingerprint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}
