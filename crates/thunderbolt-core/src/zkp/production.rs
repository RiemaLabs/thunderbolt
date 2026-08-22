//! Fixed-width production verification for the paper's Paillier relations.
//!
//! Network moduli never become arithmetic keys in this module. A caller must
//! resolve each raw modulus through an authenticated allowlist that already
//! owns a [`PublicKey3072`], and wire adapters must compare all 384 bytes before
//! constructing a statement.

use std::collections::BTreeMap;
use std::sync::OnceLock;

use crypto_bigint::{CtLt, Limb, Uint, U1024, U256, U512};
use num_bigint::BigUint;
use num_traits::One as _;
use secp::{MaybePoint, MaybeScalar, Point};
use sha2::{Digest as _, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::zkp::context::{ProofContext, ProofTag};
use crate::{Result, ThunderboltError};

pub use thunderbolt_paillier::{
    CertifiedKeyIdentity3072, CertifiedKeyRole3072, CertifiedPublicKeyRecord3072, Ciphertext3072, Encryption3072,
    ExpectedPublicKeyCertificate3072, PaillierError, ProofNonce3072, PublicExponent3072, PublicKey3072,
    RawPublicKey3072, TrustedProvisioningAuthority3072, CIPHERTEXT_BYTES as PAILLIER_CIPHERTEXT_BYTES,
    MODULUS_BYTES as PAILLIER_MODULUS_BYTES,
};

/// Exact transport width of `z = alpha + c * witness`.
pub const PROOF_RESPONSE_3072_BYTES: usize = 81;

/// Largest per-operation authenticated key set: one recipient and the maximum
/// 256-member committee roster.
pub const MAX_CERTIFIED_KEYS_PER_OPERATION: usize = 257;

const CURVE_ORDER_BYTES: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0xba, 0xae, 0xdc,
    0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
];
const STATISTICAL_SECURITY_BITS: usize = 128;

/// Authenticated lookup boundary for a certified Paillier key.
///
/// Implementations must authenticate registry membership independently of the
/// raw message. The wire adapter additionally compares the returned key's exact
/// 384-byte modulus with `raw`, so a faulty resolver cannot substitute a key.
pub trait CertifiedKeyResolver3072 {
    fn resolve_certified_key(
        &self,
        raw: &RawPublicKey3072,
        expected_role: CertifiedKeyRole3072,
    ) -> Result<PublicKey3072>;
}

#[derive(Clone, Debug)]
pub struct CertifiedKeyRegistration3072 {
    pub record: CertifiedPublicKeyRecord3072,
    pub expected: ExpectedPublicKeyCertificate3072,
}

/// Immutable exact-match allowlist for one bounded protocol operation.
#[derive(Clone, Debug)]
pub struct CertifiedKeyRegistry3072 {
    keys: BTreeMap<(CertifiedKeyRole3072, [u8; PAILLIER_MODULUS_BYTES]), PublicKey3072>,
}

impl CertifiedKeyRegistry3072 {
    /// Reconstructs an operation-scoped allowlist from persisted signed public
    /// certificates. No prime factor is accepted or loaded by this path.
    pub fn from_certificates(
        registrations: impl IntoIterator<Item = CertifiedKeyRegistration3072>,
        trusted_authorities: &[TrustedProvisioningAuthority3072],
    ) -> Result<Self> {
        let mut registry = BTreeMap::new();
        let mut supplied = 0_usize;
        let mut singleton_roles = BTreeMap::new();
        for registration in registrations {
            supplied = supplied.checked_add(1).ok_or_else(|| {
                ThunderboltError::InvalidParameter("certified Paillier key registry size overflowed".to_string())
            })?;
            if supplied > MAX_CERTIFIED_KEYS_PER_OPERATION {
                return Err(ThunderboltError::InvalidParameter(format!(
                    "certified Paillier key registry exceeds {MAX_CERTIFIED_KEYS_PER_OPERATION} entries"
                )));
            }
            let authority = trusted_authorities
                .iter()
                .find(|authority| authority.authority_id() == registration.record.body().authority_id())
                .ok_or_else(|| {
                    ThunderboltError::InvalidParameter(
                        "Paillier certificate authority is absent from deployment trust roots".to_string(),
                    )
                })?;
            let key = PublicKey3072::from_certificate(&registration.record, authority, &registration.expected)
                .map_err(paillier_error)?;
            let role = registration.expected.identity.role();
            if matches!(role, CertifiedKeyRole3072::Recipient | CertifiedKeyRole3072::Committee)
                && singleton_roles.insert(role, key.to_bytes()).is_some()
            {
                return Err(ThunderboltError::InvalidParameter(
                    "operation registry contains more than one key for a singleton role".to_string(),
                ));
            }
            let index = (role, key.to_bytes());
            if registry.insert(index, key).is_some() {
                return Err(ThunderboltError::InvalidParameter(
                    "operation registry contains a duplicate certified key".to_string(),
                ));
            }
        }
        if registry.is_empty() {
            return Err(ThunderboltError::InvalidParameter(
                "certified Paillier key registry must not be empty".to_string(),
            ));
        }
        Ok(Self { keys: registry })
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }
}

impl CertifiedKeyResolver3072 for CertifiedKeyRegistry3072 {
    fn resolve_certified_key(
        &self,
        raw: &RawPublicKey3072,
        expected_role: CertifiedKeyRole3072,
    ) -> Result<PublicKey3072> {
        self.keys.get(&(expected_role, raw.to_bytes())).cloned().ok_or_else(|| {
            ThunderboltError::InvalidParameter(
                "Paillier modulus and role are absent from the authenticated certified-key registry".to_string(),
            )
        })
    }
}

/// Canonical fixed-width public Sigma response.
///
/// For `alpha in [0, q^2 * 2^128)`, `c in [0, q)`, and a scalar witness in
/// `[0, q)`, the exact maximum is
/// `q^2 * 2^128 - 1 + (q - 1)^2`. This remains below `2^640`, so the first byte
/// of the historical 81-byte transport is entirely unused. That byte and the
/// tighter numerical bound are both enforced.
#[derive(Clone, PartialEq, Eq)]
pub struct ProofResponse3072([u8; PROOF_RESPONSE_3072_BYTES]);

impl ProofResponse3072 {
    pub fn from_bytes(bytes: impl AsRef<[u8]>) -> Result<Self> {
        let bytes = bytes.as_ref();
        if bytes.len() != PROOF_RESPONSE_3072_BYTES {
            return Err(ThunderboltError::OutOfRange(format!(
                "proof response must contain exactly {PROOF_RESPONSE_3072_BYTES} bytes"
            )));
        }
        if bytes.first().is_some_and(|first| *first != 0) {
            return Err(ThunderboltError::OutOfRange(
                "proof response uses non-canonical high bits".to_string(),
            ));
        }
        let value = BigUint::from_bytes_be(bytes);
        if value > *maximum_response_value() {
            return Err(ThunderboltError::OutOfRange(
                "proof response exceeds alpha + c * witness bound".to_string(),
            ));
        }
        let mut encoded = [0_u8; PROOF_RESPONSE_3072_BYTES];
        encoded.copy_from_slice(bytes);
        Ok(Self(encoded))
    }

    pub fn from_biguint(value: &BigUint) -> Result<Self> {
        if value > maximum_response_value() {
            return Err(ThunderboltError::OutOfRange(
                "proof response exceeds alpha + c * witness bound".to_string(),
            ));
        }
        let bytes = value.to_bytes_be();
        if bytes.len() > PROOF_RESPONSE_3072_BYTES {
            return Err(ThunderboltError::OutOfRange(
                "proof response exceeds its fixed transport width".to_string(),
            ));
        }
        let mut encoded = [0_u8; PROOF_RESPONSE_3072_BYTES];
        encoded[PROOF_RESPONSE_3072_BYTES - bytes.len()..].copy_from_slice(&bytes);
        Self::from_bytes(encoded)
    }

    #[must_use]
    pub const fn to_bytes(&self) -> [u8; PROOF_RESPONSE_3072_BYTES] {
        self.0
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8; PROOF_RESPONSE_3072_BYTES] {
        &self.0
    }

    fn as_biguint(&self) -> BigUint {
        BigUint::from_bytes_be(&self.0)
    }

    fn scalar_mod_q(&self) -> Result<MaybeScalar> {
        let reduced = self.as_biguint() % curve_order();
        let bytes = fixed_biguint::<32>(&reduced)?;
        MaybeScalar::from_slice(&bytes)
            .map_err(|_| ThunderboltError::OutOfRange("proof response reduction is not a secp256k1 scalar".to_string()))
    }

    fn paillier_exponent(&self) -> Result<PublicExponent3072> {
        PublicExponent3072::from_bytes(self.0).map_err(paillier_error)
    }
}

impl core::fmt::Debug for ProofResponse3072 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("ProofResponse3072")
            .field("bit_length", &self.as_biguint().bits())
            .finish_non_exhaustive()
    }
}

/// Consuming, zeroizing secp256k1 witness bytes used by production proof
/// builders.
///
/// This type intentionally implements neither `Clone` nor `Debug`, exposes no
/// byte serialization, and rejects zero and values outside `[1, q)`.
///
/// ```compile_fail
/// use thunderbolt_core::zkp::SecretScalar3072;
/// fn requires_clone<T: Clone>(_value: T) {}
/// fn duplicate(secret: SecretScalar3072) {
///     requires_clone(secret);
/// }
/// ```
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecretScalar3072(Zeroizing<[u8; 32]>);

impl SecretScalar3072 {
    /// Takes ownership of one exact secret scalar encoding.
    pub fn from_bytes(bytes: Zeroizing<[u8; 32]>) -> Result<Self> {
        ScalarSecret::parse(&bytes)?;
        Ok(Self(bytes))
    }

    /// Computes the public curve commitment without exporting the witness.
    pub fn public_point(&self, anchor_base: &Point) -> Result<Point> {
        Ok(*anchor_base * ScalarSecret::parse(&self.0)?)
    }

    /// Creates a one-use, non-exportable Paillier opening for this scalar.
    fn encrypt_for_key(&self, key: &PublicKey3072) -> Result<Encryption3072> {
        let plaintext = self.paillier_plaintext(key)?;
        key.encrypt(&plaintext).map_err(paillier_error)
    }

    fn paillier_plaintext(&self, key: &PublicKey3072) -> Result<thunderbolt_paillier::SecretPlaintext3072> {
        let mut padded = Zeroizing::new([0_u8; PAILLIER_MODULUS_BYTES]);
        padded[PAILLIER_MODULUS_BYTES - 32..].copy_from_slice(self.0.as_ref());
        key.plaintext_from_secret_bytes(thunderbolt_paillier::SecretPlaintextBytes3072::new(padded))
            .map_err(paillier_error)
    }

    fn as_uint(&self) -> U256 {
        U256::from_be_slice(self.0.as_ref())
    }
}

struct ScalarSecret;

impl ScalarSecret {
    fn parse(bytes: &[u8; 32]) -> Result<secp::Scalar> {
        secp::Scalar::from_slice(bytes)
            .map_err(|_| ThunderboltError::OutOfRange("secret scalar must be a nonzero secp256k1 scalar".to_string()))
    }
}

/// One-use builder for the paper's Invoice Consistency Proof.
///
/// It owns the non-cloneable encryption openings and secret refresh scalar.
/// Calling [`Self::prove`] consumes all of them.
///
/// ```compile_fail
/// use thunderbolt_core::zkp::InvoiceProver3072;
/// fn reuse(prover: InvoiceProver3072) {
///     let _ = prover.prove();
///     let _ = prover.prove();
/// }
/// ```
pub struct InvoiceProver3072 {
    statement: InvoiceStatement3072,
    refresh: SecretScalar3072,
    recipient_opening: Encryption3072,
    committee_opening: Encryption3072,
}

impl InvoiceProver3072 {
    pub fn prepare(
        context: ProofContext,
        anchor_base: Point,
        recipient_key: &PublicKey3072,
        committee_key: &PublicKey3072,
        refresh: SecretScalar3072,
    ) -> Result<Self> {
        context.expect_invoice()?;
        let delta = refresh.public_point(&anchor_base)?;
        let recipient_opening = refresh.encrypt_for_key(recipient_key)?;
        let committee_opening = refresh.encrypt_for_key(committee_key)?;
        let statement = InvoiceStatement3072 {
            context,
            anchor_base,
            recipient_key: recipient_key.clone(),
            committee_key: committee_key.clone(),
            delta,
            recipient_ciphertext: recipient_opening.ciphertext().clone(),
            committee_ciphertext: committee_opening.ciphertext().clone(),
        };
        Ok(Self {
            statement,
            refresh,
            recipient_opening,
            committee_opening,
        })
    }

    #[must_use]
    pub const fn statement(&self) -> &InvoiceStatement3072 {
        &self.statement
    }

    pub fn prove(self) -> Result<(InvoiceStatement3072, InvoiceProof3072)> {
        let Self {
            statement,
            refresh,
            recipient_opening,
            committee_opening,
        } = self;
        let alpha = ProofMask3072::sample()?;
        let a_delta = alpha.public_point(&statement.anchor_base)?;
        let recipient_commitment = alpha.encrypt_for_key(&statement.recipient_key)?;
        let committee_commitment = alpha.encrypt_for_key(&statement.committee_key)?;
        let a_recipient = recipient_commitment.ciphertext().clone();
        let a_committee = committee_commitment.ciphertext().clone();
        let challenge = invoice_challenge_components(&statement, &a_delta, &a_recipient, &a_committee)?;
        let recipient_material = statement
            .recipient_key
            .consume_proof_openings(recipient_opening, recipient_commitment, &challenge.exponent)
            .map_err(paillier_error)?;
        let committee_material = statement
            .committee_key
            .consume_proof_openings(committee_opening, committee_commitment, &challenge.exponent)
            .map_err(paillier_error)?;
        let proof = InvoiceProof3072 {
            a_delta,
            a_recipient,
            a_committee,
            z: alpha.response(&challenge.exponent, &refresh)?,
            tau_recipient: recipient_material.response_nonce().clone(),
            tau_committee: committee_material.response_nonce().clone(),
        };
        Ok((statement, proof))
    }
}

/// One-use builder for the paper's Transfer Consistency Proof.
pub struct TransferProver3072 {
    statement: TransferStatement3072,
    holder_secret: SecretScalar3072,
    holder_opening: Encryption3072,
}

impl TransferProver3072 {
    pub fn prepare(
        context: ProofContext,
        anchor_base: Point,
        recipient_key: &PublicKey3072,
        invoice_ciphertext: Ciphertext3072,
        holder_secret: SecretScalar3072,
    ) -> Result<Self> {
        context.expect_transfer()?;
        recipient_key
            .validate_ciphertext(&invoice_ciphertext)
            .map_err(paillier_error)?;
        let current_anchor = holder_secret.public_point(&anchor_base)?;
        let holder_opening = holder_secret.encrypt_for_key(recipient_key)?;
        let next_holder_ciphertext = recipient_key
            .add(holder_opening.ciphertext(), &invoice_ciphertext)
            .map_err(paillier_error)?;
        let statement = TransferStatement3072 {
            context,
            anchor_base,
            recipient_key: recipient_key.clone(),
            current_anchor,
            invoice_ciphertext,
            next_holder_ciphertext,
        };
        Ok(Self {
            statement,
            holder_secret,
            holder_opening,
        })
    }

    #[must_use]
    pub const fn statement(&self) -> &TransferStatement3072 {
        &self.statement
    }

    pub fn prove(self) -> Result<(TransferStatement3072, TransferProof3072)> {
        let Self {
            statement,
            holder_secret,
            holder_opening,
        } = self;
        let alpha = ProofMask3072::sample()?;
        let a_anchor = alpha.public_point(&statement.anchor_base)?;
        let commitment = alpha.encrypt_for_key(&statement.recipient_key)?;
        let a_ciphertext = commitment.ciphertext().clone();
        let challenge = transfer_challenge_components(&statement, &a_anchor, &a_ciphertext)?;
        let material = statement
            .recipient_key
            .consume_proof_openings(holder_opening, commitment, &challenge.exponent)
            .map_err(paillier_error)?;
        let proof = TransferProof3072 {
            a_anchor,
            a_ciphertext,
            z: alpha.response(&challenge.exponent, &holder_secret)?,
            tau: material.response_nonce().clone(),
        };
        Ok((statement, proof))
    }
}

/// One-use builder for the explicitly defined encrypted-share VEDL relation.
/// This is not an aggregate VESS prover.
pub struct ShareEncryptionProver3072 {
    statement: ShareEncryptionStatement3072,
    secret: SecretScalar3072,
    opening: Encryption3072,
}

impl ShareEncryptionProver3072 {
    pub fn prepare(
        context: ProofContext,
        anchor_base: Point,
        recipient_key: &PublicKey3072,
        member_id: u32,
        secret: SecretScalar3072,
    ) -> Result<Self> {
        context.expect_invoice()?;
        if member_id == 0 {
            return Err(ThunderboltError::InvalidParameter(
                "share-encryption member id must be positive".to_string(),
            ));
        }
        let committed_point = secret.public_point(&anchor_base)?;
        let opening = secret.encrypt_for_key(recipient_key)?;
        let statement = ShareEncryptionStatement3072 {
            context,
            anchor_base,
            recipient_key: recipient_key.clone(),
            member_id,
            committed_point,
            ciphertext: opening.ciphertext().clone(),
        };
        Ok(Self {
            statement,
            secret,
            opening,
        })
    }

    #[must_use]
    pub const fn statement(&self) -> &ShareEncryptionStatement3072 {
        &self.statement
    }

    pub fn prove(self) -> Result<(ShareEncryptionStatement3072, ShareEncryptionProof3072)> {
        let Self {
            statement,
            secret,
            opening,
        } = self;
        let alpha = ProofMask3072::sample()?;
        let a_point = alpha.public_point(&statement.anchor_base)?;
        let commitment = alpha.encrypt_for_key(&statement.recipient_key)?;
        let a_ciphertext = commitment.ciphertext().clone();
        let challenge = share_challenge_components(&statement, &a_point, &a_ciphertext)?;
        let material = statement
            .recipient_key
            .consume_proof_openings(opening, commitment, &challenge.exponent)
            .map_err(paillier_error)?;
        let proof = ShareEncryptionProof3072 {
            a_point,
            a_ciphertext,
            z: alpha.response(&challenge.exponent, &secret)?,
            tau: material.response_nonce().clone(),
        };
        Ok((statement, proof))
    }
}

#[derive(Zeroize, ZeroizeOnDrop)]
struct ProofMask3072 {
    value: U1024,
    scalar_mod_q: Zeroizing<[u8; 32]>,
}

impl ProofMask3072 {
    /// Samples a unique representation
    /// `alpha = ((a * 2^128 + u) * q) + b`, where `a,b in Z_q` and `u` is a
    /// uniform 128-bit string. This is a bijection onto
    /// `[0, q^2 * 2^128)`, uses no division or remainder, and exposes
    /// `alpha mod q = b` without secret reduction. The negligible `b = 0`
    /// case returns a retryable identity error rather than conditioning the
    /// sampled distribution.
    fn sample() -> Result<Self> {
        let (a, _) = sample_scalar_below_q()?;
        let (b, b_bytes) = sample_scalar_below_q()?;
        let mut random_tail = Zeroizing::new([0_u8; 16]);
        getrandom::fill(random_tail.as_mut())
            .map_err(|_| ThunderboltError::CryptographicError("system entropy is unavailable".to_string()))?;

        let mut coefficient_bytes = Zeroizing::new([0_u8; 64]);
        let a_bytes = secret_uint_to_padded::<{ U256::LIMBS }, 32>(&a)?;
        coefficient_bytes[16..48].copy_from_slice(a_bytes.as_ref());
        coefficient_bytes[48..].copy_from_slice(random_tail.as_ref());
        let coefficient = Zeroizing::new(U512::from_be_slice(coefficient_bytes.as_ref()));
        let q = curve_order_uint().resize::<{ U1024::LIMBS }>();
        let value = Zeroizing::new(
            coefficient
                .resize::<{ U1024::LIMBS }>()
                .wrapping_mul(&q)
                .wrapping_add(&b.resize::<{ U1024::LIMBS }>()),
        );
        Ok(Self {
            value: *value,
            scalar_mod_q: b_bytes,
        })
    }

    fn public_point(&self, anchor_base: &Point) -> Result<Point> {
        let scalar = MaybeScalar::from_slice(self.scalar_mod_q.as_ref()).map_err(|_| {
            ThunderboltError::CryptographicError("sampled proof mask has an invalid field residue".to_string())
        })?;
        (*anchor_base * scalar).not_inf().map_err(|_| {
            ThunderboltError::CryptographicError(
                "sampled proof mask maps to the identity; retry proof construction".to_string(),
            )
        })
    }

    fn paillier_plaintext(&self, key: &PublicKey3072) -> Result<thunderbolt_paillier::SecretPlaintext3072> {
        let bytes = secret_uint_to_padded::<{ U1024::LIMBS }, PAILLIER_MODULUS_BYTES>(&self.value)?;
        key.plaintext_from_secret_bytes(thunderbolt_paillier::SecretPlaintextBytes3072::new(bytes))
            .map_err(paillier_error)
    }

    fn encrypt_for_key(&self, key: &PublicKey3072) -> Result<Encryption3072> {
        let plaintext = self.paillier_plaintext(key)?;
        key.encrypt(&plaintext).map_err(paillier_error)
    }

    fn response(&self, challenge: &PublicExponent3072, witness: &SecretScalar3072) -> Result<ProofResponse3072> {
        let challenge_bytes = Zeroizing::new(challenge.to_bytes());
        let challenge = Zeroizing::new(U256::from_be_slice(&challenge_bytes[PAILLIER_MODULUS_BYTES - 32..]));
        let witness = Zeroizing::new(witness.as_uint());
        let product = Zeroizing::new(challenge.concatenating_mul(&*witness));
        let response = Zeroizing::new(self.value.wrapping_add(&product.resize::<{ U1024::LIMBS }>()));
        let encoded = secret_uint_to_padded::<{ U1024::LIMBS }, 128>(&response)?;
        ProofResponse3072::from_bytes(&encoded[128 - PROOF_RESPONSE_3072_BYTES..])
    }
}

fn sample_scalar_below_q() -> Result<(Zeroizing<U256>, Zeroizing<[u8; 32]>)> {
    let q = curve_order_uint();
    loop {
        let mut bytes = Zeroizing::new([0_u8; 32]);
        getrandom::fill(bytes.as_mut())
            .map_err(|_| ThunderboltError::CryptographicError("system entropy is unavailable".to_string()))?;
        let candidate = Zeroizing::new(U256::from_be_slice(bytes.as_ref()));
        let in_range = candidate.ct_lt(&q);
        if bool::from(in_range) {
            return Ok((candidate, bytes));
        }
    }
}

fn curve_order_uint() -> U256 {
    U256::from_be_slice(&CURVE_ORDER_BYTES)
}

fn secret_uint_to_padded<const LIMBS: usize, const N: usize>(value: &Uint<LIMBS>) -> Result<Zeroizing<[u8; N]>> {
    let encoded_len = LIMBS
        .checked_mul(Limb::BYTES)
        .ok_or_else(|| ThunderboltError::CryptographicError("fixed secret integer width overflowed".to_string()))?;
    if encoded_len > N {
        return Err(ThunderboltError::OutOfRange(format!(
            "fixed secret integer exceeds {N}-byte destination"
        )));
    }
    let mut output = Zeroizing::new([0_u8; N]);
    let offset = N - encoded_len;
    for (destination, word) in output[offset..]
        .chunks_exact_mut(Limb::BYTES)
        .zip(value.as_words().iter().rev())
    {
        let encoded_word = Zeroizing::new(word.to_be_bytes());
        destination.copy_from_slice(encoded_word.as_ref());
    }
    Ok(output)
}

#[derive(Clone, Debug)]
pub struct InvoiceStatement3072 {
    pub context: ProofContext,
    pub anchor_base: Point,
    pub recipient_key: PublicKey3072,
    pub committee_key: PublicKey3072,
    pub delta: Point,
    pub recipient_ciphertext: Ciphertext3072,
    pub committee_ciphertext: Ciphertext3072,
}

#[derive(Clone, Debug)]
pub struct InvoiceProof3072 {
    pub a_delta: Point,
    pub a_recipient: Ciphertext3072,
    pub a_committee: Ciphertext3072,
    pub z: ProofResponse3072,
    pub tau_recipient: ProofNonce3072,
    pub tau_committee: ProofNonce3072,
}

#[derive(Clone, Debug)]
pub struct TransferStatement3072 {
    pub context: ProofContext,
    pub anchor_base: Point,
    pub recipient_key: PublicKey3072,
    pub current_anchor: Point,
    pub invoice_ciphertext: Ciphertext3072,
    pub next_holder_ciphertext: Ciphertext3072,
}

#[derive(Clone, Debug)]
pub struct TransferProof3072 {
    pub a_anchor: Point,
    pub a_ciphertext: Ciphertext3072,
    pub z: ProofResponse3072,
    pub tau: ProofNonce3072,
}

/// One explicitly defined VEDL relation for an encrypted polynomial share.
/// This is not the paper's unspecified aggregate VESS transcript.
#[derive(Clone, Debug)]
pub struct ShareEncryptionStatement3072 {
    pub context: ProofContext,
    pub anchor_base: Point,
    pub recipient_key: PublicKey3072,
    pub member_id: u32,
    pub committed_point: Point,
    pub ciphertext: Ciphertext3072,
}

#[derive(Clone, Debug)]
pub struct ShareEncryptionProof3072 {
    pub a_point: Point,
    pub a_ciphertext: Ciphertext3072,
    pub z: ProofResponse3072,
    pub tau: ProofNonce3072,
}

/// Verifies the paper's three-equation invoice relation.
pub fn verify_invoice_3072(statement: &InvoiceStatement3072, proof: &InvoiceProof3072) -> Result<()> {
    statement.context.expect_invoice()?;
    let challenge = invoice_challenge(statement, proof)?;
    verify_ec_equation(
        &statement.anchor_base,
        &statement.delta,
        &proof.a_delta,
        &proof.z,
        challenge.scalar,
        "invoice EC equation zH = A_D + cD_s failed",
    )?;
    verify_paillier_equation(
        &statement.recipient_key,
        &statement.recipient_ciphertext,
        &proof.a_recipient,
        &proof.tau_recipient,
        &proof.z,
        &challenge.exponent,
        "invoice recipient Paillier equation failed",
    )?;
    verify_paillier_equation(
        &statement.committee_key,
        &statement.committee_ciphertext,
        &proof.a_committee,
        &proof.tau_committee,
        &proof.z,
        &challenge.exponent,
        "invoice committee Paillier equation failed",
    )
}

/// Verifies the paper's EC and Paillier transfer equations.
pub fn verify_transfer_3072(statement: &TransferStatement3072, proof: &TransferProof3072) -> Result<()> {
    statement.context.expect_transfer()?;
    let challenge = transfer_challenge(statement, proof)?;
    verify_ec_equation(
        &statement.anchor_base,
        &statement.current_anchor,
        &proof.a_anchor,
        &proof.z,
        challenge.scalar,
        "transfer EC equation zH = A_X + cX_s failed",
    )?;
    let offset = statement
        .recipient_key
        .subtract(&statement.next_holder_ciphertext, &statement.invoice_ciphertext)
        .map_err(paillier_error)?;
    verify_paillier_equation(
        &statement.recipient_key,
        &offset,
        &proof.a_ciphertext,
        &proof.tau,
        &proof.z,
        &challenge.exponent,
        "transfer Paillier equation failed",
    )
}

/// Verifies one paper-defined encrypted-share VEDL equation.
///
/// This function does not claim to verify a complete Simple VESS package.
pub fn verify_share_encryption_3072(
    statement: &ShareEncryptionStatement3072,
    proof: &ShareEncryptionProof3072,
) -> Result<()> {
    statement.context.expect_invoice()?;
    if statement.member_id == 0 {
        return Err(ThunderboltError::InvalidParameter(
            "share-encryption member id must be positive".to_string(),
        ));
    }
    let challenge = share_challenge(statement, proof)?;
    verify_ec_equation(
        &statement.anchor_base,
        &statement.committed_point,
        &proof.a_point,
        &proof.z,
        challenge.scalar,
        "share-encryption EC equation failed",
    )?;
    verify_paillier_equation(
        &statement.recipient_key,
        &statement.ciphertext,
        &proof.a_ciphertext,
        &proof.tau,
        &proof.z,
        &challenge.exponent,
        "share-encryption Paillier equation failed",
    )
}

/// Verifies the public anchor transition outside `R_transfer`.
pub fn verify_anchor_transition_3072(current_anchor: &Point, delta: &Point, next_anchor: &Point) -> Result<()> {
    if *current_anchor + *delta != MaybePoint::Valid(*next_anchor) {
        return Err(ThunderboltError::InvalidStateTransition(
            "anchor transition X_{s+1} = X_s + D_s failed".to_string(),
        ));
    }
    Ok(())
}

fn verify_ec_equation(
    anchor_base: &Point,
    statement_point: &Point,
    commitment_point: &Point,
    response: &ProofResponse3072,
    challenge: MaybeScalar,
    error: &'static str,
) -> Result<()> {
    let lhs = *anchor_base * response.scalar_mod_q()?;
    let rhs = *commitment_point + *statement_point * challenge;
    if lhs != rhs {
        return Err(ThunderboltError::InvalidProof(error.to_string()));
    }
    Ok(())
}

fn verify_paillier_equation(
    key: &PublicKey3072,
    statement_ciphertext: &Ciphertext3072,
    commitment_ciphertext: &Ciphertext3072,
    response_nonce: &ProofNonce3072,
    response: &ProofResponse3072,
    challenge: &PublicExponent3072,
    error: &'static str,
) -> Result<()> {
    let lhs = key
        .response_lhs(&response.paillier_exponent()?, response_nonce)
        .map_err(paillier_error)?;
    let challenged = key
        .exponentiate(statement_ciphertext, challenge)
        .map_err(paillier_error)?;
    let rhs = key.add(commitment_ciphertext, &challenged).map_err(paillier_error)?;
    if lhs != rhs {
        return Err(ThunderboltError::InvalidProof(error.to_string()));
    }
    Ok(())
}

fn invoice_challenge(statement: &InvoiceStatement3072, proof: &InvoiceProof3072) -> Result<Challenge3072> {
    invoice_challenge_components(statement, &proof.a_delta, &proof.a_recipient, &proof.a_committee)
}

fn invoice_challenge_components(
    statement: &InvoiceStatement3072,
    a_delta: &Point,
    a_recipient: &Ciphertext3072,
    a_committee: &Ciphertext3072,
) -> Result<Challenge3072> {
    let mut transcript = ProductionTranscript::new(ProofTag::Invoice);
    transcript.append_context(&statement.context);
    transcript.append_point(b"H", &statement.anchor_base);
    transcript.append_integer(b"pk_B", &statement.recipient_key.to_bytes());
    transcript.append_integer(b"pk_C", &statement.committee_key.to_bytes());
    transcript.append_point(b"D_s", &statement.delta);
    transcript.append_integer(b"ct_B", &statement.recipient_ciphertext.to_bytes());
    transcript.append_integer(b"ct_C", &statement.committee_ciphertext.to_bytes());
    transcript.append_point(b"A_D", a_delta);
    transcript.append_integer(b"A_B", &a_recipient.to_bytes());
    transcript.append_integer(b"A_C", &a_committee.to_bytes());
    transcript.challenge()
}

fn transfer_challenge(statement: &TransferStatement3072, proof: &TransferProof3072) -> Result<Challenge3072> {
    transfer_challenge_components(statement, &proof.a_anchor, &proof.a_ciphertext)
}

fn transfer_challenge_components(
    statement: &TransferStatement3072,
    a_anchor: &Point,
    a_ciphertext: &Ciphertext3072,
) -> Result<Challenge3072> {
    let mut transcript = ProductionTranscript::new(ProofTag::Transfer);
    transcript.append_context(&statement.context);
    transcript.append_point(b"H", &statement.anchor_base);
    transcript.append_integer(b"pk_B", &statement.recipient_key.to_bytes());
    transcript.append_point(b"X_s", &statement.current_anchor);
    transcript.append_integer(b"ct_B", &statement.invoice_ciphertext.to_bytes());
    transcript.append_integer(b"T_next", &statement.next_holder_ciphertext.to_bytes());
    transcript.append_point(b"A_X", a_anchor);
    transcript.append_integer(b"A_T", &a_ciphertext.to_bytes());
    transcript.challenge()
}

fn share_challenge(
    statement: &ShareEncryptionStatement3072,
    proof: &ShareEncryptionProof3072,
) -> Result<Challenge3072> {
    share_challenge_components(statement, &proof.a_point, &proof.a_ciphertext)
}

fn share_challenge_components(
    statement: &ShareEncryptionStatement3072,
    a_point: &Point,
    a_ciphertext: &Ciphertext3072,
) -> Result<Challenge3072> {
    let mut transcript = ProductionTranscript::new(ProofTag::ShareEncryption);
    transcript.append_context(&statement.context);
    transcript.append_point(b"H", &statement.anchor_base);
    transcript.append_integer(b"pk_i", &statement.recipient_key.to_bytes());
    transcript.append_u32(b"member_id", statement.member_id);
    transcript.append_point(b"S_i", &statement.committed_point);
    transcript.append_integer(b"ct_i", &statement.ciphertext.to_bytes());
    transcript.append_point(b"A_S", a_point);
    transcript.append_integer(b"A_ct", &a_ciphertext.to_bytes());
    transcript.challenge()
}

struct Challenge3072 {
    scalar: MaybeScalar,
    exponent: PublicExponent3072,
}

impl Challenge3072 {
    fn from_digest(digest: [u8; 32]) -> Result<Self> {
        let scalar = MaybeScalar::reduce_from(&digest);
        let exponent = PublicExponent3072::from_bytes(scalar.serialize()).map_err(paillier_error)?;
        Ok(Self { scalar, exponent })
    }
}

struct ProductionTranscript {
    hasher: Sha256,
}

impl ProductionTranscript {
    fn new(tag: ProofTag) -> Self {
        let mut transcript = Self { hasher: Sha256::new() };
        transcript.append_bytes(b"tag", tag.as_bytes());
        transcript
    }

    fn append_context(&mut self, context: &ProofContext) {
        self.append_bytes(b"ctx_id", context.ctx_id());
        self.append_bytes(b"inv_id", context.inv_id());
        if let Some(step) = context.step() {
            self.append_bytes(b"step", &step.to_be_bytes());
        }
    }

    fn append_point(&mut self, label: &[u8], point: &Point) {
        self.append_bytes(label, &point.serialize());
    }

    fn append_integer(&mut self, label: &[u8], fixed: &[u8]) {
        let first_nonzero = fixed.iter().position(|byte| *byte != 0);
        match first_nonzero {
            Some(offset) => self.append_bytes(label, &fixed[offset..]),
            None => self.append_bytes(label, &[0]),
        }
    }

    fn append_u32(&mut self, label: &[u8], value: u32) {
        self.append_bytes(label, &value.to_be_bytes());
    }

    fn challenge(self) -> Result<Challenge3072> {
        Challenge3072::from_digest(self.hasher.finalize().into())
    }

    fn append_bytes(&mut self, label: &[u8], value: &[u8]) {
        self.hasher.update((label.len() as u64).to_be_bytes());
        self.hasher.update(label);
        self.hasher.update((value.len() as u64).to_be_bytes());
        self.hasher.update(value);
    }
}

fn curve_order() -> &'static BigUint {
    static CURVE_ORDER: OnceLock<BigUint> = OnceLock::new();
    CURVE_ORDER.get_or_init(|| BigUint::from_bytes_be(&CURVE_ORDER_BYTES))
}

fn maximum_response_value() -> &'static BigUint {
    static MAXIMUM: OnceLock<BigUint> = OnceLock::new();
    MAXIMUM.get_or_init(|| {
        let q = curve_order();
        let q_minus_one = q - BigUint::one();
        ((q * q) << STATISTICAL_SECURITY_BITS) - BigUint::one() + &q_minus_one * &q_minus_one
    })
}

fn fixed_biguint<const N: usize>(value: &BigUint) -> Result<[u8; N]> {
    let bytes = value.to_bytes_be();
    if bytes.len() > N {
        return Err(ThunderboltError::OutOfRange(format!(
            "public integer exceeds {N}-byte fixed width"
        )));
    }
    let mut fixed = [0_u8; N];
    fixed[N - bytes.len()..].copy_from_slice(&bytes);
    Ok(fixed)
}

fn paillier_error(error: thunderbolt_paillier::PaillierError) -> ThunderboltError {
    ThunderboltError::CryptographicError(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use secp::Scalar;
    use secp256k1::{Keypair, Secp256k1, SecretKey, XOnlyPublicKey};
    use thunderbolt_paillier::{OfflineKeyGenerator, SecretKey3072, SecretPlaintext3072, SecretPlaintextBytes3072};
    use zeroize::Zeroizing;

    fn scalar(value: u64) -> Scalar {
        let mut bytes = [0_u8; 32];
        bytes[24..].copy_from_slice(&value.to_be_bytes());
        Scalar::from_slice(&bytes).expect("small nonzero scalar")
    }

    fn test_secret_key() -> &'static SecretKey3072 {
        static KEY: OnceLock<SecretKey3072> = OnceLock::new();
        KEY.get_or_init(|| {
            OfflineKeyGenerator
                .generate()
                .expect("offline test-only Paillier key generation")
        })
    }

    fn plaintext(key: &PublicKey3072, value: u64) -> SecretPlaintext3072 {
        key.plaintext_from_secret_bytes(
            SecretPlaintextBytes3072::left_pad(Zeroizing::new(value.to_be_bytes())).expect("small plaintext width"),
        )
        .expect("small plaintext")
    }

    fn secret_scalar(value: u64) -> SecretScalar3072 {
        let mut bytes = Zeroizing::new([0_u8; 32]);
        bytes[24..].copy_from_slice(&value.to_be_bytes());
        SecretScalar3072::from_bytes(bytes).expect("small secret scalar")
    }

    fn authority(
        seed: u8,
        policy: [u8; 32],
        valid_from: u64,
        valid_through: u64,
    ) -> (TrustedProvisioningAuthority3072, Keypair) {
        let secp = Secp256k1::signing_only();
        let secret = SecretKey::from_byte_array([seed; 32]).expect("authority secret");
        let keypair = Keypair::from_secret_key(&secp, &secret);
        let (public, _) = XOnlyPublicKey::from_keypair(&keypair);
        let authority = TrustedProvisioningAuthority3072::new(public.serialize(), valid_from, valid_through, policy)
            .expect("trusted authority");
        (authority, keypair)
    }

    #[allow(clippy::too_many_arguments)]
    fn registration(
        key: &PublicKey3072,
        authority: &TrustedProvisioningAuthority3072,
        keypair: &Keypair,
        deployment: [u8; 32],
        epoch: u64,
        role: CertifiedKeyRole3072,
        subject: [u8; 32],
        policy: [u8; 32],
        serial: u64,
    ) -> CertifiedKeyRegistration3072 {
        let identity = CertifiedKeyIdentity3072::new(role, subject).expect("identity");
        let body = thunderbolt_paillier::PublicKeyCertificateBody3072::new(
            deployment,
            epoch,
            identity.clone(),
            policy,
            *authority.authority_id(),
            serial,
            key.to_raw(),
        )
        .expect("certificate body");
        let signature = Secp256k1::signing_only()
            .sign_schnorr_no_aux_rand(&body.signing_digest(), keypair)
            .to_byte_array();
        let record = CertifiedPublicKeyRecord3072::new(body, signature).expect("certificate record");
        CertifiedKeyRegistration3072 {
            record,
            expected: ExpectedPublicKeyCertificate3072 {
                deployment_digest: deployment,
                committee_epoch: epoch,
                identity,
                key_validity_policy_id: policy,
                certificate_serial: serial,
            },
        }
    }

    fn unit_nonce(key: &PublicKey3072) -> ProofNonce3072 {
        let mut bytes = [0_u8; PAILLIER_MODULUS_BYTES];
        bytes[PAILLIER_MODULUS_BYTES - 1] = 1;
        key.proof_nonce_from_bytes(bytes).expect("unit proof nonce")
    }

    fn zero_response() -> ProofResponse3072 {
        ProofResponse3072::from_biguint(&BigUint::ZERO).expect("zero response")
    }

    fn response(alpha: u64, challenge: &Challenge3072, witness: u64) -> ProofResponse3072 {
        let challenge = BigUint::from_bytes_be(&challenge.exponent.to_bytes());
        ProofResponse3072::from_biguint(&(BigUint::from(alpha) + challenge * BigUint::from(witness)))
            .expect("bounded response")
    }

    fn assert_paillier_oracle(
        key: &PublicKey3072,
        statement: &Ciphertext3072,
        commitment: &Ciphertext3072,
        response_nonce: &ProofNonce3072,
        response: &ProofResponse3072,
        challenge: &Challenge3072,
    ) {
        let n = BigUint::from_bytes_be(&key.to_bytes());
        let n_squared = &n * &n;
        let generator = &n + BigUint::one();
        let z = response.as_biguint();
        let c = BigUint::from_bytes_be(&challenge.exponent.to_bytes());
        let tau = BigUint::from_bytes_be(&response_nonce.to_bytes());
        let lhs = (generator.modpow(&z, &n_squared) * tau.modpow(&n, &n_squared)) % &n_squared;
        let rhs = (BigUint::from_bytes_be(&commitment.to_bytes())
            * BigUint::from_bytes_be(&statement.to_bytes()).modpow(&c, &n_squared))
            % &n_squared;
        assert_eq!(lhs, rhs);
    }

    fn valid_invoice() -> (InvoiceStatement3072, InvoiceProof3072) {
        let key = test_secret_key().public_key();
        let anchor_base = scalar(41).base_point_mul();
        let refresh_value = 7_u64;
        let alpha_value = 13_u64;
        let recipient_opening = key
            .encrypt(&plaintext(key, refresh_value))
            .expect("recipient encryption");
        let committee_opening = key
            .encrypt(&plaintext(key, refresh_value))
            .expect("committee encryption");
        let recipient_commitment = key.encrypt(&plaintext(key, alpha_value)).expect("recipient commitment");
        let committee_commitment = key.encrypt(&plaintext(key, alpha_value)).expect("committee commitment");
        let statement = InvoiceStatement3072 {
            context: ProofContext::invoice(b"production-context", b"invoice-1"),
            anchor_base,
            recipient_key: key.clone(),
            committee_key: key.clone(),
            delta: anchor_base * scalar(refresh_value),
            recipient_ciphertext: recipient_opening.ciphertext().clone(),
            committee_ciphertext: committee_opening.ciphertext().clone(),
        };
        let provisional = InvoiceProof3072 {
            a_delta: anchor_base * scalar(alpha_value),
            a_recipient: recipient_commitment.ciphertext().clone(),
            a_committee: committee_commitment.ciphertext().clone(),
            z: zero_response(),
            tau_recipient: unit_nonce(key),
            tau_committee: unit_nonce(key),
        };
        let challenge = invoice_challenge(&statement, &provisional).expect("invoice challenge");
        let recipient_material = key
            .consume_proof_openings(recipient_opening, recipient_commitment, &challenge.exponent)
            .expect("recipient opening response");
        let committee_material = key
            .consume_proof_openings(committee_opening, committee_commitment, &challenge.exponent)
            .expect("committee opening response");
        let proof = InvoiceProof3072 {
            z: response(alpha_value, &challenge, refresh_value),
            tau_recipient: recipient_material.response_nonce().clone(),
            tau_committee: committee_material.response_nonce().clone(),
            ..provisional
        };
        assert_paillier_oracle(
            key,
            &statement.recipient_ciphertext,
            &proof.a_recipient,
            &proof.tau_recipient,
            &proof.z,
            &challenge,
        );
        assert_paillier_oracle(
            key,
            &statement.committee_ciphertext,
            &proof.a_committee,
            &proof.tau_committee,
            &proof.z,
            &challenge,
        );
        (statement, proof)
    }

    fn valid_transfer() -> (TransferStatement3072, TransferProof3072, Point, Point) {
        let key = test_secret_key().public_key();
        let anchor_base = scalar(43).base_point_mul();
        let holder_value = 11_u64;
        let refresh_value = 5_u64;
        let alpha_value = 17_u64;
        let invoice_opening = key.encrypt(&plaintext(key, refresh_value)).expect("invoice encryption");
        let holder_opening = key.encrypt(&plaintext(key, holder_value)).expect("holder encryption");
        let alpha_opening = key.encrypt(&plaintext(key, alpha_value)).expect("transfer commitment");
        let next_holder_ciphertext = key
            .add(holder_opening.ciphertext(), invoice_opening.ciphertext())
            .expect("homomorphic holder update");
        let current_anchor = anchor_base * scalar(holder_value);
        let statement = TransferStatement3072 {
            context: ProofContext::transfer(b"production-context", 1, b"invoice-1"),
            anchor_base,
            recipient_key: key.clone(),
            current_anchor,
            invoice_ciphertext: invoice_opening.ciphertext().clone(),
            next_holder_ciphertext,
        };
        let provisional = TransferProof3072 {
            a_anchor: anchor_base * scalar(alpha_value),
            a_ciphertext: alpha_opening.ciphertext().clone(),
            z: zero_response(),
            tau: unit_nonce(key),
        };
        let challenge = transfer_challenge(&statement, &provisional).expect("transfer challenge");
        let material = key
            .consume_proof_openings(holder_opening, alpha_opening, &challenge.exponent)
            .expect("transfer opening response");
        let proof = TransferProof3072 {
            z: response(alpha_value, &challenge, holder_value),
            tau: material.response_nonce().clone(),
            ..provisional
        };
        let offset = key
            .subtract(&statement.next_holder_ciphertext, &statement.invoice_ciphertext)
            .expect("holder component");
        assert_paillier_oracle(key, &offset, &proof.a_ciphertext, &proof.tau, &proof.z, &challenge);
        let delta = anchor_base * scalar(refresh_value);
        let next_anchor = (current_anchor + delta).not_inf().expect("next anchor");
        (statement, proof, delta, next_anchor)
    }

    fn valid_share() -> (ShareEncryptionStatement3072, ShareEncryptionProof3072) {
        let key = test_secret_key().public_key();
        let anchor_base = scalar(47).base_point_mul();
        let share_value = 19_u64;
        let alpha_value = 23_u64;
        let share_opening = key.encrypt(&plaintext(key, share_value)).expect("share encryption");
        let alpha_opening = key.encrypt(&plaintext(key, alpha_value)).expect("share commitment");
        let statement = ShareEncryptionStatement3072 {
            context: ProofContext::invoice(b"share-context", b"invoice-2"),
            anchor_base,
            recipient_key: key.clone(),
            member_id: 1,
            committed_point: anchor_base * scalar(share_value),
            ciphertext: share_opening.ciphertext().clone(),
        };
        let provisional = ShareEncryptionProof3072 {
            a_point: anchor_base * scalar(alpha_value),
            a_ciphertext: alpha_opening.ciphertext().clone(),
            z: zero_response(),
            tau: unit_nonce(key),
        };
        let challenge = share_challenge(&statement, &provisional).expect("share challenge");
        let material = key
            .consume_proof_openings(share_opening, alpha_opening, &challenge.exponent)
            .expect("share opening response");
        let proof = ShareEncryptionProof3072 {
            z: response(alpha_value, &challenge, share_value),
            tau: material.response_nonce().clone(),
            ..provisional
        };
        assert_paillier_oracle(
            key,
            &statement.ciphertext,
            &proof.a_ciphertext,
            &proof.tau,
            &proof.z,
            &challenge,
        );
        (statement, proof)
    }

    #[test]
    fn response_bound_is_exact_and_canonical() {
        let maximum = maximum_response_value().clone();
        let response = ProofResponse3072::from_biguint(&maximum).expect("maximum response");
        assert_eq!(response.as_biguint(), maximum);
        assert_eq!(response.as_biguint().bits(), 640);
        assert_eq!(response.as_bytes()[0], 0);

        assert!(ProofResponse3072::from_biguint(&(maximum_response_value() + BigUint::one())).is_err());
        let mut unused_high_bit = [0_u8; PROOF_RESPONSE_3072_BYTES];
        unused_high_bit[0] = 1;
        assert!(ProofResponse3072::from_bytes(unused_high_bit).is_err());
    }

    #[test]
    fn signed_certificate_registry_restarts_without_factors_and_rejects_scope_replay() {
        let key = test_secret_key().public_key().clone();
        let deployment = [0x31; 32];
        let policy = [0x41; 32];
        let subject = [0x51; 32];
        let (trusted_authority, keypair) = authority(3, policy, 1, 10);
        let trusted_registration = registration(
            &key,
            &trusted_authority,
            &keypair,
            deployment,
            7,
            CertifiedKeyRole3072::Recipient,
            subject,
            policy,
            9,
        );
        let encoded = trusted_registration.record.to_bytes();
        let decoded = CertifiedPublicKeyRecord3072::from_bytes(encoded).expect("canonical certificate codec");
        assert_eq!(decoded, trusted_registration.record);
        let restart_registration = CertifiedKeyRegistration3072 {
            record: decoded,
            expected: trusted_registration.expected.clone(),
        };
        let registry = CertifiedKeyRegistry3072::from_certificates(
            [restart_registration],
            std::slice::from_ref(&trusted_authority),
        )
        .expect("restart registry from public certificate only");
        assert_eq!(registry.len(), 1);
        assert_eq!(
            registry
                .resolve_certified_key(&key.to_raw(), CertifiedKeyRole3072::Recipient)
                .expect("exact role and key"),
            key
        );
        assert!(registry
            .resolve_certified_key(&key.to_raw(), CertifiedKeyRole3072::Committee)
            .is_err());

        let mut unregistered = key.to_bytes();
        unregistered[1] ^= 1;
        let unregistered = RawPublicKey3072::from_bytes(unregistered).expect("structured raw key");
        assert!(registry
            .resolve_certified_key(&unregistered, CertifiedKeyRole3072::Recipient)
            .is_err());

        for mutate in 0..6 {
            let mut wrong = trusted_registration.clone();
            match mutate {
                0 => wrong.expected.deployment_digest[0] ^= 1,
                1 => wrong.expected.committee_epoch += 1,
                2 => {
                    wrong.expected.identity =
                        CertifiedKeyIdentity3072::new(CertifiedKeyRole3072::Committee, subject).expect("other role")
                }
                3 => {
                    wrong.expected.identity = CertifiedKeyIdentity3072::new(CertifiedKeyRole3072::Recipient, [0x52; 32])
                        .expect("other subject")
                }
                4 => wrong.expected.key_validity_policy_id[0] ^= 1,
                5 => wrong.expected.certificate_serial += 1,
                _ => unreachable!(),
            }
            assert!(
                CertifiedKeyRegistry3072::from_certificates([wrong], std::slice::from_ref(&trusted_authority),)
                    .is_err()
            );
        }

        let (untrusted, untrusted_keypair) = authority(4, policy, 1, 10);
        let self_signed = registration(
            &key,
            &untrusted,
            &untrusted_keypair,
            deployment,
            7,
            CertifiedKeyRole3072::Recipient,
            subject,
            policy,
            9,
        );
        assert!(
            CertifiedKeyRegistry3072::from_certificates([self_signed], std::slice::from_ref(&trusted_authority),)
                .is_err()
        );

        let expired =
            TrustedProvisioningAuthority3072::new(XOnlyPublicKey::from_keypair(&keypair).0.serialize(), 1, 6, policy)
                .expect("structurally valid expired authority");
        assert!(CertifiedKeyRegistry3072::from_certificates([trusted_registration.clone()], &[expired],).is_err());

        let mut substituted = trusted_registration.record.to_bytes();
        substituted[157] ^= 1;
        let substituted = CertifiedPublicKeyRecord3072::from_bytes(substituted).expect("structured substituted cert");
        assert!(CertifiedKeyRegistry3072::from_certificates(
            [CertifiedKeyRegistration3072 {
                record: substituted,
                expected: trusted_registration.expected,
            }],
            &[trusted_authority],
        )
        .is_err());
    }

    #[test]
    fn invoice_equations_verify_and_context_or_equation_changes_fail() {
        let (statement, proof) = valid_invoice();
        verify_invoice_3072(&statement, &proof).expect("valid invoice proof");

        let mut wrong_context = statement.clone();
        wrong_context.context = ProofContext::invoice(b"other-context", b"invoice-1");
        assert!(verify_invoice_3072(&wrong_context, &proof).is_err());

        let mut wrong_equation = proof.clone();
        wrong_equation.a_recipient = statement
            .recipient_key
            .add(&proof.a_recipient, &statement.recipient_ciphertext)
            .expect("tampered commitment");
        assert!(verify_invoice_3072(&statement, &wrong_equation).is_err());
    }

    #[test]
    fn transfer_equations_and_anchor_transition_verify() {
        let (statement, proof, delta, next_anchor) = valid_transfer();
        verify_transfer_3072(&statement, &proof).expect("valid transfer proof");
        verify_anchor_transition_3072(&statement.current_anchor, &delta, &next_anchor)
            .expect("valid anchor transition");

        let mut wrong_step = statement.clone();
        wrong_step.context = ProofContext::transfer(b"production-context", 2, b"invoice-1");
        assert!(verify_transfer_3072(&wrong_step, &proof).is_err());
        assert!(verify_anchor_transition_3072(&statement.current_anchor, &delta, &statement.current_anchor).is_err());
    }

    #[test]
    fn per_share_vedl_verifies_without_claiming_aggregate_vess() {
        let (statement, proof) = valid_share();
        verify_share_encryption_3072(&statement, &proof).expect("valid share VEDL proof");

        let mut wrong_member = statement.clone();
        wrong_member.member_id = 2;
        assert!(verify_share_encryption_3072(&wrong_member, &proof).is_err());
    }

    #[test]
    fn one_use_provers_produce_verifiable_invoice_transfer_and_share_proofs() {
        let key = test_secret_key().public_key();
        let anchor_base = scalar(53).base_point_mul();

        let invoice_builder = InvoiceProver3072::prepare(
            ProofContext::invoice(b"prover-context", b"invoice-3"),
            anchor_base,
            key,
            key,
            secret_scalar(7),
        )
        .expect("invoice preparation");
        let (invoice_statement, invoice_proof) = invoice_builder.prove().expect("invoice proof");
        verify_invoice_3072(&invoice_statement, &invoice_proof).expect("generated invoice verifies");

        let transfer_builder = TransferProver3072::prepare(
            ProofContext::transfer(b"prover-context", 1, b"invoice-3"),
            anchor_base,
            key,
            invoice_statement.recipient_ciphertext.clone(),
            secret_scalar(11),
        )
        .expect("transfer preparation");
        let (transfer_statement, transfer_proof) = transfer_builder.prove().expect("transfer proof");
        verify_transfer_3072(&transfer_statement, &transfer_proof).expect("generated transfer verifies");

        let share_builder = ShareEncryptionProver3072::prepare(
            ProofContext::invoice(b"share-prover-context", b"invoice-4"),
            anchor_base,
            key,
            1,
            secret_scalar(13),
        )
        .expect("share preparation");
        let (share_statement, share_proof) = share_builder.prove().expect("share proof");
        verify_share_encryption_3072(&share_statement, &share_proof).expect("generated share verifies");
    }

    #[test]
    fn sampled_masks_obey_the_exact_paper_bound_and_known_mod_q_residue() {
        let q = BigUint::from_bytes_be(&CURVE_ORDER_BYTES);
        let bound = (&q * &q) << STATISTICAL_SECURITY_BITS;
        for _ in 0..32 {
            let mask = ProofMask3072::sample().expect("proof mask");
            let encoded = secret_uint_to_padded::<{ U1024::LIMBS }, 128>(&mask.value).expect("mask encoding");
            let value = BigUint::from_bytes_be(encoded.as_ref());
            assert!(value < bound);
            assert_eq!(value % &q, BigUint::from_bytes_be(mask.scalar_mod_q.as_ref()));
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig {
            cases: 128,
            failure_persistence: None,
            ..ProptestConfig::default()
        })]

        #[test]
        fn response_codec_round_trips_and_reduction_matches_oracle(tail in any::<[u8; 80]>()) {
            let mut bytes = [0_u8; PROOF_RESPONSE_3072_BYTES];
            bytes[1..].copy_from_slice(&tail);
            let response = ProofResponse3072::from_bytes(bytes)?;
            prop_assert_eq!(response.to_bytes(), bytes);

            let expected = BigUint::from_bytes_be(&bytes) % curve_order();
            prop_assert_eq!(response.scalar_mod_q()?.serialize(), fixed_biguint::<32>(&expected)?);
        }

        #[test]
        fn arbitrary_response_bytes_never_panic(bytes in prop::collection::vec(any::<u8>(), 0..=128)) {
            let _ = ProofResponse3072::from_bytes(bytes);
        }
    }
}
