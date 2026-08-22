//! Isolated, exact-width Paillier backend for Thunderbolt protocol version 2.
//!
//! The crate implements only the production 3072-bit modulus profile. It has
//! no profile selector and no 2048-bit fallback. Secret operations use fixed
//! precision RustCrypto arithmetic and never accept attacker-selected widths.
//! Key generation is explicitly offline and remains variable-time.
//!
//! Openings cannot be cloned or exported. Proof material consumes both the
//! statement opening and a fresh commitment opening, so the safe API cannot
//! reuse Paillier randomness:
//!
//! ```compile_fail
//! use thunderbolt_paillier::{Encryption3072, ProofOpeningResponse3072, PublicExponent3072, PublicKey3072};
//!
//! fn reuse_is_rejected(
//!     key: &PublicKey3072,
//!     statement: Encryption3072,
//!     first_commitment: Encryption3072,
//!     second_commitment: Encryption3072,
//!     challenge: &PublicExponent3072,
//! ) -> thunderbolt_paillier::Result<(ProofOpeningResponse3072, ProofOpeningResponse3072)> {
//!     let first = key.consume_proof_openings(statement, first_commitment, challenge)?;
//!     let second = key.consume_proof_openings(statement, second_commitment, challenge)?;
//!     Ok((first, second))
//! }
//! ```
//!
//! Raw nonce types are not part of the production API:
//!
//! ```compile_fail
//! use thunderbolt_paillier::EncryptionNonce3072;
//! ```
//!
//! ```compile_fail
//! use thunderbolt_paillier::Encryption3072;
//!
//! fn inspect_nonce(opening: &Encryption3072) {
//!     let _ = opening.nonce();
//! }
//! ```
//!
//! Caller-controlled encryption RNGs are also absent:
//!
//! ```compile_fail
//! use thunderbolt_paillier::{PublicKey3072, SecretPlaintext3072};
//!
//! fn inject_rng<R: rand_core::CryptoRng>(
//!     key: &PublicKey3072,
//!     plaintext: &SecretPlaintext3072,
//!     rng: &mut R,
//! ) {
//!     let _ = key.encrypt_with_rng(plaintext, rng);
//! }
//! ```
#![forbid(unsafe_code)]

mod certificate;
mod error;
mod key;
mod types;

pub use certificate::{
    provisioning_authority_id, CertifiedKeyIdentity3072, CertifiedKeyRole3072, CertifiedPublicKeyRecord3072,
    ExpectedPublicKeyCertificate3072, PublicKeyCertificateBody3072, TrustedProvisioningAuthority3072,
    PUBLIC_KEY_CERTIFICATE_BODY_BYTES, PUBLIC_KEY_CERTIFICATE_BYTES,
};
pub use error::{PaillierError, Result};
pub use key::{
    Encryption3072, OfflineKeyGenerator, ProofOpeningResponse3072, PublicKey3072, RawPublicKey3072, SecretKey3072,
};
pub use types::{
    Ciphertext3072, ProofNonce3072, PublicExponent3072, SecretKeyBytes3072, SecretPlaintext3072,
    SecretPlaintextBytes3072, CIPHERTEXT_BYTES, MODULUS_BYTES, PRIME_BYTES, SECRET_KEY_BYTES,
};

#[cfg(test)]
mod tests;

#[cfg(test)]
mod timing_tests;
