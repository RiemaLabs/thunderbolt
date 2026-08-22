use thiserror::Error;

/// Errors from the closed Paillier-3072 arithmetic boundary.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum PaillierError {
    #[error("{field} must contain exactly {expected} bytes; got {actual}")]
    InvalidLength {
        field: &'static str,
        expected: usize,
        actual: usize,
    },

    #[error("invalid Paillier-3072 public modulus: {reason}")]
    InvalidModulus { reason: &'static str },

    #[error("invalid Paillier-3072 ciphertext: {reason}")]
    InvalidCiphertext { reason: &'static str },

    #[error("invalid Paillier-3072 nonce: {reason}")]
    InvalidNonce { reason: &'static str },

    #[error("invalid Paillier-3072 plaintext or exponent: {reason}")]
    InvalidPlaintext { reason: &'static str },

    #[error("invalid Paillier-3072 secret key: {reason}")]
    InvalidSecretKey { reason: &'static str },

    #[error("{field} belongs to a different Paillier-3072 public key")]
    WrongPublicKey { field: &'static str },

    #[error("system entropy is unavailable")]
    EntropyUnavailable,

    #[error("offline Paillier-3072 key generation failed")]
    KeyGenerationFailed,

    #[error("Paillier-3072 arithmetic invariant failed: {reason}")]
    ArithmeticInvariant { reason: &'static str },
}

pub type Result<T> = core::result::Result<T, PaillierError>;
