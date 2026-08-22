use thiserror::Error;

/// Errors returned by the bounded ownership proof and codec.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum OwnershipError {
    #[error("ownership context is invalid: {0}")]
    InvalidContext(&'static str),
    #[error("anchor-suite registry must contain at least one immutable entry")]
    EmptyAnchorSuiteRegistry,
    #[error("anchor-suite registry contains a duplicate suite identifier")]
    DuplicateAnchorSuite,
    #[error("channel names an anchor suite absent from the trusted registry")]
    UnknownAnchorSuite,
    #[error("ownership envelope does not exactly match the trusted Finalize context")]
    ContextMismatch,
    #[error("ownership witness is not a canonical nonzero secp256k1 scalar")]
    InvalidWitness,
    #[error("ownership witness does not open the current anchor")]
    WitnessMismatch,
    #[error("ownership proof equation failed")]
    InvalidProof,
    #[error("ownership proof or context encoding is malformed")]
    MalformedEncoding,
    #[error("ownership proof uses an unsupported version")]
    UnsupportedVersion,
    #[error("closing transaction exceeds the public byte bound")]
    ClosingTransactionTooLarge,
    #[error("operating-system randomness is unavailable")]
    RandomnessUnavailable,
}

pub type Result<T> = std::result::Result<T, OwnershipError>;
