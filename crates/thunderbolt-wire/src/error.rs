use thiserror::Error;

/// Errors produced while decoding or verifying a public Thunderbolt message.
#[derive(Debug, Error)]
pub enum WireError {
    #[error("unsupported protocol version {actual}; expected {expected}")]
    UnsupportedVersion { expected: u16, actual: u16 },

    #[error("{field} must contain {min}..={max} bytes; got {actual}")]
    InvalidLength {
        field: &'static str,
        min: usize,
        max: usize,
        actual: usize,
    },

    #[error("{field} is not canonical lowercase hexadecimal: {reason}")]
    InvalidHex { field: &'static str, reason: &'static str },

    #[error("{field} is not a canonical non-negative integer encoding")]
    NonCanonicalInteger { field: &'static str },

    #[error("{field} is not a valid compressed secp256k1 point")]
    InvalidPoint { field: &'static str },

    #[error("{field} is not a valid 2048-bit Paillier public key")]
    InvalidPaillierKey { field: &'static str },

    #[error("invalid binding context: {reason}")]
    InvalidBinding { reason: &'static str },

    #[error("invalid {message} message: {reason}")]
    InvalidMessage {
        message: &'static str,
        reason: &'static str,
    },

    #[error("wire message contains {actual} bytes; maximum is {max}")]
    MessageTooLarge { max: usize, actual: usize },

    #[error("JSON codec error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("core {operation} failed: {source}")]
    Core {
        operation: &'static str,
        #[source]
        source: thunderbolt_core::ThunderboltError,
    },
}

pub type Result<T> = std::result::Result<T, WireError>;

pub(crate) fn core_error(operation: &'static str, source: thunderbolt_core::ThunderboltError) -> WireError {
    WireError::Core { operation, source }
}
