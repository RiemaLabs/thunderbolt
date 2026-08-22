use thiserror::Error;

/// Failures surfaced by a secret-vault implementation.
///
/// Variants intentionally carry no backend strings because those strings can
/// accidentally contain paths, key identifiers, or decrypted record data.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum VaultError {
    #[error("the secret vault is unavailable")]
    Unavailable,
    #[error("the secret vault contains an invalid record")]
    CorruptRecord,
    #[error("the secret vault rejected a conflicting write")]
    Conflict,
    #[error("the secret-vault transaction could not be committed durably")]
    CommitFailed,
}

/// Errors returned by the Holder/Recipient engine.
#[derive(Debug, Error)]
pub enum HolderError {
    #[error(transparent)]
    Vault(#[from] VaultError),

    #[error(transparent)]
    Wire(#[from] thunderbolt_wire::WireError),

    #[error("invalid protocol identifier")]
    InvalidProtocolIdentifier,

    #[error("operating-system randomness is unavailable")]
    EntropyUnavailable,

    #[error("Paillier key generation failed")]
    KeyGenerationFailed,

    #[error("the holder identity has not been initialized")]
    IdentityNotInitialized,

    #[error("{operation} failed")]
    CryptographicOperation { operation: &'static str },

    #[error("{reason}")]
    InvalidInput { reason: &'static str },

    #[error("the required committed credential is not present")]
    CredentialNotFound,

    #[error("the private invoice record is not present")]
    InvoiceNotFound,

    #[error("the private invoice has not been durably committed")]
    InvoiceNotCommitted,

    #[error("the durable acknowledgement does not identify this public message")]
    AcknowledgementMismatch,

    #[error("the public message conflicts with local private state")]
    PrivateStateMismatch,

    #[error("the requested transition conflicts with an existing monotonic state")]
    StateConflict,

    #[error("the decrypted credential does not open the committed next-holder anchor")]
    AnchorOpeningMismatch,

    #[error("the anchor transition reaches the point at infinity")]
    PointAtInfinity,

    #[error("the transfer step cannot advance monotonically")]
    InvalidStep,
}

pub(crate) fn crypto_error(operation: &'static str, _error: thunderbolt_core::ThunderboltError) -> HolderError {
    HolderError::CryptographicOperation { operation }
}
