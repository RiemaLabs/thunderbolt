use thiserror::Error;

/// Holder role service errors. Variants never contain secret material or
/// backend-provided free-form strings.
#[derive(Debug, Error)]
pub enum HolderNodeError {
    #[error("invalid Holder node configuration: {0}")]
    InvalidConfiguration(&'static str),
    #[error("invalid local-control request: {0}")]
    InvalidRequest(&'static str),
    #[error("invalid service lifecycle transition")]
    InvalidLifecycle,
    #[error("Holder node storage is unavailable")]
    StorageUnavailable,
    #[error("Holder node storage is corrupt or incompatible")]
    StorageCorrupt,
    #[error("local idempotency key conflicts with an existing command")]
    IdempotencyConflict,
    #[error("outbox capacity is exhausted")]
    OutboxCapacity,
    #[error("signed Ledger proposal is invalid or conflicts with local state")]
    InvalidProposal,
    #[error("trusted Ledger receipt conflicts with the submitted proposal or cursor")]
    FinalityConflict,
    #[error("Ledger submission failed")]
    LedgerSubmit,
    #[error("Ledger finality polling failed")]
    LedgerPoll,
    #[error("actor signing capability is unavailable or failed")]
    ActorSigning,
    #[error("required cryptographic capability is unavailable")]
    CapabilityUnavailable,
    #[error("Holder protocol engine rejected the operation")]
    HolderProtocol,
    #[error("integer or clock value is outside the supported range")]
    OutOfRange,
}

impl From<rusqlite::Error> for HolderNodeError {
    fn from(_source: rusqlite::Error) -> Self {
        Self::StorageUnavailable
    }
}

impl From<thunderbolt_holder::HolderError> for HolderNodeError {
    fn from(_source: thunderbolt_holder::HolderError) -> Self {
        Self::HolderProtocol
    }
}

impl From<thunderbolt_ledger::LedgerContractError> for HolderNodeError {
    fn from(_source: thunderbolt_ledger::LedgerContractError) -> Self {
        Self::InvalidProposal
    }
}

impl From<thunderbolt_protocol::v2::V2Error> for HolderNodeError {
    fn from(_source: thunderbolt_protocol::v2::V2Error) -> Self {
        Self::InvalidProposal
    }
}

/// Result returned by Holder node operations.
pub type Result<T> = std::result::Result<T, HolderNodeError>;
