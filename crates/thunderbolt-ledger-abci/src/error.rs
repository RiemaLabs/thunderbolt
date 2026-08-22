use thiserror::Error;

/// Failures reported by direct, checked ABCI adapter methods.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum AbciAdapterError {
    /// An ABCI request was malformed, out of bounds, or inconsistent with the
    /// configured chain.
    #[error("invalid ABCI request: {0}")]
    InvalidRequest(&'static str),

    /// A transaction was malformed, non-canonical, or invalid at admission.
    #[error("invalid Thunderbolt transaction: {0}")]
    InvalidTransaction(&'static str),

    /// The durable Ledger application rejected an operation.
    #[error("Ledger application rejected ABCI operation: {0}")]
    Application(#[from] thunderbolt_ledger_app::ApplicationError),

    /// The deterministic Ledger contract rejected a typed value.
    #[error("Ledger contract rejected ABCI value: {0}")]
    Ledger(#[from] thunderbolt_ledger::LedgerContractError),

    /// A bounded query result could not be serialized.
    #[error("ABCI query serialization failed: {0}")]
    Serialization(#[from] serde_json::Error),

    /// A requested durable object does not exist.
    #[error("ABCI query object was not found: {0}")]
    NotFound(&'static str),

    /// A second decided block conflicted with the block already staged for
    /// `Commit`.
    #[error("conflicting FinalizeBlock request while another block is staged")]
    StagedBlockConflict,

    /// `Commit` arrived without a preceding successful `FinalizeBlock` in this
    /// process and was not a duplicate of its immediately completed commit.
    #[error("Commit has no staged FinalizeBlock result")]
    MissingStagedBlock,

    /// Shared adapter state was poisoned by an earlier consensus-path failure.
    #[error("ABCI adapter is fail-closed after a consensus-path failure")]
    Faulted,

    /// A shared-state mutex was poisoned by an unwind outside this crate.
    #[error("ABCI adapter shared-state lock is poisoned")]
    LockPoisoned,

    /// Durable commit completed but the response path became ambiguous.
    #[error("ABCI commit completed but acknowledgement is ambiguous")]
    PostCommitAmbiguous,
}

impl AbciAdapterError {
    pub(crate) fn is_fatal_runtime(&self) -> bool {
        match self {
            Self::Serialization(_)
            | Self::StagedBlockConflict
            | Self::MissingStagedBlock
            | Self::Faulted
            | Self::LockPoisoned
            | Self::PostCommitAmbiguous => true,
            Self::Application(error) => matches!(
                error,
                thunderbolt_ledger_app::ApplicationError::Database(_)
                    | thunderbolt_ledger_app::ApplicationError::Serialization(_)
                    | thunderbolt_ledger_app::ApplicationError::InvalidOptions(_)
                    | thunderbolt_ledger_app::ApplicationError::WrongApplication { .. }
                    | thunderbolt_ledger_app::ApplicationError::UnrecognizedDatabase(_)
                    | thunderbolt_ledger_app::ApplicationError::UnsupportedSchema { .. }
                    | thunderbolt_ledger_app::ApplicationError::MigrationChecksumMismatch { .. }
                    | thunderbolt_ledger_app::ApplicationError::ConfigurationMismatch
                    | thunderbolt_ledger_app::ApplicationError::PreparedBlockMismatch
                    | thunderbolt_ledger_app::ApplicationError::CorruptData(_)
                    | thunderbolt_ledger_app::ApplicationError::LockPoisoned
                    | thunderbolt_ledger_app::ApplicationError::RollbackFailed { .. }
            ),
            Self::InvalidRequest(_) | Self::InvalidTransaction(_) | Self::Ledger(_) | Self::NotFound(_) => false,
        }
    }

    pub(crate) const fn response_code(&self) -> u32 {
        match self {
            Self::InvalidRequest(_) => 1,
            Self::InvalidTransaction(_) | Self::Ledger(_) => 2,
            Self::Application(_) => 3,
            Self::NotFound(_) => 4,
            Self::StagedBlockConflict | Self::MissingStagedBlock => 5,
            Self::Faulted | Self::LockPoisoned | Self::PostCommitAmbiguous => 6,
            Self::Serialization(_) => 7,
        }
    }

    pub(crate) const fn public_log(&self) -> &'static str {
        match self {
            Self::InvalidRequest(_) => "invalid_request",
            Self::InvalidTransaction(_) | Self::Ledger(_) => "invalid_transaction",
            Self::Application(_) => "application_rejected",
            Self::NotFound(_) => "not_found",
            Self::StagedBlockConflict => "staged_block_conflict",
            Self::MissingStagedBlock => "missing_staged_block",
            Self::Faulted | Self::LockPoisoned | Self::PostCommitAmbiguous => "application_unavailable",
            Self::Serialization(_) => "serialization_failed",
        }
    }
}

/// Result returned by checked adapter methods.
pub type Result<T> = std::result::Result<T, AbciAdapterError>;
