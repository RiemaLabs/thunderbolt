/// Failures reported by checked Floor ABCI adapter methods.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum FloorAbciError {
    /// An ABCI request was malformed, out of bounds, or contextually stale.
    #[error("invalid Floor ABCI request: {0}")]
    InvalidRequest(&'static str),
    /// A transaction was malformed, noncanonical, unauthorized, or invalid at the current head.
    #[error("invalid signed Floor transaction: {0}")]
    InvalidTransaction(&'static str),
    /// The durable Floor application rejected an operation.
    #[error("Floor application rejected ABCI operation")]
    Application(#[from] thunderbolt_floor_app::FloorApplicationError),
    /// A bounded response could not be serialized.
    #[error("Floor ABCI response serialization failed")]
    Serialization(#[from] serde_json::Error),
    /// A requested durable object does not exist.
    #[error("Floor ABCI query object was not found: {0}")]
    NotFound(&'static str),
    /// A second decided block conflicts with the block staged for Commit.
    #[error("conflicting FinalizeBlock while another block is staged")]
    StagedBlockConflict,
    /// Commit arrived without a successful staged FinalizeBlock.
    #[error("Commit has no staged FinalizeBlock result")]
    MissingStagedBlock,
    /// The shared adapter is fail-closed after a consensus-path failure.
    #[error("Floor ABCI adapter is faulted")]
    Faulted,
    /// An adapter mutex was poisoned by an unwind outside this crate.
    #[error("Floor ABCI shared-state lock is poisoned")]
    LockPoisoned,
    /// Durable Commit completed but response delivery became ambiguous.
    #[error("Floor ABCI Commit acknowledgement is ambiguous")]
    PostCommitAmbiguous,
}

impl FloorAbciError {
    pub(crate) fn is_fatal_runtime(&self) -> bool {
        match self {
            Self::Application(error) => !matches!(
                error,
                thunderbolt_floor_app::FloorApplicationError::InvalidInput(_)
                    | thunderbolt_floor_app::FloorApplicationError::InvalidSignature
                    | thunderbolt_floor_app::FloorApplicationError::UnauthorizedActor
                    | thunderbolt_floor_app::FloorApplicationError::BlockContinuity
                    | thunderbolt_floor_app::FloorApplicationError::BlockFork
                    | thunderbolt_floor_app::FloorApplicationError::HistoryPruned { .. }
            ),
            Self::Serialization(_)
            | Self::StagedBlockConflict
            | Self::MissingStagedBlock
            | Self::Faulted
            | Self::LockPoisoned
            | Self::PostCommitAmbiguous => true,
            Self::InvalidRequest(_) | Self::InvalidTransaction(_) | Self::NotFound(_) => false,
        }
    }

    pub(crate) const fn response_code(&self) -> u32 {
        match self {
            Self::InvalidRequest(_) => 1,
            Self::InvalidTransaction(_) => 2,
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
            Self::InvalidTransaction(_) => "invalid_transaction",
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
pub type Result<T> = std::result::Result<T, FloorAbciError>;
