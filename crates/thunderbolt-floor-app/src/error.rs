use std::path::PathBuf;

/// Fail-closed floor application error.
#[derive(Debug, thiserror::Error)]
pub enum FloorApplicationError {
    /// SQLite operation failed.
    #[error("floor application database operation failed")]
    Database(#[from] rusqlite::Error),
    /// Canonical request or profile input is invalid.
    #[error("invalid floor application input: {0}")]
    InvalidInput(&'static str),
    /// BIP340 request signature is invalid.
    #[error("floor request BIP340 signature is invalid")]
    InvalidSignature,
    /// Request actor is not the immutable registry operator.
    #[error("floor request actor is not authorized for this vault identity")]
    UnauthorizedActor,
    /// Block does not extend the current deterministic application head.
    #[error("floor block does not extend the current application head")]
    BlockContinuity,
    /// A committed height was replayed with different bytes.
    #[error("committed floor block height was reused by a fork")]
    BlockFork,
    /// Supplied genesis registry/profile differs from the database.
    #[error("floor genesis registry or consensus profile does not match the database")]
    GenesisMismatch,
    /// Mainnet floor state is disabled until an independent audit.
    #[error("mainnet floor application is disabled until audit")]
    MainnetDisabled,
    /// Prepared preview no longer matches deterministic re-execution.
    #[error("prepared floor block does not match deterministic commit execution")]
    PreparedMismatch,
    /// Stored state failed integrity or proof reconstruction.
    #[error("floor application stored state is corrupt: {0}")]
    CorruptState(&'static str),
    /// Database belongs to another application or unsupported schema.
    #[error("unsupported floor application database {path:?}")]
    WrongDatabase {
        /// Database path.
        path: PathBuf,
    },
    /// Production storage path is ephemeral, indirect, or not privately managed.
    #[error("floor application requires an absolute persistent database file in a private directory: {path:?}")]
    InvalidStoragePath {
        /// Rejected database path.
        path: PathBuf,
    },
    /// A compacted database cannot expose state before its stored anchor is independently authenticated.
    #[error("compacted floor history requires exact external anchor authentication")]
    ExternalHistoryAnchorRequired,
    /// Requested execution history has been locally pruned behind a finalized anchor.
    #[error(
        "floor history at height {requested_height} was pruned; earliest retained block is {earliest_available}, anchor is {anchor_height}"
    )]
    HistoryPruned {
        /// Requested historical height.
        requested_height: u64,
        /// Earliest retained full block height.
        earliest_available: u64,
        /// Externally finalized snapshot height.
        anchor_height: u64,
    },
    /// Candidate, snapshot, stored anchor, or current history head did not match exactly.
    #[error("history anchor does not exactly match the authenticated application state")]
    HistoryAnchorMismatch,
    /// Retained history exceeds the bounded normal-restart envelope and must be externally anchored and compacted.
    #[error(
        "retained floor history requires recovery compaction ({retained_blocks} blocks, {retained_results} results, {retained_state_deltas} deltas, {retained_live_bytes} live bytes)"
    )]
    CompactionRequired {
        /// Retained block count.
        retained_blocks: u64,
        /// Retained result count.
        retained_results: u64,
        /// Retained state-delta count.
        retained_state_deltas: u64,
        /// Approximate live SQLite bytes.
        retained_live_bytes: u64,
    },
    /// This handle observed an ambiguous or corrupt post-commit state and cannot be reused.
    #[error("floor application handle is poisoned; cold reopen and external reconciliation are required")]
    Poisoned,
    /// Rollback failed after another operation failed.
    #[error("floor application rollback failed after: {operation}")]
    RollbackFailed {
        /// Original operation summary.
        operation: String,
        /// Rollback database error.
        #[source]
        rollback: rusqlite::Error,
    },
}

/// Floor application result.
pub type Result<T> = std::result::Result<T, FloorApplicationError>;
