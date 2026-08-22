use std::path::PathBuf;

use thiserror::Error;

/// Failures returned by the deterministic Ledger application.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ApplicationError {
    /// The signed Ledger contract rejected a block or proposal.
    #[error("v2 Ledger contract rejected input: {0}")]
    Ledger(#[from] thunderbolt_ledger::LedgerContractError),

    /// The protocol v2 reducer rejected an authenticated event.
    #[error("v2 protocol reduction failed: {0}")]
    Protocol(#[from] thunderbolt_protocol::v2::V2Error),

    /// The stable version 2 wire binding was invalid.
    #[error("v2 wire binding failed: {0}")]
    Wire(#[from] thunderbolt_wire::WireError),

    /// SQLite returned an error.
    #[error("Ledger application database failed: {0}")]
    Database(#[from] rusqlite::Error),

    /// Durable typed state could not be encoded or decoded.
    #[error("Ledger application serialization failed: {0}")]
    Serialization(#[from] serde_json::Error),

    /// The configured application options are unsafe or inconsistent.
    #[error("invalid Ledger application options: {0}")]
    InvalidOptions(&'static str),

    /// A database belongs to another application.
    #[error("database at {path} has application id {found:#x}, not Bitcoin Thunderbolt Ledger v2")]
    WrongApplication {
        /// Database path.
        path: PathBuf,
        /// Unexpected SQLite application ID.
        found: i64,
    },

    /// A non-empty database has no recognized schema.
    #[error("database at {0} is non-empty but has no recognized Ledger application schema")]
    UnrecognizedDatabase(PathBuf),

    /// A database schema is newer than this binary.
    #[error("database schema {found} is newer than supported schema {supported}")]
    UnsupportedSchema {
        /// Schema version found on disk.
        found: i64,
        /// Newest schema supported by this binary.
        supported: i64,
    },

    /// A recorded migration differs from the compiled migration.
    #[error("database migration {version} checksum does not match this binary")]
    MigrationChecksumMismatch {
        /// Migration version with an unexpected checksum.
        version: i64,
    },

    /// Durable configuration differs from requested configuration.
    #[error("database configuration does not match the requested chain or protocol limits")]
    ConfigurationMismatch,

    /// A block belongs to another configured Ledger chain.
    #[error("block Ledger chain id does not match the application")]
    LedgerChainMismatch,

    /// A block repeats an already committed height with different bytes.
    #[error("block height {height} conflicts with the committed block")]
    BlockConflict {
        /// Reused consensus height.
        height: u64,
    },

    /// A block is older than the application head.
    #[error("stale block height {found}; application head is {current}")]
    StaleHeight {
        /// Current durable application height.
        current: u64,
        /// Older proposed height.
        found: u64,
    },

    /// A block skipped one or more heights.
    #[error("block height gap: expected {expected}, found {found}")]
    HeightGap {
        /// Exact next height.
        expected: u64,
        /// Proposed non-contiguous height.
        found: u64,
    },

    /// A block does not extend the committed application hash.
    #[error("block previous application hash does not match the committed head")]
    AppHashMismatch,

    /// Consensus block time moved backwards.
    #[error("consensus block time regressed from {previous_ms} to {proposed_ms}")]
    BlockTimeRegression {
        /// Previous consensus time.
        previous_ms: u64,
        /// Regressing proposed consensus time.
        proposed_ms: u64,
    },

    /// One actor-scoped request digest was reused for different entry bytes.
    #[error("actor-scoped request digest conflicts with a durable entry mapping")]
    RequestConflict,

    /// A block mixes an exact replay and a new transition for one channel.
    #[error("one block cannot mix an exact replay with another proposal for the same channel")]
    MixedReplayChain,

    /// Stored data failed an invariant or typed validation check.
    #[error("stored Ledger application data is inconsistent: {0}")]
    CorruptData(String),

    /// A protocol integer does not fit SQLite's signed integer domain.
    #[error("{0} exceeds the SQLite integer range")]
    IntegerRange(&'static str),

    /// The database mutex was poisoned.
    #[error("Ledger application database lock was poisoned")]
    LockPoisoned,

    /// Rollback also failed after an application error.
    #[error("operation failed ({operation_error}); rollback also failed: {rollback_error}")]
    RollbackFailed {
        /// Original application failure.
        operation_error: String,
        /// SQLite rollback failure.
        rollback_error: rusqlite::Error,
    },
}

/// Result type returned by the Ledger application.
pub type Result<T> = std::result::Result<T, ApplicationError>;
