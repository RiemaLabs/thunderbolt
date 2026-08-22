use thiserror::Error;

/// Committee role service failure. Variants never contain secret material.
#[derive(Debug, Error)]
pub enum NodeError {
    #[error("invalid committee node configuration: {0}")]
    InvalidConfiguration(&'static str),
    #[error("committee node identity does not match the durable database")]
    IdentityMismatch,
    #[error("signed-v2 Ledger artifact is invalid")]
    InvalidLedgerArtifact,
    #[error("external Ledger finality verification failed")]
    FinalityRejected,
    #[error("finalized cursor conflicts with previously accepted history")]
    CursorConflict,
    #[error("duplicate request digest is bound to different finalized bytes")]
    ReplayConflict,
    #[error("committee inbox or outbox reached its configured bound")]
    QueueFull,
    #[error("committee refresh package is incomplete or cross-bound incorrectly")]
    RefreshBindingMismatch,
    #[error("committee private runtime failed: {0}")]
    Runtime(String),
    #[error("committee proposal signing is unavailable")]
    SigningUnavailable,
    #[error("consensus finality integration is unavailable")]
    FinalityUnavailable,
    #[error("SQLite persistence failed: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("bounded JSON codec failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error("numeric value exceeds SQLite range")]
    NumericRange,
    #[error("stored committee node state is corrupt")]
    CorruptState,
    #[error("schema-v1 database has pending records requiring offline verified migration")]
    LegacyPendingRecords,
    #[error("injected crash after private commit")]
    InjectedCrash,
}

pub type Result<T> = std::result::Result<T, NodeError>;
