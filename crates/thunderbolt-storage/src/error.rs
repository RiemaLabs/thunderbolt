use std::path::PathBuf;

use thiserror::Error;

/// Details of a channel-scoped idempotency-key conflict.
#[derive(Debug)]
pub struct VerifiedRequestConflict {
    pub channel_id: String,
    pub idempotency_key: String,
    pub existing_actor_id: String,
    pub proposed_actor_id: String,
    pub existing_digest: String,
    pub proposed_digest: String,
}

impl std::fmt::Display for VerifiedRequestConflict {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "verified request key conflict for channel {}, idempotency key {}: \
             existing actor {} and proposal {}, proposed actor {} and proposal {}",
            self.channel_id,
            self.idempotency_key,
            self.existing_actor_id,
            self.existing_digest,
            self.proposed_actor_id,
            self.proposed_digest,
        )
    }
}

/// Failure returned by transaction-scoped proposal verification and append.
///
/// Verification failures preserve the caller's error type. Storage failures
/// cover proposal validation, database access, reduction, commit, and rollback.
#[derive(Debug)]
pub enum VerifiedAppendError<E> {
    /// The storage layer rejected or failed the operation.
    Storage(StorageError),
    /// The caller-supplied trusted verifier rejected the proposal.
    Verification(E),
}

impl<E> From<StorageError> for VerifiedAppendError<E> {
    fn from(error: StorageError) -> Self {
        Self::Storage(error)
    }
}

impl<E: std::fmt::Display> std::fmt::Display for VerifiedAppendError<E> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Storage(error) => error.fmt(formatter),
            Self::Verification(error) => write!(formatter, "proposal verification failed: {error}"),
        }
    }
}

impl<E> std::error::Error for VerifiedAppendError<E>
where
    E: std::error::Error + 'static,
{
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Storage(error) => Some(error),
            Self::Verification(error) => Some(error),
        }
    }
}

/// Errors returned by the durable storage layer.
#[derive(Debug, Error)]
pub enum StorageError {
    #[error("protocol validation failed: {0}")]
    Protocol(#[from] thunderbolt_protocol::ProtocolError),

    #[error("database error: {0}")]
    Database(#[from] rusqlite::Error),

    #[error("failed to serialize or deserialize protocol state: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("{operation} failed for {path}: {source}")]
    Io {
        operation: &'static str,
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("database at {path} belongs to another application (application id {found:#x})")]
    WrongApplication { path: PathBuf, found: i64 },

    #[error("database at {0} is non-empty but has no recognized Thunderbolt schema")]
    UnrecognizedDatabase(PathBuf),

    #[error("database schema version {found} is newer than supported version {supported}")]
    UnsupportedSchema { found: i64, supported: i64 },

    #[error("database has invalid negative schema version {found}")]
    InvalidSchemaVersion { found: i64 },

    #[error("database migration {version} checksum does not match this binary")]
    MigrationChecksumMismatch { version: i64 },

    #[error(
        "database protocol limits are entries={stored_entries}, verifications={stored_verifications}; \
         requested entries={requested_entries}, verifications={requested_verifications}"
    )]
    ProtocolLimitsMismatch {
        stored_entries: u64,
        stored_verifications: usize,
        requested_entries: u64,
        requested_verifications: usize,
    },

    #[error("invalid storage input: {0}")]
    InvalidInput(String),

    #[error("client-supplied verification evidence is forbidden for verified append")]
    ClientVerificationEvidence,

    #[error("trusted verifier returned {found} evidence records, exceeding the configured limit {limit}")]
    VerifierEvidenceLimitExceeded { limit: usize, found: usize },

    #[error("proposal digest is already committed to inconsistent stored data: {0}")]
    InvalidVerifiedReplay(String),

    #[error("{0}")]
    VerifiedRequestConflict(Box<VerifiedRequestConflict>),

    #[error("proposal references invoice {invoice_id}, but it is not the immutable pending invoice head")]
    PendingInvoiceReference { invoice_id: String },

    #[error("verified proposal was previously committed without an atomic request mapping")]
    MissingVerifiedRequestMapping,

    #[error("one serialized {kind} is {bytes} bytes, exceeding the {limit}-byte page budget")]
    PageItemTooLarge {
        kind: &'static str,
        bytes: usize,
        limit: usize,
    },

    #[error("requested {kind} page exceeds the {limit}-byte serialized page budget")]
    PageByteBudgetExceeded { kind: &'static str, limit: usize },

    #[error("channel {channel_id} is at sequence {actual}, not expected sequence {expected}")]
    SequenceConflict {
        channel_id: String,
        expected: u64,
        actual: u64,
    },

    #[error("stored protocol data is inconsistent: {0}")]
    CorruptData(String),

    #[error("database integrity check failed: {0:?}")]
    IntegrityCheckFailed(Vec<String>),

    #[error("backup destination already exists: {0}")]
    BackupDestinationExists(PathBuf),

    #[error("backup was published at {path}, but its directory entry could not be flushed: {source}")]
    BackupPublishedButDirectorySyncFailed {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("database lock was poisoned")]
    LockPoisoned,

    #[error("operation failed ({operation_error}); rollback also failed: {rollback_error}")]
    RollbackFailed {
        operation_error: String,
        rollback_error: rusqlite::Error,
    },

    #[error("system clock is before the Unix epoch")]
    InvalidSystemClock,
}

/// Result type returned by storage operations.
pub type Result<T> = std::result::Result<T, StorageError>;
