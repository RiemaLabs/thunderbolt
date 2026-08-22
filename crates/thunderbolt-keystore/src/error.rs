use std::io;

/// Errors returned by the encrypted vault.
///
/// Variants never contain passwords, keys, decrypted records, or ciphertext.
#[derive(Debug, thiserror::Error)]
pub enum KeystoreError {
    /// The supplied password is invalid.
    #[error("password does not satisfy the keystore policy")]
    InvalidPassword,

    /// A KDF configuration or an encoded KDF header is outside supported bounds.
    #[error("Argon2id parameters are outside the supported bounds")]
    InvalidKdfParameters,

    /// A typed record is empty, too large, or has an invalid fixed length.
    #[error("secret record does not satisfy its type constraints")]
    InvalidSecretRecord,

    /// A record key is empty or exceeds its canonical bound.
    #[error("record key does not satisfy the keystore policy")]
    InvalidRecordKey,

    /// The requested record is not valid for this participant role.
    #[error("secret record is not valid for this participant role")]
    InvalidRecordForRole,

    /// The deployment or committee identity is invalid.
    #[error("vault deployment identity is invalid")]
    InvalidVaultIdentity,

    /// The complete vault revision changed before a compare-and-swap commit.
    #[error("vault revision does not match the expected revision")]
    RevisionConflict,

    /// A record did not match the expected absent or versioned state.
    #[error("record version does not match the compare-and-swap request")]
    RecordConflict,

    /// The same record key was staged more than once in one transaction.
    #[error("transaction contains a duplicate record mutation")]
    DuplicateMutation,

    /// The encrypted record count or total secret bytes exceed supported bounds.
    #[error("vault record limits would be exceeded")]
    RecordLimitExceeded,

    /// One transaction contains too many record mutations.
    #[error("vault transaction contains too many mutations")]
    TransactionLimitExceeded,

    /// The bounded idempotency-receipt collection is full.
    #[error("vault transaction receipt limit is reached")]
    TransactionReceiptLimitExceeded,

    /// A receipt-pruning boundary is newer than the authenticated vault state.
    #[error("transaction receipt pruning boundary exceeds the vault revision")]
    InvalidPruneRevision,

    /// An idempotency key was reused for different mutations.
    #[error("transaction identifier was reused for a different update")]
    TransactionReplayConflict,

    /// The authenticated revision counter cannot be incremented.
    #[error("vault revision is exhausted")]
    RevisionExhausted,

    /// A consumed signing nonce cannot be inserted again.
    #[error("committee signing nonce was already consumed")]
    NonceConsumed,

    /// A reserved signing nonce is immutable until it is tombstoned.
    #[error("committee signing nonce is already reserved")]
    NonceAlreadyReserved,

    /// Generic restore cannot safely recover committee signing state.
    #[error("committee signing-state restore requires external monotonic reconciliation")]
    SigningStateRestoreForbidden,

    /// Committee state cannot be opened without an externally anchored floor.
    #[error("committee vault requires an externally authenticated minimum revision")]
    RollbackFloorRequired,

    /// The authenticated vault revision is older than the trusted external floor.
    #[error("vault rollback detected below the trusted minimum revision")]
    RollbackDetected,

    /// A write failed ambiguously and the handle must be dropped and reopened.
    #[error("vault handle is poisoned; drop it and reopen the vault")]
    Poisoned,

    /// The file does not use a supported, canonical keystore encoding.
    #[error("keystore format is invalid or unsupported")]
    InvalidFormat,

    /// The expected network, participant role, or node identity does not match.
    #[error("keystore identity does not match the expected participant")]
    IdentityMismatch,

    /// Authentication failed. This covers a wrong password or modified ciphertext.
    #[error("keystore authentication failed")]
    AuthenticationFailed,

    /// The cryptographic operation could not be completed.
    #[error("keystore cryptographic operation failed")]
    CryptographicFailure,

    /// The operating system could not provide cryptographic randomness.
    #[error("operating system randomness is unavailable")]
    RandomnessUnavailable,

    /// A no-clobber destination already exists.
    #[error("keystore destination already exists")]
    AlreadyExists,

    /// Another process holds the advisory lock for this vault.
    #[error("keystore is already open by another process")]
    Locked,

    /// The path is a symlink, a non-regular file, or has unsafe permissions.
    #[error("keystore path is not an owner-only regular file")]
    UnsafeFile,

    /// The live vault was replaced outside the process holding its lock.
    #[error("keystore file changed outside the locked process")]
    FileReplaced,

    /// A filesystem operation failed.
    #[error("keystore filesystem operation failed")]
    Io(#[source] io::Error),
}

impl From<io::Error> for KeystoreError {
    fn from(source: io::Error) -> Self {
        Self::Io(source)
    }
}

/// Result type used throughout the keystore crate.
pub type Result<T> = std::result::Result<T, KeystoreError>;
