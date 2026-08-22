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

    /// The requested record is not valid for this participant role.
    #[error("secret record is not valid for this participant role")]
    InvalidRecordForRole,

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
