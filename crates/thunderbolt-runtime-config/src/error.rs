use thiserror::Error;

/// Fail-closed configuration errors.
#[derive(Debug, Error)]
pub enum ConfigError {
    /// Input exceeded the parser allocation bound.
    #[error("runtime configuration exceeds the 256 KiB input bound")]
    InputTooLarge,
    /// TOML syntax, shape, or field names were invalid.
    #[error("runtime configuration TOML is malformed or contains unknown fields")]
    InvalidToml,
    /// The document version is not supported.
    #[error("runtime configuration version is unsupported")]
    UnsupportedVersion,
    /// A stable semantic invariant was violated.
    #[error("runtime configuration is invalid: {0}")]
    Invalid(&'static str),
    /// A key attempted to carry secret material directly.
    #[error("runtime configuration contains a forbidden secret-bearing field")]
    SecretValueForbidden,
    /// A path was relative, ambiguous, shared, or insecure.
    #[error("runtime path is unsafe: {0}")]
    UnsafePath(&'static str),
    /// A pinned owner-only external file was missing or changed.
    #[error("owner-only file reference is unavailable or has changed")]
    ReferenceMismatch,
    /// Role documents disagreed on deployment identity or resources.
    #[error("runtime configuration does not match another role in the deployment")]
    DeploymentMismatch,
    /// A committed downstream policy constructor rejected the mapping.
    #[error("a committed runtime policy rejected the mapped configuration")]
    PolicyRejected,
    /// Bounded owner-only file reading failed.
    #[error("owner-only configuration I/O failed")]
    Io(#[from] std::io::Error),
    /// The platform lacks the required Unix ownership primitives.
    #[error("owner-only filesystem validation is unsupported on this platform")]
    UnsupportedPlatform,
}

/// Result returned by runtime configuration operations.
pub type Result<T> = std::result::Result<T, ConfigError>;
