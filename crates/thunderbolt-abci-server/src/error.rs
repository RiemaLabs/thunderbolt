use std::io;
use std::path::PathBuf;

/// Bounded frame or connection protocol failure.
#[derive(Debug, thiserror::Error)]
pub enum FrameError {
    /// Peer remained idle before sending a new frame.
    #[error("ABCI connection idle deadline expired")]
    IdleTimeout,
    /// Length prefix was incomplete or too slow.
    #[error("ABCI frame header deadline expired")]
    HeaderTimeout,
    /// Length prefix exceeded the canonical u64 varint width.
    #[error("ABCI frame length prefix is invalid")]
    InvalidLengthPrefix,
    /// Length prefix used a nonminimal encoding.
    #[error("ABCI frame length prefix is noncanonical")]
    NonCanonicalLength,
    /// Zero-length requests are not valid ABCI protobuf messages.
    #[error("ABCI frame length is zero")]
    ZeroLength,
    /// Declared payload exceeds the configured preallocation cap.
    #[error("ABCI frame exceeds the preallocation cap")]
    FrameTooLarge,
    /// Payload ended before the declared length.
    #[error("ABCI frame is truncated")]
    TruncatedFrame,
    /// Payload did not complete within the absolute frame deadline.
    #[error("ABCI frame payload deadline expired")]
    FrameTimeout,
    /// Response did not complete within the write deadline.
    #[error("ABCI response write deadline expired")]
    WriteTimeout,
    /// Global in-flight reservation was unavailable before the frame deadline.
    #[error("ABCI global in-flight byte budget is exhausted")]
    InflightBudget,
    /// Bounded frame allocation failed.
    #[error("ABCI bounded frame allocation failed")]
    Allocation,
    /// Internal connection or byte reservation accounting was poisoned.
    #[error("ABCI reservation accounting invariant failed")]
    AccountingInvariant,
    /// Server shutdown cancelled the current operation.
    #[error("ABCI operation cancelled by shutdown")]
    Shutdown,
    /// Socket I/O failed.
    #[error("ABCI socket I/O failed")]
    Io(#[source] io::Error),
}

/// Server construction, lifecycle, or cleanup failure.
#[derive(Debug, thiserror::Error)]
pub enum ServerError {
    /// Configuration is zero, inconsistent, remote, or otherwise unsafe.
    #[error("invalid bounded ABCI server configuration: {0}")]
    InvalidConfig(&'static str),
    /// Listener bind or socket operation failed.
    #[error("bounded ABCI server socket operation failed")]
    Io(#[from] io::Error),
    /// Unix socket path is unsafe or cannot be cleaned exactly.
    #[error("unsafe ABCI Unix socket path {path:?}: {reason}")]
    UnixSocket {
        /// Rejected path.
        path: PathBuf,
        /// Stable rejection reason.
        reason: &'static str,
    },
    /// Startup cleanup ownership was poisoned before a server thread could start.
    #[error("bounded ABCI server startup ownership was poisoned")]
    WorkerPanicked,
}

/// Result returned by checked server construction/lifecycle methods.
pub type Result<T> = std::result::Result<T, ServerError>;
