use std::io;
use std::path::PathBuf;

use thiserror::Error;

use crate::RequestId;

/// Result alias for the local control plane.
pub type Result<T> = std::result::Result<T, ControlError>;

/// Fail-closed local-control errors.
#[derive(Debug, Error)]
pub enum ControlError {
    /// A configured safety bound is invalid.
    #[error("invalid local-control configuration: {0}")]
    InvalidConfiguration(&'static str),
    /// A request or response violates the stable frame contract.
    #[error("invalid local-control frame: {0}")]
    InvalidFrame(&'static str),
    /// The socket path or its parent is not safely owner-controlled.
    #[error("unsafe local-control path {path}: {reason}")]
    UnsafePath {
        /// Rejected filesystem path.
        path: PathBuf,
        /// Stable non-secret rejection reason.
        reason: &'static str,
    },
    /// An active daemon already owns the requested socket path.
    #[error("local-control socket is already active: {0}")]
    SocketInUse(PathBuf),
    /// The kernel-reported peer UID differs from the daemon UID.
    #[error("local-control peer UID is not authorized")]
    UnauthorizedPeer,
    /// A bounded I/O operation exceeded its deadline.
    #[error("local-control I/O deadline exceeded")]
    Timeout,
    /// The server has reached its configured concurrency bound.
    #[error("local-control server is busy")]
    Busy,
    /// A response does not correspond to the submitted request.
    #[error("local-control response request id differs")]
    ResponseMismatch,
    /// The request may have reached a mutating handler; retry the same ID.
    #[error("local-control result is ambiguous; retry request {0:?}")]
    Ambiguous(RequestId),
    /// Operating-system I/O failed at a specific path or connection stage.
    #[error("local-control I/O failed during {operation}: {source}")]
    Io {
        /// Bounded operation that failed.
        operation: &'static str,
        /// Operating-system error.
        #[source]
        source: io::Error,
    },
    /// The OS random source could not create a request id.
    #[error("operating-system randomness is unavailable")]
    Random,
    /// A blocking handler task terminated unexpectedly.
    #[error("local-control handler terminated unexpectedly")]
    Handler,
}

impl ControlError {
    pub(crate) fn io(operation: &'static str, source: io::Error) -> Self {
        Self::Io { operation, source }
    }
}
