use std::io;

use thiserror::Error;
use thunderbolt_config::AuthError;
use thunderbolt_storage::StorageError;

/// Errors raised while constructing or serving a node.
#[derive(Debug, Error)]
pub enum NodeError {
    #[error("unsafe or unsupported node configuration: {0}")]
    Configuration(String),

    #[error("failed to load bearer-token credentials: {0}")]
    Authentication(#[from] AuthError),

    #[error("failed to open or validate node storage: {0}")]
    Storage(#[from] StorageError),

    #[error("node I/O failed: {0}")]
    Io(#[from] io::Error),

    #[error("bounded database worker failed: {0}")]
    DatabaseWorker(String),

    #[error("the server did not finish within the configured graceful-shutdown timeout")]
    GracefulShutdownTimeout,
}
