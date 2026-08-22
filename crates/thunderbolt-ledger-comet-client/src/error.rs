use thiserror::Error;

/// Fail-closed finalized Ledger client error.
#[derive(Debug, Error)]
pub enum ClientError {
    /// Static coordinator, transport, profile, or bound configuration is invalid.
    #[error("invalid finalized Ledger client configuration: {0}")]
    InvalidConfiguration(&'static str),
    /// A query, reference, execution, or proof differs from its exact binding.
    #[error("finalized Ledger evidence binding mismatch")]
    BindingMismatch,
    /// Required locally finalized historical evidence is unavailable.
    #[error("required finalized Ledger history is unavailable")]
    HistoryUnavailable,
    /// A bounded range, locator scan, or canonical reference exceeded policy.
    #[error("finalized Ledger client capacity reached")]
    Capacity,
    /// Coordinator ownership was lost after cancellation or a blocking-worker failure.
    #[error("finalized Ledger client is poisoned; drop and reopen")]
    Poisoned,
    /// The crash-safe CometBFT trust coordinator rejected the operation.
    #[error(transparent)]
    Coordinator(#[from] thunderbolt_cometbft_client::CoordinatorError),
    /// The authenticated fixed-method RPC boundary rejected the operation.
    #[error(transparent)]
    Rpc(#[from] thunderbolt_cometbft_rpc::RpcTransportError),
    /// Canonical public data could not be encoded or decoded.
    #[error("invalid canonical finalized Ledger data")]
    Codec,
}

/// Result type used by the finalized Ledger client.
pub type Result<T> = std::result::Result<T, ClientError>;
