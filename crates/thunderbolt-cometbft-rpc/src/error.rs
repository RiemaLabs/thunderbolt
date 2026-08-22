use thiserror::Error;

/// Fail-closed authenticated RPC transport errors.
#[derive(Debug, Error)]
pub enum RpcTransportError {
    /// Static peer or resource configuration is invalid.
    #[error("invalid CometBFT RPC configuration: {0}")]
    InvalidConfiguration(&'static str),
    /// The coordinator requested an identity absent from the immutable roster.
    #[error("unknown CometBFT RPC peer")]
    UnknownPeer,
    /// The shared monotonic request deadline elapsed.
    #[error("CometBFT RPC deadline elapsed")]
    Deadline,
    /// Direct TCP or HTTP/1 connection establishment failed.
    #[error("CometBFT RPC connection failed")]
    Connect,
    /// The TLS handshake or authenticated stream failed.
    #[error("CometBFT RPC TLS authentication failed")]
    Tls,
    /// The certificate chain, DNS name, validity, or client identity failed.
    #[error("CometBFT RPC certificate validation failed")]
    Certificate,
    /// The authenticated leaf certificate did not match the exact SPKI pin.
    #[error("CometBFT RPC SPKI pin mismatch")]
    SpkiMismatch,
    /// A private credential path or provider failed closed.
    #[error("CometBFT client credential unavailable")]
    Credential,
    /// A credential path violated owner/type/no-follow requirements.
    #[error("unsafe CometBFT credential path")]
    UnsafePath,
    /// HTTP response status was not an accepted JSON-RPC success.
    #[error("unexpected CometBFT RPC HTTP status {0}")]
    HttpStatus(u16),
    /// HTTP content type was missing or was not JSON.
    #[error("invalid CometBFT RPC content type")]
    ContentType,
    /// One response body exceeded its pre-decode cap.
    #[error("CometBFT RPC response body exceeds its bound")]
    ResponseTooLarge,
    /// The aggregate raw RPC response budget was exhausted.
    #[error("CometBFT RPC aggregate response budget exhausted")]
    AggregateTooLarge,
    /// JSON or JSON-RPC framing was malformed, conflicting, or truncated.
    #[error("invalid CometBFT JSON-RPC response")]
    Json,
    /// A post-send transaction outcome could not be determined safely.
    #[error("CometBFT transaction write outcome is ambiguous")]
    AmbiguousWrite {
        /// Deterministic SHA-256 transaction hash used for reconciliation.
        tx_hash: [u8; 32],
    },
    /// The ABCI application rejected an exact read-only query.
    #[error("Thunderbolt ABCI query rejected with code {code}")]
    AbciQueryRejected {
        /// Stable application response code; provider log strings are discarded.
        code: u32,
    },
    /// ABCI response bytes did not match the fixed requested query contract.
    #[error("Thunderbolt ABCI query response differs from the exact request")]
    ApplicationResponse,
    /// Status returned another authenticated node identity.
    #[error("CometBFT status node id differs")]
    NodeIdentity,
    /// Status or a signed header returned another chain id.
    #[error("CometBFT chain id differs")]
    ChainIdentity,
    /// A response height differed from the exact requested adjacent height.
    #[error("CometBFT RPC height differs")]
    Height,
    /// Validator pagination was incomplete, duplicated, unstable, or excessive.
    #[error("invalid CometBFT validator pagination")]
    Pagination,
    /// Validator contents did not match the signed header commitments.
    #[error("CometBFT validator set differs from signed header")]
    ValidatorSet,
    /// The fetched trace shape or encoded output exceeded its bound.
    #[error("CometBFT trace exceeds its configured bound")]
    TraceBound,
    /// Every permitted idempotent-read attempt failed transiently.
    #[error("CometBFT RPC idempotent retry budget exhausted")]
    RetryExhausted,
}

/// Result type used by the authenticated RPC transport.
pub type Result<T> = std::result::Result<T, RpcTransportError>;
