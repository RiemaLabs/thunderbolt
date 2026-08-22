use bitcoin::{BlockHash, Network, Txid};
use thiserror::Error;

/// Result type used by the Bitcoin backend.
pub type Result<T> = std::result::Result<T, BitcoinError>;

/// Errors returned by credential providers.
#[derive(Debug, Error)]
pub enum CredentialError {
    /// The credential source could not be read.
    #[error("credential source could not be read: {0}")]
    Io(#[from] std::io::Error),
    /// The configured credential source does not meet the local security policy.
    #[error("credential source is insecure: {0}")]
    Insecure(&'static str),
    /// The credential payload is not a valid Bitcoin Core username/password pair.
    #[error("credential source has an invalid format")]
    InvalidFormat,
    /// Secure cookie-file validation is unavailable on this platform.
    #[error("secure cookie-file authentication is unsupported on this platform")]
    UnsupportedPlatform,
    /// An external provider failed without exposing credential material.
    #[error("external credential provider failed")]
    External,
}

/// Errors at the HTTP transport boundary.
#[derive(Debug, Error)]
pub enum TransportError {
    /// A transient network failure that an idempotent read may retry.
    #[error("transient Bitcoin RPC transport failure: {0}")]
    Transient(String),
    /// A permanent transport failure.
    #[error("Bitcoin RPC transport failure: {0}")]
    Permanent(String),
    /// Credential acquisition failed.
    #[error(transparent)]
    Credential(#[from] CredentialError),
    /// The declared or observed response exceeded the configured limit.
    #[error("Bitcoin RPC response exceeds the configured {limit}-byte limit")]
    ResponseTooLarge { limit: usize },
}

impl TransportError {
    /// Returns whether an idempotent operation may retry this failure.
    #[must_use]
    pub const fn is_retryable(&self) -> bool {
        matches!(self, Self::Transient(_))
    }
}

/// Pure funding or closing-transaction validation failures.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ValidationError {
    /// The expected funding policy is unsafe or internally inconsistent.
    #[error("invalid funding expectation: {0}")]
    InvalidFundingExpectation(&'static str),
    /// The observed outpoint is not the one authorized by the protocol state.
    #[error("funding observation is for a different outpoint")]
    FundingOutpointMismatch,
    /// Bitcoin Core did not report an unspent output at the funding outpoint.
    #[error("funding outpoint is spent or missing")]
    FundingSpentOrMissing,
    /// The funding script is not the protocol-authorized script.
    #[error("funding script does not match")]
    FundingScriptMismatch,
    /// The funding amount is not the protocol-authorized amount.
    #[error("funding amount does not match")]
    FundingAmountMismatch,
    /// The funding output is not sufficiently confirmed.
    #[error("funding output has {actual} confirmations; {required} required")]
    FundingConfirmations { actual: u64, required: u64 },
    /// The closing policy itself is inconsistent.
    #[error("invalid closing policy: {0}")]
    InvalidClosingPolicy(&'static str),
    /// The closing transaction has extra inputs or omits the funding input.
    #[error("closing transaction must spend exactly the authorized funding outpoint once and no other inputs")]
    ClosingInputs,
    /// A closing output uses a script that is not on the allowlist.
    #[error("closing transaction contains an output script that is not allowed")]
    ClosingOutputScript,
    /// A closing output value is outside its authorized range.
    #[error("closing transaction contains an output amount that is not allowed")]
    ClosingOutputAmount,
    /// A closing output script occurs outside its authorized count range.
    #[error("closing transaction output count violates policy")]
    ClosingOutputCount,
    /// Output-value arithmetic overflowed.
    #[error("closing transaction output amount overflows")]
    ClosingAmountOverflow,
    /// Outputs exceed the known funding input amount.
    #[error("closing transaction outputs exceed the funding amount")]
    ClosingOutputsExceedFunding,
    /// The closing fee is outside the authorized inclusive range.
    #[error("closing transaction fee is outside the authorized range")]
    ClosingFee,
    /// The transaction identifier differs from the one authorized by protocol state.
    #[error("closing transaction txid does not match")]
    ClosingTxid,
}

/// Fail-closed Bitcoin backend failures.
#[derive(Debug, Error)]
pub enum BitcoinError {
    /// Mainnet is deliberately unavailable in this release candidate.
    #[error("Bitcoin mainnet is disabled in this release candidate")]
    MainnetDisabled,
    /// The selected rust-bitcoin network is not supported by this backend.
    #[error("unsupported Bitcoin network: {0}")]
    UnsupportedNetwork(Network),
    /// The RPC endpoint violates transport policy.
    #[error("invalid Bitcoin RPC endpoint: {0}")]
    InvalidEndpoint(&'static str),
    /// A configuration value is outside its hard safety bound.
    #[error("invalid Bitcoin RPC configuration: {0}")]
    InvalidConfig(&'static str),
    /// Credential acquisition or validation failed.
    #[error(transparent)]
    Credential(#[from] CredentialError),
    /// The serialized request is too large.
    #[error("Bitcoin RPC request is {actual} bytes; configured limit is {limit} bytes")]
    RequestTooLarge { actual: usize, limit: usize },
    /// The response is too large.
    #[error("Bitcoin RPC response is {actual} bytes; configured limit is {limit} bytes")]
    ResponseTooLarge { actual: usize, limit: usize },
    /// An RPC attempt exceeded its deadline.
    #[error("Bitcoin RPC request timed out")]
    Timeout,
    /// The transport failed.
    #[error(transparent)]
    Transport(#[from] TransportError),
    /// The HTTP response status was not accepted.
    #[error("Bitcoin RPC returned HTTP status {0}")]
    HttpStatus(u16),
    /// The response was not a valid, bounded JSON-RPC envelope.
    #[error("invalid Bitcoin RPC JSON response")]
    InvalidJson(#[source] serde_json::Error),
    /// The response envelope violates the JSON-RPC contract.
    #[error("malformed Bitcoin RPC response: {0}")]
    MalformedResponse(&'static str),
    /// The response ID was not exactly the request ID.
    #[error("Bitcoin RPC response id does not match the request id")]
    ResponseIdMismatch,
    /// Bitcoin Core returned an RPC error.
    #[error("Bitcoin Core RPC error {code}: {message}")]
    RemoteRpc { code: i64, message: String },
    /// The result payload had an unexpected type or encoding.
    #[error("invalid result from Bitcoin Core: {0}")]
    InvalidResult(&'static str),
    /// Bitcoin Core reports a different chain name.
    #[error("Bitcoin Core chain mismatch: expected {expected}, received {actual}")]
    NetworkMismatch { expected: &'static str, actual: String },
    /// The height-zero block differs from the selected network genesis.
    #[error("Bitcoin Core genesis mismatch: expected {expected}, received {actual}")]
    GenesisMismatch { expected: BlockHash, actual: BlockHash },
    /// A returned header did not hash to the requested block hash.
    #[error("Bitcoin Core returned a header for a different block")]
    BlockHashMismatch,
    /// A returned transaction did not hash to the requested txid.
    #[error("Bitcoin Core returned transaction {actual} for requested txid {expected}")]
    TransactionIdMismatch { expected: Txid, actual: Txid },
    /// Broadcast returned a txid other than the transaction that was submitted.
    #[error("Bitcoin Core broadcast response txid does not match the submitted transaction")]
    BroadcastTxidMismatch,
    /// The fee estimator did not produce a usable estimate.
    #[error("Bitcoin Core fee estimate is unavailable")]
    FeeEstimateUnavailable,
    /// A fee-rate argument is outside the supported bound.
    #[error("invalid fee rate")]
    InvalidFeeRate,
    /// The chain cursor contains no matching point within retained history.
    #[error("chain reorganization exceeds retained cursor history")]
    ReorgBeyondHistory,
    /// A chain update would exceed its configured work bound.
    #[error("chain cursor update exceeds the configured block bound")]
    ChainSyncLimit,
    /// Bitcoin's best chain changed while a cursor snapshot was being assembled.
    #[error("Bitcoin best chain changed during cursor synchronization")]
    ConcurrentChainChange,
    /// The supplied cursor or chain segment is structurally invalid.
    #[error("invalid chain cursor: {0}")]
    InvalidChainCursor(&'static str),
    /// A pure settlement validator rejected the observation or transaction.
    #[error(transparent)]
    Validation(#[from] ValidationError),
}
