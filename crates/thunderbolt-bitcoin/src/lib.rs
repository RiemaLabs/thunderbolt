//! Fail-closed access to Bitcoin Core for Bitcoin Thunderbolt.
//!
//! The backend deliberately has no wallet, private-key, or signing API. It
//! validates the configured network before becoming usable and checks
//! consensus identifiers returned by the remote node.

#![forbid(unsafe_code)]

mod auth;
mod chain;
mod config;
mod error;
mod rpc;
mod types;
mod validation;

pub use auth::{CookieCredentialProvider, CredentialProvider, CredentialProviderFuture, RpcCredentials};
pub use chain::{ChainCursor, ChainDelta, ChainPoint};
pub use config::{
    RpcConfig, DEFAULT_CONNECT_TIMEOUT, DEFAULT_MAX_CHAIN_SYNC_BLOCKS, DEFAULT_MAX_REQUEST_BYTES,
    DEFAULT_MAX_RESPONSE_BYTES, DEFAULT_READ_ATTEMPTS, DEFAULT_REQUEST_TIMEOUT, HARD_MAX_BODY_BYTES,
    HARD_MAX_CHAIN_SYNC_BLOCKS,
};
pub use error::{BitcoinError, CredentialError, Result, TransportError, ValidationError};
pub use rpc::{
    BackendFuture, BitcoinCoreClient, BitcoinRpcBackend, HttpTransport, RpcHttpRequest, RpcHttpResponse, RpcTransport,
    TransportFuture,
};
pub use types::{BlockchainInfo, FeeEstimate, TxOutInfo, MAX_FEE_RATE_SAT_PER_KVB};
pub use validation::{
    validate_closing_transaction, validate_funding_outpoint, AllowedOutput, ClosingPolicy, ClosingValidation,
    FundingExpectation, FundingObservation, FundingState,
};

pub use bitcoin;
