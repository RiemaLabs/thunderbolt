//! Authenticated streaming CometBFT RPC transport.
//!
//! This crate supplies a concrete [`thunderbolt_cometbft_client::TraceTransport`]
//! and matching peer authenticator. HTTPS uses rustls with both an explicit CA
//! set and an exact leaf-SPKI SHA-256 pin. The only plaintext profile is an
//! explicit literal loopback address for regtest.
//!
//! Fixed Ledger operations reuse that authenticated session: one-attempt
//! `broadcast_tx_sync` for typed signed proposals and bounded idempotent
//! `abci_query` for committed Thunderbolt paths. Admission and application
//! bytes remain distinct from execution finality.

#![deny(missing_docs)]
#![deny(
    clippy::expect_used,
    clippy::panic,
    clippy::todo,
    clippy::unimplemented,
    clippy::unwrap_used
)]
#![forbid(unsafe_code)]

mod config;
mod credentials;
mod error;
mod ledger;
mod rpc;
mod tls;
mod transport;

#[cfg(any(test, feature = "regtest"))]
pub use config::LoopbackHttpPeer;
pub use config::{
    HttpsPeer, LedgerRpcLimits, RetryPolicy, RpcLimits, RpcPeer, RpcTransportConfig, MAX_LEDGER_RPC_AGGREGATE_BYTES,
    MAX_LEDGER_RPC_RESPONSE_BYTES, MAX_LEDGER_STATUS_RESPONSE_BYTES, MAX_RPC_ADJACENT_HEADERS,
};
pub use credentials::{ClientIdentityProvider, OwnerOnlyPemClientIdentity};
pub use error::{Result, RpcTransportError};
pub use ledger::{
    AuthenticatedAbciQueryV2, AuthenticatedBroadcastTxSyncV2, BroadcastAdmissionV2, LedgerAbciQueryV2,
    LedgerRpcSessionEvidence,
};
pub use transport::{CometBftRpcTransport, RpcPeerAuthenticator, RpcSessionEvidence};

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
mod tests;
