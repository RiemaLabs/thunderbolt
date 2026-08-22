//! Crash-safe CometBFT light-client trust coordination.
//!
//! This crate composes independently authenticated trace acquisition with
//! [`thunderbolt_cometbft`] verification and one durable SQLite trust-state
//! transition plus an independent exact checkpoint CAS. It intentionally
//! contains no network transport, permissive source authenticator, or local
//! rollback checkpoint implementation.

#![deny(missing_docs)]
#![deny(
    clippy::expect_used,
    clippy::panic,
    clippy::todo,
    clippy::unimplemented,
    clippy::unwrap_used
)]
#![forbid(unsafe_code)]

mod coordinator;
mod storage;
mod types;

pub use coordinator::TrustCoordinator;
pub use types::{
    AdvanceOutcome, AuthenticationContext, CheckpointFuture, CoordinatorConfig, CoordinatorError, CoordinatorLimits,
    CurrentTrustRoot, FetchedTrace, FinalityProofBundle, FinalitySummary, HistoricalFinality,
    HistoricalRequestFinality, HistoryEpochLimits, HistorySealIntent, HistorySealOutcome, PeerIdentity,
    RotationOutcome, SourceConfiguration, SourceRole, TraceFetchRequest, TraceFuture, TracePeerAuthenticator,
    TraceTransport, TrustCheckpoint, TrustCheckpointCasOutcome, TrustCheckpointStore, TrustCoordinatorIdentity,
    MAX_EXECUTION_ENCODED_BYTES, MAX_HISTORY_EPOCH_PROOF_BYTES, MAX_HISTORY_EPOCH_REQUESTS,
    MAX_HISTORY_EPOCH_TRANSITIONS, MAX_PROOF_BUNDLE_BYTES, MAX_TRACE_ENCODED_BYTES,
};

/// Result type used by the trust coordinator.
pub type Result<T> = std::result::Result<T, CoordinatorError>;

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
mod tests;
