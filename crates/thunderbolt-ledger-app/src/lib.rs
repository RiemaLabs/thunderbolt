//! Crash-safe SQLite application for the Bitcoin Thunderbolt v2 Ledger.
//!
//! The application accepts consensus-ordered, BIP340-authenticated proposals,
//! invokes deterministic external proof hooks, runs the v2 reducer, and
//! commits the whole executed block atomically. It deliberately carries no
//! consensus-finality capability.

#![deny(missing_docs)]
#![deny(
    clippy::expect_used,
    clippy::panic,
    clippy::todo,
    clippy::unimplemented,
    clippy::unwrap_used
)]
#![forbid(unsafe_code)]

mod error;
mod migrations;
mod store;

pub use error::{ApplicationError, Result};
pub use migrations::CURRENT_SCHEMA_VERSION;
pub use store::{
    ApplicationOptions, ApplicationStatusV2, BlockExecutionOutcomeV2, BlockInputV2, IntegrityReportV2,
    LedgerApplication, LedgerApplicationVerifierV2, PreparedBlockV2, StoredRequestV2,
};

/// Application version reported by a future CometBFT ABCI `Info`/`InitChain`
/// integration and pinned by finality verification.
pub const APPLICATION_VERSION_V2: u64 = 2;
