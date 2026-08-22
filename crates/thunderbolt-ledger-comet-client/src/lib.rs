//! Crash-safe finalized Thunderbolt Ledger client over authenticated CometBFT.
//!
//! This crate owns a durable light-client [`TrustCoordinator`] and a separate
//! fixed-method RPC transport. It finalizes complete globally contiguous
//! executed blocks, including empty blocks, before issuing private in-process
//! entry capabilities. Serializable historical references contain no receipt
//! authority and must be revalidated against the coordinator database on every
//! use.

#![deny(missing_docs)]
#![deny(
    clippy::expect_used,
    clippy::panic,
    clippy::todo,
    clippy::unimplemented,
    clippy::unwrap_used
)]
#![forbid(unsafe_code)]

mod client;
mod error;
mod types;

pub use client::LedgerCometClient;
pub use error::{ClientError, Result};
pub use types::{
    ClientProfileIdV2, FinalityAdvanceIntentV2, FinalizedAbsenceCapabilityV2, FinalizedBlockCapabilityV2,
    FinalizedExecutionSummaryV2, FinalizedFirstLocationV2, FinalizedRangeV2, HistoricalEntryReferenceV2,
    HolderFinalityCapabilityV2, LedgerCometClientConfig, LedgerCometClientLimits, LedgerCoordinatorPolicyV2,
    PreparedExecutionRangeV2, ReconciledSubmissionV2, MAX_FINALITY_ADVANCE_INTENT_BYTES,
    MAX_HISTORICAL_REFERENCE_BYTES, MAX_LOCATOR_SCAN_BLOCKS, MAX_LOCATOR_SCAN_BYTES,
};

pub use thunderbolt_cometbft_client::TrustCoordinator;

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
mod tests;
