//! Durable Holder role service for Bitcoin Thunderbolt.
//!
//! The service owns no network listener. It provides a synchronous long-running
//! library and local-control request types that a daemon can place behind
//! owner-only local IPC. Signed v2 Ledger submission and trusted finality are
//! supplied through traits.
#![forbid(unsafe_code)]
#![deny(
    clippy::expect_used,
    clippy::panic,
    clippy::todo,
    clippy::unimplemented,
    clippy::unwrap_used
)]

mod capabilities;
mod config;
mod control;
mod error;
mod ledger;
mod service;
mod store;
mod types;

pub use capabilities::{
    BitcoinSettlement, CapabilityError, SettlementArtifacts, SettlementIntent, ThresholdAction, ThresholdArtifacts,
    ThresholdSigner, UnavailableBitcoinSettlement, UnavailableThresholdSigner,
};
pub use config::{
    HolderDeploymentPolicy, HolderNodeConfig, RetryPolicy, MAX_COMMAND_ROWS, MAX_FINALITY_BATCH, MAX_OUTBOX_ROWS,
    MAX_PROPOSAL_BYTES,
};
pub use control::{LocalControlRequest, LocalControlResponse};
pub use error::{HolderNodeError, Result};
pub use ledger::{
    ActorSigner, FinalityVerifier, SignedV2LedgerClient, SubmissionStatus, TrustedLedgerReceipt, UnavailableActorSigner,
};
pub use service::HolderRoleService;
pub use types::{
    CommandId, FinalizedCursor, LifecycleState, OutboxStatus, QueueDisposition, QueueProposalRequest, QueuedProposal,
    RunReport, ServiceStatus,
};

#[cfg(test)]
mod tests;
