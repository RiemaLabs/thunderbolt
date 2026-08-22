//! Durable Holder role service for Bitcoin Thunderbolt.
//!
//! The service owns no network listener. It provides an asynchronous long-running
//! library and local-control request types that a daemon can place behind
//! owner-only local IPC. Signed-v2 submission and finality are supplied through
//! runtime-neutral asynchronous traits. Finality follows a durable
//! prepare-stage-finalize handoff so coordinator mutation can be recovered
//! without advancing role state ambiguously.
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
    HolderDeploymentPolicy, HolderNodeConfig, RetryPolicy, MAX_COMMAND_ROWS, MAX_FINALITY_ATTESTATION_BYTES,
    MAX_FINALITY_BATCH, MAX_FINALITY_SEGMENT_BYTES, MAX_OUTBOX_ROWS, MAX_PROPOSAL_BYTES,
};
pub use control::{LocalControlRequest, LocalControlResponse};
pub use error::{HolderNodeError, Result};
pub use ledger::{
    ActorSigner, FinalityVerifier, LedgerFuture, SignedV2LedgerClient, SubmissionStatus, UnavailableActorSigner,
    UnavailableFinalityVerifier, UnavailableSignedV2LedgerClient,
};
pub use service::{inspect_staged_finality_recovery, HolderRoleService};
pub use types::{
    CommandId, DurableBlockFinalityCapabilityV2, FinalityCoordinatorId, FinalityDigestV2, FinalityRangeIntentV2,
    FinalityVerifierProfileId, FinalizedBlockCursor, FinalizedRangeCapabilityV2, LifecycleState, OutboxStatus,
    QueueDisposition, QueueProposalRequest, QueuedProposal, RunReport, ServiceStatus, StagedFinalityRangeCapabilityV2,
    StagedFinalityRecoveryV2,
};

#[cfg(test)]
mod tests;
