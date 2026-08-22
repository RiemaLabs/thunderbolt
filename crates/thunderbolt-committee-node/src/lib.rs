//! Restart-safe Committee role service for Bitcoin Thunderbolt.
//!
//! This crate consumes exact signed protocol-v2 Ledger execution artifacts only
//! after an external finality verifier accepts its opaque consensus receipt. It
//! persists a bounded SQLite inbox, unsigned acknowledgement outbox, and exact
//! finalized cursor around the checkpoint-fenced one-member committee engine.
//! It implements no DKG, FROST aggregation, consensus finality, or mainnet mode.

#![forbid(unsafe_code)]
#![deny(
    clippy::dbg_macro,
    clippy::expect_used,
    clippy::panic,
    clippy::todo,
    clippy::unimplemented,
    clippy::unwrap_used
)]

mod error;
mod service;
mod storage;
mod traits;
mod types;

pub use error::{NodeError, Result};
pub use service::{CommitteeNode, FencedCommitteeNode};
pub use traits::{
    CommitteeRuntime, DisabledFinalityVerifier, DisabledProposalSigner, DisabledSignedV2LedgerClient,
    LedgerFinalityVerifier, LedgerFuture, SignedV2LedgerClient, SignedV2ProposalSigner,
};
pub use types::{
    AcknowledgementRecord, ControlRequest, ControlResponse, DurableBlockFinalityCapability, DurableFinalityCapability,
    EntryOccurrenceKindV2, ExecutedEntryEvidenceV2, FinalityCoordinatorId, FinalityDigest, FinalityRangeIntentV2,
    FinalityVerifierProfileId, FinalizedBlockV2, FinalizedRangeCapabilityV2, LedgerCursor, NodeConfig, NodeStatus,
    OutboxItem, OutboxStatus, ProcessDisposition, RefreshBlockCommitmentsV2, RuntimeRefreshOutcome,
    StagedFinalityRangeCapabilityV2, StagedFinalityRecoveryV2, SubmissionStatus, VerifiedEntryOccurrenceV2,
    VerifiedRefreshRecordV2, VerifiedV2Refresh, MAX_FINALITY_INTENT_BYTES, MAX_INBOX_RECORD_BYTES,
    MAX_SCAN_SEGMENT_BYTES,
};

#[cfg(test)]
mod tests;
