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
    CommitteeRuntime, DisabledFinalityVerifier, DisabledProposalSigner, LedgerFinalityVerifier, SignedV2LedgerClient,
    SignedV2ProposalSigner,
};
pub use types::{
    AcknowledgementRecord, ControlRequest, ControlResponse, FinalityDigest, FinalizedEntryV2, FinalizedRefreshBundleV2,
    IngestDisposition, LedgerCursor, NodeConfig, NodeStatus, OutboxItem, OutboxStatus, ProcessDisposition,
};

#[cfg(test)]
mod tests;
