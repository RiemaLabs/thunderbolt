//! Consensus-finality-gated rollback checkpoints for Bitcoin Thunderbolt.
//!
//! This crate implements the client-side [`RollbackFloorStore`] contract over
//! an independent replicated Ledger. It does not trust transport responses:
//! every response remains [`UnverifiedLedgerResponse`] until a configured
//! [`LedgerFinalityVerifier`] validates a validator quorum certificate or a
//! trusted light-client proof and canonical application inclusion.
//!
//! No local-file backend, permissive verifier, CometBFT verifier, or concrete
//! RPC transport is provided. The current `thunderbolt-ledger` crate defines
//! deterministic execution but explicitly does not provide consensus finality.
//! Therefore this adapter core is not deployable until a concrete authenticated
//! transport and audited finality verifier are supplied.

#![deny(missing_docs)]
#![forbid(unsafe_code)]

mod adapter;
mod error;
mod transport;
mod types;

pub use adapter::LedgerRollbackFloorStore;
pub use error::{FloorError, LedgerFloorStoreError, Result};
pub use thunderbolt_keystore::{CheckpointCasOutcome, RollbackFloorStore, VaultCheckpoint, VaultIdentity};
pub use transport::{
    FinalityVerifierCapability, LedgerFinalityVerifier, LedgerFloorTransport, UnverifiedCasSubmission,
    UnverifiedLedgerResponse,
};
pub use types::{
    FinalizedFloorResponse, FinalizedFloorResult, FloorCasRequest, FloorFinalityAnchor, FloorLedgerChainId,
    FloorReadRequest, FloorRequestDigest,
};
