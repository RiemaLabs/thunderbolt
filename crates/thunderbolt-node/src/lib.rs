//! Hardened HTTP runtime for the Bitcoin Thunderbolt reference node.
//!
//! This crate intentionally keeps transport concerns outside the protocol and
//! storage crates. Incoming events are untrusted. Default operation rejects
//! every client-supplied attestation and has no verifier. Deployments can
//! inject the trusted Invoice/Transfer bridge; Open and Finalize remain
//! fail-closed. An isolated regtest-only option can synthesize conspicuously
//! named attestations inside storage's transaction-scoped callback.

#![forbid(unsafe_code)]

mod api;
mod error;
mod server;
mod verifier;

pub use api::{
    AppendResponse, BackupRequest, BackupResponse, ChannelPage, EventPage, HealthResponse, InfoResponse,
    IntegrityResponse,
};
pub use error::NodeError;
pub use server::{validate_runtime_config, NodeOptions, NodeServer};
pub use verifier::{
    InvoiceProposalContext, ProposalVerifier, ProposalVerifierError, TransferProposalContext, VerifiedProposalEvidence,
};
