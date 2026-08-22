//! Hardened HTTP runtime for the Bitcoin Thunderbolt reference node.
//!
//! This crate intentionally keeps transport concerns outside the protocol and
//! storage crates. Incoming events are untrusted. Until a real verifier is
//! integrated, normal operation rejects every client-supplied attestation and
//! every unverified event. An isolated regtest-only option can synthesize
//! conspicuously named attestations for state-machine demonstrations.

#![forbid(unsafe_code)]

mod api;
mod error;
mod server;

pub use api::{
    AppendResponse, BackupRequest, BackupResponse, ChannelPage, EventPage, HealthResponse, InfoResponse,
    IntegrityResponse,
};
pub use error::NodeError;
pub use server::{validate_runtime_config, NodeOptions, NodeServer};
