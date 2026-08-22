//! Fail-closed, role-typed operator runtime shell for Bitcoin Thunderbolt v2.
//!
//! This crate supervises fixed lifecycle hooks and local operator observations.
//! It does not construct a production protocol service or open any listener.

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(
    clippy::dbg_macro,
    clippy::expect_used,
    clippy::panic,
    clippy::todo,
    clippy::unimplemented,
    clippy::unwrap_used
)]

mod control;
mod error;
mod process_lock;
mod supervisor;
mod types;

pub use control::{
    RuntimeControl, CONTROL_METHOD_BLOCKERS, CONTROL_METHOD_DRAIN, CONTROL_METHOD_REDACTED_CONFIG,
    CONTROL_METHOD_STATUS, CONTROL_METHOD_STOP, MAX_RUNTIME_CONTROL_PAYLOAD_BYTES,
};
pub use error::{Result, RuntimeError};
pub use process_lock::RUNTIME_PROCESS_LOCK_FILE;
pub use supervisor::{
    CommitteeSupervisor, HolderSupervisor, LedgerSupervisor, RuntimeHandle, RuntimeMonitor, RuntimeSupervisor,
    MAX_PENDING_LIFECYCLE_COMMANDS, MAX_RETAINED_LIFECYCLE_REQUESTS,
};
pub use thunderbolt_runtime_config::RuntimeRole;
pub use types::{
    CommitteeRole, HolderRole, LedgerRole, RedactedRuntimeConfig, RuntimeBlocker, RuntimeBlockerCategory,
    RuntimeBlockerCode, RuntimeFaultCode, RuntimeHandlerFuture, RuntimeHandlerIdentity, RuntimeLifecycleEvent,
    RuntimeLifecycleHandler, RuntimeLifecycleState, RuntimeLiveness, RuntimeReadiness, RuntimeRoleMarker,
    RuntimeStatus, RUNTIME_SHELL_VERSION_V2,
};

/// Complete operator-runtime shell contract and limitations.
#[doc = include_str!("../README.md")]
pub mod api {}

#[cfg(test)]
mod tests;
