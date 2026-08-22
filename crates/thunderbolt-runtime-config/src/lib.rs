//! Unified, secret-free operator configuration for Bitcoin Thunderbolt v2.

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

mod error;
mod mapping;
mod raw;
mod types;
mod validate;

pub use error::{ConfigError, Result};
pub use types::{
    check_deployment_consistency, check_effective_deployment_consistency, AbciRuntimePolicy, CapabilityBoundary,
    CheckpointProviderCapability, CometPeerPolicy, CometRuntimePolicy, CometTlsReferences, CommitteeRuntimeConfig,
    DeploymentConsistency, DeploymentIdentity, EffectiveRuntimeConfig, ExternalCheckpointProviderRequirement,
    ExternalFileReference, HolderRuntimeConfig, LedgerRuntimeConfig, LoadedCometTls, ParsedRuntimeConfig,
    RedactedEffectiveConfig, RuntimeHandoff, RuntimePaths, RuntimeRole, SecretFileReference, TrustRootReference,
    CONFIG_VERSION_V2,
};

#[cfg(test)]
mod tests;
