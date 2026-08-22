//! Configuration and local bearer-token authorization for Bitcoin Thunderbolt.
//!
//! The crate intentionally keeps secret token values out of the configuration
//! document. Operators put each token in a separate, owner-only file and refer
//! to that file from [`AuthConfig`].

#![forbid(unsafe_code)]

mod auth;
mod config;
mod error;

pub use auth::{AuthIdentity, TokenStore, MAX_TOKEN_BYTES, MIN_TOKEN_BYTES};
pub use config::{
    AdminConfig, AdminTlsConfig, AuthConfig, BackupConfig, CommitteeConfig, Config, DeploymentConfig,
    DevelopmentConfig, Environment, LedgerConfig, LimitsConfig, MetricsConfig, Network, NodeConfig, NodeRole,
    PathsConfig, TokenConfig, TokenScope, SAMPLE_CONFIG,
};
pub use error::{AuthError, ConfigError, ValidationErrors};
