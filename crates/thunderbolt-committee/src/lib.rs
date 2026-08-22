//! One-member-per-process committee runtime for Bitcoin Thunderbolt.
//!
//! A production process is provisioned with exactly one Paillier decryption key
//! and one Shamir share. The runtime verifies public threshold-refresh wire
//! messages, decrypts only its own ciphertext, and commits share updates through
//! an encrypted compare-and-swap vault. It never reconstructs the committee
//! secret and intentionally provides no threshold-signature finalizer.

#![forbid(unsafe_code)]
#![deny(
    clippy::dbg_macro,
    clippy::expect_used,
    clippy::panic,
    clippy::todo,
    clippy::unimplemented,
    clippy::unwrap_used
)]

mod commitment;
mod engine;
mod error;
mod record;
mod signer;
mod types;
mod vault;

#[cfg(any(test, feature = "insecure-regtest"))]
pub mod insecure_regtest;

pub use commitment::{CommittedTransfer, LedgerCommitmentVerifier};
pub use engine::CommitteeMemberEngine;
pub use error::{CommitteeError, Result};
pub use record::{PendingRefresh, RefreshEventBinding, UpdateAcknowledgement};
pub use signer::{CommitteeSigner, NonceCommitment, SignerSessionBinding, SignerSessionId, SignerSessionPhase};
pub use types::{
    CommitteeDescriptor, CommitteeEpoch, CommitteeId, CommitteeMemberDescriptor, CommitteeMemberId,
    CommitteeMemberState, ProvisionedMemberPackage, RefreshEventId, ShamirShare,
};
pub use vault::{
    CommitteeVault, VaultEntry, VaultPlaintext, VaultPlaintextError, VaultStoreError, MAX_VAULT_PLAINTEXT_BYTES,
};

pub use thunderbolt_wire::RECIPIENT_SHARE_MEMBER_ID;

#[cfg(test)]
mod tests;
