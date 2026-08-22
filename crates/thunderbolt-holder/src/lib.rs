//! Local Holder and Recipient state machine for Bitcoin Thunderbolt.
//!
//! This crate performs private protocol operations behind a transactional
//! secret-vault boundary. It contains no networking and deliberately provides
//! no serialization implementation for identity seeds, Paillier decryption
//! keys, invoice refreshes, or holder credentials.
//!
//! # Release-candidate parameter
//!
//! Version 1 currently uses a 2048-bit Paillier modulus. The accepted paper
//! evaluates a 3072-bit parameter. Moving to 3072 bits requires a versioned
//! core and wire-format migration; callers must not silently mix parameters.
#![forbid(unsafe_code)]
#![deny(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

mod engine;
mod error;
mod types;
mod vault;

pub use engine::HolderEngine;
pub use error::{HolderError, VaultError};
pub use types::{
    ChannelContext, ChannelKey, CommittedInvoice, CommittedTransfer, CredentialKey, CredentialSecret,
    CredentialSummary, DurableAcknowledgement, GenesisCredential, HolderIdentity, InvoiceRecordKey, InvoiceRequest,
    PreparedInvoice, PreparedTransfer, PrivateInvoiceRecordRef, ReceiveDisposition, TransferAcknowledgementDisposition,
    VerifiedInvoice,
};
pub use vault::{
    CredentialRecord, CredentialState, IdentityRecord, InvoiceRecord, InvoiceState, OutboundTransferRecord,
    SecretVault, VaultTransaction,
};

/// Paillier modulus size enforced by the version-one release candidate.
pub const RC_PAILLIER_MODULUS_BITS: usize = thunderbolt_core::paillier::PAILLIER_MODULUS_BYTES * 8;

#[cfg(test)]
mod tests;
