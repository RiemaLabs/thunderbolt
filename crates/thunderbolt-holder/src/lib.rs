//! Local Holder and Recipient state machine for Bitcoin Thunderbolt.
//!
//! This crate performs private protocol operations behind a transactional
//! secret-vault boundary. It contains no networking and deliberately provides
//! no serialization implementation for identity seeds, Paillier decryption
//! keys, invoice refreshes, or holder credentials.
//!
//! The threshold Invoice path emits a Recipient [`thunderbolt_wire::ShareEnvelopeV1`]
//! and a committee [`thunderbolt_wire::ThresholdEnvelopeV1`] over one refresh.
//! The Recipient proof uses the implemented `tb/share` transcript. This crate
//! does not silently claim that transcript is the paper's exact `R_inv^thr`.
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
mod keystore;
mod types;
mod vault;

pub use engine::HolderEngine;
pub use error::{HolderError, VaultError};
pub use keystore::{holder_keystore_identity, KeystoreSecretVault};
pub use thunderbolt_core::threshold::ThresholdMemberPublicKey;
pub use types::{
    threshold_invoice_package_digest, ChannelContext, ChannelKey, CommittedInvoice, CommittedThresholdInvoice,
    CommittedTransfer, CredentialKey, CredentialSecret, CredentialSummary, DurableAcknowledgement, GenesisCredential,
    HolderIdentity, InvoiceRecordKey, InvoiceRequest, PreparedInvoice, PreparedThresholdInvoice, PreparedTransfer,
    PrivateInvoiceRecordRef, ReceiveDisposition, ThresholdInvoiceRequest, ThresholdRoster,
    TransferAcknowledgementDisposition, VerifiedInvoice, VerifiedInvoiceMessages,
};
pub use vault::{
    CredentialRecord, CredentialState, IdentityRecord, InvoicePublicRecord, InvoiceRecord, InvoiceState,
    OutboundTransferRecord, SecretVault, VaultTransaction,
};

/// Paillier modulus size enforced by the version-one release candidate.
pub const RC_PAILLIER_MODULUS_BITS: usize = thunderbolt_core::paillier::PAILLIER_MODULUS_BYTES * 8;

#[cfg(test)]
mod tests;
