//! Core zero-knowledge proofs from `CORE_ZKP.md`.
//!
//! This module intentionally implements only the two concrete proofs needed for
//! the invoice and transfer consistency checks:
//! - invoice consistency (`tb/invoice`)
//! - transfer consistency (`tb/xfer`)
//!
//! It does **not** yet implement the broader register / redeem proof family.

pub mod invoice;
pub mod share;
pub(crate) mod transcript;
pub mod transfer;
pub mod types;

pub use invoice::{prove_invoice, verify_invoice, InvoiceProof, InvoiceStatement, InvoiceWitness};
pub use share::{
    prove_share_encryption, verify_share_encryption, ShareEncryptionProof, ShareEncryptionStatement,
    ShareEncryptionWitness,
};
pub use transfer::{
    prove_transfer, verify_anchor_transition, verify_transfer, TransferProof, TransferStatement, TransferWitness,
};
pub use types::{ProofContext, ProofTag};
