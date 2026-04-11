//! Core zero-knowledge proofs from `CORE_ZKP.md`.
//!
//! This module intentionally implements only the two concrete proofs needed for
//! the invoice and transfer consistency checks:
//! - invoice consistency (`tb/invoice`)
//! - transfer consistency (`tb/xfer`)
//!
//! It does **not** yet implement the broader register / redeem proof family or
//! the committee PVSS / VESS invoice machinery described elsewhere in `README.md`.

pub mod invoice;
pub(crate) mod transcript;
pub mod transfer;
pub mod types;

pub use invoice::{prove_invoice, verify_invoice, InvoiceProof, InvoiceStatement, InvoiceWitness};
pub use transfer::{
    prove_transfer, verify_anchor_transition, verify_transfer, TransferProof, TransferStatement, TransferWitness,
};
pub use types::{ProofContext, ProofTag};
