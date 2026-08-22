//! Paper-exact Holder ownership proof for Bitcoin Thunderbolt.
//!
//! The proved relation is exactly `R_own = { (X; x) : X = xH }`, as specified
//! in Sections 4.2 and 5.1 of the accepted paper. [`FinalizeSigningContext`]
//! is independently derived from authenticated Ledger state and immutable
//! suite configuration, then adds stronger Fiat-Shamir domain separation
//! around that one equation. It does not prove closing-transaction validity,
//! committee authorization, or a threshold signature.

#![forbid(unsafe_code)]
#![deny(
    clippy::dbg_macro,
    clippy::expect_used,
    clippy::panic,
    clippy::todo,
    clippy::unimplemented,
    clippy::unwrap_used
)]

mod codec;
mod error;
mod proof;
mod types;

pub use error::{OwnershipError, Result};
pub use proof::{prove_ownership, verify_ownership};
pub use types::{
    AnchorSuiteParametersV2, AnchorSuiteRegistryV2, ClosingTransactionDigest, FinalizeSigningContext,
    OwnershipEnvelopeV2, OwnershipProofV2, OwnershipWitness, VerifiedOwnership, MAX_CLOSING_TRANSACTION_BYTES,
    OWNERSHIP_CODEC_VERSION, OWNERSHIP_PROOF_VERSION,
};

#[cfg(test)]
mod tests;
