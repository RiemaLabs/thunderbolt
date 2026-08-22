//! Trusted verification bridge for Bitcoin Thunderbolt ledger events.
//!
//! This crate is the narrow boundary between untrusted public artifacts and
//! [`thunderbolt_protocol::VerificationEvidence`]. It:
//!
//! - decodes only bounded, typed [`thunderbolt_wire::PublicMessageV1`] JSON;
//! - binds every proof to trusted deployment and ledger state;
//! - compares ledger artifacts to decoded public statement fields exactly;
//! - invokes the wire layer's structural and cryptographic verification; and
//! - creates only the evidence required by the verified event.
//!
//! It deliberately has no witness, secret-key, decryption, signing, storage,
//! network, or clock API. Callers must supply authenticated ledger entries,
//! an immutable snapshot, and a timestamp sampled by the trusted ledger.
#![forbid(unsafe_code)]
#![deny(missing_debug_implementations)]

mod context;
mod error;
mod verify;

pub use context::{CommitteeBinding, DeploymentContext, VerifierIdentity, RECIPIENT_SHARE_MEMBER_ID};
pub use error::{ArtifactSlot, BindingField, PublicMessageKind, Result, VerifierError, VerifierErrorCode};
pub use verify::{decode_bounded_message, StatementDigest, StatementKind, TrustedVerifier, VerificationOutput};
