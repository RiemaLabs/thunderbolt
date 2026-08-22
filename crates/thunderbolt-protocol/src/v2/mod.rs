//! Version-two protocol state machine.
//!
//! This module adds concurrent pending invoices, stable deployment and
//! committee-epoch bindings, ledger-assigned time, and typed verification
//! hooks. It is a separate protocol surface: it does not change version-one
//! serialization, reduction, or hashes.
//!
//! The reducer implements the rules documented in the migration boundary. It
//! does not claim theorem equivalence with the research artifact.

#![deny(
    clippy::expect_used,
    clippy::panic,
    clippy::todo,
    clippy::unimplemented,
    clippy::unwrap_used
)]

#[doc = include_str!("../../docs/v2-migration.md")]
pub mod migration {}

mod canonical;
mod reducer;
mod types;

pub use reducer::{
    ApplyDispositionV2, AuthenticatedEntryV2, ConsensusEntryV2, ExternalVerifierV2, FinalizeVerificationRequestV2,
    HistoryContextV2, InvoiceVerificationRequestV2, OpenVerificationRequestV2, ReductionV2,
    TransferVerificationRequestV2, V2Reducer, VerificationStageV2,
};
pub use thunderbolt_ledger::{
    ActorRoleV2, EntryHashV2, EventDigestV2, EventKindV2, ParticipantIdV2, RequestDigestV2, VerifiedProposalViewV2,
};
pub use thunderbolt_wire::{ChannelBindingV2, InvoiceId as InvoiceIdV2};
pub use types::{
    ChannelEventV2, ChannelPhaseV2, ChannelSnapshotV2, FinalizeEventV2, InvoiceEventV2, OpenEventV2, PendingInvoiceV2,
    ProtocolLimitsV2, StateHashV2, TransferEventV2, V2Error, ABSOLUTE_MAX_INVOICE_TTL_MS_V2,
    ABSOLUTE_MAX_PENDING_INVOICES_V2, DEFAULT_MAX_ENTRIES_PER_CHANNEL_V2, DEFAULT_MAX_INVOICE_TTL_MS_V2,
    DEFAULT_MAX_PENDING_INVOICES_V2, HASH_FORMAT_VERSION_V2, PROTOCOL_VERSION_V2,
};

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
mod tests;
