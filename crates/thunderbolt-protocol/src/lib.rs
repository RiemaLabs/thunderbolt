//! Stable protocol and ledger primitives for Bitcoin Thunderbolt.
//!
//! This crate deliberately contains no networking, storage, clocks, key
//! material, or proof implementation. It provides:
//!
//! - strictly validated, serde-compatible wire identifiers;
//! - versioned append-only ledger entries with a stable canonical hash;
//! - explicit verification attestations for a node's proof-verification
//!   policy; and
//! - a deterministic per-channel reducer.
//!
//! The reducer checks ordering, lifecycle, identity, and the presence of
//! successful verification attestations. It does **not** verify signatures,
//! zero-knowledge proofs, Bitcoin transactions, or committee quorums. A node
//! must perform those checks before it creates trusted verification evidence.
#![forbid(unsafe_code)]
#![deny(missing_debug_implementations)]

mod canonical;
mod error;
mod event;
mod identifiers;
mod ledger;
mod reducer;

pub use error::{IdentifierKind, ProtocolError};
pub use event::{
    Actor, ActorRole, ChannelEvent, Committee, EventKind, FinalizeEvent, InvoiceEvent, OpenEvent, TransferEvent,
    VerificationEvidence, VerificationKind, VerificationOutcome, MAX_BITCOIN_SUPPLY_SAT, MAX_COMMITTEE_MEMBERS,
};
pub use identifiers::{
    Artifact, BitcoinTxid, ChannelId, Digest, EntryHash, IdempotencyKey, ImplementationId, InvoiceId, ParticipantId,
    MAX_ARTIFACT_BYTES, MAX_IDEMPOTENCY_KEY_BYTES, MAX_IMPLEMENTATION_ID_BYTES, MAX_INVOICE_ID_BYTES,
    MAX_PARTICIPANT_ID_BYTES,
};
pub use ledger::{LedgerEntry, HASH_FORMAT_VERSION, PROTOCOL_VERSION};
pub use reducer::{
    ApplyDisposition, ChannelPhase, ChannelReducer, ChannelSnapshot, HistoryContext, PendingInvoice, ProtocolLimits,
    Reduction, ABSOLUTE_MAX_VERIFICATIONS_PER_EVENT, DEFAULT_MAX_ENTRIES_PER_CHANNEL,
    DEFAULT_MAX_VERIFICATIONS_PER_EVENT,
};
