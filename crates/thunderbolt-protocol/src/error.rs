use crate::{ActorRole, ChannelId, EntryHash, EventKind, IdempotencyKey, InvoiceId, VerificationKind};
use thiserror::Error;

/// The class of a validated textual identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentifierKind {
    /// An idempotency key supplied by a client.
    IdempotencyKey,
    /// A participant identity.
    ParticipantId,
    /// An invoice identity.
    InvoiceId,
    /// A verifier implementation identity/version.
    ImplementationId,
}

impl core::fmt::Display for IdentifierKind {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let name = match self {
            Self::IdempotencyKey => "idempotency key",
            Self::ParticipantId => "participant id",
            Self::InvoiceId => "invoice id",
            Self::ImplementationId => "implementation id",
        };
        formatter.write_str(name)
    }
}

/// Structured validation and state-transition failures.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum ProtocolError {
    /// A Bitcoin outpoint was not in canonical `txid:vout` form.
    #[error("invalid channel id: {reason}")]
    InvalidChannelId { reason: &'static str },

    /// A Bitcoin transaction id was malformed.
    #[error("invalid Bitcoin transaction id: {reason}")]
    InvalidBitcoinTxid { reason: &'static str },

    /// A caller-controlled identifier was malformed or too long.
    #[error("invalid {kind}: {reason}")]
    InvalidIdentifier { kind: IdentifierKind, reason: &'static str },

    /// An opaque public artifact was empty or exceeded the wire limit.
    #[error("invalid protocol artifact: {reason}")]
    InvalidArtifact { reason: &'static str },

    /// A fixed-size hexadecimal digest was malformed.
    #[error("invalid {kind}: expected exactly 64 lowercase hexadecimal characters")]
    InvalidDigest { kind: &'static str },

    /// The entry uses a protocol version this crate cannot reduce.
    #[error("unsupported protocol version {found}; supported version is {supported}")]
    UnsupportedProtocolVersion { found: u16, supported: u16 },

    /// A committee description violates threshold constraints.
    #[error("invalid committee: {reason}")]
    InvalidCommittee { reason: &'static str },

    /// A channel capacity is outside Bitcoin's monetary range.
    #[error("invalid channel capacity {capacity_sat} sat")]
    InvalidCapacity { capacity_sat: u64 },

    /// Reducer limits were configured inconsistently.
    #[error("invalid protocol limits: {reason}")]
    InvalidLimits { reason: &'static str },

    /// A ledger entry targets a different channel than its snapshot.
    #[error("channel mismatch: snapshot is {expected}, entry is {found}")]
    ChannelMismatch { expected: ChannelId, found: ChannelId },

    /// Only an Open event may create a channel.
    #[error("channel does not exist; first entry must be Open at sequence 0")]
    ChannelNotOpen,

    /// Open was submitted for an existing channel.
    #[error("channel is already open")]
    ChannelAlreadyOpen,

    /// The entry is behind the next expected position.
    #[error("stale sequence {found}; next expected sequence is {expected}")]
    StaleSequence { expected: u64, found: u64 },

    /// The entry skips one or more ledger positions.
    #[error("sequence gap: expected {expected}, found {found}")]
    SequenceGap { expected: u64, found: u64 },

    /// The sequence counter can no longer advance.
    #[error("channel sequence is exhausted")]
    SequenceExhausted,

    /// The entry does not extend the current head.
    #[error("fork detected: expected previous hash {expected}, found {found}")]
    ForkDetected { expected: EntryHash, found: EntryHash },

    /// A reused idempotency key describes different bytes.
    #[error("idempotency conflict for {key}: existing entry {existing}, proposed entry {proposed}")]
    IdempotencyConflict {
        key: IdempotencyKey,
        existing: EntryHash,
        proposed: EntryHash,
    },

    /// A timestamp moved backwards relative to the channel log.
    #[error("timestamp regression: previous {previous_ms} ms, proposed {proposed_ms} ms")]
    TimestampRegression { previous_ms: u64, proposed_ms: u64 },

    /// An event claims to occur after the trusted ledger evaluation time.
    #[error("event timestamp {event_at_ms} ms is after trusted ledger time {ledger_at_ms} ms")]
    EventFromFuture { event_at_ms: u64, ledger_at_ms: u64 },

    /// An actor role is not permitted to submit this event.
    #[error("{event} requires actor role {expected:?}, found {found:?}")]
    UnauthorizedRole {
        event: EventKind,
        expected: ActorRole,
        found: ActorRole,
    },

    /// The actor id does not match the participant named by the event/state.
    #[error("actor does not match the {expected_participant} for {event}")]
    ActorMismatch {
        event: EventKind,
        expected_participant: &'static str,
    },

    /// More attestations were supplied than policy permits.
    #[error("event has {found} verification attestations; limit is {limit}")]
    TooManyVerifications { limit: usize, found: usize },

    /// An event omitted a mandatory verification attestation.
    #[error("{event} is missing required {verification:?} verification evidence")]
    MissingVerification {
        event: EventKind,
        verification: VerificationKind,
    },

    /// An event contains two attestations for the same verification kind.
    #[error("{event} contains duplicate {verification:?} verification evidence")]
    DuplicateVerification {
        event: EventKind,
        verification: VerificationKind,
    },

    /// An attestation reports that a required verification failed.
    #[error("{event} contains rejected {verification:?} verification evidence")]
    VerificationRejected {
        event: EventKind,
        verification: VerificationKind,
    },

    /// An attestation claims to have been produced after its ledger entry.
    #[error("verification timestamp {verified_at_ms} ms is after entry timestamp {entry_at_ms} ms")]
    VerificationFromFuture { verified_at_ms: u64, entry_at_ms: u64 },

    /// An invoice is already waiting to be consumed.
    #[error("invoice {invoice_id} is already pending")]
    PendingInvoiceExists { invoice_id: InvoiceId },

    /// Invoice identifiers are single-use for a channel's entire lifetime.
    #[error("invoice id {invoice_id} has already been used in this channel")]
    InvoiceAlreadyUsed { invoice_id: InvoiceId },

    /// A transfer references no pending invoice.
    #[error("there is no pending invoice to transfer")]
    NoPendingInvoice,

    /// A transfer references a different pending invoice.
    #[error("invoice mismatch: pending {expected}, transfer references {found}")]
    InvoiceMismatch { expected: InvoiceId, found: InvoiceId },

    /// A transfer was submitted at or after an invoice's expiration.
    #[error("invoice {invoice_id} expired at {expires_at_ms} ms")]
    InvoiceExpired { invoice_id: InvoiceId, expires_at_ms: u64 },

    /// An invoice's expiration does not follow its creation time.
    #[error("invoice expiration {expires_at_ms} ms must be after entry time {entry_at_ms} ms")]
    InvalidInvoiceExpiration { entry_at_ms: u64, expires_at_ms: u64 },

    /// Finalization cannot race a still-live invoice.
    #[error("cannot finalize while invoice {invoice_id} is pending")]
    PendingInvoiceBlocksFinalization { invoice_id: InvoiceId },

    /// An event was proposed after finalization.
    #[error("channel is finalized")]
    ChannelFinalized,

    /// A configured per-channel ledger bound was reached.
    #[error("channel entry limit {limit} reached")]
    EntryLimitReached { limit: u64 },

    /// A transfer counter can no longer advance.
    #[error("channel transfer counter is exhausted")]
    TransferCounterExhausted,

    /// A supplied snapshot is internally inconsistent.
    #[error("invalid channel snapshot: {reason}")]
    InvalidSnapshot { reason: &'static str },
}
