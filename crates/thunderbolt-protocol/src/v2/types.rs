use crate::{Artifact, MAX_BITCOIN_SUPPLY_SAT};
use core::{fmt, str::FromStr};
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest as _, Sha256};
use std::collections::BTreeMap;
use thiserror::Error;
use thunderbolt_ledger::{EntryHashV2, EventDigestV2, LedgerChainIdV2, ParticipantIdV2, EVENT_BYTES_MAX};
use thunderbolt_wire::{CanonicalDigest as _, ChannelBindingV2, InvoiceId, ValidateWire as _};

use super::canonical::{decode_event, encode_event, encode_state, encoded_event_len};

/// Protocol schema version for the isolated version-two application reducer.
pub const PROTOCOL_VERSION_V2: u16 = 2;
/// Canonical format version used by version-two application events and state.
pub const HASH_FORMAT_VERSION_V2: u16 = 2;
/// Default maximum total committed entries in one version-two channel.
pub const DEFAULT_MAX_ENTRIES_PER_CHANNEL_V2: u64 = 1_000_000;
/// Default maximum concurrently pending version-two invoices.
pub const DEFAULT_MAX_PENDING_INVOICES_V2: usize = 8;
/// Absolute defensive bound on concurrently pending version-two invoices.
pub const ABSOLUTE_MAX_PENDING_INVOICES_V2: usize = 32;
/// Default maximum lifetime of a pending Invoice: 24 hours.
pub const DEFAULT_MAX_INVOICE_TTL_MS_V2: u64 = 86_400_000;
/// Absolute maximum Invoice lifetime: 30 days.
pub const ABSOLUTE_MAX_INVOICE_TTL_MS_V2: u64 = 2_592_000_000;
/// Maximum committee topology supported by the active threshold wire suite.
pub const MAX_COMMITTEE_MEMBERS_V2: u16 = 256;

/// Canonical 32-byte version-two materialized-state hash.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct StateHashV2([u8; 32]);

impl StateHashV2 {
    /// Constructs the hash from exactly 32 raw bytes.
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Borrows the raw hash bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Returns the raw hash bytes.
    pub const fn to_bytes(self) -> [u8; 32] {
        self.0
    }
}

impl fmt::Debug for StateHashV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("StateHashV2").field(&self.to_string()).finish()
    }
}

impl fmt::Display for StateHashV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl FromStr for StateHashV2 {
    type Err = V2Error;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if value.len() != 64
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            return Err(V2Error::InvalidStateHash);
        }
        let mut bytes = [0_u8; 32];
        for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
            let high = hex_nibble(pair[0]).ok_or(V2Error::InvalidStateHash)?;
            let low = hex_nibble(pair[1]).ok_or(V2Error::InvalidStateHash)?;
            bytes[index] = (high << 4) | low;
        }
        Ok(Self(bytes))
    }
}

impl Serialize for StateHashV2 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for StateHashV2 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        value.parse().map_err(de::Error::custom)
    }
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

/// Deterministic resource limits for version-two reduction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProtocolLimitsV2 {
    /// Maximum total committed entries, including Open and Finalize.
    pub max_entries_per_channel: u64,
    /// Maximum number of concurrently pending invoices.
    pub max_pending_invoices: usize,
    /// Maximum lifetime assigned to one Invoice.
    pub max_invoice_ttl_ms: u64,
}

impl ProtocolLimitsV2 {
    /// Validates and constructs reducer limits.
    pub fn new(
        max_entries_per_channel: u64,
        max_pending_invoices: usize,
        max_invoice_ttl_ms: u64,
    ) -> Result<Self, V2Error> {
        let limits = Self {
            max_entries_per_channel,
            max_pending_invoices,
            max_invoice_ttl_ms,
        };
        limits.validate()?;
        Ok(limits)
    }

    pub(crate) fn validate(&self) -> Result<(), V2Error> {
        if self.max_entries_per_channel < 2 {
            return Err(V2Error::InvalidLimits {
                reason: "max_entries_per_channel must reserve Open and Finalize positions",
            });
        }
        if self.max_pending_invoices == 0 {
            return Err(V2Error::InvalidLimits {
                reason: "max_pending_invoices must be positive",
            });
        }
        if self.max_pending_invoices > ABSOLUTE_MAX_PENDING_INVOICES_V2 {
            return Err(V2Error::InvalidLimits {
                reason: "max_pending_invoices exceeds the absolute safety bound",
            });
        }
        if self.max_invoice_ttl_ms == 0 || self.max_invoice_ttl_ms > ABSOLUTE_MAX_INVOICE_TTL_MS_V2 {
            return Err(V2Error::InvalidLimits {
                reason: "max_invoice_ttl_ms is outside the safety bound",
            });
        }
        Ok(())
    }
}

impl Default for ProtocolLimitsV2 {
    fn default() -> Self {
        Self {
            max_entries_per_channel: DEFAULT_MAX_ENTRIES_PER_CHANNEL_V2,
            max_pending_invoices: DEFAULT_MAX_PENDING_INVOICES_V2,
            max_invoice_ttl_ms: DEFAULT_MAX_INVOICE_TTL_MS_V2,
        }
    }
}

/// Payload that establishes a version-two channel.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OpenEventV2 {
    /// Number of committee members in the bound descriptor.
    pub committee_member_count: u16,
    /// Threshold required by the bound committee descriptor.
    pub committee_threshold: u16,
    /// Whole-UTXO channel capacity.
    pub capacity_sat: u64,
    /// Public fixed Bitcoin lock key `P`.
    pub lock_key: Artifact,
    /// Initial public Holder anchor `X_0`.
    pub initial_holder_anchor: Artifact,
    /// Initial encrypted Holder credential `T_0`.
    pub initial_holder_ciphertext: Artifact,
    /// Public Open proof package interpreted by the trusted verifier.
    pub open_proof: Artifact,
}

/// Payload that publishes one concurrently pending invoice.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InvoiceEventV2 {
    /// Channel-lifetime-unique invoice identifier.
    pub invoice_id: InvoiceId,
    /// Holder step against which the invoice proof was formed.
    pub holder_step: u64,
    /// Recipient's public encryption key.
    pub recipient_encryption_key: Artifact,
    /// Public delta point `D_s`.
    pub public_delta: Artifact,
    /// Recipient ciphertext `ct_B`.
    pub recipient_ciphertext: Artifact,
    /// Committee ciphertext or VESS distribution package.
    pub committee_package: Artifact,
    /// Invoice consistency proof.
    pub invoice_proof: Artifact,
    /// Mandatory exclusive expiry in trusted Ledger milliseconds.
    pub expires_at_ms: u64,
}

/// Payload that consumes one referenced, committed invoice.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransferEventV2 {
    /// Pending invoice selected by the current Holder.
    pub invoice_id: InvoiceId,
    /// Exact authenticated Invoice entry selected for consumption.
    pub invoice_entry_hash: EntryHashV2,
    /// Public anchor after the transfer.
    pub next_holder_anchor: Artifact,
    /// Encrypted Holder credential after the transfer.
    pub next_holder_ciphertext: Artifact,
    /// Transfer consistency proof.
    pub transfer_proof: Artifact,
}

/// Payload that closes the channel after the latest committed event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FinalizeEventV2 {
    /// Display-order bytes of the Bitcoin closing transaction id.
    pub closing_txid: [u8; 32],
    /// Exact bounded raw closing transaction checked by the trusted verifier.
    pub closing_transaction: Artifact,
    /// Proof of current-Holder ownership.
    pub ownership_proof: Artifact,
    /// Committee threshold acknowledgement or signature material.
    pub committee_attestation: Artifact,
}

/// Version-two application event payload.
///
/// Proof artifacts are untrusted inputs to a configured verifier. There is no
/// client-supplied verification-evidence or authentication field.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", content = "data", rename_all = "snake_case", deny_unknown_fields)]
pub enum ChannelEventV2 {
    /// Establishes a channel.
    Open(OpenEventV2),
    /// Adds an invoice to the pending set.
    Invoice(InvoiceEventV2),
    /// Consumes the selected invoice and rotates ownership.
    Transfer(TransferEventV2),
    /// Irreversibly closes the channel at this total-order position.
    Finalize(FinalizeEventV2),
}

impl ChannelEventV2 {
    /// Returns the stable Ledger event discriminant.
    pub const fn kind(&self) -> thunderbolt_ledger::EventKindV2 {
        match self {
            Self::Open(_) => thunderbolt_ledger::EventKindV2::Open,
            Self::Invoice(_) => thunderbolt_ledger::EventKindV2::Invoice,
            Self::Transfer(_) => thunderbolt_ledger::EventKindV2::Transfer,
            Self::Finalize(_) => thunderbolt_ledger::EventKindV2::Finalize,
        }
    }

    /// Returns the canonical bytes embedded in an authenticated Ledger proposal.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, V2Error> {
        if encoded_event_len(self).ok_or(V2Error::InvalidCanonicalEvent)? > EVENT_BYTES_MAX {
            return Err(V2Error::InvalidCanonicalEvent);
        }
        let bytes = encode_event(self);
        thunderbolt_ledger::CanonicalEventV2::from_bytes(&bytes).map_err(|_| V2Error::InvalidCanonicalEvent)?;
        Ok(bytes)
    }

    /// Decodes one bounded, canonical version-two application event.
    pub fn from_canonical_bytes(bytes: impl AsRef<[u8]>) -> Result<Self, V2Error> {
        let bytes = bytes.as_ref();
        thunderbolt_ledger::CanonicalEventV2::from_bytes(bytes).map_err(|_| V2Error::InvalidCanonicalEvent)?;
        let event = decode_event(bytes)?;
        if encode_event(&event) != bytes {
            return Err(V2Error::InvalidCanonicalEvent);
        }
        Ok(event)
    }

    /// Returns the Ledger's domain-separated digest of the canonical event.
    pub fn event_digest(&self) -> Result<EventDigestV2, V2Error> {
        let event = thunderbolt_ledger::CanonicalEventV2::from_bytes(self.canonical_bytes()?)
            .map_err(|_| V2Error::InvalidCanonicalEvent)?;
        event.digest().map_err(|_| V2Error::InvalidCanonicalEvent)
    }

    /// Returns the Invoice id created by this event, if any.
    pub fn created_invoice_id(&self) -> Option<&InvoiceId> {
        match self {
            Self::Invoice(event) => Some(&event.invoice_id),
            _ => None,
        }
    }
}

/// A committed invoice awaiting a same-holder-step Transfer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PendingInvoiceV2 {
    /// Exact authenticated Invoice payload needed for Transfer verification.
    pub event: InvoiceEventV2,
    /// Channel-lifetime-unique invoice identifier.
    pub invoice_id: InvoiceId,
    /// Authenticated prospective next Holder.
    pub recipient: ParticipantIdV2,
    /// Holder step against which verification succeeded.
    pub holder_step: u64,
    /// Trusted block time at which the invoice committed.
    pub created_at_ms: u64,
    /// Exclusive expiry in trusted Ledger milliseconds.
    pub expires_at_ms: u64,
    /// Hash of the authenticated committed Invoice proposal.
    pub committed_entry_hash: EntryHashV2,
}

impl PendingInvoiceV2 {
    /// Returns whether the invoice is expired at the supplied trusted time.
    pub fn is_expired_at(&self, block_time_ms: u64) -> bool {
        block_time_ms >= self.expires_at_ms
    }
}

/// Version-two channel lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChannelPhaseV2 {
    /// Channel accepts invoices, transfers, and finalization.
    Active,
    /// Channel is irreversibly finalized.
    Finalized,
}

/// Materialized version-two state for one authenticated channel head.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChannelSnapshotV2 {
    /// Application schema version.
    pub protocol_version: u16,
    /// Consensus Ledger chain fixed at Open.
    pub ledger_chain_id: LedgerChainIdV2,
    /// Complete stable wire binding authenticated by every proposal.
    pub binding: ChannelBindingV2,
    /// Current lifecycle phase.
    pub phase: ChannelPhaseV2,
    /// Whole-UTXO capacity fixed at Open.
    pub capacity_sat: u64,
    /// Number of members fixed by the bound committee descriptor.
    pub committee_member_count: u16,
    /// Threshold fixed by the bound committee descriptor.
    pub committee_threshold: u16,
    /// Fixed public Bitcoin lock key `P`.
    pub lock_key: Artifact,
    /// Current Holder identity derived from its authenticated BIP340 key.
    pub current_holder: ParticipantIdV2,
    /// Current public Holder anchor.
    pub current_holder_anchor: Artifact,
    /// Current encrypted Holder credential.
    pub current_holder_ciphertext: Artifact,
    /// Number of completed ownership transfers.
    pub transfers_completed: u64,
    /// Bounded set of concurrently pending invoices, keyed canonically.
    pub pending_invoices: BTreeMap<InvoiceId, PendingInvoiceV2>,
    /// Most recently consumed invoice, if a Transfer has occurred.
    pub last_consumed_invoice_id: Option<InvoiceId>,
    /// Sequence of the current authenticated head.
    pub last_sequence: u64,
    /// Canonical Ledger entry hash of the current authenticated head.
    pub head_entry_hash: EntryHashV2,
    /// Trusted block time assigned to Open.
    pub opened_at_ms: u64,
    /// Trusted block time assigned to the current head.
    pub last_block_time_ms: u64,
    /// Trusted block time assigned to Finalize.
    pub finalized_at_ms: Option<u64>,
}

impl ChannelSnapshotV2 {
    /// Returns the next sequence, if the counter has capacity.
    pub fn next_sequence(&self) -> Result<u64, V2Error> {
        self.last_sequence.checked_add(1).ok_or(V2Error::SequenceExhausted)
    }

    /// Returns stable canonical state bytes.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, V2Error> {
        self.validate()?;
        encode_state(self)
    }

    /// Returns the domain-separated canonical state hash.
    pub fn state_hash(&self) -> Result<StateHashV2, V2Error> {
        Ok(StateHashV2::from_bytes(Sha256::digest(self.canonical_bytes()?).into()))
    }

    /// Checks public snapshot invariants independent of deployment policy.
    pub fn validate(&self) -> Result<(), V2Error> {
        if self.protocol_version != PROTOCOL_VERSION_V2 {
            return Err(V2Error::UnsupportedProtocolVersion {
                found: self.protocol_version,
            });
        }
        self.binding.validate_wire().map_err(|_| V2Error::InvalidSnapshot {
            reason: "invalid stable channel binding",
        })?;
        self.binding.canonical_digest().map_err(|_| V2Error::InvalidSnapshot {
            reason: "channel binding has no canonical digest",
        })?;
        validate_capacity(self.capacity_sat)?;
        validate_committee_topology(self.committee_member_count, self.committee_threshold)?;
        if self.opened_at_ms > self.last_block_time_ms {
            return Err(V2Error::InvalidSnapshot {
                reason: "open time exceeds head time",
            });
        }
        if self.opened_at_ms == 0 || self.last_block_time_ms == 0 {
            return Err(V2Error::InvalidSnapshot {
                reason: "trusted block times must be positive",
            });
        }
        if self.pending_invoices.len() > ABSOLUTE_MAX_PENDING_INVOICES_V2 {
            return Err(V2Error::InvalidSnapshot {
                reason: "pending invoice set exceeds absolute bound",
            });
        }
        for (invoice_id, invoice) in &self.pending_invoices {
            if invoice_id != &invoice.invoice_id {
                return Err(V2Error::InvalidSnapshot {
                    reason: "pending invoice map key does not match record",
                });
            }
            if invoice.event.invoice_id != invoice.invoice_id
                || invoice.event.holder_step != invoice.holder_step
                || invoice.event.expires_at_ms != invoice.expires_at_ms
            {
                return Err(V2Error::InvalidSnapshot {
                    reason: "pending Invoice summary does not match its exact event",
                });
            }
            if invoice.created_at_ms > self.last_block_time_ms {
                return Err(V2Error::InvalidSnapshot {
                    reason: "pending invoice was created after the head",
                });
            }
            if invoice.created_at_ms == 0 {
                return Err(V2Error::InvalidSnapshot {
                    reason: "pending invoice has zero trusted block time",
                });
            }
            if invoice.holder_step != self.transfers_completed {
                return Err(V2Error::InvalidSnapshot {
                    reason: "pending invoice does not match the current Holder step",
                });
            }
            if invoice.expires_at_ms <= invoice.created_at_ms {
                return Err(V2Error::InvalidSnapshot {
                    reason: "pending invoice expiration does not follow creation",
                });
            }
            if invoice.is_expired_at(self.last_block_time_ms) {
                return Err(V2Error::InvalidSnapshot {
                    reason: "pending invoice is expired at the snapshot head",
                });
            }
        }
        if self.last_consumed_invoice_id.is_some() != (self.transfers_completed > 0) {
            return Err(V2Error::InvalidSnapshot {
                reason: "last consumed Invoice does not match the transfer count",
            });
        }
        match self.phase {
            ChannelPhaseV2::Active if self.finalized_at_ms.is_some() => Err(V2Error::InvalidSnapshot {
                reason: "active state contains a finalization time",
            }),
            ChannelPhaseV2::Finalized => {
                if !self.pending_invoices.is_empty() {
                    return Err(V2Error::InvalidSnapshot {
                        reason: "finalized state retains pending invoices",
                    });
                }
                if self.finalized_at_ms != Some(self.last_block_time_ms) {
                    return Err(V2Error::InvalidSnapshot {
                        reason: "finalization time must equal head time",
                    });
                }
                Ok(())
            }
            ChannelPhaseV2::Active => Ok(()),
        }
    }
}

pub(crate) fn validate_capacity(capacity_sat: u64) -> Result<(), V2Error> {
    if capacity_sat == 0 || capacity_sat > MAX_BITCOIN_SUPPLY_SAT {
        return Err(V2Error::InvalidCapacity { capacity_sat });
    }
    Ok(())
}

pub(crate) fn validate_committee_topology(member_count: u16, threshold: u16) -> Result<(), V2Error> {
    if member_count == 0 || member_count > MAX_COMMITTEE_MEMBERS_V2 || threshold == 0 || threshold > member_count {
        return Err(V2Error::InvalidCommitteeTopology);
    }
    Ok(())
}

/// Structured version-two validation and reduction failure.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum V2Error {
    /// A canonical state hash was malformed.
    #[error("invalid v2 state hash: expected 64 lowercase hexadecimal characters")]
    InvalidStateHash,
    /// An event exceeded Ledger bounds or lacked canonical encoding.
    #[error("invalid canonical v2 event")]
    InvalidCanonicalEvent,
    /// An authenticated proposal's event bytes or discriminant did not match.
    #[error("typed event does not exactly match authenticated proposal bytes")]
    AuthenticatedEventMismatch,
    /// The supplied proposal could not produce an authenticated capability.
    #[error("proposal authentication failed")]
    ProposalAuthenticationFailed,
    /// Proposal was not found at the claimed consensus block position.
    #[error("proposal is not present at the claimed consensus block position")]
    ProposalNotInConsensusBlock,
    /// Proposal or snapshot belongs to another consensus Ledger chain.
    #[error("Ledger chain id does not match the configured reducer")]
    LedgerChainMismatch,
    /// An entry or snapshot used a schema other than version two.
    #[error("unsupported protocol version {found}; v2 reducer accepts version 2")]
    UnsupportedProtocolVersion { found: u16 },
    /// Reducer resource limits are inconsistent.
    #[error("invalid v2 protocol limits: {reason}")]
    InvalidLimits { reason: &'static str },
    /// Channel capacity is outside Bitcoin's monetary range.
    #[error("invalid channel capacity {capacity_sat} sat")]
    InvalidCapacity { capacity_sat: u64 },
    /// Committee member count and threshold violate public bounds.
    #[error("invalid v2 committee topology")]
    InvalidCommitteeTopology,
    /// Proposal binding differs from the immutable channel binding.
    #[error("authenticated proposal does not match the channel binding")]
    BindingMismatch,
    /// The first committed event was not Open at sequence zero.
    #[error("channel does not exist; first v2 entry must be Open at sequence 0")]
    ChannelNotOpen,
    /// Open was proposed for an existing channel.
    #[error("channel is already open")]
    ChannelAlreadyOpen,
    /// Entry sequence is behind the next expected value.
    #[error("stale sequence {found}; next expected sequence is {expected}")]
    StaleSequence { expected: u64, found: u64 },
    /// Entry sequence skips one or more committed events.
    #[error("sequence gap: expected {expected}, found {found}")]
    SequenceGap { expected: u64, found: u64 },
    /// The per-channel sequence can no longer advance.
    #[error("channel sequence is exhausted")]
    SequenceExhausted,
    /// Previous-entry hash does not extend the committed head.
    #[error("v2 predecessor hash does not extend the channel head")]
    ForkDetected,
    /// A retry key was reused for a different authenticated entry.
    #[error("v2 request-id conflict")]
    IdempotencyConflict,
    /// Trusted Ledger time moved backwards.
    #[error("trusted block time regressed from {previous_ms} to {proposed_ms}")]
    BlockTimeRegression { previous_ms: u64, proposed_ms: u64 },
    /// Consensus block time zero is outside the deployment time domain.
    #[error("trusted block time must be positive")]
    InvalidBlockTime,
    /// Authenticated actor role is not authorized for the event.
    #[error("authenticated actor role is not authorized for this event")]
    UnauthorizedRole,
    /// Authenticated actor is not the current Holder.
    #[error("authenticated actor is not the current Holder")]
    ActorMismatch,
    /// Invoice expiry did not strictly follow its trusted commit time.
    #[error("invoice expiration {expires_at_ms} must follow trusted block time {block_time_ms}")]
    InvalidInvoiceExpiration { block_time_ms: u64, expires_at_ms: u64 },
    /// Invoice lifetime exceeds configured admission policy.
    #[error("invoice lifetime {ttl_ms} ms exceeds limit {limit_ms} ms")]
    InvoiceTtlTooLong { ttl_ms: u64, limit_ms: u64 },
    /// Invoice was formed against a Holder step other than the current step.
    #[error("invoice Holder step {found} does not match current step {expected}")]
    InvoiceStepMismatch { expected: u64, found: u64 },
    /// Invoice identifier was already used in this channel's lifetime.
    #[error("invoice id has already been used in this channel")]
    InvoiceAlreadyUsed,
    /// Pending-invoice resource bound was reached.
    #[error("pending invoice limit {limit} reached")]
    PendingInvoiceLimitReached { limit: usize },
    /// Transfer did not reference a currently pending committed invoice.
    #[error("referenced invoice is not pending")]
    InvoiceNotPending,
    /// Transfer did not bind the exact committed Invoice entry.
    #[error("referenced Invoice entry hash does not match the pending record")]
    InvoiceEntryHashMismatch,
    /// Referenced invoice expired at trusted Ledger time.
    #[error("referenced invoice expired at {expires_at_ms}")]
    InvoiceExpired { expires_at_ms: u64 },
    /// Referenced invoice belongs to an earlier Holder step.
    #[error("referenced invoice belongs to Holder step {invoice_step}, current step is {current_step}")]
    StaleInvoice { invoice_step: u64, current_step: u64 },
    /// Transfer counter can no longer advance.
    #[error("transfer counter is exhausted")]
    TransferCounterExhausted,
    /// An event was proposed after finalization.
    #[error("channel is finalized")]
    ChannelFinalized,
    /// Configured entry bound was reached.
    #[error("channel entry limit {limit} reached")]
    EntryLimitReached { limit: u64 },
    /// A trusted external proof verifier rejected a typed request.
    #[error("trusted external verifier rejected {stage}")]
    ExternalVerificationRejected { stage: super::VerificationStageV2 },
    /// A supplied snapshot violates version-two invariants.
    #[error("invalid v2 channel snapshot: {reason}")]
    InvalidSnapshot { reason: &'static str },
}
