use crate::{
    ActorRole, Artifact, ChannelEvent, ChannelId, Committee, EntryHash, EventKind, InvoiceId, LedgerEntry,
    ParticipantId, ProtocolError, VerificationOutcome, PROTOCOL_VERSION,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// Default hard bound on entries in one channel log.
///
/// Deployments that need a different retention/safety policy can construct a
/// [`ProtocolLimits`] explicitly. Snapshots remain constant-size regardless.
pub const DEFAULT_MAX_ENTRIES_PER_CHANNEL: u64 = 1_000_000;

/// Default maximum verifier attestations on one event.
pub const DEFAULT_MAX_VERIFICATIONS_PER_EVENT: usize = 16;

/// Absolute defensive bound on verifier attestations accepted by this crate.
pub const ABSOLUTE_MAX_VERIFICATIONS_PER_EVENT: usize = 64;

/// Deterministic resource policy for channel reduction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProtocolLimits {
    /// Maximum total entries, including Open and Finalize.
    pub max_entries_per_channel: u64,
    /// Maximum verifier attestations in one event.
    pub max_verifications_per_event: usize,
}

impl ProtocolLimits {
    /// Validates and constructs reducer limits.
    pub fn new(max_entries_per_channel: u64, max_verifications_per_event: usize) -> Result<Self, ProtocolError> {
        let limits = Self {
            max_entries_per_channel,
            max_verifications_per_event,
        };
        limits.validate()?;
        Ok(limits)
    }

    fn validate(&self) -> Result<(), ProtocolError> {
        if self.max_entries_per_channel == 0 {
            return Err(ProtocolError::InvalidLimits {
                reason: "max_entries_per_channel must be positive",
            });
        }
        if self.max_verifications_per_event == 0 {
            return Err(ProtocolError::InvalidLimits {
                reason: "max_verifications_per_event must be positive",
            });
        }
        if self.max_verifications_per_event > ABSOLUTE_MAX_VERIFICATIONS_PER_EVENT {
            return Err(ProtocolError::InvalidLimits {
                reason: "max_verifications_per_event exceeds the absolute safety bound",
            });
        }
        Ok(())
    }
}

impl Default for ProtocolLimits {
    fn default() -> Self {
        Self {
            max_entries_per_channel: DEFAULT_MAX_ENTRIES_PER_CHANNEL,
            max_verifications_per_event: DEFAULT_MAX_VERIFICATIONS_PER_EVENT,
        }
    }
}

/// Indexed history facts needed for bounded-memory reduction.
///
/// Storage must derive these facts from the same channel and within the same
/// append transaction. This keeps [`ChannelSnapshot`] O(1) while making
/// idempotency keys and invoice ids unique for the full channel lifetime.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HistoryContext {
    /// Hash already associated with this entry's idempotency key, if any.
    pub existing_idempotency_hash: Option<EntryHash>,
    /// Whether an Invoice event already created this entry's invoice id.
    pub invoice_id_already_used: bool,
    /// Timestamp assigned by the trusted ledger when it evaluates this entry.
    pub ledger_time_ms: u64,
}

impl HistoryContext {
    /// Constructs history facts returned by indexed storage lookups.
    pub const fn new(
        existing_idempotency_hash: Option<EntryHash>,
        invoice_id_already_used: bool,
        ledger_time_ms: u64,
    ) -> Self {
        Self {
            existing_idempotency_hash,
            invoice_id_already_used,
            ledger_time_ms,
        }
    }

    /// History facts for a new key and, when applicable, a new invoice id.
    pub const fn empty(ledger_time_ms: u64) -> Self {
        Self::new(None, false, ledger_time_ms)
    }
}

/// Observable lifecycle phase after a committed entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChannelPhase {
    /// Funded and ready to accept an invoice; no transfer has completed yet.
    Open,
    /// Exactly one live invoice is waiting for the current holder.
    InvoicePending,
    /// At least one transfer completed and the channel can accept another invoice.
    TransferComplete,
    /// The holder and committee finalized the UTXO on Bitcoin.
    Finalized,
}

/// Constant-size projection of the one pending invoice.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PendingInvoice {
    /// Channel-lifetime-unique invoice id.
    pub invoice_id: InvoiceId,
    /// Prospective next holder.
    pub recipient: ParticipantId,
    /// Ledger timestamp that created the invoice.
    pub created_at_ms: u64,
    /// Optional exclusive expiry.
    pub expires_at_ms: Option<u64>,
}

impl PendingInvoice {
    fn is_expired_at(&self, occurred_at_ms: u64) -> bool {
        self.expires_at_ms
            .is_some_and(|expires_at_ms| occurred_at_ms >= expires_at_ms)
    }
}

/// Constant-size materialized state for one channel head.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChannelSnapshot {
    /// Protocol schema version.
    pub protocol_version: u16,
    /// Funding outpoint and channel identity.
    pub channel_id: ChannelId,
    /// Current lifecycle phase.
    pub phase: ChannelPhase,
    /// Whole-UTXO capacity fixed at Open.
    pub capacity_sat: u64,
    /// Committee configuration fixed at Open.
    pub committee: Committee,
    /// Fixed public Bitcoin lock key `P`.
    pub lock_key: Artifact,
    /// Current holder identity.
    pub current_holder: ParticipantId,
    /// Current public holder anchor `X_s`.
    pub current_holder_anchor: Artifact,
    /// Current encrypted holder credential `T_s`.
    pub current_holder_ciphertext: Artifact,
    /// Number of completed off-chain ownership transfers.
    pub transfers_completed: u64,
    /// The only pending invoice, if any.
    pub pending_invoice: Option<PendingInvoice>,
    /// Sequence of the current head.
    pub last_sequence: u64,
    /// Canonical hash of the current head entry.
    pub head_hash: EntryHash,
    /// Externally supplied Open timestamp.
    pub opened_at_ms: u64,
    /// Externally supplied timestamp of the current head.
    pub last_occurred_at_ms: u64,
    /// Externally supplied Finalize timestamp.
    pub finalized_at_ms: Option<u64>,
}

impl ChannelSnapshot {
    /// Returns the next sequence or a structured exhaustion error.
    pub fn next_sequence(&self) -> Result<u64, ProtocolError> {
        self.last_sequence
            .checked_add(1)
            .ok_or(ProtocolError::SequenceExhausted)
    }

    /// Checks internal invariants before a snapshot is used as reducer input.
    pub fn validate(&self) -> Result<(), ProtocolError> {
        if self.protocol_version != PROTOCOL_VERSION {
            return Err(ProtocolError::UnsupportedProtocolVersion {
                found: self.protocol_version,
                supported: PROTOCOL_VERSION,
            });
        }
        self.committee.validate()?;
        validate_capacity(self.capacity_sat)?;
        if self.opened_at_ms > self.last_occurred_at_ms {
            return Err(ProtocolError::InvalidSnapshot {
                reason: "opened_at_ms exceeds last_occurred_at_ms",
            });
        }
        if let Some(invoice) = &self.pending_invoice {
            if invoice.created_at_ms > self.last_occurred_at_ms {
                return Err(ProtocolError::InvalidSnapshot {
                    reason: "pending invoice was created after the snapshot head",
                });
            }
            if invoice
                .expires_at_ms
                .is_some_and(|expires_at_ms| expires_at_ms <= invoice.created_at_ms)
            {
                return Err(ProtocolError::InvalidSnapshot {
                    reason: "pending invoice expiration does not follow creation",
                });
            }
        }

        match self.phase {
            ChannelPhase::Open => {
                if self.pending_invoice.is_some() || self.finalized_at_ms.is_some() || self.transfers_completed != 0 {
                    return Err(ProtocolError::InvalidSnapshot {
                        reason: "Open phase has incompatible pending/finalized/transfer state",
                    });
                }
            }
            ChannelPhase::InvoicePending => {
                if self.pending_invoice.is_none() || self.finalized_at_ms.is_some() {
                    return Err(ProtocolError::InvalidSnapshot {
                        reason: "InvoicePending phase requires one invoice and no finalization",
                    });
                }
            }
            ChannelPhase::TransferComplete => {
                if self.pending_invoice.is_some() || self.finalized_at_ms.is_some() || self.transfers_completed == 0 {
                    return Err(ProtocolError::InvalidSnapshot {
                        reason: "TransferComplete phase requires completed transfer state",
                    });
                }
            }
            ChannelPhase::Finalized => {
                if self.pending_invoice.is_some() || self.finalized_at_ms.is_none() {
                    return Err(ProtocolError::InvalidSnapshot {
                        reason: "Finalized phase requires finalization and no pending invoice",
                    });
                }
                if self
                    .finalized_at_ms
                    .is_some_and(|finalized_at_ms| finalized_at_ms != self.last_occurred_at_ms)
                {
                    return Err(ProtocolError::InvalidSnapshot {
                        reason: "finalized_at_ms must equal the head timestamp",
                    });
                }
            }
        }
        Ok(())
    }
}

/// Whether a reduction appended a new entry or recognized an exact retry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApplyDisposition {
    /// A new entry advanced the channel head.
    Applied,
    /// The same idempotency key and canonical entry hash were already present.
    Replay,
}

/// Result of deterministic reduction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reduction {
    /// Derived state. On replay this is an unchanged clone of the input.
    pub snapshot: ChannelSnapshot,
    /// Whether storage should insert the entry.
    pub disposition: ApplyDisposition,
}

/// Pure deterministic channel state reducer.
#[derive(Debug, Clone)]
pub struct ChannelReducer {
    limits: ProtocolLimits,
}

impl ChannelReducer {
    /// Constructs a reducer under validated limits.
    pub fn new(limits: ProtocolLimits) -> Result<Self, ProtocolError> {
        limits.validate()?;
        Ok(Self { limits })
    }

    /// Returns the reducer's immutable resource policy.
    pub const fn limits(&self) -> ProtocolLimits {
        self.limits
    }

    /// Applies one entry to an optional channel head.
    ///
    /// `history` must be queried for `entry.channel_id` and
    /// `entry.idempotency_key` (plus `created_invoice_id`, when present) in the
    /// same atomic append transaction. No I/O, time, randomness, signatures,
    /// or cryptographic proof verification occurs here.
    pub fn apply(
        &self,
        current: Option<&ChannelSnapshot>,
        entry: &LedgerEntry,
        history: HistoryContext,
    ) -> Result<Reduction, ProtocolError> {
        validate_version(entry.protocol_version)?;

        if let Some(snapshot) = current {
            snapshot.validate()?;
            if snapshot.channel_id != entry.channel_id {
                return Err(ProtocolError::ChannelMismatch {
                    expected: snapshot.channel_id,
                    found: entry.channel_id,
                });
            }
        }

        let proposed_hash = entry.entry_hash();
        if let Some(existing_hash) = history.existing_idempotency_hash {
            if existing_hash == proposed_hash {
                let snapshot = current.ok_or(ProtocolError::InvalidSnapshot {
                    reason: "idempotent replay exists without a current snapshot",
                })?;
                return Ok(Reduction {
                    snapshot: snapshot.clone(),
                    disposition: ApplyDisposition::Replay,
                });
            }
            return Err(ProtocolError::IdempotencyConflict {
                key: entry.idempotency_key.clone(),
                existing: existing_hash,
                proposed: proposed_hash,
            });
        }

        match current {
            None => self.open(entry, proposed_hash, history.ledger_time_ms),
            Some(snapshot) => self.advance(snapshot, entry, proposed_hash, history),
        }
    }

    fn open(
        &self,
        entry: &LedgerEntry,
        entry_hash: EntryHash,
        ledger_time_ms: u64,
    ) -> Result<Reduction, ProtocolError> {
        if entry.sequence != 0 {
            return Err(ProtocolError::ChannelNotOpen);
        }
        if entry.previous_entry_hash != EntryHash::ZERO {
            return Err(ProtocolError::ForkDetected {
                expected: EntryHash::ZERO,
                found: entry.previous_entry_hash,
            });
        }
        let ChannelEvent::Open(event) = &entry.event else {
            return Err(ProtocolError::ChannelNotOpen);
        };

        require_actor(entry, ActorRole::Holder, &event.initial_holder, "initial holder")?;
        validate_capacity(event.capacity_sat)?;
        event.committee.validate()?;
        validate_entry_time(entry, ledger_time_ms)?;
        self.validate_verification(entry, ledger_time_ms)?;

        Ok(Reduction {
            snapshot: ChannelSnapshot {
                protocol_version: PROTOCOL_VERSION,
                channel_id: entry.channel_id,
                phase: ChannelPhase::Open,
                capacity_sat: event.capacity_sat,
                committee: event.committee.clone(),
                lock_key: event.lock_key.clone(),
                current_holder: event.initial_holder.clone(),
                current_holder_anchor: event.initial_holder_anchor.clone(),
                current_holder_ciphertext: event.initial_holder_ciphertext.clone(),
                transfers_completed: 0,
                pending_invoice: None,
                last_sequence: 0,
                head_hash: entry_hash,
                opened_at_ms: ledger_time_ms,
                last_occurred_at_ms: ledger_time_ms,
                finalized_at_ms: None,
            },
            disposition: ApplyDisposition::Applied,
        })
    }

    fn advance(
        &self,
        current: &ChannelSnapshot,
        entry: &LedgerEntry,
        entry_hash: EntryHash,
        history: HistoryContext,
    ) -> Result<Reduction, ProtocolError> {
        let expected_sequence = current.next_sequence()?;
        if entry.sequence < expected_sequence {
            return Err(ProtocolError::StaleSequence {
                expected: expected_sequence,
                found: entry.sequence,
            });
        }
        if entry.sequence > expected_sequence {
            return Err(ProtocolError::SequenceGap {
                expected: expected_sequence,
                found: entry.sequence,
            });
        }
        if entry.previous_entry_hash != current.head_hash {
            return Err(ProtocolError::ForkDetected {
                expected: current.head_hash,
                found: entry.previous_entry_hash,
            });
        }
        validate_entry_time(entry, history.ledger_time_ms)?;
        if history.ledger_time_ms < current.last_occurred_at_ms {
            return Err(ProtocolError::TimestampRegression {
                previous_ms: current.last_occurred_at_ms,
                proposed_ms: history.ledger_time_ms,
            });
        }
        if expected_sequence >= self.limits.max_entries_per_channel {
            return Err(ProtocolError::EntryLimitReached {
                limit: self.limits.max_entries_per_channel,
            });
        }
        if current.phase == ChannelPhase::Finalized {
            return Err(ProtocolError::ChannelFinalized);
        }
        self.validate_verification(entry, history.ledger_time_ms)?;

        let mut next = current.clone();
        match &entry.event {
            ChannelEvent::Open(_) => return Err(ProtocolError::ChannelAlreadyOpen),
            ChannelEvent::Invoice(event) => {
                require_actor(entry, ActorRole::Recipient, &event.recipient, "invoice recipient")?;
                if history.invoice_id_already_used {
                    return Err(ProtocolError::InvoiceAlreadyUsed {
                        invoice_id: event.invoice_id.clone(),
                    });
                }
                if let Some(expires_at_ms) = event.expires_at_ms {
                    if expires_at_ms <= history.ledger_time_ms {
                        return Err(ProtocolError::InvalidInvoiceExpiration {
                            entry_at_ms: history.ledger_time_ms,
                            expires_at_ms,
                        });
                    }
                }
                if let Some(pending) = &current.pending_invoice {
                    if !pending.is_expired_at(history.ledger_time_ms) {
                        return Err(ProtocolError::PendingInvoiceExists {
                            invoice_id: pending.invoice_id.clone(),
                        });
                    }
                }
                next.phase = ChannelPhase::InvoicePending;
                next.pending_invoice = Some(PendingInvoice {
                    invoice_id: event.invoice_id.clone(),
                    recipient: event.recipient.clone(),
                    created_at_ms: history.ledger_time_ms,
                    expires_at_ms: event.expires_at_ms,
                });
            }
            ChannelEvent::Transfer(event) => {
                require_actor(entry, ActorRole::Holder, &event.sender, "transfer sender")?;
                if event.sender != current.current_holder {
                    return Err(ProtocolError::ActorMismatch {
                        event: EventKind::Transfer,
                        expected_participant: "current holder",
                    });
                }
                let pending = current
                    .pending_invoice
                    .as_ref()
                    .ok_or(ProtocolError::NoPendingInvoice)?;
                if pending.invoice_id != event.invoice_id {
                    return Err(ProtocolError::InvoiceMismatch {
                        expected: pending.invoice_id.clone(),
                        found: event.invoice_id.clone(),
                    });
                }
                if pending.recipient != event.recipient {
                    return Err(ProtocolError::ActorMismatch {
                        event: EventKind::Transfer,
                        expected_participant: "pending invoice recipient",
                    });
                }
                if pending.is_expired_at(history.ledger_time_ms) {
                    return Err(ProtocolError::InvoiceExpired {
                        invoice_id: pending.invoice_id.clone(),
                        expires_at_ms: pending.expires_at_ms.ok_or(ProtocolError::InvalidSnapshot {
                            reason: "expired pending invoice has no expiration",
                        })?,
                    });
                }
                next.transfers_completed = current
                    .transfers_completed
                    .checked_add(1)
                    .ok_or(ProtocolError::TransferCounterExhausted)?;
                next.current_holder = event.recipient.clone();
                next.current_holder_anchor = event.next_holder_anchor.clone();
                next.current_holder_ciphertext = event.next_holder_ciphertext.clone();
                next.pending_invoice = None;
                next.phase = ChannelPhase::TransferComplete;
            }
            ChannelEvent::Finalize(event) => {
                require_actor(entry, ActorRole::Holder, &event.holder, "final holder")?;
                if event.holder != current.current_holder {
                    return Err(ProtocolError::ActorMismatch {
                        event: EventKind::Finalize,
                        expected_participant: "current holder",
                    });
                }
                if let Some(pending) = &current.pending_invoice {
                    if !pending.is_expired_at(history.ledger_time_ms) {
                        return Err(ProtocolError::PendingInvoiceBlocksFinalization {
                            invoice_id: pending.invoice_id.clone(),
                        });
                    }
                }
                next.pending_invoice = None;
                next.phase = ChannelPhase::Finalized;
                next.finalized_at_ms = Some(history.ledger_time_ms);
            }
        }

        next.last_sequence = entry.sequence;
        next.head_hash = entry_hash;
        next.last_occurred_at_ms = history.ledger_time_ms;
        next.validate()?;
        Ok(Reduction {
            snapshot: next,
            disposition: ApplyDisposition::Applied,
        })
    }

    fn validate_verification(&self, entry: &LedgerEntry, ledger_time_ms: u64) -> Result<(), ProtocolError> {
        let evidence = entry.event.verification();
        if evidence.len() > self.limits.max_verifications_per_event {
            return Err(ProtocolError::TooManyVerifications {
                limit: self.limits.max_verifications_per_event,
                found: evidence.len(),
            });
        }

        let event = entry.event.kind();
        let mut seen = BTreeSet::new();
        for item in evidence {
            if !seen.insert(item.kind) {
                return Err(ProtocolError::DuplicateVerification {
                    event,
                    verification: item.kind,
                });
            }
            if item.outcome != VerificationOutcome::Verified {
                return Err(ProtocolError::VerificationRejected {
                    event,
                    verification: item.kind,
                });
            }
            if item.verified_at_ms > ledger_time_ms {
                return Err(ProtocolError::VerificationFromFuture {
                    verified_at_ms: item.verified_at_ms,
                    entry_at_ms: ledger_time_ms,
                });
            }
        }
        for required in entry.event.required_verifications() {
            if !seen.contains(required) {
                return Err(ProtocolError::MissingVerification {
                    event,
                    verification: *required,
                });
            }
        }
        Ok(())
    }
}

impl Default for ChannelReducer {
    fn default() -> Self {
        Self::new(ProtocolLimits::default()).expect("default protocol limits are valid")
    }
}

fn validate_entry_time(entry: &LedgerEntry, ledger_time_ms: u64) -> Result<(), ProtocolError> {
    if entry.occurred_at_ms > ledger_time_ms {
        return Err(ProtocolError::EventFromFuture {
            event_at_ms: entry.occurred_at_ms,
            ledger_at_ms: ledger_time_ms,
        });
    }
    Ok(())
}

fn validate_version(found: u16) -> Result<(), ProtocolError> {
    if found != PROTOCOL_VERSION {
        return Err(ProtocolError::UnsupportedProtocolVersion {
            found,
            supported: PROTOCOL_VERSION,
        });
    }
    Ok(())
}

fn validate_capacity(capacity_sat: u64) -> Result<(), ProtocolError> {
    if capacity_sat == 0 || capacity_sat > crate::event::MAX_BITCOIN_SUPPLY_SAT {
        return Err(ProtocolError::InvalidCapacity { capacity_sat });
    }
    Ok(())
}

fn require_actor(
    entry: &LedgerEntry,
    required_role: ActorRole,
    required_participant: &ParticipantId,
    expected_participant: &'static str,
) -> Result<(), ProtocolError> {
    let event = entry.event.kind();
    if entry.actor.role != required_role {
        return Err(ProtocolError::UnauthorizedRole {
            event,
            expected: required_role,
            found: entry.actor.role,
        });
    }
    if &entry.actor.participant_id != required_participant {
        return Err(ProtocolError::ActorMismatch {
            event,
            expected_participant,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        Actor, BitcoinTxid, ChannelId, Digest, FinalizeEvent, IdempotencyKey, ImplementationId, InvoiceEvent,
        OpenEvent, TransferEvent, VerificationEvidence, VerificationKind,
    };

    fn participant(value: &str) -> ParticipantId {
        ParticipantId::new(value).unwrap()
    }

    fn artifact(byte: u8) -> Artifact {
        Artifact::new([byte]).unwrap()
    }

    fn channel(byte: u8) -> ChannelId {
        ChannelId::new(BitcoinTxid::from_bytes([byte; 32]), 0)
    }

    fn evidence(kind: VerificationKind, at: u64) -> VerificationEvidence {
        VerificationEvidence::verified(
            kind,
            participant("verifier:local"),
            ImplementationId::new("thunderbolt-node/1.0.0").unwrap(),
            Digest::from_bytes([kind as u8 + 1; 32]),
            at,
        )
    }

    fn required_evidence(event: EventKind, at: u64) -> Vec<VerificationEvidence> {
        let kinds: &[VerificationKind] = match event {
            EventKind::Open => &[
                VerificationKind::FundingTransaction,
                VerificationKind::InitialState,
                VerificationKind::CommitteeQuorum,
            ],
            EventKind::Invoice => &[VerificationKind::InvoiceConsistencyProof],
            EventKind::Transfer => &[
                VerificationKind::TransferConsistencyProof,
                VerificationKind::AnchorTransition,
            ],
            EventKind::Finalize => &[
                VerificationKind::HolderOwnershipProof,
                VerificationKind::CommitteeQuorum,
                VerificationKind::ClosingTransaction,
            ],
        };
        kinds.iter().map(|kind| evidence(*kind, at)).collect()
    }

    fn open_entry(channel_id: ChannelId, at: u64) -> LedgerEntry {
        let holder = participant("holder:0");
        LedgerEntry::new(
            channel_id,
            0,
            EntryHash::ZERO,
            IdempotencyKey::new("open-0").unwrap(),
            Actor::new(holder.clone(), ActorRole::Holder),
            at,
            ChannelEvent::Open(OpenEvent {
                initial_holder: holder,
                committee: Committee::new(participant("committee:main"), 5, 3).unwrap(),
                capacity_sat: 1_000_000,
                lock_key: artifact(1),
                initial_holder_anchor: artifact(2),
                initial_holder_ciphertext: artifact(3),
                verification: required_evidence(EventKind::Open, at),
            }),
        )
    }

    fn invoice_entry(
        snapshot: &ChannelSnapshot,
        invoice: &str,
        recipient: &str,
        at: u64,
        expires_at_ms: Option<u64>,
    ) -> LedgerEntry {
        let recipient = participant(recipient);
        LedgerEntry::new(
            snapshot.channel_id,
            snapshot.next_sequence().unwrap(),
            snapshot.head_hash,
            IdempotencyKey::new(format!("invoice-{invoice}")).unwrap(),
            Actor::new(recipient.clone(), ActorRole::Recipient),
            at,
            ChannelEvent::Invoice(InvoiceEvent {
                invoice_id: InvoiceId::new(invoice).unwrap(),
                recipient,
                recipient_encryption_key: artifact(4),
                public_delta: artifact(5),
                recipient_ciphertext: artifact(6),
                committee_package: artifact(7),
                invoice_proof: artifact(8),
                expires_at_ms,
                verification: required_evidence(EventKind::Invoice, at),
            }),
        )
    }

    fn transfer_entry(snapshot: &ChannelSnapshot, invoice: &str, recipient: &str, at: u64) -> LedgerEntry {
        LedgerEntry::new(
            snapshot.channel_id,
            snapshot.next_sequence().unwrap(),
            snapshot.head_hash,
            IdempotencyKey::new(format!("transfer-{invoice}")).unwrap(),
            Actor::new(snapshot.current_holder.clone(), ActorRole::Holder),
            at,
            ChannelEvent::Transfer(TransferEvent {
                invoice_id: InvoiceId::new(invoice).unwrap(),
                sender: snapshot.current_holder.clone(),
                recipient: participant(recipient),
                next_holder_anchor: artifact(9),
                next_holder_ciphertext: artifact(10),
                transfer_proof: artifact(11),
                verification: required_evidence(EventKind::Transfer, at),
            }),
        )
    }

    fn finalize_entry(snapshot: &ChannelSnapshot, at: u64) -> LedgerEntry {
        LedgerEntry::new(
            snapshot.channel_id,
            snapshot.next_sequence().unwrap(),
            snapshot.head_hash,
            IdempotencyKey::new("finalize-0").unwrap(),
            Actor::new(snapshot.current_holder.clone(), ActorRole::Holder),
            at,
            ChannelEvent::Finalize(FinalizeEvent {
                holder: snapshot.current_holder.clone(),
                closing_txid: BitcoinTxid::from_bytes([0xee; 32]),
                ownership_proof: artifact(12),
                committee_attestation: artifact(13),
                verification: required_evidence(EventKind::Finalize, at),
            }),
        )
    }

    fn apply_new(reducer: &ChannelReducer, snapshot: Option<&ChannelSnapshot>, entry: &LedgerEntry) -> ChannelSnapshot {
        let reduction = reducer
            .apply(snapshot, entry, HistoryContext::empty(entry.occurred_at_ms))
            .unwrap();
        assert_eq!(reduction.disposition, ApplyDisposition::Applied);
        reduction.snapshot
    }

    #[test]
    fn complete_lifecycle_is_deterministic() {
        let reducer = ChannelReducer::default();
        let open = open_entry(channel(1), 1_000);
        let state0 = apply_new(&reducer, None, &open);
        assert_eq!(state0.phase, ChannelPhase::Open);

        let invoice = invoice_entry(&state0, "inv-1", "holder:1", 2_000, None);
        let state1 = apply_new(&reducer, Some(&state0), &invoice);
        assert_eq!(state1.phase, ChannelPhase::InvoicePending);

        let transfer = transfer_entry(&state1, "inv-1", "holder:1", 3_000);
        let state2 = apply_new(&reducer, Some(&state1), &transfer);
        assert_eq!(state2.phase, ChannelPhase::TransferComplete);
        assert_eq!(state2.current_holder, participant("holder:1"));
        assert_eq!(state2.transfers_completed, 1);
        assert!(state2.pending_invoice.is_none());

        let finalize = finalize_entry(&state2, 4_000);
        let state3 = apply_new(&reducer, Some(&state2), &finalize);
        assert_eq!(state3.phase, ChannelPhase::Finalized);
        assert_eq!(state3.finalized_at_ms, Some(4_000));
        assert_eq!(state3.last_sequence, 3);

        let state3_again = reducer
            .apply(Some(&state2), &finalize, HistoryContext::empty(finalize.occurred_at_ms))
            .unwrap()
            .snapshot;
        assert_eq!(state3, state3_again);
    }

    #[test]
    fn exact_idempotent_replay_returns_current_state_without_reapplying() {
        let reducer = ChannelReducer::default();
        let open = open_entry(channel(2), 10);
        let state = apply_new(&reducer, None, &open);
        let invoice = invoice_entry(&state, "inv-a", "holder:a", 11, None);
        let after_invoice = apply_new(&reducer, Some(&state), &invoice);

        let replay = reducer
            .apply(
                Some(&after_invoice),
                &invoice,
                HistoryContext::new(Some(invoice.entry_hash()), true, invoice.occurred_at_ms),
            )
            .unwrap();
        assert_eq!(replay.disposition, ApplyDisposition::Replay);
        assert_eq!(replay.snapshot, after_invoice);
    }

    #[test]
    fn same_idempotency_key_with_different_entry_is_a_conflict() {
        let reducer = ChannelReducer::default();
        let open = open_entry(channel(3), 10);
        let state = apply_new(&reducer, None, &open);
        let mut invoice = invoice_entry(&state, "inv-a", "holder:a", 11, None);
        let existing_hash = invoice.entry_hash();
        invoice.occurred_at_ms = 12;

        assert!(matches!(
            reducer.apply(
                Some(&state),
                &invoice,
                HistoryContext::new(Some(existing_hash), false, invoice.occurred_at_ms),
            ),
            Err(ProtocolError::IdempotencyConflict { .. })
        ));
    }

    #[test]
    fn ordering_rejects_stale_gap_and_fork_entries() {
        let reducer = ChannelReducer::default();
        let open = open_entry(channel(4), 10);
        let state = apply_new(&reducer, None, &open);
        let invoice = invoice_entry(&state, "inv-a", "holder:a", 11, None);

        let mut stale = invoice.clone();
        stale.sequence = 0;
        assert!(matches!(
            reducer.apply(Some(&state), &stale, HistoryContext::empty(stale.occurred_at_ms),),
            Err(ProtocolError::StaleSequence { .. })
        ));

        let mut gap = invoice.clone();
        gap.sequence = 2;
        assert!(matches!(
            reducer.apply(Some(&state), &gap, HistoryContext::empty(gap.occurred_at_ms)),
            Err(ProtocolError::SequenceGap { .. })
        ));

        let mut fork = invoice;
        fork.previous_entry_hash = EntryHash::from_bytes([0x55; 32]);
        assert!(matches!(
            reducer.apply(Some(&state), &fork, HistoryContext::empty(fork.occurred_at_ms),),
            Err(ProtocolError::ForkDetected { .. })
        ));
    }

    #[test]
    fn one_pending_invoice_and_lifetime_unique_invoice_ids_are_enforced() {
        let reducer = ChannelReducer::default();
        let open = open_entry(channel(5), 10);
        let state0 = apply_new(&reducer, None, &open);
        let first = invoice_entry(&state0, "inv-a", "holder:a", 11, None);
        let state1 = apply_new(&reducer, Some(&state0), &first);
        let second = invoice_entry(&state1, "inv-b", "holder:b", 12, None);
        assert!(matches!(
            reducer.apply(Some(&state1), &second, HistoryContext::empty(second.occurred_at_ms),),
            Err(ProtocolError::PendingInvoiceExists { .. })
        ));

        let transfer = transfer_entry(&state1, "inv-a", "holder:a", 13);
        let state2 = apply_new(&reducer, Some(&state1), &transfer);
        let reused = invoice_entry(&state2, "inv-a", "holder:a", 14, None);
        assert!(matches!(
            reducer.apply(
                Some(&state2),
                &reused,
                HistoryContext::new(None, true, reused.occurred_at_ms),
            ),
            Err(ProtocolError::InvoiceAlreadyUsed { .. })
        ));
    }

    #[test]
    fn expired_invoice_can_be_replaced_but_not_transferred() {
        let reducer = ChannelReducer::default();
        let open = open_entry(channel(6), 10);
        let state0 = apply_new(&reducer, None, &open);
        let invoice = invoice_entry(&state0, "inv-a", "holder:a", 11, Some(20));
        let state1 = apply_new(&reducer, Some(&state0), &invoice);

        let expired_transfer = transfer_entry(&state1, "inv-a", "holder:a", 20);
        assert!(matches!(
            reducer.apply(
                Some(&state1),
                &expired_transfer,
                HistoryContext::empty(expired_transfer.occurred_at_ms),
            ),
            Err(ProtocolError::InvoiceExpired { .. })
        ));

        let replacement = invoice_entry(&state1, "inv-b", "holder:b", 20, None);
        let state2 = apply_new(&reducer, Some(&state1), &replacement);
        assert_eq!(
            state2.pending_invoice.as_ref().unwrap().invoice_id,
            InvoiceId::new("inv-b").unwrap()
        );
    }

    #[test]
    fn live_invoice_blocks_finalization_but_expired_invoice_does_not() {
        let reducer = ChannelReducer::default();
        let open = open_entry(channel(7), 10);
        let state0 = apply_new(&reducer, None, &open);
        let invoice = invoice_entry(&state0, "inv-a", "holder:a", 11, Some(20));
        let state1 = apply_new(&reducer, Some(&state0), &invoice);

        let early = finalize_entry(&state1, 19);
        assert!(matches!(
            reducer.apply(Some(&state1), &early, HistoryContext::empty(early.occurred_at_ms),),
            Err(ProtocolError::PendingInvoiceBlocksFinalization { .. })
        ));

        let on_expiry = finalize_entry(&state1, 20);
        let finalized = apply_new(&reducer, Some(&state1), &on_expiry);
        assert_eq!(finalized.phase, ChannelPhase::Finalized);
    }

    #[test]
    fn caller_timestamp_cannot_expire_an_invoice_ahead_of_ledger_time() {
        let reducer = ChannelReducer::default();
        let open = open_entry(channel(17), 10);
        let state0 = apply_new(&reducer, None, &open);
        let invoice = invoice_entry(&state0, "inv-a", "holder:a", 11, Some(20));
        let state1 = apply_new(&reducer, Some(&state0), &invoice);

        let forged_future = finalize_entry(&state1, 20);
        assert!(matches!(
            reducer.apply(Some(&state1), &forged_future, HistoryContext::empty(12),),
            Err(ProtocolError::EventFromFuture { .. })
        ));

        let committed_at_expiry = finalize_entry(&state1, 12);
        let finalized = reducer
            .apply(Some(&state1), &committed_at_expiry, HistoryContext::empty(20))
            .unwrap();
        assert_eq!(finalized.snapshot.phase, ChannelPhase::Finalized);
    }

    #[test]
    fn finalize_requires_closing_transaction_verification() {
        let reducer = ChannelReducer::default();
        let open = open_entry(channel(18), 10);
        let state = apply_new(&reducer, None, &open);
        let mut finalize = finalize_entry(&state, 11);
        let ChannelEvent::Finalize(event) = &mut finalize.event else {
            unreachable!()
        };
        event
            .verification
            .retain(|evidence| evidence.kind != VerificationKind::ClosingTransaction);

        assert!(matches!(
            reducer.apply(Some(&state), &finalize, HistoryContext::empty(finalize.occurred_at_ms),),
            Err(ProtocolError::MissingVerification {
                verification: VerificationKind::ClosingTransaction,
                ..
            })
        ));
    }

    #[test]
    fn missing_rejected_duplicate_and_future_evidence_are_rejected() {
        let reducer = ChannelReducer::default();
        let mut entry = open_entry(channel(8), 10);
        let ChannelEvent::Open(event) = &mut entry.event else {
            unreachable!()
        };
        event.verification.pop();
        assert!(matches!(
            reducer.apply(None, &entry, HistoryContext::empty(entry.occurred_at_ms)),
            Err(ProtocolError::MissingVerification { .. })
        ));

        let mut entry = open_entry(channel(8), 10);
        let ChannelEvent::Open(event) = &mut entry.event else {
            unreachable!()
        };
        event.verification[0].outcome = VerificationOutcome::Rejected;
        assert!(matches!(
            reducer.apply(None, &entry, HistoryContext::empty(entry.occurred_at_ms)),
            Err(ProtocolError::VerificationRejected { .. })
        ));

        let mut entry = open_entry(channel(8), 10);
        let ChannelEvent::Open(event) = &mut entry.event else {
            unreachable!()
        };
        event.verification.push(event.verification[0].clone());
        assert!(matches!(
            reducer.apply(None, &entry, HistoryContext::empty(entry.occurred_at_ms)),
            Err(ProtocolError::DuplicateVerification { .. })
        ));

        let mut entry = open_entry(channel(8), 10);
        let ChannelEvent::Open(event) = &mut entry.event else {
            unreachable!()
        };
        event.verification[0].verified_at_ms = 11;
        assert!(matches!(
            reducer.apply(None, &entry, HistoryContext::empty(entry.occurred_at_ms)),
            Err(ProtocolError::VerificationFromFuture { .. })
        ));
    }

    #[test]
    fn actor_role_and_current_holder_are_enforced() {
        let reducer = ChannelReducer::default();
        let open = open_entry(channel(9), 10);
        let state0 = apply_new(&reducer, None, &open);
        let mut invoice = invoice_entry(&state0, "inv-a", "holder:a", 11, None);
        invoice.actor.role = ActorRole::Holder;
        assert!(matches!(
            reducer.apply(Some(&state0), &invoice, HistoryContext::empty(invoice.occurred_at_ms),),
            Err(ProtocolError::UnauthorizedRole { .. })
        ));

        let invoice = invoice_entry(&state0, "inv-a", "holder:a", 11, None);
        let state1 = apply_new(&reducer, Some(&state0), &invoice);
        let mut transfer = transfer_entry(&state1, "inv-a", "holder:a", 12);
        let ChannelEvent::Transfer(event) = &mut transfer.event else {
            unreachable!()
        };
        event.sender = participant("not-current-holder");
        transfer.actor.participant_id = event.sender.clone();
        assert!(matches!(
            reducer.apply(Some(&state1), &transfer, HistoryContext::empty(transfer.occurred_at_ms),),
            Err(ProtocolError::ActorMismatch { .. })
        ));
    }

    #[test]
    fn channel_timestamp_and_entry_limit_are_enforced() {
        let reducer = ChannelReducer::new(ProtocolLimits::new(2, 16).unwrap()).unwrap();
        let open = open_entry(channel(10), 10);
        let state = apply_new(&reducer, None, &open);

        let old = invoice_entry(&state, "inv-a", "holder:a", 9, None);
        assert!(matches!(
            reducer.apply(Some(&state), &old, HistoryContext::empty(old.occurred_at_ms)),
            Err(ProtocolError::TimestampRegression { .. })
        ));

        let invoice = invoice_entry(&state, "inv-a", "holder:a", 11, None);
        let state = apply_new(&reducer, Some(&state), &invoice);
        let transfer = transfer_entry(&state, "inv-a", "holder:a", 12);
        assert!(matches!(
            reducer.apply(Some(&state), &transfer, HistoryContext::empty(transfer.occurred_at_ms),),
            Err(ProtocolError::EntryLimitReached { limit: 2 })
        ));
    }

    #[test]
    fn arbitrary_length_valid_transfer_chains_preserve_invariants() {
        let reducer = ChannelReducer::default();
        for transfer_count in 0_u64..=64 {
            let open = open_entry(channel((transfer_count + 1) as u8), 1);
            let mut state = apply_new(&reducer, None, &open);
            for index in 0..transfer_count {
                let invoice_id = format!("inv-{index}");
                let recipient = format!("holder-{}", index + 1);
                let invoice = invoice_entry(&state, &invoice_id, &recipient, 2 + index * 2, None);
                state = apply_new(&reducer, Some(&state), &invoice);
                let transfer = transfer_entry(&state, &invoice_id, &recipient, 3 + index * 2);
                state = apply_new(&reducer, Some(&state), &transfer);
            }
            assert_eq!(state.transfers_completed, transfer_count);
            assert_eq!(state.last_sequence, transfer_count * 2);
            assert!(state.pending_invoice.is_none());
            assert_eq!(
                state.phase,
                if transfer_count == 0 {
                    ChannelPhase::Open
                } else {
                    ChannelPhase::TransferComplete
                }
            );
            state.validate().unwrap();
        }
    }

    #[test]
    fn snapshot_serde_roundtrip_preserves_head_exactly() {
        let reducer = ChannelReducer::default();
        let open = open_entry(channel(11), 10);
        let state = apply_new(&reducer, None, &open);
        let encoded = serde_json::to_vec(&state).unwrap();
        let decoded: ChannelSnapshot = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(decoded, state);
        assert_eq!(decoded.head_hash, open.entry_hash());
    }
}
