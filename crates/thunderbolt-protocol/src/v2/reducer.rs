use core::fmt;
use thunderbolt_ledger::{
    ActorRoleV2, EntryHashV2, ExecutedEntryV2, LedgerChainIdV2, PendingBlockV2, SignedProposalV2,
    VerifiedProposalViewV2,
};

use super::{
    types::{retained_state_bytes, validate_capacity, validate_committee_topology},
    ArtifactV2, ChannelEventV2, ChannelPhaseV2, ChannelSnapshotV2, FinalizeEventV2, InvoiceEventV2, OpenEventV2,
    PendingInvoiceV2, ProtocolLimitsV2, TransferEventV2, V2Error, MAX_PENDING_INVOICE_EVENT_BYTES_V2,
    MAX_RETAINED_CHANNEL_STATE_BYTES_V2, PROTOCOL_VERSION_V2,
};

/// Signature-authenticated proposal paired with its exact typed event.
///
/// The Ledger capability supplies the complete stable binding, actor identity,
/// role, request digest, sequence, predecessor, and canonical event bytes. The
/// constructor checks that the decoded application event matches those bytes
/// and the authenticated event discriminant exactly.
#[derive(Debug, Clone)]
pub struct AuthenticatedEntryV2<'a> {
    proposal: VerifiedProposalViewV2<'a>,
    event: &'a ChannelEventV2,
}

impl<'a> AuthenticatedEntryV2<'a> {
    /// Exhaustively binds a typed event to an already verified Ledger view.
    pub fn from_verified(proposal: VerifiedProposalViewV2<'a>, event: &'a ChannelEventV2) -> Result<Self, V2Error> {
        if proposal.event_kind() != event.kind() || proposal.event().as_bytes() != event.canonical_bytes()?.as_slice() {
            return Err(V2Error::AuthenticatedEventMismatch);
        }
        Ok(Self { proposal, event })
    }

    /// Verifies a signed proposal and binds it to an exact typed event.
    pub fn from_signed(proposal: &'a SignedProposalV2, event: &'a ChannelEventV2) -> Result<Self, V2Error> {
        let verified = proposal
            .verified_view()
            .map_err(|_| V2Error::ProposalAuthenticationFailed)?;
        Self::from_verified(verified, event)
    }

    /// Returns the signature-authenticated Ledger proposal view.
    pub const fn proposal(&self) -> &VerifiedProposalViewV2<'a> {
        &self.proposal
    }

    /// Returns the exact typed application event.
    pub const fn event(&self) -> &ChannelEventV2 {
        self.event
    }
}

/// Authenticated entry bound to a validated consensus block position and time.
///
/// This capability cannot be built from a raw clock value. Nodes obtain it
/// from a [`PendingBlockV2`] supplied by consensus or a recomputed
/// [`ExecutedEntryV2`] loaded from executed block storage. Execution does not
/// by itself assert Byzantine finality.
#[derive(Debug, Clone)]
pub struct ConsensusEntryV2<'a> {
    authenticated: AuthenticatedEntryV2<'a>,
    block_height: u64,
    block_time_ms: u64,
    block_index: u32,
}

impl<'a> ConsensusEntryV2<'a> {
    /// Binds the proposal at `block_index` to a decoded application event.
    pub fn from_pending_block(
        block: &'a PendingBlockV2,
        block_index: usize,
        event: &'a ChannelEventV2,
    ) -> Result<Self, V2Error> {
        let proposal = block
            .proposals()
            .get(block_index)
            .ok_or(V2Error::ProposalNotInConsensusBlock)?;
        let block_index = u32::try_from(block_index).map_err(|_| V2Error::ProposalNotInConsensusBlock)?;
        Ok(Self {
            authenticated: AuthenticatedEntryV2::from_signed(proposal, event)?,
            block_height: block.height(),
            block_time_ms: block.block_time_ms(),
            block_index,
        })
    }

    /// Binds a recomputed executed entry to a decoded application event.
    pub fn from_executed_entry(entry: &'a ExecutedEntryV2, event: &'a ChannelEventV2) -> Result<Self, V2Error> {
        let metadata = entry.metadata();
        Ok(Self {
            authenticated: AuthenticatedEntryV2::from_signed(entry.proposal(), event)?,
            block_height: metadata.block_height(),
            block_time_ms: metadata.block_time_ms(),
            block_index: metadata.block_index(),
        })
    }

    /// Returns the authenticated proposal and exact typed event.
    pub const fn authenticated(&self) -> &AuthenticatedEntryV2<'a> {
        &self.authenticated
    }

    /// Returns the positive consensus block height.
    pub const fn block_height(&self) -> u64 {
        self.block_height
    }

    /// Returns the positive consensus block time in Unix milliseconds.
    pub const fn block_time_ms(&self) -> u64 {
        self.block_time_ms
    }

    /// Returns the zero-based proposal position in the consensus block.
    pub const fn block_index(&self) -> u32 {
        self.block_index
    }
}

/// Stage rejected by an external trusted proof verifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerificationStageV2 {
    /// Open funding, initial-state, and binding statements.
    Open,
    /// Invoice consistency statement.
    Invoice,
    /// Transfer consistency and anchor-transition statements.
    Transfer,
    /// Holder ownership, committee authorization, and closing transaction.
    Finalize,
}

impl fmt::Display for VerificationStageV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::Open => "Open statement",
            Self::Invoice => "Invoice statement",
            Self::Transfer => "Transfer statement",
            Self::Finalize => "Finalize statement",
        };
        formatter.write_str(label)
    }
}

/// Typed request to verify an Open event and its stable channel binding.
#[derive(Debug, Clone, Copy)]
pub struct OpenVerificationRequestV2<'a> {
    /// Consensus-bound authenticated proposal and exact event bytes.
    pub entry: &'a ConsensusEntryV2<'a>,
    /// Trusted consensus block time assigned to this transition.
    pub block_time_ms: u64,
    /// Typed Open payload.
    pub event: &'a OpenEventV2,
}

/// Typed request to verify an Invoice against committed channel state.
#[derive(Debug, Clone, Copy)]
pub struct InvoiceVerificationRequestV2<'a> {
    /// Consensus-bound authenticated proposal and exact event bytes.
    pub entry: &'a ConsensusEntryV2<'a>,
    /// Exact state at the preceding total-order position.
    pub current: &'a ChannelSnapshotV2,
    /// Trusted consensus block time assigned to this transition.
    pub block_time_ms: u64,
    /// Typed Invoice payload.
    pub event: &'a InvoiceEventV2,
}

/// Typed request to verify a Transfer against its selected committed Invoice.
#[derive(Debug, Clone, Copy)]
pub struct TransferVerificationRequestV2<'a> {
    /// Consensus-bound authenticated proposal and exact event bytes.
    pub entry: &'a ConsensusEntryV2<'a>,
    /// Exact state at the preceding total-order position.
    pub current: &'a ChannelSnapshotV2,
    /// Selected committed invoice record.
    pub selected_invoice: &'a PendingInvoiceV2,
    /// Trusted consensus block time assigned to this transition.
    pub block_time_ms: u64,
    /// Typed Transfer payload.
    pub event: &'a TransferEventV2,
}

/// Typed request to verify Finalize against the latest committed Holder state.
#[derive(Debug, Clone, Copy)]
pub struct FinalizeVerificationRequestV2<'a> {
    /// Consensus-bound authenticated proposal and exact event bytes.
    pub entry: &'a ConsensusEntryV2<'a>,
    /// Exact state at the preceding total-order position.
    pub current: &'a ChannelSnapshotV2,
    /// Trusted consensus block time assigned to this transition.
    pub block_time_ms: u64,
    /// Typed Finalize payload.
    pub event: &'a FinalizeEventV2,
}

/// Trusted cryptographic-proof boundary for version-two reduction.
///
/// Actor signatures are already proven by [`VerifiedProposalViewV2`]. These
/// hooks verify operation-specific proofs against authenticated binding and
/// exact prior state. Implementations must be deterministic and side-effect
/// free over the request plus immutable local deployment data; consensus code
/// must not consult a clock, network, or mutable database through these hooks.
/// Open verification must match every binding field and committee topology to
/// local policy. Invoice verification must bind the authenticated Recipient
/// identity to its encryption key, either by registration or explicit proof of
/// possession. The reducer does not interpret proof bytes itself.
pub trait ExternalVerifierV2 {
    /// Implementation-specific rejection detail, intentionally not committed.
    type Error;

    /// Verifies Open funding, initial state, and descriptor commitments.
    fn verify_open(&self, request: OpenVerificationRequestV2<'_>) -> Result<(), Self::Error>;

    /// Verifies an Invoice consistency statement.
    fn verify_invoice(&self, request: InvoiceVerificationRequestV2<'_>) -> Result<(), Self::Error>;

    /// Verifies a Transfer and its selected Invoice transition.
    fn verify_transfer(&self, request: TransferVerificationRequestV2<'_>) -> Result<(), Self::Error>;

    /// Verifies current-Holder ownership, committee authorization, and close.
    fn verify_finalize(&self, request: FinalizeVerificationRequestV2<'_>) -> Result<(), Self::Error>;
}

/// Indexed facts supplied by storage inside the serializable append transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HistoryContextV2 {
    /// Entry already committed under this actor-scoped request digest, if any.
    pub existing_request_entry_hash: Option<EntryHashV2>,
    /// Whether an Invoice previously used this identifier in channel history.
    pub invoice_id_already_used: bool,
}

impl HistoryContextV2 {
    /// Constructs transaction-scoped history facts.
    pub const fn new(existing_request_entry_hash: Option<EntryHashV2>, invoice_id_already_used: bool) -> Self {
        Self {
            existing_request_entry_hash,
            invoice_id_already_used,
        }
    }

    /// Constructs history for a fresh request and Invoice identifier.
    pub const fn fresh() -> Self {
        Self::new(None, false)
    }
}

/// Whether reduction committed a new event or recognized an exact retry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApplyDispositionV2 {
    /// New event advanced the channel head.
    Applied,
    /// Same request digest and same authenticated entry already exist.
    Replay,
}

/// Result of deterministic version-two reduction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReductionV2 {
    /// Derived state, unchanged for replay.
    pub snapshot: ChannelSnapshotV2,
    /// Storage action implied by the result.
    pub disposition: ApplyDispositionV2,
}

/// Pure version-two reducer with typed external proof-verification hooks.
#[derive(Debug, Clone)]
pub struct V2Reducer {
    ledger_chain_id: LedgerChainIdV2,
    limits: ProtocolLimitsV2,
}

impl V2Reducer {
    /// Constructs a reducer under validated resource limits.
    pub fn new(ledger_chain_id: LedgerChainIdV2, limits: ProtocolLimitsV2) -> Result<Self, V2Error> {
        limits.validate()?;
        Ok(Self {
            ledger_chain_id,
            limits,
        })
    }

    /// Returns the only consensus Ledger chain accepted by this reducer.
    pub const fn ledger_chain_id(&self) -> &LedgerChainIdV2 {
        &self.ledger_chain_id
    }

    /// Returns the reducer's immutable resource policy.
    pub const fn limits(&self) -> ProtocolLimitsV2 {
        self.limits
    }

    /// Applies one authenticated entry at a trusted consensus block time.
    ///
    /// Storage must obtain `history` for this proposal's authenticated channel,
    /// actor-scoped [`thunderbolt_ledger::RequestDigestV2`], and created Invoice id, if any, in the
    /// same serializable append transaction.
    pub fn apply<V: ExternalVerifierV2>(
        &self,
        current: Option<&ChannelSnapshotV2>,
        entry: &ConsensusEntryV2<'_>,
        history: HistoryContextV2,
        verifier: &V,
    ) -> Result<ReductionV2, V2Error> {
        validate_block_time(entry.block_time_ms())?;
        let authenticated = entry.authenticated();
        if authenticated.proposal().ledger_chain_id() != &self.ledger_chain_id {
            return Err(V2Error::LedgerChainMismatch);
        }
        if let Some(snapshot) = current {
            snapshot.validate()?;
            self.validate_snapshot_policy(snapshot)?;
            if snapshot.ledger_chain_id != self.ledger_chain_id {
                return Err(V2Error::LedgerChainMismatch);
            }
            if &snapshot.binding != authenticated.proposal().channel() {
                return Err(V2Error::BindingMismatch);
            }
        }

        if let Some(existing_hash) = history.existing_request_entry_hash {
            if &existing_hash == authenticated.proposal().entry_hash() {
                let snapshot = current.ok_or(V2Error::InvalidSnapshot {
                    reason: "idempotent replay exists without a current snapshot",
                })?;
                return Ok(ReductionV2 {
                    snapshot: snapshot.clone(),
                    disposition: ApplyDispositionV2::Replay,
                });
            }
            return Err(V2Error::IdempotencyConflict);
        }

        match current {
            None => self.open(entry, verifier),
            Some(snapshot) => self.advance(snapshot, entry, history, verifier),
        }
    }

    fn validate_snapshot_policy(&self, snapshot: &ChannelSnapshotV2) -> Result<(), V2Error> {
        if snapshot.pending_invoices.len() > self.limits.max_pending_invoices {
            return Err(V2Error::InvalidSnapshot {
                reason: "pending invoice set exceeds reducer policy",
            });
        }
        Ok(())
    }

    fn open<V: ExternalVerifierV2>(&self, entry: &ConsensusEntryV2<'_>, verifier: &V) -> Result<ReductionV2, V2Error> {
        let block_time_ms = entry.block_time_ms();
        validate_block_time(block_time_ms)?;
        let authenticated = entry.authenticated();
        let proposal = authenticated.proposal();
        if proposal.sequence() != 0 || !proposal.previous_entry_hash().is_zero() {
            return Err(V2Error::ChannelNotOpen);
        }
        let ChannelEventV2::Open(event) = authenticated.event() else {
            return Err(V2Error::ChannelNotOpen);
        };
        require_role(proposal.actor_role(), ActorRoleV2::Holder)?;
        validate_capacity(event.capacity_sat)?;
        validate_committee_topology(event.committee_member_count, event.committee_threshold)?;
        require_retained_state_budget(
            &event.lock_key,
            &event.initial_holder_anchor,
            &event.initial_holder_ciphertext,
            0,
        )?;
        verifier
            .verify_open(OpenVerificationRequestV2 {
                entry,
                block_time_ms,
                event,
            })
            .map_err(|_| V2Error::ExternalVerificationRejected {
                stage: VerificationStageV2::Open,
            })?;

        let snapshot = ChannelSnapshotV2 {
            protocol_version: PROTOCOL_VERSION_V2,
            ledger_chain_id: self.ledger_chain_id.clone(),
            binding: proposal.channel().clone(),
            phase: ChannelPhaseV2::Active,
            capacity_sat: event.capacity_sat,
            committee_member_count: event.committee_member_count,
            committee_threshold: event.committee_threshold,
            lock_key: event.lock_key.clone(),
            current_holder: proposal.participant_id().clone(),
            current_holder_anchor: event.initial_holder_anchor.clone(),
            current_holder_ciphertext: event.initial_holder_ciphertext.clone(),
            transfers_completed: 0,
            pending_invoices: Default::default(),
            last_consumed_invoice_id: None,
            last_sequence: 0,
            head_entry_hash: proposal.entry_hash().clone(),
            opened_at_ms: block_time_ms,
            last_block_time_ms: block_time_ms,
            finalized_at_ms: None,
        };
        snapshot.validate()?;
        Ok(ReductionV2 {
            snapshot,
            disposition: ApplyDispositionV2::Applied,
        })
    }

    fn advance<V: ExternalVerifierV2>(
        &self,
        current: &ChannelSnapshotV2,
        entry: &ConsensusEntryV2<'_>,
        history: HistoryContextV2,
        verifier: &V,
    ) -> Result<ReductionV2, V2Error> {
        let block_time_ms = entry.block_time_ms();
        validate_block_time(block_time_ms)?;
        if current.phase == ChannelPhaseV2::Finalized {
            return Err(V2Error::ChannelFinalized);
        }
        let authenticated = entry.authenticated();
        let proposal = authenticated.proposal();
        let expected_sequence = current.next_sequence()?;
        if proposal.sequence() < expected_sequence {
            return Err(V2Error::StaleSequence {
                expected: expected_sequence,
                found: proposal.sequence(),
            });
        }
        if proposal.sequence() > expected_sequence {
            return Err(V2Error::SequenceGap {
                expected: expected_sequence,
                found: proposal.sequence(),
            });
        }
        if proposal.previous_entry_hash() != &current.head_entry_hash {
            return Err(V2Error::ForkDetected);
        }
        if block_time_ms < current.last_block_time_ms {
            return Err(V2Error::BlockTimeRegression {
                previous_ms: current.last_block_time_ms,
                proposed_ms: block_time_ms,
            });
        }
        let terminal_position = self.limits.max_entries_per_channel - 1;
        let is_finalize = matches!(authenticated.event(), ChannelEventV2::Finalize(_));
        if expected_sequence >= self.limits.max_entries_per_channel
            || (!is_finalize && expected_sequence >= terminal_position)
        {
            return Err(V2Error::EntryLimitReached {
                limit: self.limits.max_entries_per_channel,
            });
        }

        let mut next = match authenticated.event() {
            ChannelEventV2::Open(_) => return Err(V2Error::ChannelAlreadyOpen),
            ChannelEventV2::Invoice(event) => {
                require_role(proposal.actor_role(), ActorRoleV2::Recipient)?;
                if event.holder_step != current.transfers_completed {
                    return Err(V2Error::InvoiceStepMismatch {
                        expected: current.transfers_completed,
                        found: event.holder_step,
                    });
                }
                if history.invoice_id_already_used || current.pending_invoices.contains_key(&event.invoice_id) {
                    return Err(V2Error::InvoiceAlreadyUsed);
                }
                if event.expires_at_ms <= block_time_ms {
                    return Err(V2Error::InvalidInvoiceExpiration {
                        block_time_ms,
                        expires_at_ms: event.expires_at_ms,
                    });
                }
                let ttl_ms = event.expires_at_ms - block_time_ms;
                if ttl_ms > self.limits.max_invoice_ttl_ms {
                    return Err(V2Error::InvoiceTtlTooLong {
                        ttl_ms,
                        limit_ms: self.limits.max_invoice_ttl_ms,
                    });
                }
                let live_invoice_count = current
                    .pending_invoices
                    .values()
                    .filter(|invoice| !invoice.is_expired_at(block_time_ms))
                    .count();
                if live_invoice_count >= self.limits.max_pending_invoices {
                    return Err(V2Error::PendingInvoiceLimitReached {
                        limit: self.limits.max_pending_invoices,
                    });
                }
                let retained_event_bytes = current
                    .pending_invoices
                    .values()
                    .filter(|invoice| !invoice.is_expired_at(block_time_ms))
                    .try_fold(0_usize, |total, invoice| {
                        total
                            .checked_add(invoice.canonical_event_len()?)
                            .ok_or(V2Error::InvalidSnapshot {
                                reason: "pending Invoice event byte count overflows",
                            })
                    })?;
                let proposed_event_bytes = super::canonical::encoded_invoice_event_len(event)
                    .filter(|length| *length <= thunderbolt_ledger::EVENT_BYTES_MAX)
                    .ok_or(V2Error::InvalidCanonicalEvent)?;
                let next_event_bytes = retained_event_bytes.checked_add(proposed_event_bytes).ok_or(
                    V2Error::PendingInvoiceBytesLimitReached {
                        limit: MAX_PENDING_INVOICE_EVENT_BYTES_V2,
                    },
                )?;
                if next_event_bytes > MAX_PENDING_INVOICE_EVENT_BYTES_V2 {
                    return Err(V2Error::PendingInvoiceBytesLimitReached {
                        limit: MAX_PENDING_INVOICE_EVENT_BYTES_V2,
                    });
                }
                require_retained_state_budget(
                    &current.lock_key,
                    &current.current_holder_anchor,
                    &current.current_holder_ciphertext,
                    next_event_bytes,
                )?;
                verifier
                    .verify_invoice(InvoiceVerificationRequestV2 {
                        entry,
                        current,
                        block_time_ms,
                        event,
                    })
                    .map_err(|_| V2Error::ExternalVerificationRejected {
                        stage: VerificationStageV2::Invoice,
                    })?;
                let mut next = current.clone();
                next.pending_invoices
                    .retain(|_, invoice| !invoice.is_expired_at(block_time_ms));
                next.pending_invoices.insert(
                    event.invoice_id.clone(),
                    PendingInvoiceV2 {
                        event: event.clone(),
                        invoice_id: event.invoice_id.clone(),
                        recipient: proposal.participant_id().clone(),
                        holder_step: event.holder_step,
                        created_at_ms: block_time_ms,
                        expires_at_ms: event.expires_at_ms,
                        committed_entry_hash: proposal.entry_hash().clone(),
                    },
                );
                next
            }
            ChannelEventV2::Transfer(event) => {
                require_role(proposal.actor_role(), ActorRoleV2::Holder)?;
                if proposal.participant_id() != &current.current_holder {
                    return Err(V2Error::ActorMismatch);
                }
                let selected = current
                    .pending_invoices
                    .get(&event.invoice_id)
                    .ok_or(V2Error::InvoiceNotPending)?;
                if event.invoice_entry_hash != selected.committed_entry_hash {
                    return Err(V2Error::InvoiceEntryHashMismatch);
                }
                if selected.is_expired_at(block_time_ms) {
                    return Err(V2Error::InvoiceExpired {
                        expires_at_ms: selected.expires_at_ms,
                    });
                }
                if selected.holder_step != current.transfers_completed {
                    return Err(V2Error::StaleInvoice {
                        invoice_step: selected.holder_step,
                        current_step: current.transfers_completed,
                    });
                }
                require_retained_state_budget(
                    &current.lock_key,
                    &event.next_holder_anchor,
                    &event.next_holder_ciphertext,
                    0,
                )?;
                verifier
                    .verify_transfer(TransferVerificationRequestV2 {
                        entry,
                        current,
                        selected_invoice: selected,
                        block_time_ms,
                        event,
                    })
                    .map_err(|_| V2Error::ExternalVerificationRejected {
                        stage: VerificationStageV2::Transfer,
                    })?;
                let mut next = current.clone();
                next.transfers_completed = current
                    .transfers_completed
                    .checked_add(1)
                    .ok_or(V2Error::TransferCounterExhausted)?;
                next.current_holder = selected.recipient.clone();
                next.current_holder_anchor = event.next_holder_anchor.clone();
                next.current_holder_ciphertext = event.next_holder_ciphertext.clone();
                next.last_consumed_invoice_id = Some(event.invoice_id.clone());
                // Exactly the selected Invoice is consumed. Other invoices are
                // invalidated because their proofs bind the preceding Holder step.
                next.pending_invoices.clear();
                next
            }
            ChannelEventV2::Finalize(event) => {
                require_role(proposal.actor_role(), ActorRoleV2::Holder)?;
                if proposal.participant_id() != &current.current_holder {
                    return Err(V2Error::ActorMismatch);
                }
                require_retained_state_budget(
                    &current.lock_key,
                    &current.current_holder_anchor,
                    &current.current_holder_ciphertext,
                    0,
                )?;
                verifier
                    .verify_finalize(FinalizeVerificationRequestV2 {
                        entry,
                        current,
                        block_time_ms,
                        event,
                    })
                    .map_err(|_| V2Error::ExternalVerificationRejected {
                        stage: VerificationStageV2::Finalize,
                    })?;
                let mut next = current.clone();
                // Finalize is ordered after the current head. Pending Invoice
                // events are abandoned and cannot veto a valid close.
                next.pending_invoices.clear();
                next.phase = ChannelPhaseV2::Finalized;
                next.finalized_at_ms = Some(block_time_ms);
                next
            }
        };

        next.last_sequence = proposal.sequence();
        next.head_entry_hash = proposal.entry_hash().clone();
        next.last_block_time_ms = block_time_ms;
        next.validate()?;
        Ok(ReductionV2 {
            snapshot: next,
            disposition: ApplyDispositionV2::Applied,
        })
    }
}

fn require_role(found: ActorRoleV2, expected: ActorRoleV2) -> Result<(), V2Error> {
    if found != expected {
        return Err(V2Error::UnauthorizedRole);
    }
    Ok(())
}

fn validate_block_time(block_time_ms: u64) -> Result<(), V2Error> {
    if block_time_ms == 0 {
        return Err(V2Error::InvalidBlockTime);
    }
    Ok(())
}

fn require_retained_state_budget(
    lock_key: &ArtifactV2,
    holder_anchor: &ArtifactV2,
    holder_ciphertext: &ArtifactV2,
    pending_event_bytes: usize,
) -> Result<(), V2Error> {
    let total = retained_state_bytes(lock_key, holder_anchor, holder_ciphertext, pending_event_bytes).ok_or(
        V2Error::RetainedStateBytesLimitReached {
            limit: MAX_RETAINED_CHANNEL_STATE_BYTES_V2,
        },
    )?;
    if total > MAX_RETAINED_CHANNEL_STATE_BYTES_V2 {
        return Err(V2Error::RetainedStateBytesLimitReached {
            limit: MAX_RETAINED_CHANNEL_STATE_BYTES_V2,
        });
    }
    Ok(())
}
