use thiserror::Error;
use thunderbolt_protocol::{
    ChannelEvent, ChannelSnapshot, Digest, EventKind, InvoiceEvent, LedgerEntry, TransferEvent, VerificationEvidence,
    VerificationKind, VerificationOutcome,
};

/// Transaction-scoped input for verification of one Invoice proposal.
///
/// Values can only be constructed by the node from storage's authoritative
/// snapshot and trusted ledger clock.
#[derive(Clone, Copy, Debug)]
pub struct InvoiceProposalContext<'a> {
    proposal: &'a LedgerEntry,
    event: &'a InvoiceEvent,
    snapshot: &'a ChannelSnapshot,
    ledger_time_ms: u64,
}

impl<'a> InvoiceProposalContext<'a> {
    pub(crate) const fn new(
        proposal: &'a LedgerEntry,
        event: &'a InvoiceEvent,
        snapshot: &'a ChannelSnapshot,
        ledger_time_ms: u64,
    ) -> Self {
        Self {
            proposal,
            event,
            snapshot,
            ledger_time_ms,
        }
    }

    /// Returns the exact evidence-free proposal received by storage.
    pub const fn proposal(&self) -> &'a LedgerEntry {
        self.proposal
    }

    /// Returns the typed Invoice payload from the proposal.
    pub const fn event(&self) -> &'a InvoiceEvent {
        self.event
    }

    /// Returns the authoritative channel head selected under the writer lock.
    pub const fn snapshot(&self) -> &'a ChannelSnapshot {
        self.snapshot
    }

    /// Returns the ledger timestamp sampled inside the write transaction.
    pub const fn ledger_time_ms(&self) -> u64 {
        self.ledger_time_ms
    }
}

/// Transaction-scoped input for verification of one Transfer proposal.
#[derive(Clone, Copy, Debug)]
pub struct TransferProposalContext<'a> {
    proposal: &'a LedgerEntry,
    event: &'a TransferEvent,
    snapshot: &'a ChannelSnapshot,
    pending_invoice_head: &'a LedgerEntry,
    pending_invoice: &'a InvoiceEvent,
    ledger_time_ms: u64,
}

impl<'a> TransferProposalContext<'a> {
    pub(crate) const fn new(
        proposal: &'a LedgerEntry,
        event: &'a TransferEvent,
        snapshot: &'a ChannelSnapshot,
        pending_invoice_head: &'a LedgerEntry,
        pending_invoice: &'a InvoiceEvent,
        ledger_time_ms: u64,
    ) -> Self {
        Self {
            proposal,
            event,
            snapshot,
            pending_invoice_head,
            pending_invoice,
            ledger_time_ms,
        }
    }

    /// Returns the exact evidence-free proposal received by storage.
    pub const fn proposal(&self) -> &'a LedgerEntry {
        self.proposal
    }

    /// Returns the typed Transfer payload from the proposal.
    pub const fn event(&self) -> &'a TransferEvent {
        self.event
    }

    /// Returns the authoritative channel head selected under the writer lock.
    pub const fn snapshot(&self) -> &'a ChannelSnapshot {
        self.snapshot
    }

    /// Returns the exact immutable Invoice ledger entry at the pending head.
    pub const fn pending_invoice_head(&self) -> &'a LedgerEntry {
        self.pending_invoice_head
    }

    /// Returns the typed payload of [`Self::pending_invoice_head`].
    pub const fn pending_invoice(&self) -> &'a InvoiceEvent {
        self.pending_invoice
    }

    /// Returns the ledger timestamp sampled inside the write transaction.
    pub const fn ledger_time_ms(&self) -> u64 {
        self.ledger_time_ms
    }
}

/// Evidence accepted from a trusted proposal verifier.
///
/// Public constructors enforce exact event kinds, order, successful outcomes,
/// and the transaction's trusted timestamp. This release deliberately has no
/// constructors for Open or Finalize.
#[derive(Clone, Debug)]
pub struct VerifiedProposalEvidence {
    evidence: Vec<VerificationEvidence>,
}

impl VerifiedProposalEvidence {
    /// Constructs evidence for an Invoice consistency proof.
    pub fn invoice(invoice: VerificationEvidence, ledger_time_ms: u64) -> Result<Self, ProposalVerifierError> {
        Self::validate(EventKind::Invoice, vec![invoice], ledger_time_ms)
    }

    /// Constructs evidence for a Transfer proof and its anchor transition.
    pub fn transfer(
        transfer: VerificationEvidence,
        anchor_transition: VerificationEvidence,
        ledger_time_ms: u64,
    ) -> Result<Self, ProposalVerifierError> {
        Self::validate(EventKind::Transfer, vec![transfer, anchor_transition], ledger_time_ms)
    }

    fn validate(
        event: EventKind,
        evidence: Vec<VerificationEvidence>,
        ledger_time_ms: u64,
    ) -> Result<Self, ProposalVerifierError> {
        let expected: &[VerificationKind] = match event {
            EventKind::Invoice => &[VerificationKind::InvoiceConsistencyProof],
            EventKind::Transfer => &[
                VerificationKind::TransferConsistencyProof,
                VerificationKind::AnchorTransition,
            ],
            EventKind::Open | EventKind::Finalize => {
                return Err(ProposalVerifierError::UnsupportedEvent { event });
            }
        };
        if evidence.len() != expected.len() {
            return Err(ProposalVerifierError::InvalidEvidence {
                event,
                reason: "wrong evidence count",
            });
        }
        for (item, required) in evidence.iter().zip(expected) {
            if item.kind != *required {
                return Err(ProposalVerifierError::InvalidEvidence {
                    event,
                    reason: "wrong evidence kind or order",
                });
            }
            if item.outcome != VerificationOutcome::Verified {
                return Err(ProposalVerifierError::InvalidEvidence {
                    event,
                    reason: "verifier returned a non-verified outcome",
                });
            }
            if item.verified_at_ms != ledger_time_ms {
                return Err(ProposalVerifierError::InvalidEvidence {
                    event,
                    reason: "evidence timestamp is not trusted ledger time",
                });
            }
            if item.statement_digest == Digest::ZERO {
                return Err(ProposalVerifierError::InvalidEvidence {
                    event,
                    reason: "statement digest must not be zero",
                });
            }
        }
        let identities_match = evidence.first().is_none_or(|first| {
            evidence
                .iter()
                .skip(1)
                .all(|item| item.verifier == first.verifier && item.implementation == first.implementation)
        });
        if !identities_match {
            return Err(ProposalVerifierError::InvalidEvidence {
                event,
                reason: "evidence identities do not match",
            });
        }
        Ok(Self { evidence })
    }

    fn into_evidence_for(
        self,
        event: EventKind,
        ledger_time_ms: u64,
    ) -> Result<Vec<VerificationEvidence>, ProposalVerifierError> {
        Self::validate(event, self.evidence, ledger_time_ms).map(|validated| validated.evidence)
    }
}

/// Synchronous verifier invoked only inside storage's locked append callback.
///
/// Open and Finalize are intentionally absent. The node fails those event
/// kinds closed until dedicated Bitcoin and ownership/quorum verifiers exist.
/// [`thunderbolt_verifier::TrustedVerifier`] implements this boundary.
pub trait ProposalVerifier: std::fmt::Debug + Send + Sync + 'static {
    /// Verifies an Invoice against the authoritative current snapshot.
    fn verify_invoice(
        &self,
        context: InvoiceProposalContext<'_>,
    ) -> Result<VerifiedProposalEvidence, ProposalVerifierError>;

    /// Verifies a Transfer against the snapshot and immutable pending Invoice.
    fn verify_transfer(
        &self,
        context: TransferProposalContext<'_>,
    ) -> Result<VerifiedProposalEvidence, ProposalVerifierError>;
}

/// Typed failures at the node's trusted verification boundary.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ProposalVerifierError {
    #[error("no trusted verifier is configured for {event}")]
    Unavailable { event: EventKind },

    #[error("trusted verification for {event} is not implemented")]
    UnsupportedEvent { event: EventKind },

    #[error("storage did not provide authoritative {field} context for {event}")]
    MissingContext { event: EventKind, field: &'static str },

    #[error("proposal verifier rejected the request: {reason}")]
    Rejected { reason: &'static str },

    #[error("trusted verifier rejected the proposal: {0}")]
    Trusted(#[from] thunderbolt_verifier::VerifierError),

    #[error("proposal verifier returned invalid evidence for {event}: {reason}")]
    InvalidEvidence { event: EventKind, reason: &'static str },
}

/// Adapts the cryptographic `thunderbolt-verifier` bridge to the node boundary.
impl ProposalVerifier for thunderbolt_verifier::TrustedVerifier {
    fn verify_invoice(
        &self,
        context: InvoiceProposalContext<'_>,
    ) -> Result<VerifiedProposalEvidence, ProposalVerifierError> {
        let output = thunderbolt_verifier::TrustedVerifier::verify_invoice(
            self,
            context.proposal(),
            context.snapshot(),
            context.ledger_time_ms(),
        )?;
        VerifiedProposalEvidence::validate(EventKind::Invoice, output.into_evidence(), context.ledger_time_ms())
    }

    fn verify_transfer(
        &self,
        context: TransferProposalContext<'_>,
    ) -> Result<VerifiedProposalEvidence, ProposalVerifierError> {
        let output = thunderbolt_verifier::TrustedVerifier::verify_transfer(
            self,
            context.proposal(),
            context.snapshot(),
            context.pending_invoice_head(),
            context.ledger_time_ms(),
        )?;
        VerifiedProposalEvidence::validate(EventKind::Transfer, output.into_evidence(), context.ledger_time_ms())
    }
}

pub(crate) fn verify_proposal(
    context: thunderbolt_storage::VerifiedProposalContext<'_>,
    verifier: Option<&dyn ProposalVerifier>,
) -> Result<Vec<VerificationEvidence>, ProposalVerifierError> {
    let proposal = context.proposal();
    match &proposal.event {
        ChannelEvent::Open(_) | ChannelEvent::Finalize(_) => Err(ProposalVerifierError::UnsupportedEvent {
            event: proposal.event.kind(),
        }),
        ChannelEvent::Invoice(event) => {
            let snapshot = context.snapshot().ok_or(ProposalVerifierError::MissingContext {
                event: EventKind::Invoice,
                field: "channel snapshot",
            })?;
            let verifier = verifier.ok_or(ProposalVerifierError::Unavailable {
                event: EventKind::Invoice,
            })?;
            verifier
                .verify_invoice(InvoiceProposalContext::new(
                    proposal,
                    event,
                    snapshot,
                    context.ledger_time_ms(),
                ))?
                .into_evidence_for(EventKind::Invoice, context.ledger_time_ms())
        }
        ChannelEvent::Transfer(event) => {
            let snapshot = context.snapshot().ok_or(ProposalVerifierError::MissingContext {
                event: EventKind::Transfer,
                field: "channel snapshot",
            })?;
            let pending_invoice_head = context
                .pending_invoice_head()
                .ok_or(ProposalVerifierError::MissingContext {
                    event: EventKind::Transfer,
                    field: "pending invoice head",
                })?;
            let ChannelEvent::Invoice(pending_invoice) = &pending_invoice_head.event else {
                return Err(ProposalVerifierError::MissingContext {
                    event: EventKind::Transfer,
                    field: "typed pending invoice head",
                });
            };
            let verifier = verifier.ok_or(ProposalVerifierError::Unavailable {
                event: EventKind::Transfer,
            })?;
            verifier
                .verify_transfer(TransferProposalContext::new(
                    proposal,
                    event,
                    snapshot,
                    pending_invoice_head,
                    pending_invoice,
                    context.ledger_time_ms(),
                ))?
                .into_evidence_for(EventKind::Transfer, context.ledger_time_ms())
        }
    }
}

pub(crate) fn development_demo_evidence(
    context: thunderbolt_storage::VerifiedProposalContext<'_>,
) -> Result<Vec<VerificationEvidence>, ProposalVerifierError> {
    const DEMO_ID: &str = "development-unverified-demo";
    let verifier = thunderbolt_protocol::ParticipantId::new(DEMO_ID).map_err(|_| ProposalVerifierError::Rejected {
        reason: "invalid built-in demo verifier identity",
    })?;
    let implementation =
        thunderbolt_protocol::ImplementationId::new(DEMO_ID).map_err(|_| ProposalVerifierError::Rejected {
            reason: "invalid built-in demo implementation identity",
        })?;
    let ledger_time_ms = context.ledger_time_ms();
    Ok(context
        .proposal()
        .event
        .required_verifications()
        .iter()
        .copied()
        .map(|kind| {
            VerificationEvidence::verified(
                kind,
                verifier.clone(),
                implementation.clone(),
                thunderbolt_protocol::Digest::ZERO,
                ledger_time_ms,
            )
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use thunderbolt_protocol::{ImplementationId, ParticipantId};

    #[test]
    fn custom_verifier_cannot_return_zero_digest_evidence() {
        let evidence = VerificationEvidence::verified(
            VerificationKind::InvoiceConsistencyProof,
            ParticipantId::new("custom-verifier").expect("participant id"),
            ImplementationId::new("custom-verifier/v1").expect("implementation id"),
            Digest::ZERO,
            42,
        );

        assert!(matches!(
            VerifiedProposalEvidence::invoice(evidence, 42),
            Err(ProposalVerifierError::InvalidEvidence {
                event: EventKind::Invoice,
                reason: "statement digest must not be zero",
            })
        ));
    }
}
