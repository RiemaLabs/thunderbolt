use sha2::{Digest as _, Sha256};
use thunderbolt_protocol::{
    ActorRole, ChannelEvent, ChannelSnapshot, Digest, EventKind, InvoiceEvent, InvoiceId, LedgerEntry, TransferEvent,
    VerificationEvidence, VerificationKind, VerificationOutcome, PROTOCOL_VERSION,
};
use thunderbolt_wire::{
    from_json_slice, BindingContext, CanonicalDigest, PublicMessageV1, ShareEnvelopeV1, ThresholdEnvelopeV1,
    TransferEnvelopeV1,
};

use crate::context::{CommitteeBinding, DeploymentContext, VerifierIdentity, RECIPIENT_SHARE_MEMBER_ID};
use crate::error::{ArtifactSlot, BindingField, PublicMessageKind, Result, VerifierError};

/// Canonical public statement identified by a successful verification.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StatementDigest {
    pub kind: StatementKind,
    pub digest: Digest,
}

/// Domain of one canonical digest returned by the bridge.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StatementKind {
    Invoice,
    RecipientShare,
    ThresholdRefresh,
    ThresholdInvoicePackage,
    Transfer,
    AnchorTransition,
}

/// Successful evidence and the canonical statements that produced it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerificationOutput {
    evidence: Vec<VerificationEvidence>,
    statement_digests: Vec<StatementDigest>,
}

impl VerificationOutput {
    /// Evidence in the exact order required by the protocol event.
    pub fn evidence(&self) -> &[VerificationEvidence] {
        &self.evidence
    }

    /// Canonical leaf and, when applicable, package statement digests.
    pub fn statement_digests(&self) -> &[StatementDigest] {
        &self.statement_digests
    }

    /// Consumes the output and returns only protocol evidence.
    pub fn into_evidence(self) -> Vec<VerificationEvidence> {
        self.evidence
    }
}

/// Stateless verifier bound to one trusted deployment epoch and identity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrustedVerifier {
    deployment: DeploymentContext,
    identity: VerifierIdentity,
}

impl TrustedVerifier {
    /// Constructs a verifier from public, trusted configuration only.
    pub fn new(deployment: DeploymentContext, identity: VerifierIdentity) -> Self {
        Self { deployment, identity }
    }

    /// Verifies an Invoice entry against the current immutable channel state.
    ///
    /// `ledger_time_ms` must be sampled by the ledger transaction. The caller
    /// must reuse the same value when replaying an idempotent append.
    pub fn verify_invoice(
        &self,
        entry: &LedgerEntry,
        snapshot: &ChannelSnapshot,
        ledger_time_ms: u64,
    ) -> Result<VerificationOutput> {
        self.validate_new_entry(entry, snapshot, ledger_time_ms, EventKind::Invoice)?;
        let ChannelEvent::Invoice(event) = &entry.event else {
            return Err(VerifierError::UnsupportedEvent {
                expected: EventKind::Invoice,
                actual: entry.event.kind(),
            });
        };
        if entry.actor.role != ActorRole::Recipient || entry.actor.participant_id != event.recipient {
            return Err(VerifierError::StateMismatch { field: "invoice.actor" });
        }
        if snapshot.pending_invoice.is_some() {
            return Err(VerifierError::StateMismatch {
                field: "snapshot.pending_invoice",
            });
        }
        ensure_not_expired(event.expires_at_ms, ledger_time_ms)?;
        self.verify_snapshot_committee(snapshot)?;

        let verified = self.verify_invoice_artifacts(entry, event)?;
        Ok(VerificationOutput {
            evidence: vec![self.evidence(
                VerificationKind::InvoiceConsistencyProof,
                verified.evidence_digest,
                ledger_time_ms,
            )],
            statement_digests: verified.statement_digests,
        })
    }

    /// Verifies a Transfer against the current snapshot and the immutable
    /// Invoice entry at that snapshot's head.
    pub fn verify_transfer(
        &self,
        entry: &LedgerEntry,
        snapshot: &ChannelSnapshot,
        pending_invoice_entry: &LedgerEntry,
        ledger_time_ms: u64,
    ) -> Result<VerificationOutput> {
        self.validate_new_entry(entry, snapshot, ledger_time_ms, EventKind::Transfer)?;
        let ChannelEvent::Transfer(event) = &entry.event else {
            return Err(VerifierError::UnsupportedEvent {
                expected: EventKind::Transfer,
                actual: entry.event.kind(),
            });
        };
        if entry.actor.role != ActorRole::Holder || entry.actor.participant_id != event.sender {
            return Err(VerifierError::StateMismatch {
                field: "transfer.actor",
            });
        }
        self.verify_snapshot_committee(snapshot)?;
        let pending = snapshot
            .pending_invoice
            .as_ref()
            .ok_or(VerifierError::PriorInvoiceMismatch {
                field: "snapshot.pending_invoice",
            })?;
        ensure_not_expired(pending.expires_at_ms, ledger_time_ms)?;

        let ChannelEvent::Invoice(invoice_event) = &pending_invoice_entry.event else {
            return Err(VerifierError::PriorInvoiceMismatch {
                field: "entry.event.type",
            });
        };
        self.verify_pending_invoice_link(snapshot, pending_invoice_entry, invoice_event)?;
        if event.invoice_id != invoice_event.invoice_id || event.invoice_id != pending.invoice_id {
            return Err(VerifierError::PriorInvoiceMismatch { field: "invoice_id" });
        }
        if event.sender != snapshot.current_holder {
            return Err(VerifierError::PriorInvoiceMismatch { field: "sender" });
        }
        if event.recipient != invoice_event.recipient || event.recipient != pending.recipient {
            return Err(VerifierError::PriorInvoiceMismatch { field: "recipient" });
        }

        let step = snapshot
            .transfers_completed
            .checked_add(1)
            .ok_or(VerifierError::ArithmeticOverflow { field: "transfer step" })?;
        let message = decode_artifact(ArtifactSlot::TransferProof, event.transfer_proof.as_bytes())?;
        let PublicMessageV1::Transfer(envelope) = message else {
            return Err(unexpected_type(
                ArtifactSlot::TransferProof,
                PublicMessageKind::Transfer,
                &message,
            ));
        };
        self.verify_binding(&envelope.binding, entry, &event.invoice_id, Some(step))?;

        // Re-verify the immutable Invoice only after all inexpensive state and
        // binding checks have passed. This keeps malformed requests from
        // forcing avoidable public-key work.
        let prior = self.verify_invoice_artifacts(pending_invoice_entry, invoice_event)?;
        self.verify_prior_evidence(
            invoice_event,
            prior.evidence_digest,
            pending.created_at_ms,
            ledger_time_ms,
        )?;
        self.verify_transfer_fields(event, snapshot, invoice_event, &envelope)?;
        envelope.verify().map_err(|source| VerifierError::VerificationFailed {
            message: PublicMessageKind::Transfer,
            source,
        })?;

        let transfer_digest = canonical_digest(PublicMessageKind::Transfer, &envelope)?;
        let transition_digest = canonical_digest(PublicMessageKind::Transfer, &envelope.anchor_transition)?;
        Ok(VerificationOutput {
            evidence: vec![
                self.evidence(
                    VerificationKind::TransferConsistencyProof,
                    transfer_digest,
                    ledger_time_ms,
                ),
                self.evidence(VerificationKind::AnchorTransition, transition_digest, ledger_time_ms),
            ],
            statement_digests: vec![
                StatementDigest {
                    kind: StatementKind::Transfer,
                    digest: transfer_digest,
                },
                StatementDigest {
                    kind: StatementKind::AnchorTransition,
                    digest: transition_digest,
                },
            ],
        })
    }

    fn validate_new_entry(
        &self,
        entry: &LedgerEntry,
        snapshot: &ChannelSnapshot,
        ledger_time_ms: u64,
        expected: EventKind,
    ) -> Result<()> {
        let actual = entry.event.kind();
        if actual != expected {
            return Err(VerifierError::UnsupportedEvent { expected, actual });
        }
        if !entry.event.verification().is_empty() {
            return Err(VerifierError::ClientEvidence { event: actual });
        }
        if entry.protocol_version != PROTOCOL_VERSION {
            return Err(VerifierError::StateMismatch {
                field: "entry.protocol_version",
            });
        }
        snapshot
            .validate()
            .map_err(|source| VerifierError::InvalidSnapshot { source })?;
        if snapshot.channel_id != entry.channel_id {
            return Err(VerifierError::StateMismatch {
                field: "snapshot.channel_id",
            });
        }
        let next_sequence = snapshot
            .next_sequence()
            .map_err(|_| VerifierError::ArithmeticOverflow {
                field: "entry sequence",
            })?;
        if entry.sequence != next_sequence {
            return Err(VerifierError::StateMismatch {
                field: "entry.sequence",
            });
        }
        if entry.previous_entry_hash != snapshot.head_hash {
            return Err(VerifierError::StateMismatch {
                field: "entry.previous_entry_hash",
            });
        }
        if snapshot.last_occurred_at_ms > ledger_time_ms {
            return Err(VerifierError::InvalidTrustedTime {
                field: "snapshot.last_occurred_at_ms",
            });
        }
        if entry.occurred_at_ms < snapshot.last_occurred_at_ms || entry.occurred_at_ms > ledger_time_ms {
            return Err(VerifierError::InvalidTrustedTime {
                field: "entry.occurred_at_ms",
            });
        }
        Ok(())
    }

    fn verify_snapshot_committee(&self, snapshot: &ChannelSnapshot) -> Result<()> {
        let committee = self.deployment.committee();
        if snapshot.committee.committee_id() != committee.committee_id() {
            return Err(VerifierError::CommitteeMismatch { field: "committee_id" });
        }
        match committee {
            CommitteeBinding::Single { .. } => {
                if snapshot.committee.member_count() != 1 || snapshot.committee.threshold() != 1 {
                    return Err(VerifierError::CommitteeMismatch {
                        field: "single_committee_shape",
                    });
                }
            }
            CommitteeBinding::Threshold { threshold, members, .. } => {
                let expected_count = u16::try_from(members.len())
                    .map_err(|_| VerifierError::CommitteeMismatch { field: "member_count" })?;
                if snapshot.committee.member_count() != expected_count {
                    return Err(VerifierError::CommitteeMismatch { field: "member_count" });
                }
                if snapshot.committee.threshold() != *threshold {
                    return Err(VerifierError::CommitteeMismatch { field: "threshold" });
                }
            }
        }
        Ok(())
    }

    fn verify_invoice_artifacts(&self, entry: &LedgerEntry, event: &InvoiceEvent) -> Result<VerifiedInvoice> {
        match self.deployment.committee() {
            CommitteeBinding::Single { encryption_key, .. } => {
                let message = decode_artifact(ArtifactSlot::InvoiceProof, event.invoice_proof.as_bytes())?;
                let PublicMessageV1::Invoice(envelope) = message else {
                    return Err(unexpected_type(
                        ArtifactSlot::InvoiceProof,
                        PublicMessageKind::Invoice,
                        &message,
                    ));
                };
                self.verify_binding(&envelope.binding, entry, &event.invoice_id, None)?;
                ensure_bytes(
                    "invoice.recipient_encryption_key",
                    event.recipient_encryption_key.as_bytes(),
                    envelope.statement.bob_key.as_bytes(),
                )?;
                ensure_bytes(
                    "invoice.public_delta",
                    event.public_delta.as_bytes(),
                    envelope.statement.delta.as_bytes(),
                )?;
                ensure_bytes(
                    "invoice.recipient_ciphertext",
                    event.recipient_ciphertext.as_bytes(),
                    envelope.statement.bob_ciphertext.as_bytes(),
                )?;
                ensure_bytes(
                    "invoice.committee_package",
                    event.committee_package.as_bytes(),
                    envelope.statement.committee_ciphertext.as_bytes(),
                )?;
                ensure_bytes(
                    "invoice.anchor_base",
                    self.deployment.anchor_base().as_bytes(),
                    envelope.statement.anchor_base.as_bytes(),
                )?;
                if envelope.statement.committee_key.as_bytes() != encryption_key.as_bytes() {
                    return Err(VerifierError::CommitteeMismatch {
                        field: "encryption_key",
                    });
                }
                envelope.verify().map_err(|source| VerifierError::VerificationFailed {
                    message: PublicMessageKind::Invoice,
                    source,
                })?;
                let digest = canonical_digest(PublicMessageKind::Invoice, &envelope)?;
                Ok(VerifiedInvoice {
                    evidence_digest: digest,
                    statement_digests: vec![StatementDigest {
                        kind: StatementKind::Invoice,
                        digest,
                    }],
                })
            }
            CommitteeBinding::Threshold { threshold, members, .. } => {
                let recipient_message = decode_artifact(ArtifactSlot::InvoiceProof, event.invoice_proof.as_bytes())?;
                let PublicMessageV1::Share(recipient) = recipient_message else {
                    return Err(unexpected_type(
                        ArtifactSlot::InvoiceProof,
                        PublicMessageKind::Share,
                        &recipient_message,
                    ));
                };
                let committee_message =
                    decode_artifact(ArtifactSlot::CommitteePackage, event.committee_package.as_bytes())?;
                let PublicMessageV1::ThresholdRefresh(distribution) = committee_message else {
                    return Err(unexpected_type(
                        ArtifactSlot::CommitteePackage,
                        PublicMessageKind::ThresholdRefresh,
                        &committee_message,
                    ));
                };
                self.verify_binding(&recipient.binding, entry, &event.invoice_id, None)?;
                self.verify_binding(&distribution.binding, entry, &event.invoice_id, None)?;
                self.verify_threshold_invoice_fields(event, &recipient, &distribution, *threshold, members)?;
                recipient.verify().map_err(|source| VerifierError::VerificationFailed {
                    message: PublicMessageKind::Share,
                    source,
                })?;
                distribution
                    .verify()
                    .map_err(|source| VerifierError::VerificationFailed {
                        message: PublicMessageKind::ThresholdRefresh,
                        source,
                    })?;
                let recipient_digest = canonical_digest(PublicMessageKind::Share, &recipient)?;
                let distribution_digest = canonical_digest(PublicMessageKind::ThresholdRefresh, &distribution)?;
                let package_digest = threshold_invoice_package_digest(recipient_digest, distribution_digest);
                Ok(VerifiedInvoice {
                    evidence_digest: package_digest,
                    statement_digests: vec![
                        StatementDigest {
                            kind: StatementKind::RecipientShare,
                            digest: recipient_digest,
                        },
                        StatementDigest {
                            kind: StatementKind::ThresholdRefresh,
                            digest: distribution_digest,
                        },
                        StatementDigest {
                            kind: StatementKind::ThresholdInvoicePackage,
                            digest: package_digest,
                        },
                    ],
                })
            }
        }
    }

    fn verify_threshold_invoice_fields(
        &self,
        event: &InvoiceEvent,
        recipient: &ShareEnvelopeV1,
        distribution: &ThresholdEnvelopeV1,
        threshold: u16,
        members: &std::collections::BTreeMap<u32, thunderbolt_wire::PaillierPublicKeyHex>,
    ) -> Result<()> {
        if recipient.statement.member_id != RECIPIENT_SHARE_MEMBER_ID {
            return Err(VerifierError::CommitteeMismatch {
                field: "recipient_share_member_id",
            });
        }
        for (field, event_bytes, statement_bytes) in [
            (
                "invoice.recipient_encryption_key",
                event.recipient_encryption_key.as_bytes(),
                recipient.statement.recipient_key.as_bytes(),
            ),
            (
                "invoice.public_delta",
                event.public_delta.as_bytes(),
                recipient.statement.committed_point.as_bytes(),
            ),
            (
                "invoice.recipient_ciphertext",
                event.recipient_ciphertext.as_bytes(),
                recipient.statement.ciphertext.as_bytes(),
            ),
            (
                "invoice.recipient_anchor_base",
                self.deployment.anchor_base().as_bytes(),
                recipient.statement.anchor_base.as_bytes(),
            ),
            (
                "invoice.committee_anchor_base",
                self.deployment.anchor_base().as_bytes(),
                distribution.distribution.anchor_base.as_bytes(),
            ),
            (
                "invoice.committee_delta",
                event.public_delta.as_bytes(),
                distribution.distribution.delta.as_bytes(),
            ),
        ] {
            ensure_bytes(field, event_bytes, statement_bytes)?;
        }
        if distribution.distribution.threshold != u32::from(threshold) {
            return Err(VerifierError::CommitteeMismatch { field: "threshold" });
        }
        if distribution.distribution.encrypted_shares.len() != members.len() {
            return Err(VerifierError::CommitteeMismatch { field: "member_count" });
        }
        for (share, (member_id, key)) in distribution.distribution.encrypted_shares.iter().zip(members.iter()) {
            if share.member_id != *member_id {
                return Err(VerifierError::CommitteeMismatch { field: "member_id" });
            }
            if share.encryption_key.as_bytes() != key.as_bytes() {
                return Err(VerifierError::CommitteeMismatch {
                    field: "member_encryption_key",
                });
            }
        }
        Ok(())
    }

    fn verify_transfer_fields(
        &self,
        event: &TransferEvent,
        snapshot: &ChannelSnapshot,
        invoice: &InvoiceEvent,
        envelope: &TransferEnvelopeV1,
    ) -> Result<()> {
        for (field, expected, actual) in [
            (
                "transfer.anchor_base",
                self.deployment.anchor_base().as_bytes(),
                envelope.statement.anchor_base.as_bytes(),
            ),
            (
                "transfer.current_anchor",
                snapshot.current_holder_anchor.as_bytes(),
                envelope.statement.current_anchor.as_bytes(),
            ),
            (
                "transfer.invoice_recipient_key",
                invoice.recipient_encryption_key.as_bytes(),
                envelope.statement.bob_key.as_bytes(),
            ),
            (
                "transfer.invoice_ciphertext",
                invoice.recipient_ciphertext.as_bytes(),
                envelope.statement.invoice_ciphertext.as_bytes(),
            ),
            (
                "transfer.next_holder_ciphertext",
                event.next_holder_ciphertext.as_bytes(),
                envelope.statement.next_holder_ciphertext.as_bytes(),
            ),
            (
                "transfer.transition_current_anchor",
                snapshot.current_holder_anchor.as_bytes(),
                envelope.anchor_transition.current_anchor.as_bytes(),
            ),
            (
                "transfer.delta",
                invoice.public_delta.as_bytes(),
                envelope.anchor_transition.delta.as_bytes(),
            ),
            (
                "transfer.next_holder_anchor",
                event.next_holder_anchor.as_bytes(),
                envelope.anchor_transition.next_anchor.as_bytes(),
            ),
        ] {
            ensure_bytes(field, expected, actual)?;
        }
        Ok(())
    }

    fn verify_pending_invoice_link(
        &self,
        snapshot: &ChannelSnapshot,
        invoice_entry: &LedgerEntry,
        invoice: &InvoiceEvent,
    ) -> Result<()> {
        if invoice_entry.protocol_version != PROTOCOL_VERSION {
            return Err(VerifierError::PriorInvoiceMismatch {
                field: "protocol_version",
            });
        }
        if invoice_entry.channel_id != snapshot.channel_id {
            return Err(VerifierError::PriorInvoiceMismatch { field: "channel_id" });
        }
        if invoice_entry.sequence != snapshot.last_sequence {
            return Err(VerifierError::PriorInvoiceMismatch { field: "sequence" });
        }
        if invoice_entry.entry_hash() != snapshot.head_hash {
            return Err(VerifierError::PriorInvoiceMismatch { field: "entry_hash" });
        }
        let pending = snapshot
            .pending_invoice
            .as_ref()
            .ok_or(VerifierError::PriorInvoiceMismatch {
                field: "snapshot.pending_invoice",
            })?;
        if pending.invoice_id != invoice.invoice_id {
            return Err(VerifierError::PriorInvoiceMismatch { field: "invoice_id" });
        }
        if pending.recipient != invoice.recipient {
            return Err(VerifierError::PriorInvoiceMismatch { field: "recipient" });
        }
        if pending.expires_at_ms != invoice.expires_at_ms {
            return Err(VerifierError::PriorInvoiceMismatch { field: "expires_at_ms" });
        }
        Ok(())
    }

    fn verify_prior_evidence(
        &self,
        invoice: &InvoiceEvent,
        expected_digest: Digest,
        expected_verified_at_ms: u64,
        ledger_time_ms: u64,
    ) -> Result<()> {
        let [evidence] = invoice.verification.as_slice() else {
            return Err(VerifierError::PriorInvoiceMismatch {
                field: "verification_count",
            });
        };
        if evidence.kind != VerificationKind::InvoiceConsistencyProof {
            return Err(VerifierError::PriorInvoiceMismatch {
                field: "verification_kind",
            });
        }
        if evidence.verifier != *self.identity.participant_id()
            || evidence.implementation != *self.identity.implementation()
        {
            return Err(VerifierError::PriorInvoiceMismatch {
                field: "verification_identity",
            });
        }
        if evidence.statement_digest != expected_digest || evidence.outcome != VerificationOutcome::Verified {
            return Err(VerifierError::PriorInvoiceMismatch {
                field: "verification_result",
            });
        }
        if evidence.verified_at_ms != expected_verified_at_ms {
            return Err(VerifierError::PriorInvoiceMismatch {
                field: "verification_time",
            });
        }
        if evidence.verified_at_ms > ledger_time_ms {
            return Err(VerifierError::InvalidTrustedTime {
                field: "pending invoice verification",
            });
        }
        Ok(())
    }

    fn verify_binding(
        &self,
        binding: &BindingContext,
        entry: &LedgerEntry,
        invoice_id: &InvoiceId,
        step: Option<u64>,
    ) -> Result<()> {
        if binding.protocol_version != entry.protocol_version {
            return Err(VerifierError::BindingMismatch {
                field: BindingField::ProtocolVersion,
            });
        }
        if binding.network != self.deployment.network() {
            return Err(VerifierError::BindingMismatch {
                field: BindingField::Network,
            });
        }
        if binding.deployment_id.as_bytes() != self.deployment.deployment_id().as_bytes() {
            return Err(VerifierError::BindingMismatch {
                field: BindingField::DeploymentId,
            });
        }
        if binding.committee_epoch != self.deployment.committee_epoch() {
            return Err(VerifierError::BindingMismatch {
                field: BindingField::CommitteeEpoch,
            });
        }
        if binding.channel_id.as_bytes() != entry.channel_id.canonical_bytes().as_slice() {
            return Err(VerifierError::BindingMismatch {
                field: BindingField::ChannelId,
            });
        }
        if binding.invoice_id.as_bytes() != invoice_id.as_str().as_bytes() {
            return Err(VerifierError::BindingMismatch {
                field: BindingField::InvoiceId,
            });
        }
        if binding.step != step {
            return Err(VerifierError::BindingMismatch {
                field: BindingField::Step,
            });
        }
        Ok(())
    }

    fn evidence(&self, kind: VerificationKind, digest: Digest, ledger_time_ms: u64) -> VerificationEvidence {
        VerificationEvidence::verified(
            kind,
            self.identity.participant_id().clone(),
            self.identity.implementation().clone(),
            digest,
            ledger_time_ms,
        )
    }
}

#[derive(Debug)]
struct VerifiedInvoice {
    evidence_digest: Digest,
    statement_digests: Vec<StatementDigest>,
}

/// Decodes one public message using the wire crate's existing 2 MiB bound and
/// field-specific canonical validation.
pub fn decode_bounded_message(encoded: &[u8]) -> Result<PublicMessageV1> {
    decode_artifact(ArtifactSlot::WireMessage, encoded)
}

fn decode_artifact(slot: ArtifactSlot, encoded: &[u8]) -> Result<PublicMessageV1> {
    from_json_slice(encoded).map_err(|source| VerifierError::ArtifactDecode { slot, source })
}

fn unexpected_type(slot: ArtifactSlot, expected: PublicMessageKind, actual: &PublicMessageV1) -> VerifierError {
    VerifierError::UnexpectedMessageType {
        slot,
        expected,
        actual: message_kind(actual),
    }
}

fn message_kind(message: &PublicMessageV1) -> PublicMessageKind {
    match message {
        PublicMessageV1::Invoice(_) => PublicMessageKind::Invoice,
        PublicMessageV1::Transfer(_) => PublicMessageKind::Transfer,
        PublicMessageV1::Share(_) => PublicMessageKind::Share,
        PublicMessageV1::ThresholdRefresh(_) => PublicMessageKind::ThresholdRefresh,
    }
}

fn ensure_bytes(field: &'static str, expected: &[u8], actual: &[u8]) -> Result<()> {
    if expected != actual {
        return Err(VerifierError::PublicFieldMismatch { field });
    }
    Ok(())
}

fn ensure_not_expired(expires_at_ms: Option<u64>, ledger_time_ms: u64) -> Result<()> {
    if let Some(expires_at_ms) = expires_at_ms {
        if ledger_time_ms >= expires_at_ms {
            return Err(VerifierError::InvoiceExpired {
                expires_at_ms,
                ledger_time_ms,
            });
        }
    }
    Ok(())
}

fn canonical_digest<T>(message: PublicMessageKind, value: &T) -> Result<Digest>
where
    T: CanonicalDigest,
{
    value
        .canonical_digest()
        .map(Digest::from_bytes)
        .map_err(|source| VerifierError::VerificationFailed { message, source })
}

fn threshold_invoice_package_digest(recipient: Digest, distribution: Digest) -> Digest {
    let mut hasher = Sha256::new();
    hasher.update(b"bitcoin-thunderbolt/verifier/threshold-invoice-package/v1");
    hasher.update(recipient.as_bytes());
    hasher.update(distribution.as_bytes());
    Digest::from_bytes(hasher.finalize().into())
}
