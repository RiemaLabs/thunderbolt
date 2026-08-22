use crate::{Artifact, BitcoinTxid, Digest, ImplementationId, InvoiceId, ParticipantId, ProtocolError};
use serde::{Deserialize, Deserializer, Serialize};

/// Maximum supported members in one threshold committee description.
pub const MAX_COMMITTEE_MEMBERS: u16 = 1_024;
/// The maximum number of satoshis that can exist under Bitcoin's consensus cap.
pub const MAX_BITCOIN_SUPPLY_SAT: u64 = 2_100_000_000_000_000;

/// A participant and the protocol role under which it submitted an entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Actor {
    /// Stable public identity of the submitting participant.
    pub participant_id: ParticipantId,
    /// Role asserted for this operation.
    pub role: ActorRole,
}

impl Actor {
    /// Constructs an actor.
    pub fn new(participant_id: ParticipantId, role: ActorRole) -> Self {
        Self { participant_id, role }
    }
}

/// Roles that may be represented in authenticated protocol messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActorRole {
    /// The party that currently controls the off-chain UTXO share.
    Holder,
    /// The invoice creator and prospective next holder.
    Recipient,
    /// A threshold committee member or aggregate committee identity.
    Committee,
    /// An operator of the shared append-only Thunderbolt Ledger.
    LedgerOperator,
}

/// Threshold committee identity and quorum parameters.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Committee {
    committee_id: ParticipantId,
    member_count: u16,
    threshold: u16,
}

impl Committee {
    /// Validates and constructs a committee descriptor.
    pub fn new(committee_id: ParticipantId, member_count: u16, threshold: u16) -> Result<Self, ProtocolError> {
        let committee = Self {
            committee_id,
            member_count,
            threshold,
        };
        committee.validate()?;
        Ok(committee)
    }

    /// Returns the stable committee identity.
    pub fn committee_id(&self) -> &ParticipantId {
        &self.committee_id
    }

    /// Returns the number of registered committee members.
    pub const fn member_count(&self) -> u16 {
        self.member_count
    }

    /// Returns the number of members required for a quorum.
    pub const fn threshold(&self) -> u16 {
        self.threshold
    }

    pub(crate) fn validate(&self) -> Result<(), ProtocolError> {
        if self.member_count == 0 {
            return Err(ProtocolError::InvalidCommittee {
                reason: "member count must be positive",
            });
        }
        if self.member_count > MAX_COMMITTEE_MEMBERS {
            return Err(ProtocolError::InvalidCommittee {
                reason: "member count exceeds protocol limit",
            });
        }
        if self.threshold == 0 || self.threshold > self.member_count {
            return Err(ProtocolError::InvalidCommittee {
                reason: "threshold must be between 1 and member count",
            });
        }
        Ok(())
    }
}

impl<'de> Deserialize<'de> for Committee {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct CommitteeWire {
            committee_id: ParticipantId,
            member_count: u16,
            threshold: u16,
        }

        let wire = CommitteeWire::deserialize(deserializer)?;
        Committee::new(wire.committee_id, wire.member_count, wire.threshold).map_err(serde::de::Error::custom)
    }
}

/// A node-verification operation represented by an attestation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationKind {
    /// The channel outpoint, amount, and lock were checked against Bitcoin.
    FundingTransaction,
    /// The initial anchor, ciphertext, and fixed-key relationship were checked.
    InitialState,
    /// The Invoice Consistency Proof was checked.
    InvoiceConsistencyProof,
    /// The Transfer Consistency Proof was checked.
    TransferConsistencyProof,
    /// The public next-anchor transition was checked.
    AnchorTransition,
    /// The final holder's ownership proof was checked.
    HolderOwnershipProof,
    /// The configured threshold of committee acknowledgements was checked.
    CommitteeQuorum,
    /// The final transaction was checked against Bitcoin.
    ClosingTransaction,
}

/// Result reported by a verifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationOutcome {
    /// The verifier accepted the public statement.
    Verified,
    /// The verifier rejected the public statement.
    Rejected,
}

/// Explicit evidence that a node-side verifier processed a statement.
///
/// This is an attestation record, not a proof verifier. `statement_digest`
/// identifies the exact statement bytes interpreted by the named
/// implementation. Nodes must decide which implementations and verifier
/// identities they trust.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerificationEvidence {
    /// Verification that was performed.
    pub kind: VerificationKind,
    /// Identity of the verifier or quorum aggregator.
    pub verifier: ParticipantId,
    /// Exact verifier implementation and version.
    pub implementation: ImplementationId,
    /// SHA-256 digest of the verifier's canonical public statement.
    pub statement_digest: Digest,
    /// Externally supplied Unix timestamp in milliseconds.
    pub verified_at_ms: u64,
    /// Reported result.
    pub outcome: VerificationOutcome,
}

impl VerificationEvidence {
    /// Constructs a successful verification attestation.
    pub fn verified(
        kind: VerificationKind,
        verifier: ParticipantId,
        implementation: ImplementationId,
        statement_digest: Digest,
        verified_at_ms: u64,
    ) -> Self {
        Self {
            kind,
            verifier,
            implementation,
            statement_digest,
            verified_at_ms,
            outcome: VerificationOutcome::Verified,
        }
    }
}

/// Payload committed when a funded UTXO becomes a Thunderbolt channel.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OpenEvent {
    /// Initial off-chain holder.
    pub initial_holder: ParticipantId,
    /// Committee and quorum configuration fixed at open.
    pub committee: Committee,
    /// Whole-UTXO channel capacity.
    pub capacity_sat: u64,
    /// Public fixed Bitcoin lock key `P`.
    pub lock_key: Artifact,
    /// Initial public holder anchor `X_0`.
    pub initial_holder_anchor: Artifact,
    /// Initial encrypted holder credential `T_0`.
    pub initial_holder_ciphertext: Artifact,
    /// Node-produced verification attestations.
    pub verification: Vec<VerificationEvidence>,
}

/// Payload committed when the prospective next holder publishes an invoice.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InvoiceEvent {
    /// Recipient-generated, channel-lifetime-unique invoice id.
    pub invoice_id: InvoiceId,
    /// Prospective next holder.
    pub recipient: ParticipantId,
    /// Recipient's public encryption key.
    pub recipient_encryption_key: Artifact,
    /// Public delta point `D_s`.
    pub public_delta: Artifact,
    /// Recipient ciphertext `ct_B`.
    pub recipient_ciphertext: Artifact,
    /// Committee ciphertext or VESS distribution package.
    pub committee_package: Artifact,
    /// Invoice Consistency Proof `pi_inv`.
    pub invoice_proof: Artifact,
    /// Optional exclusive expiration, as externally supplied Unix ms.
    pub expires_at_ms: Option<u64>,
    /// Node-produced verification attestations.
    pub verification: Vec<VerificationEvidence>,
}

/// Payload committed when the current holder transfers to the invoice creator.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransferEvent {
    /// Pending invoice being consumed.
    pub invoice_id: InvoiceId,
    /// Current holder authorizing the transition.
    pub sender: ParticipantId,
    /// New holder named by the invoice.
    pub recipient: ParticipantId,
    /// Public anchor `X_(s+1)`.
    pub next_holder_anchor: Artifact,
    /// Encrypted next-holder credential `T_(s+1)`.
    pub next_holder_ciphertext: Artifact,
    /// Transfer Consistency Proof `pi_xfer`.
    pub transfer_proof: Artifact,
    /// Node-produced verification attestations.
    pub verification: Vec<VerificationEvidence>,
}

/// Payload committed when the current holder and committee close on Bitcoin.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FinalizeEvent {
    /// Final current holder.
    pub holder: ParticipantId,
    /// Bitcoin closing transaction id.
    pub closing_txid: BitcoinTxid,
    /// Proof of knowledge for the current holder anchor.
    pub ownership_proof: Artifact,
    /// Aggregate committee acknowledgement/signature material.
    pub committee_attestation: Artifact,
    /// Node-produced verification attestations.
    pub verification: Vec<VerificationEvidence>,
}

/// Version-one channel ledger event payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", content = "data", rename_all = "snake_case")]
pub enum ChannelEvent {
    /// Establishes the channel.
    Open(OpenEvent),
    /// Publishes one invoice.
    Invoice(InvoiceEvent),
    /// Consumes the pending invoice and rotates ownership.
    Transfer(TransferEvent),
    /// Irreversibly closes the channel.
    Finalize(FinalizeEvent),
}

impl ChannelEvent {
    /// Returns the event discriminant.
    pub const fn kind(&self) -> EventKind {
        match self {
            Self::Open(_) => EventKind::Open,
            Self::Invoice(_) => EventKind::Invoice,
            Self::Transfer(_) => EventKind::Transfer,
            Self::Finalize(_) => EventKind::Finalize,
        }
    }

    /// Returns this event's verification evidence.
    pub fn verification(&self) -> &[VerificationEvidence] {
        match self {
            Self::Open(event) => &event.verification,
            Self::Invoice(event) => &event.verification,
            Self::Transfer(event) => &event.verification,
            Self::Finalize(event) => &event.verification,
        }
    }

    /// Returns the invoice id created by this event, if any.
    pub fn created_invoice_id(&self) -> Option<&InvoiceId> {
        match self {
            Self::Invoice(event) => Some(&event.invoice_id),
            _ => None,
        }
    }

    /// Verification kinds that must be successfully attested before reduction.
    pub const fn required_verifications(&self) -> &'static [VerificationKind] {
        use VerificationKind as Kind;
        match self {
            Self::Open(_) => &[Kind::FundingTransaction, Kind::InitialState, Kind::CommitteeQuorum],
            Self::Invoice(_) => &[Kind::InvoiceConsistencyProof],
            Self::Transfer(_) => &[Kind::TransferConsistencyProof, Kind::AnchorTransition],
            Self::Finalize(_) => &[
                Kind::HolderOwnershipProof,
                Kind::CommitteeQuorum,
                Kind::ClosingTransaction,
            ],
        }
    }
}

/// Event discriminant used by state and error APIs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventKind {
    /// Channel opening.
    Open,
    /// Invoice publication.
    Invoice,
    /// Off-chain ownership transfer.
    Transfer,
    /// On-chain finalization.
    Finalize,
}

impl core::fmt::Display for EventKind {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let name = match self {
            Self::Open => "Open",
            Self::Invoice => "Invoice",
            Self::Transfer => "Transfer",
            Self::Finalize => "Finalize",
        };
        formatter.write_str(name)
    }
}
