use crate::{Digest, ProtocolError, MAX_BITCOIN_SUPPLY_SAT};
use core::{fmt, str::FromStr};
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest as _, Sha256};
use std::collections::BTreeMap;
use thiserror::Error;
use thunderbolt_ledger::{EntryHashV2, EventDigestV2, LedgerChainIdV2, ParticipantIdV2, EVENT_BYTES_MAX};
use thunderbolt_wire::{CanonicalDigest as _, ChannelBindingV2, InvoiceId, ValidateWire as _};

use super::canonical::{decode_event, encode_event, encode_state, encoded_event_len, encoded_invoice_event_len};

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
/// Maximum cumulative canonical Invoice-event bytes retained in one snapshot.
pub const MAX_PENDING_INVOICE_EVENT_BYTES_V2: usize = 8 * 1024 * 1024;
/// Maximum bytes in one opaque public version-two protocol artifact.
pub const MAX_ARTIFACT_BYTES_V2: usize = 2 * 1024 * 1024;
/// Maximum retained public state bytes before canonical framing and indexes.
pub const MAX_RETAINED_CHANNEL_STATE_BYTES_V2: usize = 11 * 1024 * 1024;
/// Maximum canonical snapshot bytes returned by state-query transports.
pub const MAX_CANONICAL_SNAPSHOT_BYTES_V2: usize = 12 * 1024 * 1024;
/// Reserved canonical framing and per-pending-record metadata outside retained bytes.
pub const SNAPSHOT_CANONICAL_FRAMING_ALLOWANCE_BYTES_V2: usize = 1024 * 1024;
/// Default maximum lifetime of a pending Invoice: 24 hours.
pub const DEFAULT_MAX_INVOICE_TTL_MS_V2: u64 = 86_400_000;
/// Absolute maximum Invoice lifetime: 30 days.
pub const ABSOLUTE_MAX_INVOICE_TTL_MS_V2: u64 = 2_592_000_000;
/// Maximum committee topology supported by the active threshold wire suite.
pub const MAX_COMMITTEE_MEMBERS_V2: u16 = 256;

/// Bounded opaque public protocol data for version two.
///
/// This type is deliberately distinct from the version-one [`crate::Artifact`]
/// so increasing the v2 capacity cannot change the stable v1 boundary.
///
/// ```compile_fail
/// use thunderbolt_protocol::{Artifact, v2::ArtifactV2};
/// let v2 = ArtifactV2::new([1]).unwrap();
/// let _: Artifact = v2;
/// ```
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ArtifactV2(Vec<u8>);

impl ArtifactV2 {
    /// Validates and constructs one non-empty v2 public artifact.
    pub fn new(bytes: impl Into<Vec<u8>>) -> Result<Self, ProtocolError> {
        let bytes = bytes.into();
        if bytes.is_empty() {
            return Err(ProtocolError::InvalidArtifact {
                reason: "must not be empty",
            });
        }
        if bytes.len() > MAX_ARTIFACT_BYTES_V2 {
            return Err(ProtocolError::InvalidArtifact {
                reason: "exceeds maximum v2 byte length",
            });
        }
        Ok(Self(bytes))
    }

    /// Borrows the exact public bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Consumes the wrapper and returns its bytes.
    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }

    /// Returns the SHA-256 digest of the artifact bytes.
    pub fn digest(&self) -> Digest {
        Digest::from_bytes(Sha256::digest(&self.0).into())
    }
}

impl fmt::Debug for ArtifactV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ArtifactV2")
            .field("bytes", &self.0.len())
            .field("sha256", &self.digest())
            .finish()
    }
}

impl Serialize for ArtifactV2 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut encoded = String::with_capacity(self.0.len() * 2);
        const HEX: &[u8; 16] = b"0123456789abcdef";
        for byte in &self.0 {
            encoded.push(HEX[usize::from(byte >> 4)] as char);
            encoded.push(HEX[usize::from(byte & 0x0f)] as char);
        }
        serializer.serialize_str(&encoded)
    }
}

impl<'de> Deserialize<'de> for ArtifactV2 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct ArtifactV2Visitor;

        impl de::Visitor<'_> for ArtifactV2Visitor {
            type Value = ArtifactV2;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a non-empty bounded lowercase hexadecimal v2 artifact")
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                if value.is_empty()
                    || value.len() > MAX_ARTIFACT_BYTES_V2 * 2
                    || !value.len().is_multiple_of(2)
                    || !value
                        .bytes()
                        .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
                {
                    return Err(E::custom("v2 artifact must be non-empty bounded lowercase hexadecimal"));
                }
                let mut bytes = Vec::with_capacity(value.len() / 2);
                for pair in value.as_bytes().chunks_exact(2) {
                    let high = hex_nibble(pair[0]).ok_or_else(|| E::custom("invalid v2 artifact hex"))?;
                    let low = hex_nibble(pair[1]).ok_or_else(|| E::custom("invalid v2 artifact hex"))?;
                    bytes.push((high << 4) | low);
                }
                ArtifactV2::new(bytes).map_err(E::custom)
            }
        }

        deserializer.deserialize_str(ArtifactV2Visitor)
    }
}

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
    pub lock_key: ArtifactV2,
    /// Initial public Holder anchor `X_0`.
    pub initial_holder_anchor: ArtifactV2,
    /// Initial encrypted Holder credential `T_0`.
    pub initial_holder_ciphertext: ArtifactV2,
    /// Public Open proof package interpreted by the trusted verifier.
    pub open_proof: ArtifactV2,
}

/// Payload that publishes one concurrently pending invoice.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InvoiceEventV2 {
    /// Channel-lifetime-unique invoice identifier.
    pub invoice_id: InvoiceId,
    /// Holder step against which the invoice proof was formed.
    pub holder_step: u64,
    /// Recipient's public encryption key.
    pub recipient_encryption_key: ArtifactV2,
    /// Public delta point `D_s`.
    pub public_delta: ArtifactV2,
    /// Recipient ciphertext `ct_B`.
    pub recipient_ciphertext: ArtifactV2,
    /// Committee ciphertext or VESS distribution package.
    pub committee_package: ArtifactV2,
    /// Invoice consistency proof.
    pub invoice_proof: ArtifactV2,
    /// Mandatory exclusive expiry in trusted Ledger milliseconds.
    pub expires_at_ms: u64,
}

#[derive(Deserialize)]
#[serde(field_identifier, rename_all = "snake_case")]
enum InvoiceEventField {
    InvoiceId,
    HolderStep,
    RecipientEncryptionKey,
    PublicDelta,
    RecipientCiphertext,
    CommitteePackage,
    InvoiceProof,
    ExpiresAtMs,
}

struct InvoiceEventVisitor;

impl<'de> de::Visitor<'de> for InvoiceEventVisitor {
    type Value = InvoiceEventV2;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a bounded version-two Invoice event")
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: de::MapAccess<'de>,
    {
        let mut invoice_id = None;
        let mut holder_step = None;
        let mut recipient_encryption_key = None;
        let mut public_delta = None;
        let mut recipient_ciphertext = None;
        let mut committee_package = None;
        let mut invoice_proof = None;
        let mut expires_at_ms = None;
        let mut artifact_bytes = 0_usize;
        while let Some(field) = map.next_key::<InvoiceEventField>()? {
            match field {
                InvoiceEventField::InvoiceId => set_once(&mut invoice_id, map.next_value()?, "invoice_id")?,
                InvoiceEventField::HolderStep => set_once(&mut holder_step, map.next_value()?, "holder_step")?,
                InvoiceEventField::RecipientEncryptionKey => {
                    let value: ArtifactV2 = map.next_value()?;
                    add_invoice_artifact_bytes::<A::Error>(&mut artifact_bytes, &value)?;
                    set_once(&mut recipient_encryption_key, value, "recipient_encryption_key")?;
                }
                InvoiceEventField::PublicDelta => {
                    let value: ArtifactV2 = map.next_value()?;
                    add_invoice_artifact_bytes::<A::Error>(&mut artifact_bytes, &value)?;
                    set_once(&mut public_delta, value, "public_delta")?;
                }
                InvoiceEventField::RecipientCiphertext => {
                    let value: ArtifactV2 = map.next_value()?;
                    add_invoice_artifact_bytes::<A::Error>(&mut artifact_bytes, &value)?;
                    set_once(&mut recipient_ciphertext, value, "recipient_ciphertext")?;
                }
                InvoiceEventField::CommitteePackage => {
                    let value: ArtifactV2 = map.next_value()?;
                    add_invoice_artifact_bytes::<A::Error>(&mut artifact_bytes, &value)?;
                    set_once(&mut committee_package, value, "committee_package")?;
                }
                InvoiceEventField::InvoiceProof => {
                    let value: ArtifactV2 = map.next_value()?;
                    add_invoice_artifact_bytes::<A::Error>(&mut artifact_bytes, &value)?;
                    set_once(&mut invoice_proof, value, "invoice_proof")?;
                }
                InvoiceEventField::ExpiresAtMs => {
                    set_once(&mut expires_at_ms, map.next_value()?, "expires_at_ms")?;
                }
            }
        }
        let value = InvoiceEventV2 {
            invoice_id: required(invoice_id, "invoice_id")?,
            holder_step: required(holder_step, "holder_step")?,
            recipient_encryption_key: required(recipient_encryption_key, "recipient_encryption_key")?,
            public_delta: required(public_delta, "public_delta")?,
            recipient_ciphertext: required(recipient_ciphertext, "recipient_ciphertext")?,
            committee_package: required(committee_package, "committee_package")?,
            invoice_proof: required(invoice_proof, "invoice_proof")?,
            expires_at_ms: required(expires_at_ms, "expires_at_ms")?,
        };
        if encoded_invoice_event_len(&value).is_none_or(|length| length > EVENT_BYTES_MAX) {
            return Err(de::Error::custom(
                "Invoice event exceeds the canonical event byte bound",
            ));
        }
        Ok(value)
    }
}

impl<'de> Deserialize<'de> for InvoiceEventV2 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_struct(
            "InvoiceEventV2",
            &[
                "invoice_id",
                "holder_step",
                "recipient_encryption_key",
                "public_delta",
                "recipient_ciphertext",
                "committee_package",
                "invoice_proof",
                "expires_at_ms",
            ],
            InvoiceEventVisitor,
        )
    }
}

fn add_invoice_artifact_bytes<E: de::Error>(total: &mut usize, value: &ArtifactV2) -> Result<(), E> {
    *total = total
        .checked_add(value.as_bytes().len())
        .ok_or_else(|| E::custom("Invoice artifact byte count overflows"))?;
    if *total > EVENT_BYTES_MAX {
        return Err(E::custom("Invoice artifacts exceed the canonical event byte bound"));
    }
    Ok(())
}

fn set_once<T, E: de::Error>(slot: &mut Option<T>, value: T, field: &'static str) -> Result<(), E> {
    if slot.replace(value).is_some() {
        return Err(E::duplicate_field(field));
    }
    Ok(())
}

fn required<T, E: de::Error>(value: Option<T>, field: &'static str) -> Result<T, E> {
    value.ok_or_else(|| E::missing_field(field))
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
    pub next_holder_anchor: ArtifactV2,
    /// Encrypted Holder credential after the transfer.
    pub next_holder_ciphertext: ArtifactV2,
    /// Transfer consistency proof.
    pub transfer_proof: ArtifactV2,
}

/// Payload that closes the channel after the latest committed event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FinalizeEventV2 {
    /// Display-order bytes of the Bitcoin closing transaction id.
    pub closing_txid: [u8; 32],
    /// Exact bounded raw closing transaction checked by the trusted verifier.
    pub closing_transaction: ArtifactV2,
    /// Proof of current-Holder ownership.
    pub ownership_proof: ArtifactV2,
    /// Committee threshold acknowledgement or signature material.
    pub committee_attestation: ArtifactV2,
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

    pub(crate) fn canonical_event_len(&self) -> Result<usize, V2Error> {
        let length = encoded_invoice_event_len(&self.event).ok_or(V2Error::InvalidCanonicalEvent)?;
        if length > EVENT_BYTES_MAX {
            return Err(V2Error::InvalidCanonicalEvent);
        }
        Ok(length)
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
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
    pub lock_key: ArtifactV2,
    /// Current Holder identity derived from its authenticated BIP340 key.
    pub current_holder: ParticipantIdV2,
    /// Current public Holder anchor.
    pub current_holder_anchor: ArtifactV2,
    /// Current encrypted Holder credential.
    pub current_holder_ciphertext: ArtifactV2,
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

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ChannelSnapshotInput {
    protocol_version: u16,
    ledger_chain_id: LedgerChainIdV2,
    binding: ChannelBindingV2,
    phase: ChannelPhaseV2,
    capacity_sat: u64,
    committee_member_count: u16,
    committee_threshold: u16,
    lock_key: ArtifactV2,
    current_holder: ParticipantIdV2,
    current_holder_anchor: ArtifactV2,
    current_holder_ciphertext: ArtifactV2,
    transfers_completed: u64,
    pending_invoices: BoundedPendingInvoices,
    last_consumed_invoice_id: Option<InvoiceId>,
    last_sequence: u64,
    head_entry_hash: EntryHashV2,
    opened_at_ms: u64,
    last_block_time_ms: u64,
    finalized_at_ms: Option<u64>,
}

struct BoundedPendingInvoices(BTreeMap<InvoiceId, PendingInvoiceV2>);

struct PendingInvoiceMapVisitor;

impl<'de> de::Visitor<'de> for PendingInvoiceMapVisitor {
    type Value = BoundedPendingInvoices;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "at most {ABSOLUTE_MAX_PENDING_INVOICES_V2} pending Invoices within {MAX_PENDING_INVOICE_EVENT_BYTES_V2} canonical bytes"
        )
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: de::MapAccess<'de>,
    {
        if map
            .size_hint()
            .is_some_and(|size| size > ABSOLUTE_MAX_PENDING_INVOICES_V2)
        {
            return Err(de::Error::custom("pending Invoice count exceeds the absolute bound"));
        }
        let mut values = BTreeMap::new();
        let mut event_bytes = 0_usize;
        while let Some(invoice_id) = map.next_key::<InvoiceId>()? {
            if values.len() == ABSOLUTE_MAX_PENDING_INVOICES_V2 {
                return Err(de::Error::custom("pending Invoice count exceeds the absolute bound"));
            }
            if values.contains_key(&invoice_id) {
                return Err(de::Error::custom("snapshot contains a duplicate pending Invoice id"));
            }
            let invoice = map.next_value::<PendingInvoiceV2>()?;
            let length = invoice.canonical_event_len().map_err(de::Error::custom)?;
            event_bytes = event_bytes
                .checked_add(length)
                .ok_or_else(|| de::Error::custom("pending Invoice byte count overflows"))?;
            if event_bytes > MAX_PENDING_INVOICE_EVENT_BYTES_V2 {
                return Err(de::Error::custom(
                    "pending Invoice events exceed the cumulative byte bound",
                ));
            }
            values.insert(invoice_id, invoice);
        }
        Ok(BoundedPendingInvoices(values))
    }
}

impl<'de> Deserialize<'de> for BoundedPendingInvoices {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_map(PendingInvoiceMapVisitor)
    }
}

impl<'de> Deserialize<'de> for ChannelSnapshotV2 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let input = ChannelSnapshotInput::deserialize(deserializer)?;
        let snapshot = Self {
            protocol_version: input.protocol_version,
            ledger_chain_id: input.ledger_chain_id,
            binding: input.binding,
            phase: input.phase,
            capacity_sat: input.capacity_sat,
            committee_member_count: input.committee_member_count,
            committee_threshold: input.committee_threshold,
            lock_key: input.lock_key,
            current_holder: input.current_holder,
            current_holder_anchor: input.current_holder_anchor,
            current_holder_ciphertext: input.current_holder_ciphertext,
            transfers_completed: input.transfers_completed,
            pending_invoices: input.pending_invoices.0,
            last_consumed_invoice_id: input.last_consumed_invoice_id,
            last_sequence: input.last_sequence,
            head_entry_hash: input.head_entry_hash,
            opened_at_ms: input.opened_at_ms,
            last_block_time_ms: input.last_block_time_ms,
            finalized_at_ms: input.finalized_at_ms,
        };
        snapshot.validate().map_err(de::Error::custom)?;
        Ok(snapshot)
    }
}

impl ChannelSnapshotV2 {
    /// Returns the next sequence, if the counter has capacity.
    pub fn next_sequence(&self) -> Result<u64, V2Error> {
        self.last_sequence.checked_add(1).ok_or(V2Error::SequenceExhausted)
    }

    /// Returns stable canonical state bytes.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, V2Error> {
        self.validate()?;
        let bytes = encode_state(self)?;
        if bytes.len() > MAX_CANONICAL_SNAPSHOT_BYTES_V2 {
            return Err(V2Error::InvalidSnapshot {
                reason: "canonical snapshot exceeds the transport byte bound",
            });
        }
        Ok(bytes)
    }

    /// Returns the domain-separated canonical state hash.
    pub fn state_hash(&self) -> Result<StateHashV2, V2Error> {
        Ok(StateHashV2::from_bytes(Sha256::digest(self.canonical_bytes()?).into()))
    }

    /// Returns the cumulative canonical bytes retained for pending Invoice events.
    pub fn pending_invoice_event_bytes(&self) -> Result<usize, V2Error> {
        let total = self.pending_invoices.values().try_fold(0_usize, |total, invoice| {
            total
                .checked_add(invoice.canonical_event_len()?)
                .ok_or(V2Error::InvalidSnapshot {
                    reason: "pending Invoice event byte count overflows",
                })
        })?;
        if total > MAX_PENDING_INVOICE_EVENT_BYTES_V2 {
            return Err(V2Error::InvalidSnapshot {
                reason: "pending Invoice events exceed the cumulative byte bound",
            });
        }
        Ok(total)
    }

    /// Returns retained public artifact and pending-event bytes for query sizing.
    pub fn retained_state_bytes(&self) -> Result<usize, V2Error> {
        let pending_event_bytes = self.pending_invoice_event_bytes()?;
        let total = retained_state_bytes(
            &self.lock_key,
            &self.current_holder_anchor,
            &self.current_holder_ciphertext,
            pending_event_bytes,
        )
        .ok_or(V2Error::InvalidSnapshot {
            reason: "retained channel-state byte count overflows",
        })?;
        if total > MAX_RETAINED_CHANNEL_STATE_BYTES_V2 {
            return Err(V2Error::InvalidSnapshot {
                reason: "retained channel state exceeds the cumulative byte bound",
            });
        }
        Ok(total)
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
        let _ = self.retained_state_bytes()?;
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
    /// Pending Invoice events exceeded the consensus-bound cumulative byte budget.
    #[error("pending Invoice event bytes exceed limit {limit}")]
    PendingInvoiceBytesLimitReached { limit: usize },
    /// Retained public state exceeded the consensus-bound cumulative byte budget.
    #[error("retained channel-state bytes exceed limit {limit}")]
    RetainedStateBytesLimitReached { limit: usize },
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

pub(crate) fn retained_state_bytes(
    lock_key: &ArtifactV2,
    holder_anchor: &ArtifactV2,
    holder_ciphertext: &ArtifactV2,
    pending_event_bytes: usize,
) -> Option<usize> {
    lock_key
        .as_bytes()
        .len()
        .checked_add(holder_anchor.as_bytes().len())?
        .checked_add(holder_ciphertext.as_bytes().len())?
        .checked_add(pending_event_bytes)
}
