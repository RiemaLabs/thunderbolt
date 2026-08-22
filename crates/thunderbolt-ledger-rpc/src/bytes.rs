use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest as _, Sha256};
use thunderbolt_ledger::{EntryHashV2, LedgerChainIdV2, ParticipantIdV2};
use thunderbolt_protocol::v2::{
    ChannelEventV2, ChannelPhaseV2, ChannelSnapshotV2, PendingInvoiceV2, StateHashV2, ABSOLUTE_MAX_PENDING_INVOICES_V2,
    HASH_FORMAT_VERSION_V2, PROTOCOL_VERSION_V2,
};
use thunderbolt_protocol::Artifact;
use thunderbolt_wire::{CanonicalDigest as _, ChannelBindingV2, InvoiceId, ValidateWire as _};

use crate::error::RedactedDebug;
use crate::primitives::{deserialize_hex_bounded, FixedHex32Wire};
use crate::{FinalityVerifierProfileIdV2, Result, RpcCodecError};

/// Maximum canonical materialized channel-state bytes returned by one status query.
pub const MAX_SNAPSHOT_BYTES: usize = 12 * 1024 * 1024;
/// Maximum opaque consensus receipt carried by the transport-neutral contract.
pub const MAX_CONSENSUS_RECEIPT_BYTES: usize = 1024 * 1024;
/// Minimum opaque ambiguity-token width.
pub const MIN_AMBIGUITY_TOKEN_BYTES: usize = 16;
/// Maximum opaque ambiguity-token width.
pub const MAX_AMBIGUITY_TOKEN_BYTES: usize = 256;

const STATE_DOMAIN: &[u8] = b"bitcoin-thunderbolt/protocol-state/v2";

/// Bounded canonical protocol-v2 materialized channel-state bytes.
///
/// This wrapper checks the state codec domain and both embedded version words.
/// Full state decoding remains the protocol crate's responsibility; a finality
/// verifier must prove that these exact bytes are included in the committed
/// application state.
///
/// ```compile_fail
/// use thunderbolt_ledger_rpc::SnapshotBytesV2;
/// let _: SnapshotBytesV2 = serde_json::from_slice(b"\"00\"").unwrap();
/// ```
#[derive(Clone, PartialEq, Eq)]
pub struct SnapshotBytesV2(Vec<u8>);

impl SnapshotBytesV2 {
    /// Encodes a validated protocol snapshot into its canonical state bytes.
    pub fn from_snapshot(snapshot: &ChannelSnapshotV2) -> Result<Self> {
        snapshot.validate()?;
        Self::from_canonical_bytes(snapshot.canonical_bytes()?)
    }

    /// Validates bounded canonical state framing.
    pub fn from_canonical_bytes(bytes: impl AsRef<[u8]>) -> Result<Self> {
        let bytes = bytes.as_ref();
        if bytes.is_empty() || bytes.len() > MAX_SNAPSHOT_BYTES {
            return Err(RpcCodecError::InvalidLength {
                field: "snapshot_bytes",
                min: 1,
                max: MAX_SNAPSHOT_BYTES,
            });
        }
        let domain_len = STATE_DOMAIN.len();
        let header_len = 8_usize
            .checked_add(domain_len)
            .and_then(|length| length.checked_add(4))
            .ok_or(RpcCodecError::InvalidField("snapshot framing length overflow"))?;
        if bytes.len() < header_len {
            return Err(RpcCodecError::InvalidField("snapshot framing is truncated"));
        }
        let mut length_bytes = [0_u8; 8];
        length_bytes.copy_from_slice(&bytes[..8]);
        if u64::from_be_bytes(length_bytes) != domain_len as u64 || &bytes[8..8 + domain_len] != STATE_DOMAIN {
            return Err(RpcCodecError::InvalidField("snapshot codec domain mismatch"));
        }
        let version_offset = 8 + domain_len;
        let hash_format = u16::from_be_bytes([bytes[version_offset], bytes[version_offset + 1]]);
        let protocol_version = u16::from_be_bytes([bytes[version_offset + 2], bytes[version_offset + 3]]);
        if hash_format != HASH_FORMAT_VERSION_V2 || protocol_version != PROTOCOL_VERSION_V2 {
            return Err(RpcCodecError::InvalidField("snapshot version mismatch"));
        }
        Ok(Self(bytes.to_vec()))
    }

    /// Borrows the exact canonical bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Computes the protocol-defined materialized-state hash.
    pub fn state_hash(&self) -> StateHashV2 {
        StateHashV2::from_bytes(Sha256::digest(&self.0).into())
    }

    /// Fully decodes and validates these bytes against the exact stable channel binding.
    ///
    /// The protocol state format commits only the binding digest, so callers
    /// must supply the binding obtained from the channel-status response.
    pub fn decode(&self, binding: &ChannelBindingV2) -> Result<ChannelSnapshotV2> {
        binding.validate_wire()?;
        let mut reader = SnapshotReader::new(&self.0);
        if reader.bytes()? != STATE_DOMAIN
            || reader.u16()? != HASH_FORMAT_VERSION_V2
            || reader.u16()? != PROTOCOL_VERSION_V2
        {
            return Err(RpcCodecError::InvalidField("snapshot domain or version mismatch"));
        }
        let chain_text = std::str::from_utf8(reader.bytes()?)
            .map_err(|_| RpcCodecError::InvalidField("snapshot Ledger chain is not UTF-8"))?;
        let ledger_chain_id = LedgerChainIdV2::new(chain_text)?;
        if reader.fixed::<32>()? != binding.canonical_digest()? {
            return Err(RpcCodecError::BindingMismatch(
                "snapshot binding digest differs from the supplied channel binding",
            ));
        }
        let phase = match reader.u8()? {
            1 => ChannelPhaseV2::Active,
            2 => ChannelPhaseV2::Finalized,
            _ => return Err(RpcCodecError::InvalidField("snapshot channel phase tag")),
        };
        let capacity_sat = reader.u64()?;
        let committee_member_count = reader.u16()?;
        let committee_threshold = reader.u16()?;
        let lock_key = reader.artifact()?;
        let current_holder = ParticipantIdV2::from_bytes(reader.fixed::<32>()?)?;
        let current_holder_anchor = reader.artifact()?;
        let current_holder_ciphertext = reader.artifact()?;
        let transfers_completed = reader.u64()?;
        let pending_count = usize::try_from(reader.u64()?)
            .map_err(|_| RpcCodecError::InvalidField("snapshot pending count does not fit usize"))?;
        if pending_count > ABSOLUTE_MAX_PENDING_INVOICES_V2 {
            return Err(RpcCodecError::InvalidField("snapshot pending invoice bound exceeded"));
        }
        let mut pending_invoices = BTreeMap::new();
        for _ in 0..pending_count {
            let invoice_id = InvoiceId::from_bytes("snapshot_invoice_id", reader.bytes()?)?;
            let event = match ChannelEventV2::from_canonical_bytes(reader.bytes()?)? {
                ChannelEventV2::Invoice(event) => event,
                _ => return Err(RpcCodecError::InvalidField("snapshot pending event is not an Invoice")),
            };
            let recipient = ParticipantIdV2::from_bytes(reader.fixed::<32>()?)?;
            let holder_step = reader.u64()?;
            let created_at_ms = reader.u64()?;
            let expires_at_ms = reader.u64()?;
            let committed_entry_hash = EntryHashV2::from_bytes(reader.fixed::<32>()?)?;
            let pending = PendingInvoiceV2 {
                event,
                invoice_id: invoice_id.clone(),
                recipient,
                holder_step,
                created_at_ms,
                expires_at_ms,
                committed_entry_hash,
            };
            if pending_invoices.insert(invoice_id, pending).is_some() {
                return Err(RpcCodecError::InvalidField("snapshot contains a duplicate Invoice id"));
            }
        }
        let last_consumed_invoice_id = match reader.u8()? {
            0 => None,
            1 => Some(InvoiceId::from_bytes(
                "snapshot_last_consumed_invoice_id",
                reader.bytes()?,
            )?),
            _ => return Err(RpcCodecError::InvalidField("snapshot optional Invoice tag")),
        };
        let last_sequence = reader.u64()?;
        let head_entry_hash = EntryHashV2::from_bytes(reader.fixed::<32>()?)?;
        let opened_at_ms = reader.u64()?;
        let last_block_time_ms = reader.u64()?;
        let finalized_at_ms = reader.optional_u64()?;
        if !reader.is_empty() {
            return Err(RpcCodecError::InvalidField("snapshot contains trailing bytes"));
        }
        let snapshot = ChannelSnapshotV2 {
            protocol_version: PROTOCOL_VERSION_V2,
            ledger_chain_id,
            binding: binding.clone(),
            phase,
            capacity_sat,
            committee_member_count,
            committee_threshold,
            lock_key,
            current_holder,
            current_holder_anchor,
            current_holder_ciphertext,
            transfers_completed,
            pending_invoices,
            last_consumed_invoice_id,
            last_sequence,
            head_entry_hash,
            opened_at_ms,
            last_block_time_ms,
            finalized_at_ms,
        };
        snapshot.validate()?;
        if snapshot.canonical_bytes()? != self.0 {
            return Err(RpcCodecError::NonCanonical);
        }
        Ok(snapshot)
    }
}

impl fmt::Debug for SnapshotBytesV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        RedactedDebug {
            name: "SnapshotBytesV2",
            byte_len: self.0.len(),
        }
        .fmt(formatter)
    }
}

impl Serialize for SnapshotBytesV2 {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(&self.0))
    }
}

pub(crate) fn deserialize_snapshot_bytes<'de, D>(deserializer: D) -> std::result::Result<SnapshotBytesV2, D::Error>
where
    D: Deserializer<'de>,
{
    let bytes = deserialize_hex_bounded(deserializer, "snapshot_bytes", 1, MAX_SNAPSHOT_BYTES)?;
    SnapshotBytesV2::from_canonical_bytes(bytes).map_err(serde::de::Error::custom)
}

/// Opaque, bounded consensus proof returned by a concrete Ledger adapter.
///
/// The bytes confer no authority by themselves. Only an implementation of
/// [`crate::ExternalFinalityVerifierV2`] can turn a complete entry bundle into
/// a verified finality capability.
#[derive(Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OpaqueConsensusReceiptV2 {
    verifier_profile_id: FinalityVerifierProfileIdV2,
    #[serde(serialize_with = "serialize_receipt_bytes")]
    bytes: Vec<u8>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OpaqueConsensusReceiptInput {
    verifier_profile_id: FixedHex32Wire,
    #[serde(deserialize_with = "deserialize_consensus_receipt_bytes")]
    bytes: Vec<u8>,
}

pub(crate) fn deserialize_opaque_consensus_receipt<'de, D>(
    deserializer: D,
) -> std::result::Result<OpaqueConsensusReceiptV2, D::Error>
where
    D: Deserializer<'de>,
{
    let input = OpaqueConsensusReceiptInput::deserialize(deserializer)?;
    let profile = FinalityVerifierProfileIdV2::from_bytes(input.verifier_profile_id.into_bytes())
        .map_err(serde::de::Error::custom)?;
    OpaqueConsensusReceiptV2::new(profile, input.bytes).map_err(serde::de::Error::custom)
}

impl OpaqueConsensusReceiptV2 {
    /// Constructs an opaque receipt under a pinned verifier profile.
    pub fn new(verifier_profile_id: FinalityVerifierProfileIdV2, bytes: Vec<u8>) -> Result<Self> {
        if bytes.is_empty() || bytes.len() > MAX_CONSENSUS_RECEIPT_BYTES {
            return Err(RpcCodecError::InvalidLength {
                field: "consensus_receipt",
                min: 1,
                max: MAX_CONSENSUS_RECEIPT_BYTES,
            });
        }
        Ok(Self {
            verifier_profile_id,
            bytes,
        })
    }

    /// Returns the exact configured finality-verifier profile.
    pub const fn verifier_profile_id(&self) -> FinalityVerifierProfileIdV2 {
        self.verifier_profile_id
    }

    /// Borrows the opaque receipt bytes for an external verifier.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl fmt::Debug for OpaqueConsensusReceiptV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OpaqueConsensusReceiptV2")
            .field("verifier_profile_id", &self.verifier_profile_id)
            .field("byte_len", &self.bytes.len())
            .finish_non_exhaustive()
    }
}

fn serialize_receipt_bytes<S>(bytes: &[u8], serializer: S) -> std::result::Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&hex::encode(bytes))
}

fn deserialize_consensus_receipt_bytes<'de, D>(deserializer: D) -> std::result::Result<Vec<u8>, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_hex_bounded(deserializer, "consensus_receipt", 1, MAX_CONSENSUS_RECEIPT_BYTES)
}

/// Opaque token used only to causally resolve a potentially committed floor CAS.
#[derive(Clone, PartialEq, Eq)]
pub struct AmbiguityTokenV2(Vec<u8>);

impl AmbiguityTokenV2 {
    /// Constructs a bounded ambiguity token.
    pub fn new(bytes: Vec<u8>) -> Result<Self> {
        if !(MIN_AMBIGUITY_TOKEN_BYTES..=MAX_AMBIGUITY_TOKEN_BYTES).contains(&bytes.len()) {
            return Err(RpcCodecError::InvalidLength {
                field: "ambiguity_token",
                min: MIN_AMBIGUITY_TOKEN_BYTES,
                max: MAX_AMBIGUITY_TOKEN_BYTES,
            });
        }
        Ok(Self(bytes))
    }

    /// Borrows the opaque token bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for AmbiguityTokenV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        RedactedDebug {
            name: "AmbiguityTokenV2",
            byte_len: self.0.len(),
        }
        .fmt(formatter)
    }
}

impl Serialize for AmbiguityTokenV2 {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(&self.0))
    }
}

pub(crate) fn deserialize_ambiguity_token<'de, D>(deserializer: D) -> std::result::Result<AmbiguityTokenV2, D::Error>
where
    D: Deserializer<'de>,
{
    let bytes = deserialize_hex_bounded(
        deserializer,
        "ambiguity_token",
        MIN_AMBIGUITY_TOKEN_BYTES,
        MAX_AMBIGUITY_TOKEN_BYTES,
    )?;
    AmbiguityTokenV2::new(bytes).map_err(serde::de::Error::custom)
}

struct SnapshotReader<'a> {
    remaining: &'a [u8],
}

impl<'a> SnapshotReader<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { remaining: bytes }
    }

    const fn is_empty(&self) -> bool {
        self.remaining.is_empty()
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8]> {
        let (value, remaining) = self
            .remaining
            .split_at_checked(length)
            .ok_or(RpcCodecError::InvalidField("snapshot is truncated"))?;
        self.remaining = remaining;
        Ok(value)
    }

    fn fixed<const N: usize>(&mut self) -> Result<[u8; N]> {
        <[u8; N]>::try_from(self.take(N)?).map_err(|_| RpcCodecError::InvalidField("snapshot fixed field is truncated"))
    }

    fn u8(&mut self) -> Result<u8> {
        Ok(self.fixed::<1>()?[0])
    }

    fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_be_bytes(self.fixed()?))
    }

    fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_be_bytes(self.fixed()?))
    }

    fn bytes(&mut self) -> Result<&'a [u8]> {
        let length = usize::try_from(self.u64()?)
            .map_err(|_| RpcCodecError::InvalidField("snapshot item length does not fit usize"))?;
        self.take(length)
    }

    fn artifact(&mut self) -> Result<Artifact> {
        Artifact::new(self.bytes()?).map_err(|_| RpcCodecError::InvalidField("snapshot artifact is invalid"))
    }

    fn optional_u64(&mut self) -> Result<Option<u64>> {
        match self.u8()? {
            0 => Ok(None),
            1 => Ok(Some(self.u64()?)),
            _ => Err(RpcCodecError::InvalidField("snapshot optional integer tag")),
        }
    }
}
