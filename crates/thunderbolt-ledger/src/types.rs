use std::fmt;

use secp256k1::schnorr::Signature;
use secp256k1::XOnlyPublicKey;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use thunderbolt_wire::{ChannelBindingV2, HexBytes, ValidateWire};

use crate::canonical::CanonicalTranscript;
use crate::{LedgerContractError, Result};

/// Protocol version accepted by this Ledger contract.
pub const LEDGER_PROTOCOL_VERSION_V2: u16 = 2;
/// Minimum entropy-bearing client request nonce width.
pub const REQUEST_NONCE_MIN: usize = 16;
/// Maximum client request nonce width.
pub const REQUEST_NONCE_MAX: usize = 64;
/// Maximum canonical event payload committed by one proposal.
pub const EVENT_BYTES_MAX: usize = 256 * 1024;
/// Conservative maximum for a CometBFT-compatible Ledger chain id.
pub const LEDGER_CHAIN_ID_MAX: usize = 50;

macro_rules! fixed_digest_type {
    ($(#[$meta:meta])* $name:ident, $field:literal) => {
        $(#[$meta])*
        #[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name([u8; 32]);

        impl $name {
            /// Constructs the typed digest from exactly 32 bytes.
            pub fn from_bytes(bytes: impl AsRef<[u8]>) -> Result<Self> {
                let bytes = bytes.as_ref();
                let array = <[u8; 32]>::try_from(bytes).map_err(|_| LedgerContractError::InvalidLength {
                    field: $field,
                    min: 32,
                    max: 32,
                    actual: bytes.len(),
                })?;
                Ok(Self(array))
            }

            /// Borrows the digest bytes.
            pub fn as_bytes(&self) -> &[u8; 32] {
                &self.0
            }

            /// Returns canonical lowercase hexadecimal.
            pub fn to_hex(&self) -> String {
                hex::encode(self.0)
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.debug_tuple(stringify!($name)).field(&self.to_hex()).finish()
            }
        }

        impl Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                serializer.serialize_str(&self.to_hex())
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                let value = HexBytes::<32, 32>::deserialize(deserializer)?;
                Self::from_bytes(value.as_bytes()).map_err(serde::de::Error::custom)
            }
        }
    };
}

fixed_digest_type!(
    /// SHA-256 digest of the canonical proposal body signed by the actor.
    ProposalDigestV2,
    "proposal_digest"
);
fixed_digest_type!(
    /// Stable hash of an executed channel entry.
    EntryHashV2,
    "entry_hash"
);
fixed_digest_type!(
    /// Incremental replicated application hash after an executed block.
    AppHashV2,
    "app_hash"
);
fixed_digest_type!(
    /// Stable context id derived from [`ChannelBindingV2`].
    ChannelContextIdV2,
    "channel_context_id"
);
fixed_digest_type!(
    /// Participant identity deterministically derived from its actor key.
    ParticipantIdV2,
    "participant_id"
);
fixed_digest_type!(
    /// Channel- and actor-scoped request digest.
    RequestDigestV2,
    "request_digest"
);
fixed_digest_type!(
    /// SHA-256 digest of the bounded canonical event bytes.
    EventDigestV2,
    "event_digest"
);
fixed_digest_type!(
    /// Ordered Merkle root of all executed entries in one block.
    EntryMerkleRootV2,
    "entry_merkle_root"
);
fixed_digest_type!(
    /// Hash of one internal or sibling node in the ordered entry Merkle tree.
    MerkleNodeHashV2,
    "merkle_node_hash"
);

/// Consensus Ledger chain id included in every replay-protection domain.
///
/// The character set and 50-byte limit match a conservative CometBFT profile:
/// the first and last characters are alphanumeric, while interior characters
/// may also contain `.`, `_`, and `-`.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct LedgerChainIdV2(String);

impl LedgerChainIdV2 {
    /// Validates a consensus chain id.
    pub fn new(value: impl AsRef<str>) -> Result<Self> {
        let value = value.as_ref();
        let bytes = value.as_bytes();
        if bytes.is_empty() || bytes.len() > LEDGER_CHAIN_ID_MAX {
            return Err(LedgerContractError::InvalidLength {
                field: "ledger_chain_id",
                min: 1,
                max: LEDGER_CHAIN_ID_MAX,
                actual: bytes.len(),
            });
        }
        if !bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        {
            return Err(LedgerContractError::InvalidField {
                field: "ledger_chain_id",
                reason: "only ASCII letters, digits, dot, underscore, and hyphen are accepted",
            });
        }
        if !bytes.first().is_some_and(u8::is_ascii_alphanumeric) || !bytes.last().is_some_and(u8::is_ascii_alphanumeric)
        {
            return Err(LedgerContractError::InvalidField {
                field: "ledger_chain_id",
                reason: "must begin and end with an ASCII letter or digit",
            });
        }
        Ok(Self(value.to_owned()))
    }

    /// Borrows the canonical chain id.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Borrows the canonical ASCII chain-id bytes.
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl fmt::Debug for LedgerChainIdV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("LedgerChainIdV2").field(&self.0).finish()
    }
}

impl<'de> Deserialize<'de> for LedgerChainIdV2 {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

impl EntryHashV2 {
    /// Sentinel predecessor used only by the first entry of a channel.
    pub const ZERO_BYTES: [u8; 32] = [0; 32];

    /// Returns the sequence-zero predecessor sentinel.
    pub fn zero() -> Self {
        Self(Self::ZERO_BYTES)
    }

    /// Reports whether this is the sequence-zero predecessor sentinel.
    pub fn is_zero(&self) -> bool {
        self.as_bytes() == &Self::ZERO_BYTES
    }
}

impl AppHashV2 {
    /// Sentinel application hash before the first executed block.
    pub const ZERO_BYTES: [u8; 32] = [0; 32];

    /// Returns the initial application-hash sentinel.
    pub fn zero() -> Self {
        Self(Self::ZERO_BYTES)
    }

    /// Reports whether this is the initial application-hash sentinel.
    pub fn is_zero(&self) -> bool {
        self.as_bytes() == &Self::ZERO_BYTES
    }
}

/// The only actor signing algorithm accepted by protocol version 2.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActorKeyAlgorithmV2 {
    /// BIP340 Schnorr over secp256k1, version 1 of this Ledger profile.
    Bip340V1,
}

impl ActorKeyAlgorithmV2 {
    pub(crate) const fn tag(self) -> u8 {
        match self {
            Self::Bip340V1 => 1,
        }
    }
}

/// A validated, x-only secp256k1 actor public key.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ActorPublicKeyV2([u8; 32]);

impl ActorPublicKeyV2 {
    /// Parses an exact BIP340 x-only public key.
    pub fn from_bytes(bytes: impl AsRef<[u8]>) -> Result<Self> {
        let bytes = bytes.as_ref();
        let array = <[u8; 32]>::try_from(bytes).map_err(|_| LedgerContractError::InvalidLength {
            field: "actor_public_key",
            min: 32,
            max: 32,
            actual: bytes.len(),
        })?;
        XOnlyPublicKey::from_byte_array(array).map_err(|_| LedgerContractError::InvalidField {
            field: "actor_public_key",
            reason: "not a valid x-only secp256k1 public key",
        })?;
        Ok(Self(array))
    }

    /// Borrows the exact 32-byte x-only public key.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Returns the parsed libsecp256k1 public key.
    pub fn to_x_only_public_key(&self) -> Result<XOnlyPublicKey> {
        XOnlyPublicKey::from_byte_array(self.0).map_err(|_| LedgerContractError::InvalidField {
            field: "actor_public_key",
            reason: "validated x-only public key could not be reconstructed",
        })
    }

    /// Derives the stable participant identity from the algorithm and key.
    pub fn participant_id(&self, algorithm: ActorKeyAlgorithmV2) -> Result<ParticipantIdV2> {
        let mut transcript = CanonicalTranscript::new(b"bitcoin-thunderbolt/participant-id/v2")?;
        transcript.u8(b"actor_key_algorithm", algorithm.tag())?;
        transcript.item(b"actor_public_key", self.as_bytes())?;
        ParticipantIdV2::from_bytes(transcript.digest())
    }

    /// Returns canonical lowercase hexadecimal.
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
}

impl fmt::Debug for ActorPublicKeyV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("ActorPublicKeyV2").field(&self.to_hex()).finish()
    }
}

impl Serialize for ActorPublicKeyV2 {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for ActorPublicKeyV2 {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes = HexBytes::<32, 32>::deserialize(deserializer)?;
        Self::from_bytes(bytes.as_bytes()).map_err(serde::de::Error::custom)
    }
}

/// A validated 64-byte BIP340 signature.
#[derive(Clone, PartialEq, Eq)]
pub struct ActorSignatureV2([u8; 64]);

impl ActorSignatureV2 {
    /// Parses an exact 64-byte BIP340 signature encoding.
    pub fn from_bytes(bytes: impl AsRef<[u8]>) -> Result<Self> {
        let bytes = bytes.as_ref();
        let array = <[u8; 64]>::try_from(bytes).map_err(|_| LedgerContractError::InvalidLength {
            field: "actor_signature",
            min: 64,
            max: 64,
            actual: bytes.len(),
        })?;
        Ok(Self(array))
    }

    /// Borrows the exact 64 signature bytes.
    pub fn as_bytes(&self) -> &[u8; 64] {
        &self.0
    }

    pub(crate) fn to_signature(&self) -> Signature {
        Signature::from_byte_array(self.0)
    }

    /// Returns canonical lowercase hexadecimal.
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
}

impl fmt::Debug for ActorSignatureV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("ActorSignatureV2").field(&self.to_hex()).finish()
    }
}

impl Serialize for ActorSignatureV2 {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for ActorSignatureV2 {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes = HexBytes::<64, 64>::deserialize(deserializer)?;
        Self::from_bytes(bytes.as_bytes()).map_err(serde::de::Error::custom)
    }
}

/// Protocol role asserted by an authenticated actor key.
///
/// Transition-specific authorization remains the responsibility of the
/// deterministic event verifier. The role is authenticated but not treated as
/// an untrusted participant-name string.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActorRoleV2 {
    /// Current off-chain holder.
    Holder,
    /// Invoice creator and prospective next holder.
    Recipient,
    /// One threshold committee member.
    Committee,
    /// Replicated Ledger operator identity.
    LedgerOperator,
}

impl ActorRoleV2 {
    pub(crate) const fn tag(self) -> u8 {
        match self {
            Self::Holder => 1,
            Self::Recipient => 2,
            Self::Committee => 3,
            Self::LedgerOperator => 4,
        }
    }
}

/// Stable discriminant for a canonical protocol event payload.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventKindV2 {
    /// Channel opening transition.
    Open,
    /// Invoice publication transition.
    Invoice,
    /// Off-chain ownership transfer transition.
    Transfer,
    /// Irreversible on-chain finalization transition.
    Finalize,
}

impl EventKindV2 {
    pub(crate) const fn tag(self) -> u8 {
        match self {
            Self::Open => 1,
            Self::Invoice => 2,
            Self::Transfer => 3,
            Self::Finalize => 4,
        }
    }
}

/// Bounded canonical public event bytes.
///
/// This type contains application event bytes only. Raw verifier transcripts,
/// witnesses, decrypted shares, and node-local evidence do not belong in the
/// Ledger contract.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CanonicalEventV2(HexBytes<1, EVENT_BYTES_MAX>);

impl CanonicalEventV2 {
    /// Validates and owns one non-empty canonical event payload.
    pub fn from_bytes(bytes: impl AsRef<[u8]>) -> Result<Self> {
        HexBytes::from_bytes("canonical_event", bytes)
            .map(Self)
            .map_err(LedgerContractError::from)
    }

    /// Borrows the canonical event bytes.
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    /// Computes the domain-separated event digest committed by metadata.
    pub fn digest(&self) -> Result<EventDigestV2> {
        let mut transcript = CanonicalTranscript::new(b"bitcoin-thunderbolt/event/v2")?;
        transcript.item(b"canonical_event", self.as_bytes())?;
        EventDigestV2::from_bytes(transcript.digest())
    }
}

impl fmt::Debug for CanonicalEventV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CanonicalEventV2")
            .field("byte_len", &self.as_bytes().len())
            .finish()
    }
}

impl Serialize for CanonicalEventV2 {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.0.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for CanonicalEventV2 {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes = HexBytes::<1, EVENT_BYTES_MAX>::deserialize(deserializer)?;
        Self::from_bytes(bytes.as_bytes()).map_err(serde::de::Error::custom)
    }
}

/// Opaque client nonce from which the channel- and actor-scoped request id is derived.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ClientRequestNonceV2(HexBytes<REQUEST_NONCE_MIN, REQUEST_NONCE_MAX>);

impl ClientRequestNonceV2 {
    /// Validates a bounded, non-zero client request nonce.
    pub fn from_bytes(bytes: impl AsRef<[u8]>) -> Result<Self> {
        let bytes = HexBytes::from_bytes("client_request_nonce", bytes)?;
        if bytes.as_bytes().iter().all(|byte| *byte == 0) {
            return Err(LedgerContractError::InvalidField {
                field: "client_request_nonce",
                reason: "must not be all zero",
            });
        }
        Ok(Self(bytes))
    }

    /// Borrows the nonce bytes.
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl fmt::Debug for ClientRequestNonceV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ClientRequestNonceV2")
            .field("byte_len", &self.as_bytes().len())
            .finish_non_exhaustive()
    }
}

impl Serialize for ClientRequestNonceV2 {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.0.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for ClientRequestNonceV2 {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes = HexBytes::<REQUEST_NONCE_MIN, REQUEST_NONCE_MAX>::deserialize(deserializer)?;
        Self::from_bytes(bytes.as_bytes()).map_err(serde::de::Error::custom)
    }
}

/// An actor request id carrying both the retry nonce and its scoped digest.
///
/// Deserialization of a complete proposal re-derives `digest`; callers cannot
/// substitute a free request string or transplant an id across channels or
/// actor keys.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ActorRequestIdV2 {
    nonce: ClientRequestNonceV2,
    digest: RequestDigestV2,
}

impl ActorRequestIdV2 {
    pub(crate) fn derive(
        ledger_chain_id: &LedgerChainIdV2,
        channel: &ChannelBindingV2,
        algorithm: ActorKeyAlgorithmV2,
        actor_key: &ActorPublicKeyV2,
        role: ActorRoleV2,
        nonce: ClientRequestNonceV2,
    ) -> Result<Self> {
        channel.validate_wire()?;
        let participant_id = actor_key.participant_id(algorithm)?;
        let mut transcript = CanonicalTranscript::new(b"bitcoin-thunderbolt/actor-request-id/v2")?;
        transcript.item(b"ledger_chain_id", ledger_chain_id.as_bytes())?;
        transcript.item(b"channel_context_id", &channel.context_id()?)?;
        transcript.item(b"participant_id", participant_id.as_bytes())?;
        transcript.u8(b"actor_role", role.tag())?;
        transcript.item(b"client_request_nonce", nonce.as_bytes())?;
        Ok(Self {
            nonce,
            digest: RequestDigestV2::from_bytes(transcript.digest())?,
        })
    }

    /// Borrows the client retry nonce.
    pub const fn nonce(&self) -> &ClientRequestNonceV2 {
        &self.nonce
    }

    /// Returns the derived channel- and actor-scoped request digest.
    pub const fn digest(&self) -> &RequestDigestV2 {
        &self.digest
    }
}
