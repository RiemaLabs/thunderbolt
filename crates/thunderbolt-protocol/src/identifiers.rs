use crate::{IdentifierKind, ProtocolError};
use core::{fmt, str::FromStr};
use serde::{
    de::{self, Visitor},
    Deserialize, Deserializer, Serialize, Serializer,
};
use sha2::{Digest as _, Sha256};

/// Maximum UTF-8 bytes in an idempotency key.
pub const MAX_IDEMPOTENCY_KEY_BYTES: usize = 128;
/// Maximum UTF-8 bytes in a participant id.
pub const MAX_PARTICIPANT_ID_BYTES: usize = 128;
/// Maximum UTF-8 bytes in an invoice id.
pub const MAX_INVOICE_ID_BYTES: usize = 128;
/// Maximum UTF-8 bytes in a verifier implementation id.
pub const MAX_IMPLEMENTATION_ID_BYTES: usize = 96;
/// Maximum bytes in one opaque public protocol artifact.
pub const MAX_ARTIFACT_BYTES: usize = 1_048_576;

fn decode_lower_hex<const N: usize>(input: &str, kind: &'static str) -> Result<[u8; N], ProtocolError> {
    if input.len() != N * 2
        || !input
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(ProtocolError::InvalidDigest { kind });
    }

    let mut output = [0_u8; N];
    for (index, pair) in input.as_bytes().chunks_exact(2).enumerate() {
        let high = hex_nibble(pair[0]).ok_or(ProtocolError::InvalidDigest { kind })?;
        let low = hex_nibble(pair[1]).ok_or(ProtocolError::InvalidDigest { kind })?;
        output[index] = (high << 4) | low;
    }
    Ok(output)
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

fn write_lower_hex(bytes: &[u8], formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for byte in bytes {
        formatter.write_str(
            core::str::from_utf8(&[HEX[(byte >> 4) as usize], HEX[(byte & 0x0f) as usize]])
                .expect("hex alphabet is UTF-8"),
        )?;
    }
    Ok(())
}

fn lower_hex_string(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}

macro_rules! fixed_hex_type {
    ($name:ident, $kind:literal) => {
        #[doc = concat!("A 32-byte ", $kind, ", encoded as lowercase hexadecimal in serde formats.")]
        #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
        pub struct $name([u8; 32]);

        impl $name {
            /// The all-zero value.
            pub const ZERO: Self = Self([0_u8; 32]);

            /// Constructs a value from its raw bytes.
            pub const fn from_bytes(bytes: [u8; 32]) -> Self {
                Self(bytes)
            }

            /// Returns the raw bytes.
            pub const fn to_bytes(self) -> [u8; 32] {
                self.0
            }

            /// Borrows the raw bytes.
            pub const fn as_bytes(&self) -> &[u8; 32] {
                &self.0
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter
                    .debug_tuple(stringify!($name))
                    .field(&self.to_string())
                    .finish()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                write_lower_hex(&self.0, formatter)
            }
        }

        impl FromStr for $name {
            type Err = ProtocolError;

            fn from_str(input: &str) -> Result<Self, Self::Err> {
                decode_lower_hex::<32>(input, $kind).map(Self)
            }
        }

        impl Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                serializer.serialize_str(&self.to_string())
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                struct HexVisitor;

                impl Visitor<'_> for HexVisitor {
                    type Value = $name;

                    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                        formatter.write_str("exactly 64 lowercase hexadecimal characters")
                    }

                    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
                    where
                        E: de::Error,
                    {
                        value.parse().map_err(E::custom)
                    }
                }

                deserializer.deserialize_str(HexVisitor)
            }
        }
    };
}

fixed_hex_type!(Digest, "digest");
fixed_hex_type!(EntryHash, "entry hash");

/// A canonical Bitcoin transaction id.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BitcoinTxid([u8; 32]);

impl BitcoinTxid {
    /// Constructs a txid from display-order bytes.
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns display-order bytes.
    pub const fn to_bytes(self) -> [u8; 32] {
        self.0
    }

    /// Borrows display-order bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for BitcoinTxid {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("BitcoinTxid").field(&self.to_string()).finish()
    }
}

impl fmt::Display for BitcoinTxid {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_lower_hex(&self.0, formatter)
    }
}

impl FromStr for BitcoinTxid {
    type Err = ProtocolError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        decode_lower_hex::<32>(input, "Bitcoin transaction id")
            .map(Self)
            .map_err(|_| ProtocolError::InvalidBitcoinTxid {
                reason: "expected exactly 64 lowercase hexadecimal characters",
            })
    }
}

impl Serialize for BitcoinTxid {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for BitcoinTxid {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        value.parse().map_err(de::Error::custom)
    }
}

/// A Thunderbolt channel id, canonically encoded as Bitcoin `txid:vout`.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ChannelId {
    txid: BitcoinTxid,
    vout: u32,
}

impl ChannelId {
    /// Constructs a channel id from a Bitcoin txid and output index.
    pub const fn new(txid: BitcoinTxid, vout: u32) -> Self {
        Self { txid, vout }
    }

    /// Returns the funding transaction id.
    pub const fn txid(&self) -> BitcoinTxid {
        self.txid
    }

    /// Returns the funding output index.
    pub const fn vout(&self) -> u32 {
        self.vout
    }

    /// Returns the wire binding used by proof contexts: display-order txid
    /// bytes followed by the output index in big-endian order.
    pub fn canonical_bytes(&self) -> [u8; 36] {
        let mut bytes = [0_u8; 36];
        bytes[..32].copy_from_slice(self.txid.as_bytes());
        bytes[32..].copy_from_slice(&self.vout.to_be_bytes());
        bytes
    }
}

impl fmt::Debug for ChannelId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("ChannelId").field(&self.to_string()).finish()
    }
}

impl fmt::Display for ChannelId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}:{}", self.txid, self.vout)
    }
}

impl FromStr for ChannelId {
    type Err = ProtocolError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        let (txid, vout) = input.split_once(':').ok_or(ProtocolError::InvalidChannelId {
            reason: "expected txid:vout",
        })?;
        if vout.contains(':') {
            return Err(ProtocolError::InvalidChannelId {
                reason: "expected exactly one colon",
            });
        }
        let txid = txid.parse().map_err(|_| ProtocolError::InvalidChannelId {
            reason: "txid must be 64 lowercase hexadecimal characters",
        })?;
        if vout.is_empty() || !vout.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(ProtocolError::InvalidChannelId {
                reason: "vout must be an unsigned decimal integer",
            });
        }
        if vout.len() > 1 && vout.starts_with('0') {
            return Err(ProtocolError::InvalidChannelId {
                reason: "vout must not contain leading zeroes",
            });
        }
        let vout = vout.parse().map_err(|_| ProtocolError::InvalidChannelId {
            reason: "vout exceeds u32",
        })?;
        Ok(Self { txid, vout })
    }
}

impl Serialize for ChannelId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for ChannelId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        value.parse().map_err(de::Error::custom)
    }
}

fn validate_identifier(value: &str, kind: IdentifierKind, maximum: usize) -> Result<(), ProtocolError> {
    if value.is_empty() {
        return Err(ProtocolError::InvalidIdentifier {
            kind,
            reason: "must not be empty",
        });
    }
    if value.len() > maximum {
        return Err(ProtocolError::InvalidIdentifier {
            kind,
            reason: "exceeds maximum length",
        });
    }
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':' | b'@' | b'/'))
    {
        return Err(ProtocolError::InvalidIdentifier {
            kind,
            reason: "contains characters outside [A-Za-z0-9-_.:@/]",
        });
    }
    Ok(())
}

macro_rules! identifier_type {
    ($name:ident, $kind:expr, $maximum:expr, $docs:literal) => {
        #[doc = $docs]
        #[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(String);

        impl $name {
            /// Validates and constructs the identifier.
            pub fn new(value: impl Into<String>) -> Result<Self, ProtocolError> {
                let value = value.into();
                validate_identifier(&value, $kind, $maximum)?;
                Ok(Self(value))
            }

            /// Borrows the canonical string value.
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.debug_tuple(stringify!($name)).field(&self.0).finish()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(&self.0)
            }
        }

        impl FromStr for $name {
            type Err = ProtocolError;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                Self::new(value)
            }
        }

        impl Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                serializer.serialize_str(&self.0)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                let value = String::deserialize(deserializer)?;
                Self::new(value).map_err(de::Error::custom)
            }
        }
    };
}

identifier_type!(
    IdempotencyKey,
    IdentifierKind::IdempotencyKey,
    MAX_IDEMPOTENCY_KEY_BYTES,
    "A caller-generated key that makes an append request safely retryable."
);
identifier_type!(
    ParticipantId,
    IdentifierKind::ParticipantId,
    MAX_PARTICIPANT_ID_BYTES,
    "A stable public participant identity."
);
identifier_type!(
    InvoiceId,
    IdentifierKind::InvoiceId,
    MAX_INVOICE_ID_BYTES,
    "A recipient-generated id that is unique for a channel's lifetime."
);
identifier_type!(
    ImplementationId,
    IdentifierKind::ImplementationId,
    MAX_IMPLEMENTATION_ID_BYTES,
    "The implementation and version that produced verification evidence."
);

/// Bounded opaque public protocol data, serialized as lowercase hexadecimal.
///
/// This may hold public keys, ciphertexts, proofs, signatures, or VESS
/// packages. It is intentionally uninterpreted in this crate.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Artifact(Vec<u8>);

impl Artifact {
    /// Validates and constructs an artifact.
    pub fn new(bytes: impl Into<Vec<u8>>) -> Result<Self, ProtocolError> {
        let bytes = bytes.into();
        if bytes.is_empty() {
            return Err(ProtocolError::InvalidArtifact {
                reason: "must not be empty",
            });
        }
        if bytes.len() > MAX_ARTIFACT_BYTES {
            return Err(ProtocolError::InvalidArtifact {
                reason: "exceeds maximum byte length",
            });
        }
        Ok(Self(bytes))
    }

    /// Borrows the raw artifact bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Consumes the wrapper and returns the raw artifact bytes.
    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }

    /// Returns the SHA-256 digest of the artifact bytes.
    pub fn digest(&self) -> Digest {
        Digest::from_bytes(Sha256::digest(&self.0).into())
    }
}

impl fmt::Debug for Artifact {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Artifact")
            .field("bytes", &self.0.len())
            .field("sha256", &self.digest())
            .finish()
    }
}

impl Serialize for Artifact {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&lower_hex_string(&self.0))
    }
}

impl<'de> Deserialize<'de> for Artifact {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct ArtifactVisitor;

        impl Visitor<'_> for ArtifactVisitor {
            type Value = Artifact;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a non-empty, bounded, even-length lowercase hexadecimal string")
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                if value.is_empty()
                    || value.len() > MAX_ARTIFACT_BYTES * 2
                    || !value.len().is_multiple_of(2)
                    || !value
                        .bytes()
                        .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
                {
                    return Err(E::custom("artifact must be non-empty, bounded lowercase hexadecimal"));
                }
                let mut bytes = Vec::with_capacity(value.len() / 2);
                for pair in value.as_bytes().chunks_exact(2) {
                    let high = hex_nibble(pair[0]).ok_or_else(|| E::custom("invalid artifact hex"))?;
                    let low = hex_nibble(pair[1]).ok_or_else(|| E::custom("invalid artifact hex"))?;
                    bytes.push((high << 4) | low);
                }
                Artifact::new(bytes).map_err(E::custom)
            }
        }

        deserializer.deserialize_str(ArtifactVisitor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn artifact_retains_the_version_one_bound() {
        assert!(Artifact::new(vec![0x51; MAX_ARTIFACT_BYTES]).is_ok());
        assert!(Artifact::new(vec![0x51; MAX_ARTIFACT_BYTES + 1]).is_err());
    }

    #[test]
    fn channel_id_requires_canonical_bitcoin_outpoint() {
        let txid = "01".repeat(32);
        let channel: ChannelId = format!("{txid}:4294967295").parse().unwrap();
        assert_eq!(channel.to_string(), format!("{txid}:4294967295"));
        assert_eq!(channel.vout(), u32::MAX);

        for invalid in [
            txid.clone(),
            format!("{}:00", txid),
            format!("{}:4294967296", txid),
            format!("{}:1:2", txid),
            format!("{}:x", txid),
            format!("{}:0", "AB".repeat(32)),
            format!("{}:0", "0".repeat(63)),
        ] {
            assert!(invalid.parse::<ChannelId>().is_err(), "accepted {invalid}");
        }
    }

    #[test]
    fn channel_id_round_trips_across_boundary_vouts() {
        let txid = BitcoinTxid::from_bytes([0xab; 32]);
        for vout in [0, 1, 9, 10, 999, u32::MAX] {
            let original = ChannelId::new(txid, vout);
            let encoded = serde_json::to_string(&original).unwrap();
            let decoded: ChannelId = serde_json::from_str(&encoded).unwrap();
            assert_eq!(decoded, original);
            assert_eq!(original.to_string().parse::<ChannelId>().unwrap(), original);
            let encoded = original.canonical_bytes();
            assert_eq!(&encoded[..32], txid.as_bytes());
            assert_eq!(&encoded[32..], &vout.to_be_bytes());
        }
    }

    #[test]
    fn identifiers_are_bounded_and_wire_safe() {
        assert!(ParticipantId::new("holder:alice-1").is_ok());
        assert!(ParticipantId::new("").is_err());
        assert!(ParticipantId::new("alice smith").is_err());
        assert!(ParticipantId::new("a".repeat(MAX_PARTICIPANT_ID_BYTES + 1)).is_err());
    }

    #[test]
    fn artifact_serde_roundtrip_and_digest_are_stable() {
        let artifact = Artifact::new([0x00, 0xab, 0xff]).unwrap();
        assert_eq!(serde_json::to_string(&artifact).unwrap(), "\"00abff\"");
        assert_eq!(serde_json::from_str::<Artifact>("\"00abff\"").unwrap(), artifact);
        assert!(serde_json::from_str::<Artifact>("\"00ABFF\"").is_err());
        assert_eq!(
            artifact.digest().to_string(),
            "de4be1eb1639e64d628aa53eb7e93074228bbe1eecfd0040aacdb83c9e5fed40"
        );
    }
}
