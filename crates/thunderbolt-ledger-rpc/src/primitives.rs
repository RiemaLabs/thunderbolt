use std::fmt;

use serde::de::Visitor;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest as _, Sha256};

use crate::{Result, RpcCodecError};

pub(crate) const REQUEST_DIGEST_DOMAIN: &[u8] = b"bitcoin-thunderbolt/ledger-rpc/request-digest/v2";

macro_rules! digest_type {
    ($(#[$meta:meta])* $name:ident, $field:literal, $reject_zero:expr) => {
        $(#[$meta])*
        #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name([u8; 32]);

        impl $name {
            /// Constructs the typed value from exactly 32 bytes.
            pub fn from_bytes(bytes: [u8; 32]) -> Result<Self> {
                if $reject_zero && bytes == [0_u8; 32] {
                    return Err(RpcCodecError::InvalidField(concat!($field, " must not be all zero")));
                }
                Ok(Self(bytes))
            }

            /// Borrows the exact bytes.
            pub const fn as_bytes(&self) -> &[u8; 32] {
                &self.0
            }

            /// Returns canonical lowercase hexadecimal.
            pub fn to_hex(self) -> String {
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

    };
}

digest_type!(
    /// SHA-256 digest of one complete canonical request envelope.
    RpcRequestDigestV2,
    "rpc_request_digest",
    false
);
digest_type!(
    /// Opaque, non-zero identifier assigned when a transport admits a proposal.
    TransportAcceptanceIdV2,
    "transport_acceptance_id",
    true
);
digest_type!(
    /// Non-zero identifier for the configured external finality-verification profile.
    FinalityVerifierProfileIdV2,
    "finality_verifier_profile_id",
    true
);

#[derive(Clone, Copy)]
pub(crate) struct FixedHex32Wire([u8; 32]);

impl FixedHex32Wire {
    pub(crate) const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub(crate) const fn into_bytes(self) -> [u8; 32] {
        self.0
    }
}

impl Serialize for FixedHex32Wire {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(self.0))
    }
}

impl<'de> Deserialize<'de> for FixedHex32Wire {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserialize_hex_exact(deserializer, "fixed_32_byte_hex").map(Self)
    }
}

pub(crate) fn digest_request(canonical_request: &[u8]) -> Result<RpcRequestDigestV2> {
    RpcRequestDigestV2::from_bytes(domain_digest(REQUEST_DIGEST_DOMAIN, canonical_request))
}

fn domain_digest(domain: &[u8], value: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update((domain.len() as u64).to_be_bytes());
    hasher.update(domain);
    hasher.update((value.len() as u64).to_be_bytes());
    hasher.update(value);
    hasher.finalize().into()
}

pub(crate) fn decode_hex_bounded(field: &'static str, text: &str, min: usize, max: usize) -> Result<Vec<u8>> {
    let min_encoded = min
        .checked_mul(2)
        .ok_or(RpcCodecError::InvalidField("hex minimum length overflow"))?;
    let max_encoded = max
        .checked_mul(2)
        .ok_or(RpcCodecError::InvalidField("hex maximum length overflow"))?;
    if !(min_encoded..=max_encoded).contains(&text.len()) {
        return Err(RpcCodecError::InvalidLength { field, min, max });
    }
    if !text.len().is_multiple_of(2)
        || !text
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(RpcCodecError::invalid_hex(field));
    }
    let decoded = hex::decode(text).map_err(|_| RpcCodecError::invalid_hex(field))?;
    if !(min..=max).contains(&decoded.len()) {
        return Err(RpcCodecError::InvalidLength { field, min, max });
    }
    Ok(decoded)
}

pub(crate) fn deserialize_hex_bounded<'de, D>(
    deserializer: D,
    field: &'static str,
    min: usize,
    max: usize,
) -> std::result::Result<Vec<u8>, D::Error>
where
    D: Deserializer<'de>,
{
    deserializer.deserialize_str(BoundedHexVisitor { field, min, max })
}

pub(crate) fn deserialize_hex_exact<'de, D, const N: usize>(
    deserializer: D,
    field: &'static str,
) -> std::result::Result<[u8; N], D::Error>
where
    D: Deserializer<'de>,
{
    let bytes = deserialize_hex_bounded(deserializer, field, N, N)?;
    <[u8; N]>::try_from(bytes.as_slice()).map_err(serde::de::Error::custom)
}

struct BoundedHexVisitor {
    field: &'static str,
    min: usize,
    max: usize,
}

impl Visitor<'_> for BoundedHexVisitor {
    type Value = Vec<u8>;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "lowercase hexadecimal containing between {} and {} decoded bytes",
            self.min, self.max
        )
    }

    fn visit_str<E>(self, value: &str) -> std::result::Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        decode_hex_bounded(self.field, value, self.min, self.max).map_err(E::custom)
    }

    fn visit_borrowed_str<E>(self, value: &'_ str) -> std::result::Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        self.visit_str(value)
    }

    fn visit_string<E>(self, value: String) -> std::result::Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        self.visit_str(&value)
    }
}
