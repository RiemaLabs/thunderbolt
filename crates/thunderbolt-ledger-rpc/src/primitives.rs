use std::fmt;

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

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                let text = String::deserialize(deserializer)?;
                if text.len() != 64
                    || !text
                        .bytes()
                        .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
                {
                    return Err(serde::de::Error::custom(concat!("invalid ", $field)));
                }
                let decoded = hex::decode(text).map_err(serde::de::Error::custom)?;
                let bytes = <[u8; 32]>::try_from(decoded.as_slice())
                    .map_err(|_| serde::de::Error::custom(concat!("invalid ", $field)))?;
                Self::from_bytes(bytes).map_err(serde::de::Error::custom)
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

pub(crate) fn decode_hex_exact<const N: usize>(field: &'static str, text: &str) -> Result<[u8; N]> {
    if text.len() != N.saturating_mul(2)
        || !text
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(RpcCodecError::invalid_hex(field));
    }
    let decoded = hex::decode(text).map_err(|_| RpcCodecError::invalid_hex(field))?;
    <[u8; N]>::try_from(decoded.as_slice()).map_err(|_| RpcCodecError::invalid_hex(field))
}

pub(crate) fn decode_hex_bounded(field: &'static str, text: &str, min: usize, max: usize) -> Result<Vec<u8>> {
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
