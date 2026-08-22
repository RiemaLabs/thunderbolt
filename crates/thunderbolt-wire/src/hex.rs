use std::fmt;

use serde::de::{Error as DeError, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::{Result, WireError};

/// A byte string whose JSON representation is canonical lowercase hexadecimal.
///
/// The private representation prevents callers from constructing values that
/// bypass the declared byte bounds.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct HexBytes<const MIN: usize, const MAX: usize>(Vec<u8>);

impl<const MIN: usize, const MAX: usize> HexBytes<MIN, MAX> {
    pub fn from_bytes(field: &'static str, bytes: impl AsRef<[u8]>) -> Result<Self> {
        let bytes = bytes.as_ref();
        if bytes.len() < MIN || bytes.len() > MAX {
            return Err(WireError::InvalidLength {
                field,
                min: MIN,
                max: MAX,
                actual: bytes.len(),
            });
        }
        Ok(Self(bytes.to_vec()))
    }

    pub fn from_hex(field: &'static str, encoded: &str) -> Result<Self> {
        if encoded.len() > MAX.saturating_mul(2) {
            return Err(WireError::InvalidLength {
                field,
                min: MIN,
                max: MAX,
                actual: encoded.len().saturating_add(1) / 2,
            });
        }
        if !encoded.len().is_multiple_of(2) {
            return Err(WireError::InvalidHex {
                field,
                reason: "hexadecimal strings must contain an even number of characters",
            });
        }
        if !encoded
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(WireError::InvalidHex {
                field,
                reason: "only characters 0-9 and a-f are accepted",
            });
        }
        let decoded = hex::decode(encoded).map_err(|_| WireError::InvalidHex {
            field,
            reason: "hexadecimal decoding failed",
        })?;
        Self::from_bytes(field, decoded)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn to_hex(&self) -> String {
        hex::encode(&self.0)
    }
}

impl<const MIN: usize, const MAX: usize> fmt::Debug for HexBytes<MIN, MAX> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("HexBytes").field(&self.to_hex()).finish()
    }
}

impl<const MIN: usize, const MAX: usize> Serialize for HexBytes<MIN, MAX> {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_hex())
    }
}

struct HexVisitor<const MIN: usize, const MAX: usize>;

impl<const MIN: usize, const MAX: usize> Visitor<'_> for HexVisitor<MIN, MAX> {
    type Value = HexBytes<MIN, MAX>;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "a lowercase hexadecimal string containing {MIN}..={MAX} bytes"
        )
    }

    fn visit_str<E>(self, value: &str) -> std::result::Result<Self::Value, E>
    where
        E: DeError,
    {
        HexBytes::from_hex("hex field", value).map_err(E::custom)
    }
}

impl<'de, const MIN: usize, const MAX: usize> Deserialize<'de> for HexBytes<MIN, MAX> {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_str(HexVisitor::<MIN, MAX>)
    }
}

/// A minimal-width, non-negative big-endian integer encoded as lowercase hex.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CanonicalInteger<const MAX: usize>(HexBytes<1, MAX>);

impl<const MAX: usize> CanonicalInteger<MAX> {
    pub fn from_bytes(field: &'static str, bytes: impl AsRef<[u8]>) -> Result<Self> {
        let value = HexBytes::<1, MAX>::from_bytes(field, bytes)?;
        if value.as_bytes().len() > 1 && value.as_bytes().first() == Some(&0) {
            return Err(WireError::NonCanonicalInteger { field });
        }
        Ok(Self(value))
    }

    pub fn from_hex(field: &'static str, encoded: &str) -> Result<Self> {
        let value = HexBytes::<1, MAX>::from_hex(field, encoded)?;
        Self::from_bytes(field, value.as_bytes())
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    pub fn to_hex(&self) -> String {
        self.0.to_hex()
    }
}

impl<const MAX: usize> fmt::Debug for CanonicalInteger<MAX> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("CanonicalInteger").field(&self.to_hex()).finish()
    }
}

impl<const MAX: usize> Serialize for CanonicalInteger<MAX> {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_hex())
    }
}

struct IntegerVisitor<const MAX: usize>;

impl<const MAX: usize> Visitor<'_> for IntegerVisitor<MAX> {
    type Value = CanonicalInteger<MAX>;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "a canonical lowercase hexadecimal integer of at most {MAX} bytes"
        )
    }

    fn visit_str<E>(self, value: &str) -> std::result::Result<Self::Value, E>
    where
        E: DeError,
    {
        CanonicalInteger::from_hex("integer field", value).map_err(E::custom)
    }
}

impl<'de, const MAX: usize> Deserialize<'de> for CanonicalInteger<MAX> {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_str(IntegerVisitor::<MAX>)
    }
}
