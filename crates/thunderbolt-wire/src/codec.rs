use std::convert::TryFrom;

use libpaillier::unknown_order::BigNumber;
use libpaillier::EncryptionKey;
use secp::Point;
use serde::de::DeserializeOwned;
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::error::core_error;
use crate::hex::{CanonicalInteger, HexBytes};
use crate::{Result, WireError};

pub const MAX_WIRE_MESSAGE_BYTES: usize = 2 * 1024 * 1024;
pub const PAILLIER_MODULUS_BYTES: usize = 256;
pub const MAX_PAILLIER_CIPHERTEXT_BYTES: usize = 512;
pub const MAX_PAILLIER_NONCE_BYTES: usize = 256;
pub const MAX_PROOF_RESPONSE_BYTES: usize = 81;

pub type PointHex = HexBytes<33, 33>;
pub type PaillierPublicKeyHex = HexBytes<PAILLIER_MODULUS_BYTES, PAILLIER_MODULUS_BYTES>;
pub type PaillierCiphertextHex = CanonicalInteger<MAX_PAILLIER_CIPHERTEXT_BYTES>;
pub type PaillierNonceHex = CanonicalInteger<MAX_PAILLIER_NONCE_BYTES>;
pub type ProofResponseHex = CanonicalInteger<MAX_PROOF_RESPONSE_BYTES>;

/// Structural validation performed before a message reaches cryptographic code.
pub trait ValidateWire {
    fn validate_wire(&self) -> Result<()>;
}

/// A formatting-independent digest of the typed, validated wire fields.
pub trait CanonicalDigest: ValidateWire {
    fn canonical_digest(&self) -> Result<[u8; 32]>;
}

/// Encode a validated public message as compact JSON.
pub fn to_json_vec<T>(message: &T) -> Result<Vec<u8>>
where
    T: Serialize + ValidateWire,
{
    message.validate_wire()?;
    let encoded = serde_json::to_vec(message)?;
    if encoded.len() > MAX_WIRE_MESSAGE_BYTES {
        return Err(WireError::MessageTooLarge {
            max: MAX_WIRE_MESSAGE_BYTES,
            actual: encoded.len(),
        });
    }
    Ok(encoded)
}

/// Decode JSON only after enforcing a total input bound, then validate every
/// field-specific bound and exact cryptographic encoding.
pub fn from_json_slice<T>(encoded: &[u8]) -> Result<T>
where
    T: DeserializeOwned + ValidateWire,
{
    if encoded.len() > MAX_WIRE_MESSAGE_BYTES {
        return Err(WireError::MessageTooLarge {
            max: MAX_WIRE_MESSAGE_BYTES,
            actual: encoded.len(),
        });
    }
    let message = serde_json::from_slice::<T>(encoded)?;
    message.validate_wire()?;
    Ok(message)
}

pub(crate) fn require_canonical_json<T>(message: &T, encoded: &[u8]) -> Result<()>
where
    T: Serialize,
{
    if serde_json::to_vec(message)?.as_slice() != encoded {
        return Err(WireError::InvalidMessage {
            message: "protocol v2 JSON",
            reason: "input must use the canonical compact JSON encoding",
        });
    }
    Ok(())
}

pub(crate) fn point_to_wire(field: &'static str, point: &Point) -> Result<PointHex> {
    PointHex::from_bytes(field, point.serialize())
}

pub(crate) fn point_from_wire(field: &'static str, encoded: &PointHex) -> Result<Point> {
    let bytes = encoded.as_bytes();
    if !matches!(bytes.first(), Some(2 | 3)) {
        return Err(WireError::InvalidPoint { field });
    }
    let point = Point::from_slice(bytes).map_err(|_| WireError::InvalidPoint { field })?;
    if point.serialize().as_slice() != bytes {
        return Err(WireError::InvalidPoint { field });
    }
    Ok(point)
}

pub(crate) fn key_to_wire(field: &'static str, key: &EncryptionKey) -> Result<PaillierPublicKeyHex> {
    PaillierPublicKeyHex::from_bytes(field, key.to_bytes())
}

pub(crate) fn key_from_wire(field: &'static str, encoded: &PaillierPublicKeyHex) -> Result<EncryptionKey> {
    let bytes = encoded.as_bytes();
    if bytes.first() == Some(&0) || bytes.last().map(|byte| byte & 1) != Some(1) {
        return Err(WireError::InvalidPaillierKey { field });
    }
    let key = EncryptionKey::from_bytes(bytes).map_err(|_| WireError::InvalidPaillierKey { field })?;
    if key.to_bytes().as_slice() != bytes {
        return Err(WireError::InvalidPaillierKey { field });
    }
    Ok(key)
}

pub(crate) fn integer_to_wire<const MAX: usize>(
    field: &'static str,
    value: &BigNumber,
) -> Result<CanonicalInteger<MAX>> {
    if value < &BigNumber::zero() {
        return Err(WireError::NonCanonicalInteger { field });
    }
    let bytes = thunderbolt_core::zkp::types::canonical_big_number_bytes(value);
    CanonicalInteger::from_bytes(field, bytes)
}

pub(crate) fn integer_from_wire<const MAX: usize>(
    field: &'static str,
    encoded: &CanonicalInteger<MAX>,
) -> Result<BigNumber> {
    let value = BigNumber::from_slice(encoded.as_bytes());
    let canonical = thunderbolt_core::zkp::types::canonical_big_number_bytes(&value);
    if canonical.as_slice() != encoded.as_bytes() {
        return Err(WireError::NonCanonicalInteger { field });
    }
    Ok(value)
}

pub(crate) fn validate_ciphertext(field: &'static str, key: &EncryptionKey, ciphertext: &BigNumber) -> Result<()> {
    thunderbolt_core::paillier::validate_ciphertext(key, ciphertext).map_err(|error| core_error(field, error))
}

pub(crate) fn validate_nonce(field: &'static str, key: &EncryptionKey, nonce: &BigNumber) -> Result<()> {
    thunderbolt_core::paillier::validate_nonce(key, nonce).map_err(|error| core_error(field, error))
}

pub(crate) struct CanonicalHasher(Sha256);

impl CanonicalHasher {
    pub(crate) fn new(message_type: &'static [u8]) -> Self {
        let mut hasher = Self(Sha256::new());
        hasher.bytes(b"bitcoin-thunderbolt/wire/canonical/v1");
        hasher.bytes(message_type);
        hasher
    }

    pub(crate) fn bytes(&mut self, value: &[u8]) {
        let len = u64::try_from(value.len()).unwrap_or(u64::MAX);
        self.0.update(len.to_be_bytes());
        self.0.update(value);
    }

    pub(crate) fn u8(&mut self, value: u8) {
        self.0.update([value]);
    }

    pub(crate) fn u16(&mut self, value: u16) {
        self.0.update(value.to_be_bytes());
    }

    pub(crate) fn u32(&mut self, value: u32) {
        self.0.update(value.to_be_bytes());
    }

    pub(crate) fn u64(&mut self, value: u64) {
        self.0.update(value.to_be_bytes());
    }

    pub(crate) fn usize(&mut self, value: usize) -> Result<()> {
        let value = u64::try_from(value).map_err(|_| WireError::InvalidMessage {
            message: "canonical digest",
            reason: "collection length does not fit in the canonical encoding",
        })?;
        self.u64(value);
        Ok(())
    }

    pub(crate) fn finish(self) -> [u8; 32] {
        self.0.finalize().into()
    }
}
