use serde::{Deserialize, Serialize};

use crate::codec::{CanonicalDigest, ValidateWire};
use crate::{InvoiceEnvelopeV1, Result, ShareEnvelopeV1, ThresholdEnvelopeV1, TransferEnvelopeV1};

/// Any version 1 public protocol message accepted by a Thunderbolt endpoint.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "message_type", content = "payload", rename_all = "snake_case")]
pub enum PublicMessageV1 {
    Invoice(InvoiceEnvelopeV1),
    Transfer(TransferEnvelopeV1),
    Share(ShareEnvelopeV1),
    ThresholdRefresh(ThresholdEnvelopeV1),
}

impl PublicMessageV1 {
    pub fn verify(&self) -> Result<()> {
        match self {
            Self::Invoice(message) => message.verify(),
            Self::Transfer(message) => message.verify(),
            Self::Share(message) => message.verify(),
            Self::ThresholdRefresh(message) => message.verify(),
        }
    }
}

impl ValidateWire for PublicMessageV1 {
    fn validate_wire(&self) -> Result<()> {
        match self {
            Self::Invoice(message) => message.validate_wire(),
            Self::Transfer(message) => message.validate_wire(),
            Self::Share(message) => message.validate_wire(),
            Self::ThresholdRefresh(message) => message.validate_wire(),
        }
    }
}

impl CanonicalDigest for PublicMessageV1 {
    fn canonical_digest(&self) -> Result<[u8; 32]> {
        match self {
            Self::Invoice(message) => message.canonical_digest(),
            Self::Transfer(message) => message.canonical_digest(),
            Self::Share(message) => message.canonical_digest(),
            Self::ThresholdRefresh(message) => message.canonical_digest(),
        }
    }
}
