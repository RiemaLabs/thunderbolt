use serde::{Deserialize, Serialize};
use thunderbolt_core::zkp::CertifiedKeyResolver3072;

use crate::codec::{require_canonical_json, CanonicalDigest, ValidateWire};
use crate::invoice_v2::InvoiceEnvelopeV2Input;
use crate::threshold_v2::{RecipientShareEnvelopeV2Input, ThresholdEnvelopeV2Input};
use crate::transfer_v2::TransferEnvelopeV2Input;
use crate::{InvoiceEnvelopeV2, RecipientShareEnvelopeV2, Result, ThresholdEnvelopeV2, TransferEnvelopeV2};
use crate::{WireError, MAX_WIRE_MESSAGE_BYTES};

/// Closed set of protocol-v2 public proof messages.
///
/// This semantic type deliberately does not implement `Deserialize`. Network
/// frameworks must use [`decode_public_message_v2`], which enforces the whole
/// document size and canonical-JSON rules before returning this type.
///
/// ```compile_fail
/// use thunderbolt_wire::PublicMessageV2;
/// let _: PublicMessageV2 = serde_json::from_str("{}").unwrap();
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(
    tag = "message_type",
    content = "payload",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum PublicMessageV2 {
    Invoice(InvoiceEnvelopeV2),
    Transfer(TransferEnvelopeV2),
    RecipientShare(RecipientShareEnvelopeV2),
    ThresholdRefresh(ThresholdEnvelopeV2),
}

#[derive(Deserialize)]
#[serde(
    tag = "message_type",
    content = "payload",
    rename_all = "snake_case",
    deny_unknown_fields
)]
enum PublicMessageV2Input {
    Invoice(InvoiceEnvelopeV2Input),
    Transfer(TransferEnvelopeV2Input),
    RecipientShare(RecipientShareEnvelopeV2Input),
    ThresholdRefresh(ThresholdEnvelopeV2Input),
}

/// Decodes one canonical protocol-v2 request through private bounded DTOs.
pub fn decode_public_message_v2(encoded: &[u8]) -> Result<PublicMessageV2> {
    if encoded.len() > MAX_WIRE_MESSAGE_BYTES {
        return Err(WireError::MessageTooLarge {
            max: MAX_WIRE_MESSAGE_BYTES,
            actual: encoded.len(),
        });
    }
    let input = serde_json::from_slice::<PublicMessageV2Input>(encoded)?;
    let message = match input {
        PublicMessageV2Input::Invoice(input) => PublicMessageV2::Invoice(InvoiceEnvelopeV2::from_input(input)?),
        PublicMessageV2Input::Transfer(input) => PublicMessageV2::Transfer(TransferEnvelopeV2::from_input(input)?),
        PublicMessageV2Input::RecipientShare(input) => {
            PublicMessageV2::RecipientShare(RecipientShareEnvelopeV2::from_input(input)?)
        }
        PublicMessageV2Input::ThresholdRefresh(input) => {
            PublicMessageV2::ThresholdRefresh(ThresholdEnvelopeV2::from_input(input)?)
        }
    };
    message.validate_wire()?;
    require_canonical_json(&message, encoded)?;
    Ok(message)
}

impl PublicMessageV2 {
    /// Decodes a bounded canonical request without exposing serde ingress on
    /// the semantic message type.
    pub fn decode(encoded: &[u8]) -> Result<Self> {
        decode_public_message_v2(encoded)
    }

    /// Verifies a message through the deployment's authenticated exact-match
    /// certified-key resolver. Aggregate threshold VESS remains unavailable.
    pub fn verify_with_keys<R>(&self, resolver: &R) -> Result<()>
    where
        R: CertifiedKeyResolver3072 + ?Sized,
    {
        match self {
            Self::Invoice(message) => message.verify_with_keys(resolver),
            Self::Transfer(message) => message.verify_with_keys(resolver),
            Self::RecipientShare(message) => message.verify_with_keys(resolver),
            Self::ThresholdRefresh(message) => message.verify(),
        }
    }
}

impl ValidateWire for PublicMessageV2 {
    fn validate_wire(&self) -> Result<()> {
        match self {
            Self::Invoice(message) => message.validate_wire(),
            Self::Transfer(message) => message.validate_wire(),
            Self::RecipientShare(message) => message.validate_wire(),
            Self::ThresholdRefresh(message) => message.validate_wire(),
        }
    }
}

impl CanonicalDigest for PublicMessageV2 {
    fn canonical_digest(&self) -> Result<[u8; 32]> {
        match self {
            Self::Invoice(message) => message.canonical_digest(),
            Self::Transfer(message) => message.canonical_digest(),
            Self::RecipientShare(message) => message.canonical_digest(),
            Self::ThresholdRefresh(message) => message.canonical_digest(),
        }
    }
}
