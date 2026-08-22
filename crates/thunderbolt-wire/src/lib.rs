//! Versioned, bounded public wire messages for Bitcoin Thunderbolt.
//!
//! This crate intentionally has no wire representations for witnesses,
//! decryption keys, holder secrets, refresh scalars, or committee shares.

/// Maximum supported committee topology for bounded public messages.
pub const MAX_COMMITTEE_MEMBERS: usize = 256;
/// Reserved member identifier for the recipient's own VEDL statement.
pub const RECIPIENT_SHARE_MEMBER_ID: u32 = u32::MAX;

mod binding;
mod binding_v2;
mod codec;
mod error;
mod hex;
#[cfg(feature = "insecure-regression")]
mod invoice;
mod invoice_v2;
#[cfg(feature = "insecure-regression")]
mod message;
mod message_v2;
#[cfg(feature = "insecure-regression")]
mod share;
#[cfg(feature = "insecure-regression")]
mod threshold;
mod threshold_v2;
#[cfg(feature = "insecure-regression")]
mod transfer;
mod transfer_v2;
mod v2_values;

pub use binding::{
    BindingContext, ChannelId, DeploymentId, InvoiceId, MAX_CHANNEL_ID_BYTES, MAX_DEPLOYMENT_ID_BYTES,
    MAX_INVOICE_ID_BYTES, PROTOCOL_VERSION,
};
pub use binding_v2::{
    AnchorParameterSuiteIdV2, BitcoinGenesisHashV2, ChannelBindingV2, CommitteeDescriptorDigestV2, FundingOutpointV2,
    OperationBindingV2, ProtocolSuiteIdV2, BINDING_ID_BYTES, FUNDING_OUTPOINT_BYTES, PROTOCOL_VERSION_V2,
};
pub use codec::{
    from_json_slice, to_json_vec, CanonicalDigest, PaillierCiphertextHex, PaillierNonceHex, PaillierPublicKeyHex,
    PointHex, ProofResponseHex, ValidateWire, MAX_PAILLIER_CIPHERTEXT_BYTES, MAX_PAILLIER_NONCE_BYTES,
    MAX_PROOF_RESPONSE_BYTES, MAX_WIRE_MESSAGE_BYTES, PAILLIER_MODULUS_BYTES,
};
pub use error::{Result, WireError};
pub use hex::{CanonicalInteger, HexBytes};
#[cfg(feature = "insecure-regression")]
pub use invoice::{InvoiceEnvelopeV1, InvoiceProofV1, InvoiceStatementV1};
pub use invoice_v2::{InvoiceEnvelopeV2, InvoiceProofV2, InvoiceStatementV2};
#[cfg(feature = "insecure-regression")]
pub use message::PublicMessageV1;
pub use message_v2::{decode_public_message_v2, PublicMessageV2};
#[cfg(feature = "insecure-regression")]
pub use share::{ShareEnvelopeV1, ShareProofV1, ShareStatementV1};
#[cfg(feature = "insecure-regression")]
pub use threshold::{
    threshold_invoice_package_digest, ThresholdDistributionV1, ThresholdEncryptedShareV1, ThresholdEnvelopeV1,
};
pub use threshold_v2::{
    threshold_invoice_package_digest_v2, validate_threshold_package_v2, RecipientShareEnvelopeV2,
    RecipientShareStatementV2, ShareProofV2, ThresholdDistributionV2, ThresholdEncryptedShareV2, ThresholdEnvelopeV2,
    ThresholdPackageBindingV2, ThresholdPackageIdV2, ThresholdRosterMemberV2, ThresholdRosterV2,
};
#[cfg(feature = "insecure-regression")]
pub use transfer::{AnchorTransitionV1, TransferEnvelopeV1, TransferProofV1, TransferStatementV1};
pub use transfer_v2::{AnchorTransitionV2, TransferEnvelopeV2, TransferProofV2, TransferStatementV2};
pub use v2_values::{
    PaillierCiphertextBytesV2, PaillierModulusBytesV2, PaillierModulusProfileV2, PaillierNonceBytesV2,
    ProofResponseBytesV2, PAILLIER_V2_CIPHERTEXT_BYTES, PAILLIER_V2_MODULUS_BYTES, PROOF_RESPONSE_V2_BYTES,
};
