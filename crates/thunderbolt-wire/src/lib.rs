//! Versioned, bounded public wire messages for Bitcoin Thunderbolt.
//!
//! This crate intentionally has no wire representations for witnesses,
//! decryption keys, holder secrets, refresh scalars, or committee shares.

mod binding;
mod codec;
mod error;
mod hex;
mod invoice;
mod message;
mod share;
mod threshold;
mod transfer;

pub use binding::{
    BindingContext, ChannelId, DeploymentId, InvoiceId, MAX_CHANNEL_ID_BYTES, MAX_DEPLOYMENT_ID_BYTES,
    MAX_INVOICE_ID_BYTES, PROTOCOL_VERSION,
};
pub use codec::{
    from_json_slice, to_json_vec, CanonicalDigest, PaillierCiphertextHex, PaillierNonceHex, PaillierPublicKeyHex,
    PointHex, ProofResponseHex, ValidateWire, MAX_PAILLIER_CIPHERTEXT_BYTES, MAX_PAILLIER_NONCE_BYTES,
    MAX_PROOF_RESPONSE_BYTES, MAX_WIRE_MESSAGE_BYTES, PAILLIER_MODULUS_BYTES,
};
pub use error::{Result, WireError};
pub use hex::{CanonicalInteger, HexBytes};
pub use invoice::{InvoiceEnvelopeV1, InvoiceProofV1, InvoiceStatementV1};
pub use message::PublicMessageV1;
pub use share::{ShareEnvelopeV1, ShareProofV1, ShareStatementV1};
pub use threshold::{ThresholdDistributionV1, ThresholdEncryptedShareV1, ThresholdEnvelopeV1, MAX_COMMITTEE_MEMBERS};
pub use transfer::{AnchorTransitionV1, TransferEnvelopeV1, TransferProofV1, TransferStatementV1};
