//! Transport-neutral, canonical control-plane messages for Thunderbolt Ledger v2.
//!
//! This crate deliberately separates three different facts:
//!
//! 1. a transport admitted a signed proposal;
//! 2. [`thunderbolt_ledger::ExecutedBlockV2`] is internally deterministic; and
//! 3. an external consensus verifier accepted an opaque finality receipt.
//!
//! Encoding or decoding never creates finality authority. Concrete HTTP, gRPC,
//! CometBFT, authentication, retry, and light-client implementations live
//! outside this crate.

#![deny(missing_docs)]
#![deny(
    clippy::expect_used,
    clippy::panic,
    clippy::todo,
    clippy::unimplemented,
    clippy::unwrap_used
)]
#![forbid(unsafe_code)]

mod bytes;
mod codec;
mod error;
mod floor_codec;
mod primitives;
mod request;
mod response;

pub use bytes::{
    AmbiguityTokenV2, OpaqueConsensusReceiptV2, SnapshotBytesV2, MAX_AMBIGUITY_TOKEN_BYTES,
    MAX_CONSENSUS_RECEIPT_BYTES, MAX_SNAPSHOT_BYTES, MIN_AMBIGUITY_TOKEN_BYTES,
};
pub use codec::{MAX_RPC_REQUEST_BYTES, MAX_RPC_RESPONSE_BYTES};
pub use error::{Result, RpcCodecError};
pub use floor_codec::{RollbackFloorCasRequestV2, RollbackFloorCasResponseV2, RollbackFloorCasStatusV2};
pub use primitives::{FinalityVerifierProfileIdV2, RpcRequestDigestV2, TransportAcceptanceIdV2};
pub use request::{
    ChannelStatusRequestV2, HistoryCursorV2, HistoryPageLimitV2, HistoryRequestV2, RequestStatusRequestV2,
    RpcRequestV2, SubmitProposalRequestV2, MAX_HISTORY_PAGE_ENTRIES,
};
pub use response::{
    AdmissionRejectionV2, AdmissionStatusV2, ChannelExecutionPositionV2, ChannelStatusResponseV2,
    ExecutedMetadataRecordV2, ExternalFinalityVerifierV2, FinalityCapabilityError, FinalityStatusV2,
    FinalizedEntryBundleV2, HistoryResponseV2, RequestLifecycleV2, RequestStatusResponseV2, RpcResponseV2,
    SubmitProposalResponseV2, VerifiedFinalizedEntryV2,
};

/// Version of the transport-neutral Ledger control-plane contract.
pub const LEDGER_RPC_VERSION_V2: u16 = 2;

/// Complete control-plane contract and adapter obligations.
#[doc = include_str!("../README.md")]
pub mod api {}
