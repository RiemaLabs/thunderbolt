//! Deterministic protocol-v2 Ledger contract for Bitcoin Thunderbolt.
//!
//! This crate defines the application bytes that a replicated Ledger must
//! agree on: authenticated proposals, entry metadata, ordered Merkle roots,
//! and an incremental application hash. It deliberately contains no clock,
//! filesystem, JSON signing, network, ABCI, or verifier-evidence logic.
//! [`ExecutedBlockV2`] and [`ExecutedEntryV2`] prove deterministic execution,
//! not consensus finality. A CometBFT quorum or light-client receipt remains a
//! separate future capability. Integrations must also persist a cross-block
//! `request_digest -> entry_hash` mapping and reject conflicting reuse.
//!
//! JSON and other serde formats are transport conveniences only. Signatures
//! and hashes always cover the canonical binary transcripts defined here.

#![deny(missing_docs)]
#![deny(
    clippy::expect_used,
    clippy::panic,
    clippy::todo,
    clippy::unimplemented,
    clippy::unwrap_used
)]
#![forbid(unsafe_code)]

mod block;
mod canonical;
mod error;
mod proposal;
mod types;

pub use block::{
    compute_app_hash_v2, entry_merkle_proof_v2, entry_merkle_root_v2, EntryMerkleProofV2, ExecutedBlockV2,
    MerkleSiblingV2, MerkleSideV2, PendingBlockV2, MAX_BLOCK_ENTRIES, MAX_BLOCK_EVENT_BYTES, MAX_MERKLE_PROOF_DEPTH,
};
pub use error::{LedgerContractError, Result};
pub use proposal::{
    ExecutedEntryMetadataV2, ExecutedEntryV2, ProposalBodyV2, SignedProposalV2, VerifiedProposalViewV2,
};
pub use types::{
    ActorKeyAlgorithmV2, ActorPublicKeyV2, ActorRequestIdV2, ActorRoleV2, ActorSignatureV2, AppHashV2,
    CanonicalEventV2, ChannelContextIdV2, ClientRequestNonceV2, EntryHashV2, EntryMerkleRootV2, EventDigestV2,
    EventKindV2, LedgerChainIdV2, MerkleNodeHashV2, ParticipantIdV2, ProposalDigestV2, RequestDigestV2,
    EVENT_BYTES_MAX, LEDGER_CHAIN_ID_MAX, LEDGER_PROTOCOL_VERSION_V2, REQUEST_NONCE_MAX, REQUEST_NONCE_MIN,
};
