//! Deterministic signed rollback-floor consensus application.
//!
//! Registry identities use the closed `thunderbolt-keystore` network domain.
//! Bitcoin Testnet4 is structurally unrepresentable until that identity format
//! gains a distinct Testnet4 tag, and Mainnet is explicitly rejected until an
//! independent audit.

#![deny(missing_docs)]
#![forbid(unsafe_code)]

mod error;
mod history;
mod merkle;
mod migrations;
mod store;
mod types;

pub use error::{FloorApplicationError, Result};
pub use history::{
    FinalizedHistoryAnchor, FinalizedHistoryAnchorVerifier, HistoryAnchorCandidate, HistoryAnchorDigest,
    HistoryCompactionError, HistoryOpenError, HistoryRetentionPolicy, HistorySnapshotDigest, HistoryUsage,
    MAX_RESTART_LIVE_BYTES, MAX_RESTART_TAIL_BLOCKS, MAX_RESTART_TAIL_RESULTS, MAX_RESTART_TAIL_STATE_DELTAS,
};
pub use merkle::{
    FloorAnchorStateProof, FloorResultProof, FloorStateProof, MerkleSibling, MerkleSide, MAX_FLOOR_MERKLE_DEPTH,
};
pub use migrations::CURRENT_SCHEMA_VERSION;
pub use store::FloorApplication;
pub use types::{
    ActorRequestDigest, ActorRequestNonce, ExecutedFloorBlock, ExecutedFloorResult, FloorAppHash,
    FloorApplicationStatus, FloorBlockDigest, FloorBlockExecutionOutcome, FloorBlockInput, FloorCasAuthorization,
    FloorCasDisposition, FloorGenesis, FloorOperatorKey, FloorResultDigest, FloorResultRoot, FloorStateRoot,
    GenesisDigest, PreparedFloorBlock, RegistryDigest, RegistryEntry, SignedFloorCasRequest, VaultIdentityDigest,
    ACTOR_REQUEST_NONCE_BYTES, MAX_BLOCK_REQUESTS, MAX_REGISTRY_ENTRIES,
};

/// Version of the deterministic floor application contract.
pub const FLOOR_APPLICATION_VERSION_V2: u64 = 2;
