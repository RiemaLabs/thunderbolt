//! Bounded CometBFT ABCI 2.0 adapter for the signed Thunderbolt floor.
//!
//! This crate is an execution adapter. It does not provide networking,
//! validator governance, snapshots, vote extensions, or consensus finality.

#![deny(missing_docs)]
#![deny(
    clippy::expect_used,
    clippy::panic,
    clippy::todo,
    clippy::unimplemented,
    clippy::unwrap_used
)]
#![forbid(unsafe_code)]

mod app;
mod codec;
mod error;
mod profile;
mod query;

#[cfg(test)]
mod tests;

pub use app::{
    FatalAbciFailure, FatalAbciHandler, FatalAbciStage, ProcessExitFatalHandler, ThunderboltFloorAbci,
    QUERY_BLOCK_PATH, QUERY_CHECKPOINT_PATH, QUERY_RESULT_PROOF_PATH, QUERY_STATE_PROOF_PATH, QUERY_STATUS_PATH,
};

pub use codec::{
    decode_signed_cas, encode_signed_cas, FLOOR_TRANSACTION_CODEC_VERSION, FLOOR_TRANSACTION_MAGIC,
    MAX_TRANSACTION_BYTES, MIN_TRANSACTION_BYTES,
};
pub use error::{FloorAbciError, Result};
pub use profile::{FloorConsensusProfileV2, FloorValidatorGenesisV2};

/// ABCI application version pinned by the floor-v2 finality profile.
pub const APPLICATION_VERSION: u64 = thunderbolt_floor_app::FLOOR_APPLICATION_VERSION_V2;
/// ABCI application name returned by Info.
pub const APPLICATION_NAME: &str = "bitcoin-thunderbolt-floor-v2";
/// Deterministic ABCI codespace.
pub const ABCI_CODESPACE: &str = "thunderbolt-floor";
/// Maximum aggregate transaction bytes in one Floor block.
pub const MAX_BLOCK_TRANSACTION_BYTES: usize = MAX_TRANSACTION_BYTES * thunderbolt_floor_app::MAX_BLOCK_REQUESTS;
/// Maximum raw transactions examined by one PrepareProposal call.
pub const MAX_PREPARE_SCAN_TRANSACTIONS: usize = 4_096;
/// Maximum raw bytes examined by one PrepareProposal call.
pub const MAX_PREPARE_SCAN_BYTES: usize = MAX_TRANSACTION_BYTES * MAX_PREPARE_SCAN_TRANSACTIONS;
/// Maximum cumulative candidate entries replayed by greedy PrepareProposal.
pub const MAX_PREPARE_PREVIEW_WORK: usize = 4_096;
/// Maximum bounded in-memory mempool admission identities.
pub const MAX_MEMPOOL_ADMISSIONS: usize = 4_096;
/// Maximum query key bytes.
pub const MAX_QUERY_REQUEST_BYTES: usize = 64;
/// Maximum serialized execution-only query value bytes.
pub const MAX_QUERY_RESPONSE_BYTES: usize = 2 * 1024 * 1024;
/// Conservative JSON expansion budget for one executed result.
pub const MAX_RESULT_QUERY_JSON_BYTES: usize = 1_024;
/// Fixed metadata/proof reserve outside the executed result array.
pub const MAX_QUERY_METADATA_BYTES: usize = 64 * 1024;
/// Maximum misbehavior records accepted in one consensus callback.
pub const MAX_MISBEHAVIOR_RECORDS: usize = 64;
/// Maximum votes accepted in one commit-info value.
pub const MAX_COMMIT_VOTES: usize = 64;
/// Exact CometBFT consensus block byte limit pinned by InitChain/profile.
pub const COMET_MAX_BLOCK_BYTES: i64 = 1024 * 1024;
/// Exact CometBFT consensus gas policy pinned by InitChain/profile.
pub const COMET_MAX_BLOCK_GAS: i64 = -1;
/// Exact CometBFT evidence age in blocks.
pub const COMET_EVIDENCE_MAX_AGE_BLOCKS: i64 = 100_000;
/// Exact CometBFT evidence age in seconds.
pub const COMET_EVIDENCE_MAX_AGE_SECONDS: i64 = 172_800;
/// Exact CometBFT evidence byte limit.
pub const COMET_EVIDENCE_MAX_BYTES: i64 = 64 * 1024;
/// Maximum decoded ABCI request frame contract for an external bounded dispatcher.
pub const MAX_ABCI_REQUEST_FRAME_BYTES: usize = 3 * 1024 * 1024;

fn compiled_resource_profile_values() -> [u64; 26] {
    [
        APPLICATION_VERSION,
        u64::from(FLOOR_TRANSACTION_CODEC_VERSION),
        MAX_TRANSACTION_BYTES as u64,
        MAX_BLOCK_TRANSACTION_BYTES as u64,
        thunderbolt_floor_app::MAX_BLOCK_REQUESTS as u64,
        thunderbolt_floor_app::MAX_REGISTRY_ENTRIES as u64,
        thunderbolt_floor_app::MAX_FLOOR_MERKLE_DEPTH as u64,
        MAX_PREPARE_SCAN_TRANSACTIONS as u64,
        MAX_PREPARE_SCAN_BYTES as u64,
        MAX_PREPARE_PREVIEW_WORK as u64,
        MAX_MEMPOOL_ADMISSIONS as u64,
        MAX_QUERY_REQUEST_BYTES as u64,
        MAX_QUERY_RESPONSE_BYTES as u64,
        MAX_RESULT_QUERY_JSON_BYTES as u64,
        MAX_QUERY_METADATA_BYTES as u64,
        MAX_MISBEHAVIOR_RECORDS as u64,
        MAX_COMMIT_VOTES as u64,
        COMET_MAX_BLOCK_BYTES as u64,
        u64::from_be_bytes(COMET_MAX_BLOCK_GAS.to_be_bytes()),
        COMET_EVIDENCE_MAX_AGE_BLOCKS as u64,
        COMET_EVIDENCE_MAX_AGE_SECONDS as u64,
        0,
        COMET_EVIDENCE_MAX_BYTES as u64,
        MAX_ABCI_REQUEST_FRAME_BYTES as u64,
        0,
        0,
    ]
}

fn validate_compiled_resource_limits() -> Result<()> {
    let expected_block_bytes = MAX_TRANSACTION_BYTES
        .checked_mul(thunderbolt_floor_app::MAX_BLOCK_REQUESTS)
        .ok_or(FloorAbciError::InvalidRequest("compiled block byte bound overflows"))?;
    let expected_scan_bytes = MAX_TRANSACTION_BYTES
        .checked_mul(MAX_PREPARE_SCAN_TRANSACTIONS)
        .ok_or(FloorAbciError::InvalidRequest("compiled scan byte bound overflows"))?;
    let worst_query_bytes = MAX_RESULT_QUERY_JSON_BYTES
        .checked_mul(thunderbolt_floor_app::MAX_BLOCK_REQUESTS)
        .and_then(|value| value.checked_add(MAX_QUERY_METADATA_BYTES))
        .ok_or(FloorAbciError::InvalidRequest(
            "compiled query expansion bound overflows",
        ))?;
    if APPLICATION_VERSION != 2
        || expected_block_bytes != MAX_BLOCK_TRANSACTION_BYTES
        || expected_scan_bytes != MAX_PREPARE_SCAN_BYTES
        || MAX_BLOCK_TRANSACTION_BYTES > usize::try_from(COMET_MAX_BLOCK_BYTES).unwrap_or(0)
        || MAX_BLOCK_TRANSACTION_BYTES > MAX_ABCI_REQUEST_FRAME_BYTES
        || MAX_PREPARE_SCAN_BYTES > MAX_ABCI_REQUEST_FRAME_BYTES
        || MAX_QUERY_REQUEST_BYTES > MAX_QUERY_RESPONSE_BYTES
        || worst_query_bytes > MAX_QUERY_RESPONSE_BYTES
        || COMET_EVIDENCE_MAX_AGE_BLOCKS <= 0
        || COMET_EVIDENCE_MAX_AGE_SECONDS <= 0
        || COMET_EVIDENCE_MAX_BYTES <= 0
        || COMET_EVIDENCE_MAX_BYTES >= COMET_MAX_BLOCK_BYTES
    {
        return Err(FloorAbciError::InvalidRequest(
            "compiled Floor ABCI resource relationships are inconsistent",
        ));
    }
    Ok(())
}
