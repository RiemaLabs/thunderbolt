use std::io::{self, Write};

use serde::Serialize;
use thunderbolt_floor::VaultCheckpoint;
use thunderbolt_floor_app::{
    ExecutedFloorBlock, ExecutedFloorResult, FloorApplicationStatus, FloorGenesis, FloorResultProof, FloorStateProof,
    MerkleSide,
};

use crate::{FloorAbciError, Result, APPLICATION_VERSION, MAX_QUERY_RESPONSE_BYTES};

#[derive(Serialize)]
struct StatusValue {
    execution_only: bool,
    consensus_finality: bool,
    application_version: u64,
    chain_id: String,
    genesis_digest: String,
    profile_digest: String,
    last_height: u64,
    last_block_time_ms: u64,
    last_app_hash: String,
}

#[derive(Serialize)]
struct CheckpointValue {
    revision: u64,
    state_digest: String,
}

#[derive(Serialize)]
struct ResultValue {
    identity_digest: String,
    actor_key: String,
    nonce: String,
    request_digest: String,
    expected: Option<CheckpointValue>,
    next: CheckpointValue,
    current: Option<CheckpointValue>,
    disposition: &'static str,
    result_digest: String,
}

#[derive(Serialize)]
struct BlockValue {
    execution_only: bool,
    consensus_finality: bool,
    chain_id: String,
    genesis_digest: String,
    height: u64,
    block_time_ms: u64,
    previous_app_hash: String,
    block_digest: String,
    result_root: String,
    state_root: String,
    app_hash: String,
    results: Vec<ResultValue>,
}

#[derive(Serialize)]
struct SiblingValue {
    side: &'static str,
    hash: String,
}

#[derive(Serialize)]
struct ResultProofValue {
    execution_only: bool,
    consensus_finality: bool,
    block: BlockValue,
    block_index: u32,
    leaf_count: u32,
    request_digest: String,
    result_digest: String,
    root: String,
    siblings: Vec<SiblingValue>,
}

#[derive(Serialize)]
struct StateProofValue {
    execution_only: bool,
    consensus_finality: bool,
    block: BlockValue,
    identity_digest: String,
    checkpoint: Option<CheckpointValue>,
    leaf_index: u32,
    leaf_count: u32,
    root: String,
    siblings: Vec<SiblingValue>,
}

#[derive(Serialize)]
struct CurrentCheckpointValue {
    execution_only: bool,
    consensus_finality: bool,
    committed_height: u64,
    committed_app_hash: String,
    identity_digest: String,
    checkpoint: Option<CheckpointValue>,
    state_proof: Option<StateProofValue>,
}

pub(crate) fn status_value(status: &FloorApplicationStatus, genesis: &FloorGenesis) -> Result<Vec<u8>> {
    encode(&StatusValue {
        execution_only: true,
        consensus_finality: false,
        application_version: APPLICATION_VERSION,
        chain_id: hex(genesis.chain_id().as_bytes())?,
        genesis_digest: hex(genesis.genesis_digest().as_bytes())?,
        profile_digest: hex(genesis.profile_digest())?,
        last_height: status.last_height,
        last_block_time_ms: status.last_block_time_ms,
        last_app_hash: hex(status.last_app_hash.as_bytes())?,
    })
}

pub(crate) fn block_value(block: &ExecutedFloorBlock) -> Result<Vec<u8>> {
    encode(&block_json(block)?)
}

pub(crate) fn checkpoint_value(
    identity_digest: &[u8; 32],
    status: &FloorApplicationStatus,
    block: Option<&ExecutedFloorBlock>,
    proof: Option<&FloorStateProof>,
    checkpoint: Option<VaultCheckpoint>,
) -> Result<Vec<u8>> {
    let state_proof = match (block, proof) {
        (Some(block), Some(proof)) => Some(state_proof_json(block, proof)?),
        (None, None) => None,
        _ => return Err(FloorAbciError::InvalidRequest("checkpoint proof pairing is invalid")),
    };
    encode(&CurrentCheckpointValue {
        execution_only: true,
        consensus_finality: false,
        committed_height: status.last_height,
        committed_app_hash: hex(status.last_app_hash.as_bytes())?,
        identity_digest: hex(identity_digest)?,
        checkpoint: checkpoint_json(checkpoint)?,
        state_proof,
    })
}

pub(crate) fn result_proof_value(block: &ExecutedFloorBlock, proof: &FloorResultProof) -> Result<Vec<u8>> {
    encode(&ResultProofValue {
        execution_only: true,
        consensus_finality: false,
        block: block_json(block)?,
        block_index: proof.block_index(),
        leaf_count: proof.leaf_count(),
        request_digest: hex(proof.request_digest().as_bytes())?,
        result_digest: hex(proof.result_digest().as_bytes())?,
        root: hex(proof.root().as_bytes())?,
        siblings: siblings(proof.siblings())?,
    })
}

pub(crate) fn state_proof_value(block: &ExecutedFloorBlock, proof: &FloorStateProof) -> Result<Vec<u8>> {
    encode(&state_proof_json(block, proof)?)
}

fn state_proof_json(block: &ExecutedFloorBlock, proof: &FloorStateProof) -> Result<StateProofValue> {
    Ok(StateProofValue {
        execution_only: true,
        consensus_finality: false,
        block: block_json(block)?,
        identity_digest: hex(proof.identity_digest().as_bytes())?,
        checkpoint: checkpoint_json(proof.checkpoint())?,
        leaf_index: proof.leaf_index(),
        leaf_count: proof.leaf_count(),
        root: hex(proof.root().as_bytes())?,
        siblings: siblings(proof.siblings())?,
    })
}

fn block_json(block: &ExecutedFloorBlock) -> Result<BlockValue> {
    Ok(BlockValue {
        execution_only: true,
        consensus_finality: false,
        chain_id: hex(block.chain_id().as_bytes())?,
        genesis_digest: hex(block.genesis_digest().as_bytes())?,
        height: block.height(),
        block_time_ms: block.block_time_ms(),
        previous_app_hash: hex(block.previous_app_hash().as_bytes())?,
        block_digest: hex(block.block_digest().as_bytes())?,
        result_root: hex(block.result_root().as_bytes())?,
        state_root: hex(block.state_root().as_bytes())?,
        app_hash: hex(block.app_hash().as_bytes())?,
        results: block.results().iter().map(result_json).collect::<Result<Vec<_>>>()?,
    })
}

fn result_json(result: &ExecutedFloorResult) -> Result<ResultValue> {
    Ok(ResultValue {
        identity_digest: hex(result.identity_digest().as_bytes())?,
        actor_key: hex(result.actor_key().as_bytes())?,
        nonce: hex(result.nonce().as_bytes())?,
        request_digest: hex(result.request_digest().as_bytes())?,
        expected: checkpoint_json(result.expected())?,
        next: checkpoint_json(Some(result.next()))?
            .ok_or(FloorAbciError::InvalidRequest("next checkpoint is missing"))?,
        current: checkpoint_json(result.current())?,
        disposition: match result.disposition() {
            thunderbolt_floor_app::FloorCasDisposition::Applied => "applied",
            thunderbolt_floor_app::FloorCasDisposition::AlreadyCurrent => "already_current",
            thunderbolt_floor_app::FloorCasDisposition::Conflict => "conflict",
        },
        result_digest: hex(result.result_digest().as_bytes())?,
    })
}

fn checkpoint_json(checkpoint: Option<VaultCheckpoint>) -> Result<Option<CheckpointValue>> {
    checkpoint
        .map(|checkpoint| {
            Ok(CheckpointValue {
                revision: checkpoint.revision().get(),
                state_digest: hex(checkpoint.state_digest().as_bytes())?,
            })
        })
        .transpose()
}

fn siblings(values: &[thunderbolt_floor_app::MerkleSibling]) -> Result<Vec<SiblingValue>> {
    values
        .iter()
        .map(|value| {
            Ok(SiblingValue {
                side: match value.side() {
                    MerkleSide::Left => "left",
                    MerkleSide::Right => "right",
                },
                hash: hex(value.hash())?,
            })
        })
        .collect()
}

fn hex(bytes: &[u8]) -> Result<String> {
    let capacity = bytes
        .len()
        .checked_mul(2)
        .ok_or(FloorAbciError::InvalidRequest("hex length overflows"))?;
    let mut output = String::new();
    output
        .try_reserve_exact(capacity)
        .map_err(|_| FloorAbciError::InvalidRequest("hex allocation failed"))?;
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    for byte in bytes {
        output.push(char::from(DIGITS[usize::from(byte >> 4)]));
        output.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    Ok(output)
}

fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    let mut writer = BoundedJsonWriter::new(MAX_QUERY_RESPONSE_BYTES);
    if let Err(error) = serde_json::to_writer(&mut writer, value) {
        if writer.exceeded {
            return Err(FloorAbciError::InvalidRequest("query response exceeds bound"));
        }
        return Err(error.into());
    }
    if writer.exceeded {
        return Err(FloorAbciError::InvalidRequest("query response exceeds bound"));
    }
    Ok(writer.bytes)
}

struct BoundedJsonWriter {
    bytes: Vec<u8>,
    limit: usize,
    exceeded: bool,
}

impl BoundedJsonWriter {
    fn new(limit: usize) -> Self {
        Self {
            bytes: Vec::new(),
            limit,
            exceeded: false,
        }
    }
}

impl Write for BoundedJsonWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let Some(next) = self.bytes.len().checked_add(bytes.len()) else {
            self.exceeded = true;
            return Err(io::Error::other("bounded JSON length overflows"));
        };
        if next > self.limit {
            self.exceeded = true;
            return Err(io::Error::other("bounded JSON exceeds limit"));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
