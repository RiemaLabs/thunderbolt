use sha2::{Digest, Sha256};
use thunderbolt_floor::VaultCheckpoint;

use crate::{
    ActorRequestDigest, ExecutedFloorBlock, ExecutedFloorResult, FinalizedHistoryAnchor, FloorApplicationError,
    FloorGenesis, FloorResultDigest, FloorResultRoot, FloorStateRoot, HistoryAnchorDigest, HistorySnapshotDigest,
    Result, VaultIdentityDigest, MAX_BLOCK_REQUESTS, MAX_REGISTRY_ENTRIES,
};

const EMPTY_DOMAIN: &[u8] = b"bitcoin-thunderbolt/floor-app/merkle-empty/v2";
const NODE_DOMAIN: &[u8] = b"bitcoin-thunderbolt/floor-app/merkle-node/v2";
const STATE_LEAF_DOMAIN: &[u8] = b"bitcoin-thunderbolt/floor-app/state-leaf/v2";
const RESULT_LEAF_DOMAIN: &[u8] = b"bitcoin-thunderbolt/floor-app/result-leaf/v2";
/// Maximum proof depth for bounded registry/result trees.
pub const MAX_FLOOR_MERKLE_DEPTH: usize = 16;

/// Position of one Merkle sibling.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MerkleSide {
    /// Sibling is left of the running hash.
    Left,
    /// Sibling is right of the running hash.
    Right,
}

/// One bounded ordered Merkle sibling.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MerkleSibling {
    side: MerkleSide,
    hash: [u8; 32],
}

impl MerkleSibling {
    /// Returns sibling position.
    pub const fn side(&self) -> MerkleSide {
        self.side
    }
    /// Returns sibling hash.
    pub const fn hash(&self) -> &[u8; 32] {
        &self.hash
    }
}

/// Registry-ordered inclusion proof for a present or explicitly absent floor value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FloorStateProof {
    height: u64,
    block_time_ms: u64,
    identity_digest: VaultIdentityDigest,
    checkpoint: Option<VaultCheckpoint>,
    leaf_index: u32,
    leaf_count: u32,
    siblings: Vec<MerkleSibling>,
    root: FloorStateRoot,
}

/// Registry-ordered state proof bound to an externally finalized history anchor snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FloorAnchorStateProof {
    anchor_digest: HistoryAnchorDigest,
    snapshot_digest: HistorySnapshotDigest,
    identity_digest: VaultIdentityDigest,
    checkpoint: Option<VaultCheckpoint>,
    leaf_index: u32,
    leaf_count: u32,
    siblings: Vec<MerkleSibling>,
    root: FloorStateRoot,
}

impl FloorAnchorStateProof {
    /// Verifies one exact present/absent claim against an authenticated anchor and genesis.
    pub fn verify(
        &self,
        anchor: &FinalizedHistoryAnchor,
        genesis: &FloorGenesis,
        expected_identity: VaultIdentityDigest,
        expected_checkpoint: Option<VaultCheckpoint>,
    ) -> Result<()> {
        let expected_index = genesis
            .entries()
            .iter()
            .position(|entry| entry.identity_digest() == expected_identity)
            .ok_or(FloorApplicationError::UnauthorizedActor)?;
        if anchor.chain_id() != genesis.chain_id()
            || anchor.genesis_digest() != genesis.genesis_digest()
            || anchor.profile_digest() != genesis.profile_digest()
            || self.anchor_digest != anchor.anchor_digest()
            || self.snapshot_digest != anchor.snapshot_digest()
            || self.root != anchor.state_root()
            || self.identity_digest != expected_identity
            || self.checkpoint != expected_checkpoint
            || usize::try_from(self.leaf_index)
                .map_err(|_| FloorApplicationError::InvalidInput("anchor proof index"))?
                != expected_index
            || usize::try_from(self.leaf_count)
                .map_err(|_| FloorApplicationError::InvalidInput("anchor proof count"))?
                != genesis.entries().len()
        {
            return Err(FloorApplicationError::CorruptState("anchor state proof claim"));
        }
        verify_path(
            state_leaf_hash(self.identity_digest, self.checkpoint),
            self.leaf_index,
            self.leaf_count,
            u32::try_from(MAX_REGISTRY_ENTRIES)
                .map_err(|_| FloorApplicationError::InvalidInput("anchor proof bound"))?,
            &self.siblings,
            self.root.as_bytes(),
        )
    }

    /// Returns the proved identity digest.
    pub const fn identity_digest(&self) -> VaultIdentityDigest {
        self.identity_digest
    }
    /// Returns the proved checkpoint or explicit absence.
    pub const fn checkpoint(&self) -> Option<VaultCheckpoint> {
        self.checkpoint
    }
    /// Returns the authenticated anchor digest.
    pub const fn anchor_digest(&self) -> HistoryAnchorDigest {
        self.anchor_digest
    }
    /// Returns the proved state root.
    pub const fn root(&self) -> FloorStateRoot {
        self.root
    }
}

impl FloorStateProof {
    /// Verifies one exact present/absent state claim against committed execution evidence.
    pub fn verify(
        &self,
        block: &ExecutedFloorBlock,
        genesis: &FloorGenesis,
        expected_identity: VaultIdentityDigest,
        expected_checkpoint: Option<VaultCheckpoint>,
    ) -> Result<()> {
        let expected_index = genesis
            .entries()
            .iter()
            .position(|entry| entry.identity_digest() == expected_identity)
            .ok_or(FloorApplicationError::UnauthorizedActor)?;
        if self.height != block.height()
            || self.block_time_ms != block.block_time_ms()
            || self.root != block.state_root()
            || block.chain_id() != genesis.chain_id()
            || block.genesis_digest() != genesis.genesis_digest()
            || block.recompute_app_hash() != block.app_hash()
            || self.identity_digest != expected_identity
            || self.checkpoint != expected_checkpoint
            || usize::try_from(self.leaf_index).map_err(|_| FloorApplicationError::InvalidInput("state proof index"))?
                != expected_index
            || usize::try_from(self.leaf_count).map_err(|_| FloorApplicationError::InvalidInput("state proof count"))?
                != genesis.entries().len()
        {
            return Err(FloorApplicationError::CorruptState("state proof claim"));
        }
        verify_state_path(self)
    }
    /// Returns the committed block height.
    pub const fn height(&self) -> u64 {
        self.height
    }
    /// Returns the committed block time in Unix milliseconds.
    pub const fn block_time_ms(&self) -> u64 {
        self.block_time_ms
    }
    /// Returns proved identity digest.
    pub const fn identity_digest(&self) -> VaultIdentityDigest {
        self.identity_digest
    }
    /// Returns proved checkpoint; `None` is a registry-key absence proof.
    pub const fn checkpoint(&self) -> Option<VaultCheckpoint> {
        self.checkpoint
    }
    /// Returns committed state root.
    pub const fn root(&self) -> FloorStateRoot {
        self.root
    }
    /// Returns the registry-ordered leaf index.
    pub const fn leaf_index(&self) -> u32 {
        self.leaf_index
    }
    /// Returns the exact committed registry leaf count.
    pub const fn leaf_count(&self) -> u32 {
        self.leaf_count
    }
    /// Returns ordered siblings.
    pub fn siblings(&self) -> &[MerkleSibling] {
        &self.siblings
    }
}

/// Ordered inclusion proof for one executed floor result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FloorResultProof {
    height: u64,
    block_time_ms: u64,
    block_index: u32,
    leaf_count: u32,
    request_digest: ActorRequestDigest,
    result_digest: crate::FloorResultDigest,
    siblings: Vec<MerkleSibling>,
    root: FloorResultRoot,
}

impl FloorResultProof {
    /// Verifies inclusion of one exact result claim in one exact executed block.
    pub fn verify(&self, block: &ExecutedFloorBlock, result: &ExecutedFloorResult) -> Result<()> {
        let block_index =
            usize::try_from(self.block_index).map_err(|_| FloorApplicationError::InvalidInput("result proof index"))?;
        if self.height != block.height()
            || self.block_time_ms != block.block_time_ms()
            || self.root != block.result_root()
            || usize::try_from(self.leaf_count)
                .map_err(|_| FloorApplicationError::InvalidInput("result proof count"))?
                != block.results().len()
            || block.results().get(block_index) != Some(result)
            || self.request_digest != result.request_digest()
            || self.result_digest != result.result_digest()
            || result_root(block.height(), block.block_time_ms(), block.results())? != block.result_root()
            || block.recompute_app_hash() != block.app_hash()
        {
            return Err(FloorApplicationError::CorruptState("result proof claim"));
        }
        verify_path(
            result_leaf_hash(
                self.height,
                self.block_time_ms,
                self.block_index,
                self.request_digest,
                self.result_digest,
            ),
            self.block_index,
            self.leaf_count,
            u32::try_from(MAX_BLOCK_REQUESTS).map_err(|_| FloorApplicationError::InvalidInput("result proof bound"))?,
            &self.siblings,
            self.root.as_bytes(),
        )
    }
    /// Returns the committed block height.
    pub const fn height(&self) -> u64 {
        self.height
    }
    /// Returns the committed block time in Unix milliseconds.
    pub const fn block_time_ms(&self) -> u64 {
        self.block_time_ms
    }
    /// Returns proved request digest.
    pub const fn request_digest(&self) -> ActorRequestDigest {
        self.request_digest
    }
    /// Returns the exact committed result digest.
    pub const fn result_digest(&self) -> FloorResultDigest {
        self.result_digest
    }
    /// Returns committed result root.
    pub const fn root(&self) -> FloorResultRoot {
        self.root
    }
    /// Returns ordered result index.
    pub const fn block_index(&self) -> u32 {
        self.block_index
    }
    /// Returns the exact committed result leaf count.
    pub const fn leaf_count(&self) -> u32 {
        self.leaf_count
    }
    /// Returns ordered siblings.
    pub fn siblings(&self) -> &[MerkleSibling] {
        &self.siblings
    }
}

pub(crate) fn state_root(entries: &[(VaultIdentityDigest, Option<VaultCheckpoint>)]) -> Result<FloorStateRoot> {
    if entries.len() > MAX_REGISTRY_ENTRIES {
        return Err(FloorApplicationError::InvalidInput("state leaf count"));
    }
    let leaves = entries
        .iter()
        .map(|(key, value)| state_leaf_hash(*key, *value))
        .collect::<Vec<_>>();
    Ok(FloorStateRoot::new(merkle_root(&leaves)))
}

pub(crate) fn state_proof(
    height: u64,
    block_time_ms: u64,
    entries: &[(VaultIdentityDigest, Option<VaultCheckpoint>)],
    index: usize,
) -> Result<FloorStateProof> {
    let (identity_digest, checkpoint) = entries
        .get(index)
        .copied()
        .ok_or(FloorApplicationError::InvalidInput("state proof index"))?;
    let leaves = entries
        .iter()
        .map(|(key, value)| state_leaf_hash(*key, *value))
        .collect::<Vec<_>>();
    let siblings = merkle_proof(&leaves, index)?;
    Ok(FloorStateProof {
        height,
        block_time_ms,
        identity_digest,
        checkpoint,
        leaf_index: u32::try_from(index).map_err(|_| FloorApplicationError::InvalidInput("state index"))?,
        leaf_count: u32::try_from(leaves.len()).map_err(|_| FloorApplicationError::InvalidInput("state count"))?,
        siblings,
        root: FloorStateRoot::new(merkle_root(&leaves)),
    })
}

pub(crate) fn anchor_state_proof(
    anchor: &FinalizedHistoryAnchor,
    entries: &[(VaultIdentityDigest, Option<VaultCheckpoint>)],
    index: usize,
) -> Result<FloorAnchorStateProof> {
    let (identity_digest, checkpoint) = entries
        .get(index)
        .copied()
        .ok_or(FloorApplicationError::InvalidInput("anchor proof index"))?;
    let leaves = entries
        .iter()
        .map(|(key, value)| state_leaf_hash(*key, *value))
        .collect::<Vec<_>>();
    Ok(FloorAnchorStateProof {
        anchor_digest: anchor.anchor_digest(),
        snapshot_digest: anchor.snapshot_digest(),
        identity_digest,
        checkpoint,
        leaf_index: u32::try_from(index).map_err(|_| FloorApplicationError::InvalidInput("anchor state index"))?,
        leaf_count: u32::try_from(leaves.len())
            .map_err(|_| FloorApplicationError::InvalidInput("anchor state count"))?,
        siblings: merkle_proof(&leaves, index)?,
        root: FloorStateRoot::new(merkle_root(&leaves)),
    })
}

fn verify_state_path(proof: &FloorStateProof) -> Result<()> {
    verify_path(
        state_leaf_hash(proof.identity_digest, proof.checkpoint),
        proof.leaf_index,
        proof.leaf_count,
        u32::try_from(MAX_REGISTRY_ENTRIES).map_err(|_| FloorApplicationError::InvalidInput("state proof bound"))?,
        &proof.siblings,
        proof.root.as_bytes(),
    )
}

pub(crate) fn result_root(height: u64, time: u64, results: &[ExecutedFloorResult]) -> Result<FloorResultRoot> {
    if results.len() > MAX_BLOCK_REQUESTS {
        return Err(FloorApplicationError::InvalidInput("result leaf count"));
    }
    let leaves = result_leaves(height, time, results)?;
    Ok(FloorResultRoot::new(merkle_root(&leaves)))
}

pub(crate) fn result_proof(
    height: u64,
    time: u64,
    results: &[ExecutedFloorResult],
    index: usize,
) -> Result<FloorResultProof> {
    let result = results
        .get(index)
        .ok_or(FloorApplicationError::InvalidInput("result proof index"))?;
    let leaves = result_leaves(height, time, results)?;
    Ok(FloorResultProof {
        height,
        block_time_ms: time,
        block_index: u32::try_from(index).map_err(|_| FloorApplicationError::InvalidInput("result index"))?,
        leaf_count: u32::try_from(leaves.len()).map_err(|_| FloorApplicationError::InvalidInput("result count"))?,
        request_digest: result.request_digest(),
        result_digest: result.result_digest(),
        siblings: merkle_proof(&leaves, index)?,
        root: FloorResultRoot::new(merkle_root(&leaves)),
    })
}

fn result_leaves(height: u64, time: u64, results: &[ExecutedFloorResult]) -> Result<Vec<[u8; 32]>> {
    results
        .iter()
        .enumerate()
        .map(|(index, result)| {
            Ok(result_leaf_hash(
                height,
                time,
                u32::try_from(index).map_err(|_| FloorApplicationError::InvalidInput("result index"))?,
                result.request_digest(),
                result.result_digest(),
            ))
        })
        .collect()
}

fn state_leaf_hash(identity: VaultIdentityDigest, checkpoint: Option<VaultCheckpoint>) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(STATE_LEAF_DOMAIN);
    hasher.update(identity.as_bytes());
    if let Some(checkpoint) = checkpoint {
        hasher.update([1]);
        hasher.update(checkpoint.revision().get().to_be_bytes());
        hasher.update(checkpoint.state_digest().as_bytes());
    } else {
        hasher.update([0]);
    }
    hasher.finalize().into()
}

fn result_leaf_hash(
    height: u64,
    time: u64,
    index: u32,
    request: ActorRequestDigest,
    result: crate::FloorResultDigest,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(RESULT_LEAF_DOMAIN);
    hasher.update(height.to_be_bytes());
    hasher.update(time.to_be_bytes());
    hasher.update(index.to_be_bytes());
    hasher.update(request.as_bytes());
    hasher.update(result.as_bytes());
    hasher.finalize().into()
}

fn merkle_root(leaves: &[[u8; 32]]) -> [u8; 32] {
    if leaves.is_empty() {
        return Sha256::digest(EMPTY_DOMAIN).into();
    }
    if leaves.len() == 1 {
        return leaves[0];
    }
    let split = largest_power_of_two_less_than(leaves.len());
    node_hash(merkle_root(&leaves[..split]), merkle_root(&leaves[split..]))
}

fn merkle_proof(leaves: &[[u8; 32]], index: usize) -> Result<Vec<MerkleSibling>> {
    if leaves.is_empty() || index >= leaves.len() {
        return Err(FloorApplicationError::InvalidInput("Merkle proof index"));
    }
    let mut siblings = Vec::new();
    build_proof(leaves, index, &mut siblings);
    if siblings.len() > MAX_FLOOR_MERKLE_DEPTH {
        return Err(FloorApplicationError::InvalidInput("Merkle proof depth"));
    }
    Ok(siblings)
}

fn build_proof(leaves: &[[u8; 32]], index: usize, siblings: &mut Vec<MerkleSibling>) {
    if leaves.len() <= 1 {
        return;
    }
    let split = largest_power_of_two_less_than(leaves.len());
    if index < split {
        build_proof(&leaves[..split], index, siblings);
        siblings.push(MerkleSibling {
            side: MerkleSide::Right,
            hash: merkle_root(&leaves[split..]),
        });
    } else {
        build_proof(&leaves[split..], index - split, siblings);
        siblings.push(MerkleSibling {
            side: MerkleSide::Left,
            hash: merkle_root(&leaves[..split]),
        });
    }
}

fn verify_path(
    leaf: [u8; 32],
    index: u32,
    count: u32,
    maximum_count: u32,
    siblings: &[MerkleSibling],
    expected_root: &[u8; 32],
) -> Result<()> {
    if count == 0 || count > maximum_count || index >= count || siblings.len() > MAX_FLOOR_MERKLE_DEPTH {
        return Err(FloorApplicationError::InvalidInput("Merkle proof shape"));
    }
    let mut expected_sides = Vec::new();
    collect_sides(count as usize, index as usize, &mut expected_sides);
    if siblings.len() != expected_sides.len()
        || siblings
            .iter()
            .zip(expected_sides)
            .any(|(sibling, side)| sibling.side != side)
    {
        return Err(FloorApplicationError::InvalidInput("Merkle proof path"));
    }
    let running = siblings.iter().fold(leaf, |running, sibling| match sibling.side {
        MerkleSide::Left => node_hash(sibling.hash, running),
        MerkleSide::Right => node_hash(running, sibling.hash),
    });
    if &running != expected_root {
        return Err(FloorApplicationError::CorruptState("Merkle proof root"));
    }
    Ok(())
}

fn collect_sides(count: usize, index: usize, sides: &mut Vec<MerkleSide>) {
    if count <= 1 {
        return;
    }
    let split = largest_power_of_two_less_than(count);
    if index < split {
        collect_sides(split, index, sides);
        sides.push(MerkleSide::Right);
    } else {
        collect_sides(count - split, index - split, sides);
        sides.push(MerkleSide::Left);
    }
}

fn node_hash(left: [u8; 32], right: [u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(NODE_DOMAIN);
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

fn largest_power_of_two_less_than(value: usize) -> usize {
    debug_assert!(value > 1);
    let highest = usize::BITS - 1 - (value - 1).leading_zeros();
    1_usize << highest
}

#[cfg(test)]
mod tests {
    use super::*;
    use thunderbolt_keystore::{VaultRevision, VaultStateDigest};

    #[test]
    fn state_proof_covers_present_and_absent_leaves_and_rejects_tamper() {
        let entries = vec![
            (
                VaultIdentityDigest::new([1; 32]),
                Some(VaultCheckpoint::new(
                    VaultRevision::new(3),
                    VaultStateDigest::new([4; 32]),
                )),
            ),
            (VaultIdentityDigest::new([2; 32]), None),
        ];
        let present = state_proof(3, 4, &entries, 0).expect("present proof");
        verify_state_path(&present).expect("present proof verifies");
        let absent = state_proof(3, 4, &entries, 1).expect("absent proof");
        verify_state_path(&absent).expect("absent proof verifies");
        assert!(absent.checkpoint().is_none());

        let mut tampered = present;
        tampered.siblings[0].hash[0] ^= 1;
        assert!(verify_state_path(&tampered).is_err());
        let mut fabricated_root = absent.clone();
        fabricated_root.root = FloorStateRoot::new([0x55; 32]);
        assert!(verify_state_path(&fabricated_root).is_err());
        let mut wrong_side = absent;
        wrong_side.siblings[0].side = MerkleSide::Right;
        assert!(verify_state_path(&wrong_side).is_err());
    }
}
