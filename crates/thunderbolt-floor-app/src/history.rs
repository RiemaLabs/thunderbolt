use std::error::Error;

use sha2::{Digest, Sha256};
use thunderbolt_floor::{FloorLedgerChainId, VaultCheckpoint};

use crate::types::append_optional_checkpoint;
use crate::{FloorAppHash, FloorApplicationError, FloorStateRoot, GenesisDigest, Result, VaultIdentityDigest};

const SNAPSHOT_DOMAIN: &[u8] = b"bitcoin-thunderbolt/floor-app/history-snapshot/v2";
const CANDIDATE_DOMAIN: &[u8] = b"bitcoin-thunderbolt/floor-app/history-anchor-candidate/v2";
const ANCHOR_DOMAIN: &[u8] = b"bitcoin-thunderbolt/floor-app/finalized-history-anchor/v2";
/// Absolute retained block bound for one normal restart pass.
pub const MAX_RESTART_TAIL_BLOCKS: u64 = 100_000;
/// Absolute retained result bound for one normal restart pass.
pub const MAX_RESTART_TAIL_RESULTS: u64 = 1_000_000;
/// Absolute retained state-delta bound for one normal restart pass.
pub const MAX_RESTART_TAIL_STATE_DELTAS: u64 = 1_000_000;
/// Absolute live SQLite bytes admitted by normal restart.
pub const MAX_RESTART_LIVE_BYTES: u64 = 4 * 1024 * 1024 * 1024;

/// Digest of one canonical registry-ordered anchor snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct HistorySnapshotDigest([u8; 32]);

impl HistorySnapshotDigest {
    /// Constructs a digest from exact bytes.
    #[must_use]
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns exact digest bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Digest chaining one externally finalized local-history anchor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct HistoryAnchorDigest([u8; 32]);

impl HistoryAnchorDigest {
    /// Constructs a digest from exact bytes.
    #[must_use]
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns exact digest bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Exact application-created candidate submitted to an independent finality verifier.
#[derive(Clone, PartialEq, Eq)]
pub struct HistoryAnchorCandidate {
    chain_id: FloorLedgerChainId,
    genesis_digest: GenesisDigest,
    profile_digest: [u8; 32],
    epoch: u64,
    through_height: u64,
    through_time_ms: u64,
    previous_app_hash: FloorAppHash,
    through_app_hash: FloorAppHash,
    state_root: FloorStateRoot,
    snapshot_digest: HistorySnapshotDigest,
    prior_anchor_digest: Option<HistoryAnchorDigest>,
    candidate_digest: [u8; 32],
    pub(crate) snapshot: Vec<(VaultIdentityDigest, Option<VaultCheckpoint>)>,
}

impl std::fmt::Debug for HistoryAnchorCandidate {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("HistoryAnchorCandidate")
            .field("chain_id", &self.chain_id)
            .field("genesis_digest", &self.genesis_digest)
            .field("profile_digest", &self.profile_digest)
            .field("epoch", &self.epoch)
            .field("through_height", &self.through_height)
            .field("through_time_ms", &self.through_time_ms)
            .field("previous_app_hash", &self.previous_app_hash)
            .field("through_app_hash", &self.through_app_hash)
            .field("state_root", &self.state_root)
            .field("snapshot_digest", &self.snapshot_digest)
            .field("prior_anchor_digest", &self.prior_anchor_digest)
            .field("candidate_digest", &self.candidate_digest)
            .field("snapshot", &format_args!("[{} ENTRIES]", self.snapshot.len()))
            .finish()
    }
}

/// Fields used to construct one exact anchor candidate.
pub(crate) struct HistoryAnchorCandidateInput {
    pub chain_id: FloorLedgerChainId,
    pub genesis_digest: GenesisDigest,
    pub profile_digest: [u8; 32],
    pub epoch: u64,
    pub through_height: u64,
    pub through_time_ms: u64,
    pub previous_app_hash: FloorAppHash,
    pub through_app_hash: FloorAppHash,
    pub state_root: FloorStateRoot,
    pub prior_anchor_digest: Option<HistoryAnchorDigest>,
    pub snapshot: Vec<(VaultIdentityDigest, Option<VaultCheckpoint>)>,
}

impl HistoryAnchorCandidate {
    pub(crate) fn new(input: HistoryAnchorCandidateInput) -> Result<Self> {
        if input.epoch == 0 || input.through_height == 0 || input.through_time_ms == 0 || input.snapshot.is_empty() {
            return Err(FloorApplicationError::InvalidInput("history anchor candidate"));
        }
        let snapshot_digest = digest_snapshot(&input.snapshot);
        let candidate_digest = digest_candidate(&input, snapshot_digest);
        Ok(Self {
            chain_id: input.chain_id,
            genesis_digest: input.genesis_digest,
            profile_digest: input.profile_digest,
            epoch: input.epoch,
            through_height: input.through_height,
            through_time_ms: input.through_time_ms,
            previous_app_hash: input.previous_app_hash,
            through_app_hash: input.through_app_hash,
            state_root: input.state_root,
            snapshot_digest,
            prior_anchor_digest: input.prior_anchor_digest,
            candidate_digest,
            snapshot: input.snapshot,
        })
    }

    /// Returns the floor chain whose finality must be proven.
    pub const fn chain_id(&self) -> &FloorLedgerChainId {
        &self.chain_id
    }
    /// Returns the exact application genesis digest.
    pub const fn genesis_digest(&self) -> GenesisDigest {
        self.genesis_digest
    }
    /// Returns the exact consensus profile digest.
    pub const fn profile_digest(&self) -> &[u8; 32] {
        &self.profile_digest
    }
    /// Returns the monotonically increasing local anchor epoch.
    pub const fn epoch(&self) -> u64 {
        self.epoch
    }
    /// Returns the inclusive finalized height proposed for compaction.
    pub const fn through_height(&self) -> u64 {
        self.through_height
    }
    /// Returns consensus time at the proposed height.
    pub const fn through_time_ms(&self) -> u64 {
        self.through_time_ms
    }
    /// Returns the proposed block's prior application hash.
    pub const fn previous_app_hash(&self) -> FloorAppHash {
        self.previous_app_hash
    }
    /// Returns the proposed block's exact application hash.
    pub const fn through_app_hash(&self) -> FloorAppHash {
        self.through_app_hash
    }
    /// Returns the registry-ordered state root at the proposed height.
    pub const fn state_root(&self) -> FloorStateRoot {
        self.state_root
    }
    /// Returns the canonical full snapshot digest.
    pub const fn snapshot_digest(&self) -> HistorySnapshotDigest {
        self.snapshot_digest
    }
    /// Returns the exact prior local anchor digest, if any.
    pub const fn prior_anchor_digest(&self) -> Option<HistoryAnchorDigest> {
        self.prior_anchor_digest
    }
    /// Returns the exact verifier input digest.
    pub const fn candidate_digest(&self) -> &[u8; 32] {
        &self.candidate_digest
    }
}

/// Externally authenticated anchor installed before local history is pruned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FinalizedHistoryAnchor {
    chain_id: FloorLedgerChainId,
    genesis_digest: GenesisDigest,
    profile_digest: [u8; 32],
    epoch: u64,
    through_height: u64,
    through_time_ms: u64,
    previous_app_hash: FloorAppHash,
    through_app_hash: FloorAppHash,
    state_root: FloorStateRoot,
    snapshot_digest: HistorySnapshotDigest,
    committing_header_hash: [u8; 32],
    prior_anchor_digest: Option<HistoryAnchorDigest>,
    anchor_digest: HistoryAnchorDigest,
}

/// Stored fields used to reconstruct and authenticate one anchor.
pub(crate) struct StoredHistoryAnchor {
    pub chain_id: FloorLedgerChainId,
    pub genesis_digest: GenesisDigest,
    pub profile_digest: [u8; 32],
    pub epoch: u64,
    pub through_height: u64,
    pub through_time_ms: u64,
    pub previous_app_hash: FloorAppHash,
    pub through_app_hash: FloorAppHash,
    pub state_root: FloorStateRoot,
    pub snapshot_digest: HistorySnapshotDigest,
    pub committing_header_hash: [u8; 32],
    pub prior_anchor_digest: Option<HistoryAnchorDigest>,
    pub anchor_digest: HistoryAnchorDigest,
}

impl FinalizedHistoryAnchor {
    pub(crate) fn finalize(candidate: &HistoryAnchorCandidate, committing_header_hash: [u8; 32]) -> Result<Self> {
        if committing_header_hash == [0; 32] {
            return Err(FloorApplicationError::InvalidInput("history committing header"));
        }
        let anchor_digest = digest_anchor(candidate, committing_header_hash);
        Ok(Self {
            chain_id: candidate.chain_id.clone(),
            genesis_digest: candidate.genesis_digest,
            profile_digest: candidate.profile_digest,
            epoch: candidate.epoch,
            through_height: candidate.through_height,
            through_time_ms: candidate.through_time_ms,
            previous_app_hash: candidate.previous_app_hash,
            through_app_hash: candidate.through_app_hash,
            state_root: candidate.state_root,
            snapshot_digest: candidate.snapshot_digest,
            committing_header_hash,
            prior_anchor_digest: candidate.prior_anchor_digest,
            anchor_digest,
        })
    }

    pub(crate) fn from_stored(stored: StoredHistoryAnchor) -> Result<Self> {
        if stored.epoch == 0
            || stored.through_height == 0
            || stored.through_time_ms == 0
            || stored.committing_header_hash == [0; 32]
        {
            return Err(FloorApplicationError::CorruptState("history anchor fields"));
        }
        let candidate_digest = digest_candidate_values(
            &stored.chain_id,
            stored.genesis_digest,
            stored.profile_digest,
            stored.epoch,
            stored.through_height,
            stored.through_time_ms,
            stored.previous_app_hash,
            stored.through_app_hash,
            stored.state_root,
            stored.snapshot_digest,
            stored.prior_anchor_digest,
        );
        let anchor = Self {
            chain_id: stored.chain_id,
            genesis_digest: stored.genesis_digest,
            profile_digest: stored.profile_digest,
            epoch: stored.epoch,
            through_height: stored.through_height,
            through_time_ms: stored.through_time_ms,
            previous_app_hash: stored.previous_app_hash,
            through_app_hash: stored.through_app_hash,
            state_root: stored.state_root,
            snapshot_digest: stored.snapshot_digest,
            committing_header_hash: stored.committing_header_hash,
            prior_anchor_digest: stored.prior_anchor_digest,
            anchor_digest: stored.anchor_digest,
        };
        if digest_anchor_digest(&candidate_digest, stored.committing_header_hash) != stored.anchor_digest {
            return Err(FloorApplicationError::CorruptState("history anchor digest"));
        }
        Ok(anchor)
    }

    pub(crate) fn matches_candidate(&self, candidate: &HistoryAnchorCandidate) -> bool {
        self.chain_id == candidate.chain_id
            && self.genesis_digest == candidate.genesis_digest
            && self.profile_digest == candidate.profile_digest
            && self.epoch == candidate.epoch
            && self.through_height == candidate.through_height
            && self.through_time_ms == candidate.through_time_ms
            && self.previous_app_hash == candidate.previous_app_hash
            && self.through_app_hash == candidate.through_app_hash
            && self.state_root == candidate.state_root
            && self.snapshot_digest == candidate.snapshot_digest
            && self.prior_anchor_digest == candidate.prior_anchor_digest
    }

    /// Returns the finalized floor chain.
    pub const fn chain_id(&self) -> &FloorLedgerChainId {
        &self.chain_id
    }
    /// Returns the finalized application genesis digest.
    pub const fn genesis_digest(&self) -> GenesisDigest {
        self.genesis_digest
    }
    /// Returns the finalized consensus profile digest.
    pub const fn profile_digest(&self) -> &[u8; 32] {
        &self.profile_digest
    }
    /// Returns the monotonically increasing local anchor epoch.
    pub const fn epoch(&self) -> u64 {
        self.epoch
    }
    /// Returns the inclusive pruned-through height.
    pub const fn through_height(&self) -> u64 {
        self.through_height
    }
    /// Returns consensus time at the anchor height.
    pub const fn through_time_ms(&self) -> u64 {
        self.through_time_ms
    }
    /// Returns the anchor block's prior application hash.
    pub const fn previous_app_hash(&self) -> FloorAppHash {
        self.previous_app_hash
    }
    /// Returns the finalized application hash at the anchor height.
    pub const fn through_app_hash(&self) -> FloorAppHash {
        self.through_app_hash
    }
    /// Returns the finalized state root.
    pub const fn state_root(&self) -> FloorStateRoot {
        self.state_root
    }
    /// Returns the canonical full snapshot digest.
    pub const fn snapshot_digest(&self) -> HistorySnapshotDigest {
        self.snapshot_digest
    }
    /// Returns the exact committing header hash reported by the trusted verifier.
    pub const fn committing_header_hash(&self) -> &[u8; 32] {
        &self.committing_header_hash
    }
    /// Returns the prior local anchor digest, if any.
    pub const fn prior_anchor_digest(&self) -> Option<HistoryAnchorDigest> {
        self.prior_anchor_digest
    }
    /// Returns this exact chained anchor digest.
    pub const fn anchor_digest(&self) -> HistoryAnchorDigest {
        self.anchor_digest
    }
}

/// Trusted boundary for authenticating an independent finalized floor anchor.
///
/// Production implementations must verify validator quorum or a trusted light
/// client plus exact application-hash inclusion. This crate intentionally ships
/// no permissive or local implementation. Both methods are historical queries:
/// they **must be pure, immutable, and repeatable** for the same proof and
/// claim. They must not advance or overwrite a mutable light-client trust root;
/// trust advancement belongs in a separate orchestration step after the local
/// database commit has been reconciled.
pub trait FinalizedHistoryAnchorVerifier {
    /// Opaque external proof or receipt.
    type Proof;
    /// Non-secret verifier error.
    type Error: Error + Send + Sync + 'static;

    /// Authenticates a new exact candidate and returns its committing header hash.
    fn finalize_candidate(
        &self,
        candidate: &HistoryAnchorCandidate,
        proof: &Self::Proof,
    ) -> std::result::Result<[u8; 32], Self::Error>;

    /// Re-authenticates an exact stored anchor before a compacted restart.
    fn verify_stored_anchor(
        &self,
        anchor: &FinalizedHistoryAnchor,
        proof: &Self::Proof,
    ) -> std::result::Result<(), Self::Error>;
}

/// Failure while externally authorizing local history compaction.
#[derive(Debug, thiserror::Error)]
pub enum HistoryCompactionError<E: Error + 'static> {
    /// Local application validation or persistence failed.
    #[error(transparent)]
    Application(#[from] FloorApplicationError),
    /// Independent finality verification failed.
    #[error("external history-anchor finality verification failed")]
    Verifier(#[source] E),
}

/// Failure while reopening an already compacted application.
#[derive(Debug, thiserror::Error)]
pub enum HistoryOpenError<E: Error + 'static> {
    /// Local application validation or persistence failed.
    #[error(transparent)]
    Application(#[from] FloorApplicationError),
    /// Independent finality verification failed.
    #[error("stored history anchor failed external verification")]
    Verifier(#[source] E),
}

/// Caller-selected local hot-history maintenance policy.
///
/// This policy never changes consensus execution or application hashes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HistoryRetentionPolicy {
    preferred_blocks: u64,
    preferred_results: u64,
    preferred_state_deltas: u64,
    preferred_live_bytes: u64,
}

impl HistoryRetentionPolicy {
    /// Constructs positive local maintenance thresholds.
    pub fn new(
        preferred_blocks: u64,
        preferred_results: u64,
        preferred_state_deltas: u64,
        preferred_live_bytes: u64,
    ) -> Result<Self> {
        if preferred_blocks == 0 || preferred_results == 0 || preferred_state_deltas == 0 || preferred_live_bytes == 0 {
            return Err(FloorApplicationError::InvalidInput("history retention policy"));
        }
        Ok(Self {
            preferred_blocks,
            preferred_results,
            preferred_state_deltas,
            preferred_live_bytes,
        })
    }
    /// Returns the preferred retained block count.
    pub const fn preferred_blocks(self) -> u64 {
        self.preferred_blocks
    }
    /// Returns the preferred retained result count.
    pub const fn preferred_results(self) -> u64 {
        self.preferred_results
    }
    /// Returns the preferred retained state-delta count.
    pub const fn preferred_state_deltas(self) -> u64 {
        self.preferred_state_deltas
    }
    /// Returns the preferred live SQLite byte count.
    pub const fn preferred_live_bytes(self) -> u64 {
        self.preferred_live_bytes
    }
}

/// Current local hot-history usage and maintenance signal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HistoryUsage {
    /// Latest externally finalized local anchor height, or zero.
    pub anchor_height: u64,
    /// Retained committed blocks after the anchor.
    pub retained_blocks: u64,
    /// Retained ordered results after the anchor.
    pub retained_results: u64,
    /// Retained changed state leaves after the anchor.
    pub retained_state_deltas: u64,
    /// Approximate live SQLite bytes excluding freelist pages.
    pub retained_live_bytes: u64,
    /// Whether any caller-selected maintenance threshold is reached.
    pub compaction_recommended: bool,
}

pub(crate) fn digest_snapshot(entries: &[(VaultIdentityDigest, Option<VaultCheckpoint>)]) -> HistorySnapshotDigest {
    let mut bytes = Vec::with_capacity(entries.len() * 73 + 64);
    append_item(&mut bytes, b"domain", SNAPSHOT_DOMAIN);
    bytes.extend_from_slice(&(entries.len() as u64).to_be_bytes());
    for (identity, checkpoint) in entries {
        bytes.extend_from_slice(identity.as_bytes());
        append_optional_checkpoint(&mut bytes, *checkpoint);
    }
    HistorySnapshotDigest(Sha256::digest(bytes).into())
}

fn digest_candidate(input: &HistoryAnchorCandidateInput, snapshot: HistorySnapshotDigest) -> [u8; 32] {
    digest_candidate_values(
        &input.chain_id,
        input.genesis_digest,
        input.profile_digest,
        input.epoch,
        input.through_height,
        input.through_time_ms,
        input.previous_app_hash,
        input.through_app_hash,
        input.state_root,
        snapshot,
        input.prior_anchor_digest,
    )
}

#[allow(clippy::too_many_arguments)]
fn digest_candidate_values(
    chain_id: &FloorLedgerChainId,
    genesis: GenesisDigest,
    profile: [u8; 32],
    epoch: u64,
    height: u64,
    time: u64,
    previous: FloorAppHash,
    through: FloorAppHash,
    state_root: FloorStateRoot,
    snapshot: HistorySnapshotDigest,
    prior: Option<HistoryAnchorDigest>,
) -> [u8; 32] {
    let mut bytes = Vec::with_capacity(384);
    append_item(&mut bytes, b"domain", CANDIDATE_DOMAIN);
    append_item(&mut bytes, b"chain_id", chain_id.as_bytes());
    bytes.extend_from_slice(genesis.as_bytes());
    bytes.extend_from_slice(&profile);
    bytes.extend_from_slice(&epoch.to_be_bytes());
    bytes.extend_from_slice(&height.to_be_bytes());
    bytes.extend_from_slice(&time.to_be_bytes());
    bytes.extend_from_slice(previous.as_bytes());
    bytes.extend_from_slice(through.as_bytes());
    bytes.extend_from_slice(state_root.as_bytes());
    bytes.extend_from_slice(snapshot.as_bytes());
    append_optional_digest(&mut bytes, prior);
    Sha256::digest(bytes).into()
}

fn digest_anchor(candidate: &HistoryAnchorCandidate, committing_header_hash: [u8; 32]) -> HistoryAnchorDigest {
    digest_anchor_digest(candidate.candidate_digest(), committing_header_hash)
}

fn digest_anchor_digest(candidate_digest: &[u8; 32], committing_header_hash: [u8; 32]) -> HistoryAnchorDigest {
    let mut bytes = Vec::with_capacity(128);
    append_item(&mut bytes, b"domain", ANCHOR_DOMAIN);
    bytes.extend_from_slice(candidate_digest);
    bytes.extend_from_slice(&committing_header_hash);
    HistoryAnchorDigest(Sha256::digest(bytes).into())
}

fn append_optional_digest(bytes: &mut Vec<u8>, digest: Option<HistoryAnchorDigest>) {
    if let Some(digest) = digest {
        bytes.push(1);
        bytes.extend_from_slice(digest.as_bytes());
    } else {
        bytes.push(0);
    }
}

fn append_item(bytes: &mut Vec<u8>, label: &[u8], value: &[u8]) {
    bytes.extend_from_slice(&(label.len() as u64).to_be_bytes());
    bytes.extend_from_slice(label);
    bytes.extend_from_slice(&(value.len() as u64).to_be_bytes());
    bytes.extend_from_slice(value);
}
