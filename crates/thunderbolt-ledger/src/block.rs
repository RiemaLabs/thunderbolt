use std::convert::TryFrom;
use std::fmt;

use serde::de::{Error as _, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};

use crate::canonical::CanonicalTranscript;
use crate::{
    AppHashV2, CommittedEntryMetadataV2, CommittedEntryV2, EntryMerkleRootV2, LedgerChainIdV2, LedgerContractError,
    Result, SignedProposalV2,
};

/// Maximum number of proposals committed in one protocol-v2 block.
pub const MAX_BLOCK_ENTRIES: usize = 1_024;
/// Maximum sum of canonical event bytes committed in one block.
pub const MAX_BLOCK_EVENT_BYTES: usize = 8 * 1024 * 1024;

/// A bounded, ordered collection of verified proposals awaiting finalization.
///
/// The consensus engine supplies ordering. This type rejects duplicate request
/// ids and invalid same-block channel chains, but the ABCI application must
/// still validate the first proposal for each channel against its persisted
/// predecessor metadata.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PendingBlockV2 {
    ledger_chain_id: LedgerChainIdV2,
    height: u64,
    block_time_ms: u64,
    previous_app_hash: AppHashV2,
    proposals: Vec<SignedProposalV2>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PendingBlockInput {
    ledger_chain_id: LedgerChainIdV2,
    height: u64,
    block_time_ms: u64,
    previous_app_hash: AppHashV2,
    proposals: BoundedProposalList,
}

struct BoundedProposalList(Vec<SignedProposalV2>);

struct ProposalListVisitor;

impl<'de> Visitor<'de> for ProposalListVisitor {
    type Value = BoundedProposalList;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "at most {MAX_BLOCK_ENTRIES} proposals containing at most {MAX_BLOCK_EVENT_BYTES} event bytes"
        )
    }

    fn visit_seq<A>(self, mut sequence: A) -> std::result::Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        if sequence.size_hint().is_some_and(|size| size > MAX_BLOCK_ENTRIES) {
            return Err(A::Error::custom("proposal count exceeds the per-block limit"));
        }
        let capacity = match sequence.size_hint() {
            Some(size) => size.min(MAX_BLOCK_ENTRIES),
            None => 0,
        };
        let mut proposals = Vec::with_capacity(capacity);
        let mut event_bytes = 0_usize;
        while let Some(proposal) = sequence.next_element::<SignedProposalV2>()? {
            if proposals.len() == MAX_BLOCK_ENTRIES {
                return Err(A::Error::custom("proposal count exceeds the per-block limit"));
            }
            event_bytes = event_bytes
                .checked_add(proposal.body().event().as_bytes().len())
                .ok_or_else(|| A::Error::custom("block event byte count overflow"))?;
            if event_bytes > MAX_BLOCK_EVENT_BYTES {
                return Err(A::Error::custom("canonical event bytes exceed the per-block limit"));
            }
            proposals.push(proposal);
        }
        Ok(BoundedProposalList(proposals))
    }
}

impl<'de> Deserialize<'de> for BoundedProposalList {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_seq(ProposalListVisitor)
    }
}

impl<'de> Deserialize<'de> for PendingBlockV2 {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let input = PendingBlockInput::deserialize(deserializer)?;
        let mut pending = Self::new(
            input.ledger_chain_id,
            input.height,
            input.block_time_ms,
            input.previous_app_hash,
        )
        .map_err(serde::de::Error::custom)?;
        for proposal in input.proposals.0 {
            pending.push(proposal).map_err(serde::de::Error::custom)?;
        }
        Ok(pending)
    }
}

impl PendingBlockV2 {
    /// Starts a deterministic block over the exact prior application hash.
    pub fn new(
        ledger_chain_id: LedgerChainIdV2,
        height: u64,
        block_time_ms: u64,
        previous_app_hash: AppHashV2,
    ) -> Result<Self> {
        validate_height_and_previous_app_hash(height, &previous_app_hash)?;
        validate_block_time(block_time_ms)?;
        Ok(Self {
            ledger_chain_id,
            height,
            block_time_ms,
            previous_app_hash,
            proposals: Vec::new(),
        })
    }

    /// Appends one verified proposal in consensus order.
    pub fn push(&mut self, proposal: SignedProposalV2) -> Result<()> {
        proposal.verify()?;
        proposal.body().validate_chain_id(&self.ledger_chain_id)?;
        if self.proposals.len() >= MAX_BLOCK_ENTRIES {
            return Err(LedgerContractError::InvalidBlock {
                reason: "entry count exceeds the per-block limit",
            });
        }
        let new_total =
            self.proposals
                .iter()
                .try_fold(proposal.body().event().as_bytes().len(), |total, existing| {
                    total.checked_add(existing.body().event().as_bytes().len()).ok_or(
                        LedgerContractError::InvalidBlock {
                            reason: "block event byte count overflow",
                        },
                    )
                })?;
        if new_total > MAX_BLOCK_EVENT_BYTES {
            return Err(LedgerContractError::InvalidBlock {
                reason: "canonical event bytes exceed the per-block limit",
            });
        }
        if self
            .proposals
            .iter()
            .any(|existing| existing.body().request_id().digest() == proposal.body().request_id().digest())
        {
            return Err(LedgerContractError::InvalidBlock {
                reason: "duplicate actor request id in one block",
            });
        }

        let channel_context_id = proposal.body().channel().context_id()?;
        let mut same_channel_predecessor = None;
        for existing in self.proposals.iter().rev() {
            if existing.body().channel().context_id()? == channel_context_id {
                same_channel_predecessor = Some(existing);
                break;
            }
        }
        if let Some(predecessor) = same_channel_predecessor {
            let expected_sequence =
                predecessor
                    .body()
                    .sequence()
                    .checked_add(1)
                    .ok_or(LedgerContractError::InvalidBlock {
                        reason: "same-block channel sequence overflow",
                    })?;
            if proposal.body().sequence() != expected_sequence
                || proposal.body().previous_entry_hash() != &predecessor.body().entry_hash()?
            {
                return Err(LedgerContractError::InvalidBlock {
                    reason: "same-channel proposals do not form one contiguous predecessor chain",
                });
            }
        }

        self.proposals.push(proposal);
        Ok(())
    }

    /// Returns the consensus Ledger chain id.
    pub const fn ledger_chain_id(&self) -> &LedgerChainIdV2 {
        &self.ledger_chain_id
    }

    /// Returns the positive consensus height.
    pub const fn height(&self) -> u64 {
        self.height
    }

    /// Returns the trusted consensus block time in Unix milliseconds.
    pub const fn block_time_ms(&self) -> u64 {
        self.block_time_ms
    }

    /// Checks monotonic consensus time against the previous finalized block.
    ///
    /// Time is non-decreasing because a nanosecond consensus timestamp may be
    /// truncated to the same millisecond in adjacent blocks.
    pub fn validate_previous_block_time(&self, previous_block_time_ms: Option<u64>) -> Result<()> {
        match (self.height, previous_block_time_ms) {
            (1, None) => Ok(()),
            (1, Some(_)) => Err(LedgerContractError::InvalidBlock {
                reason: "height one must not have a previous block time",
            }),
            (_, None) => Err(LedgerContractError::InvalidBlock {
                reason: "height greater than one requires the previous block time",
            }),
            (_, Some(0)) => Err(LedgerContractError::InvalidBlock {
                reason: "previous consensus block time must be positive",
            }),
            (_, Some(previous)) if self.block_time_ms < previous => Err(LedgerContractError::InvalidBlock {
                reason: "consensus block time moved backwards",
            }),
            (_, Some(_)) => Ok(()),
        }
    }

    /// Returns the exact prior application hash.
    pub const fn previous_app_hash(&self) -> &AppHashV2 {
        &self.previous_app_hash
    }

    /// Returns proposals in consensus order.
    pub fn proposals(&self) -> &[SignedProposalV2] {
        &self.proposals
    }

    /// Finalizes metadata, the ordered Merkle root, and the next application hash.
    pub fn finalize(self) -> Result<FinalizedBlockV2> {
        let mut entries = Vec::with_capacity(self.proposals.len());
        for (index, proposal) in self.proposals.into_iter().enumerate() {
            let block_index = u32::try_from(index).map_err(|_| LedgerContractError::InvalidBlock {
                reason: "block index does not fit in u32",
            })?;
            entries.push(CommittedEntryV2::derive(
                self.height,
                self.block_time_ms,
                block_index,
                proposal,
            )?);
        }
        let metadata = entries
            .iter()
            .map(CommittedEntryV2::metadata)
            .cloned()
            .collect::<Vec<_>>();
        let entry_merkle_root = entry_merkle_root_v2(&metadata)?;
        let entry_count = u32::try_from(entries.len()).map_err(|_| LedgerContractError::InvalidBlock {
            reason: "entry count does not fit in u32",
        })?;
        let app_hash = compute_app_hash_v2(
            &self.ledger_chain_id,
            &self.previous_app_hash,
            self.height,
            self.block_time_ms,
            entry_count,
            &entry_merkle_root,
        )?;
        Ok(FinalizedBlockV2 {
            ledger_chain_id: self.ledger_chain_id,
            height: self.height,
            block_time_ms: self.block_time_ms,
            previous_app_hash: self.previous_app_hash,
            entries,
            entry_merkle_root,
            app_hash,
        })
    }
}

/// A fully recomputable protocol-v2 block ready for durable commitment.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FinalizedBlockV2 {
    ledger_chain_id: LedgerChainIdV2,
    height: u64,
    block_time_ms: u64,
    previous_app_hash: AppHashV2,
    entries: Vec<CommittedEntryV2>,
    entry_merkle_root: EntryMerkleRootV2,
    app_hash: AppHashV2,
}

struct BoundedCommittedEntryList(Vec<CommittedEntryV2>);

struct CommittedEntryListVisitor;

impl<'de> Visitor<'de> for CommittedEntryListVisitor {
    type Value = BoundedCommittedEntryList;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "at most {MAX_BLOCK_ENTRIES} committed entries containing at most {MAX_BLOCK_EVENT_BYTES} event bytes"
        )
    }

    fn visit_seq<A>(self, mut sequence: A) -> std::result::Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        if sequence.size_hint().is_some_and(|size| size > MAX_BLOCK_ENTRIES) {
            return Err(A::Error::custom("entry count exceeds the per-block limit"));
        }
        let capacity = match sequence.size_hint() {
            Some(size) => size.min(MAX_BLOCK_ENTRIES),
            None => 0,
        };
        let mut entries = Vec::with_capacity(capacity);
        let mut event_bytes = 0_usize;
        while let Some(entry) = sequence.next_element::<CommittedEntryV2>()? {
            if entries.len() == MAX_BLOCK_ENTRIES {
                return Err(A::Error::custom("entry count exceeds the per-block limit"));
            }
            event_bytes = event_bytes
                .checked_add(entry.proposal().body().event().as_bytes().len())
                .ok_or_else(|| A::Error::custom("block event byte count overflow"))?;
            if event_bytes > MAX_BLOCK_EVENT_BYTES {
                return Err(A::Error::custom("canonical event bytes exceed the per-block limit"));
            }
            entries.push(entry);
        }
        Ok(BoundedCommittedEntryList(entries))
    }
}

impl<'de> Deserialize<'de> for BoundedCommittedEntryList {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_seq(CommittedEntryListVisitor)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FinalizedBlockInput {
    ledger_chain_id: LedgerChainIdV2,
    height: u64,
    block_time_ms: u64,
    previous_app_hash: AppHashV2,
    entries: BoundedCommittedEntryList,
    entry_merkle_root: EntryMerkleRootV2,
    app_hash: AppHashV2,
}

impl<'de> Deserialize<'de> for FinalizedBlockV2 {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let input = FinalizedBlockInput::deserialize(deserializer)?;
        let supplied_root = input.entry_merkle_root;
        let supplied_app_hash = input.app_hash;
        let supplied_entries = input.entries.0;
        let mut pending = Self::pending_from_entries(
            input.ledger_chain_id,
            input.height,
            input.block_time_ms,
            input.previous_app_hash,
            &supplied_entries,
        )
        .map_err(serde::de::Error::custom)?;
        for entry in &supplied_entries {
            pending
                .push(entry.proposal().clone())
                .map_err(serde::de::Error::custom)?;
        }
        let rebuilt = pending.finalize().map_err(serde::de::Error::custom)?;
        if rebuilt.entries != supplied_entries
            || rebuilt.entry_merkle_root != supplied_root
            || rebuilt.app_hash != supplied_app_hash
        {
            return Err(serde::de::Error::custom(LedgerContractError::InvalidBlock {
                reason: "finalized block fields do not match deterministic recomputation",
            }));
        }
        Ok(rebuilt)
    }
}

impl FinalizedBlockV2 {
    fn pending_from_entries(
        ledger_chain_id: LedgerChainIdV2,
        height: u64,
        block_time_ms: u64,
        previous_app_hash: AppHashV2,
        entries: &[CommittedEntryV2],
    ) -> Result<PendingBlockV2> {
        if entries.len() > MAX_BLOCK_ENTRIES {
            return Err(LedgerContractError::InvalidBlock {
                reason: "entry count exceeds the per-block limit",
            });
        }
        PendingBlockV2::new(ledger_chain_id, height, block_time_ms, previous_app_hash)
    }

    /// Rejects a block from another consensus Ledger cluster.
    pub fn validate_chain_id(&self, expected: &LedgerChainIdV2) -> Result<()> {
        if &self.ledger_chain_id != expected {
            return Err(LedgerContractError::InvalidBlock {
                reason: "Ledger chain id does not match the local consensus chain",
            });
        }
        Ok(())
    }

    /// Returns the consensus Ledger chain id.
    pub const fn ledger_chain_id(&self) -> &LedgerChainIdV2 {
        &self.ledger_chain_id
    }

    /// Returns the positive consensus height.
    pub const fn height(&self) -> u64 {
        self.height
    }

    /// Returns the trusted consensus block time in Unix milliseconds.
    pub const fn block_time_ms(&self) -> u64 {
        self.block_time_ms
    }

    /// Checks monotonic consensus time against the previous finalized block.
    pub fn validate_previous_block_time(&self, previous_block_time_ms: Option<u64>) -> Result<()> {
        let pending = PendingBlockV2::new(
            self.ledger_chain_id.clone(),
            self.height,
            self.block_time_ms,
            self.previous_app_hash.clone(),
        )?;
        pending.validate_previous_block_time(previous_block_time_ms)
    }

    /// Returns the prior application hash.
    pub const fn previous_app_hash(&self) -> &AppHashV2 {
        &self.previous_app_hash
    }

    /// Returns committed entries in consensus order.
    pub fn entries(&self) -> &[CommittedEntryV2] {
        &self.entries
    }

    /// Returns the ordered entry Merkle root.
    pub const fn entry_merkle_root(&self) -> &EntryMerkleRootV2 {
        &self.entry_merkle_root
    }

    /// Returns the deterministic application hash after this block.
    pub const fn app_hash(&self) -> &AppHashV2 {
        &self.app_hash
    }
}

/// Computes the ordered per-block Merkle root from committed metadata.
///
/// Leaves commit to chain id, block position, and entry hash. Internal nodes
/// use a distinct domain. An odd node is promoted to the next level, matching
/// the recursive largest-power-of-two split used by Certificate Transparency.
pub fn entry_merkle_root_v2(metadata: &[CommittedEntryMetadataV2]) -> Result<EntryMerkleRootV2> {
    if metadata.len() > MAX_BLOCK_ENTRIES {
        return Err(LedgerContractError::InvalidBlock {
            reason: "entry count exceeds the per-block limit",
        });
    }
    if metadata.is_empty() {
        let transcript = CanonicalTranscript::new(b"bitcoin-thunderbolt/block-merkle-empty/v2")?;
        return EntryMerkleRootV2::from_bytes(transcript.digest());
    }

    let first = metadata.first().ok_or(LedgerContractError::InvalidBlock {
        reason: "non-empty metadata unexpectedly has no first entry",
    })?;
    let expected_height = first.block_height();
    let expected_block_time_ms = first.block_time_ms();
    let expected_chain_id = first.ledger_chain_id();
    let mut leaves = Vec::with_capacity(metadata.len());
    for (index, item) in metadata.iter().enumerate() {
        let block_index = u32::try_from(index).map_err(|_| LedgerContractError::InvalidBlock {
            reason: "block index does not fit in u32",
        })?;
        if item.block_height() != expected_height
            || item.block_time_ms() != expected_block_time_ms
            || item.block_index() != block_index
            || item.ledger_chain_id() != expected_chain_id
        {
            return Err(LedgerContractError::InvalidBlock {
                reason: "entry metadata does not describe one ordered block",
            });
        }
        leaves.push(entry_leaf_hash(item)?);
    }
    EntryMerkleRootV2::from_bytes(merkle_subtree_root(&leaves)?)
}

/// Computes the next replicated application hash.
///
/// `app_hash[h] = SHA256(domain, chain_id, app_hash[h-1], height,
/// block_time_ms, entry_count, entry_merkle_root)` with every labeled item
/// length-prefixed.
pub fn compute_app_hash_v2(
    ledger_chain_id: &LedgerChainIdV2,
    previous_app_hash: &AppHashV2,
    height: u64,
    block_time_ms: u64,
    entry_count: u32,
    entry_merkle_root: &EntryMerkleRootV2,
) -> Result<AppHashV2> {
    validate_height_and_previous_app_hash(height, previous_app_hash)?;
    validate_block_time(block_time_ms)?;
    let entry_count_usize = usize::try_from(entry_count).map_err(|_| LedgerContractError::InvalidBlock {
        reason: "entry count does not fit in usize",
    })?;
    if entry_count_usize > MAX_BLOCK_ENTRIES {
        return Err(LedgerContractError::InvalidBlock {
            reason: "entry count exceeds the per-block limit",
        });
    }
    let mut transcript = CanonicalTranscript::new(b"bitcoin-thunderbolt/application-hash/v2")?;
    transcript.item(b"ledger_chain_id", ledger_chain_id.as_bytes())?;
    transcript.item(b"previous_app_hash", previous_app_hash.as_bytes())?;
    transcript.u64(b"block_height", height)?;
    transcript.u64(b"block_time_ms", block_time_ms)?;
    transcript.u32(b"entry_count", entry_count)?;
    transcript.item(b"entry_merkle_root", entry_merkle_root.as_bytes())?;
    AppHashV2::from_bytes(transcript.digest())
}

fn entry_leaf_hash(metadata: &CommittedEntryMetadataV2) -> Result<[u8; 32]> {
    let mut transcript = CanonicalTranscript::new(b"bitcoin-thunderbolt/block-merkle-leaf/v2")?;
    transcript.item(b"ledger_chain_id", metadata.ledger_chain_id().as_bytes())?;
    transcript.u64(b"block_height", metadata.block_height())?;
    transcript.u64(b"block_time_ms", metadata.block_time_ms())?;
    transcript.u32(b"block_index", metadata.block_index())?;
    transcript.item(b"entry_hash", metadata.entry_hash().as_bytes())?;
    Ok(transcript.digest())
}

fn merkle_subtree_root(leaves: &[[u8; 32]]) -> Result<[u8; 32]> {
    if leaves.len() == 1 {
        return leaves.first().copied().ok_or(LedgerContractError::InvalidBlock {
            reason: "Merkle subtree unexpectedly has no leaf",
        });
    }
    if leaves.is_empty() {
        return Err(LedgerContractError::InvalidBlock {
            reason: "Merkle subtree must not be empty",
        });
    }
    let split = largest_power_of_two_less_than(leaves.len())?;
    let (left_leaves, right_leaves) = leaves.split_at(split);
    let left = merkle_subtree_root(left_leaves)?;
    let right = merkle_subtree_root(right_leaves)?;
    let mut transcript = CanonicalTranscript::new(b"bitcoin-thunderbolt/block-merkle-node/v2")?;
    transcript.item(b"left", &left)?;
    transcript.item(b"right", &right)?;
    Ok(transcript.digest())
}

fn largest_power_of_two_less_than(value: usize) -> Result<usize> {
    if value < 2 {
        return Err(LedgerContractError::InvalidBlock {
            reason: "Merkle split requires at least two leaves",
        });
    }
    let mut power = 1_usize;
    loop {
        let doubled = power.checked_mul(2).ok_or(LedgerContractError::InvalidBlock {
            reason: "Merkle split overflow",
        })?;
        if doubled >= value {
            return Ok(power);
        }
        power = doubled;
    }
}

fn validate_height_and_previous_app_hash(height: u64, previous_app_hash: &AppHashV2) -> Result<()> {
    if height == 0 {
        return Err(LedgerContractError::InvalidBlock {
            reason: "block height must be positive",
        });
    }
    if height == 1 && !previous_app_hash.is_zero() {
        return Err(LedgerContractError::InvalidBlock {
            reason: "height one must extend the zero application hash",
        });
    }
    if height > 1 && previous_app_hash.is_zero() {
        return Err(LedgerContractError::InvalidBlock {
            reason: "height greater than one requires a nonzero previous application hash",
        });
    }
    Ok(())
}

fn validate_block_time(block_time_ms: u64) -> Result<()> {
    if block_time_ms == 0 {
        return Err(LedgerContractError::InvalidBlock {
            reason: "consensus block time must be positive",
        });
    }
    Ok(())
}
