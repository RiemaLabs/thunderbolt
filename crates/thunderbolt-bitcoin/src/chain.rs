use bitcoin::BlockHash;

use crate::{BitcoinError, Result};

const HARD_MAX_CURSOR_POINTS: usize = 10_000;

/// A canonical block identified by height and hash.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct ChainPoint {
    /// Zero-based block height.
    pub height: u64,
    /// Block hash at that height.
    pub hash: BlockHash,
}

/// Bounded contiguous history used to identify and report reorganizations.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChainCursor {
    points: Vec<ChainPoint>,
    capacity: usize,
}

impl ChainCursor {
    /// Creates a cursor starting at one verified chain point.
    pub fn new(point: ChainPoint, capacity: usize) -> Result<Self> {
        if capacity == 0 || capacity > HARD_MAX_CURSOR_POINTS {
            return Err(BitcoinError::InvalidChainCursor(
                "history capacity is outside the hard bound",
            ));
        }
        Ok(Self {
            points: vec![point],
            capacity,
        })
    }

    /// Retained points in ascending, contiguous height order.
    #[must_use]
    pub fn points(&self) -> &[ChainPoint] {
        &self.points
    }

    /// Current canonical tip.
    #[must_use]
    pub fn tip(&self) -> Option<ChainPoint> {
        self.points.last().copied()
    }

    /// Maximum retained point count.
    #[must_use]
    pub const fn capacity(&self) -> usize {
        self.capacity
    }

    /// Rolls back to a retained common ancestor and appends a verified segment.
    ///
    /// `connected` must begin one height above `common` and be contiguous.
    /// Disconnected points are reported tip-first; connected points are
    /// reported ancestor-first.
    pub fn reconcile(&mut self, common: ChainPoint, connected: &[ChainPoint]) -> Result<ChainDelta> {
        let common_index = self
            .points
            .iter()
            .position(|point| *point == common)
            .ok_or(BitcoinError::ReorgBeyondHistory)?;

        let mut expected_height = common
            .height
            .checked_add(1)
            .ok_or(BitcoinError::InvalidChainCursor("block height overflow"))?;
        for point in connected {
            if point.height != expected_height {
                return Err(BitcoinError::InvalidChainCursor("connected segment is not contiguous"));
            }
            expected_height = expected_height
                .checked_add(1)
                .ok_or(BitcoinError::InvalidChainCursor("block height overflow"))?;
        }

        let suffix_start = common_index
            .checked_add(1)
            .ok_or(BitcoinError::InvalidChainCursor("cursor index overflow"))?;
        let mut disconnected = self
            .points
            .get(suffix_start..)
            .ok_or(BitcoinError::InvalidChainCursor("common ancestor index is invalid"))?
            .to_vec();
        disconnected.reverse();
        self.points.truncate(common_index + 1);
        self.points.extend_from_slice(connected);

        if self.points.len() > self.capacity {
            let remove = self.points.len() - self.capacity;
            self.points.drain(..remove);
        }

        Ok(ChainDelta {
            common_ancestor: common,
            disconnected,
            connected: connected.to_vec(),
        })
    }
}

/// Result of reconciling a cursor with Bitcoin Core's best chain.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChainDelta {
    /// New and old chains agree through this point.
    pub common_ancestor: ChainPoint,
    /// Old-chain points removed, ordered from old tip toward the ancestor.
    pub disconnected: Vec<ChainPoint>,
    /// New-chain points added, ordered from ancestor toward new tip.
    pub connected: Vec<ChainPoint>,
}

impl ChainDelta {
    /// Whether the update disconnected one or more previously canonical blocks.
    #[must_use]
    pub fn is_reorg(&self) -> bool {
        !self.disconnected.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use bitcoin::hashes::Hash;
    use proptest::prelude::*;

    use super::*;

    fn hash(branch: u8, height: u8) -> BlockHash {
        let mut bytes = [branch; 32];
        bytes[0] = height;
        BlockHash::from_byte_array(bytes)
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(256))]

        #[test]
        fn reorg_reconciliation_rolls_back_exact_suffix(
            old_len in 2usize..32,
            fork_index_seed in 0usize..32,
            replacement_len in 0usize..32,
        ) {
            let fork_index = fork_index_seed % old_len;
            let mut cursor = ChainCursor::new(
                ChainPoint { height: 0, hash: hash(1, 0) },
                64,
            )?;
            let old: Vec<_> = (1..old_len)
                .map(|height| ChainPoint {
                    height: height as u64,
                    hash: hash(1, height as u8),
                })
                .collect();
            let old_tip = cursor.tip().ok_or(BitcoinError::InvalidChainCursor("test cursor is empty"))?;
            cursor.reconcile(old_tip, &old)?;

            let common = cursor.points()[fork_index];
            let replacement: Vec<_> = (0..replacement_len)
                .map(|offset| {
                    let height = common.height + 1 + offset as u64;
                    ChainPoint { height, hash: hash(2, height as u8) }
                })
                .collect();
            let old_suffix = cursor.points()[(fork_index + 1)..].to_vec();
            let delta = cursor.reconcile(common, &replacement)?;

            let mut expected: Vec<_> = (0..=fork_index).map(|index| ChainPoint {
                height: index as u64,
                hash: hash(1, index as u8),
            }).collect();
            expected.extend_from_slice(&replacement);
            prop_assert_eq!(cursor.points(), expected.as_slice());

            let mut expected_disconnected = old_suffix;
            expected_disconnected.reverse();
            prop_assert_eq!(&delta.disconnected, &expected_disconnected);
            prop_assert_eq!(&delta.connected, &replacement);
            prop_assert_eq!(delta.is_reorg(), fork_index + 1 < old_len);
        }
    }
}
