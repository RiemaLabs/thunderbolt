use alloy::primitives::{BlockHash, TxHash};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TxIdentifier {
    pub tx_hash: TxHash,
    pub tx_index: u64,
    pub block_hash: BlockHash,
    pub block_number: u64,
    pub block_timestamp: u64,
}

impl TxIdentifier {
    pub fn new(tx_hash: TxHash, tx_index: u64, block_hash: BlockHash, block_number: u64, block_timestamp: u64) -> Self {
        Self {
            tx_hash,
            tx_index,
            block_hash,
            block_number,
            block_timestamp,
        }
    }
}
