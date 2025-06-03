use alloy::primitives::{BlockHash as EthBlockHash, TxHash as EthTxHash};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct EthTxIdentifier {
    pub tx_hash: EthTxHash,
    pub tx_index: u64,
    pub block_hash: EthBlockHash,
    pub block_number: u64,
    pub block_timestamp: u64,
}

impl EthTxIdentifier {
    pub fn new(
        tx_hash: EthTxHash,
        tx_index: u64,
        block_hash: EthBlockHash,
        block_number: u64,
        block_timestamp: u64,
    ) -> Self {
        Self {
            tx_hash,
            tx_index,
            block_hash,
            block_number,
            block_timestamp,
        }
    }
}
