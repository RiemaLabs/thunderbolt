use bitcoin::{hashes::Hash, Amount, BlockHash, Txid};
use rand::Rng;
use serde::{Deserialize, Serialize};

#[derive(Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Utxo {
    pub txid: Txid,
    pub vout: u32,
    pub value: Amount,
}

pub trait TxidExt {
    fn to_bytes(&self) -> [u8; 32];
    fn from_bytes(bytes: [u8; 32]) -> Self;
    fn default() -> Self;
    fn random() -> Self;
}

impl TxidExt for Txid {
    fn to_bytes(&self) -> [u8; 32] {
        self.to_raw_hash().to_byte_array()
    }

    fn from_bytes(bytes: [u8; 32]) -> Self {
        Txid::from_slice(&bytes).expect("Invalid Txid")
    }

    fn default() -> Self {
        Txid::from_byte_array([0u8; 32])
    }

    fn random() -> Self {
        let mut rng = rand::rng();
        let random_bytes: [u8; 32] = rng.random();
        Txid::from_slice(&random_bytes).unwrap()
    }
}

pub trait BlockHashExt {
    fn to_bytes(&self) -> [u8; 32];
    fn from_bytes(bytes: [u8; 32]) -> Self;
    fn default() -> Self;
    fn random() -> Self;
}

impl BlockHashExt for BlockHash {
    fn to_bytes(&self) -> [u8; 32] {
        self.to_byte_array()
    }

    fn from_bytes(bytes: [u8; 32]) -> Self {
        bitcoin::BlockHash::from_slice(&bytes).expect("Invalid BlockHash")
    }

    fn default() -> Self {
        BlockHash::from_byte_array([0u8; 32])
    }

    fn random() -> Self {
        let mut rng = rand::rng();
        let random_bytes: [u8; 32] = rng.random();
        BlockHash::from_slice(&random_bytes).unwrap()
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TxIdentifier {
    pub tx_hash: Txid,
    pub tx_index: u64,
    pub block_hash: BlockHash,
    pub block_number: u64,
    pub block_timestamp: u64,
}
