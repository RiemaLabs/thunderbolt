use bitcoin::{hashes::Hash, Amount, BlockHash, Txid};
use secp256k1::rand::{self, Rng};
use serde::Deserialize;

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
        let mut rng = rand::thread_rng();
        let random_bytes: [u8; 32] = rng.gen();
        let result = Txid::from_slice(&random_bytes).unwrap();
        result
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
        let mut rng = rand::thread_rng();
        let random_bytes: [u8; 32] = rng.gen();
        let result = BlockHash::from_slice(&random_bytes).unwrap();
        result
    }
}
