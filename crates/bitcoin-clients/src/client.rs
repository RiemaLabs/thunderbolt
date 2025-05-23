use anyhow::Result;
use bitcoin::{Address, Block, Transaction, Txid};
use serde::{Deserialize, Serialize};

use super::client_blockbook::BitcoinClientBlockbook;
use super::client_electrs::BitcoinClientElectrs;
use super::client_mock::BitcoinClientMock;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TxStatus {
    pub confirmed: bool,
    pub block_height: Option<u64>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct UtxoStatus {
    pub confirmed: bool,
    pub block_height: Option<u64>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct UtxoInfo {
    pub txid: String,
    pub vout: u32,
    pub value: u64,
    pub status: UtxoStatus,
}

#[async_trait::async_trait]
pub trait BitcoinClient {
    async fn get_address_utxos(&self, address: &Address) -> Result<Vec<UtxoInfo>>;
    async fn get_tx_status(&self, txid: &Txid) -> Result<TxStatus>;
    async fn broadcast_transaction(&self, tx: &Transaction) -> Result<Txid>;
    async fn get_minimum_fee(&self) -> Result<u64>;
    async fn get_block_height(&self) -> Result<u64>;
    async fn get_block_hash(&self, height: u64) -> Result<String>;
    async fn get_block(&self, block_hash: &str) -> Result<Block>;
}

pub enum BitcoinClientEnum {
    Electrs(BitcoinClientElectrs),
    Blockbook(BitcoinClientBlockbook),
    Mock(BitcoinClientMock),
}

#[async_trait::async_trait]
impl BitcoinClient for BitcoinClientEnum {
    async fn get_address_utxos(&self, address: &Address) -> Result<Vec<UtxoInfo>> {
        match self {
            BitcoinClientEnum::Electrs(client) => client.get_address_utxos(address).await,
            BitcoinClientEnum::Blockbook(client) => client.get_address_utxos(address).await,
            BitcoinClientEnum::Mock(client) => client.get_address_utxos(address).await,
        }
    }

    async fn get_tx_status(&self, txid: &Txid) -> Result<TxStatus> {
        match self {
            BitcoinClientEnum::Electrs(client) => client.get_tx_status(txid).await,
            BitcoinClientEnum::Blockbook(client) => client.get_tx_status(txid).await,
            BitcoinClientEnum::Mock(client) => client.get_tx_status(txid).await,
        }
    }

    async fn broadcast_transaction(&self, tx: &Transaction) -> Result<Txid> {
        match self {
            BitcoinClientEnum::Electrs(client) => client.broadcast_transaction(tx).await,
            BitcoinClientEnum::Blockbook(client) => client.broadcast_transaction(tx).await,
            BitcoinClientEnum::Mock(client) => client.broadcast_transaction(tx).await,
        }
    }

    async fn get_minimum_fee(&self) -> Result<u64> {
        match self {
            BitcoinClientEnum::Electrs(client) => client.get_minimum_fee().await,
            BitcoinClientEnum::Blockbook(client) => client.get_minimum_fee().await,
            BitcoinClientEnum::Mock(client) => client.get_minimum_fee().await,
        }
    }

    async fn get_block_height(&self) -> Result<u64> {
        match self {
            BitcoinClientEnum::Electrs(client) => client.get_block_height().await,
            BitcoinClientEnum::Blockbook(client) => client.get_block_height().await,
            BitcoinClientEnum::Mock(client) => client.get_block_height().await,
        }
    }

    async fn get_block_hash(&self, height: u64) -> Result<String> {
        match self {
            BitcoinClientEnum::Electrs(client) => client.get_block_hash(height).await,
            BitcoinClientEnum::Blockbook(client) => client.get_block_hash(height).await,
            BitcoinClientEnum::Mock(client) => client.get_block_hash(height).await,
        }
    }

    async fn get_block(&self, block_hash: &str) -> Result<Block> {
        match self {
            BitcoinClientEnum::Electrs(client) => client.get_block(block_hash).await,
            BitcoinClientEnum::Blockbook(client) => client.get_block(block_hash).await,
            BitcoinClientEnum::Mock(client) => client.get_block(block_hash).await,
        }
    }
}
