use anyhow::{anyhow, Result};
use bitcoin::hex::{Case, DisplayHex};
use bitcoin::{consensus, Address, Block, Transaction, Txid};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::str::FromStr;

use super::client::{BitcoinClient, TxStatus, UtxoInfo, UtxoStatus};

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct ElectrsTxStatus {
    pub confirmed: bool,
    pub block_height: Option<u64>,
    pub block_hash: Option<String>,
    pub block_time: Option<u64>,
}

impl From<ElectrsTxStatus> for TxStatus {
    fn from(status: ElectrsTxStatus) -> Self {
        TxStatus {
            confirmed: status.confirmed,
            block_height: status.block_height,
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub(crate) struct ElectrsUtxoStatus {
    pub confirmed: bool,
    pub block_height: Option<u64>,
    pub block_hash: Option<String>,
    pub block_time: Option<u64>,
}

impl From<ElectrsUtxoStatus> for UtxoStatus {
    fn from(status: ElectrsUtxoStatus) -> Self {
        UtxoStatus {
            confirmed: status.confirmed,
            block_height: status.block_height,
        }
    }
}
#[derive(Debug, Serialize, Deserialize, Clone)]
pub(crate) struct ElectrsUtxoInfo {
    pub txid: String,
    pub vout: u32,
    pub value: u64,
    pub status: ElectrsUtxoStatus,
}

impl From<ElectrsUtxoInfo> for UtxoInfo {
    fn from(info: ElectrsUtxoInfo) -> Self {
        UtxoInfo {
            txid: info.txid,
            vout: info.vout,
            value: info.value,
            status: info.status.into(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct ElectrsFeeEstimate {
    #[serde(rename = "fastestFee")]
    pub fastest_fee: u64,
    #[serde(rename = "halfHourFee")]
    pub half_hour_fee: u64,
    #[serde(rename = "hourFee")]
    pub hour_fee: u64,
    #[serde(rename = "economyFee")]
    pub economy_fee: u64,
    #[serde(rename = "minimumFee")]
    pub minimum_fee: u64,
}

#[derive(Debug, Clone)]
pub struct BitcoinClientElectrs {
    client: Client,
    rpc_url: String,
}

impl BitcoinClientElectrs {
    pub async fn new(rpc_url: String) -> Result<Self> {
        let client = Client::new();
        let res = Self { client, rpc_url };
        let _ = res.get_block_height_impl().await?;
        Ok(res)
    }

    async fn get_fee_estimates_impl(&self) -> Result<ElectrsFeeEstimate> {
        let url = format!("{}/api/v1/fees/recommended", self.rpc_url);
        let response = self.client.get(&url).send().await?;

        if !response.status().is_success() {
            return Err(anyhow!("Failed to get fee estimates: {}", response.status()));
        }

        let fee_estimates = response.json::<ElectrsFeeEstimate>().await?;
        Ok(fee_estimates)
    }

    async fn get_tx_status_impl(&self, txid: &Txid) -> Result<ElectrsTxStatus> {
        let url = format!("{}/api/tx/{}/status", self.rpc_url, txid);
        let response = self.client.get(&url).send().await?;

        if !response.status().is_success() {
            return Err(anyhow!("Failed to get transaction status: {}", response.status()));
        }

        let status = response.json::<ElectrsTxStatus>().await?;
        Ok(status)
    }

    async fn get_address_utxos_impl(&self, address: &Address) -> Result<Vec<ElectrsUtxoInfo>> {
        let url = format!("{}/api/address/{}/utxo", self.rpc_url, address);
        let response = self.client.get(&url).send().await?;

        if !response.status().is_success() {
            return Err(anyhow!("Failed to get address UTXOs: {}", response.status()));
        }

        let utxos = response.json::<Vec<ElectrsUtxoInfo>>().await?;
        Ok(utxos)
    }
    async fn broadcast_transaction_impl(&self, tx: &Transaction) -> Result<Txid> {
        let tx_hex = consensus::serialize(tx).to_hex_string(Case::Lower);
        let url = format!("{}/api/tx", self.rpc_url);

        let response = self
            .client
            .post(&url)
            .header("Content-Type", "text/plain")
            .body(tx_hex)
            .send()
            .await?;

        if !response.status().is_success() {
            let error_text = response.text().await?;
            return Err(anyhow!("Failed to broadcast transaction: {}", error_text));
        }

        let txid_str = response.text().await?;
        let txid = Txid::from_str(&txid_str)?;
        Ok(txid)
    }

    async fn get_block_height_impl(&self) -> Result<u64> {
        let url = format!("{}/api/blocks/tip/height", self.rpc_url);
        let response = self.client.get(&url).send().await?;

        if !response.status().is_success() {
            return Err(anyhow!("Failed to get block height: {}", response.status()));
        }

        let block_height = response.json::<u64>().await?;
        Ok(block_height)
    }

    async fn get_block_hash_impl(&self, height: u64) -> Result<String> {
        let url = format!("{}/api/block-height/{height}", self.rpc_url);
        let response = self.client.get(&url).send().await?;

        if !response.status().is_success() {
            return Err(anyhow!("Failed to get block hash: {}", response.status()));
        }

        let block_hash = response.text().await?;
        Ok(block_hash)
    }

    async fn get_block_impl(&self, block_hash: &str) -> Result<Block> {
        let url = format!("{}/api/block/{block_hash}/raw", self.rpc_url);
        let response = self.client.get(&url).send().await?;

        if !response.status().is_success() {
            return Err(anyhow!("Failed to get block: {}", response.status()));
        }

        let raw_data = response.bytes().await?;
        let block = bitcoin::consensus::deserialize(&raw_data)?;
        Ok(block)
    }
}

#[async_trait::async_trait]
impl BitcoinClient for BitcoinClientElectrs {
    async fn get_minimum_fee(&self) -> Result<u64> {
        let fee_estimates = self.get_fee_estimates_impl().await?;
        Ok(fee_estimates.minimum_fee)
    }

    async fn get_tx_status(&self, txid: &Txid) -> Result<TxStatus> {
        self.get_tx_status_impl(txid).await.map(|status| status.into())
    }

    async fn get_address_utxos(&self, address: &Address) -> Result<Vec<UtxoInfo>> {
        self.get_address_utxos_impl(address)
            .await
            .map(|utxos| utxos.into_iter().map(|u| u.into()).collect())
    }

    async fn broadcast_transaction(&self, tx: &Transaction) -> Result<Txid> {
        self.broadcast_transaction_impl(tx).await
    }

    async fn get_block_height(&self) -> Result<u64> {
        self.get_block_height_impl().await
    }

    async fn get_block_hash(&self, height: u64) -> Result<String> {
        self.get_block_hash_impl(height).await
    }

    async fn get_block(&self, block_hash: &str) -> Result<Block> {
        self.get_block_impl(block_hash).await
    }
}
