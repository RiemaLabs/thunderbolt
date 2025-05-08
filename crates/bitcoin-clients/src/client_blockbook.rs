use anyhow::Result;
use bitcoin::{Address, Transaction, Txid};
use reqwest::Client;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::str::FromStr;

use super::client::{BitcoinClient, TxStatus, UtxoInfo, UtxoStatus};

#[derive(Debug, Serialize, Deserialize)]
pub struct JSONRpcResponse<T> {
    pub result: T,
    pub error: Option<JSONRpcError>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct JSONRpcError {
    pub code: i64,
    pub message: String,
}

// https://www.quicknode.com/docs/bitcoin/bb_getutxos
#[derive(Debug, Serialize, Deserialize)]
pub struct BlockbookUtxoInfo {
    pub txid: String,
    pub vout: u32,
    pub value: String,
    pub confirmations: u64,
    pub height: u64,
}

impl From<BlockbookUtxoInfo> for UtxoInfo {
    fn from(info: BlockbookUtxoInfo) -> Self {
        UtxoInfo {
            txid: info.txid,
            vout: info.vout,
            value: info.value.parse::<u64>().unwrap(),
            status: UtxoStatus {
                confirmed: info.confirmations > 0,
                block_height: Some(info.height),
            },
        }
    }
}

// https://www.quicknode.com/docs/bitcoin/bb_gettx
#[derive(Debug, Serialize, Deserialize)]
pub struct BlockbookTransactionInfo {
    pub txid: String,
    pub version: i32,
    pub vin: Vec<Vin>,
    pub vout: Vec<Vout>,
    #[serde(rename = "blockHash")]
    pub block_hash: Option<String>,
    #[serde(rename = "blockHeight")]
    pub block_height: Option<i64>,
    pub confirmations: Option<i64>,
    #[serde(rename = "blockTime")]
    pub block_time: Option<i64>,
    pub size: i64,
    pub vsize: i64,
    pub value: String,
    #[serde(rename = "valueIn")]
    pub value_in: String,
    pub fees: String,
    pub hex: String,
}

impl From<BlockbookTransactionInfo> for TxStatus {
    fn from(info: BlockbookTransactionInfo) -> Self {
        TxStatus {
            confirmed: info.confirmations.map(|c| c > 0).unwrap_or(false),
            block_height: info.block_height.map(|h| h as u64),
        }
    }
}

// https://www.quicknode.com/docs/bitcoin/getmempoolinfo
#[derive(Debug, Serialize, Deserialize)]
pub struct MempoolInfo {
    pub loaded: bool,
    pub size: u64,
    pub bytes: u64,
    pub usage: u64,
    // The spec is not the camelCase.
    pub total_fee: f64,
    pub maxmempool: u64,
    // Minimum fee rate in BTC/kB for tx to be accepted
    #[serde(rename = "mempoolminfee")]
    pub mempool_min_fee: f64,
    #[serde(rename = "minrelaytxfee")]
    pub min_relay_tx_fee: f64,
    #[serde(rename = "incrementalrelayfee")]
    pub incremental_relay_fee: f64,
    pub unbroadcastcount: u64,
    pub fullrbf: bool,
}

// https://www.quicknode.com/docs/bitcoin/estimatesmartfee
#[derive(Debug, Serialize, Deserialize)]
pub struct EstimateSmartFee {
    pub feerate: f64,
    pub blocks: u64,
    pub errors: Option<Vec<String>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Vin {
    pub txid: String,
    pub vout: Option<u32>,
    pub sequence: u32,
    pub n: u32,
    #[serde(default)]
    pub addresses: Vec<String>,
    #[serde(default)]
    #[serde(rename = "isAddress")]
    pub is_address: bool,
    pub value: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Vout {
    pub value: String,
    pub n: u32,
    pub hex: String,
    pub spent: Option<bool>,
    pub addresses: Vec<String>,
    #[serde(rename = "isAddress")]
    pub is_address: bool,
}

pub struct BitcoinClientBlockbook {
    client: Client,
    rpc_url: String,
}

impl BitcoinClientBlockbook {
    pub async fn new(rpc_url: String) -> Result<Self> {
        let res = Self { client: Client::new(), rpc_url };
        let _ = res.get_block_height_impl().await?;
        Ok(res)
    }

    async fn call_json_rpc<T: DeserializeOwned>(
        &self,
        method: &str,
        params: &[serde_json::Value],
    ) -> Result<T> {
        let json = serde_json::json!({
            "method": method,
            "params": params
        });

        let response: JSONRpcResponse<T> =
            self.client.post(&self.rpc_url).json(&json).send().await?.json().await?;

        if let Some(error) = response.error {
            return Err(anyhow::anyhow!("Failed to call JSON-RPC: {}", error.message));
        }

        Ok(response.result)
    }

    async fn get_utxos_impl(&self, address: &Address) -> Result<Vec<BlockbookUtxoInfo>> {
        let address_str = address.to_string();
        let params = vec![
            serde_json::Value::String(address_str),
            serde_json::json!({ "confirmed": true, "unconfirmed": false }),
        ];

        let utxos = self.call_json_rpc("bb_getUTXOs", &params).await?;

        Ok(utxos)
    }

    async fn get_tx_impl(&self, txid: &Txid) -> Result<BlockbookTransactionInfo> {
        let txid_str = txid.to_string();
        let params = vec![serde_json::Value::String(txid_str)];

        let res = self.call_json_rpc("bb_getTx", &params).await?;

        Ok(res)
    }

    async fn broadcast_transaction_impl(&self, tx: &Transaction) -> Result<Txid> {
        let tx_hex = bitcoin::consensus::encode::serialize_hex(tx);
        let params = vec![serde_json::Value::String(tx_hex)];

        let res: Option<String> = self.call_json_rpc("sendrawtransaction", &params).await?;

        if let Some(txid) = res {
            Ok(Txid::from_str(&txid)
                .map_err(|e| anyhow::anyhow!("Failed to parse transaction ID: {}", e))?)
        } else {
            Err(anyhow::anyhow!("Failed to broadcast transaction"))
        }
    }

    async fn get_minimum_fee_impl(&self) -> Result<EstimateSmartFee> {
        let params = vec![serde_json::Value::Number(serde_json::Number::from(3))];
        let res: EstimateSmartFee = self.call_json_rpc("estimatesmartfee", &params).await?;
        Ok(res)
    }

    async fn get_block_height_impl(&self) -> Result<u64> {
        let res: u64 = self.call_json_rpc("getblockcount", &[]).await?;
        Ok(res)
    }
}

#[async_trait::async_trait]
impl BitcoinClient for BitcoinClientBlockbook {
    async fn get_address_utxos(&self, address: &Address) -> Result<Vec<UtxoInfo>> {
        let utxos = self.get_utxos_impl(address).await?;
        let utxos: Vec<UtxoInfo> = utxos.into_iter().map(|utxo| utxo.into()).collect();
        Ok(utxos)
    }

    async fn get_tx_status(&self, txid: &Txid) -> Result<TxStatus> {
        let tx = self.get_tx_impl(txid).await?;
        Ok(tx.into())
    }

    async fn broadcast_transaction(&self, tx: &Transaction) -> Result<Txid> {
        self.broadcast_transaction_impl(tx).await
    }

    async fn get_minimum_fee(&self) -> Result<u64> {
        let res = self.get_minimum_fee_impl().await?;

        // mempoolminfee is in BTC/kB, we need to convert it to satoshis
        // 1 BTC = 100,000,000 satoshis
        // This is the minimum fee rate for a transaction to be accepted into the mempool
        let minimum_fee = (res.feerate * 100_000.0) as u64;

        Ok(minimum_fee)
    }

    async fn get_block_height(&self) -> Result<u64> {
        self.get_block_height_impl().await
    }
}
