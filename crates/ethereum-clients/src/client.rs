use alloy::network::Ethereum;
use alloy::primitives::{Address, TxHash, TxKind, U256};
use alloy::providers::{Provider, ProviderBuilder};
use alloy::rpc::client::RpcClient;
use alloy::rpc::types::{Block, Filter, Log, TransactionReceipt, TransactionRequest};
use alloy::sol;
use alloy::sol_types::{SolCall, SolInterface};
use alloy::transports::http::reqwest::Url;
use alloy::transports::layers::RetryBackoffLayer;
use anyhow::Result;
use std::fmt;
use std::sync::Arc;

use crate::client::IERC20::IERC20Calls;

pub type EthProviderType = Arc<dyn Provider<Ethereum>>;
pub type EthBlock = Block;

sol! {
    interface IERC20 {
        function balanceOf(address account) external view returns (uint256);
    }
}

/// Ethereum RPC client using Alloy
pub struct EthereumClient {
    provider: EthProviderType,
}

impl EthereumClient {
    pub async fn new(rpc_url: &str) -> Result<Self> {
        let max_retry = 3;
        let backoff = 2000;
        let cups = 100;
        let retry_layer = RetryBackoffLayer::new(max_retry, backoff, cups);
        let url = Url::parse(rpc_url)?;
        let client = RpcClient::builder().layer(retry_layer).http(url);

        // Convert &str to Url before connecting
        let provider = ProviderBuilder::new().on_client(client);

        Ok(Self {
            provider: Arc::new(provider),
        })
    }

    pub async fn fetch_logs(&self, filter: &Filter) -> Result<Vec<Log>> {
        let logs = self.provider.get_logs(filter).await?;
        Ok(logs)
    }

    pub async fn get_last_height(&self) -> Result<u64> {
        let latest_block = self.provider.get_block_number().await?;
        Ok(latest_block)
    }

    pub async fn get_gas_price(&self) -> Result<u128> {
        let gas_price = self.provider.get_gas_price().await?;
        Ok(gas_price)
    }

    pub async fn get_balance(&self, address: Address) -> Result<U256> {
        self.provider.get_balance(address).await.map_err(Into::into)
    }

    pub async fn query_erc20_balance(&self, contract: Address, account: Address) -> Result<U256> {
        let call_data = IERC20Calls::balanceOf(IERC20::balanceOfCall { account: account }).abi_encode();
        let tx = TransactionRequest {
            to: Some(TxKind::Call(contract)),
            input: call_data.into(),
            ..Default::default()
        };

        let raw = self.provider.call(tx).await?;

        let result = <IERC20::balanceOfCall as SolCall>::abi_decode_returns(&raw, false)?;
        let balance = result._0;
        Ok(balance)
    }

    pub async fn get_nonce(&self, address: Address) -> Result<u64> {
        self.provider.get_transaction_count(address).await.map_err(Into::into)
    }

    pub async fn estimate_gas(&self, tx: TransactionRequest) -> Result<u64> {
        self.provider.estimate_gas(tx).await.map_err(Into::into)
    }

    pub async fn get_transaction_receipt(&self, hash: TxHash) -> Result<Option<TransactionReceipt>> {
        self.provider.get_transaction_receipt(hash).await.map_err(Into::into)
    }

    pub async fn broadcast_tx(&self, tx: Vec<u8>) -> Result<String> {
        match self.provider.send_raw_transaction(&tx).await {
            Ok(pending_tx) => {
                let tx_hash = pending_tx.tx_hash();
                Ok(format!("{:#x}", tx_hash))
            }
            Err(e) => Err(anyhow::anyhow!("Failed to broadcast tx: {:?}", e)),
        }
    }
}

impl fmt::Debug for EthereumClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EthereumClient").finish()
    }
}
