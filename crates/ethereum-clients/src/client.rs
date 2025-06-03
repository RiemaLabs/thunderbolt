use alloy::network::Ethereum;
use alloy::providers::{Provider, ProviderBuilder};
use alloy::rpc::client::RpcClient;
use alloy::rpc::types::Block;
use alloy::transports::http::reqwest::Url;
use alloy::transports::layers::RetryBackoffLayer;
use alloy::transports::{RpcError, TransportErrorKind};
use anyhow::Result;
use getset::Getters;
use std::fmt;
use std::sync::Arc;

pub type EthProviderType = Arc<dyn Provider<Ethereum>>;
pub type EthBlock = Block;

/// Ethereum RPC client using Alloy
#[derive(Getters)]
pub struct EthereumClient {
    #[getset(get = "pub")]
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

    pub async fn get_safe_block_number(&self) -> Result<u64, RpcError<TransportErrorKind>> {
        let confirmations = 12;
        self.provider.get_block_number().await.map(|b| b - confirmations)
    }
}

impl fmt::Debug for EthereumClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EthereumClient").finish()
    }
}
