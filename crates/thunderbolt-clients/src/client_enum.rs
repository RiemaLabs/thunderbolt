use async_trait::async_trait;
use cosmrs::{proto::cosmos::tx::v1beta1::TxRaw, rpc::endpoint, Any, ErrorReport, Tx};

use crate::{
    client_mock::MockTxBuilder, pubkey::ThunderboltPublicKey, Client, MockClient, ThunderboltAccount, TxBuilder,
};

#[derive(Debug, Clone)]
pub enum TxBuilderEnum {
    Real(TxBuilder),
    Mock(MockTxBuilder),
}

impl TxBuilderEnum {
    pub fn address(&self) -> String {
        match self {
            TxBuilderEnum::Real(builder) => builder.address(),
            TxBuilderEnum::Mock(builder) => builder.address(),
        }
    }

    pub fn signer_pubkey(&self) -> ThunderboltPublicKey {
        match self {
            TxBuilderEnum::Real(builder) => builder.signer_pubkey(),
            TxBuilderEnum::Mock(builder) => builder.signer_pubkey(),
        }
    }

    pub fn build_tx_default(&self, msg: Any, gas_limit: u64, sequence: u64) -> Tx {
        match self {
            TxBuilderEnum::Real(builder) => builder.build_tx_default(msg, gas_limit, sequence),
            TxBuilderEnum::Mock(builder) => builder.build_tx_default(msg, gas_limit, sequence),
        }
    }

    pub fn sign_tx(&self, unsigned_tx: Tx, account_number: u64) -> Result<TxRaw, ErrorReport> {
        match self {
            TxBuilderEnum::Real(builder) => builder.sign_tx(unsigned_tx, account_number),
            TxBuilderEnum::Mock(builder) => builder.sign_tx(unsigned_tx, account_number),
        }
    }

    pub fn client(&self) -> &dyn ThunderboltClient {
        match self {
            TxBuilderEnum::Real(real) => &real.client,
            TxBuilderEnum::Mock(mock) => &mock.client,
        }
    }
}

#[async_trait]
pub trait ThunderboltClient: Send + Sync {
    async fn query_base_account(&self, address: &str) -> Result<ThunderboltAccount, ErrorReport>;
    async fn health(&self) -> Result<(), ErrorReport>;
    async fn query_cw20_balance(&self, contract_address: &str, address: &str) -> Result<u128, ErrorReport>;
    async fn query_wasmd_contract_state(
        &self,
        contract_address: &str,
        query_data: &str,
    ) -> Result<serde_json::Value, ErrorReport>;
    async fn query_latest_block_height(&self) -> Result<u64, ErrorReport>;
    async fn broadcast_tx(&self, tx: Vec<u8>) -> Result<String, ErrorReport>;
    async fn query_tx_by_hash(&self, hash: &str) -> Result<endpoint::tx::Response, ErrorReport>;
}

#[async_trait::async_trait]
impl ThunderboltClient for MockClient {
    async fn query_base_account(&self, address: &str) -> Result<ThunderboltAccount, ErrorReport> {
        self.query_base_account(address).await
    }

    async fn health(&self) -> Result<(), ErrorReport> {
        self.health().await
    }

    async fn query_cw20_balance(&self, contract_address: &str, address: &str) -> Result<u128, ErrorReport> {
        self.query_cw20_balance(contract_address, address).await
    }

    async fn query_wasmd_contract_state(
        &self,
        contract_address: &str,
        query_data: &str,
    ) -> Result<serde_json::Value, ErrorReport> {
        self.query_wasmd_contract_state(contract_address, query_data).await
    }

    async fn query_latest_block_height(&self) -> Result<u64, ErrorReport> {
        self.query_latest_block_height().await
    }

    async fn broadcast_tx(&self, tx: Vec<u8>) -> Result<String, ErrorReport> {
        self.broadcast_tx(tx).await
    }

    async fn query_tx_by_hash(&self, hash: &str) -> Result<endpoint::tx::Response, ErrorReport> {
        self.query_tx_by_hash(hash).await
    }
}

#[async_trait::async_trait]
impl ThunderboltClient for Client {
    async fn query_base_account(&self, address: &str) -> Result<ThunderboltAccount, ErrorReport> {
        self.query_base_account(address).await
    }

    async fn health(&self) -> Result<(), ErrorReport> {
        self.health().await
    }

    async fn query_cw20_balance(&self, contract_address: &str, address: &str) -> Result<u128, ErrorReport> {
        self.query_cw20_balance(contract_address, address).await
    }

    async fn query_wasmd_contract_state(
        &self,
        contract_address: &str,
        query_data: &str,
    ) -> Result<serde_json::Value, ErrorReport> {
        self.query_wasmd_contract_state(contract_address, query_data).await
    }

    async fn query_latest_block_height(&self) -> Result<u64, ErrorReport> {
        self.query_latest_block_height().await
    }

    async fn broadcast_tx(&self, tx: Vec<u8>) -> Result<String, ErrorReport> {
        self.broadcast_tx(tx).await
    }

    async fn query_tx_by_hash(&self, hash: &str) -> Result<endpoint::tx::Response, ErrorReport> {
        self.query_tx_by_hash(hash).await
    }
}
#[derive(Debug, Clone)]
pub enum ClientEnum {
    Real(Client),
    Mock(MockClient),
}
