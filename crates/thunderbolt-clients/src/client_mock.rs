use anyhow::Result;
use cosmrs::proto::cosmos::tx::v1beta1::TxRaw;

use cosmrs::rpc::endpoint;
use cosmrs::tendermint::block::Height;
use cosmrs::tx::mode_info::Single;
use cosmrs::tx::{AuthInfo, Body, Fee, ModeInfo, SignerInfo, SignerPublicKey};
use cosmrs::Tx;
use cosmrs::{Any, ErrorReport};

use crate::pubkey::ThunderboltPublicKey;
use crate::ThunderboltAccount;

#[derive(Debug, Clone)]
pub struct MockTxBuilder {
    pub client: MockClient,
}

impl MockTxBuilder {
    pub fn new() -> Self {
        Self {
            client: MockClient::new(),
        }
    }

    pub fn address(&self) -> String {
        "tb1qmockaddress000000000000000000000000000000000000000".to_string()
    }

    pub fn signer_pubkey(&self) -> ThunderboltPublicKey {
        ThunderboltPublicKey {
            type_url: "mock".to_string(),
            value: vec![],
        }
    }

    pub fn build_tx_default(&self, msg: Any, gas_limit: u64, sequence: u64) -> Tx {
        Tx {
            body: Body {
                messages: vec![msg],
                memo: "mock tx".to_string(),
                timeout_height: Height::from(0u32),
                extension_options: vec![],
                non_critical_extension_options: vec![],
            },
            auth_info: AuthInfo {
                fee: Fee {
                    amount: vec![],
                    gas_limit,
                    payer: None,
                    granter: None,
                },
                signer_infos: vec![SignerInfo {
                    public_key: Some(SignerPublicKey::Any(self.signer_pubkey().to_any())),
                    mode_info: ModeInfo::Single(Single {
                        mode: cosmrs::tx::SignMode::Direct,
                    }),
                    sequence,
                }],
            },
            signatures: vec![],
        }
    }

    pub fn sign_tx(&self, unsigned_tx: Tx, _account_number: u64) -> Result<TxRaw, ErrorReport> {
        Ok(TxRaw {
            body_bytes: unsigned_tx.body.into_bytes()?,
            auth_info_bytes: unsigned_tx.auth_info.into_bytes()?,
            signatures: vec![vec![0u8; 64]], // mock signature
        })
    }
}

#[derive(Debug, Clone)]
pub struct MockClient;

impl MockClient {
    pub fn new() -> Self {
        MockClient
    }

    pub async fn query_base_account(&self, address: &str) -> Result<ThunderboltAccount, ErrorReport> {
        Ok(ThunderboltAccount {
            address: address.to_string(),
            sequence: 0,
            account_number: 0,
        })
    }

    pub async fn health(&self) -> Result<(), ErrorReport> {
        Ok(())
    }

    pub async fn query_cw20_balance(&self, _contract_address: &str, _address: &str) -> Result<u128, ErrorReport> {
        Ok(123456789u128)
    }

    pub async fn query_wasmd_contract_state(
        &self,
        _contract_address: &str,
        _query_data: &str,
    ) -> Result<serde_json::Value, ErrorReport> {
        Ok(serde_json::json!({ "balance": "123456789" }))
    }

    pub async fn query_latest_block_height(&self) -> Result<u64, ErrorReport> {
        Ok(123456u64)
    }

    pub async fn broadcast_tx(&self, _tx: Vec<u8>) -> Result<String, ErrorReport> {
        Ok("MOCK_TX_HASH_ABCDEF1234567890".to_string())
    }

    pub async fn query_tx_by_hash(&self, _hash: &str) -> Result<endpoint::tx::Response, ErrorReport> {
        Err(ErrorReport::msg("MockClient: query_tx_by_hash not implemented"))
    }
}
