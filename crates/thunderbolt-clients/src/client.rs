use anyhow::Result;
use bitcoin_utils::account::AccountInfo;
use bitcoin_utils::bitcoin::hex::DisplayHex;
use bitcoin_utils::bitcoin::{Network, PrivateKey};
use cosmrs::proto::cosmos::auth::v1beta1::{BaseAccount, QueryAccountRequest, QueryAccountResponse};
use cosmrs::proto::cosmos::tx::v1beta1::TxRaw;

use cosmrs::proto::prost::Message;
use cosmrs::rpc::client::HttpClient;
use cosmrs::rpc::Client as CosmrsClient;
use cosmrs::tendermint::block::Height;
use cosmrs::tx::mode_info::Single;
use cosmrs::tx::{AuthInfo, Body, Fee, MessageExt, ModeInfo, SignerInfo, SignerPublicKey};
use cosmrs::{tx::SignDoc, Tx};
use cosmrs::{Any, ErrorReport};

use crate::bip322::bip322_sign;
use crate::pubkey::ThunderboltPublicKey;

#[derive(Debug, Clone)]
pub struct ThunderboltAccount {
    pub address: String,
    pub pubkey: ThunderboltPublicKey,
    pub sequence: u64,
    pub account_number: u64,
}

pub struct Client {
    pub client: HttpClient,
    pub chain_id: String,
}

impl Client {
    pub async fn new(url: &str, chain_id: &str) -> Self {
        let res = HttpClient::new(url);
        if res.is_err() {
            panic!("Failed to create client");
        }
        let client = res.unwrap();
        let genesis: Result<cosmrs::tendermint::Genesis<serde_json::Value>, cosmrs::rpc::Error> =
            client.genesis().await;
        if let Err(e) = genesis {
            panic!("Failed to fetch genesis: {}", e);
        }
        let fetched_chain_id = genesis.unwrap().chain_id;
        if chain_id != fetched_chain_id.to_string() {
            panic!("Chain id mismatch: {} != {}", chain_id, fetched_chain_id);
        }
        Self {
            client,
            chain_id: chain_id.to_string(),
        }
    }

    pub async fn query_base_account(&self, address: &str) -> Result<ThunderboltAccount, ErrorReport> {
        let path = "/cosmos.auth.v1beta1.Query/Account";
        let data = {
            let req = QueryAccountRequest {
                address: address.into(),
            };
            req.to_bytes()
        }?;

        let res = self
            .client
            .abci_query(Some(path.to_string()), data, None, false)
            .await?;
        let account: QueryAccountResponse = QueryAccountResponse::decode(&res.value[..])?;
        let account_any = account.account.ok_or_else(|| ErrorReport::msg("Account not found"))?;
        let base_account: BaseAccount = BaseAccount::decode(&account_any.value[..])?;
        let thunderbolt_pubkey = ThunderboltPublicKey::try_from(base_account.pub_key.unwrap())?;
        Ok(ThunderboltAccount {
            address: address.to_string(),
            pubkey: thunderbolt_pubkey,
            sequence: base_account.sequence,
            account_number: base_account.account_number,
        })
    }

    pub async fn health(&self) -> Result<(), ErrorReport> {
        self.client.health().await?;
        Ok(())
    }
}

pub struct TxBuilder {
    pub client: Client,
    pub account: AccountInfo,
    network: Network,
}

impl TxBuilder {
    pub fn new(client: Client, account: AccountInfo, network: Network) -> Self {
        Self {
            client,
            account,
            network,
        }
    }

    pub fn address(&self) -> String {
        self.account.p2tr_address(self.network).to_string()
    }

    pub fn signer_pubkey(&self) -> ThunderboltPublicKey {
        ThunderboltPublicKey::from(self.account.get_tweaked_x_pubkey().0)
    }

    pub fn build_tx_default(&self, msg: Any, gas_limit: u64, sequence: u64) -> Tx {
        let unsigned_tx = Tx {
            body: Body {
                messages: vec![msg],
                memo: String::new(),
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
        };

        unsigned_tx
    }

    pub fn sign_tx(&self, unsigned_tx: Tx, account_number: u64) -> Result<TxRaw, ErrorReport> {
        let body_bytes = unsigned_tx.body.into_bytes()?;
        let auth_info_bytes = unsigned_tx.auth_info.into_bytes()?;
        let sign_doc = SignDoc {
            body_bytes: body_bytes.clone(),
            auth_info_bytes: auth_info_bytes.clone(),
            chain_id: self.client.chain_id.clone(),
            account_number,
        };

        let sign_doc_bytes = sign_doc.into_bytes()?;

        println!("Sign doc bytes: {:?}", sign_doc_bytes.to_lower_hex_string());

        let private_key = PrivateKey::new(self.account.get_keypair().secret_key(), self.network);

        let signature = bip322_sign(&self.account.p2tr_address(self.network), &sign_doc_bytes, private_key);
        let _ = private_key;

        if let Err(e) = signature {
            panic!("Failed to sign tx: {}", e);
        }
        let signatures = vec![signature.unwrap()];

        let signed_tx = TxRaw {
            body_bytes,
            auth_info_bytes,
            signatures,
        };

        Ok(signed_tx)
    }
}
