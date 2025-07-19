use anyhow::Result;
use cosmrs::proto::cosmos::tx::v1beta1::TxRaw;

use cosmrs::tendermint::block::Height;
use cosmrs::tx::mode_info::Single;
use cosmrs::tx::{AuthInfo, Body, Fee, ModeInfo, SignerInfo, SignerPublicKey};
use cosmrs::Tx;
use cosmrs::{Any, ErrorReport};

use crate::pubkey::ThunderboltPublicKey;

#[derive(Debug, Clone)]
pub struct MockTxBuilder;

impl MockTxBuilder {
    pub fn new() -> Self {
        Self
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
