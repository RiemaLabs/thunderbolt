use base64::engine::general_purpose;
use base64::Engine;
use cosmrs::rpc::Error;
use cosmrs::rpc::{query::Query, Client, HttpClient, Order};
use primitive_types::U256;
use serde::{Deserialize, Serialize};
use tendermint::abci::EventAttribute;
use tendermint::hash::Hash;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ThubTxIdentifier {
    pub tx_hash: Hash,
    pub tx_index: u64,
    pub block_hash: Hash,
    pub block_number: u64,
    pub block_timestamp: u64,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ParsedWithdrawRequestEvent {
    pub sender: String,
    pub btc_address: String,
    pub amount: U256,
    pub tx_idt: ThubTxIdentifier,
}

pub async fn extract_withdraw_events(
    cosm_client: &HttpClient,
    start_height: u64,
    end_height: u64,
    bridge_address: String,
) -> Result<Vec<ParsedWithdrawRequestEvent>, Error> {
    let mut events = Vec::new();
    let mut page = 1;

    loop {
        let query = Query::eq("wasm._contract_address", bridge_address.clone())
            .and_eq("wasm.method", "withdraw")
            .and_gte("tx.height", start_height)
            .and_lte("tx.height", end_height);
        let res = cosm_client.tx_search(query, false, page, 100, Order::Ascending).await?;
        let txs = res.txs;
        let is_last_page = txs.len() < 100;
        for tx in txs {
            let tx_hash = tx.hash;
            let tx_index = tx.index as u64;
            let block_number = tx.height.value();

            let block = cosm_client.block(tx.height).await?;
            let block_hash: Hash = block.block_id.hash;
            let block_timestamp = block.block.header.time.unix_timestamp() as u64;

            for event in &tx.tx_result.events {
                if event.kind != "wasm" {
                    continue;
                }

                let mut sender = None;
                let mut btc_address = None;
                let mut amount = None;
                let mut withdraw_flag = false;
                for attr in &event.attributes {
                    let (key, value) = match attr {
                        EventAttribute::V037(a) => (a.key.clone(), a.value.clone()),
                        EventAttribute::V034(a) => {
                            let key_bytes = general_purpose::STANDARD
                                .decode(&a.key)
                                .map_err(|_| Error::client_internal("base64 decode error in key".to_string()))?;
                            let val_bytes = general_purpose::STANDARD
                                .decode(&a.value)
                                .map_err(|_| Error::client_internal("base64 decode error in value".to_string()))?;
                            let key_str = String::from_utf8(key_bytes)
                                .map_err(|_| Error::client_internal("invalid UTF-8 in key".to_string()))?;
                            let val_str = String::from_utf8(val_bytes)
                                .map_err(|_| Error::client_internal("invalid UTF-8 in value".to_string()))?;
                            (key_str, val_str)
                        }
                    };

                    match key.as_str() {
                        "from" => sender = Some(value),
                        "to" => btc_address = Some(value),
                        "amount" => amount = Some(value),
                        "method" => {
                            if value == "withdraw" {
                                withdraw_flag = true;
                            }
                        }
                        _ => {}
                    }
                }
                if !withdraw_flag {
                    continue;
                }
                if let (Some(sender), Some(btc_address), Some(amount)) = (sender, btc_address, amount) {
                    let amount = U256::from_dec_str(&amount)
                        .map_err(|_| Error::client_internal("invalid U256 amount".to_string()))?;

                    let tx_idt = ThubTxIdentifier {
                        tx_hash,
                        tx_index,
                        block_hash,
                        block_number,
                        block_timestamp,
                    };

                    let parsed_event = ParsedWithdrawRequestEvent {
                        sender,
                        btc_address,
                        amount,
                        tx_idt,
                    };

                    events.push(parsed_event);
                }
            }
        }
        if is_last_page {
            break;
        }
        page += 1;
    }
    Ok(events)
}
