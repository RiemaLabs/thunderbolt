use core::time;
use std::str::FromStr;
use std::thread::sleep;

use bitcoin::{Address, Amount, Txid};
use serde_json::{json, Value};

use crate::client::{BitcoinClient, UtxoInfo};
use crate::client_electrs::BitcoinClientElectrs;

const NUBIT_FAUCET_USERNAME: &str = "admin";
const NUBIT_FAUCET_PASSWORD: &str = "admin";
const NUBIT_MEMPOOL_URL: &str = "https://mempool.nubit.org";
const NUBIT_FAUCET_URL: &str = "https://btcfaucet-api.nubit.org/send_to_address";

pub async fn init_nubit_client() -> BitcoinClientElectrs {
    let client = BitcoinClientElectrs::new(NUBIT_MEMPOOL_URL.to_string()).await.unwrap();
    client
}

pub async fn send_funding(client: &dyn BitcoinClient, receiver_address: &Address, amount: Amount) -> Option<UtxoInfo> {
    let http_client = reqwest::Client::new();
    let url = NUBIT_FAUCET_URL;
    let request_body = json!({
        "address": receiver_address.to_string(),
        "amount": amount.to_btc(),
    });
    let response = http_client
        .post(url)
        .basic_auth(NUBIT_FAUCET_USERNAME, Some(NUBIT_FAUCET_PASSWORD))
        .header("Content-Type", "application/json")
        .json(&request_body)
        .send()
        .await;
    match response {
        Ok(response) => {
            if response.status().is_success() {
                let resp: Value = response.json().await.expect("Could not parse response");
                let str = resp.get("result").unwrap().to_string().replace("\"", "");
                let txid = Txid::from_str(&str).unwrap();
                let mut tx_confirmed = false;
                while !tx_confirmed {
                    sleep(time::Duration::from_secs(1));
                    let tx = client.get_tx_status(&txid).await.unwrap();
                    tx_confirmed = tx.confirmed;
                }
                let utxos = client.get_address_utxos(receiver_address).await.unwrap();
                for u in utxos.iter() {
                    if u.value == amount.to_sat() && u.txid == txid.to_string() {
                        return Some(u.clone());
                    }
                }
                return None;
            } else {
                println!("Failed to send funding: {:?}", response.text().await);
                return None;
            }
        }
        Err(e) => {
            println!("Failed to send funding: {:?}", e);
            return None;
        }
    }
}
