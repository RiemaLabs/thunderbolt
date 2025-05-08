use std::str::FromStr;

use bitcoin::Address;
use bitcoin_clients::faucet::{init_nubit_client, send_funding};

#[tokio::test]
pub async fn test_faucet_deployer() {
    let client = init_nubit_client().await;
    let address = Address::from_str("tb1pkn9e9jd6yqtu3fhtmzuep798cf98qgdz9nfm7ysfplk4xzfwex3s340pwr")
        .unwrap()
        .assume_checked();
    let amount = bitcoin::Amount::from_sat(1000000);
    let utxo = send_funding(&client, &address, amount).await;
    println!("utxo: {:?}", utxo);
}
