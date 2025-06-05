use bitcoin_utils::account::AccountInfo;
use bitcoin_utils::bitcoin::hex::DisplayHex;
use bitcoin_utils::bitcoin::Network;
use cosmrs::proto::cosmos::base::v1beta1::Coin;
use cosmrs::proto::{cosmos::bank::v1beta1::MsgSend, cosmwasm::wasm::v1::QuerySmartContractStateRequest};
use cosmrs::rpc::Client as CosmrsClient;
use cosmrs::tx::MessageExt;
use cosmrs::Any;
use thunderbolt_clients::{Client, TxBuilder};

async fn setup_client() -> Client {
    Client::new("http://51.161.87.8:36657/", "thunderbolt-devnet").await
}

#[tokio::test]
async fn test_query_base_account() {
    let client = setup_client().await;

    let contract_deployer_seed = "58a64f071c005ae3a6a1ce386e50e43f5b4255d4e32a3a603019e664e62839d7";

    let account = AccountInfo::new(Network::Bitcoin, contract_deployer_seed);

    let deployer_address = account.p2tr_address(Network::Bitcoin).to_string();

    let thunderbolt_account = client.query_base_account(&deployer_address).await.unwrap();

    println!("Base account: {:?}", thunderbolt_account);
}

#[tokio::test]
async fn test_query_cw20_balance() {
    let client = setup_client().await;

    let contract_deployer_seed = "25f5ff288b007263c1ff7e05945a9000c6fb66d1a5e4eaa097e077d5238f7755";

    let account = AccountInfo::new(Network::Bitcoin, contract_deployer_seed);

    let deployer_address = account.p2tr_address(Network::Bitcoin).to_string();

    let bridge_address = "bc1p3k7rccf7l7gkwmf0kr3yf9727l2duwnfqhh7fxpu43plk22hsxysy2x0w4".to_string();

    let balance = client
        .query_cw20_balance(&bridge_address, &deployer_address)
        .await
        .unwrap();

    println!("Balance: {:?}", balance);
}

#[tokio::test]
async fn query_bridge_operators() {
    let client = setup_client().await;

    let contract_address = "bc1pzkzqv00zfpscjqfrujh2zlk6q5sde77s288376pn2pz3g4pm2mas6dt290";
    let query_data = r#"{"get_operators":{}}"#;
    let response_json = client
        .query_wasmd_contract_state(contract_address, query_data)
        .await
        .unwrap();

    let operators_json = response_json["operators"]
        .as_array()
        .expect("operators not found in response");

    let operators: Vec<String> = operators_json
        .iter()
        .map(|v| v.as_str().expect("operator is not a string").to_string())
        .collect();

    println!("Operators: {:?}", operators);
}

#[tokio::test]
async fn test_client() {
    let client = Client::new(
        "http://dev-thunderbolt-gateway.nubit.network:26657",
        "thunderbolt-devnet",
    )
    .await;

    let contract_deployer_seed = "25f5ff288b007263c1ff7e05945a9000c6fb66d1a5e4eaa097e077d5238f7755";

    let account = AccountInfo::new(Network::Bitcoin, contract_deployer_seed);

    let tx_builder = TxBuilder::new(client, account, Network::Bitcoin);

    let deployer_address = tx_builder.account.p2tr_address(Network::Bitcoin).to_string();

    println!("Deployer address: {}", deployer_address);

    let base_account = tx_builder.client.query_base_account(&deployer_address).await.unwrap();

    let msg = MsgSend {
        from_address: deployer_address.clone(),
        to_address: deployer_address.clone(),
        amount: vec![Coin {
            denom: "stake".to_string(),
            // 0.01 stake (assuming 6 decimals)
            amount: "1000000".to_string(),
        }],
    };

    let msg = Any::from_msg(&msg).unwrap();

    let unsigned_tx = tx_builder.build_tx_default(msg, 1000000, base_account.sequence);

    let signed_tx_bytes = tx_builder.sign_tx(unsigned_tx, base_account.account_number);

    assert!(signed_tx_bytes.is_ok());

    let signed_tx_bytes = signed_tx_bytes.unwrap().to_bytes().unwrap();

    println!("Signed tx bytes: {:?}", signed_tx_bytes.to_lower_hex_string());

    let res = tx_builder.client.client.broadcast_tx_sync(signed_tx_bytes).await;

    assert!(res.is_ok());

    println!("Res: {:?}", res);
}
