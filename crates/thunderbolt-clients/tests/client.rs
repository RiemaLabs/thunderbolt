use bitcoin_utils::account::AccountInfo;
use bitcoin_utils::bitcoin::hex::DisplayHex;
use bitcoin_utils::bitcoin::Network;
use cosmrs::proto::cosmos::bank::v1beta1::MsgSend;
use cosmrs::proto::cosmos::base::v1beta1::Coin;
use cosmrs::rpc::Client;
use cosmrs::tx::MessageExt;
use cosmrs::Any;
use thunderbolt_clients::{ThunderboltClient, TxBuilder};

async fn setup_client() -> ThunderboltClient {
    ThunderboltClient::new(
        "http://dev-thunderbolt-gateway.nubit.network:26657",
        "thunderbolt-devnet",
    )
    .await
}

#[tokio::test]
async fn test_query_base_account() {
    let client = setup_client().await;

    let contract_deployer_seed = "25f5ff288b007263c1ff7e05945a9000c6fb66d1a5e4eaa097e077d5238f7755";

    let account = AccountInfo::new(Network::Bitcoin, contract_deployer_seed);

    let deployer_address = account.p2tr_address(Network::Bitcoin).to_string();

    let thunderbolt_account = client.query_base_account(&deployer_address).await.unwrap();

    println!("Base account: {:?}", thunderbolt_account);
    println!(
        "Base account pubkey: {}",
        thunderbolt_account
            .pubkey
            .to_x_only_pubkey()
            .serialize()
            .to_lower_hex_string()
    );
}

#[tokio::test]
async fn test_client() {
    let client = ThunderboltClient::new(
        "http://dev-thunderbolt-gateway.nubit.network:26657",
        "thunderbolt-devnet",
    )
    .await;

    let contract_deployer_seed = "25f5ff288b007263c1ff7e05945a9000c6fb66d1a5e4eaa097e077d5238f7755";

    let tx_builder = TxBuilder::new(client, contract_deployer_seed, Network::Bitcoin);

    let deployer_address = tx_builder.account.p2tr_address(Network::Bitcoin).to_string();

    println!("Deployer address: {}", deployer_address);

    let base_account = tx_builder.client.query_base_account(&deployer_address).await.unwrap();

    let msg = MsgSend {
        from_address: deployer_address.clone(),
        to_address: deployer_address,
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
