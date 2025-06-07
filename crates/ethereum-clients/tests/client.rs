use alloy::primitives::Address;
use anyhow::Result;
use ethereum_clients::client::EthereumClient;
use std::str::FromStr;

async fn setup_client() -> Result<EthereumClient> {
    let rpc_url = "https://bsc-testnet-rpc.publicnode.com/";
    EthereumClient::new(rpc_url).await
}

#[tokio::test]
async fn test_query_erc20_balance() -> Result<()> {
    let client = setup_client().await?;

    let contract = Address::from_str("0xf517F45e755d097376cB6F394C9fC9d955000BE0")?;
    let holder = Address::from_str("0x50fC899fc5E27D003612f8b4Ba951a48A878A78d")?;

    let balance = client.query_erc20_balance(contract, holder).await?;

    println!("Balance: {}", balance);

    Ok(())
}
