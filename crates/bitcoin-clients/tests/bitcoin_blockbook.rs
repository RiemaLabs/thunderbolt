use std::str::FromStr;
use std::path::PathBuf;
use std::env;

use bitcoin::hex::FromHex;
use bitcoin::{Address, Network, Txid};
use bitcoin_clients::client::BitcoinClient;
use bitcoin_clients::client_blockbook::BitcoinClientBlockbook;

async fn init_client() -> BitcoinClientBlockbook {
    // Get the directory where the test file is located
    let test_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests");
    let env_path = test_dir.join(".env");
    dotenv::from_path(env_path).unwrap();
    
    let rpc = dotenv::var("BLOCKBOOK_RPC").unwrap();
    let client = BitcoinClientBlockbook::new(rpc.to_string()).await.unwrap();
    client
}

#[tokio::test]
async fn test_get_block_height() {
    let client = init_client().await;
    let height = client.get_block_height().await.unwrap();
    assert!(height > 0);
}

#[tokio::test]
async fn test_get_address_utxos_mainnet() {
    let client = init_client().await;
    let address = Address::from_str("bc1q8yj0herd4r4yxszw3nkfvt53433thk0f5qst4g")
        .unwrap()
        .require_network(Network::Bitcoin)
        .unwrap();
    let utxos = client.get_address_utxos(&address).await.unwrap();
    assert!(utxos.len() > 0);
}

#[tokio::test]
async fn test_get_tx_status_mainnet() {
    let client = init_client().await;
    let txid = Txid::from_str("b21f7a11818dc830f150c75d23a5185c92a6b542c88c838a2772a7f974d9e782").unwrap();
    let status = client.get_tx_status(&txid).await.unwrap();
    assert!(status.confirmed);
}

#[tokio::test]
async fn test_broadcast_transaction_mainnet() {
    let client = init_client().await;
    let tx_str = "0200000000010100476181588c24f7253df8c8660a783b63f7bf7cf07bded9a805174e8a1160de0000000000ffffffff01a0474a0000000000225120b8b3195c7ae97667558e38459bd8de9d1b68470be026aa1f40b921bf706b06d70c000040389e6dac57faed28231e3a5e3124ad50a2c144d856ef5f386f014132d0472ac44e6ae496f1de6e4fa81815b878d0ae62ea1a15ad6cbe54eeb9a76f729f1857a640836d11353f61a16bca3c4b388a135d63b947bab13713bfe6b69757deb54921ead9c4a9ffd75055080d1ecb53f63bd3f2224895581a0d0a5ef37a2da6150b021640b11f9b7db11d1f0cc36d074779e92e8d381fef4377659f15d6bc769d29c00c02bf8b3c3eedc5642216e2c742a1eac55265e3397b38b8d2436ec4a40ef029b1680040bd43743d527e8cc3caf65d648be8dcc723a90d7e1e62c95af3f2aad6926fb99f2ec89bf9f672ef4d646e7b52a21340173f0c3173a6d43ab4c2a31eead1c35da2402107d71b2548b9461d9b24c1ae13c947fe25ff64c1ccd8fd6a45021d39f4a0c1c5f5c0e8f502baa48add197842ba694401e6df1c8963d8e0297b2095f4cd075b4093f78ec776f2c1cc641741cfa9df13877a810e7a7d00ea22326615524a4e1b0006c66e0ac62b09d4fcbea48f1cd4d385ba358ce5ee0fb831db1cf7118d1d35ee401dfa69b7a3ed19e4340c644d63995d91d7805bd8c36452e2e5c86ec594c7a0376dc6ca8091f45712ab4c8cc02dce3da62469e3eb2dddeb062cbf3832ac80c445fd5601209e90f6ac2943ae72c9035b092541b8842a4a22e3fe71cc7697c7542ab074d3cdad2023b29f89b45f4af41588dcaf0ca572ada32872a88224f311373917f1b37d08d1ac204b15848e495a3a62283daaadb3f458a00859fe48e321f0121ebabbdd6698f9faba208242640732773249312c47ca7bdb50ca79f15f2ecc32b9c83ceebba44fb74df7ba20cbdd028cfe32c1c1f2d84bfec71e19f92df509bba7b8ad31ca6c1a134fe09204ba20d3c79b99ac4d265c2f97ac11e3232c07a598b020cf56c6f055472c893c0967aeba20d45c70d28f169e1f0c7f4a78e2bc73497afe585b70aa897955989068f3350aaaba20de13fc96ea6899acbdc5db3afaa683f62fe35b60ff6eb723dad28a11d2b12f8cba20e36200aaa8dce9453567bba108bdc51f7f1174b97a65e4dc4402fc5de779d41cba20f178fcce82f95c524b53b077e6180bd2d779a9057fdff4255a0af95af918cee0ba569c61c150929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac02fd16146837307887a3961ae992fbebe980659eae2de33f21d1e6fe46f0ba5fceec9c0cf9c9704457e7077a65f83ba2bfac6f615c06f2dfc94936869915916b500000000";
    let tx = bitcoin::consensus::encode::deserialize(&Vec::from_hex(tx_str).unwrap()).unwrap();
    let txid = client.broadcast_transaction(&tx).await;
    assert!(txid.is_err());
    assert!(txid
        .err()
        .unwrap()
        .to_string()
        .contains("Transaction already in block chain"));
}

#[tokio::test]
async fn test_get_minimum_fee() {
    let client = init_client().await;
    let fee = client.get_minimum_fee().await.unwrap();
    println!("Minimum fee: {:?}", fee);
    assert!(fee > 0);
}

#[tokio::test]
async fn test_get_block_hash() {
    let client = init_client().await;
    let block_hash = client.get_block_hash(1).await.unwrap();
    println!("Block hash: {:?}", block_hash);
    assert!(block_hash.len() > 0);
}

#[tokio::test]
async fn test_get_block_by_hash() {
    let client = init_client().await;
    let block_hash = client.get_block_hash(1).await.unwrap();
    let block = client.get_block(&block_hash).await.unwrap();
    println!("Block: {:?}", block);
    assert!(block.bip34_block_height().is_ok());
}
