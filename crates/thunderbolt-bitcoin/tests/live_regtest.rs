//! Opt-in integration test against an isolated Bitcoin Core regtest node.
//!
//! The test is ignored by default. Its caller must provide:
//!
//! - `THUNDERBOLT_BITCOIN_LIVE_RPC_URL`
//! - `THUNDERBOLT_BITCOIN_LIVE_COOKIE`
//! - `THUNDERBOLT_BITCOIN_LIVE_TXID`
//! - `THUNDERBOLT_BITCOIN_LIVE_VOUT`
//! - `THUNDERBOLT_BITCOIN_LIVE_BITCOIN_CLI`
//! - `THUNDERBOLT_BITCOIN_LIVE_DATADIR`
//! - `THUNDERBOLT_BITCOIN_LIVE_MINING_ADDRESS`
//!
//! The selected funding output must be mined and remain outside the block that
//! the test invalidates. The test mutates only the supplied disposable regtest.

use std::env;
use std::error::Error;
use std::process::Command;
use std::sync::Arc;

use thunderbolt_bitcoin::bitcoin::{Amount, BlockHash, Network, OutPoint, Txid};
use thunderbolt_bitcoin::{
    validate_funding_outpoint, BitcoinCoreClient, BitcoinError, ChainCursor, ChainPoint, CookieCredentialProvider,
    FundingExpectation, FundingObservation, RpcConfig,
};
use url::Url;

const RPC_URL_ENV: &str = "THUNDERBOLT_BITCOIN_LIVE_RPC_URL";
const COOKIE_ENV: &str = "THUNDERBOLT_BITCOIN_LIVE_COOKIE";
const TXID_ENV: &str = "THUNDERBOLT_BITCOIN_LIVE_TXID";
const VOUT_ENV: &str = "THUNDERBOLT_BITCOIN_LIVE_VOUT";
const BITCOIN_CLI_ENV: &str = "THUNDERBOLT_BITCOIN_LIVE_BITCOIN_CLI";
const DATADIR_ENV: &str = "THUNDERBOLT_BITCOIN_LIVE_DATADIR";
const MINING_ADDRESS_ENV: &str = "THUNDERBOLT_BITCOIN_LIVE_MINING_ADDRESS";

fn required_env(name: &'static str) -> Result<String, Box<dyn Error>> {
    env::var(name).map_err(|_| format!("required live-test environment variable {name} is missing").into())
}

fn run_bitcoin_cli(args: &[&str]) -> Result<String, Box<dyn Error>> {
    let executable = required_env(BITCOIN_CLI_ENV)?;
    let datadir = required_env(DATADIR_ENV)?;
    let output = Command::new(executable)
        .arg(format!("-datadir={datadir}"))
        .arg("-regtest")
        .args(args)
        .output()?;
    if !output.status.success() {
        return Err(format!(
            "bitcoin-cli command failed with status {}; stderr: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        )
        .into());
    }
    String::from_utf8(output.stdout).map_err(Into::into)
}

#[tokio::test]
#[ignore = "requires an explicitly configured disposable Bitcoin Core regtest"]
async fn live_regtest_backend_contract_and_reorg() -> Result<(), Box<dyn Error>> {
    let endpoint = Url::parse(&required_env(RPC_URL_ENV)?)?;
    let cookie = required_env(COOKIE_ENV)?;
    let credentials = Arc::new(CookieCredentialProvider::new(cookie));

    let wrong_network = RpcConfig::new(endpoint.clone(), Network::Signet)?;
    assert!(matches!(
        BitcoinCoreClient::connect(wrong_network, credentials.clone()).await,
        Err(BitcoinError::NetworkMismatch { .. })
    ));

    let config = RpcConfig::new(endpoint, Network::Regtest)?.with_max_chain_sync_blocks(1_024)?;
    let client = BitcoinCoreClient::connect(config, credentials).await?;
    client.validate_network().await?;

    let genesis = thunderbolt_bitcoin::bitcoin::constants::genesis_block(Network::Regtest).block_hash();
    assert_eq!(client.get_block_hash(0).await?, genesis);

    let before = client.get_blockchain_info().await?;
    assert!(before.blocks >= 2, "live regtest must contain at least two blocks");
    let capacity = usize::try_from(before.blocks + 1)?.min(1_024);
    let mut cursor = ChainCursor::new(
        ChainPoint {
            height: 0,
            hash: genesis,
        },
        capacity,
    )?;
    let initial_delta = client.sync_chain_cursor(&mut cursor).await?;
    assert_eq!(u64::try_from(initial_delta.connected.len())?, before.blocks);
    assert!(!initial_delta.is_reorg());
    assert_eq!(cursor.tip().map(|point| point.hash), Some(before.best_block_hash));

    let txid: Txid = required_env(TXID_ENV)?.parse()?;
    let vout: u32 = required_env(VOUT_ENV)?.parse()?;
    let outpoint = OutPoint { txid, vout };
    let raw_transaction = client.get_raw_transaction(txid).await?;
    let raw_output = raw_transaction
        .output
        .get(usize::try_from(vout)?)
        .ok_or("live funding vout is outside the raw transaction")?;
    let live_output = client
        .get_tx_out(outpoint)
        .await?
        .ok_or("live funding outpoint is spent or missing")?;
    assert!(
        live_output.coinbase,
        "live funding fixture must be a mined coinbase output"
    );
    assert_eq!(live_output.value, raw_output.value);
    assert_eq!(live_output.script_pubkey, raw_output.script_pubkey);

    let expectation = FundingExpectation::new(outpoint, raw_output.script_pubkey.clone(), raw_output.value, 1)?;
    let observation = FundingObservation::from_get_tx_out(outpoint, Some(live_output));
    validate_funding_outpoint(&expectation, &observation)?;

    let old_tip = cursor.tip().ok_or("live cursor unexpectedly has no tip")?;
    run_bitcoin_cli(&["invalidateblock", &old_tip.hash.to_string()])?;
    let rollback = client.sync_chain_cursor(&mut cursor).await?;
    assert!(rollback.is_reorg());
    assert_eq!(rollback.disconnected, vec![old_tip]);
    assert!(rollback.connected.is_empty());

    let mining_address = required_env(MINING_ADDRESS_ENV)?;
    let generated = run_bitcoin_cli(&["generatetoaddress", "1", &mining_address])?;
    let generated: Vec<BlockHash> = serde_json::from_str(generated.trim())?;
    assert_eq!(generated.len(), 1);
    assert_ne!(generated[0], old_tip.hash);

    let replacement = client.sync_chain_cursor(&mut cursor).await?;
    assert!(!replacement.is_reorg());
    assert_eq!(replacement.connected.len(), 1);
    assert_eq!(replacement.connected[0].hash, generated[0]);
    client.validate_network().await?;

    let final_output = client
        .get_tx_out(outpoint)
        .await?
        .ok_or("funding outpoint disappeared after the tip reorganization")?;
    assert_eq!(final_output.value, Amount::from_sat(expectation.amount().to_sat()));
    Ok(())
}
