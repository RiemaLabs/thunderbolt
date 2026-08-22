//! Example integration against an in-process `RpcTransport` test double.

use std::sync::{Arc, Mutex};

use bitcoin::absolute;
use bitcoin::consensus::encode::serialize_hex;
use bitcoin::hashes::Hash;
use bitcoin::transaction::Version;
use bitcoin::{Amount, BlockHash, Network, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness};
use serde_json::{json, Value};
use thunderbolt_bitcoin::{
    BitcoinCoreClient, BitcoinError, ChainCursor, ChainPoint, Result, RpcConfig, RpcHttpRequest, RpcHttpResponse,
    RpcTransport, TransportError, TransportFuture,
};
use url::Url;

#[derive(Clone)]
struct MockCore {
    state: Arc<Mutex<MockState>>,
    transaction: Transaction,
}

#[derive(Default)]
struct MockState {
    methods: Vec<String>,
    fail_broadcast: bool,
}

impl MockCore {
    fn new(transaction: Transaction, fail_broadcast: bool) -> Self {
        Self {
            state: Arc::new(Mutex::new(MockState {
                methods: Vec::new(),
                fail_broadcast,
            })),
            transaction,
        }
    }

    fn method_count(&self, method: &str) -> std::result::Result<usize, TransportError> {
        let state = self
            .state
            .lock()
            .map_err(|_| TransportError::Permanent("mock state lock failed".to_owned()))?;
        Ok(state.methods.iter().filter(|called| called.as_str() == method).count())
    }

    fn respond(&self, request: RpcHttpRequest) -> std::result::Result<RpcHttpResponse, TransportError> {
        let request: Value = serde_json::from_slice(request.body())
            .map_err(|_| TransportError::Permanent("mock received invalid JSON".to_owned()))?;
        let id = request
            .get("id")
            .and_then(Value::as_u64)
            .ok_or_else(|| TransportError::Permanent("mock request id missing".to_owned()))?;
        let method = request
            .get("method")
            .and_then(Value::as_str)
            .ok_or_else(|| TransportError::Permanent("mock method missing".to_owned()))?;
        let params = request
            .get("params")
            .and_then(Value::as_array)
            .ok_or_else(|| TransportError::Permanent("mock params missing".to_owned()))?;

        let fail_broadcast = {
            let mut state = self
                .state
                .lock()
                .map_err(|_| TransportError::Permanent("mock state lock failed".to_owned()))?;
            state.methods.push(method.to_owned());
            state.fail_broadcast && method == "sendrawtransaction"
        };
        if fail_broadcast {
            return Err(TransportError::Transient("simulated lost connection".to_owned()));
        }

        let genesis = bitcoin::constants::genesis_block(Network::Regtest);
        let block_one = BlockHash::from_byte_array([1; 32]);
        let block_two = BlockHash::from_byte_array([2; 32]);
        let result = match method {
            "getblockchaininfo" => json!({
                "chain": "regtest",
                "blocks": 2,
                "headers": 2,
                "bestblockhash": block_two.to_string(),
                "initialblockdownload": false,
                "pruned": false
            }),
            "getblockhash" => match params.first().and_then(Value::as_u64) {
                Some(0) => Value::String(genesis.block_hash().to_string()),
                Some(1) => Value::String(block_one.to_string()),
                Some(2) => Value::String(block_two.to_string()),
                _ => return remote_error(id, -8, "height out of range"),
            },
            "getblockheader" => Value::String(serialize_hex(&genesis.header)),
            "gettxout" => json!({
                "bestblock": block_two.to_string(),
                "confirmations": 6,
                "value": 0.0005,
                "scriptPubKey": {"hex": "51"},
                "coinbase": false
            }),
            "getrawtransaction" => Value::String(serialize_hex(&self.transaction)),
            "estimatesmartfee" => json!({"feerate": 0.00001, "blocks": 6}),
            "sendrawtransaction" => Value::String(self.transaction.compute_txid().to_string()),
            _ => return remote_error(id, -32601, "method not found"),
        };
        success(id, result)
    }
}

impl RpcTransport for MockCore {
    fn send(&self, request: RpcHttpRequest) -> TransportFuture<'_> {
        Box::pin(std::future::ready(self.respond(request)))
    }
}

fn success(id: u64, result: Value) -> std::result::Result<RpcHttpResponse, TransportError> {
    let body = serde_json::to_vec(&json!({"result": result, "error": null, "id": id}))
        .map_err(|_| TransportError::Permanent("mock serialization failed".to_owned()))?;
    Ok(RpcHttpResponse::new(200, body))
}

fn remote_error(id: u64, code: i64, message: &str) -> std::result::Result<RpcHttpResponse, TransportError> {
    let body = serde_json::to_vec(&json!({
        "result": null,
        "error": {"code": code, "message": message},
        "id": id
    }))
    .map_err(|_| TransportError::Permanent("mock serialization failed".to_owned()))?;
    Ok(RpcHttpResponse::new(500, body))
}

fn test_transaction() -> Transaction {
    Transaction {
        version: Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: Txid::from_byte_array([9; 32]),
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(50_000),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
    }
}

fn config() -> Result<RpcConfig> {
    let endpoint =
        Url::parse("http://127.0.0.1:18443/").map_err(|_| BitcoinError::InvalidEndpoint("mock URL is invalid"))?;
    RpcConfig::new(endpoint, Network::Regtest)
}

#[tokio::test]
async fn mock_core_exercises_the_public_backend_contract() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let transaction = test_transaction();
    let mock = MockCore::new(transaction.clone(), false);
    let client = BitcoinCoreClient::with_transport(config()?, mock).await?;

    let info = client.get_blockchain_info().await?;
    assert_eq!(info.network, Network::Regtest);
    assert_eq!(info.blocks, 2);

    let genesis = bitcoin::constants::genesis_block(Network::Regtest);
    assert_eq!(client.get_block_header(genesis.block_hash()).await?, genesis.header);

    let outpoint = OutPoint {
        txid: transaction.compute_txid(),
        vout: 0,
    };
    let output = client
        .get_tx_out(outpoint)
        .await?
        .ok_or("mock output unexpectedly missing")?;
    assert_eq!(output.value, Amount::from_sat(50_000));
    assert_eq!(output.confirmations, 6);
    assert_eq!(
        client.get_raw_transaction(transaction.compute_txid()).await?,
        transaction
    );
    assert_eq!(client.estimate_smart_fee(6).await?.sat_per_kvb, 1_000);
    assert_eq!(
        client.send_raw_transaction(&transaction, 100_000).await?,
        transaction.compute_txid()
    );

    let mut cursor = ChainCursor::new(
        ChainPoint {
            height: 0,
            hash: genesis.block_hash(),
        },
        16,
    )?;
    let delta = client.sync_chain_cursor(&mut cursor).await?;
    assert_eq!(delta.connected.len(), 2);
    assert!(!delta.is_reorg());
    assert_eq!(cursor.points().last().map(|point| point.height), Some(2));
    Ok(())
}

#[tokio::test]
async fn broadcast_transport_failure_is_never_retried() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let transaction = test_transaction();
    let mock = MockCore::new(transaction.clone(), true);
    let inspect = mock.clone();
    let client = BitcoinCoreClient::with_transport(config()?, mock).await?;

    let result = client.send_raw_transaction(&transaction, 100_000).await;
    assert!(matches!(
        result,
        Err(BitcoinError::Transport(TransportError::Transient(_)))
    ));
    assert_eq!(inspect.method_count("sendrawtransaction")?, 1);
    Ok(())
}
