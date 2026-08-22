use std::future::Future;
use std::pin::Pin;
use std::str::FromStr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use bitcoin::block::Header;
use bitcoin::consensus::encode::{deserialize_hex, serialize_hex};
use bitcoin::hex::FromHex;
use bitcoin::{Amount, BlockHash, Denomination, Network, OutPoint, ScriptBuf, Transaction, Txid};
use reqwest::header::CONTENT_TYPE;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{json, Number, Value};
use url::Url;

use crate::auth::CredentialProvider;
use crate::{
    BitcoinError, BlockchainInfo, ChainCursor, ChainDelta, ChainPoint, FeeEstimate, Result, RpcConfig, TransportError,
    TxOutInfo, MAX_FEE_RATE_SAT_PER_KVB,
};

const MAX_JSON_RPC_ID: u64 = 9_223_372_036_854_775_807;

/// A boxed transport operation, allowing tests to inject deterministic mocks.
pub type TransportFuture<'a> =
    Pin<Box<dyn Future<Output = std::result::Result<RpcHttpResponse, TransportError>> + Send + 'a>>;

/// A boxed backend operation for trait-object consumers.
pub type BackendFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T>> + Send + 'a>>;

/// A bounded serialized JSON-RPC request.
#[derive(Clone)]
pub struct RpcHttpRequest {
    body: Vec<u8>,
}

impl RpcHttpRequest {
    /// Raw JSON request body for a custom transport or test double.
    #[must_use]
    pub fn body(&self) -> &[u8] {
        &self.body
    }

    fn into_body(self) -> Vec<u8> {
        self.body
    }
}

/// An HTTP status and bounded response body returned by a transport.
#[derive(Clone)]
pub struct RpcHttpResponse {
    status: u16,
    body: Vec<u8>,
}

impl RpcHttpResponse {
    /// Creates a response for a custom transport or test double.
    #[must_use]
    pub fn new(status: u16, body: Vec<u8>) -> Self {
        Self { status, body }
    }

    /// HTTP status code.
    #[must_use]
    pub const fn status(&self) -> u16 {
        self.status
    }

    /// Raw response body.
    #[must_use]
    pub fn body(&self) -> &[u8] {
        &self.body
    }
}

/// Minimal transport trait used by the backend and deterministic tests.
pub trait RpcTransport: Send + Sync {
    /// Sends one request. Retry policy is owned by [`BitcoinCoreClient`].
    fn send(&self, request: RpcHttpRequest) -> TransportFuture<'_>;
}

/// Bounded, redirect-free HTTPS/loopback-HTTP transport.
pub struct HttpTransport {
    client: reqwest::Client,
    endpoint: Url,
    credentials: Arc<dyn CredentialProvider>,
    max_response_bytes: usize,
}

impl HttpTransport {
    /// Builds the transport from an already validated [`RpcConfig`].
    pub fn new(config: &RpcConfig, credentials: Arc<dyn CredentialProvider>) -> Result<Self> {
        let client = reqwest::Client::builder()
            .connect_timeout(config.connect_timeout())
            .timeout(config.request_timeout())
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|error| TransportError::Permanent(error.to_string()))?;
        Ok(Self {
            client,
            endpoint: config.endpoint().clone(),
            credentials,
            max_response_bytes: config.max_response_bytes(),
        })
    }
}

impl RpcTransport for HttpTransport {
    fn send(&self, request: RpcHttpRequest) -> TransportFuture<'_> {
        Box::pin(async move {
            let credentials = self.credentials.credentials().await?;
            let response = self
                .client
                .post(self.endpoint.clone())
                .header(CONTENT_TYPE, "application/json")
                .basic_auth(credentials.username(), Some(credentials.password()))
                .body(request.into_body())
                .send()
                .await
                .map_err(classify_reqwest_error)?;

            if let Some(declared) = response.content_length() {
                let limit = u64::try_from(self.max_response_bytes)
                    .map_err(|_| TransportError::Permanent("response limit conversion failed".to_owned()))?;
                if declared > limit {
                    return Err(TransportError::ResponseTooLarge {
                        limit: self.max_response_bytes,
                    });
                }
            }

            let status = response.status().as_u16();
            let mut response = response;
            let mut body = Vec::new();
            while let Some(chunk) = response.chunk().await.map_err(classify_reqwest_error)? {
                let next_len = body
                    .len()
                    .checked_add(chunk.len())
                    .ok_or(TransportError::ResponseTooLarge {
                        limit: self.max_response_bytes,
                    })?;
                if next_len > self.max_response_bytes {
                    return Err(TransportError::ResponseTooLarge {
                        limit: self.max_response_bytes,
                    });
                }
                body.extend_from_slice(&chunk);
            }
            Ok(RpcHttpResponse::new(status, body))
        })
    }
}

fn classify_reqwest_error(error: reqwest::Error) -> TransportError {
    if error.is_timeout() || error.is_connect() || error.is_request() || error.is_body() {
        TransportError::Transient(error.to_string())
    } else {
        TransportError::Permanent(error.to_string())
    }
}

/// Read-only and broadcast operations required by Thunderbolt nodes.
///
/// Implementations do not expose wallet, private-key, or signing operations.
pub trait BitcoinRpcBackend: Send + Sync {
    /// Validated network.
    fn network(&self) -> Network;
    /// Rechecks chain name and genesis.
    fn validate_network(&self) -> BackendFuture<'_, ()>;
    /// Calls `getblockchaininfo`.
    fn get_blockchain_info(&self) -> BackendFuture<'_, BlockchainInfo>;
    /// Calls `getblockhash`.
    fn get_block_hash(&self, height: u64) -> BackendFuture<'_, BlockHash>;
    /// Calls non-verbose `getblockheader` and verifies the returned hash.
    fn get_block_header(&self, hash: BlockHash) -> BackendFuture<'_, Header>;
    /// Calls `gettxout` with mempool inclusion.
    fn get_tx_out(&self, outpoint: OutPoint) -> BackendFuture<'_, Option<TxOutInfo>>;
    /// Calls non-verbose `getrawtransaction` and verifies the returned txid.
    fn get_raw_transaction(&self, txid: Txid) -> BackendFuture<'_, Transaction>;
    /// Calls conservative `estimatesmartfee`.
    fn estimate_smart_fee(&self, confirmation_target: u16) -> BackendFuture<'_, FeeEstimate>;
    /// Calls `sendrawtransaction` exactly once.
    fn send_raw_transaction<'a>(
        &'a self,
        transaction: &'a Transaction,
        max_fee_rate_sat_per_kvb: u64,
    ) -> BackendFuture<'a, Txid>;
    /// Reconciles a bounded chain cursor with Core's best chain.
    fn sync_chain_cursor<'a>(&'a self, cursor: &'a mut ChainCursor) -> BackendFuture<'a, ChainDelta>;
}

/// Validated Bitcoin Core client over an injectable transport.
pub struct BitcoinCoreClient<T> {
    config: RpcConfig,
    transport: T,
    next_id: AtomicU64,
}

impl BitcoinCoreClient<HttpTransport> {
    /// Connects over HTTP(S) and refuses to return until network and genesis match.
    pub async fn connect(config: RpcConfig, credentials: Arc<dyn CredentialProvider>) -> Result<Self> {
        let transport = HttpTransport::new(&config, credentials)?;
        Self::with_transport(config, transport).await
    }
}

impl<T: RpcTransport> BitcoinCoreClient<T> {
    /// Creates a client over a custom transport and validates network and genesis.
    pub async fn with_transport(config: RpcConfig, transport: T) -> Result<Self> {
        let client = Self {
            config,
            transport,
            next_id: AtomicU64::new(1),
        };
        client.validate_network().await?;
        Ok(client)
    }

    /// Locally selected, remotely validated network.
    #[must_use]
    pub const fn network(&self) -> Network {
        self.config.network()
    }

    /// Revalidates the chain string and genesis hash.
    pub async fn validate_network(&self) -> Result<()> {
        let _ = self.get_blockchain_info().await?;
        let actual = self.get_block_hash(0).await?;
        let expected = bitcoin::constants::genesis_block(self.config.network()).block_hash();
        if actual != expected {
            return Err(BitcoinError::GenesisMismatch { expected, actual });
        }
        Ok(())
    }

    /// Calls and validates `getblockchaininfo`.
    pub async fn get_blockchain_info(&self) -> Result<BlockchainInfo> {
        let raw: RawBlockchainInfo = self.rpc_call("getblockchaininfo", json!([]), true).await?;
        let expected_chain = self.config.network().to_core_arg();
        if raw.chain != expected_chain {
            return Err(BitcoinError::NetworkMismatch {
                expected: expected_chain,
                actual: raw.chain,
            });
        }
        if raw.headers < raw.blocks {
            return Err(BitcoinError::InvalidResult(
                "header height is below validated block height",
            ));
        }
        let best_block_hash = raw
            .best_block_hash
            .parse()
            .map_err(|_| BitcoinError::InvalidResult("bestblockhash is not a block hash"))?;
        Ok(BlockchainInfo {
            network: self.config.network(),
            blocks: raw.blocks,
            headers: raw.headers,
            best_block_hash,
            initial_block_download: raw.initial_block_download,
            pruned: raw.pruned,
        })
    }

    /// Calls `getblockhash`.
    pub async fn get_block_hash(&self, height: u64) -> Result<BlockHash> {
        let result: String = self.rpc_call("getblockhash", json!([height]), true).await?;
        result
            .parse()
            .map_err(|_| BitcoinError::InvalidResult("getblockhash result is not a block hash"))
    }

    /// Calls non-verbose `getblockheader` and checks the hash.
    pub async fn get_block_header(&self, hash: BlockHash) -> Result<Header> {
        let encoded: String = self
            .rpc_call("getblockheader", json!([hash.to_string(), false]), true)
            .await?;
        let header: Header =
            deserialize_hex(&encoded).map_err(|_| BitcoinError::InvalidResult("block header is not consensus hex"))?;
        if header.block_hash() != hash {
            return Err(BitcoinError::BlockHashMismatch);
        }
        Ok(header)
    }

    /// Calls `gettxout`, including mempool spends and outputs.
    pub async fn get_tx_out(&self, outpoint: OutPoint) -> Result<Option<TxOutInfo>> {
        let raw: Option<RawTxOut> = self
            .rpc_call(
                "gettxout",
                json!([outpoint.txid.to_string(), outpoint.vout, true]),
                true,
            )
            .await?;
        raw.map(parse_tx_out).transpose()
    }

    /// Calls non-verbose `getrawtransaction` and checks the txid.
    pub async fn get_raw_transaction(&self, txid: Txid) -> Result<Transaction> {
        let encoded: String = self
            .rpc_call("getrawtransaction", json!([txid.to_string(), false]), true)
            .await?;
        let transaction: Transaction = deserialize_hex(&encoded)
            .map_err(|_| BitcoinError::InvalidResult("raw transaction is not consensus hex"))?;
        let actual = transaction.compute_txid();
        if actual != txid {
            return Err(BitcoinError::TransactionIdMismatch { expected: txid, actual });
        }
        Ok(transaction)
    }

    /// Calls conservative `estimatesmartfee` and preserves the exact sat/kvB value.
    pub async fn estimate_smart_fee(&self, confirmation_target: u16) -> Result<FeeEstimate> {
        if !(1..=1_008).contains(&confirmation_target) {
            return Err(BitcoinError::InvalidConfig(
                "confirmation target must be between 1 and 1008",
            ));
        }
        let raw: RawFeeEstimate = self
            .rpc_call("estimatesmartfee", json!([confirmation_target, "CONSERVATIVE"]), true)
            .await?;
        if raw.errors.as_ref().is_some_and(|errors| !errors.is_empty()) {
            return Err(BitcoinError::FeeEstimateUnavailable);
        }
        let value = raw.fee_rate.ok_or(BitcoinError::FeeEstimateUnavailable)?;
        let amount = parse_btc_amount(&value)?;
        if amount.to_sat() == 0 {
            return Err(BitcoinError::FeeEstimateUnavailable);
        }
        let blocks = u16::try_from(raw.blocks).map_err(|_| BitcoinError::InvalidResult("fee target is too large"))?;
        Ok(FeeEstimate {
            sat_per_kvb: amount.to_sat(),
            blocks,
        })
    }

    /// Broadcasts a transaction once, with an explicit bounded max fee rate.
    pub async fn send_raw_transaction(&self, transaction: &Transaction, max_fee_rate_sat_per_kvb: u64) -> Result<Txid> {
        if max_fee_rate_sat_per_kvb == 0 || max_fee_rate_sat_per_kvb > MAX_FEE_RATE_SAT_PER_KVB {
            return Err(BitcoinError::InvalidFeeRate);
        }
        let max_fee_rate = Amount::from_sat(max_fee_rate_sat_per_kvb).to_string_in(Denomination::Bitcoin);
        let max_fee_rate = Number::from_str(&max_fee_rate).map_err(|_| BitcoinError::InvalidFeeRate)?;
        let expected = transaction.compute_txid();
        let returned: String = self
            .rpc_call(
                "sendrawtransaction",
                json!([serialize_hex(transaction), Value::Number(max_fee_rate)]),
                false,
            )
            .await?;
        let returned = returned
            .parse::<Txid>()
            .map_err(|_| BitcoinError::InvalidResult("broadcast result is not a txid"))?;
        if returned != expected {
            return Err(BitcoinError::BroadcastTxidMismatch);
        }
        Ok(returned)
    }

    /// Reconciles a cursor with a self-consistent, bounded best-chain snapshot.
    pub async fn sync_chain_cursor(&self, cursor: &mut ChainCursor) -> Result<ChainDelta> {
        let snapshot = self.get_blockchain_info().await?;
        let mut common = None;
        for point in cursor.points().iter().rev() {
            if point.height <= snapshot.blocks && self.get_block_hash(point.height).await? == point.hash {
                common = Some(*point);
                break;
            }
        }
        let common = common.ok_or(BitcoinError::ReorgBeyondHistory)?;
        let connected_count = snapshot
            .blocks
            .checked_sub(common.height)
            .ok_or(BitcoinError::InvalidChainCursor(
                "common ancestor is above snapshot tip",
            ))?;
        if connected_count > u64::from(self.config.max_chain_sync_blocks()) {
            return Err(BitcoinError::ChainSyncLimit);
        }
        let capacity = usize::try_from(connected_count).map_err(|_| BitcoinError::ChainSyncLimit)?;
        let mut connected = Vec::with_capacity(capacity);
        if connected_count != 0 {
            let first_height = common
                .height
                .checked_add(1)
                .ok_or(BitcoinError::InvalidChainCursor("block height overflow"))?;
            for height in first_height..=snapshot.blocks {
                connected.push(ChainPoint {
                    height,
                    hash: self.get_block_hash(height).await?,
                });
            }
        }

        let final_snapshot = self.get_blockchain_info().await?;
        if final_snapshot.blocks != snapshot.blocks || final_snapshot.best_block_hash != snapshot.best_block_hash {
            return Err(BitcoinError::ConcurrentChainChange);
        }
        if connected.last().map_or(common.hash, |point| point.hash) != snapshot.best_block_hash {
            return Err(BitcoinError::ConcurrentChainChange);
        }
        cursor.reconcile(common, &connected)
    }

    async fn rpc_call<R: DeserializeOwned>(&self, method: &'static str, params: Value, idempotent: bool) -> Result<R> {
        let id = self.next_request_id()?;
        let request = RpcRequest {
            jsonrpc: "1.0",
            id,
            method,
            params,
        };
        let body = serde_json::to_vec(&request)
            .map_err(|_| BitcoinError::MalformedResponse("request could not be serialized"))?;
        if body.len() > self.config.max_request_bytes() {
            return Err(BitcoinError::RequestTooLarge {
                actual: body.len(),
                limit: self.config.max_request_bytes(),
            });
        }
        let request = RpcHttpRequest { body };
        let attempts = if idempotent { self.config.read_attempts() } else { 1 };

        for attempt in 0..attempts {
            let response =
                tokio::time::timeout(self.config.request_timeout(), self.transport.send(request.clone())).await;
            let response = match response {
                Err(_) if idempotent && attempt + 1 < attempts => {
                    tokio::time::sleep(self.config.retry_delay()).await;
                    continue;
                }
                Err(_) => return Err(BitcoinError::Timeout),
                Ok(Err(error)) if idempotent && error.is_retryable() && attempt + 1 < attempts => {
                    tokio::time::sleep(self.config.retry_delay()).await;
                    continue;
                }
                Ok(Err(error)) => return Err(error.into()),
                Ok(Ok(response)) => response,
            };

            if response.body().len() > self.config.max_response_bytes() {
                return Err(BitcoinError::ResponseTooLarge {
                    actual: response.body().len(),
                    limit: self.config.max_response_bytes(),
                });
            }
            if is_transient_http(response.status()) && idempotent && attempt + 1 < attempts {
                tokio::time::sleep(self.config.retry_delay()).await;
                continue;
            }

            let parsed = parse_rpc_response(id, response.body());
            if response.status() != 200 {
                return match parsed {
                    Err(error @ BitcoinError::RemoteRpc { .. }) => Err(error),
                    _ => Err(BitcoinError::HttpStatus(response.status())),
                };
            }
            return parsed;
        }
        Err(BitcoinError::Timeout)
    }

    fn next_request_id(&self) -> Result<u64> {
        self.next_id
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                (current < MAX_JSON_RPC_ID).then_some(current + 1)
            })
            .map_err(|_| BitcoinError::InvalidConfig("JSON-RPC request id space exhausted"))
    }
}

impl<T: RpcTransport> BitcoinRpcBackend for BitcoinCoreClient<T> {
    fn network(&self) -> Network {
        BitcoinCoreClient::network(self)
    }

    fn validate_network(&self) -> BackendFuture<'_, ()> {
        Box::pin(BitcoinCoreClient::validate_network(self))
    }

    fn get_blockchain_info(&self) -> BackendFuture<'_, BlockchainInfo> {
        Box::pin(BitcoinCoreClient::get_blockchain_info(self))
    }

    fn get_block_hash(&self, height: u64) -> BackendFuture<'_, BlockHash> {
        Box::pin(BitcoinCoreClient::get_block_hash(self, height))
    }

    fn get_block_header(&self, hash: BlockHash) -> BackendFuture<'_, Header> {
        Box::pin(BitcoinCoreClient::get_block_header(self, hash))
    }

    fn get_tx_out(&self, outpoint: OutPoint) -> BackendFuture<'_, Option<TxOutInfo>> {
        Box::pin(BitcoinCoreClient::get_tx_out(self, outpoint))
    }

    fn get_raw_transaction(&self, txid: Txid) -> BackendFuture<'_, Transaction> {
        Box::pin(BitcoinCoreClient::get_raw_transaction(self, txid))
    }

    fn estimate_smart_fee(&self, confirmation_target: u16) -> BackendFuture<'_, FeeEstimate> {
        Box::pin(BitcoinCoreClient::estimate_smart_fee(self, confirmation_target))
    }

    fn send_raw_transaction<'a>(
        &'a self,
        transaction: &'a Transaction,
        max_fee_rate_sat_per_kvb: u64,
    ) -> BackendFuture<'a, Txid> {
        Box::pin(BitcoinCoreClient::send_raw_transaction(
            self,
            transaction,
            max_fee_rate_sat_per_kvb,
        ))
    }

    fn sync_chain_cursor<'a>(&'a self, cursor: &'a mut ChainCursor) -> BackendFuture<'a, ChainDelta> {
        Box::pin(BitcoinCoreClient::sync_chain_cursor(self, cursor))
    }
}

fn is_transient_http(status: u16) -> bool {
    matches!(status, 408 | 429 | 502 | 503 | 504)
}

#[derive(Serialize)]
struct RpcRequest {
    jsonrpc: &'static str,
    id: u64,
    method: &'static str,
    params: Value,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RpcEnvelope {
    #[serde(default)]
    jsonrpc: Option<String>,
    id: Value,
    result: Value,
    error: Value,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RemoteError {
    code: i64,
    message: String,
    #[serde(default)]
    data: Option<Value>,
}

fn parse_rpc_response<R: DeserializeOwned>(expected_id: u64, body: &[u8]) -> Result<R> {
    let envelope: RpcEnvelope = serde_json::from_slice(body).map_err(BitcoinError::InvalidJson)?;
    if envelope.jsonrpc.as_deref().is_some_and(|version| version != "1.0") {
        return Err(BitcoinError::MalformedResponse("unexpected JSON-RPC version"));
    }
    if envelope.id != Value::Number(Number::from(expected_id)) {
        return Err(BitcoinError::ResponseIdMismatch);
    }
    if envelope.error.is_null() {
        return serde_json::from_value(envelope.result)
            .map_err(|_| BitcoinError::InvalidResult("result has an unexpected JSON type"));
    }
    if !envelope.result.is_null() {
        return Err(BitcoinError::MalformedResponse("error response also contains a result"));
    }
    let remote: RemoteError = serde_json::from_value(envelope.error)
        .map_err(|_| BitcoinError::MalformedResponse("RPC error object is malformed"))?;
    let _ = remote.data;
    Err(BitcoinError::RemoteRpc {
        code: remote.code,
        message: remote.message,
    })
}

#[derive(Deserialize)]
struct RawBlockchainInfo {
    chain: String,
    blocks: u64,
    headers: u64,
    #[serde(rename = "bestblockhash")]
    best_block_hash: String,
    #[serde(rename = "initialblockdownload")]
    initial_block_download: bool,
    pruned: bool,
}

#[derive(Deserialize)]
struct RawTxOut {
    #[serde(rename = "bestblock")]
    best_block: String,
    confirmations: u64,
    value: Value,
    #[serde(rename = "scriptPubKey")]
    script_pubkey: RawScriptPubKey,
    coinbase: bool,
}

#[derive(Deserialize)]
struct RawScriptPubKey {
    hex: String,
}

fn parse_tx_out(raw: RawTxOut) -> Result<TxOutInfo> {
    let best_block = raw
        .best_block
        .parse()
        .map_err(|_| BitcoinError::InvalidResult("gettxout bestblock is not a block hash"))?;
    let value = parse_btc_amount(&raw.value)?;
    let bytes = Vec::<u8>::from_hex(&raw.script_pubkey.hex)
        .map_err(|_| BitcoinError::InvalidResult("scriptPubKey is not hex"))?;
    Ok(TxOutInfo {
        best_block,
        confirmations: raw.confirmations,
        value,
        script_pubkey: ScriptBuf::from_bytes(bytes),
        coinbase: raw.coinbase,
    })
}

#[derive(Deserialize)]
struct RawFeeEstimate {
    #[serde(rename = "feerate")]
    fee_rate: Option<Value>,
    #[serde(default)]
    errors: Option<Vec<String>>,
    blocks: u64,
}

fn parse_btc_amount(value: &Value) -> Result<Amount> {
    let Value::Number(number) = value else {
        return Err(BitcoinError::InvalidResult("Bitcoin amount is not a JSON number"));
    };
    Amount::from_str_in(&number.to_string(), Denomination::Bitcoin)
        .map_err(|_| BitcoinError::InvalidResult("Bitcoin amount is not exact satoshi precision"))
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(512))]

        #[test]
        fn rejects_every_different_numeric_response_id(
            expected in 1_u64..1_000_000_u64,
            distance in 1_u64..1_000_000_u64,
        ) {
            let actual = expected + distance;
            let body = serde_json::to_vec(&json!({
                "result": true,
                "error": null,
                "id": actual,
            }))?;
            let result: Result<bool> = parse_rpc_response(expected, &body);
            prop_assert!(matches!(result, Err(BitcoinError::ResponseIdMismatch)));
        }

        #[test]
        fn rejects_malformed_response_id_types(
            expected in 1_u64..1_000_000_u64,
            text in ".{0,64}",
        ) {
            let ids = [
                Value::String(text),
                Value::Null,
                Value::Bool(true),
                json!({"nested": expected}),
                json!([expected]),
            ];
            for id in ids {
                let body = serde_json::to_vec(&json!({
                    "result": true,
                    "error": null,
                    "id": id,
                }))?;
                let result: Result<bool> = parse_rpc_response(expected, &body);
                prop_assert!(matches!(result, Err(BitcoinError::ResponseIdMismatch)));
            }
        }
    }

    #[test]
    fn rejects_duplicate_id_fields() {
        let result: Result<bool> = parse_rpc_response(1, br#"{"result":true,"error":null,"id":1,"id":1}"#);
        assert!(matches!(result, Err(BitcoinError::InvalidJson(_))));
    }
}
