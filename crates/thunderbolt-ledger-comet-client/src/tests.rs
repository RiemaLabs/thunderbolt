use core::num::NonZeroU8;
use core::time::Duration;
use std::collections::BTreeMap;
use std::error::Error;
use std::net::{Ipv4Addr, SocketAddr};
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine as _;
use bitcoin::Network;
use ed25519_consensus::SigningKey;
use proptest::prelude::*;
use secp256k1::{Keypair, Secp256k1, SecretKey};
use serde_json::json;
use sha2::{Digest as _, Sha256};
use tendermint::block::parts::Header as PartSetHeader;
use tendermint::block::signed_header::SignedHeader;
use tendermint::block::{self, Commit, CommitSig, Header, Round};
use tendermint::chain;
use tendermint::hash::Hash;
use tendermint::node::Id as NodeId;
use tendermint::public_key::PublicKey;
use tendermint::signature::Signature;
use tendermint::validator::{Info as ValidatorInfo, Set as ValidatorSet};
use tendermint::vote::{self, Power, SignedVote, ValidatorIndex, Vote};
use tendermint::{AppHash, Time};
use tendermint_light_client_verifier::types::LightBlock;
use thunderbolt_cometbft::{FinalityPolicy, PinnedTrustRoot};
use thunderbolt_cometbft_client::{
    CheckpointFuture, CoordinatorLimits, HistoryEpochLimits, PeerIdentity, SourceConfiguration, TrustCheckpoint,
    TrustCheckpointCasOutcome, TrustCheckpointStore, TrustCoordinatorIdentity,
};
use thunderbolt_cometbft_rpc::{
    LedgerRpcLimits, LoopbackHttpPeer, RetryPolicy, RpcLimits, RpcPeer, RpcTransportConfig, RpcTransportError,
};
use thunderbolt_ledger::{
    ActorKeyAlgorithmV2, ActorPublicKeyV2, ActorRoleV2, ActorSignatureV2, AppHashV2, CanonicalEventV2,
    ClientRequestNonceV2, EntryHashV2, ExecutedBlockV2, LedgerChainIdV2, PendingBlockV2, ProposalBodyV2,
    SignedProposalV2,
};
use thunderbolt_ledger_abci::{
    ABCI_CODESPACE, QUERY_ENTRY_LOCATION_PATH, QUERY_EXECUTION_RANGE_PATH, QUERY_REQUEST_PATH,
};
use thunderbolt_ledger_rpc::{
    EntryLocationRequestV2, EntryLocationResponseV2, ExecutionLocationV2, ExecutionRangeCursorV2,
    ExecutionRangeRequestV2, ExecutionRangeResponseV2, RpcResponseV2, MAX_EXECUTION_RANGE_ENCODED_BYTES,
};
use thunderbolt_wire::{
    AnchorParameterSuiteIdV2, BitcoinGenesisHashV2, ChannelBindingV2, CommitteeDescriptorDigestV2, FundingOutpointV2,
    ProtocolSuiteIdV2,
};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpListener;

use crate::{
    ClientError, ClientProfileIdV2, FinalizedFirstLocationV2, HistoricalEntryReferenceV2, LedgerCometClient,
    LedgerCometClientConfig, LedgerCometClientLimits, LedgerCoordinatorPolicyV2, ReconciledSubmissionV2,
    MAX_HISTORICAL_REFERENCE_BYTES,
};

fn reference_fixture() -> HistoricalEntryReferenceV2 {
    HistoricalEntryReferenceV2 {
        profile_id: ClientProfileIdV2([0x11; 32]),
        coordinator_identity: thunderbolt_cometbft_client::TrustCoordinatorIdentity::new([0x22; 32]).expect("identity"),
        ledger_chain_id: thunderbolt_ledger::LedgerChainIdV2::new("reference-regtest-2").expect("chain"),
        source_config_version: 1,
        application_version: 2,
        execution_height: 7,
        execution_block_time_ms: 1_700_000_000_000,
        application_hash: thunderbolt_ledger::AppHashV2::from_bytes([0x33; 32]).expect("app hash"),
        execution_header_hash: [0x44; 32],
        committing_height: 8,
        committing_header_hash: [0x55; 32],
        block_index: 3,
        channel_context_id: thunderbolt_ledger::ChannelContextIdV2::from_bytes([0x66; 32]).expect("channel"),
        participant_id: thunderbolt_ledger::ParticipantIdV2::from_bytes([0x77; 32]).expect("participant"),
        request_digest: thunderbolt_ledger::RequestDigestV2::from_bytes([0x88; 32]).expect("request"),
        entry_hash: thunderbolt_ledger::EntryHashV2::from_bytes([0x99; 32]).expect("entry"),
        proof_digest: [0xaa; 32],
    }
}

#[test]
fn authority_free_reference_has_one_bounded_canonical_encoding() {
    let reference = reference_fixture();
    let bytes = reference.canonical_bytes();
    assert_eq!(bytes.len(), MAX_HISTORICAL_REFERENCE_BYTES);
    assert_eq!(
        HistoricalEntryReferenceV2::from_canonical_bytes(&bytes).expect("decode"),
        reference
    );
    let json = serde_json::to_vec(&reference).expect("serialize");
    assert_eq!(
        serde_json::from_slice::<HistoricalEntryReferenceV2>(&json).expect("deserialize"),
        reference
    );
    assert!(!json.windows(8).any(|window| window == b"receipt"));
    assert!(!json.windows(8).any(|window| window == b"provider"));
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(128))]

    #[test]
    fn every_reference_byte_tamper_is_rejected_or_changes_identity(
        offset in 0_usize..MAX_HISTORICAL_REFERENCE_BYTES,
        bit in 0_u8..8,
    ) {
        let reference = reference_fixture();
        let mut bytes = reference.canonical_bytes();
        bytes[offset] ^= 1_u8 << bit;
        if let Ok(changed) = HistoricalEntryReferenceV2::from_canonical_bytes(&bytes) {
            prop_assert_ne!(changed, reference);
        }
    }
}

const TEST_CHAIN: &str = "ledger-comet-client-regtest-2";
const PRIMARY_NODE: &str = "2222222222222222222222222222222222222222";
const WITNESS_NODE: &str = "3333333333333333333333333333333333333333";
const FUTURE_PRIMARY_NODE: &str = "4444444444444444444444444444444444444444";
const FUTURE_WITNESS_NODE: &str = "5555555555555555555555555555555555555555";
const MODE_GOOD: u8 = 0;
const MODE_AMBIGUOUS_BROADCAST_ONCE: u8 = 1;
const MODE_WRONG_RANGE: u8 = 2;

#[derive(Clone, Default)]
struct MemoryCheckpointStore {
    value: Arc<Mutex<Option<TrustCheckpoint>>>,
    fail_next: Arc<AtomicBool>,
    block_next: Arc<AtomicBool>,
    entered: Arc<tokio::sync::Notify>,
    release: Arc<tokio::sync::Notify>,
}

impl MemoryCheckpointStore {
    fn fail_next(&self) {
        self.fail_next.store(true, Ordering::SeqCst);
    }

    fn block_next(&self) {
        self.block_next.store(true, Ordering::SeqCst);
    }

    async fn wait_entered(&self) {
        self.entered.notified().await;
    }

    fn release(&self) {
        self.release.notify_one();
    }
}

impl TrustCheckpointStore for MemoryCheckpointStore {
    type Error = &'static str;

    fn load_checkpoint<'a>(
        &'a self,
        _identity: TrustCoordinatorIdentity,
    ) -> CheckpointFuture<'a, Option<TrustCheckpoint>, Self::Error> {
        Box::pin(async move { self.value.lock().map(|value| *value).map_err(|_| "checkpoint lock") })
    }

    fn compare_and_swap_checkpoint<'a>(
        &'a self,
        _identity: TrustCoordinatorIdentity,
        expected: Option<TrustCheckpoint>,
        next: TrustCheckpoint,
    ) -> CheckpointFuture<'a, TrustCheckpointCasOutcome, Self::Error> {
        Box::pin(async move {
            if self.fail_next.swap(false, Ordering::SeqCst) {
                return Err("injected checkpoint failure");
            }
            if self.block_next.swap(false, Ordering::SeqCst) {
                self.entered.notify_one();
                self.release.notified().await;
            }
            let mut value = self.value.lock().map_err(|_| "checkpoint lock")?;
            if *value == Some(next) {
                return Ok(TrustCheckpointCasOutcome::AlreadyCurrent);
            }
            if *value != expected {
                return Ok(TrustCheckpointCasOutcome::Conflict(*value));
            }
            *value = Some(next);
            Ok(TrustCheckpointCasOutcome::Advanced)
        })
    }
}

struct NetworkFixture {
    headers: BTreeMap<u64, SignedHeader>,
    validators: Vec<ValidatorInfo>,
    executions: Vec<ExecutedBlockV2>,
    proposal: SignedProposalV2,
    root: PinnedTrustRoot,
}

struct MockCometServer {
    address: SocketAddr,
    mode: Arc<AtomicU8>,
    calls: Arc<AtomicUsize>,
    task: tokio::task::JoinHandle<()>,
}

impl MockCometServer {
    async fn start(
        fixture: Arc<NetworkFixture>,
        node_id: &'static str,
        mode: u8,
    ) -> std::result::Result<Self, Box<dyn Error>> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let mode = Arc::new(AtomicU8::new(mode));
        let calls = Arc::new(AtomicUsize::new(0));
        let task_mode = Arc::clone(&mode);
        let task_calls = Arc::clone(&calls);
        let task = tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let fixture = Arc::clone(&fixture);
                let mode = Arc::clone(&task_mode);
                let calls = Arc::clone(&task_calls);
                tokio::spawn(async move {
                    let _ = serve_connection(stream, fixture, node_id, mode, calls).await;
                });
            }
        });
        Ok(Self {
            address,
            mode,
            calls,
            task,
        })
    }

    fn url(&self) -> String {
        format!("http://127.0.0.1:{}", self.address.port())
    }

    fn set_mode(&self, mode: u8) {
        self.mode.store(mode, Ordering::SeqCst);
    }
}

impl Drop for MockCometServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

struct RpcRequest {
    id: u64,
    method: String,
    params: serde_json::Value,
}

#[derive(serde::Serialize)]
struct MockRequestQueryValue<'a> {
    channel_context_id: &'a thunderbolt_ledger::ChannelContextIdV2,
    participant_id: &'a thunderbolt_ledger::ParticipantIdV2,
    request_digest: &'a thunderbolt_ledger::RequestDigestV2,
    entry_hash: &'a EntryHashV2,
    first_height: u64,
    first_block_index: u32,
}

async fn serve_connection(
    mut stream: tokio::net::TcpStream,
    fixture: Arc<NetworkFixture>,
    node_id: &str,
    mode: Arc<AtomicU8>,
    calls: Arc<AtomicUsize>,
) -> std::io::Result<()> {
    loop {
        let Some(request) = read_rpc_request(&mut stream).await? else {
            return Ok(());
        };
        calls.fetch_add(1, Ordering::SeqCst);
        if request.method == "broadcast_tx_sync"
            && mode
                .compare_exchange(
                    MODE_AMBIGUOUS_BROADCAST_ONCE,
                    MODE_GOOD,
                    Ordering::SeqCst,
                    Ordering::SeqCst,
                )
                .is_ok()
        {
            return Ok(());
        }
        let result = rpc_result(&fixture, node_id, mode.load(Ordering::SeqCst), &request);
        let body = serde_json::to_vec(&json!({
            "jsonrpc": "2.0",
            "id": request.id,
            "result": result,
        }))
        .map_err(std::io::Error::other)?;
        write_response(&mut stream, &body).await?;
    }
}

async fn read_rpc_request(stream: &mut tokio::net::TcpStream) -> std::io::Result<Option<RpcRequest>> {
    let mut bytes = Vec::new();
    let mut buffer = [0_u8; 4 * 1024];
    loop {
        let count = stream.read(&mut buffer).await?;
        if count == 0 {
            return Ok(None);
        }
        bytes.extend_from_slice(&buffer[..count]);
        if bytes.windows(4).any(|window| window == b"\r\n\r\n") {
            break;
        }
        if bytes.len() > 16 * 1024 {
            return Err(std::io::Error::other("request header too large"));
        }
    }
    let header_end = bytes
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|offset| offset + 4)
        .ok_or_else(|| std::io::Error::other("missing header terminator"))?;
    let header = std::str::from_utf8(&bytes[..header_end]).map_err(std::io::Error::other)?;
    let content_length = header
        .lines()
        .find_map(|line| {
            line.split_once(':').and_then(|(name, value)| {
                name.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse::<usize>().ok())
                    .flatten()
            })
        })
        .ok_or_else(|| std::io::Error::other("missing content length"))?;
    if content_length > 6 * 1024 * 1024 {
        return Err(std::io::Error::other("request body too large"));
    }
    while bytes.len().saturating_sub(header_end) < content_length {
        let count = stream.read(&mut buffer).await?;
        if count == 0 {
            return Err(std::io::Error::other("truncated request"));
        }
        bytes.extend_from_slice(&buffer[..count]);
    }
    let value: serde_json::Value = serde_json::from_slice(
        bytes
            .get(header_end..header_end + content_length)
            .ok_or_else(|| std::io::Error::other("request bounds"))?,
    )
    .map_err(std::io::Error::other)?;
    Ok(Some(RpcRequest {
        id: value
            .get("id")
            .and_then(serde_json::Value::as_u64)
            .ok_or_else(|| std::io::Error::other("missing id"))?,
        method: value
            .get("method")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| std::io::Error::other("missing method"))?
            .to_owned(),
        params: value.get("params").cloned().unwrap_or_else(|| json!({})),
    }))
}

async fn write_response(stream: &mut tokio::net::TcpStream, body: &[u8]) -> std::io::Result<()> {
    let header = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: keep-alive\r\n\r\n",
        body.len()
    );
    stream.write_all(header.as_bytes()).await?;
    stream.write_all(body).await?;
    stream.flush().await
}

fn rpc_result(fixture: &NetworkFixture, node_id: &str, mode: u8, request: &RpcRequest) -> serde_json::Value {
    match request.method.as_str() {
        "status" => json!({
            "node_info": {"id": node_id, "network": TEST_CHAIN},
            "sync_info": {"latest_block_height": "5"},
        }),
        "commit" => {
            let height = param_u64(&request.params, "height");
            json!({
                "signed_header": fixture.headers.get(&height),
                "canonical": true,
            })
        }
        "validators" => validator_result(fixture, &request.params),
        "abci_query" => abci_result(fixture, mode, &request.params),
        "broadcast_tx_sync" => broadcast_result(&request.params),
        _ => json!({"unsupported": request.method}),
    }
}

fn param_u64(params: &serde_json::Value, name: &str) -> u64 {
    params
        .get(name)
        .and_then(serde_json::Value::as_str)
        .and_then(|value| value.parse().ok())
        .unwrap_or_default()
}

fn validator_result(fixture: &NetworkFixture, params: &serde_json::Value) -> serde_json::Value {
    let height = param_u64(params, "height");
    let page = param_u64(params, "page");
    let per_page = usize::try_from(param_u64(params, "per_page")).unwrap_or_default();
    let start = usize::try_from(page.saturating_sub(1))
        .unwrap_or(usize::MAX)
        .saturating_mul(per_page);
    let end = start.saturating_add(per_page).min(fixture.validators.len());
    let validators = fixture.validators.get(start..end).unwrap_or(&[]);
    json!({
        "block_height": height.to_string(),
        "validators": validators,
        "count": validators.len().to_string(),
        "total": fixture.validators.len().to_string(),
    })
}

fn abci_result(fixture: &NetworkFixture, mode: u8, params: &serde_json::Value) -> serde_json::Value {
    let path = params
        .get("path")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default();
    let key = params
        .get("data")
        .and_then(serde_json::Value::as_str)
        .and_then(|value| hex::decode(value).ok())
        .unwrap_or_default();
    let height = param_u64(params, "height");
    let (code, value) = match path {
        QUERY_EXECUTION_RANGE_PATH => execution_range_value(fixture, mode, &key),
        QUERY_ENTRY_LOCATION_PATH => entry_location_value(fixture, &key),
        QUERY_REQUEST_PATH => request_mapping_value(fixture, &key),
        _ => (1, Vec::new()),
    };
    json!({
        "response": {
            "code": code.to_string(),
            "log": if code == 0 { "" } else { "not_found" },
            "info": "",
            "index": "0",
            "key": BASE64_STANDARD.encode(key),
            "value": BASE64_STANDARD.encode(value),
            "proof_ops": null,
            "height": height.to_string(),
            "codespace": ABCI_CODESPACE,
        }
    })
}

fn execution_range_value(fixture: &NetworkFixture, mode: u8, key: &[u8]) -> (u32, Vec<u8>) {
    if key.len() != 46 {
        return (1, Vec::new());
    }
    let start = key
        .get(0..8)
        .and_then(|bytes| bytes.try_into().ok())
        .map(u64::from_be_bytes)
        .unwrap_or_default();
    let previous = key.get(8..40).and_then(|bytes| AppHashV2::from_bytes(bytes).ok());
    let count = key
        .get(40..42)
        .and_then(|bytes| bytes.try_into().ok())
        .map(u16::from_be_bytes)
        .unwrap_or_default();
    let maximum = key
        .get(42..46)
        .and_then(|bytes| bytes.try_into().ok())
        .map(u32::from_be_bytes)
        .unwrap_or_default();
    let Some(previous) = previous else {
        return (1, Vec::new());
    };
    let cursor = match ExecutionRangeCursorV2::new(test_chain(), start, previous) {
        Ok(cursor) => cursor,
        Err(_) => return (1, Vec::new()),
    };
    let request = match ExecutionRangeRequestV2::new(cursor, count, maximum) {
        Ok(request) => request,
        Err(_) => return (1, Vec::new()),
    };
    let start_index = match usize::try_from(start.saturating_sub(1)) {
        Ok(index) => index,
        Err(_) => return (1, Vec::new()),
    };
    let end = match start_index.checked_add(usize::from(count)) {
        Some(end) => end,
        None => return (1, Vec::new()),
    };
    let Some(blocks) = fixture.executions.get(start_index..end) else {
        return (4, Vec::new());
    };
    let Some(last) = blocks.last() else {
        return (1, Vec::new());
    };
    let next = match ExecutionRangeCursorV2::new(test_chain(), last.height().saturating_add(1), last.app_hash().clone())
    {
        Ok(cursor) => cursor,
        Err(_) => return (1, Vec::new()),
    };
    let response = match ExecutionRangeResponseV2::new(&request, blocks.to_vec(), next) {
        Ok(response) => RpcResponseV2::ExecutionRange(response),
        Err(_) => return (1, Vec::new()),
    };
    let mut bytes = match response.to_canonical_bytes() {
        Ok(bytes) => bytes,
        Err(_) => return (1, Vec::new()),
    };
    if mode == MODE_WRONG_RANGE {
        if let Ok(mut value) = serde_json::from_slice::<serde_json::Value>(&bytes) {
            value["response"]["result"]["next_cursor"]["next_height"] = json!(99);
            bytes = serde_json::to_vec(&value).unwrap_or_default();
        }
    }
    (0, bytes)
}

fn entry_location_value(fixture: &NetworkFixture, key: &[u8]) -> (u32, Vec<u8>) {
    if key.len() != 104 {
        return (1, Vec::new());
    }
    let channel = match key
        .get(0..32)
        .and_then(|bytes| thunderbolt_ledger::ChannelContextIdV2::from_bytes(bytes).ok())
    {
        Some(channel) => channel,
        None => return (1, Vec::new()),
    };
    let entry_hash = match key.get(32..64).and_then(|bytes| EntryHashV2::from_bytes(bytes).ok()) {
        Some(hash) => hash,
        None => return (1, Vec::new()),
    };
    let through = key
        .get(64..72)
        .and_then(|bytes| bytes.try_into().ok())
        .map(u64::from_be_bytes)
        .unwrap_or_default();
    let through_hash = match key.get(72..104).and_then(|bytes| AppHashV2::from_bytes(bytes).ok()) {
        Some(hash) => hash,
        None => return (1, Vec::new()),
    };
    let request =
        match EntryLocationRequestV2::new(test_chain(), channel.clone(), entry_hash.clone(), through, through_hash) {
            Ok(request) => request,
            Err(_) => return (1, Vec::new()),
        };
    let location = fixture
        .executions
        .iter()
        .take(usize::try_from(through).unwrap_or_default())
        .find_map(|block| {
            block.entries().iter().enumerate().find_map(|(index, entry)| {
                (entry.metadata().channel_context_id() == &channel && entry.metadata().entry_hash() == &entry_hash)
                    .then(|| {
                        u32::try_from(index)
                            .ok()
                            .and_then(|index| ExecutionLocationV2::new(block.height(), index).ok())
                    })
                    .flatten()
            })
        });
    let response = match EntryLocationResponseV2::new(&request, location) {
        Ok(response) => RpcResponseV2::EntryLocation(response),
        Err(_) => return (1, Vec::new()),
    };
    match response.to_canonical_bytes() {
        Ok(bytes) => (0, bytes),
        Err(_) => (1, Vec::new()),
    }
}

fn request_mapping_value(fixture: &NetworkFixture, key: &[u8]) -> (u32, Vec<u8>) {
    if key.len() != 96 {
        return (1, Vec::new());
    }
    for block in &fixture.executions {
        for entry in block.entries() {
            let metadata = entry.metadata();
            if key.get(0..32) == Some(metadata.channel_context_id().as_bytes().as_slice())
                && key.get(32..64) == Some(metadata.participant_id().as_bytes().as_slice())
                && key.get(64..96) == Some(metadata.request_digest().as_bytes().as_slice())
            {
                return (
                    0,
                    serde_json::to_vec(&MockRequestQueryValue {
                        channel_context_id: metadata.channel_context_id(),
                        participant_id: metadata.participant_id(),
                        request_digest: metadata.request_digest(),
                        entry_hash: metadata.entry_hash(),
                        first_height: metadata.block_height(),
                        first_block_index: metadata.block_index(),
                    })
                    .unwrap_or_default(),
                );
            }
        }
    }
    (4, Vec::new())
}

fn broadcast_result(params: &serde_json::Value) -> serde_json::Value {
    let transaction = params
        .get("tx")
        .and_then(serde_json::Value::as_str)
        .and_then(|value| BASE64_STANDARD.decode(value).ok())
        .unwrap_or_default();
    let proposal = serde_json::from_slice::<SignedProposalV2>(&transaction).ok();
    let data = proposal
        .and_then(|proposal| proposal.body().entry_hash().ok())
        .map(|hash| hex::encode_upper(hash.as_bytes()))
        .unwrap_or_default();
    json!({
        "code": "0",
        "data": data,
        "log": "",
        "codespace": ABCI_CODESPACE,
        "hash": hex::encode_upper(Sha256::digest(transaction)),
    })
}

fn test_chain() -> LedgerChainIdV2 {
    LedgerChainIdV2::new(TEST_CHAIN).expect("chain")
}

fn signed_open(discriminator: u8) -> SignedProposalV2 {
    let secp = Secp256k1::new();
    let mut secret_bytes = [0_u8; 32];
    secret_bytes[31] = discriminator.max(1);
    let secret = SecretKey::from_byte_array(secret_bytes).expect("secret");
    let keypair = Keypair::from_secret_key(&secp, &secret);
    let (public_key, _) = keypair.x_only_public_key();
    let mut txid = [discriminator.max(1); 32];
    txid[31] ^= 0x5a;
    let binding = ChannelBindingV2::new(
        ProtocolSuiteIdV2::from_bytes([0x11; 32]).expect("suite"),
        Network::Regtest,
        BitcoinGenesisHashV2::for_network(Network::Regtest).expect("genesis"),
        b"ledger-comet-client-tests",
        FundingOutpointV2::new(txid, u32::from(discriminator)).expect("outpoint"),
        1,
        CommitteeDescriptorDigestV2::from_bytes([0x22; 32]).expect("committee"),
        AnchorParameterSuiteIdV2::from_bytes([0x33; 32]).expect("anchor suite"),
    )
    .expect("binding");
    let body = ProposalBodyV2::new(
        test_chain(),
        binding,
        0,
        EntryHashV2::zero(),
        ClientRequestNonceV2::from_bytes([discriminator.max(1); 16]).expect("nonce"),
        ActorKeyAlgorithmV2::Bip340V1,
        ActorPublicKeyV2::from_bytes(public_key.serialize()).expect("public key"),
        ActorRoleV2::Holder,
        thunderbolt_ledger::EventKindV2::Open,
        CanonicalEventV2::from_bytes([0x01, discriminator.max(1)]).expect("event"),
    )
    .expect("body");
    let signature = secp.sign_schnorr_no_aux_rand(body.proposal_digest().expect("digest").as_bytes(), &keypair);
    SignedProposalV2::new(
        body,
        ActorSignatureV2::from_bytes(signature.to_byte_array()).expect("signature"),
    )
    .expect("proposal")
}

fn build_network_fixture() -> NetworkFixture {
    let seeds = [[1_u8; 32], [2_u8; 32], [3_u8; 32], [4_u8; 32]];
    let validators = validator_set(&seeds);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("time")
        .as_secs();
    let base_seconds = now.saturating_sub(30);
    let base = i64::try_from(base_seconds).expect("base time");
    let time_one = Time::from_unix_timestamp(base, 0).expect("time one");
    let proposal = signed_open(71);
    let mut first_pending =
        PendingBlockV2::new(test_chain(), 1, base_seconds * 1_000, AppHashV2::zero()).expect("first pending");
    first_pending.push(proposal.clone()).expect("first proposal");
    let first = first_pending.execute().expect("first execution");
    let second = PendingBlockV2::new(test_chain(), 2, (base_seconds + 1) * 1_000, first.app_hash().clone())
        .expect("second pending")
        .execute()
        .expect("second execution");
    let mut third_pending = PendingBlockV2::new(test_chain(), 3, (base_seconds + 2) * 1_000, second.app_hash().clone())
        .expect("third pending");
    third_pending.push(proposal.clone()).expect("replay proposal");
    let third = third_pending.execute().expect("third execution");

    let header_one = build_header(&validators, 1, time_one, None, &[0_u8; 32]);
    let header_two = build_header(
        &validators,
        2,
        (time_one + Duration::from_secs(1)).expect("time two"),
        Some(header_one.hash()),
        first.app_hash().as_bytes(),
    );
    let header_three = build_header(
        &validators,
        3,
        (time_one + Duration::from_secs(2)).expect("time three"),
        Some(header_two.hash()),
        second.app_hash().as_bytes(),
    );
    let header_four = build_header(
        &validators,
        4,
        (time_one + Duration::from_secs(3)).expect("time four"),
        Some(header_three.hash()),
        third.app_hash().as_bytes(),
    );
    let mut headers = BTreeMap::new();
    for header in [header_one.clone(), header_two.clone(), header_three, header_four] {
        headers.insert(
            header.height.value(),
            SignedHeader::new(header.clone(), sign_commit(&header, &validators, &seeds)).expect("signed header"),
        );
    }
    let root_block = LightBlock::new(
        SignedHeader::new(header_one.clone(), sign_commit(&header_one, &validators, &seeds)).expect("root header"),
        validators.clone(),
        validators.clone(),
        NodeId::from_str("1111111111111111111111111111111111111111").expect("root provider"),
    );
    let policy = test_policy();
    let root = PinnedTrustRoot::new(
        root_block,
        &test_chain(),
        1,
        match header_one.hash() {
            Hash::Sha256(bytes) => bytes,
            Hash::None => [0_u8; 32],
        },
        policy,
    )
    .expect("root");
    NetworkFixture {
        headers,
        validators: validators.validators().clone(),
        executions: vec![first, second, third],
        proposal,
        root,
    }
}

fn validator_set(seeds: &[[u8; 32]]) -> ValidatorSet {
    ValidatorSet::without_proposer(
        seeds
            .iter()
            .map(|seed| {
                let key = tendermint::private_key::Ed25519::try_from(seed.as_slice()).expect("validator key");
                ValidatorInfo::new(
                    PublicKey::from(key.verification_key()),
                    Power::try_from(1_u64).expect("power"),
                )
            })
            .collect(),
    )
}

fn build_header(validators: &ValidatorSet, height: u64, time: Time, last: Option<Hash>, app_hash: &[u8; 32]) -> Header {
    let validator_hash = validators.hash();
    Header {
        version: block::header::Version { block: 11, app: 2 },
        chain_id: chain::Id::from_str(TEST_CHAIN).expect("chain"),
        height: block::Height::try_from(height).expect("height"),
        time,
        last_block_id: last.map(|hash| block::Id {
            hash,
            part_set_header: PartSetHeader::default(),
        }),
        last_commit_hash: None,
        data_hash: None,
        validators_hash: validator_hash,
        next_validators_hash: validator_hash,
        consensus_hash: validator_hash,
        app_hash: AppHash::try_from(app_hash.to_vec()).expect("app hash"),
        last_results_hash: None,
        evidence_hash: None,
        proposer_address: validators.validators()[0].address,
    }
}

fn sign_commit(header: &Header, validators: &ValidatorSet, seeds: &[[u8; 32]]) -> Commit {
    let header_hash = header.hash();
    let block_id = block::Id {
        hash: header_hash,
        part_set_header: PartSetHeader::new(1, header_hash).expect("parts"),
    };
    let round = Round::try_from(1_u32).expect("round");
    let signatures = validators
        .validators()
        .iter()
        .enumerate()
        .map(|(index, validator)| {
            let seed = seeds
                .iter()
                .find(|seed| {
                    let key = tendermint::private_key::Ed25519::try_from(seed.as_slice()).expect("key");
                    validator.address == tendermint::account::Id::from(key.verification_key())
                })
                .expect("seed");
            let vote = Vote {
                vote_type: vote::Type::Precommit,
                height: header.height,
                round,
                block_id: Some(block_id),
                timestamp: Some(header.time),
                validator_address: validator.address,
                validator_index: ValidatorIndex::try_from(u32::try_from(index).expect("index")).expect("index"),
                signature: Signature::new(vec![0_u8; 64]).expect("placeholder"),
                extension: Vec::new(),
                extension_signature: None,
            };
            let sign_bytes = SignedVote::from_vote(vote, header.chain_id.clone())
                .expect("vote")
                .sign_bytes();
            CommitSig::BlockIdFlagCommit {
                validator_address: validator.address,
                timestamp: header.time,
                signature: Some(SigningKey::from(*seed).sign(&sign_bytes).into()),
            }
        })
        .collect();
    Commit {
        height: header.height,
        round,
        block_id,
        signatures,
    }
}

fn test_policy() -> FinalityPolicy {
    FinalityPolicy::new(Duration::from_secs(600), Duration::from_secs(30), 4, 8, 1, 2).expect("policy")
}

fn source_configuration(
    version: u64,
    primary_node: &str,
    primary_binding: [u8; 32],
    witness_node: &str,
    witness_binding: [u8; 32],
) -> SourceConfiguration {
    SourceConfiguration::new(
        version,
        PeerIdentity::new(primary_binding, NodeId::from_str(primary_node).expect("primary node")).expect("primary"),
        vec![
            PeerIdentity::new(witness_binding, NodeId::from_str(witness_node).expect("witness node")).expect("witness"),
        ],
    )
    .expect("sources")
}

fn rpc_peer(server: &MockCometServer, node: &str, binding: [u8; 32]) -> RpcPeer {
    RpcPeer::RegtestLoopback(
        LoopbackHttpPeer::new_regtest(&server.url(), NodeId::from_str(node).expect("node"), binding).expect("peer"),
    )
}

fn rpc_config(peers: Vec<RpcPeer>) -> RpcTransportConfig {
    RpcTransportConfig::new(
        peers,
        RpcLimits::new(
            1024 * 1024,
            8 * 1024 * 1024,
            8,
            4,
            NonZeroU8::new(2).expect("page"),
            16,
            16 * 1024,
        )
        .expect("RPC limits"),
        RetryPolicy::new(NonZeroU8::new(1).expect("attempt"), Duration::from_millis(1)).expect("retry"),
    )
    .expect("RPC config")
    .with_ledger_limits(LedgerRpcLimits::new(1024 * 1024, 2 * 1024 * 1024).expect("Ledger limits"))
}

fn client_config(
    sources: SourceConfiguration,
    rpc: RpcTransportConfig,
    client_limits: LedgerCometClientLimits,
) -> LedgerCometClientConfig {
    let coordinator = LedgerCoordinatorPolicyV2::new(
        test_chain(),
        test_policy(),
        sources,
        Duration::from_secs(1),
        CoordinatorLimits::new(1024 * 1024, 1024 * 1024, 8 * 1024 * 1024, Duration::from_secs(3), 1)
            .expect("coordinator limits"),
        HistoryEpochLimits::new(8, 64 * 1024 * 1024, 8192).expect("history limits"),
    );
    LedgerCometClientConfig::new(coordinator, rpc, client_limits).expect("client config")
}

fn default_client_limits() -> LedgerCometClientLimits {
    LedgerCometClientLimits::new(8, 7, 64 * 1024 * 1024, Duration::from_secs(2)).expect("client limits")
}

fn private_directory() -> tempfile::TempDir {
    let directory = tempfile::TempDir::new().expect("tempdir");
    #[cfg(unix)]
    std::fs::set_permissions(
        directory.path(),
        <std::fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o700),
    )
    .expect("private directory");
    directory
}

fn full_range_request(fixture: &NetworkFixture) -> ExecutionRangeRequestV2 {
    ExecutionRangeRequestV2::new(
        ExecutionRangeCursorV2::new(test_chain(), 1, AppHashV2::zero()).expect("cursor"),
        u16::try_from(fixture.executions.len()).expect("count"),
        MAX_EXECUTION_RANGE_ENCODED_BYTES,
    )
    .expect("range")
}

async fn prepare_and_finalize(
    client: &mut LedgerCometClient<MemoryCheckpointStore>,
    request: &ExecutionRangeRequestV2,
) -> crate::Result<crate::FinalizedRangeV2> {
    let prepared = client.prepare_range(request).await?;
    for intent in prepared.intents() {
        let bytes = intent.to_canonical_bytes()?;
        assert!(!bytes.windows(8).any(|window| window == b"receipt"));
        assert!(!bytes.windows(8).any(|window| window == b"provider"));
        assert_eq!(crate::FinalityAdvanceIntentV2::from_canonical_bytes(&bytes)?, *intent);
    }
    client.finalize_prepared_range(&prepared).await
}

#[tokio::test]
async fn contiguous_empty_and_replay_blocks_finalize_restart_and_revalidate_reference() {
    let fixture = Arc::new(build_network_fixture());
    let primary = MockCometServer::start(Arc::clone(&fixture), PRIMARY_NODE, MODE_GOOD)
        .await
        .expect("primary");
    let witness = MockCometServer::start(Arc::clone(&fixture), WITNESS_NODE, MODE_GOOD)
        .await
        .expect("witness");
    let sources = source_configuration(1, PRIMARY_NODE, [0x41; 32], WITNESS_NODE, [0x42; 32]);
    let config = client_config(
        sources,
        rpc_config(vec![
            rpc_peer(&primary, PRIMARY_NODE, [0x41; 32]),
            rpc_peer(&witness, WITNESS_NODE, [0x42; 32]),
        ]),
        default_client_limits(),
    );
    let directory = private_directory();
    let path = directory.path().join("client.sqlite");
    let checkpoint = MemoryCheckpointStore::default();
    let mut client = LedgerCometClient::create(&path, config.clone(), fixture.root.clone(), checkpoint.clone())
        .await
        .expect("create client");
    assert!(ExecutionRangeRequestV2::new(
        ExecutionRangeCursorV2::new(test_chain(), 1, AppHashV2::zero()).expect("empty cursor"),
        0,
        MAX_EXECUTION_RANGE_ENCODED_BYTES,
    )
    .is_err());
    let finalized = prepare_and_finalize(&mut client, &full_range_request(&fixture))
        .await
        .expect("finalize range");
    assert_eq!(finalized.blocks().len(), 3);
    assert!(finalized.blocks()[1].block().entries().is_empty());
    assert_eq!(finalized.next_cursor().next_height(), 4);
    assert_eq!(client.current_trust_root().expect("root").height(), 4);

    let capability = client.finalized_entry(1, 0).expect("entry capability");
    capability
        .inclusion_proof()
        .verify(capability.entry().metadata(), &fixture.executions[0])
        .expect("compact inclusion proof");
    let reference = capability.reference().clone();
    assert_eq!(reference.execution_height(), 1);
    assert_eq!(reference.source_config_version(), 1);

    let metadata = fixture.executions[0].entries()[0].metadata();
    let locator = EntryLocationRequestV2::new(
        test_chain(),
        metadata.channel_context_id().clone(),
        metadata.entry_hash().clone(),
        3,
        fixture.executions[2].app_hash().clone(),
    )
    .expect("locator");
    let located = client.finalized_first_location(&locator).await.expect("first location");
    let FinalizedFirstLocationV2::Found(found) = located else {
        panic!("expected first location")
    };
    assert_eq!(found.reference().execution_height(), 1);

    if let Some(intent) = client.prepare_history_epoch().expect("prepare seal") {
        checkpoint.fail_next();
        assert!(matches!(
            client.seal_history_epoch(&intent).await,
            Err(ClientError::Coordinator(
                thunderbolt_cometbft_client::CoordinatorError::CheckpointUnavailable
            ))
        ));
        drop(client);
        client = LedgerCometClient::recover_history_epoch(&path, config.clone(), &intent, checkpoint.clone())
            .await
            .expect("recover history seal");
        assert_eq!(
            client
                .revalidate_reference(&reference)
                .expect("post-seal reference")
                .entry()
                .metadata()
                .entry_hash(),
            metadata.entry_hash()
        );
    }
    drop(client);

    let reopened = LedgerCometClient::open(&path, config, checkpoint)
        .await
        .expect("reopen client");
    drop(primary);
    drop(witness);
    let revalidated = reopened
        .revalidate_reference(&reference)
        .expect("offline historical revalidation");
    assert_eq!(revalidated.entry().metadata().entry_hash(), metadata.entry_hash());
    let mut tampered_bytes = reference.canonical_bytes();
    let last = tampered_bytes.len() - 1;
    tampered_bytes[last] ^= 1;
    let tampered =
        HistoricalEntryReferenceV2::from_canonical_bytes(&tampered_bytes).expect("shape-valid tampered reference");
    assert!(reopened.revalidate_reference(&tampered).is_err());
}

#[tokio::test]
async fn finalized_locator_absence_scans_every_retained_block() {
    let fixture = Arc::new(build_network_fixture());
    let primary = MockCometServer::start(Arc::clone(&fixture), PRIMARY_NODE, MODE_GOOD)
        .await
        .expect("primary");
    let witness = MockCometServer::start(Arc::clone(&fixture), WITNESS_NODE, MODE_GOOD)
        .await
        .expect("witness");
    let config = client_config(
        source_configuration(1, PRIMARY_NODE, [0x41; 32], WITNESS_NODE, [0x42; 32]),
        rpc_config(vec![
            rpc_peer(&primary, PRIMARY_NODE, [0x41; 32]),
            rpc_peer(&witness, WITNESS_NODE, [0x42; 32]),
        ]),
        default_client_limits(),
    );
    let directory = private_directory();
    let mut client = LedgerCometClient::create(
        directory.path().join("absence.sqlite"),
        config,
        fixture.root.clone(),
        MemoryCheckpointStore::default(),
    )
    .await
    .expect("client");
    prepare_and_finalize(&mut client, &full_range_request(&fixture))
        .await
        .expect("range");
    let metadata = fixture.executions[0].entries()[0].metadata();
    let request = EntryLocationRequestV2::new(
        test_chain(),
        metadata.channel_context_id().clone(),
        EntryHashV2::from_bytes([0xc1; 32]).expect("missing hash"),
        3,
        fixture.executions[2].app_hash().clone(),
    )
    .expect("locator");
    let result = client.finalized_first_location(&request).await.expect("absence");
    let FinalizedFirstLocationV2::Absent(absence) = result else {
        panic!("expected absence")
    };
    assert_eq!(absence.through_summary().execution_height(), 3);
}

#[tokio::test]
async fn ambiguous_broadcast_is_one_shot_and_reconciles_only_by_exact_request() {
    let fixture = Arc::new(build_network_fixture());
    let primary = MockCometServer::start(Arc::clone(&fixture), PRIMARY_NODE, MODE_GOOD)
        .await
        .expect("primary");
    let witness = MockCometServer::start(Arc::clone(&fixture), WITNESS_NODE, MODE_GOOD)
        .await
        .expect("witness");
    let config = client_config(
        source_configuration(1, PRIMARY_NODE, [0x41; 32], WITNESS_NODE, [0x42; 32]),
        rpc_config(vec![
            rpc_peer(&primary, PRIMARY_NODE, [0x41; 32]),
            rpc_peer(&witness, WITNESS_NODE, [0x42; 32]),
        ]),
        default_client_limits(),
    );
    let directory = private_directory();
    let mut client = LedgerCometClient::create(
        directory.path().join("broadcast.sqlite"),
        config,
        fixture.root.clone(),
        MemoryCheckpointStore::default(),
    )
    .await
    .expect("client");
    prepare_and_finalize(&mut client, &full_range_request(&fixture))
        .await
        .expect("finality");
    primary.set_mode(MODE_AMBIGUOUS_BROADCAST_ONCE);
    let before = primary.calls.load(Ordering::SeqCst);
    let error = client.broadcast(&fixture.proposal).await.expect_err("ambiguous write");
    assert!(matches!(
        error,
        ClientError::Rpc(RpcTransportError::AmbiguousWrite { .. })
    ));
    assert_eq!(primary.calls.load(Ordering::SeqCst) - before, 2);

    let reconciled = client
        .reconcile_submission(&fixture.proposal, 3)
        .await
        .expect("reconcile");
    let ReconciledSubmissionV2::Finalized(capability) = reconciled else {
        panic!("expected finalized request")
    };
    assert_eq!(capability.reference().execution_height(), 1);

    let unknown = client
        .reconcile_submission(&signed_open(72), 3)
        .await
        .expect("unknown query");
    assert!(matches!(unknown, ReconciledSubmissionV2::Unknown));
}

#[tokio::test]
async fn checkpoint_failure_requires_live_finality_recovery_after_restart() {
    let fixture = Arc::new(build_network_fixture());
    let primary = MockCometServer::start(Arc::clone(&fixture), PRIMARY_NODE, MODE_GOOD)
        .await
        .expect("primary");
    let witness = MockCometServer::start(Arc::clone(&fixture), WITNESS_NODE, MODE_GOOD)
        .await
        .expect("witness");
    let config = client_config(
        source_configuration(1, PRIMARY_NODE, [0x41; 32], WITNESS_NODE, [0x42; 32]),
        rpc_config(vec![
            rpc_peer(&primary, PRIMARY_NODE, [0x41; 32]),
            rpc_peer(&witness, WITNESS_NODE, [0x42; 32]),
        ]),
        default_client_limits(),
    );
    let directory = private_directory();
    let path = directory.path().join("recovery.sqlite");
    let checkpoint = MemoryCheckpointStore::default();
    let mut client = LedgerCometClient::create(&path, config.clone(), fixture.root.clone(), checkpoint.clone())
        .await
        .expect("client");
    checkpoint.fail_next();
    let first_request = ExecutionRangeRequestV2::new(
        ExecutionRangeCursorV2::new(test_chain(), 1, AppHashV2::zero()).expect("cursor"),
        1,
        MAX_EXECUTION_RANGE_ENCODED_BYTES,
    )
    .expect("request");
    let prepared = client.prepare_range(&first_request).await.expect("prepare intent");
    let retained_bytes = prepared.intents()[0].to_canonical_bytes().expect("retain intent");
    let retained =
        crate::FinalityAdvanceIntentV2::from_canonical_bytes(&retained_bytes).expect("reload retained intent");
    assert!(matches!(
        client.finalize_prepared_range(&prepared).await,
        Err(ClientError::Coordinator(
            thunderbolt_cometbft_client::CoordinatorError::CheckpointUnavailable
        ))
    ));
    drop(client);
    assert!(LedgerCometClient::open(&path, config.clone(), checkpoint.clone())
        .await
        .is_err());

    let recovered = LedgerCometClient::recover_finality(&path, config, retained.execution(), checkpoint)
        .await
        .expect("recover finality");
    assert_eq!(recovered.current_trust_root().expect("root").height(), 2);
    assert_eq!(
        recovered
            .finalized_entry(1, 0)
            .expect("recovered entry")
            .entry()
            .metadata()
            .entry_hash(),
        fixture.executions[0].entries()[0].metadata().entry_hash()
    );
}

#[tokio::test]
async fn cancellation_after_sqlite_commit_poison_client_until_explicit_recovery() {
    let fixture = Arc::new(build_network_fixture());
    let primary = MockCometServer::start(Arc::clone(&fixture), PRIMARY_NODE, MODE_GOOD)
        .await
        .expect("primary");
    let witness = MockCometServer::start(Arc::clone(&fixture), WITNESS_NODE, MODE_GOOD)
        .await
        .expect("witness");
    let config = client_config(
        source_configuration(1, PRIMARY_NODE, [0x41; 32], WITNESS_NODE, [0x42; 32]),
        rpc_config(vec![
            rpc_peer(&primary, PRIMARY_NODE, [0x41; 32]),
            rpc_peer(&witness, WITNESS_NODE, [0x42; 32]),
        ]),
        default_client_limits(),
    );
    let directory = private_directory();
    let path = directory.path().join("cancel.sqlite");
    let checkpoint = MemoryCheckpointStore::default();
    let mut client = LedgerCometClient::create(&path, config.clone(), fixture.root.clone(), checkpoint.clone())
        .await
        .expect("client");
    let request = ExecutionRangeRequestV2::new(
        ExecutionRangeCursorV2::new(test_chain(), 1, AppHashV2::zero()).expect("cursor"),
        1,
        MAX_EXECUTION_RANGE_ENCODED_BYTES,
    )
    .expect("request");
    let prepared = client.prepare_range(&request).await.expect("prepared");
    let retained = crate::FinalityAdvanceIntentV2::from_canonical_bytes(
        &prepared.intents()[0].to_canonical_bytes().expect("intent bytes"),
    )
    .expect("retained intent");
    checkpoint.block_next();
    let mut finalization = Box::pin(client.finalize_prepared_range(&prepared));
    tokio::select! {
        () = checkpoint.wait_entered() => {}
        result = &mut finalization => panic!("finalization returned before blocked CAS: {result:?}"),
    }
    drop(finalization);
    checkpoint.release();
    assert!(matches!(client.current_trust_root(), Err(ClientError::Poisoned)));
    assert!(matches!(client.finalized_entry(1, 0), Err(ClientError::Poisoned)));
    assert!(matches!(client.source_configuration(), Err(ClientError::Poisoned)));
    assert!(matches!(client.prepare_history_epoch(), Err(ClientError::Poisoned)));
    drop(client);

    let recovered = LedgerCometClient::recover_finality(&path, config, retained.execution(), checkpoint)
        .await
        .expect("recover after cancellation");
    assert_eq!(recovered.current_trust_root().expect("root").height(), 2);
}

#[tokio::test]
async fn source_rotation_preserves_profile_and_historical_references() {
    let fixture = Arc::new(build_network_fixture());
    let primary = MockCometServer::start(Arc::clone(&fixture), PRIMARY_NODE, MODE_GOOD)
        .await
        .expect("primary");
    let witness = MockCometServer::start(Arc::clone(&fixture), WITNESS_NODE, MODE_GOOD)
        .await
        .expect("witness");
    let future_primary = MockCometServer::start(Arc::clone(&fixture), FUTURE_PRIMARY_NODE, MODE_GOOD)
        .await
        .expect("future primary");
    let future_witness = MockCometServer::start(Arc::clone(&fixture), FUTURE_WITNESS_NODE, MODE_GOOD)
        .await
        .expect("future witness");
    let initial_sources = source_configuration(1, PRIMARY_NODE, [0x41; 32], WITNESS_NODE, [0x42; 32]);
    let next_sources = source_configuration(2, FUTURE_PRIMARY_NODE, [0x43; 32], FUTURE_WITNESS_NODE, [0x44; 32]);
    let rpc = rpc_config(vec![
        rpc_peer(&primary, PRIMARY_NODE, [0x41; 32]),
        rpc_peer(&witness, WITNESS_NODE, [0x42; 32]),
        rpc_peer(&future_primary, FUTURE_PRIMARY_NODE, [0x43; 32]),
        rpc_peer(&future_witness, FUTURE_WITNESS_NODE, [0x44; 32]),
    ]);
    let initial_config = client_config(initial_sources, rpc.clone(), default_client_limits());
    let next_config = client_config(next_sources.clone(), rpc, default_client_limits());
    assert_eq!(initial_config.profile_id(), next_config.profile_id());
    let directory = private_directory();
    let path = directory.path().join("rotation.sqlite");
    let checkpoint = MemoryCheckpointStore::default();
    let mut client = LedgerCometClient::create(&path, initial_config, fixture.root.clone(), checkpoint.clone())
        .await
        .expect("client");
    let first_request = ExecutionRangeRequestV2::new(
        ExecutionRangeCursorV2::new(test_chain(), 1, AppHashV2::zero()).expect("cursor"),
        1,
        MAX_EXECUTION_RANGE_ENCODED_BYTES,
    )
    .expect("first range");
    prepare_and_finalize(&mut client, &first_request)
        .await
        .expect("first finality");
    let old_reference = client.finalized_entry(1, 0).expect("old entry").reference().clone();
    checkpoint.block_next();
    let mut rotation = Box::pin(client.rotate_sources(1, next_sources));
    tokio::select! {
        () = checkpoint.wait_entered() => {}
        result = &mut rotation => panic!("rotation returned before blocked CAS: {result:?}"),
    }
    drop(rotation);
    checkpoint.release();
    assert!(matches!(client.current_trust_root(), Err(ClientError::Poisoned)));
    drop(client);
    let mut client = LedgerCometClient::recover_rotation(&path, next_config.clone(), 1, checkpoint.clone())
        .await
        .expect("recover rotation");
    client
        .revalidate_reference(&old_reference)
        .expect("old reference after rotation");
    let tail = ExecutionRangeRequestV2::new(
        ExecutionRangeCursorV2::new(test_chain(), 2, fixture.executions[0].app_hash().clone()).expect("tail cursor"),
        2,
        MAX_EXECUTION_RANGE_ENCODED_BYTES,
    )
    .expect("tail range");
    prepare_and_finalize(&mut client, &tail).await.expect("tail finality");
    let new_reference = client.finalized_entry(3, 0).expect("new entry").reference().clone();
    assert_eq!(old_reference.source_config_version(), 1);
    assert_eq!(new_reference.source_config_version(), 2);

    let unauthorized = source_configuration(
        3,
        "6666666666666666666666666666666666666666",
        [0x61; 32],
        FUTURE_WITNESS_NODE,
        [0x44; 32],
    );
    assert!(matches!(
        client.rotate_sources(2, unauthorized).await,
        Err(ClientError::InvalidConfiguration(_))
    ));
    drop(client);
    let reopened = LedgerCometClient::open(&path, next_config, checkpoint)
        .await
        .expect("reopen rotated client");
    reopened
        .revalidate_reference(&old_reference)
        .expect("old reference restart");
    reopened
        .revalidate_reference(&new_reference)
        .expect("new reference restart");
}

fn deterministic_rpc_config() -> RpcTransportConfig {
    rpc_config(vec![
        RpcPeer::RegtestLoopback(
            LoopbackHttpPeer::new_regtest(
                "http://127.0.0.1:28001",
                NodeId::from_str(PRIMARY_NODE).expect("primary"),
                [0x41; 32],
            )
            .expect("primary peer"),
        ),
        RpcPeer::RegtestLoopback(
            LoopbackHttpPeer::new_regtest(
                "http://127.0.0.1:28002",
                NodeId::from_str(WITNESS_NODE).expect("witness"),
                [0x42; 32],
            )
            .expect("witness peer"),
        ),
    ])
}

fn custom_coordinator_config(
    _identity: [u8; 32],
    chain_id: LedgerChainIdV2,
    policy: FinalityPolicy,
    sources: SourceConfiguration,
    busy_timeout: Duration,
    max_execution_bytes: usize,
    history_transitions: usize,
) -> LedgerCoordinatorPolicyV2 {
    LedgerCoordinatorPolicyV2::new(
        chain_id,
        policy,
        sources,
        busy_timeout,
        CoordinatorLimits::new(
            1024 * 1024,
            max_execution_bytes,
            8 * 1024 * 1024,
            Duration::from_secs(3),
            1,
        )
        .expect("limits"),
        HistoryEpochLimits::new(history_transitions, 64 * 1024 * 1024, 8192).expect("history"),
    )
}

#[allow(clippy::too_many_arguments)]
fn profile_policy(
    policy: FinalityPolicy,
    busy_timeout: Duration,
    trace_bytes: usize,
    execution_bytes: usize,
    proof_bytes: usize,
    operation_timeout: Duration,
    history_transitions: usize,
    history_proof_bytes: usize,
    history_requests: usize,
) -> LedgerCoordinatorPolicyV2 {
    LedgerCoordinatorPolicyV2::new(
        test_chain(),
        policy,
        source_configuration(1, PRIMARY_NODE, [0x41; 32], WITNESS_NODE, [0x42; 32]),
        busy_timeout,
        CoordinatorLimits::new(trace_bytes, execution_bytes, proof_bytes, operation_timeout, 1)
            .expect("profile limits"),
        HistoryEpochLimits::new(history_transitions, history_proof_bytes, history_requests).expect("profile history"),
    )
}

#[test]
fn client_profile_is_mechanical_golden_and_source_rotation_stable() {
    let sources = source_configuration(1, PRIMARY_NODE, [0x41; 32], WITNESS_NODE, [0x42; 32]);
    let rpc = deterministic_rpc_config();
    let base_coordinator = custom_coordinator_config(
        [0x77; 32],
        test_chain(),
        test_policy(),
        sources.clone(),
        Duration::from_secs(1),
        1024 * 1024,
        8,
    );
    let base =
        LedgerCometClientConfig::new(base_coordinator.clone(), rpc.clone(), default_client_limits()).expect("base");
    assert_eq!(
        hex::encode(base.profile_id().as_bytes()),
        "aebbb43e84779cba3fc1a6be097a96e1fccc5d040907972b672ebdef5fe66403"
    );
    assert_eq!(base.coordinator().identity().as_bytes(), base.profile_id().as_bytes());

    let rotated_sources = source_configuration(2, WITNESS_NODE, [0x42; 32], PRIMARY_NODE, [0x41; 32]);
    let rotated = LedgerCometClientConfig::new(
        custom_coordinator_config(
            [0x77; 32],
            test_chain(),
            test_policy(),
            rotated_sources,
            Duration::from_secs(1),
            1024 * 1024,
            8,
        ),
        rpc.clone(),
        default_client_limits(),
    )
    .expect("rotated");
    assert_eq!(base.profile_id(), rotated.profile_id());

    let mutations = [
        LedgerCometClientConfig::new(
            custom_coordinator_config(
                [0x77; 32],
                LedgerChainIdV2::new("other-ledger-regtest-2").expect("other chain"),
                test_policy(),
                sources.clone(),
                Duration::from_secs(1),
                1024 * 1024,
                8,
            ),
            rpc.clone(),
            default_client_limits(),
        )
        .expect("chain mutation"),
        LedgerCometClientConfig::new(
            custom_coordinator_config(
                [0x77; 32],
                test_chain(),
                FinalityPolicy::new(Duration::from_secs(601), Duration::from_secs(30), 4, 8, 1, 2)
                    .expect("policy mutation"),
                sources.clone(),
                Duration::from_secs(1),
                1024 * 1024,
                8,
            ),
            rpc.clone(),
            default_client_limits(),
        )
        .expect("policy mutation"),
        LedgerCometClientConfig::new(
            custom_coordinator_config(
                [0x77; 32],
                test_chain(),
                test_policy(),
                sources.clone(),
                Duration::from_secs(2),
                1024 * 1024,
                8,
            ),
            rpc.clone(),
            default_client_limits(),
        )
        .expect("busy mutation"),
        LedgerCometClientConfig::new(
            custom_coordinator_config(
                [0x77; 32],
                test_chain(),
                test_policy(),
                sources.clone(),
                Duration::from_secs(1),
                1024 * 1024 - 1,
                8,
            ),
            rpc.clone(),
            default_client_limits(),
        )
        .expect("execution mutation"),
        LedgerCometClientConfig::new(
            custom_coordinator_config(
                [0x77; 32],
                test_chain(),
                test_policy(),
                sources.clone(),
                Duration::from_secs(1),
                1024 * 1024,
                9,
            ),
            rpc.clone(),
            default_client_limits(),
        )
        .expect("history mutation"),
        LedgerCometClientConfig::new(
            profile_policy(
                FinalityPolicy::new(Duration::from_secs(600), Duration::from_secs(31), 4, 8, 1, 2)
                    .expect("drift policy"),
                Duration::from_secs(1),
                1024 * 1024,
                1024 * 1024,
                8 * 1024 * 1024,
                Duration::from_secs(3),
                8,
                64 * 1024 * 1024,
                8192,
            ),
            rpc.clone(),
            default_client_limits(),
        )
        .expect("clock drift mutation"),
        LedgerCometClientConfig::new(
            profile_policy(
                FinalityPolicy::new(Duration::from_secs(600), Duration::from_secs(30), 5, 8, 1, 2)
                    .expect("validator policy"),
                Duration::from_secs(1),
                1024 * 1024,
                1024 * 1024,
                8 * 1024 * 1024,
                Duration::from_secs(3),
                8,
                64 * 1024 * 1024,
                8192,
            ),
            rpc.clone(),
            default_client_limits(),
        )
        .expect("validator mutation"),
        LedgerCometClientConfig::new(
            profile_policy(
                FinalityPolicy::new(Duration::from_secs(600), Duration::from_secs(30), 4, 9, 1, 2)
                    .expect("adjacent policy"),
                Duration::from_secs(1),
                1024 * 1024,
                1024 * 1024,
                8 * 1024 * 1024,
                Duration::from_secs(3),
                8,
                64 * 1024 * 1024,
                8192,
            ),
            rpc.clone(),
            default_client_limits(),
        )
        .expect("adjacent mutation"),
        LedgerCometClientConfig::new(
            profile_policy(
                FinalityPolicy::new(Duration::from_secs(600), Duration::from_secs(30), 4, 8, 1, 3)
                    .expect("witness policy"),
                Duration::from_secs(1),
                1024 * 1024,
                1024 * 1024,
                8 * 1024 * 1024,
                Duration::from_secs(3),
                8,
                64 * 1024 * 1024,
                8192,
            ),
            rpc.clone(),
            default_client_limits(),
        )
        .expect("witness mutation"),
        LedgerCometClientConfig::new(
            profile_policy(
                test_policy(),
                Duration::from_secs(1),
                1024 * 1024 - 1,
                1024 * 1024,
                8 * 1024 * 1024,
                Duration::from_secs(3),
                8,
                64 * 1024 * 1024,
                8192,
            ),
            rpc.clone(),
            default_client_limits(),
        )
        .expect("trace mutation"),
        LedgerCometClientConfig::new(
            profile_policy(
                test_policy(),
                Duration::from_secs(1),
                1024 * 1024,
                1024 * 1024,
                7 * 1024 * 1024,
                Duration::from_secs(3),
                8,
                64 * 1024 * 1024,
                8192,
            ),
            rpc.clone(),
            default_client_limits(),
        )
        .expect("proof mutation"),
        LedgerCometClientConfig::new(
            profile_policy(
                test_policy(),
                Duration::from_secs(1),
                1024 * 1024,
                1024 * 1024,
                8 * 1024 * 1024,
                Duration::from_secs(4),
                8,
                64 * 1024 * 1024,
                8192,
            ),
            rpc.clone(),
            default_client_limits(),
        )
        .expect("operation timeout mutation"),
        LedgerCometClientConfig::new(
            profile_policy(
                test_policy(),
                Duration::from_secs(1),
                1024 * 1024,
                1024 * 1024,
                8 * 1024 * 1024,
                Duration::from_secs(3),
                8,
                65 * 1024 * 1024,
                8192,
            ),
            rpc.clone(),
            default_client_limits(),
        )
        .expect("history proof mutation"),
        LedgerCometClientConfig::new(
            profile_policy(
                test_policy(),
                Duration::from_secs(1),
                1024 * 1024,
                1024 * 1024,
                8 * 1024 * 1024,
                Duration::from_secs(3),
                8,
                64 * 1024 * 1024,
                8193,
            ),
            rpc.clone(),
            default_client_limits(),
        )
        .expect("history request mutation"),
        LedgerCometClientConfig::new(
            base_coordinator.clone(),
            rpc.clone(),
            LedgerCometClientLimits::new(7, 7, 64 * 1024 * 1024, Duration::from_secs(2)).expect("range mutation"),
        )
        .expect("client range mutation"),
        LedgerCometClientConfig::new(
            base_coordinator.clone(),
            rpc.clone(),
            LedgerCometClientLimits::new(8, 6, 64 * 1024 * 1024, Duration::from_secs(2)).expect("scan mutation"),
        )
        .expect("client scan mutation"),
        LedgerCometClientConfig::new(
            base_coordinator.clone(),
            rpc.clone(),
            LedgerCometClientLimits::new(8, 7, 63 * 1024 * 1024, Duration::from_secs(2)).expect("scan bytes mutation"),
        )
        .expect("client scan bytes mutation"),
        LedgerCometClientConfig::new(
            base_coordinator.clone(),
            rpc.clone(),
            LedgerCometClientLimits::new(8, 7, 64 * 1024 * 1024, Duration::from_secs(3)).expect("RPC timeout mutation"),
        )
        .expect("client timeout mutation"),
        LedgerCometClientConfig::new(
            custom_coordinator_config(
                [0x77; 32],
                test_chain(),
                test_policy(),
                sources,
                Duration::from_secs(1),
                1024 * 1024,
                8,
            ),
            rpc_config(vec![
                RpcPeer::RegtestLoopback(
                    LoopbackHttpPeer::new_regtest(
                        "http://127.0.0.1:28003",
                        NodeId::from_str(PRIMARY_NODE).expect("primary"),
                        [0x41; 32],
                    )
                    .expect("primary peer"),
                ),
                RpcPeer::RegtestLoopback(
                    LoopbackHttpPeer::new_regtest(
                        "http://127.0.0.1:28002",
                        NodeId::from_str(WITNESS_NODE).expect("witness"),
                        [0x42; 32],
                    )
                    .expect("witness peer"),
                ),
            ]),
            default_client_limits(),
        )
        .expect("RPC profile mutation"),
    ];
    for mutation in mutations {
        assert_ne!(mutation.profile_id(), base.profile_id());
    }
    let insufficient_requests = LedgerCoordinatorPolicyV2::new(
        test_chain(),
        test_policy(),
        source_configuration(1, PRIMARY_NODE, [0x41; 32], WITNESS_NODE, [0x42; 32]),
        Duration::from_secs(1),
        CoordinatorLimits::new(1024 * 1024, 1024 * 1024, 8 * 1024 * 1024, Duration::from_secs(3), 1).expect("limits"),
        HistoryEpochLimits::new(8, 64 * 1024 * 1024, 7168).expect("insufficient history"),
    );
    assert!(LedgerCometClientConfig::new(
        insufficient_requests,
        deterministic_rpc_config(),
        default_client_limits(),
    )
    .is_err());
    assert!(LedgerCometClientLimits::new(8, 8, 63 * 1024 * 1024, Duration::from_secs(2),).is_ok());
    let insufficient_locator = LedgerCometClientLimits::new(8, 8, 63 * 1024 * 1024, Duration::from_secs(2))
        .expect("shape-valid locator limits");
    assert!(LedgerCometClientConfig::new(
        custom_coordinator_config(
            [0x77; 32],
            test_chain(),
            test_policy(),
            source_configuration(1, PRIMARY_NODE, [0x41; 32], WITNESS_NODE, [0x42; 32]),
            Duration::from_secs(1),
            1024 * 1024,
            8,
        ),
        deterministic_rpc_config(),
        insufficient_locator,
    )
    .is_err());
}

#[tokio::test]
async fn wrong_range_root_source_and_reopen_profile_fail_closed() {
    let fixture = Arc::new(build_network_fixture());
    let primary = MockCometServer::start(Arc::clone(&fixture), PRIMARY_NODE, MODE_WRONG_RANGE)
        .await
        .expect("primary");
    let witness = MockCometServer::start(Arc::clone(&fixture), WITNESS_NODE, MODE_GOOD)
        .await
        .expect("witness");
    let sources = source_configuration(1, PRIMARY_NODE, [0x41; 32], WITNESS_NODE, [0x42; 32]);
    let rpc = rpc_config(vec![
        rpc_peer(&primary, PRIMARY_NODE, [0x41; 32]),
        rpc_peer(&witness, WITNESS_NODE, [0x42; 32]),
    ]);
    let config = client_config(sources.clone(), rpc.clone(), default_client_limits());
    let directory = private_directory();
    let wrong_path = directory.path().join("wrong-range.sqlite");
    let mut wrong_client = LedgerCometClient::create(
        &wrong_path,
        config.clone(),
        fixture.root.clone(),
        MemoryCheckpointStore::default(),
    )
    .await
    .expect("wrong-range client");
    assert!(prepare_and_finalize(&mut wrong_client, &full_range_request(&fixture))
        .await
        .is_err());
    assert_eq!(wrong_client.current_trust_root().expect("root").height(), 1);

    let missing_witness_rpc = rpc_config(vec![rpc_peer(&primary, PRIMARY_NODE, [0x41; 32])]);
    let coordinator = custom_coordinator_config(
        [0x77; 32],
        test_chain(),
        test_policy(),
        sources,
        Duration::from_secs(1),
        1024 * 1024,
        8,
    );
    assert!(LedgerCometClientConfig::new(coordinator, missing_witness_rpc, default_client_limits(),).is_err());

    let wrong_policy =
        FinalityPolicy::new(Duration::from_secs(601), Duration::from_secs(30), 4, 8, 1, 2).expect("wrong policy");
    let wrong_root = PinnedTrustRoot::new(
        fixture.root.light_block().clone(),
        &test_chain(),
        1,
        *fixture.root.header_hash(),
        wrong_policy,
    )
    .expect("wrong root");
    assert!(LedgerCometClient::create(
        directory.path().join("wrong-root.sqlite"),
        config.clone(),
        wrong_root,
        MemoryCheckpointStore::default(),
    )
    .await
    .is_err());

    primary.set_mode(MODE_GOOD);
    let profile_path = directory.path().join("profile.sqlite");
    let checkpoint = MemoryCheckpointStore::default();
    let mut client = LedgerCometClient::create(&profile_path, config.clone(), fixture.root.clone(), checkpoint.clone())
        .await
        .expect("profile client");
    let first_request = ExecutionRangeRequestV2::new(
        ExecutionRangeCursorV2::new(test_chain(), 1, AppHashV2::zero()).expect("cursor"),
        1,
        MAX_EXECUTION_RANGE_ENCODED_BYTES,
    )
    .expect("request");
    prepare_and_finalize(&mut client, &first_request)
        .await
        .expect("finalize");
    let reference = client.finalized_entry(1, 0).expect("entry").reference().clone();
    drop(client);
    let drifted = LedgerCometClientConfig::new(
        custom_coordinator_config(
            [0x77; 32],
            test_chain(),
            test_policy(),
            source_configuration(1, PRIMARY_NODE, [0x41; 32], WITNESS_NODE, [0x42; 32]),
            Duration::from_secs(1),
            1024 * 1024,
            8,
        ),
        config.rpc().clone(),
        LedgerCometClientLimits::new(7, 7, 64 * 1024 * 1024, Duration::from_secs(2)).expect("drift limits"),
    )
    .expect("drift config");
    let _ = reference;
    assert!(LedgerCometClient::open(&profile_path, drifted, checkpoint)
        .await
        .is_err());
}

#[tokio::test]
#[ignore = "requires an explicit local finalized CometBFT Ledger fixture"]
async fn optional_live_finalized_range_gate() {
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LivePeer {
        url: String,
        node_id: String,
        binding_hex: String,
    }
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LiveConfig {
        ledger_chain_id: String,
        root_height: u64,
        root_header_hash_hex: String,
        root_light_block: LightBlock,
        start_height: u64,
        previous_app_hash_hex: String,
        block_count: u16,
        peers: Vec<LivePeer>,
    }
    let path = std::env::var_os("THUNDERBOLT_LEDGER_COMET_CLIENT_LIVE_CONFIG")
        .expect("set THUNDERBOLT_LEDGER_COMET_CLIENT_LIVE_CONFIG");
    let live: LiveConfig = serde_json::from_slice(&std::fs::read(path).expect("read config")).expect("decode config");
    assert!(live.peers.len() >= 2 && live.peers.len() <= 5);
    let chain = LedgerChainIdV2::new(live.ledger_chain_id).expect("chain");
    let mut peers = Vec::new();
    let mut identities = Vec::new();
    for peer in live.peers {
        let binding = decode_hex_32(&peer.binding_hex).expect("binding");
        let endpoint =
            LoopbackHttpPeer::new_regtest(&peer.url, NodeId::from_str(&peer.node_id).expect("node"), binding)
                .expect("peer");
        identities.push(endpoint.identity().clone());
        peers.push(RpcPeer::RegtestLoopback(endpoint));
    }
    let sources = SourceConfiguration::new(1, identities[0].clone(), vec![identities[1].clone()]).expect("sources");
    let rpc = rpc_config(peers);
    let coordinator = LedgerCoordinatorPolicyV2::new(
        chain.clone(),
        test_policy(),
        sources,
        Duration::from_secs(1),
        CoordinatorLimits::new(
            8 * 1024 * 1024,
            32 * 1024 * 1024,
            64 * 1024 * 1024,
            Duration::from_secs(120),
            1,
        )
        .expect("limits"),
        HistoryEpochLimits::new(8, 64 * 1024 * 1024, 8192).expect("history"),
    );
    let client_config = LedgerCometClientConfig::new(
        coordinator,
        rpc,
        LedgerCometClientLimits::new(8, 1, 64 * 1024 * 1024, Duration::from_secs(120)).expect("client limits"),
    )
    .expect("client config");
    let root = PinnedTrustRoot::new(
        live.root_light_block,
        &chain,
        live.root_height,
        decode_hex_32(&live.root_header_hash_hex).expect("root hash"),
        test_policy(),
    )
    .expect("root");
    let directory = private_directory();
    let mut client = LedgerCometClient::create(
        directory.path().join("live.sqlite"),
        client_config,
        root,
        MemoryCheckpointStore::default(),
    )
    .await
    .expect("live client");
    let request = ExecutionRangeRequestV2::new(
        ExecutionRangeCursorV2::new(
            chain,
            live.start_height,
            AppHashV2::from_bytes(decode_hex_32(&live.previous_app_hash_hex).expect("previous"))
                .expect("previous hash"),
        )
        .expect("cursor"),
        live.block_count,
        MAX_EXECUTION_RANGE_ENCODED_BYTES,
    )
    .expect("request");
    let finalized = prepare_and_finalize(&mut client, &request)
        .await
        .expect("finalized range");
    assert_eq!(finalized.blocks().len(), usize::from(live.block_count));
}

fn decode_hex_32(value: &str) -> Option<[u8; 32]> {
    if value.len() != 64 {
        return None;
    }
    hex::decode(value).ok()?.try_into().ok()
}
