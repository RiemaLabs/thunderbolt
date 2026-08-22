use core::num::NonZeroU8;
use core::time::Duration;
use std::collections::BTreeMap;
use std::error::Error;
use std::io::Cursor;
use std::net::{Ipv4Addr, SocketAddr};
use std::str::FromStr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine as _;
use bitcoin::Network;
use ed25519_consensus::SigningKey;
use rcgen::{BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair, KeyUsagePurpose};
use rustls::client::ResolvesClientCert;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::sign::CertifiedKey;
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
    AdvanceOutcome, CheckpointFuture, CoordinatorConfig, CoordinatorLimits, FetchedTrace, HistoryEpochLimits,
    PeerIdentity, SourceConfiguration, TraceFetchRequest, TraceFuture, TraceTransport, TrustCheckpoint,
    TrustCheckpointCasOutcome, TrustCheckpointStore, TrustCoordinator, TrustCoordinatorIdentity,
};
use thunderbolt_ledger::{
    ActorKeyAlgorithmV2, ActorPublicKeyV2, ActorRoleV2, ActorSignatureV2, AppHashV2, CanonicalEventV2,
    ClientRequestNonceV2, EntryHashV2, ExecutedBlockV2, LedgerChainIdV2, PendingBlockV2, ProposalBodyV2,
    SignedProposalV2,
};
use thunderbolt_ledger_abci::{ABCI_CODESPACE, QUERY_BLOCK_PATH};
use thunderbolt_wire::{
    AnchorParameterSuiteIdV2, BitcoinGenesisHashV2, ChannelBindingV2, CommitteeDescriptorDigestV2, FundingOutpointV2,
    ProtocolSuiteIdV2,
};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

use crate::rpc::{fetch_trace, RpcFetchSpec, RuntimePeer};
use crate::transport::TestEvidenceFault;
use crate::{
    BroadcastAdmissionV2, ClientIdentityBinding, ClientIdentityProvider, CometBftRpcTransport, HttpsPeer,
    LedgerAbciQueryV2, LedgerRpcLimits, LoopbackHttpPeer, RetryPolicy, RpcLimits, RpcPeer, RpcPeerAuthenticator,
    RpcTransportConfig, RpcTransportError,
};

const CHAIN_ID: &str = "thunderbolt-rpc-regtest-2";
const NODE_ID: &str = "2222222222222222222222222222222222222222";

#[derive(Clone, Copy, Debug)]
enum Behavior {
    Good,
    WrongNode,
    WrongChain,
    WrongHeight,
    BadPage,
    ChangingTotal,
    EmptyPage,
    OverTotal,
    AddressKeyMismatch,
    LongValidatorName,
    RetryStatus,
    TruncateOnce,
    WrongContentType,
    Oversize,
    ChunkedOversize,
    ExcessiveHeaders,
    Padding,
    Redirect,
    WrongId,
    ExcessivePower,
    Hang,
    TamperedCommit,
    BroadcastReject,
    WrongTxHash,
    DropBroadcastRequest,
    TruncateBroadcast,
    HangBroadcast,
    BroadcastStatus,
    WrongOperationId,
    RetryAbci,
    WrongQueryHeight,
    WrongQueryKey,
    WrongQueryValue,
    ChunkedOversizeQuery,
    HangQuery,
}

struct RpcFixture {
    headers: BTreeMap<u64, SignedHeader>,
    validators: Vec<ValidatorInfo>,
    root: PinnedTrustRoot,
    execution: ExecutedBlockV2,
}

struct MockServer {
    address: SocketAddr,
    calls: Arc<AtomicUsize>,
    connections: Arc<AtomicUsize>,
    task: tokio::task::JoinHandle<()>,
}

struct ActiveConnection(Arc<AtomicUsize>);

impl Drop for ActiveConnection {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

struct MockTlsServer {
    address: SocketAddr,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for MockTlsServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl MockTlsServer {
    async fn start(
        fixture: Arc<RpcFixture>,
        config: Arc<rustls::ServerConfig>,
    ) -> std::result::Result<Self, Box<dyn Error>> {
        Self::start_with_node_and_behavior(fixture, config, NODE_ID.to_owned(), Behavior::Good).await
    }

    async fn start_with_behavior(
        fixture: Arc<RpcFixture>,
        config: Arc<rustls::ServerConfig>,
        behavior: Behavior,
    ) -> std::result::Result<Self, Box<dyn Error>> {
        Self::start_with_node_and_behavior(fixture, config, NODE_ID.to_owned(), behavior).await
    }

    async fn start_with_node(
        fixture: Arc<RpcFixture>,
        config: Arc<rustls::ServerConfig>,
        node_id: String,
    ) -> std::result::Result<Self, Box<dyn Error>> {
        Self::start_with_node_and_behavior(fixture, config, node_id, Behavior::Good).await
    }

    async fn start_with_node_and_behavior(
        fixture: Arc<RpcFixture>,
        config: Arc<rustls::ServerConfig>,
        node_id: String,
        behavior: Behavior,
    ) -> std::result::Result<Self, Box<dyn Error>> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let task = tokio::spawn(async move {
            let acceptor = TlsAcceptor::from(config);
            while let Ok((stream, _)) = listener.accept().await {
                let acceptor = acceptor.clone();
                let fixture = Arc::clone(&fixture);
                let node_id = node_id.clone();
                tokio::spawn(async move {
                    if let Ok(tls) = acceptor.accept(stream).await {
                        let _ = serve_connection(tls, fixture, behavior, Arc::new(AtomicUsize::new(0)), &node_id).await;
                    }
                });
            }
        });
        Ok(Self { address, task })
    }

    fn url(&self) -> String {
        format!("https://localhost:{}", self.address.port())
    }
}

#[derive(Clone)]
struct TestIdentityProvider {
    resolver: Arc<dyn ResolvesClientCert>,
    certificates: Vec<CertificateDer<'static>>,
    certified_public_key_spki: Vec<u8>,
}

impl ClientIdentityProvider for TestIdentityProvider {
    fn binding(&self, peer: &PeerIdentity) -> crate::Result<ClientIdentityBinding> {
        ClientIdentityBinding::new(
            peer,
            &self.certificates,
            &self.certified_public_key_spki,
            Arc::clone(&self.resolver),
        )
    }
}

#[derive(Clone)]
struct ZeroProfileProvider {
    resolver: Arc<dyn ResolvesClientCert>,
}

impl ClientIdentityProvider for ZeroProfileProvider {
    fn binding(&self, _peer: &PeerIdentity) -> crate::Result<ClientIdentityBinding> {
        Ok(ClientIdentityBinding {
            expected_profile: [0_u8; 32],
            resolver: Arc::clone(&self.resolver),
        })
    }
}

struct TestResolver {
    key: Arc<CertifiedKey>,
}

impl std::fmt::Debug for TestResolver {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("TestResolver([redacted])")
    }
}

impl ResolvesClientCert for TestResolver {
    fn resolve(
        &self,
        _root_hint_subjects: &[&[u8]],
        _sigschemes: &[rustls::SignatureScheme],
    ) -> Option<Arc<CertifiedKey>> {
        Some(Arc::clone(&self.key))
    }

    fn has_certs(&self) -> bool {
        true
    }
}

struct TlsMaterial {
    ca: CertificateDer<'static>,
    server_certificate: CertificateDer<'static>,
    server_key: Vec<u8>,
    client_provider: TestIdentityProvider,
    client_certified: Arc<CertifiedKey>,
}

struct RotatingResolver {
    key: Arc<Mutex<Arc<CertifiedKey>>>,
}

impl std::fmt::Debug for RotatingResolver {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("RotatingResolver([redacted])")
    }
}

impl ResolvesClientCert for RotatingResolver {
    fn resolve(
        &self,
        _root_hint_subjects: &[&[u8]],
        _sigschemes: &[rustls::SignatureScheme],
    ) -> Option<Arc<CertifiedKey>> {
        self.key.lock().ok().map(|key| Arc::clone(&key))
    }

    fn has_certs(&self) -> bool {
        true
    }
}

#[derive(Clone)]
struct ForgedEvidenceTransport {
    fixture: Arc<RpcFixture>,
    fault: TestEvidenceFault,
}

impl TraceTransport for ForgedEvidenceTransport {
    type Evidence = crate::RpcSessionEvidence;
    type Body = Cursor<Vec<u8>>;
    type Error = RpcTransportError;

    fn fetch<'a>(
        &'a self,
        peer: &'a PeerIdentity,
        request: &'a TraceFetchRequest,
    ) -> TraceFuture<'a, FetchedTrace<Self::Body, Self::Evidence>, Self::Error> {
        Box::pin(async move {
            let validators = ValidatorSet::without_proposer(self.fixture.validators.clone());
            let mut blocks = Vec::with_capacity(request.max_blocks());
            for height in request.first_height()..=request.last_height() {
                let signed_header = self
                    .fixture
                    .headers
                    .get(&height)
                    .cloned()
                    .ok_or(RpcTransportError::Height)?;
                blocks.push(LightBlock::new(
                    signed_header,
                    validators.clone(),
                    validators.clone(),
                    peer.node_id(),
                ));
            }
            let encoded = serde_json::to_vec(&blocks).map_err(|_| RpcTransportError::Json)?;
            let evidence =
                crate::RpcSessionEvidence::fixture_with_fault(peer, request, &blocks, encoded.len(), self.fault)?;
            Ok(FetchedTrace::new(Cursor::new(encoded), evidence))
        })
    }
}

#[derive(Clone, Default)]
struct MemoryCheckpointStore {
    value: Arc<Mutex<Option<TrustCheckpoint>>>,
}

impl TrustCheckpointStore for MemoryCheckpointStore {
    type Error = &'static str;

    fn load_checkpoint<'a>(
        &'a self,
        _identity: TrustCoordinatorIdentity,
    ) -> CheckpointFuture<'a, Option<TrustCheckpoint>, Self::Error> {
        Box::pin(async move { self.value.lock().map(|guard| *guard).map_err(|_| "checkpoint lock") })
    }

    fn compare_and_swap_checkpoint<'a>(
        &'a self,
        _identity: TrustCoordinatorIdentity,
        expected: Option<TrustCheckpoint>,
        next: TrustCheckpoint,
    ) -> CheckpointFuture<'a, TrustCheckpointCasOutcome, Self::Error> {
        Box::pin(async move {
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

impl Drop for MockServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl MockServer {
    async fn start(fixture: Arc<RpcFixture>, behavior: Behavior) -> std::result::Result<Self, Box<dyn Error>> {
        Self::start_with_node(fixture, behavior, NODE_ID.to_owned()).await
    }

    async fn start_with_node(
        fixture: Arc<RpcFixture>,
        behavior: Behavior,
        node_id: String,
    ) -> std::result::Result<Self, Box<dyn Error>> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let calls = Arc::new(AtomicUsize::new(0));
        let connections = Arc::new(AtomicUsize::new(0));
        let task_calls = Arc::clone(&calls);
        let task_connections = Arc::clone(&connections);
        let task = tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let fixture = Arc::clone(&fixture);
                let calls = Arc::clone(&task_calls);
                let connections = Arc::clone(&task_connections);
                let node_id = node_id.clone();
                tokio::spawn(async move {
                    connections.fetch_add(1, Ordering::SeqCst);
                    let _active = ActiveConnection(connections);
                    let _ = serve_connection(stream, fixture, behavior, calls, &node_id).await;
                });
            }
        });
        Ok(Self {
            address,
            calls,
            connections,
            task,
        })
    }

    fn url(&self) -> String {
        format!("http://127.0.0.1:{}", self.address.port())
    }
}

async fn serve_connection<S>(
    mut stream: S,
    fixture: Arc<RpcFixture>,
    behavior: Behavior,
    calls: Arc<AtomicUsize>,
    node_id: &str,
) -> std::io::Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    loop {
        if matches!(behavior, Behavior::DropBroadcastRequest) && calls.load(Ordering::SeqCst) == 1 {
            read_partial_rpc_request(&mut stream).await?;
            calls.fetch_add(1, Ordering::SeqCst);
            return Ok(());
        }
        let Some(request) = read_rpc_request(&mut stream).await? else {
            return Ok(());
        };
        let call = calls.fetch_add(1, Ordering::SeqCst);
        if matches!(behavior, Behavior::RetryStatus) && call == 0 {
            write_response(&mut stream, 503, "application/json", b"{}", false).await?;
            continue;
        }
        if matches!(behavior, Behavior::Redirect) {
            write_response(&mut stream, 302, "application/json", b"{}", false).await?;
            continue;
        }
        if matches!(behavior, Behavior::Hang) {
            let mut probe = [0_u8; 1];
            let _ = stream.read(&mut probe).await?;
            return Ok(());
        }
        if matches!(behavior, Behavior::HangBroadcast) && request.method == "broadcast_tx_sync" {
            let mut probe = [0_u8; 1];
            let _ = stream.read(&mut probe).await?;
            return Ok(());
        }
        if matches!(behavior, Behavior::HangQuery) && request.method == "abci_query" {
            let mut probe = [0_u8; 1];
            let _ = stream.read(&mut probe).await?;
            return Ok(());
        }
        if matches!(behavior, Behavior::ChunkedOversize)
            || (matches!(behavior, Behavior::ChunkedOversizeQuery) && request.method == "abci_query")
        {
            write_chunked_oversize(&mut stream).await?;
            continue;
        }
        if matches!(behavior, Behavior::ExcessiveHeaders) {
            write_excessive_headers(&mut stream).await?;
            continue;
        }
        let body = response_body(&fixture, behavior, &request, node_id);
        let content_type = if matches!(behavior, Behavior::WrongContentType) {
            "text/plain"
        } else {
            "application/json; charset=utf-8"
        };
        if matches!(behavior, Behavior::Oversize) {
            let oversized = vec![b'x'; 1_048_577];
            write_response(&mut stream, 200, content_type, &oversized, false).await?;
            continue;
        }
        if (matches!(behavior, Behavior::TruncateOnce) && call == 0)
            || (matches!(behavior, Behavior::TruncateBroadcast) && request.method == "broadcast_tx_sync")
        {
            write_response(&mut stream, 200, content_type, &body, true).await?;
            return Ok(());
        }
        if matches!(behavior, Behavior::BroadcastStatus) && request.method == "broadcast_tx_sync" {
            write_response(&mut stream, 503, content_type, b"{}", false).await?;
            continue;
        }
        if matches!(behavior, Behavior::RetryAbci) && request.method == "abci_query" && call == 1 {
            write_response(&mut stream, 503, content_type, b"{}", false).await?;
            continue;
        }
        write_response(&mut stream, 200, content_type, &body, false).await?;
    }
}

async fn read_partial_rpc_request<S>(stream: &mut S) -> std::io::Result<()>
where
    S: tokio::io::AsyncRead + Unpin,
{
    let mut header = Vec::new();
    let mut byte = [0_u8; 1];
    while !header.ends_with(b"\r\n\r\n") {
        if stream.read(&mut byte).await? == 0 {
            return Err(std::io::Error::other("truncated partial request header"));
        }
        header.push(byte[0]);
        if header.len() > 16 * 1024 {
            return Err(std::io::Error::other("partial request header too large"));
        }
    }
    if stream.read(&mut byte).await? == 0 {
        return Err(std::io::Error::other("partial request body missing"));
    }
    Ok(())
}

struct MockRpcRequest {
    id: u64,
    method: String,
    params: serde_json::Value,
}

async fn read_rpc_request<S>(stream: &mut S) -> std::io::Result<Option<MockRpcRequest>>
where
    S: tokio::io::AsyncRead + Unpin,
{
    let mut bytes = Vec::new();
    let mut buffer = [0_u8; 1_024];
    loop {
        let count = stream.read(&mut buffer).await?;
        if count == 0 {
            return Ok(None);
        }
        bytes.extend_from_slice(&buffer[..count]);
        if bytes.windows(4).any(|window| window == b"\r\n\r\n") {
            break;
        }
        if bytes.len() > 16 * 1_024 {
            return Ok(None);
        }
    }
    let header_end = bytes
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|position| position + 4)
        .ok_or_else(|| std::io::Error::other("missing HTTP header terminator"))?;
    let headers = std::str::from_utf8(&bytes[..header_end]).map_err(std::io::Error::other)?;
    let method = headers
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().next())
        .ok_or_else(|| std::io::Error::other("missing HTTP method"))?;
    if method != "POST" {
        return Err(std::io::Error::other("expected JSON-RPC POST"));
    }
    let content_length = headers
        .lines()
        .find_map(|line| {
            line.split_once(':').and_then(|(name, value)| {
                name.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse::<usize>().ok())
                    .flatten()
            })
        })
        .ok_or_else(|| std::io::Error::other("missing content length"))?;
    if content_length > crate::rpc::MAX_RPC_REQUEST_BYTES {
        return Err(std::io::Error::other("request body too large"));
    }
    while bytes.len().saturating_sub(header_end) < content_length {
        let count = stream.read(&mut buffer).await?;
        if count == 0 {
            return Err(std::io::Error::other("truncated request body"));
        }
        bytes.extend_from_slice(&buffer[..count]);
    }
    let request: serde_json::Value = serde_json::from_slice(
        bytes
            .get(header_end..header_end + content_length)
            .ok_or_else(|| std::io::Error::other("request body bounds"))?,
    )
    .map_err(std::io::Error::other)?;
    Ok(Some(MockRpcRequest {
        id: request
            .get("id")
            .and_then(serde_json::Value::as_u64)
            .ok_or_else(|| std::io::Error::other("missing JSON-RPC id"))?,
        method: request
            .get("method")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| std::io::Error::other("missing JSON-RPC method"))?
            .to_owned(),
        params: request
            .get("params")
            .cloned()
            .ok_or_else(|| std::io::Error::other("missing JSON-RPC params"))?,
    }))
}

async fn write_response<S>(
    stream: &mut S,
    status: u16,
    content_type: &str,
    body: &[u8],
    truncate: bool,
) -> std::io::Result<()>
where
    S: tokio::io::AsyncWrite + Unpin,
{
    let reason = if status == 200 { "OK" } else { "Service Unavailable" };
    let header = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: keep-alive\r\n\r\n",
        body.len()
    );
    stream.write_all(header.as_bytes()).await?;
    let body = if truncate { &body[..body.len() / 2] } else { body };
    stream.write_all(body).await?;
    stream.flush().await
}

async fn write_chunked_oversize<S>(stream: &mut S) -> std::io::Result<()>
where
    S: tokio::io::AsyncWrite + Unpin,
{
    stream
        .write_all(
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\nConnection: keep-alive\r\n\r\n",
        )
        .await?;
    let chunk = vec![b'x'; 64 * 1024];
    for _ in 0..17 {
        stream.write_all(b"10000\r\n").await?;
        stream.write_all(&chunk).await?;
        stream.write_all(b"\r\n").await?;
    }
    stream.write_all(b"0\r\n\r\n").await?;
    stream.flush().await
}

async fn write_excessive_headers<S>(stream: &mut S) -> std::io::Result<()>
where
    S: tokio::io::AsyncWrite + Unpin,
{
    stream
        .write_all(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\n")
        .await?;
    for index in 0..64 {
        stream
            .write_all(format!("X-Thunderbolt-{index}: bounded\r\n").as_bytes())
            .await?;
    }
    stream.write_all(b"\r\n{}").await?;
    stream.flush().await
}

fn response_body(
    fixture: &RpcFixture,
    behavior: Behavior,
    request: &MockRpcRequest,
    configured_node_id: &str,
) -> Vec<u8> {
    let mut result = if request.method == "status" {
        let node = if matches!(behavior, Behavior::WrongNode) {
            "3333333333333333333333333333333333333333"
        } else {
            configured_node_id
        };
        let chain = if matches!(behavior, Behavior::WrongChain) {
            "other-regtest"
        } else {
            CHAIN_ID
        };
        json!({
            "node_info": {"id": node, "network": chain},
            "sync_info": {"latest_block_height": "4"}
        })
    } else if request.method == "commit" {
        let requested = param_number(&request.params, "height").unwrap_or(0);
        let selected = if matches!(behavior, Behavior::WrongHeight) && requested == 2 {
            3
        } else {
            requested
        };
        let mut signed_header = fixture.headers.get(&selected).cloned();
        if matches!(behavior, Behavior::TamperedCommit) && selected == 3 {
            if let Some(signed) = signed_header.as_mut() {
                signed.header.app_hash = AppHash::try_from(vec![0x9a_u8; 32]).unwrap();
            }
        }
        json!({
            "signed_header": signed_header,
            "canonical": true
        })
    } else if request.method == "validators" {
        let height = param_number(&request.params, "height").unwrap_or(0);
        let page = param_number(&request.params, "page").unwrap_or(0);
        let per_page = usize::try_from(param_number(&request.params, "per_page").unwrap_or(0)).unwrap_or(0);
        let effective_page = if matches!(behavior, Behavior::BadPage) && page == 2 {
            1
        } else {
            page
        };
        let start = usize::try_from(effective_page.saturating_sub(1))
            .unwrap_or(usize::MAX)
            .saturating_mul(per_page);
        let end = start.saturating_add(per_page).min(fixture.validators.len());
        let values = fixture.validators.get(start..end).unwrap_or(&[]);
        let mut values = if matches!(behavior, Behavior::EmptyPage) && page == 2 {
            json!([])
        } else {
            serde_json::to_value(values).unwrap_or_else(|_| json!([]))
        };
        if matches!(behavior, Behavior::ExcessivePower) {
            if let Some(validators) = values.as_array_mut() {
                for validator in validators {
                    validator["power"] = json!(ValidatorSet::MAX_TOTAL_VOTING_POWER.to_string());
                }
            }
        }
        if matches!(behavior, Behavior::AddressKeyMismatch) {
            if let Some(validators) = values.as_array_mut() {
                for (offset, validator) in validators.iter_mut().enumerate() {
                    validator["address"] = json!(format!("{:040X}", start + offset + 1));
                }
            }
        }
        if matches!(behavior, Behavior::LongValidatorName) {
            if let Some(validators) = values.as_array_mut() {
                for validator in validators {
                    validator["name"] = json!("n".repeat(thunderbolt_cometbft::MAX_VALIDATOR_NAME_BYTES + 1));
                }
            }
        }
        let total = if matches!(behavior, Behavior::ChangingTotal) && page == 2 {
            fixture.validators.len() + 1
        } else if matches!(behavior, Behavior::OverTotal) {
            fixture.validators.len() - 1
        } else {
            fixture.validators.len()
        };
        json!({
            "block_height": height.to_string(),
            "validators": values,
            "count": values.as_array().map_or(0, Vec::len).to_string(),
            "total": total.to_string()
        })
    } else if request.method == "broadcast_tx_sync" {
        let transaction = request
            .params
            .get("tx")
            .and_then(serde_json::Value::as_str)
            .and_then(|encoded| BASE64_STANDARD.decode(encoded).ok())
            .unwrap_or_default();
        let proposal = serde_json::from_slice::<SignedProposalV2>(&transaction).ok();
        let mut transaction_hash: [u8; 32] = Sha256::digest(&transaction).into();
        if matches!(behavior, Behavior::WrongTxHash) {
            transaction_hash[0] ^= 1;
        }
        let rejected = matches!(behavior, Behavior::BroadcastReject);
        let data = if rejected {
            String::new()
        } else {
            proposal
                .as_ref()
                .and_then(|proposal| proposal.body().entry_hash().ok())
                .map(|hash| hex::encode_upper(hash.as_bytes()))
                .unwrap_or_default()
        };
        json!({
            "code": if rejected { "7" } else { "0" },
            "data": data,
            "log": if rejected { "rejected" } else { "" },
            "codespace": ABCI_CODESPACE,
            "hash": hex::encode_upper(transaction_hash),
        })
    } else if request.method == "abci_query" {
        let path = request
            .params
            .get("path")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default();
        let mut key = request
            .params
            .get("data")
            .and_then(serde_json::Value::as_str)
            .and_then(|encoded| hex::decode(encoded).ok())
            .unwrap_or_default();
        if matches!(behavior, Behavior::WrongQueryKey) {
            key.push(0xff);
        }
        let requested_height = param_number(&request.params, "height").unwrap_or(0);
        let height = if matches!(behavior, Behavior::WrongQueryHeight) {
            requested_height.saturating_add(1)
        } else {
            requested_height
        };
        let valid = path == QUERY_BLOCK_PATH
            && request.params.get("prove") == Some(&serde_json::Value::Bool(false))
            && requested_height == fixture.execution.height();
        let value = if matches!(behavior, Behavior::WrongQueryValue) {
            serde_json::to_vec(&json!({})).unwrap_or_default()
        } else if valid {
            serde_json::to_vec(&fixture.execution).unwrap_or_default()
        } else {
            Vec::new()
        };
        json!({
            "response": {
                "code": if valid { "0" } else { "2" },
                "log": if valid { "" } else { "invalid query" },
                "info": "",
                "index": "0",
                "key": BASE64_STANDARD.encode(key),
                "value": BASE64_STANDARD.encode(value),
                "proof_ops": null,
                "height": height.to_string(),
                "codespace": ABCI_CODESPACE,
            }
        })
    } else {
        json!({"unknown": request.method})
    };
    if matches!(behavior, Behavior::Padding) {
        if let Some(object) = result.as_object_mut() {
            object.insert("padding".to_owned(), json!("x".repeat(4 * 1024)));
        }
    }
    let id = if matches!(behavior, Behavior::WrongId)
        || (matches!(behavior, Behavior::WrongOperationId) && request.method != "status")
    {
        request.id.saturating_add(1)
    } else {
        request.id
    };
    serde_json::to_vec(&json!({"jsonrpc": "2.0", "id": id, "result": result})).unwrap_or_default()
}

fn param_number(params: &serde_json::Value, key: &str) -> Option<u64> {
    params
        .get(key)
        .and_then(serde_json::Value::as_str)
        .and_then(|value| value.parse().ok())
}

fn limits() -> RpcLimits {
    RpcLimits::new(
        1024 * 1024,
        8 * 1024 * 1024,
        8,
        4,
        NonZeroU8::new(2).unwrap(),
        16,
        16 * 1024,
    )
    .unwrap()
}

fn retry(attempts: u8) -> RetryPolicy {
    RetryPolicy::new(NonZeroU8::new(attempts).unwrap(), Duration::from_millis(1)).unwrap()
}

fn fetch_spec() -> RpcFetchSpec {
    RpcFetchSpec {
        ledger_chain_id: CHAIN_ID.to_owned(),
        first_height: 2,
        last_height: 3,
        max_blocks: 2,
        max_encoded_bytes: 1024 * 1024,
        deadline: Instant::now() + Duration::from_secs(5),
    }
}

fn runtime(url: &str) -> RuntimePeer {
    let peer = LoopbackHttpPeer::new_regtest(url, NodeId::from_str(NODE_ID).unwrap(), [0x44; 32]).unwrap();
    RuntimePeer::new(RpcPeer::RegtestLoopback(peer)).unwrap()
}

fn ledger_transport(url: &str, attempts: u8) -> (CometBftRpcTransport, PeerIdentity) {
    let peer = LoopbackHttpPeer::new_regtest(url, NodeId::from_str(NODE_ID).unwrap(), [0x44; 32]).unwrap();
    let identity = peer.identity().clone();
    let transport = CometBftRpcTransport::new(
        RpcTransportConfig::new(vec![RpcPeer::RegtestLoopback(peer)], limits(), retry(attempts)).unwrap(),
    )
    .unwrap();
    (transport, identity)
}

fn signed_ledger_proposal(discriminator: u8) -> SignedProposalV2 {
    let secp = Secp256k1::new();
    let mut secret_bytes = [0_u8; 32];
    secret_bytes[31] = discriminator.max(1);
    let secret = SecretKey::from_byte_array(secret_bytes).unwrap();
    let keypair = Keypair::from_secret_key(&secp, &secret);
    let (public_key, _) = keypair.x_only_public_key();
    let mut txid = [discriminator.max(1); 32];
    txid[31] ^= 0x5a;
    let binding = ChannelBindingV2::new(
        ProtocolSuiteIdV2::from_bytes([0x11; 32]).unwrap(),
        Network::Regtest,
        BitcoinGenesisHashV2::for_network(Network::Regtest).unwrap(),
        b"ledger-rpc-tests",
        FundingOutpointV2::new(txid, u32::from(discriminator)).unwrap(),
        1,
        CommitteeDescriptorDigestV2::from_bytes([0x22; 32]).unwrap(),
        AnchorParameterSuiteIdV2::from_bytes([0x33; 32]).unwrap(),
    )
    .unwrap();
    let body = ProposalBodyV2::new(
        LedgerChainIdV2::new(CHAIN_ID).unwrap(),
        binding,
        0,
        EntryHashV2::zero(),
        ClientRequestNonceV2::from_bytes([discriminator.max(1); 16]).unwrap(),
        ActorKeyAlgorithmV2::Bip340V1,
        ActorPublicKeyV2::from_bytes(public_key.serialize()).unwrap(),
        ActorRoleV2::Holder,
        thunderbolt_ledger::EventKindV2::Open,
        CanonicalEventV2::from_bytes(vec![0x41; 4 * 1024]).unwrap(),
    )
    .unwrap();
    let signature = secp.sign_schnorr_no_aux_rand(body.proposal_digest().unwrap().as_bytes(), &keypair);
    SignedProposalV2::new(body, ActorSignatureV2::from_bytes(signature.to_byte_array()).unwrap()).unwrap()
}

async fn wait_for_counter(counter: &AtomicUsize, expected: usize) {
    tokio::time::timeout(Duration::from_secs(1), async {
        while counter.load(Ordering::SeqCst) != expected {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .unwrap();
}

fn coordinator_config(root: &PinnedTrustRoot, sources: SourceConfiguration) -> CoordinatorConfig {
    CoordinatorConfig::new(
        TrustCoordinatorIdentity::new([0x77; 32]).unwrap(),
        LedgerChainIdV2::new(CHAIN_ID).unwrap(),
        root.policy(),
        sources,
        Duration::from_secs(1),
        CoordinatorLimits::new(1024 * 1024, 1024 * 1024, 8 * 1024 * 1024, Duration::from_secs(5), 1).unwrap(),
        HistoryEpochLimits::new(8, 8 * 1024 * 1024, 1_024).unwrap(),
    )
    .unwrap()
}

fn private_directory() -> tempfile::TempDir {
    let directory = tempfile::TempDir::new().unwrap();
    #[cfg(unix)]
    std::fs::set_permissions(
        directory.path(),
        <std::fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o700),
    )
    .unwrap();
    directory
}

#[tokio::test]
async fn loopback_rpc_fetches_complete_adjacent_trace() {
    let server = MockServer::start(Arc::new(build_fixture()), Behavior::Good)
        .await
        .unwrap();
    let fetched = fetch_trace(&runtime(&server.url()), &fetch_spec(), limits(), retry(1))
        .await
        .unwrap();
    assert_eq!(fetched.blocks.len(), 2);
    assert_eq!(fetched.blocks[0].height().value(), 2);
    assert_eq!(fetched.blocks[1].height().value(), 3);
    assert_ne!(fetched.transcript_digest, [0_u8; 32]);
    assert_eq!(server.calls.load(Ordering::SeqCst), 9);
}

#[tokio::test]
async fn coordinator_accepts_only_matching_transport_evidence() {
    let fixture = Arc::new(build_fixture());
    let root = fixture.root.clone();
    let execution = fixture.execution.clone();
    let primary_material = tls_material();
    let primary_server = MockTlsServer::start_with_node(
        Arc::clone(&fixture),
        server_config(&primary_material, true),
        NODE_ID.to_owned(),
    )
    .await
    .unwrap();
    let witness_node = "3333333333333333333333333333333333333333";
    let witness_material = tls_material();
    let witness_server = MockTlsServer::start_with_node(
        Arc::clone(&fixture),
        server_config(&witness_material, true),
        witness_node.to_owned(),
    )
    .await
    .unwrap();
    let primary = HttpsPeer::new(
        &primary_server.url(),
        NodeId::from_str(NODE_ID).unwrap(),
        crate::tls::spki_sha256(&primary_material.server_certificate).unwrap(),
        vec![primary_material.ca.clone()],
        &primary_material.client_provider,
    )
    .unwrap();
    let witness = HttpsPeer::new(
        &witness_server.url(),
        NodeId::from_str(witness_node).unwrap(),
        crate::tls::spki_sha256(&witness_material.server_certificate).unwrap(),
        vec![witness_material.ca.clone()],
        &witness_material.client_provider,
    )
    .unwrap();
    let source_configuration =
        SourceConfiguration::new(1, primary.identity().clone(), vec![witness.identity().clone()]).unwrap();
    let transport = CometBftRpcTransport::new(
        RpcTransportConfig::new(
            vec![RpcPeer::Https(primary), RpcPeer::Https(witness)],
            limits(),
            retry(1),
        )
        .unwrap(),
    )
    .unwrap();
    let config = CoordinatorConfig::new(
        TrustCoordinatorIdentity::new([0x77; 32]).unwrap(),
        LedgerChainIdV2::new(CHAIN_ID).unwrap(),
        root.policy(),
        source_configuration,
        Duration::from_secs(1),
        CoordinatorLimits::new(1024 * 1024, 1024 * 1024, 8 * 1024 * 1024, Duration::from_secs(5), 1).unwrap(),
        HistoryEpochLimits::new(8, 8 * 1024 * 1024, 1_024).unwrap(),
    )
    .unwrap();
    let directory = tempfile::TempDir::new().unwrap();
    #[cfg(unix)]
    std::fs::set_permissions(
        directory.path(),
        <std::fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o700),
    )
    .unwrap();
    let path = directory.path().join("coordinator.sqlite");
    let mut coordinator = TrustCoordinator::create(
        path,
        config,
        root,
        transport,
        RpcPeerAuthenticator,
        MemoryCheckpointStore::default(),
    )
    .await
    .unwrap();
    assert!(matches!(
        coordinator.advance(&execution).await.unwrap(),
        AdvanceOutcome::Applied(_)
    ));
}

#[tokio::test]
async fn coordinator_rejects_wrong_peer_request_and_trace_evidence() {
    let fixture = Arc::new(build_fixture());
    let primary = PeerIdentity::new([0x44; 32], NodeId::from_str(NODE_ID).unwrap()).unwrap();
    let witness = PeerIdentity::new(
        [0x55; 32],
        NodeId::from_str("3333333333333333333333333333333333333333").unwrap(),
    )
    .unwrap();
    let sources = SourceConfiguration::new(1, primary, vec![witness]).unwrap();
    for (index, fault) in [
        TestEvidenceFault::Binding,
        TestEvidenceFault::Request,
        TestEvidenceFault::Trace,
        TestEvidenceFault::ReplayedDeadline,
    ]
    .into_iter()
    .enumerate()
    {
        let config = CoordinatorConfig::new(
            TrustCoordinatorIdentity::new([u8::try_from(index + 0x81).unwrap(); 32]).unwrap(),
            LedgerChainIdV2::new(CHAIN_ID).unwrap(),
            fixture.root.policy(),
            sources.clone(),
            Duration::from_secs(1),
            CoordinatorLimits::new(1024 * 1024, 1024 * 1024, 8 * 1024 * 1024, Duration::from_secs(5), 1).unwrap(),
            HistoryEpochLimits::new(8, 8 * 1024 * 1024, 1_024).unwrap(),
        )
        .unwrap();
        let directory = private_directory();
        let mut coordinator = TrustCoordinator::create(
            directory.path().join("forged-evidence.sqlite"),
            config,
            fixture.root.clone(),
            ForgedEvidenceTransport {
                fixture: Arc::clone(&fixture),
                fault,
            },
            RpcPeerAuthenticator,
            MemoryCheckpointStore::default(),
        )
        .await
        .unwrap();
        assert!(coordinator.advance(&fixture.execution).await.is_err());
        assert_eq!(coordinator.current_trust_root().unwrap().height(), 1);
    }
}

#[tokio::test]
async fn tampered_commits_never_advance_coordinator_root() {
    let fixture = Arc::new(build_fixture());
    let root = fixture.root.clone();
    let execution = fixture.execution.clone();
    let primary_server =
        MockServer::start_with_node(Arc::clone(&fixture), Behavior::TamperedCommit, NODE_ID.to_owned())
            .await
            .unwrap();
    let witness_node = "3333333333333333333333333333333333333333";
    let witness_server =
        MockServer::start_with_node(Arc::clone(&fixture), Behavior::TamperedCommit, witness_node.to_owned())
            .await
            .unwrap();
    let primary =
        LoopbackHttpPeer::new_regtest(&primary_server.url(), NodeId::from_str(NODE_ID).unwrap(), [0x44; 32]).unwrap();
    let witness = LoopbackHttpPeer::new_regtest(
        &witness_server.url(),
        NodeId::from_str(witness_node).unwrap(),
        [0x55; 32],
    )
    .unwrap();
    let sources = SourceConfiguration::new(1, primary.identity().clone(), vec![witness.identity().clone()]).unwrap();
    let transport = CometBftRpcTransport::new(
        RpcTransportConfig::new(
            vec![RpcPeer::RegtestLoopback(primary), RpcPeer::RegtestLoopback(witness)],
            limits(),
            retry(1),
        )
        .unwrap(),
    )
    .unwrap();
    let config = coordinator_config(&root, sources);
    let directory = private_directory();
    let path = directory.path().join("tampered.sqlite");
    let mut coordinator = TrustCoordinator::create(
        path,
        config,
        root,
        transport,
        RpcPeerAuthenticator,
        MemoryCheckpointStore::default(),
    )
    .await
    .unwrap();
    assert!(coordinator.advance(&execution).await.is_err());
    assert_eq!(coordinator.current_trust_root().unwrap().height(), 1);
}

#[tokio::test]
async fn wrong_node_chain_height_and_page_fail_closed() {
    for (behavior, expected) in [
        (Behavior::WrongNode, "node"),
        (Behavior::WrongChain, "chain"),
        (Behavior::WrongHeight, "height"),
        (Behavior::BadPage, "page"),
    ] {
        let server = MockServer::start(Arc::new(build_fixture()), behavior).await.unwrap();
        let error = fetch_trace(&runtime(&server.url()), &fetch_spec(), limits(), retry(1))
            .await
            .unwrap_err();
        assert!(matches!(
            (&error, expected),
            (RpcTransportError::NodeIdentity, "node")
                | (RpcTransportError::ChainIdentity, "chain")
                | (RpcTransportError::Height, "height")
                | (RpcTransportError::Pagination, "page")
        ));
    }
}

#[tokio::test]
async fn validator_pagination_and_metadata_are_fully_bounded() {
    for (behavior, expected) in [
        (Behavior::ChangingTotal, "page"),
        (Behavior::EmptyPage, "page"),
        (Behavior::OverTotal, "page"),
        (Behavior::AddressKeyMismatch, "validator"),
        (Behavior::LongValidatorName, "validator"),
    ] {
        let server = MockServer::start(Arc::new(build_fixture()), behavior).await.unwrap();
        let error = fetch_trace(&runtime(&server.url()), &fetch_spec(), limits(), retry(3))
            .await
            .unwrap_err();
        assert!(
            matches!(
                (&error, expected),
                (RpcTransportError::Pagination, "page") | (RpcTransportError::ValidatorSet, "validator")
            ),
            "unexpected {error:?} for {behavior:?}/{expected}"
        );
    }
}

#[tokio::test]
async fn idempotent_reads_retry_status_and_truncation() {
    for behavior in [Behavior::RetryStatus, Behavior::TruncateOnce] {
        let server = MockServer::start(Arc::new(build_fixture()), behavior).await.unwrap();
        let fetched = fetch_trace(&runtime(&server.url()), &fetch_spec(), limits(), retry(2))
            .await
            .unwrap();
        assert_eq!(fetched.blocks.len(), 2);
        assert!(server.calls.load(Ordering::SeqCst) >= 10);
    }
}

#[tokio::test]
async fn content_type_and_oversize_fail_without_retry() {
    for (behavior, expected) in [
        (Behavior::WrongContentType, "content"),
        (Behavior::Oversize, "size"),
        (Behavior::ChunkedOversize, "size"),
    ] {
        let server = MockServer::start(Arc::new(build_fixture()), behavior).await.unwrap();
        let error = fetch_trace(&runtime(&server.url()), &fetch_spec(), limits(), retry(3))
            .await
            .unwrap_err();
        assert!(matches!(
            (&error, expected),
            (RpcTransportError::ContentType, "content") | (RpcTransportError::ResponseTooLarge, "size")
        ));
        assert_eq!(server.calls.load(Ordering::SeqCst), 1);
    }
}

#[tokio::test]
async fn redirect_wrong_id_and_power_overflow_fail_without_retry_or_panic() {
    for (behavior, expected) in [
        (Behavior::Redirect, "redirect"),
        (Behavior::WrongId, "id"),
        (Behavior::ExcessiveHeaders, "headers"),
        (Behavior::ExcessivePower, "power"),
    ] {
        let server = MockServer::start(Arc::new(build_fixture()), behavior).await.unwrap();
        let error = fetch_trace(&runtime(&server.url()), &fetch_spec(), limits(), retry(3))
            .await
            .unwrap_err();
        assert!(
            matches!(
                (&error, expected),
                (RpcTransportError::HttpStatus(302), "redirect")
                    | (RpcTransportError::Json, "id")
                    | (RpcTransportError::Json, "headers")
                    | (RpcTransportError::ValidatorSet, "power")
            ),
            "unexpected {error:?} for {expected}"
        );
        let expected_calls = if matches!(behavior, Behavior::ExcessivePower) {
            5
        } else {
            1
        };
        assert_eq!(server.calls.load(Ordering::SeqCst), expected_calls);
    }
}

#[tokio::test]
async fn aggregate_budget_and_shared_deadline_fail_closed() {
    let padded = MockServer::start(Arc::new(build_fixture()), Behavior::Padding)
        .await
        .unwrap();
    let small_aggregate = RpcLimits::new(8 * 1024, 24 * 1024, 8, 4, NonZeroU8::new(2).unwrap(), 16, 16 * 1024).unwrap();
    assert!(matches!(
        fetch_trace(&runtime(&padded.url()), &fetch_spec(), small_aggregate, retry(3)).await,
        Err(RpcTransportError::AggregateTooLarge)
    ));

    let hanging = MockServer::start(Arc::new(build_fixture()), Behavior::Hang)
        .await
        .unwrap();
    let mut deadline = fetch_spec();
    deadline.deadline = Instant::now() + Duration::from_millis(25);
    assert!(matches!(
        fetch_trace(&runtime(&hanging.url()), &deadline, limits(), retry(3)).await,
        Err(RpcTransportError::Deadline)
    ));
    assert_eq!(hanging.calls.load(Ordering::SeqCst), 1);
    wait_for_counter(&hanging.connections, 0).await;

    let cancelled = MockServer::start(Arc::new(build_fixture()), Behavior::Hang)
        .await
        .unwrap();
    let runtime = Arc::new(runtime(&cancelled.url()));
    let spec = fetch_spec();
    let task = tokio::spawn(async move { fetch_trace(&runtime, &spec, limits(), retry(3)).await });
    wait_for_counter(&cancelled.calls, 1).await;
    task.abort();
    let _ = task.await;
    wait_for_counter(&cancelled.connections, 0).await;
}

#[test]
fn plaintext_profile_rejects_nonliteral_or_nonloopback_hosts() {
    let node = NodeId::from_str(NODE_ID).unwrap();
    for url in [
        "http://localhost:26657",
        "http://192.0.2.1:26657",
        "https://127.0.0.1:26657",
        "http://127.0.0.1:26657/status",
        "http://user@127.0.0.1:26657",
    ] {
        assert!(LoopbackHttpPeer::new_regtest(url, node, [0x44; 32]).is_err());
    }
    let ipv6 = LoopbackHttpPeer::new_regtest("http://[::1]:26657", node, [0x44; 32]).unwrap();
    assert_eq!(ipv6.endpoint.host, "::1");
    assert_eq!(ipv6.endpoint.authority, "[::1]:26657");
}

#[test]
fn ledger_body_limits_are_explicit_and_independent_from_trace_limits() {
    let peer = LoopbackHttpPeer::new_regtest("http://127.0.0.1:26657", NodeId::from_str(NODE_ID).unwrap(), [0x44; 32])
        .unwrap();
    let inherited = RpcTransportConfig::new(vec![RpcPeer::RegtestLoopback(peer.clone())], limits(), retry(1)).unwrap();
    assert_eq!(inherited.ledger_limits().response_bytes(), limits().response_bytes());
    assert_eq!(inherited.ledger_limits().aggregate_bytes(), limits().aggregate_bytes());

    let ledger_limits = LedgerRpcLimits::new(33 * 1024 * 1024, 34 * 1024 * 1024).unwrap();
    let configured = RpcTransportConfig::new(vec![RpcPeer::RegtestLoopback(peer)], limits(), retry(1))
        .unwrap()
        .with_ledger_limits(ledger_limits);
    assert_eq!(configured.ledger_limits(), ledger_limits);
    assert!(LedgerRpcLimits::new(33 * 1024 * 1024 + 1, 34 * 1024 * 1024).is_err());
    assert!(LedgerRpcLimits::new(1024 * 1024, 1024 * 1024 - 1).is_err());
}

fn loopback_profile_config(
    url: &str,
    node: &str,
    binding: [u8; 32],
    rpc_limits: RpcLimits,
    retry_policy: RetryPolicy,
    ledger_limits: LedgerRpcLimits,
) -> RpcTransportConfig {
    let peer = LoopbackHttpPeer::new_regtest(url, NodeId::from_str(node).unwrap(), binding).unwrap();
    RpcTransportConfig::new(vec![RpcPeer::RegtestLoopback(peer)], rpc_limits, retry_policy)
        .unwrap()
        .with_ledger_limits(ledger_limits)
}

#[test]
fn transport_profile_has_golden_vector_and_binds_every_limit() {
    let ledger = LedgerRpcLimits::new(1024 * 1024, 2 * 1024 * 1024).unwrap();
    let base = loopback_profile_config(
        "http://127.0.0.1:26657",
        NODE_ID,
        [0x44; 32],
        limits(),
        retry(3),
        ledger,
    );
    assert_eq!(
        hex::encode(base.profile_id().as_bytes()),
        "7a7fca9a5169520d7940ae214e383696e7011427d0f35fe43a02d30b8703d81b"
    );
    let mutations = [
        loopback_profile_config(
            "http://127.0.0.1:26658",
            NODE_ID,
            [0x44; 32],
            limits(),
            retry(3),
            ledger,
        ),
        loopback_profile_config(
            "http://127.0.0.1:26657",
            "3333333333333333333333333333333333333333",
            [0x44; 32],
            limits(),
            retry(3),
            ledger,
        ),
        loopback_profile_config(
            "http://127.0.0.1:26657",
            NODE_ID,
            [0x45; 32],
            limits(),
            retry(3),
            ledger,
        ),
        loopback_profile_config(
            "http://127.0.0.1:26657",
            NODE_ID,
            [0x44; 32],
            RpcLimits::new(
                512 * 1024,
                8 * 1024 * 1024,
                8,
                4,
                NonZeroU8::new(2).unwrap(),
                16,
                16 * 1024,
            )
            .unwrap(),
            retry(3),
            ledger,
        ),
        loopback_profile_config(
            "http://127.0.0.1:26657",
            NODE_ID,
            [0x44; 32],
            RpcLimits::new(
                1024 * 1024,
                7 * 1024 * 1024,
                8,
                4,
                NonZeroU8::new(2).unwrap(),
                16,
                16 * 1024,
            )
            .unwrap(),
            retry(3),
            ledger,
        ),
        loopback_profile_config(
            "http://127.0.0.1:26657",
            NODE_ID,
            [0x44; 32],
            RpcLimits::new(
                1024 * 1024,
                8 * 1024 * 1024,
                7,
                4,
                NonZeroU8::new(2).unwrap(),
                16,
                16 * 1024,
            )
            .unwrap(),
            retry(3),
            ledger,
        ),
        loopback_profile_config(
            "http://127.0.0.1:26657",
            NODE_ID,
            [0x44; 32],
            RpcLimits::new(
                1024 * 1024,
                8 * 1024 * 1024,
                8,
                3,
                NonZeroU8::new(2).unwrap(),
                16,
                16 * 1024,
            )
            .unwrap(),
            retry(3),
            ledger,
        ),
        loopback_profile_config(
            "http://127.0.0.1:26657",
            NODE_ID,
            [0x44; 32],
            RpcLimits::new(
                1024 * 1024,
                8 * 1024 * 1024,
                8,
                4,
                NonZeroU8::new(3).unwrap(),
                16,
                16 * 1024,
            )
            .unwrap(),
            retry(3),
            ledger,
        ),
        loopback_profile_config(
            "http://127.0.0.1:26657",
            NODE_ID,
            [0x44; 32],
            RpcLimits::new(
                1024 * 1024,
                8 * 1024 * 1024,
                8,
                4,
                NonZeroU8::new(2).unwrap(),
                15,
                16 * 1024,
            )
            .unwrap(),
            retry(3),
            ledger,
        ),
        loopback_profile_config(
            "http://127.0.0.1:26657",
            NODE_ID,
            [0x44; 32],
            RpcLimits::new(
                1024 * 1024,
                8 * 1024 * 1024,
                8,
                4,
                NonZeroU8::new(2).unwrap(),
                16,
                24 * 1024,
            )
            .unwrap(),
            retry(3),
            ledger,
        ),
        loopback_profile_config(
            "http://127.0.0.1:26657",
            NODE_ID,
            [0x44; 32],
            limits(),
            retry(2),
            ledger,
        ),
        loopback_profile_config(
            "http://127.0.0.1:26657",
            NODE_ID,
            [0x44; 32],
            limits(),
            RetryPolicy::new(NonZeroU8::new(3).unwrap(), Duration::from_millis(2)).unwrap(),
            ledger,
        ),
        loopback_profile_config(
            "http://127.0.0.1:26657",
            NODE_ID,
            [0x44; 32],
            limits(),
            retry(3),
            LedgerRpcLimits::new(512 * 1024, 1024 * 1024).unwrap(),
        ),
    ];
    for mutation in mutations {
        assert_ne!(mutation.profile_id(), base.profile_id());
    }
}

#[test]
fn transport_profile_canonicalizes_peer_and_ca_set_order_and_binds_client_profile() {
    let first_material = tls_material();
    let second_material = tls_material();
    let third_material = tls_material();
    let first_peer = HttpsPeer::new(
        "https://localhost:26657",
        NodeId::from_str(NODE_ID).unwrap(),
        crate::tls::spki_sha256(&first_material.server_certificate).unwrap(),
        vec![first_material.ca.clone(), second_material.ca.clone()],
        &first_material.client_provider,
    )
    .unwrap();
    let reordered_roots = HttpsPeer::new(
        "https://localhost:26657",
        NodeId::from_str(NODE_ID).unwrap(),
        crate::tls::spki_sha256(&first_material.server_certificate).unwrap(),
        vec![second_material.ca.clone(), first_material.ca.clone()],
        &first_material.client_provider,
    )
    .unwrap();
    let base = RpcTransportConfig::new(vec![RpcPeer::Https(first_peer)], limits(), retry(1)).unwrap();
    let reordered = RpcTransportConfig::new(vec![RpcPeer::Https(reordered_roots)], limits(), retry(1)).unwrap();
    assert_eq!(base.profile_id(), reordered.profile_id());

    let changed_client = HttpsPeer::new(
        "https://localhost:26657",
        NodeId::from_str(NODE_ID).unwrap(),
        crate::tls::spki_sha256(&first_material.server_certificate).unwrap(),
        vec![first_material.ca.clone(), second_material.ca.clone()],
        &second_material.client_provider,
    )
    .unwrap();
    let changed = RpcTransportConfig::new(vec![RpcPeer::Https(changed_client)], limits(), retry(1)).unwrap();
    assert_ne!(base.profile_id(), changed.profile_id());

    let changed_ca = HttpsPeer::new(
        "https://localhost:26657",
        NodeId::from_str(NODE_ID).unwrap(),
        crate::tls::spki_sha256(&first_material.server_certificate).unwrap(),
        vec![first_material.ca.clone(), third_material.ca.clone()],
        &first_material.client_provider,
    )
    .unwrap();
    let changed_ca = RpcTransportConfig::new(vec![RpcPeer::Https(changed_ca)], limits(), retry(1)).unwrap();
    assert_ne!(base.profile_id(), changed_ca.profile_id());

    let mut changed_spki = crate::tls::spki_sha256(&first_material.server_certificate).unwrap();
    changed_spki[0] ^= 1;
    let changed_spki = HttpsPeer::new(
        "https://localhost:26657",
        NodeId::from_str(NODE_ID).unwrap(),
        changed_spki,
        vec![first_material.ca.clone(), second_material.ca.clone()],
        &first_material.client_provider,
    )
    .unwrap();
    let changed_spki = RpcTransportConfig::new(vec![RpcPeer::Https(changed_spki)], limits(), retry(1)).unwrap();
    assert_ne!(base.profile_id(), changed_spki.profile_id());

    assert!(HttpsPeer::new(
        "https://localhost:26657",
        NodeId::from_str(NODE_ID).unwrap(),
        crate::tls::spki_sha256(&first_material.server_certificate).unwrap(),
        vec![first_material.ca.clone(), first_material.ca.clone()],
        &first_material.client_provider,
    )
    .is_err());

    let zero_profile = ZeroProfileProvider {
        resolver: Arc::clone(&first_material.client_provider.resolver),
    };
    assert!(HttpsPeer::new(
        "https://localhost:26657",
        NodeId::from_str(NODE_ID).unwrap(),
        crate::tls::spki_sha256(&first_material.server_certificate).unwrap(),
        vec![first_material.ca.clone()],
        &zero_profile,
    )
    .is_err());

    let first_identity = PeerIdentity::new([0x71; 32], NodeId::from_str(NODE_ID).unwrap()).unwrap();
    let second_identity = PeerIdentity::new(
        [0x72; 32],
        NodeId::from_str("3333333333333333333333333333333333333333").unwrap(),
    )
    .unwrap();
    assert_ne!(
        first_material
            .client_provider
            .binding(&first_identity)
            .unwrap()
            .expected_profile(),
        first_material
            .client_provider
            .binding(&second_identity)
            .unwrap()
            .expected_profile()
    );

    let other_peer = LoopbackHttpPeer::new_regtest(
        "http://127.0.0.1:26658",
        NodeId::from_str("3333333333333333333333333333333333333333").unwrap(),
        [0x55; 32],
    )
    .unwrap();
    let first_loopback =
        LoopbackHttpPeer::new_regtest("http://127.0.0.1:26657", NodeId::from_str(NODE_ID).unwrap(), [0x44; 32])
            .unwrap();
    let ordered = RpcTransportConfig::new(
        vec![
            RpcPeer::RegtestLoopback(first_loopback.clone()),
            RpcPeer::RegtestLoopback(other_peer.clone()),
        ],
        limits(),
        retry(1),
    )
    .unwrap();
    let reversed = RpcTransportConfig::new(
        vec![
            RpcPeer::RegtestLoopback(other_peer),
            RpcPeer::RegtestLoopback(first_loopback),
        ],
        limits(),
        retry(1),
    )
    .unwrap();
    assert_eq!(ordered.profile_id(), reversed.profile_id());

    let duplicate_origin_first =
        LoopbackHttpPeer::new_regtest("http://127.0.0.1:26659", NodeId::from_str(NODE_ID).unwrap(), [0x81; 32])
            .unwrap();
    let duplicate_origin_second = LoopbackHttpPeer::new_regtest(
        "http://127.0.0.1:26659",
        NodeId::from_str("4444444444444444444444444444444444444444").unwrap(),
        [0x82; 32],
    )
    .unwrap();
    assert!(RpcTransportConfig::new(
        vec![
            RpcPeer::RegtestLoopback(duplicate_origin_first),
            RpcPeer::RegtestLoopback(duplicate_origin_second),
        ],
        limits(),
        retry(1),
    )
    .is_err());
}

#[test]
fn https_profile_rejects_unconnectable_names_and_canonicalizes_host_case() {
    let material = tls_material();
    let spki = crate::tls::spki_sha256(&material.server_certificate).unwrap();
    for url in [
        "https://-bad.example:26657",
        "https://bad..example:26657",
        "https://example.com.:26657",
    ] {
        assert!(HttpsPeer::new(
            url,
            NodeId::from_str(NODE_ID).unwrap(),
            spki,
            vec![material.ca.clone()],
            &material.client_provider,
        )
        .is_err());
    }
    let upper = HttpsPeer::new(
        "https://LOCALHOST:26657",
        NodeId::from_str(NODE_ID).unwrap(),
        spki,
        vec![material.ca.clone()],
        &material.client_provider,
    )
    .unwrap();
    let lower = HttpsPeer::new(
        "https://localhost:26657",
        NodeId::from_str(NODE_ID).unwrap(),
        spki,
        vec![material.ca.clone()],
        &material.client_provider,
    )
    .unwrap();
    let upper = RpcTransportConfig::new(vec![RpcPeer::Https(upper)], limits(), retry(1)).unwrap();
    let lower = RpcTransportConfig::new(vec![RpcPeer::Https(lower)], limits(), retry(1)).unwrap();
    assert_eq!(upper.profile_id(), lower.profile_id());

    assert!(HttpsPeer::new(
        "https://127.0.0.1:26657",
        NodeId::from_str(NODE_ID).unwrap(),
        spki,
        vec![material.ca.clone()],
        &material.client_provider,
    )
    .is_ok());
}

#[cfg(unix)]
#[test]
fn pem_identity_requires_owner_private_nofollow_key_path() {
    use std::os::unix::fs::{symlink, PermissionsExt as _};

    let generated = rcgen::generate_simple_self_signed(vec!["client.test".to_owned()]).unwrap();
    let directory = tempfile::TempDir::new().unwrap();
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let certificate_path = directory.path().join("client-cert.pem");
    let key_path = directory.path().join("client-key.pem");
    std::fs::write(&certificate_path, generated.cert.pem()).unwrap();
    std::fs::write(&key_path, generated.signing_key.serialize_pem()).unwrap();
    std::fs::set_permissions(&certificate_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let identity = crate::OwnerOnlyPemClientIdentity::load(&certificate_path, &key_path).unwrap();
    let first_peer = PeerIdentity::new([0x61; 32], NodeId::from_str(NODE_ID).unwrap()).unwrap();
    let second_peer = PeerIdentity::new(
        [0x62; 32],
        NodeId::from_str("3333333333333333333333333333333333333333").unwrap(),
    )
    .unwrap();
    let first_profile = *identity.binding(&first_peer).unwrap().expected_profile();
    assert_eq!(
        first_profile,
        *identity.binding(&first_peer).unwrap().expected_profile()
    );
    assert_ne!(
        first_profile,
        *identity.binding(&second_peer).unwrap().expected_profile()
    );

    let second = rcgen::generate_simple_self_signed(vec!["client-2.test".to_owned()]).unwrap();
    let second_certificate_path = directory.path().join("client-2-cert.pem");
    let second_key_path = directory.path().join("client-2-key.pem");
    std::fs::write(&second_certificate_path, second.cert.pem()).unwrap();
    std::fs::write(&second_key_path, second.signing_key.serialize_pem()).unwrap();
    std::fs::set_permissions(&second_certificate_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    std::fs::set_permissions(&second_key_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let second_identity = crate::OwnerOnlyPemClientIdentity::load(&second_certificate_path, &second_key_path).unwrap();
    assert_ne!(
        first_profile,
        *second_identity.binding(&first_peer).unwrap().expected_profile()
    );

    std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(crate::OwnerOnlyPemClientIdentity::load(&certificate_path, &key_path).is_err());
    std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let link_path = directory.path().join("client-key-link.pem");
    symlink(&key_path, &link_path).unwrap();
    assert!(crate::OwnerOnlyPemClientIdentity::load(&certificate_path, &link_path).is_err());
}

#[tokio::test]
async fn mtls_accepts_exact_ca_name_spki_and_client_certificate() {
    let material = tls_material();
    let server = MockTlsServer::start(Arc::new(build_fixture()), server_config(&material, true))
        .await
        .unwrap();
    let spki = crate::tls::spki_sha256(&material.server_certificate).unwrap();
    let peer = HttpsPeer::new(
        &server.url(),
        NodeId::from_str(NODE_ID).unwrap(),
        spki,
        vec![material.ca.clone()],
        &material.client_provider,
    )
    .unwrap();
    let fetched = fetch_trace(
        &RuntimePeer::new(RpcPeer::Https(peer)).unwrap(),
        &fetch_spec(),
        limits(),
        retry(1),
    )
    .await
    .unwrap();
    assert_eq!(fetched.blocks.len(), 2);
}

#[tokio::test]
async fn wrong_ca_spki_and_optional_client_auth_fail_closed() {
    for case in ["ca", "name", "spki", "client", "optional-client"] {
        let material = tls_material();
        let server = MockTlsServer::start(
            Arc::new(build_fixture()),
            server_config(&material, case != "optional-client"),
        )
        .await
        .unwrap();
        let other = tls_material();
        let mut spki = crate::tls::spki_sha256(&material.server_certificate).unwrap();
        if case == "spki" {
            spki[0] ^= 1;
        }
        let roots = if case == "ca" {
            vec![other.ca]
        } else {
            vec![material.ca.clone()]
        };
        let client_provider = if case == "client" {
            &other.client_provider
        } else {
            &material.client_provider
        };
        let url = if case == "name" {
            format!("https://127.0.0.1:{}", server.address.port())
        } else {
            server.url()
        };
        let peer = HttpsPeer::new(&url, NodeId::from_str(NODE_ID).unwrap(), spki, roots, client_provider).unwrap();
        let error = fetch_trace(
            &RuntimePeer::new(RpcPeer::Https(peer)).unwrap(),
            &fetch_spec(),
            limits(),
            retry(3),
        )
        .await
        .unwrap_err();
        assert!(
            matches!(
                &error,
                RpcTransportError::Tls | RpcTransportError::Certificate | RpcTransportError::SpkiMismatch
            ),
            "unexpected {error:?} for {case}"
        );
    }
}

#[tokio::test]
async fn mutable_provider_cannot_rotate_resolver_away_from_profiled_public_key() {
    let expected = tls_material();
    let rotated = tls_material();
    let server = MockTlsServer::start(Arc::new(build_fixture()), server_config(&expected, false))
        .await
        .unwrap();
    let selected = Arc::new(Mutex::new(Arc::clone(&expected.client_certified)));
    let provider = TestIdentityProvider {
        resolver: Arc::new(RotatingResolver {
            key: Arc::clone(&selected),
        }),
        certificates: expected.client_certified.cert.clone(),
        certified_public_key_spki: expected.client_certified.key.public_key().unwrap().as_ref().to_vec(),
    };
    let peer = HttpsPeer::new(
        &server.url(),
        NodeId::from_str(NODE_ID).unwrap(),
        crate::tls::spki_sha256(&expected.server_certificate).unwrap(),
        vec![expected.ca.clone()],
        &provider,
    )
    .unwrap();
    *selected.lock().unwrap() = Arc::clone(&rotated.client_certified);
    assert!(matches!(
        fetch_trace(
            &RuntimePeer::new(RpcPeer::Https(peer)).unwrap(),
            &fetch_spec(),
            limits(),
            retry(1),
        )
        .await,
        Err(RpcTransportError::Certificate | RpcTransportError::Tls)
    ));
}

#[tokio::test]
async fn pinned_mtls_ledger_broadcast_and_query_return_only_typed_execution_results() {
    let fixture = Arc::new(build_fixture());
    let expected_block = fixture.execution.clone();
    let material = tls_material();
    let server = MockTlsServer::start(Arc::clone(&fixture), server_config(&material, true))
        .await
        .unwrap();
    let spki = crate::tls::spki_sha256(&material.server_certificate).unwrap();
    let peer = HttpsPeer::new(
        &server.url(),
        NodeId::from_str(NODE_ID).unwrap(),
        spki,
        vec![material.ca.clone()],
        &material.client_provider,
    )
    .unwrap();
    let identity = peer.identity().clone();
    let transport =
        CometBftRpcTransport::new(RpcTransportConfig::new(vec![RpcPeer::Https(peer)], limits(), retry(1)).unwrap())
            .unwrap();
    let chain = LedgerChainIdV2::new(CHAIN_ID).unwrap();
    let proposal = signed_ledger_proposal(61);
    let broadcast = transport
        .broadcast_tx_sync(&identity, &chain, &proposal, Duration::from_secs(5))
        .await
        .unwrap();
    assert_eq!(broadcast.admission(), BroadcastAdmissionV2::Accepted);
    assert_eq!(broadcast.evidence().transport_binding(), &spki);
    assert_eq!(broadcast.evidence().node_id(), identity.node_id());
    assert_eq!(broadcast.evidence().ledger_chain_id(), &chain);
    assert_ne!(broadcast.evidence().session_digest(), &[0_u8; 32]);

    let query = LedgerAbciQueryV2::block(2).unwrap();
    let response = transport
        .abci_query(&identity, &chain, &query, Duration::from_secs(5))
        .await
        .unwrap();
    assert_eq!(response.query(), &query);
    assert_eq!(response.height(), 2);
    assert_eq!(response.value(), serde_json::to_vec(&expected_block).unwrap());
    assert_eq!(response.evidence().transport_binding(), &spki);
    assert_ne!(
        response.evidence().session_digest(),
        broadcast.evidence().session_digest()
    );
}

#[tokio::test]
async fn broadcast_rejection_is_definite_and_post_send_failures_are_ambiguous_without_retry() {
    let chain = LedgerChainIdV2::new(CHAIN_ID).unwrap();
    let proposal = signed_ledger_proposal(62);

    let rejected = MockServer::start(Arc::new(build_fixture()), Behavior::BroadcastReject)
        .await
        .unwrap();
    let (transport, identity) = ledger_transport(&rejected.url(), 5);
    let response = transport
        .broadcast_tx_sync(&identity, &chain, &proposal, Duration::from_secs(1))
        .await
        .unwrap();
    assert_eq!(response.admission(), BroadcastAdmissionV2::Rejected { code: 7 });
    assert_eq!(rejected.calls.load(Ordering::SeqCst), 2);

    for behavior in [
        Behavior::WrongTxHash,
        Behavior::DropBroadcastRequest,
        Behavior::TruncateBroadcast,
        Behavior::HangBroadcast,
        Behavior::BroadcastStatus,
        Behavior::WrongOperationId,
    ] {
        let server = MockServer::start(Arc::new(build_fixture()), behavior).await.unwrap();
        let (transport, identity) = ledger_transport(&server.url(), 5);
        let error = transport
            .broadcast_tx_sync(&identity, &chain, &proposal, Duration::from_millis(50))
            .await
            .unwrap_err();
        assert!(
            matches!(error, RpcTransportError::AmbiguousWrite { .. }),
            "unexpected {error:?} for {behavior:?}"
        );
        assert_eq!(server.calls.load(Ordering::SeqCst), 2, "write retried for {behavior:?}");
        wait_for_counter(&server.connections, 0).await;
    }

    let cancelled = MockServer::start(Arc::new(build_fixture()), Behavior::HangBroadcast)
        .await
        .unwrap();
    let (transport, identity) = ledger_transport(&cancelled.url(), 5);
    let transport = Arc::new(transport);
    let task_transport = Arc::clone(&transport);
    let task_chain = chain.clone();
    let task_proposal = proposal.clone();
    let task = tokio::spawn(async move {
        task_transport
            .broadcast_tx_sync(&identity, &task_chain, &task_proposal, Duration::from_secs(5))
            .await
    });
    wait_for_counter(&cancelled.calls, 2).await;
    task.abort();
    let _ = task.await;
    assert_eq!(cancelled.calls.load(Ordering::SeqCst), 2);
    wait_for_counter(&cancelled.connections, 0).await;
}

#[tokio::test]
async fn pinned_mtls_partial_broadcast_fails_as_ambiguous() {
    let fixture = Arc::new(build_fixture());
    let material = tls_material();
    let server =
        MockTlsServer::start_with_behavior(fixture, server_config(&material, true), Behavior::DropBroadcastRequest)
            .await
            .unwrap();
    let peer = HttpsPeer::new(
        &server.url(),
        NodeId::from_str(NODE_ID).unwrap(),
        crate::tls::spki_sha256(&material.server_certificate).unwrap(),
        vec![material.ca.clone()],
        &material.client_provider,
    )
    .unwrap();
    let identity = peer.identity().clone();
    let transport =
        CometBftRpcTransport::new(RpcTransportConfig::new(vec![RpcPeer::Https(peer)], limits(), retry(5)).unwrap())
            .unwrap();
    assert!(matches!(
        transport
            .broadcast_tx_sync(
                &identity,
                &LedgerChainIdV2::new(CHAIN_ID).unwrap(),
                &signed_ledger_proposal(63),
                Duration::from_secs(1),
            )
            .await,
        Err(RpcTransportError::AmbiguousWrite { .. })
    ));
}

#[tokio::test]
async fn abci_query_retries_whole_authenticated_reads_and_rejects_binding_tamper() {
    let chain = LedgerChainIdV2::new(CHAIN_ID).unwrap();
    let query = LedgerAbciQueryV2::block(2).unwrap();
    let retrying = MockServer::start(Arc::new(build_fixture()), Behavior::RetryAbci)
        .await
        .unwrap();
    let (transport, identity) = ledger_transport(&retrying.url(), 3);
    let response = transport
        .abci_query(&identity, &chain, &query, Duration::from_secs(1))
        .await
        .unwrap();
    assert_eq!(response.height(), 2);
    assert_eq!(retrying.calls.load(Ordering::SeqCst), 4);

    for behavior in [
        Behavior::WrongOperationId,
        Behavior::WrongQueryHeight,
        Behavior::WrongQueryKey,
        Behavior::WrongQueryValue,
    ] {
        let server = MockServer::start(Arc::new(build_fixture()), behavior).await.unwrap();
        let (transport, identity) = ledger_transport(&server.url(), 3);
        assert!(transport
            .abci_query(&identity, &chain, &query, Duration::from_secs(1))
            .await
            .is_err());
        assert_eq!(
            server.calls.load(Ordering::SeqCst),
            2,
            "permanent read retried for {behavior:?}"
        );
    }
}

#[tokio::test]
async fn ledger_operations_reject_wrong_authenticated_node_or_chain_before_writes() {
    let chain = LedgerChainIdV2::new(CHAIN_ID).unwrap();
    let proposal = signed_ledger_proposal(64);
    let query = LedgerAbciQueryV2::block(2).unwrap();
    for (behavior, expected) in [(Behavior::WrongNode, "node"), (Behavior::WrongChain, "chain")] {
        let server = MockServer::start(Arc::new(build_fixture()), behavior).await.unwrap();
        let (transport, identity) = ledger_transport(&server.url(), 3);
        let broadcast_error = transport
            .broadcast_tx_sync(&identity, &chain, &proposal, Duration::from_secs(1))
            .await
            .unwrap_err();
        assert!(
            matches!(
                (&broadcast_error, expected),
                (RpcTransportError::NodeIdentity, "node") | (RpcTransportError::ChainIdentity, "chain")
            ),
            "unexpected {broadcast_error:?}"
        );
        assert_eq!(server.calls.load(Ordering::SeqCst), 1);

        let query_error = transport
            .abci_query(&identity, &chain, &query, Duration::from_secs(1))
            .await
            .unwrap_err();
        assert!(
            matches!(
                (&query_error, expected),
                (RpcTransportError::NodeIdentity, "node") | (RpcTransportError::ChainIdentity, "chain")
            ),
            "unexpected {query_error:?}"
        );
        assert_eq!(server.calls.load(Ordering::SeqCst), 2);
    }
}

#[tokio::test]
async fn abci_query_stream_cap_deadline_and_cancellation_close_the_session() {
    let chain = LedgerChainIdV2::new(CHAIN_ID).unwrap();
    let query = LedgerAbciQueryV2::block(2).unwrap();
    let oversized = MockServer::start(Arc::new(build_fixture()), Behavior::ChunkedOversizeQuery)
        .await
        .unwrap();
    let (transport, identity) = ledger_transport(&oversized.url(), 3);
    assert!(matches!(
        transport
            .abci_query(&identity, &chain, &query, Duration::from_secs(1))
            .await,
        Err(RpcTransportError::ResponseTooLarge)
    ));
    assert_eq!(oversized.calls.load(Ordering::SeqCst), 2);

    let hanging = MockServer::start(Arc::new(build_fixture()), Behavior::HangQuery)
        .await
        .unwrap();
    let (transport, identity) = ledger_transport(&hanging.url(), 3);
    assert!(matches!(
        transport
            .abci_query(&identity, &chain, &query, Duration::from_millis(25))
            .await,
        Err(RpcTransportError::Deadline)
    ));
    assert_eq!(hanging.calls.load(Ordering::SeqCst), 2);
    wait_for_counter(&hanging.connections, 0).await;

    let cancelled = MockServer::start(Arc::new(build_fixture()), Behavior::HangQuery)
        .await
        .unwrap();
    let (transport, identity) = ledger_transport(&cancelled.url(), 3);
    let transport = Arc::new(transport);
    let task_transport = Arc::clone(&transport);
    let task_chain = chain.clone();
    let task_query = query.clone();
    let task = tokio::spawn(async move {
        task_transport
            .abci_query(&identity, &task_chain, &task_query, Duration::from_secs(5))
            .await
    });
    wait_for_counter(&cancelled.calls, 2).await;
    task.abort();
    let _ = task.await;
    assert_eq!(cancelled.calls.load(Ordering::SeqCst), 2);
    wait_for_counter(&cancelled.connections, 0).await;
}

#[tokio::test]
#[ignore = "requires an explicit four-node local CometBFT regtest fixture"]
async fn optional_live_four_node_regtest_gate() {
    #[derive(serde::Deserialize)]
    struct LivePeer {
        url: String,
        node_id: String,
        binding_hex: String,
    }
    #[derive(serde::Deserialize)]
    struct LiveConfig {
        chain_id: String,
        first_height: u64,
        last_height: u64,
        peers: Vec<LivePeer>,
    }
    let bytes = if let Some(inline) = std::env::var_os("THUNDERBOLT_COMETBFT_LIVE_CONFIG_JSON") {
        inline.into_encoded_bytes()
    } else {
        let path = std::env::var_os("THUNDERBOLT_COMETBFT_LIVE_CONFIG")
            .expect("set THUNDERBOLT_COMETBFT_LIVE_CONFIG to an explicit public-pin JSON file");
        std::fs::read(path).expect("read live config")
    };
    let config: LiveConfig = serde_json::from_slice(&bytes).expect("decode live config");
    assert_eq!(config.peers.len(), 4);
    let block_count = config
        .last_height
        .checked_sub(config.first_height)
        .and_then(|distance| distance.checked_add(1))
        .and_then(|count| usize::try_from(count).ok())
        .expect("bounded live height interval");
    for peer in config.peers {
        let binding = decode_hex_32(&peer.binding_hex).expect("32-byte binding hex");
        let endpoint =
            LoopbackHttpPeer::new_regtest(&peer.url, NodeId::from_str(&peer.node_id).expect("node id"), binding)
                .expect("loopback peer");
        let runtime = RuntimePeer::new(RpcPeer::RegtestLoopback(endpoint)).expect("runtime peer");
        let trace = fetch_trace(
            &runtime,
            &RpcFetchSpec {
                ledger_chain_id: config.chain_id.clone(),
                first_height: config.first_height,
                last_height: config.last_height,
                max_blocks: block_count,
                max_encoded_bytes: 16 * 1024 * 1024,
                deadline: Instant::now() + Duration::from_secs(120),
            },
            RpcLimits::new(
                8 * 1024 * 1024,
                64 * 1024 * 1024,
                block_count,
                64,
                NonZeroU8::new(64).unwrap(),
                32,
                32 * 1024,
            )
            .expect("live limits"),
            retry(3),
        )
        .await
        .expect("authenticated live trace");
        assert_eq!(trace.blocks.len(), block_count);
    }
}

#[tokio::test]
#[ignore = "requires an explicit pinned HTTPS/mTLS CometBFT Ledger endpoint"]
async fn optional_live_pinned_https_ledger_query_gate() {
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LiveConfig {
        url: String,
        node_id: String,
        spki_sha256_hex: String,
        ca_pem_path: std::path::PathBuf,
        client_certificate_path: std::path::PathBuf,
        client_key_path: std::path::PathBuf,
        ledger_chain_id: String,
        execution_height: u64,
    }

    let path = std::env::var_os("THUNDERBOLT_COMETBFT_LEDGER_LIVE_CONFIG")
        .expect("set THUNDERBOLT_COMETBFT_LEDGER_LIVE_CONFIG to the pinned HTTPS JSON file");
    let config: LiveConfig =
        serde_json::from_slice(&std::fs::read(path).expect("read live config")).expect("decode live config");
    let identity = crate::OwnerOnlyPemClientIdentity::load(&config.client_certificate_path, &config.client_key_path)
        .expect("load owner-only client identity");
    let ca_bytes = std::fs::read(&config.ca_pem_path).expect("read CA bundle");
    let roots = rustls_pemfile::certs(&mut Cursor::new(ca_bytes))
        .collect::<std::result::Result<Vec<_>, _>>()
        .expect("decode CA bundle");
    let peer = HttpsPeer::new(
        &config.url,
        NodeId::from_str(&config.node_id).expect("node id"),
        decode_hex_32(&config.spki_sha256_hex).expect("SPKI digest"),
        roots,
        &identity,
    )
    .expect("pinned HTTPS peer");
    let peer_identity = peer.identity().clone();
    let transport = CometBftRpcTransport::new(
        RpcTransportConfig::new(
            vec![RpcPeer::Https(peer)],
            RpcLimits::new(
                8 * 1024 * 1024,
                64 * 1024 * 1024,
                8,
                64,
                NonZeroU8::new(64).expect("page"),
                32,
                32 * 1024,
            )
            .expect("live limits"),
            retry(3),
        )
        .expect("live transport config")
        .with_ledger_limits(LedgerRpcLimits::new(33 * 1024 * 1024, 34 * 1024 * 1024).expect("live Ledger limits")),
    )
    .expect("live transport");
    let query = LedgerAbciQueryV2::block(config.execution_height).expect("block query");
    let response = transport
        .abci_query(
            &peer_identity,
            &LedgerChainIdV2::new(config.ledger_chain_id).expect("chain"),
            &query,
            Duration::from_secs(120),
        )
        .await
        .expect("authenticated live query");
    assert_eq!(response.height(), config.execution_height);
    assert!(!response.value().is_empty());
}

fn decode_hex_32(encoded: &str) -> Option<[u8; 32]> {
    if encoded.len() != 64 {
        return None;
    }
    let mut output = [0_u8; 32];
    for (index, byte) in output.iter_mut().enumerate() {
        let start = index.checked_mul(2)?;
        *byte = u8::from_str_radix(encoded.get(start..start + 2)?, 16).ok()?;
    }
    Some(output)
}

fn tls_material() -> TlsMaterial {
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::DigitalSignature];
    let ca_key = KeyPair::generate().unwrap();
    let ca_certificate = ca_params.self_signed(&ca_key).unwrap();
    let issuer = Issuer::new(ca_params, ca_key);

    let server_key = KeyPair::generate().unwrap();
    let mut server_params = CertificateParams::new(vec!["localhost".to_owned()]).unwrap();
    server_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let server_certificate = server_params.signed_by(&server_key, &issuer).unwrap();

    let client_key = KeyPair::generate().unwrap();
    let mut client_params = CertificateParams::new(vec!["thunderbolt-client".to_owned()]).unwrap();
    client_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    let client_certificate = client_params.signed_by(&client_key, &issuer).unwrap();
    let provider = rustls::crypto::aws_lc_rs::default_provider();
    let certified = CertifiedKey::from_der(
        vec![client_certificate.der().clone()],
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(client_key.serialize_der())),
        &provider,
    )
    .unwrap();
    let certificates = certified.cert.clone();
    let certified_public_key_spki = certified.key.public_key().unwrap().as_ref().to_vec();
    let client_certified = Arc::new(certified);
    TlsMaterial {
        ca: ca_certificate.der().clone(),
        server_certificate: server_certificate.der().clone(),
        server_key: server_key.serialize_der(),
        client_provider: TestIdentityProvider {
            resolver: Arc::new(TestResolver {
                key: Arc::clone(&client_certified),
            }),
            certificates,
            certified_public_key_spki,
        },
        client_certified,
    }
}

fn server_config(material: &TlsMaterial, require_client: bool) -> Arc<rustls::ServerConfig> {
    let builder = rustls::ServerConfig::builder();
    let mut config = if require_client {
        let mut roots = rustls::RootCertStore::empty();
        roots.add(material.ca.clone()).unwrap();
        let verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(roots))
            .build()
            .unwrap();
        builder
            .with_client_cert_verifier(verifier)
            .with_single_cert(
                vec![material.server_certificate.clone()],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(material.server_key.clone())),
            )
            .unwrap()
    } else {
        builder
            .with_no_client_auth()
            .with_single_cert(
                vec![material.server_certificate.clone()],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(material.server_key.clone())),
            )
            .unwrap()
    };
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Arc::new(config)
}

fn build_fixture() -> RpcFixture {
    let seeds = [[1_u8; 32], [2_u8; 32], [3_u8; 32], [4_u8; 32]];
    let validators = validator_set(&seeds);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let base = i64::try_from(now - 30).unwrap();
    let time = Time::from_unix_timestamp(base, 0).unwrap();
    let chain_id = LedgerChainIdV2::new(CHAIN_ID).unwrap();
    let zero = AppHashV2::zero();
    let first_execution = PendingBlockV2::new(chain_id.clone(), 1, u64::try_from(base).unwrap() * 1_000, zero.clone())
        .unwrap()
        .execute()
        .unwrap();
    let execution = PendingBlockV2::new(
        chain_id.clone(),
        2,
        (u64::try_from(base).unwrap() + 1) * 1_000,
        first_execution.app_hash().clone(),
    )
    .unwrap()
    .execute()
    .unwrap();
    let header_one = build_header(&validators, 1, time, None, &[0_u8; 32]);
    let header_two = build_header(
        &validators,
        2,
        (time + Duration::from_secs(1)).unwrap(),
        Some(header_one.hash()),
        first_execution.app_hash().as_bytes(),
    );
    let header_three = build_header(
        &validators,
        3,
        (time + Duration::from_secs(2)).unwrap(),
        Some(header_two.hash()),
        execution.app_hash().as_bytes(),
    );
    let mut headers = BTreeMap::new();
    headers.insert(
        2,
        SignedHeader::new(header_two.clone(), sign_commit(&header_two, &validators, &seeds)).unwrap(),
    );
    headers.insert(
        3,
        SignedHeader::new(header_three.clone(), sign_commit(&header_three, &validators, &seeds)).unwrap(),
    );
    let root_block = LightBlock::new(
        SignedHeader::new(header_one.clone(), sign_commit(&header_one, &validators, &seeds)).unwrap(),
        validators.clone(),
        validators.clone(),
        NodeId::from_str("1111111111111111111111111111111111111111").unwrap(),
    );
    let policy = FinalityPolicy::new(Duration::from_secs(600), Duration::from_secs(30), 4, 8, 1, 2).unwrap();
    let root = PinnedTrustRoot::new(
        root_block,
        &chain_id,
        1,
        match header_one.hash() {
            Hash::Sha256(bytes) => bytes,
            Hash::None => panic!("test header hash is empty"),
        },
        policy,
    )
    .unwrap();
    RpcFixture {
        headers,
        validators: validators.validators().clone(),
        root,
        execution,
    }
}

fn validator_set(seeds: &[[u8; 32]]) -> ValidatorSet {
    let validators = seeds
        .iter()
        .map(|seed| {
            let key = tendermint::private_key::Ed25519::try_from(seed.as_slice()).unwrap();
            ValidatorInfo::new(PublicKey::from(key.verification_key()), Power::try_from(1_u64).unwrap())
        })
        .collect();
    ValidatorSet::without_proposer(validators)
}

fn build_header(validators: &ValidatorSet, height: u64, time: Time, last: Option<Hash>, app_hash: &[u8; 32]) -> Header {
    let validator_hash = validators.hash();
    Header {
        version: block::header::Version { block: 11, app: 2 },
        chain_id: chain::Id::from_str(CHAIN_ID).unwrap(),
        height: block::Height::try_from(height).unwrap(),
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
        app_hash: AppHash::try_from(app_hash.to_vec()).unwrap(),
        last_results_hash: None,
        evidence_hash: None,
        proposer_address: validators.validators()[0].address,
    }
}

fn sign_commit(header: &Header, validators: &ValidatorSet, seeds: &[[u8; 32]]) -> Commit {
    let header_hash = header.hash();
    let block_id = block::Id {
        hash: header_hash,
        part_set_header: PartSetHeader::new(1, header_hash).unwrap(),
    };
    let round = Round::try_from(1_u32).unwrap();
    let signatures = validators
        .validators()
        .iter()
        .enumerate()
        .map(|(index, validator)| {
            let seed = seeds
                .iter()
                .find(|seed| {
                    let key = tendermint::private_key::Ed25519::try_from(seed.as_slice()).unwrap();
                    validator.address == tendermint::account::Id::from(key.verification_key())
                })
                .unwrap();
            let vote = Vote {
                vote_type: vote::Type::Precommit,
                height: header.height,
                round,
                block_id: Some(block_id),
                timestamp: Some(header.time),
                validator_address: validator.address,
                validator_index: ValidatorIndex::try_from(u32::try_from(index).unwrap()).unwrap(),
                signature: Signature::new(vec![0_u8; 64]).unwrap(),
                extension: Vec::new(),
                extension_signature: None,
            };
            let sign_bytes = SignedVote::from_vote(vote, header.chain_id.clone())
                .unwrap()
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
