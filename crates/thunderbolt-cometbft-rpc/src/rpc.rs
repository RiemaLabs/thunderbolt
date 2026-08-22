use std::collections::{BTreeMap, BTreeSet};
use std::pin::Pin;
use std::sync::Arc;
use std::time::Instant;

use bytes::Bytes;
use http::header::{ACCEPT, CONTENT_LENGTH, CONTENT_TYPE, HOST, USER_AGENT};
use http::{Method, Request, StatusCode};
use http_body_util::{BodyExt as _, Full};
use hyper::client::conn::http1;
use hyper_util::rt::TokioIo;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Deserializer};
use serde_json::json;
use sha2::{Digest, Sha256};
use tendermint::block::signed_header::SignedHeader;
use tendermint::block::{self, Height};
use tendermint::chain;
use tendermint::node::Id as NodeId;
use tendermint::validator::{Info as ValidatorInfo, Set as ValidatorSet};
use tendermint_light_client_verifier::types::LightBlock;
use thunderbolt_cometbft_client::TraceFetchRequest;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

use crate::config::{RetryPolicy, RpcLimits, RpcPeer};
use crate::tls::{client_config, server_name, spki_sha256};
use crate::{Result, RpcTransportError};

const RESPONSE_TRANSCRIPT_DOMAIN: &[u8] = b"bitcoin-thunderbolt/cometbft-rpc/response/v1";
const USER_AGENT_VALUE: &str = "bitcoin-thunderbolt-cometbft-rpc/1.0";
const MAX_RPC_REQUEST_BYTES: usize = 16 * 1024;

trait TokioStream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T> TokioStream for T where T: AsyncRead + AsyncWrite + Unpin + Send {}
type BoxedStream = Pin<Box<dyn TokioStream>>;

pub(crate) struct RuntimePeer {
    pub peer: RpcPeer,
}

impl RuntimePeer {
    pub fn new(peer: RpcPeer) -> Result<Self> {
        match &peer {
            RpcPeer::Https(https) => {
                let _ = client_config(https)?;
            }
            #[cfg(any(test, feature = "regtest"))]
            RpcPeer::RegtestLoopback(_) => {}
        }
        Ok(Self { peer })
    }
}

#[derive(Debug)]
pub(crate) struct FetchedRpcTrace {
    pub blocks: Vec<LightBlock>,
    pub encoded: Vec<u8>,
    pub transcript_digest: [u8; 32],
}

pub(crate) struct RpcFetchSpec {
    pub ledger_chain_id: String,
    pub first_height: u64,
    pub last_height: u64,
    pub max_blocks: usize,
    pub max_encoded_bytes: usize,
    pub deadline: Instant,
}

impl RpcFetchSpec {
    pub fn from_request(request: &TraceFetchRequest) -> Self {
        Self {
            ledger_chain_id: request.ledger_chain_id().as_str().to_owned(),
            first_height: request.first_height(),
            last_height: request.last_height(),
            max_blocks: request.max_blocks(),
            max_encoded_bytes: request.max_encoded_bytes(),
            deadline: request.deadline(),
        }
    }
}

pub(crate) async fn fetch_trace(
    peer: &RuntimePeer,
    request: &RpcFetchSpec,
    limits: RpcLimits,
    retry: RetryPolicy,
) -> Result<FetchedRpcTrace> {
    let expected_len = request
        .last_height
        .checked_sub(request.first_height)
        .and_then(|distance| distance.checked_add(1))
        .and_then(|count| usize::try_from(count).ok())
        .ok_or(RpcTransportError::TraceBound)?;
    if expected_len == 0 || expected_len != request.max_blocks || expected_len > limits.max_adjacent_headers() {
        return Err(RpcTransportError::TraceBound);
    }
    let mut context = RpcContext::new(request.deadline, limits, retry);
    let status: StatusResult = context.call(peer, "status", json!({})).await?;
    if status.node_info.id != peer.peer.identity().node_id() {
        return Err(RpcTransportError::NodeIdentity);
    }
    if status.node_info.network.as_str() != request.ledger_chain_id {
        return Err(RpcTransportError::ChainIdentity);
    }
    let required_validator_height = request.last_height.checked_add(1).ok_or(RpcTransportError::Height)?;
    if status.sync_info.latest_block_height.value() < required_validator_height {
        return Err(RpcTransportError::Height);
    }

    let mut signed_headers = BTreeMap::new();
    for height in request.first_height..=request.last_height {
        let result: CommitResult = context
            .call(peer, "commit", json!({"height": height.to_string()}))
            .await?;
        if result.signed_header.header.height.value() != height || result.signed_header.commit.height.value() != height
        {
            return Err(RpcTransportError::Height);
        }
        if result.signed_header.header.chain_id.as_str() != request.ledger_chain_id {
            return Err(RpcTransportError::ChainIdentity);
        }
        if !result.canonical {
            return Err(RpcTransportError::Json);
        }
        if signed_headers.insert(height, result.signed_header).is_some() {
            return Err(RpcTransportError::Height);
        }
    }

    let mut validator_sets = BTreeMap::new();
    for height in request.first_height..=required_validator_height {
        let validators = fetch_validators(peer, &mut context, height, limits).await?;
        if validator_sets.insert(height, validators).is_some() {
            return Err(RpcTransportError::Pagination);
        }
    }

    let mut blocks = Vec::with_capacity(expected_len);
    for height in request.first_height..=request.last_height {
        let signed_header = signed_headers.get(&height).cloned().ok_or(RpcTransportError::Height)?;
        let validators = validator_sets
            .get(&height)
            .cloned()
            .ok_or(RpcTransportError::Pagination)?;
        let next_height = height.checked_add(1).ok_or(RpcTransportError::Height)?;
        let next_validators = validator_sets
            .get(&next_height)
            .cloned()
            .ok_or(RpcTransportError::Pagination)?;
        if validators.hash() != signed_header.header.validators_hash
            || next_validators.hash() != signed_header.header.next_validators_hash
        {
            return Err(RpcTransportError::ValidatorSet);
        }
        blocks.push(LightBlock::new(
            signed_header,
            validators,
            next_validators,
            peer.peer.identity().node_id(),
        ));
    }
    let encoded = serde_json::to_vec(&blocks).map_err(|_| RpcTransportError::Json)?;
    if encoded.is_empty() || encoded.len() > request.max_encoded_bytes {
        return Err(RpcTransportError::TraceBound);
    }
    Ok(FetchedRpcTrace {
        blocks,
        encoded,
        transcript_digest: context.transcript_digest(),
    })
}

async fn fetch_validators(
    peer: &RuntimePeer,
    context: &mut RpcContext,
    height: u64,
    limits: RpcLimits,
) -> Result<ValidatorSet> {
    let page_size = limits.validator_page_size().get();
    let mut page = 1_u64;
    let mut expected_total = None;
    let mut validators = Vec::new();
    let mut addresses = BTreeSet::new();
    loop {
        let result: ValidatorsResult = context
            .call(
                peer,
                "validators",
                json!({
                    "height": height.to_string(),
                    "page": page.to_string(),
                    "per_page": page_size.to_string()
                }),
            )
            .await?;
        if result.block_height.value() != height || result.count != result.validators.len() {
            return Err(RpcTransportError::Pagination);
        }
        match expected_total {
            Some(total) if total != result.total => return Err(RpcTransportError::Pagination),
            None => {
                if result.total == 0 || result.total > limits.max_validators() {
                    return Err(RpcTransportError::Pagination);
                }
                expected_total = Some(result.total);
            }
            Some(_) => {}
        }
        let total = expected_total.ok_or(RpcTransportError::Pagination)?;
        let remaining = total
            .checked_sub(validators.len())
            .ok_or(RpcTransportError::Pagination)?;
        if result.count != remaining.min(usize::from(page_size)) {
            return Err(RpcTransportError::Pagination);
        }
        if result.validators.is_empty() && validators.len() < result.total {
            return Err(RpcTransportError::Pagination);
        }
        for validator in result.validators {
            if !addresses.insert(validator.address) {
                return Err(RpcTransportError::Pagination);
            }
            validators.push(validator);
        }
        if validators.len() == result.total {
            break;
        }
        if validators.len() > result.total {
            return Err(RpcTransportError::Pagination);
        }
        page = page.checked_add(1).ok_or(RpcTransportError::Pagination)?;
        let maximum_pages = u64::try_from(limits.max_validators()).map_err(|_| RpcTransportError::Pagination)?;
        if page > maximum_pages {
            return Err(RpcTransportError::Pagination);
        }
    }
    if validators.len() != expected_total.ok_or(RpcTransportError::Pagination)? {
        return Err(RpcTransportError::Pagination);
    }
    let validator_name_bytes = validators.iter().try_fold(0_usize, |total, validator| {
        total.checked_add(validator.name.as_deref().map_or(0, str::len))
    });
    if validator_name_bytes.is_none_or(|total| total > thunderbolt_cometbft::MAX_VALIDATOR_NAME_BYTES)
        || validators.iter().any(|validator| {
            validator.power() == 0 || tendermint::account::Id::from(validator.pub_key) != validator.address
        })
    {
        return Err(RpcTransportError::ValidatorSet);
    }
    let total_power = validators
        .iter()
        .try_fold(0_u64, |total, validator| total.checked_add(validator.power()));
    if total_power.is_none_or(|total| total == 0 || total > ValidatorSet::MAX_TOTAL_VOTING_POWER) {
        return Err(RpcTransportError::ValidatorSet);
    }
    Ok(ValidatorSet::without_proposer(validators))
}

struct RpcContext {
    deadline: Instant,
    limits: RpcLimits,
    retry: RetryPolicy,
    aggregate_bytes: usize,
    request_id: u64,
    transcript: Sha256,
    session: Option<RpcSession>,
}

impl RpcContext {
    fn new(deadline: Instant, limits: RpcLimits, retry: RetryPolicy) -> Self {
        let mut transcript = Sha256::new();
        transcript.update(RESPONSE_TRANSCRIPT_DOMAIN);
        Self {
            deadline,
            limits,
            retry,
            aggregate_bytes: 0,
            request_id: 1,
            transcript,
            session: None,
        }
    }

    async fn call<T: DeserializeOwned>(
        &mut self,
        peer: &RuntimePeer,
        method: &str,
        params: serde_json::Value,
    ) -> Result<T> {
        let id = self.request_id;
        self.request_id = self.request_id.checked_add(1).ok_or(RpcTransportError::TraceBound)?;
        let request_body = serde_json::to_vec(&json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": method,
            "params": params
        }))
        .map_err(|_| RpcTransportError::Json)?;
        if request_body.is_empty() || request_body.len() > MAX_RPC_REQUEST_BYTES {
            return Err(RpcTransportError::TraceBound);
        }
        let attempts = self.retry.attempts().get();
        for attempt in 0..attempts {
            match request_once(peer, method, id, &request_body, self).await {
                Ok(response) => return Ok(response),
                Err(failure) if failure.retryable && attempt + 1 < attempts => {
                    self.session = None;
                    let multiplier = 1_u32
                        .checked_shl(u32::from(attempt))
                        .ok_or(RpcTransportError::Deadline)?;
                    let delay = self
                        .retry
                        .base_delay()
                        .checked_mul(multiplier)
                        .ok_or(RpcTransportError::Deadline)?;
                    timeout_at(self.deadline, tokio::time::sleep(delay)).await?;
                }
                Err(failure) if failure.retryable => return Err(RpcTransportError::RetryExhausted),
                Err(failure) => return Err(failure.error),
            }
        }
        Err(RpcTransportError::RetryExhausted)
    }

    fn account(&mut self, length: usize) -> Result<()> {
        self.aggregate_bytes = self
            .aggregate_bytes
            .checked_add(length)
            .ok_or(RpcTransportError::AggregateTooLarge)?;
        if self.aggregate_bytes > self.limits.aggregate_bytes() {
            return Err(RpcTransportError::AggregateTooLarge);
        }
        Ok(())
    }

    fn record(
        &mut self,
        method: &str,
        request_body: &[u8],
        response_body: &[u8],
        security_binding: &[u8; 32],
    ) -> Result<()> {
        self.transcript.update(
            u64::try_from(method.len())
                .map_err(|_| RpcTransportError::TraceBound)?
                .to_be_bytes(),
        );
        self.transcript.update(method.as_bytes());
        self.transcript.update(security_binding);
        self.transcript.update(Sha256::digest(request_body));
        self.transcript.update(Sha256::digest(response_body));
        Ok(())
    }

    fn transcript_digest(self) -> [u8; 32] {
        self.transcript.finalize().into()
    }
}

struct AttemptFailure {
    error: RpcTransportError,
    retryable: bool,
}

struct RpcSession {
    sender: http1::SendRequest<Full<Bytes>>,
    _driver: AbortOnDrop,
    security_binding: [u8; 32],
    authenticated_response_seen: bool,
}

struct AbortOnDrop(tokio::task::JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

impl AttemptFailure {
    fn transient(error: RpcTransportError) -> Self {
        Self { error, retryable: true }
    }

    fn permanent(error: RpcTransportError) -> Self {
        Self {
            error,
            retryable: false,
        }
    }

    fn from_connect(error: RpcTransportError) -> Self {
        if matches!(error, RpcTransportError::Connect) {
            Self::transient(error)
        } else {
            Self::permanent(error)
        }
    }

    fn from_hyper(error: hyper::Error) -> Self {
        if error.is_parse() || error.is_user() {
            return Self::permanent(RpcTransportError::Json);
        }
        let mut source: &(dyn std::error::Error + 'static) = &error;
        loop {
            if source.downcast_ref::<rustls::Error>().is_some() {
                return Self::permanent(RpcTransportError::Tls);
            }
            let Some(next) = source.source() else {
                return Self::transient(RpcTransportError::Connect);
            };
            source = next;
        }
    }

    fn from_session_hyper(error: hyper::Error, first_https_response: bool) -> Self {
        let failure = Self::from_hyper(error);
        if first_https_response && failure.retryable {
            Self::permanent(RpcTransportError::Tls)
        } else {
            failure
        }
    }
}

async fn request_once<T: DeserializeOwned>(
    peer: &RuntimePeer,
    method: &str,
    id: u64,
    request_body: &[u8],
    context: &mut RpcContext,
) -> std::result::Result<T, AttemptFailure> {
    if context.session.is_none() {
        context.session = Some(
            open_session(peer, context.deadline, context.limits)
                .await
                .map_err(AttemptFailure::from_connect)?,
        );
    }
    let session = context
        .session
        .as_mut()
        .ok_or_else(|| AttemptFailure::transient(RpcTransportError::Connect))?;
    let security_binding = session.security_binding;
    let request = Request::builder()
        .method(Method::POST)
        .uri("/")
        .header(HOST, peer.peer.endpoint().authority.as_str())
        .header(ACCEPT, "application/json")
        .header(CONTENT_TYPE, "application/json")
        .header(USER_AGENT, USER_AGENT_VALUE)
        .body(Full::new(Bytes::copy_from_slice(request_body)))
        .map_err(|_| AttemptFailure::permanent(RpcTransportError::InvalidConfiguration("HTTP request is invalid")))?;
    let first_https_response = !session.authenticated_response_seen && matches!(&peer.peer, RpcPeer::Https(_));
    let mut response = timeout_at(context.deadline, session.sender.send_request(request))
        .await
        .map_err(AttemptFailure::from_connect)?
        .map_err(|error| AttemptFailure::from_session_hyper(error, first_https_response))?;
    session.authenticated_response_seen = true;
    let status = response.status();
    if status != StatusCode::OK {
        let retryable = matches!(status.as_u16(), 408 | 429 | 500 | 502 | 503 | 504);
        return Err(AttemptFailure {
            error: RpcTransportError::HttpStatus(status.as_u16()),
            retryable,
        });
    }
    if !valid_content_type(response.headers().get(CONTENT_TYPE)) {
        return Err(AttemptFailure::permanent(RpcTransportError::ContentType));
    }
    if response
        .headers()
        .get(CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<usize>().ok())
        .is_some_and(|length| length > context.limits.response_bytes())
    {
        return Err(AttemptFailure::permanent(RpcTransportError::ResponseTooLarge));
    }
    let mut body = Vec::new();
    while let Some(frame) = timeout_at(context.deadline, response.body_mut().frame())
        .await
        .map_err(AttemptFailure::from_connect)?
    {
        let frame = frame.map_err(AttemptFailure::from_hyper)?;
        if let Some(data) = frame.data_ref() {
            context.account(data.len()).map_err(AttemptFailure::permanent)?;
            let next = body
                .len()
                .checked_add(data.len())
                .ok_or_else(|| AttemptFailure::permanent(RpcTransportError::ResponseTooLarge))?;
            if next > context.limits.response_bytes() {
                return Err(AttemptFailure::permanent(RpcTransportError::ResponseTooLarge));
            }
            body.extend_from_slice(data);
        }
    }
    context
        .record(method, request_body, &body, &security_binding)
        .map_err(AttemptFailure::permanent)?;
    let envelope: JsonRpcEnvelope<T> = match serde_json::from_slice(&body) {
        Ok(envelope) => envelope,
        Err(error) if error.is_eof() => {
            return Err(AttemptFailure::transient(RpcTransportError::Json));
        }
        Err(_) => return Err(AttemptFailure::permanent(RpcTransportError::Json)),
    };
    if envelope.jsonrpc != "2.0"
        || envelope.id.as_u64() != Some(id)
        || envelope.error.is_some()
        || envelope.result.is_none()
    {
        return Err(AttemptFailure::permanent(RpcTransportError::Json));
    }
    envelope
        .result
        .ok_or_else(|| AttemptFailure::permanent(RpcTransportError::Json))
}

async fn open_session(peer: &RuntimePeer, deadline: Instant, limits: RpcLimits) -> Result<RpcSession> {
    let (stream, security_binding) = connect(peer, deadline).await?;
    let io = TokioIo::new(stream);
    let mut builder = http1::Builder::new();
    builder
        .max_headers(limits.max_headers())
        .max_buf_size(limits.max_header_bytes());
    let (sender, connection) = timeout_at(deadline, builder.handshake::<_, Full<Bytes>>(io))
        .await?
        .map_err(|_| RpcTransportError::Connect)?;
    let driver = tokio::spawn(async move {
        let _ = connection.await;
    });
    Ok(RpcSession {
        sender,
        _driver: AbortOnDrop(driver),
        security_binding,
        authenticated_response_seen: false,
    })
}

async fn connect(peer: &RuntimePeer, deadline: Instant) -> Result<(BoxedStream, [u8; 32])> {
    let endpoint = peer.peer.endpoint();
    let tcp = timeout_at(
        deadline,
        TcpStream::connect((endpoint.host.as_str(), endpoint.port.get())),
    )
    .await?
    .map_err(|_| RpcTransportError::Connect)?;
    tcp.set_nodelay(true).map_err(|_| RpcTransportError::Connect)?;
    match &peer.peer {
        RpcPeer::Https(https) => {
            let tracked = client_config(https)?;
            let connector = TlsConnector::from(Arc::clone(&tracked.config));
            let name = server_name(&endpoint.host)?;
            let tls = timeout_at(deadline, connector.connect(name, tcp))
                .await?
                .map_err(|_| RpcTransportError::Tls)?;
            if !tracked
                .client_certificate_used
                .load(std::sync::atomic::Ordering::SeqCst)
            {
                return Err(RpcTransportError::Certificate);
            }
            let certificates = tls
                .get_ref()
                .1
                .peer_certificates()
                .ok_or(RpcTransportError::Certificate)?;
            let leaf = certificates.first().ok_or(RpcTransportError::Certificate)?;
            let actual = spki_sha256(leaf)?;
            if actual != https.expected_spki {
                return Err(RpcTransportError::SpkiMismatch);
            }
            let mut exporter = [0_u8; 32];
            tls.get_ref()
                .1
                .export_keying_material(&mut exporter, b"EXPORTER-bitcoin-thunderbolt-cometbft-rpc-v1", None)
                .map_err(|_| RpcTransportError::Tls)?;
            let security_binding = Sha256::new()
                .chain_update(actual)
                .chain_update(exporter)
                .finalize()
                .into();
            Ok((Box::pin(tls), security_binding))
        }
        #[cfg(any(test, feature = "regtest"))]
        RpcPeer::RegtestLoopback(loopback) => Ok((Box::pin(tcp), *loopback.identity.transport_binding())),
    }
}

fn valid_content_type(value: Option<&http::HeaderValue>) -> bool {
    value
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .is_some_and(|mime| {
            mime.trim().eq_ignore_ascii_case("application/json")
                || mime.trim().eq_ignore_ascii_case("application/json-rpc")
        })
}

async fn timeout_at<F: std::future::Future>(deadline: Instant, future: F) -> Result<F::Output> {
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .filter(|duration| !duration.is_zero())
        .ok_or(RpcTransportError::Deadline)?;
    tokio::time::timeout(remaining, future)
        .await
        .map_err(|_| RpcTransportError::Deadline)
}

#[derive(Deserialize)]
struct JsonRpcEnvelope<T> {
    jsonrpc: String,
    id: serde_json::Value,
    result: Option<T>,
    error: Option<serde_json::Value>,
}

#[derive(Deserialize)]
struct StatusResult {
    node_info: StatusNodeInfo,
    sync_info: StatusSyncInfo,
}

#[derive(Deserialize)]
struct StatusNodeInfo {
    id: NodeId,
    network: chain::Id,
}

#[derive(Deserialize)]
struct StatusSyncInfo {
    latest_block_height: Height,
}

#[derive(Deserialize)]
struct CommitResult {
    signed_header: SignedHeader,
    canonical: bool,
}

#[derive(Deserialize)]
struct ValidatorsResult {
    block_height: block::Height,
    validators: Vec<ValidatorInfo>,
    #[serde(deserialize_with = "decimal_usize")]
    count: usize,
    #[serde(deserialize_with = "decimal_usize")]
    total: usize,
}

fn decimal_usize<'de, D: Deserializer<'de>>(deserializer: D) -> std::result::Result<usize, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Decimal {
        String(String),
        Number(u64),
    }
    let value = Decimal::deserialize(deserializer)?;
    match value {
        Decimal::String(value) => value.parse::<usize>().map_err(serde::de::Error::custom),
        Decimal::Number(value) => usize::try_from(value).map_err(serde::de::Error::custom),
    }
}
