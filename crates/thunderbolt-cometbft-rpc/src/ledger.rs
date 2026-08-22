use core::fmt;
use core::time::Duration;
use std::str::FromStr;
use std::time::Instant;

use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine as _;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::json;
use sha2::{Digest as _, Sha256};
use tendermint::node::Id as NodeId;
use thunderbolt_cometbft_client::PeerIdentity;
use thunderbolt_ledger::{
    AppHashV2, ChannelContextIdV2, EntryHashV2, EntryMerkleProofV2, ExecutedBlockV2, ExecutedEntryV2, LedgerChainIdV2,
    ParticipantIdV2, RequestDigestV2, SignedProposalV2, MAX_BLOCK_ENTRIES, MAX_SIGNED_PROPOSAL_JSON_BYTES,
};
use thunderbolt_ledger_abci::{
    ABCI_CODESPACE, MAX_QUERY_REQUEST_BYTES, MAX_QUERY_RESPONSE_BYTES, QUERY_BLOCK_PATH, QUERY_CHANNEL_PATH,
    QUERY_ENTRY_LOCATION_PATH, QUERY_EXECUTION_RANGE_PATH, QUERY_PROOF_PATH, QUERY_REQUEST_PATH, QUERY_STATUS_PATH,
};
use thunderbolt_ledger_rpc::{EntryLocationRequestV2, ExecutionRangeRequestV2, RpcRequestV2, RpcResponseV2};
use thunderbolt_protocol::v2::ChannelSnapshotV2;

use crate::config::{
    LedgerRpcLimits, RetryPolicy, RpcLimits, MAX_LEDGER_RPC_RESPONSE_BYTES, MAX_LEDGER_STATUS_RESPONSE_BYTES,
};
use crate::rpc::{timeout_at, RpcCall, RpcContext, RuntimePeer, StatusResult, MAX_RPC_REQUEST_BYTES};
use crate::{Result, RpcTransportError};

const MAX_LEDGER_RPC_TIMEOUT: Duration = Duration::from_secs(120);
const MIN_LEDGER_RPC_TIMEOUT: Duration = Duration::from_millis(1);
const BROADCAST_METHOD: &str = "broadcast_tx_sync";
const ABCI_QUERY_METHOD: &str = "abci_query";
const STATUS_METHOD: &str = "status";
const BROADCAST_EVIDENCE_DOMAIN: &[u8] = b"bitcoin-thunderbolt/cometbft-rpc/broadcast-evidence/v1";
const QUERY_EVIDENCE_DOMAIN: &[u8] = b"bitcoin-thunderbolt/cometbft-rpc/abci-query-evidence/v1";
const MAX_BROADCAST_RPC_RESPONSE_BYTES: usize = 1024 * 1024;
const MAX_BROADCAST_REQUEST_OVERHEAD: usize = 1_024;
const MAX_ENCODED_TRANSACTION_BYTES: usize = MAX_SIGNED_PROPOSAL_JSON_BYTES.div_ceil(3) * 4;
const MAX_QUERY_RESPONSE_OVERHEAD: usize = 1024 * 1024;
const MAX_ENCODED_QUERY_VALUE_BYTES: usize = MAX_QUERY_RESPONSE_BYTES.div_ceil(3) * 4;

const _: () = assert!(MAX_ENCODED_TRANSACTION_BYTES + MAX_BROADCAST_REQUEST_OVERHEAD <= MAX_RPC_REQUEST_BYTES);
const _: () = assert!(MAX_ENCODED_QUERY_VALUE_BYTES + MAX_QUERY_RESPONSE_OVERHEAD <= MAX_LEDGER_RPC_RESPONSE_BYTES);

/// A `broadcast_tx_sync` result is only CometBFT mempool admission.
///
/// It never proves block execution or consensus finality.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BroadcastAdmissionV2 {
    /// The authenticated peer returned CheckTx code zero.
    Accepted,
    /// The authenticated peer returned a nonzero CheckTx code.
    Rejected {
        /// Stable ABCI response code. Provider log strings are discarded.
        code: u32,
    },
}

/// Non-serializable evidence binding one fixed RPC result to the configured peer.
///
/// This authenticates transport/session provenance only and is never a
/// consensus-finality receipt.
pub struct LedgerRpcSessionEvidence {
    transport_binding: [u8; 32],
    node_id: NodeId,
    ledger_chain_id: LedgerChainIdV2,
    request_digest: [u8; 32],
    response_digest: [u8; 32],
    application_digest: [u8; 32],
    transcript_digest: [u8; 32],
    session_digest: [u8; 32],
}

impl LedgerRpcSessionEvidence {
    /// Returns the exact configured peer transport binding.
    pub const fn transport_binding(&self) -> &[u8; 32] {
        &self.transport_binding
    }

    /// Returns the exact configured CometBFT node ID.
    pub const fn node_id(&self) -> NodeId {
        self.node_id
    }

    /// Returns the exact authenticated Ledger chain.
    pub const fn ledger_chain_id(&self) -> &LedgerChainIdV2 {
        &self.ledger_chain_id
    }

    /// Returns a digest of the exact fixed-method JSON-RPC request.
    pub const fn request_digest(&self) -> &[u8; 32] {
        &self.request_digest
    }

    /// Returns a digest of the exact authenticated JSON-RPC response body.
    pub const fn response_digest(&self) -> &[u8; 32] {
        &self.response_digest
    }

    /// Returns a digest of the exact application result bytes or admission tuple.
    pub const fn application_digest(&self) -> &[u8; 32] {
        &self.application_digest
    }

    /// Returns the complete authenticated status-plus-operation transcript digest.
    pub const fn transcript_digest(&self) -> &[u8; 32] {
        &self.transcript_digest
    }

    /// Returns the session-bound evidence digest.
    pub const fn session_digest(&self) -> &[u8; 32] {
        &self.session_digest
    }
}

impl fmt::Debug for LedgerRpcSessionEvidence {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("LedgerRpcSessionEvidence([authenticated capability])")
    }
}

/// Authenticated one-attempt CometBFT mempool response.
pub struct AuthenticatedBroadcastTxSyncV2 {
    transaction_hash: [u8; 32],
    proposal_digest: [u8; 32],
    admission: BroadcastAdmissionV2,
    evidence: LedgerRpcSessionEvidence,
}

impl AuthenticatedBroadcastTxSyncV2 {
    /// Returns the deterministic SHA-256 CometBFT transaction hash.
    pub const fn transaction_hash(&self) -> &[u8; 32] {
        &self.transaction_hash
    }

    /// Returns the exact signed proposal digest submitted as transaction bytes.
    pub const fn proposal_digest(&self) -> &[u8; 32] {
        &self.proposal_digest
    }

    /// Returns transport admission or deterministic CheckTx rejection.
    pub const fn admission(&self) -> BroadcastAdmissionV2 {
        self.admission
    }

    /// Returns the authenticated in-process session evidence.
    pub const fn evidence(&self) -> &LedgerRpcSessionEvidence {
        &self.evidence
    }
}

impl fmt::Debug for AuthenticatedBroadcastTxSyncV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthenticatedBroadcastTxSyncV2")
            .field("transaction_hash", &self.transaction_hash)
            .field("proposal_digest", &self.proposal_digest)
            .field("admission", &self.admission)
            .field("evidence", &self.evidence)
            .finish()
    }
}

/// One fixed Thunderbolt Ledger ABCI query.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LedgerAbciQueryV2 {
    kind: LedgerAbciQueryKind,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum LedgerAbciQueryKind {
    Status {
        height: u64,
    },
    Block {
        height: u64,
    },
    Channel {
        channel: ChannelContextIdV2,
        height: u64,
    },
    Request {
        channel: ChannelContextIdV2,
        participant: ParticipantIdV2,
        request: RequestDigestV2,
        height: u64,
    },
    Proof {
        height: u64,
        block_index: u32,
    },
    ExecutionRange(ExecutionRangeRequestV2),
    EntryLocation(EntryLocationRequestV2),
}

impl LedgerAbciQueryV2 {
    /// Constructs an exact current-status query at a positive application height.
    pub fn status(height: u64) -> Result<Self> {
        validate_height(height)?;
        Ok(Self {
            kind: LedgerAbciQueryKind::Status { height },
        })
    }

    /// Constructs an exact whole executed-block query.
    pub fn block(height: u64) -> Result<Self> {
        validate_height(height)?;
        Ok(Self {
            kind: LedgerAbciQueryKind::Block { height },
        })
    }

    /// Constructs an exact current channel-state query.
    pub fn channel(channel: ChannelContextIdV2, height: u64) -> Result<Self> {
        validate_height(height)?;
        Ok(Self {
            kind: LedgerAbciQueryKind::Channel { channel, height },
        })
    }

    /// Constructs an exact actor-request lookup at the current application height.
    pub fn request(
        channel: ChannelContextIdV2,
        participant: ParticipantIdV2,
        request: RequestDigestV2,
        height: u64,
    ) -> Result<Self> {
        validate_height(height)?;
        Ok(Self {
            kind: LedgerAbciQueryKind::Request {
                channel,
                participant,
                request,
                height,
            },
        })
    }

    /// Constructs an exact deterministic entry-proof query.
    pub fn proof(height: u64, block_index: u32) -> Result<Self> {
        validate_height(height)?;
        if usize::try_from(block_index).map_or(true, |index| index >= MAX_BLOCK_ENTRIES) {
            return Err(RpcTransportError::InvalidConfiguration(
                "Ledger proof block index is outside bounds",
            ));
        }
        Ok(Self {
            kind: LedgerAbciQueryKind::Proof { height, block_index },
        })
    }

    /// Constructs the committed exact-count contiguous execution-range query.
    #[must_use]
    pub const fn execution_range(request: ExecutionRangeRequestV2) -> Self {
        Self {
            kind: LedgerAbciQueryKind::ExecutionRange(request),
        }
    }

    /// Constructs the committed exact historical first-location query.
    #[must_use]
    pub const fn entry_location(request: EntryLocationRequestV2) -> Self {
        Self {
            kind: LedgerAbciQueryKind::EntryLocation(request),
        }
    }

    fn path(&self) -> &'static str {
        match self.kind {
            LedgerAbciQueryKind::Status { .. } => QUERY_STATUS_PATH,
            LedgerAbciQueryKind::Block { .. } => QUERY_BLOCK_PATH,
            LedgerAbciQueryKind::Channel { .. } => QUERY_CHANNEL_PATH,
            LedgerAbciQueryKind::Request { .. } => QUERY_REQUEST_PATH,
            LedgerAbciQueryKind::Proof { .. } => QUERY_PROOF_PATH,
            LedgerAbciQueryKind::ExecutionRange(_) => QUERY_EXECUTION_RANGE_PATH,
            LedgerAbciQueryKind::EntryLocation(_) => QUERY_ENTRY_LOCATION_PATH,
        }
    }

    fn height(&self) -> Result<u64> {
        let height = match &self.kind {
            LedgerAbciQueryKind::Status { height }
            | LedgerAbciQueryKind::Block { height }
            | LedgerAbciQueryKind::Channel { height, .. }
            | LedgerAbciQueryKind::Request { height, .. }
            | LedgerAbciQueryKind::Proof { height, .. } => *height,
            LedgerAbciQueryKind::ExecutionRange(request) => request
                .cursor()
                .next_height()
                .checked_add(u64::from(request.block_count()).saturating_sub(1))
                .ok_or(RpcTransportError::Height)?,
            LedgerAbciQueryKind::EntryLocation(request) => request.through_height(),
        };
        validate_height(height)?;
        Ok(height)
    }

    fn data(&self) -> Result<Vec<u8>> {
        let mut bytes = Vec::with_capacity(MAX_QUERY_REQUEST_BYTES);
        match &self.kind {
            LedgerAbciQueryKind::Status { .. } => {}
            LedgerAbciQueryKind::Block { height } => bytes.extend_from_slice(&height.to_be_bytes()),
            LedgerAbciQueryKind::Channel { channel, .. } => bytes.extend_from_slice(channel.as_bytes()),
            LedgerAbciQueryKind::Request {
                channel,
                participant,
                request,
                ..
            } => {
                bytes.extend_from_slice(channel.as_bytes());
                bytes.extend_from_slice(participant.as_bytes());
                bytes.extend_from_slice(request.as_bytes());
            }
            LedgerAbciQueryKind::Proof { height, block_index } => {
                bytes.extend_from_slice(&height.to_be_bytes());
                bytes.extend_from_slice(&block_index.to_be_bytes());
            }
            LedgerAbciQueryKind::ExecutionRange(request) => {
                bytes.extend_from_slice(&request.cursor().next_height().to_be_bytes());
                bytes.extend_from_slice(request.cursor().expected_previous_app_hash().as_bytes());
                bytes.extend_from_slice(&request.block_count().to_be_bytes());
                bytes.extend_from_slice(&request.max_encoded_bytes().to_be_bytes());
            }
            LedgerAbciQueryKind::EntryLocation(request) => {
                bytes.extend_from_slice(request.channel_context_id().as_bytes());
                bytes.extend_from_slice(request.entry_hash().as_bytes());
                bytes.extend_from_slice(&request.through_height().to_be_bytes());
                bytes.extend_from_slice(request.expected_through_app_hash().as_bytes());
            }
        }
        if bytes.len() > MAX_QUERY_REQUEST_BYTES {
            return Err(RpcTransportError::InvalidConfiguration(
                "Ledger ABCI query key exceeds the committed bound",
            ));
        }
        Ok(bytes)
    }

    fn validate_chain(&self, expected: &LedgerChainIdV2) -> Result<()> {
        let embedded = match &self.kind {
            LedgerAbciQueryKind::ExecutionRange(request) => Some(request.cursor().ledger_chain_id()),
            LedgerAbciQueryKind::EntryLocation(request) => Some(request.ledger_chain_id()),
            _ => None,
        };
        if embedded.is_some_and(|chain| chain != expected) {
            return Err(RpcTransportError::ChainIdentity);
        }
        Ok(())
    }

    fn validate_value(&self, expected_chain: &LedgerChainIdV2, bytes: &[u8]) -> Result<()> {
        match &self.kind {
            LedgerAbciQueryKind::Status { height } => {
                let value: StatusQueryValue = decode_canonical(bytes)?;
                if value.application_version != 2
                    || value.ledger_chain_id != expected_chain.as_str()
                    || value.last_height != *height
                    || value.last_block_time_ms == 0
                    || value.last_app_hash.is_zero()
                {
                    return Err(RpcTransportError::ApplicationResponse);
                }
            }
            LedgerAbciQueryKind::Block { height } => {
                let block: ExecutedBlockV2 = decode_canonical(bytes)?;
                block
                    .validate_chain_id(expected_chain)
                    .map_err(|_| RpcTransportError::ApplicationResponse)?;
                if block.height() != *height {
                    return Err(RpcTransportError::ApplicationResponse);
                }
            }
            LedgerAbciQueryKind::Channel { channel, height } => {
                let value: ChannelQueryValue = decode_canonical(bytes)?;
                value
                    .snapshot
                    .validate()
                    .map_err(|_| RpcTransportError::ApplicationResponse)?;
                let context = value
                    .snapshot
                    .binding
                    .context_id()
                    .map_err(|_| RpcTransportError::ApplicationResponse)?;
                if value.committed_application_height != *height
                    || value.committed_application_hash.is_zero()
                    || value.snapshot.ledger_chain_id != *expected_chain
                    || context != *channel.as_bytes()
                {
                    return Err(RpcTransportError::ApplicationResponse);
                }
            }
            LedgerAbciQueryKind::Request {
                channel,
                participant,
                request,
                height,
            } => {
                let value: RequestQueryValue = decode_canonical(bytes)?;
                if value.channel_context_id != *channel
                    || value.participant_id != *participant
                    || value.request_digest != *request
                    || value.first_height == 0
                    || value.first_height > *height
                    || usize::try_from(value.first_block_index).map_or(true, |index| index >= MAX_BLOCK_ENTRIES)
                {
                    return Err(RpcTransportError::ApplicationResponse);
                }
            }
            LedgerAbciQueryKind::Proof { height, block_index } => {
                let value: ProofQueryValue = decode_canonical(bytes)?;
                value
                    .block
                    .validate_chain_id(expected_chain)
                    .map_err(|_| RpcTransportError::ApplicationResponse)?;
                let entry = value
                    .block
                    .entries()
                    .get(usize::try_from(*block_index).map_err(|_| RpcTransportError::ApplicationResponse)?)
                    .ok_or(RpcTransportError::ApplicationResponse)?;
                if !value.execution_only
                    || value.block.height() != *height
                    || entry != &value.entry
                    || value.entry.metadata().block_index() != *block_index
                {
                    return Err(RpcTransportError::ApplicationResponse);
                }
                value
                    .proof
                    .verify(value.entry.metadata(), &value.block)
                    .map_err(|_| RpcTransportError::ApplicationResponse)?;
            }
            LedgerAbciQueryKind::ExecutionRange(request) => {
                let rpc_request = RpcRequestV2::ExecutionRange(request.clone());
                let decoded = RpcResponseV2::from_canonical_bytes_for(bytes, &rpc_request)
                    .map_err(|_| RpcTransportError::ApplicationResponse)?;
                if !matches!(decoded.response(), RpcResponseV2::ExecutionRange(_)) {
                    return Err(RpcTransportError::ApplicationResponse);
                }
            }
            LedgerAbciQueryKind::EntryLocation(request) => {
                let rpc_request = RpcRequestV2::EntryLocation(request.clone());
                let decoded = RpcResponseV2::from_canonical_bytes_for(bytes, &rpc_request)
                    .map_err(|_| RpcTransportError::ApplicationResponse)?;
                if !matches!(decoded.response(), RpcResponseV2::EntryLocation(_)) {
                    return Err(RpcTransportError::ApplicationResponse);
                }
            }
        }
        Ok(())
    }
}

/// Authenticated fixed-path ABCI application bytes.
///
/// The bytes are deterministic execution output only. The caller must bind the
/// matching execution app hash to a separately verified CometBFT header before
/// issuing any finality capability.
pub struct AuthenticatedAbciQueryV2 {
    query: LedgerAbciQueryV2,
    height: u64,
    value: Vec<u8>,
    evidence: LedgerRpcSessionEvidence,
}

impl AuthenticatedAbciQueryV2 {
    /// Returns the exact fixed query.
    pub const fn query(&self) -> &LedgerAbciQueryV2 {
        &self.query
    }

    /// Returns the exact application execution height.
    pub const fn height(&self) -> u64 {
        self.height
    }

    /// Returns exact validated application response bytes.
    pub fn value(&self) -> &[u8] {
        &self.value
    }

    /// Returns authenticated in-process session evidence.
    pub const fn evidence(&self) -> &LedgerRpcSessionEvidence {
        &self.evidence
    }
}

impl fmt::Debug for AuthenticatedAbciQueryV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthenticatedAbciQueryV2")
            .field("query", &self.query)
            .field("height", &self.height)
            .field("value_bytes", &self.value.len())
            .field("evidence", &self.evidence)
            .finish()
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BroadcastResult {
    #[serde(deserialize_with = "decimal_u32")]
    code: u32,
    #[serde(default)]
    data: String,
    #[serde(default)]
    log: String,
    #[serde(default)]
    codespace: String,
    hash: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AbciQueryResult {
    response: AbciQueryResponse,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AbciQueryResponse {
    #[serde(default, deserialize_with = "decimal_u32")]
    code: u32,
    #[serde(default)]
    log: String,
    #[serde(default)]
    info: String,
    #[serde(default, deserialize_with = "decimal_i64")]
    index: i64,
    #[serde(default)]
    key: Option<String>,
    #[serde(default)]
    value: Option<String>,
    #[serde(default)]
    proof_ops: Option<serde_json::Value>,
    #[serde(default, deserialize_with = "decimal_i64")]
    height: i64,
    #[serde(default)]
    codespace: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct StatusQueryValue {
    application_version: u64,
    ledger_chain_id: String,
    last_height: u64,
    last_block_time_ms: u64,
    last_app_hash: AppHashV2,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ChannelQueryValue {
    committed_application_height: u64,
    committed_application_hash: AppHashV2,
    snapshot: ChannelSnapshotV2,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RequestQueryValue {
    channel_context_id: ChannelContextIdV2,
    participant_id: ParticipantIdV2,
    request_digest: RequestDigestV2,
    entry_hash: EntryHashV2,
    first_height: u64,
    first_block_index: u32,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ProofQueryValue {
    execution_only: bool,
    block: ExecutedBlockV2,
    entry: ExecutedEntryV2,
    proof: EntryMerkleProofV2,
}

#[derive(Clone, Copy)]
pub(crate) struct LedgerCallPolicy {
    pub limits: RpcLimits,
    pub ledger_limits: LedgerRpcLimits,
    pub retry: RetryPolicy,
    pub timeout: Duration,
}

pub(crate) async fn broadcast_tx_sync(
    peer: &RuntimePeer,
    expected_peer: &PeerIdentity,
    ledger_chain_id: &LedgerChainIdV2,
    proposal: &SignedProposalV2,
    policy: LedgerCallPolicy,
) -> Result<AuthenticatedBroadcastTxSyncV2> {
    validate_peer(peer, expected_peer)?;
    validate_ledger_chain(ledger_chain_id)?;
    proposal.verify().map_err(|_| RpcTransportError::ApplicationResponse)?;
    proposal
        .body()
        .validate_chain_id(ledger_chain_id)
        .map_err(|_| RpcTransportError::ChainIdentity)?;
    let transaction = serde_json::to_vec(proposal).map_err(|_| RpcTransportError::Json)?;
    if transaction.is_empty() || transaction.len() > MAX_SIGNED_PROPOSAL_JSON_BYTES {
        return Err(RpcTransportError::TraceBound);
    }
    let transaction_hash: [u8; 32] = Sha256::digest(&transaction).into();
    let proposal_digest = *proposal
        .body()
        .proposal_digest()
        .map_err(|_| RpcTransportError::ApplicationResponse)?
        .as_bytes();
    let entry_hash = *proposal
        .body()
        .entry_hash()
        .map_err(|_| RpcTransportError::ApplicationResponse)?
        .as_bytes();
    let deadline = request_deadline(policy.timeout)?;
    let mut context = RpcContext::with_body_limits(
        deadline,
        policy.limits,
        policy.retry,
        policy.ledger_limits.response_bytes(),
        policy.ledger_limits.aggregate_bytes(),
    )?;
    let _ = authenticate_status(&mut context, peer, expected_peer, ledger_chain_id).await?;
    let encoded_transaction = BASE64_STANDARD.encode(&transaction);
    let call: RpcCall<BroadcastResult> = context
        .call_write_once(
            peer,
            BROADCAST_METHOD,
            json!({"tx": encoded_transaction}),
            transaction_hash,
            policy
                .ledger_limits
                .response_bytes()
                .min(MAX_BROADCAST_RPC_RESPONSE_BYTES),
        )
        .await?;
    let returned_hash = decode_upper_hex_32(&call.value.hash).map_err(|_| RpcTransportError::AmbiguousWrite {
        tx_hash: transaction_hash,
    })?;
    if returned_hash != transaction_hash || call.value.log.len() > 64 * 1024 || call.value.codespace != ABCI_CODESPACE {
        return Err(RpcTransportError::AmbiguousWrite {
            tx_hash: transaction_hash,
        });
    }
    if (call.value.code == 0 && decode_upper_hex_32(&call.value.data).ok() != Some(entry_hash))
        || (call.value.code != 0 && !call.value.data.is_empty())
    {
        return Err(RpcTransportError::AmbiguousWrite {
            tx_hash: transaction_hash,
        });
    }
    let admission = if call.value.code == 0 {
        BroadcastAdmissionV2::Accepted
    } else {
        BroadcastAdmissionV2::Rejected { code: call.value.code }
    };
    let mut application = Vec::with_capacity(68);
    application.extend_from_slice(&transaction_hash);
    application.extend_from_slice(&entry_hash);
    application.extend_from_slice(&call.value.code.to_be_bytes());
    let transcript_digest = context.transcript_digest();
    let evidence = evidence(
        BROADCAST_EVIDENCE_DOMAIN,
        expected_peer,
        ledger_chain_id,
        &call,
        Sha256::digest(&application).into(),
        transcript_digest,
    );
    Ok(AuthenticatedBroadcastTxSyncV2 {
        transaction_hash,
        proposal_digest,
        admission,
        evidence,
    })
}

pub(crate) async fn abci_query(
    peer: &RuntimePeer,
    expected_peer: &PeerIdentity,
    ledger_chain_id: &LedgerChainIdV2,
    query: &LedgerAbciQueryV2,
    policy: LedgerCallPolicy,
) -> Result<AuthenticatedAbciQueryV2> {
    validate_peer(peer, expected_peer)?;
    validate_ledger_chain(ledger_chain_id)?;
    query.validate_chain(ledger_chain_id)?;
    let deadline = request_deadline(policy.timeout)?;
    let attempts = policy.retry.attempts().get();
    for attempt in 0..attempts {
        let result = abci_query_attempt(
            peer,
            expected_peer,
            ledger_chain_id,
            query,
            policy.limits,
            policy.ledger_limits,
            deadline,
        )
        .await;
        match result {
            Ok(response) => return Ok(response),
            Err(RpcTransportError::RetryExhausted) if attempt + 1 < attempts => {
                retry_wait(deadline, policy.retry, attempt).await?;
            }
            Err(error) => return Err(error),
        }
    }
    Err(RpcTransportError::RetryExhausted)
}

async fn abci_query_attempt(
    peer: &RuntimePeer,
    expected_peer: &PeerIdentity,
    ledger_chain_id: &LedgerChainIdV2,
    query: &LedgerAbciQueryV2,
    limits: RpcLimits,
    ledger_limits: LedgerRpcLimits,
    deadline: Instant,
) -> Result<AuthenticatedAbciQueryV2> {
    let mut context = RpcContext::with_body_limits(
        deadline,
        limits,
        RetryPolicy::single_attempt(),
        ledger_limits.response_bytes(),
        ledger_limits.aggregate_bytes(),
    )?;
    let latest_consensus_height = authenticate_status(&mut context, peer, expected_peer, ledger_chain_id).await?;
    let query_data = query.data()?;
    let expected_height = query.height()?;
    if latest_consensus_height < expected_height {
        return Err(RpcTransportError::Height);
    }
    let call: RpcCall<AbciQueryResult> = context
        .call_evidenced(
            peer,
            ABCI_QUERY_METHOD,
            json!({
                "path": query.path(),
                "data": hex::encode_upper(&query_data),
                "height": expected_height.to_string(),
                "prove": false,
            }),
        )
        .await?;
    let response = &call.value.response;
    if response.code != 0 {
        return Err(RpcTransportError::AbciQueryRejected { code: response.code });
    }
    if response.index != 0
        || response.proof_ops.is_some()
        || response.height != i64::try_from(expected_height).map_err(|_| RpcTransportError::Height)?
        || response.codespace != ABCI_CODESPACE
        || response.log.len() > 64 * 1024
        || response.info.len() > 64 * 1024
    {
        return Err(RpcTransportError::ApplicationResponse);
    }
    let returned_key = decode_base64_bounded(response.key.as_deref(), MAX_QUERY_REQUEST_BYTES)?;
    if returned_key != query_data {
        return Err(RpcTransportError::ApplicationResponse);
    }
    let value = decode_base64_bounded(response.value.as_deref(), MAX_QUERY_RESPONSE_BYTES)?;
    if value.is_empty() {
        return Err(RpcTransportError::ApplicationResponse);
    }
    query.validate_value(ledger_chain_id, &value)?;
    let application_digest = Sha256::digest(&value).into();
    let transcript_digest = context.transcript_digest();
    let evidence = evidence(
        QUERY_EVIDENCE_DOMAIN,
        expected_peer,
        ledger_chain_id,
        &call,
        application_digest,
        transcript_digest,
    );
    Ok(AuthenticatedAbciQueryV2 {
        query: query.clone(),
        height: expected_height,
        value,
        evidence,
    })
}

async fn authenticate_status(
    context: &mut RpcContext,
    peer: &RuntimePeer,
    expected_peer: &PeerIdentity,
    ledger_chain_id: &LedgerChainIdV2,
) -> Result<u64> {
    let status: StatusResult = context
        .call_with_limit(peer, STATUS_METHOD, json!({}), MAX_LEDGER_STATUS_RESPONSE_BYTES)
        .await?;
    if status.node_info.id != expected_peer.node_id() {
        return Err(RpcTransportError::NodeIdentity);
    }
    if status.node_info.network.as_str() != ledger_chain_id.as_str() {
        return Err(RpcTransportError::ChainIdentity);
    }
    Ok(status.sync_info.latest_block_height.value())
}

fn validate_peer(peer: &RuntimePeer, expected: &PeerIdentity) -> Result<()> {
    if peer.peer.identity().node_id() != expected.node_id()
        || peer.peer.identity().transport_binding() != expected.transport_binding()
    {
        return Err(RpcTransportError::UnknownPeer);
    }
    Ok(())
}

fn validate_ledger_chain(chain: &LedgerChainIdV2) -> Result<()> {
    tendermint::chain::Id::from_str(chain.as_str())
        .map(|_| ())
        .map_err(|_| RpcTransportError::InvalidConfiguration("Ledger chain id is not a CometBFT chain id"))
}

fn request_deadline(timeout: Duration) -> Result<Instant> {
    if !(MIN_LEDGER_RPC_TIMEOUT..=MAX_LEDGER_RPC_TIMEOUT).contains(&timeout) {
        return Err(RpcTransportError::InvalidConfiguration(
            "Ledger RPC timeout is outside bounds",
        ));
    }
    Instant::now().checked_add(timeout).ok_or(RpcTransportError::Deadline)
}

async fn retry_wait(deadline: Instant, retry: RetryPolicy, attempt: u8) -> Result<()> {
    let multiplier = 1_u32
        .checked_shl(u32::from(attempt))
        .ok_or(RpcTransportError::Deadline)?;
    let delay = retry
        .base_delay()
        .checked_mul(multiplier)
        .ok_or(RpcTransportError::Deadline)?;
    timeout_at(deadline, tokio::time::sleep(delay)).await?;
    Ok(())
}

fn evidence<T>(
    domain: &[u8],
    peer: &PeerIdentity,
    ledger_chain_id: &LedgerChainIdV2,
    call: &RpcCall<T>,
    application_digest: [u8; 32],
    transcript_digest: [u8; 32],
) -> LedgerRpcSessionEvidence {
    let mut hasher = Sha256::new();
    hasher.update(u64::try_from(domain.len()).unwrap_or(u64::MAX).to_be_bytes());
    hasher.update(domain);
    hasher.update(peer.transport_binding());
    hasher.update(peer.node_id().as_bytes());
    hasher.update(
        u64::try_from(ledger_chain_id.as_str().len())
            .unwrap_or(u64::MAX)
            .to_be_bytes(),
    );
    hasher.update(ledger_chain_id.as_str().as_bytes());
    hasher.update(call.security_binding);
    hasher.update(call.request_digest);
    hasher.update(call.response_digest);
    hasher.update(application_digest);
    hasher.update(transcript_digest);
    LedgerRpcSessionEvidence {
        transport_binding: *peer.transport_binding(),
        node_id: peer.node_id(),
        ledger_chain_id: ledger_chain_id.clone(),
        request_digest: call.request_digest,
        response_digest: call.response_digest,
        application_digest,
        transcript_digest,
        session_digest: hasher.finalize().into(),
    }
}

fn decode_canonical<T>(bytes: &[u8]) -> Result<T>
where
    T: DeserializeOwned + Serialize,
{
    let value: T = serde_json::from_slice(bytes).map_err(|_| RpcTransportError::ApplicationResponse)?;
    if serde_json::to_vec(&value).map_err(|_| RpcTransportError::ApplicationResponse)? != bytes {
        return Err(RpcTransportError::ApplicationResponse);
    }
    Ok(value)
}

fn decode_base64_bounded(encoded: Option<&str>, maximum: usize) -> Result<Vec<u8>> {
    let encoded = encoded.unwrap_or_default();
    let maximum_encoded = maximum
        .checked_add(2)
        .and_then(|value| value.checked_div(3))
        .and_then(|value| value.checked_mul(4))
        .ok_or(RpcTransportError::ResponseTooLarge)?;
    if encoded.len() > maximum_encoded {
        return Err(RpcTransportError::ResponseTooLarge);
    }
    let capacity = encoded
        .len()
        .checked_div(4)
        .and_then(|groups| groups.checked_mul(3))
        .ok_or(RpcTransportError::ResponseTooLarge)?
        .min(maximum);
    let mut decoded = vec![0_u8; capacity];
    let decoded_len = match BASE64_STANDARD.decode_slice(encoded, &mut decoded) {
        Ok(length) => length,
        Err(base64::DecodeSliceError::OutputSliceTooSmall) => {
            return Err(RpcTransportError::ResponseTooLarge);
        }
        Err(base64::DecodeSliceError::DecodeError(_)) => {
            return Err(RpcTransportError::ApplicationResponse);
        }
    };
    decoded.truncate(decoded_len);
    if BASE64_STANDARD.encode(&decoded) != encoded {
        return Err(RpcTransportError::ApplicationResponse);
    }
    Ok(decoded)
}

fn decode_upper_hex_32(encoded: &str) -> Result<[u8; 32]> {
    if encoded.len() != 64 || encoded.bytes().any(|byte| byte.is_ascii_lowercase()) {
        return Err(RpcTransportError::ApplicationResponse);
    }
    let bytes = hex::decode(encoded).map_err(|_| RpcTransportError::ApplicationResponse)?;
    bytes.try_into().map_err(|_| RpcTransportError::ApplicationResponse)
}

fn validate_height(height: u64) -> Result<()> {
    if height == 0 || height > i64::MAX as u64 {
        return Err(RpcTransportError::InvalidConfiguration(
            "Ledger ABCI query height is outside bounds",
        ));
    }
    Ok(())
}

fn decimal_u32<'de, D: Deserializer<'de>>(deserializer: D) -> std::result::Result<u32, D::Error> {
    let value = Decimal::deserialize(deserializer)?;
    match value {
        Decimal::String(value) => value.parse::<u32>().map_err(serde::de::Error::custom),
        Decimal::Number(value) => u32::try_from(value).map_err(serde::de::Error::custom),
    }
}

fn decimal_i64<'de, D: Deserializer<'de>>(deserializer: D) -> std::result::Result<i64, D::Error> {
    let value = Decimal::deserialize(deserializer)?;
    match value {
        Decimal::String(value) => value.parse::<i64>().map_err(serde::de::Error::custom),
        Decimal::Number(value) => i64::try_from(value).map_err(serde::de::Error::custom),
    }
}

#[derive(Deserialize)]
#[serde(untagged)]
enum Decimal {
    String(String),
    Number(u64),
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
mod tests {
    use proptest::prelude::*;
    use thunderbolt_ledger_rpc::{
        EntryLocationRequestV2, ExecutionRangeCursorV2, ExecutionRangeRequestV2, MAX_EXECUTION_RANGE_ENCODED_BYTES,
    };

    use super::*;

    fn chain() -> LedgerChainIdV2 {
        LedgerChainIdV2::new("ledger-query-regtest-2").expect("chain")
    }

    #[test]
    fn every_public_query_constructor_maps_to_one_fixed_committed_path() {
        let channel = ChannelContextIdV2::from_bytes([0x11; 32]).expect("channel");
        let participant = ParticipantIdV2::from_bytes([0x22; 32]).expect("participant");
        let request = RequestDigestV2::from_bytes([0x33; 32]).expect("request");
        let range = ExecutionRangeRequestV2::new(
            ExecutionRangeCursorV2::new(chain(), 2, AppHashV2::from_bytes([0x44; 32]).expect("hash")).expect("cursor"),
            3,
            MAX_EXECUTION_RANGE_ENCODED_BYTES,
        )
        .expect("range");
        let location = EntryLocationRequestV2::new(
            chain(),
            channel.clone(),
            EntryHashV2::from_bytes([0x55; 32]).expect("entry"),
            4,
            AppHashV2::from_bytes([0x66; 32]).expect("hash"),
        )
        .expect("location");
        let queries = [
            (LedgerAbciQueryV2::status(4).expect("status"), QUERY_STATUS_PATH, 0),
            (LedgerAbciQueryV2::block(4).expect("block"), QUERY_BLOCK_PATH, 8),
            (
                LedgerAbciQueryV2::channel(channel.clone(), 4).expect("channel"),
                QUERY_CHANNEL_PATH,
                32,
            ),
            (
                LedgerAbciQueryV2::request(channel, participant, request, 4).expect("request"),
                QUERY_REQUEST_PATH,
                96,
            ),
            (LedgerAbciQueryV2::proof(4, 0).expect("proof"), QUERY_PROOF_PATH, 12),
            (
                LedgerAbciQueryV2::execution_range(range),
                QUERY_EXECUTION_RANGE_PATH,
                46,
            ),
            (
                LedgerAbciQueryV2::entry_location(location),
                QUERY_ENTRY_LOCATION_PATH,
                104,
            ),
        ];
        for (query, path, data_len) in queries {
            assert_eq!(query.path(), path);
            assert_eq!(query.data().expect("query data").len(), data_len);
            assert_eq!(query.height().expect("query height"), 4);
        }
        assert!(LedgerAbciQueryV2::status(0).is_err());
        assert!(LedgerAbciQueryV2::proof(1, u32::try_from(MAX_BLOCK_ENTRIES).expect("index")).is_err());
    }

    fn fail(error: impl fmt::Display) -> TestCaseError {
        TestCaseError::fail(error.to_string())
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(96))]

        #[test]
        fn bounded_base64_decode_round_trips_canonically(bytes in prop::collection::vec(any::<u8>(), 0..=4096)) {
            let encoded = BASE64_STANDARD.encode(&bytes);
            let decoded = decode_base64_bounded(Some(&encoded), bytes.len()).map_err(fail)?;
            prop_assert_eq!(decoded, bytes);
        }

        #[test]
        fn base64_cap_is_checked_before_decode(
            bytes in prop::collection::vec(any::<u8>(), 1..=4096),
        ) {
            let encoded = BASE64_STANDARD.encode(&bytes);
            prop_assert!(decode_base64_bounded(Some(&encoded), bytes.len() - 1).is_err());
        }
    }
}
