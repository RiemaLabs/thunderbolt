//! CometBFT v0.38.25 ABCI 2.0 adapter for Bitcoin Thunderbolt Ledger v2.
//!
//! The adapter implements the `tendermint-abci` 0.40.4 [`Application`] trait
//! over [`thunderbolt_ledger_app::LedgerApplication`]. `FinalizeBlock` runs the
//! exact application path in a rollback-only SQLite transaction and stages the
//! opaque prepared value in memory. `Commit` alone re-executes and atomically
//! persists it. Application state produced at height `H` is returned from
//! `FinalizeBlock` and belongs in the CometBFT header at height `H + 1`.
//!
//! This crate is an execution adapter. It does not start CometBFT, configure a
//! validator set, establish quorum finality, implement state sync or vote
//! extensions, or turn execution proofs into finality capabilities.

#![deny(missing_docs)]
#![deny(
    clippy::expect_used,
    clippy::panic,
    clippy::todo,
    clippy::unimplemented,
    clippy::unwrap_used
)]
#![forbid(unsafe_code)]

mod error;

use std::fmt;
use std::sync::{Arc, Mutex, MutexGuard};

use bytes::Bytes;
use serde::{Deserialize, Serialize};
use tendermint_abci::Application;
use tendermint_proto::v0_38::abci::{
    response_apply_snapshot_chunk, response_offer_snapshot, response_process_proposal, response_verify_vote_extension,
    CheckTxType, ExecTxResult, RequestApplySnapshotChunk, RequestCheckTx, RequestExtendVote, RequestFinalizeBlock,
    RequestInfo, RequestInitChain, RequestLoadSnapshotChunk, RequestOfferSnapshot, RequestPrepareProposal,
    RequestProcessProposal, RequestQuery, RequestVerifyVoteExtension, ResponseApplySnapshotChunk, ResponseCheckTx,
    ResponseCommit, ResponseExtendVote, ResponseFinalizeBlock, ResponseInfo, ResponseInitChain, ResponseListSnapshots,
    ResponseLoadSnapshotChunk, ResponseOfferSnapshot, ResponsePrepareProposal, ResponseProcessProposal, ResponseQuery,
    ResponseVerifyVoteExtension,
};
use tendermint_proto::v0_38::types::{AbciParams, ConsensusParams, VersionParams};
use thunderbolt_ledger::{
    ActorSignatureV2, AppHashV2, ChannelContextIdV2, ParticipantIdV2, PendingBlockV2, ProposalBodyV2, RequestDigestV2,
    SignedProposalV2, MAX_BLOCK_ENTRIES,
};
use thunderbolt_ledger_app::{
    ApplicationStatusV2, BlockInputV2, LedgerApplication, LedgerApplicationVerifierV2, PreparedBlockV2,
};
use thunderbolt_protocol::v2::ChannelSnapshotV2;

pub use error::{AbciAdapterError, Result};
pub use thunderbolt_ledger_app::APPLICATION_VERSION_V2;

/// ABCI application name returned by `Info`.
pub const APPLICATION_NAME: &str = "bitcoin-thunderbolt-ledger-v2";
/// ABCI application version pinned by the v2 header/finality profile.
pub const APPLICATION_VERSION: u64 = APPLICATION_VERSION_V2;
/// Codespace used for deterministic transaction and query failures.
pub const ABCI_CODESPACE: &str = "thunderbolt";
/// Canonical query path for the durable application head.
pub const QUERY_STATUS_PATH: &str = "/thunderbolt/v2/status";
/// Canonical query path for an executed block. Data is one big-endian `u64`.
pub const QUERY_BLOCK_PATH: &str = "/thunderbolt/v2/block";
/// Canonical query path for a current channel. Data is a 32-byte context ID.
pub const QUERY_CHANNEL_PATH: &str = "/thunderbolt/v2/channel";
/// Canonical query path for a request mapping. Data is context, participant,
/// then request digest, each exactly 32 bytes.
pub const QUERY_REQUEST_PATH: &str = "/thunderbolt/v2/request";
/// Canonical query path for execution inclusion evidence. Data is a big-endian
/// `u64` block height followed by a big-endian `u32` entry index.
pub const QUERY_PROOF_PATH: &str = "/thunderbolt/v2/proof";

/// Maximum canonical JSON bytes accepted for one signed proposal.
pub const MAX_TRANSACTION_BYTES: usize = 1024 * 1024;
/// Maximum aggregate transaction bytes accepted in one proposal or block.
pub const MAX_BLOCK_TRANSACTION_BYTES: usize = 24 * 1024 * 1024;
/// Maximum ABCI query key bytes accepted before parsing.
pub const MAX_QUERY_REQUEST_BYTES: usize = 128;
/// Maximum serialized query value returned by this adapter.
pub const MAX_QUERY_RESPONSE_BYTES: usize = 24 * 1024 * 1024;
/// Maximum misbehavior records accepted in one consensus request.
pub const MAX_MISBEHAVIOR_RECORDS: usize = 64;
/// Maximum validator votes accepted in one commit-info value.
pub const MAX_COMMIT_VOTES: usize = 64;

const OK_CODE: u32 = 0;

/// Clone-safe ABCI application backed by one synchronized Ledger application.
///
/// Every clone shares the durable SQLite handle, verifier capability, staged
/// block, and fail-closed fault state. The verifier must be deterministic and
/// side-effect free as required by `LedgerApplicationVerifierV2`.
pub struct ThunderboltLedgerAbci<V> {
    inner: Arc<Shared<V>>,
}

impl<V> Clone for ThunderboltLedgerAbci<V> {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

impl<V> fmt::Debug for ThunderboltLedgerAbci<V> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ThunderboltLedgerAbci")
            .field("ledger_chain_id", self.inner.application.ledger_chain_id())
            .field("application_version", &APPLICATION_VERSION)
            .finish_non_exhaustive()
    }
}

struct Shared<V> {
    application: LedgerApplication,
    verifier: V,
    runtime: Mutex<RuntimeState>,
}

#[derive(Default)]
struct RuntimeState {
    staged: Option<StagedBlock>,
    faulted: bool,
}

struct StagedBlock {
    identity: FinalizeIdentity,
    prepared: PreparedBlockV2,
    response: ResponseFinalizeBlock,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct FinalizeIdentity {
    height: u64,
    block_time_ms: u64,
    block_hash: Vec<u8>,
    transactions: Vec<Vec<u8>>,
    next_validators_hash: Vec<u8>,
    proposer_address: Vec<u8>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SignedProposalEnvelope {
    body: ProposalBodyV2,
    signature: ActorSignatureV2,
}

#[derive(Serialize)]
struct StatusQueryValue<'a> {
    application_version: u64,
    ledger_chain_id: &'a str,
    last_height: u64,
    last_block_time_ms: u64,
    last_app_hash: &'a AppHashV2,
}

#[derive(Serialize)]
struct ChannelQueryValue<'a> {
    committed_application_height: u64,
    committed_application_hash: &'a AppHashV2,
    snapshot: &'a ChannelSnapshotV2,
}

#[derive(Serialize)]
struct RequestQueryValue<'a> {
    channel_context_id: &'a ChannelContextIdV2,
    participant_id: &'a ParticipantIdV2,
    request_digest: &'a RequestDigestV2,
    entry_hash: &'a thunderbolt_ledger::EntryHashV2,
    first_height: u64,
    first_block_index: u32,
}

#[derive(Serialize)]
struct ProofQueryValue<'a> {
    execution_only: bool,
    block: &'a thunderbolt_ledger::ExecutedBlockV2,
    entry: &'a thunderbolt_ledger::ExecutedEntryV2,
    proof: &'a thunderbolt_ledger::EntryMerkleProofV2,
}

impl<V> ThunderboltLedgerAbci<V>
where
    V: LedgerApplicationVerifierV2 + Send + Sync + 'static,
{
    /// Constructs an ABCI adapter over an already opened, chain-scoped Ledger.
    pub fn new(application: LedgerApplication, verifier: V) -> Result<Self> {
        if application.application_version() != APPLICATION_VERSION || APPLICATION_VERSION != APPLICATION_VERSION_V2 {
            return Err(AbciAdapterError::InvalidRequest(
                "Ledger and ABCI application versions differ",
            ));
        }
        let status = application.status()?;
        if status.application_version() != APPLICATION_VERSION
            || status.ledger_chain_id() != application.ledger_chain_id()
        {
            return Err(AbciAdapterError::InvalidRequest(
                "durable Ledger identity differs from the ABCI adapter",
            ));
        }
        Ok(Self {
            inner: Arc::new(Shared {
                application,
                verifier,
                runtime: Mutex::new(RuntimeState::default()),
            }),
        })
    }

    /// Returns the exact chain ID accepted by this adapter.
    pub fn ledger_chain_id(&self) -> &thunderbolt_ledger::LedgerChainIdV2 {
        self.inner.application.ledger_chain_id()
    }

    /// Returns the fixed header application version.
    pub const fn application_version(&self) -> u64 {
        APPLICATION_VERSION
    }

    /// Builds a checked `Info` response from the durable head only.
    pub fn try_info(&self, _request: RequestInfo) -> Result<ResponseInfo> {
        let status = self.inner.application.status()?;
        Ok(ResponseInfo {
            data: APPLICATION_NAME.to_owned(),
            version: env!("CARGO_PKG_VERSION").to_owned(),
            app_version: APPLICATION_VERSION,
            last_block_height: height_i64(status.last_height())?,
            last_block_app_hash: status.last_app_hash().as_bytes().to_vec().into(),
        })
    }

    /// Validates genesis identity and returns version-two consensus parameters.
    /// No durable application state is created or changed here.
    pub fn try_init_chain(&self, request: RequestInitChain) -> Result<ResponseInitChain> {
        self.ensure_available()?;
        let status = self.inner.application.status()?;
        if status.last_height() != 0 || status.last_app_hash() != &AppHashV2::zero() {
            return Err(AbciAdapterError::InvalidRequest(
                "InitChain requires an empty Ledger application",
            ));
        }
        if request.chain_id != self.ledger_chain_id().as_str() {
            return Err(AbciAdapterError::InvalidRequest("InitChain chain id differs"));
        }
        if !matches!(request.initial_height, 0 | 1) {
            return Err(AbciAdapterError::InvalidRequest(
                "Thunderbolt Ledger v2 must start at height one",
            ));
        }
        if !request.app_state_bytes.is_empty() {
            return Err(AbciAdapterError::InvalidRequest(
                "Thunderbolt InitChain app state must be empty",
            ));
        }
        if let Some(parameters) = request.consensus_params.as_ref() {
            if parameters
                .version
                .is_some_and(|version| !matches!(version.app, 0 | APPLICATION_VERSION))
            {
                return Err(AbciAdapterError::InvalidRequest("genesis application version differs"));
            }
            if parameters
                .abci
                .is_some_and(|abci| abci.vote_extensions_enable_height > 0)
            {
                return Err(AbciAdapterError::InvalidRequest("vote extensions are not implemented"));
            }
        }
        Ok(ResponseInitChain {
            consensus_params: Some(ConsensusParams {
                version: Some(VersionParams {
                    app: APPLICATION_VERSION,
                }),
                abci: Some(AbciParams {
                    vote_extensions_enable_height: 0,
                }),
                ..ConsensusParams::default()
            }),
            validators: Vec::new(),
            app_hash: status.last_app_hash().as_bytes().to_vec().into(),
        })
    }

    /// Performs bounded, read-only admission checks for one canonical proposal.
    /// Consensus time and operation-specific proofs are checked later against
    /// the full ordered block.
    pub fn try_check_tx(&self, request: RequestCheckTx) -> Result<ResponseCheckTx> {
        self.ensure_available()?;
        let _ = CheckTxType::try_from(request.r#type)
            .map_err(|_| AbciAdapterError::InvalidRequest("CheckTx type is unknown"))?;
        let proposal = self.decode_transaction(request.tx.as_ref())?;
        let data = proposal.body().entry_hash()?.as_bytes().to_vec().into();
        let gas = i64::try_from(request.tx.len())
            .map_err(|_| AbciAdapterError::InvalidTransaction("transaction size exceeds i64"))?;
        Ok(ResponseCheckTx {
            code: OK_CODE,
            data,
            log: String::new(),
            info: String::new(),
            gas_wanted: gas,
            gas_used: gas,
            events: Vec::new(),
            codespace: ABCI_CODESPACE.to_owned(),
        })
    }

    /// Selects a canonical, order-preserving prefix/filter within both the
    /// CometBFT byte budget and Thunderbolt's hard block limits.
    pub fn try_prepare_proposal(&self, request: RequestPrepareProposal) -> Result<ResponsePrepareProposal> {
        self.ensure_available()?;
        let budget = usize::try_from(request.max_tx_bytes)
            .ok()
            .filter(|value| *value > 0)
            .map_or(0, |value| value.min(MAX_BLOCK_TRANSACTION_BYTES));
        if budget == 0 {
            return Ok(ResponsePrepareProposal { txs: Vec::new() });
        }
        let (height, block_time_ms) = validate_prepare_shape(&request)?;
        let status = self.inner.application.status()?;
        validate_next_head(&status, height, block_time_ms)?;
        let mut pending = PendingBlockV2::new(
            self.ledger_chain_id().clone(),
            height,
            block_time_ms,
            status.last_app_hash().clone(),
        )?;
        let mut selected = Vec::new();
        let mut selected_bytes = 0_usize;
        for transaction in request.txs {
            if transaction.is_empty() || transaction.len() > MAX_TRANSACTION_BYTES {
                continue;
            }
            let Some(next_total) = selected_bytes.checked_add(transaction.len()) else {
                break;
            };
            if next_total > budget || next_total > MAX_BLOCK_TRANSACTION_BYTES {
                break;
            }
            let Ok(proposal) = self.decode_transaction(transaction.as_ref()) else {
                continue;
            };
            if pending.push(proposal).is_err() {
                continue;
            }
            selected_bytes = next_total;
            selected.push(transaction);
            if selected.len() == MAX_BLOCK_ENTRIES {
                break;
            }
        }
        Ok(ResponsePrepareProposal { txs: selected })
    }

    /// Fully validates a proposed block through rollback-only application
    /// execution. No committed or staged state is changed.
    pub fn try_process_proposal(&self, request: RequestProcessProposal) -> Result<ResponseProcessProposal> {
        self.ensure_available()?;
        validate_consensus_shape(
            request.height,
            request.time.as_ref(),
            request.hash.as_ref(),
            request.next_validators_hash.as_ref(),
            request.proposer_address.as_ref(),
            request.misbehavior.len(),
            request.proposed_last_commit.as_ref(),
        )?;
        let input = self.block_input(request.height, request.time.as_ref(), &request.txs)?;
        let _ = self.inner.application.preview_block(input, &self.inner.verifier)?;
        Ok(ResponseProcessProposal {
            status: response_process_proposal::ProposalStatus::Accept as i32,
        })
    }

    /// Runs rollback-only execution and stages the exact result for `Commit`.
    /// Repeating the same finalized block before commit returns the cached
    /// deterministic response; a conflicting block fails closed.
    pub fn try_finalize_block(&self, request: RequestFinalizeBlock) -> Result<ResponseFinalizeBlock> {
        let mut runtime = self.lock_runtime()?;
        if runtime.faulted {
            return Err(AbciAdapterError::Faulted);
        }
        let (height, block_time_ms) = validate_consensus_shape(
            request.height,
            request.time.as_ref(),
            request.hash.as_ref(),
            request.next_validators_hash.as_ref(),
            request.proposer_address.as_ref(),
            request.misbehavior.len(),
            request.decided_last_commit.as_ref(),
        )?;
        validate_transaction_bounds(&request.txs)?;
        let identity = FinalizeIdentity {
            height,
            block_time_ms,
            block_hash: request.hash.to_vec(),
            transactions: request.txs.iter().map(|value| value.to_vec()).collect(),
            next_validators_hash: request.next_validators_hash.to_vec(),
            proposer_address: request.proposer_address.to_vec(),
        };
        if let Some(staged) = runtime.staged.as_ref() {
            if staged.identity == identity {
                return Ok(staged.response.clone());
            }
            return Err(AbciAdapterError::StagedBlockConflict);
        }
        let input = self.block_input(request.height, request.time.as_ref(), &request.txs)?;
        let prepared = self.inner.application.preview_block(input, &self.inner.verifier)?;
        let response = successful_finalize_response(&prepared);
        runtime.staged = Some(StagedBlock {
            identity,
            prepared,
            response: response.clone(),
        });
        Ok(response)
    }

    /// Atomically persists the currently staged block. With no staged block,
    /// this is an idempotent no-op suitable for a duplicated `Commit` call.
    pub fn try_commit(&self) -> Result<ResponseCommit> {
        let mut runtime = self.lock_runtime()?;
        if runtime.faulted {
            return Err(AbciAdapterError::Faulted);
        }
        let Some(staged) = runtime.staged.take() else {
            return Ok(ResponseCommit { retain_height: 0 });
        };
        let expected_hash = staged.prepared.outcome().block().app_hash().clone();
        match self
            .inner
            .application
            .commit_prepared_block(staged.prepared, &self.inner.verifier)
        {
            Ok(outcome) if outcome.block().app_hash() == &expected_hash => Ok(ResponseCommit { retain_height: 0 }),
            Ok(_) => {
                runtime.faulted = true;
                Err(AbciAdapterError::Application(
                    thunderbolt_ledger_app::ApplicationError::PreparedBlockMismatch,
                ))
            }
            Err(error) => {
                runtime.faulted = true;
                Err(error.into())
            }
        }
    }

    /// Executes one bounded, read-only application query.
    pub fn try_query(&self, request: RequestQuery) -> Result<ResponseQuery> {
        self.ensure_available()?;
        if request.data.len() > MAX_QUERY_REQUEST_BYTES {
            return Err(AbciAdapterError::InvalidRequest("query data exceeds bound"));
        }
        if request.height < 0 {
            return Err(AbciAdapterError::InvalidRequest("query height is negative"));
        }
        let status = self.inner.application.status()?;
        let (value, response_height) = match request.path.as_str() {
            QUERY_STATUS_PATH => {
                require_empty_data(request.data.as_ref())?;
                if request.prove {
                    return Err(AbciAdapterError::InvalidRequest(
                        "status query does not produce CometBFT ProofOps",
                    ));
                }
                require_current_query_height(request.height, status.last_height())?;
                let value = StatusQueryValue {
                    application_version: status.application_version(),
                    ledger_chain_id: status.ledger_chain_id().as_str(),
                    last_height: status.last_height(),
                    last_block_time_ms: status.last_block_time_ms(),
                    last_app_hash: status.last_app_hash(),
                };
                (encode_query_value(&value)?, status.last_height())
            }
            QUERY_BLOCK_PATH => {
                if request.prove {
                    return Err(AbciAdapterError::InvalidRequest(
                        "block query does not produce CometBFT ProofOps",
                    ));
                }
                let height = parse_height(request.data.as_ref())?;
                require_exact_query_height(request.height, height)?;
                let block = self
                    .inner
                    .application
                    .block(height)?
                    .ok_or(AbciAdapterError::NotFound("executed block"))?;
                (encode_query_value(&block)?, height)
            }
            QUERY_CHANNEL_PATH => {
                if request.prove {
                    return Err(AbciAdapterError::InvalidRequest(
                        "channel query does not produce CometBFT ProofOps",
                    ));
                }
                require_current_query_height(request.height, status.last_height())?;
                let context = ChannelContextIdV2::from_bytes(parse_array::<32>(request.data.as_ref(), "channel")?)?;
                let snapshot = self
                    .inner
                    .application
                    .channel_by_context(&context)?
                    .ok_or(AbciAdapterError::NotFound("channel"))?;
                let value = ChannelQueryValue {
                    committed_application_height: status.last_height(),
                    committed_application_hash: status.last_app_hash(),
                    snapshot: &snapshot,
                };
                (encode_query_value(&value)?, status.last_height())
            }
            QUERY_REQUEST_PATH => {
                if request.prove {
                    return Err(AbciAdapterError::InvalidRequest(
                        "request query does not produce CometBFT ProofOps",
                    ));
                }
                require_current_query_height(request.height, status.last_height())?;
                let (channel, participant, request_digest) = parse_request_key(request.data.as_ref())?;
                let stored = self
                    .inner
                    .application
                    .request(&channel, &participant, &request_digest)?
                    .ok_or(AbciAdapterError::NotFound("request mapping"))?;
                let value = RequestQueryValue {
                    channel_context_id: stored.channel_context_id(),
                    participant_id: stored.participant_id(),
                    request_digest: stored.request_digest(),
                    entry_hash: stored.entry_hash(),
                    first_height: stored.first_height(),
                    first_block_index: stored.first_block_index(),
                };
                (encode_query_value(&value)?, status.last_height())
            }
            QUERY_PROOF_PATH => {
                let (height, index) = parse_proof_key(request.data.as_ref())?;
                require_exact_query_height(request.height, height)?;
                let block = self
                    .inner
                    .application
                    .block(height)?
                    .ok_or(AbciAdapterError::NotFound("proof block"))?;
                let entry = block
                    .entries()
                    .get(index)
                    .ok_or(AbciAdapterError::NotFound("proof entry"))?;
                let proof = self.inner.application.entry_proof(height, index)?;
                let value = ProofQueryValue {
                    execution_only: true,
                    block: &block,
                    entry,
                    proof: &proof,
                };
                (encode_query_value(&value)?, height)
            }
            _ => return Err(AbciAdapterError::InvalidRequest("unknown query path")),
        };
        Ok(ResponseQuery {
            code: OK_CODE,
            log: String::new(),
            info: String::new(),
            index: 0,
            key: request.data,
            value: value.into(),
            proof_ops: None,
            height: height_i64(response_height)?,
            codespace: ABCI_CODESPACE.to_owned(),
        })
    }

    fn decode_transaction(&self, bytes: &[u8]) -> Result<SignedProposalV2> {
        if bytes.is_empty() || bytes.len() > MAX_TRANSACTION_BYTES {
            return Err(AbciAdapterError::InvalidTransaction(
                "transaction byte length is outside the bound",
            ));
        }
        let envelope: SignedProposalEnvelope = serde_json::from_slice(bytes)
            .map_err(|_| AbciAdapterError::InvalidTransaction("transaction JSON is invalid"))?;
        envelope
            .body
            .validate_chain_id(self.ledger_chain_id())
            .map_err(|_| AbciAdapterError::InvalidTransaction("transaction chain id differs"))?;
        let body = &envelope.body;
        let channel = ChannelContextIdV2::from_bytes(
            body.channel()
                .context_id()
                .map_err(|_| AbciAdapterError::InvalidTransaction("channel binding is invalid"))?,
        )
        .map_err(|_| AbciAdapterError::InvalidTransaction("channel context is invalid"))?;
        let participant = body
            .participant_id()
            .map_err(|_| AbciAdapterError::InvalidTransaction("participant identity is invalid"))?;
        if let Some(existing) = self
            .inner
            .application
            .request(&channel, &participant, body.request_id().digest())?
        {
            let entry_hash = body
                .entry_hash()
                .map_err(|_| AbciAdapterError::InvalidTransaction("entry hash is invalid"))?;
            if existing.entry_hash() != &entry_hash {
                return Err(AbciAdapterError::InvalidTransaction(
                    "actor request conflicts with durable mapping",
                ));
            }
        }
        let proposal = SignedProposalV2::new(envelope.body, envelope.signature)
            .map_err(|_| AbciAdapterError::InvalidTransaction("proposal signature or body is invalid"))?;
        let canonical = serde_json::to_vec(&proposal)
            .map_err(|_| AbciAdapterError::InvalidTransaction("transaction cannot be encoded"))?;
        if canonical != bytes {
            return Err(AbciAdapterError::InvalidTransaction(
                "transaction JSON is not canonical",
            ));
        }
        Ok(proposal)
    }

    fn block_input(
        &self,
        height: i64,
        time: Option<&tendermint_proto::google::protobuf::Timestamp>,
        transactions: &[Bytes],
    ) -> Result<BlockInputV2> {
        validate_transaction_bounds(transactions)?;
        let (height, block_time_ms) = height_and_time(height, time)?;
        let proposals = transactions
            .iter()
            .map(|transaction| self.decode_transaction(transaction.as_ref()))
            .collect::<Result<Vec<_>>>()?;
        let status = self.inner.application.status()?;
        validate_next_or_replay_head(&status, height, block_time_ms)?;
        Ok(BlockInputV2::new(
            self.ledger_chain_id().clone(),
            height,
            block_time_ms,
            if height == status.last_height() && height > 0 {
                self.inner
                    .application
                    .block(height)?
                    .ok_or(AbciAdapterError::NotFound("replayed block"))?
                    .previous_app_hash()
                    .clone()
            } else {
                status.last_app_hash().clone()
            },
            proposals,
        )?)
    }

    fn lock_runtime(&self) -> Result<MutexGuard<'_, RuntimeState>> {
        self.inner.runtime.lock().map_err(|_| AbciAdapterError::LockPoisoned)
    }

    fn ensure_available(&self) -> Result<()> {
        if self.lock_runtime()?.faulted {
            Err(AbciAdapterError::Faulted)
        } else {
            Ok(())
        }
    }

    fn mark_faulted(&self) {
        if let Ok(mut runtime) = self.inner.runtime.lock() {
            runtime.faulted = true;
        }
    }
}

fn validate_transaction_bounds(transactions: &[Bytes]) -> Result<()> {
    if transactions.len() > MAX_BLOCK_ENTRIES {
        return Err(AbciAdapterError::InvalidRequest(
            "block transaction count exceeds bound",
        ));
    }
    let total = transactions.iter().try_fold(0_usize, |sum, transaction| {
        sum.checked_add(transaction.len())
            .ok_or(AbciAdapterError::InvalidRequest("block byte count overflows"))
    })?;
    if total > MAX_BLOCK_TRANSACTION_BYTES {
        return Err(AbciAdapterError::InvalidRequest("block transaction bytes exceed bound"));
    }
    Ok(())
}

fn validate_prepare_shape(request: &RequestPrepareProposal) -> Result<(u64, u64)> {
    let pair = height_and_time(request.height, request.time.as_ref())?;
    if request.next_validators_hash.len() != 32 {
        return Err(AbciAdapterError::InvalidRequest("next validator hash must be 32 bytes"));
    }
    if request.proposer_address.len() != 20 {
        return Err(AbciAdapterError::InvalidRequest("proposer address must be 20 bytes"));
    }
    if request.misbehavior.len() > MAX_MISBEHAVIOR_RECORDS {
        return Err(AbciAdapterError::InvalidRequest(
            "misbehavior record count exceeds bound",
        ));
    }
    if let Some(commit) = request.local_last_commit.as_ref() {
        if commit.round < 0
            || commit.votes.len() > MAX_COMMIT_VOTES
            || commit
                .votes
                .iter()
                .any(|vote| !vote.vote_extension.is_empty() || !vote.extension_signature.is_empty())
        {
            return Err(AbciAdapterError::InvalidRequest(
                "extended commit info is unsupported or outside bounds",
            ));
        }
    }
    Ok(pair)
}

impl<V> Application for ThunderboltLedgerAbci<V>
where
    V: LedgerApplicationVerifierV2 + Send + Sync + 'static,
{
    fn info(&self, request: RequestInfo) -> ResponseInfo {
        self.try_info(request).unwrap_or_else(|_| {
            self.mark_faulted();
            ResponseInfo {
                data: APPLICATION_NAME.to_owned(),
                version: env!("CARGO_PKG_VERSION").to_owned(),
                app_version: APPLICATION_VERSION,
                last_block_height: 0,
                last_block_app_hash: Vec::new().into(),
            }
        })
    }

    fn init_chain(&self, request: RequestInitChain) -> ResponseInitChain {
        self.try_init_chain(request).unwrap_or_else(|_| {
            self.mark_faulted();
            ResponseInitChain {
                consensus_params: Some(ConsensusParams {
                    version: Some(VersionParams {
                        app: APPLICATION_VERSION,
                    }),
                    abci: Some(AbciParams {
                        vote_extensions_enable_height: 0,
                    }),
                    ..ConsensusParams::default()
                }),
                validators: Vec::new(),
                app_hash: Vec::new().into(),
            }
        })
    }

    fn query(&self, request: RequestQuery) -> ResponseQuery {
        let key = if request.data.len() <= MAX_QUERY_REQUEST_BYTES {
            request.data.clone()
        } else {
            Bytes::new()
        };
        self.try_query(request)
            .unwrap_or_else(|error| query_error_response(key, &error))
    }

    fn check_tx(&self, request: RequestCheckTx) -> ResponseCheckTx {
        self.try_check_tx(request)
            .unwrap_or_else(|error| check_error_response(&error))
    }

    fn prepare_proposal(&self, request: RequestPrepareProposal) -> ResponsePrepareProposal {
        self.try_prepare_proposal(request)
            .unwrap_or(ResponsePrepareProposal { txs: Vec::new() })
    }

    fn process_proposal(&self, request: RequestProcessProposal) -> ResponseProcessProposal {
        self.try_process_proposal(request).unwrap_or(ResponseProcessProposal {
            status: response_process_proposal::ProposalStatus::Reject as i32,
        })
    }

    fn finalize_block(&self, request: RequestFinalizeBlock) -> ResponseFinalizeBlock {
        let transaction_count = request.txs.len();
        match self.try_finalize_block(request) {
            Ok(response) => response,
            Err(error) => {
                self.mark_faulted();
                failed_finalize_response(transaction_count, &error)
            }
        }
    }

    fn commit(&self) -> ResponseCommit {
        self.try_commit().unwrap_or_else(|_| {
            self.mark_faulted();
            ResponseCommit { retain_height: 0 }
        })
    }

    fn list_snapshots(&self) -> ResponseListSnapshots {
        ResponseListSnapshots { snapshots: Vec::new() }
    }

    fn offer_snapshot(&self, _request: RequestOfferSnapshot) -> ResponseOfferSnapshot {
        ResponseOfferSnapshot {
            result: response_offer_snapshot::Result::Abort as i32,
        }
    }

    fn load_snapshot_chunk(&self, _request: RequestLoadSnapshotChunk) -> ResponseLoadSnapshotChunk {
        ResponseLoadSnapshotChunk {
            chunk: Vec::new().into(),
        }
    }

    fn apply_snapshot_chunk(&self, _request: RequestApplySnapshotChunk) -> ResponseApplySnapshotChunk {
        ResponseApplySnapshotChunk {
            result: response_apply_snapshot_chunk::Result::Abort as i32,
            refetch_chunks: Vec::new(),
            reject_senders: Vec::new(),
        }
    }

    fn extend_vote(&self, _request: RequestExtendVote) -> ResponseExtendVote {
        ResponseExtendVote {
            vote_extension: Vec::new().into(),
        }
    }

    fn verify_vote_extension(&self, _request: RequestVerifyVoteExtension) -> ResponseVerifyVoteExtension {
        ResponseVerifyVoteExtension {
            status: response_verify_vote_extension::VerifyStatus::Reject as i32,
        }
    }
}

fn validate_consensus_shape(
    height: i64,
    time: Option<&tendermint_proto::google::protobuf::Timestamp>,
    block_hash: &[u8],
    next_validators_hash: &[u8],
    proposer_address: &[u8],
    misbehavior_count: usize,
    commit: Option<&tendermint_proto::v0_38::abci::CommitInfo>,
) -> Result<(u64, u64)> {
    let pair = height_and_time(height, time)?;
    if block_hash.len() != 32 {
        return Err(AbciAdapterError::InvalidRequest("CometBFT block hash must be 32 bytes"));
    }
    if next_validators_hash.len() != 32 {
        return Err(AbciAdapterError::InvalidRequest("next validator hash must be 32 bytes"));
    }
    if proposer_address.len() != 20 {
        return Err(AbciAdapterError::InvalidRequest("proposer address must be 20 bytes"));
    }
    if misbehavior_count > MAX_MISBEHAVIOR_RECORDS {
        return Err(AbciAdapterError::InvalidRequest(
            "misbehavior record count exceeds bound",
        ));
    }
    if let Some(commit) = commit {
        if commit.round < 0 || commit.votes.len() > MAX_COMMIT_VOTES {
            return Err(AbciAdapterError::InvalidRequest("last commit info is outside bounds"));
        }
    }
    Ok(pair)
}

fn height_and_time(height: i64, time: Option<&tendermint_proto::google::protobuf::Timestamp>) -> Result<(u64, u64)> {
    let height = u64::try_from(height)
        .ok()
        .filter(|height| *height > 0)
        .ok_or(AbciAdapterError::InvalidRequest("consensus height must be positive"))?;
    let time = time.ok_or(AbciAdapterError::InvalidRequest("consensus time is missing"))?;
    if time.seconds < 0 || !(0..1_000_000_000).contains(&time.nanos) {
        return Err(AbciAdapterError::InvalidRequest(
            "consensus timestamp is outside protobuf bounds",
        ));
    }
    let seconds =
        u64::try_from(time.seconds).map_err(|_| AbciAdapterError::InvalidRequest("consensus seconds are negative"))?;
    let millis = seconds
        .checked_mul(1_000)
        .and_then(|value| value.checked_add(u64::try_from(time.nanos / 1_000_000).ok()?))
        .filter(|value| *value > 0)
        .ok_or(AbciAdapterError::InvalidRequest(
            "consensus time must be positive milliseconds",
        ))?;
    Ok((height, millis))
}

fn validate_next_head(status: &ApplicationStatusV2, height: u64, time_ms: u64) -> Result<()> {
    let expected = status
        .last_height()
        .checked_add(1)
        .ok_or(AbciAdapterError::InvalidRequest("application height overflows"))?;
    if height != expected {
        return Err(AbciAdapterError::InvalidRequest(
            "proposal height does not extend the committed head",
        ));
    }
    if time_ms < status.last_block_time_ms() {
        return Err(AbciAdapterError::InvalidRequest(
            "proposal time regresses from committed head",
        ));
    }
    Ok(())
}

fn validate_next_or_replay_head(status: &ApplicationStatusV2, height: u64, time_ms: u64) -> Result<()> {
    if height == status.last_height() && height > 0 {
        if time_ms != status.last_block_time_ms() {
            return Err(AbciAdapterError::InvalidRequest(
                "replayed height has a different consensus time",
            ));
        }
        return Ok(());
    }
    validate_next_head(status, height, time_ms)
}

fn successful_finalize_response(prepared: &PreparedBlockV2) -> ResponseFinalizeBlock {
    let block = prepared.outcome().block();
    let tx_results = block
        .entries()
        .iter()
        .map(|entry| ExecTxResult {
            code: OK_CODE,
            data: entry.metadata().entry_hash().as_bytes().to_vec().into(),
            log: String::new(),
            info: String::new(),
            gas_wanted: 0,
            gas_used: 0,
            events: Vec::new(),
            codespace: ABCI_CODESPACE.to_owned(),
        })
        .collect();
    ResponseFinalizeBlock {
        events: Vec::new(),
        tx_results,
        validator_updates: Vec::new(),
        consensus_param_updates: None,
        app_hash: block.app_hash().as_bytes().to_vec().into(),
    }
}

fn failed_finalize_response(transaction_count: usize, error: &AbciAdapterError) -> ResponseFinalizeBlock {
    let result_count = transaction_count.min(MAX_BLOCK_ENTRIES);
    let tx_results = (0..result_count)
        .map(|_| ExecTxResult {
            code: error.response_code(),
            data: Vec::new().into(),
            log: error.public_log().to_owned(),
            info: String::new(),
            gas_wanted: 0,
            gas_used: 0,
            events: Vec::new(),
            codespace: ABCI_CODESPACE.to_owned(),
        })
        .collect();
    ResponseFinalizeBlock {
        events: Vec::new(),
        tx_results,
        validator_updates: Vec::new(),
        consensus_param_updates: None,
        app_hash: Vec::new().into(),
    }
}

fn check_error_response(error: &AbciAdapterError) -> ResponseCheckTx {
    ResponseCheckTx {
        code: error.response_code(),
        data: Vec::new().into(),
        log: error.public_log().to_owned(),
        info: String::new(),
        gas_wanted: 0,
        gas_used: 0,
        events: Vec::new(),
        codespace: ABCI_CODESPACE.to_owned(),
    }
}

fn query_error_response(key: Bytes, error: &AbciAdapterError) -> ResponseQuery {
    ResponseQuery {
        code: error.response_code(),
        log: error.public_log().to_owned(),
        info: String::new(),
        index: 0,
        key,
        value: Vec::new().into(),
        proof_ops: None,
        height: 0,
        codespace: ABCI_CODESPACE.to_owned(),
    }
}

fn encode_query_value<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    let encoded = serde_json::to_vec(value)?;
    if encoded.len() > MAX_QUERY_RESPONSE_BYTES {
        return Err(AbciAdapterError::InvalidRequest("query response exceeds bound"));
    }
    Ok(encoded)
}

fn require_empty_data(data: &[u8]) -> Result<()> {
    if data.is_empty() {
        Ok(())
    } else {
        Err(AbciAdapterError::InvalidRequest("status query data must be empty"))
    }
}

fn require_current_query_height(requested: i64, current: u64) -> Result<()> {
    if requested == 0 || u64::try_from(requested).ok() == Some(current) {
        Ok(())
    } else {
        Err(AbciAdapterError::InvalidRequest(
            "query height is not the current committed height",
        ))
    }
}

fn require_exact_query_height(requested: i64, value_height: u64) -> Result<()> {
    if requested == 0 || u64::try_from(requested).ok() == Some(value_height) {
        Ok(())
    } else {
        Err(AbciAdapterError::InvalidRequest("query height differs from its key"))
    }
}

fn parse_height(data: &[u8]) -> Result<u64> {
    Ok(u64::from_be_bytes(parse_array::<8>(data, "block height")?))
}

fn parse_request_key(data: &[u8]) -> Result<(ChannelContextIdV2, ParticipantIdV2, RequestDigestV2)> {
    if data.len() != 96 {
        return Err(AbciAdapterError::InvalidRequest("request query key must be 96 bytes"));
    }
    let channel = ChannelContextIdV2::from_bytes(parse_array::<32>(&data[0..32], "channel key is invalid")?)?;
    let participant = ParticipantIdV2::from_bytes(parse_array::<32>(&data[32..64], "participant key is invalid")?)?;
    let request = RequestDigestV2::from_bytes(parse_array::<32>(&data[64..96], "request digest key is invalid")?)?;
    Ok((channel, participant, request))
}

fn parse_proof_key(data: &[u8]) -> Result<(u64, usize)> {
    if data.len() != 12 {
        return Err(AbciAdapterError::InvalidRequest("proof query key must be 12 bytes"));
    }
    let height = u64::from_be_bytes(
        data[0..8]
            .try_into()
            .map_err(|_| AbciAdapterError::InvalidRequest("proof height is invalid"))?,
    );
    let index = u32::from_be_bytes(
        data[8..12]
            .try_into()
            .map_err(|_| AbciAdapterError::InvalidRequest("proof index is invalid"))?,
    );
    let index =
        usize::try_from(index).map_err(|_| AbciAdapterError::InvalidRequest("proof index exceeds platform size"))?;
    Ok((height, index))
}

fn parse_array<const N: usize>(data: &[u8], label: &'static str) -> Result<[u8; N]> {
    data.try_into().map_err(|_| AbciAdapterError::InvalidRequest(label))
}

fn height_i64(height: u64) -> Result<i64> {
    i64::try_from(height).map_err(|_| AbciAdapterError::InvalidRequest("height exceeds ABCI i64"))
}

#[cfg(test)]
mod tests;
