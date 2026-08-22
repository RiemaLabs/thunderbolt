use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt;
use std::sync::{Arc, Mutex, MutexGuard};

#[cfg(test)]
use std::sync::atomic::{AtomicBool, Ordering};

use bytes::Bytes;
use sha2::{Digest, Sha256};
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
use tendermint_proto::v0_38::types::{
    AbciParams, BlockParams, ConsensusParams, EvidenceParams, ValidatorParams, VersionParams,
};
use thunderbolt_floor_app::{
    FloorAppHash, FloorApplication, FloorApplicationStatus, FloorBlockInput, FloorCasDisposition, PreparedFloorBlock,
    SignedFloorCasRequest, VaultIdentityDigest,
};
use thunderbolt_keystore::{Network, VaultIdentity};

use crate::query;
use crate::{
    decode_signed_cas, validate_compiled_resource_limits, FloorAbciError, FloorConsensusProfileV2,
    FloorValidatorGenesisV2, Result, ABCI_CODESPACE, APPLICATION_NAME, APPLICATION_VERSION,
    COMET_EVIDENCE_MAX_AGE_BLOCKS, COMET_EVIDENCE_MAX_AGE_SECONDS, COMET_EVIDENCE_MAX_BYTES, COMET_MAX_BLOCK_BYTES,
    COMET_MAX_BLOCK_GAS, MAX_BLOCK_TRANSACTION_BYTES, MAX_COMMIT_VOTES, MAX_MEMPOOL_ADMISSIONS,
    MAX_MISBEHAVIOR_RECORDS, MAX_PREPARE_PREVIEW_WORK, MAX_PREPARE_SCAN_BYTES, MAX_PREPARE_SCAN_TRANSACTIONS,
    MAX_QUERY_REQUEST_BYTES, MAX_TRANSACTION_BYTES,
};

/// Canonical query path for the durable Floor head.
pub const QUERY_STATUS_PATH: &str = "/thunderbolt/floor/v2/status";
/// Canonical query path for a registered identity's current checkpoint.
pub const QUERY_CHECKPOINT_PATH: &str = "/thunderbolt/floor/v2/checkpoint";
/// Canonical query path for one retained committed block.
pub const QUERY_BLOCK_PATH: &str = "/thunderbolt/floor/v2/block";
/// Canonical query path for exact result inclusion evidence.
pub const QUERY_RESULT_PROOF_PATH: &str = "/thunderbolt/floor/v2/result-proof";
/// Canonical query path for exact state inclusion/absence evidence.
pub const QUERY_STATE_PROOF_PATH: &str = "/thunderbolt/floor/v2/state-proof";

const OK_CODE: u32 = 0;

/// ABCI stage whose runtime failure cannot be returned as an ordinary response.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FatalAbciStage {
    /// Durable handshake information.
    Info,
    /// Genesis/profile initialization.
    InitChain,
    /// Read-only query.
    Query,
    /// Mempool admission.
    CheckTx,
    /// Proposer filtering.
    PrepareProposal,
    /// Deterministic proposal validation.
    ProcessProposal,
    /// Decided-block staging.
    FinalizeBlock,
    /// Durable commit or acknowledgement.
    Commit,
    /// Disabled state-sync snapshot surface.
    Snapshot,
    /// Disabled vote-extension surface.
    VoteExtension,
}

/// Redacted fatal failure passed to the process/session supervisor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FatalAbciFailure {
    stage: FatalAbciStage,
    code: &'static str,
}

impl FatalAbciFailure {
    /// Returns the fatal ABCI stage.
    pub const fn stage(&self) -> FatalAbciStage {
        self.stage
    }
    /// Returns the stable redacted failure code.
    pub const fn code(&self) -> &'static str {
        self.code
    }
}

/// Non-returning fatal boundary for infallible ABCI callbacks.
pub trait FatalAbciHandler: Send + Sync + 'static {
    /// Terminates the current ABCI session or complete application process.
    fn terminate(&self, failure: FatalAbciFailure) -> !;
}

/// Fatal handler that exits the complete process with a nonzero code.
#[derive(Clone, Copy, Debug)]
pub struct ProcessExitFatalHandler {
    exit_code: u8,
}

impl ProcessExitFatalHandler {
    /// Constructs a non-success process exit policy.
    pub fn new(exit_code: u8) -> Result<Self> {
        if exit_code == 0 {
            return Err(FloorAbciError::InvalidRequest("fatal exit code must be nonzero"));
        }
        Ok(Self { exit_code })
    }
}

impl FatalAbciHandler for ProcessExitFatalHandler {
    fn terminate(&self, failure: FatalAbciFailure) -> ! {
        eprintln!(
            "fatal Floor ABCI failure: stage={:?} code={}",
            failure.stage(),
            failure.code()
        );
        std::process::exit(i32::from(self.exit_code));
    }
}

/// Clone-safe ABCI application sharing one durable Floor and staged runtime.
pub struct ThunderboltFloorAbci<F> {
    inner: Arc<Shared<F>>,
}

impl<F> Clone for ThunderboltFloorAbci<F> {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

impl<F> fmt::Debug for ThunderboltFloorAbci<F> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ThunderboltFloorAbci")
            .field("chain_id", &self.inner.comet_chain_id)
            .field("application_version", &APPLICATION_VERSION)
            .finish_non_exhaustive()
    }
}

struct Shared<F> {
    application: FloorApplication,
    validator_genesis: FloorValidatorGenesisV2,
    consensus_profile: FloorConsensusProfileV2,
    comet_chain_id: String,
    fatal_handler: F,
    runtime: Mutex<RuntimeState>,
    mempool: Mutex<MempoolAdmissionCache>,
    prepare_cursor: Mutex<usize>,
    #[cfg(test)]
    fail_after_commit: AtomicBool,
}

#[derive(Default)]
struct RuntimeState {
    staged: Option<StagedBlock>,
    faulted: bool,
}

struct StagedBlock {
    identity: FinalizeIdentity,
    prepared: PreparedFloorBlock,
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

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct IdentityKey([u8; 106]);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct AdmissionKey {
    identity: IdentityKey,
    target_height: u64,
    previous_app_hash: [u8; 32],
}

#[derive(Default)]
struct MempoolAdmissionCache {
    order: VecDeque<AdmissionKey>,
    entries: HashMap<AdmissionKey, [u8; 32]>,
}

impl MempoolAdmissionCache {
    fn get(&self, key: &AdmissionKey) -> Option<&[u8; 32]> {
        self.entries.get(key)
    }

    fn insert(&mut self, key: AdmissionKey, raw_digest: [u8; 32]) {
        if self.entries.contains_key(&key) {
            return;
        }
        self.entries.insert(key, raw_digest);
        self.order.push_back(key);
        while self.order.len() > MAX_MEMPOOL_ADMISSIONS {
            if let Some(evicted) = self.order.pop_front() {
                self.entries.remove(&evicted);
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AdmissionPurpose {
    New,
    Recheck,
    Prepare,
    Consensus,
}

impl<F> ThunderboltFloorAbci<F>
where
    F: FatalAbciHandler,
{
    /// Constructs an adapter pinned to the exact Floor genesis and validator profile.
    pub fn new(
        application: FloorApplication,
        validator_genesis: FloorValidatorGenesisV2,
        fatal_handler: F,
    ) -> Result<Self> {
        validate_compiled_resource_limits()?;
        let genesis = application.genesis();
        let raw_chain_id = std::str::from_utf8(genesis.chain_id().as_bytes())
            .map_err(|_| FloorAbciError::InvalidRequest("CometBFT chain id must be UTF-8"))?;
        let comet_chain_id = tendermint::chain::Id::try_from(raw_chain_id)
            .map_err(|_| FloorAbciError::InvalidRequest("Floor chain id is not a canonical CometBFT chain id"))?
            .to_string();
        if genesis
            .entries()
            .iter()
            .any(|entry| entry.identity().network() == Network::Mainnet)
        {
            return Err(FloorAbciError::InvalidRequest("Mainnet Floor ABCI is disabled"));
        }
        let consensus_profile = FloorConsensusProfileV2::derive(genesis.chain_id(), &validator_genesis)?;
        if genesis.profile_digest() != consensus_profile.as_bytes() {
            return Err(FloorAbciError::InvalidRequest(
                "durable Floor consensus profile differs",
            ));
        }
        application.verify_integrity()?;
        Ok(Self {
            inner: Arc::new(Shared {
                application,
                validator_genesis,
                consensus_profile,
                comet_chain_id,
                fatal_handler,
                runtime: Mutex::new(RuntimeState::default()),
                mempool: Mutex::new(MempoolAdmissionCache::default()),
                prepare_cursor: Mutex::new(0),
                #[cfg(test)]
                fail_after_commit: AtomicBool::new(false),
            }),
        })
    }

    /// Returns the exact CometBFT chain ID.
    pub fn chain_id(&self) -> &str {
        &self.inner.comet_chain_id
    }

    /// Returns the mechanically derived consensus profile.
    pub fn consensus_profile(&self) -> &FloorConsensusProfileV2 {
        &self.inner.consensus_profile
    }

    /// Returns the exact CometBFT consensus parameters pinned by this profile.
    pub fn consensus_parameters(&self) -> ConsensusParams {
        expected_consensus_parameters()
    }

    /// Builds a checked Info response from the durable head and pinned profile.
    pub fn try_info(&self, _request: RequestInfo) -> Result<ResponseInfo> {
        self.ensure_available()?;
        self.validate_durable_identity()?;
        let status = self.inner.application.status()?;
        Ok(ResponseInfo {
            data: APPLICATION_NAME.to_owned(),
            version: env!("CARGO_PKG_VERSION").to_owned(),
            app_version: APPLICATION_VERSION,
            last_block_height: height_i64(status.last_height)?,
            last_block_app_hash: status.last_app_hash.as_bytes().to_vec().into(),
        })
    }

    /// Validates exact chain, validator, profile, and consensus resource genesis.
    pub fn try_init_chain(&self, request: RequestInitChain) -> Result<ResponseInitChain> {
        self.ensure_available()?;
        self.validate_durable_identity()?;
        let status = self.inner.application.status()?;
        if status.last_height != 0 || status.last_app_hash != FloorAppHash::new([0; 32]) {
            return Err(FloorAbciError::InvalidRequest("InitChain requires an empty Floor"));
        }
        if request.chain_id != self.chain_id() || request.initial_height != 1 {
            return Err(FloorAbciError::InvalidRequest(
                "InitChain chain or initial height differs",
            ));
        }
        let _ = height_and_time(1, request.time.as_ref())?;
        validate_consensus_parameters(request.consensus_params.as_ref())?;
        if request.validators != self.inner.validator_genesis.validators() {
            return Err(FloorAbciError::InvalidRequest("InitChain validator set differs"));
        }
        if request.app_state_bytes.as_ref()
            != self
                .inner
                .consensus_profile
                .genesis_app_state_bytes(self.inner.application.genesis())?
                .as_slice()
        {
            return Err(FloorAbciError::InvalidRequest("InitChain app-state profile differs"));
        }
        Ok(ResponseInitChain {
            consensus_params: Some(expected_consensus_parameters()),
            validators: Vec::new(),
            app_hash: status.last_app_hash.as_bytes().to_vec().into(),
        })
    }

    /// Performs bounded contextual admission against the exact durable next head.
    pub fn try_check_tx(&self, request: RequestCheckTx) -> Result<ResponseCheckTx> {
        self.ensure_available()?;
        let purpose = match CheckTxType::try_from(request.r#type)
            .map_err(|_| FloorAbciError::InvalidRequest("CheckTx type is unknown"))?
        {
            CheckTxType::New => AdmissionPurpose::New,
            CheckTxType::Recheck => AdmissionPurpose::Recheck,
        };
        let signed = self.admit_transaction(request.tx.as_ref(), purpose)?;
        let gas = i64::try_from(request.tx.len())
            .map_err(|_| FloorAbciError::InvalidTransaction("transaction size exceeds i64"))?;
        Ok(ResponseCheckTx {
            code: OK_CODE,
            data: signed.authorization().request_digest().as_bytes().to_vec().into(),
            log: String::new(),
            info: String::new(),
            gas_wanted: gas,
            gas_used: gas,
            events: Vec::new(),
            codespace: ABCI_CODESPACE.to_owned(),
        })
    }

    /// Selects a bounded order-preserving, identity-deduplicated proposal.
    pub fn try_prepare_proposal(&self, request: RequestPrepareProposal) -> Result<ResponsePrepareProposal> {
        self.ensure_available()?;
        if request.max_tx_bytes <= 0 || request.max_tx_bytes > COMET_MAX_BLOCK_BYTES {
            return Err(FloorAbciError::InvalidRequest(
                "PrepareProposal max_tx_bytes differs from the committed profile",
            ));
        }
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
        let mut selected_raw = Vec::new();
        let mut selected_signed = Vec::new();
        let mut identities = HashSet::new();
        let mut request_digests = HashSet::new();
        let mut selected_bytes = 0_usize;
        let mut scanned_bytes = 0_usize;
        let mut scanned = 0_usize;
        let mut preview_work = 0_usize;
        let transaction_count = request.txs.len();
        let mut cursor = self
            .inner
            .prepare_cursor
            .lock()
            .map_err(|_| FloorAbciError::LockPoisoned)?;
        if *cursor >= transaction_count {
            *cursor = 0;
        }
        let start = *cursor;
        for (index, raw) in request.txs.into_iter().enumerate().skip(start) {
            if scanned == MAX_PREPARE_SCAN_TRANSACTIONS {
                break;
            }
            scanned = scanned.saturating_add(1);
            *cursor = if index.saturating_add(1) >= transaction_count {
                0
            } else {
                index.saturating_add(1)
            };
            let Some(next_scanned) = scanned_bytes.checked_add(raw.len()) else {
                break;
            };
            if next_scanned > MAX_PREPARE_SCAN_BYTES {
                break;
            }
            scanned_bytes = next_scanned;
            if raw.is_empty() || raw.len() > MAX_TRANSACTION_BYTES {
                continue;
            }
            let Some(next_total) = selected_bytes.checked_add(raw.len()) else {
                break;
            };
            if next_total > budget || next_total > MAX_BLOCK_TRANSACTION_BYTES {
                continue;
            }
            let Ok(signed) = self.admit_transaction(raw.as_ref(), AdmissionPurpose::Prepare) else {
                continue;
            };
            let identity = identity_key(signed.authorization().cas().identity())?;
            let digest = *signed.authorization().request_digest().as_bytes();
            if identities.contains(&identity) || request_digests.contains(&digest) {
                continue;
            }
            let mut candidate = selected_signed.clone();
            candidate.push(signed.clone());
            let Some(next_work) = preview_work.checked_add(candidate.len()) else {
                break;
            };
            if next_work > MAX_PREPARE_PREVIEW_WORK {
                break;
            }
            let input = match FloorBlockInput::new(
                self.inner.application.genesis().chain_id().clone(),
                height,
                block_time_ms,
                status.last_app_hash,
                candidate,
            ) {
                Ok(input) => input,
                Err(_) => continue,
            };
            preview_work = next_work;
            match self.inner.application.preview_block(input) {
                Ok(prepared) if preview_has_no_conflicts(&prepared) => {}
                Ok(_) => continue,
                Err(error) => {
                    let error = FloorAbciError::Application(error);
                    if error.is_fatal_runtime() {
                        return Err(error);
                    }
                    continue;
                }
            }
            identities.insert(identity);
            request_digests.insert(digest);
            selected_signed.push(signed);
            selected_bytes = next_total;
            selected_raw.push(raw);
            if selected_raw.len() == thunderbolt_floor_app::MAX_BLOCK_REQUESTS {
                break;
            }
        }
        Ok(ResponsePrepareProposal { txs: selected_raw })
    }

    /// Fully validates a proposal by deterministic rollback-only execution.
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
        let input = self.block_input(request.height, request.time.as_ref(), &request.txs, false)?;
        let prepared = self.inner.application.preview_block(input)?;
        if !preview_has_no_conflicts(&prepared) {
            return Err(FloorAbciError::InvalidTransaction(
                "proposal contains a conflicting CAS",
            ));
        }
        Ok(ResponseProcessProposal {
            status: response_process_proposal::ProposalStatus::Accept as i32,
        })
    }

    /// Runs exact rollback preview and stages the decided block for Commit.
    pub fn try_finalize_block(&self, request: RequestFinalizeBlock) -> Result<ResponseFinalizeBlock> {
        let mut runtime = self.lock_runtime()?;
        if runtime.faulted {
            return Err(FloorAbciError::Faulted);
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
            transactions: request.txs.iter().map(|tx| tx.to_vec()).collect(),
            next_validators_hash: request.next_validators_hash.to_vec(),
            proposer_address: request.proposer_address.to_vec(),
        };
        if let Some(staged) = runtime.staged.as_ref() {
            if staged.identity == identity {
                return Ok(staged.response.clone());
            }
            return Err(FloorAbciError::StagedBlockConflict);
        }
        let input = self.block_input(request.height, request.time.as_ref(), &request.txs, true)?;
        let prepared = self.inner.application.preview_block(input)?;
        if !preview_has_no_conflicts(&prepared) {
            return Err(FloorAbciError::InvalidTransaction(
                "decided block contains a conflicting CAS",
            ));
        }
        let response = successful_finalize_response(&prepared);
        runtime.staged = Some(StagedBlock {
            identity,
            prepared,
            response: response.clone(),
        });
        Ok(response)
    }

    /// Atomically persists the staged block; no other callback writes durable state.
    pub fn try_commit(&self) -> Result<ResponseCommit> {
        let mut runtime = self.lock_runtime()?;
        if runtime.faulted {
            return Err(FloorAbciError::Faulted);
        }
        let Some(staged) = runtime.staged.take() else {
            runtime.faulted = true;
            return Err(FloorAbciError::MissingStagedBlock);
        };
        let expected = staged.prepared.block().clone();
        match self.inner.application.commit_prepared_block(staged.prepared) {
            Ok(outcome) if outcome.block() == &expected => {
                #[cfg(test)]
                if self.inner.fail_after_commit.swap(false, Ordering::SeqCst) {
                    runtime.faulted = true;
                    return Err(FloorAbciError::PostCommitAmbiguous);
                }
                Ok(ResponseCommit { retain_height: 0 })
            }
            Ok(_) => {
                runtime.faulted = true;
                Err(FloorAbciError::Application(
                    thunderbolt_floor_app::FloorApplicationError::PreparedMismatch,
                ))
            }
            Err(error) => {
                runtime.faulted = true;
                Err(error.into())
            }
        }
    }

    /// Executes one bounded read-only execution-evidence query.
    pub fn try_query(&self, request: RequestQuery) -> Result<ResponseQuery> {
        self.ensure_available()?;
        if request.data.len() > MAX_QUERY_REQUEST_BYTES || request.height < 0 {
            return Err(FloorAbciError::InvalidRequest("query key or height is outside bounds"));
        }
        if request.prove {
            return Err(FloorAbciError::InvalidRequest(
                "Floor execution evidence is not CometBFT ProofOps",
            ));
        }
        let (value, response_height) = match request.path.as_str() {
            QUERY_STATUS_PATH => {
                require_empty(request.data.as_ref())?;
                let status = self.inner.application.status()?;
                require_current_query_height(request.height, status.last_height)?;
                (
                    query::status_value(&status, self.inner.application.genesis())?,
                    status.last_height,
                )
            }
            QUERY_CHECKPOINT_PATH => {
                let digest = VaultIdentityDigest::new(parse_array::<32>(request.data.as_ref(), "identity key")?);
                let status = self.inner.application.status()?;
                require_current_query_height(request.height, status.last_height)?;
                if status.last_height == 0 {
                    let checkpoint = self.inner.application.checkpoint(digest)?;
                    let confirmed = self.inner.application.status()?;
                    if confirmed.last_height != status.last_height || confirmed.last_app_hash != status.last_app_hash {
                        return Err(FloorAbciError::InvalidRequest("checkpoint query head changed"));
                    }
                    (
                        query::checkpoint_value(digest.as_bytes(), &status, None, None, checkpoint)?,
                        0,
                    )
                } else {
                    let proof = self.inner.application.state_proof(digest)?;
                    let block = self.inner.application.committed_block(proof.height())?;
                    if proof.height() != status.last_height || block.app_hash() != status.last_app_hash {
                        return Err(FloorAbciError::InvalidRequest("checkpoint query head changed"));
                    }
                    proof.verify(&block, self.inner.application.genesis(), digest, proof.checkpoint())?;
                    (
                        query::checkpoint_value(
                            digest.as_bytes(),
                            &status,
                            Some(&block),
                            Some(&proof),
                            proof.checkpoint(),
                        )?,
                        proof.height(),
                    )
                }
            }
            QUERY_BLOCK_PATH => {
                let height = parse_height(request.data.as_ref())?;
                require_exact_query_height(request.height, height)?;
                let block = self.inner.application.committed_block(height)?;
                (query::block_value(&block)?, height)
            }
            QUERY_RESULT_PROOF_PATH => {
                let (height, index) = parse_proof_key(request.data.as_ref())?;
                require_exact_query_height(request.height, height)?;
                let block = self.inner.application.committed_block(height)?;
                let result = block.results().get(index).ok_or(FloorAbciError::NotFound("result"))?;
                let proof = self.inner.application.result_proof(height, index)?;
                proof.verify(&block, result)?;
                (query::result_proof_value(&block, &proof)?, height)
            }
            QUERY_STATE_PROOF_PATH => {
                let (height, digest) = parse_state_key(request.data.as_ref())?;
                require_exact_query_height(request.height, height)?;
                let block = self.inner.application.committed_block(height)?;
                let proof = self.inner.application.state_proof_at(height, digest)?;
                proof.verify(&block, self.inner.application.genesis(), digest, proof.checkpoint())?;
                (query::state_proof_value(&block, &proof)?, height)
            }
            _ => return Err(FloorAbciError::InvalidRequest("unknown Floor query path")),
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

    fn admit_transaction(&self, bytes: &[u8], purpose: AdmissionPurpose) -> Result<SignedFloorCasRequest> {
        let signed = decode_signed_cas(bytes)?;
        if signed.authorization().cas().chain_id() != self.inner.application.genesis().chain_id() {
            return Err(FloorAbciError::InvalidTransaction("transaction chain differs"));
        }
        if !matches!(purpose, AdmissionPurpose::New | AdmissionPurpose::Recheck) {
            return Ok(signed);
        }
        let status = self.inner.application.status()?;
        validate_signed_next_head(&signed, &status)?;
        let identity = identity_key(signed.authorization().cas().identity())?;
        let key = AdmissionKey {
            identity,
            target_height: signed.authorization().target_height(),
            previous_app_hash: *signed.authorization().expected_previous_app_hash().as_bytes(),
        };
        let raw_digest: [u8; 32] = Sha256::digest(bytes).into();
        let mut cache = self.inner.mempool.lock().map_err(|_| FloorAbciError::LockPoisoned)?;
        if let Some(existing) = cache.get(&key) {
            let exact_recheck = purpose == AdmissionPurpose::Recheck && existing == &raw_digest;
            if !exact_recheck {
                return Err(FloorAbciError::InvalidTransaction(
                    "identity already has a same-head mempool request",
                ));
            }
        }
        let admission_time = status.last_block_time_ms.max(1);
        let input = FloorBlockInput::new(
            self.inner.application.genesis().chain_id().clone(),
            signed.authorization().target_height(),
            admission_time,
            status.last_app_hash,
            vec![signed.clone()],
        )
        .map_err(|_| FloorAbciError::InvalidTransaction("transaction head binding is invalid"))?;
        let prepared = match self.inner.application.preview_block(input) {
            Ok(prepared) => prepared,
            Err(error) => {
                let error = FloorAbciError::Application(error);
                if error.is_fatal_runtime() {
                    return Err(error);
                }
                return Err(FloorAbciError::InvalidTransaction(
                    "transaction conflicts with current Floor state",
                ));
            }
        };
        if !preview_has_no_conflicts(&prepared) {
            return Err(FloorAbciError::InvalidTransaction(
                "transaction conflicts with current Floor state",
            ));
        }
        cache.insert(key, raw_digest);
        Ok(signed)
    }

    fn block_input(
        &self,
        height: i64,
        time: Option<&tendermint_proto::google::protobuf::Timestamp>,
        transactions: &[Bytes],
        allow_replay: bool,
    ) -> Result<FloorBlockInput> {
        validate_transaction_bounds(transactions)?;
        let (height, block_time_ms) = height_and_time(height, time)?;
        let signed = transactions
            .iter()
            .map(|tx| self.admit_transaction(tx.as_ref(), AdmissionPurpose::Consensus))
            .collect::<Result<Vec<_>>>()?;
        let status = self.inner.application.status()?;
        let previous = if allow_replay && height == status.last_height && height > 0 {
            if block_time_ms != status.last_block_time_ms {
                return Err(FloorAbciError::InvalidRequest("replayed height has different time"));
            }
            self.inner.application.committed_block(height)?.previous_app_hash()
        } else {
            validate_next_head(&status, height, block_time_ms)?;
            status.last_app_hash
        };
        FloorBlockInput::new(
            self.inner.application.genesis().chain_id().clone(),
            height,
            block_time_ms,
            previous,
            signed,
        )
        .map_err(|_| FloorAbciError::InvalidTransaction("block transaction binding is invalid"))
    }

    fn validate_durable_identity(&self) -> Result<()> {
        validate_compiled_resource_limits()?;
        let genesis = self.inner.application.genesis();
        if genesis.profile_digest() != self.inner.consensus_profile.as_bytes()
            || genesis.chain_id().as_bytes() != self.chain_id().as_bytes()
            || self.inner.validator_genesis.digest() != self.inner.consensus_profile.validator_digest()
        {
            return Err(FloorAbciError::InvalidRequest("durable Floor ABCI identity differs"));
        }
        Ok(())
    }

    fn lock_runtime(&self) -> Result<MutexGuard<'_, RuntimeState>> {
        self.inner.runtime.lock().map_err(|_| FloorAbciError::LockPoisoned)
    }

    fn ensure_available(&self) -> Result<()> {
        if self.lock_runtime()?.faulted {
            return Err(FloorAbciError::Faulted);
        }
        let _ = self.inner.application.status()?;
        Ok(())
    }

    fn mark_faulted(&self) {
        if let Ok(mut runtime) = self.inner.runtime.lock() {
            runtime.faulted = true;
        }
    }

    fn terminate(&self, stage: FatalAbciStage, error: &FloorAbciError) -> ! {
        self.mark_faulted();
        self.inner.fatal_handler.terminate(FatalAbciFailure {
            stage,
            code: error.public_log(),
        })
    }

    #[cfg(test)]
    pub(crate) fn fail_after_next_commit_for_test(&self) {
        self.inner.fail_after_commit.store(true, Ordering::SeqCst);
    }
}

impl<F> Application for ThunderboltFloorAbci<F>
where
    F: FatalAbciHandler,
{
    fn info(&self, request: RequestInfo) -> ResponseInfo {
        match self.try_info(request) {
            Ok(response) => response,
            Err(error) => self.terminate(FatalAbciStage::Info, &error),
        }
    }

    fn init_chain(&self, request: RequestInitChain) -> ResponseInitChain {
        match self.try_init_chain(request) {
            Ok(response) => response,
            Err(error) => self.terminate(FatalAbciStage::InitChain, &error),
        }
    }

    fn query(&self, request: RequestQuery) -> ResponseQuery {
        let key = if request.data.len() <= MAX_QUERY_REQUEST_BYTES {
            request.data.clone()
        } else {
            Bytes::new()
        };
        match self.try_query(request) {
            Ok(response) => response,
            Err(error) if error.is_fatal_runtime() => self.terminate(FatalAbciStage::Query, &error),
            Err(error) => query_error_response(key, &error),
        }
    }

    fn check_tx(&self, request: RequestCheckTx) -> ResponseCheckTx {
        match self.try_check_tx(request) {
            Ok(response) => response,
            Err(error) if error.is_fatal_runtime() => self.terminate(FatalAbciStage::CheckTx, &error),
            Err(error) => check_error_response(&error),
        }
    }

    fn prepare_proposal(&self, request: RequestPrepareProposal) -> ResponsePrepareProposal {
        match self.try_prepare_proposal(request) {
            Ok(response) => response,
            Err(error) if error.is_fatal_runtime() => self.terminate(FatalAbciStage::PrepareProposal, &error),
            Err(_) => ResponsePrepareProposal { txs: Vec::new() },
        }
    }

    fn process_proposal(&self, request: RequestProcessProposal) -> ResponseProcessProposal {
        match self.try_process_proposal(request) {
            Ok(response) => response,
            Err(error) if error.is_fatal_runtime() => self.terminate(FatalAbciStage::ProcessProposal, &error),
            Err(_) => ResponseProcessProposal {
                status: response_process_proposal::ProposalStatus::Reject as i32,
            },
        }
    }

    fn finalize_block(&self, request: RequestFinalizeBlock) -> ResponseFinalizeBlock {
        match self.try_finalize_block(request) {
            Ok(response) => response,
            Err(error) => self.terminate(FatalAbciStage::FinalizeBlock, &error),
        }
    }

    fn commit(&self) -> ResponseCommit {
        match self.try_commit() {
            Ok(response) => response,
            Err(error) => self.terminate(FatalAbciStage::Commit, &error),
        }
    }

    fn list_snapshots(&self) -> ResponseListSnapshots {
        if let Err(error) = self.ensure_available() {
            self.terminate(FatalAbciStage::Snapshot, &error);
        }
        ResponseListSnapshots { snapshots: Vec::new() }
    }

    fn offer_snapshot(&self, _request: RequestOfferSnapshot) -> ResponseOfferSnapshot {
        if let Err(error) = self.ensure_available() {
            self.terminate(FatalAbciStage::Snapshot, &error);
        }
        ResponseOfferSnapshot {
            result: response_offer_snapshot::Result::Abort as i32,
        }
    }

    fn load_snapshot_chunk(&self, _request: RequestLoadSnapshotChunk) -> ResponseLoadSnapshotChunk {
        if let Err(error) = self.ensure_available() {
            self.terminate(FatalAbciStage::Snapshot, &error);
        }
        ResponseLoadSnapshotChunk {
            chunk: Vec::new().into(),
        }
    }

    fn apply_snapshot_chunk(&self, _request: RequestApplySnapshotChunk) -> ResponseApplySnapshotChunk {
        if let Err(error) = self.ensure_available() {
            self.terminate(FatalAbciStage::Snapshot, &error);
        }
        ResponseApplySnapshotChunk {
            result: response_apply_snapshot_chunk::Result::Abort as i32,
            refetch_chunks: Vec::new(),
            reject_senders: Vec::new(),
        }
    }

    fn extend_vote(&self, _request: RequestExtendVote) -> ResponseExtendVote {
        if let Err(error) = self.ensure_available() {
            self.terminate(FatalAbciStage::VoteExtension, &error);
        }
        ResponseExtendVote {
            vote_extension: Vec::new().into(),
        }
    }

    fn verify_vote_extension(&self, request: RequestVerifyVoteExtension) -> ResponseVerifyVoteExtension {
        if let Err(error) = self.ensure_available() {
            self.terminate(FatalAbciStage::VoteExtension, &error);
        }
        let status = if request.vote_extension.is_empty() {
            response_verify_vote_extension::VerifyStatus::Accept
        } else {
            response_verify_vote_extension::VerifyStatus::Reject
        };
        ResponseVerifyVoteExtension { status: status as i32 }
    }
}

pub(crate) fn expected_consensus_parameters() -> ConsensusParams {
    ConsensusParams {
        block: Some(BlockParams {
            max_bytes: COMET_MAX_BLOCK_BYTES,
            max_gas: COMET_MAX_BLOCK_GAS,
        }),
        evidence: Some(EvidenceParams {
            max_age_num_blocks: COMET_EVIDENCE_MAX_AGE_BLOCKS,
            max_age_duration: Some(tendermint_proto::google::protobuf::Duration {
                seconds: COMET_EVIDENCE_MAX_AGE_SECONDS,
                nanos: 0,
            }),
            max_bytes: COMET_EVIDENCE_MAX_BYTES,
        }),
        validator: Some(ValidatorParams {
            pub_key_types: vec!["ed25519".to_owned()],
        }),
        version: Some(VersionParams {
            app: APPLICATION_VERSION,
        }),
        abci: Some(AbciParams {
            vote_extensions_enable_height: 0,
        }),
    }
}

fn validate_consensus_parameters(parameters: Option<&ConsensusParams>) -> Result<()> {
    let parameters = parameters.ok_or(FloorAbciError::InvalidRequest("consensus parameters are missing"))?;
    if parameters != &expected_consensus_parameters() {
        return Err(FloorAbciError::InvalidRequest(
            "CometBFT consensus parameters differ from the Floor profile",
        ));
    }
    Ok(())
}

fn preview_has_no_conflicts(prepared: &PreparedFloorBlock) -> bool {
    prepared
        .block()
        .results()
        .iter()
        .all(|result| result.disposition() != FloorCasDisposition::Conflict)
}

fn validate_signed_next_head(signed: &SignedFloorCasRequest, status: &FloorApplicationStatus) -> Result<()> {
    let expected = status
        .last_height
        .checked_add(1)
        .ok_or(FloorAbciError::InvalidTransaction("Floor height overflows"))?;
    if signed.authorization().target_height() != expected
        || signed.authorization().expected_previous_app_hash() != status.last_app_hash
    {
        return Err(FloorAbciError::InvalidTransaction(
            "transaction targets a stale or future head",
        ));
    }
    Ok(())
}

fn identity_key(identity: VaultIdentity) -> Result<IdentityKey> {
    let mut bytes = [0_u8; 106];
    bytes[0] = match identity.network() {
        Network::Regtest => 1,
        Network::Signet => 2,
        Network::Testnet => 3,
        Network::Mainnet => return Err(FloorAbciError::InvalidTransaction("Mainnet is disabled")),
    };
    bytes[1] = match identity.role() {
        thunderbolt_keystore::VaultRole::Holder => 1,
        thunderbolt_keystore::VaultRole::CommitteeMember => 2,
    };
    bytes[2..34].copy_from_slice(identity.node_id().as_bytes());
    bytes[34..66].copy_from_slice(identity.deployment().deployment_id().as_bytes());
    bytes[66..74].copy_from_slice(&identity.deployment().committee_epoch().to_be_bytes());
    bytes[74..106].copy_from_slice(identity.deployment().committee_descriptor().as_bytes());
    Ok(IdentityKey(bytes))
}

fn validate_transaction_bounds(transactions: &[Bytes]) -> Result<()> {
    if transactions.len() > thunderbolt_floor_app::MAX_BLOCK_REQUESTS {
        return Err(FloorAbciError::InvalidRequest("block transaction count exceeds bound"));
    }
    let total = transactions.iter().try_fold(0_usize, |sum, tx| {
        if tx.is_empty() || tx.len() > MAX_TRANSACTION_BYTES {
            return Err(FloorAbciError::InvalidTransaction(
                "transaction byte length is outside bounds",
            ));
        }
        sum.checked_add(tx.len())
            .ok_or(FloorAbciError::InvalidRequest("block byte count overflows"))
    })?;
    if total > MAX_BLOCK_TRANSACTION_BYTES {
        return Err(FloorAbciError::InvalidRequest("block transaction bytes exceed bound"));
    }
    Ok(())
}

fn validate_prepare_shape(request: &RequestPrepareProposal) -> Result<(u64, u64)> {
    let pair = height_and_time(request.height, request.time.as_ref())?;
    if request.next_validators_hash.len() != 32 || request.proposer_address.len() != 20 {
        return Err(FloorAbciError::InvalidRequest(
            "prepare consensus identifiers have wrong width",
        ));
    }
    if request.misbehavior.len() > MAX_MISBEHAVIOR_RECORDS {
        return Err(FloorAbciError::InvalidRequest(
            "prepare misbehavior count exceeds bound",
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
            return Err(FloorAbciError::InvalidRequest(
                "prepare vote extensions are unsupported",
            ));
        }
    }
    Ok(pair)
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
    if block_hash.len() != 32 || next_validators_hash.len() != 32 || proposer_address.len() != 20 {
        return Err(FloorAbciError::InvalidRequest("consensus identifiers have wrong width"));
    }
    if misbehavior_count > MAX_MISBEHAVIOR_RECORDS {
        return Err(FloorAbciError::InvalidRequest("misbehavior count exceeds bound"));
    }
    if commit.is_some_and(|commit| commit.round < 0 || commit.votes.len() > MAX_COMMIT_VOTES) {
        return Err(FloorAbciError::InvalidRequest("commit info is outside bounds"));
    }
    Ok(pair)
}

fn height_and_time(height: i64, time: Option<&tendermint_proto::google::protobuf::Timestamp>) -> Result<(u64, u64)> {
    let height = u64::try_from(height)
        .ok()
        .filter(|height| *height > 0)
        .ok_or(FloorAbciError::InvalidRequest("consensus height must be positive"))?;
    let time = time.ok_or(FloorAbciError::InvalidRequest("consensus time is missing"))?;
    if time.seconds < 0 || !(0..1_000_000_000).contains(&time.nanos) {
        return Err(FloorAbciError::InvalidRequest("consensus timestamp is invalid"));
    }
    let millis = u64::try_from(time.seconds)
        .ok()
        .and_then(|seconds| seconds.checked_mul(1_000))
        .and_then(|value| value.checked_add(u64::try_from(time.nanos / 1_000_000).ok()?))
        .filter(|value| *value > 0)
        .ok_or(FloorAbciError::InvalidRequest("consensus milliseconds are invalid"))?;
    Ok((height, millis))
}

fn validate_next_head(status: &FloorApplicationStatus, height: u64, time_ms: u64) -> Result<()> {
    let expected = status
        .last_height
        .checked_add(1)
        .ok_or(FloorAbciError::InvalidRequest("Floor height overflows"))?;
    if height != expected || time_ms < status.last_block_time_ms {
        return Err(FloorAbciError::InvalidRequest(
            "proposal does not extend the durable head",
        ));
    }
    Ok(())
}

fn successful_finalize_response(prepared: &PreparedFloorBlock) -> ResponseFinalizeBlock {
    let block = prepared.block();
    let tx_results = block
        .results()
        .iter()
        .map(|result| ExecTxResult {
            code: OK_CODE,
            data: result.result_digest().as_bytes().to_vec().into(),
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

fn check_error_response(error: &FloorAbciError) -> ResponseCheckTx {
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

fn query_error_response(key: Bytes, error: &FloorAbciError) -> ResponseQuery {
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

fn require_empty(data: &[u8]) -> Result<()> {
    if data.is_empty() {
        Ok(())
    } else {
        Err(FloorAbciError::InvalidRequest("status query data must be empty"))
    }
}

fn require_current_query_height(requested: i64, current: u64) -> Result<()> {
    if requested == 0 || u64::try_from(requested).ok() == Some(current) {
        Ok(())
    } else {
        Err(FloorAbciError::InvalidRequest("query height is not the current head"))
    }
}

fn require_exact_query_height(requested: i64, value: u64) -> Result<()> {
    if requested == 0 || u64::try_from(requested).ok() == Some(value) {
        Ok(())
    } else {
        Err(FloorAbciError::InvalidRequest("query height differs from key"))
    }
}

fn parse_height(data: &[u8]) -> Result<u64> {
    Ok(u64::from_be_bytes(parse_array(data, "block height")?))
}

fn parse_proof_key(data: &[u8]) -> Result<(u64, usize)> {
    if data.len() != 12 {
        return Err(FloorAbciError::InvalidRequest("result-proof key must be 12 bytes"));
    }
    let height = u64::from_be_bytes(parse_array(&data[..8], "proof height")?);
    let index = usize::try_from(u32::from_be_bytes(parse_array(&data[8..], "proof index")?))
        .map_err(|_| FloorAbciError::InvalidRequest("proof index exceeds platform"))?;
    Ok((height, index))
}

fn parse_state_key(data: &[u8]) -> Result<(u64, VaultIdentityDigest)> {
    if data.len() != 40 {
        return Err(FloorAbciError::InvalidRequest("state-proof key must be 40 bytes"));
    }
    Ok((
        u64::from_be_bytes(parse_array(&data[..8], "state height")?),
        VaultIdentityDigest::new(parse_array(&data[8..], "state identity")?),
    ))
}

fn parse_array<const N: usize>(data: &[u8], label: &'static str) -> Result<[u8; N]> {
    data.try_into().map_err(|_| FloorAbciError::InvalidRequest(label))
}

fn height_i64(height: u64) -> Result<i64> {
    i64::try_from(height).map_err(|_| FloorAbciError::InvalidRequest("height exceeds ABCI i64"))
}
