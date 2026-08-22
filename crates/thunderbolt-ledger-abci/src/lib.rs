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

use std::collections::{HashSet, VecDeque};
use std::fmt;
use std::io::{self, Write};
use std::sync::{Arc, Mutex, MutexGuard};

#[cfg(test)]
use std::sync::atomic::{AtomicBool, Ordering};

use bytes::Bytes;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
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
    SignedProposalV2, MAX_BLOCK_ENTRIES, MAX_BLOCK_EVENT_BYTES,
};
use thunderbolt_ledger_app::{
    ApplicationStatusV2, BlockInputV2, LedgerApplication, LedgerApplicationVerifierV2, PreparedBlockV2,
};
use thunderbolt_protocol::v2::{ChannelEventV2, ChannelSnapshotV2, ProtocolLimitsV2};

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
/// Maximum cumulative proposal entries re-executed while greedily constructing
/// one fully previewed proposer block.
pub const MAX_PREPARE_PREVIEW_WORK: usize = 4_096;
/// Maximum raw transactions examined by one `PrepareProposal` call, including
/// malformed, duplicate, oversized, or otherwise rejected values.
pub const MAX_PREPARE_SCAN_TRANSACTIONS: usize = 4_096;
/// Maximum raw bytes examined by one `PrepareProposal` call, including every
/// rejected value.
pub const MAX_PREPARE_SCAN_BYTES: usize = 32 * 1024 * 1024;
/// Maximum permanent static-admission rejections cached across ABCI clones.
pub const MAX_STATIC_REJECTION_CACHE_ENTRIES: usize = 4_096;

const OK_CODE: u32 = 0;

/// Time- and state-independent signed proposal presented for static proof
/// admission before it may enter or remain in the CometBFT mempool.
#[derive(Clone, Copy, Debug)]
pub struct StaticAdmissionRequestV2<'a> {
    proposal: &'a SignedProposalV2,
    event: &'a ChannelEventV2,
}

impl<'a> StaticAdmissionRequestV2<'a> {
    /// Returns the signature-verified proposal and complete stable binding.
    pub const fn proposal(&self) -> &'a SignedProposalV2 {
        self.proposal
    }

    /// Returns the exact typed event carrying the proof artifacts.
    pub const fn event(&self) -> &'a ChannelEventV2 {
        self.event
    }
}

/// Deterministic static proof-admission boundary for `CheckTx` and proposer
/// filtering.
///
/// Implementations must reject permanently malformed cryptographic statements
/// without consulting a clock, mutable channel state, a network, or client
/// evidence. Checks that intrinsically require consensus time or prior state
/// remain in `LedgerApplicationVerifierV2` and run during rollback preview.
pub trait StaticAdmissionVerifierV2 {
    /// Implementation-specific rejection detail, never committed or returned
    /// to an untrusted client.
    type Error;

    /// Returns the immutable identity of the installed static/contextual proof
    /// implementation and verification-key policy.
    fn verifier_profile_id(&self) -> [u8; 32];

    /// Returns the immutable deployment/committee descriptor authenticated by
    /// this verifier.
    fn deployment_descriptor(&self) -> [u8; 32];

    /// Verifies time- and state-independent proof validity.
    fn verify_static(&self, request: StaticAdmissionRequestV2<'_>) -> std::result::Result<(), Self::Error>;
}

/// ABCI stage that encountered a failure which cannot be represented by an
/// ordinary protocol response without risking consensus/application drift.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FatalAbciStage {
    /// Durable handshake information could not be read.
    Info,
    /// Genesis identity or initialization failed.
    InitChain,
    /// A read query encountered storage corruption or another fatal runtime
    /// failure.
    Query,
    /// Mempool admission encountered a fatal runtime failure.
    CheckTx,
    /// Proposer construction encountered a fatal runtime failure.
    PrepareProposal,
    /// Deterministic proposal processing encountered a fatal runtime failure.
    ProcessProposal,
    /// A decided block could not be staged exactly.
    FinalizeBlock,
    /// Commit was missing, failed, or became ambiguous.
    Commit,
}

/// Redacted fatal failure passed to the configured supervisor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FatalAbciFailure {
    stage: FatalAbciStage,
    code: &'static str,
}

impl FatalAbciFailure {
    /// Returns the ABCI stage that must be restarted/replayed.
    pub const fn stage(&self) -> FatalAbciStage {
        self.stage
    }

    /// Returns a stable redacted failure code.
    pub const fn code(&self) -> &'static str {
        self.code
    }
}

/// Supervised fatal boundary for infallible `tendermint-abci` callbacks.
///
/// Implementations must close the ABCI session or terminate the application
/// process and never return. This prevents CometBFT from observing an ordinary
/// successful response after storage or commit ambiguity.
pub trait FatalAbciHandler: Send + Sync + 'static {
    /// Terminates the current ABCI session/process for handshake recovery.
    fn terminate(&self, failure: FatalAbciFailure) -> !;
}

/// Fatal handler that terminates the complete application process.
#[derive(Clone, Copy, Debug)]
pub struct ProcessExitFatalHandler {
    exit_code: u8,
}

impl ProcessExitFatalHandler {
    /// Constructs a process-exit handler. Zero is rejected because fatal exits
    /// must never look successful to a supervisor.
    pub fn new(exit_code: u8) -> Result<Self> {
        if exit_code == 0 {
            return Err(AbciAdapterError::InvalidRequest(
                "fatal process exit code must be nonzero",
            ));
        }
        Ok(Self { exit_code })
    }
}

impl FatalAbciHandler for ProcessExitFatalHandler {
    fn terminate(&self, failure: FatalAbciFailure) -> ! {
        eprintln!(
            "fatal ABCI failure: stage={:?} code={}",
            failure.stage(),
            failure.code()
        );
        std::process::exit(i32::from(self.exit_code));
    }
}

/// Immutable digest binding every replica to one verifier/deployment/resource
/// profile.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ConsensusProfileV2 {
    digest: [u8; 32],
}

impl ConsensusProfileV2 {
    /// Derives a canonical profile from the exact chain, verifier identity,
    /// deployment descriptor, reducer limits, and compiled ABCI resource
    /// limits.
    pub fn from_verifier<V: StaticAdmissionVerifierV2>(
        ledger_chain_id: &thunderbolt_ledger::LedgerChainIdV2,
        protocol_limits: ProtocolLimitsV2,
        verifier: &V,
    ) -> Result<Self> {
        let pending_invoices = u64::try_from(protocol_limits.max_pending_invoices)
            .map_err(|_| AbciAdapterError::InvalidRequest("pending Invoice limit exceeds u64"))?;
        let chain_len = u64::try_from(ledger_chain_id.as_str().len())
            .map_err(|_| AbciAdapterError::InvalidRequest("Ledger chain id length exceeds u64"))?;
        let mut hasher = Sha256::new();
        hasher.update(b"bitcoin-thunderbolt/abci-consensus-profile/v2");
        hasher.update(chain_len.to_be_bytes());
        hasher.update(ledger_chain_id.as_str().as_bytes());
        hasher.update(verifier.verifier_profile_id());
        hasher.update(verifier.deployment_descriptor());
        hasher.update(protocol_limits.max_entries_per_channel.to_be_bytes());
        hasher.update(pending_invoices.to_be_bytes());
        hasher.update(protocol_limits.max_invoice_ttl_ms.to_be_bytes());
        for value in [
            APPLICATION_VERSION,
            MAX_TRANSACTION_BYTES as u64,
            MAX_BLOCK_TRANSACTION_BYTES as u64,
            MAX_QUERY_REQUEST_BYTES as u64,
            MAX_QUERY_RESPONSE_BYTES as u64,
            MAX_PREPARE_PREVIEW_WORK as u64,
            MAX_PREPARE_SCAN_TRANSACTIONS as u64,
            MAX_PREPARE_SCAN_BYTES as u64,
            MAX_MISBEHAVIOR_RECORDS as u64,
            MAX_COMMIT_VOTES as u64,
            MAX_BLOCK_ENTRIES as u64,
            MAX_BLOCK_EVENT_BYTES as u64,
            MAX_STATIC_REJECTION_CACHE_ENTRIES as u64,
        ] {
            hasher.update(value.to_be_bytes());
        }
        Ok(Self {
            digest: hasher.finalize().into(),
        })
    }

    /// Returns the exact durable/genesis digest.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.digest
    }

    /// Returns the canonical JSON bytes required in CometBFT genesis
    /// `app_state` and delivered as `InitChain.app_state_bytes`.
    pub fn genesis_app_state_bytes(&self) -> Result<Vec<u8>> {
        #[derive(Serialize)]
        struct GenesisProfile<'a> {
            application_version: u64,
            consensus_profile_digest: &'a [u8; 32],
        }
        Ok(serde_json::to_vec(&GenesisProfile {
            application_version: APPLICATION_VERSION,
            consensus_profile_digest: &self.digest,
        })?)
    }
}

/// Clone-safe ABCI application backed by one synchronized Ledger application.
///
/// Every clone shares the durable SQLite handle, verifier capability, staged
/// block, and fail-closed fault state. The verifier must be deterministic and
/// side-effect free as required by `LedgerApplicationVerifierV2`.
pub struct ThunderboltLedgerAbci<V, F> {
    inner: Arc<Shared<V, F>>,
}

impl<V, F> Clone for ThunderboltLedgerAbci<V, F> {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

impl<V, F> fmt::Debug for ThunderboltLedgerAbci<V, F> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ThunderboltLedgerAbci")
            .field("ledger_chain_id", self.inner.application.ledger_chain_id())
            .field("application_version", &APPLICATION_VERSION)
            .finish_non_exhaustive()
    }
}

struct Shared<V, F> {
    application: LedgerApplication,
    verifier: V,
    fatal_handler: F,
    consensus_profile: ConsensusProfileV2,
    runtime: Mutex<RuntimeState>,
    static_rejections: Mutex<StaticRejectionCache>,
    mempool_admissions: Mutex<MempoolAdmissionCache>,
    prepare_cursor: Mutex<usize>,
    #[cfg(test)]
    fail_after_commit: AtomicBool,
}

#[derive(Default)]
struct RuntimeState {
    staged: Option<StagedBlock>,
    faulted: bool,
}

#[derive(Default)]
struct StaticRejectionCache {
    order: VecDeque<AdmissionKey>,
    entries: HashSet<AdmissionKey>,
}

impl StaticRejectionCache {
    fn contains(&self, key: &AdmissionKey) -> bool {
        self.entries.contains(key)
    }

    fn insert(&mut self, key: AdmissionKey) {
        if !self.entries.insert(key) {
            return;
        }
        self.order.push_back(key);
        while self.order.len() > MAX_STATIC_REJECTION_CACHE_ENTRIES {
            if let Some(evicted) = self.order.pop_front() {
                self.entries.remove(&evicted);
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct AdmissionKey {
    channel: [u8; 32],
    participant: [u8; 32],
    request: [u8; 32],
    entry: [u8; 32],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AdmissionPurpose {
    MempoolNew,
    MempoolRecheck,
    Prepare,
    Consensus,
}

#[derive(Default)]
struct MempoolAdmissionCache {
    order: VecDeque<AdmissionKey>,
    entries: std::collections::HashMap<AdmissionKey, [u8; 32]>,
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
        while self.order.len() > MAX_STATIC_REJECTION_CACHE_ENTRIES {
            if let Some(evicted) = self.order.pop_front() {
                self.entries.remove(&evicted);
            }
        }
    }
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

struct BoundedJsonWriter {
    bytes: Vec<u8>,
    limit: usize,
    exceeded: bool,
}

impl BoundedJsonWriter {
    fn new(limit: usize) -> Self {
        Self {
            bytes: Vec::new(),
            limit,
            exceeded: false,
        }
    }
}

impl Write for BoundedJsonWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let Some(next_len) = self.bytes.len().checked_add(bytes.len()) else {
            self.exceeded = true;
            return Err(io::Error::other("bounded JSON response length overflows"));
        };
        if next_len > self.limit {
            self.exceeded = true;
            return Err(io::Error::other("bounded JSON response exceeds limit"));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<V, F> ThunderboltLedgerAbci<V, F>
where
    V: LedgerApplicationVerifierV2 + StaticAdmissionVerifierV2 + Send + Sync + 'static,
    F: FatalAbciHandler,
{
    /// Constructs an ABCI adapter over an already opened, chain-scoped Ledger.
    pub fn new(application: LedgerApplication, verifier: V, fatal_handler: F) -> Result<Self> {
        if application.application_version() != APPLICATION_VERSION || APPLICATION_VERSION != APPLICATION_VERSION_V2 {
            return Err(AbciAdapterError::InvalidRequest(
                "Ledger and ABCI application versions differ",
            ));
        }
        let consensus_profile =
            ConsensusProfileV2::from_verifier(application.ledger_chain_id(), application.protocol_limits(), &verifier)?;
        let status = application.status()?;
        if status.application_version() != APPLICATION_VERSION
            || status.ledger_chain_id() != application.ledger_chain_id()
            || application.consensus_profile_digest() != Some(consensus_profile.as_bytes())
        {
            return Err(AbciAdapterError::InvalidRequest(
                "durable Ledger identity differs from the ABCI adapter",
            ));
        }
        Ok(Self {
            inner: Arc::new(Shared {
                application,
                verifier,
                fatal_handler,
                consensus_profile,
                runtime: Mutex::new(RuntimeState::default()),
                static_rejections: Mutex::new(StaticRejectionCache::default()),
                mempool_admissions: Mutex::new(MempoolAdmissionCache::default()),
                prepare_cursor: Mutex::new(0),
                #[cfg(test)]
                fail_after_commit: AtomicBool::new(false),
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

    /// Returns the mechanically derived profile required by genesis and the
    /// durable application identity.
    pub fn consensus_profile(&self) -> &ConsensusProfileV2 {
        &self.inner.consensus_profile
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
        if request.validators.len() > MAX_COMMIT_VOTES {
            return Err(AbciAdapterError::InvalidRequest(
                "genesis validator count exceeds bound",
            ));
        }
        if request.app_state_bytes.as_ref() != self.inner.consensus_profile.genesis_app_state_bytes()?.as_slice() {
            return Err(AbciAdapterError::InvalidRequest(
                "Thunderbolt InitChain consensus profile differs",
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
        let check_type = CheckTxType::try_from(request.r#type)
            .map_err(|_| AbciAdapterError::InvalidRequest("CheckTx type is unknown"))?;
        let purpose = match check_type {
            CheckTxType::New => AdmissionPurpose::MempoolNew,
            CheckTxType::Recheck => AdmissionPurpose::MempoolRecheck,
        };
        let proposal = self.admit_transaction(request.tx.as_ref(), purpose)?;
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
        let mut preview_work = 0_usize;
        let mut scanned_transactions = 0_usize;
        let mut scanned_bytes = 0_usize;
        let transaction_count = request.txs.len();
        let mut cursor = self
            .inner
            .prepare_cursor
            .lock()
            .map_err(|_| AbciAdapterError::LockPoisoned)?;
        if *cursor >= transaction_count {
            *cursor = 0;
        }
        let start = *cursor;
        for (index, transaction) in request.txs.into_iter().enumerate().skip(start) {
            if scanned_transactions == MAX_PREPARE_SCAN_TRANSACTIONS {
                break;
            }
            let Some(next_scanned_bytes) = scanned_bytes.checked_add(transaction.len()) else {
                break;
            };
            if next_scanned_bytes > MAX_PREPARE_SCAN_BYTES {
                break;
            }
            scanned_transactions = scanned_transactions.saturating_add(1);
            scanned_bytes = next_scanned_bytes;
            *cursor = if index.saturating_add(1) >= transaction_count {
                0
            } else {
                index.saturating_add(1)
            };
            if transaction.is_empty() || transaction.len() > MAX_TRANSACTION_BYTES {
                continue;
            }
            let Some(next_total) = selected_bytes.checked_add(transaction.len()) else {
                break;
            };
            if next_total > budget || next_total > MAX_BLOCK_TRANSACTION_BYTES {
                continue;
            }
            let Ok(proposal) = self.admit_transaction(transaction.as_ref(), AdmissionPurpose::Prepare) else {
                continue;
            };
            let event = ChannelEventV2::from_canonical_bytes(proposal.body().event().as_bytes())
                .map_err(|_| AbciAdapterError::InvalidTransaction("transaction event cannot be decoded"))?;
            if matches!(
                event,
                ChannelEventV2::Invoice(ref invoice) if invoice.expires_at_ms <= block_time_ms
            ) {
                continue;
            }
            let mut candidate = pending.clone();
            if candidate.push(proposal).is_err() {
                continue;
            }
            let candidate_work = candidate.proposals().len();
            let Some(next_work) = preview_work.checked_add(candidate_work) else {
                break;
            };
            if next_work > MAX_PREPARE_PREVIEW_WORK {
                break;
            }
            let Ok(input) = BlockInputV2::new(
                self.ledger_chain_id().clone(),
                height,
                block_time_ms,
                status.last_app_hash().clone(),
                candidate.proposals().to_vec(),
            ) else {
                continue;
            };
            preview_work = next_work;
            match self.inner.application.preview_block(input, &self.inner.verifier) {
                Ok(_) => {}
                Err(error) => {
                    let error = AbciAdapterError::Application(error);
                    if error.is_fatal_runtime() {
                        return Err(error);
                    }
                    continue;
                }
            }
            pending = candidate;
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

    /// Atomically persists the currently staged block.
    ///
    /// Any missing-stage call fails closed: CometBFT calls `Commit` exactly once
    /// after `FinalizeBlock`, and crash recovery must replay `FinalizeBlock`
    /// before attempting the commit again.
    pub fn try_commit(&self) -> Result<ResponseCommit> {
        let mut runtime = self.lock_runtime()?;
        if runtime.faulted {
            return Err(AbciAdapterError::Faulted);
        }
        let Some(staged) = runtime.staged.take() else {
            return Err(AbciAdapterError::MissingStagedBlock);
        };
        let expected_hash = staged.prepared.outcome().block().app_hash().clone();
        match self
            .inner
            .application
            .commit_prepared_block(staged.prepared, &self.inner.verifier)
        {
            Ok(outcome) if outcome.block().app_hash() == &expected_hash => {
                #[cfg(test)]
                if self.inner.fail_after_commit.swap(false, Ordering::SeqCst) {
                    runtime.faulted = true;
                    return Err(AbciAdapterError::PostCommitAmbiguous);
                }
                Ok(ResponseCommit { retain_height: 0 })
            }
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
        let (value, response_height) = match request.path.as_str() {
            QUERY_STATUS_PATH => {
                let status = self.inner.application.status()?;
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
                let context = ChannelContextIdV2::from_bytes(parse_array::<32>(request.data.as_ref(), "channel")?)?;
                let read = self.inner.application.channel_at_head(&context)?;
                require_current_query_height(request.height, read.status().last_height())?;
                let snapshot = read.channel().ok_or(AbciAdapterError::NotFound("channel"))?;
                let value = ChannelQueryValue {
                    committed_application_height: read.status().last_height(),
                    committed_application_hash: read.status().last_app_hash(),
                    snapshot,
                };
                (encode_query_value(&value)?, read.status().last_height())
            }
            QUERY_REQUEST_PATH => {
                if request.prove {
                    return Err(AbciAdapterError::InvalidRequest(
                        "request query does not produce CometBFT ProofOps",
                    ));
                }
                let (channel, participant, request_digest) = parse_request_key(request.data.as_ref())?;
                let read = self
                    .inner
                    .application
                    .request_at_head(&channel, &participant, &request_digest)?;
                require_current_query_height(request.height, read.status().last_height())?;
                let stored = read.request().ok_or(AbciAdapterError::NotFound("request mapping"))?;
                let value = RequestQueryValue {
                    channel_context_id: stored.channel_context_id(),
                    participant_id: stored.participant_id(),
                    request_digest: stored.request_digest(),
                    entry_hash: stored.entry_hash(),
                    first_height: stored.first_height(),
                    first_block_index: stored.first_block_index(),
                };
                (encode_query_value(&value)?, read.status().last_height())
            }
            QUERY_PROOF_PATH => {
                if request.prove {
                    return Err(AbciAdapterError::InvalidRequest(
                        "execution proof is not a CometBFT ProofOps capability",
                    ));
                }
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

    fn admit_transaction(&self, bytes: &[u8], purpose: AdmissionPurpose) -> Result<SignedProposalV2> {
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
        let entry_hash = body
            .entry_hash()
            .map_err(|_| AbciAdapterError::InvalidTransaction("entry hash is invalid"))?;
        let key = AdmissionKey {
            channel: *channel.as_bytes(),
            participant: *participant.as_bytes(),
            request: *body.request_id().digest().as_bytes(),
            entry: *entry_hash.as_bytes(),
        };
        if self
            .inner
            .static_rejections
            .lock()
            .map_err(|_| AbciAdapterError::LockPoisoned)?
            .contains(&key)
        {
            return Err(AbciAdapterError::InvalidTransaction(
                "logical request is in the static rejection cache",
            ));
        }
        if let Some(existing) = self
            .inner
            .application
            .request(&channel, &participant, body.request_id().digest())?
        {
            if existing.entry_hash() != &entry_hash {
                return Err(AbciAdapterError::InvalidTransaction(
                    "actor request conflicts with durable mapping",
                ));
            }
            if purpose != AdmissionPurpose::Consensus {
                return Err(AbciAdapterError::InvalidTransaction(
                    "actor request is already durably executed",
                ));
            }
        }
        let raw_digest: [u8; 32] = Sha256::digest(bytes).into();
        if matches!(purpose, AdmissionPurpose::MempoolNew | AdmissionPurpose::MempoolRecheck) {
            let cache = self
                .inner
                .mempool_admissions
                .lock()
                .map_err(|_| AbciAdapterError::LockPoisoned)?;
            if let Some(existing_digest) = cache.get(&key) {
                let rechecking_same = purpose == AdmissionPurpose::MempoolRecheck && existing_digest == &raw_digest;
                if !rechecking_same {
                    return Err(AbciAdapterError::InvalidTransaction(
                        "logical request is already admitted to the mempool",
                    ));
                }
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
        let event = ChannelEventV2::from_canonical_bytes(proposal.body().event().as_bytes())
            .map_err(|_| AbciAdapterError::InvalidTransaction("transaction event cannot be decoded"))?;
        if self
            .inner
            .verifier
            .verify_static(StaticAdmissionRequestV2 {
                proposal: &proposal,
                event: &event,
            })
            .is_err()
        {
            self.inner
                .static_rejections
                .lock()
                .map_err(|_| AbciAdapterError::LockPoisoned)?
                .insert(key);
            return Err(AbciAdapterError::InvalidTransaction(
                "transaction fails static proof admission",
            ));
        }
        if matches!(purpose, AdmissionPurpose::MempoolNew | AdmissionPurpose::MempoolRecheck) {
            self.preview_mempool_candidate(proposal.clone())?;
            self.inner
                .mempool_admissions
                .lock()
                .map_err(|_| AbciAdapterError::LockPoisoned)?
                .insert(key, raw_digest);
        }
        Ok(proposal)
    }

    fn preview_mempool_candidate(&self, proposal: SignedProposalV2) -> Result<()> {
        match self
            .inner
            .application
            .preview_next_block_for_admission(vec![proposal], &self.inner.verifier)
        {
            Ok(_) => Ok(()),
            Err(error) => {
                let error = AbciAdapterError::Application(error);
                if error.is_fatal_runtime() {
                    Err(error)
                } else {
                    Err(AbciAdapterError::InvalidTransaction(
                        "transaction is invalid against the current durable head",
                    ))
                }
            }
        }
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
            .map(|transaction| self.admit_transaction(transaction.as_ref(), AdmissionPurpose::Consensus))
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

    fn terminate(&self, stage: FatalAbciStage, error: &AbciAdapterError) -> ! {
        self.mark_faulted();
        self.inner.fatal_handler.terminate(FatalAbciFailure {
            stage,
            code: error.public_log(),
        })
    }

    #[cfg(test)]
    fn fail_after_next_commit_for_test(&self) {
        self.inner.fail_after_commit.store(true, Ordering::SeqCst);
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

impl<V, F> Application for ThunderboltLedgerAbci<V, F>
where
    V: LedgerApplicationVerifierV2 + StaticAdmissionVerifierV2 + Send + Sync + 'static,
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

    fn verify_vote_extension(&self, request: RequestVerifyVoteExtension) -> ResponseVerifyVoteExtension {
        let status = if request.vote_extension.is_empty() {
            response_verify_vote_extension::VerifyStatus::Accept
        } else {
            response_verify_vote_extension::VerifyStatus::Reject
        };
        ResponseVerifyVoteExtension { status: status as i32 }
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
    let mut writer = BoundedJsonWriter::new(MAX_QUERY_RESPONSE_BYTES);
    if let Err(error) = serde_json::to_writer(&mut writer, value) {
        if writer.exceeded {
            return Err(AbciAdapterError::InvalidRequest("query response exceeds bound"));
        }
        return Err(error.into());
    }
    if writer.exceeded {
        return Err(AbciAdapterError::InvalidRequest("query response exceeds bound"));
    }
    Ok(writer.bytes)
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
