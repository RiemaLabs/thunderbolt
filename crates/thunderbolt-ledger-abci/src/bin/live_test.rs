//! Insecure, feature-gated process used only by the isolated CometBFT gate.

#![deny(
    clippy::expect_used,
    clippy::panic,
    clippy::todo,
    clippy::unimplemented,
    clippy::unwrap_used
)]
#![forbid(unsafe_code)]

use std::env;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use serde_json::json;
use tendermint_abci::Application;
use tendermint_proto::v0_38::abci::{
    RequestApplySnapshotChunk, RequestCheckTx, RequestEcho, RequestExtendVote, RequestFinalizeBlock, RequestInfo,
    RequestInitChain, RequestLoadSnapshotChunk, RequestOfferSnapshot, RequestPrepareProposal, RequestProcessProposal,
    RequestQuery, RequestVerifyVoteExtension, ResponseApplySnapshotChunk, ResponseCheckTx, ResponseCommit,
    ResponseEcho, ResponseExtendVote, ResponseFinalizeBlock, ResponseFlush, ResponseInfo, ResponseInitChain,
    ResponseListSnapshots, ResponseLoadSnapshotChunk, ResponseOfferSnapshot, ResponsePrepareProposal,
    ResponseProcessProposal, ResponseQuery, ResponseVerifyVoteExtension,
};
use thunderbolt_abci_server::{
    start, FatalServerEvent, FatalServerHandler, ServerConfig, ServerDeadlines, ServerEndpoint, ServerLimits,
    MAX_SERVER_INFLIGHT_BYTES,
};
use thunderbolt_ledger::LedgerChainIdV2;
use thunderbolt_ledger_abci::{
    ConsensusProfileV2, ProcessExitFatalHandler, StaticAdmissionRequestV2, StaticAdmissionVerifierV2,
    ThunderboltLedgerAbci, MAX_COMMIT_VOTES, MAX_MISBEHAVIOR_RECORDS, MAX_PREPARE_SCAN_TRANSACTIONS,
};
use thunderbolt_ledger_app::{ApplicationOptions, LedgerApplication};
use thunderbolt_protocol::v2::{
    ExternalVerifierV2, FinalizeVerificationRequestV2, InvoiceVerificationRequestV2, OpenVerificationRequestV2,
    TransferVerificationRequestV2,
};

const CRASH_EXIT_CODE: u8 = 86;
const POST_COMMIT_CRASH_EXIT_CODE: u8 = 87;
const INFO_CRASH_EXIT_CODE: u8 = 88;
const SERVER_FATAL_EXIT_CODE: u8 = 89;
const MAX_ABCI_FRAME_BYTES: usize = 26 * 1024 * 1024;
const MAX_ABCI_CONNECTIONS: usize = 16;
const MAX_CONCURRENT_HANDLERS: usize = 8;
const MAX_REQUEST_DECODE_ITEMS: usize = MAX_PREPARE_SCAN_TRANSACTIONS + MAX_MISBEHAVIOR_RECORDS + MAX_COMMIT_VOTES;

#[derive(Clone, Copy)]
struct LiveServerFatal;

impl FatalServerHandler for LiveServerFatal {
    fn terminate(&self, event: FatalServerEvent) -> ! {
        eprintln!(
            "fatal live-test ABCI server failure: kind={:?} connection={:?}",
            event.kind(),
            event.connection_id()
        );
        std::process::exit(i32::from(SERVER_FATAL_EXIT_CODE));
    }
}

#[derive(Debug, Default)]
struct InsecureAcceptAll;

impl ExternalVerifierV2 for InsecureAcceptAll {
    type Error = ();

    fn verify_open(&self, _request: OpenVerificationRequestV2<'_>) -> Result<(), Self::Error> {
        Ok(())
    }

    fn verify_invoice(&self, _request: InvoiceVerificationRequestV2<'_>) -> Result<(), Self::Error> {
        Ok(())
    }

    fn verify_transfer(&self, _request: TransferVerificationRequestV2<'_>) -> Result<(), Self::Error> {
        Ok(())
    }

    fn verify_finalize(&self, _request: FinalizeVerificationRequestV2<'_>) -> Result<(), Self::Error> {
        Ok(())
    }
}

impl StaticAdmissionVerifierV2 for InsecureAcceptAll {
    type Error = ();

    fn verifier_profile_id(&self) -> [u8; 32] {
        [0x91; 32]
    }

    fn deployment_descriptor(&self) -> [u8; 32] {
        [0x92; 32]
    }

    fn verify_static(&self, _request: StaticAdmissionRequestV2<'_>) -> Result<(), Self::Error> {
        Ok(())
    }
}

#[derive(Clone)]
struct CrashBeforeCommit<A> {
    inner: A,
    before_target_height: Option<i64>,
    before_armed_height: Arc<AtomicI64>,
    before_marker: Option<Arc<PathBuf>>,
    after_target_height: Option<i64>,
    after_armed_height: Arc<AtomicI64>,
    after_marker: Option<Arc<PathBuf>>,
    crash_on_info: Arc<AtomicBool>,
    info_marker: Option<Arc<PathBuf>>,
}

impl<A> CrashBeforeCommit<A> {
    fn new(
        inner: A,
        before_target_height: Option<i64>,
        before_marker: Option<PathBuf>,
        after_target_height: Option<i64>,
        after_marker: Option<PathBuf>,
        info_marker: Option<PathBuf>,
    ) -> Self {
        Self {
            inner,
            before_target_height,
            before_armed_height: Arc::new(AtomicI64::new(0)),
            before_marker: before_marker.map(Arc::new),
            after_target_height,
            after_armed_height: Arc::new(AtomicI64::new(0)),
            after_marker: after_marker.map(Arc::new),
            crash_on_info: Arc::new(AtomicBool::new(info_marker.is_some())),
            info_marker: info_marker.map(Arc::new),
        }
    }

    fn crash_now(marker: Option<&PathBuf>, height: i64, exit_code: u8) -> ! {
        if let Some(path) = marker {
            let result = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(path)
                .and_then(|mut file| {
                    writeln!(file, "{height}")?;
                    file.sync_all()
                });
            if let Err(error) = result {
                eprintln!("failed to write crash marker: {error}");
            }
        }
        std::process::exit(i32::from(exit_code));
    }
}

impl<A: Application> Application for CrashBeforeCommit<A> {
    fn echo(&self, request: RequestEcho) -> ResponseEcho {
        self.inner.echo(request)
    }

    fn info(&self, request: RequestInfo) -> ResponseInfo {
        if self.crash_on_info.swap(false, Ordering::SeqCst) {
            Self::crash_now(self.info_marker.as_deref(), 0, INFO_CRASH_EXIT_CODE);
        }
        self.inner.info(request)
    }

    fn init_chain(&self, request: RequestInitChain) -> ResponseInitChain {
        self.inner.init_chain(request)
    }

    fn query(&self, request: RequestQuery) -> ResponseQuery {
        self.inner.query(request)
    }

    fn check_tx(&self, request: RequestCheckTx) -> ResponseCheckTx {
        self.inner.check_tx(request)
    }

    fn flush(&self) -> ResponseFlush {
        self.inner.flush()
    }

    fn commit(&self) -> ResponseCommit {
        let before_height = self.before_armed_height.swap(0, Ordering::SeqCst);
        if before_height > 0 {
            Self::crash_now(self.before_marker.as_deref(), before_height, CRASH_EXIT_CODE);
        }
        let after_height = self.after_armed_height.swap(0, Ordering::SeqCst);
        let response = self.inner.commit();
        if after_height > 0 {
            Self::crash_now(self.after_marker.as_deref(), after_height, POST_COMMIT_CRASH_EXIT_CODE);
        }
        response
    }

    fn list_snapshots(&self) -> ResponseListSnapshots {
        self.inner.list_snapshots()
    }

    fn offer_snapshot(&self, request: RequestOfferSnapshot) -> ResponseOfferSnapshot {
        self.inner.offer_snapshot(request)
    }

    fn load_snapshot_chunk(&self, request: RequestLoadSnapshotChunk) -> ResponseLoadSnapshotChunk {
        self.inner.load_snapshot_chunk(request)
    }

    fn apply_snapshot_chunk(&self, request: RequestApplySnapshotChunk) -> ResponseApplySnapshotChunk {
        self.inner.apply_snapshot_chunk(request)
    }

    fn prepare_proposal(&self, request: RequestPrepareProposal) -> ResponsePrepareProposal {
        self.inner.prepare_proposal(request)
    }

    fn process_proposal(&self, request: RequestProcessProposal) -> ResponseProcessProposal {
        self.inner.process_proposal(request)
    }

    fn extend_vote(&self, request: RequestExtendVote) -> ResponseExtendVote {
        self.inner.extend_vote(request)
    }

    fn verify_vote_extension(&self, request: RequestVerifyVoteExtension) -> ResponseVerifyVoteExtension {
        self.inner.verify_vote_extension(request)
    }

    fn finalize_block(&self, request: RequestFinalizeBlock) -> ResponseFinalizeBlock {
        let height = request.height;
        let response = self.inner.finalize_block(request);
        if self.before_target_height == Some(height) && response.app_hash.len() == 32 {
            self.before_armed_height.store(height, Ordering::SeqCst);
        }
        if self.after_target_height == Some(height) && response.app_hash.len() == 32 {
            self.after_armed_height.store(height, Ordering::SeqCst);
        }
        response
    }
}

struct ServeOptions {
    listen: SocketAddr,
    database: PathBuf,
    chain_id: LedgerChainIdV2,
    crash_before_commit_height: Option<i64>,
    crash_before_commit_marker: Option<PathBuf>,
    crash_after_commit_height: Option<i64>,
    crash_after_commit_marker: Option<PathBuf>,
    crash_on_info_marker: Option<PathBuf>,
}

enum Command {
    Serve(ServeOptions),
    Status {
        database: PathBuf,
        chain_id: LedgerChainIdV2,
    },
    Profile {
        chain_id: LedgerChainIdV2,
    },
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    match parse_command()? {
        Command::Serve(options) => serve(options),
        Command::Status { database, chain_id } => print_status(&database, chain_id),
        Command::Profile { chain_id } => print_profile(chain_id),
    }
}

fn serve(options: ServeOptions) -> Result<(), String> {
    let ServeOptions {
        listen,
        database,
        chain_id,
        crash_before_commit_height,
        crash_before_commit_marker,
        crash_after_commit_height,
        crash_after_commit_marker,
        crash_on_info_marker,
    } = options;
    let verifier = InsecureAcceptAll;
    let application = open_application(&database, chain_id, &verifier)?;
    let fatal_handler =
        ProcessExitFatalHandler::new(87).map_err(|error| format!("cannot construct fatal handler: {error}"))?;
    let adapter = ThunderboltLedgerAbci::new(application, verifier, fatal_handler)
        .map_err(|error| format!("cannot construct live-test adapter: {error}"))?;
    let application = CrashBeforeCommit::new(
        adapter,
        crash_before_commit_height,
        crash_before_commit_marker,
        crash_after_commit_height,
        crash_after_commit_marker,
        crash_on_info_marker,
    );
    if !listen.ip().is_loopback() {
        return Err("live-test ABCI listener must use a loopback address".to_owned());
    }
    let limits = server_limits()?;
    let deadlines = ServerDeadlines::new(
        Duration::from_millis(5),
        Duration::from_secs(30),
        Duration::from_secs(2),
        Duration::from_secs(2),
        Duration::from_secs(15),
        Duration::from_secs(5),
        Duration::from_secs(15),
        Duration::from_secs(60),
        Duration::from_secs(75),
    )
    .map_err(|error| format!("cannot construct live-test ABCI deadlines: {error}"))?;
    let config = ServerConfig::new(ServerEndpoint::Tcp(listen), limits, deadlines)
        .map_err(|error| format!("cannot construct live-test ABCI server config: {error}"))?;
    let _server = start(config, application, LiveServerFatal)
        .map_err(|error| format!("cannot start bounded live-test ABCI server: {error}"))?;
    loop {
        thread::park();
    }
}

fn server_limits() -> Result<ServerLimits, String> {
    let per_handler =
        ServerLimits::required_per_handler_bytes(MAX_ABCI_FRAME_BYTES, MAX_ABCI_FRAME_BYTES, MAX_REQUEST_DECODE_ITEMS)
            .ok_or_else(|| "live-test ABCI per-handler reservation overflows".to_owned())?;
    let max_inflight = per_handler
        .checked_mul(MAX_CONCURRENT_HANDLERS)
        .filter(|value| *value <= MAX_SERVER_INFLIGHT_BYTES)
        .ok_or_else(|| "live-test ABCI aggregate reservation exceeds the hard cap".to_owned())?;
    ServerLimits::new(
        MAX_ABCI_FRAME_BYTES,
        MAX_ABCI_FRAME_BYTES,
        MAX_ABCI_CONNECTIONS,
        max_inflight,
        MAX_REQUEST_DECODE_ITEMS,
    )
    .map_err(|error| format!("cannot construct live-test ABCI limits: {error}"))
}

fn print_status(database: &Path, chain_id: LedgerChainIdV2) -> Result<(), String> {
    let verifier = InsecureAcceptAll;
    let application = open_application(database, chain_id, &verifier)?;
    let status = application
        .status()
        .map_err(|error| format!("cannot read live-test status: {error}"))?;
    let value = json!({
        "application_version": status.application_version(),
        "ledger_chain_id": status.ledger_chain_id().as_str(),
        "last_height": status.last_height(),
        "last_block_time_ms": status.last_block_time_ms(),
        "last_app_hash": status.last_app_hash(),
    });
    println!(
        "{}",
        serde_json::to_string(&value).map_err(|error| format!("cannot encode status: {error}"))?
    );
    Ok(())
}

fn print_profile(chain_id: LedgerChainIdV2) -> Result<(), String> {
    let verifier = InsecureAcceptAll;
    let profile = ConsensusProfileV2::from_verifier(
        &chain_id,
        thunderbolt_protocol::v2::ProtocolLimitsV2::default(),
        &verifier,
    )
    .map_err(|error| format!("cannot derive consensus profile: {error}"))?;
    let bytes = profile
        .genesis_app_state_bytes()
        .map_err(|error| format!("cannot encode consensus profile: {error}"))?;
    println!(
        "{}",
        String::from_utf8(bytes).map_err(|_| "consensus profile JSON is not UTF-8".to_owned())?
    );
    Ok(())
}

fn open_application(
    database: &Path,
    chain_id: LedgerChainIdV2,
    verifier: &InsecureAcceptAll,
) -> Result<LedgerApplication, String> {
    if let Some(parent) = database.parent() {
        fs::create_dir_all(parent).map_err(|error| format!("cannot create database directory: {error}"))?;
    }
    let limits = thunderbolt_protocol::v2::ProtocolLimitsV2::default();
    let profile = ConsensusProfileV2::from_verifier(&chain_id, limits, verifier)
        .map_err(|error| format!("cannot derive consensus profile: {error}"))?;
    LedgerApplication::open(
        database,
        chain_id,
        ApplicationOptions {
            protocol_limits: limits,
            consensus_profile_digest: Some(*profile.as_bytes()),
            ..ApplicationOptions::default()
        },
    )
    .map_err(|error| format!("cannot open live-test database: {error}"))
}

fn parse_command() -> Result<Command, String> {
    let mut arguments = env::args().skip(1);
    let mode = arguments
        .next()
        .ok_or_else(|| usage("missing serve or status command"))?;
    let mut listen = None;
    let mut database = None;
    let mut chain_id = None;
    let mut crash_before_commit_height = None;
    let mut crash_before_commit_marker = None;
    let mut crash_after_commit_height = None;
    let mut crash_after_commit_marker = None;
    let mut crash_on_info_marker = None;
    while let Some(flag) = arguments.next() {
        let value = arguments.next().ok_or_else(|| usage("command option has no value"))?;
        match flag.as_str() {
            "--listen" => {
                listen = Some(
                    value
                        .parse()
                        .map_err(|_| usage("--listen must be an IP socket address"))?,
                );
            }
            "--db" => database = Some(PathBuf::from(value)),
            "--chain-id" => {
                chain_id = Some(LedgerChainIdV2::new(value).map_err(|_| usage("--chain-id is invalid"))?);
            }
            "--crash-before-commit-height" => {
                let height = value
                    .parse::<i64>()
                    .ok()
                    .filter(|height| *height > 0)
                    .ok_or_else(|| usage("crash height must be positive"))?;
                crash_before_commit_height = Some(height);
            }
            "--crash-before-commit-marker" => crash_before_commit_marker = Some(PathBuf::from(value)),
            "--crash-after-commit-height" => {
                let height = value
                    .parse::<i64>()
                    .ok()
                    .filter(|height| *height > 0)
                    .ok_or_else(|| usage("post-commit crash height must be positive"))?;
                crash_after_commit_height = Some(height);
            }
            "--crash-after-commit-marker" => crash_after_commit_marker = Some(PathBuf::from(value)),
            "--crash-on-info-marker" => crash_on_info_marker = Some(PathBuf::from(value)),
            _ => return Err(usage("unknown command option")),
        }
    }
    let chain_id = chain_id.ok_or_else(|| usage("--chain-id is required"))?;
    match mode.as_str() {
        "serve" => {
            let database = database.ok_or_else(|| usage("serve requires --db"))?;
            let listen = listen.ok_or_else(|| usage("serve requires --listen"))?;
            if crash_before_commit_height.is_some() != crash_before_commit_marker.is_some()
                || crash_after_commit_height.is_some() != crash_after_commit_marker.is_some()
            {
                return Err(usage("each commit crash height and marker must be supplied together"));
            }
            Ok(Command::Serve(ServeOptions {
                listen,
                database,
                chain_id,
                crash_before_commit_height,
                crash_before_commit_marker,
                crash_after_commit_height,
                crash_after_commit_marker,
                crash_on_info_marker,
            }))
        }
        "status" => {
            let database = database.ok_or_else(|| usage("status requires --db"))?;
            if listen.is_some()
                || crash_before_commit_height.is_some()
                || crash_before_commit_marker.is_some()
                || crash_after_commit_height.is_some()
                || crash_after_commit_marker.is_some()
                || crash_on_info_marker.is_some()
            {
                return Err(usage("status accepts only --db and --chain-id"));
            }
            Ok(Command::Status { database, chain_id })
        }
        "profile" => {
            if listen.is_some()
                || database.is_some()
                || crash_before_commit_height.is_some()
                || crash_before_commit_marker.is_some()
                || crash_after_commit_height.is_some()
                || crash_after_commit_marker.is_some()
                || crash_on_info_marker.is_some()
            {
                return Err(usage("profile accepts only --chain-id"));
            }
            Ok(Command::Profile { chain_id })
        }
        _ => Err(usage("unknown command")),
    }
}

fn usage(reason: &str) -> String {
    format!(
        "{reason}\nusage: thunderbolt-ledger-abci-live-test serve --listen IP:PORT --db PATH --chain-id ID [--crash-before-commit-height N --crash-before-commit-marker PATH] [--crash-after-commit-height N --crash-after-commit-marker PATH] [--crash-on-info-marker PATH]\n       thunderbolt-ledger-abci-live-test status --db PATH --chain-id ID\n       thunderbolt-ledger-abci-live-test profile --chain-id ID\nWARNING: this binary accepts all operation proofs and is only for the isolated live test"
    )
}
