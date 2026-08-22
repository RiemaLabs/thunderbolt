//! Feature-gated deterministic process for the isolated CometBFT smoke gate.

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
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use serde::Deserialize;
use serde_json::json;
use tendermint::PublicKey as CometPublicKey;
use tendermint_abci::Application;
use tendermint_proto::v0_38::abci::{
    RequestApplySnapshotChunk, RequestCheckTx, RequestEcho, RequestExtendVote, RequestFinalizeBlock, RequestInfo,
    RequestInitChain, RequestLoadSnapshotChunk, RequestOfferSnapshot, RequestPrepareProposal, RequestProcessProposal,
    RequestQuery, RequestVerifyVoteExtension, ResponseApplySnapshotChunk, ResponseCheckTx, ResponseCommit,
    ResponseEcho, ResponseExtendVote, ResponseFinalizeBlock, ResponseFlush, ResponseInfo, ResponseInitChain,
    ResponseListSnapshots, ResponseLoadSnapshotChunk, ResponseOfferSnapshot, ResponsePrepareProposal,
    ResponseProcessProposal, ResponseQuery, ResponseVerifyVoteExtension, ValidatorUpdate,
};
use tendermint_proto::v0_38::crypto::{public_key, PublicKey};
use thunderbolt_abci_server::{
    start, FatalServerEvent, FatalServerHandler, ServerConfig, ServerDeadlines, ServerEndpoint, ServerLimits,
    MAX_SERVER_INFLIGHT_BYTES,
};
use thunderbolt_floor::FloorLedgerChainId;
use thunderbolt_floor_abci::{
    FloorConsensusProfileV2, FloorValidatorGenesisV2, ProcessExitFatalHandler, ThunderboltFloorAbci,
    MAX_ABCI_REQUEST_FRAME_BYTES, MAX_COMMIT_VOTES, MAX_MISBEHAVIOR_RECORDS, MAX_PREPARE_SCAN_TRANSACTIONS,
    MAX_QUERY_RESPONSE_BYTES,
};
use thunderbolt_floor_app::{FloorApplication, FloorGenesis, FloorOperatorKey, RegistryEntry};
use thunderbolt_keystore::{
    CommitteeDescriptorDigest, DeploymentBinding, DeploymentId, Network, NodeId, VaultIdentity, VaultRole,
};

const CRASH_EXIT_CODE: u8 = 86;
const ADAPTER_FATAL_EXIT_CODE: u8 = 87;
const SERVER_FATAL_EXIT_CODE: u8 = 89;
const MAX_ABCI_CONNECTIONS: usize = 16;
const MAX_CONCURRENT_HANDLERS: usize = 8;
const MAX_REQUEST_DECODE_ITEMS: usize = MAX_PREPARE_SCAN_TRANSACTIONS + MAX_MISBEHAVIOR_RECORDS + MAX_COMMIT_VOTES;
const OPERATOR_X_ONLY_KEY: [u8; 32] = [
    0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87, 0x0b, 0x07, 0x02, 0x9b, 0xfc,
    0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8, 0x17, 0x98,
];

#[derive(Clone, Copy)]
struct LiveServerFatal;

impl FatalServerHandler for LiveServerFatal {
    fn terminate(&self, event: FatalServerEvent) -> ! {
        eprintln!(
            "fatal Floor live-test server failure: kind={:?} connection={:?}",
            event.kind(),
            event.connection_id()
        );
        std::process::exit(i32::from(SERVER_FATAL_EXIT_CODE));
    }
}

#[derive(Clone)]
struct CrashBeforeCommit<A> {
    inner: A,
    init: Arc<InitExpectation>,
    target_height: Option<i64>,
    armed_height: Arc<AtomicI64>,
    marker: Option<Arc<PathBuf>>,
}

impl<A> CrashBeforeCommit<A> {
    fn new(inner: A, init: InitExpectation, target_height: Option<i64>, marker: Option<PathBuf>) -> Self {
        Self {
            inner,
            init: Arc::new(init),
            target_height,
            armed_height: Arc::new(AtomicI64::new(0)),
            marker: marker.map(Arc::new),
        }
    }

    fn crash_now(&self, height: i64) -> ! {
        if let Some(path) = self.marker.as_deref() {
            let result = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(path)
                .and_then(|mut file| {
                    writeln!(file, "{height}")?;
                    file.sync_all()
                });
            if let Err(error) = result {
                eprintln!("failed to write Floor crash marker: {error}");
            }
        }
        std::process::exit(i32::from(CRASH_EXIT_CODE));
    }
}

impl<A: Application> Application for CrashBeforeCommit<A> {
    fn echo(&self, request: RequestEcho) -> ResponseEcho {
        self.inner.echo(request)
    }
    fn info(&self, request: RequestInfo) -> ResponseInfo {
        self.inner.info(request)
    }
    fn init_chain(&self, request: RequestInitChain) -> ResponseInitChain {
        if request.chain_id != self.init.chain_id {
            eprintln!("Floor live InitChain mismatch: chain_id");
        }
        if request.initial_height != 1 {
            eprintln!(
                "Floor live InitChain mismatch: initial_height={}",
                request.initial_height
            );
        }
        if request.consensus_params.as_ref() != Some(&self.init.consensus_params) {
            eprintln!("Floor live InitChain mismatch: consensus_params");
        }
        if request.validators != self.init.validators {
            eprintln!("Floor live InitChain mismatch: validators");
        }
        if request.app_state_bytes.as_ref() != self.init.app_state.as_slice() {
            eprintln!(
                "Floor live InitChain mismatch: app_state length={} expected={}",
                request.app_state_bytes.len(),
                self.init.app_state.len()
            );
        }
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
        let height = self.armed_height.swap(0, Ordering::SeqCst);
        if height > 0 {
            self.crash_now(height);
        }
        self.inner.commit()
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
        if self.target_height == Some(height) && response.app_hash.len() == 32 {
            self.armed_height.store(height, Ordering::SeqCst);
        }
        response
    }
}

#[derive(Clone)]
struct InitExpectation {
    chain_id: String,
    consensus_params: tendermint_proto::v0_38::types::ConsensusParams,
    validators: Vec<ValidatorUpdate>,
    app_state: Vec<u8>,
}

struct Options {
    listen: Option<SocketAddr>,
    database: Option<PathBuf>,
    chain_id: FloorLedgerChainId,
    comet_genesis: PathBuf,
    crash_height: Option<i64>,
    crash_marker: Option<PathBuf>,
}

enum Command {
    Serve(Options),
    Status(Options),
    Profile(Options),
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
        Command::Status(options) => status(options),
        Command::Profile(options) => profile(options),
    }
}

fn serve(options: Options) -> Result<(), String> {
    let listen = options.listen.ok_or_else(|| usage("serve requires --listen"))?;
    let database = options
        .database
        .as_deref()
        .ok_or_else(|| usage("serve requires --db"))?;
    let (genesis, validators) = floor_genesis(&options.chain_id, &options.comet_genesis)?;
    let profile = FloorConsensusProfileV2::derive(&options.chain_id, &validators)
        .map_err(|error| format!("cannot derive Floor live profile: {error}"))?;
    let init = InitExpectation {
        chain_id: std::str::from_utf8(options.chain_id.as_bytes())
            .map_err(|_| "Floor live chain is not UTF-8".to_owned())?
            .to_owned(),
        consensus_params: expected_floor_consensus_parameters(),
        validators: validators.validators().to_vec(),
        app_state: profile
            .genesis_app_state_bytes(&genesis)
            .map_err(|error| format!("cannot encode expected Floor app state: {error}"))?,
    };
    prepare_database_parent(database)?;
    let application = FloorApplication::open(database, genesis)
        .map_err(|error| format!("cannot open Floor live-test database: {error}"))?;
    let fatal = ProcessExitFatalHandler::new(ADAPTER_FATAL_EXIT_CODE)
        .map_err(|error| format!("cannot construct Floor adapter fatal handler: {error}"))?;
    let adapter = ThunderboltFloorAbci::new(application, validators, fatal)
        .map_err(|error| format!("cannot construct Floor live-test adapter: {error}"))?;
    let application = CrashBeforeCommit::new(adapter, init, options.crash_height, options.crash_marker);
    let config = ServerConfig::new(ServerEndpoint::Tcp(listen), server_limits()?, server_deadlines()?)
        .map_err(|error| format!("cannot construct Floor live-test server config: {error}"))?;
    let _server = start(config, application, LiveServerFatal)
        .map_err(|error| format!("cannot start bounded Floor live-test server: {error}"))?;
    loop {
        thread::park();
    }
}

fn status(options: Options) -> Result<(), String> {
    let database = options
        .database
        .as_deref()
        .ok_or_else(|| usage("status requires --db"))?;
    let (genesis, _) = floor_genesis(&options.chain_id, &options.comet_genesis)?;
    let application = FloorApplication::open(database, genesis)
        .map_err(|error| format!("cannot open Floor status database: {error}"))?;
    let status = application
        .status()
        .map_err(|error| format!("cannot read Floor status: {error}"))?;
    println!(
        "{}",
        serde_json::to_string(&json!({
            "application_version": 2,
            "last_height": status.last_height,
            "last_block_time_ms": status.last_block_time_ms,
            "last_app_hash": hex_digest(status.last_app_hash.as_bytes()),
            "genesis_digest": hex_digest(status.genesis_digest.as_bytes()),
        }))
        .map_err(|error| format!("cannot encode Floor status: {error}"))?
    );
    Ok(())
}

fn hex_digest(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn profile(options: Options) -> Result<(), String> {
    let (genesis, validators) = floor_genesis(&options.chain_id, &options.comet_genesis)?;
    let profile = FloorConsensusProfileV2::derive(&options.chain_id, &validators)
        .map_err(|error| format!("cannot derive Floor consensus profile: {error}"))?;
    let bytes = profile
        .genesis_app_state_bytes(&genesis)
        .map_err(|error| format!("cannot encode Floor genesis app state: {error}"))?;
    println!(
        "{}",
        String::from_utf8(bytes).map_err(|_| "Floor genesis app state is not UTF-8 JSON".to_owned())?
    );
    Ok(())
}

fn floor_genesis(
    chain_id: &FloorLedgerChainId,
    comet_genesis: &Path,
) -> Result<(FloorGenesis, FloorValidatorGenesisV2), String> {
    let bytes = fs::read(comet_genesis).map_err(|error| format!("cannot read CometBFT genesis: {error}"))?;
    let comet: CometGenesisInput =
        serde_json::from_slice(&bytes).map_err(|error| format!("cannot decode CometBFT genesis: {error}"))?;
    let expected_chain = std::str::from_utf8(chain_id.as_bytes()).map_err(|_| "Floor chain is not UTF-8".to_owned())?;
    if comet.chain_id != expected_chain {
        return Err("CometBFT genesis chain differs from the Floor chain".to_owned());
    }
    let validator_set = tendermint::validator::Set::without_proposer(comet.validators);
    let validators = validator_set
        .validators
        .into_iter()
        .map(|validator| {
            let key = match validator.pub_key {
                CometPublicKey::Ed25519(key) => key.as_bytes().to_vec(),
                _ => return Err("Floor live gate requires Ed25519 validators".to_owned()),
            };
            let power = i64::try_from(validator.power.value())
                .map_err(|_| "CometBFT validator power exceeds i64".to_owned())?;
            Ok(ValidatorUpdate {
                pub_key: Some(PublicKey {
                    sum: Some(public_key::Sum::Ed25519(key)),
                }),
                power,
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    let validators = FloorValidatorGenesisV2::new(validators)
        .map_err(|error| format!("invalid Floor validator genesis: {error}"))?;
    let profile = FloorConsensusProfileV2::derive(chain_id, &validators)
        .map_err(|error| format!("cannot derive Floor profile: {error}"))?;
    let identity = VaultIdentity::new(
        Network::Regtest,
        VaultRole::CommitteeMember,
        NodeId::new([0x41; 32]),
        DeploymentBinding::new(
            DeploymentId::new([0x51; 32]).map_err(|error| format!("invalid deployment ID: {error}"))?,
            7,
            CommitteeDescriptorDigest::new([0x52; 32]).map_err(|error| format!("invalid committee digest: {error}"))?,
        )
        .map_err(|error| format!("invalid deployment binding: {error}"))?,
    );
    let operator = FloorOperatorKey::new(OPERATOR_X_ONLY_KEY)
        .map_err(|error| format!("invalid deterministic Floor operator key: {error}"))?;
    let entry = RegistryEntry::new(identity, operator)
        .map_err(|error| format!("invalid deterministic Floor registry: {error}"))?;
    let genesis = FloorGenesis::new(chain_id.clone(), *profile.as_bytes(), vec![entry])
        .map_err(|error| format!("cannot construct Floor genesis: {error}"))?;
    Ok((genesis, validators))
}

#[derive(Deserialize)]
struct CometGenesisInput {
    chain_id: String,
    validators: Vec<tendermint::validator::Info>,
}

fn prepare_database_parent(database: &Path) -> Result<(), String> {
    let parent = database
        .parent()
        .ok_or_else(|| "Floor database has no parent".to_owned())?;
    fs::create_dir_all(parent).map_err(|error| format!("cannot create Floor database directory: {error}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(parent, fs::Permissions::from_mode(0o700))
            .map_err(|error| format!("cannot harden Floor database directory: {error}"))?;
    }
    Ok(())
}

fn server_limits() -> Result<ServerLimits, String> {
    let response_frame = MAX_ABCI_REQUEST_FRAME_BYTES.max(MAX_QUERY_RESPONSE_BYTES + 64 * 1024);
    let per_handler = ServerLimits::required_per_handler_bytes(
        MAX_ABCI_REQUEST_FRAME_BYTES,
        response_frame,
        MAX_REQUEST_DECODE_ITEMS,
    )
    .ok_or_else(|| "Floor live-test per-handler reservation overflows".to_owned())?;
    let max_inflight = per_handler
        .checked_mul(MAX_CONCURRENT_HANDLERS)
        .filter(|value| *value <= MAX_SERVER_INFLIGHT_BYTES)
        .ok_or_else(|| "Floor live-test aggregate reservation exceeds the hard cap".to_owned())?;
    ServerLimits::new(
        MAX_ABCI_REQUEST_FRAME_BYTES,
        response_frame,
        MAX_ABCI_CONNECTIONS,
        max_inflight,
        MAX_REQUEST_DECODE_ITEMS,
    )
    .map_err(|error| format!("cannot construct Floor live-test limits: {error}"))
}

fn server_deadlines() -> Result<ServerDeadlines, String> {
    ServerDeadlines::new(
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
    .map_err(|error| format!("cannot construct Floor live-test deadlines: {error}"))
}

fn expected_floor_consensus_parameters() -> tendermint_proto::v0_38::types::ConsensusParams {
    use tendermint_proto::google::protobuf::Duration as ProtoDuration;
    use tendermint_proto::v0_38::types::{
        AbciParams, BlockParams, ConsensusParams, EvidenceParams, ValidatorParams, VersionParams,
    };

    ConsensusParams {
        block: Some(BlockParams {
            max_bytes: thunderbolt_floor_abci::COMET_MAX_BLOCK_BYTES,
            max_gas: thunderbolt_floor_abci::COMET_MAX_BLOCK_GAS,
        }),
        evidence: Some(EvidenceParams {
            max_age_num_blocks: thunderbolt_floor_abci::COMET_EVIDENCE_MAX_AGE_BLOCKS,
            max_age_duration: Some(ProtoDuration {
                seconds: thunderbolt_floor_abci::COMET_EVIDENCE_MAX_AGE_SECONDS,
                nanos: 0,
            }),
            max_bytes: thunderbolt_floor_abci::COMET_EVIDENCE_MAX_BYTES,
        }),
        validator: Some(ValidatorParams {
            pub_key_types: vec!["ed25519".to_owned()],
        }),
        version: Some(VersionParams { app: 2 }),
        abci: Some(AbciParams {
            vote_extensions_enable_height: 0,
        }),
    }
}

fn parse_command() -> Result<Command, String> {
    let mut arguments = env::args().skip(1);
    let mode = arguments.next().ok_or_else(|| usage("missing command"))?;
    let mut listen = None;
    let mut database = None;
    let mut chain_id = None;
    let mut comet_genesis = None;
    let mut crash_height = None;
    let mut crash_marker = None;
    while let Some(flag) = arguments.next() {
        let value = arguments.next().ok_or_else(|| usage("command option has no value"))?;
        match flag.as_str() {
            "--listen" => listen = Some(value.parse().map_err(|_| usage("--listen is invalid"))?),
            "--db" => database = Some(PathBuf::from(value)),
            "--chain-id" => {
                chain_id =
                    Some(FloorLedgerChainId::new(value.into_bytes()).map_err(|_| usage("--chain-id is invalid"))?)
            }
            "--comet-genesis" => comet_genesis = Some(PathBuf::from(value)),
            "--crash-before-commit-height" => {
                crash_height = Some(
                    value
                        .parse::<i64>()
                        .ok()
                        .filter(|height| *height > 0)
                        .ok_or_else(|| usage("crash height must be positive"))?,
                )
            }
            "--crash-before-commit-marker" => crash_marker = Some(PathBuf::from(value)),
            _ => return Err(usage("unknown option")),
        }
    }
    let options = Options {
        listen,
        database,
        chain_id: chain_id.ok_or_else(|| usage("--chain-id is required"))?,
        comet_genesis: comet_genesis.ok_or_else(|| usage("--comet-genesis is required"))?,
        crash_height,
        crash_marker,
    };
    match mode.as_str() {
        "serve" => {
            if options.crash_height.is_some() != options.crash_marker.is_some() {
                return Err(usage("crash height and marker must be supplied together"));
            }
            Ok(Command::Serve(options))
        }
        "status" if options.listen.is_none() && options.crash_height.is_none() && options.crash_marker.is_none() => {
            Ok(Command::Status(options))
        }
        "profile"
            if options.listen.is_none()
                && options.database.is_none()
                && options.crash_height.is_none()
                && options.crash_marker.is_none() =>
        {
            Ok(Command::Profile(options))
        }
        "status" | "profile" => Err(usage("command received unsupported options")),
        _ => Err(usage("unknown command")),
    }
}

fn usage(reason: &str) -> String {
    format!(
        "{reason}\nusage: thunderbolt-floor-abci-live-test serve --listen IP:PORT --db PATH --chain-id ID --comet-genesis PATH [--crash-before-commit-height N --crash-before-commit-marker PATH]\n       thunderbolt-floor-abci-live-test status --db PATH --chain-id ID --comet-genesis PATH\n       thunderbolt-floor-abci-live-test profile --chain-id ID --comet-genesis PATH\nWARNING: this deterministic registry process is only for the isolated live test"
    )
}
