use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tendermint::validator::Info as CometValidatorInfo;
use tendermint::vote::Power as CometVotingPower;
use tendermint::PublicKey as CometPublicKey;
use tendermint_proto::v0_38::abci::ValidatorUpdate;
use tendermint_proto::v0_38::crypto::{public_key, PublicKey as ProtoPublicKey};
use thunderbolt_abci_server::{ServerConfig, ServerDeadlines, ServerEndpoint, ServerLimits, MAX_SERVER_CONNECTIONS};
use thunderbolt_floor::FloorLedgerChainId;
use thunderbolt_floor_abci::{
    FloorConsensusProfileV2, FloorValidatorGenesisV2, MAX_ABCI_REQUEST_FRAME_BYTES, MAX_COMMIT_VOTES,
    MAX_MISBEHAVIOR_RECORDS, MAX_PREPARE_SCAN_TRANSACTIONS, MAX_QUERY_RESPONSE_BYTES,
};
use thunderbolt_floor_app::{FloorGenesis, FloorOperatorKey, RegistryEntry};
use thunderbolt_keystore::{
    CommitteeDescriptorDigest, DeploymentBinding, DeploymentId, Network, NodeId, VaultIdentity, VaultRole,
};

use crate::error::{NodeError, Result};
use crate::fs::{DatabaseLease, DatabasePath, SecureFile, UnixSocketPath};

const CONFIG_FORMAT: &str = "bitcoin-thunderbolt-floor-node";
const REGISTRY_FORMAT: &str = "bitcoin-thunderbolt-floor-registry";
const VALIDATOR_FORMAT: &str = "bitcoin-thunderbolt-floor-validators";
const MAX_CONFIG_BYTES: usize = 256 * 1024;
const MAX_REGISTRY_MANIFEST_BYTES: usize = 2 * 1024 * 1024;
const MAX_VALIDATOR_MANIFEST_BYTES: usize = 512 * 1024;
const MAX_CONCURRENT_HANDLERS: usize = 32;
const RESPONSE_METADATA_RESERVE: usize = 64 * 1024;
const MAX_REQUEST_DECODE_ITEMS: usize = MAX_PREPARE_SCAN_TRANSACTIONS + MAX_MISBEHAVIOR_RECORDS + MAX_COMMIT_VOTES;

pub(crate) struct ValidatedConfig {
    config_file: SecureFile,
    registry_file: SecureFile,
    validator_file: SecureFile,
    comet_chain_id: String,
    genesis_time: tendermint::Time,
    network: Network,
    database: DatabasePath,
    endpoint: EndpointGuard,
    limits: ServerLimits,
    deadlines: ServerDeadlines,
    genesis: FloorGenesis,
    validators: FloorValidatorGenesisV2,
    comet_validators: Vec<CometValidatorInfo>,
    profile: FloorConsensusProfileV2,
}

impl ValidatedConfig {
    pub(crate) fn load(path: &Path) -> Result<Self> {
        let config_file = SecureFile::open(path, MAX_CONFIG_BYTES, "configuration file")?;
        let text = std::str::from_utf8(config_file.bytes()).map_err(|_| NodeError::ConfigEncoding)?;
        let raw: RawConfig = toml::from_str(text).map_err(|_| NodeError::ConfigDecode)?;
        if raw.format != CONFIG_FORMAT {
            return Err(NodeError::InvalidConfig("configuration format"));
        }
        let comet_chain =
            tendermint::chain::Id::try_from(raw.chain_id.as_str()).map_err(|_| NodeError::InvalidConfig("chain ID"))?;
        if comet_chain.to_string() != raw.chain_id {
            return Err(NodeError::InvalidConfig("chain ID is not canonical"));
        }
        let chain_id = FloorLedgerChainId::new(raw.chain_id.as_bytes().to_vec())
            .map_err(|_| NodeError::InvalidConfig("chain ID"))?;
        let genesis_time = tendermint::Time::parse_from_rfc3339(&raw.genesis_time)
            .map_err(|_| NodeError::InvalidConfig("genesis time"))?;
        if genesis_time.to_rfc3339() != raw.genesis_time {
            return Err(NodeError::InvalidConfig("genesis time is not canonical"));
        }
        let network = raw.network.to_network()?;
        if network == Network::Mainnet {
            return Err(NodeError::InvalidConfig("Mainnet is disabled"));
        }

        let registry_digest = decode_hex32(&raw.registry_manifest.sha256, "registry manifest digest")?;
        let validator_digest = decode_hex32(&raw.validator_manifest.sha256, "validator manifest digest")?;
        let registry_file = SecureFile::open(
            &raw.registry_manifest.path,
            MAX_REGISTRY_MANIFEST_BYTES,
            "registry manifest",
        )?;
        if registry_file.digest() != &registry_digest {
            return Err(NodeError::InvalidConfig("registry manifest digest"));
        }
        let validator_file = SecureFile::open(
            &raw.validator_manifest.path,
            MAX_VALIDATOR_MANIFEST_BYTES,
            "validator manifest",
        )?;
        if validator_file.digest() != &validator_digest {
            return Err(NodeError::InvalidConfig("validator manifest digest"));
        }

        let raw_validators: ValidatorManifest = parse_canonical_manifest(validator_file.bytes(), "validator manifest")?;
        if raw_validators.format != VALIDATOR_FORMAT {
            return Err(NodeError::InvalidConfig("validator manifest format"));
        }
        let (validators, comet_validators) = build_validators(raw_validators.validators)?;
        let profile = FloorConsensusProfileV2::derive(&chain_id, &validators)
            .map_err(|_| NodeError::InvalidConfig("consensus profile"))?;

        let raw_registry: RegistryManifest = parse_canonical_manifest(registry_file.bytes(), "registry manifest")?;
        if raw_registry.format != REGISTRY_FORMAT {
            return Err(NodeError::InvalidConfig("registry manifest format"));
        }
        let entries = build_registry(raw_registry.entries, network)?;
        let genesis = FloorGenesis::new(chain_id.clone(), *profile.as_bytes(), entries)
            .map_err(|_| NodeError::InvalidConfig("Floor genesis"))?;

        let database = DatabasePath::validate(&raw.database_path)?;
        let (endpoint, limits, deadlines) = build_server(raw.server)?;
        let mut paths = vec![
            config_file.path(),
            registry_file.path(),
            validator_file.path(),
            database.path(),
        ];
        let database_lock = database.lock_path()?;
        paths.push(&database_lock);
        if let Some(socket_path) = endpoint.path() {
            paths.push(socket_path);
        }
        for (index, path) in paths.iter().enumerate() {
            if paths[..index].contains(path) {
                return Err(NodeError::InvalidConfig("configured paths must be distinct"));
            }
        }
        let value = Self {
            config_file,
            registry_file,
            validator_file,
            comet_chain_id: comet_chain.to_string(),
            genesis_time,
            network,
            database,
            endpoint,
            limits,
            deadlines,
            genesis,
            validators,
            comet_validators,
            profile,
        };
        value.revalidate()?;
        Ok(value)
    }

    pub(crate) fn revalidate(&self) -> Result<()> {
        self.config_file.revalidate()?;
        self.registry_file.revalidate()?;
        self.validator_file.revalidate()?;
        self.database.revalidate_before_open()?;
        self.endpoint.revalidate()
    }

    pub(crate) fn revalidate_after_database_open(&self) -> Result<()> {
        self.config_file.revalidate()?;
        self.registry_file.revalidate()?;
        self.validator_file.revalidate()?;
        self.database.revalidate_after_open()?;
        self.endpoint.revalidate()
    }

    pub(crate) fn check_json(&self) -> Result<String> {
        serde_json::to_string(&CheckOutput {
            chain_id: &self.comet_chain_id,
            consensus_profile_digest: encode_hex(self.profile.as_bytes()),
            endpoint: self.endpoint.kind(),
            floor_genesis_digest: encode_hex(self.genesis.genesis_digest().as_bytes()),
            network: network_name(self.network),
            registry_digest: encode_hex(self.genesis.registry_digest().as_bytes()),
            registry_entries: self.genesis.entries().len(),
            status: "ok",
            validator_digest: encode_hex(self.validators.digest()),
            validators: self.validators.validators().len(),
        })
        .map_err(|_| NodeError::GenesisEncoding)
    }

    pub(crate) fn comet_chain_id(&self) -> &str {
        &self.comet_chain_id
    }

    pub(crate) const fn genesis_time(&self) -> tendermint::Time {
        self.genesis_time
    }

    pub(crate) const fn genesis(&self) -> &FloorGenesis {
        &self.genesis
    }

    pub(crate) const fn validators(&self) -> &FloorValidatorGenesisV2 {
        &self.validators
    }

    pub(crate) fn comet_validators(&self) -> &[CometValidatorInfo] {
        &self.comet_validators
    }

    pub(crate) const fn profile(&self) -> &FloorConsensusProfileV2 {
        &self.profile
    }

    pub(crate) fn database_path(&self) -> &Path {
        self.database.path()
    }

    pub(crate) fn acquire_database_lease(&self) -> Result<DatabaseLease> {
        DatabaseLease::acquire(&self.database)
    }

    pub(crate) fn server_config(&self) -> Result<ServerConfig> {
        ServerConfig::new(self.endpoint.endpoint(), self.limits, self.deadlines).map_err(|_| NodeError::Server)
    }
}

enum EndpointGuard {
    Tcp(SocketAddr),
    #[cfg(unix)]
    Unix(UnixSocketPath),
}

impl EndpointGuard {
    fn endpoint(&self) -> ServerEndpoint {
        match self {
            Self::Tcp(address) => ServerEndpoint::Tcp(*address),
            #[cfg(unix)]
            Self::Unix(path) => ServerEndpoint::Unix(path.path().to_path_buf()),
        }
    }

    fn revalidate(&self) -> Result<()> {
        match self {
            Self::Tcp(_) => Ok(()),
            #[cfg(unix)]
            Self::Unix(path) => path.revalidate(),
        }
    }

    const fn kind(&self) -> &'static str {
        match self {
            Self::Tcp(_) => "tcp_loopback",
            #[cfg(unix)]
            Self::Unix(_) => "unix",
        }
    }

    fn path(&self) -> Option<&Path> {
        match self {
            Self::Tcp(_) => None,
            #[cfg(unix)]
            Self::Unix(path) => Some(path.path()),
        }
    }
}

fn build_server(raw: RawServer) -> Result<(EndpointGuard, ServerLimits, ServerDeadlines)> {
    let endpoint = match raw.endpoint {
        RawEndpoint::Tcp { address } => {
            let parsed: SocketAddr = address.parse().map_err(|_| NodeError::InvalidConfig("TCP endpoint"))?;
            if parsed.to_string() != address || !parsed.ip().is_loopback() || parsed.port() == 0 {
                return Err(NodeError::InvalidConfig("TCP endpoint"));
            }
            EndpointGuard::Tcp(parsed)
        }
        RawEndpoint::Unix { path } => {
            #[cfg(not(unix))]
            {
                let _ = path;
                return Err(NodeError::UnsupportedPlatform);
            }
            #[cfg(unix)]
            {
                EndpointGuard::Unix(UnixSocketPath::validate(&path)?)
            }
        }
    };
    if raw.limits.max_connections == 0
        || raw.limits.max_connections > MAX_SERVER_CONNECTIONS
        || raw.limits.max_concurrent_handlers == 0
        || raw.limits.max_concurrent_handlers > MAX_CONCURRENT_HANDLERS
        || raw.limits.max_concurrent_handlers > raw.limits.max_connections
    {
        return Err(NodeError::InvalidConfig("server limits"));
    }
    let response_frame_bytes = MAX_QUERY_RESPONSE_BYTES
        .checked_add(RESPONSE_METADATA_RESERVE)
        .map(|value| value.max(MAX_ABCI_REQUEST_FRAME_BYTES))
        .ok_or(NodeError::InvalidConfig("response frame limit"))?;
    let per_handler = ServerLimits::required_per_handler_bytes(
        MAX_ABCI_REQUEST_FRAME_BYTES,
        response_frame_bytes,
        MAX_REQUEST_DECODE_ITEMS,
    )
    .ok_or(NodeError::InvalidConfig("server reservation"))?;
    let inflight = per_handler
        .checked_mul(raw.limits.max_concurrent_handlers)
        .ok_or(NodeError::InvalidConfig("server reservation"))?;
    let limits = ServerLimits::new(
        MAX_ABCI_REQUEST_FRAME_BYTES,
        response_frame_bytes,
        raw.limits.max_connections,
        inflight,
        MAX_REQUEST_DECODE_ITEMS,
    )
    .map_err(|_| NodeError::InvalidConfig("server limits"))?;
    let deadlines = ServerDeadlines::new(
        millis(raw.deadlines_ms.accept_poll)?,
        millis(raw.deadlines_ms.idle)?,
        millis(raw.deadlines_ms.header)?,
        millis(raw.deadlines_ms.read)?,
        millis(raw.deadlines_ms.frame)?,
        millis(raw.deadlines_ms.decode)?,
        millis(raw.deadlines_ms.write)?,
        millis(raw.deadlines_ms.handler)?,
        millis(raw.deadlines_ms.shutdown_grace)?,
    )
    .map_err(|_| NodeError::InvalidConfig("server deadlines"))?;
    Ok((endpoint, limits, deadlines))
}

fn millis(value: u64) -> Result<Duration> {
    if value == 0 {
        return Err(NodeError::InvalidConfig("server deadline"));
    }
    Ok(Duration::from_millis(value))
}

fn build_validators(raw: Vec<RawValidator>) -> Result<(FloorValidatorGenesisV2, Vec<CometValidatorInfo>)> {
    if raw.is_empty() || raw.len() > MAX_COMMIT_VOTES {
        return Err(NodeError::InvalidConfig("validator count"));
    }
    let mut updates = Vec::new();
    let mut infos = Vec::new();
    updates
        .try_reserve_exact(raw.len())
        .map_err(|_| NodeError::InvalidConfig("validator allocation"))?;
    infos
        .try_reserve_exact(raw.len())
        .map_err(|_| NodeError::InvalidConfig("validator allocation"))?;
    let mut total = 0_u64;
    for value in raw {
        let key = decode_hex32(&value.public_key, "validator public key")?;
        let public_key =
            CometPublicKey::from_raw_ed25519(&key).ok_or(NodeError::InvalidConfig("validator public key"))?;
        if value.power == 0 {
            return Err(NodeError::InvalidConfig("validator voting power"));
        }
        total = total
            .checked_add(value.power)
            .filter(|sum| *sum <= tendermint::validator::Set::MAX_TOTAL_VOTING_POWER)
            .ok_or(NodeError::InvalidConfig("validator voting power"))?;
        let power =
            CometVotingPower::try_from(value.power).map_err(|_| NodeError::InvalidConfig("validator voting power"))?;
        let proto_power = i64::try_from(value.power).map_err(|_| NodeError::InvalidConfig("validator voting power"))?;
        updates.push(ValidatorUpdate {
            pub_key: Some(ProtoPublicKey {
                sum: Some(public_key::Sum::Ed25519(key.to_vec())),
            }),
            power: proto_power,
        });
        infos.push(CometValidatorInfo::new(public_key, power));
    }
    let canonical = tendermint::validator::Set::without_proposer(infos.clone());
    if canonical.validators != infos {
        return Err(NodeError::InvalidConfig("validator manifest order"));
    }
    let validators =
        FloorValidatorGenesisV2::new(updates).map_err(|_| NodeError::InvalidConfig("validator manifest"))?;
    Ok((validators, infos))
}

fn build_registry(raw: Vec<RawRegistryEntry>, network: Network) -> Result<Vec<RegistryEntry>> {
    if raw.is_empty() || raw.len() > thunderbolt_floor_app::MAX_REGISTRY_ENTRIES {
        return Err(NodeError::InvalidConfig("registry count"));
    }
    let mut entries = Vec::new();
    entries
        .try_reserve_exact(raw.len())
        .map_err(|_| NodeError::InvalidConfig("registry allocation"))?;
    for value in raw {
        if value.network.to_network()? != network || network == Network::Mainnet {
            return Err(NodeError::InvalidConfig("registry network"));
        }
        let role = value.role.to_role();
        let node_bytes = decode_hex32(&value.node_id, "registry node ID")?;
        if node_bytes == [0; 32] {
            return Err(NodeError::InvalidConfig("registry node ID"));
        }
        let deployment = DeploymentBinding::new(
            DeploymentId::new(decode_hex32(&value.deployment_id, "registry deployment ID")?)
                .map_err(|_| NodeError::InvalidConfig("registry deployment ID"))?,
            value.committee_epoch,
            CommitteeDescriptorDigest::new(decode_hex32(
                &value.committee_descriptor,
                "registry committee descriptor",
            )?)
            .map_err(|_| NodeError::InvalidConfig("registry committee descriptor"))?,
        )
        .map_err(|_| NodeError::InvalidConfig("registry deployment binding"))?;
        let identity = VaultIdentity::new(network, role, NodeId::new(node_bytes), deployment);
        let operator = FloorOperatorKey::new(decode_hex32(&value.operator_key, "registry operator key")?)
            .map_err(|_| NodeError::InvalidConfig("registry operator key"))?;
        entries.push(RegistryEntry::new(identity, operator).map_err(|_| NodeError::InvalidConfig("registry entry"))?);
    }
    if entries
        .windows(2)
        .any(|window| window[0].identity_digest() >= window[1].identity_digest())
    {
        return Err(NodeError::InvalidConfig("registry manifest order"));
    }
    Ok(entries)
}

fn parse_canonical_manifest<T>(bytes: &[u8], label: &'static str) -> Result<T>
where
    T: for<'de> Deserialize<'de> + Serialize,
{
    let value: T = serde_json::from_slice(bytes).map_err(|_| NodeError::ManifestDecode(label))?;
    let mut canonical = serde_json::to_vec(&value).map_err(|_| NodeError::ManifestDecode(label))?;
    canonical.push(b'\n');
    if canonical != bytes {
        return Err(NodeError::ManifestCanonical(label));
    }
    Ok(value)
}

pub(crate) fn decode_hex32(value: &str, label: &'static str) -> Result<[u8; 32]> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(NodeError::InvalidConfig(label));
    }
    let mut bytes = [0_u8; 32];
    hex::decode_to_slice(value, &mut bytes).map_err(|_| NodeError::InvalidConfig(label))?;
    if bytes == [0; 32] {
        return Err(NodeError::InvalidConfig(label));
    }
    Ok(bytes)
}

pub(crate) fn encode_hex(value: &[u8; 32]) -> String {
    hex::encode(value)
}

const fn network_name(network: Network) -> &'static str {
    match network {
        Network::Regtest => "regtest",
        Network::Signet => "signet",
        Network::Testnet => "testnet",
        Network::Mainnet => "mainnet",
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawConfig {
    format: String,
    chain_id: String,
    genesis_time: String,
    network: RawNetwork,
    database_path: PathBuf,
    registry_manifest: RawManifestReference,
    validator_manifest: RawManifestReference,
    server: RawServer,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawManifestReference {
    path: PathBuf,
    sha256: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawServer {
    endpoint: RawEndpoint,
    limits: RawLimits,
    deadlines_ms: RawDeadlines,
}

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum RawEndpoint {
    Unix { path: PathBuf },
    Tcp { address: String },
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawLimits {
    max_connections: usize,
    max_concurrent_handlers: usize,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawDeadlines {
    accept_poll: u64,
    idle: u64,
    header: u64,
    read: u64,
    frame: u64,
    decode: u64,
    write: u64,
    handler: u64,
    shutdown_grace: u64,
}

#[derive(Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum RawNetwork {
    Regtest,
    Signet,
    Testnet,
    Mainnet,
}

impl RawNetwork {
    const fn to_network(self) -> Result<Network> {
        Ok(match self {
            Self::Regtest => Network::Regtest,
            Self::Signet => Network::Signet,
            Self::Testnet => Network::Testnet,
            Self::Mainnet => Network::Mainnet,
        })
    }
}

#[derive(Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum RawRole {
    Holder,
    CommitteeMember,
}

impl RawRole {
    const fn to_role(self) -> VaultRole {
        match self {
            Self::Holder => VaultRole::Holder,
            Self::CommitteeMember => VaultRole::CommitteeMember,
        }
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RegistryManifest {
    format: String,
    entries: Vec<RawRegistryEntry>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RawRegistryEntry {
    network: RawNetwork,
    role: RawRole,
    node_id: String,
    deployment_id: String,
    committee_epoch: u64,
    committee_descriptor: String,
    operator_key: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ValidatorManifest {
    format: String,
    validators: Vec<RawValidator>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RawValidator {
    public_key: String,
    power: u64,
}

#[derive(Serialize)]
struct CheckOutput<'a> {
    chain_id: &'a str,
    consensus_profile_digest: String,
    endpoint: &'static str,
    floor_genesis_digest: String,
    network: &'static str,
    registry_digest: String,
    registry_entries: usize,
    status: &'static str,
    validator_digest: String,
    validators: usize,
}
