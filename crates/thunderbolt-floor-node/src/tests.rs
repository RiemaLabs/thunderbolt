#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::collections::BTreeSet;
use std::error::Error;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{FileExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use clap::CommandFactory as _;
use proptest::prelude::*;
use serde::Serialize;
use sha2::{Digest, Sha256};
use tendermint_proto::google::protobuf::{Duration as ProtoDuration, Timestamp};
use tendermint_proto::v0_38::abci::{RequestInitChain, ValidatorUpdate};
use tendermint_proto::v0_38::crypto::{public_key, PublicKey as ProtoPublicKey};
use tendermint_proto::v0_38::types::{
    AbciParams, BlockParams, ConsensusParams, EvidenceParams, ValidatorParams, VersionParams,
};
use thunderbolt_abci_server::{FatalServerEvent, FatalServerHandler};
use thunderbolt_floor_abci::{FatalAbciFailure, FatalAbciHandler, ThunderboltFloorAbci};
use thunderbolt_floor_app::FloorApplication;

use super::*;

type TestResult<T = ()> = std::result::Result<T, Box<dyn Error>>;

const OPERATOR_KEY: &str = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
const VALIDATOR_KEY: &str = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";

#[derive(Serialize)]
struct TestRegistryManifest<'a> {
    format: &'a str,
    entries: Vec<TestRegistryEntry<'a>>,
}

#[derive(Serialize)]
struct TestRegistryEntry<'a> {
    network: &'a str,
    role: &'a str,
    node_id: &'a str,
    deployment_id: &'a str,
    committee_epoch: u64,
    committee_descriptor: &'a str,
    operator_key: &'a str,
}

#[derive(Serialize)]
struct TestValidatorManifest<'a> {
    format: &'a str,
    validators: Vec<TestValidator<'a>>,
}

#[derive(Serialize)]
struct TestValidator<'a> {
    public_key: &'a str,
    power: u64,
}

struct Fixture {
    _directory: tempfile::TempDir,
    root: PathBuf,
    config_dir: PathBuf,
    config: PathBuf,
    registry: PathBuf,
    validators: PathBuf,
    database: PathBuf,
    socket: PathBuf,
}

impl Fixture {
    fn new() -> TestResult<Self> {
        let directory = tempfile::tempdir()?;
        let root = fs::canonicalize(directory.path())?;
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700))?;
        let config_dir = root.join("config");
        fs::create_dir(&config_dir)?;
        fs::set_permissions(&config_dir, fs::Permissions::from_mode(0o700))?;
        let config = config_dir.join("floor-node.toml");
        let registry = config_dir.join("registry.json");
        let validators = config_dir.join("validators.json");
        let database = root.join("floor.sqlite3");
        let socket = root.join("floor.sock");
        let value = Self {
            _directory: directory,
            root,
            config_dir,
            config,
            registry,
            validators,
            database,
            socket,
        };
        value.write_public_manifests("regtest", &[(VALIDATOR_KEY, 10)])?;
        value.write_config("regtest", "thunderbolt-floor-regtest-1", Endpoint::Unix)?;
        Ok(value)
    }

    fn write_public_manifests(&self, network: &str, validators: &[(&str, u64)]) -> TestResult {
        let registry = canonical_json(&TestRegistryManifest {
            format: "bitcoin-thunderbolt-floor-registry",
            entries: vec![TestRegistryEntry {
                network,
                role: "committee_member",
                node_id: &"41".repeat(32),
                deployment_id: &"51".repeat(32),
                committee_epoch: 7,
                committee_descriptor: &"52".repeat(32),
                operator_key: OPERATOR_KEY,
            }],
        })?;
        let validators = canonical_json(&TestValidatorManifest {
            format: "bitcoin-thunderbolt-floor-validators",
            validators: validators
                .iter()
                .map(|(public_key, power)| TestValidator {
                    public_key,
                    power: *power,
                })
                .collect(),
        })?;
        owner_file(&self.registry, &registry)?;
        owner_file(&self.validators, &validators)?;
        Ok(())
    }

    fn write_config(&self, network: &str, chain_id: &str, endpoint: Endpoint) -> TestResult {
        let endpoint = match endpoint {
            Endpoint::Unix => format!("kind = \"unix\"\npath = \"{}\"", toml_path(&self.socket)),
            Endpoint::Tcp(address) => format!("kind = \"tcp\"\naddress = \"{address}\""),
        };
        let bytes = format!(
            "format = \"bitcoin-thunderbolt-floor-node\"\n\
             chain_id = \"{chain_id}\"\n\
             genesis_time = \"2026-01-01T00:00:00Z\"\n\
             network = \"{network}\"\n\
             database_path = \"{}\"\n\
             \n\
             [registry_manifest]\n\
             path = \"{}\"\n\
             sha256 = \"{}\"\n\
             \n\
             [validator_manifest]\n\
             path = \"{}\"\n\
             sha256 = \"{}\"\n\
             \n\
             [server.endpoint]\n\
             {endpoint}\n\
             \n\
             [server.limits]\n\
             max_connections = 16\n\
             max_concurrent_handlers = 8\n\
             \n\
             [server.deadlines_ms]\n\
             accept_poll = 5\n\
             idle = 30000\n\
             header = 2000\n\
             read = 2000\n\
             frame = 15000\n\
             decode = 5000\n\
             write = 15000\n\
             handler = 60000\n\
             shutdown_grace = 75000\n",
            toml_path(&self.database),
            toml_path(&self.registry),
            file_digest(&self.registry)?,
            toml_path(&self.validators),
            file_digest(&self.validators)?,
        );
        owner_file(&self.config, bytes.as_bytes())
    }

    fn replace_config(&self, before: &str, after: &str) -> TestResult {
        let text = fs::read_to_string(&self.config)?;
        if !text.contains(before) {
            return Err(format!("fixture config omitted {before:?}").into());
        }
        owner_file(&self.config, text.replace(before, after).as_bytes())
    }

    fn refresh_manifest_digest(&self, manifest: &Path, key: &str) -> TestResult {
        let text = fs::read_to_string(&self.config)?;
        let line = text
            .lines()
            .find(|line| line.starts_with(key))
            .ok_or("manifest digest line")?;
        let replacement = format!("{key} = \"{}\"", file_digest(manifest)?);
        owner_file(&self.config, text.replace(line, &replacement).as_bytes())
    }
}

#[derive(Clone, Copy)]
enum Endpoint<'a> {
    Unix,
    Tcp(&'a str),
}

#[derive(Clone, Copy)]
struct TestAbciFatal;

impl FatalAbciHandler for TestAbciFatal {
    fn terminate(&self, failure: FatalAbciFailure) -> ! {
        panic!(
            "unexpected fatal ABCI failure: {:?} {}",
            failure.stage(),
            failure.code()
        )
    }
}

#[derive(Clone, Copy)]
struct TestServerFatal;

impl FatalServerHandler for TestServerFatal {
    fn terminate(&self, event: FatalServerEvent) -> ! {
        panic!("unexpected fatal server failure: {:?}", event.kind())
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(128))]

    #[test]
    fn lowercase_hex32_round_trips_and_noncanonical_forms_fail(
        first in 0xa0_u8..=0xaf,
        tail in any::<[u8; 31]>(),
    ) {
        let mut bytes = [0_u8; 32];
        bytes[0] = first;
        bytes[1..].copy_from_slice(&tail);
        let encoded = hex::encode(bytes);
        prop_assert_eq!(config::decode_hex32(&encoded, "property hex").ok(), Some(bytes));
        prop_assert!(config::decode_hex32(&encoded.to_uppercase(), "property hex").is_err());
        let overlong = format!("0{}", encoded);
        prop_assert!(config::decode_hex32(&overlong, "property hex").is_err());
    }
}

#[test]
fn default_operator_schema_is_exact_and_visible() {
    let mut root = Cli::command();
    root.build();
    let commands = root
        .get_subcommands()
        .map(|command| command.get_name().to_owned())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        commands,
        ["check", "genesis", "help", "start"]
            .into_iter()
            .map(str::to_owned)
            .collect()
    );
    let options = root
        .get_arguments()
        .filter_map(|argument| argument.get_long())
        .collect::<BTreeSet<_>>();
    assert_eq!(options, ["config", "help", "version"].into_iter().collect());
    let short_options = root
        .get_arguments()
        .filter_map(|argument| argument.get_short())
        .collect::<BTreeSet<_>>();
    assert_eq!(short_options, ['V', 'h'].into_iter().collect());
    assert_command_tree_visible(&root);
    for name in ["check", "genesis", "start"] {
        let command = root.find_subcommand(name).expect("subcommand");
        let options = command
            .get_arguments()
            .filter_map(|argument| argument.get_long())
            .collect::<BTreeSet<_>>();
        assert_eq!(options, ["help"].into_iter().collect());
        let short_options = command
            .get_arguments()
            .filter_map(|argument| argument.get_short())
            .collect::<BTreeSet<_>>();
        assert_eq!(short_options, ['h'].into_iter().collect());
        assert!(command.get_subcommands().next().is_none());
    }
}

#[test]
fn check_and_genesis_are_strictly_non_mutating() -> TestResult {
    let fixture = Fixture::new()?;
    let before = directory_names(&fixture.root)?;
    let config = ValidatedConfig::load(&fixture.config)?;
    config.revalidate()?;
    let check = config.check_json()?;
    let genesis = genesis::canonical_genesis_json(&config)?;
    assert!(check.contains("\"status\":\"ok\""));
    assert!(genesis.contains("\"app_state\""));
    let private_root = fixture.root.to_string_lossy();
    assert!(!check.contains(private_root.as_ref()));
    assert!(!genesis.contains(private_root.as_ref()));
    assert!(!fixture.database.exists());
    assert!(!fixture.socket.exists());
    assert_eq!(directory_names(&fixture.root)?, before);
    Ok(())
}

#[test]
fn emitted_genesis_round_trips_through_exact_init_chain() -> TestResult {
    let fixture = Fixture::new()?;
    let config = ValidatedConfig::load(&fixture.config)?;
    let encoded = genesis::canonical_genesis_json(&config)?;
    assert_eq!(
        serde_json::to_string(&serde_json::from_str::<serde_json::Value>(&encoded)?)?,
        encoded
    );
    let document: serde_json::Value = serde_json::from_str(&encoded)?;
    let app_state = serde_json::to_vec(&document["app_state"])?;
    assert_eq!(app_state, config.profile().genesis_app_state_bytes(config.genesis())?);
    let validators: Vec<tendermint::validator::Info> = serde_json::from_value(document["validators"].clone())?;
    let updates = validator_updates(&validators)?;
    assert_eq!(updates, config.validators().validators());
    let consensus = consensus_from_json(&document["consensus_params"])?;
    assert_eq!(consensus, genesis::consensus_parameters());

    let application = FloorApplication::open(config.database_path(), config.genesis().clone())?;
    config.revalidate_after_database_open()?;
    let adapter = ThunderboltFloorAbci::new(application, config.validators().clone(), TestAbciFatal)?;
    let time = tendermint::Time::parse_from_rfc3339(document["genesis_time"].as_str().ok_or("genesis time")?)?;
    let response = adapter.try_init_chain(RequestInitChain {
        time: Some(Timestamp::from(time)),
        chain_id: document["chain_id"].as_str().ok_or("chain")?.to_owned(),
        consensus_params: Some(consensus),
        validators: updates,
        app_state_bytes: app_state.into(),
        initial_height: document["initial_height"].as_str().ok_or("initial height")?.parse()?,
    })?;
    assert!(response.validators.is_empty());
    assert_eq!(response.consensus_params, Some(genesis::consensus_parameters()));
    Ok(())
}

#[test]
fn configuration_rejects_unknown_fields_relative_paths_and_loose_modes() -> TestResult {
    let fixture = Fixture::new()?;
    fixture.replace_config(
        "format = \"bitcoin-thunderbolt-floor-node\"",
        "format = \"bitcoin-thunderbolt-floor-node\"\npassword = \"forbidden\"",
    )?;
    assert!(ValidatedConfig::load(&fixture.config).is_err());

    fixture.write_config("regtest", "thunderbolt-floor-regtest-1", Endpoint::Unix)?;
    assert!(ValidatedConfig::load(Path::new("floor-node.toml")).is_err());
    fs::set_permissions(&fixture.config, fs::Permissions::from_mode(0o644))?;
    assert!(ValidatedConfig::load(&fixture.config).is_err());

    fs::set_permissions(&fixture.config, fs::Permissions::from_mode(0o600))?;
    fs::set_permissions(&fixture.config_dir, fs::Permissions::from_mode(0o755))?;
    assert!(ValidatedConfig::load(&fixture.config).is_err());
    fs::set_permissions(&fixture.config_dir, fs::Permissions::from_mode(0o700))?;
    fixture.write_config("regtest", "thunderbolt-floor-regtest-1", Endpoint::Unix)?;
    fixture.replace_config(
        &format!("database_path = \"{}\"", toml_path(&fixture.database)),
        &format!("database_path = \"{}\"", toml_path(&fixture.registry)),
    )?;
    assert!(ValidatedConfig::load(&fixture.config).is_err());
    Ok(())
}

#[test]
fn manifests_reject_digest_drift_noncanonical_json_symlinks_and_hardlinks() -> TestResult {
    let fixture = Fixture::new()?;
    fs::OpenOptions::new()
        .append(true)
        .open(&fixture.registry)?
        .write_all(b" ")?;
    assert!(ValidatedConfig::load(&fixture.config).is_err());

    fixture.write_public_manifests("regtest", &[(VALIDATOR_KEY, 10)])?;
    fixture.write_config("regtest", "thunderbolt-floor-regtest-1", Endpoint::Unix)?;
    let mut bytes = fs::read(&fixture.registry)?;
    bytes.insert(0, b' ');
    owner_file(&fixture.registry, &bytes)?;
    fixture.refresh_manifest_digest(&fixture.registry, "sha256")?;
    assert!(ValidatedConfig::load(&fixture.config).is_err());

    fixture.write_public_manifests("regtest", &[(VALIDATOR_KEY, 10)])?;
    fixture.write_config("regtest", "thunderbolt-floor-regtest-1", Endpoint::Unix)?;
    let source = fixture.root.join("registry-source.json");
    fs::rename(&fixture.registry, &source)?;
    std::os::unix::fs::symlink(&source, &fixture.registry)?;
    assert!(ValidatedConfig::load(&fixture.config).is_err());
    fs::remove_file(&fixture.registry)?;
    fs::hard_link(&source, &fixture.registry)?;
    assert!(ValidatedConfig::load(&fixture.config).is_err());
    Ok(())
}

#[test]
fn retained_file_descriptors_detect_in_place_and_inode_tampering() -> TestResult {
    let fixture = Fixture::new()?;
    let config = ValidatedConfig::load(&fixture.config)?;
    let bytes = fs::read(&fixture.registry)?;
    let file = OpenOptions::new().write(true).open(&fixture.registry)?;
    file.write_at(b"X", 0)?;
    file.sync_all()?;
    assert!(config.revalidate().is_err());
    file.write_at(&bytes[..1], 0)?;
    file.sync_all()?;
    config.revalidate()?;
    let backup = fixture.root.join("registry-old.json");
    fs::rename(&fixture.registry, &backup)?;
    owner_file(&fixture.registry, &bytes)?;
    assert!(config.revalidate().is_err());
    Ok(())
}

#[test]
fn retained_parent_identity_detects_directory_replacement() -> TestResult {
    let fixture = Fixture::new()?;
    let config = ValidatedConfig::load(&fixture.config)?;
    let moved = fixture.root.join("config-old");
    fs::rename(&fixture.config_dir, &moved)?;
    fs::create_dir(&fixture.config_dir)?;
    fs::set_permissions(&fixture.config_dir, fs::Permissions::from_mode(0o700))?;
    for name in ["floor-node.toml", "registry.json", "validators.json"] {
        let bytes = fs::read(moved.join(name))?;
        owner_file(&fixture.config_dir.join(name), &bytes)?;
    }
    assert!(config.revalidate().is_err());
    Ok(())
}

#[test]
fn mainnet_remote_zero_and_unbounded_settings_are_rejected() -> TestResult {
    let fixture = Fixture::new()?;
    fixture.replace_config("network = \"regtest\"", "network = \"mainnet\"")?;
    assert!(ValidatedConfig::load(&fixture.config).is_err());

    fixture.write_config("regtest", "thunderbolt-floor-regtest-1", Endpoint::Tcp("0.0.0.0:26658"))?;
    assert!(ValidatedConfig::load(&fixture.config).is_err());
    fixture.write_config("regtest", "thunderbolt-floor-regtest-1", Endpoint::Tcp("127.0.0.1:0"))?;
    assert!(ValidatedConfig::load(&fixture.config).is_err());

    fixture.write_config("regtest", "thunderbolt-floor-regtest-1", Endpoint::Unix)?;
    fixture.replace_config("max_connections = 16", "max_connections = 0")?;
    assert!(ValidatedConfig::load(&fixture.config).is_err());
    fixture.write_config("regtest", "thunderbolt-floor-regtest-1", Endpoint::Unix)?;
    fixture.replace_config("max_concurrent_handlers = 8", "max_concurrent_handlers = 999999")?;
    assert!(ValidatedConfig::load(&fixture.config).is_err());
    fixture.write_config("regtest", "thunderbolt-floor-regtest-1", Endpoint::Unix)?;
    fixture.replace_config("handler = 60000", "handler = 0")?;
    assert!(ValidatedConfig::load(&fixture.config).is_err());
    fixture.write_config("regtest", "thunderbolt-floor-regtest-1", Endpoint::Unix)?;
    fixture.replace_config("handler = 60000", "handler = 999999999")?;
    assert!(ValidatedConfig::load(&fixture.config).is_err());
    Ok(())
}

#[test]
fn numeric_loopback_endpoint_is_the_only_tcp_mode() -> TestResult {
    let fixture = Fixture::new()?;
    fixture.write_config(
        "regtest",
        "thunderbolt-floor-regtest-1",
        Endpoint::Tcp("127.0.0.1:26658"),
    )?;
    let config = ValidatedConfig::load(&fixture.config)?;
    assert!(config.check_json()?.contains("\"endpoint\":\"tcp_loopback\""));
    Ok(())
}

#[test]
fn empty_noncanonical_and_magic_identity_values_are_rejected() -> TestResult {
    let fixture = Fixture::new()?;
    fixture.replace_config("chain_id = \"thunderbolt-floor-regtest-1\"", "chain_id = \"\"")?;
    assert!(ValidatedConfig::load(&fixture.config).is_err());

    fixture.write_config("regtest", "thunderbolt-floor-regtest-1", Endpoint::Unix)?;
    fixture.replace_config(
        "genesis_time = \"2026-01-01T00:00:00Z\"",
        "genesis_time = \"2026-01-01T00:00:00+00:00\"",
    )?;
    assert!(ValidatedConfig::load(&fixture.config).is_err());

    fixture.write_config("regtest", "thunderbolt-floor-regtest-1", Endpoint::Unix)?;
    fixture.replace_config(
        &format!("database_path = \"{}\"", toml_path(&fixture.database)),
        &format!("database_path = \"{}\"", toml_path(&fixture.root.join(":memory:"))),
    )?;
    assert!(ValidatedConfig::load(&fixture.config).is_err());

    fixture.write_config("regtest", "thunderbolt-floor-regtest-1", Endpoint::Unix)?;
    let text = fs::read_to_string(&fixture.config)?;
    let first_digest = text.lines().find(|line| line.starts_with("sha256")).ok_or("digest")?;
    owner_file(
        &fixture.config,
        text.replace(first_digest, &format!("sha256 = \"{}\"", "00".repeat(32)))
            .as_bytes(),
    )?;
    assert!(ValidatedConfig::load(&fixture.config).is_err());
    Ok(())
}

#[test]
fn validator_manifest_requires_valid_keys_power_and_comet_order() -> TestResult {
    let fixture = Fixture::new()?;
    fixture.write_public_manifests("regtest", &[(&"00".repeat(32), 10)])?;
    fixture.write_config("regtest", "thunderbolt-floor-regtest-1", Endpoint::Unix)?;
    assert!(ValidatedConfig::load(&fixture.config).is_err());

    fixture.write_public_manifests("regtest", &[(VALIDATOR_KEY, 0)])?;
    fixture.write_config("regtest", "thunderbolt-floor-regtest-1", Endpoint::Unix)?;
    assert!(ValidatedConfig::load(&fixture.config).is_err());

    let second = "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c";
    let canonical = canonical_validator_pairs(&[(VALIDATOR_KEY, 10), (second, 10)])?;
    let reversed = [canonical[1], canonical[0]];
    fixture.write_public_manifests("regtest", &reversed)?;
    fixture.write_config("regtest", "thunderbolt-floor-regtest-1", Endpoint::Unix)?;
    assert!(ValidatedConfig::load(&fixture.config).is_err());
    Ok(())
}

#[test]
fn database_profile_copy_and_live_inode_replacement_are_rejected() -> TestResult {
    let first = Fixture::new()?;
    let first_config = ValidatedConfig::load(&first.config)?;
    let application = FloorApplication::open(first_config.database_path(), first_config.genesis().clone())?;
    first_config.revalidate_after_database_open()?;

    let old = first.root.join("floor-old.sqlite3");
    fs::rename(&first.database, &old)?;
    fs::copy(&old, &first.database)?;
    fs::set_permissions(&first.database, fs::Permissions::from_mode(0o600))?;
    assert!(application.status().is_err());
    drop(application);

    let source = Fixture::new()?;
    let source_config = ValidatedConfig::load(&source.config)?;
    let source_application = FloorApplication::open(source_config.database_path(), source_config.genesis().clone())?;
    source_application.verify_integrity()?;
    drop(source_application);

    let second = Fixture::new()?;
    second.write_config("regtest", "thunderbolt-floor-regtest-other", Endpoint::Unix)?;
    fs::copy(&source.database, &second.database)?;
    fs::set_permissions(&second.database, fs::Permissions::from_mode(0o600))?;
    let second_config = ValidatedConfig::load(&second.config)?;
    assert!(FloorApplication::open(second_config.database_path(), second_config.genesis().clone()).is_err());
    Ok(())
}

#[test]
fn durable_database_rejects_validator_profile_change() -> TestResult {
    let fixture = Fixture::new()?;
    let initial = ValidatedConfig::load(&fixture.config)?;
    let application = FloorApplication::open(initial.database_path(), initial.genesis().clone())?;
    application.verify_integrity()?;
    drop(application);

    let replacement = "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c";
    fixture.write_public_manifests("regtest", &[(replacement, 10)])?;
    fixture.write_config("regtest", "thunderbolt-floor-regtest-1", Endpoint::Unix)?;
    let changed = ValidatedConfig::load(&fixture.config)?;
    assert!(FloorApplication::open(changed.database_path(), changed.genesis().clone()).is_err());
    Ok(())
}

#[test]
fn database_ownership_lock_is_exclusive_and_inode_fenced() -> TestResult {
    let fixture = Fixture::new()?;
    let config = ValidatedConfig::load(&fixture.config)?;
    let lease = config.acquire_database_lease()?;
    assert!(config.acquire_database_lease().is_err());
    let lock = fixture.root.join("floor.sqlite3.floor-node.lock");
    let moved = fixture.root.join("moved-floor.lock");
    fs::rename(&lock, &moved)?;
    owner_file(&lock, b"replacement")?;
    assert!(lease.revalidate().is_err());
    Ok(())
}

#[test]
fn tampered_database_is_rejected_on_restart() -> TestResult {
    let fixture = Fixture::new()?;
    let config = ValidatedConfig::load(&fixture.config)?;
    let application = FloorApplication::open(config.database_path(), config.genesis().clone())?;
    application.verify_integrity()?;
    drop(application);
    let file = OpenOptions::new().write(true).open(&fixture.database)?;
    file.write_at(&[0_u8], 0)?;
    file.sync_all()?;
    let reopened = ValidatedConfig::load(&fixture.config)?;
    assert!(FloorApplication::open(reopened.database_path(), reopened.genesis().clone()).is_err());
    Ok(())
}

#[test]
fn bounded_unix_server_shuts_down_and_restarts_cleanly() -> TestResult {
    let fixture = Fixture::new()?;
    for _ in 0..2 {
        let config = ValidatedConfig::load(&fixture.config)?;
        config.revalidate()?;
        let lease = config.acquire_database_lease()?;
        let application = FloorApplication::open(config.database_path(), config.genesis().clone())?;
        config.revalidate_after_database_open()?;
        lease.revalidate()?;
        let adapter = ThunderboltFloorAbci::new(application, config.validators().clone(), TestAbciFatal)?;
        let server = thunderbolt_abci_server::start(config.server_config()?, adapter, TestServerFatal)?;
        assert!(fixture.socket.exists());
        server.shutdown_and_join();
        assert!(!fixture.socket.exists());
        drop(lease);
    }
    Ok(())
}

fn canonical_json<T: Serialize>(value: &T) -> TestResult<Vec<u8>> {
    let mut bytes = serde_json::to_vec(value)?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn owner_file(path: &Path, bytes: &[u8]) -> TestResult {
    if path.exists() {
        fs::remove_file(path)?;
    }
    let mut file = OpenOptions::new().write(true).create_new(true).mode(0o600).open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn file_digest(path: &Path) -> TestResult<String> {
    Ok(hex::encode(Sha256::digest(fs::read(path)?)))
}

fn toml_path(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "\\\\").replace('"', "\\\"")
}

fn directory_names(path: &Path) -> TestResult<Vec<String>> {
    let mut names = fs::read_dir(path)?
        .map(|entry| Ok(entry?.file_name().to_string_lossy().into_owned()))
        .collect::<std::io::Result<Vec<_>>>()?;
    names.sort();
    Ok(names)
}

fn validator_updates(validators: &[tendermint::validator::Info]) -> TestResult<Vec<ValidatorUpdate>> {
    validators
        .iter()
        .map(|validator| {
            let key = validator.pub_key.to_bytes();
            Ok(ValidatorUpdate {
                pub_key: Some(ProtoPublicKey {
                    sum: Some(public_key::Sum::Ed25519(key)),
                }),
                power: i64::try_from(validator.power.value())?,
            })
        })
        .collect()
}

fn consensus_from_json(value: &serde_json::Value) -> TestResult<ConsensusParams> {
    let integer = |path: &[&str]| -> TestResult<i64> {
        let mut current = value;
        for key in path {
            current = &current[*key];
        }
        Ok(current.as_str().ok_or("consensus integer")?.parse()?)
    };
    let duration_nanos = integer(&["evidence", "max_age_duration"])?;
    if duration_nanos < 0 || duration_nanos % 1_000_000_000 != 0 {
        return Err("consensus duration".into());
    }
    Ok(ConsensusParams {
        block: Some(BlockParams {
            max_bytes: integer(&["block", "max_bytes"])?,
            max_gas: integer(&["block", "max_gas"])?,
        }),
        evidence: Some(EvidenceParams {
            max_age_num_blocks: integer(&["evidence", "max_age_num_blocks"])?,
            max_age_duration: Some(ProtoDuration {
                seconds: duration_nanos / 1_000_000_000,
                nanos: 0,
            }),
            max_bytes: integer(&["evidence", "max_bytes"])?,
        }),
        validator: Some(ValidatorParams {
            pub_key_types: value["validator"]["pub_key_types"]
                .as_array()
                .ok_or("validator types")?
                .iter()
                .map(|item| item.as_str().ok_or("validator type").map(str::to_owned))
                .collect::<std::result::Result<Vec<_>, _>>()?,
        }),
        version: Some(VersionParams {
            app: u64::try_from(integer(&["version", "app"])?)?,
        }),
        abci: Some(AbciParams {
            vote_extensions_enable_height: integer(&["abci", "vote_extensions_enable_height"])?,
        }),
    })
}

fn canonical_validator_pairs<'a>(values: &[(&'a str, u64)]) -> TestResult<Vec<(&'a str, u64)>> {
    let mut infos = values
        .iter()
        .map(|(key, power)| {
            let bytes = hex::decode(key)?;
            let public = tendermint::PublicKey::from_raw_ed25519(&bytes).ok_or("validator key")?;
            let power = tendermint::vote::Power::try_from(*power)?;
            Ok((tendermint::validator::Info::new(public, power), (*key, power.value())))
        })
        .collect::<TestResult<Vec<_>>>()?;
    infos.sort_by_key(|(info, _)| (std::cmp::Reverse(info.power), info.address));
    Ok(infos.into_iter().map(|(_, raw)| raw).collect())
}

fn assert_command_tree_visible(command: &clap::Command) {
    assert!(!command.is_hide_set());
    assert!(!command.is_allow_external_subcommands_set());
    assert!(!command.is_multicall_set());
    assert!(command.get_short_flag().is_none());
    assert!(command.get_long_flag().is_none());
    assert!(command.get_all_aliases().next().is_none());
    assert!(command.get_all_short_flag_aliases().next().is_none());
    assert!(command.get_all_long_flag_aliases().next().is_none());
    for argument in command.get_arguments() {
        assert!(!argument.is_hide_set());
        assert!(!argument.is_hide_short_help_set());
        assert!(!argument.is_hide_long_help_set());
        assert!(!argument.is_hide_default_value_set());
        assert!(!argument.is_hide_possible_values_set());
        assert!(argument.get_all_aliases().is_none_or(|aliases| aliases.is_empty()));
        assert!(argument
            .get_all_short_aliases()
            .is_none_or(|aliases| aliases.is_empty()));
    }
    for child in command.get_subcommands() {
        assert_command_tree_visible(child);
    }
}
