#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::collections::BTreeSet;
use std::error::Error;
use std::fs;
use std::os::unix::fs::{FileTypeExt as _, PermissionsExt as _};
use std::os::unix::net::UnixListener as StdUnixListener;
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use std::time::Duration;

use clap::CommandFactory as _;
use sha2::{Digest as _, Sha256};
use thunderbolt_control::{ControlClient, ControlRequest, ControlResponse, ControlStatus, RequestId};
use thunderbolt_ledger::LedgerChainIdV2;
use thunderbolt_ledger_abci::{ConsensusProfileV2, StaticAdmissionRequestV2, StaticAdmissionVerifierV2};
use thunderbolt_protocol::v2::ProtocolLimitsV2;
use thunderbolt_runtime::{
    HolderRole, HolderSupervisor, RuntimeBlockerCode, RuntimeHandlerIdentity, CONTROL_METHOD_BLOCKERS,
    CONTROL_METHOD_DRAIN, CONTROL_METHOD_REDACTED_CONFIG, CONTROL_METHOD_STATUS, CONTROL_METHOD_STOP,
    RUNTIME_PROCESS_LOCK_FILE,
};
use thunderbolt_runtime_config::RuntimeRole;

use super::*;

const LEDGER_SAMPLE: &str = include_str!("../../thunderbolt-runtime-config/examples/ledger-regtest.toml");
const HOLDER_SAMPLE: &str = include_str!("../../thunderbolt-runtime-config/examples/holder-regtest.toml");
const COMMITTEE_SAMPLE: &str = include_str!("../../thunderbolt-runtime-config/examples/committee-regtest.toml");

type TestResult<T = ()> = std::result::Result<T, Box<dyn Error>>;

struct TestAdmissionIdentity {
    verifier_profile: [u8; 32],
    deployment_descriptor: [u8; 32],
}

impl StaticAdmissionVerifierV2 for TestAdmissionIdentity {
    type Error = ();

    fn verifier_profile_id(&self) -> [u8; 32] {
        self.verifier_profile
    }

    fn deployment_descriptor(&self) -> [u8; 32] {
        self.deployment_descriptor
    }

    fn verify_static(&self, _request: StaticAdmissionRequestV2<'_>) -> std::result::Result<(), Self::Error> {
        Err(())
    }
}

struct RoleFixture {
    _directory: tempfile::TempDir,
    config_path: PathBuf,
    data_dir: PathBuf,
    control_socket: PathBuf,
}

struct CommonRoleFiles {
    descriptor: PathBuf,
    anchor: PathBuf,
    profile: PathBuf,
    trust_root: PathBuf,
    cookie: PathBuf,
}

impl CommonRoleFiles {
    fn new(root: &Path) -> TestResult<Self> {
        Ok(Self {
            descriptor: owner_file(root, "shared-descriptor.json", b"descriptor")?,
            anchor: owner_file(root, "shared-anchor.json", b"anchor")?,
            profile: owner_file(root, "shared-profile.json", b"profile")?,
            trust_root: owner_file(root, "shared-trust-root.json", b"trust-root")?,
            cookie: owner_file(root, "shared-bitcoin.cookie", b"__cookie__:test-only")?,
        })
    }
}

impl RoleFixture {
    fn new(role: RuntimeRole) -> TestResult<Self> {
        let directory = tempfile::tempdir()?;
        let root = fs::canonicalize(directory.path())?;
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700))?;
        let common = CommonRoleFiles::new(&root)?;
        let sample = match role {
            RuntimeRole::Ledger => LEDGER_SAMPLE,
            RuntimeRole::Holder => HOLDER_SAMPLE,
            RuntimeRole::Committee => COMMITTEE_SAMPLE,
        };
        let config = materialize_role_sample(sample, role, &root, &common)?;
        let role_name = role_name(role);
        let config_path = owner_file(&root, &format!("{role_name}.toml"), config.as_bytes())?;
        let data_dir = root.join(format!("{role_name}-data"));
        let control_socket = root.join(format!("{role_name}-control/control.sock"));
        Ok(Self {
            _directory: directory,
            config_path,
            data_dir,
            control_socket,
        })
    }
}

#[test]
fn default_help_exposes_only_check_and_start() {
    let help = Cli::command().render_long_help().to_string();
    assert!(help.contains("check"));
    assert!(help.contains("start"));
    for forbidden in [
        "init",
        "demo",
        "HTTP",
        "submit",
        "legacy",
        "v1",
        "v2",
        "version 1",
        "version 2",
    ] {
        assert!(!help.contains(forbidden), "default help leaked {forbidden}");
    }
}

#[test]
fn default_operator_schema_is_exact_and_visible() {
    let mut root = Cli::command();
    root.build();
    assert_visible_without_aliases(&root);
    assert_eq!(command_names(&root), strings(&["check", "start", "help"]));
    assert_eq!(
        argument_schema(&root),
        arguments(&[
            ("config", Some("config"), None),
            ("help", Some("help"), Some('h')),
            ("version", Some("version"), Some('V')),
        ])
    );

    let check = root.find_subcommand("check").unwrap();
    assert_eq!(
        argument_schema(check),
        arguments(&[("config", Some("config"), None), ("help", Some("help"), Some('h')),])
    );
    assert!(check.get_subcommands().next().is_none());

    let start = root.find_subcommand("start").unwrap();
    assert_eq!(
        argument_schema(start),
        arguments(&[
            ("config", Some("config"), None),
            ("log_format", Some("log-format"), None),
            ("help", Some("help"), Some('h')),
        ])
    );
    assert!(start.get_subcommands().next().is_none());
    assert_generated_help_tree(root.find_subcommand("help").unwrap(), &["check", "start", "help"]);
}

#[test]
fn manifest_keeps_legacy_binary_and_dependencies_feature_gated() {
    let manifest: toml::Value = toml::from_str(include_str!("../Cargo.toml")).unwrap();
    assert_eq!(manifest["package"]["default-run"].as_str(), Some("thunderboltd"));
    assert!(manifest["features"]["default"].as_array().unwrap().is_empty());
    let legacy_features = manifest["features"]["legacy-v1"].as_array().unwrap();
    for feature in [
        "dep:getrandom",
        "dep:thunderbolt-config",
        "dep:thunderbolt-node",
        "dep:thunderbolt-storage",
        "dep:toml",
        "dep:zeroize",
    ] {
        assert!(legacy_features.iter().any(|value| value.as_str() == Some(feature)));
    }
    let legacy_bin = manifest["bin"]
        .as_array()
        .unwrap()
        .iter()
        .find(|target| target["name"].as_str() == Some("thunderboltd-legacy-v1"))
        .unwrap();
    assert_eq!(
        legacy_bin["required-features"].as_array().unwrap()[0].as_str(),
        Some("legacy-v1")
    );
    for dependency in [
        "getrandom",
        "thunderbolt-config",
        "thunderbolt-node",
        "thunderbolt-storage",
        "toml",
        "zeroize",
    ] {
        assert_eq!(manifest["dependencies"][dependency]["optional"].as_bool(), Some(true));
    }
    for dependency in [
        "thunderbolt-control",
        "thunderbolt-runtime",
        "thunderbolt-runtime-config",
    ] {
        assert_ne!(
            manifest["dependencies"][dependency]
                .get("optional")
                .and_then(toml::Value::as_bool),
            Some(true)
        );
    }
}

#[test]
fn check_revalidates_all_three_roles_without_runtime_mutation() -> TestResult {
    for role in [RuntimeRole::Ledger, RuntimeRole::Holder, RuntimeRole::Committee] {
        let fixture = RoleFixture::new(role)?;
        check(&fixture.config_path)?;
        assert!(!fixture.control_socket.exists());
        assert!(!fixture.data_dir.join(RUNTIME_PROCESS_LOCK_FILE).exists());
    }
    Ok(())
}

#[test]
fn check_requires_absolute_owner_only_nonsymlink_config() -> TestResult {
    let fixture = RoleFixture::new(RuntimeRole::Holder)?;
    fs::set_permissions(&fixture.config_path, fs::Permissions::from_mode(0o644))?;
    assert!(check(&fixture.config_path).is_err());
    fs::set_permissions(&fixture.config_path, fs::Permissions::from_mode(0o600))?;

    let link = fixture.config_path.with_extension("link");
    std::os::unix::fs::symlink(&fixture.config_path, &link)?;
    assert!(check(&link).is_err());
    assert!(check(Path::new("relative-runtime.toml")).is_err());
    Ok(())
}

#[tokio::test]
async fn immediate_shutdown_is_clean_for_every_role() -> TestResult {
    for role in [RuntimeRole::Ledger, RuntimeRole::Holder, RuntimeRole::Committee] {
        let fixture = RoleFixture::new(role)?;
        start(&fixture.config_path, async {}).await?;
        assert!(!fixture.control_socket.exists());
        assert!(marker(&fixture.data_dir)?.ends_with(b"state=clean\n"));
    }
    Ok(())
}

#[tokio::test]
async fn live_control_reports_not_ready_and_flushes_stop_before_exit() -> TestResult {
    let fixture = RoleFixture::new(RuntimeRole::Holder)?;
    let effective = load_effective(&fixture.config_path)?;
    let handoff = effective.revalidate_for_handoff()?;
    let config = handoff.holder().ok_or("Holder handoff")?;
    let identity = RuntimeHandlerIdentity::for_holder(config);
    let control_config = config.control().clone();
    let handler = UnavailableRoleHandler::<HolderRole>::new(identity);
    let hook_calls = handler.hook_counter();
    let supervisor = HolderSupervisor::new(handoff, handler)?;
    let client = ControlClient::from_server_config(&control_config)?;

    let operations = async {
        wait_for_socket(&fixture.control_socket).await?;
        let status = client.call(&control_request(1, CONTROL_METHOD_STATUS)).await?;
        assert_eq!(status.status(), ControlStatus::Ok);
        let status: serde_json::Value = serde_json::from_slice(status.payload())?;
        assert_eq!(status["lifecycle"], "initialized");
        assert_eq!(status["liveness"], "live");
        assert_eq!(status["readiness"], "not_ready");

        let blockers = client.call(&control_request(2, CONTROL_METHOD_BLOCKERS)).await?;
        assert_eq!(blockers.status(), ControlStatus::Ok);
        let blocker_text = std::str::from_utf8(blockers.payload())?;
        assert!(blocker_text.contains(RuntimeBlockerCode::HolderSigningUnavailable.as_str()));

        let redacted = client.call(&control_request(3, CONTROL_METHOD_REDACTED_CONFIG)).await?;
        assert_eq!(redacted.status(), ControlStatus::Ok);
        let redacted_text = std::str::from_utf8(redacted.payload())?;
        assert!(!redacted_text.contains(fixture._directory.path().to_string_lossy().as_ref()));
        assert!(!redacted_text.contains("127.0.0.1"));

        let drain = client.call(&control_request(4, CONTROL_METHOD_DRAIN)).await?;
        assert_eq!(drain.status(), ControlStatus::Conflict);
        let stop = client.call(&control_request(5, CONTROL_METHOD_STOP)).await?;
        assert_eq!(stop.status(), ControlStatus::Ok);
        Ok::<(), Box<dyn Error>>(())
    };
    let (serve_result, operation_result) = tokio::join!(
        serve_supervisor(supervisor, control_config, std::future::pending()),
        operations
    );
    serve_result?;
    operation_result?;
    assert_eq!(hook_calls.load(Ordering::Acquire), 0);
    assert!(!fixture.control_socket.exists());
    assert!(marker(&fixture.data_dir)?.ends_with(b"state=clean\n"));
    Ok(())
}

#[tokio::test]
async fn bind_failure_cleans_process_marker_and_preserves_active_socket() -> TestResult {
    let fixture = RoleFixture::new(RuntimeRole::Holder)?;
    let active = StdUnixListener::bind(&fixture.control_socket)?;
    fs::set_permissions(&fixture.control_socket, fs::Permissions::from_mode(0o600))?;
    let result = tokio::time::timeout(
        Duration::from_secs(2),
        start(&fixture.config_path, std::future::pending()),
    )
    .await?;
    assert!(matches!(result, Err(AppError::Control(ControlError::SocketInUse(_)))));
    assert!(fs::symlink_metadata(&fixture.control_socket)?.file_type().is_socket());
    assert!(marker(&fixture.data_dir)?.ends_with(b"state=clean\n"));
    drop(active);
    fs::remove_file(&fixture.control_socket)?;
    Ok(())
}

#[tokio::test]
async fn control_server_failure_still_cleans_runtime_marker_without_hooks() -> TestResult {
    let fixture = RoleFixture::new(RuntimeRole::Holder)?;
    let effective = load_effective(&fixture.config_path)?;
    let handoff = effective.revalidate_for_handoff()?;
    let config = handoff.holder().ok_or("Holder handoff")?;
    let control_config = config.control().clone();
    let handler = UnavailableRoleHandler::<HolderRole>::new(RuntimeHandlerIdentity::for_holder(config));
    let hook_calls = handler.hook_counter();
    let supervisor = HolderSupervisor::new(handoff, handler)?;
    let (signal_tx, signal_rx) = tokio::sync::oneshot::channel();
    let moved = fixture.control_socket.with_extension("moved");

    let operations = async {
        wait_for_socket(&fixture.control_socket).await?;
        fs::rename(&fixture.control_socket, &moved)?;
        let replacement = StdUnixListener::bind(&fixture.control_socket)?;
        fs::set_permissions(&fixture.control_socket, fs::Permissions::from_mode(0o600))?;
        drop(replacement);
        let _ = signal_tx.send(());
        Ok::<(), Box<dyn Error>>(())
    };
    let signal = async move {
        let _ = signal_rx.await;
    };
    let (serve_result, operation_result) =
        tokio::join!(serve_supervisor(supervisor, control_config, signal), operations);
    operation_result?;
    assert!(matches!(
        serve_result,
        Err(AppError::Control(ControlError::UnsafePath { .. }))
    ));
    assert_eq!(hook_calls.load(Ordering::Acquire), 0);
    assert!(marker(&fixture.data_dir)?.ends_with(b"state=clean\n"));
    assert!(fixture.control_socket.exists());
    assert!(moved.exists());
    fs::remove_file(&fixture.control_socket)?;
    fs::remove_file(moved)?;
    Ok(())
}

#[tokio::test]
async fn stale_socket_is_recovered_but_dirty_restart_remains_blocked() -> TestResult {
    let fixture = RoleFixture::new(RuntimeRole::Holder)?;
    let effective = load_effective(&fixture.config_path)?;
    let handoff = effective.revalidate_for_handoff()?;
    let config = handoff.holder().ok_or("Holder handoff")?;
    let handler = UnavailableRoleHandler::<HolderRole>::new(RuntimeHandlerIdentity::for_holder(config));
    let hook_calls = handler.hook_counter();
    let supervisor = HolderSupervisor::new(handoff, handler)?;
    drop(supervisor);
    assert!(marker(&fixture.data_dir)?.ends_with(b"state=running\n"));

    let stale = StdUnixListener::bind(&fixture.control_socket)?;
    fs::set_permissions(&fixture.control_socket, fs::Permissions::from_mode(0o600))?;
    drop(stale);

    let config_path = fixture.config_path.clone();
    let task = tokio::spawn(async move { start(&config_path, std::future::pending()).await });
    let client = control_client(&fixture.config_path)?;
    let status = wait_for_control(&client, 6, CONTROL_METHOD_STATUS).await?;
    assert_eq!(status.status(), ControlStatus::Ok);
    let blockers = client.call(&control_request(11, CONTROL_METHOD_BLOCKERS)).await?;
    assert_eq!(blockers.status(), ControlStatus::Ok);
    assert!(
        std::str::from_utf8(blockers.payload())?.contains(RuntimeBlockerCode::DirtyRestartRecoveryRequired.as_str())
    );
    let drain = client.call(&control_request(12, CONTROL_METHOD_DRAIN)).await?;
    assert_eq!(drain.status(), ControlStatus::Conflict);
    let stop = client.call(&control_request(13, CONTROL_METHOD_STOP)).await?;
    assert_eq!(stop.status(), ControlStatus::Ok);
    task.await??;
    assert_eq!(hook_calls.load(Ordering::Acquire), 0);
    assert!(marker(&fixture.data_dir)?.ends_with(b"state=dirty\n"));
    assert!(!fixture.control_socket.exists());
    Ok(())
}

#[tokio::test]
async fn simultaneous_second_daemon_is_rejected_without_disturbing_first() -> TestResult {
    let fixture = RoleFixture::new(RuntimeRole::Holder)?;
    let first_path = fixture.config_path.clone();
    let first = tokio::spawn(async move { start(&first_path, std::future::pending()).await });
    wait_for_socket(&fixture.control_socket).await?;

    let second = start(&fixture.config_path, async {}).await;
    assert!(matches!(
        second,
        Err(AppError::Runtime(RuntimeError::ProcessAlreadyRunning))
    ));
    let client = control_client(&fixture.config_path)?;
    let status = client.call(&control_request(9, CONTROL_METHOD_STATUS)).await?;
    assert_eq!(status.status(), ControlStatus::Ok);
    let stop = client.call(&control_request(10, CONTROL_METHOD_STOP)).await?;
    assert_eq!(stop.status(), ControlStatus::Ok);
    first.await??;
    assert!(marker(&fixture.data_dir)?.ends_with(b"state=clean\n"));
    Ok(())
}

fn control_request(discriminator: u8, method: &str) -> ControlRequest {
    ControlRequest::new(RequestId::from_bytes([discriminator; 16]).unwrap(), method, Vec::new()).unwrap()
}

fn control_client(config_path: &Path) -> TestResult<ControlClient> {
    let effective = load_effective(config_path)?;
    let handoff = effective.revalidate_for_handoff()?;
    let config = handoff.holder().ok_or("Holder handoff")?;
    Ok(ControlClient::from_server_config(config.control())?)
}

async fn wait_for_socket(path: &Path) -> TestResult {
    for _ in 0..200 {
        if fs::symlink_metadata(path).is_ok_and(|metadata| metadata.file_type().is_socket()) {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    Err("control socket did not appear".into())
}

async fn wait_for_control(client: &ControlClient, discriminator: u8, method: &str) -> TestResult<ControlResponse> {
    for _ in 0..200 {
        if let Ok(response) = client.call(&control_request(discriminator, method)).await {
            return Ok(response);
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    Err("control server did not accept a request".into())
}

fn marker(data_dir: &Path) -> TestResult<Vec<u8>> {
    Ok(fs::read(data_dir.join(RUNTIME_PROCESS_LOCK_FILE))?)
}

fn materialize_role_sample(
    sample: &str,
    role: RuntimeRole,
    root: &Path,
    common: &CommonRoleFiles,
) -> TestResult<String> {
    let role_name = role_name(role);
    let (old_data, old_control) = match role {
        RuntimeRole::Ledger => (
            "/var/lib/thunderbolt/regtest/ledger",
            "/run/user/1000/thunderbolt-regtest-ledger",
        ),
        RuntimeRole::Holder => (
            "/var/lib/thunderbolt/regtest/holder-01",
            "/run/user/1000/thunderbolt-regtest-holder-01",
        ),
        RuntimeRole::Committee => (
            "/var/lib/thunderbolt/regtest/committee-01",
            "/run/user/1000/thunderbolt-regtest-committee-01",
        ),
    };
    let data = root.join(format!("{role_name}-data"));
    let control = root.join(format!("{role_name}-control"));
    fs::create_dir(&data)?;
    fs::create_dir(&control)?;
    fs::set_permissions(&data, fs::Permissions::from_mode(0o700))?;
    fs::set_permissions(&control, fs::Permissions::from_mode(0o700))?;

    let descriptor_digest = digest(b"descriptor");
    let anchor_digest = digest(b"anchor");
    let profile_digest = digest(b"profile");
    let runtime_profile = derived(b"bitcoin-thunderbolt/runtime-config/runtime-profile/v2", profile_digest);
    let finality_profile = derived_pair(
        b"bitcoin-thunderbolt/runtime-config/finality-verifier-profile/v2",
        profile_digest,
        decode_hex32("50d4e01279dbb7fcf6cb0e8a7d407b7713d86b83346b13c60f13b52f8045728d")?,
    );
    let static_profile = derived(
        b"bitcoin-thunderbolt/runtime-config/static-verifier-profile/v2",
        profile_digest,
    );
    let deployment_descriptor = test_deployment_descriptor(descriptor_digest, anchor_digest)?;
    let consensus_profile = ConsensusProfileV2::from_verifier(
        &LedgerChainIdV2::new("thunderbolt-regtest-1")?,
        ProtocolLimitsV2::new(1_000_000, 8, 86_400_000)?,
        &TestAdmissionIdentity {
            verifier_profile: static_profile,
            deployment_descriptor,
        },
    )?;
    let mut config = sample
        .replace(old_data, &toml_path(&data))
        .replace(old_control, &toml_path(&control))
        .replace(
            "/etc/thunderbolt/regtest/bitcoin-cookie.ref",
            &toml_path(&common.cookie),
        )
        .replace(
            "/etc/thunderbolt/regtest/committee-descriptor.json",
            &toml_path(&common.descriptor),
        )
        .replace("/etc/thunderbolt/regtest/anchor-suite.json", &toml_path(&common.anchor))
        .replace(
            "/etc/thunderbolt/regtest/runtime-profile.json",
            &toml_path(&common.profile),
        )
        .replace(
            "/etc/thunderbolt/regtest/comet-root.json",
            &toml_path(&common.trust_root),
        )
        .replace(&"22".repeat(32), &hex::encode(descriptor_digest))
        .replace(&"33".repeat(32), &hex::encode(anchor_digest))
        .replace(&"aa".repeat(32), &hex::encode(profile_digest))
        .replace(&"66".repeat(32), &hex::encode(digest(b"trust-root")))
        .replace(
            "4ba1fc95b531329ae4161c164302210a740b60e9071859687aa64d3ebbad53c2",
            &hex::encode(runtime_profile),
        )
        .replace(
            "5e4d04cd79e904b5457c689d6c1f810f01c81c156ec637af30126f7a9fbfe7b8",
            &hex::encode(finality_profile),
        )
        .replace(
            "b1e18cafc550975a6602a8311b016bc3ad9b2580975ff427eb1da9b0af17359b",
            &hex::encode(static_profile),
        )
        .replace(
            "36fc734f78f1fb5fdcb380ae7905d6871144063db36f2846bb6412dfde3e1eb7",
            &hex::encode(deployment_descriptor),
        )
        .replace(
            "81461d89549ebcc121f89b19f80148d0f2b1c80f3c08cac31530dd58b6e9a5e0",
            &hex::encode(consensus_profile.as_bytes()),
        );
    if role != RuntimeRole::Ledger {
        let password = owner_file(root, &format!("{role_name}-vault.password"), b"test-only")?;
        let vault_manifest = owner_file(
            root,
            &format!("{role_name}-vault-provider.json"),
            format!("{role_name}-vault-provider").as_bytes(),
        )?;
        let trust_manifest = owner_file(
            root,
            &format!("{role_name}-trust-provider.json"),
            format!("{role_name}-trust-provider").as_bytes(),
        )?;
        let (old_password, old_vault, old_trust, vault_placeholder, trust_placeholder) = match role {
            RuntimeRole::Holder => (
                "/etc/thunderbolt/regtest/holder-01-vault-password",
                "/etc/thunderbolt/regtest/holder-01-vault-checkpoint-provider.json",
                "/etc/thunderbolt/regtest/holder-01-trust-checkpoint-provider.json",
                "44",
                "55",
            ),
            RuntimeRole::Committee => (
                "/etc/thunderbolt/regtest/committee-01-vault-password",
                "/etc/thunderbolt/regtest/committee-01-vault-checkpoint-provider.json",
                "/etc/thunderbolt/regtest/committee-01-trust-checkpoint-provider.json",
                "47",
                "57",
            ),
            RuntimeRole::Ledger => return Err("Ledger has no checkpoint providers".into()),
        };
        config = config
            .replace(old_password, &toml_path(&password))
            .replace(old_vault, &toml_path(&vault_manifest))
            .replace(old_trust, &toml_path(&trust_manifest))
            .replace(
                &vault_placeholder.repeat(32),
                &hex::encode(digest(format!("{role_name}-vault-provider").as_bytes())),
            )
            .replace(
                &trust_placeholder.repeat(32),
                &hex::encode(digest(format!("{role_name}-trust-provider").as_bytes())),
            );
    }
    Ok(config)
}

fn test_deployment_descriptor(committee_descriptor: [u8; 32], anchor_suite: [u8; 32]) -> TestResult<[u8; 32]> {
    let mut hasher = Sha256::new();
    hasher.update(b"bitcoin-thunderbolt/runtime-config/deployment-descriptor/v2");
    hasher.update([4]);
    append_hash(&mut hasher, b"thunderbolt-regtest-1");
    append_hash(&mut hasher, b"thunderbolt-regtest");
    append_hash(&mut hasher, &[0x11; 32]);
    append_hash(
        &mut hasher,
        &decode_hex32("0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206")?,
    );
    hasher.update(9_u64.to_be_bytes());
    append_hash(&mut hasher, &committee_descriptor);
    append_hash(&mut hasher, &anchor_suite);
    Ok(hasher.finalize().into())
}

type ArgumentSchema = (String, Option<String>, Option<char>);

fn strings(values: &[&str]) -> BTreeSet<String> {
    values.iter().map(|value| (*value).to_owned()).collect()
}

fn arguments(values: &[(&str, Option<&str>, Option<char>)]) -> BTreeSet<ArgumentSchema> {
    values
        .iter()
        .map(|(id, long, short)| ((*id).to_owned(), long.map(str::to_owned), *short))
        .collect()
}

fn command_names(command: &clap::Command) -> BTreeSet<String> {
    command
        .get_subcommands()
        .map(|child| child.get_name().to_owned())
        .collect()
}

fn argument_schema(command: &clap::Command) -> BTreeSet<ArgumentSchema> {
    command
        .get_arguments()
        .map(|argument| {
            (
                argument.get_id().to_string(),
                argument.get_long().map(str::to_owned),
                argument.get_short(),
            )
        })
        .collect()
}

fn assert_visible_without_aliases(command: &clap::Command) {
    assert!(!command.is_hide_set(), "hidden command: {}", command.get_name());
    assert!(
        !command.is_allow_external_subcommands_set(),
        "external subcommands enabled for {}",
        command.get_name()
    );
    assert!(
        !command.is_multicall_set(),
        "multicall enabled for {}",
        command.get_name()
    );
    assert!(
        command.get_short_flag().is_none(),
        "short command flag: {}",
        command.get_name()
    );
    assert!(
        command.get_long_flag().is_none(),
        "long command flag: {}",
        command.get_name()
    );
    assert!(
        command.get_all_aliases().next().is_none(),
        "command alias: {}",
        command.get_name()
    );
    assert!(
        command.get_all_short_flag_aliases().next().is_none(),
        "short command alias: {}",
        command.get_name()
    );
    assert!(
        command.get_all_long_flag_aliases().next().is_none(),
        "long command alias: {}",
        command.get_name()
    );
    for argument in command.get_arguments() {
        assert!(!argument.is_hide_set(), "hidden argument: {}", argument.get_id());
        assert!(
            !argument.is_hide_short_help_set() && !argument.is_hide_long_help_set(),
            "partially hidden argument: {}",
            argument.get_id()
        );
        assert!(
            !argument.is_hide_default_value_set() && !argument.is_hide_possible_values_set(),
            "argument metadata hidden: {}",
            argument.get_id()
        );
        assert!(
            argument.get_all_aliases().is_none_or(|aliases| aliases.is_empty()),
            "argument alias: {}",
            argument.get_id()
        );
        assert!(
            argument
                .get_all_short_aliases()
                .is_none_or(|aliases| aliases.is_empty()),
            "short argument alias: {}",
            argument.get_id()
        );
    }
    for child in command.get_subcommands() {
        assert_visible_without_aliases(child);
    }
}

fn assert_generated_help_tree(help: &clap::Command, names: &[&str]) {
    assert!(argument_schema(help).is_empty());
    assert_eq!(command_names(help), strings(names));
    for command in help.get_subcommands() {
        assert!(argument_schema(command).is_empty());
        assert!(command.get_subcommands().next().is_none());
    }
}

fn owner_file(root: &Path, name: &str, bytes: &[u8]) -> TestResult<PathBuf> {
    let path = root.join(name);
    fs::write(&path, bytes)?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
    Ok(path)
}

fn digest(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn derived(domain: &[u8], source: [u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(source);
    hasher.finalize().into()
}

fn derived_pair(domain: &[u8], first: [u8; 32], second: [u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(first);
    hasher.update(second);
    hasher.finalize().into()
}

fn append_hash(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update(u64::try_from(bytes.len()).unwrap().to_be_bytes());
    hasher.update(bytes);
}

fn decode_hex32(value: &str) -> TestResult<[u8; 32]> {
    Ok(hex::decode(value)?.try_into().map_err(|_| "hex width")?)
}

fn toml_path(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

const fn role_name(role: RuntimeRole) -> &'static str {
    match role {
        RuntimeRole::Ledger => "ledger",
        RuntimeRole::Holder => "holder",
        RuntimeRole::Committee => "committee",
    }
}
