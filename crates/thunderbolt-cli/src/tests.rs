#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::error::Error;
use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use clap::CommandFactory as _;
use sha2::{Digest as _, Sha256};
use thunderbolt_control::{
    ControlHandler, ControlHandlerFuture, ControlRequest, ControlResponse, ControlServer, ControlStatus, RequestId,
};
use tokio_util::sync::CancellationToken;

use super::*;

const HOLDER_SAMPLE: &str = include_str!("../../thunderbolt-runtime-config/examples/holder-regtest.toml");

type TestResult<T = ()> = std::result::Result<T, Box<dyn Error>>;

struct HolderFixture {
    _directory: tempfile::TempDir,
    config_path: PathBuf,
    socket_path: PathBuf,
}

#[derive(Clone)]
struct RetryOnceHandler {
    calls: Arc<AtomicUsize>,
    request_ids: Arc<Mutex<Vec<RequestId>>>,
    methods: Arc<Mutex<Vec<String>>>,
    payload_lengths: Arc<Mutex<Vec<usize>>>,
}

impl ControlHandler for RetryOnceHandler {
    fn handle(&self, request: ControlRequest) -> ControlHandlerFuture<'_> {
        let call = self.calls.fetch_add(1, Ordering::AcqRel);
        self.request_ids.lock().unwrap().push(request.request_id());
        self.methods.lock().unwrap().push(request.method().to_owned());
        self.payload_lengths.lock().unwrap().push(request.payload().len());
        Box::pin(async move {
            if call == 0 {
                ControlResponse::failure(request.request_id(), ControlStatus::Ambiguous, "retry exact request").unwrap()
            } else {
                ControlResponse::success(request.request_id(), br#"{"liveness":"live"}"#.to_vec())
            }
        })
    }
}

#[derive(Clone)]
struct RecordingHandler {
    calls: Arc<Mutex<Vec<(RequestId, String, usize)>>>,
}

impl ControlHandler for RecordingHandler {
    fn handle(&self, request: ControlRequest) -> ControlHandlerFuture<'_> {
        self.calls.lock().unwrap().push((
            request.request_id(),
            request.method().to_owned(),
            request.payload().len(),
        ));
        let method = request.method().to_owned();
        Box::pin(async move {
            let payload = if method == CONTROL_METHOD_STATUS {
                serde_json::json!({"liveness": "live", "readiness": "not_ready"})
            } else {
                serde_json::json!({"method": method})
            };
            ControlResponse::success(request.request_id(), serde_json::to_vec(&payload).unwrap())
        })
    }
}

impl HolderFixture {
    fn new() -> TestResult<Self> {
        let directory = tempfile::tempdir()?;
        let root = fs::canonicalize(directory.path())?;
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700))?;
        let data = root.join("holder-data");
        let control = root.join("holder-control");
        fs::create_dir(&data)?;
        fs::create_dir(&control)?;
        fs::set_permissions(&data, fs::Permissions::from_mode(0o700))?;
        fs::set_permissions(&control, fs::Permissions::from_mode(0o700))?;

        let descriptor = owner_file(&root, "descriptor.json", b"descriptor")?;
        let anchor = owner_file(&root, "anchor.json", b"anchor")?;
        let profile = owner_file(&root, "profile.json", b"profile")?;
        let vault_checkpoint = owner_file(&root, "vault-checkpoint.json", b"vault-checkpoint")?;
        let trust_checkpoint = owner_file(&root, "trust-checkpoint.json", b"trust-checkpoint")?;
        let trust_root = owner_file(&root, "trust-root.json", b"trust-root")?;
        let cookie = owner_file(&root, "bitcoin.cookie", b"__cookie__:test-only")?;
        let vault_password = owner_file(&root, "vault.password", b"test-only")?;

        let descriptor_digest = digest(b"descriptor");
        let anchor_digest = digest(b"anchor");
        let profile_digest = digest(b"profile");
        let runtime_profile = derived(b"bitcoin-thunderbolt/runtime-config/runtime-profile/v2", profile_digest);
        let finality_profile = derived_pair(
            b"bitcoin-thunderbolt/runtime-config/finality-verifier-profile/v2",
            profile_digest,
            decode_hex32("50d4e01279dbb7fcf6cb0e8a7d407b7713d86b83346b13c60f13b52f8045728d")?,
        );
        let mut config = HOLDER_SAMPLE
            .replace("/var/lib/thunderbolt/regtest/holder-01", &toml_path(&data))
            .replace("/run/user/1000/thunderbolt-regtest-holder-01", &toml_path(&control))
            .replace(
                "/etc/thunderbolt/regtest/holder-01-vault-password",
                &toml_path(&vault_password),
            )
            .replace(
                "/etc/thunderbolt/regtest/holder-01-vault-checkpoint-provider.json",
                &toml_path(&vault_checkpoint),
            )
            .replace(
                "/etc/thunderbolt/regtest/holder-01-trust-checkpoint-provider.json",
                &toml_path(&trust_checkpoint),
            )
            .replace("/etc/thunderbolt/regtest/comet-root.json", &toml_path(&trust_root))
            .replace("/etc/thunderbolt/regtest/bitcoin-cookie.ref", &toml_path(&cookie))
            .replace(
                "/etc/thunderbolt/regtest/committee-descriptor.json",
                &toml_path(&descriptor),
            )
            .replace("/etc/thunderbolt/regtest/anchor-suite.json", &toml_path(&anchor))
            .replace("/etc/thunderbolt/regtest/runtime-profile.json", &toml_path(&profile))
            .replace(&"22".repeat(32), &hex::encode(descriptor_digest))
            .replace(&"33".repeat(32), &hex::encode(anchor_digest))
            .replace(&"aa".repeat(32), &hex::encode(profile_digest))
            .replace(&"44".repeat(32), &hex::encode(digest(b"vault-checkpoint")))
            .replace(&"55".repeat(32), &hex::encode(digest(b"trust-checkpoint")))
            .replace(&"66".repeat(32), &hex::encode(digest(b"trust-root")))
            .replace(
                "4ba1fc95b531329ae4161c164302210a740b60e9071859687aa64d3ebbad53c2",
                &hex::encode(runtime_profile),
            )
            .replace(
                "5e4d04cd79e904b5457c689d6c1f810f01c81c156ec637af30126f7a9fbfe7b8",
                &hex::encode(finality_profile),
            );
        config = config.replace("handler_timeout_ms = 4000", "handler_timeout_ms = 100");
        let config_path = owner_file(&root, "runtime.toml", config.as_bytes())?;
        Ok(Self {
            _directory: directory,
            config_path,
            socket_path: control.join("control.sock"),
        })
    }

    fn server_config(&self) -> TestResult<thunderbolt_control::ControlServerConfig> {
        let effective = ParsedRuntimeConfig::load_owner_only(&self.config_path)?.validate_filesystem()?;
        let handoff = effective.revalidate_for_handoff()?;
        Ok(handoff.holder().ok_or("Holder handoff")?.control().clone())
    }
}

#[test]
fn default_help_exposes_only_fixed_owner_control_commands() {
    let help = Cli::command().render_long_help().to_string();
    for command in ["status", "blockers", "redacted-config", "drain", "stop"] {
        assert!(help.contains(command));
    }
    for forbidden in [
        "start",
        "submit",
        "database",
        "channel",
        "endpoint",
        "token",
        "timeout-seconds",
        "payload",
        "HTTP",
        "legacy",
        "v1",
        "v2",
    ] {
        assert!(!help.contains(forbidden), "default help leaked {forbidden}");
    }
}

#[test]
fn manifest_keeps_http_cli_and_dependencies_feature_gated() {
    let manifest: toml::Value = toml::from_str(include_str!("../Cargo.toml")).unwrap();
    assert_eq!(manifest["package"]["default-run"].as_str(), Some("thunderbolt-cli"));
    assert!(manifest["features"]["default"].as_array().unwrap().is_empty());
    let legacy = manifest["features"]["legacy-v1"].as_array().unwrap();
    for feature in [
        "dep:libc",
        "dep:reqwest",
        "dep:thunderbolt-config",
        "dep:thunderbolt-protocol",
        "dep:zeroize",
    ] {
        assert!(legacy.iter().any(|value| value.as_str() == Some(feature)));
    }
    let legacy_bin = manifest["bin"]
        .as_array()
        .unwrap()
        .iter()
        .find(|target| target["name"].as_str() == Some("thunderbolt-cli-legacy-v1"))
        .unwrap();
    assert_eq!(
        legacy_bin["required-features"].as_array().unwrap()[0].as_str(),
        Some("legacy-v1")
    );
    for dependency in [
        "libc",
        "reqwest",
        "thunderbolt-config",
        "thunderbolt-protocol",
        "zeroize",
    ] {
        assert_eq!(manifest["dependencies"][dependency]["optional"].as_bool(), Some(true));
    }
}

#[test]
fn owner_only_config_is_required_and_sets_exact_client_deadlines() -> TestResult {
    let fixture = HolderFixture::new()?;
    let context = ControlContext::load(&fixture.config_path)?;
    let config = fixture.server_config()?;
    assert_eq!(context.client.socket_path(), fixture.socket_path);
    assert_eq!(context.client.max_frame_bytes(), config.max_frame_bytes);
    assert_eq!(context.client.io_timeout(), config.io_timeout);
    assert_eq!(
        context.client.response_timeout(),
        config
            .handler_timeout
            .checked_add(config.io_timeout)
            .ok_or("deadline overflow")?
    );

    fs::set_permissions(&fixture.config_path, fs::Permissions::from_mode(0o644))?;
    assert!(ControlContext::load(&fixture.config_path).is_err());
    fs::set_permissions(&fixture.config_path, fs::Permissions::from_mode(0o600))?;
    let link = fixture.config_path.with_extension("link");
    std::os::unix::fs::symlink(&fixture.config_path, &link)?;
    assert!(ControlContext::load(&link).is_err());
    assert!(ControlContext::load(Path::new("relative.toml")).is_err());
    Ok(())
}

#[tokio::test]
async fn ambiguous_response_retries_once_with_exact_same_request() -> TestResult {
    let fixture = HolderFixture::new()?;
    let calls = Arc::new(AtomicUsize::new(0));
    let request_ids = Arc::new(Mutex::new(Vec::new()));
    let methods = Arc::new(Mutex::new(Vec::new()));
    let payload_lengths = Arc::new(Mutex::new(Vec::new()));
    let handler = RetryOnceHandler {
        calls: calls.clone(),
        request_ids: request_ids.clone(),
        methods: methods.clone(),
        payload_lengths: payload_lengths.clone(),
    };
    let server = ControlServer::bind(fixture.server_config()?, handler).await?;
    let shutdown = CancellationToken::new();
    let task_shutdown = shutdown.clone();
    let task = tokio::spawn(async move { server.run(task_shutdown).await });
    let context = ControlContext::load(&fixture.config_path)?;
    let request_id = RequestId::from_bytes([0x41; 16])?;
    let value = execute_command(&context.client, Command::Status, request_id).await?;
    assert!(status_is_live(&value));
    assert_eq!(calls.load(Ordering::Acquire), 2);
    assert_eq!(*request_ids.lock().unwrap(), [request_id, request_id]);
    assert_eq!(
        *methods.lock().unwrap(),
        [CONTROL_METHOD_STATUS.to_owned(), CONTROL_METHOD_STATUS.to_owned()]
    );
    assert_eq!(*payload_lengths.lock().unwrap(), [0, 0]);
    shutdown.cancel();
    task.await??;
    Ok(())
}

#[tokio::test]
async fn every_default_command_uses_fixed_method_empty_payload_and_fresh_id() -> TestResult {
    let fixture = HolderFixture::new()?;
    let calls = Arc::new(Mutex::new(Vec::new()));
    let server = ControlServer::bind(fixture.server_config()?, RecordingHandler { calls: calls.clone() }).await?;
    let shutdown = CancellationToken::new();
    let task_shutdown = shutdown.clone();
    let task = tokio::spawn(async move { server.run(task_shutdown).await });
    let context = ControlContext::load(&fixture.config_path)?;
    let commands = [
        Command::Status,
        Command::Blockers,
        Command::RedactedConfig,
        Command::Drain,
        Command::Stop,
    ];
    for (index, command) in commands.into_iter().enumerate() {
        let byte = u8::try_from(index + 1)?;
        let request_id = RequestId::from_bytes([byte; 16])?;
        let value = execute_command(&context.client, command, request_id).await?;
        if command == Command::Status {
            assert!(status_is_live(&value));
        }
    }
    {
        let calls = calls.lock().unwrap();
        assert_eq!(calls.len(), 5);
        for (index, (request_id, method, payload_len)) in calls.iter().enumerate() {
            assert_eq!(request_id.as_bytes(), &[u8::try_from(index + 1)?; 16]);
            assert_eq!(method, commands[index].method());
            assert_eq!(*payload_len, 0);
        }
    }
    shutdown.cancel();
    task.await??;
    Ok(())
}

#[test]
fn daemon_failures_are_correlated_and_nonlive_status_fails() {
    let request_id = RequestId::from_bytes([0x51; 16]).unwrap();
    let failure = ControlResponse::failure(request_id, ControlStatus::Conflict, "runtime not started").unwrap();
    let error = decode_success(failure).unwrap_err();
    assert!(matches!(
        error,
        AppError::Daemon {
            request_id: ref id,
            status: "conflict",
            ref message,
        } if id == &"51".repeat(16) && message == "runtime not started"
    ));
    assert!(!status_is_live(&serde_json::json!({"liveness": "not_live"})));
    assert!(!status_is_live(&serde_json::json!({"readiness": "not_ready"})));
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

fn decode_hex32(value: &str) -> TestResult<[u8; 32]> {
    Ok(hex::decode(value)?.try_into().map_err(|_| "hex width")?)
}

fn toml_path(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}
