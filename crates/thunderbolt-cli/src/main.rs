#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use serde_json::Value;
use thiserror::Error;
use thunderbolt_control::{ControlClient, ControlError, ControlRequest, ControlResponse, ControlStatus, RequestId};
use thunderbolt_runtime::{
    CONTROL_METHOD_BLOCKERS, CONTROL_METHOD_DRAIN, CONTROL_METHOD_REDACTED_CONFIG, CONTROL_METHOD_STATUS,
    CONTROL_METHOD_STOP,
};
use thunderbolt_runtime_config::{ConfigError, EffectiveRuntimeConfig, ParsedRuntimeConfig, RuntimeRole};

const DEFAULT_CONFIG_PATH: &str = "/var/lib/thunderbolt/runtime.toml";

#[derive(Debug, Parser)]
#[command(
    name = "thunderbolt-cli",
    version,
    about = "Owner-only Unix control client for Bitcoin Thunderbolt"
)]
struct Cli {
    /// Absolute path to the daemon's owner-only runtime configuration.
    #[arg(long, global = true, default_value = DEFAULT_CONFIG_PATH)]
    config: PathBuf,

    #[command(subcommand)]
    command: Command,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Subcommand)]
enum Command {
    /// Show process liveness, protocol readiness, role, and lifecycle.
    Status,
    /// Show immutable readiness blocker codes.
    Blockers,
    /// Show the public effective configuration with sensitive values redacted.
    RedactedConfig,
    /// Request a bounded lifecycle drain.
    Drain,
    /// Request a clean daemon stop.
    Stop,
}

impl Command {
    const fn method(self) -> &'static str {
        match self {
            Self::Status => CONTROL_METHOD_STATUS,
            Self::Blockers => CONTROL_METHOD_BLOCKERS,
            Self::RedactedConfig => CONTROL_METHOD_REDACTED_CONFIG,
            Self::Drain => CONTROL_METHOD_DRAIN,
            Self::Stop => CONTROL_METHOD_STOP,
        }
    }
}

#[derive(Debug, Error)]
enum AppError {
    #[error("runtime configuration failed: {0}")]
    Config(#[from] ConfigError),
    #[error("local control failed: {0}")]
    Control(#[from] ControlError),
    #[error("runtime configuration role did not match its handoff")]
    RoleMismatch,
    #[error("invalid JSON response: {0}")]
    Json(#[from] serde_json::Error),
    #[error("daemon rejected request {request_id} with {status}: {message}")]
    Daemon {
        request_id: String,
        status: &'static str,
        message: String,
    },
    #[error("daemon status is not live")]
    NotLive,
}

struct ControlContext {
    _effective: EffectiveRuntimeConfig,
    client: ControlClient,
}

#[tokio::main]
async fn main() -> ExitCode {
    match run(Cli::parse()).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::FAILURE
        }
    }
}

async fn run(cli: Cli) -> Result<(), AppError> {
    let context = ControlContext::load(&cli.config)?;
    let request_id = RequestId::random()?;
    let value = execute_command(&context.client, cli.command, request_id).await?;
    println!("{}", serde_json::to_string_pretty(&value)?);
    if cli.command == Command::Status && !status_is_live(&value) {
        return Err(AppError::NotLive);
    }
    Ok(())
}

async fn execute_command(client: &ControlClient, command: Command, request_id: RequestId) -> Result<Value, AppError> {
    let request = ControlRequest::new(request_id, command.method(), Vec::new())?;
    let response = call_exact(client, &request).await?;
    decode_success(response)
}

impl ControlContext {
    fn load(config_path: &Path) -> Result<Self, AppError> {
        let effective = ParsedRuntimeConfig::load_owner_only(config_path)?.validate_filesystem()?;
        let control_config = {
            let handoff = effective.revalidate_for_handoff()?;
            match effective.role() {
                RuntimeRole::Ledger => handoff.ledger().ok_or(AppError::RoleMismatch)?.control().clone(),
                RuntimeRole::Holder => handoff.holder().ok_or(AppError::RoleMismatch)?.control().clone(),
                RuntimeRole::Committee => handoff.committee().ok_or(AppError::RoleMismatch)?.control().clone(),
            }
        };
        let client = ControlClient::from_server_config(&control_config)?;
        Ok(Self {
            _effective: effective,
            client,
        })
    }
}

async fn call_exact(client: &ControlClient, request: &ControlRequest) -> thunderbolt_control::Result<ControlResponse> {
    let first = client.call(request).await;
    match first {
        Err(ControlError::Ambiguous(id)) if id == request.request_id() => client.call(request).await,
        Ok(response) if response.status() == ControlStatus::Ambiguous => client.call(request).await,
        result => result,
    }
}

fn decode_success(response: ControlResponse) -> Result<Value, AppError> {
    if !response.is_success() {
        return Err(AppError::Daemon {
            request_id: hex::encode(response.request_id().as_bytes()),
            status: status_name(response.status()),
            message: response.message().to_owned(),
        });
    }
    Ok(serde_json::from_slice(response.payload())?)
}

fn status_is_live(value: &Value) -> bool {
    value.get("liveness").and_then(Value::as_str) == Some("live")
}

const fn status_name(status: ControlStatus) -> &'static str {
    match status {
        ControlStatus::Ok => "ok",
        ControlStatus::InvalidRequest => "invalid_request",
        ControlStatus::Unauthorized => "unauthorized",
        ControlStatus::Conflict => "conflict",
        ControlStatus::Busy => "busy",
        ControlStatus::Draining => "draining",
        ControlStatus::Internal => "internal",
        ControlStatus::Ambiguous => "ambiguous",
    }
}

#[cfg(test)]
mod tests;
