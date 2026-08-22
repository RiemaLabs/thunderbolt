#![forbid(unsafe_code)]

use core::future::Future;
use core::marker::PhantomData;
use core::pin::Pin;
use std::fmt;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use clap::{Args, Parser, Subcommand, ValueEnum};
use thiserror::Error;
use thunderbolt_control::{ControlError, ControlServer, ControlServerConfig};
use thunderbolt_runtime::{
    CommitteeRole, CommitteeSupervisor, HolderRole, HolderSupervisor, LedgerRole, LedgerSupervisor, RuntimeError,
    RuntimeHandlerFuture, RuntimeHandlerIdentity, RuntimeLifecycleEvent, RuntimeLifecycleHandler, RuntimeRoleMarker,
    RuntimeSupervisor,
};
use thunderbolt_runtime_config::{ConfigError, EffectiveRuntimeConfig, ParsedRuntimeConfig, RuntimeRole};
use tokio_util::sync::CancellationToken;
use tracing::info;
use tracing_subscriber::EnvFilter;

const DEFAULT_CONFIG_PATH: &str = "/var/lib/thunderbolt/runtime.toml";

#[derive(Debug, Parser)]
#[command(
    name = "thunderboltd",
    version,
    about = "Fail-closed Bitcoin Thunderbolt v2 operator runtime"
)]
struct Cli {
    /// Absolute path to an owner-only version 2 runtime configuration.
    #[arg(long, global = true, default_value = DEFAULT_CONFIG_PATH)]
    config: PathBuf,

    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Validate the owner-only configuration and all referenced resources.
    Check,
    /// Start the local Unix control plane in Live/NotReady mode.
    Start(StartArgs),
}

#[derive(Debug, Args)]
struct StartArgs {
    /// Structured JSON is the default for operator log collection.
    #[arg(long, value_enum, default_value_t = LogFormat::Json)]
    log_format: LogFormat,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum LogFormat {
    Json,
    Pretty,
}

#[derive(Debug, Error)]
enum AppError {
    #[error("runtime configuration failed: {0}")]
    Config(#[from] ConfigError),
    #[error("runtime supervision failed: {0}")]
    Runtime(#[from] RuntimeError),
    #[error("local control failed: {0}")]
    Control(#[from] ControlError),
    #[error("runtime configuration role did not match its handoff")]
    RoleMismatch,
    #[error("failed to encode redacted configuration: {0}")]
    Json(#[from] serde_json::Error),
    #[error("failed to initialize tracing: {0}")]
    Tracing(String),
    #[error("failed to install shutdown signal handlers: {0}")]
    Signal(String),
    #[error("control bind failed ({bind}); runtime cleanup also failed ({cleanup})")]
    BindCleanup { bind: String, cleanup: String },
    #[error("runtime failed ({runtime}); control cleanup also failed ({control})")]
    Concurrent { runtime: String, control: String },
}

struct UnavailableRoleHandler<R: RuntimeRoleMarker> {
    identity: RuntimeHandlerIdentity,
    hook_calls: Arc<AtomicUsize>,
    _role: PhantomData<R>,
}

impl<R: RuntimeRoleMarker> UnavailableRoleHandler<R> {
    fn new(identity: RuntimeHandlerIdentity) -> Self {
        Self {
            identity,
            hook_calls: Arc::new(AtomicUsize::new(0)),
            _role: PhantomData,
        }
    }

    #[cfg(test)]
    fn hook_counter(&self) -> Arc<AtomicUsize> {
        self.hook_calls.clone()
    }
}

#[derive(Clone, Copy, Debug)]
struct UnavailableRoleError;

impl fmt::Display for UnavailableRoleError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("role service capability is unavailable")
    }
}

impl std::error::Error for UnavailableRoleError {}

impl<R: RuntimeRoleMarker> RuntimeLifecycleHandler<R> for UnavailableRoleHandler<R> {
    type Error = UnavailableRoleError;

    fn identity(&self) -> RuntimeHandlerIdentity {
        self.identity.clone()
    }

    fn on_lifecycle(
        &self,
        _event: RuntimeLifecycleEvent,
        _cancellation: CancellationToken,
    ) -> RuntimeHandlerFuture<'_, Self::Error> {
        let hook_calls = self.hook_calls.clone();
        Box::pin(async move {
            hook_calls.fetch_add(1, Ordering::AcqRel);
            Err(UnavailableRoleError)
        })
    }
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
    match cli.command {
        Command::Check => check(&cli.config),
        Command::Start(arguments) => {
            initialize_tracing(arguments.log_format)?;
            let shutdown_signal = install_shutdown_signal()?;
            start(&cli.config, shutdown_signal).await
        }
    }
}

fn check(config_path: &Path) -> Result<(), AppError> {
    let effective = load_effective(config_path)?;
    let handoff = effective.revalidate_for_handoff()?;
    match effective.role() {
        RuntimeRole::Ledger => {
            let config = handoff.ledger().ok_or(AppError::RoleMismatch)?;
            let _ = RuntimeHandlerIdentity::for_ledger(config);
        }
        RuntimeRole::Holder => {
            let config = handoff.holder().ok_or(AppError::RoleMismatch)?;
            let _ = RuntimeHandlerIdentity::for_holder(config);
        }
        RuntimeRole::Committee => {
            let config = handoff.committee().ok_or(AppError::RoleMismatch)?;
            let _ = RuntimeHandlerIdentity::for_committee(config);
        }
    }
    let output = serde_json::json!({
        "configuration_valid": true,
        "liveness": "not_started",
        "readiness": "not_ready",
        "effective_config": effective.redacted(),
    });
    println!("{}", serde_json::to_string_pretty(&output)?);
    Ok(())
}

async fn start<S>(config_path: &Path, shutdown_signal: S) -> Result<(), AppError>
where
    S: Future<Output = ()>,
{
    let effective = load_effective(config_path)?;
    let handoff = effective.revalidate_for_handoff()?;
    match effective.role() {
        RuntimeRole::Ledger => {
            let (identity, control) = {
                let config = handoff.ledger().ok_or(AppError::RoleMismatch)?;
                (RuntimeHandlerIdentity::for_ledger(config), config.control().clone())
            };
            let supervisor = LedgerSupervisor::new(handoff, UnavailableRoleHandler::<LedgerRole>::new(identity))?;
            serve_supervisor(supervisor, control, shutdown_signal).await
        }
        RuntimeRole::Holder => {
            let (identity, control) = {
                let config = handoff.holder().ok_or(AppError::RoleMismatch)?;
                (RuntimeHandlerIdentity::for_holder(config), config.control().clone())
            };
            let supervisor = HolderSupervisor::new(handoff, UnavailableRoleHandler::<HolderRole>::new(identity))?;
            serve_supervisor(supervisor, control, shutdown_signal).await
        }
        RuntimeRole::Committee => {
            let (identity, control) = {
                let config = handoff.committee().ok_or(AppError::RoleMismatch)?;
                (RuntimeHandlerIdentity::for_committee(config), config.control().clone())
            };
            let supervisor = CommitteeSupervisor::new(handoff, UnavailableRoleHandler::<CommitteeRole>::new(identity))?;
            serve_supervisor(supervisor, control, shutdown_signal).await
        }
    }
}

fn load_effective(config_path: &Path) -> Result<EffectiveRuntimeConfig, AppError> {
    Ok(ParsedRuntimeConfig::load_owner_only(config_path)?.validate_filesystem()?)
}

async fn serve_supervisor<'a, R, H, S>(
    supervisor: RuntimeSupervisor<'a, R, H>,
    mut control_config: ControlServerConfig,
    shutdown_signal: S,
) -> Result<(), AppError>
where
    R: RuntimeRoleMarker,
    H: RuntimeLifecycleHandler<R>,
    S: Future<Output = ()>,
{
    let monitor = supervisor.handle()?.monitor();
    let control_handler = supervisor.control_handler()?;
    control_config.recover_stale_socket = true;
    let control_server = match ControlServer::bind(control_config, control_handler).await {
        Ok(server) => server,
        Err(bind) => {
            let cleanup = CancellationToken::new();
            cleanup.cancel();
            return match supervisor.run(cleanup).await {
                Ok(()) => Err(AppError::Control(bind)),
                Err(cleanup) => Err(AppError::BindCleanup {
                    bind: bind.to_string(),
                    cleanup: cleanup.to_string(),
                }),
            };
        }
    };
    info!(
        role = ?monitor.status().role(),
        blocker_count = monitor.blockers().len(),
        "owner-only control bound; protocol readiness remains blocked"
    );

    let shutdown = CancellationToken::new();
    let runtime = supervisor.run(shutdown.clone());
    let control = control_server.run(shutdown.clone());
    tokio::pin!(runtime);
    tokio::pin!(control);
    tokio::pin!(shutdown_signal);

    let (runtime_result, control_result) = tokio::select! {
        runtime_result = &mut runtime => {
            shutdown.cancel();
            let control_result = control.await;
            (runtime_result, control_result)
        }
        control_result = &mut control => {
            shutdown.cancel();
            let runtime_result = runtime.await;
            (runtime_result, control_result)
        }
        () = &mut shutdown_signal => {
            shutdown.cancel();
            tokio::join!(runtime, control)
        }
    };
    combine_results(runtime_result, control_result)?;
    info!("operator runtime stopped cleanly");
    Ok(())
}

fn combine_results(
    runtime: thunderbolt_runtime::Result<()>,
    control: thunderbolt_control::Result<()>,
) -> Result<(), AppError> {
    match (runtime, control) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(runtime), Ok(())) => Err(AppError::Runtime(runtime)),
        (Ok(()), Err(control)) => Err(AppError::Control(control)),
        (Err(runtime), Err(control)) => Err(AppError::Concurrent {
            runtime: runtime.to_string(),
            control: control.to_string(),
        }),
    }
}

fn initialize_tracing(format: LogFormat) -> Result<(), AppError> {
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("thunderbolt=info,thunderboltd=info"));
    let result = match format {
        LogFormat::Json => tracing_subscriber::fmt()
            .with_env_filter(filter)
            .json()
            .flatten_event(true)
            .try_init(),
        LogFormat::Pretty => tracing_subscriber::fmt().with_env_filter(filter).pretty().try_init(),
    };
    result.map_err(|error| AppError::Tracing(error.to_string()))
}

fn install_shutdown_signal() -> Result<Pin<Box<dyn Future<Output = ()> + Send>>, AppError> {
    use tokio::signal::unix::{signal, SignalKind};

    let mut interrupt = signal(SignalKind::interrupt()).map_err(|error| AppError::Signal(error.to_string()))?;
    let mut terminate = signal(SignalKind::terminate()).map_err(|error| AppError::Signal(error.to_string()))?;
    Ok(Box::pin(async move {
        tokio::select! {
            _ = interrupt.recv() => {}
            _ = terminate.recv() => {}
        }
    }))
}

#[cfg(test)]
mod tests;
