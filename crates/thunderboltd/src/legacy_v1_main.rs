#![forbid(unsafe_code)]

use std::collections::BTreeSet;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Args, Parser, Subcommand, ValueEnum};
use thiserror::Error;
use thunderbolt_config::{Config, ConfigError, NodeRole, TokenConfig, TokenScope, TokenStore};
use thunderbolt_node::{validate_runtime_config, NodeError, NodeOptions, NodeServer};
use thunderbolt_storage::{SqliteStorage, StorageError};
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;
use zeroize::Zeroizing;

const DEFAULT_CONFIG_PATH: &str = "thunderbolt.toml";
const DEFAULT_DATA_DIR: &str = "data";

#[derive(Debug, Parser)]
#[command(
    name = "thunderboltd-legacy-v1",
    version,
    about = "Legacy version 1 Bitcoin Thunderbolt reference Ledger"
)]
struct Cli {
    /// Path to the node's TOML configuration.
    #[arg(long, global = true, default_value = DEFAULT_CONFIG_PATH)]
    config: PathBuf,

    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Create a safe regtest configuration and owner-only operator token.
    Init(InitArgs),
    /// Validate configuration, credentials, and an existing database.
    Check,
    /// Start the loopback JSON API.
    Start(StartArgs),
}

#[derive(Debug, Args)]
struct InitArgs {
    /// Directory for the database, logs, local socket reservation, and backups.
    #[arg(long, default_value = DEFAULT_DATA_DIR)]
    data_dir: PathBuf,

    /// Public node identifier.
    #[arg(long, default_value = "thunderbolt-node")]
    node_id: String,
}

#[derive(Debug, Args)]
struct StartArgs {
    /// Permit unverified state-machine demonstrations on development regtest.
    #[arg(long)]
    development_allow_unverified_demo_events: bool,

    /// Structured JSON is the default for production log collection.
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
    #[error("configuration failed: {0}")]
    Config(#[from] ConfigError),

    #[error("node preflight failed: {0}")]
    Node(#[from] NodeError),

    #[error("storage check failed: {0}")]
    Storage(#[from] StorageError),

    #[error("I/O failed for {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to encode generated configuration: {0}")]
    Toml(#[from] toml::ser::Error),

    #[error("refusing to overwrite existing path: {0}")]
    Exists(PathBuf),

    #[error("operating-system randomness is unavailable: {0}")]
    Random(String),

    #[error("failed to initialize tracing: {0}")]
    Tracing(String),

    #[error("database worker failed: {0}")]
    Worker(String),
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
        Command::Init(arguments) => initialize(&cli.config, arguments),
        Command::Check => check(&cli.config).await,
        Command::Start(arguments) => start(&cli.config, arguments).await,
    }
}

fn initialize(config_path: &Path, arguments: InitArgs) -> Result<(), AppError> {
    let token_path = arguments.data_dir.join("auth/operator.token");
    for path in [config_path, token_path.as_path()] {
        if path.exists() {
            return Err(AppError::Exists(path.to_path_buf()));
        }
    }

    if let Some(parent) = config_path.parent().filter(|path| !path.as_os_str().is_empty()) {
        create_private_directory(parent)?;
    }
    create_private_directory(&arguments.data_dir)?;
    create_private_directory(&arguments.data_dir.join("auth"))?;
    create_private_directory(&arguments.data_dir.join("logs"))?;
    create_private_directory(&arguments.data_dir.join("backups"))?;

    let mut config = Config::default();
    config.node.id = arguments.node_id;
    config.node.role = NodeRole::Ledger;
    config.paths.data_dir = arguments.data_dir.clone();
    config.paths.log_dir = arguments.data_dir.join("logs");
    config.paths.database_path = arguments.data_dir.join("thunderbolt.sqlite3");
    config.paths.socket_path = arguments.data_dir.join("thunderboltd.sock");
    config.backup.directory = arguments.data_dir.join("backups");
    config.metrics.enabled = false;
    config.ledger.endpoint = format!("http://{}:{}/", config.admin.bind_address, config.admin.port);
    config.ledger.auth_token_file = Some(token_path.clone());
    config.auth.tokens = vec![TokenConfig {
        id: config.node.id.clone(),
        token_file: token_path.clone(),
        scopes: BTreeSet::from([TokenScope::Admin]),
    }];
    config
        .validate()
        .map_err(|error| AppError::Node(NodeError::Configuration(error.to_string())))?;

    write_operator_token(&token_path)?;
    if let Err(error) = write_config(config_path, &config) {
        let _ = fs::remove_file(&token_path);
        return Err(error);
    }

    println!("initialized Bitcoin Thunderbolt node");
    println!("configuration: {}", config_path.display());
    println!("operator token: {}", token_path.display());
    println!("network: regtest (mainnet is disabled in this release candidate)");
    Ok(())
}

async fn check(config_path: &Path) -> Result<(), AppError> {
    let config = Config::load(config_path)?;
    validate_runtime_config(&config, NodeOptions::default())?;
    let tokens = TokenStore::load(&config.auth)
        .map_err(NodeError::from)
        .map_err(AppError::from)?;

    let database_path = config.paths.database_path.clone();
    let database_exists = database_path.exists();
    let integrity = if database_exists {
        Some(
            tokio::task::spawn_blocking(move || {
                let storage = SqliteStorage::open(database_path)?;
                storage.integrity_check()
            })
            .await
            .map_err(|error| AppError::Worker(error.to_string()))??,
        )
    } else {
        None
    };

    let output = serde_json::json!({
        "status": "ok",
        "tokens_loaded": tokens.len(),
        "database_initialized": database_exists,
        "integrity": integrity.map(|report| serde_json::json!({
            "channels_checked": report.channels_checked,
            "entries_checked": report.entries_checked,
        })),
        "mainnet_enabled": false,
    });
    println!(
        "{}",
        serde_json::to_string_pretty(&output).map_err(|error| AppError::Tracing(error.to_string()))?
    );
    Ok(())
}

async fn start(config_path: &Path, arguments: StartArgs) -> Result<(), AppError> {
    initialize_tracing(arguments.log_format)?;
    let config = Config::load(config_path)?;
    let options = NodeOptions {
        allow_unverified_demo_events: arguments.development_allow_unverified_demo_events,
    };
    let server = NodeServer::bind(config, options).await?;
    let address = server.local_addr()?;
    info!(%address, mainnet_enabled = false, "Bitcoin Thunderbolt node is ready");
    server.run(shutdown_signal()).await?;
    info!("Bitcoin Thunderbolt node stopped cleanly");
    Ok(())
}

fn initialize_tracing(format: LogFormat) -> Result<(), AppError> {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("thunderbolt=info,thunderboltd=info,tower_http=info"));
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

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};

        match signal(SignalKind::terminate()) {
            Ok(mut terminate) => {
                tokio::select! {
                    result = tokio::signal::ctrl_c() => {
                        if let Err(error) = result {
                            warn!(%error, "failed to listen for Ctrl-C");
                        }
                    }
                    _ = terminate.recv() => {}
                }
            }
            Err(error) => {
                warn!(%error, "failed to listen for SIGTERM");
                if let Err(error) = tokio::signal::ctrl_c().await {
                    warn!(%error, "failed to listen for Ctrl-C");
                }
            }
        }
    }

    #[cfg(not(unix))]
    if let Err(error) = tokio::signal::ctrl_c().await {
        warn!(%error, "failed to listen for Ctrl-C");
    }
}

fn create_private_directory(path: &Path) -> Result<(), AppError> {
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(path).map_err(|source| AppError::Io {
        path: path.to_path_buf(),
        source,
    })
}

fn write_operator_token(path: &Path) -> Result<(), AppError> {
    let mut random = Zeroizing::new([0_u8; 32]);
    getrandom::fill(&mut *random).map_err(|error| AppError::Random(error.to_string()))?;
    let mut encoded = Zeroizing::new(String::with_capacity(65));
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for byte in random.iter().copied() {
        encoded.push(HEX[usize::from(byte >> 4)] as char);
        encoded.push(HEX[usize::from(byte & 0x0f)] as char);
    }
    encoded.push('\n');

    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path).map_err(|source| AppError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    file.write_all(encoded.as_bytes())
        .and_then(|()| file.sync_all())
        .map_err(|source| AppError::Io {
            path: path.to_path_buf(),
            source,
        })
}

fn write_config(path: &Path, config: &Config) -> Result<(), AppError> {
    let document = format!(
        "# Bitcoin Thunderbolt 1.0 release-candidate configuration.\n\
         # Generated in safe development regtest mode. Mainnet is disabled.\n\
         # Token values belong only in owner-readable files, never in this document.\n\n{}",
        toml::to_string_pretty(config)?
    );
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o644);
    }
    let mut file = options.open(path).map_err(|source| AppError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    file.write_all(document.as_bytes())
        .and_then(|()| file.sync_all())
        .map_err(|source| AppError::Io {
            path: path.to_path_buf(),
            source,
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use thunderbolt_config::{Network, NodeRole};

    #[test]
    fn init_is_safe_regtest_and_never_overwrites_credentials() {
        let temporary = tempfile::TempDir::new().expect("temporary directory");
        let config_path = temporary.path().join("thunderbolt.toml");
        let data_dir = temporary.path().join("node-data");
        initialize(
            &config_path,
            InitArgs {
                data_dir: data_dir.clone(),
                node_id: "test-holder".to_owned(),
            },
        )
        .expect("first initialization");

        let token_path = data_dir.join("auth/operator.token");
        let original_config = fs::read(&config_path).expect("read generated config");
        let original_token = fs::read(&token_path).expect("read generated token");
        let second = initialize(
            &config_path,
            InitArgs {
                data_dir,
                node_id: "replacement".to_owned(),
            },
        );
        assert!(matches!(second, Err(AppError::Exists(_))));
        assert_eq!(fs::read(&config_path).expect("reread config"), original_config);
        assert_eq!(fs::read(&token_path).expect("reread token"), original_token);

        let config = Config::load(&config_path).expect("load generated config");
        assert_eq!(config.deployment.network, Network::Regtest);
        assert_eq!(config.node.role, NodeRole::Ledger);
        assert_eq!(config.auth.tokens[0].id, "test-holder");
        assert_eq!(original_token.len(), 65);

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(token_path).expect("token metadata").permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
    }
}
