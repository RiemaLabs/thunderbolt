#![forbid(unsafe_code)]

use std::fs::{File, OpenOptions};
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::str::FromStr;
use std::time::Duration;

use clap::{Args, Parser, Subcommand};
use reqwest::header::{HeaderValue, AUTHORIZATION, CONTENT_TYPE};
use reqwest::{Method, StatusCode, Url};
use serde_json::{json, Value};
use thiserror::Error;
use thunderbolt_config::{Config, ConfigError, Network, MAX_TOKEN_BYTES, MIN_TOKEN_BYTES};
use thunderbolt_protocol::{ChannelId, LedgerEntry};
use zeroize::Zeroizing;

const DEFAULT_CONFIG_PATH: &str = "thunderbolt.toml";
const MAX_RESPONSE_BYTES: usize = 16 * 1024 * 1024;

#[derive(Debug, Parser)]
#[command(
    name = "thunderbolt-cli",
    version,
    about = "Operator client for a Bitcoin Thunderbolt node"
)]
struct Cli {
    /// Local configuration used to discover the endpoint and token file.
    #[arg(long, global = true, default_value = DEFAULT_CONFIG_PATH)]
    config: PathBuf,

    /// Override the configured node endpoint.
    #[arg(long, global = true)]
    endpoint: Option<String>,

    /// Override the configured bearer-token file.
    #[arg(long, global = true)]
    token_file: Option<PathBuf>,

    /// Per-request timeout in seconds.
    #[arg(long, global = true)]
    timeout_seconds: Option<u64>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Query the unauthenticated liveness or readiness endpoint.
    Health(HealthArgs),
    /// Show public node identity, version, role, and safety mode.
    Getinfo,
    /// Inspect effective server configuration with secret paths redacted.
    Config {
        #[command(subcommand)]
        command: ConfigCommand,
    },
    /// Read channel state and immutable ledger events.
    Channel {
        #[command(subcommand)]
        command: ChannelCommand,
    },
    /// Submit protocol input.
    Submit {
        #[command(subcommand)]
        command: SubmitCommand,
    },
    /// Run authenticated database administration.
    Database {
        #[command(subcommand)]
        command: DatabaseCommand,
    },
    /// Ask the daemon to drain in-flight requests and stop.
    Stop,
}

#[derive(Debug, Args)]
struct HealthArgs {
    /// Query readiness instead of process liveness.
    #[arg(long)]
    ready: bool,
}

#[derive(Debug, Subcommand)]
enum ConfigCommand {
    Show,
}

#[derive(Debug, Subcommand)]
enum ChannelCommand {
    /// Get one materialized channel snapshot.
    Get { channel_id: String },
    /// List channel snapshots using a stable keyset cursor.
    List {
        #[arg(long)]
        after: Option<String>,
        #[arg(long, default_value_t = 100)]
        limit: usize,
    },
    /// List immutable events for one channel.
    Events {
        channel_id: String,
        #[arg(long)]
        after_sequence: Option<u64>,
        #[arg(long, default_value_t = 100)]
        limit: usize,
    },
    /// Get one immutable event by sequence.
    Event { channel_id: String, sequence: u64 },
}

#[derive(Debug, Subcommand)]
enum SubmitCommand {
    /// Submit a LedgerEntry JSON document; omit --file or use '-' for stdin.
    Event {
        #[arg(long)]
        file: Option<PathBuf>,
    },
}

#[derive(Debug, Subcommand)]
enum DatabaseCommand {
    /// Replay and verify SQLite plus every channel hash chain.
    Integrity,
    /// Create a no-clobber, verified online backup.
    Backup {
        /// Safe filename relative to the configured backup directory.
        #[arg(long)]
        filename: Option<String>,
    },
}

#[derive(Debug, Error)]
enum AppError {
    #[error("configuration failed: {0}")]
    Config(#[from] ConfigError),

    #[error("request failed: {0}")]
    Http(#[from] reqwest::Error),

    #[error("invalid endpoint: {0}")]
    Endpoint(String),

    #[error("I/O failed for {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: io::Error,
    },

    #[error("invalid JSON input: {0}")]
    Json(#[from] serde_json::Error),

    #[error("invalid bearer token file: {0}")]
    Token(String),

    #[error("input exceeds the configured request-body limit of {0} bytes")]
    InputTooLarge(usize),

    #[error("response exceeds the client safety limit of {MAX_RESPONSE_BYTES} bytes")]
    ResponseTooLarge,

    #[error("node returned HTTP {status}: {body}")]
    Server { status: StatusCode, body: String },

    #[error("mainnet is disabled in the 1.0 release candidate")]
    MainnetDisabled,
}

struct NodeClient {
    http: reqwest::Client,
    endpoint: Url,
    authorization: Option<HeaderValue>,
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
    let loaded_config = if cli.config.exists() {
        Some(Config::load(&cli.config)?)
    } else if cli.endpoint.is_none() {
        return Err(AppError::Io {
            path: cli.config.clone(),
            source: io::Error::new(io::ErrorKind::NotFound, "configuration file does not exist"),
        });
    } else {
        None
    };
    if loaded_config
        .as_ref()
        .is_some_and(|config| config.deployment.network == Network::Mainnet)
    {
        return Err(AppError::MainnetDisabled);
    }

    let endpoint = match (cli.endpoint.as_deref(), loaded_config.as_ref()) {
        (Some(endpoint), _) => endpoint.to_owned(),
        (None, Some(config)) => config.ledger.endpoint.clone(),
        (None, None) => {
            return Err(AppError::Endpoint(
                "provide --endpoint or an existing --config".to_owned(),
            ));
        }
    };
    let token_path = cli.token_file.or_else(|| {
        loaded_config
            .as_ref()
            .and_then(|config| config.ledger.auth_token_file.clone())
    });
    let timeout_seconds = cli.timeout_seconds.unwrap_or_else(|| {
        loaded_config
            .as_ref()
            .map_or(30, |config| (config.limits.request_timeout_ms / 1_000).max(1))
    });
    let input_limit = loaded_config
        .as_ref()
        .and_then(|config| usize::try_from(config.limits.max_request_body_bytes).ok())
        .unwrap_or(1024 * 1024);
    let client = NodeClient::new(&endpoint, token_path.as_deref(), timeout_seconds)?;

    let result = match cli.command {
        Command::Health(arguments) => {
            let path = if arguments.ready {
                "/v1/health/ready"
            } else {
                "/v1/health/live"
            };
            client.request(Method::GET, path, &[], None).await?
        }
        Command::Getinfo => client.request(Method::GET, "/v1/info", &[], None).await?,
        Command::Config {
            command: ConfigCommand::Show,
        } => client.request(Method::GET, "/v1/config", &[], None).await?,
        Command::Channel { command } => run_channel(&client, command).await?,
        Command::Submit {
            command: SubmitCommand::Event { file },
        } => submit_event(&client, file.as_deref(), input_limit).await?,
        Command::Database { command } => run_database(&client, command).await?,
        Command::Stop => {
            client
                .request(Method::POST, "/v1/admin/stop", &[], Some(json!({})))
                .await?
        }
    };
    print_json(&result)?;
    Ok(())
}

async fn run_channel(client: &NodeClient, command: ChannelCommand) -> Result<Value, AppError> {
    match command {
        ChannelCommand::Get { channel_id } => {
            let channel_id = parse_channel_id(&channel_id)?;
            client
                .request(Method::GET, &format!("/v1/channels/{channel_id}"), &[], None)
                .await
        }
        ChannelCommand::List { after, limit } => {
            let after = after
                .as_deref()
                .map(parse_channel_id)
                .transpose()?
                .map(|value| value.to_string());
            let limit = limit.to_string();
            let mut query = vec![("limit", limit.as_str())];
            if let Some(after) = after.as_deref() {
                query.push(("after", after));
            }
            client.request(Method::GET, "/v1/channels", &query, None).await
        }
        ChannelCommand::Events {
            channel_id,
            after_sequence,
            limit,
        } => {
            let channel_id = parse_channel_id(&channel_id)?;
            let limit = limit.to_string();
            let after_sequence = after_sequence.map(|value| value.to_string());
            let mut query = vec![("limit", limit.as_str())];
            if let Some(after_sequence) = after_sequence.as_deref() {
                query.push(("after_sequence", after_sequence));
            }
            client
                .request(Method::GET, &format!("/v1/channels/{channel_id}/events"), &query, None)
                .await
        }
        ChannelCommand::Event { channel_id, sequence } => {
            let channel_id = parse_channel_id(&channel_id)?;
            client
                .request(
                    Method::GET,
                    &format!("/v1/channels/{channel_id}/events/{sequence}"),
                    &[],
                    None,
                )
                .await
        }
    }
}

async fn submit_event(client: &NodeClient, file: Option<&Path>, input_limit: usize) -> Result<Value, AppError> {
    let bytes = match file {
        None => read_limited(&mut io::stdin().lock(), input_limit)?,
        Some(path) if path == Path::new("-") => read_limited(&mut io::stdin().lock(), input_limit)?,
        Some(path) => {
            let mut file = File::open(path).map_err(|source| AppError::Io {
                path: path.to_path_buf(),
                source,
            })?;
            read_limited(&mut file, input_limit)?
        }
    };
    let entry: LedgerEntry = serde_json::from_slice(&bytes)?;
    let channel_id = entry.channel_id;
    let body = serde_json::to_value(entry)?;
    client
        .request(
            Method::POST,
            &format!("/v1/channels/{channel_id}/events"),
            &[],
            Some(body),
        )
        .await
}

async fn run_database(client: &NodeClient, command: DatabaseCommand) -> Result<Value, AppError> {
    match command {
        DatabaseCommand::Integrity => {
            client
                .request(Method::POST, "/v1/database/integrity", &[], Some(json!({})))
                .await
        }
        DatabaseCommand::Backup { filename } => {
            client
                .request(
                    Method::POST,
                    "/v1/database/backup",
                    &[],
                    Some(json!({ "filename": filename })),
                )
                .await
        }
    }
}

impl NodeClient {
    fn new(endpoint: &str, token_file: Option<&Path>, timeout_seconds: u64) -> Result<Self, AppError> {
        let mut endpoint = Url::parse(endpoint).map_err(|error| AppError::Endpoint(error.to_string()))?;
        if !matches!(endpoint.scheme(), "http" | "https")
            || endpoint.host().is_none()
            || !endpoint.username().is_empty()
            || endpoint.password().is_some()
            || endpoint.query().is_some()
            || endpoint.fragment().is_some()
        {
            return Err(AppError::Endpoint(
                "expected an absolute http:// or https:// URL without credentials, query, or fragment".to_owned(),
            ));
        }
        let loopback = endpoint.host_str().is_some_and(|host| {
            host.eq_ignore_ascii_case("localhost")
                || host
                    .parse::<std::net::IpAddr>()
                    .is_ok_and(|address| address.is_loopback())
        });
        if endpoint.scheme() == "http" && !loopback {
            return Err(AppError::Endpoint(
                "cleartext HTTP is allowed only for a loopback endpoint".to_owned(),
            ));
        }
        endpoint.set_path("/");
        let authorization = token_file.map(load_authorization).transpose()?;
        let http = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(timeout_seconds.min(30)))
            .timeout(Duration::from_secs(timeout_seconds))
            .https_only(false)
            .build()?;
        Ok(Self {
            http,
            endpoint,
            authorization,
        })
    }

    async fn request(
        &self,
        method: Method,
        path: &str,
        query: &[(&str, &str)],
        body: Option<Value>,
    ) -> Result<Value, AppError> {
        let mut url = self.endpoint.clone();
        url.set_path(path);
        if !query.is_empty() {
            url.query_pairs_mut().extend_pairs(query.iter().copied());
        }
        let mut request = self.http.request(method, url);
        if let Some(authorization) = &self.authorization {
            request = request.header(AUTHORIZATION, authorization.clone());
        }
        if let Some(body) = body {
            request = request.header(CONTENT_TYPE, "application/json").json(&body);
        }
        let mut response = request.send().await?;
        let status = response.status();
        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await? {
            let next_length = bytes.len().checked_add(chunk.len()).ok_or(AppError::ResponseTooLarge)?;
            if next_length > MAX_RESPONSE_BYTES {
                return Err(AppError::ResponseTooLarge);
            }
            bytes.extend_from_slice(&chunk);
        }
        if !status.is_success() {
            let body = serde_json::from_slice::<Value>(&bytes)
                .map(|value| value.to_string())
                .unwrap_or_else(|_| String::from_utf8_lossy(&bytes).into_owned());
            return Err(AppError::Server { status, body });
        }
        if bytes.is_empty() {
            return Ok(json!({ "status": status.as_u16() }));
        }
        serde_json::from_slice(&bytes).map_err(AppError::from)
    }
}

fn parse_channel_id(value: &str) -> Result<ChannelId, AppError> {
    ChannelId::from_str(value).map_err(|error| AppError::Endpoint(format!("invalid channel id: {error}")))
}

fn read_limited(reader: &mut dyn Read, maximum: usize) -> Result<Vec<u8>, AppError> {
    let limit = u64::try_from(maximum)
        .ok()
        .and_then(|value| value.checked_add(1))
        .unwrap_or(u64::MAX);
    let mut bytes = Vec::with_capacity(maximum.min(64 * 1024));
    reader
        .take(limit)
        .read_to_end(&mut bytes)
        .map_err(|source| AppError::Io {
            path: PathBuf::from("<input>"),
            source,
        })?;
    if bytes.len() > maximum {
        return Err(AppError::InputTooLarge(maximum));
    }
    Ok(bytes)
}

fn load_authorization(path: &Path) -> Result<HeaderValue, AppError> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    }
    let mut file = options.open(path).map_err(|source| AppError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    let metadata = file.metadata().map_err(|source| AppError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    if !metadata.file_type().is_file() {
        return Err(AppError::Token("token path must be a regular file".to_owned()));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = metadata.permissions().mode() & 0o777;
        if !matches!(mode, 0o400 | 0o600) {
            return Err(AppError::Token(format!(
                "token file mode must be 0400 or 0600, found {mode:04o}"
            )));
        }
    }
    let mut token = Zeroizing::new(Vec::with_capacity(MAX_TOKEN_BYTES + 2));
    file.by_ref()
        .take((MAX_TOKEN_BYTES + 2) as u64)
        .read_to_end(&mut token)
        .map_err(|source| AppError::Io {
            path: path.to_path_buf(),
            source,
        })?;
    if token.ends_with(b"\n") {
        token.pop();
        if token.ends_with(b"\r") {
            token.pop();
        }
    }
    if token.len() < MIN_TOKEN_BYTES || token.len() > MAX_TOKEN_BYTES {
        return Err(AppError::Token(format!(
            "token must contain between {MIN_TOKEN_BYTES} and {MAX_TOKEN_BYTES} bytes"
        )));
    }
    if !token.iter().all(u8::is_ascii_graphic) {
        return Err(AppError::Token(
            "token must contain visible ASCII without whitespace".to_owned(),
        ));
    }
    let mut bearer = Zeroizing::new(Vec::with_capacity(7 + token.len()));
    bearer.extend_from_slice(b"Bearer ");
    bearer.extend_from_slice(&token);
    let mut header = HeaderValue::from_bytes(&bearer)
        .map_err(|error| AppError::Token(format!("token is not a valid HTTP credential: {error}")))?;
    header.set_sensitive(true);
    Ok(header)
}

fn print_json(value: &Value) -> Result<(), AppError> {
    println!("{}", serde_json::to_string_pretty(value)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remote_cleartext_endpoint_is_rejected() {
        let result = NodeClient::new("http://example.com/", None, 1);
        assert!(matches!(result, Err(AppError::Endpoint(_))));
    }

    #[cfg(unix)]
    #[test]
    fn bearer_token_symlinks_are_rejected() {
        use std::os::unix::fs::{symlink, PermissionsExt};

        let temporary = tempfile::TempDir::new().expect("temporary directory");
        let token_path = temporary.path().join("token");
        let link_path = temporary.path().join("token-link");
        std::fs::write(
            &token_path,
            b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n",
        )
        .expect("write token");
        std::fs::set_permissions(&token_path, std::fs::Permissions::from_mode(0o600)).expect("set token permissions");
        symlink(&token_path, &link_path).expect("create token symlink");
        assert!(load_authorization(&link_path).is_err());
    }
}
