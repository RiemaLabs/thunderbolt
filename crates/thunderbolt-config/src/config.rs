use crate::error::{ConfigError, ValidationErrors};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashSet};
use std::env;
use std::ffi::{OsStr, OsString};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr};
use std::path::{Component, Path, PathBuf};
use std::time::Duration;
use toml::Value;
use url::{Host, Url};

/// A commented, regtest release-candidate configuration template.
pub const SAMPLE_CONFIG: &str = include_str!("../sample-config.toml");

const ENV_PREFIX: &str = "THUNDERBOLT_";

/// A complete Bitcoin Thunderbolt node configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub config_version: u32,
    pub node: NodeConfig,
    pub deployment: DeploymentConfig,
    pub paths: PathsConfig,
    pub committee: CommitteeConfig,
    pub admin: AdminConfig,
    pub ledger: LedgerConfig,
    pub limits: LimitsConfig,
    pub metrics: MetricsConfig,
    pub backup: BackupConfig,
    pub auth: AuthConfig,
    pub development: DevelopmentConfig,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            config_version: 1,
            node: NodeConfig::default(),
            deployment: DeploymentConfig::default(),
            paths: PathsConfig::default(),
            committee: CommitteeConfig::default(),
            admin: AdminConfig::default(),
            ledger: LedgerConfig::default(),
            limits: LimitsConfig::default(),
            metrics: MetricsConfig::default(),
            backup: BackupConfig::default(),
            auth: AuthConfig::default(),
            development: DevelopmentConfig::default(),
        }
    }
}

impl Config {
    /// Loads TOML from `path`, applies process environment overrides, and validates it.
    ///
    /// Override names use `THUNDERBOLT_` plus `__` between nested fields. For example,
    /// `THUNDERBOLT_ADMIN__PORT=29736` overrides `admin.port`.
    pub fn load(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let path = path.as_ref();
        let source = fs::read_to_string(path).map_err(|source| ConfigError::Read {
            path: path.to_path_buf(),
            source,
        })?;
        Self::from_toml_str_with_env(&source, env::vars_os())
    }

    /// Parses TOML on top of safe defaults without consulting the process environment.
    pub fn from_toml_str(source: &str) -> Result<Self, ConfigError> {
        Self::from_toml_str_with_env(source, std::iter::empty::<(OsString, OsString)>())
    }

    /// Parses TOML and applies a supplied environment iterator.
    ///
    /// This is useful to make configuration assembly deterministic in launchers and tests.
    pub fn from_toml_str_with_env<I, K, V>(source: &str, variables: I) -> Result<Self, ConfigError>
    where
        I: IntoIterator<Item = (K, V)>,
        K: AsRef<OsStr>,
        V: AsRef<OsStr>,
    {
        let mut effective = Value::try_from(Self::default())?;
        let supplied: Value = toml::from_str(source)?;
        merge_toml(&mut effective, supplied);
        apply_environment(&mut effective, variables)?;

        let config: Self = effective.try_into()?;
        config.validate()?;
        Ok(config)
    }

    /// Validates cross-field safety properties and operational limits.
    pub fn validate(&self) -> Result<(), ValidationErrors> {
        let mut errors = Vec::new();

        if self.config_version != 1 {
            errors.push("config_version must be 1".to_owned());
        }

        validate_node_id(&self.node.id, &mut errors);
        validate_deployment_id(&self.deployment.id, &mut errors);
        validate_port("node.listen_port", self.node.listen_port, &mut errors);
        if self.admin.enabled {
            validate_port("admin.port", self.admin.port, &mut errors);
        }
        if self.metrics.enabled {
            validate_port("metrics.port", self.metrics.port, &mut errors);
        }

        if self.admin.enabled
            && endpoints_overlap(
                self.node.listen_address,
                self.node.listen_port,
                self.admin.bind_address,
                self.admin.port,
            )
        {
            errors.push("node and admin listeners must use different ports".to_owned());
        }
        if self.admin.enabled
            && self.metrics.enabled
            && endpoints_overlap(
                self.admin.bind_address,
                self.admin.port,
                self.metrics.bind_address,
                self.metrics.port,
            )
        {
            errors.push("admin and metrics listeners must use different ports".to_owned());
        }
        if self.metrics.enabled
            && endpoints_overlap(
                self.node.listen_address,
                self.node.listen_port,
                self.metrics.bind_address,
                self.metrics.port,
            )
        {
            errors.push("node and metrics listeners must use different ports".to_owned());
        }

        if self.admin.enabled && !self.admin.bind_address.is_loopback() && !self.admin.remote_http {
            errors
                .push("admin.bind_address must be loopback unless admin.remote_http is explicitly enabled".to_owned());
        }
        if self.admin.remote_http && !self.admin.enabled {
            errors.push("admin.remote_http cannot be enabled while the admin server is disabled".to_owned());
        }
        validate_admin_tls(self, &mut errors);

        if self.metrics.enabled && !self.metrics.bind_address.is_loopback() && !self.metrics.allow_remote {
            errors.push(
                "metrics.bind_address must be loopback unless metrics.allow_remote is explicitly enabled".to_owned(),
            );
        }
        if !self.metrics.path.starts_with('/') || self.metrics.path.contains(char::is_whitespace) {
            errors.push("metrics.path must be an absolute HTTP path without whitespace".to_owned());
        }

        validate_committee(&self.committee, &mut errors);
        validate_limits(&self.limits, &mut errors);
        validate_ledger(self, &mut errors);
        validate_paths(self, &mut errors);
        validate_backup(self, &mut errors);
        validate_auth(self, &mut errors);
        validate_deployment_safety(self, &mut errors);

        if errors.is_empty() {
            Ok(())
        } else {
            Err(ValidationErrors::new(errors))
        }
    }

    /// Returns a clone with secret-bearing file locations replaced.
    pub fn redacted(&self) -> Self {
        let mut redacted = self.clone();
        if redacted.admin.tls.private_key_path.is_some() {
            redacted.admin.tls.private_key_path = Some(PathBuf::from("<redacted>"));
        }
        if redacted.ledger.auth_token_file.is_some() {
            redacted.ledger.auth_token_file = Some(PathBuf::from("<redacted>"));
        }
        if redacted.backup.encryption_key_file.is_some() {
            redacted.backup.encryption_key_file = Some(PathBuf::from("<redacted>"));
        }
        for token in &mut redacted.auth.tokens {
            token.token_file = PathBuf::from("<redacted>");
        }
        redacted
    }

    /// Renders the fully merged, validated configuration without secret-bearing paths.
    pub fn effective_redacted_toml(&self) -> Result<String, ConfigError> {
        Ok(toml::to_string_pretty(&self.redacted())?)
    }

    /// Returns the built-in, commented regtest configuration template.
    pub fn sample_toml() -> &'static str {
        SAMPLE_CONFIG
    }

    /// Writes the built-in sample without replacing an existing file.
    pub fn write_sample(path: impl AsRef<Path>) -> Result<(), ConfigError> {
        let path = path.as_ref();
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o644);
        }
        let mut file = options.open(path).map_err(|source| ConfigError::WriteSample {
            path: path.to_path_buf(),
            source,
        })?;
        file.write_all(SAMPLE_CONFIG.as_bytes())
            .and_then(|_| file.sync_all())
            .map_err(|source| ConfigError::WriteSample {
                path: path.to_path_buf(),
                source,
            })
    }
}

/// The protocol role this process performs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum NodeRole {
    /// Owns funds and initiates transfers.
    Holder,
    /// Co-signs protocol operations as a threshold committee member.
    Committee,
    /// Provides the ledger-facing service.
    Ledger,
}

/// Runtime hardening profile, deliberately separate from the Bitcoin network.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Environment {
    Development,
    Staging,
    Production,
}

/// Bitcoin ledger network.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Network {
    Regtest,
    Signet,
    Testnet,
    Mainnet,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct NodeConfig {
    pub id: String,
    pub role: NodeRole,
    pub listen_address: IpAddr,
    pub listen_port: u16,
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            id: "thunderbolt-node".to_owned(),
            role: NodeRole::Holder,
            listen_address: IpAddr::V4(Ipv4Addr::LOCALHOST),
            listen_port: 19_735,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DeploymentConfig {
    pub environment: Environment,
    pub network: Network,
    /// Stable proof-domain identifier shared by every participant.
    pub id: String,
}

impl Default for DeploymentConfig {
    fn default() -> Self {
        Self {
            environment: Environment::Development,
            network: Network::Regtest,
            id: "thunderbolt-regtest-v1".to_owned(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct PathsConfig {
    pub data_dir: PathBuf,
    pub log_dir: PathBuf,
    pub database_path: PathBuf,
    pub socket_path: PathBuf,
}

impl Default for PathsConfig {
    fn default() -> Self {
        Self {
            data_dir: PathBuf::from("./data"),
            log_dir: PathBuf::from("./data/logs"),
            database_path: PathBuf::from("./data/thunderbolt.sqlite3"),
            socket_path: PathBuf::from("./data/thunderboltd.sock"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct CommitteeConfig {
    pub members: u16,
    pub signing_threshold: u16,
    /// Monotonic roster and share epoch bound into protocol messages.
    pub epoch: u64,
}

impl Default for CommitteeConfig {
    fn default() -> Self {
        Self {
            members: 3,
            signing_threshold: 2,
            epoch: 1,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AdminConfig {
    pub enabled: bool,
    pub bind_address: IpAddr,
    pub port: u16,
    pub remote_http: bool,
    pub tls: AdminTlsConfig,
}

impl Default for AdminConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            bind_address: IpAddr::V4(Ipv4Addr::LOCALHOST),
            port: 19_736,
            remote_http: false,
            tls: AdminTlsConfig::default(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct AdminTlsConfig {
    pub enabled: bool,
    pub certificate_path: Option<PathBuf>,
    pub private_key_path: Option<PathBuf>,
    pub client_ca_path: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct LedgerConfig {
    pub endpoint: String,
    pub auth_token_file: Option<PathBuf>,
}

impl Default for LedgerConfig {
    fn default() -> Self {
        Self {
            endpoint: "http://127.0.0.1:18443/".to_owned(),
            auth_token_file: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct LimitsConfig {
    pub max_request_header_bytes: u64,
    pub max_request_body_bytes: u64,
    pub max_concurrent_requests: u32,
    pub connect_timeout_ms: u64,
    pub request_timeout_ms: u64,
    pub idle_timeout_ms: u64,
    pub graceful_shutdown_timeout_ms: u64,
}

impl Default for LimitsConfig {
    fn default() -> Self {
        Self {
            max_request_header_bytes: 32 * 1024,
            max_request_body_bytes: 1024 * 1024,
            max_concurrent_requests: 256,
            connect_timeout_ms: 5_000,
            request_timeout_ms: 30_000,
            idle_timeout_ms: 60_000,
            graceful_shutdown_timeout_ms: 30_000,
        }
    }
}

impl LimitsConfig {
    pub fn connect_timeout(&self) -> Duration {
        Duration::from_millis(self.connect_timeout_ms)
    }

    pub fn request_timeout(&self) -> Duration {
        Duration::from_millis(self.request_timeout_ms)
    }

    pub fn idle_timeout(&self) -> Duration {
        Duration::from_millis(self.idle_timeout_ms)
    }

    pub fn graceful_shutdown_timeout(&self) -> Duration {
        Duration::from_millis(self.graceful_shutdown_timeout_ms)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct MetricsConfig {
    pub enabled: bool,
    pub bind_address: IpAddr,
    pub port: u16,
    pub path: String,
    pub allow_remote: bool,
}

impl Default for MetricsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            bind_address: IpAddr::V4(Ipv4Addr::LOCALHOST),
            port: 19_090,
            path: "/metrics".to_owned(),
            allow_remote: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct BackupConfig {
    pub enabled: bool,
    pub directory: PathBuf,
    pub interval_seconds: u64,
    pub retention_count: u16,
    pub verify_after_write: bool,
    pub encryption_key_file: Option<PathBuf>,
}

impl Default for BackupConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            directory: PathBuf::from("./data/backups"),
            interval_seconds: 3_600,
            retention_count: 24,
            verify_after_write: true,
            encryption_key_file: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AuthConfig {
    pub enabled: bool,
    pub tokens: Vec<TokenConfig>,
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            tokens: vec![TokenConfig {
                id: "local-operator".to_owned(),
                token_file: PathBuf::from("./data/auth/operator.token"),
                scopes: BTreeSet::from([TokenScope::Admin]),
            }],
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TokenConfig {
    pub id: String,
    pub token_file: PathBuf,
    pub scopes: BTreeSet<TokenScope>,
}

/// Authorization scopes, ordered from least to most privileged.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TokenScope {
    Read,
    Write,
    Operator,
    Admin,
}

impl TokenScope {
    /// Returns whether this scope includes `required` in the built-in privilege hierarchy.
    pub fn allows(self, required: Self) -> bool {
        self >= required
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct DevelopmentConfig {
    pub allow_insecure_ledger_http: bool,
    pub allow_unauthenticated_admin: bool,
    pub accept_invalid_tls_certificates: bool,
    pub allow_ephemeral_storage: bool,
}

fn merge_toml(target: &mut Value, supplied: Value) {
    match (target, supplied) {
        (Value::Table(target), Value::Table(supplied)) => {
            for (key, value) in supplied {
                match target.get_mut(&key) {
                    Some(existing) => merge_toml(existing, value),
                    None => {
                        target.insert(key, value);
                    }
                }
            }
        }
        (target, supplied) => *target = supplied,
    }
}

fn apply_environment<I, K, V>(root: &mut Value, variables: I) -> Result<(), ConfigError>
where
    I: IntoIterator<Item = (K, V)>,
    K: AsRef<OsStr>,
    V: AsRef<OsStr>,
{
    for (raw_name, raw_value) in variables {
        let name = match raw_name.as_ref().to_str() {
            Some(name) if name.starts_with(ENV_PREFIX) => name,
            _ => continue,
        };
        let value = raw_value.as_ref().to_str().ok_or_else(|| ConfigError::Environment {
            variable: name.to_owned(),
            reason: "value is not valid UTF-8",
        })?;
        let suffix = &name[ENV_PREFIX.len()..];
        let path = environment_path(suffix).ok_or_else(|| ConfigError::Environment {
            variable: name.to_owned(),
            reason: "use non-empty field names separated by double underscores",
        })?;
        set_environment_value(root, &path, value).map_err(|reason| ConfigError::Environment {
            variable: name.to_owned(),
            reason,
        })?;
    }
    Ok(())
}

fn environment_path(suffix: &str) -> Option<Vec<String>> {
    let alias: Option<&[&str]> = match suffix {
        "ROLE" => Some(&["node", "role"]),
        "ENVIRONMENT" => Some(&["deployment", "environment"]),
        "NETWORK" => Some(&["deployment", "network"]),
        "DATA_DIR" => Some(&["paths", "data_dir"]),
        "LOG_DIR" => Some(&["paths", "log_dir"]),
        "DATABASE_PATH" => Some(&["paths", "database_path"]),
        "SOCKET_PATH" => Some(&["paths", "socket_path"]),
        "LEDGER_ENDPOINT" => Some(&["ledger", "endpoint"]),
        _ => None,
    };
    if let Some(alias) = alias {
        return Some(alias.iter().map(|part| (*part).to_owned()).collect());
    }

    let parts: Vec<String> = suffix.split("__").map(|part| part.to_ascii_lowercase()).collect();
    if parts.is_empty() || parts.iter().any(String::is_empty) {
        None
    } else {
        Some(parts)
    }
}

fn set_environment_value(root: &mut Value, path: &[String], raw_value: &str) -> Result<(), &'static str> {
    let (leaf, parents) = path.split_last().ok_or("override path is empty")?;
    let mut cursor = root;
    for segment in parents {
        let table = cursor.as_table_mut().ok_or("override traverses a non-table field")?;
        cursor = table
            .entry(segment.clone())
            .or_insert_with(|| Value::Table(Default::default()));
    }
    let table = cursor.as_table_mut().ok_or("override parent is not a table")?;
    let parsed = match table.get(leaf) {
        Some(existing) => parse_environment_like(existing, raw_value)?,
        None => parse_environment_unknown(raw_value)?,
    };
    table.insert(leaf.clone(), parsed);
    Ok(())
}

fn parse_environment_like(existing: &Value, raw: &str) -> Result<Value, &'static str> {
    match existing {
        Value::String(_) => Ok(Value::String(raw.to_owned())),
        Value::Integer(_) => raw
            .parse::<i64>()
            .map(Value::Integer)
            .map_err(|_| "expected an integer"),
        Value::Float(_) => raw
            .parse::<f64>()
            .map(Value::Float)
            .map_err(|_| "expected a floating-point value"),
        Value::Boolean(_) => raw
            .parse::<bool>()
            .map(Value::Boolean)
            .map_err(|_| "expected true or false"),
        Value::Array(_) => parse_toml_value(raw).and_then(|value| {
            if value.is_array() {
                Ok(value)
            } else {
                Err("expected a TOML array")
            }
        }),
        Value::Datetime(_) => parse_toml_value(raw).and_then(|value| {
            if value.is_datetime() {
                Ok(value)
            } else {
                Err("expected a TOML datetime")
            }
        }),
        Value::Table(_) => Err("cannot replace a table; override one of its fields"),
    }
}

fn parse_environment_unknown(raw: &str) -> Result<Value, &'static str> {
    if raw.eq_ignore_ascii_case("true") || raw.eq_ignore_ascii_case("false") {
        return raw
            .parse::<bool>()
            .map(Value::Boolean)
            .map_err(|_| "expected true or false");
    }
    if raw.starts_with('[') || raw.starts_with('{') {
        return parse_toml_value(raw);
    }
    Ok(Value::String(raw.to_owned()))
}

fn parse_toml_value(raw: &str) -> Result<Value, &'static str> {
    let wrapped = format!("value = {raw}");
    let table: toml::Table = toml::from_str(&wrapped).map_err(|_| "invalid TOML value")?;
    table.get("value").cloned().ok_or("invalid TOML value")
}

fn validate_node_id(id: &str, errors: &mut Vec<String>) {
    if id.is_empty() || id.len() > 64 {
        errors.push("node.id must contain between 1 and 64 characters".to_owned());
    } else if !id
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        errors.push("node.id may contain only ASCII letters, digits, '.', '_' and '-'".to_owned());
    }
}

fn validate_deployment_id(id: &str, errors: &mut Vec<String>) {
    if id.is_empty() || id.len() > 64 {
        errors.push("deployment.id must contain between 1 and 64 characters".to_owned());
    } else if !id
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        errors.push("deployment.id may contain only ASCII letters, digits, '.', '_' and '-'".to_owned());
    }
}

fn validate_port(name: &str, port: u16, errors: &mut Vec<String>) {
    if port == 0 {
        errors.push(format!("{name} must be between 1 and 65535"));
    }
}

fn endpoints_overlap(left_address: IpAddr, left_port: u16, right_address: IpAddr, right_port: u16) -> bool {
    if left_port != right_port {
        return false;
    }
    left_address == right_address || left_address.is_unspecified() || right_address.is_unspecified()
}

fn validate_admin_tls(config: &Config, errors: &mut Vec<String>) {
    let admin = &config.admin;
    if admin.remote_http && !admin.tls.enabled {
        errors.push("remote admin HTTP requires admin.tls.enabled".to_owned());
    }
    if admin.tls.enabled {
        match admin.tls.certificate_path.as_deref() {
            Some(path) => {
                validate_nonempty_path("admin.tls.certificate_path", path, errors);
                validate_production_absolute(config, "admin.tls.certificate_path", path, errors);
            }
            None => errors.push("admin TLS requires a certificate_path".to_owned()),
        }
        match admin.tls.private_key_path.as_deref() {
            Some(path) => {
                validate_nonempty_path("admin.tls.private_key_path", path, errors);
                validate_production_absolute(config, "admin.tls.private_key_path", path, errors);
            }
            None => errors.push("admin TLS requires a private_key_path".to_owned()),
        }
        if admin.tls.certificate_path == admin.tls.private_key_path && admin.tls.certificate_path.is_some() {
            errors.push("admin TLS certificate and private key paths must differ".to_owned());
        }
        if let Some(path) = admin.tls.client_ca_path.as_deref() {
            validate_nonempty_path("admin.tls.client_ca_path", path, errors);
            validate_production_absolute(config, "admin.tls.client_ca_path", path, errors);
        }
    }
}

fn validate_committee(committee: &CommitteeConfig, errors: &mut Vec<String>) {
    if committee.members == 0 || committee.members > 256 {
        errors.push("committee.members must be between 1 and 256".to_owned());
    }
    if committee.signing_threshold == 0 || committee.signing_threshold > committee.members {
        errors.push("committee.signing_threshold must be between 1 and committee.members".to_owned());
    }
    if committee.epoch == 0 {
        errors.push("committee.epoch must be positive".to_owned());
    }
}

fn validate_limits(limits: &LimitsConfig, errors: &mut Vec<String>) {
    validate_range(
        "limits.max_request_header_bytes",
        limits.max_request_header_bytes,
        1_024,
        1024 * 1024,
        errors,
    );
    validate_range(
        "limits.max_request_body_bytes",
        limits.max_request_body_bytes,
        1_024,
        64 * 1024 * 1024,
        errors,
    );
    validate_range(
        "limits.max_concurrent_requests",
        u64::from(limits.max_concurrent_requests),
        1,
        65_535,
        errors,
    );
    for (name, value) in [
        ("limits.connect_timeout_ms", limits.connect_timeout_ms),
        ("limits.request_timeout_ms", limits.request_timeout_ms),
        ("limits.idle_timeout_ms", limits.idle_timeout_ms),
        (
            "limits.graceful_shutdown_timeout_ms",
            limits.graceful_shutdown_timeout_ms,
        ),
    ] {
        validate_range(name, value, 100, 24 * 60 * 60 * 1_000, errors);
    }
}

fn validate_range(name: &str, value: u64, minimum: u64, maximum: u64, errors: &mut Vec<String>) {
    if !(minimum..=maximum).contains(&value) {
        errors.push(format!("{name} must be between {minimum} and {maximum}"));
    }
}

fn validate_ledger(config: &Config, errors: &mut Vec<String>) {
    let endpoint = match Url::parse(&config.ledger.endpoint) {
        Ok(endpoint) => endpoint,
        Err(_) => {
            errors.push("ledger.endpoint must be an absolute http:// or https:// URL".to_owned());
            return;
        }
    };
    if !endpoint.username().is_empty() || endpoint.password().is_some() {
        errors.push("ledger.endpoint must not contain inline credentials; use auth_token_file".to_owned());
    }
    let scheme = endpoint.scheme();
    if !matches!(scheme, "http" | "https") || endpoint.host().is_none() {
        errors.push("ledger.endpoint must be an absolute http:// or https:// URL".to_owned());
        return;
    }
    if endpoint.fragment().is_some() || endpoint.query().is_some() {
        errors.push("ledger.endpoint must not contain a query string or fragment".to_owned());
    }

    if scheme == "http" {
        let local = match endpoint.host() {
            Some(Host::Domain(host)) => host.eq_ignore_ascii_case("localhost"),
            Some(Host::Ipv4(address)) => address.is_loopback(),
            Some(Host::Ipv6(address)) => address.is_loopback(),
            None => false,
        };
        if !local && !config.development.allow_insecure_ledger_http {
            errors.push("non-loopback ledger HTTP requires development.allow_insecure_ledger_http".to_owned());
        }
    }
    if let Some(path) = config.ledger.auth_token_file.as_deref() {
        validate_nonempty_path("ledger.auth_token_file", path, errors);
        validate_production_absolute(config, "ledger.auth_token_file", path, errors);
    }
}

fn validate_paths(config: &Config, errors: &mut Vec<String>) {
    let paths = [
        ("paths.data_dir", config.paths.data_dir.as_path()),
        ("paths.log_dir", config.paths.log_dir.as_path()),
        ("paths.database_path", config.paths.database_path.as_path()),
        ("paths.socket_path", config.paths.socket_path.as_path()),
    ];
    for (name, path) in paths {
        validate_nonempty_path(name, path, errors);
        if path.components().any(|component| component == Component::ParentDir) {
            errors.push(format!("{name} must not contain '..'"));
        }
        if config.deployment.environment == Environment::Production && !path.is_absolute() {
            errors.push(format!("{name} must be absolute in production"));
        }
    }

    if config.paths.data_dir == Path::new("/") {
        errors.push("paths.data_dir must not be the filesystem root".to_owned());
    }
    if config.paths.database_path == config.paths.data_dir || config.paths.socket_path == config.paths.data_dir {
        errors.push("database_path and socket_path must name files, not data_dir".to_owned());
    }
    if config.deployment.environment == Environment::Production {
        for (name, path) in [
            ("paths.log_dir", config.paths.log_dir.as_path()),
            ("paths.database_path", config.paths.database_path.as_path()),
            ("paths.socket_path", config.paths.socket_path.as_path()),
        ] {
            if !path.starts_with(&config.paths.data_dir) {
                errors.push(format!("{name} must be inside paths.data_dir in production"));
            }
        }
    }

    #[cfg(unix)]
    if config.paths.socket_path.as_os_str().as_encoded_bytes().len() > 100 {
        errors.push("paths.socket_path is too long for a portable Unix-domain socket".to_owned());
    }
}

fn validate_nonempty_path(name: &str, path: &Path, errors: &mut Vec<String>) {
    if path.as_os_str().is_empty() {
        errors.push(format!("{name} must not be empty"));
    }
}

fn validate_production_absolute(config: &Config, name: &str, path: &Path, errors: &mut Vec<String>) {
    if config.deployment.environment == Environment::Production && !path.is_absolute() {
        errors.push(format!("{name} must be absolute in production"));
    }
}

fn validate_backup(config: &Config, errors: &mut Vec<String>) {
    validate_nonempty_path("backup.directory", &config.backup.directory, errors);
    if config
        .backup
        .directory
        .components()
        .any(|component| component == Component::ParentDir)
    {
        errors.push("backup.directory must not contain '..'".to_owned());
    }
    if config.deployment.environment == Environment::Production && !config.backup.directory.is_absolute() {
        errors.push("backup.directory must be absolute in production".to_owned());
    }
    if config.backup.enabled {
        validate_range(
            "backup.interval_seconds",
            config.backup.interval_seconds,
            60,
            31 * 24 * 60 * 60,
            errors,
        );
        validate_range(
            "backup.retention_count",
            u64::from(config.backup.retention_count),
            1,
            3_650,
            errors,
        );
        if !config.backup.verify_after_write {
            errors.push("enabled backups must set backup.verify_after_write=true".to_owned());
        }
        if let Some(path) = config.backup.encryption_key_file.as_deref() {
            validate_nonempty_path("backup.encryption_key_file", path, errors);
            validate_production_absolute(config, "backup.encryption_key_file", path, errors);
        }
    }
}

fn validate_auth(config: &Config, errors: &mut Vec<String>) {
    if config.auth.enabled && config.auth.tokens.is_empty() {
        errors.push("auth.tokens must contain at least one token when authentication is enabled".to_owned());
    }
    if !config.auth.enabled && config.admin.enabled && !config.development.allow_unauthenticated_admin {
        errors.push(
            "disabling auth for an enabled admin server requires development.allow_unauthenticated_admin".to_owned(),
        );
    }

    let mut ids = HashSet::new();
    let mut files = HashSet::new();
    for token in &config.auth.tokens {
        validate_node_id(&token.id, errors);
        validate_nonempty_path("auth.tokens[].token_file", &token.token_file, errors);
        if token
            .token_file
            .components()
            .any(|component| component == Component::ParentDir)
        {
            errors.push("auth token paths must not contain '..'".to_owned());
        }
        if config.deployment.environment == Environment::Production && !token.token_file.is_absolute() {
            errors.push("auth token paths must be absolute in production".to_owned());
        }
        if token.scopes.is_empty() {
            errors.push(format!("auth token '{}' must have at least one scope", token.id));
        }
        if !ids.insert(token.id.clone()) {
            errors.push(format!("auth token id '{}' is duplicated", token.id));
        }
        if !files.insert(token.token_file.clone()) {
            errors.push("each auth token must use a distinct token_file".to_owned());
        }
    }
}

fn validate_deployment_safety(config: &Config, errors: &mut Vec<String>) {
    if config.deployment.network == Network::Mainnet {
        errors.push("mainnet is disabled in version 1.0".to_owned());
    }

    let unsafe_flags = [
        (
            "development.allow_insecure_ledger_http",
            config.development.allow_insecure_ledger_http,
        ),
        (
            "development.allow_unauthenticated_admin",
            config.development.allow_unauthenticated_admin,
        ),
        (
            "development.accept_invalid_tls_certificates",
            config.development.accept_invalid_tls_certificates,
        ),
        (
            "development.allow_ephemeral_storage",
            config.development.allow_ephemeral_storage,
        ),
    ];
    if config.deployment.environment == Environment::Production || config.deployment.network == Network::Mainnet {
        for (name, enabled) in unsafe_flags {
            if enabled {
                errors.push(format!("{name} is forbidden in production and on mainnet"));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn safe_defaults_validate_and_keep_admin_local() {
        let config = Config::default();
        config.validate().expect("safe defaults should validate");
        assert!(config.admin.bind_address.is_loopback());
        assert!(!config.admin.remote_http);
        assert!(config.auth.enabled);
        assert_eq!(config.deployment.network, Network::Regtest);
        assert_eq!(config.deployment.environment, Environment::Development);
    }

    #[test]
    fn redaction_removes_all_secret_file_locations() {
        let source = r#"
[admin.tls]
enabled = false
private_key_path = "/sensitive/admin.key"

[ledger]
auth_token_file = "/sensitive/ledger.token"

[backup]
encryption_key_file = "/sensitive/backup.key"

[[auth.tokens]]
id = "operator"
token_file = "/sensitive/operator.token"
scopes = ["admin"]
"#;
        let config = Config::from_toml_str(source).expect("config should parse");
        let rendered = config.effective_redacted_toml().expect("redacted config should render");
        assert!(!rendered.contains("/sensitive/"));
        assert!(rendered.matches("<redacted>").count() >= 4);
    }

    #[test]
    fn environment_takes_precedence_over_file() {
        let source = r#"
[node]
role = "holder"

[admin]
port = 21000
"#;
        let variables = [("THUNDERBOLT_ROLE", "committee"), ("THUNDERBOLT_ADMIN__PORT", "22000")];
        let config = Config::from_toml_str_with_env(source, variables).expect("environment should override file");
        assert_eq!(config.node.role, NodeRole::Committee);
        assert_eq!(config.admin.port, 22_000);
    }

    #[test]
    fn unsafe_admin_bind_is_rejected() {
        let source = r#"
[admin]
bind_address = "0.0.0.0"
remote_http = false
"#;
        let error = Config::from_toml_str(source).expect_err("public admin bind must fail");
        assert!(error.to_string().contains("admin.bind_address must be loopback"));
    }

    #[test]
    fn deployment_id_and_committee_epoch_are_mandatory_proof_bindings() {
        let mut config = Config::default();
        config.deployment.id.clear();
        config.committee.epoch = 0;
        let error = config.validate().expect_err("missing proof bindings must fail");
        assert!(error.to_string().contains("deployment.id"));
        assert!(error.to_string().contains("committee.epoch"));
    }

    #[test]
    fn committee_size_matches_the_wire_roster_limit() {
        let mut config = Config::default();
        config.committee.members = 257;
        let error = config.validate().expect_err("oversized committee roster must fail");
        assert!(error.to_string().contains("between 1 and 256"));
    }

    #[test]
    fn remote_admin_requires_certificate_and_key() {
        let source = r#"
[admin]
bind_address = "0.0.0.0"
remote_http = true
"#;
        let error = Config::from_toml_str(source).expect_err("remote admin needs TLS");
        assert!(error.to_string().contains("admin.tls.enabled"));

        let source = r#"
[admin]
bind_address = "0.0.0.0"
remote_http = true

[admin.tls]
enabled = true
certificate_path = "/etc/thunderbolt/admin.crt"
private_key_path = "/etc/thunderbolt/admin.key"
"#;
        Config::from_toml_str(source).expect("remote TLS config should validate");
    }

    #[test]
    fn mainnet_rejects_development_flags() {
        let mut config = Config::default();
        config.deployment.environment = Environment::Production;
        config.deployment.network = Network::Mainnet;
        config.paths.data_dir = PathBuf::from("/var/lib/thunderbolt");
        config.paths.log_dir = PathBuf::from("/var/lib/thunderbolt/logs");
        config.paths.database_path = PathBuf::from("/var/lib/thunderbolt/thunderbolt.sqlite3");
        config.paths.socket_path = PathBuf::from("/var/lib/thunderbolt/thunderboltd.sock");
        config.backup.directory = PathBuf::from("/var/lib/thunderbolt/backups");
        config.auth.tokens[0].token_file = PathBuf::from("/etc/thunderbolt/operator.token");
        config.ledger.endpoint = "https://ledger.example.com/".to_owned();
        config.development.accept_invalid_tls_certificates = true;
        let errors = config.validate().expect_err("unsafe mainnet flag must fail");
        assert!(errors.to_string().contains("mainnet is disabled"));
        assert!(errors
            .to_string()
            .contains("accept_invalid_tls_certificates is forbidden"));
    }

    #[test]
    fn release_candidate_rejects_mainnet_even_with_safe_flags() {
        let source = r#"
[deployment]
environment = "production"
network = "mainnet"

[paths]
data_dir = "/var/lib/thunderbolt"
log_dir = "/var/lib/thunderbolt/logs"
database_path = "/var/lib/thunderbolt/thunderbolt.sqlite3"
socket_path = "/var/lib/thunderbolt/thunderboltd.sock"

[backup]
directory = "/var/lib/thunderbolt/backups"

[[auth.tokens]]
id = "administrator"
token_file = "/etc/thunderbolt/admin.token"
scopes = ["admin"]

[ledger]
endpoint = "https://ledger.example.com/"
"#;
        let error = Config::from_toml_str(source).expect_err("mainnet must stay disabled in version 1.0");
        assert!(error.to_string().contains("mainnet is disabled"));
    }

    #[test]
    fn built_in_sample_is_valid() {
        Config::from_toml_str(SAMPLE_CONFIG).expect("sample configuration should stay valid");
    }

    #[test]
    fn writes_sample_without_overwriting() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("thunderbolt.toml");
        Config::write_sample(&path).expect("sample should be written");
        assert_eq!(fs::read_to_string(&path).expect("sample should read"), SAMPLE_CONFIG);
        assert!(Config::write_sample(&path).is_err());
    }
}
