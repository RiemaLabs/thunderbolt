use std::fmt;
use std::io;
use std::path::PathBuf;

/// One or more independently actionable configuration errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidationErrors {
    errors: Vec<String>,
}

impl ValidationErrors {
    pub(crate) fn new(errors: Vec<String>) -> Self {
        Self { errors }
    }

    /// Returns each validation failure without discarding the others.
    pub fn errors(&self) -> &[String] {
        &self.errors
    }

    /// Consumes the error collection.
    pub fn into_errors(self) -> Vec<String> {
        self.errors
    }
}

impl fmt::Display for ValidationErrors {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}", self.errors.join("; "))
    }
}

impl std::error::Error for ValidationErrors {}

/// Failures while reading, merging, validating, or rendering configuration.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("could not read configuration file {path}: {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: io::Error,
    },

    #[error("could not parse configuration: {0}")]
    Parse(#[from] toml::de::Error),

    #[error("could not render configuration: {0}")]
    Render(#[from] toml::ser::Error),

    #[error("invalid environment override {variable}: {reason}")]
    Environment { variable: String, reason: &'static str },

    #[error("invalid configuration: {0}")]
    Validation(#[from] ValidationErrors),

    #[error("could not create sample configuration file {path}: {source}")]
    WriteSample {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
}

/// Failures while loading bearer tokens from protected local files.
#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("token file for {token_id} could not be opened: {source}")]
    Open {
        token_id: String,
        #[source]
        source: io::Error,
    },

    #[error("token file for {token_id} could not be inspected: {source}")]
    Metadata {
        token_id: String,
        #[source]
        source: io::Error,
    },

    #[error("token file for {token_id} must be a regular file")]
    NotRegularFile { token_id: String },

    #[cfg(unix)]
    #[error("token file for {token_id} has mode {mode:04o}; expected exactly 0400 or 0600")]
    InsecurePermissions { token_id: String, mode: u32 },

    #[error("token file for {token_id} could not be read: {source}")]
    Read {
        token_id: String,
        #[source]
        source: io::Error,
    },

    #[error("token file for {token_id} contains an invalid bearer token: {reason}")]
    InvalidToken { token_id: String, reason: &'static str },

    #[error("bearer tokens for {first_id} and {second_id} have identical contents")]
    DuplicateToken { first_id: String, second_id: String },
}
