use thiserror::Error;

pub(crate) type Result<T> = std::result::Result<T, NodeError>;

#[derive(Debug, Error)]
pub(crate) enum NodeError {
    #[error("invalid Floor node configuration: {0}")]
    InvalidConfig(&'static str),
    #[error("Floor node configuration or manifest I/O failed: {0}")]
    FileIo(&'static str),
    #[error("Floor node configuration file is not valid UTF-8")]
    ConfigEncoding,
    #[error("Floor node TOML decoding failed")]
    ConfigDecode,
    #[error("Floor node JSON manifest decoding failed: {0}")]
    ManifestDecode(&'static str),
    #[error("Floor node manifest is not in canonical form: {0}")]
    ManifestCanonical(&'static str),
    #[error("Floor application construction failed")]
    Application,
    #[error("Floor ABCI construction failed")]
    Abci,
    #[error("Floor ABCI server construction failed")]
    Server,
    #[error("Floor genesis encoding failed")]
    GenesisEncoding,
    #[error("Floor node signal handling failed")]
    Signal,
    #[cfg(not(unix))]
    #[error("Floor node is supported only on Unix")]
    UnsupportedPlatform,
}
