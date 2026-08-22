use std::fmt;

/// Failure while constructing, encoding, or decoding a Ledger RPC envelope.
#[derive(Debug, thiserror::Error)]
pub enum RpcCodecError {
    /// The complete request or response exceeds its fixed transport-neutral bound.
    #[error("{direction} envelope exceeds its {limit}-byte bound")]
    BodyTooLarge {
        /// Envelope direction being decoded or encoded.
        direction: &'static str,
        /// Maximum accepted byte count.
        limit: usize,
    },
    /// JSON syntax or a nested validated protocol type is invalid.
    #[error("invalid RPC envelope: {0}")]
    InvalidEnvelope(#[source] serde_json::Error),
    /// The RPC version is not supported by this crate.
    #[error("unsupported Ledger RPC version {found}")]
    UnsupportedVersion {
        /// Version carried by the rejected envelope.
        found: u16,
    },
    /// The input is semantically valid JSON but not the unique canonical encoding.
    #[error("RPC envelope is not canonical")]
    NonCanonical,
    /// A fixed-size hexadecimal field is malformed.
    #[error("invalid {field}")]
    InvalidHex {
        /// Stable public field name.
        field: &'static str,
    },
    /// A bounded byte string is empty or outside its maximum.
    #[error("{field} length is outside [{min}, {max}]")]
    InvalidLength {
        /// Stable public field name.
        field: &'static str,
        /// Minimum accepted byte count.
        min: usize,
        /// Maximum accepted byte count.
        max: usize,
    },
    /// Two otherwise valid fields do not describe the same chain, deployment, or claim.
    #[error("RPC binding mismatch: {0}")]
    BindingMismatch(&'static str),
    /// A bounded enum or state transition has an invalid shape.
    #[error("invalid RPC field: {0}")]
    InvalidField(&'static str),
    /// A nested Ledger contract rejected deterministic data.
    #[error("Ledger contract rejected RPC data: {0}")]
    Ledger(#[from] thunderbolt_ledger::LedgerContractError),
    /// A nested protocol state rejected deterministic data.
    #[error("protocol state rejected RPC data: {0}")]
    Protocol(#[from] thunderbolt_protocol::v2::V2Error),
    /// A nested wire binding is invalid.
    #[error("wire binding rejected RPC data: {0}")]
    Wire(#[from] thunderbolt_wire::WireError),
    /// A rollback-floor request is malformed.
    #[error("rollback-floor request rejected RPC data: {0}")]
    Floor(#[from] thunderbolt_floor::FloorError),
    /// A reconstructed vault identity is malformed.
    #[error("vault identity rejected RPC data: {0}")]
    Keystore(#[from] thunderbolt_keystore::KeystoreError),
}

impl RpcCodecError {
    pub(crate) const fn invalid_hex(field: &'static str) -> Self {
        Self::InvalidHex { field }
    }
}

/// Result type for the Ledger RPC codec.
pub type Result<T> = std::result::Result<T, RpcCodecError>;

pub(crate) struct RedactedDebug<'a> {
    pub(crate) name: &'a str,
    pub(crate) byte_len: usize,
}

impl fmt::Debug for RedactedDebug<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct(self.name)
            .field("byte_len", &self.byte_len)
            .finish_non_exhaustive()
    }
}
