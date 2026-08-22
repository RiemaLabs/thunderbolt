use std::error::Error;
use std::fmt;

/// Canonical floor contract validation failure.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum FloorError {
    /// Consensus chain identifier is empty or too large.
    #[error("floor Ledger chain identifier is invalid")]
    InvalidChainId,
    /// A finality anchor contains a zero height, time, or hash.
    #[error("floor finality anchor is invalid")]
    InvalidFinalityAnchor,
    /// CAS is not initialization or the exact next revision.
    #[error("floor checkpoint transition is not exact-next")]
    InvalidTransition,
}

/// Fail-closed Ledger floor adapter error.
pub enum LedgerFloorStoreError<T, V> {
    /// Canonical request construction failed.
    Contract(FloorError),
    /// Transport failed before a potentially committed submission.
    Transport(Box<T>),
    /// An ambiguous CAS could not be causally resolved.
    AmbiguousResolution(Box<T>),
    /// Quorum/light-client finality verification failed.
    Finality(Box<V>),
    /// Verified claims did not bind the exact request or configured chain.
    ResponseMismatch(&'static str),
}

impl<T, V> fmt::Debug for LedgerFloorStoreError<T, V>
where
    T: fmt::Debug,
    V: fmt::Debug,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Contract(error) => formatter.debug_tuple("Contract").field(error).finish(),
            Self::Transport(_) => formatter.write_str("Transport([REDACTED])"),
            Self::AmbiguousResolution(_) => formatter.write_str("AmbiguousResolution([REDACTED])"),
            Self::Finality(_) => formatter.write_str("Finality([REDACTED])"),
            Self::ResponseMismatch(reason) => formatter.debug_tuple("ResponseMismatch").field(reason).finish(),
        }
    }
}

impl<T, V> fmt::Display for LedgerFloorStoreError<T, V>
where
    T: fmt::Display,
    V: fmt::Display,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Contract(error) => error.fmt(formatter),
            Self::Transport(error) => error.fmt(formatter),
            Self::AmbiguousResolution(error) => error.fmt(formatter),
            Self::Finality(error) => error.fmt(formatter),
            Self::ResponseMismatch(reason) => write!(formatter, "finalized floor response mismatch: {reason}"),
        }
    }
}

impl<T, V> Error for LedgerFloorStoreError<T, V>
where
    T: Error + 'static,
    V: Error + 'static,
{
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Contract(error) => Some(error),
            Self::Transport(error) | Self::AmbiguousResolution(error) => Some(error.as_ref()),
            Self::Finality(error) => Some(error.as_ref()),
            Self::ResponseMismatch(_) => None,
        }
    }
}

/// Result type for canonical floor contract construction.
pub type Result<T> = std::result::Result<T, FloorError>;
