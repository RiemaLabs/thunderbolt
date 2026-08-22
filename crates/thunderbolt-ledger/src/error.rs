use thiserror::Error;

/// Errors returned by the deterministic Ledger contract.
#[derive(Debug, Error)]
pub enum LedgerContractError {
    /// A fixed- or bounded-width byte field had an invalid length.
    #[error("{field} must contain {min}..={max} bytes; got {actual}")]
    InvalidLength {
        /// Name of the invalid field.
        field: &'static str,
        /// Smallest accepted byte length.
        min: usize,
        /// Largest accepted byte length.
        max: usize,
        /// Observed byte length.
        actual: usize,
    },

    /// A canonical byte field used an invalid representation.
    #[error("invalid {field}: {reason}")]
    InvalidField {
        /// Name of the invalid field.
        field: &'static str,
        /// Stable explanation suitable for an operator log.
        reason: &'static str,
    },

    /// A proposal violated a deterministic protocol-v2 invariant.
    #[error("invalid protocol-v2 proposal: {reason}")]
    InvalidProposal {
        /// Stable invariant failure description.
        reason: &'static str,
    },

    /// The actor's BIP340 signature did not authenticate the proposal.
    #[error("proposal actor signature verification failed")]
    InvalidActorSignature,

    /// A request identifier did not match its channel, actor, role, and nonce.
    #[error("actor request id is not bound to the proposal channel and actor")]
    RequestBindingMismatch,

    /// A pending or executed block violated a deterministic block invariant.
    #[error("invalid protocol-v2 block: {reason}")]
    InvalidBlock {
        /// Stable invariant failure description.
        reason: &'static str,
    },

    /// An ordered entry-Merkle inclusion proof was malformed or invalid.
    #[error("invalid protocol-v2 entry inclusion proof: {reason}")]
    InvalidMerkleProof {
        /// Stable proof failure description.
        reason: &'static str,
    },

    /// The stable channel binding failed its own validation.
    #[error("invalid stable channel binding: {0}")]
    InvalidChannelBinding(#[from] thunderbolt_wire::WireError),
}

/// Result type used by the deterministic Ledger contract.
pub type Result<T> = std::result::Result<T, LedgerContractError>;
