use thiserror::Error;

use crate::{CommitteeEpoch, CommitteeMemberId, RefreshEventId, SignerSessionId};

/// Errors returned by the one-member committee runtime.
#[derive(Debug, Error)]
pub enum CommitteeError {
    /// Committee member zero is reserved and cannot be provisioned.
    #[error("committee member identifiers must be positive and must not use the reserved recipient identifier")]
    InvalidMemberId,

    /// The public committee descriptor has an invalid threshold or member set.
    #[error("invalid committee descriptor: {0}")]
    InvalidDescriptor(&'static str),

    /// The provisioned secret package does not open the public descriptor.
    #[error("the provisioned member package does not match its public descriptor")]
    ProvisioningMismatch,

    /// A public wire message failed structural or cryptographic validation.
    #[error("threshold-refresh wire verification failed: {0}")]
    Wire(#[from] thunderbolt_wire::WireError),

    /// A cryptographic operation in the protocol core failed.
    #[error("committee cryptographic operation failed: {0}")]
    Core(#[from] thunderbolt_core::ThunderboltError),

    /// The refresh is bound to a different Bitcoin network or deployment.
    #[error("threshold refresh is bound to a different committee deployment")]
    WrongDeployment,

    /// The refresh is bound to a different committee epoch.
    #[error("threshold refresh epoch {actual} does not match local epoch {expected}")]
    WrongEpoch {
        /// Locally provisioned epoch.
        expected: CommitteeEpoch,
        /// Epoch carried by the public event.
        actual: CommitteeEpoch,
    },

    /// The refresh threshold differs from the provisioned descriptor.
    #[error("threshold refresh requires {actual} members; local descriptor requires {expected}")]
    WrongThreshold {
        /// Locally provisioned threshold.
        expected: u32,
        /// Threshold carried by the public distribution.
        actual: u32,
    },

    /// The wire distribution does not select the exact provisioned member set.
    #[error("threshold refresh does not target the exact provisioned committee")]
    WrongMemberSet,

    /// The recipient proof does not use the protocol-reserved share identifier.
    #[error("recipient share proof must use the reserved recipient identifier")]
    WrongRecipientShareId,

    /// The recipient share and committee distribution use different bindings.
    #[error("recipient share proof binding does not match the threshold distribution")]
    RecipientBindingMismatch,

    /// The recipient share proof does not open the distributed public delta.
    #[error("recipient share proof does not match the threshold distribution anchor and delta")]
    RecipientDeltaMismatch,

    /// The committed transfer does not consume the proven recipient ciphertext.
    #[error("committed transfer does not consume the proven recipient ciphertext and key")]
    RecipientTransferMismatch,

    /// A transfer wire message does not consume the same invoice/distribution.
    #[error("committed transfer does not match the threshold-refresh invoice")]
    TransferBindingMismatch,

    /// The transfer's public anchor transition does not use the distributed delta.
    #[error("committed transfer anchor transition does not use the threshold-refresh delta")]
    TransferDeltaMismatch,

    /// The configured ledger verifier rejected or could not verify commitment.
    #[error("ledger commitment verification failed: {0}")]
    LedgerCommitment(String),

    /// The committed receipt does not bind the exact verified wire messages.
    #[error("ledger commitment does not bind the exact invoice and transfer messages")]
    LedgerCommitmentMismatch,

    /// The distribution does not contain this process's member.
    #[error("threshold refresh does not contain member {0}")]
    MissingOwnShare(CommitteeMemberId),

    /// The member ciphertext was encrypted under a different public key.
    #[error("threshold refresh uses an unexpected Paillier key for member {0}")]
    WrongRecipientKey(CommitteeMemberId),

    /// Decrypted share material does not open the public Feldman commitment.
    #[error("decrypted refresh share does not match its Feldman commitment")]
    ShareCommitmentMismatch,

    /// Applying a refresh would produce the forbidden zero Shamir share.
    #[error("threshold refresh would replace the local Shamir share with zero")]
    ZeroUpdatedShare,

    /// Another event is already durably pending and must be resumed first.
    #[error("event {pending} is pending; refusing unrelated event {requested}")]
    PendingEventConflict {
        /// The event already stored in the vault.
        pending: RefreshEventId,
        /// The newly requested event.
        requested: RefreshEventId,
    },

    /// A persisted signing-session identifier was presented again.
    #[error("signing session {0} was already reserved; refusing possible nonce reuse")]
    SigningSessionReuse(SignerSessionId),

    /// A signing-session transition did not match the stored exact binding.
    #[error("signing session state does not match its exact persisted binding")]
    SigningSessionMismatch,

    /// A signer returned an invalid or oversized public nonce commitment.
    #[error("signer returned an invalid nonce commitment")]
    InvalidNonceCommitment,

    /// The signer backend failed after the nonce session was durably burned.
    #[error("committee signer failed: {0}")]
    Signer(String),

    /// A vault operation failed. The string must not contain secret material.
    #[error("encrypted committee vault failed: {0}")]
    Vault(String),

    /// The encrypted vault changed concurrently with this process.
    #[error("encrypted committee vault revision changed concurrently")]
    VaultConflict,

    /// The decrypted vault record is malformed or contradicts public state.
    #[error("invalid encrypted committee vault record: {0}")]
    InvalidVaultRecord(&'static str),

    /// A write outcome was ambiguous, so this engine must be reopened.
    #[error("committee engine must be reopened to reconcile the durable vault state")]
    RecoveryRequired,

    /// The bounded durable replay journal has reached its configured maximum.
    #[error("durable committee event history is full; rotate the committee epoch")]
    EventHistoryFull,

    /// The bounded durable signing-session journal has reached its maximum.
    #[error("durable signing-session history is full; rotate the committee epoch")]
    SigningHistoryFull,

    /// A numeric state revision overflowed.
    #[error("committee vault revision exhausted its numeric range")]
    RevisionExhausted,
}

/// Result type used by the committee runtime.
pub type Result<T> = std::result::Result<T, CommitteeError>;
