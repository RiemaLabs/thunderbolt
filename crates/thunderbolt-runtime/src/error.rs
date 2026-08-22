use thunderbolt_runtime_config::RuntimeRole;

use crate::{RuntimeLifecycleEvent, RuntimeLifecycleState};

/// Fail-closed runtime construction, lifecycle, or supervision failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum RuntimeError {
    /// A role-typed supervisor received a handoff for another role.
    #[error("runtime handoff role mismatch: expected {expected:?}, found {actual:?}")]
    WrongRole {
        /// Role fixed by the supervisor type.
        expected: RuntimeRole,
        /// Role carried by the revalidated handoff.
        actual: RuntimeRole,
    },
    /// The mandatory handler was built for another immutable deployment identity.
    #[error("runtime handler identity does not match the revalidated handoff")]
    HandlerIdentityMismatch,
    /// The process-lock path or its parent failed owner-only validation.
    #[error("owner-only runtime process lock is unsafe")]
    UnsafeProcessLock,
    /// Another process currently holds the exact role data-directory lock.
    #[error("runtime process lock is already held")]
    ProcessAlreadyRunning,
    /// The lock file could not be opened or locked without weakening policy.
    #[error("runtime process lock is unavailable")]
    ProcessLockUnavailable,
    /// The data-directory lock belongs to another exact deployment identity.
    #[error("runtime process lock identity does not match the handoff")]
    ProcessLockIdentityMismatch,
    /// The durable clean/dirty marker could not be read or persisted.
    #[error("runtime process-state marker is unavailable")]
    ProcessStateUnavailable,
    /// A fixed secret-free control payload could not be encoded.
    #[error("runtime diagnostic payload encoding failed")]
    DiagnosticEncoding,
    /// The bounded actor mailbox has no remaining capacity.
    #[error("runtime lifecycle command queue is full")]
    CommandQueueFull,
    /// The bounded request-id ledger cannot accept another distinct identifier.
    #[error("runtime lifecycle request-id ledger is full")]
    RequestLedgerFull,
    /// One request identifier was reused for a different lifecycle event.
    #[error("runtime lifecycle request id conflicts with its original event")]
    RequestIdConflict,
    /// The command caller disappeared before the lifecycle transition committed.
    #[error("runtime lifecycle command was cancelled before commit")]
    CommandCancelled,
    /// A prior unclean lifetime blocks role hooks pending external recovery.
    #[error("runtime lifecycle is blocked by an unclean prior lifetime")]
    DirtyRestartBlocked,
    /// The background actor has stopped or was never polled.
    #[error("runtime lifecycle actor is unavailable")]
    ActorUnavailable,
    /// The actor did not correlate a command result within committed bounds.
    #[error("runtime lifecycle command deadline elapsed")]
    CommandDeadline,
    /// The requested transition is not valid from the current lifecycle state.
    #[error("runtime cannot apply {event:?} while in {state:?}")]
    InvalidTransition {
        /// Current lifecycle state.
        state: RuntimeLifecycleState,
        /// Requested fixed lifecycle operation.
        event: RuntimeLifecycleEvent,
    },
    /// The role handler returned a failure; its potentially sensitive detail is discarded.
    #[error("runtime lifecycle handler failed")]
    HandlerFailure,
    /// The role handler exceeded the immutable configured deadline.
    #[error("runtime lifecycle handler deadline elapsed")]
    HandlerDeadline,
    /// The role handler panicked across the supervised boundary.
    #[error("runtime lifecycle handler panicked")]
    HandlerPanic,
    /// The actor future was dropped before an explicit terminal transition.
    #[error("runtime lifecycle actor was cancelled")]
    ActorCancelled,
}

/// Runtime result type.
pub type Result<T> = std::result::Result<T, RuntimeError>;
