/// Fatal server condition requiring immediate process/session termination.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FatalServerKind {
    /// Application callback panicked or invoked a panic-based fatal boundary.
    HandlerPanic,
    /// Application callback exceeded its hard response deadline.
    HandlerTimeout,
    /// Worker registry, join, or accounting invariant failed.
    WorkerInvariant,
    /// Normal shutdown could not join every worker within its grace period.
    ShutdownTimeout,
    /// Exact Unix socket cleanup failed or the path was replaced.
    CleanupFailure,
    /// Listener accept failed outside normal shutdown.
    ListenerFailure,
}

/// Redacted event passed to the non-returning production fatal handler.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FatalServerEvent {
    kind: FatalServerKind,
    connection_id: Option<u64>,
}

impl FatalServerEvent {
    /// Constructs one redacted fatal event.
    #[must_use]
    pub const fn new(kind: FatalServerKind, connection_id: Option<u64>) -> Self {
        Self { kind, connection_id }
    }
    /// Returns the fatal condition class.
    #[must_use]
    pub const fn kind(self) -> FatalServerKind {
        self.kind
    }
    /// Returns the affected connection ID, if any.
    #[must_use]
    pub const fn connection_id(self) -> Option<u64> {
        self.connection_id
    }
}

/// Hard fatal boundary for uncancellable or invariant-breaking server failures.
pub trait FatalServerHandler: Send + Sync + 'static {
    /// Terminates the application process/session and never returns.
    fn terminate(&self, event: FatalServerEvent) -> !;
}

/// Fatal handler that immediately exits the complete process with a nonzero code.
///
/// It deliberately performs no potentially blocking logging on the fatal path;
/// the process supervisor observes the configured exit status.
#[derive(Clone, Copy, Debug)]
pub struct ProcessExitFatalServerHandler {
    exit_code: u8,
}

impl ProcessExitFatalServerHandler {
    /// Constructs a non-success process exit policy.
    pub fn new(exit_code: u8) -> crate::Result<Self> {
        if exit_code == 0 {
            return Err(crate::ServerError::InvalidConfig(
                "fatal server exit code must be nonzero",
            ));
        }
        Ok(Self { exit_code })
    }
}

impl FatalServerHandler for ProcessExitFatalServerHandler {
    fn terminate(&self, _event: FatalServerEvent) -> ! {
        std::process::exit(i32::from(self.exit_code));
    }
}
