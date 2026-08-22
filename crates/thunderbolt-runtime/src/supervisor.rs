use std::collections::BTreeMap;
use std::marker::PhantomData;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use futures_util::FutureExt as _;
use thunderbolt_control::{ControlServerConfig, RequestId};
use thunderbolt_runtime_config::{DeploymentIdentity, RuntimeHandoff, RuntimePaths, RuntimeRole};
use tokio::sync::{mpsc, oneshot, watch, Mutex};
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;

use crate::process_lock::ProcessLock;
use crate::types::{COMMITTEE_BLOCKERS, COMMON_BLOCKERS, HOLDER_BLOCKERS, LEDGER_BLOCKERS};
use crate::{
    CommitteeRole, HolderRole, LedgerRole, RedactedRuntimeConfig, Result, RuntimeBlocker, RuntimeBlockerCode,
    RuntimeControl, RuntimeError, RuntimeFaultCode, RuntimeHandlerIdentity, RuntimeLifecycleEvent,
    RuntimeLifecycleHandler, RuntimeLifecycleState, RuntimeLiveness, RuntimeReadiness, RuntimeRoleMarker,
    RuntimeStatus,
};

/// Maximum queued lifecycle commands for one runtime actor.
pub const MAX_PENDING_LIFECYCLE_COMMANDS: usize = 8;
/// Maximum distinct lifecycle request IDs retained for exact replay.
pub const MAX_RETAINED_LIFECYCLE_REQUESTS: usize = 64;

/// Role-typed Ledger supervisor.
pub type LedgerSupervisor<'a, H> = RuntimeSupervisor<'a, LedgerRole, H>;
/// Role-typed Holder supervisor.
pub type HolderSupervisor<'a, H> = RuntimeSupervisor<'a, HolderRole, H>;
/// Role-typed Committee supervisor.
pub type CommitteeSupervisor<'a, H> = RuntimeSupervisor<'a, CommitteeRole, H>;

/// Handle for bounded lifecycle commands and immutable operator observations.
pub struct RuntimeHandle<R: RuntimeRoleMarker> {
    command_tx: mpsc::Sender<LifecycleCommand>,
    status_rx: watch::Receiver<RuntimeStatus>,
    request_ledger: Arc<Mutex<RequestLedger>>,
    blockers: Arc<[RuntimeBlocker]>,
    redacted: Arc<RedactedRuntimeConfig>,
    response_timeout: Duration,
    _role: PhantomData<R>,
}

impl<R: RuntimeRoleMarker> Clone for RuntimeHandle<R> {
    fn clone(&self) -> Self {
        Self {
            command_tx: self.command_tx.clone(),
            status_rx: self.status_rx.clone(),
            request_ledger: self.request_ledger.clone(),
            blockers: self.blockers.clone(),
            redacted: self.redacted.clone(),
            response_timeout: self.response_timeout,
            _role: PhantomData,
        }
    }
}

impl<R: RuntimeRoleMarker> RuntimeHandle<R> {
    /// Returns the latest secret-free status without invoking the actor.
    pub fn status(&self) -> RuntimeStatus {
        *self.status_rx.borrow()
    }

    /// Returns the immutable readiness-blocker set.
    pub fn blockers(&self) -> &[RuntimeBlocker] {
        &self.blockers
    }

    /// Returns the immutable redacted configuration view.
    pub fn redacted_config(&self) -> &RedactedRuntimeConfig {
        &self.redacted
    }

    /// Starts the role handler exactly once under a stable request ID.
    pub async fn start(&self, request_id: RequestId) -> Result<RuntimeStatus> {
        self.command(request_id, RuntimeLifecycleEvent::Start).await
    }

    /// Drains a running role under a stable request ID.
    pub async fn drain(&self, request_id: RequestId) -> Result<RuntimeStatus> {
        self.command(request_id, RuntimeLifecycleEvent::Drain).await
    }

    /// Stops the role under a stable request ID and terminates the lifecycle actor.
    pub async fn stop(&self, request_id: RequestId) -> Result<RuntimeStatus> {
        self.command(request_id, RuntimeLifecycleEvent::Stop).await
    }

    async fn command(&self, request_id: RequestId, event: RuntimeLifecycleEvent) -> Result<RuntimeStatus> {
        if let Some(cached) = self.cached_result(request_id, event).await? {
            return cached;
        }
        let caller_cancellation = CancellationToken::new();
        let _guard = CancelOnDrop(caller_cancellation.clone());
        let (reply_tx, reply_rx) = oneshot::channel();
        self.command_tx
            .try_send(LifecycleCommand {
                request_id,
                event,
                caller_cancellation,
                reply_tx,
            })
            .map_err(|error| match error {
                mpsc::error::TrySendError::Full(_) => RuntimeError::CommandQueueFull,
                mpsc::error::TrySendError::Closed(_) => RuntimeError::ActorUnavailable,
            })?;
        timeout(self.response_timeout, reply_rx)
            .await
            .map_err(|_| RuntimeError::CommandDeadline)?
            .map_err(|_| RuntimeError::ActorUnavailable)?
    }

    async fn cached_result(
        &self,
        request_id: RequestId,
        event: RuntimeLifecycleEvent,
    ) -> Result<Option<Result<RuntimeStatus>>> {
        let ledger = self.request_ledger.lock().await;
        let Some(cached) = ledger.entries.get(&request_id) else {
            if ledger.entries.len() == MAX_RETAINED_LIFECYCLE_REQUESTS {
                return Err(RuntimeError::RequestLedgerFull);
            }
            return Ok(None);
        };
        if cached.event != event {
            return Err(RuntimeError::RequestIdConflict);
        }
        Ok(match cached.outcome {
            CachedOutcome::Complete(result) => Some(result),
            CachedOutcome::InFlight | CachedOutcome::Retryable => None,
        })
    }

    /// Creates a status-only monitor that does not keep the command actor alive.
    pub fn monitor(&self) -> RuntimeMonitor<R> {
        RuntimeMonitor {
            status_rx: self.status_rx.clone(),
            blockers: self.blockers.clone(),
            redacted: self.redacted.clone(),
            _role: PhantomData,
        }
    }

    #[cfg(test)]
    pub(crate) fn enqueue_ignored(&self, request_id: RequestId, event: RuntimeLifecycleEvent) -> Result<()> {
        let (reply_tx, reply_rx) = oneshot::channel();
        drop(reply_rx);
        self.command_tx
            .try_send(LifecycleCommand {
                request_id,
                event,
                caller_cancellation: CancellationToken::new(),
                reply_tx,
            })
            .map_err(|error| match error {
                mpsc::error::TrySendError::Full(_) => RuntimeError::CommandQueueFull,
                mpsc::error::TrySendError::Closed(_) => RuntimeError::ActorUnavailable,
            })
    }
}

/// Status-only observation handle that does not retain an actor sender.
pub struct RuntimeMonitor<R: RuntimeRoleMarker> {
    status_rx: watch::Receiver<RuntimeStatus>,
    blockers: Arc<[RuntimeBlocker]>,
    redacted: Arc<RedactedRuntimeConfig>,
    _role: PhantomData<R>,
}

impl<R: RuntimeRoleMarker> Clone for RuntimeMonitor<R> {
    fn clone(&self) -> Self {
        Self {
            status_rx: self.status_rx.clone(),
            blockers: self.blockers.clone(),
            redacted: self.redacted.clone(),
            _role: PhantomData,
        }
    }
}

impl<R: RuntimeRoleMarker> RuntimeMonitor<R> {
    /// Returns the latest secret-free runtime status.
    pub fn status(&self) -> RuntimeStatus {
        *self.status_rx.borrow()
    }

    /// Returns the immutable readiness blockers.
    pub fn blockers(&self) -> &[RuntimeBlocker] {
        &self.blockers
    }

    /// Returns the immutable redacted configuration.
    pub fn redacted_config(&self) -> &RedactedRuntimeConfig {
        &self.redacted
    }
}

/// Lifetime-bound supervisor retaining a fresh [`RuntimeHandoff`] and process lock.
///
/// This type opens no listener. The caller must continuously poll [`Self::run`]
/// and may separately pass [`Self::control_handler`] to an owner-only control
/// transport.
pub struct RuntimeSupervisor<'a, R, H>
where
    R: RuntimeRoleMarker,
    H: RuntimeLifecycleHandler<R>,
{
    _handoff: RuntimeHandoff<'a>,
    handler: H,
    process_lock: Option<ProcessLock>,
    dirty_restart: bool,
    command_tx: Option<mpsc::Sender<LifecycleCommand>>,
    command_rx: mpsc::Receiver<LifecycleCommand>,
    request_ledger: Arc<Mutex<RequestLedger>>,
    status_tx: watch::Sender<RuntimeStatus>,
    blockers: Arc<[RuntimeBlocker]>,
    redacted: Arc<RedactedRuntimeConfig>,
    hook_timeout: Duration,
    shutdown_timeout: Duration,
    response_timeout: Duration,
    exit_guard: ActorExitGuard,
    _role: PhantomData<R>,
}

impl<'a, H> RuntimeSupervisor<'a, LedgerRole, H>
where
    H: RuntimeLifecycleHandler<LedgerRole>,
{
    /// Constructs a Ledger supervisor from an exact revalidated Ledger handoff.
    pub fn new(handoff: RuntimeHandoff<'a>, handler: H) -> Result<Self> {
        Self::new_for_role(handoff, handler)
    }
}

impl<'a, H> RuntimeSupervisor<'a, HolderRole, H>
where
    H: RuntimeLifecycleHandler<HolderRole>,
{
    /// Constructs a Holder supervisor from an exact revalidated Holder handoff.
    pub fn new(handoff: RuntimeHandoff<'a>, handler: H) -> Result<Self> {
        Self::new_for_role(handoff, handler)
    }
}

impl<'a, H> RuntimeSupervisor<'a, CommitteeRole, H>
where
    H: RuntimeLifecycleHandler<CommitteeRole>,
{
    /// Constructs a Committee supervisor from an exact revalidated Committee handoff.
    pub fn new(handoff: RuntimeHandoff<'a>, handler: H) -> Result<Self> {
        Self::new_for_role(handoff, handler)
    }
}

impl<'a, R, H> RuntimeSupervisor<'a, R, H>
where
    R: RuntimeRoleMarker,
    H: RuntimeLifecycleHandler<R>,
{
    fn new_for_role(handoff: RuntimeHandoff<'a>, handler: H) -> Result<Self> {
        let resources = RoleResources::from_handoff::<R>(&handoff)?;
        let handler_identity =
            catch_unwind(AssertUnwindSafe(|| handler.identity())).map_err(|_| RuntimeError::HandlerPanic)?;
        if handler_identity != resources.handler_identity {
            return Err(RuntimeError::HandlerIdentityMismatch);
        }
        let process_lock = ProcessLock::acquire(&resources.data_dir, &resources.handler_identity)?;
        let dirty_restart = process_lock.dirty_on_entry();
        let mut blockers = Vec::with_capacity(
            COMMON_BLOCKERS.len() + resources.role_blockers.len() + usize::from(process_lock.dirty_on_entry()),
        );
        blockers.extend_from_slice(COMMON_BLOCKERS);
        blockers.extend_from_slice(resources.role_blockers);
        if process_lock.dirty_on_entry() {
            blockers.push(RuntimeBlocker::recovery(
                RuntimeBlockerCode::DirtyRestartRecoveryRequired,
            ));
        }
        let blockers: Arc<[RuntimeBlocker]> = blockers.into();
        let initial = RuntimeStatus::new(
            R::ROLE,
            RuntimeLifecycleState::Initialized,
            RuntimeLiveness::NotLive,
            RuntimeReadiness::NotReady,
            None,
        );
        let (status_tx, status_rx) = watch::channel(initial);
        let (command_tx, command_rx) = mpsc::channel(MAX_PENDING_LIFECYCLE_COMMANDS);
        let request_ledger = Arc::new(Mutex::new(RequestLedger::default()));
        let response_timeout = resources
            .control
            .handler_timeout
            .saturating_add(resources.control.io_timeout);
        let redacted = Arc::new(resources.redacted);
        let exit_guard = ActorExitGuard::new(status_tx.clone(), R::ROLE);
        let supervisor = Self {
            _handoff: handoff,
            handler,
            process_lock: Some(process_lock),
            dirty_restart,
            command_tx: Some(command_tx),
            command_rx,
            request_ledger,
            status_tx,
            blockers: blockers.clone(),
            redacted: redacted.clone(),
            hook_timeout: resources.control.handler_timeout,
            shutdown_timeout: resources.control.shutdown_grace,
            response_timeout,
            exit_guard,
            _role: PhantomData,
        };
        drop(status_rx);
        Ok(supervisor)
    }

    /// Creates a clonable lifecycle/status handle before moving the supervisor into `run`.
    pub fn handle(&self) -> Result<RuntimeHandle<R>> {
        Ok(RuntimeHandle {
            command_tx: self.command_tx.as_ref().ok_or(RuntimeError::ActorUnavailable)?.clone(),
            status_rx: self.status_tx.subscribe(),
            request_ledger: self.request_ledger.clone(),
            blockers: self.blockers.clone(),
            redacted: self.redacted.clone(),
            response_timeout: self.response_timeout,
            _role: PhantomData,
        })
    }

    /// Creates the fixed-method local control handler without binding a listener.
    pub fn control_handler(&self) -> Result<RuntimeControl<R>> {
        Ok(RuntimeControl::new(self.handle()?))
    }

    /// Runs the bounded lifecycle actor until explicit stop, external cancellation, or fault.
    pub async fn run(mut self, shutdown: CancellationToken) -> Result<()> {
        drop(self.command_tx.take());
        let mut state = RuntimeLifecycleState::Initialized;
        self.publish(state, RuntimeLiveness::Live, None);
        loop {
            let command = tokio::select! {
                biased;
                _ = shutdown.cancelled() => {
                    return self.shutdown_role(state).await;
                }
                command = self.command_rx.recv() => command,
            };
            let Some(command) = command else {
                return self
                    .finish_fault(
                        RuntimeError::ActorUnavailable,
                        RuntimeFaultCode::ActorChannelClosed,
                        None,
                    )
                    .await;
            };
            match self.begin_request(command.request_id, command.event).await {
                BeginRequest::Replay(result) => {
                    send_reply(command.reply_tx, result);
                    continue;
                }
                BeginRequest::Reject(error) => {
                    send_reply(command.reply_tx, Err(error));
                    continue;
                }
                BeginRequest::Execute => {}
            }
            if command.caller_cancellation.is_cancelled() {
                self.record_retryable(command.request_id).await;
                send_reply(command.reply_tx, Err(RuntimeError::CommandCancelled));
                continue;
            }
            match command.event {
                RuntimeLifecycleEvent::Start => {
                    if self.dirty_restart {
                        self.record_complete(command.request_id, Err(RuntimeError::DirtyRestartBlocked))
                            .await;
                        send_reply(command.reply_tx, Err(RuntimeError::DirtyRestartBlocked));
                        continue;
                    }
                    if state != RuntimeLifecycleState::Initialized {
                        let error = RuntimeError::InvalidTransition {
                            state,
                            event: command.event,
                        };
                        self.record_complete(command.request_id, Err(error)).await;
                        send_reply(command.reply_tx, Err(error));
                        continue;
                    }
                    let previous = state;
                    state = RuntimeLifecycleState::Starting;
                    self.publish(state, RuntimeLiveness::Live, None);
                    match invoke_handler::<R, H>(
                        &self.handler,
                        RuntimeLifecycleEvent::Start,
                        self.hook_timeout,
                        &command.caller_cancellation,
                    )
                    .await
                    {
                        Ok(()) => {
                            state = RuntimeLifecycleState::Running;
                            let status = self.publish(state, RuntimeLiveness::Live, None);
                            self.record_complete(command.request_id, Ok(status)).await;
                            send_reply(command.reply_tx, Ok(status));
                        }
                        Err(RuntimeError::CommandCancelled) => {
                            state = previous;
                            self.publish(state, RuntimeLiveness::Live, None);
                            self.record_retryable(command.request_id).await;
                            send_reply(command.reply_tx, Err(RuntimeError::CommandCancelled));
                        }
                        Err(error) => {
                            let fault = fault_code(error);
                            return self.finish_fault(error, fault, Some(command)).await;
                        }
                    }
                }
                RuntimeLifecycleEvent::Drain => {
                    if self.dirty_restart {
                        self.record_complete(command.request_id, Err(RuntimeError::DirtyRestartBlocked))
                            .await;
                        send_reply(command.reply_tx, Err(RuntimeError::DirtyRestartBlocked));
                        continue;
                    }
                    if state != RuntimeLifecycleState::Running {
                        let error = RuntimeError::InvalidTransition {
                            state,
                            event: command.event,
                        };
                        self.record_complete(command.request_id, Err(error)).await;
                        send_reply(command.reply_tx, Err(error));
                        continue;
                    }
                    let previous = state;
                    state = RuntimeLifecycleState::Draining;
                    self.publish(state, RuntimeLiveness::Live, None);
                    match invoke_handler::<R, H>(
                        &self.handler,
                        RuntimeLifecycleEvent::Drain,
                        self.hook_timeout,
                        &command.caller_cancellation,
                    )
                    .await
                    {
                        Ok(()) => {
                            let status = self.publish(state, RuntimeLiveness::Live, None);
                            self.record_complete(command.request_id, Ok(status)).await;
                            send_reply(command.reply_tx, Ok(status));
                        }
                        Err(RuntimeError::CommandCancelled) => {
                            state = previous;
                            self.publish(state, RuntimeLiveness::Live, None);
                            self.record_retryable(command.request_id).await;
                            send_reply(command.reply_tx, Err(RuntimeError::CommandCancelled));
                        }
                        Err(error) => {
                            let fault = fault_code(error);
                            return self.finish_fault(error, fault, Some(command)).await;
                        }
                    }
                }
                RuntimeLifecycleEvent::Stop => {
                    if state == RuntimeLifecycleState::Initialized {
                        return if self.dirty_restart {
                            self.finish_dirty_shutdown(Some(command)).await
                        } else {
                            self.finish_clean(Some(command)).await
                        };
                    }
                    if !matches!(
                        state,
                        RuntimeLifecycleState::Initialized
                            | RuntimeLifecycleState::Running
                            | RuntimeLifecycleState::Draining
                    ) {
                        let error = RuntimeError::InvalidTransition {
                            state,
                            event: command.event,
                        };
                        self.record_complete(command.request_id, Err(error)).await;
                        send_reply(command.reply_tx, Err(error));
                        continue;
                    }
                    let previous = state;
                    self.publish(RuntimeLifecycleState::Stopping, RuntimeLiveness::Live, None);
                    match invoke_handler::<R, H>(
                        &self.handler,
                        RuntimeLifecycleEvent::Stop,
                        self.shutdown_timeout,
                        &command.caller_cancellation,
                    )
                    .await
                    {
                        Ok(()) => return self.finish_clean(Some(command)).await,
                        Err(RuntimeError::CommandCancelled) => {
                            state = previous;
                            self.publish(state, RuntimeLiveness::Live, None);
                            self.record_retryable(command.request_id).await;
                            send_reply(command.reply_tx, Err(RuntimeError::CommandCancelled));
                        }
                        Err(error) => {
                            let fault = fault_code(error);
                            return self.finish_fault(error, fault, Some(command)).await;
                        }
                    }
                }
            }
        }
    }

    async fn shutdown_role(&mut self, state: RuntimeLifecycleState) -> Result<()> {
        if state == RuntimeLifecycleState::Initialized {
            return if self.dirty_restart {
                self.finish_dirty_shutdown(None).await
            } else {
                self.finish_clean(None).await
            };
        }
        self.publish(RuntimeLifecycleState::Stopping, RuntimeLiveness::Live, None);
        let never_cancelled = CancellationToken::new();
        match invoke_handler::<R, H>(
            &self.handler,
            RuntimeLifecycleEvent::Stop,
            self.shutdown_timeout,
            &never_cancelled,
        )
        .await
        {
            Ok(()) => self.finish_clean(None).await,
            Err(error) => {
                let fault = fault_code(error);
                let _ = state;
                self.finish_fault(error, fault, None).await
            }
        }
    }

    async fn finish_clean(&mut self, command: Option<LifecycleCommand>) -> Result<()> {
        let marker_result = self
            .process_lock
            .as_ref()
            .ok_or(RuntimeError::ProcessStateUnavailable)?
            .mark_clean();
        if marker_result.is_err() {
            return self
                .finish_fault(
                    RuntimeError::ProcessStateUnavailable,
                    RuntimeFaultCode::ProcessStateUnavailable,
                    command,
                )
                .await;
        }
        let status = self.publish(RuntimeLifecycleState::Stopped, RuntimeLiveness::NotLive, None);
        if let Some(command) = &command {
            self.record_complete(command.request_id, Ok(status)).await;
        }
        self.exit_guard.disarm();
        drop(self.process_lock.take());
        if let Some(command) = command {
            send_reply(command.reply_tx, Ok(status));
        }
        Ok(())
    }

    async fn finish_dirty_shutdown(&mut self, command: Option<LifecycleCommand>) -> Result<()> {
        let status = self.publish(RuntimeLifecycleState::Stopped, RuntimeLiveness::NotLive, None);
        if let Some(command) = &command {
            self.record_complete(command.request_id, Ok(status)).await;
        }
        self.exit_guard.disarm();
        drop(self.process_lock.take());
        if let Some(command) = command {
            send_reply(command.reply_tx, Ok(status));
        }
        Ok(())
    }

    async fn finish_fault(
        &mut self,
        error: RuntimeError,
        fault: RuntimeFaultCode,
        command: Option<LifecycleCommand>,
    ) -> Result<()> {
        let terminal = match self.process_lock.as_ref() {
            Some(lock) if lock.mark_faulted().is_ok() => error,
            Some(_) | None => RuntimeError::ProcessStateUnavailable,
        };
        let terminal_fault = if terminal == RuntimeError::ProcessStateUnavailable {
            RuntimeFaultCode::ProcessStateUnavailable
        } else {
            fault
        };
        self.publish(
            RuntimeLifecycleState::Faulted,
            RuntimeLiveness::NotLive,
            Some(terminal_fault),
        );
        if let Some(command) = &command {
            self.record_complete(command.request_id, Err(terminal)).await;
        }
        self.exit_guard.disarm();
        drop(self.process_lock.take());
        if let Some(command) = command {
            send_reply(command.reply_tx, Err(terminal));
        }
        Err(terminal)
    }

    async fn begin_request(&self, request_id: RequestId, event: RuntimeLifecycleEvent) -> BeginRequest {
        let mut ledger = self.request_ledger.lock().await;
        if let Some(cached) = ledger.entries.get_mut(&request_id) {
            if cached.event != event {
                return BeginRequest::Reject(RuntimeError::RequestIdConflict);
            }
            return match cached.outcome {
                CachedOutcome::Complete(result) => BeginRequest::Replay(result),
                CachedOutcome::Retryable => {
                    cached.outcome = CachedOutcome::InFlight;
                    BeginRequest::Execute
                }
                CachedOutcome::InFlight => BeginRequest::Reject(RuntimeError::CommandQueueFull),
            };
        }
        if ledger.entries.len() == MAX_RETAINED_LIFECYCLE_REQUESTS {
            return BeginRequest::Reject(RuntimeError::RequestLedgerFull);
        }
        ledger.entries.insert(
            request_id,
            CachedCommand {
                event,
                outcome: CachedOutcome::InFlight,
            },
        );
        BeginRequest::Execute
    }

    async fn record_retryable(&self, request_id: RequestId) {
        if let Some(cached) = self.request_ledger.lock().await.entries.get_mut(&request_id) {
            cached.outcome = CachedOutcome::Retryable;
        }
    }

    async fn record_complete(&self, request_id: RequestId, result: Result<RuntimeStatus>) {
        if let Some(cached) = self.request_ledger.lock().await.entries.get_mut(&request_id) {
            cached.outcome = CachedOutcome::Complete(result);
        }
    }

    fn publish(
        &self,
        lifecycle: RuntimeLifecycleState,
        liveness: RuntimeLiveness,
        fault: Option<RuntimeFaultCode>,
    ) -> RuntimeStatus {
        let status = RuntimeStatus::new(R::ROLE, lifecycle, liveness, RuntimeReadiness::NotReady, fault);
        self.status_tx.send_replace(status);
        status
    }
}

struct LifecycleCommand {
    request_id: RequestId,
    event: RuntimeLifecycleEvent,
    caller_cancellation: CancellationToken,
    reply_tx: oneshot::Sender<Result<RuntimeStatus>>,
}

#[derive(Default)]
struct RequestLedger {
    entries: BTreeMap<RequestId, CachedCommand>,
}

#[derive(Clone, Copy)]
struct CachedCommand {
    event: RuntimeLifecycleEvent,
    outcome: CachedOutcome,
}

#[derive(Clone, Copy)]
enum CachedOutcome {
    InFlight,
    Retryable,
    Complete(Result<RuntimeStatus>),
}

enum BeginRequest {
    Execute,
    Replay(Result<RuntimeStatus>),
    Reject(RuntimeError),
}

struct RoleResources {
    data_dir: PathBuf,
    handler_identity: RuntimeHandlerIdentity,
    control: ControlServerConfig,
    redacted: RedactedRuntimeConfig,
    role_blockers: &'static [RuntimeBlocker],
}

impl RoleResources {
    fn from_handoff<R: RuntimeRoleMarker>(handoff: &RuntimeHandoff<'_>) -> Result<Self> {
        let actual = handoff_role(handoff);
        if actual != R::ROLE {
            return Err(RuntimeError::WrongRole {
                expected: R::ROLE,
                actual,
            });
        }
        match R::ROLE {
            RuntimeRole::Ledger => {
                let config = handoff.ledger().ok_or(RuntimeError::WrongRole {
                    expected: R::ROLE,
                    actual,
                })?;
                Ok(Self::common(
                    R::ROLE,
                    config.identity(),
                    config.paths(),
                    config.control(),
                    RuntimeHandlerIdentity::for_ledger(config),
                    LEDGER_BLOCKERS,
                ))
            }
            RuntimeRole::Holder => {
                let config = handoff.holder().ok_or(RuntimeError::WrongRole {
                    expected: R::ROLE,
                    actual,
                })?;
                Ok(Self::common(
                    R::ROLE,
                    config.identity(),
                    config.paths(),
                    config.control(),
                    RuntimeHandlerIdentity::for_holder(config),
                    HOLDER_BLOCKERS,
                ))
            }
            RuntimeRole::Committee => {
                let config = handoff.committee().ok_or(RuntimeError::WrongRole {
                    expected: R::ROLE,
                    actual,
                })?;
                Ok(Self::common(
                    R::ROLE,
                    config.identity(),
                    config.paths(),
                    config.control(),
                    RuntimeHandlerIdentity::for_committee(config),
                    COMMITTEE_BLOCKERS,
                ))
            }
        }
    }

    fn common(
        role: RuntimeRole,
        identity: &DeploymentIdentity,
        paths: &RuntimePaths,
        control: &ControlServerConfig,
        handler_identity: RuntimeHandlerIdentity,
        role_blockers: &'static [RuntimeBlocker],
    ) -> Self {
        Self {
            data_dir: paths.data_dir().to_path_buf(),
            handler_identity,
            control: control.clone(),
            redacted: RedactedRuntimeConfig::from_identity(role, identity),
            role_blockers,
        }
    }
}

fn handoff_role(handoff: &RuntimeHandoff<'_>) -> RuntimeRole {
    if handoff.ledger().is_some() {
        RuntimeRole::Ledger
    } else if handoff.holder().is_some() {
        RuntimeRole::Holder
    } else {
        RuntimeRole::Committee
    }
}

async fn invoke_handler<R, H>(
    handler: &H,
    event: RuntimeLifecycleEvent,
    deadline: Duration,
    caller_cancellation: &CancellationToken,
) -> Result<()>
where
    R: RuntimeRoleMarker,
    H: RuntimeLifecycleHandler<R>,
{
    if caller_cancellation.is_cancelled() {
        return Err(RuntimeError::CommandCancelled);
    }
    let cancellation = CancellationToken::new();
    let _guard = CancelOnDrop(cancellation.clone());
    let future = catch_unwind(AssertUnwindSafe(|| handler.on_lifecycle(event, cancellation)))
        .map_err(|_| RuntimeError::HandlerPanic)?;
    let outcome = tokio::select! {
        biased;
        result = timeout(deadline, AssertUnwindSafe(future).catch_unwind()) => result,
        _ = caller_cancellation.cancelled() => return Err(RuntimeError::CommandCancelled),
    };
    match outcome {
        Ok(Ok(Ok(()))) => Ok(()),
        Ok(Ok(Err(_))) => Err(RuntimeError::HandlerFailure),
        Ok(Err(_)) => Err(RuntimeError::HandlerPanic),
        Err(_) => Err(RuntimeError::HandlerDeadline),
    }
}

struct CancelOnDrop(CancellationToken);

impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        self.0.cancel();
    }
}

struct ActorExitGuard {
    status_tx: watch::Sender<RuntimeStatus>,
    role: RuntimeRole,
    armed: bool,
}

impl ActorExitGuard {
    fn new(status_tx: watch::Sender<RuntimeStatus>, role: RuntimeRole) -> Self {
        Self {
            status_tx,
            role,
            armed: true,
        }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for ActorExitGuard {
    fn drop(&mut self) {
        if self.armed {
            self.status_tx.send_replace(RuntimeStatus::new(
                self.role,
                RuntimeLifecycleState::Faulted,
                RuntimeLiveness::NotLive,
                RuntimeReadiness::NotReady,
                Some(RuntimeFaultCode::ActorCancelled),
            ));
        }
    }
}

fn send_reply(reply: oneshot::Sender<Result<RuntimeStatus>>, result: Result<RuntimeStatus>) {
    let _ = reply.send(result);
}

const fn fault_code(error: RuntimeError) -> RuntimeFaultCode {
    match error {
        RuntimeError::HandlerFailure => RuntimeFaultCode::HandlerFailure,
        RuntimeError::HandlerDeadline => RuntimeFaultCode::HandlerDeadline,
        RuntimeError::HandlerPanic => RuntimeFaultCode::HandlerPanic,
        RuntimeError::ProcessStateUnavailable => RuntimeFaultCode::ProcessStateUnavailable,
        RuntimeError::DiagnosticEncoding => RuntimeFaultCode::ProcessStateUnavailable,
        RuntimeError::ActorUnavailable
        | RuntimeError::WrongRole { .. }
        | RuntimeError::HandlerIdentityMismatch
        | RuntimeError::UnsafeProcessLock
        | RuntimeError::ProcessAlreadyRunning
        | RuntimeError::ProcessLockUnavailable
        | RuntimeError::ProcessLockIdentityMismatch
        | RuntimeError::CommandQueueFull
        | RuntimeError::RequestLedgerFull
        | RuntimeError::RequestIdConflict
        | RuntimeError::CommandCancelled
        | RuntimeError::DirtyRestartBlocked
        | RuntimeError::CommandDeadline
        | RuntimeError::InvalidTransition { .. }
        | RuntimeError::ActorCancelled => RuntimeFaultCode::ActorChannelClosed,
    }
}
