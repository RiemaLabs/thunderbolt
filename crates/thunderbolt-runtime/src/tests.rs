#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::error::Error;
use std::fmt;
use std::marker::PhantomData;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures_util::FutureExt as _;
use sha2::{Digest as _, Sha256};
use thunderbolt_control::{ControlHandler as _, ControlRequest, ControlStatus, RequestId};
use thunderbolt_runtime_config::{EffectiveRuntimeConfig, ParsedRuntimeConfig, RuntimeRole};
use tokio_util::sync::CancellationToken;

use crate::types::{COMMITTEE_BLOCKERS, COMMON_BLOCKERS, HOLDER_BLOCKERS, LEDGER_BLOCKERS};
use crate::*;

const HOLDER_SAMPLE: &str = include_str!("../../thunderbolt-runtime-config/examples/holder-regtest.toml");

enum HandlerBehavior {
    Success,
    FailStart(Duration),
    HangStart(Arc<AtomicBool>),
    SlowSuccess {
        event: RuntimeLifecycleEvent,
        delay: Duration,
        completed: Arc<AtomicBool>,
    },
    RaceSuccess {
        event: RuntimeLifecycleEvent,
        entered: Arc<Mutex<Option<tokio::sync::oneshot::Sender<()>>>>,
        release: Arc<tokio::sync::Notify>,
        mutations: Arc<AtomicUsize>,
    },
}

struct TestHandler<R> {
    identity: RuntimeHandlerIdentity,
    behavior: HandlerBehavior,
    events: Arc<Mutex<Vec<RuntimeLifecycleEvent>>>,
    _role: PhantomData<R>,
}

impl<R> TestHandler<R> {
    fn success(identity: RuntimeHandlerIdentity) -> Self {
        Self {
            identity,
            behavior: HandlerBehavior::Success,
            events: Arc::new(Mutex::new(Vec::new())),
            _role: PhantomData,
        }
    }

    fn failing_start(identity: RuntimeHandlerIdentity, delay: Duration) -> Self {
        Self {
            identity,
            behavior: HandlerBehavior::FailStart(delay),
            events: Arc::new(Mutex::new(Vec::new())),
            _role: PhantomData,
        }
    }

    fn hanging_start(identity: RuntimeHandlerIdentity, dropped: Arc<AtomicBool>) -> Self {
        Self {
            identity,
            behavior: HandlerBehavior::HangStart(dropped),
            events: Arc::new(Mutex::new(Vec::new())),
            _role: PhantomData,
        }
    }

    fn slow_success(
        identity: RuntimeHandlerIdentity,
        event: RuntimeLifecycleEvent,
        delay: Duration,
        completed: Arc<AtomicBool>,
    ) -> Self {
        Self {
            identity,
            behavior: HandlerBehavior::SlowSuccess {
                event,
                delay,
                completed,
            },
            events: Arc::new(Mutex::new(Vec::new())),
            _role: PhantomData,
        }
    }

    fn racing_success(
        identity: RuntimeHandlerIdentity,
        event: RuntimeLifecycleEvent,
        entered: tokio::sync::oneshot::Sender<()>,
        release: Arc<tokio::sync::Notify>,
        mutations: Arc<AtomicUsize>,
    ) -> Self {
        Self {
            identity,
            behavior: HandlerBehavior::RaceSuccess {
                event,
                entered: Arc::new(Mutex::new(Some(entered))),
                release,
                mutations,
            },
            events: Arc::new(Mutex::new(Vec::new())),
            _role: PhantomData,
        }
    }

    fn event_log(&self) -> Arc<Mutex<Vec<RuntimeLifecycleEvent>>> {
        self.events.clone()
    }
}

#[derive(Debug)]
struct TestHandlerError;

impl fmt::Display for TestHandlerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("test handler failed")
    }
}

impl Error for TestHandlerError {}

impl<R: RuntimeRoleMarker> RuntimeLifecycleHandler<R> for TestHandler<R> {
    type Error = TestHandlerError;

    fn identity(&self) -> RuntimeHandlerIdentity {
        self.identity.clone()
    }

    fn on_lifecycle(
        &self,
        event: RuntimeLifecycleEvent,
        cancellation: CancellationToken,
    ) -> RuntimeHandlerFuture<'_, Self::Error> {
        self.events.lock().unwrap().push(event);
        match &self.behavior {
            HandlerBehavior::Success => Box::pin(async { Ok(()) }),
            HandlerBehavior::FailStart(delay) if event == RuntimeLifecycleEvent::Start => {
                let delay = *delay;
                Box::pin(async move {
                    tokio::time::sleep(delay).await;
                    Err(TestHandlerError)
                })
            }
            HandlerBehavior::HangStart(dropped) if event == RuntimeLifecycleEvent::Start => {
                let dropped = dropped.clone();
                Box::pin(async move {
                    let _drop_signal = DropSignal(dropped);
                    cancellation.cancelled().await;
                    Err(TestHandlerError)
                })
            }
            HandlerBehavior::SlowSuccess {
                event: target,
                delay,
                completed,
            } if event == *target => {
                let delay = *delay;
                let completed = completed.clone();
                Box::pin(async move {
                    tokio::time::sleep(delay).await;
                    completed.store(true, Ordering::SeqCst);
                    Ok(())
                })
            }
            HandlerBehavior::RaceSuccess {
                event: target,
                entered,
                release,
                mutations,
            } if event == *target => {
                let entered = entered.lock().unwrap().take();
                let release = release.clone();
                let mutations = mutations.clone();
                Box::pin(async move {
                    if let Some(entered) = entered {
                        let _ = entered.send(());
                    }
                    release.notified().await;
                    mutations.fetch_add(1, Ordering::SeqCst);
                    Ok(())
                })
            }
            HandlerBehavior::FailStart(_)
            | HandlerBehavior::HangStart(_)
            | HandlerBehavior::SlowSuccess { .. }
            | HandlerBehavior::RaceSuccess { .. } => Box::pin(async { Ok(()) }),
        }
    }
}

struct DropSignal(Arc<AtomicBool>);

impl Drop for DropSignal {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
}

#[test]
fn three_role_types_have_distinct_nonempty_blocker_sets() {
    assert_eq!(<LedgerRole as RuntimeRoleMarker>::ROLE, RuntimeRole::Ledger);
    assert_eq!(<HolderRole as RuntimeRoleMarker>::ROLE, RuntimeRole::Holder);
    assert_eq!(<CommitteeRole as RuntimeRoleMarker>::ROLE, RuntimeRole::Committee);
    assert_eq!(COMMON_BLOCKERS[0].code(), RuntimeBlockerCode::NonProductionProfile);
    assert!(LEDGER_BLOCKERS
        .iter()
        .any(|blocker| blocker.code() == RuntimeBlockerCode::StaticAdmissionVerifierUnavailable));
    assert!(HOLDER_BLOCKERS
        .iter()
        .any(|blocker| blocker.code() == RuntimeBlockerCode::HolderSigningUnavailable));
    assert!(COMMITTEE_BLOCKERS
        .iter()
        .any(|blocker| blocker.code() == RuntimeBlockerCode::CommitteeThresholdSigningUnavailable));
}

#[tokio::test]
async fn start_drain_stop_distinguishes_liveness_and_readiness() -> TestResult {
    let (_directory, effective) = holder_effective(200)?;
    let profile = handler_identity(&effective);
    let handler = TestHandler::<HolderRole>::success(profile.clone());
    let events = handler.event_log();
    let supervisor = HolderSupervisor::new(effective.revalidate_for_handoff()?, handler)?;
    let handle = supervisor.handle()?;
    assert_eq!(handle.status().liveness(), RuntimeLiveness::NotLive);
    assert_eq!(handle.status().readiness(), RuntimeReadiness::NotReady);
    assert!(handle
        .blockers()
        .iter()
        .any(|blocker| blocker.code() == RuntimeBlockerCode::NonProductionProfile));
    assert!(handle
        .blockers()
        .iter()
        .any(|blocker| blocker.code() == RuntimeBlockerCode::HolderSigningUnavailable));

    let operations = async {
        let started = handle.start(request_id(1)).await?;
        assert_eq!(handle.status().lifecycle(), RuntimeLifecycleState::Running);
        assert_eq!(handle.status().liveness(), RuntimeLiveness::Live);
        assert_eq!(handle.status().readiness(), RuntimeReadiness::NotReady);
        assert_eq!(handle.start(request_id(1)).await?, started);
        assert!(matches!(
            handle.drain(request_id(1)).await,
            Err(RuntimeError::RequestIdConflict)
        ));
        assert!(matches!(
            handle.start(request_id(2)).await,
            Err(RuntimeError::InvalidTransition {
                state: RuntimeLifecycleState::Running,
                event: RuntimeLifecycleEvent::Start,
            })
        ));
        assert!(matches!(
            handle.start(request_id(2)).await,
            Err(RuntimeError::InvalidTransition {
                state: RuntimeLifecycleState::Running,
                event: RuntimeLifecycleEvent::Start,
            })
        ));
        let drained = handle.drain(request_id(3)).await?;
        assert_eq!(handle.status().lifecycle(), RuntimeLifecycleState::Draining);
        assert_eq!(handle.status().readiness(), RuntimeReadiness::NotReady);
        assert_eq!(handle.drain(request_id(3)).await?, drained);
        let stopped = handle.stop(request_id(4)).await?;
        assert_eq!(handle.status().lifecycle(), RuntimeLifecycleState::Stopped);
        assert_eq!(handle.status().liveness(), RuntimeLiveness::NotLive);
        assert_eq!(handle.stop(request_id(4)).await?, stopped);
        Ok::<(), RuntimeError>(())
    };
    let (run_result, operation_result) = tokio::join!(supervisor.run(CancellationToken::new()), operations);
    run_result?;
    operation_result?;
    assert_eq!(
        *events.lock().unwrap(),
        [
            RuntimeLifecycleEvent::Start,
            RuntimeLifecycleEvent::Drain,
            RuntimeLifecycleEvent::Stop,
        ]
    );
    let restarted = HolderSupervisor::new(
        effective.revalidate_for_handoff()?,
        TestHandler::<HolderRole>::success(profile.clone()),
    )?;
    assert!(!restarted
        .handle()?
        .blockers()
        .iter()
        .any(|blocker| blocker.code() == RuntimeBlockerCode::DirtyRestartRecoveryRequired));
    drop(restarted);
    Ok(())
}

#[tokio::test]
async fn initialized_stop_skips_handler_and_remains_clean() -> TestResult {
    let (_directory, effective) = holder_effective(200)?;
    let identity = handler_identity(&effective);
    let handler = TestHandler::<HolderRole>::success(identity.clone());
    let events = handler.event_log();
    let supervisor = HolderSupervisor::new(effective.revalidate_for_handoff()?, handler)?;
    let handle = supervisor.handle()?;
    let operations = async {
        let stopped = handle.stop(request_id(1)).await?;
        assert_eq!(stopped.lifecycle(), RuntimeLifecycleState::Stopped);
        assert_eq!(handle.stop(request_id(1)).await?, stopped);
        Ok::<(), RuntimeError>(())
    };
    let (run_result, operation_result) = tokio::join!(supervisor.run(CancellationToken::new()), operations);
    run_result?;
    operation_result?;
    assert!(events.lock().unwrap().is_empty());

    let restart_handler = TestHandler::<HolderRole>::success(identity.clone());
    let restart_events = restart_handler.event_log();
    let restarted = HolderSupervisor::new(effective.revalidate_for_handoff()?, restart_handler)?;
    assert!(!restarted
        .handle()?
        .blockers()
        .iter()
        .any(|blocker| blocker.code() == RuntimeBlockerCode::DirtyRestartRecoveryRequired));
    let shutdown = CancellationToken::new();
    shutdown.cancel();
    restarted.run(shutdown).await?;
    assert!(restart_events.lock().unwrap().is_empty());

    let third = HolderSupervisor::new(
        effective.revalidate_for_handoff()?,
        TestHandler::<HolderRole>::success(identity),
    )?;
    assert!(!third
        .handle()?
        .blockers()
        .iter()
        .any(|blocker| blocker.code() == RuntimeBlockerCode::DirtyRestartRecoveryRequired));
    drop(third);
    Ok(())
}

#[test]
fn process_lock_rejects_double_start_and_unsafe_permissions() -> TestResult {
    use std::os::unix::fs::PermissionsExt as _;

    let (_directory, effective) = holder_effective(200)?;
    let profile = handler_identity(&effective);
    let first = HolderSupervisor::new(
        effective.revalidate_for_handoff()?,
        TestHandler::<HolderRole>::success(profile.clone()),
    )?;
    let second = HolderSupervisor::new(
        effective.revalidate_for_handoff()?,
        TestHandler::<HolderRole>::success(profile.clone()),
    );
    assert!(matches!(second, Err(RuntimeError::ProcessAlreadyRunning)));
    let lock_path = effective_data_dir(&effective)?.join(RUNTIME_PROCESS_LOCK_FILE);
    assert_eq!(std::fs::metadata(&lock_path)?.permissions().mode() & 0o777, 0o600);
    drop(first);

    std::fs::set_permissions(&lock_path, std::fs::Permissions::from_mode(0o644))?;
    let unsafe_lock = HolderSupervisor::new(
        effective.revalidate_for_handoff()?,
        TestHandler::<HolderRole>::success(profile),
    );
    assert!(matches!(unsafe_lock, Err(RuntimeError::UnsafeProcessLock)));
    Ok(())
}

#[test]
fn process_lock_marker_binds_exact_identity_and_rejects_malformed_state() -> TestResult {
    let (_directory, effective) = holder_effective(200)?;
    let (_other_directory, other_effective) = holder_effective_with_profile(200, b"other-lock-profile")?;
    let data_dir = effective_data_dir(&effective)?;
    let holder_identity = handler_identity(&effective);
    let other_identity = handler_identity(&other_effective);
    let lock = crate::process_lock::ProcessLock::acquire(&data_dir, &holder_identity)?;
    lock.mark_clean()?;
    drop(lock);

    assert!(matches!(
        crate::process_lock::ProcessLock::acquire(&data_dir, &other_identity),
        Err(RuntimeError::ProcessLockIdentityMismatch)
    ));
    std::fs::write(data_dir.join(RUNTIME_PROCESS_LOCK_FILE), b"malformed")?;
    assert!(matches!(
        crate::process_lock::ProcessLock::acquire(&data_dir, &holder_identity),
        Err(RuntimeError::ProcessStateUnavailable)
    ));
    Ok(())
}

#[tokio::test]
async fn lifecycle_mailbox_rejects_the_ninth_pending_command() -> TestResult {
    let (_directory, effective) = holder_effective(200)?;
    let profile = handler_identity(&effective);
    let supervisor = HolderSupervisor::new(
        effective.revalidate_for_handoff()?,
        TestHandler::<HolderRole>::success(profile.clone()),
    )?;
    let handle = supervisor.handle()?;
    for index in 0..MAX_PENDING_LIFECYCLE_COMMANDS {
        let id = request_id(u8::try_from(index + 1).unwrap());
        assert!(handle.start(id).now_or_never().is_none());
    }
    assert!(matches!(
        handle.start(request_id(20)).now_or_never(),
        Some(Err(RuntimeError::CommandQueueFull))
    ));
    drop(supervisor);
    Ok(())
}

#[tokio::test]
async fn request_id_ledger_never_evicts_and_rejects_the_sixty_fifth_id() -> TestResult {
    let (_directory, effective) = holder_effective(200)?;
    let identity = handler_identity(&effective);
    let supervisor = HolderSupervisor::new(
        effective.revalidate_for_handoff()?,
        TestHandler::<HolderRole>::success(identity),
    )?;
    let handle = supervisor.handle()?;
    let shutdown = CancellationToken::new();
    let operation_shutdown = shutdown.clone();
    let operations = async move {
        let first = handle.start(request_id(1)).await?;
        for discriminator in 2_u8..=64 {
            assert!(matches!(
                handle.start(request_id(discriminator)).await,
                Err(RuntimeError::InvalidTransition {
                    state: RuntimeLifecycleState::Running,
                    event: RuntimeLifecycleEvent::Start,
                })
            ));
        }
        assert!(matches!(
            handle.drain(request_id(65)).await,
            Err(RuntimeError::RequestLedgerFull)
        ));
        assert_eq!(handle.start(request_id(1)).await?, first);
        assert!(matches!(
            handle.drain(request_id(1)).await,
            Err(RuntimeError::RequestIdConflict)
        ));
        operation_shutdown.cancel();
        Ok::<(), RuntimeError>(())
    };
    let (run_result, operation_result) = tokio::join!(supervisor.run(shutdown), operations);
    run_result?;
    operation_result?;
    Ok(())
}

#[tokio::test]
async fn dropped_actor_marks_a_sticky_dirty_restart() -> TestResult {
    let (_directory, effective) = holder_effective(200)?;
    let profile = handler_identity(&effective);
    let supervisor = HolderSupervisor::new(
        effective.revalidate_for_handoff()?,
        TestHandler::<HolderRole>::success(profile.clone()),
    )?;
    let handle = supervisor.handle()?;
    let mut run = Box::pin(supervisor.run(CancellationToken::new()));
    let mut start = Box::pin(handle.start(request_id(1)));
    tokio::select! {
        result = &mut start => {
            let _ = result?;
        }
        result = &mut run => panic!("actor exited before start: {result:?}"),
    }
    assert_eq!(handle.status().lifecycle(), RuntimeLifecycleState::Running);
    drop(run);
    assert_eq!(handle.status().fault(), Some(RuntimeFaultCode::ActorCancelled));

    let second_handler = TestHandler::<HolderRole>::success(profile.clone());
    let second_events = second_handler.event_log();
    let second = HolderSupervisor::new(effective.revalidate_for_handoff()?, second_handler)?;
    let second_handle = second.handle()?;
    assert!(second_handle
        .blockers()
        .iter()
        .any(|blocker| blocker.code() == RuntimeBlockerCode::DirtyRestartRecoveryRequired));
    let operations = async {
        assert!(matches!(
            second_handle.start(request_id(2)).await,
            Err(RuntimeError::DirtyRestartBlocked)
        ));
        assert!(matches!(
            second_handle.start(request_id(2)).await,
            Err(RuntimeError::DirtyRestartBlocked)
        ));
        assert!(matches!(
            second_handle.drain(request_id(3)).await,
            Err(RuntimeError::DirtyRestartBlocked)
        ));
        let _ = second_handle.stop(request_id(4)).await?;
        Ok::<(), RuntimeError>(())
    };
    let (run_result, stop_result) = tokio::join!(second.run(CancellationToken::new()), operations);
    run_result?;
    stop_result?;
    assert!(second_events.lock().unwrap().is_empty());

    let third = HolderSupervisor::new(
        effective.revalidate_for_handoff()?,
        TestHandler::<HolderRole>::success(profile),
    )?;
    assert!(third
        .handle()?
        .blockers()
        .iter()
        .any(|blocker| blocker.code() == RuntimeBlockerCode::DirtyRestartRecoveryRequired));
    drop(third);
    Ok(())
}

#[tokio::test]
async fn handler_deadline_cancels_and_faults_the_actor() -> TestResult {
    let (_directory, effective) = holder_effective(20)?;
    let profile = handler_identity(&effective);
    let dropped = Arc::new(AtomicBool::new(false));
    let supervisor = HolderSupervisor::new(
        effective.revalidate_for_handoff()?,
        TestHandler::<HolderRole>::hanging_start(profile, dropped.clone()),
    )?;
    let handle = supervisor.handle()?;
    let (run_result, start_result) =
        tokio::join!(supervisor.run(CancellationToken::new()), handle.start(request_id(1)));
    assert!(matches!(run_result, Err(RuntimeError::HandlerDeadline)));
    assert!(matches!(start_result, Err(RuntimeError::HandlerDeadline)));
    assert!(dropped.load(Ordering::SeqCst));
    assert_eq!(handle.status().liveness(), RuntimeLiveness::NotLive);
    assert_eq!(handle.status().readiness(), RuntimeReadiness::NotReady);
    assert_eq!(handle.status().fault(), Some(RuntimeFaultCode::HandlerDeadline));
    Ok(())
}

#[tokio::test]
async fn external_cancellation_runs_the_bounded_stop_hook() -> TestResult {
    let (_directory, effective) = holder_effective(200)?;
    let profile = handler_identity(&effective);
    let handler = TestHandler::<HolderRole>::success(profile);
    let events = handler.event_log();
    let supervisor = HolderSupervisor::new(effective.revalidate_for_handoff()?, handler)?;
    let handle = supervisor.handle()?;
    let shutdown = CancellationToken::new();
    let operation_shutdown = shutdown.clone();
    let operations = async move {
        handle.start(request_id(1)).await?;
        operation_shutdown.cancel();
        Ok::<(), RuntimeError>(())
    };
    let (run_result, operation_result) = tokio::join!(supervisor.run(shutdown), operations);
    run_result?;
    operation_result?;
    assert_eq!(
        *events.lock().unwrap(),
        [RuntimeLifecycleEvent::Start, RuntimeLifecycleEvent::Stop]
    );
    Ok(())
}

#[tokio::test]
async fn dropped_outer_control_future_cancels_without_late_state_mutation() -> TestResult {
    let (_directory, effective) = holder_effective(200)?;
    let identity = handler_identity(&effective);
    let completed = Arc::new(AtomicBool::new(false));
    let supervisor = HolderSupervisor::new(
        effective.revalidate_for_handoff()?,
        TestHandler::<HolderRole>::slow_success(
            identity,
            RuntimeLifecycleEvent::Drain,
            Duration::from_millis(40),
            completed.clone(),
        ),
    )?;
    let handle = supervisor.handle()?;
    let control = supervisor.control_handler()?;
    let mut run = Box::pin(supervisor.run(CancellationToken::new()));
    let mut start = Box::pin(handle.start(request_id(1)));
    tokio::select! {
        result = &mut start => {
            let _ = result?;
        }
        result = &mut run => panic!("actor exited before start: {result:?}"),
    }

    let drain_id = request_id(2);
    let request = ControlRequest::new(drain_id, CONTROL_METHOD_DRAIN, Vec::new())?;
    let mut abandoned = Box::pin(control.handle(request));
    tokio::select! {
        () = tokio::time::sleep(Duration::from_millis(5)) => {}
        response = &mut abandoned => panic!("drain completed before outer timeout: {:?}", response.status()),
        result = &mut run => panic!("actor exited during drain barrier: {result:?}"),
    }
    drop(abandoned);
    tokio::select! {
        () = tokio::time::sleep(Duration::from_millis(60)) => {}
        result = &mut run => panic!("actor exited after caller cancellation: {result:?}"),
    }
    assert_eq!(handle.status().lifecycle(), RuntimeLifecycleState::Running);
    assert!(!completed.load(Ordering::SeqCst));

    let retry = ControlRequest::new(drain_id, CONTROL_METHOD_DRAIN, Vec::new())?;
    let mut retried = Box::pin(control.handle(retry));
    tokio::select! {
        response = &mut retried => assert_eq!(response.status(), ControlStatus::Ok),
        result = &mut run => panic!("actor exited before exact retry completed: {result:?}"),
    }
    assert!(completed.load(Ordering::SeqCst));
    assert_eq!(handle.status().lifecycle(), RuntimeLifecycleState::Draining);

    let stop = ControlRequest::new(request_id(3), CONTROL_METHOD_STOP, Vec::new())?;
    let (response, run_result) = tokio::join!(control.handle(stop), run.as_mut());
    assert_eq!(response.status(), ControlStatus::Ok);
    run_result?;
    Ok(())
}

#[tokio::test]
async fn simultaneous_hook_completion_and_outer_drop_commits_once_and_replays() -> TestResult {
    let (_directory, effective) = holder_effective(200)?;
    let identity = handler_identity(&effective);
    let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
    let release = Arc::new(tokio::sync::Notify::new());
    let mutations = Arc::new(AtomicUsize::new(0));
    let supervisor = HolderSupervisor::new(
        effective.revalidate_for_handoff()?,
        TestHandler::<HolderRole>::racing_success(
            identity,
            RuntimeLifecycleEvent::Drain,
            entered_tx,
            release.clone(),
            mutations.clone(),
        ),
    )?;
    let handle = supervisor.handle()?;
    let control = supervisor.control_handler()?;
    let mut run = Box::pin(supervisor.run(CancellationToken::new()));
    let mut start = Box::pin(handle.start(request_id(1)));
    tokio::select! {
        result = &mut start => {
            let _ = result?;
        }
        result = &mut run => panic!("actor exited before start: {result:?}"),
    }

    let drain_id = request_id(2);
    let request = ControlRequest::new(drain_id, CONTROL_METHOD_DRAIN, Vec::new())?;
    let mut outer = Box::pin(control.handle(request));
    let mut entered_rx = Box::pin(entered_rx);
    tokio::select! {
        entered = &mut entered_rx => entered.map_err(|_| "handler entry signal dropped")?,
        response = &mut outer => panic!("drain returned before barrier release: {:?}", response.status()),
        result = &mut run => panic!("actor exited before barrier release: {result:?}"),
    }
    release.notify_one();
    drop(outer);

    tokio::select! {
        () = tokio::time::sleep(Duration::from_millis(10)) => {}
        result = &mut run => panic!("actor exited after committed drain: {result:?}"),
    }
    assert_eq!(mutations.load(Ordering::SeqCst), 1);
    assert_eq!(handle.status().lifecycle(), RuntimeLifecycleState::Draining);
    let replayed = handle.drain(drain_id).await?;
    assert_eq!(replayed.lifecycle(), RuntimeLifecycleState::Draining);
    assert_eq!(mutations.load(Ordering::SeqCst), 1);

    let stop = handle.stop(request_id(3));
    let (stop_result, run_result) = tokio::join!(stop, run.as_mut());
    let _ = stop_result?;
    run_result?;
    Ok(())
}

#[tokio::test]
async fn ambiguous_command_crash_cannot_reapply_on_dirty_restart() -> TestResult {
    let (_directory, effective) = holder_effective(200)?;
    let identity = handler_identity(&effective);
    let completed = Arc::new(AtomicBool::new(false));
    let supervisor = HolderSupervisor::new(
        effective.revalidate_for_handoff()?,
        TestHandler::<HolderRole>::slow_success(
            identity.clone(),
            RuntimeLifecycleEvent::Start,
            Duration::from_millis(40),
            completed.clone(),
        ),
    )?;
    let handle = supervisor.handle()?;
    let mut run = Box::pin(supervisor.run(CancellationToken::new()));
    let command_id = request_id(9);
    let mut abandoned = Box::pin(handle.start(command_id));
    tokio::select! {
        () = tokio::time::sleep(Duration::from_millis(5)) => {}
        result = &mut abandoned => panic!("start completed before ambiguity barrier: {result:?}"),
        result = &mut run => panic!("actor exited before ambiguity barrier: {result:?}"),
    }
    drop(abandoned);
    tokio::select! {
        () = tokio::time::sleep(Duration::from_millis(60)) => {}
        result = &mut run => panic!("actor exited after cancelled start: {result:?}"),
    }
    assert_eq!(handle.status().lifecycle(), RuntimeLifecycleState::Initialized);
    assert!(!completed.load(Ordering::SeqCst));
    drop(run);

    let restart_handler = TestHandler::<HolderRole>::success(identity);
    let restart_events = restart_handler.event_log();
    let restarted = HolderSupervisor::new(effective.revalidate_for_handoff()?, restart_handler)?;
    let restarted_handle = restarted.handle()?;
    let operations = async {
        assert!(matches!(
            restarted_handle.start(command_id).await,
            Err(RuntimeError::DirtyRestartBlocked)
        ));
        let _ = restarted_handle.stop(request_id(10)).await?;
        Ok::<(), RuntimeError>(())
    };
    let (run_result, operation_result) = tokio::join!(restarted.run(CancellationToken::new()), operations);
    run_result?;
    operation_result?;
    assert!(restart_events.lock().unwrap().is_empty());
    Ok(())
}

#[tokio::test]
async fn dropping_every_external_sender_faults_live_actor_and_marks_dirty() -> TestResult {
    let (_directory, effective) = holder_effective(200)?;
    let identity = handler_identity(&effective);
    let supervisor = HolderSupervisor::new(
        effective.revalidate_for_handoff()?,
        TestHandler::<HolderRole>::success(identity.clone()),
    )?;
    let handle = supervisor.handle()?;
    let monitor = handle.monitor();
    let mut run = Box::pin(supervisor.run(CancellationToken::new()));
    let mut start = Box::pin(handle.start(request_id(1)));
    tokio::select! {
        result = &mut start => {
            let _ = result?;
        }
        result = &mut run => panic!("actor exited before start: {result:?}"),
    }
    drop(start);
    drop(handle);
    assert!(matches!(run.await, Err(RuntimeError::ActorUnavailable)));
    assert_eq!(monitor.status().lifecycle(), RuntimeLifecycleState::Faulted);
    assert_eq!(monitor.status().fault(), Some(RuntimeFaultCode::ActorChannelClosed));

    let restarted = HolderSupervisor::new(
        effective.revalidate_for_handoff()?,
        TestHandler::<HolderRole>::success(identity),
    )?;
    assert!(restarted
        .handle()?
        .blockers()
        .iter()
        .any(|blocker| blocker.code() == RuntimeBlockerCode::DirtyRestartRecoveryRequired));
    drop(restarted);
    Ok(())
}

#[tokio::test]
async fn ignored_handler_error_still_faults_and_fails_run() -> TestResult {
    let (_directory, effective) = holder_effective(100)?;
    let profile = handler_identity(&effective);
    let supervisor = HolderSupervisor::new(
        effective.revalidate_for_handoff()?,
        TestHandler::<HolderRole>::failing_start(profile, Duration::from_millis(25)),
    )?;
    let handle = supervisor.handle()?;
    handle.enqueue_ignored(request_id(1), RuntimeLifecycleEvent::Start)?;
    assert!(matches!(
        supervisor.run(CancellationToken::new()).await,
        Err(RuntimeError::HandlerFailure)
    ));
    assert_eq!(handle.status().fault(), Some(RuntimeFaultCode::HandlerFailure));
    assert_eq!(handle.status().liveness(), RuntimeLiveness::NotLive);
    Ok(())
}

#[test]
fn wrong_role_and_identity_are_rejected_before_locking() -> TestResult {
    let (_directory, effective) = holder_effective(200)?;
    let identity = handler_identity(&effective);
    let wrong_role = LedgerSupervisor::new(
        effective.revalidate_for_handoff()?,
        TestHandler::<LedgerRole>::success(identity),
    );
    assert!(matches!(
        wrong_role,
        Err(RuntimeError::WrongRole {
            expected: RuntimeRole::Ledger,
            actual: RuntimeRole::Holder,
        })
    ));
    let (_other_directory, other_effective) = holder_effective_with_profile(200, b"different-profile")?;
    let wrong_identity = HolderSupervisor::new(
        effective.revalidate_for_handoff()?,
        TestHandler::<HolderRole>::success(handler_identity(&other_effective)),
    );
    assert!(matches!(wrong_identity, Err(RuntimeError::HandlerIdentityMismatch)));
    assert!(!effective_data_dir(&effective)?.join(RUNTIME_PROCESS_LOCK_FILE).exists());
    Ok(())
}

#[tokio::test]
async fn control_surface_is_fixed_empty_payload_and_redacted() -> TestResult {
    let (directory, effective) = holder_effective(200)?;
    let profile = handler_identity(&effective);
    let supervisor = HolderSupervisor::new(
        effective.revalidate_for_handoff()?,
        TestHandler::<HolderRole>::success(profile),
    )?;
    let handle = supervisor.handle()?;
    let control = supervisor.control_handler()?;
    let root_text = directory.path().to_string_lossy().into_owned();
    let operations = async {
        let status = control_call(&control, 1, CONTROL_METHOD_STATUS, Vec::new()).await?;
        assert_eq!(status.status(), ControlStatus::Ok);
        let status_json: serde_json::Value = serde_json::from_slice(status.payload())?;
        assert_eq!(status_json["readiness"], "not_ready");
        assert!(status.payload().len() <= MAX_RUNTIME_CONTROL_PAYLOAD_BYTES);

        let config = control_call(&control, 2, CONTROL_METHOD_REDACTED_CONFIG, Vec::new()).await?;
        assert_eq!(config.status(), ControlStatus::Ok);
        let config_text = std::str::from_utf8(config.payload())?;
        assert!(!config_text.contains(&root_text));
        assert!(!config_text.contains("127.0.0.1"));
        assert!(!config_text.contains("__cookie__"));
        assert!(!config_text.contains("vault.password"));
        assert!(config_text.contains("<redacted>"));
        assert!(config.payload().len() <= MAX_RUNTIME_CONTROL_PAYLOAD_BYTES);

        let blockers = control_call(&control, 3, CONTROL_METHOD_BLOCKERS, Vec::new()).await?;
        assert_eq!(blockers.status(), ControlStatus::Ok);
        assert!(std::str::from_utf8(blockers.payload())?.contains("holder_signing_unavailable"));
        assert!(blockers.payload().len() <= MAX_RUNTIME_CONTROL_PAYLOAD_BYTES);

        let raw = control_call(&control, 4, CONTROL_METHOD_STATUS, vec![0x01]).await?;
        assert_eq!(raw.status(), ControlStatus::InvalidRequest);
        let start = control_call(&control, 5, "runtime.start", Vec::new()).await?;
        assert_eq!(start.status(), ControlStatus::InvalidRequest);

        handle.start(request_id(8)).await?;
        let drain = control_call(&control, 6, CONTROL_METHOD_DRAIN, Vec::new()).await?;
        assert_eq!(drain.status(), ControlStatus::Ok);
        let stop = control_call(&control, 7, CONTROL_METHOD_STOP, Vec::new()).await?;
        assert_eq!(stop.status(), ControlStatus::Ok);
        Ok::<(), Box<dyn Error>>(())
    };
    let (run_result, operation_result) = tokio::join!(supervisor.run(CancellationToken::new()), operations);
    run_result?;
    operation_result?;
    Ok(())
}

async fn control_call<R: RuntimeRoleMarker>(
    control: &RuntimeControl<R>,
    discriminator: u8,
    method: &str,
    payload: Vec<u8>,
) -> TestResult<thunderbolt_control::ControlResponse> {
    let request = ControlRequest::new(RequestId::from_bytes([discriminator; 16])?, method, payload)?;
    Ok(control.handle(request).await)
}

type TestResult<T = ()> = std::result::Result<T, Box<dyn Error>>;

fn request_id(discriminator: u8) -> RequestId {
    RequestId::from_bytes([discriminator; 16]).unwrap()
}

fn holder_effective(handler_timeout_ms: u64) -> TestResult<(tempfile::TempDir, EffectiveRuntimeConfig)> {
    holder_effective_with_profile(handler_timeout_ms, b"profile")
}

fn holder_effective_with_profile(
    handler_timeout_ms: u64,
    profile_bytes: &[u8],
) -> TestResult<(tempfile::TempDir, EffectiveRuntimeConfig)> {
    use std::os::unix::fs::PermissionsExt as _;

    let directory = tempfile::tempdir()?;
    let root = std::fs::canonicalize(directory.path())?;
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700))?;
    let data = root.join("holder-data");
    let control = root.join("holder-control");
    std::fs::create_dir(&data)?;
    std::fs::create_dir(&control)?;
    std::fs::set_permissions(&data, std::fs::Permissions::from_mode(0o700))?;
    std::fs::set_permissions(&control, std::fs::Permissions::from_mode(0o700))?;

    let descriptor = owner_file(&root, "descriptor.json", b"descriptor")?;
    let anchor = owner_file(&root, "anchor.json", b"anchor")?;
    let profile = owner_file(&root, "profile.json", profile_bytes)?;
    let vault_checkpoint = owner_file(&root, "vault-checkpoint.json", b"vault-checkpoint")?;
    let trust_checkpoint = owner_file(&root, "trust-checkpoint.json", b"trust-checkpoint")?;
    let trust_root = owner_file(&root, "trust-root.json", b"trust-root")?;
    let cookie = owner_file(&root, "bitcoin.cookie", b"__cookie__:secret")?;
    let vault_password = owner_file(&root, "vault.password", b"secret")?;

    let descriptor_digest = digest(b"descriptor");
    let anchor_digest = digest(b"anchor");
    let profile_digest = digest(profile_bytes);
    let runtime_profile = derived(b"bitcoin-thunderbolt/runtime-config/runtime-profile/v2", profile_digest);
    let finality_profile = derived_pair(
        b"bitcoin-thunderbolt/runtime-config/finality-verifier-profile/v2",
        profile_digest,
        decode_hex32("50d4e01279dbb7fcf6cb0e8a7d407b7713d86b83346b13c60f13b52f8045728d")?,
    );
    let mut config = HOLDER_SAMPLE
        .replace("/var/lib/thunderbolt/regtest/holder-01", &toml_path(&data))
        .replace("/run/user/1000/thunderbolt-regtest-holder-01", &toml_path(&control))
        .replace(
            "/etc/thunderbolt/regtest/holder-01-vault-password",
            &toml_path(&vault_password),
        )
        .replace(
            "/etc/thunderbolt/regtest/holder-01-vault-checkpoint-provider.json",
            &toml_path(&vault_checkpoint),
        )
        .replace(
            "/etc/thunderbolt/regtest/holder-01-trust-checkpoint-provider.json",
            &toml_path(&trust_checkpoint),
        )
        .replace("/etc/thunderbolt/regtest/comet-root.json", &toml_path(&trust_root))
        .replace("/etc/thunderbolt/regtest/bitcoin-cookie.ref", &toml_path(&cookie))
        .replace(
            "/etc/thunderbolt/regtest/committee-descriptor.json",
            &toml_path(&descriptor),
        )
        .replace("/etc/thunderbolt/regtest/anchor-suite.json", &toml_path(&anchor))
        .replace("/etc/thunderbolt/regtest/runtime-profile.json", &toml_path(&profile))
        .replace(&"22".repeat(32), &hex::encode(descriptor_digest))
        .replace(&"33".repeat(32), &hex::encode(anchor_digest))
        .replace(&"aa".repeat(32), &hex::encode(profile_digest))
        .replace(&"44".repeat(32), &hex::encode(digest(b"vault-checkpoint")))
        .replace(&"55".repeat(32), &hex::encode(digest(b"trust-checkpoint")))
        .replace(&"66".repeat(32), &hex::encode(digest(b"trust-root")))
        .replace(
            "4ba1fc95b531329ae4161c164302210a740b60e9071859687aa64d3ebbad53c2",
            &hex::encode(runtime_profile),
        )
        .replace(
            "5e4d04cd79e904b5457c689d6c1f810f01c81c156ec637af30126f7a9fbfe7b8",
            &hex::encode(finality_profile),
        );
    config = config.replace(
        "handler_timeout_ms = 4000",
        &format!("handler_timeout_ms = {handler_timeout_ms}"),
    );
    let effective = ParsedRuntimeConfig::parse_toml(&config)?.validate_filesystem()?;
    Ok((directory, effective))
}

fn effective_data_dir(effective: &EffectiveRuntimeConfig) -> TestResult<PathBuf> {
    let handoff = effective.revalidate_for_handoff()?;
    Ok(handoff
        .holder()
        .ok_or("expected Holder handoff")?
        .paths()
        .data_dir()
        .to_path_buf())
}

fn handler_identity(effective: &EffectiveRuntimeConfig) -> RuntimeHandlerIdentity {
    let handoff = effective.revalidate_for_handoff().unwrap();
    RuntimeHandlerIdentity::for_holder(handoff.holder().unwrap())
}

fn owner_file(root: &Path, name: &str, bytes: &[u8]) -> TestResult<PathBuf> {
    use std::os::unix::fs::PermissionsExt as _;

    let path = root.join(name);
    std::fs::write(&path, bytes)?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    Ok(path)
}

fn digest(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn derived(domain: &[u8], source: [u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(source);
    hasher.finalize().into()
}

fn derived_pair(domain: &[u8], first: [u8; 32], second: [u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(first);
    hasher.update(second);
    hasher.finalize().into()
}

fn decode_hex32(value: &str) -> TestResult<[u8; 32]> {
    Ok(hex::decode(value)?.try_into().map_err(|_| "hex length")?)
}

fn toml_path(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}
