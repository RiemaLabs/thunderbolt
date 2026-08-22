use serde::Serialize;
use thunderbolt_control::{ControlHandler, ControlHandlerFuture, ControlRequest, ControlResponse, ControlStatus};

use crate::{Result, RuntimeError, RuntimeHandle, RuntimeLifecycleState, RuntimeRoleMarker, RUNTIME_SHELL_VERSION_V2};

/// Fixed status method for the owner-only local control plane.
pub const CONTROL_METHOD_STATUS: &str = "runtime.status";
/// Fixed redacted-configuration method for the owner-only local control plane.
pub const CONTROL_METHOD_REDACTED_CONFIG: &str = "runtime.redacted_config";
/// Fixed readiness-blocker method for the owner-only local control plane.
pub const CONTROL_METHOD_BLOCKERS: &str = "runtime.blockers";
/// Fixed drain method for the owner-only local control plane.
pub const CONTROL_METHOD_DRAIN: &str = "runtime.drain";
/// Fixed stop method for the owner-only local control plane.
pub const CONTROL_METHOD_STOP: &str = "runtime.stop";
/// Maximum encoded status, blocker, or redacted-configuration payload.
pub const MAX_RUNTIME_CONTROL_PAYLOAD_BYTES: usize = 16 * 1024;

/// Fixed-method runtime control adapter. It binds no socket or network listener.
pub struct RuntimeControl<R: RuntimeRoleMarker> {
    handle: RuntimeHandle<R>,
}

impl<R: RuntimeRoleMarker> Clone for RuntimeControl<R> {
    fn clone(&self) -> Self {
        Self {
            handle: self.handle.clone(),
        }
    }
}

impl<R: RuntimeRoleMarker> RuntimeControl<R> {
    pub(crate) fn new(handle: RuntimeHandle<R>) -> Self {
        Self { handle }
    }

    async fn dispatch(&self, request: ControlRequest) -> ControlResponse {
        let request_id = request.request_id();
        if !request.payload().is_empty() {
            return failure(
                request_id,
                ControlStatus::InvalidRequest,
                "runtime control methods require an empty payload",
            );
        }
        match request.method() {
            CONTROL_METHOD_STATUS => encode_success(request_id, &self.handle.status()),
            CONTROL_METHOD_REDACTED_CONFIG => encode_success(request_id, self.handle.redacted_config()),
            CONTROL_METHOD_BLOCKERS => encode_success(
                request_id,
                &BlockerReport {
                    runtime_version: RUNTIME_SHELL_VERSION_V2,
                    role: R::ROLE,
                    blockers: self.handle.blockers(),
                },
            ),
            CONTROL_METHOD_DRAIN => self.lifecycle_response(request_id, self.handle.drain(request_id).await),
            CONTROL_METHOD_STOP => self.lifecycle_response(request_id, self.handle.stop(request_id).await),
            _ => failure(
                request_id,
                ControlStatus::InvalidRequest,
                "unknown runtime control method",
            ),
        }
    }

    fn lifecycle_response(
        &self,
        request_id: thunderbolt_control::RequestId,
        result: Result<crate::RuntimeStatus>,
    ) -> ControlResponse {
        match result {
            Ok(status) => encode_success(request_id, &status),
            Err(error) => runtime_failure(request_id, error),
        }
    }
}

impl<R: RuntimeRoleMarker> ControlHandler for RuntimeControl<R> {
    fn handle(&self, request: ControlRequest) -> ControlHandlerFuture<'_> {
        Box::pin(async move { self.dispatch(request).await })
    }
}

#[derive(Serialize)]
struct BlockerReport<'a> {
    runtime_version: u16,
    role: thunderbolt_runtime_config::RuntimeRole,
    blockers: &'a [crate::RuntimeBlocker],
}

fn encode_success<T: Serialize>(request_id: thunderbolt_control::RequestId, value: &T) -> ControlResponse {
    match serde_json::to_vec(value) {
        Ok(payload) if payload.len() <= MAX_RUNTIME_CONTROL_PAYLOAD_BYTES => {
            ControlResponse::success(request_id, payload)
        }
        Ok(_) => failure(
            request_id,
            ControlStatus::Internal,
            "runtime diagnostic payload exceeded its bound",
        ),
        Err(_) => failure(
            request_id,
            ControlStatus::Internal,
            "runtime diagnostic encoding failed",
        ),
    }
}

fn runtime_failure(request_id: thunderbolt_control::RequestId, error: RuntimeError) -> ControlResponse {
    let (status, message) = match error {
        RuntimeError::InvalidTransition {
            state: RuntimeLifecycleState::Draining,
            ..
        } => (ControlStatus::Draining, "runtime is already draining"),
        RuntimeError::InvalidTransition { .. } => (ControlStatus::Conflict, "runtime lifecycle transition conflicts"),
        RuntimeError::CommandQueueFull => (ControlStatus::Busy, "runtime lifecycle queue is full"),
        RuntimeError::RequestLedgerFull => (ControlStatus::Busy, "runtime request ledger is full"),
        RuntimeError::RequestIdConflict => (ControlStatus::Conflict, "runtime request id conflicts"),
        RuntimeError::CommandCancelled => (
            ControlStatus::Ambiguous,
            "runtime command was cancelled before commit; retry the exact request id",
        ),
        RuntimeError::DirtyRestartBlocked => (
            ControlStatus::Conflict,
            "runtime is blocked pending external dirty-restart recovery",
        ),
        RuntimeError::CommandDeadline => (
            ControlStatus::Ambiguous,
            "runtime command deadline elapsed; retry the exact request id",
        ),
        RuntimeError::ActorUnavailable | RuntimeError::ActorCancelled => {
            (ControlStatus::Internal, "runtime lifecycle actor is unavailable")
        }
        RuntimeError::HandlerFailure | RuntimeError::HandlerDeadline | RuntimeError::HandlerPanic => {
            (ControlStatus::Internal, "runtime lifecycle handler failed")
        }
        RuntimeError::ProcessStateUnavailable
        | RuntimeError::DiagnosticEncoding
        | RuntimeError::WrongRole { .. }
        | RuntimeError::HandlerIdentityMismatch
        | RuntimeError::UnsafeProcessLock
        | RuntimeError::ProcessAlreadyRunning
        | RuntimeError::ProcessLockUnavailable
        | RuntimeError::ProcessLockIdentityMismatch => (ControlStatus::Internal, "runtime internal failure"),
    };
    failure(request_id, status, message)
}

fn failure(
    request_id: thunderbolt_control::RequestId,
    status: ControlStatus,
    message: &'static str,
) -> ControlResponse {
    match ControlResponse::failure(request_id, status, message) {
        Ok(response) => response,
        Err(_) => std::process::abort(),
    }
}
