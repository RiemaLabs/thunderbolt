use core::future::Future;
use core::pin::Pin;
use std::panic::AssertUnwindSafe;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use futures_util::FutureExt as _;
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;

use crate::client::{read_frame, validate_client_limits, write_frame};
use crate::codec::{decode_request, encode_response};
use crate::filesystem::{
    canonical_socket_path, current_uid, harden_socket, inspect_newly_bound_socket, inspect_socket, path_identity,
    remove_if_same_newly_bound_socket, remove_if_same_socket, validate_private_parent, SocketIdentity,
};
use crate::{
    ControlError, ControlRequest, ControlResponse, ControlStatus, Result, ABSOLUTE_MAX_FRAME_BYTES,
    DEFAULT_MAX_FRAME_BYTES,
};

/// Boxed, cancellation-safe role handler future.
pub type ControlHandlerFuture<'a> = Pin<Box<dyn Future<Output = ControlResponse> + Send + 'a>>;

/// Asynchronous role-specific request handler.
pub trait ControlHandler: Send + Sync + 'static {
    /// Processes one already framed request. Durable idempotency belongs to the
    /// role service and must use [`ControlRequest::request_id`]. The future must
    /// be cancellation-safe and must move blocking work to its own bounded
    /// executor.
    fn handle(&self, request: ControlRequest) -> ControlHandlerFuture<'_>;
}

/// Immutable local-control server limits and filesystem policy.
#[derive(Clone, Debug)]
pub struct ControlServerConfig {
    /// Owner-only Unix socket path.
    pub socket_path: PathBuf,
    /// Complete frame bound including protocol headers.
    pub max_frame_bytes: usize,
    /// Maximum simultaneous connections and handler tasks.
    pub max_concurrent_requests: usize,
    /// Aggregate reserved bytes across accepted connections.
    pub max_inflight_bytes: usize,
    /// Per-frame read/write and connect deadline.
    pub io_timeout: Duration,
    /// Maximum time allowed for one role handler future.
    pub handler_timeout: Duration,
    /// Maximum time allowed for in-flight requests after shutdown begins.
    pub shutdown_grace: Duration,
    /// Permit removal of an owner-owned, identity-stable stale socket.
    pub recover_stale_socket: bool,
}

impl ControlServerConfig {
    /// Creates safe defaults for one explicit socket path.
    pub fn new(socket_path: impl Into<PathBuf>) -> Self {
        Self {
            socket_path: socket_path.into(),
            max_frame_bytes: DEFAULT_MAX_FRAME_BYTES,
            max_concurrent_requests: 32,
            max_inflight_bytes: 8 * DEFAULT_MAX_FRAME_BYTES,
            io_timeout: Duration::from_secs(5),
            handler_timeout: Duration::from_secs(4),
            shutdown_grace: Duration::from_secs(10),
            recover_stale_socket: false,
        }
    }

    fn validate(&self) -> Result<()> {
        validate_client_limits(self.max_frame_bytes, self.io_timeout)?;
        if self.max_frame_bytes > ABSOLUTE_MAX_FRAME_BYTES {
            return Err(ControlError::InvalidConfiguration(
                "frame bound exceeds the absolute limit",
            ));
        }
        if self.max_concurrent_requests == 0 || self.max_concurrent_requests > 1_024 {
            return Err(ControlError::InvalidConfiguration(
                "concurrency is outside the supported bound",
            ));
        }
        let per_connection = self
            .max_frame_bytes
            .checked_mul(2)
            .ok_or(ControlError::InvalidConfiguration(
                "per-connection byte reservation overflows",
            ))?;
        if self.max_inflight_bytes < per_connection || self.max_inflight_bytes > 256 * 1024 * 1024 {
            return Err(ControlError::InvalidConfiguration(
                "aggregate in-flight bytes are outside the supported bound",
            ));
        }
        if self.shutdown_grace.is_zero() || self.shutdown_grace > Duration::from_secs(300) {
            return Err(ControlError::InvalidConfiguration(
                "shutdown grace is outside the supported bound",
            ));
        }
        if self.handler_timeout.is_zero() || self.handler_timeout > Duration::from_secs(300) {
            return Err(ControlError::InvalidConfiguration(
                "handler timeout is outside the supported bound",
            ));
        }
        Ok(())
    }
}

/// Bound owner-only local-control server.
pub struct ControlServer<H> {
    config: ControlServerConfig,
    listener: UnixListener,
    handler: Arc<H>,
    socket_guard: SocketGuard,
}

impl<H: ControlHandler> ControlServer<H> {
    /// Safely binds the socket without replacing an active or foreign path.
    pub async fn bind(mut config: ControlServerConfig, handler: H) -> Result<Self> {
        config.validate()?;
        config.socket_path = canonical_socket_path(&config.socket_path)?;
        let parent = validate_private_parent(&config.socket_path)?;
        let parent_identity = path_identity(&parent)?;
        prepare_socket_path(&config.socket_path, config.recover_stale_socket).await?;
        let listener =
            UnixListener::bind(&config.socket_path).map_err(|source| ControlError::io("bind socket", source))?;
        let bound_identity = inspect_newly_bound_socket(&config.socket_path)?;
        match validate_private_parent(&config.socket_path).and_then(|path| path_identity(&path)) {
            Ok(current) if current == parent_identity => {}
            _ => {
                drop(listener);
                let _ = remove_if_same_newly_bound_socket(&config.socket_path, bound_identity);
                return Err(ControlError::UnsafePath {
                    path: parent,
                    reason: "socket parent identity changed during bind",
                });
            }
        }
        let identity = match harden_socket(&config.socket_path) {
            Ok(identity) => identity,
            Err(error) => {
                drop(listener);
                let _ = remove_if_same_newly_bound_socket(&config.socket_path, bound_identity);
                return Err(error);
            }
        };
        if identity != bound_identity {
            drop(listener);
            let _ = remove_if_same_newly_bound_socket(&config.socket_path, bound_identity);
            return Err(ControlError::UnsafePath {
                path: config.socket_path.clone(),
                reason: "socket identity changed while applying permissions",
            });
        }
        Ok(Self {
            socket_guard: SocketGuard {
                path: config.socket_path.clone(),
                identity,
                armed: true,
            },
            config,
            listener,
            handler: Arc::new(handler),
        })
    }

    /// Returns the exact bound socket path.
    pub fn socket_path(&self) -> &Path {
        &self.config.socket_path
    }

    /// Serves until cancellation, then drains bounded in-flight work.
    pub async fn run(self, shutdown: CancellationToken) -> Result<()> {
        let Self {
            config,
            listener,
            handler,
            mut socket_guard,
        } = self;
        let semaphore = Arc::new(Semaphore::new(config.max_concurrent_requests));
        let byte_semaphore = Arc::new(Semaphore::new(config.max_inflight_bytes));
        let byte_reservation = u32::try_from(
            config
                .max_frame_bytes
                .checked_mul(2)
                .ok_or(ControlError::InvalidConfiguration("byte reservation overflows"))?,
        )
        .map_err(|_| ControlError::InvalidConfiguration("byte reservation does not fit u32"))?;
        let mut tasks = JoinSet::new();
        let serve_result = loop {
            let mut task_panicked = false;
            while let Some(result) = tasks.try_join_next() {
                if result.is_err() {
                    task_panicked = true;
                }
            }
            if task_panicked {
                break Err(ControlError::Handler);
            }
            let permit = tokio::select! {
                biased;
                _ = shutdown.cancelled() => break Ok(()),
                result = semaphore.clone().acquire_owned() => {
                    result.map_err(|_| ControlError::Handler)?
                }
            };
            let byte_permit = tokio::select! {
                biased;
                _ = shutdown.cancelled() => break Ok(()),
                result = byte_semaphore.clone().acquire_many_owned(byte_reservation) => {
                    result.map_err(|_| ControlError::Handler)?
                }
            };
            let accepted = tokio::select! {
                biased;
                _ = shutdown.cancelled() => break Ok(()),
                result = listener.accept() => result,
            };
            let (stream, _) = match accepted {
                Ok(value) => value,
                Err(source) => break Err(ControlError::io("accept connection", source)),
            };
            if shutdown.is_cancelled() {
                drop(stream);
                break Ok(());
            }
            let handler = handler.clone();
            let task_shutdown = shutdown.clone();
            let max_frame_bytes = config.max_frame_bytes;
            let io_timeout = config.io_timeout;
            let handler_timeout = config.handler_timeout;
            tasks.spawn(async move {
                let _permit = permit;
                let _byte_permit = byte_permit;
                handle_connection(
                    stream,
                    handler,
                    max_frame_bytes,
                    io_timeout,
                    handler_timeout,
                    task_shutdown,
                )
                .await
            });
        };
        drop(listener);

        let drain = async {
            while let Some(result) = tasks.join_next().await {
                if result.is_err() {
                    return Err(ControlError::Handler);
                }
            }
            Ok(())
        };
        let drain_result = match timeout(config.shutdown_grace, drain).await {
            Ok(result) => result,
            Err(_) => {
                tasks.abort_all();
                while tasks.join_next().await.is_some() {}
                Err(ControlError::Timeout)
            }
        };
        let cleanup_result = socket_guard.cleanup();
        serve_result?;
        drain_result?;
        cleanup_result?;
        Ok(())
    }
}

async fn handle_connection<H: ControlHandler>(
    mut stream: UnixStream,
    handler: Arc<H>,
    max_frame_bytes: usize,
    io_timeout: Duration,
    handler_timeout: Duration,
    shutdown: CancellationToken,
) -> Result<()> {
    let credentials = stream
        .peer_cred()
        .map_err(|source| ControlError::io("read peer credentials", source))?;
    if credentials.uid() != current_uid() {
        return Err(ControlError::UnauthorizedPeer);
    }
    let frame = tokio::select! {
        biased;
        _ = shutdown.cancelled() => return Ok(()),
        result = read_frame(&mut stream, max_frame_bytes, io_timeout) => result?,
    };
    let request = decode_request(&frame, max_frame_bytes)?;
    drop(frame);
    let request_id = request.request_id();
    if shutdown.is_cancelled() {
        let response = ControlResponse::failure(request_id, ControlStatus::Draining, "daemon is draining")?;
        let frame = encode_response(&response, max_frame_bytes)?;
        return write_frame(&mut stream, &frame, io_timeout).await;
    }
    let response = match timeout(
        handler_timeout,
        AssertUnwindSafe(handler.handle(request)).catch_unwind(),
    )
    .await
    {
        Ok(Ok(response)) => response,
        Ok(Err(_)) => ControlResponse::failure(
            request_id,
            ControlStatus::Ambiguous,
            "handler failed; retry the exact request id",
        )?,
        Err(_) => ControlResponse::failure(
            request_id,
            ControlStatus::Ambiguous,
            "handler deadline exceeded; retry the exact request id",
        )?,
    };
    let response = if response.request_id() == request_id {
        response
    } else {
        ControlResponse::failure(
            request_id,
            ControlStatus::Ambiguous,
            "handler response id mismatch; retry the exact request id",
        )?
    };
    let frame = match encode_response(&response, max_frame_bytes) {
        Ok(frame) => frame,
        Err(_) => encode_response(
            &ControlResponse::failure(
                request_id,
                ControlStatus::Ambiguous,
                "handler response exceeded limits; retry the exact request id",
            )?,
            max_frame_bytes,
        )?,
    };
    write_frame(&mut stream, &frame, io_timeout).await
}

async fn prepare_socket_path(path: &Path, recover_stale_socket: bool) -> Result<()> {
    let Some(identity) = inspect_socket(path)? else {
        return Ok(());
    };
    if !recover_stale_socket {
        return Err(ControlError::SocketInUse(path.to_path_buf()));
    }
    match timeout(Duration::from_millis(250), UnixStream::connect(path)).await {
        Ok(Ok(_stream)) => Err(ControlError::SocketInUse(path.to_path_buf())),
        Err(_) => Err(ControlError::SocketInUse(path.to_path_buf())),
        Ok(Err(error))
            if matches!(
                error.kind(),
                std::io::ErrorKind::ConnectionRefused | std::io::ErrorKind::NotFound
            ) =>
        {
            remove_if_same_socket(path, identity)?;
            Ok(())
        }
        Ok(Err(_)) => Err(ControlError::SocketInUse(path.to_path_buf())),
    }
}

#[derive(Debug)]
struct SocketGuard {
    path: PathBuf,
    identity: SocketIdentity,
    armed: bool,
}

impl SocketGuard {
    fn cleanup(&mut self) -> Result<()> {
        if self.armed {
            remove_if_same_socket(&self.path, self.identity)?;
            self.armed = false;
        }
        Ok(())
    }
}

impl Drop for SocketGuard {
    fn drop(&mut self) {
        if self.armed {
            let _ = remove_if_same_socket(&self.path, self.identity);
        }
    }
}
