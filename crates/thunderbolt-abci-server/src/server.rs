use std::collections::HashMap;
#[cfg(unix)]
use std::ffi::OsString;
#[cfg(unix)]
use std::fs::File;
use std::io::{self, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Condvar, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

#[cfg(unix)]
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
#[cfg(unix)]
use std::os::unix::net::{UnixListener, UnixStream};

use socket2::{Domain, Protocol, Socket, Type};
use tendermint_abci::Application;

use crate::config::{ServerConfig, ServerEndpoint};
use crate::dispatch::{decode_frame, dispatch_value, DecodeFailure, DispatchFailure};
use crate::fatal::{FatalServerEvent, FatalServerHandler, FatalServerKind};
use crate::framing::{read_frame, write_frame, TimedStream};
use crate::semaphore::{Permit, PermitPool};
use crate::{Result, ServerError};

/// Actual local endpoint bound by a running server.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BoundEndpoint {
    /// Bound numeric loopback TCP address.
    Tcp(SocketAddr),
    /// Bound owner-only Unix socket path.
    #[cfg(unix)]
    Unix(PathBuf),
}

struct Shared {
    config: ServerConfig,
    shutdown: AtomicBool,
    invariant_failed: AtomicBool,
    connection_permits: Arc<PermitPool>,
    inflight_permits: Arc<PermitPool>,
    connections: Mutex<HashMap<u64, LocalStream>>,
    workers: Mutex<Vec<JoinHandle<()>>>,
    listener_wait: Mutex<()>,
    listener_changed: Condvar,
    next_connection_id: AtomicU64,
    fatal: Arc<dyn FatalServerHandler>,
}

/// Cloneable shutdown signal for a running server.
#[derive(Clone)]
pub struct ShutdownHandle {
    shared: Arc<Shared>,
}

impl ShutdownHandle {
    /// Stops admission, cancels live sockets, and starts biased worker drain.
    pub fn shutdown(&self) {
        begin_shutdown(&self.shared);
    }

    /// Reports whether shutdown has begun.
    #[must_use]
    pub fn is_shutdown(&self) -> bool {
        self.shared.shutdown.load(Ordering::Acquire)
    }

    #[cfg(test)]
    pub(crate) fn tracked_worker_count(&self) -> Result<usize> {
        self.shared
            .workers
            .lock()
            .map(|workers| workers.len())
            .map_err(|_| ServerError::WorkerPanicked)
    }
}

/// Running bounded ABCI server. Dropping it performs shutdown and exact join.
#[must_use = "dropping RunningServer shuts down and joins all workers"]
pub struct RunningServer {
    endpoint: BoundEndpoint,
    shutdown: ShutdownHandle,
    join: Option<JoinHandle<()>>,
    fatal: Arc<dyn FatalServerHandler>,
}

impl RunningServer {
    /// Returns the actual bound local endpoint.
    #[must_use]
    pub const fn endpoint(&self) -> &BoundEndpoint {
        &self.endpoint
    }

    /// Returns a cloneable shutdown signal.
    #[must_use]
    pub fn shutdown_handle(&self) -> ShutdownHandle {
        self.shutdown.clone()
    }

    /// Signals shutdown and blocks until the server and every worker join.
    pub fn shutdown_and_join(mut self) {
        self.shutdown.shutdown();
        self.join_or_terminate();
    }

    fn join_or_terminate(&mut self) {
        let Some(join) = self.join.take() else {
            return;
        };
        if join.join().is_err() {
            self.fatal
                .terminate(FatalServerEvent::new(FatalServerKind::WorkerInvariant, None));
        }
    }
}

impl Drop for RunningServer {
    fn drop(&mut self) {
        self.shutdown.shutdown();
        self.join_or_terminate();
    }
}

/// Binds and starts a production-bounded local ABCI server.
pub fn start<A, H>(config: ServerConfig, application: A, fatal_handler: H) -> Result<RunningServer>
where
    A: Application,
    H: FatalServerHandler,
{
    let fatal_policy: Arc<dyn FatalServerHandler> = Arc::new(fatal_handler);
    let (listener, endpoint, cleanup) = bind_listener(config.endpoint())?;
    let cleanup_cell = Arc::new(Mutex::new(cleanup));
    let application = Arc::new(Mutex::new(application));
    let shared = Arc::new(Shared {
        config: config.clone(),
        shutdown: AtomicBool::new(false),
        invariant_failed: AtomicBool::new(false),
        connection_permits: PermitPool::new(config.limits().max_connections()),
        inflight_permits: PermitPool::new(config.limits().max_inflight_bytes()),
        connections: Mutex::new(HashMap::new()),
        workers: Mutex::new(Vec::new()),
        listener_wait: Mutex::new(()),
        listener_changed: Condvar::new(),
        next_connection_id: AtomicU64::new(1),
        fatal: Arc::clone(&fatal_policy),
    });
    let server_shared = Arc::clone(&shared);
    let server_cleanup = Arc::clone(&cleanup_cell);
    let join = match thread::Builder::new()
        .name("thunderbolt-abci-server".to_owned())
        .spawn(move || {
            let cleanup = match server_cleanup.lock() {
                Ok(mut cleanup) => cleanup.take(),
                Err(_) => fatal(&server_shared, FatalServerKind::WorkerInvariant, None),
            };
            let panic_shared = Arc::clone(&server_shared);
            if catch_unwind(AssertUnwindSafe(|| {
                run_server(listener, cleanup, application, server_shared);
            }))
            .is_err()
            {
                fatal(&panic_shared, FatalServerKind::WorkerInvariant, None);
            }
        }) {
        Ok(join) => join,
        Err(error) => {
            let cleanup = cleanup_cell.lock().map_err(|_| ServerError::WorkerPanicked)?.take();
            if let Some(cleanup) = cleanup {
                cleanup.cleanup()?;
            }
            return Err(error.into());
        }
    };
    Ok(RunningServer {
        endpoint,
        shutdown: ShutdownHandle { shared },
        join: Some(join),
        fatal: fatal_policy,
    })
}

fn run_server<A: Application>(
    listener: LocalListener,
    cleanup: Option<UnixCleanup>,
    application: Arc<Mutex<A>>,
    shared: Arc<Shared>,
) {
    while !shared.shutdown.load(Ordering::Acquire) {
        if shared.invariant_failed.load(Ordering::Acquire) {
            fatal(&shared, FatalServerKind::WorkerInvariant, None);
        }
        if reap_finished(&shared).is_err() {
            fatal(&shared, FatalServerKind::WorkerInvariant, None);
        }
        match listener.accept() {
            Ok((stream, peer)) => {
                if shared.shutdown.load(Ordering::Acquire) {
                    let _ = stream.shutdown_both();
                    continue;
                }
                if peer.is_some_and(|address| !address.ip().is_loopback()) {
                    let _ = stream.shutdown_both();
                    fatal(&shared, FatalServerKind::WorkerInvariant, None);
                }
                let connection_permit = match shared.connection_permits.try_acquire(1) {
                    Ok(Some(permit)) => permit,
                    Ok(None) => {
                        let _ = stream.shutdown_both();
                        continue;
                    }
                    Err(()) => fatal(&shared, FatalServerKind::WorkerInvariant, None),
                };
                if stream.configure().is_err() {
                    let _ = stream.shutdown_both();
                    continue;
                }
                let connection_id =
                    match shared
                        .next_connection_id
                        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| current.checked_add(1))
                    {
                        Ok(connection_id) => connection_id,
                        Err(_) => fatal(&shared, FatalServerKind::WorkerInvariant, None),
                    };
                let control = match stream.try_clone() {
                    Ok(control) => control,
                    Err(_) => fatal(&shared, FatalServerKind::WorkerInvariant, Some(connection_id)),
                };
                let duplicate = match shared.connections.lock() {
                    Ok(mut values) => values.insert(connection_id, control).is_some(),
                    Err(_) => fatal(&shared, FatalServerKind::WorkerInvariant, Some(connection_id)),
                };
                if duplicate {
                    fatal(&shared, FatalServerKind::WorkerInvariant, Some(connection_id));
                }
                let worker_shared = Arc::clone(&shared);
                let worker_application = Arc::clone(&application);
                let handle = match thread::Builder::new()
                    .name(format!("thunderbolt-abci-connection-{connection_id}"))
                    .spawn(move || {
                        connection_loop(
                            connection_id,
                            stream,
                            worker_application,
                            worker_shared,
                            connection_permit,
                        );
                    }) {
                    Ok(handle) => handle,
                    Err(_) => fatal(&shared, FatalServerKind::WorkerInvariant, Some(connection_id)),
                };
                register_worker(&shared, handle, Some(connection_id));
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                let wait = match shared.listener_wait.lock() {
                    Ok(wait) => wait,
                    Err(_) => fatal(&shared, FatalServerKind::WorkerInvariant, None),
                };
                if shared
                    .listener_changed
                    .wait_timeout_while(wait, shared.config.deadlines().accept_poll(), |_| {
                        !shared.shutdown.load(Ordering::Acquire)
                    })
                    .is_err()
                {
                    fatal(&shared, FatalServerKind::WorkerInvariant, None);
                }
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(_) => fatal(&shared, FatalServerKind::ListenerFailure, None),
        }
    }
    if shared.invariant_failed.load(Ordering::Acquire) {
        fatal(&shared, FatalServerKind::WorkerInvariant, None);
    }
    begin_shutdown(&shared);
    drain_workers(&shared);
    drop(listener);
    if let Some(cleanup) = cleanup {
        if cleanup.cleanup().is_err() {
            fatal(&shared, FatalServerKind::CleanupFailure, None);
        }
    }
}

fn connection_loop<A: Application>(
    connection_id: u64,
    mut stream: LocalStream,
    application: Arc<Mutex<A>>,
    shared: Arc<Shared>,
    _connection_permit: Permit,
) {
    let _registration = ConnectionRegistration {
        connection_id,
        shared: Arc::clone(&shared),
    };
    loop {
        if shared.shutdown.load(Ordering::Acquire) {
            let _ = stream.shutdown_both();
            return;
        }
        let inbound = match read_frame(
            &mut stream,
            shared.config.limits(),
            shared.config.deadlines(),
            &shared.shutdown,
            &shared.inflight_permits,
        ) {
            Ok(Some(frame)) => frame,
            Ok(None) => return,
            Err(crate::FrameError::Shutdown) => return,
            Err(crate::FrameError::Allocation | crate::FrameError::AccountingInvariant) => {
                begin_shutdown(&shared);
                let _ = stream.shutdown_both();
                fatal(&shared, FatalServerKind::WorkerInvariant, Some(connection_id));
            }
            Err(_) => {
                let _ = stream.shutdown_both();
                return;
            }
        };
        if shared.shutdown.load(Ordering::Acquire) {
            return;
        }
        let decode_deadline = match Instant::now().checked_add(shared.config.deadlines().decode()) {
            Some(deadline) => deadline,
            None => fatal(&shared, FatalServerKind::WorkerInvariant, Some(connection_id)),
        };
        let request_decode_item_limit = shared.config.limits().max_request_decode_items();
        let request = match decode_frame(&inbound.bytes, request_decode_item_limit, decode_deadline) {
            Ok(request) => request,
            Err(DecodeFailure::Client | DecodeFailure::Deadline) => {
                let _ = stream.shutdown_both();
                return;
            }
            Err(DecodeFailure::Panicked) => {
                begin_shutdown(&shared);
                let _ = stream.shutdown_both();
                fatal(&shared, FatalServerKind::WorkerInvariant, Some(connection_id));
            }
        };
        let (sender, receiver) = mpsc::sync_channel(1);
        let handler_application = Arc::clone(&application);
        let response_cap = shared.config.limits().response_frame_bytes();
        let handler_deadline = match Instant::now().checked_add(shared.config.deadlines().handler()) {
            Some(deadline) => deadline,
            None => fatal(&shared, FatalServerKind::WorkerInvariant, Some(connection_id)),
        };
        let handler = match thread::Builder::new()
            .name(format!("thunderbolt-abci-handler-{connection_id}"))
            .spawn(move || {
                let outcome = dispatch_value(
                    || match handler_application.lock() {
                        Ok(application) => Ok(application.clone()),
                        Err(_) => Err(DispatchFailure::Server),
                    },
                    request,
                    response_cap,
                );
                let _ = sender.send(HandlerOutcome {
                    outcome,
                    _permit: inbound.permit,
                });
            }) {
            Ok(handle) => handle,
            Err(_) => fatal(&shared, FatalServerKind::WorkerInvariant, Some(connection_id)),
        };
        let remaining = match handler_deadline.checked_duration_since(Instant::now()) {
            Some(remaining) if !remaining.is_zero() => remaining,
            _ => {
                begin_shutdown(&shared);
                let _ = stream.shutdown_both();
                fatal(&shared, FatalServerKind::HandlerTimeout, Some(connection_id));
            }
        };
        let handled = match receiver.recv_timeout(remaining) {
            Ok(handled) if Instant::now() <= handler_deadline => handled,
            Ok(_) => {
                begin_shutdown(&shared);
                let _ = stream.shutdown_both();
                fatal(&shared, FatalServerKind::HandlerTimeout, Some(connection_id));
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                begin_shutdown(&shared);
                let _ = stream.shutdown_both();
                fatal(&shared, FatalServerKind::HandlerTimeout, Some(connection_id));
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                begin_shutdown(&shared);
                let _ = stream.shutdown_both();
                fatal(&shared, FatalServerKind::WorkerInvariant, Some(connection_id));
            }
        };
        if handler.join().is_err() {
            begin_shutdown(&shared);
            let _ = stream.shutdown_both();
            fatal(&shared, FatalServerKind::WorkerInvariant, Some(connection_id));
        }
        let HandlerOutcome {
            outcome,
            _permit: permit,
        } = handled;
        match outcome {
            Ok(response) => {
                if shared.shutdown.load(Ordering::Acquire) {
                    return;
                }
                let configured_write_deadline = match Instant::now().checked_add(shared.config.deadlines().write()) {
                    Some(deadline) => deadline,
                    None => fatal(&shared, FatalServerKind::WorkerInvariant, Some(connection_id)),
                };
                let output_deadline = configured_write_deadline.min(handler_deadline);
                if write_frame(
                    &mut stream,
                    &response,
                    shared.config.limits().response_frame_bytes(),
                    output_deadline,
                    &shared.shutdown,
                )
                .is_err()
                {
                    let _ = stream.shutdown_both();
                    return;
                }
            }
            #[cfg(test)]
            Err(DispatchFailure::Client) => {
                let _ = stream.shutdown_both();
                return;
            }
            Err(DispatchFailure::Server) => {
                begin_shutdown(&shared);
                let _ = stream.shutdown_both();
                fatal(&shared, FatalServerKind::WorkerInvariant, Some(connection_id));
            }
            Err(DispatchFailure::Panicked) => {
                begin_shutdown(&shared);
                let _ = stream.shutdown_both();
                fatal(&shared, FatalServerKind::HandlerPanic, Some(connection_id));
            }
        }
        drop(permit);
    }
}

struct HandlerOutcome {
    outcome: std::result::Result<Vec<u8>, DispatchFailure>,
    _permit: Permit,
}

struct ConnectionRegistration {
    connection_id: u64,
    shared: Arc<Shared>,
}

impl Drop for ConnectionRegistration {
    fn drop(&mut self) {
        let removed = match self.shared.connections.lock() {
            Ok(mut connections) => connections.remove(&self.connection_id).is_some(),
            Err(_) => false,
        };
        if !removed {
            flag_invariant_failure(&self.shared);
        }
    }
}

fn register_worker(shared: &Arc<Shared>, worker: JoinHandle<()>, connection_id: Option<u64>) {
    if let Ok(mut workers) = shared.workers.lock() {
        workers.push(worker);
    } else {
        fatal(shared, FatalServerKind::WorkerInvariant, connection_id);
    }
}

fn reap_finished(shared: &Arc<Shared>) -> std::result::Result<(), ()> {
    let finished = {
        let mut workers = shared.workers.lock().map_err(|_| ())?;
        let mut finished = Vec::new();
        let mut index = 0_usize;
        while index < workers.len() {
            if workers[index].is_finished() {
                finished.push(workers.swap_remove(index));
            } else {
                index = index.saturating_add(1);
            }
        }
        finished
    };
    for worker in finished {
        worker.join().map_err(|_| ())?;
    }
    Ok(())
}

fn drain_workers(shared: &Arc<Shared>) {
    let deadline = match Instant::now().checked_add(shared.config.deadlines().shutdown_grace()) {
        Some(deadline) => deadline,
        None => fatal(shared, FatalServerKind::WorkerInvariant, None),
    };
    loop {
        if shared.invariant_failed.load(Ordering::Acquire) {
            fatal(shared, FatalServerKind::WorkerInvariant, None);
        }
        if reap_finished(shared).is_err() {
            fatal(shared, FatalServerKind::WorkerInvariant, None);
        }
        let empty = match shared.workers.lock() {
            Ok(workers) => workers.is_empty(),
            Err(_) => fatal(shared, FatalServerKind::WorkerInvariant, None),
        };
        if empty {
            return;
        }
        if Instant::now() >= deadline {
            fatal(shared, FatalServerKind::ShutdownTimeout, None);
        }
        let remaining = match deadline.checked_duration_since(Instant::now()) {
            Some(remaining) => remaining,
            None => fatal(shared, FatalServerKind::ShutdownTimeout, None),
        };
        thread::sleep(shared.config.deadlines().accept_poll().min(remaining));
    }
}

fn begin_shutdown(shared: &Arc<Shared>) {
    shared.shutdown.store(true, Ordering::Release);
    shared.listener_changed.notify_all();
    shared.inflight_permits.wake_all();
    shared.connection_permits.wake_all();
    match shared.connections.lock() {
        Ok(connections) => {
            for stream in connections.values() {
                let _ = stream.shutdown_both();
            }
        }
        Err(_) => shared.invariant_failed.store(true, Ordering::Release),
    }
}

fn flag_invariant_failure(shared: &Arc<Shared>) {
    shared.invariant_failed.store(true, Ordering::Release);
    shared.shutdown.store(true, Ordering::Release);
    shared.listener_changed.notify_all();
    shared.inflight_permits.wake_all();
    shared.connection_permits.wake_all();
}

fn fatal(shared: &Arc<Shared>, kind: FatalServerKind, connection_id: Option<u64>) -> ! {
    begin_shutdown(shared);
    shared.fatal.terminate(FatalServerEvent::new(kind, connection_id))
}

enum LocalListener {
    Tcp(TcpListener),
    #[cfg(unix)]
    Unix(UnixListener),
}

impl LocalListener {
    fn accept(&self) -> io::Result<(LocalStream, Option<SocketAddr>)> {
        match self {
            Self::Tcp(listener) => listener
                .accept()
                .map(|(stream, peer)| (LocalStream::Tcp(stream), Some(peer))),
            #[cfg(unix)]
            Self::Unix(listener) => listener.accept().map(|(stream, _)| (LocalStream::Unix(stream), None)),
        }
    }
}

enum LocalStream {
    Tcp(TcpStream),
    #[cfg(unix)]
    Unix(UnixStream),
}

impl LocalStream {
    fn configure(&self) -> io::Result<()> {
        match self {
            Self::Tcp(stream) => {
                stream.set_nonblocking(false)?;
                stream.set_nodelay(true)
            }
            #[cfg(unix)]
            Self::Unix(stream) => stream.set_nonblocking(false),
        }
    }

    fn try_clone(&self) -> io::Result<Self> {
        match self {
            Self::Tcp(stream) => stream.try_clone().map(Self::Tcp),
            #[cfg(unix)]
            Self::Unix(stream) => stream.try_clone().map(Self::Unix),
        }
    }
}

impl Read for LocalStream {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Tcp(stream) => stream.read(bytes),
            #[cfg(unix)]
            Self::Unix(stream) => stream.read(bytes),
        }
    }
}

impl Write for LocalStream {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        match self {
            Self::Tcp(stream) => stream.write(bytes),
            #[cfg(unix)]
            Self::Unix(stream) => stream.write(bytes),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            Self::Tcp(stream) => stream.flush(),
            #[cfg(unix)]
            Self::Unix(stream) => stream.flush(),
        }
    }
}

impl TimedStream for LocalStream {
    fn set_read_deadline(&self, timeout: Duration) -> io::Result<()> {
        match self {
            Self::Tcp(stream) => stream.set_read_timeout(Some(timeout)),
            #[cfg(unix)]
            Self::Unix(stream) => stream.set_read_timeout(Some(timeout)),
        }
    }

    fn set_write_deadline(&self, timeout: Duration) -> io::Result<()> {
        match self {
            Self::Tcp(stream) => stream.set_write_timeout(Some(timeout)),
            #[cfg(unix)]
            Self::Unix(stream) => stream.set_write_timeout(Some(timeout)),
        }
    }

    fn shutdown_both(&self) -> io::Result<()> {
        match self {
            Self::Tcp(stream) => stream.shutdown(Shutdown::Both),
            #[cfg(unix)]
            Self::Unix(stream) => stream.shutdown(Shutdown::Both),
        }
    }
}

fn bind_listener(endpoint: &ServerEndpoint) -> Result<(LocalListener, BoundEndpoint, Option<UnixCleanup>)> {
    match endpoint {
        ServerEndpoint::Tcp(address) => {
            if !address.ip().is_loopback() {
                return Err(ServerError::InvalidConfig("TCP listener must use loopback"));
            }
            let socket = Socket::new(Domain::for_address(*address), Type::STREAM, Some(Protocol::TCP))?;
            #[cfg(unix)]
            socket.set_reuse_address(true)?;
            socket.bind(&(*address).into())?;
            socket.listen(
                i32::try_from(crate::MAX_SERVER_CONNECTIONS)
                    .map_err(|_| ServerError::InvalidConfig("connection cap does not fit the TCP listen backlog"))?,
            )?;
            let listener = TcpListener::from(socket);
            listener.set_nonblocking(true)?;
            let bound = listener.local_addr()?;
            if !bound.ip().is_loopback() {
                return Err(ServerError::InvalidConfig("bound TCP listener is not loopback"));
            }
            Ok((LocalListener::Tcp(listener), BoundEndpoint::Tcp(bound), None))
        }
        #[cfg(unix)]
        ServerEndpoint::Unix(path) => bind_unix(path),
    }
}

#[cfg(unix)]
fn bind_unix(path: &Path) -> Result<(LocalListener, BoundEndpoint, Option<UnixCleanup>)> {
    let parent = validate_unix_parent(path)?;
    let file_name = path.file_name().ok_or_else(|| ServerError::UnixSocket {
        path: path.to_path_buf(),
        reason: "socket path must end in a file name",
    })?;
    let path = parent.path.join(file_name);
    let lock = UnixSocketLock::acquire(&path)?;
    if let Err(error) = remove_stale_socket(&path) {
        return match lock.cleanup() {
            Ok(()) => Err(error),
            Err(cleanup_error) => Err(cleanup_error),
        };
    }
    let listener = match UnixListener::bind(&path) {
        Ok(listener) => listener,
        Err(error) => {
            return match lock.cleanup() {
                Ok(()) => Err(error.into()),
                Err(cleanup_error) => Err(cleanup_error),
            };
        }
    };
    let metadata = match std::fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) => {
            drop(listener);
            drop(lock);
            return Err(error.into());
        }
    };
    let uid = rustix::process::geteuid().as_raw();
    if !metadata.file_type().is_socket() || metadata.uid() != uid || metadata.nlink() != 1 {
        drop(listener);
        drop(lock);
        return Err(ServerError::UnixSocket {
            path,
            reason: "created socket identity is unsafe",
        });
    }
    let cleanup = UnixCleanup {
        path: path.clone(),
        device: metadata.dev(),
        inode: metadata.ino(),
        uid,
        lock,
    };
    let harden_result = (|| {
        listener.set_nonblocking(true)?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        let hardened = std::fs::symlink_metadata(&path)?;
        if !hardened.file_type().is_socket()
            || hardened.dev() != cleanup.device
            || hardened.ino() != cleanup.inode
            || hardened.uid() != uid
            || hardened.nlink() != 1
            || hardened.permissions().mode() & 0o077 != 0
        {
            return Err(ServerError::UnixSocket {
                path: path.clone(),
                reason: "created socket identity changed while hardening",
            });
        }
        parent.verify()
    })();
    if let Err(error) = harden_result {
        drop(listener);
        return match cleanup.cleanup() {
            Ok(()) => Err(error),
            Err(cleanup_error) => Err(cleanup_error),
        };
    }
    Ok((LocalListener::Unix(listener), BoundEndpoint::Unix(path), Some(cleanup)))
}

#[cfg(unix)]
fn validate_unix_parent(path: &Path) -> Result<UnixParent> {
    if !path.is_absolute() || path.file_name().is_none() {
        return Err(ServerError::UnixSocket {
            path: path.to_path_buf(),
            reason: "socket path must be absolute with a file name",
        });
    }
    let parent = path.parent().ok_or_else(|| ServerError::UnixSocket {
        path: path.to_path_buf(),
        reason: "socket parent is missing",
    })?;
    let metadata = std::fs::symlink_metadata(parent)?;
    let uid = rustix::process::geteuid().as_raw();
    let mode = metadata.permissions().mode();
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.uid() != uid
        || mode & 0o077 != 0
        || mode & 0o300 != 0o300
    {
        return Err(ServerError::UnixSocket {
            path: path.to_path_buf(),
            reason: "socket parent must be owner-only and current-uid",
        });
    }
    let canonical = std::fs::canonicalize(parent)?;
    validate_unix_ancestry(&canonical)?;
    let canonical_metadata = std::fs::symlink_metadata(&canonical)?;
    Ok(UnixParent {
        path: canonical,
        device: canonical_metadata.dev(),
        inode: canonical_metadata.ino(),
        uid,
    })
}

#[cfg(unix)]
fn validate_unix_ancestry(parent: &Path) -> Result<()> {
    let uid = rustix::process::geteuid().as_raw();
    for ancestor in parent.ancestors() {
        let metadata = std::fs::symlink_metadata(ancestor)?;
        let mode = metadata.permissions().mode();
        if metadata.file_type().is_symlink()
            || !metadata.is_dir()
            || (metadata.uid() != 0 && metadata.uid() != uid)
            || (mode & 0o022 != 0 && mode & 0o1000 == 0)
        {
            return Err(ServerError::UnixSocket {
                path: ancestor.to_path_buf(),
                reason: "socket ancestry contains a renameable directory",
            });
        }
    }
    Ok(())
}

#[cfg(unix)]
struct UnixParent {
    path: PathBuf,
    device: u64,
    inode: u64,
    uid: u32,
}

#[cfg(unix)]
impl UnixParent {
    fn verify(&self) -> Result<()> {
        let metadata = std::fs::symlink_metadata(&self.path)?;
        if !metadata.is_dir()
            || metadata.file_type().is_symlink()
            || metadata.dev() != self.device
            || metadata.ino() != self.inode
            || metadata.uid() != self.uid
        {
            return Err(ServerError::UnixSocket {
                path: self.path.clone(),
                reason: "socket parent identity changed during bind",
            });
        }
        Ok(())
    }
}

#[cfg(unix)]
struct UnixSocketLock {
    file: File,
    path: PathBuf,
    device: u64,
    inode: u64,
    uid: u32,
}

#[cfg(unix)]
impl UnixSocketLock {
    fn acquire(socket_path: &Path) -> Result<Self> {
        let lock_path = unix_lock_path(socket_path)?;
        let descriptor = rustix::fs::open(
            &lock_path,
            rustix::fs::OFlags::CREATE
                | rustix::fs::OFlags::RDWR
                | rustix::fs::OFlags::CLOEXEC
                | rustix::fs::OFlags::NOFOLLOW,
            rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
        )
        .map_err(|_| ServerError::UnixSocket {
            path: lock_path.clone(),
            reason: "cannot safely open the socket ownership lock",
        })?;
        let file = File::from(descriptor);
        let metadata = file.metadata()?;
        let uid = rustix::process::geteuid().as_raw();
        if !metadata.is_file()
            || metadata.uid() != uid
            || metadata.nlink() != 1
            || metadata.permissions().mode() & 0o077 != 0
        {
            return Err(ServerError::UnixSocket {
                path: lock_path,
                reason: "socket ownership lock is not an owner-only regular file",
            });
        }
        rustix::fs::flock(&file, rustix::fs::FlockOperation::NonBlockingLockExclusive).map_err(|_| {
            ServerError::UnixSocket {
                path: lock_path.clone(),
                reason: "another ABCI server holds the socket ownership lock",
            }
        })?;
        let path_metadata = std::fs::symlink_metadata(&lock_path)?;
        if !path_metadata.is_file()
            || path_metadata.dev() != metadata.dev()
            || path_metadata.ino() != metadata.ino()
            || path_metadata.nlink() != 1
        {
            return Err(ServerError::UnixSocket {
                path: lock_path,
                reason: "socket ownership lock identity changed during acquisition",
            });
        }
        Ok(Self {
            file,
            path: lock_path,
            device: metadata.dev(),
            inode: metadata.ino(),
            uid,
        })
    }

    fn cleanup(self) -> Result<()> {
        let metadata = std::fs::symlink_metadata(&self.path).map_err(|_| ServerError::UnixSocket {
            path: self.path.clone(),
            reason: "socket ownership lock disappeared before cleanup",
        })?;
        if !metadata.is_file()
            || metadata.dev() != self.device
            || metadata.ino() != self.inode
            || metadata.uid() != self.uid
            || metadata.nlink() != 1
        {
            return Err(ServerError::UnixSocket {
                path: self.path,
                reason: "socket ownership lock identity changed before cleanup",
            });
        }
        std::fs::remove_file(&self.path)?;
        drop(self.file);
        Ok(())
    }
}

#[cfg(unix)]
fn unix_lock_path(socket_path: &Path) -> Result<PathBuf> {
    let file_name = socket_path.file_name().ok_or_else(|| ServerError::UnixSocket {
        path: socket_path.to_path_buf(),
        reason: "socket path must end in a file name",
    })?;
    let mut lock_name = OsString::from(file_name);
    lock_name.push(".lock");
    Ok(socket_path.with_file_name(lock_name))
}

#[cfg(unix)]
fn remove_stale_socket(path: &Path) -> Result<()> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    let uid = rustix::process::geteuid().as_raw();
    if !metadata.file_type().is_socket()
        || metadata.uid() != uid
        || metadata.nlink() != 1
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err(ServerError::UnixSocket {
            path: path.to_path_buf(),
            reason: "existing path is not a removable owner socket",
        });
    }
    match UnixStream::connect(path) {
        Ok(_) => {
            return Err(ServerError::UnixSocket {
                path: path.to_path_buf(),
                reason: "another ABCI server is active",
            });
        }
        Err(error) if error.kind() == io::ErrorKind::ConnectionRefused => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(_) => {
            return Err(ServerError::UnixSocket {
                path: path.to_path_buf(),
                reason: "existing socket liveness is ambiguous",
            });
        }
    }
    let before = std::fs::symlink_metadata(path)?;
    if before.dev() != metadata.dev() || before.ino() != metadata.ino() || before.nlink() != 1 {
        return Err(ServerError::UnixSocket {
            path: path.to_path_buf(),
            reason: "stale socket identity changed before cleanup",
        });
    }
    std::fs::remove_file(path)?;
    Ok(())
}

struct UnixCleanup {
    #[cfg(unix)]
    path: PathBuf,
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
    #[cfg(unix)]
    uid: u32,
    #[cfg(unix)]
    lock: UnixSocketLock,
}

impl UnixCleanup {
    fn cleanup(self) -> Result<()> {
        #[cfg(unix)]
        {
            let metadata = std::fs::symlink_metadata(&self.path).map_err(|error| ServerError::UnixSocket {
                path: self.path.clone(),
                reason: if error.kind() == io::ErrorKind::NotFound {
                    "socket disappeared before exact cleanup"
                } else {
                    "socket metadata failed during cleanup"
                },
            })?;
            if !metadata.file_type().is_socket()
                || metadata.dev() != self.device
                || metadata.ino() != self.inode
                || metadata.uid() != self.uid
                || metadata.nlink() != 1
            {
                return Err(ServerError::UnixSocket {
                    path: self.path,
                    reason: "socket identity changed before exact cleanup",
                });
            }
            std::fs::remove_file(&self.path)?;
            self.lock.cleanup()?;
        }
        Ok(())
    }
}
