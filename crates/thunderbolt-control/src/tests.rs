use std::fs;
use std::os::unix::fs::{FileTypeExt as _, PermissionsExt as _};
use std::os::unix::net::UnixListener as StdUnixListener;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use proptest::prelude::*;
use static_assertions::assert_not_impl_any;
use tempfile::TempDir;
use tokio::io::AsyncWriteExt as _;
use tokio::net::UnixStream;
use tokio_util::sync::CancellationToken;

use crate::codec::{decode_request, decode_response, encode_request, encode_response};
use crate::{
    ControlClient, ControlError, ControlHandler, ControlHandlerFuture, ControlRequest, ControlResponse, ControlServer,
    ControlServerConfig, ControlStatus, RequestId, MAX_CONTROL_HANDLER_TIMEOUT, MAX_CONTROL_IO_TIMEOUT,
    MAX_CONTROL_RESPONSE_TIMEOUT,
};

#[derive(Clone, Debug)]
struct EchoHandler;

impl ControlHandler for EchoHandler {
    fn handle(&self, request: ControlRequest) -> ControlHandlerFuture<'_> {
        Box::pin(async move { ControlResponse::success(request.request_id(), request.into_payload()) })
    }
}

#[derive(Clone, Debug)]
struct WrongIdHandler;

impl ControlHandler for WrongIdHandler {
    fn handle(&self, _request: ControlRequest) -> ControlHandlerFuture<'_> {
        Box::pin(async { ControlResponse::success(RequestId::from_bytes([9_u8; 16]).unwrap(), b"wrong".to_vec()) })
    }
}

#[derive(Clone, Debug)]
struct HangingHandler {
    dropped: Arc<AtomicBool>,
}

#[derive(Clone, Debug)]
struct CountingHandler(Arc<AtomicUsize>);

impl ControlHandler for CountingHandler {
    fn handle(&self, request: ControlRequest) -> ControlHandlerFuture<'_> {
        self.0.fetch_add(1, Ordering::AcqRel);
        Box::pin(async move { ControlResponse::success(request.request_id(), Vec::new()) })
    }
}

#[derive(Clone, Debug)]
struct PanicHandler;

impl ControlHandler for PanicHandler {
    fn handle(&self, _request: ControlRequest) -> ControlHandlerFuture<'_> {
        Box::pin(async { panic!("test handler panic") })
    }
}

impl ControlHandler for HangingHandler {
    fn handle(&self, _request: ControlRequest) -> ControlHandlerFuture<'_> {
        let dropped = self.dropped.clone();
        Box::pin(async move {
            struct DropSignal(Arc<AtomicBool>);
            impl Drop for DropSignal {
                fn drop(&mut self) {
                    self.0.store(true, Ordering::Release);
                }
            }
            let _signal = DropSignal(dropped);
            std::future::pending::<ControlResponse>().await
        })
    }
}

assert_not_impl_any!(ControlRequest: Clone);
assert_not_impl_any!(ControlResponse: Clone);

fn private_socket() -> (TempDir, PathBuf) {
    let directory = tempfile::tempdir().unwrap();
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let socket = directory.path().join("control.sock");
    (directory, socket)
}

fn test_config(socket: &Path) -> ControlServerConfig {
    let mut config = ControlServerConfig::new(socket);
    config.io_timeout = Duration::from_millis(250);
    config.shutdown_grace = Duration::from_secs(2);
    config
}

fn request(byte: u8, payload: &[u8]) -> ControlRequest {
    ControlRequest::new(
        RequestId::from_bytes([byte; 16]).unwrap(),
        "status.get",
        payload.to_vec(),
    )
    .unwrap()
}

#[test]
fn client_deadline_matches_checked_server_handler_plus_io_maximum() {
    let (_directory, socket) = private_socket();
    let mut config = ControlServerConfig::new(&socket);
    config.handler_timeout = MAX_CONTROL_HANDLER_TIMEOUT;
    config.io_timeout = MAX_CONTROL_IO_TIMEOUT;
    let client = ControlClient::from_server_config(&config).unwrap();
    assert_eq!(client.socket_path(), socket);
    assert_eq!(client.max_frame_bytes(), config.max_frame_bytes);
    assert_eq!(client.io_timeout(), MAX_CONTROL_IO_TIMEOUT);
    assert_eq!(client.response_timeout(), MAX_CONTROL_RESPONSE_TIMEOUT);
    assert_eq!(
        config.handler_timeout.checked_add(config.io_timeout),
        Some(MAX_CONTROL_RESPONSE_TIMEOUT)
    );
}

#[test]
fn client_deadline_rejects_zero_overflow_and_one_nanosecond_over() {
    let (_directory, socket) = private_socket();
    assert!(ControlClient::new(&socket).with_limits(64, Duration::ZERO).is_err());
    assert!(ControlClient::new(&socket)
        .with_limits(64, MAX_CONTROL_IO_TIMEOUT)
        .is_ok());
    assert!(ControlClient::new(&socket)
        .with_limits(64, MAX_CONTROL_IO_TIMEOUT.checked_add(Duration::from_nanos(1)).unwrap(),)
        .is_err());
    assert!(ControlClient::new(&socket).with_limits(64, Duration::MAX).is_err());
    assert!(ControlClient::new(&socket)
        .with_deadlines(64, MAX_CONTROL_IO_TIMEOUT, MAX_CONTROL_RESPONSE_TIMEOUT)
        .is_ok());
    assert!(ControlClient::new(&socket)
        .with_deadlines(
            64,
            MAX_CONTROL_IO_TIMEOUT,
            MAX_CONTROL_RESPONSE_TIMEOUT
                .checked_add(Duration::from_nanos(1))
                .unwrap(),
        )
        .is_err());
    assert!(ControlClient::new(&socket)
        .with_deadlines(64, MAX_CONTROL_IO_TIMEOUT, Duration::ZERO)
        .is_err());

    let mut overflow = ControlServerConfig::new(&socket);
    overflow.handler_timeout = Duration::MAX;
    overflow.io_timeout = Duration::from_nanos(1);
    assert!(matches!(
        ControlClient::from_server_config(&overflow),
        Err(ControlError::InvalidConfiguration("client deadline overflows"))
    ));
}

#[test]
fn widening_response_wait_does_not_widen_server_io_or_handler_caps() {
    let (_directory, socket) = private_socket();
    let mut config = ControlServerConfig::new(&socket);
    config.io_timeout = MAX_CONTROL_IO_TIMEOUT;
    config.handler_timeout = MAX_CONTROL_HANDLER_TIMEOUT;
    assert!(config.validate().is_ok());

    config.io_timeout = MAX_CONTROL_IO_TIMEOUT.checked_add(Duration::from_nanos(1)).unwrap();
    assert!(config.validate().is_err());
    config.io_timeout = MAX_CONTROL_IO_TIMEOUT;
    config.handler_timeout = MAX_CONTROL_HANDLER_TIMEOUT
        .checked_add(Duration::from_nanos(1))
        .unwrap();
    assert!(config.validate().is_err());
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(128))]

    #[test]
    fn request_codec_roundtrips(
        first in 1_u8..=u8::MAX,
        tail in any::<[u8; 15]>(),
        method in "[a-z][a-z0-9._-]{0,31}",
        payload in prop::collection::vec(any::<u8>(), 0..2048),
    ) {
        let mut id = [0_u8; 16];
        id[0] = first;
        id[1..].copy_from_slice(&tail);
        let request = ControlRequest::new(RequestId::from_bytes(id).unwrap(), method, payload).unwrap();
        let encoded = encode_request(&request, 4096).unwrap();
        let decoded = decode_request(&encoded, 4096).unwrap();
        prop_assert_eq!(decoded.request_id(), request.request_id());
        prop_assert_eq!(decoded.method(), request.method());
        prop_assert_eq!(decoded.payload(), request.payload());
    }

    #[test]
    fn response_codec_roundtrips(
        first in 1_u8..=u8::MAX,
        tail in any::<[u8; 15]>(),
        payload in prop::collection::vec(any::<u8>(), 0..2048),
    ) {
        let mut id = [0_u8; 16];
        id[0] = first;
        id[1..].copy_from_slice(&tail);
        let response = ControlResponse::success(RequestId::from_bytes(id).unwrap(), payload);
        let encoded = encode_response(&response, 4096).unwrap();
        let decoded = decode_response(&encoded, 4096).unwrap();
        prop_assert_eq!(decoded.request_id(), response.request_id());
        prop_assert_eq!(decoded.status(), response.status());
        prop_assert_eq!(decoded.message(), response.message());
        prop_assert_eq!(decoded.payload(), response.payload());
    }
}

#[test]
fn malformed_and_noncanonical_frames_fail_closed() {
    let request = request(1, b"hello");
    let encoded = encode_request(&request, 1024).unwrap();

    let mut wrong_magic = encoded.clone();
    wrong_magic[0] ^= 1;
    assert!(decode_request(&wrong_magic, 1024).is_err());

    let mut wrong_version = encoded.clone();
    wrong_version[5] = 2;
    assert!(decode_request(&wrong_version, 1024).is_err());

    let mut trailing = encoded.clone();
    trailing.push(0);
    assert!(decode_request(&trailing, 1024).is_err());

    assert!(decode_request(&encoded[..20], 1024).is_err());
    assert!(decode_request(&encoded, encoded.len() - 1).is_err());
}

#[test]
fn method_and_failure_response_shapes_are_strict() {
    let id = RequestId::from_bytes([1_u8; 16]).unwrap();
    assert!(ControlRequest::new(id, "Admin.Stop", Vec::new()).is_err());
    assert!(ControlRequest::new(id, "", Vec::new()).is_err());
    assert!(ControlResponse::failure(id, ControlStatus::Ok, "not an error").is_err());

    let failure = ControlResponse::failure(id, ControlStatus::Conflict, "duplicate command").unwrap();
    let encoded = encode_response(&failure, 1024).unwrap();
    let decoded = decode_response(&encoded, 1024).unwrap();
    assert_eq!(decoded.request_id(), failure.request_id());
    assert_eq!(decoded.status(), failure.status());
    assert_eq!(decoded.message(), failure.message());
    assert_eq!(decoded.payload(), failure.payload());
}

#[test]
fn debug_output_redacts_payload_and_failure_text() {
    let id = RequestId::from_bytes([7_u8; 16]).unwrap();
    let request = ControlRequest::new(id, "sign.request", b"super-secret-request".to_vec()).unwrap();
    let response = ControlResponse::failure(id, ControlStatus::Internal, "super-secret-response").unwrap();
    let request_debug = format!("{request:?}");
    let response_debug = format!("{response:?}");
    assert!(!request_debug.contains("super-secret"));
    assert!(!response_debug.contains("super-secret"));
    assert!(request_debug.contains("payload_len"));
    assert!(response_debug.contains("message_len"));
}

#[test]
fn relative_socket_paths_fail_before_io() {
    assert!(matches!(
        crate::filesystem::validate_private_parent(Path::new("relative/control.sock")).unwrap_err(),
        ControlError::UnsafePath { .. }
    ));
}

#[tokio::test]
async fn owner_only_server_and_client_roundtrip_then_clean_up() {
    let (_directory, socket) = private_socket();
    let server = ControlServer::bind(test_config(&socket), EchoHandler).await.unwrap();
    let metadata = fs::symlink_metadata(&socket).unwrap();
    assert!(metadata.file_type().is_socket());
    assert_eq!(metadata.permissions().mode() & 0o777, 0o600);

    let shutdown = CancellationToken::new();
    let task_shutdown = shutdown.clone();
    let task = tokio::spawn(async move { server.run(task_shutdown).await });
    let client = ControlClient::new(&socket)
        .with_limits(1024, Duration::from_secs(1))
        .unwrap();
    let request = request(2, b"ready");
    let response = client.call(&request).await.unwrap();
    assert!(response.is_success());
    assert_eq!(response.payload(), b"ready");

    shutdown.cancel();
    task.await.unwrap().unwrap();
    assert!(!socket.exists());
}

#[tokio::test]
async fn handler_cannot_substitute_response_request_id() {
    let (_directory, socket) = private_socket();
    let server = ControlServer::bind(test_config(&socket), WrongIdHandler).await.unwrap();
    let shutdown = CancellationToken::new();
    let task_shutdown = shutdown.clone();
    let task = tokio::spawn(async move { server.run(task_shutdown).await });

    let request = request(3, b"payload");
    let response = ControlClient::new(&socket).call(&request).await.unwrap();
    assert_eq!(response.request_id(), request.request_id());
    assert_eq!(response.status(), ControlStatus::Ambiguous);

    shutdown.cancel();
    task.await.unwrap().unwrap();
}

#[tokio::test]
async fn handler_deadline_cancels_the_future_before_shutdown() {
    let (_directory, socket) = private_socket();
    let dropped = Arc::new(AtomicBool::new(false));
    let mut config = test_config(&socket);
    config.handler_timeout = Duration::from_millis(50);
    let server = ControlServer::bind(
        config,
        HangingHandler {
            dropped: dropped.clone(),
        },
    )
    .await
    .unwrap();
    let shutdown = CancellationToken::new();
    let task_shutdown = shutdown.clone();
    let task = tokio::spawn(async move { server.run(task_shutdown).await });

    let response = ControlClient::new(&socket)
        .with_limits(1024, Duration::from_secs(1))
        .unwrap()
        .call(&request(6, b"bounded"))
        .await
        .unwrap();
    assert_eq!(response.status(), ControlStatus::Ambiguous);
    assert!(dropped.load(Ordering::Acquire));

    shutdown.cancel();
    task.await.unwrap().unwrap();
}

#[tokio::test]
async fn handler_panic_returns_correlated_ambiguous_status() {
    let (_directory, socket) = private_socket();
    let server = ControlServer::bind(test_config(&socket), PanicHandler).await.unwrap();
    let shutdown = CancellationToken::new();
    let task_shutdown = shutdown.clone();
    let task = tokio::spawn(async move { server.run(task_shutdown).await });

    let request = request(10, b"mutate");
    let response = ControlClient::new(&socket).call(&request).await.unwrap();
    assert_eq!(response.request_id(), request.request_id());
    assert_eq!(response.status(), ControlStatus::Ambiguous);

    shutdown.cancel();
    task.await.unwrap().unwrap();
}

#[tokio::test]
async fn partial_frame_accepted_before_shutdown_never_reaches_handler() {
    let (_directory, socket) = private_socket();
    let calls = Arc::new(AtomicUsize::new(0));
    let server = ControlServer::bind(test_config(&socket), CountingHandler(calls.clone()))
        .await
        .unwrap();
    let shutdown = CancellationToken::new();
    let task_shutdown = shutdown.clone();
    let task = tokio::spawn(async move { server.run(task_shutdown).await });

    let frame = encode_request(&request(11, b"must-not-run"), 1024).unwrap();
    let mut stream = UnixStream::connect(&socket).await.unwrap();
    stream
        .write_all(&u32::try_from(frame.len()).unwrap().to_be_bytes())
        .await
        .unwrap();
    stream.write_all(&frame[..5]).await.unwrap();
    tokio::time::sleep(Duration::from_millis(20)).await;
    shutdown.cancel();
    tokio::time::sleep(Duration::from_millis(20)).await;
    let _ = stream.write_all(&frame[5..]).await;
    drop(stream);

    task.await.unwrap().unwrap();
    assert_eq!(calls.load(Ordering::Acquire), 0);
}

#[tokio::test]
async fn active_socket_is_never_replaced_and_stale_socket_requires_opt_in() {
    let (_directory, socket) = private_socket();
    let active = StdUnixListener::bind(&socket).unwrap();
    fs::set_permissions(&socket, fs::Permissions::from_mode(0o600)).unwrap();
    let mut config = test_config(&socket);
    config.recover_stale_socket = true;
    let error = match ControlServer::bind(config.clone(), EchoHandler).await {
        Ok(_) => panic!("active socket must not be replaced"),
        Err(error) => error,
    };
    assert!(matches!(error, ControlError::SocketInUse(_)));
    drop(active);

    let error = match ControlServer::bind(test_config(&socket), EchoHandler).await {
        Ok(_) => panic!("stale socket recovery must require opt-in"),
        Err(error) => error,
    };
    assert!(matches!(error, ControlError::SocketInUse(_)));

    let server = ControlServer::bind(config, EchoHandler).await.unwrap();
    drop(server);
    assert!(!socket.exists());
}

#[tokio::test]
async fn symlink_regular_file_and_insecure_parent_are_rejected() {
    let (directory, socket) = private_socket();
    let target = directory.path().join("target");
    fs::write(&target, b"not a socket").unwrap();
    std::os::unix::fs::symlink(&target, &socket).unwrap();
    let error = match ControlServer::bind(test_config(&socket), EchoHandler).await {
        Ok(_) => panic!("symlink socket path must be rejected"),
        Err(error) => error,
    };
    assert!(matches!(error, ControlError::UnsafePath { .. }));
    fs::remove_file(&socket).unwrap();

    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o755)).unwrap();
    let error = match ControlServer::bind(test_config(&socket), EchoHandler).await {
        Ok(_) => panic!("insecure parent must be rejected"),
        Err(error) => error,
    };
    assert!(matches!(error, ControlError::UnsafePath { .. }));
}

#[tokio::test]
async fn client_refuses_a_group_or_world_accessible_socket() {
    let (_directory, socket) = private_socket();
    let listener = StdUnixListener::bind(&socket).unwrap();
    fs::set_permissions(&socket, fs::Permissions::from_mode(0o666)).unwrap();
    let error = ControlClient::new(&socket)
        .call(&request(8, b"secret"))
        .await
        .unwrap_err();
    assert!(matches!(error, ControlError::UnsafePath { .. }));
    drop(listener);
}

#[tokio::test]
async fn invalid_aggregate_memory_budget_is_rejected_before_bind() {
    let (_directory, socket) = private_socket();
    let mut config = test_config(&socket);
    config.max_frame_bytes = 1024 * 1024;
    config.max_inflight_bytes = 1024 * 1024;
    let error = match ControlServer::bind(config, EchoHandler).await {
        Ok(_) => panic!("under-sized aggregate byte budget must fail"),
        Err(error) => error,
    };
    assert!(matches!(error, ControlError::InvalidConfiguration(_)));
}

#[tokio::test]
async fn client_reports_ambiguous_after_connection_write_or_read_failure() {
    let (_directory, socket) = private_socket();
    let listener = tokio::net::UnixListener::bind(&socket).unwrap();
    fs::set_permissions(&socket, fs::Permissions::from_mode(0o600)).unwrap();
    let task = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        drop(stream);
    });
    let request = request(12, b"maybe-committed");
    let error = ControlClient::new(&socket).call(&request).await.unwrap_err();
    assert!(matches!(error, ControlError::Ambiguous(id) if id == request.request_id()));
    task.await.unwrap();
}

#[tokio::test]
async fn response_prefix_and_body_share_one_absolute_deadline() {
    let (_directory, socket) = private_socket();
    let listener = tokio::net::UnixListener::bind(&socket).unwrap();
    fs::set_permissions(&socket, fs::Permissions::from_mode(0o600)).unwrap();
    let request = request(13, b"absolute-response-budget");
    let response = ControlResponse::success(request.request_id(), b"too-late".to_vec());
    let frame = encode_response(&response, 1024).unwrap();
    let frame_length = u32::try_from(frame.len()).unwrap().to_be_bytes();
    let task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        tokio::time::sleep(Duration::from_millis(40)).await;
        stream.write_all(&frame_length).await.unwrap();
        tokio::time::sleep(Duration::from_millis(70)).await;
        let _ = stream.write_all(&frame).await;
    });

    let error = ControlClient::new(&socket)
        .with_deadlines(1024, Duration::from_secs(1), Duration::from_millis(80))
        .unwrap()
        .call(&request)
        .await
        .unwrap_err();
    assert!(matches!(error, ControlError::Ambiguous(id) if id == request.request_id()));
    task.await.unwrap();
}

#[tokio::test]
async fn cleanup_identity_failure_is_reported_and_replacement_is_preserved() {
    let (directory, socket) = private_socket();
    let server = ControlServer::bind(test_config(&socket), EchoHandler).await.unwrap();
    let shutdown = CancellationToken::new();
    let task_shutdown = shutdown.clone();
    let task = tokio::spawn(async move { server.run(task_shutdown).await });

    let moved = directory.path().join("moved.sock");
    fs::rename(&socket, &moved).unwrap();
    let replacement = StdUnixListener::bind(&socket).unwrap();
    fs::set_permissions(&socket, fs::Permissions::from_mode(0o600)).unwrap();
    shutdown.cancel();
    let error = task.await.unwrap().unwrap_err();
    assert!(matches!(error, ControlError::UnsafePath { .. }));
    assert!(socket.exists());

    drop(replacement);
    fs::remove_file(&socket).unwrap();
    fs::remove_file(&moved).unwrap();
}

#[tokio::test]
async fn nonsticky_writable_ancestor_is_rejected() {
    let (directory, _socket) = private_socket();
    let writable = directory.path().join("writable");
    let private = writable.join("private");
    fs::create_dir(&writable).unwrap();
    fs::create_dir(&private).unwrap();
    fs::set_permissions(&writable, fs::Permissions::from_mode(0o777)).unwrap();
    fs::set_permissions(&private, fs::Permissions::from_mode(0o700)).unwrap();
    let socket = private.join("control.sock");
    let error = match ControlServer::bind(test_config(&socket), EchoHandler).await {
        Ok(_) => panic!("renameable ancestor must fail"),
        Err(error) => error,
    };
    assert!(matches!(error, ControlError::UnsafePath { .. }));
}

#[tokio::test]
async fn oversized_and_partial_frames_do_not_stop_the_server() {
    let (_directory, socket) = private_socket();
    let mut config = test_config(&socket);
    config.max_frame_bytes = 256;
    config.io_timeout = Duration::from_millis(100);
    let server = ControlServer::bind(config, EchoHandler).await.unwrap();
    let shutdown = CancellationToken::new();
    let task_shutdown = shutdown.clone();
    let task = tokio::spawn(async move { server.run(task_shutdown).await });

    let mut oversized = UnixStream::connect(&socket).await.unwrap();
    oversized.write_all(&257_u32.to_be_bytes()).await.unwrap();
    drop(oversized);

    let mut partial = UnixStream::connect(&socket).await.unwrap();
    partial.write_all(&100_u32.to_be_bytes()).await.unwrap();
    partial.write_all(b"short").await.unwrap();
    tokio::time::sleep(Duration::from_millis(150)).await;
    drop(partial);

    let client = ControlClient::new(&socket)
        .with_limits(256, Duration::from_secs(1))
        .unwrap();
    let response = client.call(&request(4, b"still-live")).await.unwrap();
    assert_eq!(response.payload(), b"still-live");

    shutdown.cancel();
    task.await.unwrap().unwrap();
}
