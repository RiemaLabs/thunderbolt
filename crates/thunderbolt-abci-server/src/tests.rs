use std::error::Error;
use std::io::{Read, Write};
use std::mem::size_of;
use std::net::{SocketAddr, TcpStream};
use std::process::Command;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

#[cfg(unix)]
use std::fs;
#[cfg(unix)]
use std::os::unix::fs::{FileTypeExt, PermissionsExt};

use proptest::prelude::*;
use prost::{bytes::Bytes, Message as _};
use tendermint_abci::Application;
use tendermint_proto::v0_38::abci::{
    request, response, ExtendedCommitInfo, ExtendedVoteInfo, Misbehavior, Request, RequestEcho, RequestInitChain,
    RequestPrepareProposal, Response, ResponseEcho, ValidatorUpdate,
};
use tendermint_proto::v0_38::types::{ConsensusParams, ValidatorParams};

use crate::dispatch::{dispatch_frame, DispatchFailure};
use crate::framing::{encode_varint, read_frame, write_frame, TimedStream};
use crate::preflight::preflight_request;
use crate::semaphore::PermitPool;
use crate::*;

type TestResult<T> = std::result::Result<T, Box<dyn Error>>;

#[derive(Clone, Copy)]
struct EchoApplication;

impl Application for EchoApplication {}

#[derive(Clone, Copy)]
struct PanicApplication;

impl Application for PanicApplication {
    fn echo(&self, _request: RequestEcho) -> tendermint_proto::v0_38::abci::ResponseEcho {
        std::panic::resume_unwind(Box::new("application panic"))
    }
}

#[derive(Clone, Copy)]
struct PanicFatal;

impl FatalServerHandler for PanicFatal {
    fn terminate(&self, event: FatalServerEvent) -> ! {
        std::panic::resume_unwind(Box::new(event))
    }
}

#[derive(Clone, Copy)]
struct ClassifiedExitFatal;

impl FatalServerHandler for ClassifiedExitFatal {
    fn terminate(&self, event: FatalServerEvent) -> ! {
        let code = match event.kind() {
            FatalServerKind::HandlerPanic => 79,
            FatalServerKind::HandlerTimeout => 80,
            FatalServerKind::WorkerInvariant => 81,
            FatalServerKind::CleanupFailure => 82,
            FatalServerKind::ShutdownTimeout => 83,
            FatalServerKind::ListenerFailure => 84,
        };
        std::process::exit(code);
    }
}

fn limits() -> Result<ServerLimits> {
    ServerLimits::new(64 * 1024, 64 * 1024, 16, 64 * 1024 * 1024, 4_224)
}

fn deadlines() -> Result<ServerDeadlines> {
    ServerDeadlines::new(
        Duration::from_millis(5),
        Duration::from_secs(5),
        Duration::from_millis(500),
        Duration::from_millis(250),
        Duration::from_secs(3),
        Duration::from_secs(1),
        Duration::from_secs(2),
        Duration::from_secs(3),
        Duration::from_secs(5),
    )
}

fn tcp_config() -> Result<ServerConfig> {
    ServerConfig::new(
        ServerEndpoint::Tcp(SocketAddr::from(([127, 0, 0, 1], 0))),
        limits()?,
        deadlines()?,
    )
}

fn tcp_config_with(limits: ServerLimits, deadlines: ServerDeadlines) -> Result<ServerConfig> {
    ServerConfig::new(
        ServerEndpoint::Tcp(SocketAddr::from(([127, 0, 0, 1], 0))),
        limits,
        deadlines,
    )
}

fn encode_request(value: request::Value) -> TestResult<Vec<u8>> {
    let request = Request { value: Some(value) };
    let mut payload = Vec::new();
    payload.try_reserve_exact(request.encoded_len())?;
    request.encode(&mut payload)?;
    let mut framed = encode_varint(u64::try_from(payload.len())?);
    framed.extend_from_slice(&payload);
    Ok(framed)
}

fn read_response(stream: &mut TcpStream) -> TestResult<Response> {
    let mut prefix = Vec::new();
    let length = loop {
        let mut byte = [0_u8; 1];
        stream.read_exact(&mut byte)?;
        prefix.push(byte[0]);
        if byte[0] & 0x80 == 0 {
            let mut value = 0_u64;
            for (index, byte) in prefix.iter().copied().enumerate() {
                value |= u64::from(byte & 0x7f) << (index * 7);
            }
            break usize::try_from(value)?;
        }
    };
    let mut payload = vec![0_u8; length];
    stream.read_exact(&mut payload)?;
    Ok(Response::decode(payload.as_slice())?)
}

fn assert_connection_closed(stream: &mut TcpStream) -> TestResult<()> {
    if let Err(error) = stream.set_read_timeout(Some(Duration::from_secs(1))) {
        if matches!(
            error.kind(),
            std::io::ErrorKind::InvalidInput | std::io::ErrorKind::NotConnected
        ) {
            return Ok(());
        }
        return Err(error.into());
    }
    let mut byte = [0_u8; 1];
    match stream.read(&mut byte) {
        Ok(0) => Ok(()),
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::ConnectionReset
                    | std::io::ErrorKind::ConnectionAborted
                    | std::io::ErrorKind::BrokenPipe
            ) =>
        {
            Ok(())
        }
        Ok(_) => Err("server emitted bytes after rejecting a connection".into()),
        Err(error) => Err(format!("connection did not close: {error}").into()),
    }
}

#[test]
fn loopback_server_dispatches_echo_and_joins_cleanly() -> TestResult<()> {
    let server = start(tcp_config()?, EchoApplication, PanicFatal)?;
    let BoundEndpoint::Tcp(address) = server.endpoint() else {
        return Err("expected TCP endpoint".into());
    };
    let address = *address;
    let rebound_config = ServerConfig::new(ServerEndpoint::Tcp(address), limits()?, deadlines()?)?;
    assert!(matches!(
        start(rebound_config.clone(), EchoApplication, PanicFatal),
        Err(ServerError::Io(_))
    ));
    let mut stream = TcpStream::connect(address)?;
    stream.write_all(&encode_request(request::Value::Echo(RequestEcho {
        message: "hello".to_owned(),
    }))?)?;
    let response = read_response(&mut stream)?;
    let Some(response::Value::Echo(response)) = response.value else {
        return Err("expected Echo response".into());
    };
    assert_eq!(response.message, "hello");
    drop(stream);
    server.shutdown_and_join();
    let retry_deadline = Instant::now() + Duration::from_secs(2);
    let restarted = loop {
        match start(rebound_config.clone(), EchoApplication, PanicFatal) {
            Ok(server) => break server,
            Err(ServerError::Io(error))
                if error.kind() == std::io::ErrorKind::AddrInUse && Instant::now() < retry_deadline =>
            {
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(error) => return Err(error.into()),
        }
    };
    restarted.shutdown_and_join();
    Ok(())
}

#[test]
fn parallel_clients_share_the_bounded_server() -> TestResult<()> {
    let calls = Arc::new(AtomicUsize::new(0));
    let server = start(tcp_config()?, CountingApplication(Arc::clone(&calls)), PanicFatal)?;
    let BoundEndpoint::Tcp(address) = *server.endpoint() else {
        return Err("expected TCP endpoint".into());
    };
    let request = Arc::new(encode_request(request::Value::Echo(RequestEcho {
        message: "parallel".to_owned(),
    }))?);
    let mut clients = Vec::new();
    for _ in 0..8 {
        let request = Arc::clone(&request);
        clients.push(std::thread::spawn(move || -> std::result::Result<(), String> {
            let mut stream = TcpStream::connect(address).map_err(|error| error.to_string())?;
            stream.write_all(&request).map_err(|error| error.to_string())?;
            let response = read_response(&mut stream).map_err(|error| error.to_string())?;
            if matches!(response.value, Some(response::Value::Echo(_))) {
                Ok(())
            } else {
                Err("parallel client received the wrong response".to_owned())
            }
        }));
    }
    for client in clients {
        client.join().map_err(|_| "parallel client panicked")??;
    }
    assert_eq!(calls.load(Ordering::Acquire), 8);
    server.shutdown_and_join();
    Ok(())
}

#[test]
fn per_request_handlers_are_joined_without_worker_registry_growth() -> TestResult<()> {
    let server = start(tcp_config()?, EchoApplication, PanicFatal)?;
    let shutdown = server.shutdown_handle();
    let BoundEndpoint::Tcp(address) = *server.endpoint() else {
        return Err("expected TCP endpoint".into());
    };
    let mut stream = TcpStream::connect(address)?;
    let request = encode_request(request::Value::Echo(RequestEcho {
        message: "reap".to_owned(),
    }))?;
    for _ in 0..256 {
        stream.write_all(&request)?;
        assert!(matches!(
            read_response(&mut stream)?.value,
            Some(response::Value::Echo(_))
        ));
    }
    assert_eq!(shutdown.tracked_worker_count()?, 1);
    drop(stream);
    server.shutdown_and_join();
    Ok(())
}

#[test]
fn expired_decode_budget_closes_only_the_client_connection() -> TestResult<()> {
    let decode_bound = ServerDeadlines::new(
        Duration::from_millis(5),
        Duration::from_secs(2),
        Duration::from_millis(200),
        Duration::from_millis(100),
        Duration::from_secs(1),
        Duration::from_nanos(1),
        Duration::from_secs(1),
        Duration::from_secs(1),
        Duration::from_secs(2),
    )?;
    let server = start(tcp_config_with(limits()?, decode_bound)?, EchoApplication, PanicFatal)?;
    let shutdown = server.shutdown_handle();
    let BoundEndpoint::Tcp(address) = *server.endpoint() else {
        return Err("expected TCP endpoint".into());
    };
    let mut stream = TcpStream::connect(address)?;
    stream.write_all(&encode_request(request::Value::Echo(RequestEcho {
        message: "decode deadline".to_owned(),
    }))?)?;
    assert_connection_closed(&mut stream)?;
    assert!(!shutdown.is_shutdown());
    server.shutdown_and_join();
    Ok(())
}

#[test]
fn partial_frame_is_cancelled_by_shutdown() -> TestResult<()> {
    let server = start(tcp_config()?, EchoApplication, PanicFatal)?;
    let BoundEndpoint::Tcp(address) = server.endpoint() else {
        return Err("expected TCP endpoint".into());
    };
    let mut stream = TcpStream::connect(address)?;
    stream.write_all(&[0x80])?;
    std::thread::sleep(Duration::from_millis(20));
    server.shutdown_and_join();
    assert!(stream.write_all(&[0]).is_err() || stream.read(&mut [0_u8; 1])? == 0);
    Ok(())
}

#[test]
fn shutdown_wakes_a_long_listener_poll_immediately() -> TestResult<()> {
    let long_poll = ServerDeadlines::new(
        Duration::from_secs(5),
        Duration::from_secs(5),
        Duration::from_secs(1),
        Duration::from_millis(250),
        Duration::from_secs(2),
        Duration::from_secs(1),
        Duration::from_secs(1),
        Duration::from_secs(1),
        Duration::from_secs(1),
    )?;
    let server = start(tcp_config_with(limits()?, long_poll)?, EchoApplication, PanicFatal)?;
    std::thread::sleep(Duration::from_millis(25));
    let started = Instant::now();
    server.shutdown_and_join();
    assert!(started.elapsed() < Duration::from_secs(2));
    Ok(())
}

#[derive(Clone)]
struct DrainingApplication {
    started: Arc<AtomicBool>,
    finished: Arc<AtomicBool>,
}

impl Application for DrainingApplication {
    fn echo(&self, request: RequestEcho) -> ResponseEcho {
        self.started.store(true, Ordering::Release);
        std::thread::sleep(Duration::from_millis(100));
        self.finished.store(true, Ordering::Release);
        ResponseEcho {
            message: request.message,
        }
    }
}

#[test]
fn normal_shutdown_joins_an_admitted_callback() -> TestResult<()> {
    let started = Arc::new(AtomicBool::new(false));
    let finished = Arc::new(AtomicBool::new(false));
    let server = start(
        tcp_config()?,
        DrainingApplication {
            started: Arc::clone(&started),
            finished: Arc::clone(&finished),
        },
        PanicFatal,
    )?;
    let BoundEndpoint::Tcp(address) = *server.endpoint() else {
        return Err("expected TCP endpoint".into());
    };
    let mut stream = TcpStream::connect(address)?;
    stream.write_all(&encode_request(request::Value::Echo(RequestEcho {
        message: "drain".to_owned(),
    }))?)?;
    let wait_deadline = Instant::now() + Duration::from_secs(2);
    while !started.load(Ordering::Acquire) && Instant::now() < wait_deadline {
        std::thread::sleep(Duration::from_millis(5));
    }
    assert!(started.load(Ordering::Acquire));
    server.shutdown_and_join();
    assert!(finished.load(Ordering::Acquire));
    assert_connection_closed(&mut stream)?;
    Ok(())
}

#[test]
fn application_panic_produces_no_response_payload() -> TestResult<()> {
    let frame = Request {
        value: Some(request::Value::Echo(RequestEcho {
            message: "panic".to_owned(),
        })),
    }
    .encode_to_vec();
    assert!(matches!(
        dispatch_frame(|| Ok(PanicApplication), frame, 1024, MAX_SERVER_REQUEST_DECODE_ITEMS),
        Err(DispatchFailure::Panicked)
    ));
    Ok(())
}

#[test]
fn malformed_trailing_bytes_do_not_dispatch_a_callback() -> TestResult<()> {
    let calls = Arc::new(AtomicUsize::new(0));
    let factory_calls = AtomicUsize::new(0);
    let mut frame = Request {
        value: Some(request::Value::Echo(RequestEcho {
            message: "never".to_owned(),
        })),
    }
    .encode_to_vec();
    frame.push(0xff);
    assert!(matches!(
        dispatch_frame(
            || {
                factory_calls.fetch_add(1, Ordering::AcqRel);
                Ok(CountingApplication(Arc::clone(&calls)))
            },
            frame,
            1024,
            MAX_SERVER_REQUEST_DECODE_ITEMS
        ),
        Err(DispatchFailure::Client)
    ));
    assert_eq!(factory_calls.load(Ordering::Acquire), 0);
    assert_eq!(calls.load(Ordering::Acquire), 0);
    Ok(())
}

#[test]
fn repeated_empty_transactions_are_rejected_before_factory_or_prost_allocation() -> TestResult<()> {
    let item_count = MAX_SERVER_REQUEST_DECODE_ITEMS + 1;
    let frame = Request {
        value: Some(request::Value::PrepareProposal(RequestPrepareProposal {
            txs: vec![Bytes::new(); item_count],
            ..RequestPrepareProposal::default()
        })),
    }
    .encode_to_vec();
    assert!(frame.len() < item_count * size_of::<Bytes>());
    assert!(preflight_request(&frame, MAX_SERVER_REQUEST_DECODE_ITEMS).is_err());
    let factory_calls = AtomicUsize::new(0);
    assert!(matches!(
        dispatch_frame(
            || {
                factory_calls.fetch_add(1, Ordering::AcqRel);
                Ok(EchoApplication)
            },
            frame,
            64 * 1024,
            MAX_SERVER_REQUEST_DECODE_ITEMS,
        ),
        Err(DispatchFailure::Client)
    ));
    assert_eq!(factory_calls.load(Ordering::Acquire), 0);
    Ok(())
}

#[test]
fn nested_vote_misbehavior_validator_and_consensus_items_share_one_cap() -> TestResult<()> {
    let proposal = Request {
        value: Some(request::Value::PrepareProposal(RequestPrepareProposal {
            txs: vec![Bytes::new(); 2],
            local_last_commit: Some(ExtendedCommitInfo {
                votes: vec![ExtendedVoteInfo::default(); 2],
                ..ExtendedCommitInfo::default()
            }),
            misbehavior: vec![Misbehavior::default(); 2],
            ..RequestPrepareProposal::default()
        })),
    }
    .encode_to_vec();
    assert_eq!(
        preflight_request(&proposal, 6).map_err(|()| "proposal preflight failed")?,
        6
    );
    assert!(preflight_request(&proposal, 5).is_err());

    let init_chain = Request {
        value: Some(request::Value::InitChain(RequestInitChain {
            consensus_params: Some(ConsensusParams {
                validator: Some(ValidatorParams {
                    pub_key_types: vec![String::new(); 2],
                }),
                ..ConsensusParams::default()
            }),
            validators: vec![ValidatorUpdate::default(); 2],
            ..RequestInitChain::default()
        })),
    }
    .encode_to_vec();
    assert_eq!(
        preflight_request(&init_chain, 4).map_err(|()| "init preflight failed")?,
        4
    );
    assert!(preflight_request(&init_chain, 3).is_err());
    Ok(())
}

#[test]
fn every_v038_request_maps_to_the_matching_response_variant() -> TestResult<()> {
    use tendermint_proto::v0_38::abci::*;

    let requests = vec![
        request::Value::Echo(RequestEcho::default()),
        request::Value::Flush(RequestFlush::default()),
        request::Value::Info(RequestInfo::default()),
        request::Value::InitChain(RequestInitChain::default()),
        request::Value::Query(RequestQuery::default()),
        request::Value::CheckTx(RequestCheckTx::default()),
        request::Value::Commit(RequestCommit::default()),
        request::Value::ListSnapshots(RequestListSnapshots::default()),
        request::Value::OfferSnapshot(RequestOfferSnapshot::default()),
        request::Value::LoadSnapshotChunk(RequestLoadSnapshotChunk::default()),
        request::Value::ApplySnapshotChunk(RequestApplySnapshotChunk::default()),
        request::Value::PrepareProposal(RequestPrepareProposal::default()),
        request::Value::ProcessProposal(RequestProcessProposal::default()),
        request::Value::ExtendVote(RequestExtendVote::default()),
        request::Value::VerifyVoteExtension(RequestVerifyVoteExtension::default()),
        request::Value::FinalizeBlock(RequestFinalizeBlock::default()),
    ];
    for request in requests {
        let expected = expected_response_kind(&request);
        let frame = Request { value: Some(request) }.encode_to_vec();
        let response = dispatch_frame(
            || Ok(EchoApplication),
            frame,
            64 * 1024,
            MAX_SERVER_REQUEST_DECODE_ITEMS,
        )
        .map_err(|_| "dispatch failed")?;
        let response = Response::decode(response.as_slice())?;
        let value = response.value.ok_or("response value missing")?;
        assert_eq!(response_kind(&value), expected);
    }
    Ok(())
}

fn expected_response_kind(value: &request::Value) -> u8 {
    match value {
        request::Value::Echo(_) => 1,
        request::Value::Flush(_) => 2,
        request::Value::Info(_) => 3,
        request::Value::InitChain(_) => 4,
        request::Value::Query(_) => 5,
        request::Value::CheckTx(_) => 6,
        request::Value::Commit(_) => 7,
        request::Value::ListSnapshots(_) => 8,
        request::Value::OfferSnapshot(_) => 9,
        request::Value::LoadSnapshotChunk(_) => 10,
        request::Value::ApplySnapshotChunk(_) => 11,
        request::Value::PrepareProposal(_) => 12,
        request::Value::ProcessProposal(_) => 13,
        request::Value::ExtendVote(_) => 14,
        request::Value::VerifyVoteExtension(_) => 15,
        request::Value::FinalizeBlock(_) => 16,
    }
}

fn response_kind(value: &response::Value) -> u8 {
    match value {
        response::Value::Exception(_) => 0,
        response::Value::Echo(_) => 1,
        response::Value::Flush(_) => 2,
        response::Value::Info(_) => 3,
        response::Value::InitChain(_) => 4,
        response::Value::Query(_) => 5,
        response::Value::CheckTx(_) => 6,
        response::Value::Commit(_) => 7,
        response::Value::ListSnapshots(_) => 8,
        response::Value::OfferSnapshot(_) => 9,
        response::Value::LoadSnapshotChunk(_) => 10,
        response::Value::ApplySnapshotChunk(_) => 11,
        response::Value::PrepareProposal(_) => 12,
        response::Value::ProcessProposal(_) => 13,
        response::Value::ExtendVote(_) => 14,
        response::Value::VerifyVoteExtension(_) => 15,
        response::Value::FinalizeBlock(_) => 16,
    }
}

#[derive(Clone)]
struct CountingApplication(Arc<AtomicUsize>);

impl Application for CountingApplication {
    fn echo(&self, request: RequestEcho) -> ResponseEcho {
        self.0.fetch_add(1, Ordering::AcqRel);
        ResponseEcho {
            message: request.message,
        }
    }
}

#[test]
fn global_inflight_budget_serializes_frame_allocation() -> TestResult<()> {
    let frame_cap = 4 * 1024;
    let limits = ServerLimits::new(frame_cap, frame_cap, 1, 64 * 1024, 8)?;
    let pool = PermitPool::new(limits.reservation_per_handler());
    let shutdown = Arc::new(AtomicBool::new(false));
    let mut first_bytes = encode_varint(3);
    first_bytes.extend_from_slice(b"one");
    let mut first_stream = MemoryStream::new(first_bytes);
    let first = read_frame(&mut first_stream, limits, deadlines()?, &shutdown, &pool)?.ok_or("first frame missing")?;

    let mut second_bytes = encode_varint(3);
    second_bytes.extend_from_slice(b"two");
    let second_pool = Arc::clone(&pool);
    let second_shutdown = Arc::clone(&shutdown);
    let framing_deadlines = deadlines()?;
    let (sender, receiver) = std::sync::mpsc::sync_channel(1);
    let worker = std::thread::spawn(move || {
        let mut stream = MemoryStream::new(second_bytes);
        let result = read_frame(&mut stream, limits, framing_deadlines, &second_shutdown, &second_pool)
            .and_then(|frame| frame.ok_or(FrameError::TruncatedFrame));
        let _ = sender.send(result);
    });
    std::thread::sleep(Duration::from_millis(75));
    assert!(matches!(receiver.try_recv(), Err(std::sync::mpsc::TryRecvError::Empty)));
    drop(first);
    let second = receiver.recv_timeout(Duration::from_secs(1))??;
    assert_eq!(second.bytes, b"two");
    worker.join().map_err(|_| "budget worker panicked")?;
    Ok(())
}

#[test]
fn poisoned_reservation_accounting_fails_closed_before_allocation() -> TestResult<()> {
    let mut bytes = encode_varint(3);
    bytes.extend_from_slice(b"one");
    let mut stream = MemoryStream::new(bytes);
    let shutdown = AtomicBool::new(false);
    let limits = framing_limits(1024)?;
    let pool = PermitPool::new(limits.reservation_per_handler());
    pool.poison_for_test();
    assert!(matches!(
        read_frame(&mut stream, limits, deadlines()?, &shutdown, &pool),
        Err(FrameError::AccountingInvariant)
    ));
    Ok(())
}

#[test]
fn connection_cap_rejects_excess_idle_clients() -> TestResult<()> {
    let limits = ServerLimits::new(4 * 1024, 4 * 1024, 1, 64 * 1024, 8)?;
    let server = start(tcp_config_with(limits, deadlines()?)?, EchoApplication, PanicFatal)?;
    let BoundEndpoint::Tcp(address) = *server.endpoint() else {
        return Err("expected TCP endpoint".into());
    };
    let mut first = TcpStream::connect(address)?;
    first.write_all(&[0x80])?;
    std::thread::sleep(Duration::from_millis(30));
    let mut excess = TcpStream::connect(address)?;
    std::thread::sleep(Duration::from_millis(30));
    assert_connection_closed(&mut excess)?;
    server.shutdown_and_join();
    Ok(())
}

#[test]
fn slow_header_and_payload_are_cancelled_without_stopping_server() -> TestResult<()> {
    let bounded_deadlines = ServerDeadlines::new(
        Duration::from_millis(5),
        Duration::from_millis(300),
        Duration::from_millis(75),
        Duration::from_millis(50),
        Duration::from_millis(100),
        Duration::from_millis(75),
        Duration::from_secs(1),
        Duration::from_secs(1),
        Duration::from_secs(2),
    )?;
    let server = start(
        tcp_config_with(limits()?, bounded_deadlines)?,
        EchoApplication,
        PanicFatal,
    )?;
    let BoundEndpoint::Tcp(address) = *server.endpoint() else {
        return Err("expected TCP endpoint".into());
    };

    let mut delayed = TcpStream::connect(address)?;
    std::thread::sleep(Duration::from_millis(100));
    delayed.write_all(&encode_request(request::Value::Echo(RequestEcho {
        message: "delayed but within idle deadline".to_owned(),
    }))?)?;
    assert!(matches!(
        read_response(&mut delayed)?.value,
        Some(response::Value::Echo(_))
    ));

    let mut idle = TcpStream::connect(address)?;
    std::thread::sleep(Duration::from_millis(375));
    assert_connection_closed(&mut idle)?;

    let mut slow_header = TcpStream::connect(address)?;
    slow_header.write_all(&[0x80])?;
    std::thread::sleep(Duration::from_millis(150));
    assert_connection_closed(&mut slow_header)?;

    let mut slow_payload = TcpStream::connect(address)?;
    slow_payload.write_all(&[64, 1])?;
    std::thread::sleep(Duration::from_millis(175));
    assert_connection_closed(&mut slow_payload)?;

    let mut healthy = TcpStream::connect(address)?;
    healthy.write_all(&encode_request(request::Value::Echo(RequestEcho {
        message: "healthy".to_owned(),
    }))?)?;
    assert!(matches!(
        read_response(&mut healthy)?.value,
        Some(response::Value::Echo(_))
    ));
    server.shutdown_and_join();
    Ok(())
}

#[test]
fn shutdown_releases_no_partial_request_output_or_callback() -> TestResult<()> {
    let calls = Arc::new(AtomicUsize::new(0));
    let server = start(tcp_config()?, CountingApplication(Arc::clone(&calls)), PanicFatal)?;
    let BoundEndpoint::Tcp(address) = *server.endpoint() else {
        return Err("expected TCP endpoint".into());
    };
    let mut stream = TcpStream::connect(address)?;
    let request = encode_request(request::Value::Echo(RequestEcho {
        message: "must not run".to_owned(),
    }))?;
    stream.write_all(&request[..2])?;
    std::thread::sleep(Duration::from_millis(20));
    server.shutdown_handle().shutdown();
    let _ = stream.write_all(&request[2..]);
    server.shutdown_and_join();
    assert_eq!(calls.load(Ordering::Acquire), 0);
    assert_connection_closed(&mut stream)?;
    Ok(())
}

#[cfg(unix)]
#[test]
fn unix_socket_is_owner_only_restarts_and_cleans_exact_path() -> TestResult<()> {
    let directory = tempfile::TempDir::new()?;
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))?;
    let path = directory.path().join("abci.sock");
    let config = ServerConfig::new(ServerEndpoint::Unix(path.clone()), limits()?, deadlines()?)?;
    let server = start(config.clone(), EchoApplication, PanicFatal)?;
    let metadata = fs::symlink_metadata(&path)?;
    assert!(metadata.file_type().is_socket());
    assert_eq!(metadata.permissions().mode() & 0o077, 0);
    let lock_path = path.with_file_name("abci.sock.lock");
    let lock_metadata = fs::symlink_metadata(&lock_path)?;
    assert!(lock_metadata.is_file());
    assert_eq!(lock_metadata.permissions().mode() & 0o077, 0);
    let duplicate = start(config.clone(), EchoApplication, PanicFatal);
    assert!(matches!(duplicate, Err(ServerError::UnixSocket { .. })));
    server.shutdown_and_join();
    assert!(!path.exists());
    assert!(!lock_path.exists());
    let restarted = start(config, EchoApplication, PanicFatal)?;
    restarted.shutdown_and_join();
    assert!(!path.exists());
    assert!(!lock_path.exists());
    Ok(())
}

#[cfg(unix)]
#[test]
fn unix_socket_recovers_only_refused_stale_inode_and_rejects_hardlinked_lock() -> TestResult<()> {
    use std::os::unix::net::UnixListener;

    let directory = tempfile::TempDir::new()?;
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))?;
    let path = directory.path().join("abci.sock");
    let stale = UnixListener::bind(&path)?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
    drop(stale);
    let config = ServerConfig::new(ServerEndpoint::Unix(path.clone()), limits()?, deadlines()?)?;
    let recovered = start(config.clone(), EchoApplication, PanicFatal)?;
    recovered.shutdown_and_join();

    let insecure = UnixListener::bind(&path)?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o666))?;
    drop(insecure);
    assert!(matches!(
        start(config.clone(), EchoApplication, PanicFatal),
        Err(ServerError::UnixSocket { .. })
    ));
    assert!(path.exists());
    fs::remove_file(&path)?;

    let lock_path = path.with_file_name("abci.sock.lock");
    let alias = path.with_file_name("abci.sock.lock.alias");
    fs::write(&lock_path, b"")?;
    fs::set_permissions(&lock_path, fs::Permissions::from_mode(0o600))?;
    fs::hard_link(&lock_path, &alias)?;
    assert!(matches!(
        start(config, EchoApplication, PanicFatal),
        Err(ServerError::UnixSocket { .. })
    ));
    assert!(!path.exists());
    Ok(())
}

#[cfg(unix)]
#[test]
fn unix_socket_rejects_symlink_foreign_path_and_insecure_parent() -> TestResult<()> {
    use std::os::unix::fs::symlink;

    let directory = tempfile::TempDir::new()?;
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))?;
    let path = directory.path().join("abci.sock");
    let target = directory.path().join("target");
    fs::write(&target, b"not a socket")?;
    symlink(&target, &path)?;
    let config = ServerConfig::new(ServerEndpoint::Unix(path.clone()), limits()?, deadlines()?)?;
    assert!(matches!(
        start(config, EchoApplication, PanicFatal),
        Err(ServerError::UnixSocket { .. })
    ));
    fs::remove_file(&path)?;
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o755))?;
    let config = ServerConfig::new(ServerEndpoint::Unix(path), limits()?, deadlines()?)?;
    assert!(matches!(
        start(config, EchoApplication, PanicFatal),
        Err(ServerError::UnixSocket { .. })
    ));
    Ok(())
}

enum FatalTestApplication {
    Panic,
    Timeout,
    Oversize,
    ClonePanic,
}

impl Clone for FatalTestApplication {
    fn clone(&self) -> Self {
        match self {
            Self::ClonePanic => std::panic::resume_unwind(Box::new("fatal application clone panic")),
            Self::Panic => Self::Panic,
            Self::Timeout => Self::Timeout,
            Self::Oversize => Self::Oversize,
        }
    }
}

impl Application for FatalTestApplication {
    fn echo(&self, request: RequestEcho) -> ResponseEcho {
        match self {
            Self::Panic => std::panic::resume_unwind(Box::new("fatal callback panic")),
            Self::Timeout => {
                std::thread::sleep(Duration::from_secs(5));
                ResponseEcho {
                    message: request.message,
                }
            }
            Self::Oversize => ResponseEcho {
                message: "x".repeat(128 * 1024),
            },
            Self::ClonePanic => ResponseEcho {
                message: request.message,
            },
        }
    }
}

#[test]
fn fatal_boundary_subprocess_entry() -> TestResult<()> {
    let Ok(scenario) = std::env::var("THUNDERBOLT_ABCI_FATAL_SCENARIO") else {
        return Ok(());
    };
    if scenario == "cleanup" {
        #[cfg(unix)]
        run_cleanup_fatal_subprocess()?;
        std::process::exit(0);
    }
    let application = match scenario.as_str() {
        "panic" => FatalTestApplication::Panic,
        "timeout" => FatalTestApplication::Timeout,
        "oversize" => FatalTestApplication::Oversize,
        "clone-panic" => FatalTestApplication::ClonePanic,
        _ => std::process::exit(2),
    };
    let fatal_deadlines = ServerDeadlines::new(
        Duration::from_millis(5),
        Duration::from_secs(1),
        Duration::from_millis(100),
        Duration::from_millis(50),
        Duration::from_millis(250),
        Duration::from_millis(100),
        Duration::from_millis(250),
        Duration::from_millis(50),
        Duration::from_millis(100),
    )?;
    let server = start(
        tcp_config_with(limits()?, fatal_deadlines)?,
        application,
        ClassifiedExitFatal,
    )?;
    let BoundEndpoint::Tcp(address) = *server.endpoint() else {
        std::process::exit(3);
    };
    let mut stream = TcpStream::connect(address)?;
    stream.write_all(&encode_request(request::Value::Echo(RequestEcho {
        message: "fatal".to_owned(),
    }))?)?;
    std::thread::sleep(Duration::from_secs(3));
    std::process::exit(0);
}

#[cfg(unix)]
fn run_cleanup_fatal_subprocess() -> TestResult<()> {
    use std::os::unix::net::UnixListener;

    let directory = std::env::var_os("THUNDERBOLT_ABCI_FATAL_DIR").ok_or("fatal directory missing")?;
    let directory = std::path::PathBuf::from(directory);
    let path = directory.join("abci.sock");
    let moved = directory.join("moved.sock");
    let config = ServerConfig::new(ServerEndpoint::Unix(path.clone()), limits()?, deadlines()?)?;
    let server = start(config, EchoApplication, ClassifiedExitFatal)?;
    fs::rename(&path, &moved)?;
    let _replacement = UnixListener::bind(&path)?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
    server.shutdown_and_join();
    Ok(())
}

fn run_fatal_subprocess(scenario: &str, directory: Option<&std::path::Path>) -> TestResult<std::process::Output> {
    let executable = std::env::current_exe()?;
    let mut command = Command::new(executable);
    command
        .arg("--exact")
        .arg("tests::fatal_boundary_subprocess_entry")
        .arg("--nocapture")
        .arg("--test-threads=1")
        .env("THUNDERBOLT_ABCI_FATAL_SCENARIO", scenario);
    if let Some(directory) = directory {
        command.env("THUNDERBOLT_ABCI_FATAL_DIR", directory);
    }
    Ok(command.output()?)
}

#[test]
fn callback_panic_and_timeout_cross_the_nonreturning_fatal_boundary() -> TestResult<()> {
    for (scenario, expected_code) in [("panic", 79), ("clone-panic", 79), ("timeout", 80), ("oversize", 81)] {
        let output = run_fatal_subprocess(scenario, None)?;
        assert_eq!(output.status.code(), Some(expected_code), "scenario={scenario}");
    }
    Ok(())
}

#[cfg(unix)]
#[test]
fn replaced_unix_socket_cleanup_is_fatal_and_preserves_replacement() -> TestResult<()> {
    let directory = tempfile::TempDir::new()?;
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))?;
    let output = run_fatal_subprocess("cleanup", Some(directory.path()))?;
    assert_eq!(output.status.code(), Some(82));
    let replacement = directory.path().join("abci.sock");
    let moved = directory.path().join("moved.sock");
    assert!(fs::symlink_metadata(replacement)?.file_type().is_socket());
    assert!(fs::symlink_metadata(moved)?.file_type().is_socket());
    Ok(())
}

struct MemoryStream {
    read: std::io::Cursor<Vec<u8>>,
    written: Vec<u8>,
}

impl MemoryStream {
    fn new(bytes: Vec<u8>) -> Self {
        Self {
            read: std::io::Cursor::new(bytes),
            written: Vec::new(),
        }
    }
}

impl Read for MemoryStream {
    fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
        self.read.read(bytes)
    }
}

impl Write for MemoryStream {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.written.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl TimedStream for MemoryStream {
    fn set_read_deadline(&self, _timeout: Duration) -> std::io::Result<()> {
        Ok(())
    }
    fn set_write_deadline(&self, _timeout: Duration) -> std::io::Result<()> {
        Ok(())
    }
    fn shutdown_both(&self) -> std::io::Result<()> {
        Ok(())
    }
}

struct StalledWriteStream;

impl Read for StalledWriteStream {
    fn read(&mut self, _bytes: &mut [u8]) -> std::io::Result<usize> {
        Ok(0)
    }
}

impl Write for StalledWriteStream {
    fn write(&mut self, _bytes: &[u8]) -> std::io::Result<usize> {
        Err(std::io::Error::from(std::io::ErrorKind::WouldBlock))
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl TimedStream for StalledWriteStream {
    fn set_read_deadline(&self, _timeout: Duration) -> std::io::Result<()> {
        Ok(())
    }

    fn set_write_deadline(&self, _timeout: Duration) -> std::io::Result<()> {
        Ok(())
    }

    fn shutdown_both(&self) -> std::io::Result<()> {
        Ok(())
    }
}

#[test]
fn stalled_response_write_is_bounded_and_returns_no_success() -> TestResult<()> {
    let mut stream = StalledWriteStream;
    let shutdown = AtomicBool::new(false);
    assert!(matches!(
        write_frame(
            &mut stream,
            b"response",
            1024,
            Instant::now() + Duration::from_millis(10),
            &shutdown
        ),
        Err(FrameError::WriteTimeout)
    ));
    let mut expired = MemoryStream::new(Vec::new());
    assert!(matches!(
        write_frame(&mut expired, b"late", 1024, Instant::now(), &shutdown),
        Err(FrameError::WriteTimeout)
    ));
    assert!(expired.written.is_empty());
    Ok(())
}

fn framing_limits(cap: usize) -> Result<ServerLimits> {
    ServerLimits::new(cap, cap, 1, 64 * 1024, 8)
}

#[test]
fn framing_rejects_varint_bombs_noncanonical_and_truncated_payloads() -> TestResult<()> {
    let shutdown = AtomicBool::new(false);
    let deadlines = deadlines()?;
    for (bytes, expected) in [
        (vec![0x80; 10], "invalid"),
        (vec![0x81, 0x00, 0], "noncanonical"),
        (vec![0], "zero"),
        (vec![5, 1, 2], "truncated"),
    ] {
        let mut stream = MemoryStream::new(bytes);
        let limits = framing_limits(1024)?;
        let pool = PermitPool::new(limits.reservation_per_handler());
        let error = match read_frame(&mut stream, limits, deadlines, &shutdown, &pool) {
            Ok(_) => return Err("malformed frame was accepted".into()),
            Err(error) => error,
        };
        assert!(error.to_string().contains(expected));
    }
    let mut oversized = encode_varint(1025);
    oversized.extend_from_slice(&[0; 4]);
    let mut stream = MemoryStream::new(oversized);
    let limits = framing_limits(1024)?;
    let pool = PermitPool::new(limits.reservation_per_handler());
    assert!(matches!(
        read_frame(&mut stream, limits, deadlines, &shutdown, &pool),
        Err(FrameError::FrameTooLarge)
    ));
    Ok(())
}

#[test]
fn extra_bytes_form_the_next_independent_frame() -> TestResult<()> {
    let mut bytes = encode_varint(3);
    bytes.extend_from_slice(b"abc");
    bytes.extend_from_slice(&encode_varint(1));
    bytes.push(b'z');
    let mut stream = MemoryStream::new(bytes);
    let shutdown = AtomicBool::new(false);
    let limits = framing_limits(1024)?;
    let pool = PermitPool::new(limits.reservation_per_handler());
    let first = read_frame(&mut stream, limits, deadlines()?, &shutdown, &pool)?.ok_or("first frame missing")?;
    assert_eq!(first.bytes, b"abc");
    drop(first);
    let second = read_frame(&mut stream, limits, deadlines()?, &shutdown, &pool)?.ok_or("second frame missing")?;
    assert_eq!(second.bytes, b"z");
    Ok(())
}

#[test]
fn remote_bind_and_unbounded_resource_profiles_are_unrepresentable() -> TestResult<()> {
    assert!(matches!(
        ProcessExitFatalServerHandler::new(0),
        Err(ServerError::InvalidConfig(_))
    ));
    assert!(ProcessExitFatalServerHandler::new(1).is_ok());
    assert!(matches!(
        ServerConfig::new(
            ServerEndpoint::Tcp(SocketAddr::from(([0, 0, 0, 0], 26658))),
            limits()?,
            deadlines()?
        ),
        Err(ServerError::InvalidConfig(_))
    ));
    assert!(matches!(
        ServerLimits::new(MAX_SERVER_FRAME_BYTES + 1, 1024, 1, MAX_SERVER_INFLIGHT_BYTES, 1),
        Err(ServerError::InvalidConfig(_))
    ));
    assert!(matches!(
        ServerLimits::new(1024, 1024, MAX_SERVER_CONNECTIONS + 1, MAX_SERVER_INFLIGHT_BYTES, 1),
        Err(ServerError::InvalidConfig(_))
    ));
    assert!(matches!(
        ServerLimits::new(1024, 1024, 1, 1024, 1),
        Err(ServerError::InvalidConfig(_))
    ));
    assert!(matches!(
        ServerLimits::new(
            1024,
            1024,
            1,
            MAX_SERVER_INFLIGHT_BYTES,
            MAX_SERVER_REQUEST_DECODE_ITEMS + 1
        ),
        Err(ServerError::InvalidConfig(_))
    ));
    let required = ServerLimits::required_per_handler_bytes(1024, 2048, 10).ok_or("required reservation overflowed")?;
    assert_eq!(
        required,
        1024 + 2048
            + 2048
            + 10 * SERVER_REQUEST_DECODE_ITEM_RESERVATION_BYTES
            + SERVER_REQUEST_FIXED_DECODE_RESERVATION_BYTES
    );
    assert!(ServerLimits::new(1024, 2048, 1, required, 10).is_ok());
    assert!(matches!(
        ServerLimits::new(1024, 2048, 1, required - 1, 10),
        Err(ServerError::InvalidConfig(_))
    ));
    assert!(matches!(
        ServerDeadlines::new(
            Duration::from_millis(1),
            Duration::from_secs(1),
            Duration::from_secs(1),
            Duration::from_secs(2),
            Duration::from_secs(1),
            Duration::from_secs(1),
            Duration::from_secs(1),
            Duration::from_secs(1),
            Duration::from_secs(1),
        ),
        Err(ServerError::InvalidConfig(_))
    ));
    Ok(())
}

#[test]
fn response_cap_failure_returns_no_encoded_payload() -> TestResult<()> {
    let frame = Request {
        value: Some(request::Value::Echo(RequestEcho {
            message: "larger than the cap".to_owned(),
        })),
    }
    .encode_to_vec();
    assert!(matches!(
        dispatch_frame(|| Ok(EchoApplication), frame, 1, MAX_SERVER_REQUEST_DECODE_ITEMS),
        Err(DispatchFailure::Server)
    ));
    Ok(())
}

fn prop_result<T, E: Error>(
    result: std::result::Result<T, E>,
) -> std::result::Result<T, proptest::test_runner::TestCaseError> {
    result.map_err(|error| proptest::test_runner::TestCaseError::fail(error.to_string()))
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(128))]

    #[test]
    fn arbitrary_header_bytes_never_panic(bytes in prop::collection::vec(any::<u8>(), 0..32)) {
        let mut stream = MemoryStream::new(bytes);
        let shutdown = AtomicBool::new(false);
        let limits = prop_result(framing_limits(1024))?;
        let deadlines = prop_result(deadlines())?;
        let pool = PermitPool::new(limits.reservation_per_handler());
        let _ = read_frame(&mut stream, limits, deadlines, &shutdown, &pool);
    }


    #[test]
    fn arbitrary_bounded_frames_never_panic(bytes in prop::collection::vec(any::<u8>(), 0..2048)) {
        let _ = dispatch_frame(
            || Ok(EchoApplication),
            bytes,
            4096,
            MAX_SERVER_REQUEST_DECODE_ITEMS,
        );
    }
}
