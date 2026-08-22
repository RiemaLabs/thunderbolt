use std::path::{Path, PathBuf};
use std::time::Duration;

use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::UnixStream;
use tokio::time::timeout;
use zeroize::Zeroizing;

use crate::codec::{decode_response, encode_request};
use crate::filesystem::{canonical_socket_path, current_uid, inspect_socket};
use crate::server::ControlServerConfig;
use crate::{
    ControlError, ControlRequest, ControlResponse, Result, ABSOLUTE_MAX_FRAME_BYTES, DEFAULT_MAX_FRAME_BYTES,
    MAX_CONTROL_IO_TIMEOUT, MAX_CONTROL_RESPONSE_TIMEOUT,
};

/// Local Unix-socket client used by `thunderbolt-cli` and operator tooling.
#[derive(Clone, Debug)]
pub struct ControlClient {
    socket_path: PathBuf,
    max_frame_bytes: usize,
    io_timeout: Duration,
    response_timeout: Duration,
}

impl ControlClient {
    /// Creates a client with the default 1 MiB frame and six-second deadline.
    pub fn new(socket_path: impl Into<PathBuf>) -> Self {
        Self {
            socket_path: socket_path.into(),
            max_frame_bytes: DEFAULT_MAX_FRAME_BYTES,
            io_timeout: Duration::from_secs(6),
            response_timeout: Duration::from_secs(6),
        }
    }

    /// Overrides the bounded frame and per-stage I/O deadline. The same value
    /// remains the response deadline for backward-compatible manual clients.
    pub fn with_limits(mut self, max_frame_bytes: usize, io_timeout: Duration) -> Result<Self> {
        validate_frame_and_timeout(max_frame_bytes, io_timeout, MAX_CONTROL_IO_TIMEOUT)?;
        self.max_frame_bytes = max_frame_bytes;
        self.io_timeout = io_timeout;
        self.response_timeout = io_timeout;
        Ok(self)
    }

    /// Overrides the bounded frame, connect/write I/O deadline, and separate
    /// absolute response deadline.
    pub fn with_deadlines(
        mut self,
        max_frame_bytes: usize,
        io_timeout: Duration,
        response_timeout: Duration,
    ) -> Result<Self> {
        validate_frame_and_timeout(max_frame_bytes, io_timeout, MAX_CONTROL_IO_TIMEOUT)?;
        validate_timeout(response_timeout, MAX_CONTROL_RESPONSE_TIMEOUT)?;
        self.max_frame_bytes = max_frame_bytes;
        self.io_timeout = io_timeout;
        self.response_timeout = response_timeout;
        Ok(self)
    }

    /// Constructs a client using one validated server's exact socket, frame
    /// bound, and checked handler-plus-I/O deadline.
    pub fn from_server_config(config: &ControlServerConfig) -> Result<Self> {
        let deadline = config
            .handler_timeout
            .checked_add(config.io_timeout)
            .ok_or(ControlError::InvalidConfiguration("client deadline overflows"))?;
        config.validate()?;
        Self::new(config.socket_path.clone()).with_deadlines(config.max_frame_bytes, config.io_timeout, deadline)
    }

    /// Returns the configured local socket path.
    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    /// Returns the complete frame bound.
    pub const fn max_frame_bytes(&self) -> usize {
        self.max_frame_bytes
    }

    /// Returns the connect and write I/O deadline.
    pub const fn io_timeout(&self) -> Duration {
        self.io_timeout
    }

    /// Returns the absolute response prefix-plus-body deadline.
    pub const fn response_timeout(&self) -> Duration {
        self.response_timeout
    }

    /// Sends one request over one owner-authenticated local connection.
    pub async fn call(&self, request: &ControlRequest) -> Result<ControlResponse> {
        let socket_path = canonical_socket_path(&self.socket_path)?;
        inspect_socket(&socket_path)?.ok_or_else(|| ControlError::UnsafePath {
            path: socket_path.clone(),
            reason: "control socket does not exist",
        })?;
        let mut stream = timeout(self.io_timeout, UnixStream::connect(&socket_path))
            .await
            .map_err(|_| ControlError::Timeout)?
            .map_err(|source| ControlError::io("connect", source))?;
        let credentials = stream
            .peer_cred()
            .map_err(|source| ControlError::io("read server credentials", source))?;
        if credentials.uid() != current_uid() {
            return Err(ControlError::UnauthorizedPeer);
        }
        let frame = encode_request(request, self.max_frame_bytes)?;
        if write_frame(&mut stream, &frame, self.io_timeout).await.is_err() {
            return Err(ControlError::Ambiguous(request.request_id()));
        }
        drop(frame);
        let response_frame = read_response_frame(&mut stream, self.max_frame_bytes, self.response_timeout)
            .await
            .map_err(|_| ControlError::Ambiguous(request.request_id()))?;
        let response = decode_response(&response_frame, self.max_frame_bytes)
            .map_err(|_| ControlError::Ambiguous(request.request_id()))?;
        drop(response_frame);
        if response.request_id() != request.request_id() {
            return Err(ControlError::ResponseMismatch);
        }
        Ok(response)
    }
}

pub(crate) async fn write_frame(stream: &mut UnixStream, frame: &[u8], deadline: Duration) -> Result<()> {
    let length = u32::try_from(frame.len()).map_err(|_| ControlError::InvalidFrame("frame length does not fit u32"))?;
    timeout(deadline, async {
        stream.write_all(&length.to_be_bytes()).await?;
        stream.write_all(frame).await?;
        stream.flush().await
    })
    .await
    .map_err(|_| ControlError::Timeout)?
    .map_err(|source| ControlError::io("write frame", source))
}

pub(crate) async fn read_frame(
    stream: &mut UnixStream,
    max_frame_bytes: usize,
    deadline: Duration,
) -> Result<Zeroizing<Vec<u8>>> {
    let mut prefix = [0_u8; 4];
    timeout(deadline, stream.read_exact(&mut prefix))
        .await
        .map_err(|_| ControlError::Timeout)?
        .map_err(|source| ControlError::io("read frame length", source))?;
    let length = decode_frame_length(prefix, max_frame_bytes)?;
    let mut frame = Zeroizing::new(vec![0_u8; length]);
    timeout(deadline, stream.read_exact(&mut frame))
        .await
        .map_err(|_| ControlError::Timeout)?
        .map_err(|source| ControlError::io("read frame", source))?;
    Ok(frame)
}

async fn read_response_frame(
    stream: &mut UnixStream,
    max_frame_bytes: usize,
    deadline: Duration,
) -> Result<Zeroizing<Vec<u8>>> {
    timeout(deadline, read_frame_inner(stream, max_frame_bytes))
        .await
        .map_err(|_| ControlError::Timeout)?
}

async fn read_frame_inner(stream: &mut UnixStream, max_frame_bytes: usize) -> Result<Zeroizing<Vec<u8>>> {
    let mut prefix = [0_u8; 4];
    stream
        .read_exact(&mut prefix)
        .await
        .map_err(|source| ControlError::io("read frame length", source))?;
    let length = decode_frame_length(prefix, max_frame_bytes)?;
    let mut frame = Zeroizing::new(vec![0_u8; length]);
    stream
        .read_exact(&mut frame)
        .await
        .map_err(|source| ControlError::io("read frame", source))?;
    Ok(frame)
}

fn decode_frame_length(prefix: [u8; 4], max_frame_bytes: usize) -> Result<usize> {
    let length = usize::try_from(u32::from_be_bytes(prefix))
        .map_err(|_| ControlError::InvalidFrame("frame length does not fit this platform"))?;
    if length == 0 || length > max_frame_bytes {
        return Err(ControlError::InvalidFrame(
            "frame length is outside the configured bound",
        ));
    }
    Ok(length)
}

fn validate_frame_and_timeout(max_frame_bytes: usize, timeout: Duration, maximum_timeout: Duration) -> Result<()> {
    if !(64..=ABSOLUTE_MAX_FRAME_BYTES).contains(&max_frame_bytes) {
        return Err(ControlError::InvalidConfiguration(
            "max frame bytes is outside the supported bound",
        ));
    }
    validate_timeout(timeout, maximum_timeout)
}

fn validate_timeout(timeout: Duration, maximum_timeout: Duration) -> Result<()> {
    if timeout.is_zero() || timeout > maximum_timeout {
        return Err(ControlError::InvalidConfiguration(
            "timeout is outside the supported bound",
        ));
    }
    Ok(())
}

pub(crate) fn validate_server_io_limits(max_frame_bytes: usize, io_timeout: Duration) -> Result<()> {
    validate_frame_and_timeout(max_frame_bytes, io_timeout, MAX_CONTROL_IO_TIMEOUT)
}
