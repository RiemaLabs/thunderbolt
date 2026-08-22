use std::path::{Path, PathBuf};
use std::time::Duration;

use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::UnixStream;
use tokio::time::timeout;
use zeroize::Zeroizing;

use crate::codec::{decode_response, encode_request};
use crate::filesystem::{canonical_socket_path, current_uid, inspect_socket};
use crate::{ControlError, ControlRequest, ControlResponse, Result, ABSOLUTE_MAX_FRAME_BYTES, DEFAULT_MAX_FRAME_BYTES};

/// Local Unix-socket client used by `thunderbolt-cli` and operator tooling.
#[derive(Clone, Debug)]
pub struct ControlClient {
    socket_path: PathBuf,
    max_frame_bytes: usize,
    io_timeout: Duration,
}

impl ControlClient {
    /// Creates a client with the default 1 MiB frame and six-second deadline.
    pub fn new(socket_path: impl Into<PathBuf>) -> Self {
        Self {
            socket_path: socket_path.into(),
            max_frame_bytes: DEFAULT_MAX_FRAME_BYTES,
            io_timeout: Duration::from_secs(6),
        }
    }

    /// Overrides bounded frame and I/O deadline settings.
    pub fn with_limits(mut self, max_frame_bytes: usize, io_timeout: Duration) -> Result<Self> {
        validate_limits(max_frame_bytes, io_timeout)?;
        self.max_frame_bytes = max_frame_bytes;
        self.io_timeout = io_timeout;
        Ok(self)
    }

    /// Returns the configured local socket path.
    pub fn socket_path(&self) -> &Path {
        &self.socket_path
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
        let response_frame = read_frame(&mut stream, self.max_frame_bytes, self.io_timeout)
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
    let length = usize::try_from(u32::from_be_bytes(prefix))
        .map_err(|_| ControlError::InvalidFrame("frame length does not fit this platform"))?;
    if length == 0 || length > max_frame_bytes {
        return Err(ControlError::InvalidFrame(
            "frame length is outside the configured bound",
        ));
    }
    let mut frame = Zeroizing::new(vec![0_u8; length]);
    timeout(deadline, stream.read_exact(&mut frame))
        .await
        .map_err(|_| ControlError::Timeout)?
        .map_err(|source| ControlError::io("read frame", source))?;
    Ok(frame)
}

fn validate_limits(max_frame_bytes: usize, io_timeout: Duration) -> Result<()> {
    if !(64..=ABSOLUTE_MAX_FRAME_BYTES).contains(&max_frame_bytes) {
        return Err(ControlError::InvalidConfiguration(
            "max frame bytes is outside the supported bound",
        ));
    }
    if io_timeout.is_zero() || io_timeout > Duration::from_secs(60) {
        return Err(ControlError::InvalidConfiguration(
            "I/O timeout is outside the supported bound",
        ));
    }
    Ok(())
}

pub(crate) fn validate_client_limits(max_frame_bytes: usize, io_timeout: Duration) -> Result<()> {
    validate_limits(max_frame_bytes, io_timeout)
}
