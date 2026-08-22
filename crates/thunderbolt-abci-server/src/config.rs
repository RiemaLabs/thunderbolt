use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use crate::{Result, ServerError};

/// Absolute request/response frame cap accepted by this implementation.
pub const MAX_SERVER_FRAME_BYTES: usize = 64 * 1024 * 1024;
/// Absolute global in-flight reservation cap.
pub const MAX_SERVER_INFLIGHT_BYTES: usize = 1024 * 1024 * 1024;
/// Absolute accepted-connection cap, including idle local peers.
pub const MAX_SERVER_CONNECTIONS: usize = 64;
/// Absolute count of allocation-producing repeated values in one v0.38 request.
pub const MAX_SERVER_REQUEST_DECODE_ITEMS: usize = 8_192;
/// Conservative Vec element/capacity/allocator reservation per decoded item.
pub const SERVER_REQUEST_DECODE_ITEM_RESERVATION_BYTES: usize = 1_024;
/// Fixed decoded request and allocator metadata reservation.
pub const SERVER_REQUEST_FIXED_DECODE_RESERVATION_BYTES: usize = 4 * 1_024;
/// Absolute deadline cap preventing configuration from disabling cancellation.
pub const MAX_SERVER_DEADLINE: Duration = Duration::from_secs(300);

/// Local listener endpoint; remote TCP and TLS are intentionally unavailable.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ServerEndpoint {
    /// Numeric loopback-only TCP socket.
    Tcp(SocketAddr),
    /// Owner-only local Unix-domain socket.
    #[cfg(unix)]
    Unix(PathBuf),
}

/// Hard connection, frame, and transport reservation limits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ServerLimits {
    request_frame_bytes: usize,
    response_frame_bytes: usize,
    max_connections: usize,
    max_inflight_bytes: usize,
    max_request_decode_items: usize,
    reservation_per_handler: usize,
}

impl ServerLimits {
    /// Validates frame, connection, and global in-flight limits.
    pub fn new(
        request_frame_bytes: usize,
        response_frame_bytes: usize,
        max_connections: usize,
        max_inflight_bytes: usize,
        max_request_decode_items: usize,
    ) -> Result<Self> {
        if request_frame_bytes == 0
            || response_frame_bytes == 0
            || max_connections == 0
            || max_request_decode_items == 0
        {
            return Err(ServerError::InvalidConfig(
                "frame, connection, and decode-item limits must be positive",
            ));
        }
        if request_frame_bytes > MAX_SERVER_FRAME_BYTES || response_frame_bytes > MAX_SERVER_FRAME_BYTES {
            return Err(ServerError::InvalidConfig(
                "frame limit exceeds hard implementation cap",
            ));
        }
        if max_inflight_bytes > MAX_SERVER_INFLIGHT_BYTES {
            return Err(ServerError::InvalidConfig(
                "global in-flight bytes exceed hard implementation cap",
            ));
        }
        if max_connections > MAX_SERVER_CONNECTIONS {
            return Err(ServerError::InvalidConfig("connection limit exceeds hard bound"));
        }
        if max_request_decode_items > MAX_SERVER_REQUEST_DECODE_ITEMS {
            return Err(ServerError::InvalidConfig(
                "request decode-item limit exceeds hard bound",
            ));
        }
        let reservation_per_handler =
            Self::required_per_handler_bytes(request_frame_bytes, response_frame_bytes, max_request_decode_items)
                .ok_or(ServerError::InvalidConfig("per-handler reservation overflows"))?;
        if max_inflight_bytes < reservation_per_handler {
            return Err(ServerError::InvalidConfig(
                "global in-flight bytes cannot admit one maximum handler",
            ));
        }
        Ok(Self {
            request_frame_bytes,
            response_frame_bytes,
            max_connections,
            max_inflight_bytes,
            max_request_decode_items,
            reservation_per_handler,
        })
    }

    /// Returns the request payload cap checked before allocation.
    pub const fn request_frame_bytes(self) -> usize {
        self.request_frame_bytes
    }
    /// Returns the encoded response payload cap.
    pub const fn response_frame_bytes(self) -> usize {
        self.response_frame_bytes
    }
    /// Returns the simultaneous accepted-connection cap.
    pub const fn max_connections(self) -> usize {
        self.max_connections
    }
    /// Returns the global handler reservation byte budget.
    ///
    /// This is admission accounting, not a measurement of application-owned
    /// allocations inside an ABCI callback.
    pub const fn max_inflight_bytes(self) -> usize {
        self.max_inflight_bytes
    }
    /// Returns the schema-aware repeated-value cap checked before prost decode.
    ///
    /// Consensus replicas must derive the same value from their committed
    /// application resource profile.
    pub const fn max_request_decode_items(self) -> usize {
        self.max_request_decode_items
    }
    /// Returns the conservative reservation held by every handler.
    pub const fn reservation_per_handler(self) -> usize {
        self.reservation_per_handler
    }

    /// Computes the minimum admission reservation for one maximum request.
    #[must_use]
    pub const fn required_per_handler_bytes(
        request_frame_bytes: usize,
        response_frame_bytes: usize,
        max_request_decode_items: usize,
    ) -> Option<usize> {
        let decoded_payload = if request_frame_bytes > response_frame_bytes {
            request_frame_bytes
        } else {
            response_frame_bytes
        };
        let decoded_items = match max_request_decode_items.checked_mul(SERVER_REQUEST_DECODE_ITEM_RESERVATION_BYTES) {
            Some(value) => value,
            None => return None,
        };
        match request_frame_bytes.checked_add(response_frame_bytes) {
            Some(value) => match value.checked_add(decoded_payload) {
                Some(value) => match value.checked_add(decoded_items) {
                    Some(value) => value.checked_add(SERVER_REQUEST_FIXED_DECODE_RESERVATION_BYTES),
                    None => None,
                },
                None => None,
            },
            None => None,
        }
    }
}

/// Absolute and per-operation socket/handler deadlines.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ServerDeadlines {
    accept_poll: Duration,
    idle: Duration,
    header: Duration,
    read: Duration,
    frame: Duration,
    write: Duration,
    handler: Duration,
    shutdown_grace: Duration,
}

impl ServerDeadlines {
    /// Validates positive deadlines and a shutdown grace covering one handler deadline.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        accept_poll: Duration,
        idle: Duration,
        header: Duration,
        read: Duration,
        frame: Duration,
        write: Duration,
        handler: Duration,
        shutdown_grace: Duration,
    ) -> Result<Self> {
        if [accept_poll, idle, header, read, frame, write, handler, shutdown_grace]
            .into_iter()
            .any(|duration| duration.is_zero())
        {
            return Err(ServerError::InvalidConfig("all server deadlines must be positive"));
        }
        if [accept_poll, idle, header, read, frame, write, handler, shutdown_grace]
            .into_iter()
            .any(|duration| duration > MAX_SERVER_DEADLINE)
        {
            return Err(ServerError::InvalidConfig(
                "server deadline exceeds hard implementation cap",
            ));
        }
        if accept_poll > idle || read > frame || shutdown_grace < handler {
            return Err(ServerError::InvalidConfig(
                "server deadlines are internally inconsistent",
            ));
        }
        Ok(Self {
            accept_poll,
            idle,
            header,
            read,
            frame,
            write,
            handler,
            shutdown_grace,
        })
    }

    /// Returns the nonblocking listener poll interval.
    pub const fn accept_poll(self) -> Duration {
        self.accept_poll
    }
    /// Returns the between-frame idle deadline.
    pub const fn idle(self) -> Duration {
        self.idle
    }
    /// Returns the partial length-header deadline.
    pub const fn header(self) -> Duration {
        self.header
    }
    /// Returns the maximum duration of one read syscall.
    pub const fn read(self) -> Duration {
        self.read
    }
    /// Returns the absolute payload frame deadline.
    pub const fn frame(self) -> Duration {
        self.frame
    }
    /// Returns the absolute response write deadline.
    pub const fn write(self) -> Duration {
        self.write
    }
    /// Returns the application callback deadline.
    pub const fn handler(self) -> Duration {
        self.handler
    }
    /// Returns the normal worker-drain grace period.
    pub const fn shutdown_grace(self) -> Duration {
        self.shutdown_grace
    }
}

/// Complete immutable server configuration.
#[derive(Clone, Debug)]
pub struct ServerConfig {
    endpoint: ServerEndpoint,
    limits: ServerLimits,
    deadlines: ServerDeadlines,
}

impl ServerConfig {
    /// Constructs a local bounded server configuration.
    pub fn new(endpoint: ServerEndpoint, limits: ServerLimits, deadlines: ServerDeadlines) -> Result<Self> {
        if matches!(&endpoint, ServerEndpoint::Tcp(address) if !address.ip().is_loopback()) {
            return Err(ServerError::InvalidConfig("TCP endpoint must be numeric loopback"));
        }
        #[cfg(unix)]
        if matches!(&endpoint, ServerEndpoint::Unix(path) if !path.is_absolute()) {
            return Err(ServerError::InvalidConfig("Unix socket path must be absolute"));
        }
        Ok(Self {
            endpoint,
            limits,
            deadlines,
        })
    }

    /// Returns the configured endpoint.
    pub const fn endpoint(&self) -> &ServerEndpoint {
        &self.endpoint
    }
    /// Returns hard resource limits.
    pub const fn limits(&self) -> ServerLimits {
        self.limits
    }
    /// Returns socket and handler deadlines.
    pub const fn deadlines(&self) -> ServerDeadlines {
        self.deadlines
    }
}
