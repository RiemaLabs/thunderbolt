//! Production-bounded local ABCI 2.0 server shared by Thunderbolt applications.
//!
//! The server accepts loopback TCP and, on Unix, owner-only Unix sockets. It
//! deliberately provides no TLS or remote bind mode. Every transport-managed
//! resource and I/O phase is bounded before work begins.
//!
//! A synchronous [`tendermint_abci::Application`] callback cannot be safely
//! cancelled. Callback panic/timeout and lifecycle invariant failures invoke
//! [`FatalServerHandler::terminate`], which must end the complete production
//! process or hosting session. No clean fatal return path is exposed.

#![deny(missing_docs)]
#![deny(
    clippy::expect_used,
    clippy::panic,
    clippy::todo,
    clippy::unimplemented,
    clippy::unwrap_used
)]
#![forbid(unsafe_code)]

mod config;
mod dispatch;
mod error;
mod fatal;
mod framing;
mod preflight;
mod semaphore;
mod server;

#[cfg(test)]
mod tests;

pub use config::{
    ServerConfig, ServerDeadlines, ServerEndpoint, ServerLimits, MAX_SERVER_CONNECTIONS, MAX_SERVER_DEADLINE,
    MAX_SERVER_FRAME_BYTES, MAX_SERVER_INFLIGHT_BYTES, MAX_SERVER_REQUEST_DECODE_ITEMS,
    SERVER_REQUEST_DECODE_ITEM_RESERVATION_BYTES, SERVER_REQUEST_FIXED_DECODE_RESERVATION_BYTES,
};
pub use error::{FrameError, Result, ServerError};
pub use fatal::{FatalServerEvent, FatalServerHandler, FatalServerKind, ProcessExitFatalServerHandler};
pub use server::{start, BoundEndpoint, RunningServer, ShutdownHandle};

/// ABCI protocol version implemented by this server.
pub const ABCI_PROTOCOL_VERSION: &str = "2.0";
