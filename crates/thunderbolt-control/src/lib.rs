//! Owner-only local control plane for Bitcoin Thunderbolt daemons.
//!
//! The network protocol remains separate from this local operator plane. A
//! CLI connects to a daemon through a mode-0600 Unix-domain socket inside an
//! owner-only directory. The server additionally checks the kernel-reported
//! peer UID before decoding a bounded request.

#![deny(missing_docs)]
#![deny(
    clippy::expect_used,
    clippy::panic,
    clippy::todo,
    clippy::unimplemented,
    clippy::unwrap_used
)]
#![forbid(unsafe_code)]

#[cfg(not(unix))]
compile_error!("thunderbolt-control requires Unix-domain sockets");

mod client;
mod codec;
mod error;
mod filesystem;
mod server;
mod types;

pub use client::ControlClient;
pub use error::{ControlError, Result};
pub use server::{ControlHandler, ControlHandlerFuture, ControlServer, ControlServerConfig};
pub use types::{
    ControlPayload, ControlRequest, ControlResponse, ControlStatus, RequestId, ABSOLUTE_MAX_FRAME_BYTES,
    CONTROL_PROTOCOL_VERSION, DEFAULT_MAX_FRAME_BYTES, MAX_CONTROL_HANDLER_TIMEOUT, MAX_CONTROL_IO_TIMEOUT,
    MAX_CONTROL_RESPONSE_TIMEOUT, MAX_ERROR_MESSAGE_BYTES, MAX_METHOD_BYTES,
};

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
mod tests;
