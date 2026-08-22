use std::net::IpAddr;
use std::time::Duration;

use bitcoin::Network;
use url::{Host, Url};

use crate::{BitcoinError, Result};

/// Default per-attempt request deadline.
pub const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(15);
/// Default TCP connection deadline.
pub const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// Default maximum serialized JSON-RPC request size.
pub const DEFAULT_MAX_REQUEST_BYTES: usize = 4 * 1024 * 1024;
/// Default maximum serialized JSON-RPC response size.
pub const DEFAULT_MAX_RESPONSE_BYTES: usize = 4 * 1024 * 1024;
/// Default number of attempts for idempotent reads.
pub const DEFAULT_READ_ATTEMPTS: u8 = 3;
/// Default maximum number of blocks fetched in one cursor update.
pub const DEFAULT_MAX_CHAIN_SYNC_BLOCKS: u32 = 2_016;
/// Absolute request/response allocation ceiling.
pub const HARD_MAX_BODY_BYTES: usize = 16 * 1024 * 1024;
/// Absolute cursor work ceiling for a single synchronization call.
pub const HARD_MAX_CHAIN_SYNC_BLOCKS: u32 = 10_000;

const MAX_REQUEST_TIMEOUT: Duration = Duration::from_secs(60);
const MAX_CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_READ_ATTEMPTS: u8 = 5;
const DEFAULT_RETRY_DELAY: Duration = Duration::from_millis(100);
const MAX_RETRY_DELAY: Duration = Duration::from_secs(2);

/// Hardened Bitcoin Core JSON-RPC configuration.
#[derive(Clone, Debug)]
pub struct RpcConfig {
    endpoint: Url,
    network: Network,
    request_timeout: Duration,
    connect_timeout: Duration,
    retry_delay: Duration,
    max_request_bytes: usize,
    max_response_bytes: usize,
    read_attempts: u8,
    max_chain_sync_blocks: u32,
}

impl RpcConfig {
    /// Creates a configuration with production-safe bounds.
    ///
    /// Plain HTTP endpoints must use a literal loopback IP address. Mainnet and
    /// testnet4 are rejected by this release candidate.
    pub fn new(endpoint: Url, network: Network) -> Result<Self> {
        validate_endpoint(&endpoint)?;
        validate_network(network)?;

        Ok(Self {
            endpoint,
            network,
            request_timeout: DEFAULT_REQUEST_TIMEOUT,
            connect_timeout: DEFAULT_CONNECT_TIMEOUT,
            retry_delay: DEFAULT_RETRY_DELAY,
            max_request_bytes: DEFAULT_MAX_REQUEST_BYTES,
            max_response_bytes: DEFAULT_MAX_RESPONSE_BYTES,
            read_attempts: DEFAULT_READ_ATTEMPTS,
            max_chain_sync_blocks: DEFAULT_MAX_CHAIN_SYNC_BLOCKS,
        })
    }

    /// Sets request and connection deadlines.
    pub fn with_timeouts(mut self, request: Duration, connect: Duration) -> Result<Self> {
        if request.is_zero() || request > MAX_REQUEST_TIMEOUT {
            return Err(BitcoinError::InvalidConfig(
                "request timeout must be between 1ns and 60s",
            ));
        }
        if connect.is_zero() || connect > MAX_CONNECT_TIMEOUT || connect > request {
            return Err(BitcoinError::InvalidConfig(
                "connect timeout must be nonzero, at most 30s, and no longer than request timeout",
            ));
        }
        self.request_timeout = request;
        self.connect_timeout = connect;
        Ok(self)
    }

    /// Sets hard per-message request and response limits.
    pub fn with_body_limits(mut self, request: usize, response: usize) -> Result<Self> {
        if request == 0 || request > HARD_MAX_BODY_BYTES {
            return Err(BitcoinError::InvalidConfig(
                "request body limit is outside the hard bound",
            ));
        }
        if response == 0 || response > HARD_MAX_BODY_BYTES {
            return Err(BitcoinError::InvalidConfig(
                "response body limit is outside the hard bound",
            ));
        }
        self.max_request_bytes = request;
        self.max_response_bytes = response;
        Ok(self)
    }

    /// Sets the number of attempts and delay for idempotent reads.
    pub fn with_read_retry(mut self, attempts: u8, delay: Duration) -> Result<Self> {
        if attempts == 0 || attempts > MAX_READ_ATTEMPTS {
            return Err(BitcoinError::InvalidConfig("read attempts must be between 1 and 5"));
        }
        if delay > MAX_RETRY_DELAY {
            return Err(BitcoinError::InvalidConfig("retry delay must be at most 2s"));
        }
        self.read_attempts = attempts;
        self.retry_delay = delay;
        Ok(self)
    }

    /// Sets the maximum number of new canonical blocks accepted per cursor update.
    pub fn with_max_chain_sync_blocks(mut self, blocks: u32) -> Result<Self> {
        if blocks == 0 || blocks > HARD_MAX_CHAIN_SYNC_BLOCKS {
            return Err(BitcoinError::InvalidConfig(
                "chain synchronization bound is outside the hard limit",
            ));
        }
        self.max_chain_sync_blocks = blocks;
        Ok(self)
    }

    /// RPC endpoint URL.
    #[must_use]
    pub fn endpoint(&self) -> &Url {
        &self.endpoint
    }

    /// Selected Bitcoin network.
    #[must_use]
    pub const fn network(&self) -> Network {
        self.network
    }

    /// Per-attempt request deadline.
    #[must_use]
    pub const fn request_timeout(&self) -> Duration {
        self.request_timeout
    }

    /// Connection deadline.
    #[must_use]
    pub const fn connect_timeout(&self) -> Duration {
        self.connect_timeout
    }

    /// Retry delay for idempotent reads.
    #[must_use]
    pub const fn retry_delay(&self) -> Duration {
        self.retry_delay
    }

    /// Request body limit.
    #[must_use]
    pub const fn max_request_bytes(&self) -> usize {
        self.max_request_bytes
    }

    /// Response body limit.
    #[must_use]
    pub const fn max_response_bytes(&self) -> usize {
        self.max_response_bytes
    }

    /// Attempts for idempotent reads.
    #[must_use]
    pub const fn read_attempts(&self) -> u8 {
        self.read_attempts
    }

    /// Per-call chain cursor block bound.
    #[must_use]
    pub const fn max_chain_sync_blocks(&self) -> u32 {
        self.max_chain_sync_blocks
    }
}

fn validate_network(network: Network) -> Result<()> {
    match network {
        Network::Bitcoin => Err(BitcoinError::MainnetDisabled),
        Network::Testnet4 => Err(BitcoinError::UnsupportedNetwork(network)),
        Network::Testnet | Network::Signet | Network::Regtest => Ok(()),
    }
}

fn validate_endpoint(endpoint: &Url) -> Result<()> {
    if !endpoint.username().is_empty() || endpoint.password().is_some() {
        return Err(BitcoinError::InvalidEndpoint("embedded credentials are forbidden"));
    }
    if endpoint.query().is_some() || endpoint.fragment().is_some() {
        return Err(BitcoinError::InvalidEndpoint(
            "query strings and fragments are forbidden",
        ));
    }
    if endpoint.host().is_none() {
        return Err(BitcoinError::InvalidEndpoint("host is required"));
    }

    match endpoint.scheme() {
        "https" => Ok(()),
        "http" => match endpoint.host() {
            Some(Host::Ipv4(address)) if IpAddr::V4(address).is_loopback() => Ok(()),
            Some(Host::Ipv6(address)) if IpAddr::V6(address).is_loopback() => Ok(()),
            _ => Err(BitcoinError::InvalidEndpoint(
                "plain HTTP requires a literal loopback IP address",
            )),
        },
        _ => Err(BitcoinError::InvalidEndpoint(
            "only http and https schemes are supported",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_mainnet_and_remote_http() -> Result<()> {
        let loopback = Url::parse("http://127.0.0.1:18443/").map_err(|_| BitcoinError::InvalidEndpoint("test URL"))?;
        assert!(matches!(
            RpcConfig::new(loopback, Network::Bitcoin),
            Err(BitcoinError::MainnetDisabled)
        ));

        let remote = Url::parse("http://192.0.2.1:8332/").map_err(|_| BitcoinError::InvalidEndpoint("test URL"))?;
        assert!(matches!(
            RpcConfig::new(remote, Network::Signet),
            Err(BitcoinError::InvalidEndpoint(_))
        ));
        Ok(())
    }

    #[test]
    fn accepts_loopback_http_and_remote_https() -> Result<()> {
        let loopback = Url::parse("http://[::1]:18443/").map_err(|_| BitcoinError::InvalidEndpoint("test URL"))?;
        RpcConfig::new(loopback, Network::Regtest)?;

        let remote =
            Url::parse("https://rpc.example.invalid/").map_err(|_| BitcoinError::InvalidEndpoint("test URL"))?;
        RpcConfig::new(remote, Network::Signet)?;
        Ok(())
    }
}
