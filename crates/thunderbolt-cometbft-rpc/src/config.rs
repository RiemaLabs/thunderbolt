use core::num::{NonZeroU16, NonZeroU8};
use core::time::Duration;
use std::collections::BTreeSet;
use std::fmt;
#[cfg(any(test, feature = "regtest"))]
use std::net::IpAddr;
use std::sync::Arc;

use rustls::client::ResolvesClientCert;
use rustls::pki_types::CertificateDer;
use sha2::{Digest as _, Sha256};
use tendermint::node::Id as NodeId;
use thunderbolt_cometbft::{MAX_ADJACENT_HEADERS, MAX_VALIDATORS, MAX_WITNESSES};
use thunderbolt_cometbft_client::PeerIdentity;
use url::{Host, Url};

use crate::{ClientIdentityProvider, Result, RpcTransportError};

const TRANSPORT_PROFILE_DOMAIN: &[u8] = b"bitcoin-thunderbolt/cometbft-rpc/transport-profile/v1";

/// Maximum adjacent headers fetched through one RPC session. Larger trust gaps
/// must be advanced in multiple coordinator updates.
pub const MAX_RPC_ADJACENT_HEADERS: usize = 256;

/// Maximum raw bytes accepted for one trace-fetch JSON-RPC response.
pub const MAX_RPC_RESPONSE_BYTES: usize = 8 * 1024 * 1024;
/// Maximum aggregate raw JSON-RPC bytes accepted for one fetched trace.
pub const MAX_RPC_AGGREGATE_BYTES: usize = 64 * 1024 * 1024;
/// Maximum raw JSON-RPC response for one fixed Ledger ABCI query.
pub const MAX_LEDGER_RPC_RESPONSE_BYTES: usize = 33 * 1024 * 1024;
/// Maximum status-plus-operation raw bytes for one fixed Ledger attempt.
pub const MAX_LEDGER_RPC_AGGREGATE_BYTES: usize = 34 * 1024 * 1024;
/// Maximum authenticated CometBFT status response used before a Ledger operation.
pub const MAX_LEDGER_STATUS_RESPONSE_BYTES: usize = 64 * 1024;
/// Maximum accepted HTTP response headers.
pub const MAX_HTTP_HEADERS: usize = 64;
/// Maximum HTTP/1 read buffer used for response headers.
pub const MAX_HTTP_HEADER_BYTES: usize = 64 * 1024;

const _: () =
    assert!(MAX_LEDGER_RPC_RESPONSE_BYTES + MAX_LEDGER_STATUS_RESPONSE_BYTES <= MAX_LEDGER_RPC_AGGREGATE_BYTES);

/// Mechanically derived identity of the complete authenticated RPC policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RpcTransportProfileId([u8; 32]);

impl RpcTransportProfileId {
    /// Returns the exact transport-policy digest.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Immutable retry policy for idempotent CometBFT JSON-RPC reads.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RetryPolicy {
    attempts: NonZeroU8,
    base_delay: Duration,
}

impl RetryPolicy {
    /// Constructs a one-to-five attempt bounded exponential policy.
    pub fn new(attempts: NonZeroU8, base_delay: Duration) -> Result<Self> {
        if attempts.get() > 5 || base_delay < Duration::from_millis(1) || base_delay > Duration::from_secs(1) {
            return Err(RpcTransportError::InvalidConfiguration(
                "retry attempts or base delay are outside bounds",
            ));
        }
        Ok(Self { attempts, base_delay })
    }

    /// Returns the total number of permitted idempotent attempts.
    pub const fn attempts(&self) -> NonZeroU8 {
        self.attempts
    }

    /// Returns the initial retry delay.
    pub const fn base_delay(&self) -> Duration {
        self.base_delay
    }

    pub(crate) const fn single_attempt() -> Self {
        Self {
            attempts: NonZeroU8::MIN,
            base_delay: Duration::from_millis(1),
        }
    }
}

/// Compositional network and RPC decoding limits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RpcLimits {
    response_bytes: usize,
    aggregate_bytes: usize,
    max_adjacent_headers: usize,
    max_validators: usize,
    validator_page_size: NonZeroU8,
    max_headers: usize,
    max_header_bytes: usize,
}

/// Independent raw-body limits for fixed Ledger status, query, and broadcast operations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LedgerRpcLimits {
    response_bytes: usize,
    aggregate_bytes: usize,
}

impl LedgerRpcLimits {
    /// Constructs bounded Ledger RPC body limits.
    pub fn new(response_bytes: usize, aggregate_bytes: usize) -> Result<Self> {
        let minimum_aggregate = response_bytes
            .checked_add(response_bytes.min(MAX_LEDGER_STATUS_RESPONSE_BYTES))
            .ok_or(RpcTransportError::InvalidConfiguration(
                "Ledger RPC aggregate limit overflows",
            ))?;
        if !(1_024..=MAX_LEDGER_RPC_RESPONSE_BYTES).contains(&response_bytes)
            || aggregate_bytes < minimum_aggregate
            || aggregate_bytes > MAX_LEDGER_RPC_AGGREGATE_BYTES
        {
            return Err(RpcTransportError::InvalidConfiguration(
                "Ledger RPC body limit is outside bounds",
            ));
        }
        Ok(Self {
            response_bytes,
            aggregate_bytes,
        })
    }

    /// Returns the per-response raw JSON cap.
    pub const fn response_bytes(self) -> usize {
        self.response_bytes
    }

    /// Returns the status-plus-operation aggregate raw JSON cap.
    pub const fn aggregate_bytes(self) -> usize {
        self.aggregate_bytes
    }

    fn inherited(limits: RpcLimits) -> Self {
        Self {
            response_bytes: limits.response_bytes.min(MAX_LEDGER_RPC_RESPONSE_BYTES),
            aggregate_bytes: limits.aggregate_bytes.min(MAX_LEDGER_RPC_AGGREGATE_BYTES),
        }
    }
}

impl RpcLimits {
    /// Constructs bounded RPC limits.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        response_bytes: usize,
        aggregate_bytes: usize,
        max_adjacent_headers: usize,
        max_validators: usize,
        validator_page_size: NonZeroU8,
        max_headers: usize,
        max_header_bytes: usize,
    ) -> Result<Self> {
        if !(1_024..=MAX_RPC_RESPONSE_BYTES).contains(&response_bytes)
            || aggregate_bytes < response_bytes
            || aggregate_bytes > MAX_RPC_AGGREGATE_BYTES
            || !(1..=MAX_ADJACENT_HEADERS.min(MAX_RPC_ADJACENT_HEADERS)).contains(&max_adjacent_headers)
            || !(1..=MAX_VALIDATORS).contains(&max_validators)
            || usize::from(validator_page_size.get()) > 100
            || !(8..=MAX_HTTP_HEADERS).contains(&max_headers)
            || !(8 * 1024..=MAX_HTTP_HEADER_BYTES).contains(&max_header_bytes)
        {
            return Err(RpcTransportError::InvalidConfiguration(
                "RPC resource limit is outside bounds",
            ));
        }
        let minimum_aggregate = response_bytes
            .checked_mul(3)
            .ok_or(RpcTransportError::InvalidConfiguration(
                "aggregate response budget overflows",
            ))?;
        if aggregate_bytes < minimum_aggregate {
            return Err(RpcTransportError::InvalidConfiguration(
                "aggregate budget cannot contain status, commit, and validators",
            ));
        }
        Ok(Self {
            response_bytes,
            aggregate_bytes,
            max_adjacent_headers,
            max_validators,
            validator_page_size,
            max_headers,
            max_header_bytes,
        })
    }

    /// Returns the per-response raw byte cap.
    pub const fn response_bytes(&self) -> usize {
        self.response_bytes
    }

    /// Returns the aggregate raw RPC byte cap.
    pub const fn aggregate_bytes(&self) -> usize {
        self.aggregate_bytes
    }

    /// Returns the adjacent-header count cap.
    pub const fn max_adjacent_headers(&self) -> usize {
        self.max_adjacent_headers
    }

    /// Returns the validator count cap.
    pub const fn max_validators(&self) -> usize {
        self.max_validators
    }

    /// Returns the exact validator pagination size.
    pub const fn validator_page_size(&self) -> NonZeroU8 {
        self.validator_page_size
    }

    /// Returns the HTTP header-count cap.
    pub const fn max_headers(&self) -> usize {
        self.max_headers
    }

    /// Returns the HTTP response-header buffer cap.
    pub const fn max_header_bytes(&self) -> usize {
        self.max_header_bytes
    }
}

/// Production HTTPS/mTLS peer with explicit CA and leaf-SPKI pins.
#[derive(Clone)]
pub struct HttpsPeer {
    pub(crate) endpoint: Endpoint,
    pub(crate) identity: PeerIdentity,
    pub(crate) roots: Vec<CertificateDer<'static>>,
    pub(crate) expected_spki: [u8; 32],
    pub(crate) client_identity_profile: [u8; 32],
    pub(crate) client_resolver: Arc<dyn ResolvesClientCert>,
}

impl HttpsPeer {
    /// Constructs one immutable production peer.
    pub fn new(
        url: &str,
        expected_node_id: NodeId,
        expected_spki_sha256: [u8; 32],
        ca_certificates: Vec<CertificateDer<'static>>,
        client_identity: &dyn ClientIdentityProvider,
    ) -> Result<Self> {
        if expected_spki_sha256 == [0_u8; 32]
            || ca_certificates.is_empty()
            || ca_certificates.len() > 8
            || ca_certificates
                .iter()
                .any(|certificate| certificate.is_empty() || certificate.len() > 64 * 1024)
        {
            return Err(RpcTransportError::InvalidConfiguration(
                "HTTPS peer certificate pins are outside bounds",
            ));
        }
        let identity = PeerIdentity::new(expected_spki_sha256, expected_node_id)
            .map_err(|_| RpcTransportError::InvalidConfiguration("peer identity is invalid"))?;
        let endpoint = Endpoint::parse(url, EndpointKind::Https)?;
        if endpoint.host.ends_with('.') {
            return Err(RpcTransportError::InvalidConfiguration(
                "HTTPS host must not use a trailing DNS root label",
            ));
        }
        let _ = crate::tls::server_name(&endpoint.host)?;
        let client_binding = client_identity.binding(&identity)?;
        let client_identity_profile = client_binding.expected_profile;
        if client_identity_profile == [0_u8; 32] {
            return Err(RpcTransportError::InvalidConfiguration(
                "client identity profile must be nonzero",
            ));
        }
        let mut root_digests = BTreeSet::new();
        if ca_certificates
            .iter()
            .map(|certificate| <[u8; 32]>::from(Sha256::digest(certificate.as_ref())))
            .any(|digest| !root_digests.insert(digest))
        {
            return Err(RpcTransportError::InvalidConfiguration(
                "HTTPS CA certificates must be distinct",
            ));
        }
        Ok(Self {
            endpoint,
            identity,
            roots: ca_certificates,
            expected_spki: expected_spki_sha256,
            client_identity_profile,
            client_resolver: client_binding.resolver,
        })
    }

    /// Returns the exact coordinator-facing peer identity.
    pub const fn identity(&self) -> &PeerIdentity {
        &self.identity
    }
}

impl fmt::Debug for HttpsPeer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HttpsPeer")
            .field("endpoint", &self.endpoint)
            .field("identity", &self.identity)
            .field("expected_spki", &self.expected_spki)
            .field("ca_certificates", &self.roots.len())
            .field("client_identity_profile", &self.client_identity_profile)
            .field("client_identity", &"[redacted provider]")
            .finish()
    }
}

/// Explicit plaintext profile for a literal loopback regtest RPC endpoint.
#[cfg(any(test, feature = "regtest"))]
#[derive(Clone, Debug)]
pub struct LoopbackHttpPeer {
    pub(crate) endpoint: Endpoint,
    pub(crate) identity: PeerIdentity,
}

#[cfg(any(test, feature = "regtest"))]
impl LoopbackHttpPeer {
    /// Constructs a loopback-only plaintext peer for explicit regtest use.
    pub fn new_regtest(url: &str, expected_node_id: NodeId, local_binding: [u8; 32]) -> Result<Self> {
        let identity = PeerIdentity::new(local_binding, expected_node_id)
            .map_err(|_| RpcTransportError::InvalidConfiguration("peer identity is invalid"))?;
        let endpoint = Endpoint::parse(url, EndpointKind::LoopbackHttp)?;
        Ok(Self { endpoint, identity })
    }

    /// Returns the exact coordinator-facing peer identity.
    pub const fn identity(&self) -> &PeerIdentity {
        &self.identity
    }
}

/// One immutable authenticated RPC endpoint.
#[derive(Clone, Debug)]
pub enum RpcPeer {
    /// Production HTTPS/mTLS endpoint.
    Https(HttpsPeer),
    /// Explicit literal-loopback plaintext regtest endpoint.
    #[cfg(any(test, feature = "regtest"))]
    RegtestLoopback(LoopbackHttpPeer),
}

impl RpcPeer {
    /// Returns the exact coordinator-facing identity.
    pub const fn identity(&self) -> &PeerIdentity {
        match self {
            Self::Https(peer) => peer.identity(),
            #[cfg(any(test, feature = "regtest"))]
            Self::RegtestLoopback(peer) => peer.identity(),
        }
    }

    pub(crate) const fn endpoint(&self) -> &Endpoint {
        match self {
            Self::Https(peer) => &peer.endpoint,
            #[cfg(any(test, feature = "regtest"))]
            Self::RegtestLoopback(peer) => &peer.endpoint,
        }
    }

    fn profile_origin(&self) -> (u8, String) {
        let kind = match self {
            Self::Https(_) => 1,
            #[cfg(any(test, feature = "regtest"))]
            Self::RegtestLoopback(_) => 2,
        };
        (kind, self.endpoint().authority.clone())
    }

    fn profile_descriptor(&self) -> Vec<u8> {
        let mut descriptor = Vec::with_capacity(512);
        match self {
            Self::Https(peer) => {
                descriptor.push(1);
                append_profile_bytes(&mut descriptor, peer.endpoint.authority.as_bytes());
                descriptor.extend_from_slice(peer.identity.transport_binding());
                descriptor.extend_from_slice(peer.identity.node_id().as_bytes());
                descriptor.extend_from_slice(&peer.expected_spki);
                descriptor.extend_from_slice(&peer.client_identity_profile);
                let mut roots = peer
                    .roots
                    .iter()
                    .map(|certificate| <[u8; 32]>::from(Sha256::digest(certificate.as_ref())))
                    .collect::<Vec<_>>();
                roots.sort_unstable();
                descriptor.extend_from_slice(&u64::try_from(roots.len()).unwrap_or(u64::MAX).to_be_bytes());
                for root in roots {
                    descriptor.extend_from_slice(&root);
                }
            }
            #[cfg(any(test, feature = "regtest"))]
            Self::RegtestLoopback(peer) => {
                descriptor.push(2);
                append_profile_bytes(&mut descriptor, peer.endpoint.authority.as_bytes());
                descriptor.extend_from_slice(peer.identity.transport_binding());
                descriptor.extend_from_slice(peer.identity.node_id().as_bytes());
            }
        }
        descriptor
    }
}

fn derive_transport_profile(
    peers: &[RpcPeer],
    limits: RpcLimits,
    ledger_limits: LedgerRpcLimits,
    retry: RetryPolicy,
) -> RpcTransportProfileId {
    let mut descriptors = peers.iter().map(RpcPeer::profile_descriptor).collect::<Vec<_>>();
    descriptors.sort_unstable();
    let mut hasher = Sha256::new();
    hasher.update(TRANSPORT_PROFILE_DOMAIN);
    hasher.update(u64::try_from(descriptors.len()).unwrap_or(u64::MAX).to_be_bytes());
    for descriptor in descriptors {
        hasher.update(u64::try_from(descriptor.len()).unwrap_or(u64::MAX).to_be_bytes());
        hasher.update(descriptor);
    }
    for value in [
        limits.response_bytes(),
        limits.aggregate_bytes(),
        limits.max_adjacent_headers(),
        limits.max_validators(),
        usize::from(limits.validator_page_size().get()),
        limits.max_headers(),
        limits.max_header_bytes(),
        ledger_limits.response_bytes(),
        ledger_limits.aggregate_bytes(),
        usize::from(retry.attempts().get()),
    ] {
        hasher.update(u64::try_from(value).unwrap_or(u64::MAX).to_be_bytes());
    }
    hasher.update(retry.base_delay().as_nanos().to_be_bytes());
    RpcTransportProfileId(hasher.finalize().into())
}

fn append_profile_bytes(output: &mut Vec<u8>, bytes: &[u8]) {
    output.extend_from_slice(&u64::try_from(bytes.len()).unwrap_or(u64::MAX).to_be_bytes());
    output.extend_from_slice(bytes);
}

/// Complete immutable RPC transport configuration.
#[derive(Clone, Debug)]
pub struct RpcTransportConfig {
    peers: Vec<RpcPeer>,
    limits: RpcLimits,
    ledger_limits: LedgerRpcLimits,
    retry: RetryPolicy,
    profile_id: RpcTransportProfileId,
}

impl RpcTransportConfig {
    /// Constructs a distinct one-to-five-peer transport roster.
    ///
    /// Fixed Ledger operations initially inherit the trace body limits. Use
    /// [`Self::with_ledger_limits`] when full-size Ledger query values are
    /// required, and bind that override in runtime policy.
    pub fn new(peers: Vec<RpcPeer>, limits: RpcLimits, retry: RetryPolicy) -> Result<Self> {
        if peers.is_empty() || peers.len() > MAX_WITNESSES + 1 {
            return Err(RpcTransportError::InvalidConfiguration(
                "RPC peer count is outside bounds",
            ));
        }
        let mut bindings = BTreeSet::new();
        let mut node_ids = BTreeSet::new();
        let mut origins = BTreeSet::new();
        for peer in &peers {
            if !bindings.insert(*peer.identity().transport_binding())
                || !node_ids.insert(peer.identity().node_id())
                || !origins.insert(peer.profile_origin())
            {
                return Err(RpcTransportError::InvalidConfiguration(
                    "RPC peer identities and origins must be distinct",
                ));
            }
        }
        let ledger_limits = LedgerRpcLimits::inherited(limits);
        let profile_id = derive_transport_profile(&peers, limits, ledger_limits, retry);
        Ok(Self {
            peers,
            limits,
            ledger_limits,
            retry,
            profile_id,
        })
    }

    /// Returns configured immutable peers.
    pub fn peers(&self) -> &[RpcPeer] {
        &self.peers
    }

    /// Returns RPC resource limits.
    pub const fn limits(&self) -> RpcLimits {
        self.limits
    }

    /// Overrides fixed Ledger body limits. Runtime policy must bind this value.
    #[must_use]
    pub fn with_ledger_limits(mut self, limits: LedgerRpcLimits) -> Self {
        self.ledger_limits = limits;
        self.profile_id = derive_transport_profile(&self.peers, self.limits, self.ledger_limits, self.retry);
        self
    }

    /// Returns fixed Ledger operation body limits.
    pub const fn ledger_limits(&self) -> LedgerRpcLimits {
        self.ledger_limits
    }

    /// Returns the mechanically derived complete transport-policy identity.
    pub const fn profile_id(&self) -> RpcTransportProfileId {
        self.profile_id
    }

    /// Returns the idempotent retry policy.
    pub const fn retry(&self) -> RetryPolicy {
        self.retry
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum EndpointKind {
    Https,
    #[cfg(any(test, feature = "regtest"))]
    LoopbackHttp,
}

#[derive(Clone, Debug)]
pub(crate) struct Endpoint {
    pub host: String,
    pub port: NonZeroU16,
    pub authority: String,
}

impl Endpoint {
    fn parse(raw: &str, kind: EndpointKind) -> Result<Self> {
        if raw.is_empty() || raw.len() > 2_048 {
            return Err(RpcTransportError::InvalidConfiguration("RPC URL length is invalid"));
        }
        let parsed = Url::parse(raw).map_err(|_| RpcTransportError::InvalidConfiguration("RPC URL is invalid"))?;
        let expected_scheme = match kind {
            EndpointKind::Https => "https",
            #[cfg(any(test, feature = "regtest"))]
            EndpointKind::LoopbackHttp => "http",
        };
        if parsed.scheme() != expected_scheme
            || !parsed.username().is_empty()
            || parsed.password().is_some()
            || parsed.query().is_some()
            || parsed.fragment().is_some()
            || !matches!(parsed.path(), "" | "/")
        {
            return Err(RpcTransportError::InvalidConfiguration(
                "RPC URL must be an origin without credentials, path, query, or fragment",
            ));
        }
        let host = parsed
            .host()
            .ok_or(RpcTransportError::InvalidConfiguration("RPC URL host is missing"))?;
        #[cfg(any(test, feature = "regtest"))]
        if kind == EndpointKind::LoopbackHttp {
            match host {
                Host::Ipv4(address) if IpAddr::V4(address).is_loopback() => {}
                Host::Ipv6(address) if IpAddr::V6(address).is_loopback() => {}
                _ => {
                    return Err(RpcTransportError::InvalidConfiguration(
                        "regtest HTTP requires a literal loopback IP",
                    ));
                }
            }
        }
        let host = match host {
            Host::Domain(domain) => domain.to_owned(),
            Host::Ipv4(address) => address.to_string(),
            Host::Ipv6(address) => address.to_string(),
        };
        let port = parsed
            .port_or_known_default()
            .and_then(NonZeroU16::new)
            .ok_or(RpcTransportError::InvalidConfiguration("RPC URL port is invalid"))?;
        let authority = match parsed.host() {
            Some(Host::Ipv6(_)) => format!("[{host}]:{}", port.get()),
            Some(_) => format!("{host}:{}", port.get()),
            None => return Err(RpcTransportError::InvalidConfiguration("RPC URL host is missing")),
        };
        Ok(Self { host, port, authority })
    }
}
