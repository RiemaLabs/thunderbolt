use std::collections::BTreeMap;
use std::fmt;
use std::io::Cursor;
use std::sync::Arc;
use std::time::Instant;

use sha2::{Digest, Sha256};
use tendermint::node::Id as NodeId;
use tendermint_light_client_verifier::types::LightBlock;
use thunderbolt_cometbft_client::{
    AuthenticationContext, FetchedTrace, PeerIdentity, SourceRole, TraceFetchRequest, TraceFuture,
    TracePeerAuthenticator, TraceTransport,
};

use crate::config::RpcTransportConfig;
use crate::rpc::{fetch_trace, RpcFetchSpec, RuntimePeer};
use crate::{Result, RpcTransportError};

const REQUEST_DOMAIN: &[u8] = b"bitcoin-thunderbolt/cometbft-rpc/fetch-request/v1";
const TRACE_DOMAIN: &[u8] = b"bitcoin-thunderbolt/cometbft-rpc/trace/v1";
const SESSION_DOMAIN: &[u8] = b"bitcoin-thunderbolt/cometbft-rpc/session-evidence/v1";

/// Concrete authenticated streaming transport for CometBFT adjacent traces.
pub struct CometBftRpcTransport {
    peers: BTreeMap<[u8; 32], Arc<RuntimePeer>>,
    limits: crate::RpcLimits,
    retry: crate::RetryPolicy,
}

impl CometBftRpcTransport {
    /// Builds immutable per-peer clients and validates every TLS configuration.
    pub fn new(config: RpcTransportConfig) -> Result<Self> {
        let mut peers = BTreeMap::new();
        for peer in config.peers().iter().cloned() {
            let binding = *peer.identity().transport_binding();
            let runtime = Arc::new(RuntimePeer::new(peer)?);
            if peers.insert(binding, runtime).is_some() {
                return Err(RpcTransportError::InvalidConfiguration(
                    "duplicate RPC transport binding",
                ));
            }
        }
        Ok(Self {
            peers,
            limits: config.limits(),
            retry: config.retry(),
        })
    }
}

impl fmt::Debug for CometBftRpcTransport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CometBftRpcTransport")
            .field("peer_count", &self.peers.len())
            .field("limits", &self.limits)
            .field("retry", &self.retry)
            .finish()
    }
}

impl TraceTransport for CometBftRpcTransport {
    type Evidence = RpcSessionEvidence;
    type Body = Cursor<Vec<u8>>;
    type Error = RpcTransportError;

    fn fetch<'a>(
        &'a self,
        peer: &'a PeerIdentity,
        request: &'a TraceFetchRequest,
    ) -> TraceFuture<'a, FetchedTrace<Self::Body, Self::Evidence>, Self::Error> {
        Box::pin(async move {
            let runtime = self
                .peers
                .get(peer.transport_binding())
                .ok_or(RpcTransportError::UnknownPeer)?;
            if runtime.peer.identity().node_id() != peer.node_id()
                || runtime.peer.identity().transport_binding() != peer.transport_binding()
            {
                return Err(RpcTransportError::UnknownPeer);
            }
            let spec = RpcFetchSpec::from_request(request);
            let fetched = fetch_trace(runtime, &spec, self.limits, self.retry).await?;
            let request_digest = request_digest(request)?;
            let trace_digest = trace_digest(&fetched.blocks)?;
            let session_digest = session_digest(
                peer.transport_binding(),
                peer.node_id(),
                &request_digest,
                &trace_digest,
                &fetched.transcript_digest,
            );
            let evidence = RpcSessionEvidence {
                transport_binding: *peer.transport_binding(),
                node_id: peer.node_id(),
                request_digest,
                trace_digest,
                transcript_digest: fetched.transcript_digest,
                session_digest,
                deadline: request.deadline(),
                encoded_bytes: fetched.encoded.len(),
            };
            Ok(FetchedTrace::new(Cursor::new(fetched.encoded), evidence))
        })
    }
}

/// Non-serializable evidence created only after all authenticated RPC reads.
pub struct RpcSessionEvidence {
    transport_binding: [u8; 32],
    node_id: NodeId,
    request_digest: [u8; 32],
    trace_digest: [u8; 32],
    transcript_digest: [u8; 32],
    session_digest: [u8; 32],
    deadline: Instant,
    encoded_bytes: usize,
}

#[cfg(test)]
#[derive(Clone, Copy)]
pub(crate) enum TestEvidenceFault {
    Binding,
    Request,
    Trace,
    ReplayedDeadline,
}

#[cfg(test)]
impl RpcSessionEvidence {
    pub(crate) fn fixture_with_fault(
        peer: &PeerIdentity,
        request: &TraceFetchRequest,
        blocks: &[LightBlock],
        encoded_bytes: usize,
        fault: TestEvidenceFault,
    ) -> Result<Self> {
        let request_digest = request_digest(request)?;
        let trace_digest = trace_digest(blocks)?;
        let transcript_digest = [0x66_u8; 32];
        let session_digest = session_digest(
            peer.transport_binding(),
            peer.node_id(),
            &request_digest,
            &trace_digest,
            &transcript_digest,
        );
        let mut evidence = Self {
            transport_binding: *peer.transport_binding(),
            node_id: peer.node_id(),
            request_digest,
            trace_digest,
            transcript_digest,
            session_digest,
            deadline: request.deadline(),
            encoded_bytes,
        };
        match fault {
            TestEvidenceFault::Binding => evidence.transport_binding[0] ^= 1,
            TestEvidenceFault::Request => evidence.request_digest[0] ^= 1,
            TestEvidenceFault::Trace => evidence.trace_digest[0] ^= 1,
            TestEvidenceFault::ReplayedDeadline => {
                evidence.deadline -= std::time::Duration::from_millis(1);
            }
        }
        Ok(evidence)
    }
}

impl fmt::Debug for RpcSessionEvidence {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RpcSessionEvidence([authenticated capability])")
    }
}

/// Matching authenticator for [`CometBftRpcTransport`] session evidence.
#[derive(Clone, Copy, Debug, Default)]
pub struct RpcPeerAuthenticator;

impl TracePeerAuthenticator<RpcSessionEvidence> for RpcPeerAuthenticator {
    type Error = RpcTransportError;

    fn authenticate<'a>(
        &'a self,
        expected: &'a PeerIdentity,
        context: AuthenticationContext<'a>,
        evidence: &'a RpcSessionEvidence,
    ) -> TraceFuture<'a, (), Self::Error> {
        Box::pin(async move {
            let request_digest = request_digest(context.request())?;
            let trace_digest = trace_digest(context.blocks())?;
            let session_digest = session_digest(
                expected.transport_binding(),
                expected.node_id(),
                &request_digest,
                &trace_digest,
                &evidence.transcript_digest,
            );
            if evidence.transport_binding != *expected.transport_binding()
                || evidence.node_id != expected.node_id()
                || evidence.request_digest != request_digest
                || evidence.trace_digest != trace_digest
                || evidence.session_digest != session_digest
                || evidence.deadline != context.request().deadline()
                || evidence.encoded_bytes != context.encoded_bytes()
                || context.trace_digest() == &[0_u8; 32]
            {
                return Err(RpcTransportError::Tls);
            }
            Ok(())
        })
    }
}

fn request_digest(request: &TraceFetchRequest) -> Result<[u8; 32]> {
    let mut canonical = Vec::with_capacity(160);
    append(&mut canonical, request.ledger_chain_id().as_str().as_bytes())?;
    canonical.extend_from_slice(&request.config_version().to_be_bytes());
    match request.role() {
        SourceRole::Primary => canonical.extend_from_slice(&[0, 0]),
        SourceRole::Witness(index) => canonical.extend_from_slice(&[1, index]),
    }
    canonical.extend_from_slice(&request.first_height().to_be_bytes());
    canonical.extend_from_slice(&request.last_height().to_be_bytes());
    canonical.extend_from_slice(
        &u64::try_from(request.max_blocks())
            .map_err(|_| RpcTransportError::TraceBound)?
            .to_be_bytes(),
    );
    canonical.extend_from_slice(
        &u64::try_from(request.max_encoded_bytes())
            .map_err(|_| RpcTransportError::TraceBound)?
            .to_be_bytes(),
    );
    Ok(domain_digest(REQUEST_DOMAIN, &[canonical.as_slice()]))
}

fn trace_digest(blocks: &[LightBlock]) -> Result<[u8; 32]> {
    let encoded = serde_json::to_vec(blocks).map_err(|_| RpcTransportError::Json)?;
    Ok(domain_digest(TRACE_DOMAIN, &[encoded.as_slice()]))
}

fn session_digest(
    binding: &[u8; 32],
    node_id: NodeId,
    request_digest: &[u8; 32],
    trace_digest: &[u8; 32],
    transcript_digest: &[u8; 32],
) -> [u8; 32] {
    domain_digest(
        SESSION_DOMAIN,
        &[
            binding,
            node_id.as_bytes(),
            request_digest,
            trace_digest,
            transcript_digest,
        ],
    )
}

fn domain_digest(domain: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(u64::try_from(domain.len()).unwrap_or(u64::MAX).to_be_bytes());
    hasher.update(domain);
    for part in parts {
        hasher.update(u64::try_from(part.len()).unwrap_or(u64::MAX).to_be_bytes());
        hasher.update(part);
    }
    hasher.finalize().into()
}

fn append(output: &mut Vec<u8>, bytes: &[u8]) -> Result<()> {
    output.extend_from_slice(
        &u64::try_from(bytes.len())
            .map_err(|_| RpcTransportError::TraceBound)?
            .to_be_bytes(),
    );
    output.extend_from_slice(bytes);
    Ok(())
}
