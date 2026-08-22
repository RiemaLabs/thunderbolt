use serde::{Deserialize, Deserializer, Serialize, Serializer};
use thunderbolt_floor::{FloorCasRequest, FloorLedgerChainId, FloorRequestDigest};
use thunderbolt_keystore::{
    CheckpointCasOutcome, CommitteeDescriptorDigest, DeploymentBinding, DeploymentId, Network, NodeId, VaultCheckpoint,
    VaultIdentity, VaultRevision, VaultRole, VaultStateDigest,
};

use crate::primitives::decode_hex_exact;
use crate::{AmbiguityTokenV2, OpaqueConsensusReceiptV2, Result, RpcCodecError, TransportAcceptanceIdV2};

const FLOOR_CAS_DOMAIN: &[u8] = b"bitcoin-thunderbolt/floor/cas/v1";

/// RPC wrapper for the floor crate's exact chain-bound checkpoint CAS request.
///
/// The JSON field contains the floor crate's own canonical application bytes;
/// decoding reconstructs [`FloorCasRequest`] and requires exact re-encoding and
/// digest equality. No alternate checkpoint identity or transition type is
/// defined by this crate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RollbackFloorCasRequestV2(FloorCasRequest);

impl RollbackFloorCasRequestV2 {
    /// Wraps a validated floor CAS request.
    #[must_use]
    pub const fn new(request: FloorCasRequest) -> Self {
        Self(request)
    }

    /// Borrows the exact floor CAS request.
    pub const fn request(&self) -> &FloorCasRequest {
        &self.0
    }

    pub(crate) fn validate(&self) -> Result<()> {
        let parsed = parse_floor_cas(&self.0.canonical_bytes())?;
        if &parsed != self.request() || parsed.digest() != self.0.digest() {
            return Err(RpcCodecError::BindingMismatch(
                "floor CAS canonical bytes, identity, chain, transition, or digest differ",
            ));
        }
        Ok(())
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FloorCasWire {
    canonical_request: String,
    request_digest: String,
}

/// Transport and finalized-state outcomes for one rollback-floor CAS.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RollbackFloorCasStatusV2 {
    /// The transport admitted the CAS but execution and finality are not known.
    TransportAccepted {
        /// Opaque transport correlation identifier.
        acceptance_id: TransportAcceptanceIdV2,
    },
    /// Submission may have committed and requires causal resolution.
    Ambiguous {
        /// Opaque token consumed by the transport's ambiguity resolver.
        token: AmbiguityTokenV2,
    },
    /// A result and opaque consensus receipt are available for the floor verifier.
    FinalityReceiptAvailable {
        /// Exact floor state-machine result.
        outcome: CheckpointCasOutcome,
        /// Receipt authenticated under the separate floor control-plane trust profile.
        consensus_receipt: OpaqueConsensusReceiptV2,
    },
}

/// Response to one exact rollback-floor CAS request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RollbackFloorCasResponseV2 {
    request_digest: FloorRequestDigest,
    status: RollbackFloorCasStatusV2,
}

impl RollbackFloorCasResponseV2 {
    /// Constructs a response bound to the floor crate's canonical request digest.
    pub fn new(request: &FloorCasRequest, status: RollbackFloorCasStatusV2) -> Result<Self> {
        let response = Self {
            request_digest: request.digest(),
            status,
        };
        response.validate_for(request)?;
        Ok(response)
    }

    /// Returns the exact floor request digest.
    pub const fn request_digest(&self) -> FloorRequestDigest {
        self.request_digest
    }

    /// Returns transport acceptance, ambiguity, or a finality-carrying result.
    pub const fn status(&self) -> &RollbackFloorCasStatusV2 {
        &self.status
    }

    /// Checks digest binding and deterministic floor CAS outcome shape.
    pub fn validate_for(&self, request: &FloorCasRequest) -> Result<()> {
        if self.request_digest != request.digest() {
            return Err(RpcCodecError::BindingMismatch(
                "floor CAS response request digest differs",
            ));
        }
        if let RollbackFloorCasStatusV2::FinalityReceiptAvailable {
            outcome: CheckpointCasOutcome::Conflict(current),
            ..
        } = &self.status
        {
            if *current == request.expected() || *current == Some(request.next()) {
                return Err(RpcCodecError::InvalidField(
                    "floor conflict outcome matches expected or exact desired checkpoint",
                ));
            }
        }
        Ok(())
    }

    pub(crate) fn validate(&self) -> Result<()> {
        match &self.status {
            RollbackFloorCasStatusV2::TransportAccepted { .. }
            | RollbackFloorCasStatusV2::Ambiguous { .. }
            | RollbackFloorCasStatusV2::FinalityReceiptAvailable { .. } => Ok(()),
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FloorCasResponseWire {
    request_digest: String,
    status: FloorCasStatusWire,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
enum FloorCasStatusWire {
    TransportAccepted {
        acceptance_id: TransportAcceptanceIdV2,
    },
    Ambiguous {
        token: AmbiguityTokenV2,
    },
    FinalityReceiptAvailable {
        outcome: FloorOutcomeWire,
        consensus_receipt: OpaqueConsensusReceiptV2,
    },
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
enum FloorOutcomeWire {
    Advanced,
    AlreadyCurrent,
    Conflict { current: Option<CheckpointWire> },
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CheckpointWire {
    revision: u64,
    state_digest: String,
}

impl Serialize for RollbackFloorCasResponseV2 {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        FloorCasResponseWire {
            request_digest: hex::encode(self.request_digest.as_bytes()),
            status: FloorCasStatusWire::from_status(&self.status),
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for RollbackFloorCasResponseV2 {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = FloorCasResponseWire::deserialize(deserializer)?;
        let request_digest = FloorRequestDigest::new(
            decode_hex_exact::<32>("floor_request_digest", &wire.request_digest).map_err(serde::de::Error::custom)?,
        );
        Ok(Self {
            request_digest,
            status: wire.status.into_status().map_err(serde::de::Error::custom)?,
        })
    }
}

impl FloorCasStatusWire {
    fn from_status(status: &RollbackFloorCasStatusV2) -> Self {
        match status {
            RollbackFloorCasStatusV2::TransportAccepted { acceptance_id } => Self::TransportAccepted {
                acceptance_id: *acceptance_id,
            },
            RollbackFloorCasStatusV2::Ambiguous { token } => Self::Ambiguous { token: token.clone() },
            RollbackFloorCasStatusV2::FinalityReceiptAvailable {
                outcome,
                consensus_receipt,
            } => Self::FinalityReceiptAvailable {
                outcome: FloorOutcomeWire::from_outcome(*outcome),
                consensus_receipt: consensus_receipt.clone(),
            },
        }
    }

    fn into_status(self) -> Result<RollbackFloorCasStatusV2> {
        Ok(match self {
            Self::TransportAccepted { acceptance_id } => RollbackFloorCasStatusV2::TransportAccepted { acceptance_id },
            Self::Ambiguous { token } => RollbackFloorCasStatusV2::Ambiguous { token },
            Self::FinalityReceiptAvailable {
                outcome,
                consensus_receipt,
            } => RollbackFloorCasStatusV2::FinalityReceiptAvailable {
                outcome: outcome.into_outcome()?,
                consensus_receipt,
            },
        })
    }
}

impl FloorOutcomeWire {
    fn from_outcome(outcome: CheckpointCasOutcome) -> Self {
        match outcome {
            CheckpointCasOutcome::Advanced => Self::Advanced,
            CheckpointCasOutcome::AlreadyCurrent => Self::AlreadyCurrent,
            CheckpointCasOutcome::Conflict(current) => Self::Conflict {
                current: current.map(CheckpointWire::from_checkpoint),
            },
        }
    }

    fn into_outcome(self) -> Result<CheckpointCasOutcome> {
        Ok(match self {
            Self::Advanced => CheckpointCasOutcome::Advanced,
            Self::AlreadyCurrent => CheckpointCasOutcome::AlreadyCurrent,
            Self::Conflict { current } => {
                CheckpointCasOutcome::Conflict(current.map(CheckpointWire::into_checkpoint).transpose()?)
            }
        })
    }
}

impl CheckpointWire {
    fn from_checkpoint(checkpoint: VaultCheckpoint) -> Self {
        Self {
            revision: checkpoint.revision().get(),
            state_digest: hex::encode(checkpoint.state_digest().as_bytes()),
        }
    }

    fn into_checkpoint(self) -> Result<VaultCheckpoint> {
        Ok(VaultCheckpoint::new(
            VaultRevision::new(self.revision),
            VaultStateDigest::new(decode_hex_exact::<32>("vault_state_digest", &self.state_digest)?),
        ))
    }
}

impl Serialize for RollbackFloorCasRequestV2 {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        FloorCasWire {
            canonical_request: hex::encode(self.0.canonical_bytes()),
            request_digest: hex::encode(self.0.digest().as_bytes()),
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for RollbackFloorCasRequestV2 {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = FloorCasWire::deserialize(deserializer)?;
        if !wire.canonical_request.len().is_multiple_of(2)
            || !wire
                .canonical_request
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            return Err(serde::de::Error::custom("invalid floor canonical request"));
        }
        let canonical = hex::decode(&wire.canonical_request).map_err(serde::de::Error::custom)?;
        let request = parse_floor_cas(&canonical).map_err(serde::de::Error::custom)?;
        let supplied_digest =
            decode_hex_exact::<32>("floor_request_digest", &wire.request_digest).map_err(serde::de::Error::custom)?;
        if request.digest().as_bytes() != &supplied_digest || request.canonical_bytes() != canonical {
            return Err(serde::de::Error::custom(
                "floor CAS request digest or canonical bytes mismatch",
            ));
        }
        Ok(Self(request))
    }
}

fn parse_floor_cas(bytes: &[u8]) -> Result<FloorCasRequest> {
    let mut reader = Reader::new(bytes);
    if reader.bytes()? != FLOOR_CAS_DOMAIN {
        return Err(RpcCodecError::InvalidField("floor CAS domain mismatch"));
    }
    let chain_id = FloorLedgerChainId::new(reader.bytes()?.to_vec())?;
    let network = match reader.u8()? {
        1 => Network::Regtest,
        2 => Network::Signet,
        3 => Network::Testnet,
        4 => Network::Mainnet,
        _ => return Err(RpcCodecError::InvalidField("floor vault network tag")),
    };
    let role = match reader.u8()? {
        1 => VaultRole::Holder,
        2 => VaultRole::CommitteeMember,
        _ => return Err(RpcCodecError::InvalidField("floor vault role tag")),
    };
    let node_id = NodeId::new(reader.fixed()?);
    let deployment_id = DeploymentId::new(reader.fixed()?)?;
    let committee_epoch = reader.u64()?;
    let committee_descriptor = CommitteeDescriptorDigest::new(reader.fixed()?)?;
    let deployment = DeploymentBinding::new(deployment_id, committee_epoch, committee_descriptor)?;
    let identity = VaultIdentity::new(network, role, node_id, deployment);
    let expected = match reader.u8()? {
        0 => None,
        1 => Some(reader.checkpoint()?),
        _ => return Err(RpcCodecError::InvalidField("floor expected-checkpoint tag")),
    };
    let next = reader.checkpoint()?;
    if !reader.is_empty() {
        return Err(RpcCodecError::InvalidField("trailing floor CAS bytes"));
    }
    let request = FloorCasRequest::new(&chain_id, identity, expected, next)?;
    if request.canonical_bytes() != bytes {
        return Err(RpcCodecError::NonCanonical);
    }
    Ok(request)
}

struct Reader<'a> {
    remaining: &'a [u8],
}

impl<'a> Reader<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { remaining: bytes }
    }

    const fn is_empty(&self) -> bool {
        self.remaining.is_empty()
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8]> {
        let (value, remaining) = self
            .remaining
            .split_at_checked(length)
            .ok_or(RpcCodecError::InvalidField("truncated floor CAS request"))?;
        self.remaining = remaining;
        Ok(value)
    }

    fn fixed<const N: usize>(&mut self) -> Result<[u8; N]> {
        <[u8; N]>::try_from(self.take(N)?).map_err(|_| RpcCodecError::InvalidField("truncated fixed field"))
    }

    fn u8(&mut self) -> Result<u8> {
        Ok(self.fixed::<1>()?[0])
    }

    fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_be_bytes(self.fixed()?))
    }

    fn bytes(&mut self) -> Result<&'a [u8]> {
        let length =
            usize::try_from(self.u64()?).map_err(|_| RpcCodecError::InvalidField("floor length does not fit usize"))?;
        self.take(length)
    }

    fn checkpoint(&mut self) -> Result<VaultCheckpoint> {
        let revision = VaultRevision::new(self.u64()?);
        let state_digest = VaultStateDigest::new(self.fixed()?);
        Ok(VaultCheckpoint::new(revision, state_digest))
    }
}
