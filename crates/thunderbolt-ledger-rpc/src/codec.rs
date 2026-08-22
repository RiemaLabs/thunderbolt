use serde::{Deserialize, Serialize};
use thunderbolt_ledger::MAX_SIGNED_PROPOSAL_JSON_BYTES;

use crate::{
    primitives::digest_request, CorrelatedRpcResponseV2, Result, RpcCodecError, RpcRequestDigestV2, RpcRequestV2,
    RpcResponseV2, LEDGER_RPC_VERSION_V2,
};

/// Maximum canonical request body accepted by the codec.
pub const MAX_RPC_REQUEST_BYTES: usize = MAX_SIGNED_PROPOSAL_JSON_BYTES;
/// Maximum canonical response body accepted by the codec.
pub const MAX_RPC_RESPONSE_BYTES: usize = 32 * 1024 * 1024;

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct RequestEnvelopeRef<'a> {
    api_version: u16,
    request: &'a RpcRequestV2,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RequestEnvelopeOwned {
    api_version: u16,
    request: RequestWire,
}

#[derive(Deserialize)]
#[serde(tag = "method", content = "params", rename_all = "snake_case")]
enum RequestWire {
    SubmitProposal(serde_json::Value),
    ChannelStatus(serde_json::Value),
    RequestStatus(serde_json::Value),
    History(serde_json::Value),
    ExecutionRange(serde_json::Value),
    EntryLocation(serde_json::Value),
    RollbackFloorCas(serde_json::Value),
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct ResponseEnvelopeRef<'a> {
    api_version: u16,
    response: &'a RpcResponseV2,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ResponseEnvelopeOwned {
    api_version: u16,
    response: ResponseWire,
}

#[derive(Deserialize)]
#[serde(tag = "method", content = "result", rename_all = "snake_case")]
enum ResponseWire {
    SubmitProposal(serde_json::Value),
    ChannelStatus(serde_json::Value),
    RequestStatus(serde_json::Value),
    History(serde_json::Value),
    ExecutionRange(serde_json::Value),
    EntryLocation(serde_json::Value),
    RollbackFloorCas(serde_json::Value),
}

impl TryFrom<RequestWire> for RpcRequestV2 {
    type Error = RpcCodecError;

    fn try_from(wire: RequestWire) -> Result<Self> {
        Ok(match wire {
            RequestWire::SubmitProposal(value) => {
                Self::SubmitProposal(crate::request::decode_submit_request_value(value)?)
            }
            RequestWire::ChannelStatus(value) => {
                Self::ChannelStatus(crate::request::decode_channel_status_request_value(value)?)
            }
            RequestWire::RequestStatus(value) => {
                Self::RequestStatus(crate::request::decode_request_status_request_value(value)?)
            }
            RequestWire::History(value) => Self::History(crate::request::decode_history_request_value(value)?),
            RequestWire::ExecutionRange(value) => {
                Self::ExecutionRange(crate::request::decode_execution_range_request_value(value)?)
            }
            RequestWire::EntryLocation(value) => {
                Self::EntryLocation(crate::request::decode_entry_location_request_value(value)?)
            }
            RequestWire::RollbackFloorCas(value) => {
                Self::RollbackFloorCas(crate::floor_codec::decode_floor_request_value(value)?)
            }
        })
    }
}

impl TryFrom<ResponseWire> for RpcResponseV2 {
    type Error = RpcCodecError;

    fn try_from(wire: ResponseWire) -> Result<Self> {
        Ok(match wire {
            ResponseWire::SubmitProposal(value) => {
                Self::SubmitProposal(crate::response::decode_submit_response_value(value)?)
            }
            ResponseWire::ChannelStatus(value) => {
                Self::ChannelStatus(Box::new(crate::response::decode_channel_status_response_value(value)?))
            }
            ResponseWire::RequestStatus(value) => {
                Self::RequestStatus(Box::new(crate::response::decode_request_status_response_value(value)?))
            }
            ResponseWire::History(value) => Self::History(crate::response::decode_history_response_value(value)?),
            ResponseWire::ExecutionRange(value) => {
                Self::ExecutionRange(crate::response::decode_execution_range_response_value(value)?)
            }
            ResponseWire::EntryLocation(value) => {
                Self::EntryLocation(crate::response::decode_entry_location_response_value(value)?)
            }
            ResponseWire::RollbackFloorCas(value) => {
                Self::RollbackFloorCas(crate::floor_codec::decode_floor_response_value(value)?)
            }
        })
    }
}

impl RpcRequestV2 {
    /// Encodes the unique compact JSON representation of this typed request.
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let bytes = serde_json::to_vec(&RequestEnvelopeRef {
            api_version: LEDGER_RPC_VERSION_V2,
            request: self,
        })
        .map_err(RpcCodecError::InvalidEnvelope)?;
        enforce_bound("request", bytes.len(), MAX_RPC_REQUEST_BYTES)?;
        Ok(bytes)
    }

    /// Decodes a bounded request and rejects whitespace, reordered fields,
    /// unknown fields, uppercase hexadecimal, and all other non-canonical forms.
    pub fn from_canonical_bytes(bytes: impl AsRef<[u8]>) -> Result<Self> {
        let bytes = bytes.as_ref();
        enforce_bound("request", bytes.len(), MAX_RPC_REQUEST_BYTES)?;
        let envelope: RequestEnvelopeOwned = serde_json::from_slice(bytes).map_err(RpcCodecError::InvalidEnvelope)?;
        if envelope.api_version != LEDGER_RPC_VERSION_V2 {
            return Err(RpcCodecError::UnsupportedVersion {
                found: envelope.api_version,
            });
        }
        let request = RpcRequestV2::try_from(envelope.request)?;
        request.validate()?;
        if request.to_canonical_bytes()? != bytes {
            return Err(RpcCodecError::NonCanonical);
        }
        Ok(request)
    }

    /// Computes the domain-separated digest of the complete canonical request.
    pub fn request_digest(&self) -> Result<RpcRequestDigestV2> {
        digest_request(&self.to_canonical_bytes()?)
    }
}

impl RpcResponseV2 {
    /// Encodes the unique compact JSON representation of this typed response.
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let bytes = serde_json::to_vec(&ResponseEnvelopeRef {
            api_version: LEDGER_RPC_VERSION_V2,
            response: self,
        })
        .map_err(RpcCodecError::InvalidEnvelope)?;
        enforce_bound("response", bytes.len(), MAX_RPC_RESPONSE_BYTES)?;
        Ok(bytes)
    }

    /// Decodes a bounded response and binds it to the exact correlated request.
    ///
    /// There is intentionally no public raw response decoder. Successful
    /// decoding always performs method and request-key correlation before
    /// returning a capability.
    pub fn from_canonical_bytes_for(
        bytes: impl AsRef<[u8]>,
        request: &RpcRequestV2,
    ) -> Result<CorrelatedRpcResponseV2> {
        let response = Self::decode_canonical_bytes(bytes)?;
        response.validate_for(request)?;
        Ok(CorrelatedRpcResponseV2::new(response))
    }

    fn decode_canonical_bytes(bytes: impl AsRef<[u8]>) -> Result<Self> {
        let bytes = bytes.as_ref();
        enforce_bound("response", bytes.len(), MAX_RPC_RESPONSE_BYTES)?;
        let envelope: ResponseEnvelopeOwned = serde_json::from_slice(bytes).map_err(RpcCodecError::InvalidEnvelope)?;
        if envelope.api_version != LEDGER_RPC_VERSION_V2 {
            return Err(RpcCodecError::UnsupportedVersion {
                found: envelope.api_version,
            });
        }
        let response = RpcResponseV2::try_from(envelope.response)?;
        response.validate()?;
        if response.to_canonical_bytes()? != bytes {
            return Err(RpcCodecError::NonCanonical);
        }
        Ok(response)
    }
}

fn enforce_bound(direction: &'static str, actual: usize, limit: usize) -> Result<()> {
    if actual == 0 {
        return Err(RpcCodecError::InvalidField("RPC envelope is empty"));
    }
    if actual > limit {
        return Err(RpcCodecError::BodyTooLarge { direction, limit });
    }
    Ok(())
}
