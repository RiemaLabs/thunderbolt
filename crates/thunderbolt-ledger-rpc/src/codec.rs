use serde::{Deserialize, Serialize};

use crate::{
    primitives::digest_request, Result, RpcCodecError, RpcRequestDigestV2, RpcRequestV2, RpcResponseV2,
    LEDGER_RPC_VERSION_V2,
};

/// Maximum canonical request body accepted by the codec.
pub const MAX_RPC_REQUEST_BYTES: usize = 2 * 1024 * 1024;
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
    SubmitProposal(crate::SubmitProposalRequestV2),
    ChannelStatus(crate::ChannelStatusRequestV2),
    RequestStatus(crate::RequestStatusRequestV2),
    History(crate::HistoryRequestV2),
    RollbackFloorCas(crate::RollbackFloorCasRequestV2),
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
    SubmitProposal(crate::SubmitProposalResponseV2),
    ChannelStatus(Box<crate::ChannelStatusResponseV2>),
    RequestStatus(Box<crate::RequestStatusResponseV2>),
    History(crate::HistoryResponseV2),
    RollbackFloorCas(crate::RollbackFloorCasResponseV2),
}

impl From<RequestWire> for RpcRequestV2 {
    fn from(wire: RequestWire) -> Self {
        match wire {
            RequestWire::SubmitProposal(request) => Self::SubmitProposal(request),
            RequestWire::ChannelStatus(request) => Self::ChannelStatus(request),
            RequestWire::RequestStatus(request) => Self::RequestStatus(request),
            RequestWire::History(request) => Self::History(request),
            RequestWire::RollbackFloorCas(request) => Self::RollbackFloorCas(request),
        }
    }
}

impl From<ResponseWire> for RpcResponseV2 {
    fn from(wire: ResponseWire) -> Self {
        match wire {
            ResponseWire::SubmitProposal(response) => Self::SubmitProposal(response),
            ResponseWire::ChannelStatus(response) => Self::ChannelStatus(response),
            ResponseWire::RequestStatus(response) => Self::RequestStatus(response),
            ResponseWire::History(response) => Self::History(response),
            ResponseWire::RollbackFloorCas(response) => Self::RollbackFloorCas(response),
        }
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
        let request = RpcRequestV2::from(envelope.request);
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

    /// Decodes a bounded response and requires exact canonical re-encoding.
    pub fn from_canonical_bytes(bytes: impl AsRef<[u8]>) -> Result<Self> {
        let bytes = bytes.as_ref();
        enforce_bound("response", bytes.len(), MAX_RPC_RESPONSE_BYTES)?;
        let envelope: ResponseEnvelopeOwned = serde_json::from_slice(bytes).map_err(RpcCodecError::InvalidEnvelope)?;
        if envelope.api_version != LEDGER_RPC_VERSION_V2 {
            return Err(RpcCodecError::UnsupportedVersion {
                found: envelope.api_version,
            });
        }
        let response = RpcResponseV2::from(envelope.response);
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
