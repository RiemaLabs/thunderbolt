use core::fmt;

use zeroize::Zeroizing;

use crate::{ControlError, Result};

/// Stable local-control protocol version.
pub const CONTROL_PROTOCOL_VERSION: u16 = 1;
/// Maximum method-name width.
pub const MAX_METHOD_BYTES: usize = 64;
/// Maximum human-readable error-message width.
pub const MAX_ERROR_MESSAGE_BYTES: usize = 512;
/// Default complete frame bound, including headers.
pub const DEFAULT_MAX_FRAME_BYTES: usize = 1024 * 1024;
/// Absolute complete frame bound accepted by any configuration.
pub const ABSOLUTE_MAX_FRAME_BYTES: usize = 16 * 1024 * 1024;

/// Nonzero 128-bit idempotency and correlation identifier.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RequestId([u8; 16]);

impl RequestId {
    /// Validates an exact nonzero request identifier.
    pub fn from_bytes(bytes: [u8; 16]) -> Result<Self> {
        if bytes == [0; 16] {
            return Err(ControlError::InvalidFrame("request id must not be all zero"));
        }
        Ok(Self(bytes))
    }

    /// Generates a request identifier from operating-system randomness.
    pub fn random() -> Result<Self> {
        let mut bytes = [0_u8; 16];
        getrandom::fill(&mut bytes).map_err(|_| ControlError::Random)?;
        Self::from_bytes(bytes)
    }

    /// Borrows the canonical 16 bytes.
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

impl fmt::Debug for RequestId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RequestId(")?;
        for byte in self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        formatter.write_str(")")
    }
}

/// Versioned local-control request.
pub struct ControlRequest {
    request_id: RequestId,
    method: String,
    payload: ControlPayload,
}

impl ControlRequest {
    /// Constructs a bounded request. The payload is role-owned canonical data,
    /// not implicitly trusted JSON.
    pub fn new(request_id: RequestId, method: impl Into<String>, payload: Vec<u8>) -> Result<Self> {
        let method = method.into();
        let payload = ControlPayload::new(payload);
        validate_method(&method)?;
        Ok(Self {
            request_id,
            method,
            payload,
        })
    }

    /// Returns the idempotency and correlation identifier.
    pub const fn request_id(&self) -> RequestId {
        self.request_id
    }

    /// Returns the stable lowercase method name.
    pub fn method(&self) -> &str {
        &self.method
    }

    /// Returns the opaque bounded role payload.
    pub fn payload(&self) -> &[u8] {
        self.payload.as_bytes()
    }

    /// Consumes the request and returns its zeroizing payload.
    pub fn into_payload(self) -> ControlPayload {
        self.payload
    }
}

impl fmt::Debug for ControlRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ControlRequest")
            .field("request_id", &self.request_id)
            .field("method", &self.method)
            .field("payload_len", &self.payload.as_bytes().len())
            .finish()
    }
}

/// Opaque payload that zeroizes its backing allocation on drop.
pub struct ControlPayload(Zeroizing<Vec<u8>>);

impl ControlPayload {
    /// Wraps an owned payload for automatic zeroization.
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(Zeroizing::new(bytes))
    }

    /// Creates an empty payload.
    pub fn empty() -> Self {
        Self::new(Vec::new())
    }

    /// Borrows payload bytes without cloning them.
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_slice()
    }
}

impl From<Vec<u8>> for ControlPayload {
    fn from(bytes: Vec<u8>) -> Self {
        Self::new(bytes)
    }
}

impl fmt::Debug for ControlPayload {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ControlPayload")
            .field("len", &self.as_bytes().len())
            .finish_non_exhaustive()
    }
}

/// Stable response status codes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum ControlStatus {
    /// Request completed successfully.
    Ok = 0,
    /// Request was malformed or semantically invalid.
    InvalidRequest = 1,
    /// The authenticated local caller lacks authorization.
    Unauthorized = 2,
    /// The request id conflicts with a prior command.
    Conflict = 3,
    /// The daemon is at a bounded work limit.
    Busy = 4,
    /// The daemon is draining and accepts no new work.
    Draining = 5,
    /// An internal failure occurred without exposing secret detail.
    Internal = 6,
    /// The command may or may not have committed; retry the exact request ID.
    Ambiguous = 7,
}

impl ControlStatus {
    pub(crate) fn from_u16(value: u16) -> Result<Self> {
        match value {
            0 => Ok(Self::Ok),
            1 => Ok(Self::InvalidRequest),
            2 => Ok(Self::Unauthorized),
            3 => Ok(Self::Conflict),
            4 => Ok(Self::Busy),
            5 => Ok(Self::Draining),
            6 => Ok(Self::Internal),
            7 => Ok(Self::Ambiguous),
            _ => Err(ControlError::InvalidFrame("unknown response status")),
        }
    }
}

/// Versioned local-control response.
pub struct ControlResponse {
    request_id: RequestId,
    status: ControlStatus,
    message: Zeroizing<String>,
    payload: ControlPayload,
}

impl ControlResponse {
    /// Constructs a successful response.
    pub fn success(request_id: RequestId, payload: impl Into<ControlPayload>) -> Self {
        Self {
            request_id,
            status: ControlStatus::Ok,
            message: Zeroizing::new(String::new()),
            payload: payload.into(),
        }
    }

    /// Constructs a bounded non-success response.
    pub fn failure(request_id: RequestId, status: ControlStatus, message: impl Into<String>) -> Result<Self> {
        let message = Zeroizing::new(message.into());
        if status == ControlStatus::Ok {
            return Err(ControlError::InvalidFrame(
                "failure response cannot use the success status",
            ));
        }
        if message.len() > MAX_ERROR_MESSAGE_BYTES {
            return Err(ControlError::InvalidFrame("response message exceeds the safety bound"));
        }
        Ok(Self {
            request_id,
            status,
            message,
            payload: ControlPayload::empty(),
        })
    }

    /// Returns the correlation identifier.
    pub const fn request_id(&self) -> RequestId {
        self.request_id
    }

    /// Returns the stable status code.
    pub const fn status(&self) -> ControlStatus {
        self.status
    }

    /// Returns the redacted human-readable failure description.
    pub fn message(&self) -> &str {
        self.message.as_str()
    }

    /// Returns the opaque role response payload.
    pub fn payload(&self) -> &[u8] {
        self.payload.as_bytes()
    }

    /// Reports whether the request completed successfully.
    pub const fn is_success(&self) -> bool {
        matches!(self.status, ControlStatus::Ok)
    }
}

impl fmt::Debug for ControlResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ControlResponse")
            .field("request_id", &self.request_id)
            .field("status", &self.status)
            .field("message_len", &self.message.len())
            .field("payload_len", &self.payload.as_bytes().len())
            .finish()
    }
}

pub(crate) fn validate_method(method: &str) -> Result<()> {
    if method.is_empty() || method.len() > MAX_METHOD_BYTES {
        return Err(ControlError::InvalidFrame("method length is outside the safety bound"));
    }
    if !method
        .bytes()
        .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(ControlError::InvalidFrame(
            "method must use lowercase ASCII letters, digits, dot, underscore, or hyphen",
        ));
    }
    Ok(())
}
