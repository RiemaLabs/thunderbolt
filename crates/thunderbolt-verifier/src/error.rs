use core::fmt;

use thiserror::Error;
use thunderbolt_protocol::EventKind;

/// Stable machine-readable verifier error codes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum VerifierErrorCode {
    InvalidConfiguration,
    UnsupportedEvent,
    ClientEvidence,
    InvalidSnapshot,
    StateMismatch,
    InvalidTrustedTime,
    ArtifactDecode,
    UnexpectedMessageType,
    BindingMismatch,
    PublicFieldMismatch,
    CommitteeMismatch,
    PriorInvoiceMismatch,
    InvoiceExpired,
    VerificationFailed,
    ArithmeticOverflow,
}

impl VerifierErrorCode {
    /// Stable lowercase identifier suitable for API error responses and logs.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidConfiguration => "invalid_configuration",
            Self::UnsupportedEvent => "unsupported_event",
            Self::ClientEvidence => "client_evidence",
            Self::InvalidSnapshot => "invalid_snapshot",
            Self::StateMismatch => "state_mismatch",
            Self::InvalidTrustedTime => "invalid_trusted_time",
            Self::ArtifactDecode => "artifact_decode",
            Self::UnexpectedMessageType => "unexpected_message_type",
            Self::BindingMismatch => "binding_mismatch",
            Self::PublicFieldMismatch => "public_field_mismatch",
            Self::CommitteeMismatch => "committee_mismatch",
            Self::PriorInvoiceMismatch => "prior_invoice_mismatch",
            Self::InvoiceExpired => "invoice_expired",
            Self::VerificationFailed => "verification_failed",
            Self::ArithmeticOverflow => "arithmetic_overflow",
        }
    }
}

impl fmt::Display for VerifierErrorCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Artifact position being decoded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ArtifactSlot {
    WireMessage,
    InvoiceProof,
    CommitteePackage,
    TransferProof,
}

impl fmt::Display for ArtifactSlot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::WireMessage => "wire message",
            Self::InvoiceProof => "invoice_proof",
            Self::CommitteePackage => "committee_package",
            Self::TransferProof => "transfer_proof",
        })
    }
}

/// Public message discriminant used in exact-type errors.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PublicMessageKind {
    Invoice,
    Transfer,
    Share,
    ThresholdRefresh,
}

impl fmt::Display for PublicMessageKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Invoice => "invoice",
            Self::Transfer => "transfer",
            Self::Share => "share",
            Self::ThresholdRefresh => "threshold_refresh",
        })
    }
}

/// Trusted binding component that did not match the decoded message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BindingField {
    ProtocolVersion,
    Network,
    DeploymentId,
    CommitteeEpoch,
    ChannelId,
    InvoiceId,
    Step,
}

impl fmt::Display for BindingField {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::ProtocolVersion => "protocol_version",
            Self::Network => "network",
            Self::DeploymentId => "deployment_id",
            Self::CommitteeEpoch => "committee_epoch",
            Self::ChannelId => "channel_id",
            Self::InvoiceId => "invoice_id",
            Self::Step => "step",
        })
    }
}

/// Stable, typed failures at the trusted verifier boundary.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum VerifierError {
    #[error("invalid trusted configuration field {field}: {source}")]
    InvalidConfiguration {
        field: &'static str,
        #[source]
        source: thunderbolt_wire::WireError,
    },

    #[error("invalid trusted configuration field {field}: {reason}")]
    InvalidConfigurationValue { field: &'static str, reason: &'static str },

    #[error("unsupported ledger event {actual}; expected {expected}")]
    UnsupportedEvent { expected: EventKind, actual: EventKind },

    #[error("client-supplied verification evidence is forbidden for {event} events")]
    ClientEvidence { event: EventKind },

    #[error("channel snapshot is invalid: {source}")]
    InvalidSnapshot {
        #[source]
        source: thunderbolt_protocol::ProtocolError,
    },

    #[error("ledger state mismatch at {field}")]
    StateMismatch { field: &'static str },

    #[error("trusted ledger time is inconsistent with {field}")]
    InvalidTrustedTime { field: &'static str },

    #[error("cannot decode {slot}: {source}")]
    ArtifactDecode {
        slot: ArtifactSlot,
        #[source]
        source: thunderbolt_wire::WireError,
    },

    #[error("{slot} has message type {actual}; expected exactly {expected}")]
    UnexpectedMessageType {
        slot: ArtifactSlot,
        expected: PublicMessageKind,
        actual: PublicMessageKind,
    },

    #[error("decoded message does not match trusted binding field {field}")]
    BindingMismatch { field: BindingField },

    #[error("ledger event and decoded public statement differ at {field}")]
    PublicFieldMismatch { field: &'static str },

    #[error("decoded committee package does not match trusted committee field {field}")]
    CommitteeMismatch { field: &'static str },

    #[error("pending invoice linkage failed at {field}")]
    PriorInvoiceMismatch { field: &'static str },

    #[error("invoice expired at {expires_at_ms} before trusted ledger time {ledger_time_ms}")]
    InvoiceExpired { expires_at_ms: u64, ledger_time_ms: u64 },

    #[error("{message} cryptographic verification failed: {source}")]
    VerificationFailed {
        message: PublicMessageKind,
        #[source]
        source: thunderbolt_wire::WireError,
    },

    #[error("arithmetic overflow while deriving {field}")]
    ArithmeticOverflow { field: &'static str },
}

impl VerifierError {
    /// Returns a stable code independent of nested parser or crypto messages.
    pub const fn code(&self) -> VerifierErrorCode {
        match self {
            Self::InvalidConfiguration { .. } | Self::InvalidConfigurationValue { .. } => {
                VerifierErrorCode::InvalidConfiguration
            }
            Self::UnsupportedEvent { .. } => VerifierErrorCode::UnsupportedEvent,
            Self::ClientEvidence { .. } => VerifierErrorCode::ClientEvidence,
            Self::InvalidSnapshot { .. } => VerifierErrorCode::InvalidSnapshot,
            Self::StateMismatch { .. } => VerifierErrorCode::StateMismatch,
            Self::InvalidTrustedTime { .. } => VerifierErrorCode::InvalidTrustedTime,
            Self::ArtifactDecode { .. } => VerifierErrorCode::ArtifactDecode,
            Self::UnexpectedMessageType { .. } => VerifierErrorCode::UnexpectedMessageType,
            Self::BindingMismatch { .. } => VerifierErrorCode::BindingMismatch,
            Self::PublicFieldMismatch { .. } => VerifierErrorCode::PublicFieldMismatch,
            Self::CommitteeMismatch { .. } => VerifierErrorCode::CommitteeMismatch,
            Self::PriorInvoiceMismatch { .. } => VerifierErrorCode::PriorInvoiceMismatch,
            Self::InvoiceExpired { .. } => VerifierErrorCode::InvoiceExpired,
            Self::VerificationFailed { .. } => VerifierErrorCode::VerificationFailed,
            Self::ArithmeticOverflow { .. } => VerifierErrorCode::ArithmeticOverflow,
        }
    }
}

pub type Result<T> = std::result::Result<T, VerifierError>;
