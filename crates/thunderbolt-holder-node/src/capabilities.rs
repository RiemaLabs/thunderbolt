use thiserror::Error;
use thunderbolt_ledger::EntryHashV2;
use thunderbolt_wire::ChannelBindingV2;

const MAX_CAPABILITY_ARTIFACT_BYTES: usize = 1_048_576;

/// Fail-closed capability error.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum CapabilityError {
    #[error("capability is not configured")]
    Unavailable,
    #[error("capability rejected the request")]
    Rejected,
}

/// Public intent passed to an audited Bitcoin settlement implementation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SettlementIntent {
    pub channel: ChannelBindingV2,
    pub current_entry_hash: EntryHashV2,
    pub expected_holder_anchor: Vec<u8>,
}

/// Public settlement artifacts suitable for a v2 Finalize event.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SettlementArtifacts {
    pub closing_txid: [u8; 32],
    pub closing_transaction: Vec<u8>,
    pub ownership_proof: Vec<u8>,
}

impl SettlementArtifacts {
    pub fn validate(self) -> std::result::Result<Self, CapabilityError> {
        if self.closing_txid == [0_u8; 32]
            || self.closing_transaction.is_empty()
            || self.closing_transaction.len() > MAX_CAPABILITY_ARTIFACT_BYTES
            || self.ownership_proof.is_empty()
            || self.ownership_proof.len() > MAX_CAPABILITY_ARTIFACT_BYTES
        {
            return Err(CapabilityError::Rejected);
        }
        Ok(self)
    }
}

/// Bitcoin settlement capability. Implementations own chain RPC and signing.
pub trait BitcoinSettlement {
    type Error: std::error::Error + Send + Sync + 'static;
    fn prepare(&mut self, intent: &SettlementIntent) -> std::result::Result<SettlementArtifacts, Self::Error>;
}

/// Public threshold-signing action.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ThresholdAction {
    pub channel: ChannelBindingV2,
    pub entry_hash: EntryHashV2,
    pub message_digest: [u8; 32],
}

/// Public threshold result.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ThresholdArtifacts {
    pub committee_attestation: Vec<u8>,
}

impl ThresholdArtifacts {
    pub fn validate(self) -> std::result::Result<Self, CapabilityError> {
        if self.committee_attestation.is_empty() || self.committee_attestation.len() > MAX_CAPABILITY_ARTIFACT_BYTES {
            return Err(CapabilityError::Rejected);
        }
        Ok(self)
    }
}

/// Threshold-signing capability. Implementations own nonce and share safety.
pub trait ThresholdSigner {
    type Error: std::error::Error + Send + Sync + 'static;
    fn sign(&mut self, action: &ThresholdAction) -> std::result::Result<ThresholdArtifacts, Self::Error>;
}

/// Bundled Bitcoin capability that always refuses settlement.
#[derive(Clone, Copy, Debug, Default)]
pub struct UnavailableBitcoinSettlement;

impl BitcoinSettlement for UnavailableBitcoinSettlement {
    type Error = CapabilityError;

    fn prepare(&mut self, _intent: &SettlementIntent) -> std::result::Result<SettlementArtifacts, Self::Error> {
        Err(CapabilityError::Unavailable)
    }
}

/// Bundled threshold capability that always refuses signing.
#[derive(Clone, Copy, Debug, Default)]
pub struct UnavailableThresholdSigner;

impl ThresholdSigner for UnavailableThresholdSigner {
    type Error = CapabilityError;

    fn sign(&mut self, _action: &ThresholdAction) -> std::result::Result<ThresholdArtifacts, Self::Error> {
        Err(CapabilityError::Unavailable)
    }
}
