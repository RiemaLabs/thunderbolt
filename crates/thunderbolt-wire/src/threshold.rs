use std::convert::TryFrom;

use serde::{Deserialize, Serialize};
use thunderbolt_core::threshold::{
    verify_threshold_refresh_distribution, ThresholdEncryptedShare, ThresholdRefreshDistribution,
};

use crate::binding::BindingContext;
use crate::codec::{
    integer_from_wire, integer_to_wire, key_from_wire, key_to_wire, point_from_wire, point_to_wire,
    validate_ciphertext, validate_nonce, CanonicalDigest, CanonicalHasher, PaillierCiphertextHex, PaillierPublicKeyHex,
    PointHex, ValidateWire,
};
use crate::error::core_error;
use crate::share::ShareProofV1;
use crate::{Result, WireError};

pub const MAX_COMMITTEE_MEMBERS: usize = 256;
/// Reserved share identifier for the Recipient proof in a threshold Invoice.
///
/// Committee rosters must never assign this identifier to an operator.
pub const RECIPIENT_SHARE_MEMBER_ID: u32 = u32::MAX;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ThresholdEncryptedShareV1 {
    pub member_id: u32,
    pub encryption_key: PaillierPublicKeyHex,
    pub ciphertext: PaillierCiphertextHex,
    pub proof: ShareProofV1,
}

impl ThresholdEncryptedShareV1 {
    pub fn from_core(share: &ThresholdEncryptedShare) -> Result<Self> {
        if share.member_id == 0 || share.member_id == RECIPIENT_SHARE_MEMBER_ID {
            return Err(WireError::InvalidMessage {
                message: "threshold refresh",
                reason: "committee member identifiers must be positive and not reserved",
            });
        }
        let wire = Self {
            member_id: share.member_id,
            encryption_key: key_to_wire("threshold.share.encryption_key", &share.encryption_key)?,
            ciphertext: integer_to_wire("threshold.share.ciphertext", &share.ciphertext)?,
            proof: ShareProofV1::from_core(&share.proof)?,
        };
        wire.validate_wire()?;
        Ok(wire)
    }

    pub fn to_core(&self) -> Result<ThresholdEncryptedShare> {
        if self.member_id == 0 || self.member_id == RECIPIENT_SHARE_MEMBER_ID {
            return Err(WireError::InvalidMessage {
                message: "threshold refresh",
                reason: "committee member identifiers must be positive and not reserved",
            });
        }
        Ok(ThresholdEncryptedShare {
            member_id: self.member_id,
            encryption_key: key_from_wire("threshold.share.encryption_key", &self.encryption_key)?,
            ciphertext: integer_from_wire("threshold.share.ciphertext", &self.ciphertext)?,
            proof: self.proof.to_core()?,
        })
    }

    fn append_canonical(&self, hasher: &mut CanonicalHasher) {
        hasher.u32(self.member_id);
        hasher.bytes(self.encryption_key.as_bytes());
        hasher.bytes(self.ciphertext.as_bytes());
        self.proof.append_canonical(hasher);
    }
}

impl ValidateWire for ThresholdEncryptedShareV1 {
    fn validate_wire(&self) -> Result<()> {
        let share = self.to_core()?;
        validate_ciphertext("threshold.share.ciphertext", &share.encryption_key, &share.ciphertext)?;
        validate_ciphertext(
            "threshold.share.proof.a_ciphertext",
            &share.encryption_key,
            &share.proof.a_ciphertext,
        )?;
        validate_nonce("threshold.share.proof.tau", &share.encryption_key, &share.proof.tau)?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ThresholdDistributionV1 {
    pub anchor_base: PointHex,
    pub threshold: u32,
    pub delta: PointHex,
    pub polynomial_commitments: Vec<PointHex>,
    pub encrypted_shares: Vec<ThresholdEncryptedShareV1>,
}

impl ThresholdDistributionV1 {
    pub fn from_core(distribution: &ThresholdRefreshDistribution) -> Result<Self> {
        let threshold = u32::try_from(distribution.threshold).map_err(|_| WireError::InvalidMessage {
            message: "threshold refresh",
            reason: "threshold does not fit in the version 1 wire format",
        })?;
        let mut encrypted_shares = distribution
            .encrypted_shares
            .iter()
            .map(ThresholdEncryptedShareV1::from_core)
            .collect::<Result<Vec<_>>>()?;
        encrypted_shares.sort_by_key(|share| share.member_id);

        let wire = Self {
            anchor_base: point_to_wire("threshold.anchor_base", &distribution.anchor_base)?,
            threshold,
            delta: point_to_wire("threshold.delta", &distribution.delta)?,
            polynomial_commitments: distribution
                .polynomial_commitments
                .iter()
                .map(|point| point_to_wire("threshold.polynomial_commitment", point))
                .collect::<Result<Vec<_>>>()?,
            encrypted_shares,
        };
        wire.validate_wire()?;
        Ok(wire)
    }

    pub fn to_core(&self, context: thunderbolt_core::zkp::ProofContext) -> Result<ThresholdRefreshDistribution> {
        self.validate_shape()?;
        let threshold = usize::try_from(self.threshold).map_err(|_| WireError::InvalidMessage {
            message: "threshold refresh",
            reason: "threshold does not fit on this platform",
        })?;
        Ok(ThresholdRefreshDistribution {
            context,
            anchor_base: point_from_wire("threshold.anchor_base", &self.anchor_base)?,
            threshold,
            delta: point_from_wire("threshold.delta", &self.delta)?,
            polynomial_commitments: self
                .polynomial_commitments
                .iter()
                .map(|point| point_from_wire("threshold.polynomial_commitment", point))
                .collect::<Result<Vec<_>>>()?,
            encrypted_shares: self
                .encrypted_shares
                .iter()
                .map(ThresholdEncryptedShareV1::to_core)
                .collect::<Result<Vec<_>>>()?,
        })
    }

    fn validate_shape(&self) -> Result<()> {
        let threshold = usize::try_from(self.threshold).map_err(|_| WireError::InvalidMessage {
            message: "threshold refresh",
            reason: "threshold does not fit on this platform",
        })?;
        if threshold == 0 || threshold > MAX_COMMITTEE_MEMBERS {
            return Err(WireError::InvalidMessage {
                message: "threshold refresh",
                reason: "threshold must be within the supported committee bound",
            });
        }
        if self.polynomial_commitments.len() != threshold {
            return Err(WireError::InvalidMessage {
                message: "threshold refresh",
                reason: "polynomial commitment count must equal the threshold",
            });
        }
        if self.encrypted_shares.len() < threshold || self.encrypted_shares.len() > MAX_COMMITTEE_MEMBERS {
            return Err(WireError::InvalidMessage {
                message: "threshold refresh",
                reason: "encrypted share count is outside the supported committee bound",
            });
        }
        let mut previous = None;
        for share in &self.encrypted_shares {
            if share.member_id == 0
                || share.member_id == RECIPIENT_SHARE_MEMBER_ID
                || previous.is_some_and(|id| share.member_id <= id)
            {
                return Err(WireError::InvalidMessage {
                    message: "threshold refresh",
                    reason: "encrypted shares must have unique non-reserved positive member ids in ascending order",
                });
            }
            previous = Some(share.member_id);
        }
        Ok(())
    }

    fn append_canonical(&self, hasher: &mut CanonicalHasher) -> Result<()> {
        hasher.bytes(self.anchor_base.as_bytes());
        hasher.u32(self.threshold);
        hasher.bytes(self.delta.as_bytes());
        hasher.usize(self.polynomial_commitments.len())?;
        for commitment in &self.polynomial_commitments {
            hasher.bytes(commitment.as_bytes());
        }
        hasher.usize(self.encrypted_shares.len())?;
        for share in &self.encrypted_shares {
            share.append_canonical(hasher);
        }
        Ok(())
    }
}

impl ValidateWire for ThresholdDistributionV1 {
    fn validate_wire(&self) -> Result<()> {
        self.validate_shape()?;
        let context = thunderbolt_core::zkp::ProofContext::invoice(b"wire-validation", b"invoice");
        let distribution = self.to_core(context)?;
        for share in &distribution.encrypted_shares {
            validate_ciphertext("threshold.share.ciphertext", &share.encryption_key, &share.ciphertext)?;
            validate_ciphertext(
                "threshold.share.proof.a_ciphertext",
                &share.encryption_key,
                &share.proof.a_ciphertext,
            )?;
            validate_nonce("threshold.share.proof.tau", &share.encryption_key, &share.proof.tau)?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ThresholdEnvelopeV1 {
    pub binding: BindingContext,
    pub distribution: ThresholdDistributionV1,
}

impl ThresholdEnvelopeV1 {
    pub fn from_core(binding: BindingContext, distribution: &ThresholdRefreshDistribution) -> Result<Self> {
        binding.require_invoice_scope()?;
        binding.matches_core(&distribution.context)?;
        let envelope = Self {
            binding,
            distribution: ThresholdDistributionV1::from_core(distribution)?,
        };
        envelope.validate_wire()?;
        Ok(envelope)
    }

    pub fn to_core(&self) -> Result<ThresholdRefreshDistribution> {
        self.binding.require_invoice_scope()?;
        self.distribution.to_core(self.binding.proof_context()?)
    }

    pub fn verify(&self) -> Result<()> {
        self.validate_wire()?;
        let distribution = self.to_core()?;
        verify_threshold_refresh_distribution(&distribution)
            .map_err(|error| core_error("threshold refresh verification", error))
    }
}

impl ValidateWire for ThresholdEnvelopeV1 {
    fn validate_wire(&self) -> Result<()> {
        self.binding.require_invoice_scope()?;
        self.distribution.validate_wire()
    }
}

impl CanonicalDigest for ThresholdEnvelopeV1 {
    fn canonical_digest(&self) -> Result<[u8; 32]> {
        self.validate_wire()?;
        let mut hasher = CanonicalHasher::new(b"threshold_refresh");
        self.binding.append_canonical(&mut hasher);
        self.distribution.append_canonical(&mut hasher)?;
        Ok(hasher.finish())
    }
}
