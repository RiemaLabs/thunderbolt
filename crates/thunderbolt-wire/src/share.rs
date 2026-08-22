use serde::{Deserialize, Serialize};
use thunderbolt_core::zkp::{verify_share_encryption, ShareEncryptionProof, ShareEncryptionStatement};

use crate::binding::BindingContext;
use crate::codec::{
    integer_from_wire, integer_to_wire, key_from_wire, key_to_wire, point_from_wire, point_to_wire,
    validate_ciphertext, validate_nonce, CanonicalDigest, CanonicalHasher, PaillierCiphertextHex, PaillierNonceHex,
    PaillierPublicKeyHex, PointHex, ProofResponseHex, ValidateWire,
};
use crate::error::core_error;
use crate::{Result, WireError};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShareStatementV1 {
    pub anchor_base: PointHex,
    pub recipient_key: PaillierPublicKeyHex,
    pub member_id: u32,
    pub committed_point: PointHex,
    pub ciphertext: PaillierCiphertextHex,
}

impl ShareStatementV1 {
    pub fn from_core(statement: &ShareEncryptionStatement) -> Result<Self> {
        let wire = Self {
            anchor_base: point_to_wire("share.statement.anchor_base", &statement.anchor_base)?,
            recipient_key: key_to_wire("share.statement.recipient_key", &statement.recipient_key)?,
            member_id: statement.member_id,
            committed_point: point_to_wire("share.statement.committed_point", &statement.committed_point)?,
            ciphertext: integer_to_wire("share.statement.ciphertext", &statement.ciphertext)?,
        };
        wire.validate_wire()?;
        Ok(wire)
    }

    pub fn to_core(&self, context: thunderbolt_core::zkp::ProofContext) -> Result<ShareEncryptionStatement> {
        if self.member_id == 0 {
            return Err(WireError::InvalidMessage {
                message: "share",
                reason: "committee member identifiers must be positive",
            });
        }
        Ok(ShareEncryptionStatement {
            context,
            anchor_base: point_from_wire("share.statement.anchor_base", &self.anchor_base)?,
            recipient_key: key_from_wire("share.statement.recipient_key", &self.recipient_key)?,
            member_id: self.member_id,
            committed_point: point_from_wire("share.statement.committed_point", &self.committed_point)?,
            ciphertext: integer_from_wire("share.statement.ciphertext", &self.ciphertext)?,
        })
    }

    fn append_canonical(&self, hasher: &mut CanonicalHasher) {
        hasher.bytes(self.anchor_base.as_bytes());
        hasher.bytes(self.recipient_key.as_bytes());
        hasher.u32(self.member_id);
        hasher.bytes(self.committed_point.as_bytes());
        hasher.bytes(self.ciphertext.as_bytes());
    }
}

impl ValidateWire for ShareStatementV1 {
    fn validate_wire(&self) -> Result<()> {
        let context = thunderbolt_core::zkp::ProofContext::invoice(b"wire-validation", b"invoice");
        let statement = self.to_core(context)?;
        validate_ciphertext(
            "share.statement.ciphertext",
            &statement.recipient_key,
            &statement.ciphertext,
        )?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShareProofV1 {
    pub a_point: PointHex,
    pub a_ciphertext: PaillierCiphertextHex,
    pub z: ProofResponseHex,
    pub tau: PaillierNonceHex,
}

impl ShareProofV1 {
    pub fn from_core(proof: &ShareEncryptionProof) -> Result<Self> {
        let wire = Self {
            a_point: point_to_wire("share.proof.a_point", &proof.a_point)?,
            a_ciphertext: integer_to_wire("share.proof.a_ciphertext", &proof.a_ciphertext)?,
            z: integer_to_wire("share.proof.z", &proof.z)?,
            tau: integer_to_wire("share.proof.tau", &proof.tau)?,
        };
        wire.validate_wire()?;
        Ok(wire)
    }

    pub fn to_core(&self) -> Result<ShareEncryptionProof> {
        Ok(ShareEncryptionProof {
            a_point: point_from_wire("share.proof.a_point", &self.a_point)?,
            a_ciphertext: integer_from_wire("share.proof.a_ciphertext", &self.a_ciphertext)?,
            z: integer_from_wire("share.proof.z", &self.z)?,
            tau: integer_from_wire("share.proof.tau", &self.tau)?,
        })
    }

    pub(crate) fn append_canonical(&self, hasher: &mut CanonicalHasher) {
        hasher.bytes(self.a_point.as_bytes());
        hasher.bytes(self.a_ciphertext.as_bytes());
        hasher.bytes(self.z.as_bytes());
        hasher.bytes(self.tau.as_bytes());
    }
}

impl ValidateWire for ShareProofV1 {
    fn validate_wire(&self) -> Result<()> {
        let _ = self.to_core()?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShareEnvelopeV1 {
    pub binding: BindingContext,
    pub statement: ShareStatementV1,
    pub proof: ShareProofV1,
}

impl ShareEnvelopeV1 {
    pub fn from_core(
        binding: BindingContext,
        statement: &ShareEncryptionStatement,
        proof: &ShareEncryptionProof,
    ) -> Result<Self> {
        binding.require_invoice_scope()?;
        binding.matches_core(&statement.context)?;
        let envelope = Self {
            binding,
            statement: ShareStatementV1::from_core(statement)?,
            proof: ShareProofV1::from_core(proof)?,
        };
        envelope.validate_wire()?;
        Ok(envelope)
    }

    pub fn to_core(&self) -> Result<(ShareEncryptionStatement, ShareEncryptionProof)> {
        self.binding.require_invoice_scope()?;
        let context = self.binding.proof_context()?;
        Ok((self.statement.to_core(context)?, self.proof.to_core()?))
    }

    pub fn verify(&self) -> Result<()> {
        self.validate_wire()?;
        let (statement, proof) = self.to_core()?;
        verify_share_encryption(&statement, &proof).map_err(|error| core_error("share verification", error))
    }
}

impl ValidateWire for ShareEnvelopeV1 {
    fn validate_wire(&self) -> Result<()> {
        self.binding.require_invoice_scope()?;
        let (statement, proof) = self.to_core()?;
        validate_ciphertext(
            "share.statement.ciphertext",
            &statement.recipient_key,
            &statement.ciphertext,
        )?;
        validate_ciphertext(
            "share.proof.a_ciphertext",
            &statement.recipient_key,
            &proof.a_ciphertext,
        )?;
        validate_nonce("share.proof.tau", &statement.recipient_key, &proof.tau)?;
        Ok(())
    }
}

impl CanonicalDigest for ShareEnvelopeV1 {
    fn canonical_digest(&self) -> Result<[u8; 32]> {
        self.validate_wire()?;
        let mut hasher = CanonicalHasher::new(b"share");
        self.binding.append_canonical(&mut hasher);
        self.statement.append_canonical(&mut hasher);
        self.proof.append_canonical(&mut hasher);
        Ok(hasher.finish())
    }
}
