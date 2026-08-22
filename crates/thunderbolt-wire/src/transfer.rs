use serde::{Deserialize, Serialize};
use thunderbolt_core::zkp::{verify_anchor_transition, verify_transfer, TransferProof, TransferStatement};

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
pub struct TransferStatementV1 {
    pub anchor_base: PointHex,
    pub bob_key: PaillierPublicKeyHex,
    pub current_anchor: PointHex,
    pub invoice_ciphertext: PaillierCiphertextHex,
    pub next_holder_ciphertext: PaillierCiphertextHex,
}

impl TransferStatementV1 {
    pub fn from_core(statement: &TransferStatement) -> Result<Self> {
        let wire = Self {
            anchor_base: point_to_wire("transfer.statement.anchor_base", &statement.anchor_base)?,
            bob_key: key_to_wire("transfer.statement.bob_key", &statement.bob_key)?,
            current_anchor: point_to_wire("transfer.statement.current_anchor", &statement.current_anchor)?,
            invoice_ciphertext: integer_to_wire(
                "transfer.statement.invoice_ciphertext",
                &statement.invoice_ciphertext,
            )?,
            next_holder_ciphertext: integer_to_wire(
                "transfer.statement.next_holder_ciphertext",
                &statement.next_holder_ciphertext,
            )?,
        };
        wire.validate_wire()?;
        Ok(wire)
    }

    pub fn to_core(&self, context: thunderbolt_core::zkp::ProofContext) -> Result<TransferStatement> {
        Ok(TransferStatement {
            context,
            anchor_base: point_from_wire("transfer.statement.anchor_base", &self.anchor_base)?,
            bob_key: key_from_wire("transfer.statement.bob_key", &self.bob_key)?,
            current_anchor: point_from_wire("transfer.statement.current_anchor", &self.current_anchor)?,
            invoice_ciphertext: integer_from_wire("transfer.statement.invoice_ciphertext", &self.invoice_ciphertext)?,
            next_holder_ciphertext: integer_from_wire(
                "transfer.statement.next_holder_ciphertext",
                &self.next_holder_ciphertext,
            )?,
        })
    }

    fn append_canonical(&self, hasher: &mut CanonicalHasher) {
        hasher.bytes(self.anchor_base.as_bytes());
        hasher.bytes(self.bob_key.as_bytes());
        hasher.bytes(self.current_anchor.as_bytes());
        hasher.bytes(self.invoice_ciphertext.as_bytes());
        hasher.bytes(self.next_holder_ciphertext.as_bytes());
    }
}

impl ValidateWire for TransferStatementV1 {
    fn validate_wire(&self) -> Result<()> {
        let context = thunderbolt_core::zkp::ProofContext::transfer(b"wire-validation", 0, b"invoice");
        let statement = self.to_core(context)?;
        validate_ciphertext(
            "transfer.statement.invoice_ciphertext",
            &statement.bob_key,
            &statement.invoice_ciphertext,
        )?;
        validate_ciphertext(
            "transfer.statement.next_holder_ciphertext",
            &statement.bob_key,
            &statement.next_holder_ciphertext,
        )?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransferProofV1 {
    pub a_anchor: PointHex,
    pub a_ciphertext: PaillierCiphertextHex,
    pub z: ProofResponseHex,
    pub tau: PaillierNonceHex,
}

impl TransferProofV1 {
    pub fn from_core(proof: &TransferProof) -> Result<Self> {
        let wire = Self {
            a_anchor: point_to_wire("transfer.proof.a_anchor", &proof.a_anchor)?,
            a_ciphertext: integer_to_wire("transfer.proof.a_ciphertext", &proof.a_ciphertext)?,
            z: integer_to_wire("transfer.proof.z", &proof.z)?,
            tau: integer_to_wire("transfer.proof.tau", &proof.tau)?,
        };
        wire.validate_wire()?;
        Ok(wire)
    }

    pub fn to_core(&self) -> Result<TransferProof> {
        Ok(TransferProof {
            a_anchor: point_from_wire("transfer.proof.a_anchor", &self.a_anchor)?,
            a_ciphertext: integer_from_wire("transfer.proof.a_ciphertext", &self.a_ciphertext)?,
            z: integer_from_wire("transfer.proof.z", &self.z)?,
            tau: integer_from_wire("transfer.proof.tau", &self.tau)?,
        })
    }

    fn append_canonical(&self, hasher: &mut CanonicalHasher) {
        hasher.bytes(self.a_anchor.as_bytes());
        hasher.bytes(self.a_ciphertext.as_bytes());
        hasher.bytes(self.z.as_bytes());
        hasher.bytes(self.tau.as_bytes());
    }
}

impl ValidateWire for TransferProofV1 {
    fn validate_wire(&self) -> Result<()> {
        let _ = self.to_core()?;
        Ok(())
    }
}

/// The public anchor update checked alongside every transfer proof.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AnchorTransitionV1 {
    pub current_anchor: PointHex,
    pub delta: PointHex,
    pub next_anchor: PointHex,
}

impl AnchorTransitionV1 {
    pub fn from_core(current_anchor: &secp::Point, delta: &secp::Point, next_anchor: &secp::Point) -> Result<Self> {
        let transition = Self {
            current_anchor: point_to_wire("transfer.anchor_transition.current_anchor", current_anchor)?,
            delta: point_to_wire("transfer.anchor_transition.delta", delta)?,
            next_anchor: point_to_wire("transfer.anchor_transition.next_anchor", next_anchor)?,
        };
        transition.validate_wire()?;
        Ok(transition)
    }

    pub fn to_core(&self) -> Result<(secp::Point, secp::Point, secp::Point)> {
        Ok((
            point_from_wire("transfer.anchor_transition.current_anchor", &self.current_anchor)?,
            point_from_wire("transfer.anchor_transition.delta", &self.delta)?,
            point_from_wire("transfer.anchor_transition.next_anchor", &self.next_anchor)?,
        ))
    }

    pub fn verify(&self) -> Result<()> {
        self.validate_wire()?;
        let (current_anchor, delta, next_anchor) = self.to_core()?;
        verify_anchor_transition(&current_anchor, &delta, &next_anchor)
            .map_err(|error| core_error("anchor transition verification", error))
    }

    fn append_canonical(&self, hasher: &mut CanonicalHasher) {
        hasher.bytes(self.current_anchor.as_bytes());
        hasher.bytes(self.delta.as_bytes());
        hasher.bytes(self.next_anchor.as_bytes());
    }
}

impl ValidateWire for AnchorTransitionV1 {
    fn validate_wire(&self) -> Result<()> {
        let _ = self.to_core()?;
        Ok(())
    }
}

impl CanonicalDigest for AnchorTransitionV1 {
    fn canonical_digest(&self) -> Result<[u8; 32]> {
        self.validate_wire()?;
        let mut hasher = CanonicalHasher::new(b"anchor_transition");
        self.append_canonical(&mut hasher);
        Ok(hasher.finish())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransferEnvelopeV1 {
    pub binding: BindingContext,
    pub statement: TransferStatementV1,
    pub proof: TransferProofV1,
    pub anchor_transition: AnchorTransitionV1,
}

impl TransferEnvelopeV1 {
    pub fn from_core(
        binding: BindingContext,
        statement: &TransferStatement,
        proof: &TransferProof,
        delta: &secp::Point,
        next_anchor: &secp::Point,
    ) -> Result<Self> {
        binding.require_transfer_scope()?;
        binding.matches_core(&statement.context)?;
        let envelope = Self {
            binding,
            statement: TransferStatementV1::from_core(statement)?,
            proof: TransferProofV1::from_core(proof)?,
            anchor_transition: AnchorTransitionV1::from_core(&statement.current_anchor, delta, next_anchor)?,
        };
        envelope.validate_wire()?;
        Ok(envelope)
    }

    pub fn to_core(&self) -> Result<(TransferStatement, TransferProof)> {
        self.binding.require_transfer_scope()?;
        let context = self.binding.proof_context()?;
        Ok((self.statement.to_core(context)?, self.proof.to_core()?))
    }

    pub fn verify(&self) -> Result<()> {
        self.validate_wire()?;
        let (statement, proof) = self.to_core()?;
        verify_transfer(&statement, &proof).map_err(|error| core_error("transfer verification", error))?;
        self.anchor_transition.verify()
    }
}

impl ValidateWire for TransferEnvelopeV1 {
    fn validate_wire(&self) -> Result<()> {
        self.binding.require_transfer_scope()?;
        if self.statement.current_anchor != self.anchor_transition.current_anchor {
            return Err(WireError::InvalidMessage {
                message: "transfer",
                reason: "proof statement and anchor transition must use the same current anchor",
            });
        }
        let (statement, proof) = self.to_core()?;
        let _ = self.anchor_transition.to_core()?;
        validate_ciphertext(
            "transfer.statement.invoice_ciphertext",
            &statement.bob_key,
            &statement.invoice_ciphertext,
        )?;
        validate_ciphertext(
            "transfer.statement.next_holder_ciphertext",
            &statement.bob_key,
            &statement.next_holder_ciphertext,
        )?;
        validate_ciphertext("transfer.proof.a_ciphertext", &statement.bob_key, &proof.a_ciphertext)?;
        validate_nonce("transfer.proof.tau", &statement.bob_key, &proof.tau)?;
        Ok(())
    }
}

impl CanonicalDigest for TransferEnvelopeV1 {
    fn canonical_digest(&self) -> Result<[u8; 32]> {
        self.validate_wire()?;
        let mut hasher = CanonicalHasher::new(b"transfer");
        self.binding.append_canonical(&mut hasher);
        self.statement.append_canonical(&mut hasher);
        self.proof.append_canonical(&mut hasher);
        self.anchor_transition.append_canonical(&mut hasher);
        Ok(hasher.finish())
    }
}
