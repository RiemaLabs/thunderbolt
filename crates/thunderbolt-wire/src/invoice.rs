use serde::{Deserialize, Serialize};
use thunderbolt_core::zkp::{verify_invoice, InvoiceProof, InvoiceStatement};

use crate::binding::BindingContext;
use crate::codec::{
    integer_from_wire, integer_to_wire, key_from_wire, key_to_wire, point_from_wire, point_to_wire,
    validate_ciphertext, validate_nonce, CanonicalDigest, CanonicalHasher, PaillierCiphertextHex, PaillierNonceHex,
    PaillierPublicKeyHex, PointHex, ProofResponseHex, ValidateWire,
};
use crate::error::core_error;
use crate::Result;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InvoiceStatementV1 {
    pub anchor_base: PointHex,
    pub bob_key: PaillierPublicKeyHex,
    pub committee_key: PaillierPublicKeyHex,
    pub delta: PointHex,
    pub bob_ciphertext: PaillierCiphertextHex,
    pub committee_ciphertext: PaillierCiphertextHex,
}

impl InvoiceStatementV1 {
    pub fn from_core(statement: &InvoiceStatement) -> Result<Self> {
        let wire = Self {
            anchor_base: point_to_wire("invoice.statement.anchor_base", &statement.anchor_base)?,
            bob_key: key_to_wire("invoice.statement.bob_key", &statement.bob_key)?,
            committee_key: key_to_wire("invoice.statement.committee_key", &statement.committee_key)?,
            delta: point_to_wire("invoice.statement.delta", &statement.delta)?,
            bob_ciphertext: integer_to_wire("invoice.statement.bob_ciphertext", &statement.bob_ciphertext)?,
            committee_ciphertext: integer_to_wire(
                "invoice.statement.committee_ciphertext",
                &statement.committee_ciphertext,
            )?,
        };
        wire.validate_wire()?;
        Ok(wire)
    }

    pub fn to_core(&self, context: thunderbolt_core::zkp::ProofContext) -> Result<InvoiceStatement> {
        Ok(InvoiceStatement {
            context,
            anchor_base: point_from_wire("invoice.statement.anchor_base", &self.anchor_base)?,
            bob_key: key_from_wire("invoice.statement.bob_key", &self.bob_key)?,
            committee_key: key_from_wire("invoice.statement.committee_key", &self.committee_key)?,
            delta: point_from_wire("invoice.statement.delta", &self.delta)?,
            bob_ciphertext: integer_from_wire("invoice.statement.bob_ciphertext", &self.bob_ciphertext)?,
            committee_ciphertext: integer_from_wire(
                "invoice.statement.committee_ciphertext",
                &self.committee_ciphertext,
            )?,
        })
    }

    fn append_canonical(&self, hasher: &mut CanonicalHasher) {
        hasher.bytes(self.anchor_base.as_bytes());
        hasher.bytes(self.bob_key.as_bytes());
        hasher.bytes(self.committee_key.as_bytes());
        hasher.bytes(self.delta.as_bytes());
        hasher.bytes(self.bob_ciphertext.as_bytes());
        hasher.bytes(self.committee_ciphertext.as_bytes());
    }
}

impl ValidateWire for InvoiceStatementV1 {
    fn validate_wire(&self) -> Result<()> {
        let context = thunderbolt_core::zkp::ProofContext::invoice(b"wire-validation", b"invoice");
        let statement = self.to_core(context)?;
        validate_ciphertext(
            "invoice.statement.bob_ciphertext",
            &statement.bob_key,
            &statement.bob_ciphertext,
        )?;
        validate_ciphertext(
            "invoice.statement.committee_ciphertext",
            &statement.committee_key,
            &statement.committee_ciphertext,
        )?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InvoiceProofV1 {
    pub a_delta: PointHex,
    pub a_bob: PaillierCiphertextHex,
    pub a_committee: PaillierCiphertextHex,
    pub z: ProofResponseHex,
    pub tau_bob: PaillierNonceHex,
    pub tau_committee: PaillierNonceHex,
}

impl InvoiceProofV1 {
    pub fn from_core(proof: &InvoiceProof) -> Result<Self> {
        let wire = Self {
            a_delta: point_to_wire("invoice.proof.a_delta", &proof.a_delta)?,
            a_bob: integer_to_wire("invoice.proof.a_bob", &proof.a_bob)?,
            a_committee: integer_to_wire("invoice.proof.a_committee", &proof.a_committee)?,
            z: integer_to_wire("invoice.proof.z", &proof.z)?,
            tau_bob: integer_to_wire("invoice.proof.tau_bob", &proof.tau_bob)?,
            tau_committee: integer_to_wire("invoice.proof.tau_committee", &proof.tau_committee)?,
        };
        wire.validate_wire()?;
        Ok(wire)
    }

    pub fn to_core(&self) -> Result<InvoiceProof> {
        Ok(InvoiceProof {
            a_delta: point_from_wire("invoice.proof.a_delta", &self.a_delta)?,
            a_bob: integer_from_wire("invoice.proof.a_bob", &self.a_bob)?,
            a_committee: integer_from_wire("invoice.proof.a_committee", &self.a_committee)?,
            z: integer_from_wire("invoice.proof.z", &self.z)?,
            tau_bob: integer_from_wire("invoice.proof.tau_bob", &self.tau_bob)?,
            tau_committee: integer_from_wire("invoice.proof.tau_committee", &self.tau_committee)?,
        })
    }

    fn append_canonical(&self, hasher: &mut CanonicalHasher) {
        hasher.bytes(self.a_delta.as_bytes());
        hasher.bytes(self.a_bob.as_bytes());
        hasher.bytes(self.a_committee.as_bytes());
        hasher.bytes(self.z.as_bytes());
        hasher.bytes(self.tau_bob.as_bytes());
        hasher.bytes(self.tau_committee.as_bytes());
    }
}

impl ValidateWire for InvoiceProofV1 {
    fn validate_wire(&self) -> Result<()> {
        let _ = self.to_core()?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InvoiceEnvelopeV1 {
    pub binding: BindingContext,
    pub statement: InvoiceStatementV1,
    pub proof: InvoiceProofV1,
}

impl InvoiceEnvelopeV1 {
    pub fn from_core(binding: BindingContext, statement: &InvoiceStatement, proof: &InvoiceProof) -> Result<Self> {
        binding.require_invoice_scope()?;
        binding.matches_core(&statement.context)?;
        let envelope = Self {
            binding,
            statement: InvoiceStatementV1::from_core(statement)?,
            proof: InvoiceProofV1::from_core(proof)?,
        };
        envelope.validate_wire()?;
        Ok(envelope)
    }

    pub fn to_core(&self) -> Result<(InvoiceStatement, InvoiceProof)> {
        self.binding.require_invoice_scope()?;
        let context = self.binding.proof_context()?;
        Ok((self.statement.to_core(context)?, self.proof.to_core()?))
    }

    pub fn verify(&self) -> Result<()> {
        self.validate_wire()?;
        let (statement, proof) = self.to_core()?;
        verify_invoice(&statement, &proof).map_err(|error| core_error("invoice verification", error))
    }
}

impl ValidateWire for InvoiceEnvelopeV1 {
    fn validate_wire(&self) -> Result<()> {
        self.binding.require_invoice_scope()?;
        let (statement, proof) = self.to_core()?;
        validate_ciphertext(
            "invoice.statement.bob_ciphertext",
            &statement.bob_key,
            &statement.bob_ciphertext,
        )?;
        validate_ciphertext(
            "invoice.statement.committee_ciphertext",
            &statement.committee_key,
            &statement.committee_ciphertext,
        )?;
        validate_ciphertext("invoice.proof.a_bob", &statement.bob_key, &proof.a_bob)?;
        validate_ciphertext(
            "invoice.proof.a_committee",
            &statement.committee_key,
            &proof.a_committee,
        )?;
        validate_nonce("invoice.proof.tau_bob", &statement.bob_key, &proof.tau_bob)?;
        validate_nonce(
            "invoice.proof.tau_committee",
            &statement.committee_key,
            &proof.tau_committee,
        )?;
        Ok(())
    }
}

impl CanonicalDigest for InvoiceEnvelopeV1 {
    fn canonical_digest(&self) -> Result<[u8; 32]> {
        self.validate_wire()?;
        let mut hasher = CanonicalHasher::new(b"invoice");
        self.binding.append_canonical(&mut hasher);
        self.statement.append_canonical(&mut hasher);
        self.proof.append_canonical(&mut hasher);
        Ok(hasher.finish())
    }
}
