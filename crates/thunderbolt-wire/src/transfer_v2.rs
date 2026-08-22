use serde::{Deserialize, Serialize};
use thunderbolt_core::paillier::PaillierModulusProfile;
use thunderbolt_core::zkp::{verify_anchor_transition, verify_transfer_with_profile, TransferProof, TransferStatement};

use crate::codec::{CanonicalDigest, CanonicalHasher, ValidateWire};
use crate::error::core_error;
use crate::v2_values::{
    decode_ciphertext_v2, decode_key_v2, decode_nonce_v2, decode_point_v2, decode_response_v2, derive_proof_context_v2,
    encode_ciphertext_v2, encode_key_v2, encode_nonce_v2, encode_point_v2, encode_response_v2,
    require_matching_context, validate_modulus, validate_nonzero_fixed, validate_point_v2, validate_response,
    PaillierCiphertextBytesV2Input, PaillierModulusBytesV2Input, PaillierModulusProfileV2Input,
    PaillierNonceBytesV2Input, ProofResponseBytesV2Input,
};
use crate::{
    OperationBindingV2, PaillierCiphertextBytesV2, PaillierModulusBytesV2, PaillierModulusProfileV2,
    PaillierNonceBytesV2, PointHex, ProofResponseBytesV2, Result, WireError,
};

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TransferStatementV2 {
    pub anchor_base: PointHex,
    pub recipient_key: PaillierModulusBytesV2,
    pub current_anchor: PointHex,
    pub invoice_ciphertext: PaillierCiphertextBytesV2,
    pub next_holder_ciphertext: PaillierCiphertextBytesV2,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TransferStatementV2Input {
    anchor_base: PointHex,
    recipient_key: PaillierModulusBytesV2Input,
    current_anchor: PointHex,
    invoice_ciphertext: PaillierCiphertextBytesV2Input,
    next_holder_ciphertext: PaillierCiphertextBytesV2Input,
}

impl TransferStatementV2 {
    fn from_input(input: TransferStatementV2Input) -> Result<Self> {
        let value = Self {
            anchor_base: input.anchor_base,
            recipient_key: PaillierModulusBytesV2::from_bytes(
                "transfer_v2.statement.recipient_key",
                input.recipient_key.as_bytes(),
            )?,
            current_anchor: input.current_anchor,
            invoice_ciphertext: PaillierCiphertextBytesV2::from_bytes(
                "transfer_v2.statement.invoice_ciphertext",
                input.invoice_ciphertext.as_bytes(),
            )?,
            next_holder_ciphertext: PaillierCiphertextBytesV2::from_bytes(
                "transfer_v2.statement.next_holder_ciphertext",
                input.next_holder_ciphertext.as_bytes(),
            )?,
        };
        value.validate_wire()?;
        Ok(value)
    }

    pub fn from_core(statement: &TransferStatement) -> Result<Self> {
        let recipient_key = encode_key_v2(&statement.bob_key)?;
        let value = Self {
            anchor_base: encode_point_v2("transfer_v2.statement.anchor_base", &statement.anchor_base)?,
            recipient_key,
            current_anchor: encode_point_v2("transfer_v2.statement.current_anchor", &statement.current_anchor)?,
            invoice_ciphertext: encode_ciphertext_v2(&statement.bob_key, &statement.invoice_ciphertext)?,
            next_holder_ciphertext: encode_ciphertext_v2(&statement.bob_key, &statement.next_holder_ciphertext)?,
        };
        value.validate_wire()?;
        Ok(value)
    }

    fn append_canonical(&self, hasher: &mut CanonicalHasher) {
        hasher.bytes(self.anchor_base.as_bytes());
        hasher.bytes(self.recipient_key.as_bytes());
        hasher.bytes(self.current_anchor.as_bytes());
        hasher.bytes(self.invoice_ciphertext.as_bytes());
        hasher.bytes(self.next_holder_ciphertext.as_bytes());
    }
}

impl ValidateWire for TransferStatementV2 {
    fn validate_wire(&self) -> Result<()> {
        validate_modulus("transfer_v2.statement.recipient_key", &self.recipient_key)?;
        validate_nonzero_fixed(
            "transfer_v2.statement.invoice_ciphertext",
            self.invoice_ciphertext.as_bytes(),
        )?;
        validate_nonzero_fixed(
            "transfer_v2.statement.next_holder_ciphertext",
            self.next_holder_ciphertext.as_bytes(),
        )?;
        validate_point_v2("transfer_v2.statement.anchor_base", &self.anchor_base)?;
        validate_point_v2("transfer_v2.statement.current_anchor", &self.current_anchor)?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TransferProofV2 {
    pub a_anchor: PointHex,
    pub a_ciphertext: PaillierCiphertextBytesV2,
    pub z: ProofResponseBytesV2,
    pub tau: PaillierNonceBytesV2,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TransferProofV2Input {
    a_anchor: PointHex,
    a_ciphertext: PaillierCiphertextBytesV2Input,
    z: ProofResponseBytesV2Input,
    tau: PaillierNonceBytesV2Input,
}

impl TransferProofV2 {
    fn from_input(input: TransferProofV2Input) -> Result<Self> {
        let value = Self {
            a_anchor: input.a_anchor,
            a_ciphertext: PaillierCiphertextBytesV2::from_bytes(
                "transfer_v2.proof.a_ciphertext",
                input.a_ciphertext.as_bytes(),
            )?,
            z: ProofResponseBytesV2::from_bytes("transfer_v2.proof.z", input.z.as_bytes())?,
            tau: PaillierNonceBytesV2::from_bytes("transfer_v2.proof.tau", input.tau.as_bytes())?,
        };
        value.validate_wire()?;
        Ok(value)
    }

    pub fn from_core(statement: &TransferStatement, proof: &TransferProof) -> Result<Self> {
        let _ = encode_key_v2(&statement.bob_key)?;
        let value = Self {
            a_anchor: encode_point_v2("transfer_v2.proof.a_anchor", &proof.a_anchor)?,
            a_ciphertext: encode_ciphertext_v2(&statement.bob_key, &proof.a_ciphertext)?,
            z: encode_response_v2(&proof.z)?,
            tau: encode_nonce_v2(&statement.bob_key, &proof.tau)?,
        };
        value.validate_wire()?;
        Ok(value)
    }

    fn append_canonical(&self, hasher: &mut CanonicalHasher) {
        hasher.bytes(self.a_anchor.as_bytes());
        hasher.bytes(self.a_ciphertext.as_bytes());
        hasher.bytes(self.z.as_bytes());
        hasher.bytes(self.tau.as_bytes());
    }
}

impl ValidateWire for TransferProofV2 {
    fn validate_wire(&self) -> Result<()> {
        validate_nonzero_fixed("transfer_v2.proof.a_ciphertext", self.a_ciphertext.as_bytes())?;
        validate_nonzero_fixed("transfer_v2.proof.tau", self.tau.as_bytes())?;
        validate_response("transfer_v2.proof.z", &self.z)?;
        validate_point_v2("transfer_v2.proof.a_anchor", &self.a_anchor)?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AnchorTransitionV2 {
    pub current_anchor: PointHex,
    pub delta: PointHex,
    pub next_anchor: PointHex,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AnchorTransitionV2Input {
    current_anchor: PointHex,
    delta: PointHex,
    next_anchor: PointHex,
}

impl AnchorTransitionV2 {
    fn from_input(input: AnchorTransitionV2Input) -> Result<Self> {
        let value = Self {
            current_anchor: input.current_anchor,
            delta: input.delta,
            next_anchor: input.next_anchor,
        };
        value.validate_wire()?;
        Ok(value)
    }

    pub fn from_core(current_anchor: &secp::Point, delta: &secp::Point, next_anchor: &secp::Point) -> Result<Self> {
        let value = Self {
            current_anchor: encode_point_v2("transfer_v2.anchor_transition.current_anchor", current_anchor)?,
            delta: encode_point_v2("transfer_v2.anchor_transition.delta", delta)?,
            next_anchor: encode_point_v2("transfer_v2.anchor_transition.next_anchor", next_anchor)?,
        };
        value.validate_wire()?;
        Ok(value)
    }

    pub fn to_core(&self) -> Result<(secp::Point, secp::Point, secp::Point)> {
        self.validate_wire()?;
        Ok((
            decode_point_v2("transfer_v2.anchor_transition.current_anchor", &self.current_anchor)?,
            decode_point_v2("transfer_v2.anchor_transition.delta", &self.delta)?,
            decode_point_v2("transfer_v2.anchor_transition.next_anchor", &self.next_anchor)?,
        ))
    }

    fn append_canonical(&self, hasher: &mut CanonicalHasher) {
        hasher.bytes(self.current_anchor.as_bytes());
        hasher.bytes(self.delta.as_bytes());
        hasher.bytes(self.next_anchor.as_bytes());
    }
}

impl ValidateWire for AnchorTransitionV2 {
    fn validate_wire(&self) -> Result<()> {
        validate_point_v2("transfer_v2.anchor_transition.current_anchor", &self.current_anchor)?;
        validate_point_v2("transfer_v2.anchor_transition.delta", &self.delta)?;
        validate_point_v2("transfer_v2.anchor_transition.next_anchor", &self.next_anchor)?;
        Ok(())
    }
}

impl CanonicalDigest for AnchorTransitionV2 {
    fn canonical_digest(&self) -> Result<[u8; 32]> {
        self.validate_wire()?;
        let mut hasher = CanonicalHasher::new(b"anchor_transition_v2");
        self.append_canonical(&mut hasher);
        Ok(hasher.finish())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TransferEnvelopeV2 {
    pub binding: OperationBindingV2,
    pub paillier_profile: PaillierModulusProfileV2,
    pub statement: TransferStatementV2,
    pub proof: TransferProofV2,
    pub anchor_transition: AnchorTransitionV2,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TransferEnvelopeV2Input {
    binding: OperationBindingV2,
    paillier_profile: PaillierModulusProfileV2Input,
    statement: TransferStatementV2Input,
    proof: TransferProofV2Input,
    anchor_transition: AnchorTransitionV2Input,
}

impl TransferEnvelopeV2 {
    pub(crate) fn from_input(input: TransferEnvelopeV2Input) -> Result<Self> {
        let value = Self {
            binding: input.binding,
            paillier_profile: PaillierModulusProfileV2::from_input(input.paillier_profile),
            statement: TransferStatementV2::from_input(input.statement)?,
            proof: TransferProofV2::from_input(input.proof)?,
            anchor_transition: AnchorTransitionV2::from_input(input.anchor_transition)?,
        };
        value.validate_wire()?;
        Ok(value)
    }

    pub fn from_core(
        binding: OperationBindingV2,
        statement: &TransferStatement,
        proof: &TransferProof,
        delta: &secp::Point,
        next_anchor: &secp::Point,
    ) -> Result<Self> {
        binding.validate_wire()?;
        if !matches!(binding, OperationBindingV2::Transfer { .. }) {
            return Err(WireError::InvalidBinding {
                reason: "protocol v2 Transfer envelope requires a transfer operation binding",
            });
        }
        let expected_context = Self::proof_context_for(&binding)?;
        require_matching_context(&expected_context, &statement.context)?;
        let value = Self {
            binding,
            paillier_profile: PaillierModulusProfileV2::ProtocolV2Production3072,
            statement: TransferStatementV2::from_core(statement)?,
            proof: TransferProofV2::from_core(statement, proof)?,
            anchor_transition: AnchorTransitionV2::from_core(&statement.current_anchor, delta, next_anchor)?,
        };
        value.validate_wire()?;
        Ok(value)
    }

    /// Derives the Fiat-Shamir context from the complete transfer operation,
    /// including its positive step and mandatory production profile.
    pub fn proof_context_for(binding: &OperationBindingV2) -> Result<thunderbolt_core::zkp::ProofContext> {
        binding.validate_wire()?;
        if !matches!(binding, OperationBindingV2::Transfer { .. }) {
            return Err(WireError::InvalidBinding {
                reason: "protocol v2 Transfer proof context requires a transfer operation",
            });
        }
        derive_proof_context_v2(binding, b"transfer", &[])
    }

    /// Returns this envelope's exact Fiat-Shamir context.
    pub fn proof_context(&self) -> Result<thunderbolt_core::zkp::ProofContext> {
        Self::proof_context_for(&self.binding)
    }

    /// Converts through the core raw-profile ingress and never falls back to
    /// the legacy 2048-bit profile.
    pub fn to_core(&self) -> Result<(TransferStatement, TransferProof)> {
        self.validate_wire()?;
        let context = self.proof_context()?;
        let recipient_key = decode_key_v2("transfer_v2.statement.recipient_key", &self.statement.recipient_key)?;
        let statement = TransferStatement {
            context,
            anchor_base: decode_point_v2("transfer_v2.statement.anchor_base", &self.statement.anchor_base)?,
            current_anchor: decode_point_v2("transfer_v2.statement.current_anchor", &self.statement.current_anchor)?,
            invoice_ciphertext: decode_ciphertext_v2(&recipient_key, &self.statement.invoice_ciphertext)?,
            next_holder_ciphertext: decode_ciphertext_v2(&recipient_key, &self.statement.next_holder_ciphertext)?,
            bob_key: recipient_key.clone(),
        };
        let proof = TransferProof {
            a_anchor: decode_point_v2("transfer_v2.proof.a_anchor", &self.proof.a_anchor)?,
            a_ciphertext: decode_ciphertext_v2(&recipient_key, &self.proof.a_ciphertext)?,
            z: decode_response_v2(&self.proof.z),
            tau: decode_nonce_v2(&recipient_key, &self.proof.tau)?,
        };
        Ok((statement, proof))
    }

    pub fn verify(&self) -> Result<()> {
        let (statement, proof) = self.to_core()?;
        verify_transfer_with_profile(PaillierModulusProfile::ProtocolV2Production3072, &statement, &proof)
            .map_err(|source| core_error("protocol v2 transfer verification", source))?;
        let (current_anchor, delta, next_anchor) = self.anchor_transition.to_core()?;
        verify_anchor_transition(&current_anchor, &delta, &next_anchor)
            .map_err(|source| core_error("protocol v2 anchor transition verification", source))
    }

    fn append_canonical(&self, hasher: &mut CanonicalHasher) {
        self.binding.append_canonical(hasher);
        hasher.u8(self.paillier_profile.core() as u8);
        self.statement.append_canonical(hasher);
        self.proof.append_canonical(hasher);
        self.anchor_transition.append_canonical(hasher);
    }
}

impl ValidateWire for TransferEnvelopeV2 {
    fn validate_wire(&self) -> Result<()> {
        self.binding.validate_wire()?;
        if !matches!(self.binding, OperationBindingV2::Transfer { .. }) {
            return Err(WireError::InvalidBinding {
                reason: "protocol v2 Transfer envelope requires a transfer operation binding",
            });
        }
        self.statement.validate_wire()?;
        self.proof.validate_wire()?;
        self.anchor_transition.validate_wire()?;
        if self.statement.current_anchor != self.anchor_transition.current_anchor {
            return Err(WireError::InvalidMessage {
                message: "protocol v2 transfer",
                reason: "proof statement and anchor transition must use the same current anchor",
            });
        }
        Ok(())
    }
}

impl CanonicalDigest for TransferEnvelopeV2 {
    fn canonical_digest(&self) -> Result<[u8; 32]> {
        self.validate_wire()?;
        let mut hasher = CanonicalHasher::new(b"transfer_v2");
        self.append_canonical(&mut hasher);
        Ok(hasher.finish())
    }
}
