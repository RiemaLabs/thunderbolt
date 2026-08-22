use serde::{Deserialize, Serialize};
use thunderbolt_core::zkp::{
    verify_invoice_3072, CertifiedKeyResolver3072, CertifiedKeyRole3072, InvoiceProof3072, InvoiceStatement3072,
};

use crate::codec::{CanonicalDigest, CanonicalHasher, ValidateWire};
use crate::error::core_error;
use crate::v2_values::{
    decode_ciphertext_v2, decode_nonce_v2, decode_point_v2, decode_response_v2, derive_proof_context_v2,
    encode_ciphertext_v2, encode_key_v2, encode_nonce_v2, encode_point_v2, encode_response_v2,
    require_matching_context, resolve_key_v2, validate_modulus, validate_nonzero_fixed, validate_point_v2,
    validate_response, PaillierCiphertextBytesV2Input, PaillierModulusBytesV2Input, PaillierModulusProfileV2Input,
    PaillierNonceBytesV2Input, ProofResponseBytesV2Input,
};
use crate::{
    OperationBindingV2, PaillierCiphertextBytesV2, PaillierModulusBytesV2, PaillierModulusProfileV2,
    PaillierNonceBytesV2, PointHex, ProofResponseBytesV2, Result, WireError,
};

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
/// Public v2 Invoice statement returned only by the bounded request decoder.
///
/// ```compile_fail
/// use thunderbolt_wire::InvoiceStatementV2;
/// let _: InvoiceStatementV2 = serde_json::from_str("{}").unwrap();
/// ```
pub struct InvoiceStatementV2 {
    pub anchor_base: PointHex,
    pub recipient_key: PaillierModulusBytesV2,
    pub committee_key: PaillierModulusBytesV2,
    pub delta: PointHex,
    pub recipient_ciphertext: PaillierCiphertextBytesV2,
    pub committee_ciphertext: PaillierCiphertextBytesV2,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct InvoiceStatementV2Input {
    anchor_base: PointHex,
    recipient_key: PaillierModulusBytesV2Input,
    committee_key: PaillierModulusBytesV2Input,
    delta: PointHex,
    recipient_ciphertext: PaillierCiphertextBytesV2Input,
    committee_ciphertext: PaillierCiphertextBytesV2Input,
}

impl InvoiceStatementV2 {
    fn from_input(input: InvoiceStatementV2Input) -> Result<Self> {
        let value = Self {
            anchor_base: input.anchor_base,
            recipient_key: PaillierModulusBytesV2::from_bytes(
                "invoice_v2.statement.recipient_key",
                input.recipient_key.as_bytes(),
            )?,
            committee_key: PaillierModulusBytesV2::from_bytes(
                "invoice_v2.statement.committee_key",
                input.committee_key.as_bytes(),
            )?,
            delta: input.delta,
            recipient_ciphertext: PaillierCiphertextBytesV2::from_bytes(
                "invoice_v2.statement.recipient_ciphertext",
                input.recipient_ciphertext.as_bytes(),
            )?,
            committee_ciphertext: PaillierCiphertextBytesV2::from_bytes(
                "invoice_v2.statement.committee_ciphertext",
                input.committee_ciphertext.as_bytes(),
            )?,
        };
        value.validate_wire()?;
        Ok(value)
    }

    pub fn from_core(statement: &InvoiceStatement3072) -> Result<Self> {
        let recipient_key = encode_key_v2(&statement.recipient_key)?;
        let committee_key = encode_key_v2(&statement.committee_key)?;
        let value = Self {
            anchor_base: encode_point_v2("invoice_v2.statement.anchor_base", &statement.anchor_base)?,
            recipient_ciphertext: encode_ciphertext_v2(&statement.recipient_key, &statement.recipient_ciphertext)?,
            committee_ciphertext: encode_ciphertext_v2(&statement.committee_key, &statement.committee_ciphertext)?,
            recipient_key,
            committee_key,
            delta: encode_point_v2("invoice_v2.statement.delta", &statement.delta)?,
        };
        value.validate_wire()?;
        Ok(value)
    }

    fn append_canonical(&self, hasher: &mut CanonicalHasher) {
        hasher.bytes(self.anchor_base.as_bytes());
        hasher.bytes(self.recipient_key.as_bytes());
        hasher.bytes(self.committee_key.as_bytes());
        hasher.bytes(self.delta.as_bytes());
        hasher.bytes(self.recipient_ciphertext.as_bytes());
        hasher.bytes(self.committee_ciphertext.as_bytes());
    }
}

impl ValidateWire for InvoiceStatementV2 {
    fn validate_wire(&self) -> Result<()> {
        validate_modulus("invoice_v2.statement.recipient_key", &self.recipient_key)?;
        validate_modulus("invoice_v2.statement.committee_key", &self.committee_key)?;
        validate_nonzero_fixed(
            "invoice_v2.statement.recipient_ciphertext",
            self.recipient_ciphertext.as_bytes(),
        )?;
        validate_nonzero_fixed(
            "invoice_v2.statement.committee_ciphertext",
            self.committee_ciphertext.as_bytes(),
        )?;
        validate_point_v2("invoice_v2.statement.anchor_base", &self.anchor_base)?;
        validate_point_v2("invoice_v2.statement.delta", &self.delta)?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InvoiceProofV2 {
    pub a_delta: PointHex,
    pub a_recipient: PaillierCiphertextBytesV2,
    pub a_committee: PaillierCiphertextBytesV2,
    pub z: ProofResponseBytesV2,
    pub tau_recipient: PaillierNonceBytesV2,
    pub tau_committee: PaillierNonceBytesV2,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct InvoiceProofV2Input {
    a_delta: PointHex,
    a_recipient: PaillierCiphertextBytesV2Input,
    a_committee: PaillierCiphertextBytesV2Input,
    z: ProofResponseBytesV2Input,
    tau_recipient: PaillierNonceBytesV2Input,
    tau_committee: PaillierNonceBytesV2Input,
}

impl InvoiceProofV2 {
    fn from_input(input: InvoiceProofV2Input) -> Result<Self> {
        let value = Self {
            a_delta: input.a_delta,
            a_recipient: PaillierCiphertextBytesV2::from_bytes(
                "invoice_v2.proof.a_recipient",
                input.a_recipient.as_bytes(),
            )?,
            a_committee: PaillierCiphertextBytesV2::from_bytes(
                "invoice_v2.proof.a_committee",
                input.a_committee.as_bytes(),
            )?,
            z: ProofResponseBytesV2::from_bytes("invoice_v2.proof.z", input.z.as_bytes())?,
            tau_recipient: PaillierNonceBytesV2::from_bytes(
                "invoice_v2.proof.tau_recipient",
                input.tau_recipient.as_bytes(),
            )?,
            tau_committee: PaillierNonceBytesV2::from_bytes(
                "invoice_v2.proof.tau_committee",
                input.tau_committee.as_bytes(),
            )?,
        };
        value.validate_wire()?;
        Ok(value)
    }

    pub fn from_core(statement: &InvoiceStatement3072, proof: &InvoiceProof3072) -> Result<Self> {
        let _ = encode_key_v2(&statement.recipient_key)?;
        let _ = encode_key_v2(&statement.committee_key)?;
        let value = Self {
            a_delta: encode_point_v2("invoice_v2.proof.a_delta", &proof.a_delta)?,
            a_recipient: encode_ciphertext_v2(&statement.recipient_key, &proof.a_recipient)?,
            a_committee: encode_ciphertext_v2(&statement.committee_key, &proof.a_committee)?,
            z: encode_response_v2(&proof.z)?,
            tau_recipient: encode_nonce_v2(&statement.recipient_key, &proof.tau_recipient)?,
            tau_committee: encode_nonce_v2(&statement.committee_key, &proof.tau_committee)?,
        };
        value.validate_wire()?;
        Ok(value)
    }

    fn append_canonical(&self, hasher: &mut CanonicalHasher) {
        hasher.bytes(self.a_delta.as_bytes());
        hasher.bytes(self.a_recipient.as_bytes());
        hasher.bytes(self.a_committee.as_bytes());
        hasher.bytes(self.z.as_bytes());
        hasher.bytes(self.tau_recipient.as_bytes());
        hasher.bytes(self.tau_committee.as_bytes());
    }
}

impl ValidateWire for InvoiceProofV2 {
    fn validate_wire(&self) -> Result<()> {
        validate_nonzero_fixed("invoice_v2.proof.a_recipient", self.a_recipient.as_bytes())?;
        validate_nonzero_fixed("invoice_v2.proof.a_committee", self.a_committee.as_bytes())?;
        validate_nonzero_fixed("invoice_v2.proof.tau_recipient", self.tau_recipient.as_bytes())?;
        validate_nonzero_fixed("invoice_v2.proof.tau_committee", self.tau_committee.as_bytes())?;
        validate_response("invoice_v2.proof.z", &self.z)?;
        validate_point_v2("invoice_v2.proof.a_delta", &self.a_delta)?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InvoiceEnvelopeV2 {
    pub binding: OperationBindingV2,
    pub paillier_profile: PaillierModulusProfileV2,
    pub expected_transfer_step: u64,
    pub statement: InvoiceStatementV2,
    pub proof: InvoiceProofV2,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct InvoiceEnvelopeV2Input {
    pub(crate) binding: OperationBindingV2,
    pub(crate) paillier_profile: PaillierModulusProfileV2Input,
    pub(crate) expected_transfer_step: u64,
    statement: InvoiceStatementV2Input,
    proof: InvoiceProofV2Input,
}

impl InvoiceEnvelopeV2 {
    pub(crate) fn from_input(input: InvoiceEnvelopeV2Input) -> Result<Self> {
        let value = Self {
            binding: input.binding,
            paillier_profile: PaillierModulusProfileV2::from_input(input.paillier_profile),
            expected_transfer_step: input.expected_transfer_step,
            statement: InvoiceStatementV2::from_input(input.statement)?,
            proof: InvoiceProofV2::from_input(input.proof)?,
        };
        value.validate_wire()?;
        Ok(value)
    }

    pub fn from_core(
        binding: OperationBindingV2,
        expected_transfer_step: u64,
        statement: &InvoiceStatement3072,
        proof: &InvoiceProof3072,
    ) -> Result<Self> {
        binding.validate_wire()?;
        if !matches!(binding, OperationBindingV2::Invoice { .. }) {
            return Err(WireError::InvalidBinding {
                reason: "protocol v2 Invoice envelope requires an invoice operation binding",
            });
        }
        if expected_transfer_step == 0 {
            return Err(WireError::InvalidBinding {
                reason: "protocol v2 Invoice expected_transfer_step must be positive",
            });
        }
        let expected_context = Self::proof_context_for(&binding, expected_transfer_step)?;
        require_matching_context(&expected_context, &statement.context)?;
        let value = Self {
            binding,
            paillier_profile: PaillierModulusProfileV2::ProtocolV2Production3072,
            expected_transfer_step,
            statement: InvoiceStatementV2::from_core(statement)?,
            proof: InvoiceProofV2::from_core(statement, proof)?,
        };
        value.validate_wire()?;
        Ok(value)
    }

    /// Derives the Fiat-Shamir context from the complete v2 Invoice binding.
    pub fn proof_context_for(
        binding: &OperationBindingV2,
        expected_transfer_step: u64,
    ) -> Result<thunderbolt_core::zkp::ProofContext> {
        binding.validate_wire()?;
        if !matches!(binding, OperationBindingV2::Invoice { .. }) || expected_transfer_step == 0 {
            return Err(WireError::InvalidBinding {
                reason: "protocol v2 Invoice proof context requires an invoice operation and positive expected step",
            });
        }
        let step = expected_transfer_step.to_be_bytes();
        derive_proof_context_v2(binding, b"invoice", &[&step])
    }

    /// Returns this envelope's exact Fiat-Shamir context.
    pub fn proof_context(&self) -> Result<thunderbolt_core::zkp::ProofContext> {
        Self::proof_context_for(&self.binding, self.expected_transfer_step)
    }

    /// Converts only after both raw moduli resolve through an authenticated
    /// exact-match certified-key registry.
    pub fn to_core_with_keys<R>(&self, resolver: &R) -> Result<(InvoiceStatement3072, InvoiceProof3072)>
    where
        R: CertifiedKeyResolver3072 + ?Sized,
    {
        self.validate_wire()?;
        let context = self.proof_context()?;
        let recipient_key = resolve_key_v2(
            "invoice_v2.statement.recipient_key",
            &self.statement.recipient_key,
            CertifiedKeyRole3072::Recipient,
            resolver,
        )?;
        let committee_key = resolve_key_v2(
            "invoice_v2.statement.committee_key",
            &self.statement.committee_key,
            CertifiedKeyRole3072::Committee,
            resolver,
        )?;
        let statement = InvoiceStatement3072 {
            context,
            anchor_base: decode_point_v2("invoice_v2.statement.anchor_base", &self.statement.anchor_base)?,
            recipient_ciphertext: decode_ciphertext_v2(&recipient_key, &self.statement.recipient_ciphertext)?,
            committee_ciphertext: decode_ciphertext_v2(&committee_key, &self.statement.committee_ciphertext)?,
            recipient_key: recipient_key.clone(),
            committee_key: committee_key.clone(),
            delta: decode_point_v2("invoice_v2.statement.delta", &self.statement.delta)?,
        };
        let proof = InvoiceProof3072 {
            a_delta: decode_point_v2("invoice_v2.proof.a_delta", &self.proof.a_delta)?,
            a_recipient: decode_ciphertext_v2(&recipient_key, &self.proof.a_recipient)?,
            a_committee: decode_ciphertext_v2(&committee_key, &self.proof.a_committee)?,
            z: decode_response_v2(&self.proof.z)?,
            tau_recipient: decode_nonce_v2(&recipient_key, &self.proof.tau_recipient)?,
            tau_committee: decode_nonce_v2(&committee_key, &self.proof.tau_committee)?,
        };
        Ok((statement, proof))
    }

    pub fn verify_with_keys<R>(&self, resolver: &R) -> Result<()>
    where
        R: CertifiedKeyResolver3072 + ?Sized,
    {
        let (statement, proof) = self.to_core_with_keys(resolver)?;
        verify_invoice_3072(&statement, &proof).map_err(|source| core_error("protocol v2 invoice verification", source))
    }

    fn append_canonical(&self, hasher: &mut CanonicalHasher) {
        self.binding.append_canonical(hasher);
        hasher.u8(self.paillier_profile.profile_id());
        hasher.u64(self.expected_transfer_step);
        self.statement.append_canonical(hasher);
        self.proof.append_canonical(hasher);
    }
}

impl ValidateWire for InvoiceEnvelopeV2 {
    fn validate_wire(&self) -> Result<()> {
        self.binding.validate_wire()?;
        if !matches!(self.binding, OperationBindingV2::Invoice { .. }) {
            return Err(WireError::InvalidBinding {
                reason: "protocol v2 Invoice envelope requires an invoice operation binding",
            });
        }
        if self.expected_transfer_step == 0 {
            return Err(WireError::InvalidBinding {
                reason: "protocol v2 Invoice expected_transfer_step must be positive",
            });
        }
        self.statement.validate_wire()?;
        self.proof.validate_wire()
    }
}

impl CanonicalDigest for InvoiceEnvelopeV2 {
    fn canonical_digest(&self) -> Result<[u8; 32]> {
        self.validate_wire()?;
        let mut hasher = CanonicalHasher::new(b"invoice_v2");
        self.append_canonical(&mut hasher);
        Ok(hasher.finish())
    }
}
