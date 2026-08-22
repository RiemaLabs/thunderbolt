use std::convert::TryFrom;
use std::fmt;

use serde::de::{Error as DeError, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use thunderbolt_core::zkp::{
    verify_share_encryption_3072, CertifiedKeyResolver3072, CertifiedKeyRole3072, ShareEncryptionProof3072,
    ShareEncryptionStatement3072,
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
    HexBytes, OperationBindingV2, PaillierCiphertextBytesV2, PaillierModulusBytesV2, PaillierModulusProfileV2,
    PaillierNonceBytesV2, PointHex, ProofResponseBytesV2, Result, WireError, MAX_COMMITTEE_MEMBERS,
    RECIPIENT_SHARE_MEMBER_ID,
};

const THRESHOLD_PACKAGE_ID_BYTES: usize = 32;
const THRESHOLD_PACKAGE_INTENT_DOMAIN: &[u8] = b"bitcoin-thunderbolt/threshold-package-intent/v2";
const THRESHOLD_PACKAGE_DIGEST_DOMAIN: &[u8] = b"bitcoin-thunderbolt/verifier/threshold-invoice-package/v2";

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ThresholdPackageIdV2(HexBytes<THRESHOLD_PACKAGE_ID_BYTES, THRESHOLD_PACKAGE_ID_BYTES>);

impl ThresholdPackageIdV2 {
    pub fn from_bytes(bytes: impl AsRef<[u8]>) -> Result<Self> {
        let value = HexBytes::from_bytes("threshold_package_id", bytes)?;
        if value.as_bytes().iter().all(|byte| *byte == 0) {
            return Err(WireError::InvalidBinding {
                reason: "threshold_package_id must not be all zero",
            });
        }
        Ok(Self(value))
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    pub fn to_hex(&self) -> String {
        self.0.to_hex()
    }
}

impl fmt::Debug for ThresholdPackageIdV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("ThresholdPackageIdV2")
            .field(&self.to_hex())
            .finish()
    }
}

impl Serialize for ThresholdPackageIdV2 {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.0.serialize(serializer)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ThresholdRosterMemberV2 {
    pub member_id: u32,
    pub encryption_key: PaillierModulusBytesV2,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ThresholdRosterMemberV2Input {
    member_id: u32,
    encryption_key: PaillierModulusBytesV2Input,
}

impl ThresholdRosterMemberV2 {
    fn from_input(input: ThresholdRosterMemberV2Input) -> Result<Self> {
        let value = Self {
            member_id: input.member_id,
            encryption_key: PaillierModulusBytesV2::from_bytes(
                "threshold_v2.roster.member.encryption_key",
                input.encryption_key.as_bytes(),
            )?,
        };
        value.validate_wire()?;
        Ok(value)
    }
}

impl ValidateWire for ThresholdRosterMemberV2 {
    fn validate_wire(&self) -> Result<()> {
        if self.member_id == 0 || self.member_id == RECIPIENT_SHARE_MEMBER_ID {
            return Err(WireError::InvalidMessage {
                message: "protocol v2 threshold roster",
                reason: "member ids must be positive and must not use the reserved Recipient id",
            });
        }
        validate_modulus("threshold_v2.roster.member.encryption_key", &self.encryption_key)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ThresholdRosterV2 {
    pub threshold: u32,
    pub members: Vec<ThresholdRosterMemberV2>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ThresholdRosterV2Input {
    threshold: u32,
    #[serde(deserialize_with = "deserialize_roster_members")]
    members: Vec<ThresholdRosterMemberV2Input>,
}

impl ThresholdRosterV2 {
    fn from_input(input: ThresholdRosterV2Input) -> Result<Self> {
        let value = Self {
            threshold: input.threshold,
            members: input
                .members
                .into_iter()
                .map(ThresholdRosterMemberV2::from_input)
                .collect::<Result<Vec<_>>>()?,
        };
        value.validate_wire()?;
        Ok(value)
    }

    pub fn new(threshold: u32, mut members: Vec<ThresholdRosterMemberV2>) -> Result<Self> {
        members.sort_by_key(|member| member.member_id);
        let value = Self { threshold, members };
        value.validate_wire()?;
        Ok(value)
    }

    fn append_canonical(&self, hasher: &mut CanonicalHasher) -> Result<()> {
        hasher.u32(self.threshold);
        hasher.usize(self.members.len())?;
        for member in &self.members {
            hasher.u32(member.member_id);
            hasher.bytes(member.encryption_key.as_bytes());
        }
        Ok(())
    }

    fn proof_commitment(&self) -> Result<[u8; 32]> {
        self.validate_wire()?;
        let mut hasher = CanonicalHasher::new(b"threshold_roster_v2");
        self.append_canonical(&mut hasher)?;
        Ok(hasher.finish())
    }
}

impl ValidateWire for ThresholdRosterV2 {
    fn validate_wire(&self) -> Result<()> {
        let threshold = usize::try_from(self.threshold).map_err(|_| WireError::InvalidMessage {
            message: "protocol v2 threshold roster",
            reason: "threshold does not fit on this platform",
        })?;
        if threshold == 0 || self.members.len() < threshold || self.members.len() > MAX_COMMITTEE_MEMBERS {
            return Err(WireError::InvalidMessage {
                message: "protocol v2 threshold roster",
                reason: "threshold and member count are outside the supported bounds",
            });
        }
        let mut previous = None;
        for member in &self.members {
            member.validate_wire()?;
            if previous.is_some_and(|member_id| member.member_id <= member_id) {
                return Err(WireError::InvalidMessage {
                    message: "protocol v2 threshold roster",
                    reason: "members must have unique ids in ascending order",
                });
            }
            previous = Some(member.member_id);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ThresholdPackageBindingV2 {
    pub package_id: ThresholdPackageIdV2,
    pub expected_transfer_step: u64,
    pub roster: ThresholdRosterV2,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ThresholdPackageBindingV2Input {
    package_id: HexBytes<THRESHOLD_PACKAGE_ID_BYTES, THRESHOLD_PACKAGE_ID_BYTES>,
    expected_transfer_step: u64,
    roster: ThresholdRosterV2Input,
}

impl ThresholdPackageBindingV2 {
    fn from_input(input: ThresholdPackageBindingV2Input) -> Result<Self> {
        let value = Self {
            package_id: ThresholdPackageIdV2::from_bytes(input.package_id.as_bytes())?,
            expected_transfer_step: input.expected_transfer_step,
            roster: ThresholdRosterV2::from_input(input.roster)?,
        };
        value.validate_wire()?;
        Ok(value)
    }

    pub fn new(operation: &OperationBindingV2, expected_transfer_step: u64, roster: ThresholdRosterV2) -> Result<Self> {
        require_invoice_operation(operation)?;
        roster.validate_wire()?;
        if expected_transfer_step == 0 {
            return Err(WireError::InvalidBinding {
                reason: "threshold package expected_transfer_step must be positive",
            });
        }
        let package_id = compute_package_id(operation, expected_transfer_step, &roster)?;
        Ok(Self {
            package_id,
            expected_transfer_step,
            roster,
        })
    }

    pub fn validate_for_operation(&self, operation: &OperationBindingV2) -> Result<()> {
        self.validate_wire()?;
        require_invoice_operation(operation)?;
        let expected = compute_package_id(operation, self.expected_transfer_step, &self.roster)?;
        if expected != self.package_id {
            return Err(WireError::InvalidBinding {
                reason: "threshold package id does not match its operation, step, and roster",
            });
        }
        Ok(())
    }

    /// Derives the shared Recipient/VESS Fiat-Shamir context from the exact
    /// operation, profile, expected step, package id, and ordered roster.
    pub fn proof_context(&self, operation: &OperationBindingV2) -> Result<thunderbolt_core::zkp::ProofContext> {
        self.validate_for_operation(operation)?;
        let step = self.expected_transfer_step.to_be_bytes();
        let roster = self.roster.proof_commitment()?;
        derive_proof_context_v2(
            operation,
            b"threshold_invoice_package",
            &[self.package_id.as_bytes(), &step, &roster],
        )
    }

    fn append_canonical(&self, hasher: &mut CanonicalHasher) -> Result<()> {
        hasher.bytes(self.package_id.as_bytes());
        hasher.u64(self.expected_transfer_step);
        self.roster.append_canonical(hasher)
    }
}

impl ValidateWire for ThresholdPackageBindingV2 {
    fn validate_wire(&self) -> Result<()> {
        if self.expected_transfer_step == 0 {
            return Err(WireError::InvalidBinding {
                reason: "threshold package expected_transfer_step must be positive",
            });
        }
        self.roster.validate_wire()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ShareProofV2 {
    pub a_point: PointHex,
    pub a_ciphertext: PaillierCiphertextBytesV2,
    pub z: ProofResponseBytesV2,
    pub tau: PaillierNonceBytesV2,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ShareProofV2Input {
    a_point: PointHex,
    a_ciphertext: PaillierCiphertextBytesV2Input,
    z: ProofResponseBytesV2Input,
    tau: PaillierNonceBytesV2Input,
}

impl ShareProofV2 {
    fn from_input(input: ShareProofV2Input) -> Result<Self> {
        let value = Self {
            a_point: input.a_point,
            a_ciphertext: PaillierCiphertextBytesV2::from_bytes(
                "share_v2.proof.a_ciphertext",
                input.a_ciphertext.as_bytes(),
            )?,
            z: ProofResponseBytesV2::from_bytes("share_v2.proof.z", input.z.as_bytes())?,
            tau: PaillierNonceBytesV2::from_bytes("share_v2.proof.tau", input.tau.as_bytes())?,
        };
        value.validate_wire()?;
        Ok(value)
    }

    fn from_core(
        key: &thunderbolt_core::zkp::production::PublicKey3072,
        proof: &ShareEncryptionProof3072,
    ) -> Result<Self> {
        let _ = encode_key_v2(key)?;
        let value = Self {
            a_point: encode_point_v2("share_v2.proof.a_point", &proof.a_point)?,
            a_ciphertext: encode_ciphertext_v2(key, &proof.a_ciphertext)?,
            z: encode_response_v2(&proof.z)?,
            tau: encode_nonce_v2(key, &proof.tau)?,
        };
        value.validate_wire()?;
        Ok(value)
    }

    fn to_core(&self, key: &thunderbolt_core::zkp::production::PublicKey3072) -> Result<ShareEncryptionProof3072> {
        Ok(ShareEncryptionProof3072 {
            a_point: decode_point_v2("share_v2.proof.a_point", &self.a_point)?,
            a_ciphertext: decode_ciphertext_v2(key, &self.a_ciphertext)?,
            z: decode_response_v2(&self.z)?,
            tau: decode_nonce_v2(key, &self.tau)?,
        })
    }

    fn append_canonical(&self, hasher: &mut CanonicalHasher) {
        hasher.bytes(self.a_point.as_bytes());
        hasher.bytes(self.a_ciphertext.as_bytes());
        hasher.bytes(self.z.as_bytes());
        hasher.bytes(self.tau.as_bytes());
    }
}

impl ValidateWire for ShareProofV2 {
    fn validate_wire(&self) -> Result<()> {
        validate_nonzero_fixed("share_v2.proof.a_ciphertext", self.a_ciphertext.as_bytes())?;
        validate_nonzero_fixed("share_v2.proof.tau", self.tau.as_bytes())?;
        validate_response("share_v2.proof.z", &self.z)?;
        validate_point_v2("share_v2.proof.a_point", &self.a_point)?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecipientShareStatementV2 {
    pub anchor_base: PointHex,
    pub recipient_key: PaillierModulusBytesV2,
    pub member_id: u32,
    pub committed_point: PointHex,
    pub ciphertext: PaillierCiphertextBytesV2,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RecipientShareStatementV2Input {
    anchor_base: PointHex,
    recipient_key: PaillierModulusBytesV2Input,
    member_id: u32,
    committed_point: PointHex,
    ciphertext: PaillierCiphertextBytesV2Input,
}

impl RecipientShareStatementV2 {
    fn from_input(input: RecipientShareStatementV2Input) -> Result<Self> {
        let value = Self {
            anchor_base: input.anchor_base,
            recipient_key: PaillierModulusBytesV2::from_bytes(
                "recipient_share_v2.statement.recipient_key",
                input.recipient_key.as_bytes(),
            )?,
            member_id: input.member_id,
            committed_point: input.committed_point,
            ciphertext: PaillierCiphertextBytesV2::from_bytes(
                "recipient_share_v2.statement.ciphertext",
                input.ciphertext.as_bytes(),
            )?,
        };
        value.validate_wire()?;
        Ok(value)
    }

    pub fn from_core(statement: &ShareEncryptionStatement3072) -> Result<Self> {
        let recipient_key = encode_key_v2(&statement.recipient_key)?;
        let value = Self {
            anchor_base: encode_point_v2("recipient_share_v2.statement.anchor_base", &statement.anchor_base)?,
            recipient_key,
            member_id: statement.member_id,
            committed_point: encode_point_v2(
                "recipient_share_v2.statement.committed_point",
                &statement.committed_point,
            )?,
            ciphertext: encode_ciphertext_v2(&statement.recipient_key, &statement.ciphertext)?,
        };
        value.validate_wire()?;
        Ok(value)
    }

    fn append_canonical(&self, hasher: &mut CanonicalHasher) {
        hasher.bytes(self.anchor_base.as_bytes());
        hasher.bytes(self.recipient_key.as_bytes());
        hasher.u32(self.member_id);
        hasher.bytes(self.committed_point.as_bytes());
        hasher.bytes(self.ciphertext.as_bytes());
    }
}

impl ValidateWire for RecipientShareStatementV2 {
    fn validate_wire(&self) -> Result<()> {
        if self.member_id != RECIPIENT_SHARE_MEMBER_ID {
            return Err(WireError::InvalidMessage {
                message: "protocol v2 Recipient share",
                reason: "Recipient share must use the reserved member id",
            });
        }
        validate_modulus("recipient_share_v2.statement.recipient_key", &self.recipient_key)?;
        validate_nonzero_fixed("recipient_share_v2.statement.ciphertext", self.ciphertext.as_bytes())?;
        validate_point_v2("recipient_share_v2.statement.anchor_base", &self.anchor_base)?;
        validate_point_v2("recipient_share_v2.statement.committed_point", &self.committed_point)?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecipientShareEnvelopeV2 {
    pub binding: OperationBindingV2,
    pub paillier_profile: PaillierModulusProfileV2,
    pub package: ThresholdPackageBindingV2,
    pub statement: RecipientShareStatementV2,
    pub proof: ShareProofV2,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RecipientShareEnvelopeV2Input {
    binding: OperationBindingV2,
    paillier_profile: PaillierModulusProfileV2Input,
    package: ThresholdPackageBindingV2Input,
    statement: RecipientShareStatementV2Input,
    proof: ShareProofV2Input,
}

impl RecipientShareEnvelopeV2 {
    pub(crate) fn from_input(input: RecipientShareEnvelopeV2Input) -> Result<Self> {
        let value = Self {
            binding: input.binding,
            paillier_profile: PaillierModulusProfileV2::from_input(input.paillier_profile),
            package: ThresholdPackageBindingV2::from_input(input.package)?,
            statement: RecipientShareStatementV2::from_input(input.statement)?,
            proof: ShareProofV2::from_input(input.proof)?,
        };
        value.validate_wire()?;
        Ok(value)
    }

    pub fn from_core(
        binding: OperationBindingV2,
        package: ThresholdPackageBindingV2,
        statement: &ShareEncryptionStatement3072,
        proof: &ShareEncryptionProof3072,
    ) -> Result<Self> {
        require_invoice_operation(&binding)?;
        package.validate_for_operation(&binding)?;
        let expected_context = package.proof_context(&binding)?;
        require_matching_context(&expected_context, &statement.context)?;
        let value = Self {
            binding,
            paillier_profile: PaillierModulusProfileV2::ProtocolV2Production3072,
            package,
            statement: RecipientShareStatementV2::from_core(statement)?,
            proof: ShareProofV2::from_core(&statement.recipient_key, proof)?,
        };
        value.validate_wire()?;
        Ok(value)
    }

    pub fn to_core_with_keys<R>(&self, resolver: &R) -> Result<(ShareEncryptionStatement3072, ShareEncryptionProof3072)>
    where
        R: CertifiedKeyResolver3072 + ?Sized,
    {
        self.validate_wire()?;
        let key = resolve_key_v2(
            "recipient_share_v2.statement.recipient_key",
            &self.statement.recipient_key,
            CertifiedKeyRole3072::Recipient,
            resolver,
        )?;
        let statement = ShareEncryptionStatement3072 {
            context: self.proof_context()?,
            anchor_base: decode_point_v2("recipient_share_v2.statement.anchor_base", &self.statement.anchor_base)?,
            recipient_key: key.clone(),
            member_id: self.statement.member_id,
            committed_point: decode_point_v2(
                "recipient_share_v2.statement.committed_point",
                &self.statement.committed_point,
            )?,
            ciphertext: decode_ciphertext_v2(&key, &self.statement.ciphertext)?,
        };
        let proof = self.proof.to_core(&key)?;
        Ok((statement, proof))
    }

    /// Returns the exact package-bound Fiat-Shamir context.
    pub fn proof_context(&self) -> Result<thunderbolt_core::zkp::ProofContext> {
        self.package.proof_context(&self.binding)
    }

    pub fn verify_with_keys<R>(&self, resolver: &R) -> Result<()>
    where
        R: CertifiedKeyResolver3072 + ?Sized,
    {
        let (statement, proof) = self.to_core_with_keys(resolver)?;
        verify_share_encryption_3072(&statement, &proof)
            .map_err(|source| core_error("protocol v2 Recipient share verification", source))
    }

    fn append_canonical(&self, hasher: &mut CanonicalHasher) -> Result<()> {
        self.binding.append_canonical(hasher);
        hasher.u8(self.paillier_profile.profile_id());
        self.package.append_canonical(hasher)?;
        self.statement.append_canonical(hasher);
        self.proof.append_canonical(hasher);
        Ok(())
    }
}

impl ValidateWire for RecipientShareEnvelopeV2 {
    fn validate_wire(&self) -> Result<()> {
        require_invoice_operation(&self.binding)?;
        self.package.validate_for_operation(&self.binding)?;
        self.statement.validate_wire()?;
        self.proof.validate_wire()
    }
}

impl CanonicalDigest for RecipientShareEnvelopeV2 {
    fn canonical_digest(&self) -> Result<[u8; 32]> {
        self.validate_wire()?;
        let mut hasher = CanonicalHasher::new(b"recipient_share_v2");
        self.append_canonical(&mut hasher)?;
        Ok(hasher.finish())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ThresholdEncryptedShareV2 {
    pub member_id: u32,
    pub encryption_key: PaillierModulusBytesV2,
    pub ciphertext: PaillierCiphertextBytesV2,
    pub proof: ShareProofV2,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ThresholdEncryptedShareV2Input {
    member_id: u32,
    encryption_key: PaillierModulusBytesV2Input,
    ciphertext: PaillierCiphertextBytesV2Input,
    proof: ShareProofV2Input,
}

impl ThresholdEncryptedShareV2 {
    fn from_input(input: ThresholdEncryptedShareV2Input) -> Result<Self> {
        let value = Self {
            member_id: input.member_id,
            encryption_key: PaillierModulusBytesV2::from_bytes(
                "threshold_v2.share.encryption_key",
                input.encryption_key.as_bytes(),
            )?,
            ciphertext: PaillierCiphertextBytesV2::from_bytes(
                "threshold_v2.share.ciphertext",
                input.ciphertext.as_bytes(),
            )?,
            proof: ShareProofV2::from_input(input.proof)?,
        };
        value.validate_wire()?;
        Ok(value)
    }

    fn append_canonical(&self, hasher: &mut CanonicalHasher) {
        hasher.u32(self.member_id);
        hasher.bytes(self.encryption_key.as_bytes());
        hasher.bytes(self.ciphertext.as_bytes());
        self.proof.append_canonical(hasher);
    }
}

impl ValidateWire for ThresholdEncryptedShareV2 {
    fn validate_wire(&self) -> Result<()> {
        if self.member_id == 0 || self.member_id == RECIPIENT_SHARE_MEMBER_ID {
            return Err(WireError::InvalidMessage {
                message: "protocol v2 threshold share",
                reason: "member id must be positive and not reserved",
            });
        }
        validate_modulus("threshold_v2.share.encryption_key", &self.encryption_key)?;
        validate_nonzero_fixed("threshold_v2.share.ciphertext", self.ciphertext.as_bytes())?;
        self.proof.validate_wire()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ThresholdDistributionV2 {
    pub anchor_base: PointHex,
    pub threshold: u32,
    pub delta: PointHex,
    pub polynomial_commitments: Vec<PointHex>,
    pub encrypted_shares: Vec<ThresholdEncryptedShareV2>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ThresholdDistributionV2Input {
    anchor_base: PointHex,
    threshold: u32,
    delta: PointHex,
    #[serde(deserialize_with = "deserialize_commitments")]
    polynomial_commitments: Vec<PointHex>,
    #[serde(deserialize_with = "deserialize_encrypted_shares")]
    encrypted_shares: Vec<ThresholdEncryptedShareV2Input>,
}

impl ThresholdDistributionV2 {
    fn from_input(input: ThresholdDistributionV2Input) -> Result<Self> {
        let value = Self {
            anchor_base: input.anchor_base,
            threshold: input.threshold,
            delta: input.delta,
            polynomial_commitments: input.polynomial_commitments,
            encrypted_shares: input
                .encrypted_shares
                .into_iter()
                .map(ThresholdEncryptedShareV2::from_input)
                .collect::<Result<Vec<_>>>()?,
        };
        value.validate_wire()?;
        Ok(value)
    }

    fn validate_against_roster(&self, roster: &ThresholdRosterV2) -> Result<()> {
        self.validate_wire()?;
        roster.validate_wire()?;
        if self.threshold != roster.threshold || self.encrypted_shares.len() != roster.members.len() {
            return Err(WireError::InvalidMessage {
                message: "protocol v2 threshold refresh",
                reason: "distribution shape does not match the exact package roster",
            });
        }
        for (share, member) in self.encrypted_shares.iter().zip(&roster.members) {
            if share.member_id != member.member_id || share.encryption_key != member.encryption_key {
                return Err(WireError::InvalidMessage {
                    message: "protocol v2 threshold refresh",
                    reason: "distribution member does not match the exact package roster",
                });
            }
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

impl ValidateWire for ThresholdDistributionV2 {
    fn validate_wire(&self) -> Result<()> {
        let threshold = usize::try_from(self.threshold).map_err(|_| WireError::InvalidMessage {
            message: "protocol v2 threshold refresh",
            reason: "threshold does not fit on this platform",
        })?;
        if threshold == 0
            || threshold > MAX_COMMITTEE_MEMBERS
            || self.polynomial_commitments.len() != threshold
            || self.encrypted_shares.len() < threshold
            || self.encrypted_shares.len() > MAX_COMMITTEE_MEMBERS
        {
            return Err(WireError::InvalidMessage {
                message: "protocol v2 threshold refresh",
                reason: "distribution shape is outside the supported bounds",
            });
        }
        validate_point_v2("threshold_v2.anchor_base", &self.anchor_base)?;
        validate_point_v2("threshold_v2.delta", &self.delta)?;
        for commitment in &self.polynomial_commitments {
            validate_point_v2("threshold_v2.polynomial_commitment", commitment)?;
        }
        let mut previous = None;
        for share in &self.encrypted_shares {
            share.validate_wire()?;
            if previous.is_some_and(|member_id| share.member_id <= member_id) {
                return Err(WireError::InvalidMessage {
                    message: "protocol v2 threshold refresh",
                    reason: "encrypted shares must have unique member ids in ascending order",
                });
            }
            previous = Some(share.member_id);
        }
        if self.polynomial_commitments.first() != Some(&self.delta) {
            return Err(WireError::InvalidMessage {
                message: "protocol v2 threshold refresh",
                reason: "free-term commitment must equal the public delta",
            });
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ThresholdEnvelopeV2 {
    pub binding: OperationBindingV2,
    pub paillier_profile: PaillierModulusProfileV2,
    pub package: ThresholdPackageBindingV2,
    pub distribution: ThresholdDistributionV2,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ThresholdEnvelopeV2Input {
    binding: OperationBindingV2,
    paillier_profile: PaillierModulusProfileV2Input,
    package: ThresholdPackageBindingV2Input,
    distribution: ThresholdDistributionV2Input,
}

impl ThresholdEnvelopeV2 {
    pub(crate) fn from_input(input: ThresholdEnvelopeV2Input) -> Result<Self> {
        let value = Self {
            binding: input.binding,
            paillier_profile: PaillierModulusProfileV2::from_input(input.paillier_profile),
            package: ThresholdPackageBindingV2::from_input(input.package)?,
            distribution: ThresholdDistributionV2::from_input(input.distribution)?,
        };
        value.validate_wire()?;
        Ok(value)
    }

    /// Returns the exact package-bound Fiat-Shamir context shared with the
    /// Recipient proof.
    pub fn proof_context(&self) -> Result<thunderbolt_core::zkp::ProofContext> {
        self.package.proof_context(&self.binding)
    }

    /// The paper does not specify the concrete aggregate VESS equations or
    /// Fiat-Shamir transcript. Wire/package validation remains available, but
    /// cryptographic activation stays closed until that specification exists.
    pub fn verify(&self) -> Result<()> {
        self.validate_wire()?;
        Err(WireError::InvalidMessage {
            message: "protocol v2 threshold refresh",
            reason:
                "aggregate VESS verification is unavailable without a concrete equation and transcript specification",
        })
    }

    fn append_canonical(&self, hasher: &mut CanonicalHasher) -> Result<()> {
        self.binding.append_canonical(hasher);
        hasher.u8(self.paillier_profile.profile_id());
        self.package.append_canonical(hasher)?;
        self.distribution.append_canonical(hasher)
    }
}

impl ValidateWire for ThresholdEnvelopeV2 {
    fn validate_wire(&self) -> Result<()> {
        require_invoice_operation(&self.binding)?;
        self.package.validate_for_operation(&self.binding)?;
        self.distribution.validate_against_roster(&self.package.roster)
    }
}

impl CanonicalDigest for ThresholdEnvelopeV2 {
    fn canonical_digest(&self) -> Result<[u8; 32]> {
        self.validate_wire()?;
        let mut hasher = CanonicalHasher::new(b"threshold_refresh_v2");
        self.append_canonical(&mut hasher)?;
        Ok(hasher.finish())
    }
}

/// Validates the two-message threshold Invoice package boundary without
/// claiming that `tb/share` is the paper's exact `R_inv^thr` transcript.
pub fn validate_threshold_package_v2(
    recipient: &RecipientShareEnvelopeV2,
    threshold: &ThresholdEnvelopeV2,
) -> Result<()> {
    recipient.validate_wire()?;
    threshold.validate_wire()?;
    if recipient.binding != threshold.binding || recipient.package != threshold.package {
        return Err(WireError::InvalidMessage {
            message: "protocol v2 threshold package",
            reason: "Recipient share and threshold refresh bindings must match exactly",
        });
    }
    if recipient.statement.anchor_base != threshold.distribution.anchor_base
        || recipient.statement.committed_point != threshold.distribution.delta
    {
        return Err(WireError::InvalidMessage {
            message: "protocol v2 threshold package",
            reason: "Recipient share and threshold refresh public points must match",
        });
    }
    Ok(())
}

pub fn threshold_invoice_package_digest_v2(
    recipient: &RecipientShareEnvelopeV2,
    threshold: &ThresholdEnvelopeV2,
) -> Result<[u8; 32]> {
    validate_threshold_package_v2(recipient, threshold)?;
    let mut hasher = CanonicalHasher::new(THRESHOLD_PACKAGE_DIGEST_DOMAIN);
    hasher.bytes(&recipient.canonical_digest()?);
    hasher.bytes(&threshold.canonical_digest()?);
    Ok(hasher.finish())
}

fn compute_package_id(
    operation: &OperationBindingV2,
    expected_transfer_step: u64,
    roster: &ThresholdRosterV2,
) -> Result<ThresholdPackageIdV2> {
    require_invoice_operation(operation)?;
    roster.validate_wire()?;
    let mut hasher = CanonicalHasher::new(THRESHOLD_PACKAGE_INTENT_DOMAIN);
    operation.append_canonical(&mut hasher);
    hasher.u64(expected_transfer_step);
    roster.append_canonical(&mut hasher)?;
    ThresholdPackageIdV2::from_bytes(hasher.finish())
}

fn require_invoice_operation(operation: &OperationBindingV2) -> Result<()> {
    operation.validate_wire()?;
    if !matches!(operation, OperationBindingV2::Invoice { .. }) {
        return Err(WireError::InvalidBinding {
            reason: "protocol v2 threshold messages require an invoice operation binding",
        });
    }
    Ok(())
}

fn deserialize_roster_members<'de, D>(
    deserializer: D,
) -> std::result::Result<Vec<ThresholdRosterMemberV2Input>, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_bounded_vec(deserializer, MAX_COMMITTEE_MEMBERS, "threshold roster members")
}

fn deserialize_commitments<'de, D>(deserializer: D) -> std::result::Result<Vec<PointHex>, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_bounded_vec(deserializer, MAX_COMMITTEE_MEMBERS, "threshold polynomial commitments")
}

fn deserialize_encrypted_shares<'de, D>(
    deserializer: D,
) -> std::result::Result<Vec<ThresholdEncryptedShareV2Input>, D::Error>
where
    D: Deserializer<'de>,
{
    deserialize_bounded_vec(deserializer, MAX_COMMITTEE_MEMBERS, "threshold encrypted shares")
}

fn deserialize_bounded_vec<'de, D, T>(
    deserializer: D,
    max: usize,
    label: &'static str,
) -> std::result::Result<Vec<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    struct BoundedVisitor<T> {
        max: usize,
        label: &'static str,
        marker: std::marker::PhantomData<T>,
    }

    impl<'de, T> Visitor<'de> for BoundedVisitor<T>
    where
        T: Deserialize<'de>,
    {
        type Value = Vec<T>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(formatter, "{} with at most {} entries", self.label, self.max)
        }

        fn visit_seq<A>(self, mut sequence: A) -> std::result::Result<Self::Value, A::Error>
        where
            A: SeqAccess<'de>,
        {
            let capacity = sequence.size_hint().unwrap_or(0).min(self.max);
            let mut values = Vec::with_capacity(capacity);
            while let Some(value) = sequence.next_element()? {
                if values.len() == self.max {
                    return Err(A::Error::custom(format_args!(
                        "{} exceeds {} entries",
                        self.label, self.max
                    )));
                }
                values.push(value);
            }
            Ok(values)
        }
    }

    deserializer.deserialize_seq(BoundedVisitor {
        max,
        label,
        marker: std::marker::PhantomData,
    })
}
