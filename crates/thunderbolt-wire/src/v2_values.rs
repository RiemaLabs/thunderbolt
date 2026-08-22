use serde::{Deserialize, Serialize, Serializer};
use sha2::{Digest as _, Sha256};
use thunderbolt_core::zkp::production::{
    CertifiedKeyResolver3072, CertifiedKeyRole3072, Ciphertext3072, ProofNonce3072, ProofResponse3072, PublicKey3072,
    RawPublicKey3072, PAILLIER_CIPHERTEXT_BYTES, PAILLIER_MODULUS_BYTES, PROOF_RESPONSE_3072_BYTES,
};

use crate::codec::{point_from_wire, point_to_wire, ValidateWire};
use crate::{HexBytes, OperationBindingV2, PointHex, Result, WireError};

/// Exact protocol-v2 Paillier modulus and nonce width.
pub const PAILLIER_V2_MODULUS_BYTES: usize = PAILLIER_MODULUS_BYTES;
/// Exact protocol-v2 Paillier ciphertext width.
pub const PAILLIER_V2_CIPHERTEXT_BYTES: usize = PAILLIER_CIPHERTEXT_BYTES;
/// Fixed-width protocol-v2 integer-response encoding.
pub const PROOF_RESPONSE_V2_BYTES: usize = PROOF_RESPONSE_3072_BYTES;

macro_rules! fixed_v2_bytes {
    ($(#[$meta:meta])* $name:ident, $width:expr) => {
        $(#[$meta])*
        #[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(HexBytes<$width, $width>);

        impl $name {
            pub fn from_bytes(field: &'static str, bytes: impl AsRef<[u8]>) -> Result<Self> {
                HexBytes::from_bytes(field, bytes).map(Self)
            }

            pub fn as_bytes(&self) -> &[u8] {
                self.0.as_bytes()
            }

            pub fn to_hex(&self) -> String {
                self.0.to_hex()
            }
        }

        impl std::fmt::Debug for $name {
            fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.debug_tuple(stringify!($name)).field(&self.to_hex()).finish()
            }
        }

        impl Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                serializer.serialize_str(&self.to_hex())
            }
        }
    };
}

fixed_v2_bytes!(
    /// Raw fixed-width protocol-v2 Paillier modulus. This semantic type has no serde ingress.
    ///
    /// ```compile_fail
    /// use thunderbolt_wire::PaillierModulusBytesV2;
    /// let _: PaillierModulusBytesV2 = serde_json::from_str("\"00\"").unwrap();
    /// ```
    PaillierModulusBytesV2,
    PAILLIER_V2_MODULUS_BYTES
);
fixed_v2_bytes!(
    /// Raw fixed-width protocol-v2 Paillier nonce. This semantic type has no serde ingress.
    PaillierNonceBytesV2,
    PAILLIER_V2_MODULUS_BYTES
);
fixed_v2_bytes!(
    /// Raw fixed-width protocol-v2 Paillier ciphertext. This semantic type has no serde ingress.
    PaillierCiphertextBytesV2,
    PAILLIER_V2_CIPHERTEXT_BYTES
);
fixed_v2_bytes!(
    /// Raw fixed-width protocol-v2 proof response. This semantic type has no serde ingress.
    ProofResponseBytesV2,
    PROOF_RESPONSE_V2_BYTES
);

pub(crate) type PaillierModulusBytesV2Input = HexBytes<PAILLIER_V2_MODULUS_BYTES, PAILLIER_V2_MODULUS_BYTES>;
pub(crate) type PaillierNonceBytesV2Input = HexBytes<PAILLIER_V2_MODULUS_BYTES, PAILLIER_V2_MODULUS_BYTES>;
pub(crate) type PaillierCiphertextBytesV2Input = HexBytes<PAILLIER_V2_CIPHERTEXT_BYTES, PAILLIER_V2_CIPHERTEXT_BYTES>;
pub(crate) type ProofResponseBytesV2Input = HexBytes<PROOF_RESPONSE_V2_BYTES, PROOF_RESPONSE_V2_BYTES>;

/// The only Paillier profile valid inside a protocol-v2 public proof envelope.
///
/// ```compile_fail
/// use thunderbolt_wire::PaillierModulusProfileV2;
/// let _: PaillierModulusProfileV2 =
///     serde_json::from_str("\"protocol_v2_production_3072\"").unwrap();
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PaillierModulusProfileV2 {
    ProtocolV2Production3072,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum PaillierModulusProfileV2Input {
    ProtocolV2Production3072,
}

impl PaillierModulusProfileV2 {
    pub(crate) const fn profile_id(self) -> u8 {
        match self {
            Self::ProtocolV2Production3072 => 2,
        }
    }

    pub(crate) const fn from_input(input: PaillierModulusProfileV2Input) -> Self {
        match input {
            PaillierModulusProfileV2Input::ProtocolV2Production3072 => Self::ProtocolV2Production3072,
        }
    }
}

pub(crate) fn validate_modulus(_field: &'static str, value: &PaillierModulusBytesV2) -> Result<()> {
    let bytes = value.as_bytes();
    let has_profile_bit_length = bytes.first().is_some_and(|first| first & 0x80 != 0);
    let is_odd = bytes.last().is_some_and(|last| last & 1 == 1);
    if !has_profile_bit_length || !is_odd {
        return Err(WireError::InvalidMessage {
            message: "protocol v2 Paillier modulus",
            reason: "modulus must be an odd integer with exact 3072-bit width",
        });
    }
    Ok(())
}

pub(crate) fn validate_nonzero_fixed(field: &'static str, value: &[u8]) -> Result<()> {
    if value.iter().all(|byte| *byte == 0) {
        return Err(WireError::InvalidMessage {
            message: "protocol v2 proof",
            reason: field,
        });
    }
    Ok(())
}

pub(crate) fn validate_response(field: &'static str, value: &ProofResponseBytesV2) -> Result<()> {
    ProofResponse3072::from_bytes(value.as_bytes())
        .map(|_| ())
        .map_err(|_| WireError::InvalidMessage {
            message: "protocol v2 proof",
            reason: field,
        })
}

/// Resolves a raw modulus only through the deployment's authenticated
/// certified-key boundary, then rechecks the exact 384-byte identity.
pub(crate) fn resolve_key_v2<R>(
    field: &'static str,
    value: &PaillierModulusBytesV2,
    expected_role: CertifiedKeyRole3072,
    resolver: &R,
) -> Result<PublicKey3072>
where
    R: CertifiedKeyResolver3072 + ?Sized,
{
    validate_modulus(field, value)?;
    let raw = RawPublicKey3072::from_bytes(value.as_bytes())
        .map_err(|source| paillier_error("protocol v2 raw Paillier key ingress", source))?;
    let key = resolver
        .resolve_certified_key(&raw, expected_role)
        .map_err(|source| crate::error::core_error("protocol v2 certified Paillier key resolution", source))?;
    if key.to_bytes().as_slice() != value.as_bytes() {
        return Err(WireError::InvalidMessage {
            message: "protocol v2 Paillier modulus",
            reason: "certified-key resolver returned a different modulus",
        });
    }
    Ok(key)
}

pub(crate) fn decode_ciphertext_v2(key: &PublicKey3072, value: &PaillierCiphertextBytesV2) -> Result<Ciphertext3072> {
    key.ciphertext_from_bytes(value.as_bytes())
        .map_err(|source| paillier_error("protocol v2 Paillier ciphertext ingress", source))
}

pub(crate) fn decode_nonce_v2(key: &PublicKey3072, value: &PaillierNonceBytesV2) -> Result<ProofNonce3072> {
    key.proof_nonce_from_bytes(value.as_bytes())
        .map_err(|source| paillier_error("protocol v2 Paillier nonce ingress", source))
}

pub(crate) fn decode_response_v2(value: &ProofResponseBytesV2) -> Result<ProofResponse3072> {
    ProofResponse3072::from_bytes(value.as_bytes())
        .map_err(|source| crate::error::core_error("protocol v2 proof response ingress", source))
}

pub(crate) fn encode_key_v2(key: &PublicKey3072) -> Result<PaillierModulusBytesV2> {
    PaillierModulusBytesV2::from_bytes("protocol v2 Paillier modulus", key.to_bytes())
}

pub(crate) fn encode_ciphertext_v2(
    key: &PublicKey3072,
    ciphertext: &Ciphertext3072,
) -> Result<PaillierCiphertextBytesV2> {
    key.validate_ciphertext(ciphertext)
        .map_err(|source| paillier_error("protocol v2 Paillier ciphertext egress", source))?;
    PaillierCiphertextBytesV2::from_bytes("protocol v2 Paillier ciphertext", ciphertext.to_bytes())
}

pub(crate) fn encode_nonce_v2(key: &PublicKey3072, nonce: &ProofNonce3072) -> Result<PaillierNonceBytesV2> {
    key.validate_proof_nonce(nonce)
        .map_err(|source| paillier_error("protocol v2 Paillier nonce egress", source))?;
    PaillierNonceBytesV2::from_bytes("protocol v2 Paillier nonce", nonce.to_bytes())
}

pub(crate) fn encode_response_v2(value: &ProofResponse3072) -> Result<ProofResponseBytesV2> {
    ProofResponseBytesV2::from_bytes("protocol v2 proof response", value.to_bytes())
}

pub(crate) fn validate_point_v2(field: &'static str, point: &PointHex) -> Result<()> {
    if !matches!(point.as_bytes().first(), Some(2 | 3)) {
        return Err(WireError::InvalidPoint { field });
    }
    Ok(())
}

pub(crate) fn decode_point_v2(field: &'static str, point: &PointHex) -> Result<secp::Point> {
    // Exact curve decoding happens only after the envelope's Paillier key has
    // passed the core raw-profile ingress gate.
    point_from_wire(field, point)
}

pub(crate) fn encode_point_v2(field: &'static str, point: &secp::Point) -> Result<PointHex> {
    point_to_wire(field, point)
}

fn paillier_error(operation: &'static str, source: thunderbolt_core::zkp::production::PaillierError) -> WireError {
    crate::error::core_error(
        operation,
        thunderbolt_core::ThunderboltError::CryptographicError(source.to_string()),
    )
}

/// Derives a proof-only context from the stable channel id and all operation
/// fields. The stable [`crate::ChannelBindingV2::context_id`] remains unchanged.
pub(crate) fn derive_proof_context_v2(
    binding: &OperationBindingV2,
    proof_domain: &'static [u8],
    extensions: &[&[u8]],
) -> Result<thunderbolt_core::zkp::ProofContext> {
    binding.validate_wire()?;
    let mut hasher = Sha256::new();
    append_context_field(&mut hasher, b"bitcoin-thunderbolt/proof-context/v2");
    append_context_field(&mut hasher, proof_domain);
    append_context_field(&mut hasher, &binding.channel().context_id()?);
    append_context_field(
        &mut hasher,
        &[PaillierModulusProfileV2::ProtocolV2Production3072.profile_id()],
    );
    append_context_field(&mut hasher, binding.invoice_id().as_bytes());
    match binding.step() {
        Some(step) => {
            append_context_field(&mut hasher, &[1]);
            append_context_field(&mut hasher, &step.to_be_bytes());
        }
        None => append_context_field(&mut hasher, &[0]),
    }
    for extension in extensions {
        append_context_field(&mut hasher, extension);
    }
    let context_id: [u8; 32] = hasher.finalize().into();
    Ok(match binding.step() {
        Some(step) => thunderbolt_core::zkp::ProofContext::transfer(context_id, step, binding.invoice_id().as_bytes()),
        None => thunderbolt_core::zkp::ProofContext::invoice(context_id, binding.invoice_id().as_bytes()),
    })
}

pub(crate) fn require_matching_context(
    expected: &thunderbolt_core::zkp::ProofContext,
    actual: &thunderbolt_core::zkp::ProofContext,
) -> Result<()> {
    if expected.ctx_id() != actual.ctx_id() || expected.inv_id() != actual.inv_id() || expected.step() != actual.step()
    {
        return Err(WireError::InvalidBinding {
            reason: "protocol v2 proof context does not match its complete envelope binding",
        });
    }
    Ok(())
}

fn append_context_field(hasher: &mut Sha256, value: &[u8]) {
    hasher.update(u64::try_from(value.len()).unwrap_or(u64::MAX).to_be_bytes());
    hasher.update(value);
}
