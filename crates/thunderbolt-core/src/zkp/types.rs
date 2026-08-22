use std::sync::OnceLock;

use bitcoin::key::rand::{thread_rng, RngCore};
use libpaillier::unknown_order::BigNumber;
use secp::{MaybePoint, MaybeScalar, Point, Scalar};

use crate::{Result, ThunderboltError};

const CURVE_ORDER_BYTES: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0xba, 0xae, 0xdc,
    0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
];

const STATISTICAL_SECURITY_PARAMETER: u32 = 128;

/// Domain-separation identifiers are network-controlled inputs in a deployed
/// verifier. Keeping them small prevents oversized transcripts from becoming
/// an allocation or hashing denial of service.
pub const MAX_CONTEXT_ID_BYTES: usize = 128;
pub const MAX_INVOICE_ID_BYTES: usize = 128;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProofTag {
    Invoice,
    Transfer,
    ShareEncryption,
}

impl ProofTag {
    pub fn as_bytes(self) -> &'static [u8] {
        match self {
            ProofTag::Invoice => b"tb/invoice",
            ProofTag::Transfer => b"tb/xfer",
            ProofTag::ShareEncryption => b"tb/share",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProofContext {
    ctx_id: Vec<u8>,
    inv_id: Vec<u8>,
    step: Option<u64>,
}

impl ProofContext {
    pub fn invoice(ctx_id: impl AsRef<[u8]>, inv_id: impl AsRef<[u8]>) -> Self {
        Self {
            ctx_id: ctx_id.as_ref().to_vec(),
            inv_id: inv_id.as_ref().to_vec(),
            step: None,
        }
    }

    pub fn transfer(ctx_id: impl AsRef<[u8]>, step: u64, inv_id: impl AsRef<[u8]>) -> Self {
        Self {
            ctx_id: ctx_id.as_ref().to_vec(),
            inv_id: inv_id.as_ref().to_vec(),
            step: Some(step),
        }
    }

    pub fn ctx_id(&self) -> &[u8] {
        &self.ctx_id
    }

    pub fn inv_id(&self) -> &[u8] {
        &self.inv_id
    }

    pub fn step(&self) -> Option<u64> {
        self.step
    }

    pub fn expect_invoice(&self) -> Result<()> {
        self.validate_bounds()?;
        if self.step.is_some() {
            return Err(ThunderboltError::InvalidParameter(
                "invoice proofs must not bind a step index".to_string(),
            ));
        }

        Ok(())
    }

    pub fn expect_transfer(&self) -> Result<u64> {
        self.validate_bounds()?;
        self.step.ok_or_else(|| {
            ThunderboltError::InvalidParameter("transfer proofs must bind an explicit step index".to_string())
        })
    }

    fn validate_bounds(&self) -> Result<()> {
        if self.ctx_id.is_empty() || self.ctx_id.len() > MAX_CONTEXT_ID_BYTES {
            return Err(ThunderboltError::InvalidParameter(format!(
                "context id must contain 1..={MAX_CONTEXT_ID_BYTES} bytes"
            )));
        }
        if self.inv_id.is_empty() || self.inv_id.len() > MAX_INVOICE_ID_BYTES {
            return Err(ThunderboltError::InvalidParameter(format!(
                "invoice id must contain 1..={MAX_INVOICE_ID_BYTES} bytes"
            )));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChallengeValue {
    scalar: MaybeScalar,
    integer: BigNumber,
}

impl ChallengeValue {
    pub fn from_digest(digest: [u8; 32]) -> Self {
        let scalar = MaybeScalar::reduce_from(&digest);
        let integer = maybe_scalar_to_big_number(scalar);
        Self { scalar, integer }
    }

    pub fn scalar(&self) -> MaybeScalar {
        self.scalar
    }

    pub fn integer(&self) -> &BigNumber {
        &self.integer
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IntegerResponse {
    integer: BigNumber,
    scalar_mod_q: MaybeScalar,
}

impl IntegerResponse {
    pub fn new(integer: BigNumber) -> Result<Self> {
        ensure_non_negative("response z", &integer)?;
        // z = alpha + c*x, where alpha is sampled below q^2 * 2^128 and
        // c,x < q. One extra bit safely accommodates the sum while bounding
        // verifier-controlled modular exponentiation.
        let max_bits = masking_range().bit_length() + 1;
        if integer.bit_length() > max_bits {
            return Err(ThunderboltError::OutOfRange(format!(
                "response z exceeds the {max_bits}-bit protocol bound"
            )));
        }
        let scalar_mod_q = reduce_big_number_mod_curve_order(&integer)?;
        Ok(Self { integer, scalar_mod_q })
    }

    pub fn from_linear_relation(alpha: &BigNumber, challenge: &BigNumber, witness: Scalar) -> Result<Self> {
        ensure_non_negative("commitment scalar alpha", alpha)?;
        ensure_non_negative("Fiat-Shamir challenge", challenge)?;

        let witness_bn = scalar_to_big_number(witness);
        let response = alpha + &(challenge.clone() * witness_bn);

        Self::new(response)
    }

    pub fn integer(&self) -> &BigNumber {
        &self.integer
    }

    pub fn scalar_mod_q(&self) -> MaybeScalar {
        self.scalar_mod_q
    }
}

pub fn curve_order() -> &'static BigNumber {
    static CURVE_ORDER: OnceLock<BigNumber> = OnceLock::new();
    CURVE_ORDER.get_or_init(|| BigNumber::from_slice(CURVE_ORDER_BYTES))
}

pub fn masking_range() -> &'static BigNumber {
    static MASKING_RANGE: OnceLock<BigNumber> = OnceLock::new();
    MASKING_RANGE.get_or_init(|| {
        let q = curve_order();
        let q_squared = q * q;
        q_squared << STATISTICAL_SECURITY_PARAMETER
    })
}

pub fn random_commitment_scalar() -> BigNumber {
    let q_tilde = masking_range();
    let byte_len = (q_tilde.bit_length() + 8) / 8;
    let mut buf = vec![0u8; byte_len];
    loop {
        thread_rng().fill_bytes(&mut buf);
        buf[0] &= 0x7f;
        let candidate = BigNumber::from_slice(&buf);
        if &candidate < q_tilde {
            return candidate;
        }
    }
}

pub fn scalar_to_big_number(scalar: Scalar) -> BigNumber {
    BigNumber::from_slice(scalar.serialize())
}

pub fn maybe_scalar_to_big_number(scalar: MaybeScalar) -> BigNumber {
    BigNumber::from_slice(scalar.serialize())
}

pub fn canonical_big_number_bytes(value: &BigNumber) -> Vec<u8> {
    let bytes = value.to_bytes();
    if bytes.is_empty() {
        vec![0]
    } else {
        bytes
    }
}

fn ensure_non_negative(label: &str, value: &BigNumber) -> Result<()> {
    if value < &BigNumber::zero() {
        return Err(ThunderboltError::OutOfRange(format!("{label} must be non-negative")));
    }

    Ok(())
}

fn to_fixed_32_bytes(value: &BigNumber) -> Result<[u8; 32]> {
    ensure_non_negative("scalar value", value)?;
    let bytes = canonical_big_number_bytes(value);
    if bytes.len() > 32 {
        return Err(ThunderboltError::OutOfRange(
            "scalar value exceeds 32-byte secp256k1 encoding width".to_string(),
        ));
    }

    let mut out = [0u8; 32];
    out[32 - bytes.len()..].copy_from_slice(&bytes);
    Ok(out)
}

pub fn big_number_to_maybe_scalar(value: &BigNumber) -> Result<MaybeScalar> {
    let bytes = to_fixed_32_bytes(value)?;
    MaybeScalar::from_slice(&bytes)
        .map_err(|_| ThunderboltError::OutOfRange("value does not fit inside the secp256k1 scalar field".to_string()))
}

pub fn big_number_to_scalar(value: &BigNumber) -> Result<Scalar> {
    big_number_to_maybe_scalar(value)?
        .not_zero()
        .map_err(|_| ThunderboltError::OutOfRange("scalar must be non-zero".to_string()))
}

pub fn reduce_big_number_mod_curve_order(value: &BigNumber) -> Result<MaybeScalar> {
    ensure_non_negative("scalar reduction input", value)?;
    let reduced = value.nmod(curve_order());
    big_number_to_maybe_scalar(&reduced)
}

pub fn parse_anchor_base(bytes: &[u8]) -> Result<Point> {
    match MaybePoint::from_slice(bytes)
        .map_err(|_| ThunderboltError::InvalidPoint("anchor base bytes are not a valid secp256k1 point".to_string()))?
    {
        MaybePoint::Valid(point) => Ok(point),
        MaybePoint::Infinity => Err(ThunderboltError::InvalidPoint(
            "anchor base must not be the point at infinity".to_string(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scalar_from_u8(value: u8) -> Scalar {
        let mut bytes = [0u8; 32];
        bytes[31] = value;
        Scalar::from_slice(&bytes).unwrap()
    }

    #[test]
    fn parses_and_rejects_anchor_base_bytes() {
        let point = scalar_from_u8(42).base_point_mul();
        let parsed = parse_anchor_base(&point.serialize()).unwrap();
        assert_eq!(parsed, point);
        assert!(parse_anchor_base(&[0u8; 33]).is_err());
    }

    #[test]
    fn reduces_large_big_numbers_mod_curve_order() {
        let value = curve_order().clone() + BigNumber::from(11u32);
        let reduced = reduce_big_number_mod_curve_order(&value).unwrap();
        assert_eq!(reduced, MaybeScalar::Valid(scalar_from_u8(11)));
    }

    #[test]
    fn proof_context_rejects_empty_and_oversized_identifiers() {
        assert!(ProofContext::invoice([], b"invoice").expect_invoice().is_err());
        assert!(ProofContext::invoice(b"channel", []).expect_invoice().is_err());
        assert!(ProofContext::invoice(vec![1; MAX_CONTEXT_ID_BYTES + 1], b"invoice")
            .expect_invoice()
            .is_err());
        assert!(ProofContext::transfer(b"channel", 1, vec![1; MAX_INVOICE_ID_BYTES + 1])
            .expect_transfer()
            .is_err());
    }

    #[test]
    fn integer_response_rejects_excessive_values() {
        let oversized = BigNumber::one() << (masking_range().bit_length() + 2);
        assert!(IntegerResponse::new(oversized).is_err());
    }
}
