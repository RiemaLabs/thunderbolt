#![no_std]

extern crate alloc;

use alloc::vec::Vec;
use crypto_bigint::{
    modular::runtime_mod::{DynResidue, DynResidueParams},
    Concat, Encoding, Uint,
};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TransferPublicValues {
    pub next_holder: u64,
    pub next_committee: u64,
    pub invariant_before: u64,
    pub invariant_after: u64,
}

impl TransferPublicValues {
    pub fn to_bytes(self) -> [u8; 32] {
        let mut out = [0u8; 32];
        out[0..8].copy_from_slice(&self.next_holder.to_le_bytes());
        out[8..16].copy_from_slice(&self.next_committee.to_le_bytes());
        out[16..24].copy_from_slice(&self.invariant_before.to_le_bytes());
        out[24..32].copy_from_slice(&self.invariant_after.to_le_bytes());
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Self {
        assert!(bytes.len() >= 32);
        let mut chunk = [0u8; 8];
        chunk.copy_from_slice(&bytes[0..8]);
        let next_holder = u64::from_le_bytes(chunk);
        chunk.copy_from_slice(&bytes[8..16]);
        let next_committee = u64::from_le_bytes(chunk);
        chunk.copy_from_slice(&bytes[16..24]);
        let invariant_before = u64::from_le_bytes(chunk);
        chunk.copy_from_slice(&bytes[24..32]);
        let invariant_after = u64::from_le_bytes(chunk);
        Self {
            next_holder,
            next_committee,
            invariant_before,
            invariant_after,
        }
    }
}

pub fn transfer_step(holder_secret: u64, refresh: u64, committee_share: u64) -> TransferPublicValues {
    let next_holder = holder_secret.checked_add(refresh).expect("holder + refresh overflowed");
    let next_committee = committee_share.checked_sub(refresh).expect("committee - refresh underflowed");
    let invariant_before = holder_secret.checked_add(committee_share).expect("before invariant overflowed");
    let invariant_after = next_holder.checked_add(next_committee).expect("after invariant overflowed");
    assert_eq!(invariant_before, invariant_after, "transfer invariant must be preserved");
    TransferPublicValues {
        next_holder,
        next_committee,
        invariant_before,
        invariant_after,
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InvoicePaillierInput {
    pub bob_modulus: Vec<u8>,
    pub committee_modulus: Vec<u8>,
    pub bob_ciphertext: Vec<u8>,
    pub committee_ciphertext: Vec<u8>,
    pub a_bob: Vec<u8>,
    pub a_committee: Vec<u8>,
    pub challenge: Vec<u8>,
    pub z: Vec<u8>,
    pub tau_bob: Vec<u8>,
    pub tau_committee: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransferPaillierInput {
    pub bob_modulus: Vec<u8>,
    pub invoice_ciphertext: Vec<u8>,
    pub next_holder_ciphertext: Vec<u8>,
    pub a_ciphertext: Vec<u8>,
    pub challenge: Vec<u8>,
    pub z: Vec<u8>,
    pub tau: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FullBenchmarkInput {
    pub modulus_bits: usize,
    pub invoice: InvoicePaillierInput,
    pub transfer: TransferPaillierInput,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FullBenchmarkPublicValues {
    pub invoice_bob_prefix: [u8; 16],
    pub invoice_committee_prefix: [u8; 16],
    pub transfer_prefix: [u8; 16],
}

impl FullBenchmarkPublicValues {
    pub fn to_bytes(&self) -> [u8; 48] {
        let mut out = [0u8; 48];
        out[0..16].copy_from_slice(&self.invoice_bob_prefix);
        out[16..32].copy_from_slice(&self.invoice_committee_prefix);
        out[32..48].copy_from_slice(&self.transfer_prefix);
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Self {
        assert!(bytes.len() >= 48);
        let mut invoice_bob_prefix = [0u8; 16];
        let mut invoice_committee_prefix = [0u8; 16];
        let mut transfer_prefix = [0u8; 16];
        invoice_bob_prefix.copy_from_slice(&bytes[0..16]);
        invoice_committee_prefix.copy_from_slice(&bytes[16..32]);
        transfer_prefix.copy_from_slice(&bytes[32..48]);
        Self {
            invoice_bob_prefix,
            invoice_committee_prefix,
            transfer_prefix,
        }
    }
}

fn parse_uint<const LIMBS: usize>(bytes: &[u8]) -> Uint<LIMBS> {
    assert_eq!(bytes.len(), Uint::<LIMBS>::BYTES);
    Uint::<LIMBS>::from_be_slice(bytes)
}

fn lift_uint<const MLIMBS: usize, const DLIMBS: usize>(value: &Uint<MLIMBS>) -> Uint<DLIMBS>
where
    Uint<MLIMBS>: Concat<Output = Uint<DLIMBS>>,
{
    Uint::<MLIMBS>::ZERO.concat(value)
}

fn ciphertext_lhs<const MLIMBS: usize, const DLIMBS: usize>(
    modulus: &Uint<MLIMBS>,
    z: &Uint<MLIMBS>,
    tau: &Uint<MLIMBS>,
) -> Uint<DLIMBS>
where
    Uint<MLIMBS>: Concat<Output = Uint<DLIMBS>>,
{
    let modulus_sq: Uint<DLIMBS> = modulus.square();
    let params = DynResidueParams::new(&modulus_sq);
    let g = lift_uint::<MLIMBS, DLIMBS>(modulus).wrapping_add(&Uint::<DLIMBS>::ONE);
    let g_term = DynResidue::new(&g, params).pow(z).retrieve();
    let tau_term = DynResidue::new(&lift_uint::<MLIMBS, DLIMBS>(tau), params)
        .pow(modulus)
        .retrieve();
    (DynResidue::new(&g_term, params) * DynResidue::new(&tau_term, params)).retrieve()
}

fn ciphertext_pow<const MLIMBS: usize, const DLIMBS: usize>(
    modulus: &Uint<MLIMBS>,
    ciphertext: &Uint<DLIMBS>,
    exponent: &Uint<MLIMBS>,
) -> Uint<DLIMBS>
where
    Uint<MLIMBS>: Concat<Output = Uint<DLIMBS>>,
{
    let modulus_sq: Uint<DLIMBS> = modulus.square();
    let params = DynResidueParams::new(&modulus_sq);
    DynResidue::new(ciphertext, params).pow(exponent).retrieve()
}

fn ciphertext_mul<const MLIMBS: usize, const DLIMBS: usize>(
    modulus: &Uint<MLIMBS>,
    left: &Uint<DLIMBS>,
    right: &Uint<DLIMBS>,
) -> Uint<DLIMBS>
where
    Uint<MLIMBS>: Concat<Output = Uint<DLIMBS>>,
{
    let modulus_sq: Uint<DLIMBS> = modulus.square();
    let params = DynResidueParams::new(&modulus_sq);
    (DynResidue::new(left, params) * DynResidue::new(right, params)).retrieve()
}

fn ciphertext_div<const MLIMBS: usize, const DLIMBS: usize>(
    modulus: &Uint<MLIMBS>,
    numerator: &Uint<DLIMBS>,
    denominator: &Uint<DLIMBS>,
) -> Uint<DLIMBS>
where
    Uint<MLIMBS>: Concat<Output = Uint<DLIMBS>>,
{
    let modulus_sq: Uint<DLIMBS> = modulus.square();
    let params = DynResidueParams::new(&modulus_sq);
    let numerator_residue = DynResidue::new(numerator, params);
    let denominator_residue = DynResidue::new(denominator, params);
    let (inverse, is_some) = denominator_residue.invert();
    assert!(bool::from(is_some), "transfer benchmark ciphertext must be invertible mod N^2");
    (numerator_residue * inverse).retrieve()
}

fn prefix16<const DLIMBS: usize>(value: &Uint<DLIMBS>) -> [u8; 16]
where
    Uint<DLIMBS>: Encoding,
{
    let bytes = value.to_be_bytes();
    let bytes = bytes.as_ref();
    let mut prefix = [0u8; 16];
    prefix.copy_from_slice(&bytes[0..16]);
    prefix
}

fn prove_full_relation_typed<const MLIMBS: usize, const DLIMBS: usize>(
    input: &FullBenchmarkInput,
) -> FullBenchmarkPublicValues
where
    Uint<MLIMBS>: Concat<Output = Uint<DLIMBS>>,
    Uint<DLIMBS>: Encoding,
{
    let invoice_bob_modulus = parse_uint::<MLIMBS>(&input.invoice.bob_modulus);
    let invoice_committee_modulus = parse_uint::<MLIMBS>(&input.invoice.committee_modulus);
    let invoice_bob_ciphertext = parse_uint::<DLIMBS>(&input.invoice.bob_ciphertext);
    let invoice_committee_ciphertext = parse_uint::<DLIMBS>(&input.invoice.committee_ciphertext);
    let invoice_a_bob = parse_uint::<DLIMBS>(&input.invoice.a_bob);
    let invoice_a_committee = parse_uint::<DLIMBS>(&input.invoice.a_committee);
    let invoice_challenge = parse_uint::<MLIMBS>(&input.invoice.challenge);
    let invoice_z = parse_uint::<MLIMBS>(&input.invoice.z);
    let invoice_tau_bob = parse_uint::<MLIMBS>(&input.invoice.tau_bob);
    let invoice_tau_committee = parse_uint::<MLIMBS>(&input.invoice.tau_committee);

    let invoice_bob_lhs =
        ciphertext_lhs::<MLIMBS, DLIMBS>(&invoice_bob_modulus, &invoice_z, &invoice_tau_bob);
    let invoice_bob_rhs = ciphertext_mul(
        &invoice_bob_modulus,
        &invoice_a_bob,
        &ciphertext_pow(&invoice_bob_modulus, &invoice_bob_ciphertext, &invoice_challenge),
    );
    assert_eq!(invoice_bob_lhs, invoice_bob_rhs, "invoice Bob Paillier equation failed");

    let invoice_committee_lhs = ciphertext_lhs::<MLIMBS, DLIMBS>(
        &invoice_committee_modulus,
        &invoice_z,
        &invoice_tau_committee,
    );
    let invoice_committee_rhs = ciphertext_mul(
        &invoice_committee_modulus,
        &invoice_a_committee,
        &ciphertext_pow(
            &invoice_committee_modulus,
            &invoice_committee_ciphertext,
            &invoice_challenge,
        ),
    );
    assert_eq!(
        invoice_committee_lhs, invoice_committee_rhs,
        "invoice committee Paillier equation failed"
    );

    let transfer_bob_modulus = parse_uint::<MLIMBS>(&input.transfer.bob_modulus);
    let transfer_invoice_ciphertext = parse_uint::<DLIMBS>(&input.transfer.invoice_ciphertext);
    let transfer_next_holder_ciphertext = parse_uint::<DLIMBS>(&input.transfer.next_holder_ciphertext);
    let transfer_a_ciphertext = parse_uint::<DLIMBS>(&input.transfer.a_ciphertext);
    let transfer_challenge = parse_uint::<MLIMBS>(&input.transfer.challenge);
    let transfer_z = parse_uint::<MLIMBS>(&input.transfer.z);
    let transfer_tau = parse_uint::<MLIMBS>(&input.transfer.tau);

    let transfer_offset = ciphertext_div(
        &transfer_bob_modulus,
        &transfer_next_holder_ciphertext,
        &transfer_invoice_ciphertext,
    );
    let transfer_lhs = ciphertext_lhs::<MLIMBS, DLIMBS>(&transfer_bob_modulus, &transfer_z, &transfer_tau);
    let transfer_rhs = ciphertext_mul(
        &transfer_bob_modulus,
        &transfer_a_ciphertext,
        &ciphertext_pow(&transfer_bob_modulus, &transfer_offset, &transfer_challenge),
    );
    assert_eq!(transfer_lhs, transfer_rhs, "transfer Paillier equation failed");

    FullBenchmarkPublicValues {
        invoice_bob_prefix: prefix16(&invoice_bob_lhs),
        invoice_committee_prefix: prefix16(&invoice_committee_lhs),
        transfer_prefix: prefix16(&transfer_lhs),
    }
}

pub fn prove_full_relation(input: &FullBenchmarkInput) -> FullBenchmarkPublicValues {
    match input.modulus_bits {
        128 => prove_full_relation_typed::<2, 4>(input),
        256 => prove_full_relation_typed::<4, 8>(input),
        512 => prove_full_relation_typed::<8, 16>(input),
        1024 => prove_full_relation_typed::<16, 32>(input),
        2048 => prove_full_relation_typed::<32, 64>(input),
        3072 => prove_full_relation_typed::<48, 96>(input),
        other => panic!("unsupported Paillier modulus size {other}; expected 128, 256, 512, 1024, 2048, or 3072"),
    }
}
