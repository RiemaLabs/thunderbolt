use halo2_base::halo2_proofs::halo2curves::secp256k1::Fq;
use pse_poseidon::Poseidon;
use utils::fq_mod_from_bytes_le;

pub mod circuit;
/// Module for the Poseidon hash function in Foreign Field (Secp256-K1).
pub(super) mod hasher;
pub(super) mod state;

pub(super) mod gate;
pub(super) mod utils;

pub(crate) const LIMB_BITS: usize = 88;
pub(crate) const NUM_LIMBS: usize = 3;
pub(crate) const T: usize = 3;
pub(crate) const RATE: usize = 2;
pub(crate) const R_F: usize = 8;
pub(crate) const R_P: usize = 57;

pub fn hash_affine_point(input: &[u8; 64]) -> [u8; 32] {
    let (x_bytes, y_bytes) = input.split_at(32);

    let x = fq_mod_from_bytes_le(x_bytes);
    let y = fq_mod_from_bytes_le(y_bytes);

    let mut sponge = Poseidon::<Fq, T, RATE>::new(R_F, R_P);
    sponge.update(&[x, y]);
    let secret = sponge.squeeze();

    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&secret.to_bytes());
    bytes
}
