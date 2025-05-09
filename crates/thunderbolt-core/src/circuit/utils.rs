use std::str::FromStr;

use halo2_base::halo2_proofs::halo2curves::ff::PrimeField;
use halo2_base::halo2_proofs::halo2curves::secp256k1::Fq;
use halo2_base::utils::{biguint_to_fe, BigPrimeField};
use num_bigint::BigUint;
use num_traits::Num;

pub fn fq_mod_from_bytes_le(bytes: &[u8]) -> Fq {
    let bigint = BigUint::from_bytes_le(bytes);
    let fq_modulus = BigUint::from_str_radix(&Fq::MODULUS[2..], 16).unwrap();
    let reduced = bigint % fq_modulus;
    biguint_to_fe::<Fq>(&reduced)
}

pub fn dump_fe<F: BigPrimeField>(f: &F) -> String {
    format!("{}", BigUint::from_bytes_le(&f.to_bytes_le()))
}
