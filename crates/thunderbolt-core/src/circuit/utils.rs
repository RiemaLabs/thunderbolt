use halo2_base::halo2_proofs::halo2curves::bn256::Fr;
use halo2_base::halo2_proofs::halo2curves::ff::PrimeField;
use halo2_base::halo2_proofs::halo2curves::secp256k1::{Fp, Fq};
use halo2_base::utils::{biguint_to_fe, decompose_biguint, BigPrimeField, ScalarField};
use num_bigint::BigUint;
use num_traits::Num;

use super::circuit::SharedSecretProofData;
use super::{LIMB_BITS, NUM_LIMBS};

pub fn fq_mod_from_bytes_le(bytes: &[u8]) -> Fq {
    let bigint = BigUint::from_bytes_le(bytes);
    let fq_modulus = BigUint::from_str_radix(&Fq::MODULUS[2..], 16).unwrap();
    let reduced = bigint % fq_modulus;
    biguint_to_fe::<Fq>(&reduced)
}

pub fn generate_instances_from_data(data: &SharedSecretProofData) -> Vec<Fr> {
    let mut instances = Vec::new();

    let limbs_from_fq = |fq: &Fp| -> Vec<Fr> {
        let bigint = BigUint::from_bytes_le(fq.to_bytes_le().as_slice());
        decompose_biguint::<Fr>(&bigint, NUM_LIMBS, LIMB_BITS)
    };
    instances.extend(limbs_from_fq(&data.pk_b.x));
    instances.extend(limbs_from_fq(&data.pk_b.y));
    instances.extend(limbs_from_fq(&data.pk_c.x));
    instances.extend(limbs_from_fq(&data.pk_c.y));

    instances
}
