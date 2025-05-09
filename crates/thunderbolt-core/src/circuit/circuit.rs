use frost_secp256k1::rand_core::OsRng;
use halo2_base::halo2_proofs::halo2curves::bn256::Fr;
use halo2_base::halo2_proofs::halo2curves::group::Curve;

use halo2_base::halo2_proofs::halo2curves::serde::SerdeObject;
use halo2_base::utils::testing::{check_proof_with_instances, gen_proof_with_instances};
use halo2_base::{
    gates::{
        circuit::{builder::RangeCircuitBuilder, CircuitBuilderStage},
        RangeChip,
    },
    halo2_proofs::{
        arithmetic::Field,
        halo2curves::secp256k1::{Fq, Secp256k1Affine},
        plonk::{keygen_pk, keygen_vk},
    },
    poseidon::hasher::spec::OptimizedPoseidonSpec,
    utils::{fs::gen_srs, BigPrimeField},
    AssignedValue, Context,
};
use halo2_ecc::{
    bigint::ProperCrtUint,
    ecc::{EcPoint, EccChip},
    fields::FieldChip,
    secp256k1::{FpChip, FqChip},
};
use pse_poseidon::Poseidon;
use std::time::Instant;

use crate::circuit::{gate::ForeignGate, hasher::PoseidonForeignHasher};

pub const LIMB_BITS: usize = 88;
pub const NUM_LIMBS: usize = 3;
pub const WINDOW_BITS: usize = 4;
pub const T: usize = 3;
pub const RATE: usize = 2;
pub const R_F: usize = 8;
pub const R_P: usize = 57;

#[derive(Debug, Clone, Default)]
/// Represents all inputs and outputs for the shared secret derivation and commitment flow.
pub struct SharedSecretProofData {
    /// The secret scalar (private key).
    pub sk: Fq,

    /// The counterparty's public key.
    pub pk_b: Secp256k1Affine,

    /// The Poseidon hash output derived from the shared secret point.
    pub secret: Fq,

    /// The output public key = secret * G.
    pub pk_c: Secp256k1Affine,
}

impl SharedSecretProofData {
    pub fn generate() -> Self {
        // Sample the secret key `sk ∈ Fq`
        let sk = Fq::random(OsRng);

        // Sample the counterparty's secret `b ∈ Fq`, and compute `pk_b = b ⋅ G`
        let b = Fq::random(OsRng);
        let pk_b = (Secp256k1Affine::generator() * b).to_affine();

        // Derive the shared point: `P = sk ⋅ pk_b`
        let shared_point = (pk_b * sk).to_affine();

        // Hash the affine coordinates of the shared point using SHA-256
        let x_bytes = shared_point.x.to_raw_bytes();
        let y_bytes = shared_point.y.to_raw_bytes();
        //  TODO: Need hash.
        let mut native_sponge = Poseidon::<Fq, T, RATE>::new(R_F, R_P);
        // native_sponge.update(&[x_bytes, y_bytes]);
        let secret = native_sponge.squeeze();
        todo!();

        // Compute the final public key: `pk_c = secret ⋅ G`
        let pk_c = (Secp256k1Affine::generator() * secret).to_affine();

        // Self { sk, pk_b, secret, pk_c }
    }
}

#[derive(Debug, Clone)]
pub struct SharePKCircuitParams {
    pub(crate) k: usize,
    pub(crate) lookup_bits: usize,
    pub(crate) unusable_rows: usize,
    pub(crate) data: SharedSecretProofData,
}

impl Default for SharePKCircuitParams {
    fn default() -> Self {
        Self {
            k: 17,
            lookup_bits: 9,
            unusable_rows: 9,
            data: SharedSecretProofData::default(),
        }
    }
}

pub fn prove_pk_share(params: SharePKCircuitParams) {
    let t_start = Instant::now();

    // === Phase 1: Setup (Keygen builder) ===
    let mut builder = RangeCircuitBuilder::from_stage(CircuitBuilderStage::Keygen).use_k(params.k);
    builder.set_lookup_bits(params.lookup_bits);
    builder.set_instance_columns(1);

    let range = RangeChip::new(params.lookup_bits, builder.lookup_manager().clone());
    let t0 = Instant::now();

    let outputs = generate_share_pk(builder.main(0), &range, SharedSecretProofData::default());
    for val in outputs {
        builder.assigned_instances[0].push(val);
    }
    println!(">> generate_share_pk (keygen) done in {:?}", t0.elapsed());

    let t1 = Instant::now();
    let t_cells_lookup = builder.lookup_manager().iter().map(|lm| lm.total_rows()).sum::<usize>();
    let lookup_bits = if t_cells_lookup == 0 {
        None
    } else {
        Some(params.lookup_bits)
    };
    builder.config_params.lookup_bits = lookup_bits;

    let config_params = builder.calculate_params(Some(params.unusable_rows));
    println!(">> calculate_params done in {:?}", t1.elapsed());

    let t2 = Instant::now();
    let params_kzg = gen_srs(params.k as u32);
    let vk = keygen_vk(&params_kzg, &builder).unwrap();
    let pk = keygen_pk(&params_kzg, vk, &builder).unwrap();
    println!(">> keygen_vk + keygen_pk done in {:?}", t2.elapsed());

    let break_points = builder.break_points();
    drop(builder);

    // === Phase 2: Prover ===
    let t3 = Instant::now();
    let mut builder = RangeCircuitBuilder::prover(config_params.clone(), break_points);
    let range = RangeChip::new(params.lookup_bits, builder.lookup_manager().clone());

    let outputs = generate_share_pk(builder.main(0), &range, params.data);
    for val in outputs.clone() {
        builder.assigned_instances[0].push(val);
    }
    println!(">> generate_share_pk (prover) done in {:?}", t3.elapsed());

    // === Phase 3: Proof generation ===
    let t4 = Instant::now();

    let instances_vec: Vec<Fr> = outputs.iter().map(|v| *v.value()).collect(); // 不是 &Fr，是 Fr
    let instance_slices: Vec<&[Fr]> = vec![instances_vec.as_slice()];
    let instances: &[&[Fr]] = &instance_slices;
    let proof = gen_proof_with_instances(&params_kzg, &pk, builder, &instances);
    println!(">> gen_proof done in {:?}", t4.elapsed());

    // === Phase 4: Verification ===
    let t5 = Instant::now();
    check_proof_with_instances(&params_kzg, pk.get_vk(), &proof, &instances, true);
    println!(">> check_proof done in {:?}", t5.elapsed());

    println!(">> TOTAL prove_pk_share done in {:?}", t_start.elapsed());
}

fn generate_share_pk<F: BigPrimeField>(
    ctx: &mut Context<F>,
    range: &RangeChip<F>,
    shared_data: SharedSecretProofData,
) -> Vec<AssignedValue<F>> {
    let fq_chip = FqChip::<F>::new(range, LIMB_BITS, NUM_LIMBS);
    let sk = fq_chip.load_private(ctx, shared_data.sk);
    let (pk_b, shared_secret) = scalar_multiply(ctx, range, shared_data.pk_b, false, sk);

    let secret = hash_shared_secret(ctx, range, &shared_secret);
    let generator = Secp256k1Affine::generator();
    let (_, pk_c) = scalar_multiply(ctx, range, generator, true, secret);

    let mut public_inputs = vec![];
    public_inputs.extend(pk_b.x().limbs());
    public_inputs.extend(pk_b.y().limbs());
    public_inputs.extend(pk_c.x().limbs());
    public_inputs.extend(pk_c.y().limbs());
    public_inputs
}

fn hash_shared_secret<F: BigPrimeField>(
    ctx: &mut Context<F>,
    range: &RangeChip<F>,
    point: &EcPoint<F, ProperCrtUint<F>>,
) -> ProperCrtUint<F> {
    let fq_chip = FqChip::<F>::new(range, LIMB_BITS, NUM_LIMBS);
    let spec = OptimizedPoseidonSpec::<Fq, T, RATE>::new::<R_F, R_P, 0>();
    let limbs = vec![point.x().clone(), point.y().clone()];
    let mut hasher = PoseidonForeignHasher::<F, T, RATE>::new(spec);
    let gate = ForeignGate::new(fq_chip.clone());
    hasher.initialize_consts(ctx, &fq_chip, &gate);

    hasher.hash_fix_len_array(ctx, &gate, &limbs)
}

fn scalar_multiply<F: BigPrimeField>(
    ctx: &mut Context<F>,
    range: &RangeChip<F>,
    base: Secp256k1Affine,
    is_base_const: bool,
    scalar: ProperCrtUint<F>,
) -> (EcPoint<F, ProperCrtUint<F>>, EcPoint<F, ProperCrtUint<F>>) {
    let fp_chip = FpChip::<F>::new(range, LIMB_BITS, NUM_LIMBS);

    let ecc_chip = EccChip::<F, FpChip<F>>::new(&fp_chip);

    let p = if is_base_const {
        ecc_chip.assign_constant_point(ctx, base)
    } else {
        ecc_chip.assign_point_unchecked(ctx, base)
    };

    let sm = ecc_chip.scalar_mult::<Secp256k1Affine>(ctx, p.clone(), scalar.limbs().to_vec(), LIMB_BITS, WINDOW_BITS);

    (p, sm)
}

#[cfg(test)]
mod test {
    use super::*;
    use super::{prove_pk_share, SharePKCircuitParams, SharedSecretProofData};

    #[test]
    fn test_prove_pk_share_soundness() {
        let mut params = SharePKCircuitParams::default();

        params.data = SharedSecretProofData {
            sk: todo!(),
            pk_b: todo!(),
            secret: todo!(),
            pk_c: todo!(),
        };
        prove_pk_share(params);
    }

    fn random_shared_secret_proof_data() -> SharedSecretProofData {
        let sk = loop {
            let val = Fq::random(OsRng);
            if !bool::from(val.is_zero()) {
                break val;
            }
        };

        let b = Fq::random(OsRng);
        let pk_b = (Secp256k1Affine::generator() * b).to_affine();

        SharedSecretProofData {
            sk,
            pk_b,
            ..Default::default()
        }
    }

    #[test]
    fn test_prove_pk_share_consistency() {
        let mut params = SharePKCircuitParams::default();
        params.data = random_shared_secret_proof_data();
        prove_pk_share(params);
    }
}
