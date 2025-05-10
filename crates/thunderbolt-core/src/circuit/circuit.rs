use frost_secp256k1::rand_core::OsRng;
use halo2_base::gates::circuit::BaseCircuitParams;
use halo2_base::halo2_proofs::halo2curves::bn256::{Bn256, Fr, G1Affine};
use halo2_base::halo2_proofs::halo2curves::group::Curve;

use halo2_base::halo2_proofs::plonk::{ProvingKey, VerifyingKey};
use halo2_base::halo2_proofs::poly::kzg::commitment::ParamsKZG;
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

use crate::circuit::utils::fq_mod_from_bytes_le;
use crate::circuit::{gate::ForeignGate, hasher::PoseidonForeignHasher};

use super::utils::generate_instances_from_data;
use super::{LIMB_BITS, NUM_LIMBS, RATE, R_F, R_P, T};

pub(crate) const WINDOW_BITS: usize = 4;

pub type ProofBytes = Vec<u8>;
pub type BreakPoint = Vec<Vec<usize>>;
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
    fn generate() -> Self {
        // Sample the secret key `sk ∈ Fq`
        let sk = Fq::random(OsRng);
        // Sample the counterparty's secret `b ∈ Fq`, and compute `pk_b = b ⋅ G`
        let b = Fq::random(OsRng);
        let pk_b = (Secp256k1Affine::generator() * b).to_affine();

        // Derive the shared point: `P = sk ⋅ pk_b`
        let shared_point = (pk_b * sk).to_affine();
        // Hash the affine coordinates of the shared point using Poseidon
        let x_bytes = shared_point.x.to_bytes();
        let y_bytes = shared_point.y.to_bytes();
        let x = fq_mod_from_bytes_le(&x_bytes);
        let y = fq_mod_from_bytes_le(&y_bytes);
        let mut native_sponge = Poseidon::<Fq, T, RATE>::new(R_F, R_P);
        native_sponge.update(&[x, y]);
        let secret = native_sponge.squeeze();

        // Compute the final public key: `pk_c = secret ⋅ G`
        let pk_c = (Secp256k1Affine::generator() * secret).to_affine();

        Self { sk, pk_b, secret, pk_c }
    }
}

#[derive(Debug, Clone)]
pub struct SharePKCircuitConfig {
    pub(crate) k: usize,
    pub(crate) lookup_bits: usize,
    pub(crate) unusable_rows: usize,
}

#[derive(Debug, Clone)]
pub struct SharePKCircuitParams {
    pub(crate) params_kzg: ParamsKZG<Bn256>,
    pub(crate) breakpoint: BreakPoint,
    pub(crate) circuit_params: BaseCircuitParams,
}

impl Default for SharePKCircuitConfig {
    fn default() -> Self {
        Self {
            k: 17,
            lookup_bits: 9,
            unusable_rows: 9,
        }
    }
}

pub fn setup(params: &SharePKCircuitConfig) -> (SharePKCircuitParams, ProvingKey<G1Affine>, VerifyingKey<G1Affine>) {
    let mut builder = RangeCircuitBuilder::from_stage(CircuitBuilderStage::Keygen).use_k(params.k);
    builder.set_lookup_bits(params.lookup_bits);
    builder.set_instance_columns(1);

    let range = RangeChip::new(params.lookup_bits, builder.lookup_manager().clone());
    let outputs = generate_share_pk(builder.main(0), &range, SharedSecretProofData::default());

    for val in outputs {
        builder.assigned_instances[0].push(val);
    }

    let t_cells_lookup = builder.lookup_manager().iter().map(|lm| lm.total_rows()).sum::<usize>();
    builder.config_params.lookup_bits = if t_cells_lookup == 0 {
        None
    } else {
        Some(params.lookup_bits)
    };

    let circuit_params = builder.calculate_params(Some(params.unusable_rows));

    let params_kzg = gen_srs(params.k as u32);

    let vk = keygen_vk(&params_kzg, &builder).unwrap();
    let pk = keygen_pk(&params_kzg, vk.clone(), &builder).unwrap();
    let breakpoint = builder.break_points();
    drop(builder);
    (
        SharePKCircuitParams {
            params_kzg,
            circuit_params,
            breakpoint,
        },
        pk,
        vk,
    )
}

pub fn prove(params: &SharePKCircuitParams, pk: &ProvingKey<G1Affine>, data: SharedSecretProofData) -> ProofBytes {
    let circuit_params = &params.circuit_params;
    let breakpoint = &params.breakpoint;
    let params_kzg = &params.params_kzg;

    let mut builder = RangeCircuitBuilder::prover(circuit_params.clone(), breakpoint.clone());
    let range = RangeChip::new(
        circuit_params.lookup_bits.unwrap_or_default(),
        builder.lookup_manager().clone(),
    );

    let outputs = generate_share_pk(builder.main(0), &range, data);
    for val in outputs.clone() {
        builder.assigned_instances[0].push(val);
    }

    let instances_vec: Vec<Fr> = outputs.iter().map(|v| *v.value()).collect();
    let instance_slices: Vec<&[Fr]> = vec![instances_vec.as_slice()];
    gen_proof_with_instances(&params_kzg, pk, builder, &instance_slices)
}

pub fn verify(
    params: &SharePKCircuitParams,
    vk: &VerifyingKey<G1Affine>,
    data: SharedSecretProofData,
    proof: &ProofBytes,
) {
    let params_kzg = params.params_kzg.clone();

    let instances = generate_instances_from_data(&data);
    let instances_slice = [instances.as_slice()];
    check_proof_with_instances(&params_kzg, vk, proof, &instances_slice, true)
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

    #[cfg(feature = "sanity-check")]
    if shared_data.sk != Fq::zero() {
        assert_eq!(
            shared_data.pk_c.x,
            Fp::from_bytes_le(pk_c.x().value().to_bytes_le().as_slice())
        );
        assert_eq!(
            shared_data.pk_c.y,
            Fp::from_bytes_le(pk_c.y().value().to_bytes_le().as_slice())
        );
    }

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
    hasher.initialize_consts(ctx, &fq_chip);
    let gate = ForeignGate::new(fq_chip);
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
    use super::{prove, SharePKCircuitConfig, SharedSecretProofData};

    #[test]
    fn test_prove_soundness() {
        let config = SharePKCircuitConfig::default();
        let (params, pk, vk) = setup(&config);
        let data = SharedSecretProofData::generate();
        let proof = prove(&params, &pk, data.clone());
        verify(&params, &vk, data, &proof);
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
    fn test_prove_consistency() {
        let config = SharePKCircuitConfig::default();
        let (params, pk, _) = setup(&config);
        let data = random_shared_secret_proof_data();
        let _ = prove(&params, &pk, data.clone());
    }
}
