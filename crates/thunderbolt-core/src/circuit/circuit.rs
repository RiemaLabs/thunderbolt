use frost_secp256k1::rand_core::OsRng;
use halo2_base::halo2_proofs::halo2curves::group::Curve;

use halo2_base::halo2_proofs::halo2curves::serde::SerdeObject;
use halo2_base::utils::biguint_to_fe;
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
    utils::{
        fs::gen_srs,
        testing::{check_proof, gen_proof},
        BigPrimeField,
    },
    AssignedValue, Context,
};
use halo2_ecc::{
    bigint::ProperCrtUint,
    ecc::{EcPoint, EccChip},
    fields::FieldChip,
    secp256k1::{FpChip, FqChip},
};
use num_bigint::BigUint;

use crate::circuit::{gate::ForeignGate, hasher::PoseidonForeignHasher};

pub const LIMB_BITS: usize = 88;
pub const NUM_LIMBS: usize = 3;
pub const WINDOW_BITS: usize = 4;

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
        todo!()
        // Interpret the hash output as a scalar `secret ∈ Fq`
        // let hash_bigint = BigUint::from_bytes_be(&hash_bytes);
        // let secret = biguint_to_fe::<Fq>(&hash_bigint);

        // Compute the final public key: `pk_c = secret ⋅ G`
        // let pk_c = (Secp256k1Affine::generator() * secret).to_affine();

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
            k: 18,
            lookup_bits: 9,
            unusable_rows: 9,
            data: SharedSecretProofData::default(),
        }
    }
}

pub fn prove_pk_share(params: SharePKCircuitParams) {
    let mut builder = RangeCircuitBuilder::from_stage(CircuitBuilderStage::Keygen).use_k(params.k);
    builder.set_lookup_bits(params.lookup_bits);
    builder.set_instance_columns(1);

    let range = RangeChip::new(params.lookup_bits, builder.lookup_manager().clone());

    generate_share_pk(builder.main(0), &range, SharedSecretProofData::default());

    // helper check: if your function didn't use lookups, turn lookup table "off"
    let t_cells_lookup = builder.lookup_manager().iter().map(|lm| lm.total_rows()).sum::<usize>();
    let lookup_bits = if t_cells_lookup == 0 {
        None
    } else {
        Some(params.lookup_bits)
    };
    builder.config_params.lookup_bits = lookup_bits;

    // configure the circuit shape, 9 blinding rows seems enough
    let config_params = builder.calculate_params(Some(params.unusable_rows));
    let params_kzg = gen_srs(params.k as u32);

    let vk = keygen_vk(&params_kzg, &builder).unwrap();
    let pk = keygen_pk(&params_kzg, vk, &builder).unwrap();

    let break_points = builder.break_points();
    drop(builder);

    // create real proof
    let mut builder = RangeCircuitBuilder::prover(config_params.clone(), break_points);
    let range = RangeChip::new(params.lookup_bits, builder.lookup_manager().clone());

    let outputs = generate_share_pk(builder.main(0), &range, params.data);
    for val in outputs {
        builder.assigned_instances[0].push(val);
    }
    // prove
    let proof = gen_proof(&params_kzg, &pk, builder);

    // verify
    check_proof(&params_kzg, pk.get_vk(), &proof, true);
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
    const T: usize = 3;
    const RATE: usize = 2;

    let fq_chip = FqChip::<F>::new(range, LIMB_BITS, NUM_LIMBS);
    let spec = OptimizedPoseidonSpec::<Fq, 3, 2>::new::<8, 57, 0>();
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
    use super::{prove_pk_share, SharePKCircuitParams, SharedSecretProofData};

    #[test]
    fn test_prove_pk_share() {
        let mut params = SharePKCircuitParams::default();

        let sk = Scalar::random(OsRng);

        params.data = SharedSecretProofData {
            sk: todo!(),
            pk_b: todo!(),
            secret: todo!(),
            pk_c: todo!(),
        };
        prove_pk_share(params);
    }
}
