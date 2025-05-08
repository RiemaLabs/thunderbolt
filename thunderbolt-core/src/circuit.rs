

use itertools::Itertools;

use halo2_base::{
    gates::{
        circuit::{builder::RangeCircuitBuilder, CircuitBuilderStage},
        RangeChip, RangeInstructions,
    },
    halo2_proofs::{
        halo2curves::secp256k1::{Fq, Secp256k1Affine},
        plonk::{keygen_pk, keygen_vk},
    },
    poseidon::hasher::{spec::OptimizedPoseidonSpec, PoseidonHasher},
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

#[derive(Debug, Clone)]
pub struct SharePKCircuitParams {
    k: usize,
    lookup_bits: usize,
    unusable_rows: usize,
    data: SharedSecretProofData,
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
    let t_cells_lookup = builder
        .lookup_manager()
        .iter()
        .map(|lm| lm.total_rows())
        .sum::<usize>();
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
    let (pk_b, shared_secret) = scalar_multiply(ctx, range, shared_data.pk_b, shared_data.sk);
    let secret = hash_shared_secret(ctx, range, &shared_secret);

    let generator = Secp256k1Affine::generator();

    todo!()
}

fn hash_shared_secret<F: BigPrimeField>(
    ctx: &mut Context<F>,
    range: &RangeChip<F>,
    point: &EcPoint<F, ProperCrtUint<F>>,
) -> AssignedValue<F> {
    const T: usize = 3;
    const RATE: usize = 2;

    let spec = OptimizedPoseidonSpec::<F, 3, 2>::new::<8, 57, 0>();
    let limbs = point
        .x()
        .limbs()
        .iter()
        .chain(point.y().limbs().iter())
        .cloned()
        .collect_vec();

    let mut hasher = PoseidonHasher::<F, T, RATE>::new(spec);
    hasher.initialize_consts(ctx, range.gate());

    hasher.hash_fix_len_array(ctx, range.gate(), &limbs)
}

fn scalar_multiply<F: BigPrimeField>(
    ctx: &mut Context<F>,
    range: &RangeChip<F>,
    base: Secp256k1Affine,
    scalar: Fq,
) -> (EcPoint<F, ProperCrtUint<F>>, EcPoint<F, ProperCrtUint<F>>) {
    let fp_chip = FpChip::<F>::new(range, LIMB_BITS, NUM_LIMBS);
    let fq_chip = FqChip::<F>::new(range, LIMB_BITS, NUM_LIMBS);
    let ecc_chip = EccChip::<F, FpChip<F>>::new(&fp_chip);

    let s = fq_chip.load_private(ctx, scalar);
    let p = ecc_chip.assign_point(ctx, base);

    let sm = ecc_chip.scalar_mult::<Secp256k1Affine>(
        ctx,
        p.clone(),
        s.limbs().to_vec(),
        fq_chip.limb_bits,
        WINDOW_BITS,
    );

    (p, sm)
}
