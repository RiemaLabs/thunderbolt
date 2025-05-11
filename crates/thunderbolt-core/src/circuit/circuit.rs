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

use crate::circuit::utils::fq_mod_from_bytes_le;
use crate::circuit::{gate::ForeignGate, hasher::PoseidonForeignHasher};

use super::utils::generate_instances_from_data;
use super::{LIMB_BITS, NUM_LIMBS, RATE, R_F, R_P, T};

pub(crate) const WINDOW_BITS: usize = 4;

pub type ProofBytes = Vec<u8>;
pub type BreakPoint = Vec<Vec<usize>>;

#[derive(Debug, Clone, Default)]
/// Represents all inputs and outputs involved in the shared secret derivation and commitment flow
/// between Alice and Bob using elliptic curve and Poseidon-based operations.
pub struct SharedSecretProofData {
    /// The secret scalar component `s` of Alice's original Schnorr signature. Known only to Alice.
    pub signature_sk: Fq,

    /// The public commitment to the secret scalar, computed as `s * G`.
    pub signature_pk: Secp256k1Affine,

    /// Alice's private tweak scalar `sk`, used in the Diffie-Hellman key exchange.
    pub sk: Fq,

    /// Bob's public tweak key `tweak_pk`, used as the base for computing the shared secret.
    pub tweak_pk: Secp256k1Affine,

    /// The Poseidon hash of the Diffie-Hellman shared secret `sk * tweak_pk`, yielding a scalar.
    pub secret: Fq,

    /// The elliptic curve point `secret * G`, serving as the public representation of the shared secret.
    pub secret_pub: Secp256k1Affine,

    /// The final tweaked signature public key, computed as `signature_pk + secret_pub`.
    pub tweaked_signature_pk: Secp256k1Affine,
}

impl SharedSecretProofData {
    pub fn new(signature_sk: Fq, sk: Fq, tweak_pk: Secp256k1Affine) -> Self {
        // signature_pk = signature_sk * G
        let signature_pk = (Secp256k1Affine::generator() * signature_sk).to_affine();

        // shared_point = sk * tweak_pk
        let shared_point = (tweak_pk * sk).to_affine();

        // Poseidon hash on (x, y) coordinates of the shared_point
        let x_bytes = shared_point.x.to_bytes();
        let y_bytes = shared_point.y.to_bytes();
        let x = fq_mod_from_bytes_le(&x_bytes);
        let y = fq_mod_from_bytes_le(&y_bytes);

        let mut sponge = Poseidon::<Fq, T, RATE>::new(R_F, R_P);
        sponge.update(&[x, y]);
        let secret = sponge.squeeze();

        // secret_pub = secret * G
        let secret_pub = (Secp256k1Affine::generator() * secret).to_affine();

        // tweaked_signature_pk = signature_pk + secret_pub
        let tweaked_signature_pk = (signature_pk + secret_pub).to_affine();

        SharedSecretProofData {
            signature_sk,
            signature_pk,
            sk,
            tweak_pk,
            secret,
            secret_pub,
            tweaked_signature_pk,
        }
    }
}

impl SharedSecretProofData {
    pub fn generate() -> Self {
        // Alice samples the secret scalar part of the Schnorr signature
        let signature_sk = Fq::random(OsRng);
        let signature_pk = (Secp256k1Affine::generator() * signature_sk).to_affine();

        // Bob's private tweak (sk) and Alice's tweak public key (tweak_pk = b * G)
        let sk = Fq::random(OsRng);
        let tweak_scalar = Fq::random(OsRng);
        let tweak_pk = (Secp256k1Affine::generator() * tweak_scalar).to_affine();

        // Compute the shared secret point: sk * tweak_pk
        let shared_point = (tweak_pk * sk).to_affine();

        // Convert coordinates to Poseidon input field elements
        let x = fq_mod_from_bytes_le(&shared_point.x.to_bytes());
        let y = fq_mod_from_bytes_le(&shared_point.y.to_bytes());

        // Hash with Poseidon to get a scalar in the base field
        let mut sponge = Poseidon::<Fq, T, RATE>::new(R_F, R_P);
        sponge.update(&[x, y]);
        let secret = sponge.squeeze();

        // Convert the scalar to a public key: secret * G
        let secret_pub = (Secp256k1Affine::generator() * secret).to_affine();

        // Compute the tweaked signature public key: signature_pk + secret_pub
        let tweaked_signature_pk = (signature_pk + secret_pub).to_affine();

        SharedSecretProofData {
            signature_sk,
            signature_pk,
            sk,
            tweak_pk,
            secret,
            secret_pub,
            tweaked_signature_pk,
        }
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
            k: 16,
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

    // Load sk and signature_sk
    let sk = fq_chip.load_private(ctx, shared_data.sk);
    let signature_sk = fq_chip.load_private(ctx, shared_data.signature_sk);

    // signature_pk = signature_sk * G
    let signature_pk = scalar_multiply(ctx, range, Secp256k1Affine::generator(), true, signature_sk).1;
    let signature_pk_x = signature_pk.x();
    let signature_pk_y = signature_pk.y();

    // tweak_pk = pk_b, compute sk * tweak_pk
    let (tweak_pk, shared_secret_point) = scalar_multiply(ctx, range, shared_data.tweak_pk, false, sk);
    let tweak_pk_x = tweak_pk.x();
    let tweak_pk_y = tweak_pk.y();

    // Poseidon hash over shared_secret_point (x, y)
    let secret = hash_shared_secret(ctx, range, &shared_secret_point);

    // secret_pub = secret * G
    let (_, secret_pub) = scalar_multiply(ctx, range, Secp256k1Affine::generator(), true, secret);
    let secret_pub_x = secret_pub.x();
    let secret_pub_y = secret_pub.y();

    // tweaked_signature_pk = signature_pk + secret_pub
    let tweaked_signature_pk = ecc_add_points(ctx, range, signature_pk.clone(), secret_pub.clone());
    let tweaked_x = tweaked_signature_pk.x();
    let tweaked_y = tweaked_signature_pk.y();

    #[cfg(feature = "sanity-check")]
    {
        assert_eq!(
            shared_data.signature_pk,
            (Secp256k1Affine::generator() * shared_data.signature_sk).to_affine()
        );
        assert_eq!(shared_data.secret_pub.x, secret_pub_x.value().unwrap());
        assert_eq!(shared_data.secret_pub.y, secret_pub_y.value().unwrap());
        assert_eq!(shared_data.tweaked_signature_pk.x, tweaked_x.value().unwrap());
        assert_eq!(shared_data.tweaked_signature_pk.y, tweaked_y.value().unwrap());
    }

    // Assemble public inputs
    let mut public_inputs = vec![];
    public_inputs.extend(signature_pk_x.limbs());
    public_inputs.extend(signature_pk_y.limbs());

    public_inputs.extend(tweak_pk_x.limbs());
    public_inputs.extend(tweak_pk_y.limbs());

    public_inputs.extend(secret_pub_x.limbs());
    public_inputs.extend(secret_pub_y.limbs());

    public_inputs.extend(tweaked_x.limbs());
    public_inputs.extend(tweaked_y.limbs());

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

fn ecc_add_points<F: BigPrimeField>(
    ctx: &mut Context<F>,
    range: &RangeChip<F>,
    p1: EcPoint<F, ProperCrtUint<F>>,
    p2: EcPoint<F, ProperCrtUint<F>>,
) -> EcPoint<F, ProperCrtUint<F>> {
    let fp_chip = FpChip::<F>::new(range, LIMB_BITS, NUM_LIMBS);
    let ecc_chip = EccChip::<F, FpChip<F>>::new(&fp_chip);

    ecc_chip.add_unequal(ctx, &p1, &p2, true)
}

#[cfg(test)]
mod test {
    use super::*;
    use super::{prove, SharePKCircuitConfig, SharedSecretProofData};
    use std::time::Instant;

    #[test]
    fn test_prove_soundness() {
        let config = SharePKCircuitConfig::default();
        let (params, pk, vk) = setup(&config);
        let data = SharedSecretProofData::generate();

        let start = Instant::now();
        let proof = prove(&params, &pk, data.clone());
        let duration = start.elapsed();

        println!("Prove time: {:.2?}", duration);
        verify(&params, &vk, data, &proof);
    }
}
