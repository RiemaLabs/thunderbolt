// use core::hash;
// use secp256k1::{rand, PublicKey, Scalar, Secp256k1, SecretKey};
// use sha2::{Digest, Sha256};
// use snark_verifier::{
//     halo2_base::{
//         gates::{circuit::builder::RangeCircuitBuilder, GateChip, RangeChip},
//         halo2_proofs::{
//             circuit::SimpleFloorPlanner,
//             dev::MockProver,
//             halo2curves::{
//                 bls12_381::G1,
//                 bn256::{Fr, G1Affine},
//                 serde::SerdeObject,
//             },
//             transcript::TranscriptReadBuffer,
//         },
//         poseidon::{
//             hasher::{spec::OptimizedPoseidonSpec, PoseidonHasher},
//             PoseidonChip, PoseidonInstructions,
//         },
//         safe_types::SafeTypeChip,
//         AssignedValue, Context,
//     },
//     halo2_ecc::{ecc::EccChip, secp256k1::FpChip},
//     util::arithmetic::{Curve, Field, FromUniformBytes, PrimeField},
// };

mod tweak;
mod tx_constructor;

// const R_F: usize = 8;
// const R_P: usize = 57;

// mod Party {
//     use snark_verifier::halo2_base::gates::circuit::builder::BaseCircuitBuilder;

//     use super::*;

//     pub struct Alice {
//         sk_pa: Fr,
//         pub pk_pa: G1Affine,
//         sk_ra: Fr,
//         sk_ta: Fr,
//         pub pk_ra: G1Affine,
//         pub pk_ta: G1Affine,
//     }

//     impl Alice {
//         pub fn new() -> Self {
//             let (sk_pa, pk_pa) = public_key_sample();
//             let (sk_ra, pk_ra) = public_key_sample();
//             let (sk_ta, pk_ta) = public_key_sample();

//             Self {
//                 sk_pa,
//                 pk_pa,
//                 sk_ra,
//                 sk_ta,
//                 pk_ra,
//                 pk_ta
//             }
//         }

//         pub fn transaction_sig(&self, c: &Fr) -> Fr {
//             let s = self.sk_ra + (self.sk_pa * c);
//             s
//         }

//         pub fn transfer_prove(&self, ctx: &mut Context<Fr>, range: &RangeChip<Fr>, b: &G1Affine) {
//             let g = G1Affine::generator();
//             let t = (b * self.sk_ta).to_affine();
//             let t_bytes = t.to_raw_bytes();
//             let t_bytes = t_bytes.iter().map(|&b| Fr::from(b as u64)).collect::<Vec<_>>();
//             let t_bytes: [Fr; 64] = t_bytes.try_into().expect("t_bytes must have length 32");
//             let h: AssignedValue<Fr> = hash_t(ctx, t_bytes);

//             let h_val = h.value();
//             let H = (g * h_val).to_affine();

//             // 2. prove
//             let g = G1Affine::generator();
//             // t_a * g = a
//             public_key_prove(ctx, &range, self.sk_ta, g, self.pk_ta);
//             // h = H(t)
//             hash_prove(ctx, &range, t_bytes, &h);
//             // h * G = H
//             public_key_prove(ctx, &range, h_val.clone(), g, H);
//         }
//     }

//     pub struct Bob {
//         sk_pb: Fr,
//         pub pk_pb: G1Affine,
//         sk_tb: Fr,
//         sk_tb2: Fr,
//         pub pk_tb: G1Affine,
//         pub pk_tb2: G1Affine
//     }

//     impl Bob {
//         pub fn new() -> Self {
//             let (sk_pb, pk_pb) = public_key_sample();
//             let (sk_tb, pk_tb) = public_key_sample();
//             let (sk_tb2, pk_tb2) = public_key_sample();

//             Self {
//                 sk_pb,
//                 pk_pb,
//                 sk_tb,
//                 sk_tb2,
//                 pk_tb,
//                 pk_tb2,
//             }
//         }

//         pub fn transfer_prove(&self, ctx: &mut Context<Fr>, range: &RangeChip<Fr>) {
//             let g = G1Affine::generator();

//             // t_b * g = b
//             public_key_prove(ctx, &range, self.sk_tb, g, self.pk_tb);
//         }
//     }

//     pub struct Committee {
//         sk_pk: Fr,
//         pub pk_pk: G1Affine,
//         sk_rk: Fr,
//         pub pk_rk: G1Affine
//     }

//     impl Committee {
//         pub fn new() -> Self {
//             let (sk_pk, pk_pk) = public_key_sample();
//             let (sk_rk, pk_rk) = public_key_sample();

//             Self {
//                 sk_pk,
//                 pk_pk,
//                 sk_rk,
//                 pk_rk
//             }
//         }

//         pub fn transaction_sig(&self, c: &Fr) -> Fr {
//             let s = self.sk_rk + (self.sk_pk * c);
//             s
//         }

//         pub fn transfer_verify(&self, k: u32, lookup_bits: usize, builder: &mut BaseCircuitBuilder<Fr>) {
//             let t_cells_lookup = builder.lookup_manager().iter().map(|lm| lm.total_rows()).sum::<usize>();
//             let look_up_bits = if t_cells_lookup == 0 { None } else { Some(lookup_bits) };
//             builder.config_params.lookup_bits = look_up_bits;
//             let _ = builder.calculate_params(Some(9));

//             MockProver::run(k as u32, builder, vec![]).unwrap().assert_satisfied();
//         }
//     }
// }

// use Party::Alice;
// use Party::Committee;
// use Party::Bob;

// pub fn sample_setup(k: usize, lookup_bits: usize) -> (RangeCircuitBuilder<Fr>, RangeChip<Fr>) {
//     let mut builder = RangeCircuitBuilder::<Fr>::default().use_k(k);
//     builder.set_lookup_bits(lookup_bits);
//     let range = RangeChip::new(lookup_bits, builder.lookup_manager().clone());
//     (builder, range)
// }

// pub fn public_key_sample() -> (Fr, G1Affine) {
//     let mut rng = rand::thread_rng();
//     let sk = Fr::random(&mut rng);
//     let pk = (G1Affine::generator() * sk).to_affine();
//     (sk, pk)
// }

// pub fn public_key_prove(ctx: &mut Context<Fr>, range: &RangeChip<Fr>, t_a: Fr, g: G1Affine, a: G1Affine) {
//     let fp_chip = FpChip::new(range, 88, 3);
//     let ecc_chip = EccChip::new(&fp_chip);

//     let g = ecc_chip.assign_constant_point(ctx, g);
//     let a_expected = ecc_chip.assign_constant_point(ctx, a);

//     let t_a = ctx.assign_witnesses([t_a]);
//     let a_real = ecc_chip.scalar_mult::<G1Affine>(ctx, g, t_a, Fr::NUM_BITS as usize, 4);

//     ecc_chip.assert_equal(ctx, a_real, a_expected);
// }

// pub fn joint_key_prove(ctx: &mut Context<Fr>, range: &RangeChip<Fr>, t_a: Fr, b: G1Affine, t: G1Affine) {
//     let fp_chip = FpChip::new(range, 88, 3);
//     let ecc_chip = EccChip::new(&fp_chip);

//     let t_expected = ecc_chip.assign_constant_point(ctx, t);
//     let b = ecc_chip.assign_constant_point(ctx, b);
//     let t_a = ctx.assign_witnesses([t_a]);
//     let t_real = ecc_chip.scalar_mult::<G1Affine>(ctx, b, t_a, Fr::NUM_BITS as usize, 4);

//     ecc_chip.assert_equal(ctx, t_real, t_expected);
// }

// pub fn hash_t(ctx: &mut Context<Fr>, inputs: [Fr; 64]) -> AssignedValue<Fr> {
//     let assigned_inputs = ctx.assign_witnesses(inputs);
//     let poseidon_gate = GateChip::<Fr>::default();
//     let mut poseidon =
//         PoseidonHasher::<Fr, 3, 2>::new(OptimizedPoseidonSpec::new::<R_F, R_P, 0>());
//     poseidon.initialize_consts(ctx, &poseidon_gate);
//     let h =  poseidon.hash_fix_len_array(ctx, &poseidon_gate, &assigned_inputs);

//     h
// }

// pub fn hash_prove(ctx: &mut Context<Fr>, range: &RangeChip<Fr>, inputs: [Fr; 64], h: &AssignedValue<Fr>) {
//     let poseidon_spec =  OptimizedPoseidonSpec::new::<R_F, R_P, 0>();
//     let poseidon_chip = PoseidonChip::<Fr, 3, 2>::new(
//         ctx,
//         poseidon_spec,
//         range,
//     );

//     let safetype_chip = SafeTypeChip::new(&range);
//     let inputs = ctx.assign_witnesses(inputs);
//     let inputs: [AssignedValue<Fr>; 64] = inputs.try_into().expect("inputs must have length 64");
//     let inputs = safetype_chip.raw_to_fix_len_bytes(ctx, inputs);

//     let hash = poseidon_chip.hash_fix_len_bytes(ctx, &inputs);

//     ctx.constrain_equal(&h, &hash);
// }

// // Alice creates a UTXO on-chain with the required Schnorr signature as:
// pub fn prepare_transaction(alice: &Alice, commitee: &Committee) {
//     let secp = Secp256k1::new();

//     // === Step 1: Compute challenge: c = H(R || P || m) ===
//     let message = b"prepare transaction";

//     let agg_pk: G1Affine = (alice.pk_pa + commitee.pk_pk).to_affine();
//     let agg_R: G1Affine = (alice.pk_ra + commitee.pk_rk).to_affine();

//     let mut hasher = Sha256::new();

//     hasher.update(agg_R.to_raw_bytes());
//     hasher.update(agg_pk.to_raw_bytes());
//     hasher.update(message);

//     let hash_result = hasher.finalize();
//     let mut c_bytes = [0u8; 64];
//     c_bytes[..32].copy_from_slice(&hash_result);
//     let c = Fr::from_uniform_bytes(&c_bytes);

//     // === Step 2: Compute signature scalar s = r_a + r_k + c * (sk_pa + sk_pk) ===
//     let sig1 = alice.transaction_sig(&c);
//     let sig2 = commitee.transaction_sig(&c);
//     let s = sig1 + sig2;

//     // === Step 3: Verify s*G = R + c * P ===
//     let g = G1Affine::generator();
//     let sG = (g * s).to_affine();
//     let expected = (agg_R + (agg_pk * c)).to_affine();

//     println!("s * G     : {:?}", sG);
//     println!("R + c * P : {:?}", expected);

//     // // Verify the equation: s * G == R + c * P
//     if sG == expected {
//         println!("✅ Prepare transaction verified successfully!");
//     } else {
//         println!("❌ Prepare transaction verification failed!");
//     };
// }

// pub fn transfer_transaction(alice: &Alice, committee: &Committee, bob: &Bob) {
//     // step 1: verify the joint key
//     let k = 20;
//     let lookup_bits = 19;
//     let (mut builder, range) = sample_setup(k, lookup_bits);
//     alice.transfer_prove(builder.main(0), &range, &bob.pk_tb);
//     bob.transfer_prove(builder.main(0), &range);
//     committee.transfer_verify(k as u32, lookup_bits, &mut builder);
//     println!("✅ Transfer transaction verified successfully!");

//     //TODO: step 2: signature
// }

// TODO: ZK proof

fn main() {
    // let alice = Alice::new();
    // let committee = Committee::new();
    // let bob: Bob = Bob::new();

    // prepare_transaction(&alice, &committee);
    // transfer_transaction(&alice, &committee, &bob);
}
