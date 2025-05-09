use halo2_base::{
    halo2_proofs::halo2curves::{ff::PrimeField, secp256k1::Fq},
    poseidon::hasher::{mds::SparseMDSMatrix, spec::OptimizedPoseidonSpec},
    utils::BigPrimeField,
    Context,
};
use halo2_ecc::{bigint::ProperCrtUint, fields::FieldChip, secp256k1::FqChip};

use super::gate::ForeignGate;

#[derive(Clone, Debug)]
pub(crate) struct PoseidonForeignState<F: BigPrimeField, const T: usize, const RATE: usize> {
    pub(crate) s: [ProperCrtUint<F>; T],
}

impl<F: BigPrimeField, const T: usize, const RATE: usize> PoseidonForeignState<F, T, RATE> {
    pub fn default(ctx: &mut Context<F>, chip: &FqChip<F>) -> Self {
        let mut default_state = [Fq::zero(); T];
        // from Section 4.2 of https://eprint.iacr.org/2019/458.pdf
        // • Variable-Input-Length Hashing. The capacity value is 2^64 + (o−1) where o the output length.
        // for our transcript use cases, o = 1
        default_state[0] = Fq::from_u128(1u128 << 64);
        Self {
            s: default_state.map(|f| chip.load_constant(ctx, f)),
        }
    }

    /// Perform permutation on this state.
    ///
    /// ATTETION: inputs.len() needs to be fixed at compile time.
    /// Assume len <= inputs.len().
    /// `inputs` is right padded.
    /// If `len` is `None`, treat `inputs` as a fixed length array.
    pub fn permutation(
        &mut self,
        ctx: &mut Context<F>,
        gate: &ForeignGate<F>,
        inputs: &[ProperCrtUint<F>],
        spec: &OptimizedPoseidonSpec<Fq, T, RATE>,
    ) {
        let r_f = spec.r_f() / 2;
        let mds = spec.mds_matrices().mds().as_ref();
        let pre_sparse_mds = spec.mds_matrices().pre_sparse_mds().as_ref();
        let sparse_matrices = spec.mds_matrices().sparse_matrices();

        // First half of the full round
        let constants = spec.constants().start();

        // Only apply for fixed-len array.
        self.absorb_with_pre_constants(ctx, gate, inputs, &constants[0]);
        for constants in constants.iter().skip(1).take(r_f - 1) {
            self.sbox_full(ctx, gate, constants);
            self.apply_mds(ctx, gate, mds);
        }
        self.sbox_full(ctx, gate, constants.last().unwrap());
        self.apply_mds(ctx, gate, pre_sparse_mds);

        // Partial rounds
        let constants = &spec.constants().partial();
        for (constant, sparse_mds) in constants.iter().zip(sparse_matrices.iter()) {
            self.sbox_part(ctx, gate, constant);
            self.apply_sparse_mds(ctx, gate, sparse_mds);
        }

        // Second half of the full rounds
        let constants = &spec.constants().end();
        for constants in constants.iter() {
            self.sbox_full(ctx, gate, constants);
            self.apply_mds(ctx, gate, mds);
        }
        self.sbox_full(ctx, gate, &[Fq::zero(); T]);
        self.apply_mds(ctx, gate, mds);
    }

    fn x_power5_with_constant(
        ctx: &mut Context<F>,
        gate: &ForeignGate<F>,
        x: &ProperCrtUint<F>,
        constant: &Fq,
    ) -> ProperCrtUint<F> {
        let x2 = gate.mul(ctx, &x, &x);
        let x4 = gate.mul(ctx, &x2, &x2);
        gate.mul_add_const(ctx, &x, &x4, *constant)
    }

    fn sbox_full(&mut self, ctx: &mut Context<F>, gate: &ForeignGate<F>, constants: &[Fq; T]) {
        for (x, constant) in self.s.iter_mut().zip(constants.iter()) {
            *x = Self::x_power5_with_constant(ctx, gate, x, constant);
        }
    }

    fn sbox_part(&mut self, ctx: &mut Context<F>, gate: &ForeignGate<F>, constant: &Fq) {
        let x = &mut self.s[0];
        *x = Self::x_power5_with_constant(ctx, gate, x, constant);
    }

    fn absorb_with_pre_constants(
        &mut self,
        ctx: &mut Context<F>,
        gate: &ForeignGate<F>,
        inputs: &[ProperCrtUint<F>],
        pre_constants: &[Fq; T],
    ) {
        assert!(inputs.len() < T);

        // Explanation of what's going on: before each round of the poseidon permutation,
        // two things have to be added to the state: inputs (the absorbed elements) and
        // preconstants. Imagine the state as a list of T elements, the first of which is
        // the capacity:  |--cap--|--el1--|--el2--|--elR--|
        // - A preconstant is added to each of all T elements (which is different for each)
        // - The inputs are added to all elements starting from el1 (so, not to the capacity),
        //   to as many elements as inputs are available.
        // - To the first element for which no input is left (if any), an extra 1 is added.
        // adding preconstant to the distinguished capacity element (only one)
        self.s[0] = gate.add_const(ctx, &self.s[0], pre_constants[0]);
        // adding pre-constants and inputs to the elements for which both are available
        for ((x, constant), input) in self.s.iter_mut().zip(pre_constants.iter()).skip(1).zip(inputs.iter()) {
            let val = gate.add(ctx, x, input);
            *x = gate.add_const(ctx, &val, *constant);
        }

        let offset = inputs.len() + 1;
        // adding only pre-constants when no input is left
        for (i, (x, constant)) in self.s.iter_mut().zip(pre_constants.iter()).skip(offset).enumerate() {
            *x = gate.add_const(ctx, x, if i == 0 { Fq::one() + constant } else { *constant });
            // the if idx == 0 { F::one() } else { F::zero() } is to pad the input with a single 1 and then 0s
            // this is the padding suggested in pg 31 of https://eprint.iacr.org/2019/458.pdf and in Section 4.2 (Variable-Input-Length Hashing. The padding consists of one field element being 1, and the remaining elements being 0.)
        }
    }

    fn apply_mds(&mut self, ctx: &mut Context<F>, gate: &ForeignGate<F>, mds: &[[Fq; T]; T]) {
        let res = mds
            .iter()
            .map(|row| gate.inner_product(ctx, &self.s, row))
            .collect::<Vec<_>>();

        self.s = res.try_into().unwrap();
    }

    fn apply_sparse_mds(&mut self, ctx: &mut Context<F>, gate: &ForeignGate<F>, mds: &SparseMDSMatrix<Fq, T, RATE>) {
        self.s = std::iter::once(gate.inner_product(ctx, &self.s, mds.row()))
            .chain(
                mds.col_hat()
                    .iter()
                    .zip(self.s.iter().skip(1))
                    .map(|(coeff, state)| gate.mul_const_add(ctx, &self.s[0], *coeff, state)),
            )
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
    }
}
