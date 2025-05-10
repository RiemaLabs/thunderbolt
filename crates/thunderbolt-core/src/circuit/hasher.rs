use std::cell::OnceCell;

use getset::Getters;
use halo2_base::{
    halo2_proofs::halo2curves::secp256k1::Fq, poseidon::hasher::spec::OptimizedPoseidonSpec, utils::BigPrimeField,
    Context,
};
use halo2_ecc::{bigint::ProperCrtUint, secp256k1::FqChip};

use super::{gate::ForeignGate, state::PoseidonForeignState};

#[derive(Clone, Debug, Getters)]
pub struct PoseidonForeignHasher<F: BigPrimeField, const T: usize, const RATE: usize> {
    /// Spec, contains round constants and optimized matrices.
    #[getset(get = "pub")]
    spec: OptimizedPoseidonSpec<Fq, T, RATE>,
    consts: OnceCell<PoseidonForeignHasherConsts<F, T, RATE>>,
}

impl<F: BigPrimeField, const T: usize, const RATE: usize> PoseidonForeignHasher<F, T, RATE> {
    /// Create a poseidon hasher from an existing spec.
    pub fn new(spec: OptimizedPoseidonSpec<Fq, T, RATE>) -> Self {
        Self {
            spec,
            consts: OnceCell::new(),
        }
    }
    /// Initialize necessary consts of hasher. Must be called before any computation.
    pub fn initialize_consts(&mut self, ctx: &mut Context<F>, fq_chip: &FqChip<F>) {
        self.consts
            .get_or_init(|| PoseidonForeignHasherConsts::<F, T, RATE>::new(ctx, fq_chip));
    }

    pub fn hash_fix_len_array(
        &self,
        ctx: &mut Context<F>,
        gate: &ForeignGate<F>,
        inputs: &[ProperCrtUint<F>],
    ) -> ProperCrtUint<F>
    where
        F: BigPrimeField,
    {
        let mut state = self.init_state().clone();
        fix_len_array_squeeze(ctx, gate, inputs, &mut state, &self.spec)
    }

    fn init_state(&self) -> &PoseidonForeignState<F, T, RATE> {
        self.consts.get().unwrap().init_state()
    }
}

#[derive(Clone, Debug, Getters)]
struct PoseidonForeignHasherConsts<F: BigPrimeField, const T: usize, const RATE: usize> {
    #[getset(get = "pub")]
    init_state: PoseidonForeignState<F, T, RATE>,
}

impl<F: BigPrimeField, const T: usize, const RATE: usize> PoseidonForeignHasherConsts<F, T, RATE> {
    pub fn new(ctx: &mut Context<F>, fq_chip: &FqChip<F>) -> Self {
        let init_state = PoseidonForeignState::default(ctx, fq_chip);
        Self { init_state }
    }
}

/// ATTETION: input_elements.len() needs to be fixed at compile time.
pub fn fix_len_array_squeeze<F: BigPrimeField, const T: usize, const RATE: usize>(
    ctx: &mut Context<F>,
    gate: &ForeignGate<F>,
    input_elements: &[ProperCrtUint<F>],
    state: &mut PoseidonForeignState<F, T, RATE>,
    spec: &OptimizedPoseidonSpec<Fq, T, RATE>,
) -> ProperCrtUint<F> {
    let exact = input_elements.len() % RATE == 0;

    for chunk in input_elements.chunks(RATE) {
        state.permutation(ctx, gate, chunk, spec);
    }
    if exact {
        state.permutation(ctx, gate, &[], spec);
    }

    state.s[1].clone()
}
