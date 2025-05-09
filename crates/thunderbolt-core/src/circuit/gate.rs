use std::usize;

use halo2_base::{halo2_proofs::halo2curves::secp256k1::Fq, utils::BigPrimeField, Context};
use halo2_ecc::{bigint::ProperCrtUint, fields::FieldChip, secp256k1::FqChip};

/// Impls foreign arithmetic operations for a gate, wich only serves for poseidon hash.
#[derive(Debug, Clone)]
pub struct ForeignGate<'a, F: BigPrimeField> {
    fq_chip: FqChip<'a, F>,
}
impl<'a, F: BigPrimeField> ForeignGate<'a, F> {
    pub fn new(fq_chip: FqChip<'a, F>) -> Self {
        Self { fq_chip }
    }
}

impl<F: BigPrimeField> ForeignGate<'_, F> {
    pub fn add_const(&self, ctx: &mut Context<F>, a: &ProperCrtUint<F>, b: Fq) -> ProperCrtUint<F> {
        let res = self.fq_chip.add_constant_no_carry(ctx, a, b);
        self.fq_chip.carry_mod(ctx, res)
    }

    pub fn add(&self, ctx: &mut Context<F>, a: &ProperCrtUint<F>, b: &ProperCrtUint<F>) -> ProperCrtUint<F> {
        let res = self.fq_chip.add_no_carry(ctx, a, b);
        self.fq_chip.carry_mod(ctx, res)
    }

    pub fn mul(&self, ctx: &mut Context<F>, a: &ProperCrtUint<F>, b: &ProperCrtUint<F>) -> ProperCrtUint<F> {
        let res = self.fq_chip.mul_no_carry(ctx, a, b);
        self.fq_chip.carry_mod(ctx, res)
    }

    pub fn mul_add_const(
        &self,
        ctx: &mut Context<F>,
        a: &ProperCrtUint<F>,
        b: &ProperCrtUint<F>,
        c: Fq,
    ) -> ProperCrtUint<F> {
        let mul_res = self.fq_chip.mul_no_carry(ctx, a, b);
        let sum_res = self.fq_chip.add_constant_no_carry(ctx, mul_res, c);
        self.fq_chip.carry_mod(ctx, sum_res)
    }

    pub fn mul_const_add(
        &self,
        ctx: &mut Context<F>,
        a: &ProperCrtUint<F>,
        b: Fq,
        c: &ProperCrtUint<F>,
    ) -> ProperCrtUint<F> {
        let b = self.fq_chip.load_constant(ctx, b);
        let mul_res = self.fq_chip.mul_no_carry(ctx, a, b);
        let sum_res = self.fq_chip.add_no_carry(ctx, mul_res, c);
        self.fq_chip.carry_mod(ctx, sum_res)
    }

    pub fn inner_product<const T: usize>(
        &self,
        ctx: &mut Context<F>,
        a: &[ProperCrtUint<F>; T],
        b: &[Fq; T],
    ) -> ProperCrtUint<F> {
        assert_eq!(a.len(), b.len(), "Inner product input length mismatch");

        let mut acc = self.fq_chip.load_constant(ctx, Fq::zero());

        for (a_i, b_i) in a.iter().zip(b.iter()) {
            let b_i = self.fq_chip.load_constant(ctx, *b_i);
            let term = self.fq_chip.mul_no_carry(ctx, a_i, b_i);
            let new_acc = self.fq_chip.add_no_carry(ctx, acc, term);
            acc = self.fq_chip.carry_mod(ctx, new_acc);
        }

        acc
    }
}
