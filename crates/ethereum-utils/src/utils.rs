use alloy::primitives::U256 as AlloyU256;
use primitive_types::U256 as PrimitiveU256;

pub fn u256_from_primitive_u256(p: PrimitiveU256) -> AlloyU256 {
    AlloyU256::from_limbs(p.0)
}

pub fn primitive_u256_from_u256(u: AlloyU256) -> PrimitiveU256 {
    PrimitiveU256::from_dec_str(&u.to_string()).unwrap()
}
