use primitive_types::U256 as PrimitiveU256;

pub fn primitive_u256_from_u256(u256: alloy::primitives::U256) -> PrimitiveU256 {
    PrimitiveU256::from_dec_str(&u256.to_string()).unwrap()
}
