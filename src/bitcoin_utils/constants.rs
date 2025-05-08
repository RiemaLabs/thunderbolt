// TODO: Replace the dust with more precise computation:
// https://github.com/bitcoin/bitcoin/blob/c536dfbcb00fb15963bf5d507b7017c241718bf6/src/policy/policy.cpp#L18
pub const DUST_SATS: u64 = 548;

pub const SAFETY_INPUT_VBYTES: u64 = 148;
pub const OVERHEAD: u64 = 12;
pub const TAPROOT_OUTPUT_VBYTES: u64 = 43;
