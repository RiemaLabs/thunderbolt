#![no_main]
sp1_zkvm::entrypoint!(main);

use transfer_compare_lib::{prove_full_relation, FullBenchmarkInput};

pub fn main() {
    let input = sp1_zkvm::io::read::<FullBenchmarkInput>();
    let public_values = prove_full_relation(&input);
    sp1_zkvm::io::commit_slice(&public_values.to_bytes());
}
