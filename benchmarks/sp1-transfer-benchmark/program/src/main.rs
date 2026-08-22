#![no_main]
sp1_zkvm::entrypoint!(main);

use transfer_compare_lib::transfer_step;

pub fn main() {
    let holder_secret = sp1_zkvm::io::read::<u64>();
    let refresh = sp1_zkvm::io::read::<u64>();
    let committee_share = sp1_zkvm::io::read::<u64>();

    let public_values = transfer_step(holder_secret, refresh, committee_share);
    sp1_zkvm::io::commit_slice(&public_values.to_bytes());
}
