use bitcoin::key::rand::{self, thread_rng};
use bitcoin::{Network, XOnlyPublicKey};
use bitcoin_utils::account::AccountInfo;
use lazy_static::lazy_static;
use secp::{Point, Scalar};

const COMMITTEE_SECRET: &str = "6148c7cec662b4161a960321c1a92e706bddd70dc05f3b46bde0031f9bc2b046";

lazy_static! {
    pub static ref COMMITTEE: AccountInfo = AccountInfo::new(Network::Testnet, COMMITTEE_SECRET);
}

pub struct MockCommittee {
    pub account: AccountInfo,

    nonces: Vec<Scalar>,
}

impl MockCommittee {
    pub fn new(account: AccountInfo) -> Self {
        Self {
            account,
            nonces: vec![],
        }
    }

    // TODO: A deterministic nonce generation.
    #[allow(unused_variables)]
    pub fn gen_nonce(&mut self, user_pubkey: XOnlyPublicKey, user_nonce_index: usize) -> (usize, Point) {
        // let mut rng = rand::thread_rng();
        // let nonce = Scalar::random(&mut rng);
        let nonce = Scalar::two();
        self.nonces.push(nonce);
        (self.nonces.len() - 1, nonce.base_point_mul())
    }

    pub fn get_nonce(&self, index: usize) -> Scalar {
        self.nonces[index]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_print_committee_p2tr_address() {
        let committee = MockCommittee::new(COMMITTEE.clone());
        println!(
            "committee p2tr address: {}",
            committee.account.p2tr_address(Network::Testnet)
        );
    }
}
