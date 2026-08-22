use bitcoin::key::rand::thread_rng;
use bitcoin::{Network, XOnlyPublicKey};
use bitcoin_utils::account::AccountInfo;
use secp::{Point, Scalar};

pub fn committee_account() -> AccountInfo {
    AccountInfo::from_seed(Network::Regtest, &[0xd4; 32]).expect("fixed mock seed must derive")
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

    pub fn gen_nonce(&mut self, _user_pubkey: XOnlyPublicKey, _user_nonce_index: usize) -> (usize, Point) {
        let nonce = Scalar::random(&mut thread_rng());
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
        let committee = MockCommittee::new(committee_account());
        println!(
            "committee p2tr address: {}",
            committee.account.p2tr_address(Network::Testnet)
        );
    }
}
