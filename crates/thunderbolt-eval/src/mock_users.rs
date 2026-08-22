use bitcoin::key::rand::thread_rng;
use bitcoin::Network;
use bitcoin_utils::account::AccountInfo;
use secp::{Point, Scalar};

pub fn alice_account() -> AccountInfo {
    AccountInfo::from_seed(Network::Regtest, &[0xa1; 32]).expect("fixed mock seed must derive")
}

pub fn bob_account() -> AccountInfo {
    AccountInfo::from_seed(Network::Regtest, &[0xb2; 32]).expect("fixed mock seed must derive")
}

pub fn zeta_account() -> AccountInfo {
    AccountInfo::from_seed(Network::Regtest, &[0xc3; 32]).expect("fixed mock seed must derive")
}

pub struct MockUser {
    pub account: AccountInfo,

    nonces: Vec<Scalar>,
}

impl MockUser {
    pub fn new(account: AccountInfo) -> Self {
        Self {
            account,
            nonces: vec![],
        }
    }

    pub fn gen_nonce(&mut self) -> (usize, Point) {
        let nonce = Scalar::random(&mut thread_rng());
        self.nonces.push(nonce);
        (self.nonces.len() - 1, nonce.base_point_mul())
    }

    pub fn get_nonce(&self, index: usize) -> Scalar {
        self.nonces[index]
    }
}
