use bitcoin::key::rand::thread_rng;
use bitcoin::{Network, XOnlyPublicKey};
use bitcoin_utils::account::AccountInfo;
use lazy_static::lazy_static;
use secp::{Point, Scalar};

const COMMITTEE_SECRET: &str = "a6f1b630d3a9cefdd2f5f81a5e647dd9e8ed89330c65186adfa455388a8a1bc5";

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

    pub fn gen_nonce(&mut self, user_pubkey: XOnlyPublicKey, user_nonce_index: usize) -> (usize, Point) {
        // TODO: A deterministic nonce generation.
        let nonce = Scalar::random(&mut thread_rng());
        self.nonces.push(nonce);
        (self.nonces.len() - 1, Point::generator() * nonce)
    }

    pub fn get_nonce(&self, index: usize) -> Scalar {
        self.nonces[index]
    }

    pub fn get_secret(&self) -> Scalar {
        Scalar::from_slice(&self.account.keypair.secret_key().secret_bytes()).unwrap()
    }

    pub fn get_pubkey(&self) -> XOnlyPublicKey {
        XOnlyPublicKey::from_keypair(&self.account.keypair).0
    }
}
