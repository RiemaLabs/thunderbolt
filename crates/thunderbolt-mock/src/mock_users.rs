use bitcoin::bip32::Xpriv;
use bitcoin::key::{rand, Parity};
use bitcoin::{Address, Network, PublicKey, XOnlyPublicKey};
use bitcoin_utils::account::AccountInfo;
use lazy_static::lazy_static;
use secp::{Point, Scalar};

const ALICE_SECRET: &str = "a6f1b630d3a9cefdd2f5f81a5e647dd9e8ed89330c65186adfa455388a8a1bc5";
const BOB_SECRET: &str = "d67c3041fbdba5c9b6a9f400c8207769671025d7eb847f69bf690867ddc63160";
const ZETA_SECRET: &str = "af0e23f1b2a749dd99c4b2191f55bb1b516a5a16ae807b47ae4a5573f0cdeb73";

lazy_static! {
    pub static ref ALICE: AccountInfo = AccountInfo::new(Network::Testnet, ALICE_SECRET);
    pub static ref BOB: AccountInfo = AccountInfo::new(Network::Testnet, BOB_SECRET);
    pub static ref ZETA: AccountInfo = AccountInfo::new(Network::Testnet, ZETA_SECRET);
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
        // let mut rng = rand::thread_rng();
        // let nonce = Scalar::random(&mut rng);
        let nonce = Scalar::one();
        self.nonces.push(nonce);
        (self.nonces.len() - 1, nonce.base_point_mul())
    }

    pub fn get_nonce(&self, index: usize) -> Scalar {
        self.nonces[index]
    }
}
