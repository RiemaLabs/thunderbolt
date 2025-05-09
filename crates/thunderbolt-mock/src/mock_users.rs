use bitcoin::bip32::Xpriv;
use bitcoin::key::rand::thread_rng;
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
    account: AccountInfo,

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
        let nonce = Scalar::one();
        self.nonces.push(nonce);
        (self.nonces.len() - 1, Point::generator() * nonce)
    }

    pub fn get_nonce(&self, index: usize) -> Scalar {
        self.nonces[index]
    }

    pub fn get_tweaked_secret(&self) -> Scalar {
        Scalar::from_slice(&self.account.p2tr_tweaked_keypair.secret_bytes()).unwrap()
    }

    pub fn get_pubkey(&self) -> PublicKey {
        self.account.public_key
    }

    pub fn get_tweaked_x_pubkey(&self) -> XOnlyPublicKey {
        XOnlyPublicKey::from_keypair(&self.account.p2tr_tweaked_keypair).0
    }

    pub fn get_xpriv(&self) -> Xpriv {
        self.account.xpriv
    }

    pub fn get_p2tr_address(&self, network: Network) -> Address {
        self.account.p2tr_address(network)
    }
}
