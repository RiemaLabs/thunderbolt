use bitcoin::bip32::Xpriv;
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
    account: AccountInfo,

    nonces: Vec<Scalar>,
}

impl MockCommittee {
    pub fn new(account: AccountInfo) -> Self {
        Self {
            account,
            nonces: vec![],
        }
    }

    pub fn gen_nonce(
        &mut self,
        user_pubkey: XOnlyPublicKey,
        user_nonce: Point,
        user_nonce_index: usize,
    ) -> (usize, Point) {
        // TODO: A deterministic nonce generation.
        let mut rng = rand::thread_rng();
        let mut nonce = Scalar::random(&mut rng);
        let mut nonce_point = nonce.base_point_mul();
        let p_nonce = nonce_point + user_nonce;
        if p_nonce.is_infinity() {
            // TODO: A better way to handle this.
            panic!("p_nonce is infinity");
        }
        let p_nonce = p_nonce.unwrap();
        if p_nonce.has_odd_y() {
            nonce = -nonce;
            nonce_point = -nonce_point;
        }
        self.nonces.push(nonce);
        (self.nonces.len() - 1, nonce_point)
    }

    pub fn get_nonce(&self, index: usize) -> Scalar {
        self.nonces[index]
    }

    pub fn get_secret(&self) -> Scalar {
        Scalar::from_slice(&self.account.keypair.secret_key().secret_bytes()).unwrap()
    }

    pub fn get_x_pubkey(&self) -> XOnlyPublicKey {
        XOnlyPublicKey::from_keypair(&self.account.keypair).0
    }

    pub fn get_xpriv(&self) -> Xpriv {
        self.account.xpriv
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
