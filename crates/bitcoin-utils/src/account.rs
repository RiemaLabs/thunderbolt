use bitcoin::key::{Parity, TapTweak};
use bitcoin::{
    bip32::Xpriv,
    hex::FromHex,
    key::{Keypair, Secp256k1},
    secp256k1::All,
    Address, Network, PrivateKey, PublicKey, XOnlyPublicKey,
};
use secp::{Point, Scalar};

use crate::utils::{generate_p2sh_address, generate_p2tr_address, generate_p2wpkh_address, generate_p2wsh_address};

#[derive(Clone)]
pub struct AccountInfo {
    pub secp: Secp256k1<All>,
    pub xpriv: Xpriv,

    keypair: Keypair,
    tweaked_keypair: Keypair,

    public_key: PublicKey,
    x_pubkey: XOnlyPublicKey,
}

impl AccountInfo {
    pub fn p2tr_address(&self, network: Network) -> Address {
        generate_p2tr_address(network, &self.x_pubkey)
    }

    pub fn p2wpkh_address(&self, network: Network) -> Address {
        generate_p2wpkh_address(network, &self.public_key).unwrap()
    }

    pub fn p2sh_address(&self, network: Network) -> Address {
        generate_p2sh_address(network, &self.public_key).unwrap()
    }

    pub fn p2wsh_address(&self, network: Network) -> Address {
        generate_p2wsh_address(network, &self.public_key)
    }

    pub fn new(network: Network, secret: &str) -> Self {
        let secp = Secp256k1::new();
        let xpriv = Xpriv::new_master(network, &Vec::from_hex(secret).unwrap()).unwrap();
        let keypair = xpriv.to_keypair(&secp);
        let tweaked_keypair = keypair.tap_tweak(&secp, None).to_inner();
        let private_key = PrivateKey::new(keypair.secret_key(), network);
        let public_key = PublicKey::from_private_key(&secp, &private_key);
        let (x_pubkey, _) = XOnlyPublicKey::from_keypair(&keypair);
        AccountInfo {
            secp,
            xpriv,
            keypair,
            tweaked_keypair,
            public_key,
            x_pubkey,
        }
    }

    pub fn get_tweaked_keypair(&self) -> Keypair {
        self.tweaked_keypair
    }

    pub fn get_tweaked_secret(&self) -> Scalar {
        let secret = Scalar::from_slice(&self.tweaked_keypair.secret_bytes()).unwrap();
        let actual_pubkey = secret.base_point_mul();
        if actual_pubkey.has_even_y() {
            secret
        } else {
            -secret
        }
    }

    pub fn get_tweaked_pubkey(&self) -> PublicKey {
        self.tweaked_keypair.public_key().into()
    }

    pub fn get_tweaked_p_pubkey(&self) -> Point {
        Point::lift_x(&self.tweaked_keypair.x_only_public_key().0.serialize()).unwrap()
    }

    pub fn get_tweaked_x_pubkey(&self) -> (XOnlyPublicKey, Parity) {
        self.tweaked_keypair.x_only_public_key()
    }

    pub fn get_keypair(&self) -> Keypair {
        self.keypair
    }

    pub fn get_secret(&self) -> Scalar {
        Scalar::from_slice(&self.keypair.secret_bytes()).unwrap()
    }

    pub fn get_pubkey(&self) -> PublicKey {
        self.keypair.public_key().into()
    }

    pub fn get_p_pubkey(&self) -> Point {
        Point::from_slice(&self.keypair.public_key().serialize()).unwrap()
    }

    pub fn get_x_pubkey(&self) -> (XOnlyPublicKey, Parity) {
        self.keypair.x_only_public_key()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tweaked_keypair_match_p2tr() {
        for _ in 0..10 {
            let secret = format!("{:064x}", rand::random::<u128>() as u64);
            let account = AccountInfo::new(Network::Testnet, &secret);
            let p2tr_address = account.p2tr_address(Network::Testnet);
            let (tweaked_x_pubkey, _) = account.get_tweaked_x_pubkey();
            assert_eq!(
                tweaked_x_pubkey.serialize(),
                // Remove the first two bytes of the script pubkey as opcodes.
                p2tr_address.script_pubkey().as_bytes()[2..]
            );
        }
    }

    #[test]
    fn test_tweaked_pubkey_match_secret() {
        for _ in 0..10 {
            let secret = format!("{:064x}", rand::random::<u128>() as u64);
            let account = AccountInfo::new(Network::Testnet, &secret);

            let tweaked_secret = account.get_tweaked_secret();
            let tweaked_public = account.get_tweaked_p_pubkey();
            assert_eq!(tweaked_secret.base_point_mul(), tweaked_public);
        }
    }
}
