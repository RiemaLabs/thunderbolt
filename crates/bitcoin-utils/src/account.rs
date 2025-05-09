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

    pub keypair: Keypair,
    pub tweaked_keypair: Keypair,

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

    pub fn get_tweaked_secret(&self) -> Scalar {
        Scalar::from_slice(&self.tweaked_keypair.secret_bytes()).unwrap()
    }

    pub fn get_tweaked_public(&self) -> Point {
        Point::from_slice(&self.tweaked_keypair.public_key().serialize()).unwrap()
    }

    pub fn get_tweaked_x_pubkey(&self) -> (XOnlyPublicKey, Parity) {
        self.tweaked_keypair.x_only_public_key()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &str = "df207ca59c80138f6eba206c3dd7ef2307687ab5493620c95c671008945b63a1";

    #[test]
    fn test_p2tr_tweaked_keypair_mainnet() {
        let account = AccountInfo::new(Network::Bitcoin, SECRET);
        let p2tr_address = account.p2tr_address(Network::Bitcoin);
        let (tweaked_x_pubkey, _) = account.get_tweaked_x_pubkey();
        assert_eq!(
            tweaked_x_pubkey.serialize(),
            // Remove the first two bytes of the script pubkey as opcodes.
            p2tr_address.script_pubkey().as_bytes()[2..]
        );

        let tweaked_secret = account.get_tweaked_secret();
        let tweaked_public = account.get_tweaked_public();
        assert_eq!(tweaked_secret.base_point_mul(), tweaked_public);
        assert_eq!(tweaked_public.serialize_xonly(), tweaked_x_pubkey.serialize());
    }

    #[test]
    fn test_p2tr_tweaked_keypair_testnet() {
        let account = AccountInfo::new(Network::Testnet, SECRET);
        let p2tr_address = account.p2tr_address(Network::Testnet);
        let (tweaked_x_pubkey, _) = account.get_tweaked_x_pubkey();
        assert_eq!(
            tweaked_x_pubkey.serialize(),
            // Remove the first two bytes of the script pubkey as opcodes.
            p2tr_address.script_pubkey().as_bytes()[2..]
        );

        let tweaked_secret = account.get_tweaked_secret();
        let tweaked_public = account.get_tweaked_public();
        assert_eq!(tweaked_secret.base_point_mul(), tweaked_public);
        assert_eq!(tweaked_public.serialize_xonly(), tweaked_x_pubkey.serialize());
    }
}
