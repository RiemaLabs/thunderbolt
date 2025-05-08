use bitcoin::key::TapTweak;
use bitcoin::{
    bip32::Xpriv,
    hex::FromHex,
    key::{Keypair, Secp256k1},
    secp256k1::All,
    Address, Network, PrivateKey, PublicKey, XOnlyPublicKey,
};

use crate::utils::{
    generate_p2sh_address, generate_p2tr_address, generate_p2wpkh_address, generate_p2wsh_address,
};

#[derive(Clone)]
pub struct AccountInfo {
    pub secp: Secp256k1<All>,
    pub xpriv: Xpriv,
    pub keypair: Keypair,
    pub private_key: PrivateKey,
    pub public_key: PublicKey,
    pub x_pubkey: XOnlyPublicKey,
    pub p2tr_tweaked_keypair: Keypair,
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
        let private_key = PrivateKey::new(keypair.secret_key(), network);
        let public_key = PublicKey::from_private_key(&secp, &private_key);
        let (x_pubkey, _) = XOnlyPublicKey::from_keypair(&keypair);
        let p2tr_tweaked_keypair = keypair.tap_tweak(&secp, None).to_inner();
        AccountInfo {
            secp,
            xpriv,
            keypair,
            private_key,
            public_key,
            x_pubkey,
            p2tr_tweaked_keypair,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &str = "df207ca59c80138f6eba206c3dd7ef2307687ab5493620c95c671008945b63a1";

    #[test]
    fn test_p2tr_tweaked_keypair_mainnet() {
        let account = AccountInfo::new(Network::Bitcoin, SECRET);
        let p2tr_tweaked_keypair = account.p2tr_tweaked_keypair;
        let p2tr_address = account.p2tr_address(Network::Bitcoin);
        assert_eq!(
            p2tr_tweaked_keypair
                .public_key()
                .x_only_public_key()
                .0
                .serialize(),
            // Remove the first two bytes of the script pubkey as opcodes.
            p2tr_address.script_pubkey().as_bytes()[2..]
        );
    }

    #[test]
    fn test_p2tr_tweaked_keypair_testnet() {
        let account = AccountInfo::new(Network::Testnet, SECRET);
        let p2tr_tweaked_keypair = account.p2tr_tweaked_keypair;
        let p2tr_address = account.p2tr_address(Network::Testnet);
        assert_eq!(
            p2tr_tweaked_keypair
                .public_key()
                .x_only_public_key()
                .0
                .serialize(),
            // Remove the first two bytes of the script pubkey as opcodes.
            p2tr_address.script_pubkey().as_bytes()[2..]
        );
    }
}
