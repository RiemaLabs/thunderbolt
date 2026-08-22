use std::fmt;
use std::str::FromStr;

use bitcoin::hashes::{sha256, Hash};
use bitcoin::key::{Parity, TapTweak};
use bitcoin::secp256k1::schnorr::Signature;
use bitcoin::secp256k1::{Message, SecretKey};
use bitcoin::{
    bip32::Xpriv,
    hex::FromHex,
    key::{Keypair, Secp256k1},
    secp256k1::All,
    Address, Network, PrivateKey, PublicKey, XOnlyPublicKey,
};
use secp::{Point, Scalar};

use crate::errors::AccountError;
use crate::utils::{generate_p2sh_address, generate_p2tr_address, generate_p2wpkh_address, generate_p2wsh_address};

/// Legacy in-memory account used by the transaction regression harness.
/// Production nodes should use a locked keystore or external signer.
#[derive(Clone)]
pub struct AccountInfo {
    secp: Secp256k1<All>,
    xpriv: Option<Xpriv>,

    keypair: Keypair,
    tweaked_keypair: Keypair,

    public_key: PublicKey,
    x_pubkey: XOnlyPublicKey,
}

impl fmt::Debug for AccountInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AccountInfo")
            .field("public_key", &self.public_key)
            .field("has_master_key", &self.xpriv.is_some())
            .finish_non_exhaustive()
    }
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

    pub fn new(network: Network, seed: &str) -> Result<Self, AccountError> {
        let seed = Vec::from_hex(seed).map_err(|error| AccountError::InvalidSeedHex(error.to_string()))?;
        Self::from_seed(network, &seed)
    }

    pub fn from_seed(network: Network, seed: &[u8]) -> Result<Self, AccountError> {
        let secp = Secp256k1::new();
        let xpriv =
            Xpriv::new_master(network, seed).map_err(|error| AccountError::InvalidMasterKey(error.to_string()))?;
        let keypair = xpriv.to_keypair(&secp);
        let tweaked_keypair = keypair.tap_tweak(&secp, None).to_keypair();
        let private_key = PrivateKey::new(keypair.secret_key(), network);
        let public_key = PublicKey::from_private_key(&secp, &private_key);
        let (x_pubkey, _) = XOnlyPublicKey::from_keypair(&keypair);
        Ok(AccountInfo {
            secp,
            xpriv: Some(xpriv),
            keypair,
            tweaked_keypair,
            public_key,
            x_pubkey,
        })
    }

    pub fn new_from_secret_key(secret_key: &str) -> Result<Self, AccountError> {
        let secp = Secp256k1::new();
        let secret_key = SecretKey::from_str(secret_key)?;
        let keypair = Keypair::from_secret_key(&secp, &secret_key);
        let tweaked_keypair = keypair.tap_tweak(&secp, None).to_keypair();
        let public_key = keypair.public_key().into();
        let (x_pubkey, _) = XOnlyPublicKey::from_keypair(&keypair);
        let xpriv = None;
        Ok(AccountInfo {
            secp,
            xpriv,
            keypair,
            tweaked_keypair,
            public_key,
            x_pubkey,
        })
    }

    /// Signs a domain message after hashing it to the 32-byte BIP340 message
    /// domain expected by libsecp256k1.
    pub fn sign_message(&self, message: &[u8]) -> Signature {
        let digest = sha256::Hash::hash(message).to_byte_array();
        self.secp.sign_schnorr(&Message::from_digest(digest), &self.keypair)
    }

    /// Returns the BIP32 master key for the legacy PSBT builder.
    ///
    /// New node code should sign through a keystore or external signer instead
    /// of exporting key material.
    pub fn master_xpriv(&self) -> Option<&Xpriv> {
        self.xpriv.as_ref()
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
            let account = AccountInfo::new(Network::Testnet, &secret).unwrap();
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
            let account = AccountInfo::new(Network::Testnet, &secret).unwrap();

            let tweaked_secret = account.get_tweaked_secret();
            let tweaked_public = account.get_tweaked_p_pubkey();
            assert_eq!(tweaked_secret.base_point_mul(), tweaked_public);
        }
    }

    #[test]
    fn test_fixed_seed_taproot_address() {
        let seed_hex = "000102030405060708090a0b0c0d0e0f";
        let network = Network::Bitcoin;

        let account = AccountInfo::new(network, seed_hex).unwrap();
        let p2tr_address = account.p2tr_address(network);

        assert!(!p2tr_address.to_string().is_empty());
    }

    #[test]
    fn rejects_malformed_seed_without_panicking() {
        assert!(AccountInfo::new(Network::Testnet, "not hex").is_err());
    }

    #[test]
    fn signs_and_verifies_domain_messages() {
        let account = AccountInfo::new(Network::Testnet, "000102030405060708090a0b0c0d0e0f").unwrap();
        let digest = sha256::Hash::hash(b"bitcoin-thunderbolt/test").to_byte_array();
        let message = Message::from_digest(digest);
        let signature = account.sign_message(b"bitcoin-thunderbolt/test");
        let (public_key, _) = account.get_x_pubkey();
        assert!(account.secp.verify_schnorr(&signature, &message, &public_key).is_ok());
    }
}
