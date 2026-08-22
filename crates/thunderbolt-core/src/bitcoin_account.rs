use bitcoin::bip32::Xpriv;
use bitcoin::key::Parity;
use bitcoin::secp256k1::schnorr::Signature;
use bitcoin::PublicKey;
use bitcoin::{Address, Network, XOnlyPublicKey};
use bitcoin_utils::account::AccountInfo;

pub trait BitcoinAccount {
    fn get_x_pubkey(&self) -> (XOnlyPublicKey, Parity);
    fn get_p2tr_address(&self) -> Address;
    fn sign(&self, message: &[u8]) -> Signature;
}

pub struct BitcoinAccountLocal {
    account: AccountInfo,
    network: Network,
}

impl BitcoinAccount for BitcoinAccountLocal {
    fn get_x_pubkey(&self) -> (XOnlyPublicKey, Parity) {
        self.account.get_x_pubkey()
    }

    fn get_p2tr_address(&self) -> Address {
        self.account.p2tr_address(self.network)
    }

    fn sign(&self, message: &[u8]) -> Signature {
        self.account.sign_message(message)
    }
}

impl BitcoinAccountLocal {
    pub fn new(account: AccountInfo, network: Network) -> Self {
        Self { account, network }
    }

    pub fn get_pubkey(&self) -> PublicKey {
        self.account.get_pubkey()
    }

    pub fn get_xpriv(&self) -> crate::Result<&Xpriv> {
        self.account.master_xpriv().ok_or_else(|| {
            crate::ThunderboltError::InvalidParameter(
                "legacy PSBT signing requires an account derived from a BIP32 seed".to_string(),
            )
        })
    }
}
