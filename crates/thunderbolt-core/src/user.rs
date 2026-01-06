use crate::bitcoin_account::{BitcoinAccount, BitcoinAccountLocal};
use crate::paillier::{PaillierAccount, PaillierAccountLocal};

pub trait User {
    fn get_name(&self) -> String;
    fn get_bitcoin_account(&self) -> &impl BitcoinAccount;
    fn get_paillier_account(&self) -> &impl PaillierAccount;
}

pub struct UserLocal {
    pub name: String,
    pub bitcoin_account: BitcoinAccountLocal,
    pub paillier_account: PaillierAccountLocal,
}

impl User for UserLocal {
    fn get_name(&self) -> String {
        self.name.clone()
    }

    fn get_bitcoin_account(&self) -> &impl BitcoinAccount {
        &self.bitcoin_account
    }

    fn get_paillier_account(&self) -> &impl PaillierAccount {
        &self.paillier_account
    }
}

impl UserLocal {
    pub fn new(name: String, bitcoin_account: BitcoinAccountLocal, paillier_account: PaillierAccountLocal) -> Self {
        Self {
            name,
            bitcoin_account,
            paillier_account,
        }
    }

    pub fn get_bitcoin_account_local(&self) -> &BitcoinAccountLocal {
        &self.bitcoin_account
    }

    pub fn get_paillier_account_local(&self) -> &PaillierAccountLocal {
        &self.paillier_account
    }
}
