use libpaillier::{unknown_order::BigNumber, Ciphertext, DecryptionKey, EncryptionKey, Nonce};
use zeroize::Zeroize;

const PAILLIER_KEY_SIZE: usize = 3072;
const PAILLIER_P_SIZE: usize = 2048;
const PAILLIER_Q_SIZE: usize = 1024;

pub trait PaillierAccount {
    fn encrypt(&self, secret: &[u8], nonce: Nonce) -> Option<(Ciphertext, Nonce)>;
    fn decrypt(&self, ciphertext: &Ciphertext) -> Option<Vec<u8>>;
}

pub struct PaillierAccountLocal {
    nonce: Nonce,
    public_key: EncryptionKey,
    private_key: DecryptionKey,
}

impl PaillierAccount for PaillierAccountLocal {
    fn encrypt(&self, secret: &[u8], nonce: Nonce) -> Option<(Ciphertext, Nonce)> {
        self.public_key.encrypt(secret, Some(nonce))
    }

    fn decrypt(&self, ciphertext: &Ciphertext) -> Option<Vec<u8>> {
        self.private_key.decrypt(ciphertext)
    }
}

impl PaillierAccountLocal {
    fn new() -> Option<Self> {
        let mut p = BigNumber::prime(PAILLIER_P_SIZE);
        let mut q = BigNumber::prime(PAILLIER_Q_SIZE);
        let res = DecryptionKey::with_primes_unchecked(&p, &q);
        // Make sure the primes are zero'd
        p.zeroize();
        q.zeroize();
        let private_key = res?;
        let public_key = EncryptionKey::from(&private_key);
        Some(Self {
            nonce: Nonce::zero(),
            public_key,
            private_key,
        })
    }

    fn nonce(&self) -> Nonce {
        self.nonce.clone()
    }

    fn nonce_increment(&mut self) {
        self.nonce += 1;
    }
}
