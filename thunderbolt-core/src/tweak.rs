use bitcoin::hashes::{sha256, Hash};
use secp::{Point, Scalar};

use secp256k1::ecdh;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum TweakerError {
}

struct Tweaker {
    secret_key_a: Scalar,
    p_pubkey_b: Point,
}

impl Tweaker {
    pub fn new(secret_key_a: Scalar, p_pubkey_b: Point) -> Self {
        Self {
            secret_key_a,
            p_pubkey_b,
        }
    }

    pub fn compute_shared_secret(&self) -> Scalar {
        let pubkey = secp256k1::PublicKey::from_slice(&self.p_pubkey_b.serialize_uncompressed()).unwrap();
        let secret_key = secp256k1::SecretKey::from_slice(&self.secret_key_a.serialize()).unwrap();
        let secret = ecdh::shared_secret_point(&pubkey, &secret_key);
        let hash = sha256::Hash::hash(&secret);
        let scalar = Scalar::from_slice(hash.as_byte_array()).unwrap();
        scalar
    }
}
