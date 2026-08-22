use bitcoin::{
    hashes::{sha256, Hash},
    secp256k1::{ecdh, PublicKey, SecretKey},
};
use secp::{MaybeScalar, Point, Scalar};

pub struct Tweaker {
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

    pub fn compute_shared_secret(&self) -> crate::Result<Scalar> {
        let pubkey = PublicKey::from_slice(&self.p_pubkey_b.serialize_uncompressed())
            .map_err(|error| crate::ThunderboltError::InvalidPoint(error.to_string()))?;
        let secret_key = SecretKey::from_slice(&self.secret_key_a.serialize())
            .map_err(|error| crate::ThunderboltError::InvalidParameter(error.to_string()))?;
        let secret = ecdh::shared_secret_point(&pubkey, &secret_key);
        let hash = sha256::Hash::hash(&secret).to_byte_array();
        MaybeScalar::reduce_from(&hash)
            .not_zero()
            .map_err(|_| crate::ThunderboltError::CryptographicError("ECDH-derived tweak reduced to zero".to_string()))
    }
}

#[cfg(test)]
mod tests {
    use bitcoin::key::rand::thread_rng;

    use super::*;

    #[test]
    fn test_compute_shared_secret() {
        for _ in 0..10 {
            let secret_key_a = Scalar::random(&mut thread_rng());
            let secret_key_b = Scalar::random(&mut thread_rng());
            let p_pubkey_a = secret_key_a.base_point_mul();
            let p_pubkey_b = secret_key_b.base_point_mul();
            let tweaker_ab = Tweaker::new(secret_key_a, p_pubkey_b);
            let tweaker_ba = Tweaker::new(secret_key_b, p_pubkey_a);
            let shared_secret_ab = tweaker_ab.compute_shared_secret().unwrap();
            let shared_secret_ba = tweaker_ba.compute_shared_secret().unwrap();
            assert_eq!(shared_secret_ab, shared_secret_ba);
        }
    }
}
