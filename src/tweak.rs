use secp::{Point, Scalar};

use thiserror::Error;

#[derive(Error, Debug)]
pub enum TweakerError {
    #[error("invalid secret key pair")]
    InvalidSecretKeyPair,
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

    pub fn compute_shared_secret(&self) -> Point {
        // TODO: The implementation is not safe.
        // The check of points is not done.
        (self.secret_key_a * self.p_pubkey_b)
    }
}
