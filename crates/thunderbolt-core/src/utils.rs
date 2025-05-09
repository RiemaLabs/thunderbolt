use secp::{MaybeScalar, Point, Scalar};
use sha2::{Digest, Sha256};

pub fn compute_challenge(nonce_point: &Point, pubkey: &Point, msg: &[u8]) -> MaybeScalar {
    let hash: [u8; 32] = Sha256::new()
        .chain_update(&nonce_point.serialize())
        .chain_update(&pubkey.serialize())
        .chain_update(msg)
        .finalize()
        .into();
    MaybeScalar::reduce_from(&hash)
}

pub fn schnorr_sign(nonce: Scalar, secret_key: Scalar, message: &[u8]) -> (Point, MaybeScalar) {
    let nonce_point = nonce.base_point_mul();
    let pubkey = secret_key.base_point_mul();

    let e = compute_challenge(&nonce_point, &pubkey, message);
    let s = nonce + secret_key * e;
    (nonce_point, s)
}

pub fn schnorr_verify(public_key: Point, signature: (Point, MaybeScalar), message: &[u8]) -> bool {
    let (r, s) = signature;
    let e = compute_challenge(&r, &public_key, message);
    s.base_point_mul() == r + e * public_key
}