use musig2::compute_challenge_hash_tweak;
use secp::{MaybeScalar, Point, Scalar};

pub fn compute_challenge(nonce_point: &Point, pubkey: &Point, msg: &[u8]) -> MaybeScalar {
    compute_challenge_hash_tweak(&nonce_point.serialize_xonly(), pubkey, msg)
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
