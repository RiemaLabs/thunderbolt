use musig2::compute_challenge_hash_tweak;
use secp::{MaybeScalar, Point, Scalar};

pub type Signature = ([u8; 32], MaybeScalar);

pub fn schnorr_compute_challenge(pubkey: &Point, msg: &[u8], x_pubnonce: &[u8; 32]) -> MaybeScalar {
    compute_challenge_hash_tweak(x_pubnonce, pubkey, msg)
}

pub fn schnorr_sign(secret_key: Scalar, nonce: Scalar, e: MaybeScalar) -> Signature {
    let nonce_point = nonce.base_point_mul();

    let s = nonce + secret_key * e;
    (nonce_point.serialize_xonly(), s)
}

// Faithfully implemented for https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki#verification
pub fn schnorr_verify(x_pubkey: [u8; 32], msg: &[u8], signature: Signature) -> bool {
    let Ok(pubkey) = Point::lift_x(&x_pubkey) else {
        return false;
    };
    let (r, s) = signature;
    let e = schnorr_compute_challenge(&pubkey, msg, &r);
    let p_r = s.base_point_mul() - e * pubkey;
    if p_r.is_infinity() {
        return false;
    }
    if !p_r.has_even_y() {
        return false;
    }
    p_r.serialize_xonly() == r
}

#[cfg(test)]
mod tests {
    use bitcoin::key::rand::{self, thread_rng};
    use bitcoin::Network;
    use bitcoin_utils::account::AccountInfo;
    use musig2::{sign_solo, LiftedSignature, NonceSeed};

    use super::*;

    #[test]
    fn test_schnorr_verify() {
        for _ in 0..10 {
            let secret = format!("{:064x}", rand::random::<u128>() as u64);
            let account = AccountInfo::new(Network::Testnet, &secret).unwrap();
            let msg = b"Hello, world!";

            let pubkey = account.get_tweaked_p_pubkey();

            let mut nonce = Scalar::random(&mut thread_rng());
            let p_r = nonce.base_point_mul();
            let p_r_has_even_y = p_r.has_even_y();
            if !p_r_has_even_y {
                nonce = -nonce;
            }
            let mut secret_key = account.get_tweaked_secret();
            if !pubkey.has_even_y() {
                secret_key = -secret_key;
            }

            let e = schnorr_compute_challenge(&pubkey, msg, &p_r.serialize_xonly());
            let signature = schnorr_sign(secret_key, nonce, e);
            let veri_result = schnorr_verify(pubkey.serialize_xonly(), msg, signature);
            assert!(veri_result);
        }
    }

    #[test]
    fn test_schnorr_verify_2_of_2() {
        for _ in 0..10 {
            let secret0 = format!("{:064x}", rand::random::<u128>() as u64);
            let secret1 = format!("{:064x}", rand::random::<u128>() as u64);
            let account0 = AccountInfo::new(Network::Testnet, &secret0).unwrap();
            let account1 = AccountInfo::new(Network::Testnet, &secret1).unwrap();
            let msg = b"Hello, world!";

            let pubkey0 = account0.get_tweaked_p_pubkey();
            let pubkey1 = account1.get_p_pubkey();

            let pubkey = (pubkey0 + pubkey1).unwrap();

            let mut secret0 = account0.get_tweaked_secret();
            let mut secret1 = account1.get_secret();
            if !pubkey.has_even_y() {
                secret0 = -secret0;
                secret1 = -secret1;
            }

            let mut nonce0 = Scalar::random(&mut thread_rng());
            let mut nonce1 = Scalar::random(&mut thread_rng());

            let p_nonce0 = nonce0.base_point_mul();
            let p_nonce1 = nonce1.base_point_mul();
            let p_nonce = (p_nonce0 + p_nonce1).unwrap();

            if !p_nonce.has_even_y() {
                nonce0 = -nonce0;
                nonce1 = -nonce1;
            }

            let e = schnorr_compute_challenge(&pubkey, msg, &p_nonce.serialize_xonly());
            let signature0 = schnorr_sign(secret0, nonce0, e);
            let signature1 = schnorr_sign(secret1, nonce1, e);

            let signature = (p_nonce.serialize_xonly(), signature0.1 + signature1.1);

            let veri_result = schnorr_verify(pubkey.serialize_xonly(), msg, signature);
            assert!(veri_result);
        }
    }

    #[test]
    fn test_schnorr_verify_capability() {
        for _ in 0..10 {
            let secret = format!("{:064x}", rand::random::<u128>() as u64);
            let account = AccountInfo::new(Network::Testnet, &secret).unwrap();
            let msg = b"Hello, world!";

            let nonce = Scalar::random(&mut thread_rng());
            let nonce_seed = NonceSeed::from(nonce.serialize());

            let signature: LiftedSignature = sign_solo(account.get_tweaked_secret(), msg, nonce_seed);
            let signature_compact = signature.compact();

            let veri_result = schnorr_verify(
                account.get_tweaked_x_pubkey().0.serialize(),
                msg,
                (signature_compact.rx, signature_compact.s),
            );
            assert!(veri_result);
        }
    }

    #[test]
    fn schnorr_verify_rejects_malformed_public_key_without_panicking() {
        assert!(!schnorr_verify(
            [0xff; 32],
            b"malformed",
            ([0u8; 32], MaybeScalar::Zero),
        ));
    }
}
