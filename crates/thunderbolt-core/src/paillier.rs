use libpaillier::{Ciphertext, DecryptionKey, EncryptionKey, Nonce};
use secp::Scalar;

pub fn generate_paillier_keypair() -> (EncryptionKey, DecryptionKey) {
    let dk = DecryptionKey::random().expect("paillier keygen");
    let ek: EncryptionKey = (&dk).into();
    (ek, dk)
}

pub fn paillier_encrypt(ek: &EncryptionKey, plaintext_be: &[u8]) -> Result<(Ciphertext, Nonce), String> {
    ek.encrypt(plaintext_be, None)
        .ok_or_else(|| "Paillier encryption failed".to_string())
}

pub fn paillier_decrypt(dk: &DecryptionKey, ciphertext: &Ciphertext) -> Result<Vec<u8>, String> {
    dk.decrypt(&ciphertext)
        .ok_or_else(|| "Paillier decryption failed".to_string())
}

pub fn vec_to_scalar(vec: &[u8]) -> Scalar {
    let mut buf = [0u8; 32];
    let start = 32usize.saturating_sub(vec.len());
    buf[start..].copy_from_slice(&vec);

    // Parse back into a nonzero Scalar
    let sk2 = Scalar::from_slice(&buf).expect("valid scalar");
    sk2
}

#[cfg(test)]
mod tests {

    use super::*;

    use rand::{rng, RngCore};

    #[test]
    fn encrypt_and_decrypt_scalar() {
        // Draw 32 bytes, reduce to a valid nonzero scalar.
        // (You could also call Scalar::random(&mut rng).)
        let mut raw = [0u8; 32];
        let mut thread_rng = rng();
        thread_rng.fill_bytes(&mut raw);
        let sk = Scalar::reduce_from(&raw); // always in [1,n)
        let scalar_bytes: [u8; 32] = sk.serialize();

        let (ek, dk) = generate_paillier_keypair();
        let (ciphertext, _nonce) = paillier_encrypt(&ek, &scalar_bytes).unwrap();
        let decrypted_bytes = paillier_decrypt(&dk, &ciphertext).unwrap();
        let scalar_decrypted = vec_to_scalar(&decrypted_bytes);

        assert_eq!(sk.serialize(), scalar_decrypted.serialize());

        println!("the test is successful!");
    }
}
