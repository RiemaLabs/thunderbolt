use sha2::{Digest as _, Sha256};
use thunderbolt_wire::{
    to_json_vec, BindingContext, CanonicalDigest, CanonicalInteger, InvoiceEnvelopeV1, InvoiceProofV1,
    InvoiceStatementV1, PaillierPublicKeyHex, PointHex,
};

#[test]
fn v1_invoice_encoding_and_digest_are_frozen() {
    let point = PointHex::from_bytes(
        "golden point",
        hex::decode("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798").expect("point hex"),
    )
    .expect("point width");
    let mut modulus = vec![0_u8; 256];
    modulus[0] = 0x40;
    modulus[255] = 1;
    let key = PaillierPublicKeyHex::from_bytes("golden key", modulus).expect("key width");
    let ciphertext = CanonicalInteger::from_bytes("golden ciphertext", [1_u8]).expect("ciphertext");
    let response = CanonicalInteger::from_bytes("golden response", [1_u8]).expect("response");
    let nonce = CanonicalInteger::from_bytes("golden nonce", [1_u8]).expect("nonce");
    let envelope = InvoiceEnvelopeV1 {
        binding: BindingContext::invoice(bitcoin::Network::Regtest, [1_u8], 1, [2_u8], [3_u8]).expect("binding"),
        statement: InvoiceStatementV1 {
            anchor_base: point.clone(),
            bob_key: key.clone(),
            committee_key: key,
            delta: point.clone(),
            bob_ciphertext: ciphertext.clone(),
            committee_ciphertext: ciphertext.clone(),
        },
        proof: InvoiceProofV1 {
            a_delta: point,
            a_bob: ciphertext.clone(),
            a_committee: ciphertext,
            z: response,
            tau_bob: nonce.clone(),
            tau_committee: nonce,
        },
    };
    let encoded = to_json_vec(&envelope).expect("v1 JSON");
    let json_hash = hex::encode(Sha256::digest(&encoded));
    let wire_digest = hex::encode(envelope.canonical_digest().expect("v1 digest"));
    assert_eq!(
        json_hash,
        "3a5ecb48244087df016ff7dc2d5e6f5b2a159e5967dbd0379609ef0cd1f7d914"
    );
    assert_eq!(
        wire_digest,
        "fe9c1c993d99365ceeab760ee12b92465e1ab2939e43c258143c434855c4cdfb"
    );
}
