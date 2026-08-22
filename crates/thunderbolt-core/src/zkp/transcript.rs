use libpaillier::{unknown_order::BigNumber, Ciphertext, EncryptionKey};
use secp::Point;
use sha2::{Digest, Sha256};

use crate::zkp::types::{canonical_big_number_bytes, ChallengeValue, ProofContext, ProofTag};

#[derive(Debug, Default)]
pub(crate) struct ProofTranscript {
    hasher: Sha256,
}

impl ProofTranscript {
    pub(crate) fn new(tag: ProofTag) -> Self {
        let mut transcript = Self { hasher: Sha256::new() };
        transcript.append_bytes(b"tag", tag.as_bytes());
        transcript
    }

    pub(crate) fn append_context(&mut self, context: &ProofContext) {
        self.append_bytes(b"ctx_id", context.ctx_id());
        self.append_bytes(b"inv_id", context.inv_id());
        if let Some(step) = context.step() {
            self.append_bytes(b"step", &step.to_be_bytes());
        }
    }

    pub(crate) fn append_point(&mut self, label: &[u8], point: &Point) {
        self.append_bytes(label, &point.serialize());
    }

    pub(crate) fn append_key(&mut self, label: &[u8], key: &EncryptionKey) {
        self.append_big_number(label, key.n());
    }

    pub(crate) fn append_ciphertext(&mut self, label: &[u8], ciphertext: &Ciphertext) {
        self.append_big_number(label, ciphertext);
    }

    pub(crate) fn append_big_number(&mut self, label: &[u8], value: &BigNumber) {
        let bytes = canonical_big_number_bytes(value);
        self.append_bytes(label, &bytes);
    }

    pub(crate) fn append_u32(&mut self, label: &[u8], value: u32) {
        self.append_bytes(label, &value.to_be_bytes());
    }

    pub(crate) fn challenge(self) -> ChallengeValue {
        let digest: [u8; 32] = self.hasher.finalize().into();
        ChallengeValue::from_digest(digest)
    }

    fn append_bytes(&mut self, label: &[u8], value: &[u8]) {
        self.append_length(label.len());
        self.hasher.update(label);
        self.append_length(value.len());
        self.hasher.update(value);
    }

    fn append_length(&mut self, len: usize) {
        self.hasher.update((len as u64).to_be_bytes());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::zkp::types::{canonical_big_number_bytes, ProofContext};
    use libpaillier::EncryptionKey;
    use secp::Scalar;

    fn scalar_from_u8(value: u8) -> Scalar {
        let mut bytes = [0u8; 32];
        bytes[31] = value;
        Scalar::from_slice(&bytes).unwrap()
    }

    #[test]
    fn transcript_binding_changes_when_only_tag_changes() {
        let point = scalar_from_u8(9).base_point_mul();
        let context = ProofContext::invoice(b"ctx", b"inv");

        let mut invoice = ProofTranscript::new(ProofTag::Invoice);
        invoice.append_context(&context);
        invoice.append_point(b"H", &point);
        let invoice_challenge = invoice.challenge();

        let mut transfer = ProofTranscript::new(ProofTag::Transfer);
        transfer.append_context(&context);
        transfer.append_point(b"H", &point);
        let transfer_challenge = transfer.challenge();

        assert_ne!(invoice_challenge.integer(), transfer_challenge.integer());
    }

    #[test]
    fn transcript_binding_changes_when_only_context_changes() {
        let point = scalar_from_u8(13).base_point_mul();
        let context_a = ProofContext::invoice(b"ctx-a", b"inv");
        let context_b = ProofContext::invoice(b"ctx-b", b"inv");

        let mut transcript_a = ProofTranscript::new(ProofTag::Invoice);
        transcript_a.append_context(&context_a);
        transcript_a.append_point(b"H", &point);

        let mut transcript_b = ProofTranscript::new(ProofTag::Invoice);
        transcript_b.append_context(&context_b);
        transcript_b.append_point(b"H", &point);

        assert_ne!(transcript_a.challenge().integer(), transcript_b.challenge().integer());
    }

    #[test]
    fn legacy_invoice_transcript_matches_golden_challenge() {
        let point = scalar_from_u8(9).base_point_mul();
        let modulus = (BigNumber::one() << 2047) + BigNumber::from(0x101u32);
        let key = EncryptionKey::from_n(modulus);
        let mut transcript = ProofTranscript::new(ProofTag::Invoice);
        transcript.append_context(&ProofContext::invoice(b"legacy-ctx", b"legacy-invoice"));
        transcript.append_point(b"H", &point);
        transcript.append_key(b"pk_B", &key);
        transcript.append_key(b"pk_C", &key);
        transcript.append_point(b"D_s", &(point * scalar_from_u8(2)));
        transcript.append_ciphertext(b"ct_B", &BigNumber::from(3u32));
        transcript.append_ciphertext(b"ct_C", &BigNumber::from(5u32));
        transcript.append_point(b"A_D", &(point * scalar_from_u8(3)));
        transcript.append_ciphertext(b"A_B", &BigNumber::from(7u32));
        transcript.append_ciphertext(b"A_C", &BigNumber::from(11u32));

        assert_eq!(
            canonical_big_number_bytes(transcript.challenge().integer()),
            vec![
                2, 114, 55, 117, 89, 47, 39, 40, 195, 255, 68, 105, 210, 123, 209, 119, 162, 221, 202, 45, 214, 49, 51,
                21, 190, 252, 163, 131, 199, 200, 173, 142,
            ]
        );
    }
}
