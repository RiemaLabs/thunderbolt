#![no_std]

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TransferPublicValues {
    pub next_holder: u64,
    pub next_committee: u64,
    pub invariant_before: u64,
    pub invariant_after: u64,
}

impl TransferPublicValues {
    pub fn to_bytes(self) -> [u8; 32] {
        let mut out = [0u8; 32];
        out[0..8].copy_from_slice(&self.next_holder.to_le_bytes());
        out[8..16].copy_from_slice(&self.next_committee.to_le_bytes());
        out[16..24].copy_from_slice(&self.invariant_before.to_le_bytes());
        out[24..32].copy_from_slice(&self.invariant_after.to_le_bytes());
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Self {
        assert!(bytes.len() >= 32);
        let mut chunk = [0u8; 8];
        chunk.copy_from_slice(&bytes[0..8]);
        let next_holder = u64::from_le_bytes(chunk);
        chunk.copy_from_slice(&bytes[8..16]);
        let next_committee = u64::from_le_bytes(chunk);
        chunk.copy_from_slice(&bytes[16..24]);
        let invariant_before = u64::from_le_bytes(chunk);
        chunk.copy_from_slice(&bytes[24..32]);
        let invariant_after = u64::from_le_bytes(chunk);
        Self {
            next_holder,
            next_committee,
            invariant_before,
            invariant_after,
        }
    }
}

pub fn transfer_step(holder_secret: u64, refresh: u64, committee_share: u64) -> TransferPublicValues {
    let next_holder = holder_secret.checked_add(refresh).expect("holder + refresh overflowed");
    let next_committee = committee_share.checked_sub(refresh).expect("committee - refresh underflowed");
    let invariant_before = holder_secret.checked_add(committee_share).expect("before invariant overflowed");
    let invariant_after = next_holder.checked_add(next_committee).expect("after invariant overflowed");
    assert_eq!(invariant_before, invariant_after, "transfer invariant must be preserved");
    TransferPublicValues {
        next_holder,
        next_committee,
        invariant_before,
        invariant_after,
    }
}
