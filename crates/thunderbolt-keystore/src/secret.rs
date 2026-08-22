use crate::{KeystoreError, Result, VaultRole};
use zeroize::Zeroizing;

pub(crate) const BITCOIN_SEED_TAG: u8 = 1;
pub(crate) const PAILLIER_KEY_TAG: u8 = 2;
pub(crate) const HOLDER_CREDENTIAL_TAG: u8 = 3;
pub(crate) const COMMITTEE_SHARE_TAG: u8 = 4;
pub(crate) const SESSION_NONCE_TAG: u8 = 5;

const MIN_BITCOIN_SEED_BYTES: usize = 16;
const MAX_BITCOIN_SEED_BYTES: usize = 64;
const MIN_PAILLIER_KEY_BYTES: usize = 32;
const MAX_PAILLIER_KEY_BYTES: usize = 256 * 1024;
const MAX_CREDENTIAL_BYTES: usize = 64 * 1024;
const MAX_COMMITTEE_SHARE_BYTES: usize = 64 * 1024;
const SESSION_NONCE_BYTES: usize = 32;

macro_rules! opaque_secret {
    ($(#[$metadata:meta])* $name:ident, $minimum:expr, $maximum:expr) => {
        $(#[$metadata])*
        pub struct $name(Zeroizing<Vec<u8>>);

        impl $name {
            /// Moves bytes into an opaque, zeroizing record.
            pub fn from_bytes(bytes: Vec<u8>) -> Result<Self> {
                let bytes = Zeroizing::new(bytes);
                if bytes.len() < $minimum || bytes.len() > $maximum {
                    return Err(KeystoreError::InvalidSecretRecord);
                }
                Ok(Self(bytes))
            }

            /// Explicitly borrows the secret bytes for a cryptographic operation.
            #[must_use]
            pub fn expose_secret(&self) -> &[u8] {
                self.0.as_slice()
            }
        }
    };
}

opaque_secret!(
    /// BIP32/BIP39 seed material for one Holder wallet.
    BitcoinSeed,
    MIN_BITCOIN_SEED_BYTES,
    MAX_BITCOIN_SEED_BYTES
);
opaque_secret!(
    /// Serialized private Paillier key material.
    PaillierKeyBytes,
    MIN_PAILLIER_KEY_BYTES,
    MAX_PAILLIER_KEY_BYTES
);
opaque_secret!(
    /// Serialized current-Holder ownership credential.
    HolderCredential,
    1,
    MAX_CREDENTIAL_BYTES
);
opaque_secret!(
    /// Serialized threshold share held by one committee member.
    CommitteeMemberShare,
    1,
    MAX_COMMITTEE_SHARE_BYTES
);
opaque_secret!(
    /// A persisted one-time committee signing-session nonce.
    CommitteeSessionNonce,
    SESSION_NONCE_BYTES,
    SESSION_NONCE_BYTES
);

#[derive(Default)]
pub(crate) struct Records {
    pub(crate) bitcoin_seed: Option<BitcoinSeed>,
    pub(crate) paillier_key: Option<PaillierKeyBytes>,
    pub(crate) holder_credential: Option<HolderCredential>,
    pub(crate) committee_share: Option<CommitteeMemberShare>,
    pub(crate) session_nonce: Option<CommitteeSessionNonce>,
}

impl Records {
    pub(crate) fn bitmap(&self) -> u8 {
        let mut bitmap = 0_u8;
        if self.bitcoin_seed.is_some() {
            bitmap |= 1 << (BITCOIN_SEED_TAG - 1);
        }
        if self.paillier_key.is_some() {
            bitmap |= 1 << (PAILLIER_KEY_TAG - 1);
        }
        if self.holder_credential.is_some() {
            bitmap |= 1 << (HOLDER_CREDENTIAL_TAG - 1);
        }
        if self.committee_share.is_some() {
            bitmap |= 1 << (COMMITTEE_SHARE_TAG - 1);
        }
        if self.session_nonce.is_some() {
            bitmap |= 1 << (SESSION_NONCE_TAG - 1);
        }
        bitmap
    }

    pub(crate) fn validate_role(&self, role: VaultRole) -> Result<()> {
        let invalid = match role {
            VaultRole::Holder => self.committee_share.is_some() || self.session_nonce.is_some(),
            VaultRole::CommitteeMember => self.bitcoin_seed.is_some() || self.holder_credential.is_some(),
        };
        if invalid {
            Err(KeystoreError::InvalidRecordForRole)
        } else {
            Ok(())
        }
    }

    pub(crate) fn encode(&self) -> Result<Zeroizing<Vec<u8>>> {
        let mut output = Zeroizing::new(Vec::with_capacity(1024));
        let count = self.bitmap().count_ones();
        let count = u8::try_from(count).map_err(|_| KeystoreError::InvalidFormat)?;
        output.push(count);

        if let Some(record) = &self.bitcoin_seed {
            encode_record(&mut output, BITCOIN_SEED_TAG, record.expose_secret())?;
        }
        if let Some(record) = &self.paillier_key {
            encode_record(&mut output, PAILLIER_KEY_TAG, record.expose_secret())?;
        }
        if let Some(record) = &self.holder_credential {
            encode_record(&mut output, HOLDER_CREDENTIAL_TAG, record.expose_secret())?;
        }
        if let Some(record) = &self.committee_share {
            encode_record(&mut output, COMMITTEE_SHARE_TAG, record.expose_secret())?;
        }
        if let Some(record) = &self.session_nonce {
            encode_record(&mut output, SESSION_NONCE_TAG, record.expose_secret())?;
        }
        Ok(output)
    }

    pub(crate) fn decode(plaintext: &[u8], authenticated_bitmap: u8, role: VaultRole) -> Result<Self> {
        if authenticated_bitmap & !0b0001_1111 != 0 {
            return Err(KeystoreError::InvalidFormat);
        }

        let mut cursor = SecretCursor::new(plaintext);
        let count = cursor.read_u8()?;
        let mut records = Self::default();
        let mut seen = 0_u8;

        for _ in 0..count {
            let tag = cursor.read_u8()?;
            if !(BITCOIN_SEED_TAG..=SESSION_NONCE_TAG).contains(&tag) {
                return Err(KeystoreError::InvalidFormat);
            }
            let bit = 1_u8
                .checked_shl(u32::from(tag - 1))
                .ok_or(KeystoreError::InvalidFormat)?;
            if seen & bit != 0 {
                return Err(KeystoreError::InvalidFormat);
            }
            seen |= bit;

            let length = cursor.read_u32()?;
            let length = usize::try_from(length).map_err(|_| KeystoreError::InvalidFormat)?;
            let bytes = cursor.take(length)?;
            match tag {
                BITCOIN_SEED_TAG => records.bitcoin_seed = Some(BitcoinSeed::from_bytes(bytes.to_vec())?),
                PAILLIER_KEY_TAG => records.paillier_key = Some(PaillierKeyBytes::from_bytes(bytes.to_vec())?),
                HOLDER_CREDENTIAL_TAG => {
                    records.holder_credential = Some(HolderCredential::from_bytes(bytes.to_vec())?);
                }
                COMMITTEE_SHARE_TAG => {
                    records.committee_share = Some(CommitteeMemberShare::from_bytes(bytes.to_vec())?);
                }
                SESSION_NONCE_TAG => {
                    records.session_nonce = Some(CommitteeSessionNonce::from_bytes(bytes.to_vec())?);
                }
                _ => return Err(KeystoreError::InvalidFormat),
            }
        }

        if !cursor.is_empty() || seen != authenticated_bitmap || u32::from(count) != seen.count_ones() {
            return Err(KeystoreError::InvalidFormat);
        }
        records.validate_role(role)?;
        Ok(records)
    }
}

fn encode_record(output: &mut Zeroizing<Vec<u8>>, tag: u8, bytes: &[u8]) -> Result<()> {
    let length = u32::try_from(bytes.len()).map_err(|_| KeystoreError::InvalidSecretRecord)?;
    output.push(tag);
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(bytes);
    Ok(())
}

struct SecretCursor<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> SecretCursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    fn read_u8(&mut self) -> Result<u8> {
        let byte = self
            .bytes
            .get(self.position)
            .copied()
            .ok_or(KeystoreError::InvalidFormat)?;
        self.position = self.position.checked_add(1).ok_or(KeystoreError::InvalidFormat)?;
        Ok(byte)
    }

    fn read_u32(&mut self) -> Result<u32> {
        let bytes = self.take(4)?;
        let bytes = <[u8; 4]>::try_from(bytes).map_err(|_| KeystoreError::InvalidFormat)?;
        Ok(u32::from_be_bytes(bytes))
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8]> {
        let end = self.position.checked_add(length).ok_or(KeystoreError::InvalidFormat)?;
        let value = self.bytes.get(self.position..end).ok_or(KeystoreError::InvalidFormat)?;
        self.position = end;
        Ok(value)
    }

    fn is_empty(&self) -> bool {
        self.position == self.bytes.len()
    }
}
