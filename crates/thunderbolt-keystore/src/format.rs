use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use zeroize::Zeroizing;

use crate::secret::Records;
use crate::{KdfParams, KeystoreError, Network, NodeId, Password, Result, VaultIdentity, VaultRole};

const MAGIC: &[u8; 8] = b"THBKVLT1";
pub(crate) const FORMAT_VERSION: u16 = 1;
const SALT_BYTES: usize = 16;
const NONCE_BYTES: usize = 24;
const KEY_BYTES: usize = 32;
const TAG_BYTES: usize = 16;
const HEADER_BYTES: usize = 8 + 2 + 1 + 1 + 32 + 4 + 4 + 4 + SALT_BYTES + NONCE_BYTES + 1 + 4;
pub(crate) const MAX_VAULT_FILE_BYTES: usize = 512 * 1024;
const AAD_DOMAIN: &[u8] = b"bitcoin-thunderbolt/keystore/aad";

pub(crate) struct LoadedVault {
    pub(crate) identity: VaultIdentity,
    pub(crate) params: KdfParams,
    pub(crate) salt: [u8; SALT_BYTES],
    pub(crate) key: Zeroizing<[u8; KEY_BYTES]>,
    pub(crate) records: Records,
}

struct Header {
    version: u16,
    identity: VaultIdentity,
    params: KdfParams,
    salt: [u8; SALT_BYTES],
    nonce: [u8; NONCE_BYTES],
    bitmap: u8,
    ciphertext_length: u32,
}

struct ParsedVault<'a> {
    header: Header,
    ciphertext: &'a [u8],
}

pub(crate) fn new_salt() -> Result<[u8; SALT_BYTES]> {
    let mut salt = [0_u8; SALT_BYTES];
    getrandom::fill(&mut salt).map_err(|_| KeystoreError::RandomnessUnavailable)?;
    Ok(salt)
}

pub(crate) fn derive_key(
    password: Password,
    salt: &[u8; SALT_BYTES],
    params: KdfParams,
) -> Result<Zeroizing<[u8; KEY_BYTES]>> {
    params.validate()?;
    let argon_params = Params::new(
        params.memory_kib(),
        params.iterations(),
        params.parallelism(),
        Some(KEY_BYTES),
    )
    .map_err(|_| KeystoreError::InvalidKdfParameters)?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon_params);
    let mut key = Zeroizing::new([0_u8; KEY_BYTES]);
    argon2
        .hash_password_into(password.expose_secret(), salt, key.as_mut())
        .map_err(|_| KeystoreError::CryptographicFailure)?;
    Ok(key)
}

pub(crate) fn encode(
    identity: VaultIdentity,
    params: KdfParams,
    salt: [u8; SALT_BYTES],
    key: &[u8; KEY_BYTES],
    records: &Records,
) -> Result<Vec<u8>> {
    records.validate_role(identity.role())?;
    let plaintext = records.encode()?;
    let plaintext_length = plaintext
        .len()
        .checked_add(TAG_BYTES)
        .ok_or(KeystoreError::InvalidFormat)?;
    let ciphertext_length = u32::try_from(plaintext_length).map_err(|_| KeystoreError::InvalidFormat)?;

    let mut nonce = [0_u8; NONCE_BYTES];
    getrandom::fill(&mut nonce).map_err(|_| KeystoreError::RandomnessUnavailable)?;
    let header = Header {
        version: FORMAT_VERSION,
        identity,
        params,
        salt,
        nonce,
        bitmap: records.bitmap(),
        ciphertext_length,
    };
    let aad = build_aad(&header);
    let cipher = XChaCha20Poly1305::new_from_slice(key).map_err(|_| KeystoreError::CryptographicFailure)?;
    let nonce = XNonce::from(header.nonce);
    let ciphertext = cipher
        .encrypt(
            &nonce,
            Payload {
                msg: plaintext.as_slice(),
                aad: &aad,
            },
        )
        .map_err(|_| KeystoreError::CryptographicFailure)?;
    if ciphertext.len() != plaintext_length {
        return Err(KeystoreError::CryptographicFailure);
    }

    let total_length = HEADER_BYTES
        .checked_add(ciphertext.len())
        .ok_or(KeystoreError::InvalidFormat)?;
    if total_length > MAX_VAULT_FILE_BYTES {
        return Err(KeystoreError::InvalidSecretRecord);
    }
    let mut output = Vec::with_capacity(total_length);
    encode_header(&mut output, &header);
    output.extend_from_slice(&ciphertext);
    Ok(output)
}

pub(crate) fn decode(blob: &[u8], expected: VaultIdentity, password: Password) -> Result<LoadedVault> {
    let parsed = parse(blob)?;
    if parsed.header.identity != expected {
        return Err(KeystoreError::IdentityMismatch);
    }
    let key = derive_key(password, &parsed.header.salt, parsed.header.params)?;
    let records = decrypt_records(&parsed, &key)?;
    Ok(LoadedVault {
        identity: parsed.header.identity,
        params: parsed.header.params,
        salt: parsed.header.salt,
        key,
        records,
    })
}

fn decrypt_records(parsed: &ParsedVault<'_>, key: &[u8; KEY_BYTES]) -> Result<Records> {
    let aad = build_aad(&parsed.header);
    let cipher = XChaCha20Poly1305::new_from_slice(key).map_err(|_| KeystoreError::CryptographicFailure)?;
    let nonce = XNonce::from(parsed.header.nonce);
    let plaintext = cipher
        .decrypt(
            &nonce,
            Payload {
                msg: parsed.ciphertext,
                aad: &aad,
            },
        )
        .map_err(|_| KeystoreError::AuthenticationFailed)?;
    let plaintext = Zeroizing::new(plaintext);
    Records::decode(
        plaintext.as_slice(),
        parsed.header.bitmap,
        parsed.header.identity.role(),
    )
}

fn build_aad(header: &Header) -> Vec<u8> {
    let mut aad = Vec::with_capacity(160);
    aad.extend_from_slice(AAD_DOMAIN);
    aad.extend_from_slice(b"\0format-version\0");
    aad.extend_from_slice(&header.version.to_be_bytes());
    aad.extend_from_slice(b"\0network\0");
    aad.push(header.identity.network().tag());
    aad.extend_from_slice(b"\0role\0");
    aad.push(header.identity.role().tag());
    aad.extend_from_slice(b"\0node-identity\0");
    aad.extend_from_slice(header.identity.node_id().as_bytes());
    aad.extend_from_slice(b"\0argon2id-parameters\0");
    aad.extend_from_slice(&header.params.memory_kib().to_be_bytes());
    aad.extend_from_slice(&header.params.iterations().to_be_bytes());
    aad.extend_from_slice(&header.params.parallelism().to_be_bytes());
    aad.extend_from_slice(b"\0salt\0");
    aad.extend_from_slice(&header.salt);
    aad.extend_from_slice(b"\0nonce\0");
    aad.extend_from_slice(&header.nonce);
    aad.extend_from_slice(b"\0record-types\0");
    aad.push(header.bitmap);
    aad.extend_from_slice(b"\0ciphertext-length\0");
    aad.extend_from_slice(&header.ciphertext_length.to_be_bytes());
    aad
}

fn encode_header(output: &mut Vec<u8>, header: &Header) {
    output.extend_from_slice(MAGIC);
    output.extend_from_slice(&header.version.to_be_bytes());
    output.push(header.identity.network().tag());
    output.push(header.identity.role().tag());
    output.extend_from_slice(header.identity.node_id().as_bytes());
    output.extend_from_slice(&header.params.memory_kib().to_be_bytes());
    output.extend_from_slice(&header.params.iterations().to_be_bytes());
    output.extend_from_slice(&header.params.parallelism().to_be_bytes());
    output.extend_from_slice(&header.salt);
    output.extend_from_slice(&header.nonce);
    output.push(header.bitmap);
    output.extend_from_slice(&header.ciphertext_length.to_be_bytes());
}

fn parse(blob: &[u8]) -> Result<ParsedVault<'_>> {
    if blob.len() < HEADER_BYTES || blob.len() > MAX_VAULT_FILE_BYTES {
        return Err(KeystoreError::InvalidFormat);
    }
    let mut cursor = Cursor::new(blob);
    if cursor.take(MAGIC.len())? != MAGIC {
        return Err(KeystoreError::InvalidFormat);
    }
    let version = cursor.read_u16()?;
    if version != FORMAT_VERSION {
        return Err(KeystoreError::InvalidFormat);
    }
    let network = Network::from_tag(cursor.read_u8()?)?;
    let role = VaultRole::from_tag(cursor.read_u8()?)?;
    let node_id = NodeId::new(cursor.read_array::<32>()?);
    let params = KdfParams::new(cursor.read_u32()?, cursor.read_u32()?, cursor.read_u32()?)?;
    let salt = cursor.read_array::<SALT_BYTES>()?;
    let nonce = cursor.read_array::<NONCE_BYTES>()?;
    let bitmap = cursor.read_u8()?;
    let ciphertext_length = cursor.read_u32()?;
    let ciphertext_usize = usize::try_from(ciphertext_length).map_err(|_| KeystoreError::InvalidFormat)?;
    if ciphertext_usize < TAG_BYTES {
        return Err(KeystoreError::InvalidFormat);
    }
    let ciphertext = cursor.take(ciphertext_usize)?;
    if !cursor.is_empty() {
        return Err(KeystoreError::InvalidFormat);
    }
    Ok(ParsedVault {
        header: Header {
            version,
            identity: VaultIdentity::new(network, role, node_id),
            params,
            salt,
            nonce,
            bitmap,
            ciphertext_length,
        },
        ciphertext,
    })
}

struct Cursor<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Cursor<'a> {
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

    fn read_u16(&mut self) -> Result<u16> {
        Ok(u16::from_be_bytes(self.read_array::<2>()?))
    }

    fn read_u32(&mut self) -> Result<u32> {
        Ok(u32::from_be_bytes(self.read_array::<4>()?))
    }

    fn read_array<const N: usize>(&mut self) -> Result<[u8; N]> {
        let bytes = self.take(N)?;
        <[u8; N]>::try_from(bytes).map_err(|_| KeystoreError::InvalidFormat)
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

#[cfg(test)]
mod tests {
    use proptest::prelude::*;
    use subtle::ConstantTimeEq;

    use super::{decrypt_records, encode, parse};
    use crate::secret::Records;
    use crate::{
        BitcoinSeed, CommitteeMemberShare, CommitteeSessionNonce, HolderCredential, KdfParams, Network, NodeId,
        PaillierKeyBytes, VaultIdentity, VaultRole,
    };

    fn holder_identity() -> VaultIdentity {
        VaultIdentity::new(Network::Signet, VaultRole::Holder, NodeId::new([0x42; 32]))
    }

    fn committee_identity() -> VaultIdentity {
        VaultIdentity::new(Network::Testnet, VaultRole::CommitteeMember, NodeId::new([0x24; 32]))
    }

    fn test_params() -> KdfParams {
        KdfParams::new(crate::MIN_ARGON2_MEMORY_KIB, crate::MIN_ARGON2_ITERATIONS, 1).unwrap_or_default()
    }

    fn test_error(error: impl std::fmt::Display) -> TestCaseError {
        TestCaseError::fail(error.to_string())
    }

    fn secret_option_eq(left: Option<&[u8]>, right: Option<&[u8]>) -> bool {
        match (left, right) {
            (Some(left), Some(right)) => bool::from(left.ct_eq(right)),
            (None, None) => true,
            (Some(_), None) | (None, Some(_)) => false,
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(128))]

        #[test]
        fn aead_record_set_roundtrips(
            holder in any::<bool>(),
            seed in prop::collection::vec(any::<u8>(), 16..=64),
            paillier in prop::collection::vec(any::<u8>(), 32..=512),
            credential in prop::collection::vec(any::<u8>(), 1..=512),
            share in prop::collection::vec(any::<u8>(), 1..=512),
            nonce in any::<[u8; 32]>(),
            key in any::<[u8; 32]>(),
            salt in any::<[u8; 16]>(),
        ) {
            let (identity, records) = if holder {
                (
                    holder_identity(),
                    Records {
                        bitcoin_seed: Some(BitcoinSeed::from_bytes(seed).map_err(test_error)?),
                        paillier_key: Some(PaillierKeyBytes::from_bytes(paillier).map_err(test_error)?),
                        holder_credential: Some(HolderCredential::from_bytes(credential).map_err(test_error)?),
                        ..Records::default()
                    },
                )
            } else {
                (
                    committee_identity(),
                    Records {
                        paillier_key: Some(PaillierKeyBytes::from_bytes(paillier).map_err(test_error)?),
                        committee_share: Some(CommitteeMemberShare::from_bytes(share).map_err(test_error)?),
                        session_nonce: Some(
                            CommitteeSessionNonce::from_bytes(nonce.to_vec()).map_err(test_error)?,
                        ),
                        ..Records::default()
                    },
                )
            };

            let encoded = encode(identity, test_params(), salt, &key, &records).map_err(test_error)?;
            let parsed = parse(&encoded).map_err(test_error)?;
            let decoded = decrypt_records(&parsed, &key).map_err(test_error)?;

            prop_assert_eq!(decoded.bitmap(), records.bitmap());
            prop_assert!(secret_option_eq(
                decoded.paillier_key.as_ref().map(PaillierKeyBytes::expose_secret),
                records.paillier_key.as_ref().map(PaillierKeyBytes::expose_secret),
            ));
            prop_assert!(secret_option_eq(
                decoded.bitcoin_seed.as_ref().map(BitcoinSeed::expose_secret),
                records.bitcoin_seed.as_ref().map(BitcoinSeed::expose_secret),
            ));
            prop_assert!(secret_option_eq(
                decoded.holder_credential.as_ref().map(HolderCredential::expose_secret),
                records.holder_credential.as_ref().map(HolderCredential::expose_secret),
            ));
            prop_assert!(secret_option_eq(
                decoded.committee_share.as_ref().map(CommitteeMemberShare::expose_secret),
                records.committee_share.as_ref().map(CommitteeMemberShare::expose_secret),
            ));
            prop_assert!(secret_option_eq(
                decoded.session_nonce.as_ref().map(CommitteeSessionNonce::expose_secret),
                records.session_nonce.as_ref().map(CommitteeSessionNonce::expose_secret),
            ));
        }

        #[test]
        fn every_single_bit_file_tamper_is_rejected(
            seed in prop::collection::vec(any::<u8>(), 16..=64),
            credential in prop::collection::vec(any::<u8>(), 1..=256),
            key in any::<[u8; 32]>(),
            salt in any::<[u8; 16]>(),
            mutation_selector in any::<usize>(),
            bit in 0_u8..8,
        ) {
            let records = Records {
                bitcoin_seed: Some(BitcoinSeed::from_bytes(seed).map_err(test_error)?),
                holder_credential: Some(HolderCredential::from_bytes(credential).map_err(test_error)?),
                ..Records::default()
            };
            let mut encoded = encode(holder_identity(), test_params(), salt, &key, &records).map_err(test_error)?;
            let index = mutation_selector % encoded.len();
            let mask = 1_u8.checked_shl(u32::from(bit)).ok_or_else(|| TestCaseError::fail("invalid bit"))?;
            if let Some(byte) = encoded.get_mut(index) {
                *byte ^= mask;
            } else {
                return Err(TestCaseError::fail("mutation index outside encoded vault"));
            }

            let result = parse(&encoded).and_then(|parsed| decrypt_records(&parsed, &key));
            prop_assert!(result.is_err());
        }
    }

    #[test]
    fn fresh_nonce_changes_ciphertext() -> crate::Result<()> {
        let records = Records {
            bitcoin_seed: Some(BitcoinSeed::from_bytes(vec![7; 32])?),
            ..Records::default()
        };
        let first = encode(holder_identity(), test_params(), [9; 16], &[3; 32], &records)?;
        let second = encode(holder_identity(), test_params(), [9; 16], &[3; 32], &records)?;
        assert_ne!(first, second);
        Ok(())
    }
}
