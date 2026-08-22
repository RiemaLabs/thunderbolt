use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use zeroize::Zeroizing;

use crate::secret::{
    RecordKey, RecordNamespace, RecordStore, RecordVersion, SecretValue, StoredRecord, TransactionId,
    TransactionReceipt, MAX_RECORDS, MAX_RECORD_KEY_BYTES, MAX_RECORD_VALUE_BYTES, MAX_TRANSACTION_RECEIPTS,
};
use crate::{
    CommitteeDescriptorDigest, DeploymentBinding, DeploymentId, KdfParams, KeystoreError, Network, NodeId, Password,
    Result, VaultIdentity, VaultRole,
};

const MAGIC: &[u8; 8] = b"THBKVLT2";
pub(crate) const FORMAT_VERSION: u16 = 2;
const SALT_BYTES: usize = 16;
const NONCE_BYTES: usize = 24;
const KEY_BYTES: usize = 32;
const TAG_BYTES: usize = 16;
const HEADER_BYTES: usize = 8 + 2 + 1 + 1 + 32 + 32 + 8 + 32 + 4 + 4 + 4 + SALT_BYTES + NONCE_BYTES + 8 + 4 + 4 + 4;
pub(crate) const MAX_VAULT_FILE_BYTES: usize = 12 * 1024 * 1024;
const AAD_DOMAIN: &[u8] = b"bitcoin-thunderbolt/keystore/aad/v2";

pub(crate) struct LoadedVault {
    pub(crate) identity: VaultIdentity,
    pub(crate) params: KdfParams,
    pub(crate) salt: [u8; SALT_BYTES],
    pub(crate) key: Zeroizing<[u8; KEY_BYTES]>,
    pub(crate) store: RecordStore,
}

struct Header {
    version: u16,
    identity: VaultIdentity,
    params: KdfParams,
    salt: [u8; SALT_BYTES],
    nonce: [u8; NONCE_BYTES],
    revision: u64,
    record_count: u32,
    receipt_count: u32,
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
    store: &RecordStore,
) -> Result<Vec<u8>> {
    store.validate(identity.role())?;
    let plaintext = encode_store(store)?;
    let encrypted_length = plaintext
        .len()
        .checked_add(TAG_BYTES)
        .ok_or(KeystoreError::InvalidFormat)?;
    let ciphertext_length = u32::try_from(encrypted_length).map_err(|_| KeystoreError::InvalidFormat)?;
    let record_count = u32::try_from(store.record_count()).map_err(|_| KeystoreError::InvalidFormat)?;
    let receipt_count = u32::try_from(store.receipt_count()).map_err(|_| KeystoreError::InvalidFormat)?;

    let mut nonce = [0_u8; NONCE_BYTES];
    getrandom::fill(&mut nonce).map_err(|_| KeystoreError::RandomnessUnavailable)?;
    let header = Header {
        version: FORMAT_VERSION,
        identity,
        params,
        salt,
        nonce,
        revision: store.revision,
        record_count,
        receipt_count,
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
    if ciphertext.len() != encrypted_length {
        return Err(KeystoreError::CryptographicFailure);
    }
    let total_length = HEADER_BYTES
        .checked_add(ciphertext.len())
        .ok_or(KeystoreError::InvalidFormat)?;
    if total_length > MAX_VAULT_FILE_BYTES {
        return Err(KeystoreError::RecordLimitExceeded);
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
    let store = decrypt_store(&parsed, &key)?;
    Ok(LoadedVault {
        identity: parsed.header.identity,
        params: parsed.header.params,
        salt: parsed.header.salt,
        key,
        store,
    })
}

fn encryptable_store_header(store: &RecordStore) -> Result<(u32, u32)> {
    Ok((
        u32::try_from(store.record_count()).map_err(|_| KeystoreError::InvalidFormat)?,
        u32::try_from(store.receipt_count()).map_err(|_| KeystoreError::InvalidFormat)?,
    ))
}

fn encode_store(store: &RecordStore) -> Result<Zeroizing<Vec<u8>>> {
    let (record_count, receipt_count) = encryptable_store_header(store)?;
    let mut output = Zeroizing::new(Vec::with_capacity(
        store
            .total_value_bytes()
            .saturating_add(store.record_count().saturating_mul(64)),
    ));
    output.extend_from_slice(&record_count.to_be_bytes());
    for (key, record) in &store.records {
        output.push(key.namespace.tag());
        let key_length = u16::try_from(key.id.len()).map_err(|_| KeystoreError::InvalidRecordKey)?;
        output.extend_from_slice(&key_length.to_be_bytes());
        output.extend_from_slice(&key.id);
        output.extend_from_slice(&record.version.0.to_be_bytes());
        match &record.value {
            Some(value) => {
                output.push(1);
                let value_length =
                    u32::try_from(value.expose_secret().len()).map_err(|_| KeystoreError::InvalidSecretRecord)?;
                output.extend_from_slice(&value_length.to_be_bytes());
                output.extend_from_slice(value.expose_secret());
            }
            None => {
                output.push(2);
                output.extend_from_slice(&0_u32.to_be_bytes());
            }
        }
    }
    output.extend_from_slice(&receipt_count.to_be_bytes());
    for (transaction_id, receipt) in &store.receipts {
        output.extend_from_slice(transaction_id.as_bytes());
        output.extend_from_slice(&receipt.revision.to_be_bytes());
        output.extend_from_slice(&receipt.mutation_digest);
    }
    Ok(output)
}

fn decrypt_store(parsed: &ParsedVault<'_>, key: &[u8; KEY_BYTES]) -> Result<RecordStore> {
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
    decode_store(
        plaintext.as_slice(),
        parsed.header.identity.role(),
        parsed.header.revision,
        parsed.header.record_count,
        parsed.header.receipt_count,
    )
}

fn decode_store(
    plaintext: &[u8],
    role: VaultRole,
    revision: u64,
    authenticated_record_count: u32,
    authenticated_receipt_count: u32,
) -> Result<RecordStore> {
    let mut cursor = Cursor::new(plaintext);
    let record_count = cursor.read_u32()?;
    if record_count != authenticated_record_count
        || usize::try_from(record_count).map_err(|_| KeystoreError::InvalidFormat)? > MAX_RECORDS
    {
        return Err(KeystoreError::InvalidFormat);
    }
    let mut store = RecordStore {
        revision,
        ..RecordStore::default()
    };
    let mut previous_key: Option<RecordKey> = None;
    for _ in 0..record_count {
        let namespace = RecordNamespace::from_tag(cursor.read_u8()?)?;
        if !namespace.valid_for_role(role) {
            return Err(KeystoreError::InvalidRecordForRole);
        }
        let key_length = usize::from(cursor.read_u16()?);
        if key_length == 0 || key_length > MAX_RECORD_KEY_BYTES {
            return Err(KeystoreError::InvalidFormat);
        }
        let key = RecordKey::new(namespace, cursor.take(key_length)?.to_vec())?;
        if previous_key.as_ref().is_some_and(|previous| previous >= &key) {
            return Err(KeystoreError::InvalidFormat);
        }
        previous_key = Some(key.clone());
        let record_revision = cursor.read_u64()?;
        let state = cursor.read_u8()?;
        let value_length = usize::try_from(cursor.read_u32()?).map_err(|_| KeystoreError::InvalidFormat)?;
        let value = match state {
            1 if value_length > 0 && value_length <= MAX_RECORD_VALUE_BYTES => {
                Some(SecretValue::from_bytes(cursor.take(value_length)?.to_vec())?)
            }
            2 if value_length == 0 && namespace == RecordNamespace::SessionNonce => None,
            _ => return Err(KeystoreError::InvalidFormat),
        };
        store.insert_loaded(
            key,
            StoredRecord {
                version: RecordVersion(record_revision),
                value,
            },
        )?;
    }
    let receipt_count = cursor.read_u32()?;
    if receipt_count != authenticated_receipt_count
        || usize::try_from(receipt_count).map_err(|_| KeystoreError::InvalidFormat)? > MAX_TRANSACTION_RECEIPTS
    {
        return Err(KeystoreError::InvalidFormat);
    }
    let mut previous_id: Option<TransactionId> = None;
    for _ in 0..receipt_count {
        let transaction_id = TransactionId(cursor.read_array::<32>()?);
        if previous_id.is_some_and(|previous| previous >= transaction_id) {
            return Err(KeystoreError::InvalidFormat);
        }
        previous_id = Some(transaction_id);
        let committed_revision = cursor.read_u64()?;
        let mutation_digest = cursor.read_array::<32>()?;
        if store
            .receipts
            .insert(
                transaction_id,
                TransactionReceipt {
                    revision: committed_revision,
                    mutation_digest,
                },
            )
            .is_some()
        {
            return Err(KeystoreError::InvalidFormat);
        }
    }
    if !cursor.is_empty() {
        return Err(KeystoreError::InvalidFormat);
    }
    store.validate(role)?;
    Ok(store)
}

fn build_aad(header: &Header) -> Vec<u8> {
    let mut aad = Vec::with_capacity(224);
    aad.extend_from_slice(AAD_DOMAIN);
    aad.extend_from_slice(b"\0format-version\0");
    aad.extend_from_slice(&header.version.to_be_bytes());
    aad.extend_from_slice(b"\0network\0");
    aad.push(header.identity.network().tag());
    aad.extend_from_slice(b"\0role\0");
    aad.push(header.identity.role().tag());
    aad.extend_from_slice(b"\0node-identity\0");
    aad.extend_from_slice(header.identity.node_id().as_bytes());
    aad.extend_from_slice(b"\0deployment-identity\0");
    aad.extend_from_slice(header.identity.deployment().deployment_id().as_bytes());
    aad.extend_from_slice(b"\0committee-epoch\0");
    aad.extend_from_slice(&header.identity.deployment().committee_epoch().to_be_bytes());
    aad.extend_from_slice(b"\0committee-descriptor\0");
    aad.extend_from_slice(header.identity.deployment().committee_descriptor().as_bytes());
    aad.extend_from_slice(b"\0argon2id-parameters\0");
    aad.extend_from_slice(&header.params.memory_kib().to_be_bytes());
    aad.extend_from_slice(&header.params.iterations().to_be_bytes());
    aad.extend_from_slice(&header.params.parallelism().to_be_bytes());
    aad.extend_from_slice(b"\0salt\0");
    aad.extend_from_slice(&header.salt);
    aad.extend_from_slice(b"\0nonce\0");
    aad.extend_from_slice(&header.nonce);
    aad.extend_from_slice(b"\0revision\0");
    aad.extend_from_slice(&header.revision.to_be_bytes());
    aad.extend_from_slice(b"\0record-count\0");
    aad.extend_from_slice(&header.record_count.to_be_bytes());
    aad.extend_from_slice(b"\0receipt-count\0");
    aad.extend_from_slice(&header.receipt_count.to_be_bytes());
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
    output.extend_from_slice(header.identity.deployment().deployment_id().as_bytes());
    output.extend_from_slice(&header.identity.deployment().committee_epoch().to_be_bytes());
    output.extend_from_slice(header.identity.deployment().committee_descriptor().as_bytes());
    output.extend_from_slice(&header.params.memory_kib().to_be_bytes());
    output.extend_from_slice(&header.params.iterations().to_be_bytes());
    output.extend_from_slice(&header.params.parallelism().to_be_bytes());
    output.extend_from_slice(&header.salt);
    output.extend_from_slice(&header.nonce);
    output.extend_from_slice(&header.revision.to_be_bytes());
    output.extend_from_slice(&header.record_count.to_be_bytes());
    output.extend_from_slice(&header.receipt_count.to_be_bytes());
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
    let deployment_id = DeploymentId::new(cursor.read_array::<32>()?)?;
    let committee_epoch = cursor.read_u64()?;
    let committee_descriptor = CommitteeDescriptorDigest::new(cursor.read_array::<32>()?)?;
    let deployment = DeploymentBinding::new(deployment_id, committee_epoch, committee_descriptor)?;
    let params = KdfParams::new(cursor.read_u32()?, cursor.read_u32()?, cursor.read_u32()?)?;
    let salt = cursor.read_array::<SALT_BYTES>()?;
    let nonce = cursor.read_array::<NONCE_BYTES>()?;
    let revision = cursor.read_u64()?;
    let record_count = cursor.read_u32()?;
    let receipt_count = cursor.read_u32()?;
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
            identity: VaultIdentity::new(network, role, node_id, deployment),
            params,
            salt,
            nonce,
            revision,
            record_count,
            receipt_count,
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

    fn read_u64(&mut self) -> Result<u64> {
        Ok(u64::from_be_bytes(self.read_array::<8>()?))
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

    use super::{decode_store, encode_store};
    use crate::secret::{RecordKey, RecordNamespace, RecordStore, RecordVersion, SecretValue, StoredRecord};
    use crate::VaultRole;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]

        #[test]
        fn record_store_codec_roundtrips(
            entries in prop::collection::btree_map(
                (1_u8..=4, prop::collection::vec(any::<u8>(), 1..=32)),
                prop::collection::vec(any::<u8>(), 1..=256),
                0..64,
            )
        ) {
            let mut store = RecordStore { revision: 1, ..RecordStore::default() };
            for ((tag, id), bytes) in entries {
                let namespace = match tag {
                    1 => RecordNamespace::Channel,
                    2 => RecordNamespace::Invoice,
                    3 => RecordNamespace::Credential,
                    _ => RecordNamespace::AdapterState,
                };
                let key = RecordKey::new(namespace, id)?;
                store.insert_loaded(
                    key,
                    StoredRecord {
                        version: RecordVersion(1),
                        value: Some(SecretValue::from_bytes(bytes)?),
                    },
                )?;
            }
            let encoded = encode_store(&store)?;
            let decoded = decode_store(
                encoded.as_slice(),
                VaultRole::Holder,
                store.revision,
                u32::try_from(store.record_count()).unwrap_or_default(),
                0,
            )?;
            prop_assert_eq!(decoded.record_count(), store.record_count());
            for (key, original) in &store.records {
                let recovered = decoded.records.get(key).ok_or(TestCaseError::fail("missing decoded record"))?;
                prop_assert_eq!(recovered.version, original.version);
                let recovered_value = recovered.value.as_ref().ok_or(TestCaseError::fail("missing decoded value"))?;
                let original_value = original.value.as_ref().ok_or(TestCaseError::fail("missing original value"))?;
                prop_assert_eq!(recovered_value.expose_secret(), original_value.expose_secret());
            }
        }
    }
}
