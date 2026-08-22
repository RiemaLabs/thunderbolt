use std::collections::{BTreeMap, BTreeSet};

use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::{KeystoreError, Result, VaultRole};

/// Maximum number of encrypted records in one vault.
pub const MAX_RECORDS: usize = 4_096;
/// Maximum number of committed transaction receipts retained by one vault.
pub const MAX_TRANSACTION_RECEIPTS: usize = 4_096;
/// Maximum number of records changed by one atomic transaction.
pub const MAX_TRANSACTION_MUTATIONS: usize = 256;
/// Maximum byte length of a public record key within its namespace.
pub const MAX_RECORD_KEY_BYTES: usize = 128;
/// Maximum byte length of one opaque secret record.
pub const MAX_RECORD_VALUE_BYTES: usize = 512 * 1024;
/// Maximum combined byte length of all decrypted record values.
pub const MAX_TOTAL_SECRET_BYTES: usize = 8 * 1024 * 1024;

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

        impl From<$name> for SecretValue {
            fn from(value: $name) -> Self {
                Self(value.0)
            }
        }
    };
}

opaque_secret!(
    /// BIP32/BIP39 seed material for one Holder wallet.
    BitcoinSeed,
    16,
    64
);
opaque_secret!(
    /// Serialized private Paillier key material.
    PaillierKeyBytes,
    32,
    256 * 1024
);
opaque_secret!(
    /// Serialized current-Holder ownership credential.
    HolderCredential,
    1,
    64 * 1024
);
opaque_secret!(
    /// Serialized threshold share held by one committee member.
    CommitteeMemberShare,
    1,
    64 * 1024
);
opaque_secret!(
    /// A persisted one-time committee signing-session nonce.
    CommitteeSessionNonce,
    32,
    32
);

/// Opaque secret bytes stored by a Holder or committee engine adapter.
///
/// The value intentionally implements neither `Debug`, `Clone`, nor a serde
/// trait. Its allocation is zeroized on every return path.
pub struct SecretValue(Zeroizing<Vec<u8>>);

impl SecretValue {
    /// Moves bounded, non-empty bytes into a zeroizing value.
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self> {
        let bytes = Zeroizing::new(bytes);
        if bytes.is_empty() || bytes.len() > MAX_RECORD_VALUE_BYTES {
            return Err(KeystoreError::InvalidSecretRecord);
        }
        Ok(Self(bytes))
    }

    /// Explicitly borrows the secret bytes for an engine operation.
    #[must_use]
    pub fn expose_secret(&self) -> &[u8] {
        self.0.as_slice()
    }
}

/// Typed collection containing an encrypted record.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum RecordNamespace {
    /// The Holder wallet seed collection.
    WalletSeed,
    /// Private Paillier material, keyed by key identifier or epoch.
    PaillierKey,
    /// Per-channel participant state.
    Channel,
    /// Per-invoice Holder state.
    Invoice,
    /// Holder ownership credentials, including pending and acknowledged state.
    Credential,
    /// Per-channel or per-epoch committee shares.
    CommitteeShare,
    /// Reserved or burned committee signing nonces.
    SessionNonce,
    /// Versioned private state owned by an external participant engine adapter.
    AdapterState,
}

impl RecordNamespace {
    pub(crate) const fn tag(self) -> u8 {
        match self {
            Self::WalletSeed => 1,
            Self::PaillierKey => 2,
            Self::Channel => 3,
            Self::Invoice => 4,
            Self::Credential => 5,
            Self::CommitteeShare => 6,
            Self::SessionNonce => 7,
            Self::AdapterState => 8,
        }
    }

    pub(crate) fn from_tag(tag: u8) -> Result<Self> {
        match tag {
            1 => Ok(Self::WalletSeed),
            2 => Ok(Self::PaillierKey),
            3 => Ok(Self::Channel),
            4 => Ok(Self::Invoice),
            5 => Ok(Self::Credential),
            6 => Ok(Self::CommitteeShare),
            7 => Ok(Self::SessionNonce),
            8 => Ok(Self::AdapterState),
            _ => Err(KeystoreError::InvalidFormat),
        }
    }

    pub(crate) const fn valid_for_role(self, role: VaultRole) -> bool {
        match role {
            VaultRole::Holder => !matches!(self, Self::CommitteeShare | Self::SessionNonce),
            VaultRole::CommitteeMember => !matches!(self, Self::WalletSeed | Self::Invoice | Self::Credential),
        }
    }
}

/// A bounded public key inside one typed encrypted collection.
///
/// This type intentionally omits `Debug` so identifiers cannot be emitted by
/// broad structure logging. It contains no secret value bytes.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct RecordKey {
    pub(crate) namespace: RecordNamespace,
    pub(crate) id: Vec<u8>,
}

impl RecordKey {
    /// Constructs a namespaced key from canonical public identifier bytes.
    pub fn new(namespace: RecordNamespace, id: Vec<u8>) -> Result<Self> {
        if id.is_empty() || id.len() > MAX_RECORD_KEY_BYTES {
            return Err(KeystoreError::InvalidRecordKey);
        }
        Ok(Self { namespace, id })
    }

    /// Constructs a per-channel record key.
    pub fn channel(id: Vec<u8>) -> Result<Self> {
        Self::new(RecordNamespace::Channel, id)
    }

    /// Constructs a per-invoice record key.
    pub fn invoice(id: Vec<u8>) -> Result<Self> {
        Self::new(RecordNamespace::Invoice, id)
    }

    /// Constructs a Holder credential record key.
    pub fn credential(id: Vec<u8>) -> Result<Self> {
        Self::new(RecordNamespace::Credential, id)
    }

    /// Constructs a committee signing-nonce record key.
    pub fn session_nonce(id: Vec<u8>) -> Result<Self> {
        Self::new(RecordNamespace::SessionNonce, id)
    }

    /// Returns the typed collection.
    #[must_use]
    pub const fn namespace(&self) -> RecordNamespace {
        self.namespace
    }

    /// Returns the canonical public identifier bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.id.as_slice()
    }
}

/// Authenticated revision of the complete vault state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct VaultRevision(pub(crate) u64);

impl VaultRevision {
    /// Constructs a revision for a compare-and-swap request.
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Returns the canonical integer revision.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// Authenticated revision at which one record was last changed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct RecordVersion(pub(crate) u64);

impl RecordVersion {
    /// Constructs an expected record version for compare-and-swap.
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Returns the canonical integer version.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// Authenticated state of a namespaced record key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordStatus {
    /// No live record or durable tombstone exists.
    Absent,
    /// A live secret exists at this version.
    Present(RecordVersion),
    /// A committee signing nonce was consumed at this version.
    Tombstoned(RecordVersion),
}

/// Expected state of a record in a compare-and-swap mutation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExpectedRecord {
    /// The key must not exist.
    Absent,
    /// The key must exist at exactly this authenticated version.
    Version(RecordVersion),
}

/// Stable caller-chosen identifier for an idempotent transaction.
///
/// This type intentionally omits `Debug`; applications should log their own
/// non-sensitive request correlation identifier instead.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct TransactionId(pub(crate) [u8; 32]);

impl TransactionId {
    /// Constructs an identifier from canonical bytes.
    #[must_use]
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the canonical bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Result of an idempotent vault transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommitOutcome {
    /// The mutations were durably committed at this revision.
    Applied(VaultRevision),
    /// The identifier was already durably committed at this revision.
    Replayed(VaultRevision),
}

/// Borrowed opaque record returned by a healthy open vault.
///
/// This view intentionally implements neither `Debug` nor `Clone`.
pub struct RecordView<'a> {
    version: RecordVersion,
    value: &'a SecretValue,
}

impl<'a> RecordView<'a> {
    /// Returns the authenticated record version for compare-and-swap.
    #[must_use]
    pub const fn version(&self) -> RecordVersion {
        self.version
    }

    /// Explicitly borrows the secret record bytes.
    #[must_use]
    pub fn expose_secret(&self) -> &'a [u8] {
        self.value.expose_secret()
    }
}

pub(crate) struct StoredRecord {
    pub(crate) version: RecordVersion,
    pub(crate) value: Option<SecretValue>,
}

pub(crate) struct TransactionReceipt {
    pub(crate) revision: u64,
    pub(crate) mutation_digest: [u8; 32],
}

#[derive(Default)]
pub(crate) struct RecordStore {
    pub(crate) revision: u64,
    pub(crate) records: BTreeMap<RecordKey, StoredRecord>,
    pub(crate) receipts: BTreeMap<TransactionId, TransactionReceipt>,
    pub(crate) total_value_bytes: usize,
}

impl RecordStore {
    pub(crate) fn get(&self, key: &RecordKey) -> Option<RecordView<'_>> {
        self.records.get(key).and_then(|record| {
            record.value.as_ref().map(|value| RecordView {
                version: record.version,
                value,
            })
        })
    }

    pub(crate) fn status(&self, key: &RecordKey) -> RecordStatus {
        match self.records.get(key) {
            None => RecordStatus::Absent,
            Some(record) if record.value.is_some() => RecordStatus::Present(record.version),
            Some(record) => RecordStatus::Tombstoned(record.version),
        }
    }

    pub(crate) fn receipt(&self, transaction_id: &TransactionId) -> Option<&TransactionReceipt> {
        self.receipts.get(transaction_id)
    }

    pub(crate) fn record_count(&self) -> usize {
        self.records.len()
    }

    pub(crate) fn receipt_count(&self) -> usize {
        self.receipts.len()
    }

    pub(crate) fn total_value_bytes(&self) -> usize {
        self.total_value_bytes
    }

    pub(crate) fn validate(&self, role: VaultRole) -> Result<()> {
        if self.records.len() > MAX_RECORDS
            || self.receipts.len() > MAX_TRANSACTION_RECEIPTS
            || self.total_value_bytes > MAX_TOTAL_SECRET_BYTES
        {
            return Err(KeystoreError::RecordLimitExceeded);
        }
        let mut calculated_total = 0_usize;
        for (key, record) in &self.records {
            if !key.namespace.valid_for_role(role) {
                return Err(KeystoreError::InvalidRecordForRole);
            }
            if key.id.is_empty()
                || key.id.len() > MAX_RECORD_KEY_BYTES
                || record.version.0 == 0
                || record.version.0 > self.revision
            {
                return Err(KeystoreError::InvalidFormat);
            }
            match &record.value {
                Some(value) => {
                    if value.expose_secret().is_empty() || value.expose_secret().len() > MAX_RECORD_VALUE_BYTES {
                        return Err(KeystoreError::InvalidFormat);
                    }
                    calculated_total = calculated_total
                        .checked_add(value.expose_secret().len())
                        .ok_or(KeystoreError::RecordLimitExceeded)?;
                }
                None if key.namespace != RecordNamespace::SessionNonce => {
                    return Err(KeystoreError::InvalidFormat);
                }
                None => {}
            }
        }
        if calculated_total != self.total_value_bytes {
            return Err(KeystoreError::InvalidFormat);
        }
        if self
            .receipts
            .values()
            .any(|receipt| receipt.revision == 0 || receipt.revision > self.revision)
        {
            return Err(KeystoreError::InvalidFormat);
        }
        Ok(())
    }

    pub(crate) fn insert_loaded(&mut self, key: RecordKey, record: StoredRecord) -> Result<()> {
        if let Some(value) = &record.value {
            self.total_value_bytes = self
                .total_value_bytes
                .checked_add(value.expose_secret().len())
                .ok_or(KeystoreError::RecordLimitExceeded)?;
        }
        if self.records.insert(key, record).is_some() {
            return Err(KeystoreError::InvalidFormat);
        }
        Ok(())
    }

    pub(crate) fn apply(
        &mut self,
        revision: u64,
        mutations: BTreeMap<RecordKey, StagedMutation>,
    ) -> Vec<(RecordKey, Option<StoredRecord>)> {
        let mut journal = Vec::with_capacity(mutations.len());
        for (key, mutation) in mutations {
            let previous = self.records.remove(&key);
            if let Some(value) = previous.as_ref().and_then(|record| record.value.as_ref()) {
                self.total_value_bytes -= value.expose_secret().len();
            }
            match mutation {
                StagedMutation::Put { value, .. } => {
                    self.total_value_bytes += value.expose_secret().len();
                    self.records.insert(
                        key.clone(),
                        StoredRecord {
                            version: RecordVersion(revision),
                            value: Some(value),
                        },
                    );
                }
                StagedMutation::Remove { .. } if key.namespace == RecordNamespace::SessionNonce => {
                    self.records.insert(
                        key.clone(),
                        StoredRecord {
                            version: RecordVersion(revision),
                            value: None,
                        },
                    );
                }
                StagedMutation::Remove { .. } => {}
            }
            journal.push((key, previous));
        }
        journal
    }

    pub(crate) fn rollback(&mut self, journal: Vec<(RecordKey, Option<StoredRecord>)>) {
        for (key, previous) in journal.into_iter().rev() {
            if let Some(value) = self.records.remove(&key).and_then(|record| record.value) {
                self.total_value_bytes -= value.expose_secret().len();
            }
            if let Some(record) = previous {
                if let Some(value) = &record.value {
                    self.total_value_bytes += value.expose_secret().len();
                }
                self.records.insert(key, record);
            }
        }
    }

    pub(crate) fn preflight(&self, mutations: &BTreeMap<RecordKey, StagedMutation>) -> Result<()> {
        if mutations.len() > MAX_TRANSACTION_MUTATIONS {
            return Err(KeystoreError::TransactionLimitExceeded);
        }
        let mut count = self.records.len();
        let mut total = self.total_value_bytes;
        for (key, mutation) in mutations {
            let previous = self.records.get(key);
            if let Some(value) = previous.and_then(|record| record.value.as_ref()) {
                total = total
                    .checked_sub(value.expose_secret().len())
                    .ok_or(KeystoreError::InvalidFormat)?;
            }
            if previous.is_none() && matches!(mutation, StagedMutation::Put { .. }) {
                count = count.checked_add(1).ok_or(KeystoreError::RecordLimitExceeded)?;
            }
            match mutation {
                StagedMutation::Put { value, .. } => {
                    total = total
                        .checked_add(value.expose_secret().len())
                        .ok_or(KeystoreError::RecordLimitExceeded)?;
                }
                StagedMutation::Remove { .. } if key.namespace == RecordNamespace::SessionNonce => {}
                StagedMutation::Remove { .. } => {
                    count = count.checked_sub(1).ok_or(KeystoreError::InvalidFormat)?;
                }
            }
        }
        if count > MAX_RECORDS || total > MAX_TOTAL_SECRET_BYTES {
            return Err(KeystoreError::RecordLimitExceeded);
        }
        Ok(())
    }

    pub(crate) fn validate_conflicts(&self, mutations: &BTreeMap<RecordKey, StagedMutation>) -> Result<()> {
        for (key, mutation) in mutations {
            let actual = self.records.get(key);
            if key.namespace == RecordNamespace::SessionNonce
                && matches!(mutation, StagedMutation::Put { .. })
                && actual.is_some_and(|record| record.value.is_some())
            {
                return Err(KeystoreError::NonceAlreadyReserved);
            }
            let matches = match mutation.expected() {
                ExpectedRecord::Absent => actual.is_none(),
                ExpectedRecord::Version(version) => actual.map(|record| record.version) == Some(version),
            };
            if !matches {
                return Err(KeystoreError::RecordConflict);
            }
            if key.namespace == RecordNamespace::SessionNonce && actual.is_some_and(|record| record.value.is_none()) {
                return Err(KeystoreError::NonceConsumed);
            }
        }
        Ok(())
    }

    pub(crate) fn clear_sensitive(&mut self) {
        self.records.clear();
        self.receipts.clear();
        self.total_value_bytes = 0;
    }
}

pub(crate) enum StagedMutation {
    Put {
        expected: ExpectedRecord,
        value: SecretValue,
    },
    Remove {
        expected: ExpectedRecord,
    },
}

impl StagedMutation {
    fn expected(&self) -> ExpectedRecord {
        match self {
            Self::Put { expected, .. } | Self::Remove { expected } => *expected,
        }
    }
}

/// Fenced operation over one exact authenticated vault snapshot.
///
/// Secret reads are available only inside the operation callback. Any owned
/// output returned by that callback is withheld until the local replacement and
/// external checkpoint CAS both succeed.
pub struct Transaction<'a> {
    base: &'a RecordStore,
    role: VaultRole,
    staged: BTreeMap<RecordKey, StagedMutation>,
    touched: BTreeSet<RecordKey>,
}

impl<'a> Transaction<'a> {
    pub(crate) fn new(base: &'a RecordStore, role: VaultRole) -> Self {
        Self {
            base,
            role,
            staged: BTreeMap::new(),
            touched: BTreeSet::new(),
        }
    }

    /// Reads one secret from the exact snapshot fenced by this operation.
    #[must_use]
    pub fn get(&self, key: &RecordKey) -> Option<RecordView<'_>> {
        self.base.get(key)
    }

    /// Returns whether a key is absent, live, or a consumed nonce tombstone.
    #[must_use]
    pub fn record_status(&self, key: &RecordKey) -> RecordStatus {
        self.base.status(key)
    }

    /// Returns the number of live records and nonce tombstones in this snapshot.
    #[must_use]
    pub fn record_count(&self) -> usize {
        self.base.record_count()
    }

    /// Iterates public keys in one namespace from this exact fenced snapshot.
    pub fn record_keys(&self, namespace: RecordNamespace) -> impl Iterator<Item = &RecordKey> {
        self.base.records.keys().filter(move |key| key.namespace() == namespace)
    }

    /// Stages an insert or replacement only if the current version matches.
    pub fn compare_and_swap(&mut self, key: RecordKey, expected: ExpectedRecord, value: SecretValue) -> Result<()> {
        self.check_key(&key)?;
        self.staged.insert(key, StagedMutation::Put { expected, value });
        Ok(())
    }

    /// Stages a removal only if the current authenticated version matches.
    pub fn remove(&mut self, key: RecordKey, expected: RecordVersion) -> Result<()> {
        self.check_key(&key)?;
        self.staged.insert(
            key,
            StagedMutation::Remove {
                expected: ExpectedRecord::Version(expected),
            },
        );
        Ok(())
    }

    fn check_key(&mut self, key: &RecordKey) -> Result<()> {
        if !key.namespace.valid_for_role(self.role) {
            return Err(KeystoreError::InvalidRecordForRole);
        }
        if !self.touched.insert(key.clone()) {
            return Err(KeystoreError::DuplicateMutation);
        }
        if self.touched.len() > MAX_TRANSACTION_MUTATIONS {
            return Err(KeystoreError::TransactionLimitExceeded);
        }
        Ok(())
    }

    pub(crate) fn into_mutations(self) -> BTreeMap<RecordKey, StagedMutation> {
        self.staged
    }
}

pub(crate) fn mutation_digest(mutations: &BTreeMap<RecordKey, StagedMutation>) -> Result<[u8; 32]> {
    let mut hasher = Sha256::new();
    hasher.update(b"bitcoin-thunderbolt/keystore/transaction/v1\0");
    let count = u32::try_from(mutations.len()).map_err(|_| KeystoreError::TransactionLimitExceeded)?;
    hasher.update(count.to_be_bytes());
    for (key, mutation) in mutations {
        hasher.update([key.namespace.tag()]);
        let key_length = u16::try_from(key.id.len()).map_err(|_| KeystoreError::InvalidRecordKey)?;
        hasher.update(key_length.to_be_bytes());
        hasher.update(&key.id);
        match mutation.expected() {
            ExpectedRecord::Absent => hasher.update([0]),
            ExpectedRecord::Version(version) => {
                hasher.update([1]);
                hasher.update(version.0.to_be_bytes());
            }
        }
        match mutation {
            StagedMutation::Put { value, .. } => {
                hasher.update([1]);
                let length =
                    u32::try_from(value.expose_secret().len()).map_err(|_| KeystoreError::InvalidSecretRecord)?;
                hasher.update(length.to_be_bytes());
                hasher.update(Sha256::digest(value.expose_secret()));
            }
            StagedMutation::Remove { .. } => hasher.update([2]),
        }
    }
    Ok(hasher.finalize().into())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::{
        ExpectedRecord, RecordKey, RecordNamespace, RecordStore, RecordVersion, SecretValue, StagedMutation,
        StoredRecord, MAX_RECORDS, MAX_RECORD_VALUE_BYTES,
    };
    use crate::KeystoreError;

    #[test]
    fn record_count_bound_rejects_one_more_key() -> crate::Result<()> {
        let mut store = RecordStore {
            revision: 1,
            ..RecordStore::default()
        };
        for index in 0..MAX_RECORDS {
            store.insert_loaded(
                RecordKey::new(RecordNamespace::AdapterState, index.to_be_bytes().to_vec())?,
                StoredRecord {
                    version: RecordVersion(1),
                    value: Some(SecretValue::from_bytes(vec![0x71])?),
                },
            )?;
        }
        let mut mutations = BTreeMap::new();
        mutations.insert(
            RecordKey::new(RecordNamespace::AdapterState, b"one-too-many".to_vec())?,
            StagedMutation::Put {
                expected: ExpectedRecord::Absent,
                value: SecretValue::from_bytes(vec![0x72])?,
            },
        );
        assert!(matches!(
            store.preflight(&mutations),
            Err(KeystoreError::RecordLimitExceeded)
        ));
        Ok(())
    }

    #[test]
    fn total_secret_bound_rejects_one_more_byte() -> crate::Result<()> {
        let mut store = RecordStore {
            revision: 1,
            ..RecordStore::default()
        };
        for index in 0..16_usize {
            store.insert_loaded(
                RecordKey::new(RecordNamespace::AdapterState, index.to_be_bytes().to_vec())?,
                StoredRecord {
                    version: RecordVersion(1),
                    value: Some(SecretValue::from_bytes(vec![0x73; MAX_RECORD_VALUE_BYTES])?),
                },
            )?;
        }
        let mut mutations = BTreeMap::new();
        mutations.insert(
            RecordKey::new(RecordNamespace::AdapterState, b"one-byte-over".to_vec())?,
            StagedMutation::Put {
                expected: ExpectedRecord::Absent,
                value: SecretValue::from_bytes(vec![0x74])?,
            },
        );
        assert!(matches!(
            store.preflight(&mutations),
            Err(KeystoreError::RecordLimitExceeded)
        ));
        Ok(())
    }
}
