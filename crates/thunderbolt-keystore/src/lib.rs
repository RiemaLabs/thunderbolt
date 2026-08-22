//! Encrypted local secret storage for Bitcoin Thunderbolt participants.
//!
//! A [`Vault`] belongs to exactly one [`VaultIdentity`]. Its Bitcoin network,
//! deployment, committee epoch and descriptor, participant role, and node
//! identity are authenticated as AEAD associated data. Opaque secret records
//! live in typed collections and are updated with revision-checked, atomic,
//! idempotent transactions.
//!
//! The crate intentionally has no password prompt, environment-variable
//! integration, or command-line parsing. Runtime code should obtain a password
//! from an interactive or operating-system credential channel and immediately
//! move its bytes into [`Password`].

#![forbid(unsafe_code)]

mod error;
mod fs;
mod record_format;
mod secret;

use std::path::{Path, PathBuf};
use std::{collections::BTreeMap, mem};

use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

pub use error::{KeystoreError, Result};
pub use secret::{
    BitcoinSeed, CommitOutcome, CommitteeMemberShare, CommitteeSessionNonce, ExpectedRecord, HolderCredential,
    PaillierKeyBytes, RecordKey, RecordNamespace, RecordStatus, RecordVersion, RecordView, SecretValue, Transaction,
    TransactionId, VaultRevision, MAX_RECORDS, MAX_RECORD_KEY_BYTES, MAX_RECORD_VALUE_BYTES, MAX_TOTAL_SECRET_BYTES,
    MAX_TRANSACTION_MUTATIONS, MAX_TRANSACTION_RECEIPTS,
};

use crate::fs::{acquire_lock, atomic_create, atomic_replace, read_secure, FileIdentity, LockGuard};
use crate::record_format::{decode, derive_key, encode, new_salt};
use crate::secret::{mutation_digest, RecordStore, StagedMutation, TransactionReceipt};

/// Minimum accepted Argon2id memory cost, in KiB.
pub const MIN_ARGON2_MEMORY_KIB: u32 = 19 * 1024;
/// Maximum accepted Argon2id memory cost, in KiB.
pub const MAX_ARGON2_MEMORY_KIB: u32 = 256 * 1024;
/// Minimum accepted Argon2id iteration count.
pub const MIN_ARGON2_ITERATIONS: u32 = 2;
/// Maximum accepted Argon2id iteration count.
pub const MAX_ARGON2_ITERATIONS: u32 = 10;
/// Maximum accepted Argon2id parallelism.
pub const MAX_ARGON2_PARALLELISM: u32 = 8;
/// Minimum accepted password length.
pub const MIN_PASSWORD_BYTES: usize = 12;
/// Maximum accepted password length.
pub const MAX_PASSWORD_BYTES: usize = 1024;

/// Bounded Argon2id cost parameters stored in the authenticated vault header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KdfParams {
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
}

impl KdfParams {
    /// Constructs and validates tunable Argon2id parameters.
    pub fn new(memory_kib: u32, iterations: u32, parallelism: u32) -> Result<Self> {
        let params = Self {
            memory_kib,
            iterations,
            parallelism,
        };
        params.validate()?;
        Ok(params)
    }

    /// Returns the Argon2id memory cost in KiB.
    #[must_use]
    pub const fn memory_kib(self) -> u32 {
        self.memory_kib
    }

    /// Returns the Argon2id iteration count.
    #[must_use]
    pub const fn iterations(self) -> u32 {
        self.iterations
    }

    /// Returns the Argon2id parallelism.
    #[must_use]
    pub const fn parallelism(self) -> u32 {
        self.parallelism
    }

    pub(crate) fn validate(self) -> Result<()> {
        if !(MIN_ARGON2_MEMORY_KIB..=MAX_ARGON2_MEMORY_KIB).contains(&self.memory_kib)
            || !(MIN_ARGON2_ITERATIONS..=MAX_ARGON2_ITERATIONS).contains(&self.iterations)
            || !(1..=MAX_ARGON2_PARALLELISM).contains(&self.parallelism)
            || self.memory_kib < self.parallelism.saturating_mul(8)
        {
            return Err(KeystoreError::InvalidKdfParameters);
        }
        Ok(())
    }
}

impl Default for KdfParams {
    fn default() -> Self {
        Self {
            memory_kib: 64 * 1024,
            iterations: 3,
            parallelism: 1,
        }
    }
}

/// A password buffer that is zeroized on every return path.
///
/// This type intentionally implements neither `Debug` nor `Clone`.
pub struct Password(Zeroizing<Vec<u8>>);

impl Password {
    /// Moves password bytes into a zeroizing allocation.
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self> {
        let bytes = Zeroizing::new(bytes);
        if !(MIN_PASSWORD_BYTES..=MAX_PASSWORD_BYTES).contains(&bytes.len()) {
            return Err(KeystoreError::InvalidPassword);
        }
        Ok(Self(bytes))
    }

    pub(crate) fn expose_secret(&self) -> &[u8] {
        self.0.as_slice()
    }
}

/// Bitcoin network to which a vault is cryptographically bound.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Network {
    /// Local Bitcoin Core regression-test network.
    Regtest,
    /// Public signet.
    Signet,
    /// Public Bitcoin testnet.
    Testnet,
    /// Bitcoin mainnet.
    Mainnet,
}

impl Network {
    const fn tag(self) -> u8 {
        match self {
            Self::Regtest => 1,
            Self::Signet => 2,
            Self::Testnet => 3,
            Self::Mainnet => 4,
        }
    }

    fn from_tag(tag: u8) -> Result<Self> {
        match tag {
            1 => Ok(Self::Regtest),
            2 => Ok(Self::Signet),
            3 => Ok(Self::Testnet),
            4 => Ok(Self::Mainnet),
            _ => Err(KeystoreError::InvalidFormat),
        }
    }
}

/// Secret-bearing participant role for this vault.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VaultRole {
    /// Current or prospective Holder runtime.
    Holder,
    /// One independently administered Threshold Committee member.
    CommitteeMember,
}

impl VaultRole {
    const fn tag(self) -> u8 {
        match self {
            Self::Holder => 1,
            Self::CommitteeMember => 2,
        }
    }

    fn from_tag(tag: u8) -> Result<Self> {
        match tag {
            1 => Ok(Self::Holder),
            2 => Ok(Self::CommitteeMember),
            _ => Err(KeystoreError::InvalidFormat),
        }
    }
}

/// Stable, public 32-byte identity of the owning participant process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NodeId([u8; 32]);

impl NodeId {
    /// Constructs a node identity from its canonical bytes.
    #[must_use]
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the canonical node-identity bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Stable public identifier for one Thunderbolt deployment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeploymentId([u8; 32]);

impl DeploymentId {
    /// Constructs an identifier from a canonical deployment-descriptor digest.
    pub fn new(bytes: [u8; 32]) -> Result<Self> {
        if bytes == [0_u8; 32] {
            return Err(KeystoreError::InvalidVaultIdentity);
        }
        Ok(Self(bytes))
    }

    /// Returns the canonical digest bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Digest of the canonical ordered committee descriptor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CommitteeDescriptorDigest([u8; 32]);

impl CommitteeDescriptorDigest {
    /// Constructs a digest from canonical bytes.
    pub fn new(bytes: [u8; 32]) -> Result<Self> {
        if bytes == [0_u8; 32] {
            return Err(KeystoreError::InvalidVaultIdentity);
        }
        Ok(Self(bytes))
    }

    /// Returns the canonical digest bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Public deployment and committee context bound to every vault record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeploymentBinding {
    deployment_id: DeploymentId,
    committee_epoch: u64,
    committee_descriptor: CommitteeDescriptorDigest,
}

impl DeploymentBinding {
    /// Constructs a binding. Epoch zero is reserved and rejected.
    pub fn new(
        deployment_id: DeploymentId,
        committee_epoch: u64,
        committee_descriptor: CommitteeDescriptorDigest,
    ) -> Result<Self> {
        if committee_epoch == 0 {
            return Err(KeystoreError::InvalidVaultIdentity);
        }
        Ok(Self {
            deployment_id,
            committee_epoch,
            committee_descriptor,
        })
    }

    /// Returns the deployment identifier.
    #[must_use]
    pub const fn deployment_id(self) -> DeploymentId {
        self.deployment_id
    }

    /// Returns the positive committee epoch.
    #[must_use]
    pub const fn committee_epoch(self) -> u64 {
        self.committee_epoch
    }

    /// Returns the canonical committee descriptor digest.
    #[must_use]
    pub const fn committee_descriptor(self) -> CommitteeDescriptorDigest {
        self.committee_descriptor
    }
}

/// Public identity cryptographically bound to one vault.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VaultIdentity {
    network: Network,
    role: VaultRole,
    node_id: NodeId,
    deployment: DeploymentBinding,
}

impl VaultIdentity {
    /// Constructs an identity from network, role, node, and deployment context.
    #[must_use]
    pub const fn new(network: Network, role: VaultRole, node_id: NodeId, deployment: DeploymentBinding) -> Self {
        Self {
            network,
            role,
            node_id,
            deployment,
        }
    }

    /// Returns the bound Bitcoin network.
    #[must_use]
    pub const fn network(self) -> Network {
        self.network
    }

    /// Returns the bound participant role.
    #[must_use]
    pub const fn role(self) -> VaultRole {
        self.role
    }

    /// Returns the bound public node identity.
    #[must_use]
    pub const fn node_id(self) -> NodeId {
        self.node_id
    }

    /// Returns the authenticated deployment and committee context.
    #[must_use]
    pub const fn deployment(self) -> DeploymentBinding {
        self.deployment
    }
}

/// An open, exclusively locked participant vault.
///
/// The vault and every contained record intentionally implement neither
/// `Debug` nor `Clone`.
pub struct Vault {
    path: PathBuf,
    _lock: LockGuard,
    identity: VaultIdentity,
    params: KdfParams,
    salt: [u8; 16],
    key: Zeroizing<[u8; 32]>,
    store: RecordStore,
    file_identity: FileIdentity,
    poisoned: bool,
}

impl Vault {
    /// Creates and exclusively locks a new empty vault without overwriting a path.
    pub fn create(
        path: impl AsRef<Path>,
        identity: VaultIdentity,
        password: Password,
        params: KdfParams,
    ) -> Result<Self> {
        params.validate()?;
        let path = path.as_ref().to_path_buf();
        let lock = acquire_lock(&path)?;
        let salt = new_salt()?;
        let key = derive_key(password, &salt, params)?;
        let store = RecordStore::default();
        let encoded = encode(identity, params, salt, &key, &store)?;
        let file_identity = atomic_create(&path, &encoded)?;
        Ok(Self {
            path,
            _lock: lock,
            identity,
            params,
            salt,
            key,
            store,
            file_identity,
            poisoned: false,
        })
    }

    /// Opens a Holder vault and exclusively locks it.
    ///
    /// Committee-member vaults require [`Vault::open_with_minimum_revision`]
    /// so an older authenticated file cannot silently resurrect signing state.
    pub fn open(path: impl AsRef<Path>, expected: VaultIdentity, password: Password) -> Result<Self> {
        if expected.role() == VaultRole::CommitteeMember {
            return Err(KeystoreError::RollbackFloorRequired);
        }
        Self::open_checked(path.as_ref(), expected, password, None)
    }

    /// Opens a vault only if its authenticated revision meets an external floor.
    ///
    /// A committee operator must durably advance this floor outside the vault
    /// after every nonce, share, or signing-state commit. Supplying a stale or
    /// unauthenticated floor defeats rollback protection. Committee floors must
    /// be positive so an empty bootstrap vault cannot later be treated as safe.
    pub fn open_with_minimum_revision(
        path: impl AsRef<Path>,
        expected: VaultIdentity,
        password: Password,
        minimum_revision: VaultRevision,
    ) -> Result<Self> {
        if minimum_revision.get() == 0 {
            return Err(KeystoreError::RollbackFloorRequired);
        }
        Self::open_checked(path.as_ref(), expected, password, Some(minimum_revision))
    }

    fn open_checked(
        path: &Path,
        expected: VaultIdentity,
        password: Password,
        minimum_revision: Option<VaultRevision>,
    ) -> Result<Self> {
        let path = path.to_path_buf();
        let lock = acquire_lock(&path)?;
        let (encoded, file_identity) = read_secure(&path)?;
        let loaded = decode(&encoded, expected, password)?;
        if minimum_revision.is_some_and(|floor| loaded.store.revision < floor.get()) {
            return Err(KeystoreError::RollbackDetected);
        }
        Ok(Self {
            path,
            _lock: lock,
            identity: loaded.identity,
            params: loaded.params,
            salt: loaded.salt,
            key: loaded.key,
            store: loaded.store,
            file_identity,
            poisoned: false,
        })
    }

    /// Authenticates a Holder backup at an external revision floor and restores it.
    ///
    /// Committee-member restore is deliberately forbidden: accepting an older
    /// authenticated backup could resurrect a consumed signing nonce. Committee
    /// recovery requires an external monotonic checkpoint and reconciliation,
    /// which this local keystore cannot establish by itself.
    pub fn restore(
        backup_path: impl AsRef<Path>,
        target_path: impl AsRef<Path>,
        expected: VaultIdentity,
        password: Password,
        minimum_revision: VaultRevision,
    ) -> Result<Self> {
        if expected.role() == VaultRole::CommitteeMember {
            return Err(KeystoreError::SigningStateRestoreForbidden);
        }
        let target_path = target_path.as_ref().to_path_buf();
        let lock = acquire_lock(&target_path)?;
        let (backup, _) = read_secure(backup_path.as_ref())?;
        let loaded = decode(&backup, expected, password)?;
        if loaded.store.revision < minimum_revision.get() {
            return Err(KeystoreError::RollbackDetected);
        }
        let restored = encode(loaded.identity, loaded.params, loaded.salt, &loaded.key, &loaded.store)?;
        let file_identity = atomic_create(&target_path, &restored)?;
        Ok(Self {
            path: target_path,
            _lock: lock,
            identity: loaded.identity,
            params: loaded.params,
            salt: loaded.salt,
            key: loaded.key,
            store: loaded.store,
            file_identity,
            poisoned: false,
        })
    }

    /// Returns the authenticated identity of this vault.
    #[must_use]
    pub const fn identity(&self) -> VaultIdentity {
        self.identity
    }

    /// Returns the bounded Argon2id settings encoded in this vault.
    #[must_use]
    pub const fn kdf_params(&self) -> KdfParams {
        self.params
    }

    /// Writes an authenticated, owner-only backup without overwriting a target.
    pub fn backup_to(&self, target: impl AsRef<Path>) -> Result<()> {
        self.ensure_healthy()?;
        let encoded = encode(self.identity, self.params, self.salt, &self.key, &self.store)?;
        atomic_create(target.as_ref(), &encoded).map(|_| ())
    }

    /// Returns the authenticated current vault revision.
    pub fn revision(&self) -> Result<VaultRevision> {
        self.ensure_healthy()?;
        Ok(VaultRevision::new(self.store.revision))
    }

    /// Returns the number of live records and nonce tombstones.
    pub fn record_count(&self) -> Result<usize> {
        self.ensure_healthy()?;
        Ok(self.store.record_count())
    }

    /// Returns one opaque record and its compare-and-swap version.
    pub fn get(&self, key: &RecordKey) -> Result<Option<RecordView<'_>>> {
        self.ensure_healthy()?;
        Ok(self.store.get(key))
    }

    /// Returns whether a key is absent, live, or a consumed nonce tombstone.
    pub fn record_status(&self, key: &RecordKey) -> Result<RecordStatus> {
        self.ensure_healthy()?;
        Ok(self.store.status(key))
    }

    /// Applies a bounded multi-record transaction exactly once.
    ///
    /// The callback only stages mutations. No record is changed unless every
    /// comparison succeeds and the complete encrypted vault replacement is
    /// durably committed. Exact replays return [`CommitOutcome::Replayed`]; a
    /// reused transaction identifier with different mutations fails closed.
    pub fn transact<F>(
        &mut self,
        expected_revision: VaultRevision,
        transaction_id: TransactionId,
        update: F,
    ) -> Result<CommitOutcome>
    where
        F: FnOnce(&mut Transaction) -> Result<()>,
    {
        self.ensure_healthy()?;
        let mut transaction = Transaction::new(self.identity.role());
        update(&mut transaction)?;
        let mutations = transaction.into_mutations();
        let digest = mutation_digest(&mutations)?;

        if let Some(receipt) = self.store.receipt(&transaction_id) {
            if !bool::from(receipt.mutation_digest.ct_eq(&digest)) {
                return Err(KeystoreError::TransactionReplayConflict);
            }
            return Ok(CommitOutcome::Replayed(VaultRevision::new(receipt.revision)));
        }
        if expected_revision.get() != self.store.revision {
            return Err(KeystoreError::RevisionConflict);
        }
        self.store.validate_conflicts(&mutations)?;
        self.store.preflight(&mutations)?;
        if self.store.receipt_count() >= MAX_TRANSACTION_RECEIPTS {
            return Err(KeystoreError::TransactionReceiptLimitExceeded);
        }
        let next_revision = self
            .store
            .revision
            .checked_add(1)
            .ok_or(KeystoreError::RevisionExhausted)?;
        let journal = self.store.apply(next_revision, mutations);
        let old_revision = mem::replace(&mut self.store.revision, next_revision);
        self.store.receipts.insert(
            transaction_id,
            TransactionReceipt {
                revision: next_revision,
                mutation_digest: digest,
            },
        );
        if let Err(error) = self.persist() {
            self.store.receipts.remove(&transaction_id);
            self.store.revision = old_revision;
            self.store.rollback(journal);
            self.poison();
            return Err(error);
        }
        Ok(CommitOutcome::Applied(VaultRevision::new(next_revision)))
    }

    /// Prunes idempotency receipts through an externally finalized revision.
    ///
    /// Callers must retain their own durable request history before pruning;
    /// after a receipt is removed, this vault alone can no longer recognize its
    /// transaction identifier as a replay. Nonce tombstones are never pruned.
    pub fn prune_transaction_receipts(
        &mut self,
        expected_revision: VaultRevision,
        through_revision: VaultRevision,
    ) -> Result<VaultRevision> {
        self.ensure_healthy()?;
        if expected_revision.get() != self.store.revision {
            return Err(KeystoreError::RevisionConflict);
        }
        if through_revision.get() > self.store.revision {
            return Err(KeystoreError::InvalidPruneRevision);
        }
        let keys: Vec<_> = self
            .store
            .receipts
            .iter()
            .filter_map(|(id, receipt)| (receipt.revision <= through_revision.get()).then_some(*id))
            .collect();
        if keys.is_empty() {
            return Ok(expected_revision);
        }
        let next_revision = self
            .store
            .revision
            .checked_add(1)
            .ok_or(KeystoreError::RevisionExhausted)?;
        let mut removed = BTreeMap::new();
        for key in keys {
            if let Some(receipt) = self.store.receipts.remove(&key) {
                removed.insert(key, receipt);
            }
        }
        let old_revision = mem::replace(&mut self.store.revision, next_revision);
        if let Err(error) = self.persist() {
            self.store.revision = old_revision;
            self.store.receipts.append(&mut removed);
            self.poison();
            return Err(error);
        }
        Ok(VaultRevision::new(next_revision))
    }

    /// Returns the legacy default Holder wallet-seed record, if stored.
    pub fn bitcoin_seed(&self) -> Result<Option<RecordView<'_>>> {
        self.get(&RecordKey::legacy(RecordNamespace::WalletSeed))
    }

    /// Atomically stores the legacy default Holder wallet seed.
    pub fn set_bitcoin_seed(&mut self, value: BitcoinSeed) -> Result<()> {
        self.replace_legacy(RecordKey::legacy(RecordNamespace::WalletSeed), value.into_value())
    }

    /// Atomically removes the Holder wallet seed, returning whether one existed.
    pub fn remove_bitcoin_seed(&mut self) -> Result<bool> {
        self.remove_legacy(RecordKey::legacy(RecordNamespace::WalletSeed))
    }

    /// Returns the legacy default private Paillier record, if stored.
    pub fn paillier_key(&self) -> Result<Option<RecordView<'_>>> {
        self.get(&RecordKey::legacy(RecordNamespace::PaillierKey))
    }

    /// Atomically stores serialized private Paillier material.
    pub fn set_paillier_key(&mut self, value: PaillierKeyBytes) -> Result<()> {
        self.replace_legacy(RecordKey::legacy(RecordNamespace::PaillierKey), value.into_value())
    }

    /// Atomically removes private Paillier material, returning whether one existed.
    pub fn remove_paillier_key(&mut self) -> Result<bool> {
        self.remove_legacy(RecordKey::legacy(RecordNamespace::PaillierKey))
    }

    /// Returns the current Holder credential, if stored.
    pub fn holder_credential(&self) -> Result<Option<RecordView<'_>>> {
        self.get(&RecordKey::legacy(RecordNamespace::Credential))
    }

    /// Atomically stores the current Holder credential.
    pub fn set_holder_credential(&mut self, value: HolderCredential) -> Result<()> {
        self.replace_legacy(RecordKey::legacy(RecordNamespace::Credential), value.into_value())
    }

    /// Atomically removes the Holder credential, returning whether one existed.
    pub fn remove_holder_credential(&mut self) -> Result<bool> {
        self.remove_legacy(RecordKey::legacy(RecordNamespace::Credential))
    }

    /// Returns this committee member's threshold share, if stored.
    pub fn committee_share(&self) -> Result<Option<RecordView<'_>>> {
        self.get(&RecordKey::legacy(RecordNamespace::CommitteeShare))
    }

    /// Atomically stores this committee member's threshold share.
    pub fn set_committee_share(&mut self, value: CommitteeMemberShare) -> Result<()> {
        self.replace_legacy(RecordKey::legacy(RecordNamespace::CommitteeShare), value.into_value())
    }

    /// Atomically removes the committee share, returning whether one existed.
    pub fn remove_committee_share(&mut self) -> Result<bool> {
        self.remove_legacy(RecordKey::legacy(RecordNamespace::CommitteeShare))
    }

    /// Returns the persisted one-time committee session nonce, if stored.
    pub fn committee_session_nonce(&self) -> Result<Option<RecordView<'_>>> {
        self.get(&RecordKey::legacy(RecordNamespace::SessionNonce))
    }

    /// Atomically stores a one-time committee session nonce before use.
    pub fn set_committee_session_nonce(&mut self, value: CommitteeSessionNonce) -> Result<()> {
        self.replace_legacy(RecordKey::legacy(RecordNamespace::SessionNonce), value.into_value())
    }

    /// Atomically removes a committee session nonce, returning whether one existed.
    pub fn remove_committee_session_nonce(&mut self) -> Result<bool> {
        self.remove_legacy(RecordKey::legacy(RecordNamespace::SessionNonce))
    }

    fn persist(&mut self) -> Result<()> {
        let encoded = encode(self.identity, self.params, self.salt, &self.key, &self.store)?;
        self.file_identity = atomic_replace(&self.path, &encoded, self.file_identity)?;
        Ok(())
    }

    fn replace_legacy(&mut self, key: RecordKey, value: SecretValue) -> Result<()> {
        self.ensure_healthy()?;
        if !key.namespace().valid_for_role(self.identity.role()) {
            return Err(KeystoreError::InvalidRecordForRole);
        }
        let expected = match self.store.status(&key) {
            RecordStatus::Absent => ExpectedRecord::Absent,
            RecordStatus::Present(version) | RecordStatus::Tombstoned(version) => ExpectedRecord::Version(version),
        };
        let mut mutations = BTreeMap::new();
        mutations.insert(key, StagedMutation::Put { expected, value });
        self.commit_untracked(mutations).map(|_| ())
    }

    fn remove_legacy(&mut self, key: RecordKey) -> Result<bool> {
        self.ensure_healthy()?;
        if !key.namespace().valid_for_role(self.identity.role()) {
            return Err(KeystoreError::InvalidRecordForRole);
        }
        let version = match self.store.status(&key) {
            RecordStatus::Absent | RecordStatus::Tombstoned(_) => return Ok(false),
            RecordStatus::Present(version) => version,
        };
        let mut mutations = BTreeMap::new();
        mutations.insert(
            key,
            StagedMutation::Remove {
                expected: ExpectedRecord::Version(version),
            },
        );
        self.commit_untracked(mutations)?;
        Ok(true)
    }

    fn commit_untracked(&mut self, mutations: BTreeMap<RecordKey, StagedMutation>) -> Result<VaultRevision> {
        self.store.validate_conflicts(&mutations)?;
        self.store.preflight(&mutations)?;
        let next_revision = self
            .store
            .revision
            .checked_add(1)
            .ok_or(KeystoreError::RevisionExhausted)?;
        let journal = self.store.apply(next_revision, mutations);
        let old_revision = mem::replace(&mut self.store.revision, next_revision);
        if let Err(error) = self.persist() {
            self.store.revision = old_revision;
            self.store.rollback(journal);
            self.poison();
            return Err(error);
        }
        Ok(VaultRevision::new(next_revision))
    }

    fn ensure_healthy(&self) -> Result<()> {
        if self.poisoned {
            Err(KeystoreError::Poisoned)
        } else {
            Ok(())
        }
    }

    fn poison(&mut self) {
        self.poisoned = true;
        self.store.clear_sensitive();
    }
}

#[cfg(test)]
mod poison_tests {
    use std::error::Error;

    use tempfile::TempDir;

    use super::{
        BitcoinSeed, CommitteeDescriptorDigest, DeploymentBinding, DeploymentId, ExpectedRecord, KdfParams,
        KeystoreError, Network, NodeId, Password, RecordKey, SecretValue, TransactionId, Vault, VaultIdentity,
        VaultRevision, VaultRole, MIN_ARGON2_ITERATIONS, MIN_ARGON2_MEMORY_KIB,
    };

    fn identity() -> Result<VaultIdentity, Box<dyn Error>> {
        let binding = DeploymentBinding::new(
            DeploymentId::new([0x51; 32])?,
            1,
            CommitteeDescriptorDigest::new([0x52; 32])?,
        )?;
        Ok(VaultIdentity::new(
            Network::Regtest,
            VaultRole::Holder,
            NodeId::new([0x53; 32]),
            binding,
        ))
    }

    fn password() -> super::Result<Password> {
        Password::from_bytes(b"fault injection password".to_vec())
    }

    #[test]
    fn post_rename_error_poison_requires_reopen() -> Result<(), Box<dyn Error>> {
        let directory = TempDir::new()?;
        let path = directory.path().join("poison.vault");
        let params = KdfParams::new(MIN_ARGON2_MEMORY_KIB, MIN_ARGON2_ITERATIONS, 1)?;
        let mut vault = Vault::create(&path, identity()?, password()?, params)?;

        crate::fs::inject_failure_after_rename_once();
        assert!(matches!(
            vault.set_bitcoin_seed(BitcoinSeed::from_bytes(vec![0xa7; 32])?),
            Err(KeystoreError::Io(_))
        ));
        assert!(matches!(vault.revision(), Err(KeystoreError::Poisoned)));
        assert!(matches!(vault.bitcoin_seed(), Err(KeystoreError::Poisoned)));
        assert!(matches!(
            vault.backup_to(directory.path().join("poisoned.backup")),
            Err(KeystoreError::Poisoned)
        ));
        drop(vault);

        let reopened = Vault::open(&path, identity()?, password()?)?;
        let stored = reopened.bitcoin_seed()?.ok_or("missing durably renamed record")?;
        assert_eq!(stored.expose_secret(), [0xa7; 32]);
        Ok(())
    }

    #[test]
    fn pre_rename_failure_rolls_back_complete_transaction_and_poisons() -> Result<(), Box<dyn Error>> {
        let directory = TempDir::new()?;
        let path = directory.path().join("rollback.vault");
        let params = KdfParams::new(MIN_ARGON2_MEMORY_KIB, MIN_ARGON2_ITERATIONS, 1)?;
        let first = RecordKey::channel(b"rollback-channel".to_vec())?;
        let second = RecordKey::invoice(b"rollback-invoice".to_vec())?;
        let mut vault = Vault::create(&path, identity()?, password()?, params)?;

        crate::fs::inject_failure_before_rename_once();
        assert!(matches!(
            vault.transact(VaultRevision::new(0), TransactionId::new([0xb1; 32]), |transaction| {
                transaction.compare_and_swap(
                    first.clone(),
                    ExpectedRecord::Absent,
                    SecretValue::from_bytes(vec![0xb2; 32])?,
                )?;
                transaction.compare_and_swap(
                    second.clone(),
                    ExpectedRecord::Absent,
                    SecretValue::from_bytes(vec![0xb3; 32])?,
                )
            }),
            Err(KeystoreError::Io(_))
        ));
        assert!(matches!(vault.get(&first), Err(KeystoreError::Poisoned)));
        drop(vault);

        let reopened = Vault::open(&path, identity()?, password()?)?;
        assert_eq!(reopened.revision()?, VaultRevision::new(0));
        assert!(reopened.get(&first)?.is_none());
        assert!(reopened.get(&second)?.is_none());
        Ok(())
    }
}
