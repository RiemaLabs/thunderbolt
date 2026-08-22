//! Encrypted local secret storage for Bitcoin Thunderbolt participants.
//!
//! A [`Vault`] belongs to exactly one [`VaultIdentity`]: a Bitcoin network, a
//! Holder or committee-member role, and a stable 32-byte node identity. That
//! complete identity and the exact record-type set are authenticated as AEAD
//! associated data, so an encrypted record cannot be moved to another role,
//! network, node, or record slot.
//!
//! The crate intentionally has no password prompt, environment-variable
//! integration, or command-line parsing. Runtime code should obtain a password
//! from an interactive or operating-system credential channel and immediately
//! move its bytes into [`Password`].

#![forbid(unsafe_code)]

mod error;
mod format;
mod fs;
mod secret;

use std::path::{Path, PathBuf};

use zeroize::Zeroizing;

pub use error::{KeystoreError, Result};
pub use secret::{BitcoinSeed, CommitteeMemberShare, CommitteeSessionNonce, HolderCredential, PaillierKeyBytes};

use crate::format::{decode, derive_key, encode, new_salt};
use crate::fs::{acquire_lock, atomic_create, atomic_replace, read_secure, FileIdentity, LockGuard};
use crate::secret::Records;

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

/// Public identity cryptographically bound to one vault.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VaultIdentity {
    network: Network,
    role: VaultRole,
    node_id: NodeId,
}

impl VaultIdentity {
    /// Constructs an identity from network, participant role, and node ID.
    #[must_use]
    pub const fn new(network: Network, role: VaultRole, node_id: NodeId) -> Self {
        Self { network, role, node_id }
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
    records: Records,
    file_identity: FileIdentity,
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
        let records = Records::default();
        let encoded = encode(identity, params, salt, &key, &records)?;
        let file_identity = atomic_create(&path, &encoded)?;
        Ok(Self {
            path,
            _lock: lock,
            identity,
            params,
            salt,
            key,
            records,
            file_identity,
        })
    }

    /// Opens, authenticates, and exclusively locks an existing vault.
    pub fn open(path: impl AsRef<Path>, expected: VaultIdentity, password: Password) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        let lock = acquire_lock(&path)?;
        let (encoded, file_identity) = read_secure(&path)?;
        let loaded = decode(&encoded, expected, password)?;
        Ok(Self {
            path,
            _lock: lock,
            identity: loaded.identity,
            params: loaded.params,
            salt: loaded.salt,
            key: loaded.key,
            records: loaded.records,
            file_identity,
        })
    }

    /// Authenticates a backup and restores it to a path that must not exist.
    pub fn restore(
        backup_path: impl AsRef<Path>,
        target_path: impl AsRef<Path>,
        expected: VaultIdentity,
        password: Password,
    ) -> Result<Self> {
        let target_path = target_path.as_ref().to_path_buf();
        let lock = acquire_lock(&target_path)?;
        let (backup, _) = read_secure(backup_path.as_ref())?;
        let loaded = decode(&backup, expected, password)?;
        let restored = encode(
            loaded.identity,
            loaded.params,
            loaded.salt,
            &loaded.key,
            &loaded.records,
        )?;
        let file_identity = atomic_create(&target_path, &restored)?;
        Ok(Self {
            path: target_path,
            _lock: lock,
            identity: loaded.identity,
            params: loaded.params,
            salt: loaded.salt,
            key: loaded.key,
            records: loaded.records,
            file_identity,
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
        let encoded = encode(self.identity, self.params, self.salt, &self.key, &self.records)?;
        atomic_create(target.as_ref(), &encoded).map(|_| ())
    }

    /// Returns the Holder wallet seed, if stored.
    #[must_use]
    pub fn bitcoin_seed(&self) -> Option<&BitcoinSeed> {
        self.records.bitcoin_seed.as_ref()
    }

    /// Atomically stores a Holder wallet seed.
    pub fn set_bitcoin_seed(&mut self, value: BitcoinSeed) -> Result<()> {
        if self.identity.role() != VaultRole::Holder {
            return Err(KeystoreError::InvalidRecordForRole);
        }
        let previous = self.records.bitcoin_seed.replace(value);
        self.persist_or_restore(previous, |records| &mut records.bitcoin_seed)
    }

    /// Atomically removes the Holder wallet seed, returning whether one existed.
    pub fn remove_bitcoin_seed(&mut self) -> Result<bool> {
        if self.identity.role() != VaultRole::Holder {
            return Err(KeystoreError::InvalidRecordForRole);
        }
        let previous = self.records.bitcoin_seed.take();
        self.persist_removal(previous, |records| &mut records.bitcoin_seed)
    }

    /// Returns serialized private Paillier material, if stored.
    #[must_use]
    pub fn paillier_key(&self) -> Option<&PaillierKeyBytes> {
        self.records.paillier_key.as_ref()
    }

    /// Atomically stores serialized private Paillier material.
    pub fn set_paillier_key(&mut self, value: PaillierKeyBytes) -> Result<()> {
        let previous = self.records.paillier_key.replace(value);
        self.persist_or_restore(previous, |records| &mut records.paillier_key)
    }

    /// Atomically removes private Paillier material, returning whether one existed.
    pub fn remove_paillier_key(&mut self) -> Result<bool> {
        let previous = self.records.paillier_key.take();
        self.persist_removal(previous, |records| &mut records.paillier_key)
    }

    /// Returns the current Holder credential, if stored.
    #[must_use]
    pub fn holder_credential(&self) -> Option<&HolderCredential> {
        self.records.holder_credential.as_ref()
    }

    /// Atomically stores the current Holder credential.
    pub fn set_holder_credential(&mut self, value: HolderCredential) -> Result<()> {
        if self.identity.role() != VaultRole::Holder {
            return Err(KeystoreError::InvalidRecordForRole);
        }
        let previous = self.records.holder_credential.replace(value);
        self.persist_or_restore(previous, |records| &mut records.holder_credential)
    }

    /// Atomically removes the Holder credential, returning whether one existed.
    pub fn remove_holder_credential(&mut self) -> Result<bool> {
        if self.identity.role() != VaultRole::Holder {
            return Err(KeystoreError::InvalidRecordForRole);
        }
        let previous = self.records.holder_credential.take();
        self.persist_removal(previous, |records| &mut records.holder_credential)
    }

    /// Returns this committee member's threshold share, if stored.
    #[must_use]
    pub fn committee_share(&self) -> Option<&CommitteeMemberShare> {
        self.records.committee_share.as_ref()
    }

    /// Atomically stores this committee member's threshold share.
    pub fn set_committee_share(&mut self, value: CommitteeMemberShare) -> Result<()> {
        if self.identity.role() != VaultRole::CommitteeMember {
            return Err(KeystoreError::InvalidRecordForRole);
        }
        let previous = self.records.committee_share.replace(value);
        self.persist_or_restore(previous, |records| &mut records.committee_share)
    }

    /// Atomically removes the committee share, returning whether one existed.
    pub fn remove_committee_share(&mut self) -> Result<bool> {
        if self.identity.role() != VaultRole::CommitteeMember {
            return Err(KeystoreError::InvalidRecordForRole);
        }
        let previous = self.records.committee_share.take();
        self.persist_removal(previous, |records| &mut records.committee_share)
    }

    /// Returns the persisted one-time committee session nonce, if stored.
    #[must_use]
    pub fn committee_session_nonce(&self) -> Option<&CommitteeSessionNonce> {
        self.records.session_nonce.as_ref()
    }

    /// Atomically stores a one-time committee session nonce before use.
    pub fn set_committee_session_nonce(&mut self, value: CommitteeSessionNonce) -> Result<()> {
        if self.identity.role() != VaultRole::CommitteeMember {
            return Err(KeystoreError::InvalidRecordForRole);
        }
        let previous = self.records.session_nonce.replace(value);
        self.persist_or_restore(previous, |records| &mut records.session_nonce)
    }

    /// Atomically removes a committee session nonce, returning whether one existed.
    pub fn remove_committee_session_nonce(&mut self) -> Result<bool> {
        if self.identity.role() != VaultRole::CommitteeMember {
            return Err(KeystoreError::InvalidRecordForRole);
        }
        let previous = self.records.session_nonce.take();
        self.persist_removal(previous, |records| &mut records.session_nonce)
    }

    fn persist(&mut self) -> Result<()> {
        let encoded = encode(self.identity, self.params, self.salt, &self.key, &self.records)?;
        self.file_identity = atomic_replace(&self.path, &encoded, self.file_identity)?;
        Ok(())
    }

    fn persist_or_restore<T>(&mut self, previous: Option<T>, field: fn(&mut Records) -> &mut Option<T>) -> Result<()> {
        if let Err(error) = self.persist() {
            let rejected = field(&mut self.records).take();
            *field(&mut self.records) = previous;
            drop(rejected);
            return Err(error);
        }
        Ok(())
    }

    fn persist_removal<T>(&mut self, previous: Option<T>, field: fn(&mut Records) -> &mut Option<T>) -> Result<bool> {
        if previous.is_none() {
            return Ok(false);
        }
        if let Err(error) = self.persist() {
            *field(&mut self.records) = previous;
            return Err(error);
        }
        Ok(true)
    }
}
