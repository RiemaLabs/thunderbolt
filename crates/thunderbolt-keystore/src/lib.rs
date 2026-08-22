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

use sha2::{Digest as _, Sha256};
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
use crate::record_format::{checkpoint as checkpoint_for_blob, decode, derive_key, encode, new_salt};
use crate::secret::{mutation_digest, RecordStore, TransactionReceipt};

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
/// Maximum raw deployment identifier width accepted by the shared digest mapping.
pub const MAX_DEPLOYMENT_ID_BYTES: usize = 64;
const DEPLOYMENT_ID_DOMAIN: &[u8] = b"bitcoin-thunderbolt/keystore-deployment-id/v1";

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

    /// Derives the shared vault deployment digest from a public network and
    /// the protocol's bounded raw deployment identifier.
    ///
    /// Holder and committee adapters must use this mapping rather than
    /// role-specific hashing or direct raw-byte comparison.
    pub fn derive(network: Network, raw_deployment_id: impl AsRef<[u8]>) -> Result<Self> {
        let raw_deployment_id = raw_deployment_id.as_ref();
        if raw_deployment_id.is_empty() || raw_deployment_id.len() > MAX_DEPLOYMENT_ID_BYTES {
            return Err(KeystoreError::InvalidVaultIdentity);
        }
        let mut hasher = Sha256::new();
        hasher.update(DEPLOYMENT_ID_DOMAIN);
        hasher.update([network.tag()]);
        hasher.update((raw_deployment_id.len() as u64).to_be_bytes());
        hasher.update(raw_deployment_id);
        Self::new(hasher.finalize().into())
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

/// Public digest of one exact authenticated encrypted vault file.
///
/// The digest intentionally commits to the randomized ciphertext, not decrypted
/// values. It therefore reveals no additional plaintext and distinguishes two
/// independently written forks even when they have the same numeric revision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VaultStateDigest([u8; 32]);

impl VaultStateDigest {
    /// Constructs a digest from canonical bytes.
    #[must_use]
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the canonical digest bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Exact rollback checkpoint for one authenticated encrypted vault state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VaultCheckpoint {
    revision: VaultRevision,
    state_digest: VaultStateDigest,
}

impl VaultCheckpoint {
    /// Constructs a checkpoint from its numeric revision and exact state digest.
    #[must_use]
    pub const fn new(revision: VaultRevision, state_digest: VaultStateDigest) -> Self {
        Self { revision, state_digest }
    }

    /// Returns the authenticated numeric revision.
    #[must_use]
    pub const fn revision(self) -> VaultRevision {
        self.revision
    }

    /// Returns the exact encrypted-state digest.
    #[must_use]
    pub const fn state_digest(self) -> VaultStateDigest {
        self.state_digest
    }
}

/// Result of an atomic rollback-checkpoint compare-and-swap.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckpointCasOutcome {
    /// `expected` matched and `next` was durably installed.
    Advanced,
    /// `next` was already the exact durable checkpoint.
    AlreadyCurrent,
    /// Neither `expected` nor `next` matched the durable checkpoint.
    Conflict(Option<VaultCheckpoint>),
}

/// Failure while authenticating a recovery handle against an independent store.
#[derive(Debug)]
pub enum CheckpointAnchorError<E> {
    /// Local vault authentication or filesystem operation failed.
    Keystore(KeystoreError),
    /// The independent checkpoint backend failed.
    Store(E),
    /// The exact identity has no independently anchored checkpoint.
    Missing,
    /// The encrypted file and independently anchored checkpoint differ.
    Mismatch {
        /// Checkpoint of the authenticated encrypted file.
        actual: VaultCheckpoint,
        /// Checkpoint loaded from the independent store.
        anchored: VaultCheckpoint,
    },
}

impl<E> std::fmt::Display for CheckpointAnchorError<E>
where
    E: std::fmt::Display,
{
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Keystore(error) => error.fmt(formatter),
            Self::Store(error) => error.fmt(formatter),
            Self::Missing => formatter.write_str("vault identity has no independent checkpoint"),
            Self::Mismatch { .. } => formatter.write_str("vault does not match the independent checkpoint"),
        }
    }
}

impl<E> std::error::Error for CheckpointAnchorError<E>
where
    E: std::error::Error + 'static,
{
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Keystore(error) => Some(error),
            Self::Store(error) => Some(error),
            Self::Missing | Self::Mismatch { .. } => None,
        }
    }
}

/// Failure of a mutation that must durably update both vault and checkpoint.
#[derive(Debug)]
pub enum AnchoredMutationError<E> {
    /// Local vault validation, encryption, or filesystem operation failed.
    Keystore(KeystoreError),
    /// The independent checkpoint backend failed.
    Store {
        /// Candidate being reconciled, if the backend result was ambiguous.
        candidate: Option<VaultCheckpoint>,
        /// Backend-specific non-secret error.
        source: E,
    },
    /// The local or external checkpoint did not match the required transition.
    CheckpointConflict(Box<CheckpointConflict>),
}

/// Exact states involved in an anchored mutation checkpoint conflict.
#[derive(Debug)]
pub struct CheckpointConflict {
    /// Checkpoint required by the caller before mutation.
    pub expected: VaultCheckpoint,
    /// Candidate persisted locally, if a local write completed.
    pub candidate: Option<VaultCheckpoint>,
    /// Current independent checkpoint, if it could be loaded.
    pub current: Option<VaultCheckpoint>,
}

/// Result of a fenced transaction whose output is released only once.
pub enum AnchoredTransactOutcome<T> {
    /// A new local state and exact external checkpoint were durably committed.
    Applied {
        /// Authenticated revision of the new vault state.
        revision: VaultRevision,
        /// Owned callback output released after checkpoint anchoring.
        output: T,
    },
    /// The transaction receipt already existed; no callback output is released.
    Replayed {
        /// Revision at which the original transaction was committed.
        revision: VaultRevision,
    },
}

impl<T> std::fmt::Debug for AnchoredTransactOutcome<T> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Applied { revision, .. } => formatter
                .debug_struct("Applied")
                .field("revision", revision)
                .field("output", &"[REDACTED]")
                .finish(),
            Self::Replayed { revision } => formatter.debug_struct("Replayed").field("revision", revision).finish(),
        }
    }
}

impl<E> std::fmt::Display for AnchoredMutationError<E>
where
    E: std::fmt::Display,
{
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Keystore(error) => error.fmt(formatter),
            Self::Store { source, .. } => source.fmt(formatter),
            Self::CheckpointConflict(_) => formatter.write_str("vault checkpoint compare-and-swap conflict"),
        }
    }
}

impl<E> std::error::Error for AnchoredMutationError<E>
where
    E: std::error::Error + 'static,
{
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Keystore(error) => Some(error),
            Self::Store { source, .. } => Some(source),
            Self::CheckpointConflict(_) => None,
        }
    }
}

/// Independent checkpoint anchor used to detect authenticated vault rollback.
///
/// A production implementation must live in a trust and failure domain that is
/// independent from the vault file and its backups, such as an authenticated
/// remote ledger, HSM-backed monotonic service, or equivalent operator-owned
/// control plane. A second file beside the vault is not independent and must
/// not be used as a production floor store.
///
/// Implementations must key every operation by the complete [`VaultIdentity`]
/// tuple: network, participant role, node ID, deployment ID, positive committee
/// epoch, and exact committee-descriptor digest. The backing service must
/// authenticate that namespace so a caller cannot substitute another
/// deployment or participant identity.
///
/// `compare_and_swap_checkpoint` must be atomic. Initialization is the exact
/// transition `None -> revision 0`. Every later transition must advance by
/// exactly one revision and must match the complete expected checkpoint. An
/// exact `next` checkpoint is an idempotent success even after an ambiguous
/// backend result. Equal revisions with different digests, stale expected
/// checkpoints, skipped revisions, and regressions must return `Conflict`.
/// Success may be returned only after `next` is durable. After a backend error,
/// callers must read back and reconcile the exact checkpoint before releasing
/// any signature share, nonce commitment, credential acknowledgement, or other
/// external effect.
///
/// This crate deliberately provides no production local-file implementation.
pub trait RollbackFloorStore: Send + Sync {
    /// Backend error that never formats passwords, keys, secret records, or
    /// authentication credentials.
    type Error: std::error::Error + Send + Sync + 'static;

    /// Loads the authenticated durable checkpoint for the exact identity.
    ///
    /// `None` means the identity has not yet been provisioned in the independent
    /// store; it does not authorize an unanchored production vault open.
    fn load_checkpoint(&self, identity: VaultIdentity) -> std::result::Result<Option<VaultCheckpoint>, Self::Error>;

    /// Atomically installs the exact next checkpoint for this identity.
    ///
    /// Implementations must satisfy the atomic, idempotent, and durability
    /// contract described on [`RollbackFloorStore`].
    fn compare_and_swap_checkpoint(
        &self,
        identity: VaultIdentity,
        expected: Option<VaultCheckpoint>,
        next: VaultCheckpoint,
    ) -> std::result::Result<CheckpointCasOutcome, Self::Error>;
}

/// An open, exclusively locked participant vault.
///
/// The vault and every contained record intentionally implement neither
/// `Debug` nor `Clone`.
///
/// Secret records are intentionally unavailable outside a fenced transaction:
///
/// ```compile_fail
/// use thunderbolt_keystore::{RecordKey, Vault};
/// fn stale_reads_are_unavailable(vault: &Vault, key: &RecordKey) {
///     let _ = vault.get(key);
/// }
/// ```
pub struct Vault {
    path: PathBuf,
    _lock: LockGuard,
    identity: VaultIdentity,
    params: KdfParams,
    salt: [u8; 16],
    key: Zeroizing<[u8; 32]>,
    store: RecordStore,
    file_identity: FileIdentity,
    checkpoint: VaultCheckpoint,
    poisoned: bool,
}

/// Authenticated but not yet externally anchored vault state.
///
/// This restricted handle exposes no secret records or mutation methods. A
/// caller must first durably install its exact checkpoint in an independent
/// [`RollbackFloorStore`], then consume the handle with [`RecoveryVault::anchor`].
/// It intentionally implements neither `Debug` nor `Clone`.
///
/// ```compile_fail
/// use thunderbolt_keystore::{RecordKey, RecoveryVault};
/// fn secrets_are_unavailable(recovery: &RecoveryVault, key: &RecordKey) {
///     let _ = recovery.get(key);
/// }
/// ```
///
/// ```compile_fail
/// use thunderbolt_keystore::{RecoveryVault, TransactionId, VaultRevision};
/// fn mutations_are_unavailable(recovery: &mut RecoveryVault) {
///     let _ = recovery.transact(VaultRevision::new(0), TransactionId::new([1; 32]), |_| Ok(()));
/// }
/// ```
pub struct RecoveryVault {
    vault: Vault,
}

impl RecoveryVault {
    /// Creates and locks a new revision-zero vault without overwriting a path.
    ///
    /// The returned handle remains unusable until its checkpoint wins the
    /// external `None -> revision 0` compare-and-swap.
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
        let checkpoint = checkpoint_for_blob(&encoded, store.revision);
        let file_identity = atomic_create(&path, &encoded)?;
        Ok(Self {
            vault: Vault {
                path,
                _lock: lock,
                identity,
                params,
                salt,
                key,
                store,
                file_identity,
                checkpoint,
                poisoned: false,
            },
        })
    }

    /// Opens and authenticates a vault without exposing its secret records.
    ///
    /// Use this only for initial checkpoint provisioning or ambiguous-write
    /// reconciliation. Production work requires [`RecoveryVault::anchor`].
    pub fn open(path: impl AsRef<Path>, expected: VaultIdentity, password: Password) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        let lock = acquire_lock(&path)?;
        let (encoded, file_identity) = read_secure(&path)?;
        let loaded = decode(&encoded, expected, password)?;
        let checkpoint = checkpoint_for_blob(&encoded, loaded.store.revision);
        Ok(Self {
            vault: Vault {
                path,
                _lock: lock,
                identity: loaded.identity,
                params: loaded.params,
                salt: loaded.salt,
                key: loaded.key,
                store: loaded.store,
                file_identity,
                checkpoint,
                poisoned: false,
            },
        })
    }

    /// Returns the authenticated identity without exposing secret records.
    #[must_use]
    pub const fn identity(&self) -> VaultIdentity {
        self.vault.identity
    }

    /// Returns the exact checkpoint that must be reconciled externally.
    #[must_use]
    pub const fn checkpoint(&self) -> VaultCheckpoint {
        self.vault.checkpoint
    }

    /// Consumes this restricted handle after an independent exact-store match.
    pub fn anchor<S>(self, checkpoint_store: &S) -> std::result::Result<Vault, CheckpointAnchorError<S::Error>>
    where
        S: RollbackFloorStore,
    {
        let anchored = checkpoint_store
            .load_checkpoint(self.vault.identity)
            .map_err(CheckpointAnchorError::Store)?
            .ok_or(CheckpointAnchorError::Missing)?;
        if self.vault.checkpoint != anchored {
            return Err(CheckpointAnchorError::Mismatch {
                actual: self.vault.checkpoint,
                anchored,
            });
        }
        Ok(self.vault)
    }
}

impl Vault {
    /// Opens a production vault only at the exact externally anchored checkpoint.
    pub fn open_anchored<S>(
        path: impl AsRef<Path>,
        expected: VaultIdentity,
        password: Password,
        checkpoint_store: &S,
    ) -> std::result::Result<Self, CheckpointAnchorError<S::Error>>
    where
        S: RollbackFloorStore,
    {
        let recovery = RecoveryVault::open(path, expected, password).map_err(CheckpointAnchorError::Keystore)?;
        recovery.anchor(checkpoint_store)
    }

    /// Authenticates and restores an exact externally anchored backup.
    ///
    /// The original authenticated bytes are preserved, so a current backup has
    /// the same checkpoint as the live vault. Stale or forked backups fail before
    /// any secret record is exposed.
    pub fn restore<S>(
        backup_path: impl AsRef<Path>,
        target_path: impl AsRef<Path>,
        expected: VaultIdentity,
        password: Password,
        checkpoint_store: &S,
    ) -> std::result::Result<Self, CheckpointAnchorError<S::Error>>
    where
        S: RollbackFloorStore,
    {
        let target_path = target_path.as_ref().to_path_buf();
        let lock = acquire_lock(&target_path).map_err(CheckpointAnchorError::Keystore)?;
        let (backup, _) = read_secure(backup_path.as_ref()).map_err(CheckpointAnchorError::Keystore)?;
        let loaded = decode(&backup, expected, password).map_err(CheckpointAnchorError::Keystore)?;
        let checkpoint = checkpoint_for_blob(&backup, loaded.store.revision);
        let anchored = checkpoint_store
            .load_checkpoint(loaded.identity)
            .map_err(CheckpointAnchorError::Store)?
            .ok_or(CheckpointAnchorError::Missing)?;
        if checkpoint != anchored {
            return Err(CheckpointAnchorError::Mismatch {
                actual: checkpoint,
                anchored,
            });
        }
        let file_identity = atomic_create(&target_path, &backup).map_err(CheckpointAnchorError::Keystore)?;
        Ok(Self {
            path: target_path,
            _lock: lock,
            identity: loaded.identity,
            params: loaded.params,
            salt: loaded.salt,
            key: loaded.key,
            store: loaded.store,
            file_identity,
            checkpoint,
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
        let (encoded, current_identity) = read_secure(&self.path)?;
        if current_identity != self.file_identity
            || checkpoint_for_blob(&encoded, self.store.revision) != self.checkpoint
        {
            return Err(KeystoreError::FileReplaced);
        }
        atomic_create(target.as_ref(), &encoded).map(|_| ())
    }

    /// Returns the exact externally anchorable checkpoint of the live file.
    pub fn checkpoint(&self) -> Result<VaultCheckpoint> {
        self.ensure_healthy()?;
        Ok(self.checkpoint)
    }

    /// Returns the authenticated current vault revision.
    pub fn revision(&self) -> Result<VaultRevision> {
        self.ensure_healthy()?;
        Ok(VaultRevision::new(self.store.revision))
    }

    /// Applies and externally anchors a bounded multi-record transaction.
    ///
    /// The callback only stages mutations. No record is changed unless every
    /// comparison succeeds and the complete encrypted vault replacement is
    /// durably committed. This method returns only after the exact candidate
    /// checkpoint is durably installed or confirmed by readback in
    /// `checkpoint_store`. Any conflict after local persistence poisons the
    /// handle. Exact replays return [`AnchoredTransactOutcome::Replayed`]
    /// without a newly computed output.
    ///
    /// The callback must be locally pure: it may compute an owned return value,
    /// but it must not publish messages, signatures, acknowledgements, or other
    /// external effects itself. Its owned `'static` output is withheld and
    /// dropped on failure, and is returned only after the external checkpoint is
    /// durably advanced. Even an operation that stages no record mutations
    /// writes an idempotency receipt and advances the checkpoint before returning.
    pub fn transact<S, F, T>(
        &mut self,
        expected: VaultCheckpoint,
        transaction_id: TransactionId,
        checkpoint_store: &S,
        update: F,
    ) -> std::result::Result<AnchoredTransactOutcome<T>, AnchoredMutationError<S::Error>>
    where
        S: RollbackFloorStore,
        F: FnOnce(&mut Transaction<'_>) -> Result<T>,
        T: 'static,
    {
        self.verify_anchor(expected, checkpoint_store)?;
        match self.transact_local(expected.revision(), transaction_id, update) {
            Ok(AnchoredTransactOutcome::Replayed { revision }) => Ok(AnchoredTransactOutcome::Replayed { revision }),
            Ok(AnchoredTransactOutcome::Applied { revision, output }) => {
                let candidate = self.checkpoint;
                self.anchor_candidate(expected, candidate, checkpoint_store)?;
                Ok(AnchoredTransactOutcome::Applied { revision, output })
            }
            Err(error) => {
                if let KeystoreError::AmbiguousWrite { candidate, .. } = &error {
                    self.reconcile_ambiguous_write(expected, *candidate, checkpoint_store)?;
                }
                Err(AnchoredMutationError::Keystore(error))
            }
        }
    }

    fn transact_local<F, T>(
        &mut self,
        expected_revision: VaultRevision,
        transaction_id: TransactionId,
        update: F,
    ) -> Result<AnchoredTransactOutcome<T>>
    where
        F: FnOnce(&mut Transaction<'_>) -> Result<T>,
        T: 'static,
    {
        self.ensure_healthy()?;
        let mut transaction = Transaction::new(&self.store, self.identity.role());
        let output = update(&mut transaction)?;
        let mutations = transaction.into_mutations();
        let digest = mutation_digest(&mutations)?;

        if let Some(receipt) = self.store.receipt(&transaction_id) {
            if !bool::from(receipt.mutation_digest.ct_eq(&digest)) {
                return Err(KeystoreError::TransactionReplayConflict);
            }
            drop(output);
            return Ok(AnchoredTransactOutcome::Replayed {
                revision: VaultRevision::new(receipt.revision),
            });
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
            if matches!(&error, KeystoreError::AmbiguousWrite { .. }) {
                self.poison();
            }
            return Err(error);
        }
        Ok(AnchoredTransactOutcome::Applied {
            revision: VaultRevision::new(next_revision),
            output,
        })
    }

    /// Prunes finalized idempotency receipts and anchors the resulting state.
    ///
    /// Callers must retain their own durable request history before pruning;
    /// after a receipt is removed, this vault alone can no longer recognize its
    /// transaction identifier as a replay. Nonce tombstones are never pruned.
    pub fn prune_transaction_receipts<S>(
        &mut self,
        expected: VaultCheckpoint,
        through_revision: VaultRevision,
        checkpoint_store: &S,
    ) -> std::result::Result<VaultCheckpoint, AnchoredMutationError<S::Error>>
    where
        S: RollbackFloorStore,
    {
        self.verify_anchor(expected, checkpoint_store)?;
        match self.prune_transaction_receipts_local(expected.revision(), through_revision) {
            Ok(revision) if revision == expected.revision() => Ok(expected),
            Ok(_) => {
                let candidate = self.checkpoint;
                self.anchor_candidate(expected, candidate, checkpoint_store)?;
                Ok(candidate)
            }
            Err(error) => {
                if let KeystoreError::AmbiguousWrite { candidate, .. } = &error {
                    self.reconcile_ambiguous_write(expected, *candidate, checkpoint_store)?;
                }
                Err(AnchoredMutationError::Keystore(error))
            }
        }
    }

    fn prune_transaction_receipts_local(
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
            if matches!(&error, KeystoreError::AmbiguousWrite { .. }) {
                self.poison();
            }
            return Err(error);
        }
        Ok(VaultRevision::new(next_revision))
    }

    fn persist(&mut self) -> Result<()> {
        let encoded = encode(self.identity, self.params, self.salt, &self.key, &self.store)?;
        let candidate = checkpoint_for_blob(&encoded, self.store.revision);
        self.file_identity = atomic_replace(&self.path, &encoded, self.file_identity).map_err(|source| {
            KeystoreError::AmbiguousWrite {
                candidate,
                source: Box::new(source),
            }
        })?;
        self.checkpoint = candidate;
        Ok(())
    }

    fn verify_anchor<S>(
        &mut self,
        expected: VaultCheckpoint,
        checkpoint_store: &S,
    ) -> std::result::Result<(), AnchoredMutationError<S::Error>>
    where
        S: RollbackFloorStore,
    {
        self.ensure_healthy().map_err(AnchoredMutationError::Keystore)?;
        if self.checkpoint != expected {
            return Err(AnchoredMutationError::CheckpointConflict(Box::new(
                CheckpointConflict {
                    expected,
                    candidate: None,
                    current: Some(self.checkpoint),
                },
            )));
        }
        let current =
            checkpoint_store
                .load_checkpoint(self.identity)
                .map_err(|source| AnchoredMutationError::Store {
                    candidate: None,
                    source,
                })?;
        if current != Some(expected) {
            self.poison();
            return Err(AnchoredMutationError::CheckpointConflict(Box::new(
                CheckpointConflict {
                    expected,
                    candidate: None,
                    current,
                },
            )));
        }
        Ok(())
    }

    fn anchor_candidate<S>(
        &mut self,
        expected: VaultCheckpoint,
        candidate: VaultCheckpoint,
        checkpoint_store: &S,
    ) -> std::result::Result<(), AnchoredMutationError<S::Error>>
    where
        S: RollbackFloorStore,
    {
        match checkpoint_store.compare_and_swap_checkpoint(self.identity, Some(expected), candidate) {
            Ok(CheckpointCasOutcome::Advanced | CheckpointCasOutcome::AlreadyCurrent) => Ok(()),
            Ok(CheckpointCasOutcome::Conflict(current)) if current == Some(candidate) => Ok(()),
            Ok(CheckpointCasOutcome::Conflict(current)) => {
                self.poison();
                Err(AnchoredMutationError::CheckpointConflict(Box::new(
                    CheckpointConflict {
                        expected,
                        candidate: Some(candidate),
                        current,
                    },
                )))
            }
            Err(source) => match checkpoint_store.load_checkpoint(self.identity) {
                Ok(Some(current)) if current == candidate => Ok(()),
                Ok(current) => {
                    self.poison();
                    Err(AnchoredMutationError::CheckpointConflict(Box::new(
                        CheckpointConflict {
                            expected,
                            candidate: Some(candidate),
                            current,
                        },
                    )))
                }
                Err(_) => {
                    self.poison();
                    Err(AnchoredMutationError::Store {
                        candidate: Some(candidate),
                        source,
                    })
                }
            },
        }
    }

    fn reconcile_ambiguous_write<S>(
        &mut self,
        expected: VaultCheckpoint,
        candidate: VaultCheckpoint,
        checkpoint_store: &S,
    ) -> std::result::Result<(), AnchoredMutationError<S::Error>>
    where
        S: RollbackFloorStore,
    {
        let (encoded, _) = read_secure(&self.path).map_err(AnchoredMutationError::Keystore)?;
        let candidate_on_disk = checkpoint_for_blob(&encoded, candidate.revision().get());
        if candidate_on_disk == candidate {
            return self.anchor_candidate(expected, candidate, checkpoint_store);
        }
        let prior_on_disk = checkpoint_for_blob(&encoded, expected.revision().get());
        if prior_on_disk == expected {
            return Ok(());
        }
        self.poison();
        Err(AnchoredMutationError::CheckpointConflict(Box::new(
            CheckpointConflict {
                expected,
                candidate: Some(candidate),
                current: None,
            },
        )))
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
    use std::convert::Infallible;
    use std::error::Error;

    use tempfile::TempDir;

    use super::{
        CheckpointCasOutcome, CommitteeDescriptorDigest, DeploymentBinding, DeploymentId, ExpectedRecord, KdfParams,
        KeystoreError, Network, NodeId, Password, RecordKey, RecordNamespace, RecoveryVault, RollbackFloorStore,
        SecretValue, TransactionId, Vault, VaultCheckpoint, VaultIdentity, VaultRevision, VaultRole,
        MIN_ARGON2_ITERATIONS, MIN_ARGON2_MEMORY_KIB,
    };

    struct ExactCheckpointStore {
        identity: VaultIdentity,
        checkpoint: VaultCheckpoint,
    }

    impl RollbackFloorStore for ExactCheckpointStore {
        type Error = Infallible;

        fn load_checkpoint(&self, identity: VaultIdentity) -> Result<Option<VaultCheckpoint>, Self::Error> {
            Ok((identity == self.identity).then_some(self.checkpoint))
        }

        fn compare_and_swap_checkpoint(
            &self,
            _identity: VaultIdentity,
            _expected: Option<VaultCheckpoint>,
            _next: VaultCheckpoint,
        ) -> Result<CheckpointCasOutcome, Self::Error> {
            Ok(CheckpointCasOutcome::Conflict(Some(self.checkpoint)))
        }
    }

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

    fn create_vault(
        path: &std::path::Path,
        identity: VaultIdentity,
        password: Password,
        params: KdfParams,
    ) -> super::Result<Vault> {
        let recovery = RecoveryVault::create(path, identity, password, params)?;
        let checkpoint = recovery.checkpoint();
        let checkpoint_store = ExactCheckpointStore { identity, checkpoint };
        recovery
            .anchor(&checkpoint_store)
            .map_err(|_| KeystoreError::CheckpointMismatch)
    }

    fn ambiguous_candidate(error: KeystoreError) -> Result<VaultCheckpoint, Box<dyn Error>> {
        match error {
            KeystoreError::AmbiguousWrite { candidate, .. } => Ok(candidate),
            other => Err(format!("expected ambiguous write, got {other}").into()),
        }
    }

    #[test]
    fn post_rename_error_poison_requires_reopen() -> Result<(), Box<dyn Error>> {
        let directory = TempDir::new()?;
        let path = directory.path().join("poison.vault");
        let params = KdfParams::new(MIN_ARGON2_MEMORY_KIB, MIN_ARGON2_ITERATIONS, 1)?;
        let mut vault = create_vault(&path, identity()?, password()?, params)?;

        crate::fs::inject_failure_after_rename_once();
        let key = RecordKey::new(RecordNamespace::WalletSeed, b"default".to_vec())?;
        let error = vault
            .transact_local(VaultRevision::new(0), TransactionId::new([0xa6; 32]), |transaction| {
                transaction.compare_and_swap(key, ExpectedRecord::Absent, SecretValue::from_bytes(vec![0xa7; 32])?)
            })
            .expect_err("injected post-rename failure must be returned");
        let candidate = ambiguous_candidate(error)?;
        assert!(matches!(vault.revision(), Err(KeystoreError::Poisoned)));
        assert!(matches!(vault.ensure_healthy(), Err(KeystoreError::Poisoned)));
        assert!(matches!(
            vault.backup_to(directory.path().join("poisoned.backup")),
            Err(KeystoreError::Poisoned)
        ));
        drop(vault);

        let recovery = RecoveryVault::open(&path, identity()?, password()?)?;
        assert_eq!(recovery.checkpoint(), candidate);
        let checkpoint_store = ExactCheckpointStore {
            identity: identity()?,
            checkpoint: candidate,
        };
        let reopened = recovery.anchor(&checkpoint_store)?;
        let key = RecordKey::new(RecordNamespace::WalletSeed, b"default".to_vec())?;
        let stored = reopened.store.get(&key).ok_or("missing durably renamed record")?;
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
        let mut vault = create_vault(&path, identity()?, password()?, params)?;
        let prior = vault.checkpoint()?;

        crate::fs::inject_failure_before_rename_once();
        let error = vault
            .transact_local(VaultRevision::new(0), TransactionId::new([0xb1; 32]), |transaction| {
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
            })
            .expect_err("injected pre-rename failure must be returned");
        let candidate = ambiguous_candidate(error)?;
        assert_ne!(candidate, prior);
        assert!(matches!(vault.ensure_healthy(), Err(KeystoreError::Poisoned)));
        drop(vault);

        let recovery = RecoveryVault::open(&path, identity()?, password()?)?;
        assert_eq!(recovery.checkpoint(), prior);
        assert_ne!(recovery.checkpoint(), candidate);
        let checkpoint_store = ExactCheckpointStore {
            identity: identity()?,
            checkpoint: prior,
        };
        let reopened = recovery.anchor(&checkpoint_store)?;
        assert_eq!(reopened.revision()?, VaultRevision::new(0));
        assert!(reopened.store.get(&first).is_none());
        assert!(reopened.store.get(&second).is_none());
        Ok(())
    }
}
