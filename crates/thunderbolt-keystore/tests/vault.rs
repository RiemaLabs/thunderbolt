use std::convert::Infallible;
use std::error::Error;
use std::fs;
use std::ops::{Deref, DerefMut};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use static_assertions::assert_not_impl_any;
use subtle::ConstantTimeEq;
use tempfile::TempDir;
use thunderbolt_keystore::{
    AnchoredTransactOutcome, BitcoinSeed, CheckpointAnchorError, CheckpointCasOutcome, CommitOutcome,
    CommitteeDescriptorDigest, CommitteeMemberShare, CommitteeSessionNonce, DeploymentBinding, DeploymentId,
    ExpectedRecord, HolderCredential, KdfParams, KeystoreError, Network, NodeId, PaillierKeyBytes, Password, RecordKey,
    RecordNamespace, RecordStatus, RecoveryVault, RollbackFloorStore, SecretValue, TransactionId, Vault,
    VaultCheckpoint, VaultIdentity, VaultRevision, VaultRole, MAX_RECORD_KEY_BYTES, MAX_RECORD_VALUE_BYTES,
    MAX_TRANSACTION_MUTATIONS, MIN_ARGON2_ITERATIONS, MIN_ARGON2_MEMORY_KIB,
};

#[cfg(unix)]
use std::os::unix::fs::{symlink, PermissionsExt};

assert_not_impl_any!(Password: Clone, std::fmt::Debug);
assert_not_impl_any!(BitcoinSeed: Clone, std::fmt::Debug);
assert_not_impl_any!(PaillierKeyBytes: Clone, std::fmt::Debug);
assert_not_impl_any!(HolderCredential: Clone, std::fmt::Debug);
assert_not_impl_any!(CommitteeMemberShare: Clone, std::fmt::Debug);
assert_not_impl_any!(CommitteeSessionNonce: Clone, std::fmt::Debug);
assert_not_impl_any!(SecretValue: Clone, std::fmt::Debug);
assert_not_impl_any!(RecordKey: std::fmt::Debug);
assert_not_impl_any!(TransactionId: std::fmt::Debug);
assert_not_impl_any!(Vault: Clone, std::fmt::Debug);
assert_not_impl_any!(RecoveryVault: Clone, std::fmt::Debug);

#[derive(Clone)]
struct TestCheckpointStore {
    identity: VaultIdentity,
    checkpoint: Arc<Mutex<Option<VaultCheckpoint>>>,
}

impl TestCheckpointStore {
    fn anchored(identity: VaultIdentity, checkpoint: VaultCheckpoint) -> Self {
        Self {
            identity,
            checkpoint: Arc::new(Mutex::new(Some(checkpoint))),
        }
    }
}

impl RollbackFloorStore for TestCheckpointStore {
    type Error = Infallible;

    fn load_checkpoint(&self, identity: VaultIdentity) -> Result<Option<VaultCheckpoint>, Self::Error> {
        if identity != self.identity {
            return Ok(None);
        }
        Ok(*self.checkpoint.lock().expect("test checkpoint lock"))
    }

    fn compare_and_swap_checkpoint(
        &self,
        identity: VaultIdentity,
        expected: Option<VaultCheckpoint>,
        next: VaultCheckpoint,
    ) -> Result<CheckpointCasOutcome, Self::Error> {
        if identity != self.identity {
            return Ok(CheckpointCasOutcome::Conflict(None));
        }
        let mut current = self.checkpoint.lock().expect("test checkpoint lock");
        if *current == Some(next) {
            return Ok(CheckpointCasOutcome::AlreadyCurrent);
        }
        let valid_next = match expected {
            None => next.revision() == VaultRevision::new(0),
            Some(previous) => previous
                .revision()
                .get()
                .checked_add(1)
                .is_some_and(|revision| next.revision() == VaultRevision::new(revision)),
        };
        if *current != expected || !valid_next {
            return Ok(CheckpointCasOutcome::Conflict(*current));
        }
        *current = Some(next);
        Ok(CheckpointCasOutcome::Advanced)
    }
}

struct TestVault {
    vault: Vault,
    checkpoint_store: TestCheckpointStore,
    next_transaction: u64,
}

struct TestRecord {
    version: thunderbolt_keystore::RecordVersion,
    bytes: Vec<u8>,
}

impl TestRecord {
    fn version(&self) -> thunderbolt_keystore::RecordVersion {
        self.version
    }

    fn expose_secret(&self) -> &[u8] {
        &self.bytes
    }
}

impl Deref for TestVault {
    type Target = Vault;

    fn deref(&self) -> &Self::Target {
        &self.vault
    }
}

impl DerefMut for TestVault {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.vault
    }
}

impl TestVault {
    fn new(vault: Vault, checkpoint_store: TestCheckpointStore) -> thunderbolt_keystore::Result<Self> {
        let next_transaction = vault.revision()?.get().saturating_add(1).saturating_mul(1_000_000);
        Ok(Self {
            vault,
            checkpoint_store,
            next_transaction,
        })
    }

    fn transact<F>(
        &mut self,
        expected_revision: VaultRevision,
        transaction_id: TransactionId,
        update: F,
    ) -> thunderbolt_keystore::Result<CommitOutcome>
    where
        F: FnOnce(&mut thunderbolt_keystore::Transaction) -> thunderbolt_keystore::Result<()>,
    {
        let expected = self.vault.checkpoint()?;
        if expected.revision() != expected_revision {
            return Err(KeystoreError::RevisionConflict);
        }
        self.vault
            .transact(expected, transaction_id, &self.checkpoint_store, update)
            .map(|outcome| match outcome {
                AnchoredTransactOutcome::Applied { revision, output: () } => CommitOutcome::Applied(revision),
                AnchoredTransactOutcome::Replayed { revision } => CommitOutcome::Replayed(revision),
            })
            .map_err(map_mutation_error)
    }

    fn set_record(&mut self, namespace: RecordNamespace, value: SecretValue) -> thunderbolt_keystore::Result<()> {
        let key = RecordKey::new(namespace, b"default".to_vec())?;
        let expected_record = match self.record_status(&key)? {
            RecordStatus::Absent => ExpectedRecord::Absent,
            RecordStatus::Present(version) | RecordStatus::Tombstoned(version) => ExpectedRecord::Version(version),
        };
        let transaction_id = self.next_transaction_id();
        self.transact(self.vault.revision()?, transaction_id, |transaction| {
            transaction.compare_and_swap(key, expected_record, value)
        })?;
        Ok(())
    }

    fn remove_record(&mut self, namespace: RecordNamespace) -> thunderbolt_keystore::Result<bool> {
        let key = RecordKey::new(namespace, b"default".to_vec())?;
        let version = match self.record_status(&key)? {
            RecordStatus::Absent | RecordStatus::Tombstoned(_) => return Ok(false),
            RecordStatus::Present(version) => version,
        };
        let transaction_id = self.next_transaction_id();
        self.transact(self.vault.revision()?, transaction_id, |transaction| {
            transaction.remove(key, version)
        })?;
        Ok(true)
    }

    fn next_transaction_id(&mut self) -> TransactionId {
        self.next_transaction = self.next_transaction.saturating_add(1);
        let mut bytes = [0xf1; 32];
        bytes[24..].copy_from_slice(&self.next_transaction.to_be_bytes());
        TransactionId::new(bytes)
    }

    fn set_bitcoin_seed(&mut self, value: BitcoinSeed) -> thunderbolt_keystore::Result<()> {
        self.set_record(RecordNamespace::WalletSeed, value.into())
    }

    fn set_paillier_key(&mut self, value: PaillierKeyBytes) -> thunderbolt_keystore::Result<()> {
        self.set_record(RecordNamespace::PaillierKey, value.into())
    }

    fn set_holder_credential(&mut self, value: HolderCredential) -> thunderbolt_keystore::Result<()> {
        self.set_record(RecordNamespace::Credential, value.into())
    }

    fn remove_holder_credential(&mut self) -> thunderbolt_keystore::Result<bool> {
        self.remove_record(RecordNamespace::Credential)
    }

    fn set_committee_share(&mut self, value: CommitteeMemberShare) -> thunderbolt_keystore::Result<()> {
        self.set_record(RecordNamespace::CommitteeShare, value.into())
    }

    fn set_committee_session_nonce(&mut self, value: CommitteeSessionNonce) -> thunderbolt_keystore::Result<()> {
        self.set_record(RecordNamespace::SessionNonce, value.into())
    }

    fn prune_transaction_receipts(
        &mut self,
        expected_revision: VaultRevision,
        through_revision: VaultRevision,
    ) -> thunderbolt_keystore::Result<VaultCheckpoint> {
        let expected = self.vault.checkpoint()?;
        if expected.revision() != expected_revision {
            return Err(KeystoreError::RevisionConflict);
        }
        self.vault
            .prune_transaction_receipts(expected, through_revision, &self.checkpoint_store)
            .map_err(map_mutation_error)
    }

    fn read_record(&mut self, key: RecordKey) -> thunderbolt_keystore::Result<Option<TestRecord>> {
        let expected = self.vault.checkpoint()?;
        let transaction_id = self.next_transaction_id();
        self.vault
            .transact(expected, transaction_id, &self.checkpoint_store, |transaction| {
                Ok(transaction.get(&key).map(|record| TestRecord {
                    version: record.version(),
                    bytes: record.expose_secret().to_vec(),
                }))
            })
            .map_err(map_mutation_error)
            .and_then(take_applied_output)
    }

    fn get(&mut self, key: &RecordKey) -> thunderbolt_keystore::Result<Option<TestRecord>> {
        self.read_record(key.clone())
    }

    fn record_status(&mut self, key: &RecordKey) -> thunderbolt_keystore::Result<RecordStatus> {
        let expected = self.vault.checkpoint()?;
        let transaction_id = self.next_transaction_id();
        self.vault
            .transact(expected, transaction_id, &self.checkpoint_store, |transaction| {
                Ok(transaction.record_status(key))
            })
            .map_err(map_mutation_error)
            .and_then(take_applied_output)
    }

    fn bitcoin_seed(&mut self) -> thunderbolt_keystore::Result<Option<TestRecord>> {
        self.read_record(RecordKey::new(RecordNamespace::WalletSeed, b"default".to_vec())?)
    }

    fn paillier_key(&mut self) -> thunderbolt_keystore::Result<Option<TestRecord>> {
        self.read_record(RecordKey::new(RecordNamespace::PaillierKey, b"default".to_vec())?)
    }

    fn holder_credential(&mut self) -> thunderbolt_keystore::Result<Option<TestRecord>> {
        self.read_record(RecordKey::new(RecordNamespace::Credential, b"default".to_vec())?)
    }

    fn committee_share(&mut self) -> thunderbolt_keystore::Result<Option<TestRecord>> {
        self.read_record(RecordKey::new(RecordNamespace::CommitteeShare, b"default".to_vec())?)
    }

    fn committee_session_nonce(&mut self) -> thunderbolt_keystore::Result<Option<TestRecord>> {
        self.read_record(RecordKey::new(RecordNamespace::SessionNonce, b"default".to_vec())?)
    }

    fn record_count(&mut self) -> thunderbolt_keystore::Result<usize> {
        let expected = self.vault.checkpoint()?;
        let transaction_id = self.next_transaction_id();
        self.vault
            .transact(expected, transaction_id, &self.checkpoint_store, |transaction| {
                Ok(transaction.record_count())
            })
            .map_err(map_mutation_error)
            .and_then(take_applied_output)
    }
}

fn map_mutation_error(error: thunderbolt_keystore::AnchoredMutationError<Infallible>) -> KeystoreError {
    match error {
        thunderbolt_keystore::AnchoredMutationError::Keystore(error) => error,
        thunderbolt_keystore::AnchoredMutationError::Store { source, .. } => match source {},
        thunderbolt_keystore::AnchoredMutationError::CheckpointConflict(_) => KeystoreError::CheckpointMismatch,
    }
}

fn take_applied_output<T>(outcome: AnchoredTransactOutcome<T>) -> thunderbolt_keystore::Result<T> {
    match outcome {
        AnchoredTransactOutcome::Applied { output, .. } => Ok(output),
        AnchoredTransactOutcome::Replayed { .. } => Err(KeystoreError::TransactionReplayConflict),
    }
}

fn password() -> thunderbolt_keystore::Result<Password> {
    Password::from_bytes(b"correct horse battery staple".to_vec())
}

fn wrong_password() -> thunderbolt_keystore::Result<Password> {
    Password::from_bytes(b"this is the wrong password".to_vec())
}

fn params() -> thunderbolt_keystore::Result<KdfParams> {
    KdfParams::new(MIN_ARGON2_MEMORY_KIB, MIN_ARGON2_ITERATIONS, 1)
}

fn deployment() -> DeploymentBinding {
    DeploymentBinding::new(
        DeploymentId::new([0x33; 32]).expect("nonzero deployment id"),
        7,
        CommitteeDescriptorDigest::new([0x44; 32]).expect("nonzero committee descriptor"),
    )
    .expect("valid test deployment")
}

fn holder_identity() -> VaultIdentity {
    VaultIdentity::new(
        Network::Regtest,
        VaultRole::Holder,
        NodeId::new([0x11; 32]),
        deployment(),
    )
}

fn committee_identity() -> VaultIdentity {
    VaultIdentity::new(
        Network::Regtest,
        VaultRole::CommitteeMember,
        NodeId::new([0x22; 32]),
        deployment(),
    )
}

fn vault_path(directory: &TempDir) -> PathBuf {
    directory.path().join("participant.vault")
}

fn create_vault(
    path: impl AsRef<Path>,
    identity: VaultIdentity,
    password: Password,
    params: KdfParams,
) -> thunderbolt_keystore::Result<TestVault> {
    let recovery = RecoveryVault::create(path, identity, password, params)?;
    let checkpoint = recovery.checkpoint();
    let checkpoint_store = TestCheckpointStore::anchored(identity, checkpoint);
    let vault = recovery
        .anchor(&checkpoint_store)
        .map_err(|_| KeystoreError::CheckpointMismatch)?;
    TestVault::new(vault, checkpoint_store)
}

fn open_vault(
    path: impl AsRef<Path>,
    identity: VaultIdentity,
    password: Password,
) -> thunderbolt_keystore::Result<TestVault> {
    let recovery = RecoveryVault::open(path, identity, password)?;
    let checkpoint = recovery.checkpoint();
    let checkpoint_store = TestCheckpointStore::anchored(identity, checkpoint);
    let vault = recovery
        .anchor(&checkpoint_store)
        .map_err(|_| KeystoreError::CheckpointMismatch)?;
    TestVault::new(vault, checkpoint_store)
}

fn secret_option_eq(left: Option<TestRecord>, right: &[u8]) -> bool {
    left.is_some_and(|left| bool::from(left.expose_secret().ct_eq(right)))
}

#[test]
fn holder_records_survive_atomic_updates_and_restart() -> Result<(), Box<dyn Error>> {
    let directory = TempDir::new()?;
    let path = vault_path(&directory);
    let mut vault = create_vault(&path, holder_identity(), password()?, params()?)?;
    vault.set_bitcoin_seed(BitcoinSeed::from_bytes(vec![0x31; 32])?)?;
    vault.set_paillier_key(PaillierKeyBytes::from_bytes(vec![0x52; 384])?)?;
    vault.set_holder_credential(HolderCredential::from_bytes(vec![0x73; 96])?)?;
    drop(vault);

    let mut reopened = open_vault(&path, holder_identity(), password()?)?;
    assert!(secret_option_eq(reopened.bitcoin_seed()?, [0x31; 32].as_slice()));
    assert!(secret_option_eq(reopened.paillier_key()?, [0x52; 384].as_slice()));
    assert!(secret_option_eq(reopened.holder_credential()?, [0x73; 96].as_slice()));
    assert!(reopened.remove_holder_credential()?);
    assert!(!reopened.remove_holder_credential()?);
    drop(reopened);

    let mut reopened = open_vault(&path, holder_identity(), password()?)?;
    assert!(reopened.holder_credential()?.is_none());
    Ok(())
}

#[test]
fn committee_records_are_role_scoped_and_durable() -> Result<(), Box<dyn Error>> {
    let directory = TempDir::new()?;
    let path = vault_path(&directory);
    let mut vault = create_vault(&path, committee_identity(), password()?, params()?)?;
    vault.set_paillier_key(PaillierKeyBytes::from_bytes(vec![0x19; 512])?)?;
    vault.set_committee_share(CommitteeMemberShare::from_bytes(vec![0x2a; 128])?)?;
    vault.set_committee_session_nonce(CommitteeSessionNonce::from_bytes(vec![0x3b; 32])?)?;
    assert!(matches!(
        vault.set_bitcoin_seed(BitcoinSeed::from_bytes(vec![0x4c; 32])?),
        Err(KeystoreError::InvalidRecordForRole)
    ));
    assert!(matches!(
        vault.set_holder_credential(HolderCredential::from_bytes(vec![0x5d; 64])?),
        Err(KeystoreError::InvalidRecordForRole)
    ));
    let trusted_checkpoint = vault.checkpoint()?;
    drop(vault);

    let checkpoint_store = TestCheckpointStore::anchored(committee_identity(), trusted_checkpoint);
    let vault = Vault::open_anchored(&path, committee_identity(), password()?, &checkpoint_store)?;
    let mut vault = TestVault::new(vault, checkpoint_store)?;
    assert!(secret_option_eq(vault.committee_share()?, [0x2a; 128].as_slice()));
    assert!(secret_option_eq(
        vault.committee_session_nonce()?,
        [0x3b; 32].as_slice()
    ));
    Ok(())
}

#[test]
fn wrong_password_and_ciphertext_tamper_fail_closed() -> Result<(), Box<dyn Error>> {
    let directory = TempDir::new()?;
    let path = vault_path(&directory);
    let mut vault = create_vault(&path, holder_identity(), password()?, params()?)?;
    vault.set_bitcoin_seed(BitcoinSeed::from_bytes(vec![0xa1; 32])?)?;
    drop(vault);

    let wrong = open_vault(&path, holder_identity(), wrong_password()?);
    assert!(matches!(wrong, Err(KeystoreError::AuthenticationFailed)));

    let mut encoded = fs::read(&path)?;
    let last = encoded.last_mut().ok_or("vault unexpectedly empty")?;
    *last ^= 0x80;
    fs::write(&path, encoded)?;
    let tampered = open_vault(&path, holder_identity(), password()?);
    assert!(matches!(tampered, Err(KeystoreError::AuthenticationFailed)));
    Ok(())
}

#[test]
fn network_role_and_node_identity_are_bound() -> Result<(), Box<dyn Error>> {
    let directory = TempDir::new()?;
    let path = vault_path(&directory);
    drop(create_vault(&path, holder_identity(), password()?, params()?)?);

    let wrong_network = VaultIdentity::new(
        Network::Signet,
        VaultRole::Holder,
        NodeId::new([0x11; 32]),
        deployment(),
    );
    assert!(matches!(
        open_vault(&path, wrong_network, password()?),
        Err(KeystoreError::IdentityMismatch)
    ));
    let wrong_role = VaultIdentity::new(
        Network::Regtest,
        VaultRole::CommitteeMember,
        NodeId::new([0x11; 32]),
        deployment(),
    );
    assert!(matches!(
        RecoveryVault::open(&path, wrong_role, password()?),
        Err(KeystoreError::IdentityMismatch)
    ));
    let wrong_node = VaultIdentity::new(
        Network::Regtest,
        VaultRole::Holder,
        NodeId::new([0x12; 32]),
        deployment(),
    );
    assert!(matches!(
        open_vault(&path, wrong_node, password()?),
        Err(KeystoreError::IdentityMismatch)
    ));
    let wrong_deployment = VaultIdentity::new(
        Network::Regtest,
        VaultRole::Holder,
        NodeId::new([0x11; 32]),
        DeploymentBinding::new(
            DeploymentId::new([0x34; 32])?,
            7,
            CommitteeDescriptorDigest::new([0x44; 32])?,
        )?,
    );
    assert!(matches!(
        open_vault(&path, wrong_deployment, password()?),
        Err(KeystoreError::IdentityMismatch)
    ));
    let wrong_epoch = VaultIdentity::new(
        Network::Regtest,
        VaultRole::Holder,
        NodeId::new([0x11; 32]),
        DeploymentBinding::new(
            DeploymentId::new([0x33; 32])?,
            8,
            CommitteeDescriptorDigest::new([0x44; 32])?,
        )?,
    );
    assert!(matches!(
        open_vault(&path, wrong_epoch, password()?),
        Err(KeystoreError::IdentityMismatch)
    ));
    let wrong_descriptor = VaultIdentity::new(
        Network::Regtest,
        VaultRole::Holder,
        NodeId::new([0x11; 32]),
        DeploymentBinding::new(
            DeploymentId::new([0x33; 32])?,
            7,
            CommitteeDescriptorDigest::new([0x45; 32])?,
        )?,
    );
    assert!(matches!(
        open_vault(&path, wrong_descriptor, password()?),
        Err(KeystoreError::IdentityMismatch)
    ));
    Ok(())
}

#[test]
fn advisory_lock_allows_only_one_open_instance() -> Result<(), Box<dyn Error>> {
    let directory = TempDir::new()?;
    let path = vault_path(&directory);
    let first = create_vault(&path, holder_identity(), password()?, params()?)?;
    assert!(matches!(
        open_vault(&path, holder_identity(), password()?),
        Err(KeystoreError::Locked)
    ));
    drop(first);
    let second = open_vault(&path, holder_identity(), password()?)?;
    drop(second);
    Ok(())
}

#[test]
fn backup_is_authenticated_and_restore_requires_empty_target() -> Result<(), Box<dyn Error>> {
    let directory = TempDir::new()?;
    let source = directory.path().join("holder.vault");
    let backup = directory.path().join("holder.backup");
    let restored = directory.path().join("restored.vault");
    let wrong_target = directory.path().join("wrong-password.vault");
    let rollback_target = directory.path().join("rollback.vault");
    let mut vault = create_vault(&source, holder_identity(), password()?, params()?)?;
    vault.set_bitcoin_seed(BitcoinSeed::from_bytes(vec![0xd1; 32])?)?;
    let backup_checkpoint = vault.checkpoint()?;
    vault.backup_to(&backup)?;
    drop(vault);
    let backup_store = TestCheckpointStore::anchored(holder_identity(), backup_checkpoint);

    let failed_restore = Vault::restore(
        &backup,
        &wrong_target,
        holder_identity(),
        wrong_password()?,
        &backup_store,
    );
    assert!(matches!(
        failed_restore,
        Err(CheckpointAnchorError::Keystore(KeystoreError::AuthenticationFailed))
    ));
    assert!(!wrong_target.exists());
    assert!(matches!(
        Vault::restore(
            &backup,
            &rollback_target,
            holder_identity(),
            password()?,
            &TestCheckpointStore::anchored(
                holder_identity(),
                thunderbolt_keystore::VaultCheckpoint::new(
                    VaultRevision::new(backup_checkpoint.revision().get() + 1),
                    backup_checkpoint.state_digest()
                ),
            )
        ),
        Err(CheckpointAnchorError::Mismatch { .. })
    ));
    assert!(!rollback_target.exists());

    let restored_vault = Vault::restore(&backup, &restored, holder_identity(), password()?, &backup_store)?;
    assert_eq!(restored_vault.checkpoint()?, backup_checkpoint);
    let mut restored_vault = TestVault::new(restored_vault, backup_store.clone())?;
    assert!(secret_option_eq(restored_vault.bitcoin_seed()?, [0xd1; 32].as_slice()));
    drop(restored_vault);

    let existing_empty = directory.path().join("existing-empty.vault");
    fs::write(&existing_empty, [])?;
    set_owner_only(&existing_empty)?;
    assert!(matches!(
        Vault::restore(
            &backup,
            &existing_empty,
            holder_identity(),
            password()?,
            &TestCheckpointStore::anchored(holder_identity(), backup_checkpoint)
        ),
        Err(CheckpointAnchorError::Keystore(KeystoreError::AlreadyExists))
    ));
    assert_eq!(fs::read(&existing_empty)?, Vec::<u8>::new());
    Ok(())
}

#[test]
fn create_and_backup_never_overwrite_existing_files() -> Result<(), Box<dyn Error>> {
    let directory = TempDir::new()?;
    let source = vault_path(&directory);
    let vault = create_vault(&source, holder_identity(), password()?, params()?)?;

    assert!(matches!(
        create_vault(&source, holder_identity(), password()?, params()?),
        Err(KeystoreError::Locked)
    ));

    let destination = directory.path().join("do-not-overwrite");
    let sentinel = b"operator data";
    fs::write(&destination, sentinel)?;
    set_owner_only(&destination)?;
    assert!(matches!(
        vault.backup_to(&destination),
        Err(KeystoreError::AlreadyExists)
    ));
    assert_eq!(fs::read(&destination)?, sentinel);
    drop(vault);

    assert!(matches!(
        create_vault(&source, holder_identity(), password()?, params()?),
        Err(KeystoreError::AlreadyExists)
    ));
    Ok(())
}

#[test]
fn stale_crash_temporary_file_cannot_replace_live_vault() -> Result<(), Box<dyn Error>> {
    let directory = TempDir::new()?;
    let path = vault_path(&directory);
    let mut vault = create_vault(&path, holder_identity(), password()?, params()?)?;
    vault.set_bitcoin_seed(BitcoinSeed::from_bytes(vec![0xe1; 32])?)?;
    drop(vault);

    let stale = directory
        .path()
        .join(".participant.vault.tmp-deadbeefdeadbeefdeadbeefdeadbeef");
    fs::write(&stale, b"incomplete crash write")?;
    set_owner_only(&stale)?;

    let mut reopened = open_vault(&path, holder_identity(), password()?)?;
    assert!(secret_option_eq(reopened.bitcoin_seed()?, [0xe1; 32].as_slice()));
    reopened.set_holder_credential(HolderCredential::from_bytes(vec![0xf2; 64])?)?;
    assert_eq!(fs::read(&stale)?, b"incomplete crash write");
    drop(reopened);

    let mut reopened = open_vault(&path, holder_identity(), password()?)?;
    assert!(secret_option_eq(reopened.holder_credential()?, [0xf2; 64].as_slice()));
    Ok(())
}

#[test]
fn external_file_replacement_aborts_update_and_restores_memory() -> Result<(), Box<dyn Error>> {
    let directory = TempDir::new()?;
    let path = vault_path(&directory);
    let replacement = directory.path().join("replacement.vault");
    let mut vault = create_vault(&path, holder_identity(), password()?, params()?)?;
    vault.set_bitcoin_seed(BitcoinSeed::from_bytes(vec![0x61; 32])?)?;

    drop(create_vault(&replacement, holder_identity(), password()?, params()?)?);
    fs::rename(&replacement, &path)?;

    let result = vault.set_holder_credential(HolderCredential::from_bytes(vec![0x72; 48])?);
    assert!(matches!(result, Err(KeystoreError::CheckpointMismatch)));
    assert!(matches!(vault.holder_credential(), Err(KeystoreError::Poisoned)));
    assert!(matches!(vault.bitcoin_seed(), Err(KeystoreError::Poisoned)));
    Ok(())
}

#[test]
fn multi_record_transaction_is_atomic_and_survives_restart() -> Result<(), Box<dyn Error>> {
    let directory = TempDir::new()?;
    let path = vault_path(&directory);
    let channel = RecordKey::channel(b"funding-outpoint-1".to_vec())?;
    let invoice = RecordKey::invoice(b"invoice-1".to_vec())?;
    let credential = RecordKey::credential(b"credential-1".to_vec())?;
    let transaction_id = TransactionId::new([0x81; 32]);
    let mut vault = create_vault(&path, holder_identity(), password()?, params()?)?;

    let outcome = vault.transact(vault.revision()?, transaction_id, |transaction| {
        transaction.compare_and_swap(
            channel.clone(),
            ExpectedRecord::Absent,
            SecretValue::from_bytes(vec![0x11; 48])?,
        )?;
        transaction.compare_and_swap(
            invoice.clone(),
            ExpectedRecord::Absent,
            SecretValue::from_bytes(vec![0x22; 96])?,
        )?;
        transaction.compare_and_swap(
            credential.clone(),
            ExpectedRecord::Absent,
            SecretValue::from_bytes(vec![0x33; 128])?,
        )
    })?;
    assert_eq!(outcome, CommitOutcome::Applied(VaultRevision::new(1)));
    drop(vault);

    let mut reopened = open_vault(&path, holder_identity(), password()?)?;
    assert_eq!(reopened.revision()?, VaultRevision::new(1));
    assert!(secret_option_eq(reopened.get(&channel)?, [0x11; 48].as_slice()));
    assert!(secret_option_eq(reopened.get(&invoice)?, [0x22; 96].as_slice()));
    assert!(secret_option_eq(reopened.get(&credential)?, [0x33; 128].as_slice()));
    Ok(())
}

#[test]
fn exact_replay_is_idempotent_and_changed_replay_fails() -> Result<(), Box<dyn Error>> {
    let directory = TempDir::new()?;
    let path = vault_path(&directory);
    let key = RecordKey::channel(b"channel-replay".to_vec())?;
    let transaction_id = TransactionId::new([0x82; 32]);
    let mut vault = create_vault(&path, holder_identity(), password()?, params()?)?;
    let stage = |transaction: &mut thunderbolt_keystore::Transaction| {
        transaction.compare_and_swap(
            key.clone(),
            ExpectedRecord::Absent,
            SecretValue::from_bytes(vec![0x44; 64])?,
        )
    };
    assert_eq!(
        vault.transact(VaultRevision::new(0), transaction_id, stage)?,
        CommitOutcome::Applied(VaultRevision::new(1))
    );
    drop(vault);

    let mut reopened = open_vault(&path, holder_identity(), password()?)?;
    assert_eq!(
        reopened.transact(reopened.revision()?, transaction_id, |transaction| {
            transaction.compare_and_swap(
                key.clone(),
                ExpectedRecord::Absent,
                SecretValue::from_bytes(vec![0x44; 64])?,
            )
        })?,
        CommitOutcome::Replayed(VaultRevision::new(1))
    );
    assert!(matches!(
        reopened.transact(reopened.revision()?, transaction_id, |transaction| {
            transaction.compare_and_swap(
                key.clone(),
                ExpectedRecord::Absent,
                SecretValue::from_bytes(vec![0x45; 64])?,
            )
        }),
        Err(KeystoreError::TransactionReplayConflict)
    ));
    assert!(matches!(
        reopened.prune_transaction_receipts(VaultRevision::new(1), VaultRevision::new(2)),
        Err(KeystoreError::InvalidPruneRevision)
    ));
    assert_eq!(
        reopened.transact(reopened.revision()?, transaction_id, |transaction| {
            transaction.compare_and_swap(
                key.clone(),
                ExpectedRecord::Absent,
                SecretValue::from_bytes(vec![0x44; 64])?,
            )
        })?,
        CommitOutcome::Replayed(VaultRevision::new(1))
    );
    assert!(secret_option_eq(reopened.get(&key)?, [0x44; 64].as_slice()));
    Ok(())
}

#[test]
fn compare_and_swap_conflict_rolls_back_every_staged_record() -> Result<(), Box<dyn Error>> {
    let directory = TempDir::new()?;
    let path = vault_path(&directory);
    let first = RecordKey::channel(b"channel-cas".to_vec())?;
    let second = RecordKey::invoice(b"invoice-cas".to_vec())?;
    let mut vault = create_vault(&path, holder_identity(), password()?, params()?)?;
    vault.transact(VaultRevision::new(0), TransactionId::new([0x83; 32]), |transaction| {
        transaction.compare_and_swap(
            first.clone(),
            ExpectedRecord::Absent,
            SecretValue::from_bytes(vec![0x51; 32])?,
        )
    })?;

    assert!(matches!(
        vault.transact(VaultRevision::new(1), TransactionId::new([0x84; 32]), |transaction| {
            transaction.compare_and_swap(
                first.clone(),
                ExpectedRecord::Version(thunderbolt_keystore::RecordVersion::new(1)),
                SecretValue::from_bytes(vec![0x52; 32])?,
            )?;
            transaction.compare_and_swap(
                second.clone(),
                ExpectedRecord::Version(thunderbolt_keystore::RecordVersion::new(99)),
                SecretValue::from_bytes(vec![0x53; 32])?,
            )
        }),
        Err(KeystoreError::RecordConflict)
    ));
    assert_eq!(vault.revision()?, VaultRevision::new(1));
    assert!(secret_option_eq(vault.get(&first)?, [0x51; 32].as_slice()));
    assert!(vault.get(&second)?.is_none());
    Ok(())
}

#[test]
fn consumed_nonce_tombstone_survives_restart_and_stale_backup_is_rejected() -> Result<(), Box<dyn Error>> {
    let directory = TempDir::new()?;
    let path = vault_path(&directory);
    let stale_backup = directory.path().join("committee-old.backup");
    let rejected_restore = directory.path().join("committee-restored.vault");
    let nonce_key = RecordKey::session_nonce(b"signing-session-9".to_vec())?;
    let mut vault = create_vault(&path, committee_identity(), password()?, params()?)?;
    vault.set_committee_share(CommitteeMemberShare::from_bytes(vec![0x61; 64])?)?;
    let stale_checkpoint = vault.checkpoint()?;
    vault.backup_to(&stale_backup)?;
    vault.transact(vault.revision()?, TransactionId::new([0x85; 32]), |transaction| {
        transaction.compare_and_swap(
            nonce_key.clone(),
            ExpectedRecord::Absent,
            SecretValue::from_bytes(vec![0x62; 32])?,
        )
    })?;
    let nonce_version = vault.get(&nonce_key)?.ok_or("missing nonce")?.version();
    assert!(matches!(
        vault.transact(vault.revision()?, TransactionId::new([0x89; 32]), |transaction| {
            transaction.compare_and_swap(
                nonce_key.clone(),
                ExpectedRecord::Version(nonce_version),
                SecretValue::from_bytes(vec![0x64; 32])?,
            )
        }),
        Err(KeystoreError::NonceAlreadyReserved)
    ));
    assert!(secret_option_eq(vault.get(&nonce_key)?, [0x62; 32].as_slice()));
    vault.transact(vault.revision()?, TransactionId::new([0x86; 32]), |transaction| {
        transaction.remove(nonce_key.clone(), nonce_version)
    })?;
    let tombstone_version = match vault.record_status(&nonce_key)? {
        RecordStatus::Tombstoned(version) => version,
        _ => return Err("nonce was not tombstoned".into()),
    };
    let trusted_checkpoint = vault.checkpoint()?;
    drop(vault);

    let checkpoint_store = TestCheckpointStore::anchored(committee_identity(), trusted_checkpoint);
    let reopened = Vault::open_anchored(&path, committee_identity(), password()?, &checkpoint_store)?;
    let mut reopened = TestVault::new(reopened, checkpoint_store.clone())?;
    assert_eq!(
        reopened.record_status(&nonce_key)?,
        RecordStatus::Tombstoned(tombstone_version)
    );
    assert!(matches!(
        reopened.transact(reopened.revision()?, TransactionId::new([0x87; 32]), |transaction| {
            transaction.compare_and_swap(
                nonce_key.clone(),
                ExpectedRecord::Version(tombstone_version),
                SecretValue::from_bytes(vec![0x63; 32])?,
            )
        },),
        Err(KeystoreError::NonceConsumed)
    ));
    drop(reopened);

    fs::copy(&stale_backup, &path)?;
    assert!(matches!(
        Vault::open_anchored(&path, committee_identity(), password()?, &checkpoint_store),
        Err(CheckpointAnchorError::Mismatch { .. })
    ));
    assert!(matches!(
        Vault::restore(
            &stale_backup,
            &rejected_restore,
            committee_identity(),
            password()?,
            &checkpoint_store
        ),
        Err(CheckpointAnchorError::Mismatch { .. })
    ));
    assert!(stale_checkpoint.revision() < trusted_checkpoint.revision());
    assert!(!rejected_restore.exists());
    Ok(())
}

#[test]
fn identity_and_record_limits_fail_closed() -> Result<(), Box<dyn Error>> {
    assert!(matches!(
        DeploymentId::new([0_u8; 32]),
        Err(KeystoreError::InvalidVaultIdentity)
    ));
    assert!(matches!(
        CommitteeDescriptorDigest::new([0_u8; 32]),
        Err(KeystoreError::InvalidVaultIdentity)
    ));
    assert!(matches!(
        RecordKey::new(RecordNamespace::AdapterState, Vec::new()),
        Err(KeystoreError::InvalidRecordKey)
    ));
    assert!(matches!(
        RecordKey::new(RecordNamespace::AdapterState, vec![0x01; MAX_RECORD_KEY_BYTES + 1]),
        Err(KeystoreError::InvalidRecordKey)
    ));
    assert!(matches!(
        SecretValue::from_bytes(Vec::new()),
        Err(KeystoreError::InvalidSecretRecord)
    ));
    assert!(matches!(
        SecretValue::from_bytes(vec![0x02; MAX_RECORD_VALUE_BYTES + 1]),
        Err(KeystoreError::InvalidSecretRecord)
    ));

    let directory = TempDir::new()?;
    let path = vault_path(&directory);
    let mut vault = create_vault(&path, holder_identity(), password()?, params()?)?;
    assert!(matches!(
        vault.transact(VaultRevision::new(0), TransactionId::new([0x88; 32]), |transaction| {
            for index in 0..=MAX_TRANSACTION_MUTATIONS {
                transaction.compare_and_swap(
                    RecordKey::new(RecordNamespace::AdapterState, index.to_be_bytes().to_vec())?,
                    ExpectedRecord::Absent,
                    SecretValue::from_bytes(vec![0x03])?,
                )?;
            }
            Ok(())
        }),
        Err(KeystoreError::TransactionLimitExceeded)
    ));
    assert_eq!(vault.revision()?, VaultRevision::new(0));
    assert_eq!(vault.record_count()?, 0);
    Ok(())
}

#[cfg(unix)]
#[test]
fn vault_and_lock_files_are_owner_only() -> Result<(), Box<dyn Error>> {
    let directory = TempDir::new()?;
    let path = vault_path(&directory);
    let backup = directory.path().join("owner-only.backup");
    let vault = create_vault(&path, holder_identity(), password()?, params()?)?;
    vault.backup_to(&backup)?;

    assert_eq!(fs::metadata(&path)?.permissions().mode() & 0o777, 0o600);
    assert_eq!(
        fs::metadata(path.with_extension("vault.lock"))?.permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(fs::metadata(&backup)?.permissions().mode() & 0o777, 0o600);
    Ok(())
}

#[cfg(unix)]
#[test]
fn group_readable_vault_is_rejected() -> Result<(), Box<dyn Error>> {
    let directory = TempDir::new()?;
    let path = vault_path(&directory);
    drop(create_vault(&path, holder_identity(), password()?, params()?)?);
    fs::set_permissions(&path, fs::Permissions::from_mode(0o640))?;

    assert!(matches!(
        open_vault(&path, holder_identity(), password()?),
        Err(KeystoreError::UnsafeFile)
    ));
    Ok(())
}

#[cfg(unix)]
#[test]
fn symlink_vault_backup_and_lock_paths_are_rejected() -> Result<(), Box<dyn Error>> {
    let directory = TempDir::new()?;
    let path = vault_path(&directory);
    let alias = directory.path().join("vault-link");
    let backup_link = directory.path().join("backup-link");
    let lock_attack_target = directory.path().join("lock-victim");
    let attacked_vault = directory.path().join("attacked.vault");
    let vault = create_vault(&path, holder_identity(), password()?, params()?)?;

    symlink(&path, &alias)?;
    assert!(matches!(
        open_vault(&alias, holder_identity(), password()?),
        Err(KeystoreError::UnsafeFile)
    ));

    fs::write(&lock_attack_target, b"do not modify")?;
    set_owner_only(&lock_attack_target)?;
    symlink(&lock_attack_target, &backup_link)?;
    assert!(matches!(
        vault.backup_to(&backup_link),
        Err(KeystoreError::AlreadyExists)
    ));
    assert_eq!(fs::read(&lock_attack_target)?, b"do not modify");
    drop(vault);

    symlink(&lock_attack_target, attacked_vault.with_extension("vault.lock"))?;
    assert!(matches!(
        create_vault(&attacked_vault, holder_identity(), password()?, params()?),
        Err(KeystoreError::UnsafeFile)
    ));
    assert_eq!(fs::read(&lock_attack_target)?, b"do not modify");
    Ok(())
}

#[cfg(unix)]
fn set_owner_only(path: &Path) -> std::io::Result<()> {
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
}

#[cfg(not(unix))]
fn set_owner_only(_path: &Path) -> std::io::Result<()> {
    Ok(())
}
