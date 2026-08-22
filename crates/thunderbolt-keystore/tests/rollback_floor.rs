use std::error::Error;
use std::fmt;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Mutex;

use tempfile::TempDir;
use thunderbolt_keystore::{
    CheckpointCasOutcome, CommitteeDescriptorDigest, DeploymentBinding, DeploymentId, KdfParams, Network, NodeId,
    PaillierKeyBytes, Password, RecoveryVault, RollbackFloorStore, VaultCheckpoint, VaultIdentity, VaultRevision,
    VaultRole, VaultStateDigest, MIN_ARGON2_ITERATIONS, MIN_ARGON2_MEMORY_KIB,
};

const NO_FAILURE: u8 = 0;
const FAIL_BEFORE: u8 = 1;
const FAIL_AFTER: u8 = 2;

#[derive(Debug)]
struct TestFloorError(&'static str);

impl fmt::Display for TestFloorError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.0)
    }
}

impl Error for TestFloorError {}

#[derive(Default)]
struct MemoryFloorStore {
    entries: Mutex<Vec<(VaultIdentity, VaultCheckpoint)>>,
    failure: AtomicU8,
}

impl MemoryFloorStore {
    fn fail_before_next_cas(&self) {
        self.failure.store(FAIL_BEFORE, Ordering::SeqCst);
    }

    fn fail_after_next_cas(&self) {
        self.failure.store(FAIL_AFTER, Ordering::SeqCst);
    }
}

impl RollbackFloorStore for MemoryFloorStore {
    type Error = TestFloorError;

    fn load_checkpoint(&self, identity: VaultIdentity) -> Result<Option<VaultCheckpoint>, Self::Error> {
        let entries = self.entries.lock().map_err(|_| TestFloorError("test lock poisoned"))?;
        Ok(entries
            .iter()
            .find_map(|(stored_identity, checkpoint)| (*stored_identity == identity).then_some(*checkpoint)))
    }

    fn compare_and_swap_checkpoint(
        &self,
        identity: VaultIdentity,
        expected: Option<VaultCheckpoint>,
        next: VaultCheckpoint,
    ) -> Result<CheckpointCasOutcome, Self::Error> {
        let failure = self.failure.swap(NO_FAILURE, Ordering::SeqCst);
        if failure == FAIL_BEFORE {
            return Err(TestFloorError("injected failure before durable CAS"));
        }
        let mut entries = self.entries.lock().map_err(|_| TestFloorError("test lock poisoned"))?;
        let position = entries
            .iter()
            .position(|(stored_identity, _)| *stored_identity == identity);
        let current = position.map(|index| entries[index].1);
        let outcome = if current == Some(next) {
            CheckpointCasOutcome::AlreadyCurrent
        } else if current != expected || !valid_next(expected, next) {
            CheckpointCasOutcome::Conflict(current)
        } else {
            match position {
                Some(index) => entries[index].1 = next,
                None => entries.push((identity, next)),
            }
            CheckpointCasOutcome::Advanced
        };
        drop(entries);
        if failure == FAIL_AFTER {
            return Err(TestFloorError("injected failure after durable CAS"));
        }
        Ok(outcome)
    }
}

fn valid_next(expected: Option<VaultCheckpoint>, next: VaultCheckpoint) -> bool {
    match expected {
        None => next.revision() == VaultRevision::new(0),
        Some(previous) => previous
            .revision()
            .get()
            .checked_add(1)
            .is_some_and(|revision| next.revision() == VaultRevision::new(revision)),
    }
}

fn identity(deployment_byte: u8, epoch: u64, descriptor_byte: u8) -> Result<VaultIdentity, Box<dyn Error>> {
    let deployment = DeploymentBinding::new(
        DeploymentId::new([deployment_byte; 32])?,
        epoch,
        CommitteeDescriptorDigest::new([descriptor_byte; 32])?,
    )?;
    Ok(VaultIdentity::new(
        Network::Regtest,
        VaultRole::CommitteeMember,
        NodeId::new([0x91; 32]),
        deployment,
    ))
}

fn checkpoint(revision: u64, digest_byte: u8) -> VaultCheckpoint {
    VaultCheckpoint::new(VaultRevision::new(revision), VaultStateDigest::new([digest_byte; 32]))
}

fn password() -> thunderbolt_keystore::Result<Password> {
    Password::from_bytes(b"checkpoint fork test password".to_vec())
}

fn params() -> thunderbolt_keystore::Result<KdfParams> {
    KdfParams::new(MIN_ARGON2_MEMORY_KIB, MIN_ARGON2_ITERATIONS, 1)
}

#[test]
fn checkpoint_cas_detects_same_revision_forks_and_stale_expected() -> Result<(), Box<dyn Error>> {
    let store = MemoryFloorStore::default();
    let identity = identity(0x92, 3, 0x93)?;
    let initial = checkpoint(0, 0xa0);
    let first_fork = checkpoint(1, 0xa1);
    let second_fork = checkpoint(1, 0xa2);

    assert_eq!(store.load_checkpoint(identity)?, None);
    assert_eq!(
        store.compare_and_swap_checkpoint(identity, None, initial)?,
        CheckpointCasOutcome::Advanced
    );
    assert_eq!(
        store.compare_and_swap_checkpoint(identity, Some(initial), first_fork)?,
        CheckpointCasOutcome::Advanced
    );
    assert_eq!(
        store.compare_and_swap_checkpoint(identity, Some(initial), first_fork)?,
        CheckpointCasOutcome::AlreadyCurrent
    );
    assert_eq!(
        store.compare_and_swap_checkpoint(identity, Some(initial), second_fork)?,
        CheckpointCasOutcome::Conflict(Some(first_fork))
    );
    assert_eq!(
        store.compare_and_swap_checkpoint(identity, Some(initial), checkpoint(2, 0xa3))?,
        CheckpointCasOutcome::Conflict(Some(first_fork))
    );
    Ok(())
}

#[test]
fn ambiguous_cas_is_reconciled_by_exact_readback() -> Result<(), Box<dyn Error>> {
    let store = MemoryFloorStore::default();
    let identity = identity(0xb1, 4, 0xb2)?;
    let initial = checkpoint(0, 0xb3);
    let next = checkpoint(1, 0xb4);
    store.compare_and_swap_checkpoint(identity, None, initial)?;

    store.fail_before_next_cas();
    assert!(store
        .compare_and_swap_checkpoint(identity, Some(initial), next)
        .is_err());
    assert_eq!(store.load_checkpoint(identity)?, Some(initial));

    store.fail_after_next_cas();
    assert!(store
        .compare_and_swap_checkpoint(identity, Some(initial), next)
        .is_err());
    assert_eq!(store.load_checkpoint(identity)?, Some(next));
    assert_eq!(
        store.compare_and_swap_checkpoint(identity, Some(initial), next)?,
        CheckpointCasOutcome::AlreadyCurrent
    );
    Ok(())
}

#[test]
fn complete_deployment_identity_keys_each_checkpoint() -> Result<(), Box<dyn Error>> {
    let store = MemoryFloorStore::default();
    let base = identity(0xc1, 7, 0xc2)?;
    let other_deployment = identity(0xc3, 7, 0xc2)?;
    let other_epoch = identity(0xc1, 8, 0xc2)?;
    let other_descriptor = identity(0xc1, 7, 0xc4)?;
    let initial = checkpoint(0, 0xc5);

    store.compare_and_swap_checkpoint(base, None, initial)?;
    assert_eq!(store.load_checkpoint(base)?, Some(initial));
    assert_eq!(store.load_checkpoint(other_deployment)?, None);
    assert_eq!(store.load_checkpoint(other_epoch)?, None);
    assert_eq!(store.load_checkpoint(other_descriptor)?, None);
    Ok(())
}

#[test]
fn copied_vaults_at_same_revision_cannot_both_advance() -> Result<(), Box<dyn Error>> {
    let directory = TempDir::new()?;
    let first_path = directory.path().join("first.vault");
    let copied_path = directory.path().join("copied.vault");
    let identity = identity(0xd1, 9, 0xd2)?;
    let checkpoint_store = MemoryFloorStore::default();

    let recovery = RecoveryVault::create(&first_path, identity, password()?, params()?)?;
    let initial = recovery.checkpoint();
    assert_eq!(
        checkpoint_store.compare_and_swap_checkpoint(identity, None, initial)?,
        CheckpointCasOutcome::Advanced
    );
    let mut first = recovery.anchor(&checkpoint_store)?;
    first.backup_to(&copied_path)?;
    let copied_recovery = RecoveryVault::open(&copied_path, identity, password()?)?;
    assert_eq!(copied_recovery.checkpoint(), initial);
    let mut copied = copied_recovery.anchor(&checkpoint_store)?;

    first.set_paillier_key(PaillierKeyBytes::from_bytes(vec![0xe1; 64])?)?;
    let first_next = first.checkpoint()?;
    assert_eq!(first_next.revision(), VaultRevision::new(1));
    assert_eq!(
        checkpoint_store.compare_and_swap_checkpoint(identity, Some(initial), first_next)?,
        CheckpointCasOutcome::Advanced
    );

    copied.set_paillier_key(PaillierKeyBytes::from_bytes(vec![0xe2; 64])?)?;
    let copied_next = copied.checkpoint()?;
    assert_eq!(copied_next.revision(), VaultRevision::new(1));
    assert_ne!(copied_next.state_digest(), first_next.state_digest());
    assert_eq!(
        checkpoint_store.compare_and_swap_checkpoint(identity, Some(initial), copied_next)?,
        CheckpointCasOutcome::Conflict(Some(first_next))
    );
    Ok(())
}
