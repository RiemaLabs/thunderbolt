use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};

use static_assertions::assert_not_impl_any;
use subtle::ConstantTimeEq;
use tempfile::TempDir;
use thunderbolt_keystore::{
    BitcoinSeed, CommitOutcome, CommitteeDescriptorDigest, CommitteeMemberShare, CommitteeSessionNonce,
    DeploymentBinding, DeploymentId, ExpectedRecord, HolderCredential, KdfParams, KeystoreError, Network, NodeId,
    PaillierKeyBytes, Password, RecordKey, RecordNamespace, RecordStatus, SecretValue, TransactionId, Vault,
    VaultIdentity, VaultRevision, VaultRole, MAX_RECORD_KEY_BYTES, MAX_RECORD_VALUE_BYTES, MAX_TRANSACTION_MUTATIONS,
    MIN_ARGON2_ITERATIONS, MIN_ARGON2_MEMORY_KIB,
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

fn secret_option_eq(left: Option<&[u8]>, right: &[u8]) -> bool {
    left.is_some_and(|left| bool::from(left.ct_eq(right)))
}

#[test]
fn holder_records_survive_atomic_updates_and_restart() -> Result<(), Box<dyn Error>> {
    let directory = TempDir::new()?;
    let path = vault_path(&directory);
    let mut vault = Vault::create(&path, holder_identity(), password()?, params()?)?;
    vault.set_bitcoin_seed(BitcoinSeed::from_bytes(vec![0x31; 32])?)?;
    vault.set_paillier_key(PaillierKeyBytes::from_bytes(vec![0x52; 384])?)?;
    vault.set_holder_credential(HolderCredential::from_bytes(vec![0x73; 96])?)?;
    drop(vault);

    let mut reopened = Vault::open(&path, holder_identity(), password()?)?;
    assert!(secret_option_eq(
        reopened.bitcoin_seed()?.map(|value| value.expose_secret()),
        [0x31; 32].as_slice()
    ));
    assert!(secret_option_eq(
        reopened.paillier_key()?.map(|value| value.expose_secret()),
        [0x52; 384].as_slice()
    ));
    assert!(secret_option_eq(
        reopened.holder_credential()?.map(|value| value.expose_secret()),
        [0x73; 96].as_slice()
    ));
    assert!(reopened.remove_holder_credential()?);
    assert!(!reopened.remove_holder_credential()?);
    drop(reopened);

    let reopened = Vault::open(&path, holder_identity(), password()?)?;
    assert!(reopened.holder_credential()?.is_none());
    Ok(())
}

#[test]
fn committee_records_are_role_scoped_and_durable() -> Result<(), Box<dyn Error>> {
    let directory = TempDir::new()?;
    let path = vault_path(&directory);
    let mut vault = Vault::create(&path, committee_identity(), password()?, params()?)?;
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
    let minimum_revision = vault.revision()?;
    drop(vault);

    let vault = Vault::open_with_minimum_revision(&path, committee_identity(), password()?, minimum_revision)?;
    assert!(secret_option_eq(
        vault.committee_share()?.map(|value| value.expose_secret()),
        [0x2a; 128].as_slice()
    ));
    assert!(secret_option_eq(
        vault.committee_session_nonce()?.map(|value| value.expose_secret()),
        [0x3b; 32].as_slice()
    ));
    Ok(())
}

#[test]
fn wrong_password_and_ciphertext_tamper_fail_closed() -> Result<(), Box<dyn Error>> {
    let directory = TempDir::new()?;
    let path = vault_path(&directory);
    let mut vault = Vault::create(&path, holder_identity(), password()?, params()?)?;
    vault.set_bitcoin_seed(BitcoinSeed::from_bytes(vec![0xa1; 32])?)?;
    drop(vault);

    let wrong = Vault::open(&path, holder_identity(), wrong_password()?);
    assert!(matches!(wrong, Err(KeystoreError::AuthenticationFailed)));

    let mut encoded = fs::read(&path)?;
    let last = encoded.last_mut().ok_or("vault unexpectedly empty")?;
    *last ^= 0x80;
    fs::write(&path, encoded)?;
    let tampered = Vault::open(&path, holder_identity(), password()?);
    assert!(matches!(tampered, Err(KeystoreError::AuthenticationFailed)));
    Ok(())
}

#[test]
fn network_role_and_node_identity_are_bound() -> Result<(), Box<dyn Error>> {
    let directory = TempDir::new()?;
    let path = vault_path(&directory);
    drop(Vault::create(&path, holder_identity(), password()?, params()?)?);

    let wrong_network = VaultIdentity::new(
        Network::Signet,
        VaultRole::Holder,
        NodeId::new([0x11; 32]),
        deployment(),
    );
    assert!(matches!(
        Vault::open(&path, wrong_network, password()?),
        Err(KeystoreError::IdentityMismatch)
    ));
    let wrong_role = VaultIdentity::new(
        Network::Regtest,
        VaultRole::CommitteeMember,
        NodeId::new([0x11; 32]),
        deployment(),
    );
    assert!(matches!(
        Vault::open_with_minimum_revision(
            &path,
            wrong_role,
            password()?,
            thunderbolt_keystore::VaultRevision::new(1)
        ),
        Err(KeystoreError::IdentityMismatch)
    ));
    let wrong_node = VaultIdentity::new(
        Network::Regtest,
        VaultRole::Holder,
        NodeId::new([0x12; 32]),
        deployment(),
    );
    assert!(matches!(
        Vault::open(&path, wrong_node, password()?),
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
        Vault::open(&path, wrong_deployment, password()?),
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
        Vault::open(&path, wrong_epoch, password()?),
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
        Vault::open(&path, wrong_descriptor, password()?),
        Err(KeystoreError::IdentityMismatch)
    ));
    Ok(())
}

#[test]
fn advisory_lock_allows_only_one_open_instance() -> Result<(), Box<dyn Error>> {
    let directory = TempDir::new()?;
    let path = vault_path(&directory);
    let first = Vault::create(&path, holder_identity(), password()?, params()?)?;
    assert!(matches!(
        Vault::open(&path, holder_identity(), password()?),
        Err(KeystoreError::Locked)
    ));
    drop(first);
    let second = Vault::open(&path, holder_identity(), password()?)?;
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
    let mut vault = Vault::create(&source, holder_identity(), password()?, params()?)?;
    vault.set_bitcoin_seed(BitcoinSeed::from_bytes(vec![0xd1; 32])?)?;
    let backup_revision = vault.revision()?;
    vault.backup_to(&backup)?;
    drop(vault);

    let failed_restore = Vault::restore(
        &backup,
        &wrong_target,
        holder_identity(),
        wrong_password()?,
        backup_revision,
    );
    assert!(matches!(failed_restore, Err(KeystoreError::AuthenticationFailed)));
    assert!(!wrong_target.exists());
    assert!(matches!(
        Vault::restore(
            &backup,
            &rollback_target,
            holder_identity(),
            password()?,
            VaultRevision::new(backup_revision.get() + 1)
        ),
        Err(KeystoreError::RollbackDetected)
    ));
    assert!(!rollback_target.exists());

    let restored_vault = Vault::restore(&backup, &restored, holder_identity(), password()?, backup_revision)?;
    assert!(secret_option_eq(
        restored_vault.bitcoin_seed()?.map(|value| value.expose_secret()),
        [0xd1; 32].as_slice()
    ));
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
            backup_revision
        ),
        Err(KeystoreError::AlreadyExists)
    ));
    assert_eq!(fs::read(&existing_empty)?, Vec::<u8>::new());
    Ok(())
}

#[test]
fn create_and_backup_never_overwrite_existing_files() -> Result<(), Box<dyn Error>> {
    let directory = TempDir::new()?;
    let source = vault_path(&directory);
    let vault = Vault::create(&source, holder_identity(), password()?, params()?)?;

    assert!(matches!(
        Vault::create(&source, holder_identity(), password()?, params()?),
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
        Vault::create(&source, holder_identity(), password()?, params()?),
        Err(KeystoreError::AlreadyExists)
    ));
    Ok(())
}

#[test]
fn stale_crash_temporary_file_cannot_replace_live_vault() -> Result<(), Box<dyn Error>> {
    let directory = TempDir::new()?;
    let path = vault_path(&directory);
    let mut vault = Vault::create(&path, holder_identity(), password()?, params()?)?;
    vault.set_bitcoin_seed(BitcoinSeed::from_bytes(vec![0xe1; 32])?)?;
    drop(vault);

    let stale = directory
        .path()
        .join(".participant.vault.tmp-deadbeefdeadbeefdeadbeefdeadbeef");
    fs::write(&stale, b"incomplete crash write")?;
    set_owner_only(&stale)?;

    let mut reopened = Vault::open(&path, holder_identity(), password()?)?;
    assert!(secret_option_eq(
        reopened.bitcoin_seed()?.map(|value| value.expose_secret()),
        [0xe1; 32].as_slice()
    ));
    reopened.set_holder_credential(HolderCredential::from_bytes(vec![0xf2; 64])?)?;
    assert_eq!(fs::read(&stale)?, b"incomplete crash write");
    drop(reopened);

    let reopened = Vault::open(&path, holder_identity(), password()?)?;
    assert!(secret_option_eq(
        reopened.holder_credential()?.map(|value| value.expose_secret()),
        [0xf2; 64].as_slice()
    ));
    Ok(())
}

#[test]
fn external_file_replacement_aborts_update_and_restores_memory() -> Result<(), Box<dyn Error>> {
    let directory = TempDir::new()?;
    let path = vault_path(&directory);
    let replacement = directory.path().join("replacement.vault");
    let mut vault = Vault::create(&path, holder_identity(), password()?, params()?)?;
    vault.set_bitcoin_seed(BitcoinSeed::from_bytes(vec![0x61; 32])?)?;

    drop(Vault::create(&replacement, holder_identity(), password()?, params()?)?);
    fs::rename(&replacement, &path)?;

    let result = vault.set_holder_credential(HolderCredential::from_bytes(vec![0x72; 48])?);
    assert!(matches!(result, Err(KeystoreError::FileReplaced)));
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
    let mut vault = Vault::create(&path, holder_identity(), password()?, params()?)?;

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

    let reopened = Vault::open(&path, holder_identity(), password()?)?;
    assert_eq!(reopened.revision()?, VaultRevision::new(1));
    assert!(secret_option_eq(
        reopened.get(&channel)?.map(|record| record.expose_secret()),
        [0x11; 48].as_slice()
    ));
    assert!(secret_option_eq(
        reopened.get(&invoice)?.map(|record| record.expose_secret()),
        [0x22; 96].as_slice()
    ));
    assert!(secret_option_eq(
        reopened.get(&credential)?.map(|record| record.expose_secret()),
        [0x33; 128].as_slice()
    ));
    Ok(())
}

#[test]
fn exact_replay_is_idempotent_and_changed_replay_fails() -> Result<(), Box<dyn Error>> {
    let directory = TempDir::new()?;
    let path = vault_path(&directory);
    let key = RecordKey::channel(b"channel-replay".to_vec())?;
    let transaction_id = TransactionId::new([0x82; 32]);
    let mut vault = Vault::create(&path, holder_identity(), password()?, params()?)?;
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

    let mut reopened = Vault::open(&path, holder_identity(), password()?)?;
    assert_eq!(
        reopened.transact(VaultRevision::new(0), transaction_id, |transaction| {
            transaction.compare_and_swap(
                key.clone(),
                ExpectedRecord::Absent,
                SecretValue::from_bytes(vec![0x44; 64])?,
            )
        })?,
        CommitOutcome::Replayed(VaultRevision::new(1))
    );
    assert!(matches!(
        reopened.transact(VaultRevision::new(1), transaction_id, |transaction| {
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
        reopened.transact(VaultRevision::new(0), transaction_id, |transaction| {
            transaction.compare_and_swap(
                key.clone(),
                ExpectedRecord::Absent,
                SecretValue::from_bytes(vec![0x44; 64])?,
            )
        })?,
        CommitOutcome::Replayed(VaultRevision::new(1))
    );
    assert!(secret_option_eq(
        reopened.get(&key)?.map(|record| record.expose_secret()),
        [0x44; 64].as_slice()
    ));
    Ok(())
}

#[test]
fn compare_and_swap_conflict_rolls_back_every_staged_record() -> Result<(), Box<dyn Error>> {
    let directory = TempDir::new()?;
    let path = vault_path(&directory);
    let first = RecordKey::channel(b"channel-cas".to_vec())?;
    let second = RecordKey::invoice(b"invoice-cas".to_vec())?;
    let mut vault = Vault::create(&path, holder_identity(), password()?, params()?)?;
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
    assert!(secret_option_eq(
        vault.get(&first)?.map(|record| record.expose_secret()),
        [0x51; 32].as_slice()
    ));
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
    let mut vault = Vault::create(&path, committee_identity(), password()?, params()?)?;
    vault.set_committee_share(CommitteeMemberShare::from_bytes(vec![0x61; 64])?)?;
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
    assert!(secret_option_eq(
        vault.get(&nonce_key)?.map(|record| record.expose_secret()),
        [0x62; 32].as_slice()
    ));
    vault.transact(vault.revision()?, TransactionId::new([0x86; 32]), |transaction| {
        transaction.remove(nonce_key.clone(), nonce_version)
    })?;
    let trusted_floor = vault.revision()?;
    assert_eq!(trusted_floor, VaultRevision::new(3));
    assert_eq!(
        vault.record_status(&nonce_key)?,
        RecordStatus::Tombstoned(thunderbolt_keystore::RecordVersion::new(3))
    );
    drop(vault);

    assert!(matches!(
        Vault::open(&path, committee_identity(), password()?),
        Err(KeystoreError::RollbackFloorRequired)
    ));
    let mut reopened = Vault::open_with_minimum_revision(&path, committee_identity(), password()?, trusted_floor)?;
    assert_eq!(
        reopened.record_status(&nonce_key)?,
        RecordStatus::Tombstoned(thunderbolt_keystore::RecordVersion::new(3))
    );
    assert!(matches!(
        reopened.transact(trusted_floor, TransactionId::new([0x87; 32]), |transaction| {
            transaction.compare_and_swap(
                nonce_key.clone(),
                ExpectedRecord::Version(thunderbolt_keystore::RecordVersion::new(3)),
                SecretValue::from_bytes(vec![0x63; 32])?,
            )
        }),
        Err(KeystoreError::NonceConsumed)
    ));
    drop(reopened);

    fs::copy(&stale_backup, &path)?;
    assert!(matches!(
        Vault::open_with_minimum_revision(&path, committee_identity(), password()?, trusted_floor),
        Err(KeystoreError::RollbackDetected)
    ));
    assert!(matches!(
        Vault::restore(
            &stale_backup,
            &rejected_restore,
            committee_identity(),
            password()?,
            VaultRevision::new(1)
        ),
        Err(KeystoreError::SigningStateRestoreForbidden)
    ));
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
    let mut vault = Vault::create(&path, holder_identity(), password()?, params()?)?;
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
    let vault = Vault::create(&path, holder_identity(), password()?, params()?)?;
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
    drop(Vault::create(&path, holder_identity(), password()?, params()?)?);
    fs::set_permissions(&path, fs::Permissions::from_mode(0o640))?;

    assert!(matches!(
        Vault::open(&path, holder_identity(), password()?),
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
    let vault = Vault::create(&path, holder_identity(), password()?, params()?)?;

    symlink(&path, &alias)?;
    assert!(matches!(
        Vault::open(&alias, holder_identity(), password()?),
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
        Vault::create(&attacked_vault, holder_identity(), password()?, params()?),
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
