use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};

use static_assertions::assert_not_impl_any;
use subtle::ConstantTimeEq;
use tempfile::TempDir;
use thunderbolt_keystore::{
    BitcoinSeed, CommitteeMemberShare, CommitteeSessionNonce, HolderCredential, KdfParams, KeystoreError, Network,
    NodeId, PaillierKeyBytes, Password, Vault, VaultIdentity, VaultRole, MIN_ARGON2_ITERATIONS, MIN_ARGON2_MEMORY_KIB,
};

#[cfg(unix)]
use std::os::unix::fs::{symlink, PermissionsExt};

assert_not_impl_any!(Password: Clone, std::fmt::Debug);
assert_not_impl_any!(BitcoinSeed: Clone, std::fmt::Debug);
assert_not_impl_any!(PaillierKeyBytes: Clone, std::fmt::Debug);
assert_not_impl_any!(HolderCredential: Clone, std::fmt::Debug);
assert_not_impl_any!(CommitteeMemberShare: Clone, std::fmt::Debug);
assert_not_impl_any!(CommitteeSessionNonce: Clone, std::fmt::Debug);
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

fn holder_identity() -> VaultIdentity {
    VaultIdentity::new(Network::Regtest, VaultRole::Holder, NodeId::new([0x11; 32]))
}

fn committee_identity() -> VaultIdentity {
    VaultIdentity::new(Network::Regtest, VaultRole::CommitteeMember, NodeId::new([0x22; 32]))
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
        reopened.bitcoin_seed().map(BitcoinSeed::expose_secret),
        [0x31; 32].as_slice()
    ));
    assert!(secret_option_eq(
        reopened.paillier_key().map(PaillierKeyBytes::expose_secret),
        [0x52; 384].as_slice()
    ));
    assert!(secret_option_eq(
        reopened.holder_credential().map(HolderCredential::expose_secret),
        [0x73; 96].as_slice()
    ));
    assert!(reopened.remove_holder_credential()?);
    assert!(!reopened.remove_holder_credential()?);
    drop(reopened);

    let reopened = Vault::open(&path, holder_identity(), password()?)?;
    assert!(reopened.holder_credential().is_none());
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
    drop(vault);

    let vault = Vault::open(&path, committee_identity(), password()?)?;
    assert!(secret_option_eq(
        vault.committee_share().map(CommitteeMemberShare::expose_secret),
        [0x2a; 128].as_slice()
    ));
    assert!(secret_option_eq(
        vault
            .committee_session_nonce()
            .map(CommitteeSessionNonce::expose_secret),
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

    let wrong_network = VaultIdentity::new(Network::Signet, VaultRole::Holder, NodeId::new([0x11; 32]));
    assert!(matches!(
        Vault::open(&path, wrong_network, password()?),
        Err(KeystoreError::IdentityMismatch)
    ));
    let wrong_role = VaultIdentity::new(Network::Regtest, VaultRole::CommitteeMember, NodeId::new([0x11; 32]));
    assert!(matches!(
        Vault::open(&path, wrong_role, password()?),
        Err(KeystoreError::IdentityMismatch)
    ));
    let wrong_node = VaultIdentity::new(Network::Regtest, VaultRole::Holder, NodeId::new([0x12; 32]));
    assert!(matches!(
        Vault::open(&path, wrong_node, password()?),
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
    let mut vault = Vault::create(&source, holder_identity(), password()?, params()?)?;
    vault.set_bitcoin_seed(BitcoinSeed::from_bytes(vec![0xd1; 32])?)?;
    vault.backup_to(&backup)?;
    drop(vault);

    let failed_restore = Vault::restore(&backup, &wrong_target, holder_identity(), wrong_password()?);
    assert!(matches!(failed_restore, Err(KeystoreError::AuthenticationFailed)));
    assert!(!wrong_target.exists());

    let restored_vault = Vault::restore(&backup, &restored, holder_identity(), password()?)?;
    assert!(secret_option_eq(
        restored_vault.bitcoin_seed().map(BitcoinSeed::expose_secret),
        [0xd1; 32].as_slice()
    ));
    drop(restored_vault);

    let existing_empty = directory.path().join("existing-empty.vault");
    fs::write(&existing_empty, [])?;
    set_owner_only(&existing_empty)?;
    assert!(matches!(
        Vault::restore(&backup, &existing_empty, holder_identity(), password()?),
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
        reopened.bitcoin_seed().map(BitcoinSeed::expose_secret),
        [0xe1; 32].as_slice()
    ));
    reopened.set_holder_credential(HolderCredential::from_bytes(vec![0xf2; 64])?)?;
    assert_eq!(fs::read(&stale)?, b"incomplete crash write");
    drop(reopened);

    let reopened = Vault::open(&path, holder_identity(), password()?)?;
    assert!(secret_option_eq(
        reopened.holder_credential().map(HolderCredential::expose_secret),
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
    assert!(vault.holder_credential().is_none());
    assert!(secret_option_eq(
        vault.bitcoin_seed().map(BitcoinSeed::expose_secret),
        [0x61; 32].as_slice()
    ));
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
