use std::ffi::OsString;
use std::fs::{self, File, Metadata, OpenOptions, TryLockError};
use std::io::{ErrorKind, Read, Write};
use std::path::{Path, PathBuf};

use crate::record_format::MAX_VAULT_FILE_BYTES;
use crate::{KeystoreError, Result};

#[cfg(test)]
thread_local! {
    static FAIL_BEFORE_RENAME: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static FAIL_AFTER_RENAME: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};

pub(crate) struct LockGuard {
    _file: File,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct FileIdentity {
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
    #[cfg(not(unix))]
    length: u64,
}

pub(crate) fn acquire_lock(vault_path: &Path) -> Result<LockGuard> {
    let lock_path = lock_path(vault_path)?;
    reject_symlink(&lock_path)?;
    let file = open_lock(&lock_path)?;
    validate_regular_owner_only(&file.metadata()?)?;
    match file.try_lock() {
        Ok(()) => Ok(LockGuard { _file: file }),
        Err(TryLockError::WouldBlock) => Err(KeystoreError::Locked),
        Err(TryLockError::Error(error)) => Err(KeystoreError::Io(error)),
    }
}

pub(crate) fn read_secure(path: &Path) -> Result<(Vec<u8>, FileIdentity)> {
    reject_symlink(path)?;
    let file = open_read(path)?;
    let metadata = file.metadata()?;
    validate_regular_owner_only(&metadata)?;
    let length = usize::try_from(metadata.len()).map_err(|_| KeystoreError::InvalidFormat)?;
    if length > MAX_VAULT_FILE_BYTES {
        return Err(KeystoreError::InvalidFormat);
    }
    let mut bytes = Vec::with_capacity(length);
    let read_limit = u64::try_from(MAX_VAULT_FILE_BYTES)
        .map_err(|_| KeystoreError::InvalidFormat)?
        .checked_add(1)
        .ok_or(KeystoreError::InvalidFormat)?;
    file.take(read_limit).read_to_end(&mut bytes)?;
    if bytes.len() > MAX_VAULT_FILE_BYTES {
        return Err(KeystoreError::InvalidFormat);
    }
    Ok((bytes, FileIdentity::from_metadata(&metadata)))
}

pub(crate) fn atomic_create(path: &Path, bytes: &[u8]) -> Result<FileIdentity> {
    if fs::symlink_metadata(path).is_ok() {
        return Err(KeystoreError::AlreadyExists);
    }
    let parent = parent_directory(path)?;
    let temporary = write_temporary(path, bytes)?;
    let link_result = fs::hard_link(&temporary, path);
    match link_result {
        Ok(()) => {
            sync_directory(parent)?;
            remove_temporary(&temporary)?;
            sync_directory(parent)?;
            let (_, identity) = read_secure(path)?;
            Ok(identity)
        }
        Err(error) => {
            let _ = fs::remove_file(&temporary);
            if error.kind() == ErrorKind::AlreadyExists {
                Err(KeystoreError::AlreadyExists)
            } else {
                Err(KeystoreError::Io(error))
            }
        }
    }
}

pub(crate) fn atomic_replace(path: &Path, bytes: &[u8], expected: FileIdentity) -> Result<FileIdentity> {
    let parent = parent_directory(path)?;
    let temporary = write_temporary(path, bytes)?;
    let replace_result = (|| {
        let (_, current) = read_secure(path)?;
        if current != expected {
            return Err(KeystoreError::FileReplaced);
        }
        #[cfg(test)]
        if FAIL_BEFORE_RENAME.with(|flag| flag.replace(false)) {
            return Err(KeystoreError::Io(std::io::Error::other(
                "injected failure before durable-state transition",
            )));
        }
        fs::rename(&temporary, path)?;
        #[cfg(test)]
        if FAIL_AFTER_RENAME.with(|flag| flag.replace(false)) {
            return Err(KeystoreError::Io(std::io::Error::other(
                "injected failure after durable-state transition",
            )));
        }
        sync_directory(parent)?;
        let (_, identity) = read_secure(path)?;
        Ok(identity)
    })();
    if replace_result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    replace_result
}

#[cfg(test)]
pub(crate) fn inject_failure_before_rename_once() {
    FAIL_BEFORE_RENAME.with(|flag| flag.set(true));
}

#[cfg(test)]
pub(crate) fn inject_failure_after_rename_once() {
    FAIL_AFTER_RENAME.with(|flag| flag.set(true));
}

fn write_temporary(target: &Path, bytes: &[u8]) -> Result<PathBuf> {
    let parent = parent_directory(target)?;
    let filename = target.file_name().ok_or_else(invalid_path_error)?;
    for _ in 0..32 {
        let mut random = [0_u8; 16];
        getrandom::fill(&mut random).map_err(|_| KeystoreError::RandomnessUnavailable)?;
        let mut name = OsString::from(".");
        name.push(filename);
        name.push(".tmp-");
        name.push(hex(&random)?);
        let path = parent.join(name);
        match open_temporary(&path) {
            Ok(mut file) => {
                set_owner_only(&file)?;
                if let Err(error) = file.write_all(bytes).and_then(|()| file.sync_all()) {
                    drop(file);
                    let _ = fs::remove_file(&path);
                    return Err(KeystoreError::Io(error));
                }
                drop(file);
                return Ok(path);
            }
            Err(error) if error.kind() == ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(KeystoreError::Io(error)),
        }
    }
    Err(KeystoreError::Io(std::io::Error::new(
        ErrorKind::AlreadyExists,
        "could not allocate a keystore temporary file",
    )))
}

fn remove_temporary(path: &Path) -> Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(()),
        Err(error) => Err(KeystoreError::Io(error)),
    }
}

fn lock_path(vault_path: &Path) -> Result<PathBuf> {
    let filename = vault_path.file_name().ok_or_else(invalid_path_error)?;
    let mut name = filename.to_os_string();
    name.push(".lock");
    Ok(parent_directory(vault_path)?.join(name))
}

fn parent_directory(path: &Path) -> Result<&Path> {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .ok_or_else(invalid_path_error)
}

fn invalid_path_error() -> KeystoreError {
    KeystoreError::Io(std::io::Error::new(
        ErrorKind::InvalidInput,
        "keystore path must have an existing parent and file name",
    ))
}

fn reject_symlink(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => Err(KeystoreError::UnsafeFile),
        Ok(_) => Ok(()),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(()),
        Err(error) => Err(KeystoreError::Io(error)),
    }
}

fn validate_regular_owner_only(metadata: &Metadata) -> Result<()> {
    if !metadata.is_file() {
        return Err(KeystoreError::UnsafeFile);
    }
    #[cfg(unix)]
    {
        let permissions = metadata.permissions().mode();
        if metadata.uid() != rustix::process::geteuid().as_raw()
            || permissions & 0o077 != 0
            || permissions & 0o400 == 0
            || permissions & 0o100 != 0
        {
            return Err(KeystoreError::UnsafeFile);
        }
    }
    Ok(())
}

fn sync_directory(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        let directory = open_directory(path)?;
        directory.sync_all()?;
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
    Ok(())
}

fn hex(bytes: &[u8; 16]) -> Result<String> {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(32);
    for byte in bytes {
        let high = DIGITS
            .get(usize::from(byte >> 4))
            .copied()
            .ok_or(KeystoreError::CryptographicFailure)?;
        let low = DIGITS
            .get(usize::from(byte & 0x0f))
            .copied()
            .ok_or(KeystoreError::CryptographicFailure)?;
        encoded.push(char::from(high));
        encoded.push(char::from(low));
    }
    Ok(encoded)
}

#[cfg(unix)]
fn set_owner_only(file: &File) -> Result<()> {
    file.set_permissions(fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_owner_only(_file: &File) -> Result<()> {
    Ok(())
}

impl FileIdentity {
    fn from_metadata(metadata: &Metadata) -> Self {
        #[cfg(unix)]
        {
            Self {
                device: metadata.dev(),
                inode: metadata.ino(),
            }
        }
        #[cfg(not(unix))]
        {
            Self { length: metadata.len() }
        }
    }
}

#[cfg(unix)]
fn open_read(path: &Path) -> std::io::Result<File> {
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
}

#[cfg(not(unix))]
fn open_read(path: &Path) -> std::io::Result<File> {
    OpenOptions::new().read(true).open(path)
}

#[cfg(unix)]
fn open_lock(path: &Path) -> std::io::Result<File> {
    OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
}

#[cfg(not(unix))]
fn open_lock(path: &Path) -> std::io::Result<File> {
    OpenOptions::new().read(true).write(true).create(true).open(path)
}

#[cfg(unix)]
fn open_temporary(path: &Path) -> std::io::Result<File> {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
}

#[cfg(not(unix))]
fn open_temporary(path: &Path) -> std::io::Result<File> {
    OpenOptions::new().write(true).create_new(true).open(path)
}

#[cfg(unix)]
fn open_directory(path: &Path) -> std::io::Result<File> {
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
}
