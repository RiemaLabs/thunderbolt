use std::fs::{File, OpenOptions, TryLockError};
use std::io::{Read as _, Seek as _, SeekFrom, Write as _};
use std::path::{Component, Path};

use crate::{Result, RuntimeError, RuntimeHandlerIdentity, RuntimeRole};

#[cfg(unix)]
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};

/// Stable process-lock filename inside the audited role data directory.
pub const RUNTIME_PROCESS_LOCK_FILE: &str = ".thunderbolt-runtime-v2.lock";

const MARKER_DOMAIN_TEXT: &str = "bitcoin-thunderbolt/runtime-lock/v2\n";
const MARKER_DOMAIN: &[u8] = MARKER_DOMAIN_TEXT.as_bytes();
const MAX_MARKER_BYTES: u64 = 2 * 1024;

pub(crate) struct ProcessLock {
    file: File,
    _directory: File,
    dirty_on_entry: bool,
    clean_marker: Vec<u8>,
    dirty_marker: Vec<u8>,
}

impl ProcessLock {
    #[cfg(unix)]
    pub(crate) fn acquire(data_dir: &Path, identity: &RuntimeHandlerIdentity) -> Result<Self> {
        validate_normal_absolute_path(data_dir)?;
        let path_metadata = std::fs::symlink_metadata(data_dir).map_err(|_| RuntimeError::UnsafeProcessLock)?;
        validate_owner_directory(&path_metadata)?;
        let directory = open_directory(data_dir)?;
        let opened_directory_metadata = directory.metadata().map_err(|_| RuntimeError::UnsafeProcessLock)?;
        validate_owner_directory(&opened_directory_metadata)?;
        if file_identity(&path_metadata) != file_identity(&opened_directory_metadata) {
            return Err(RuntimeError::UnsafeProcessLock);
        }

        let lock_path = data_dir.join(RUNTIME_PROCESS_LOCK_FILE);
        let (file, created) = open_lock_file(&lock_path)?;
        let lock_metadata = file.metadata().map_err(|_| RuntimeError::UnsafeProcessLock)?;
        validate_owner_lock_file(&lock_metadata)?;
        let path_lock_metadata = std::fs::symlink_metadata(&lock_path).map_err(|_| RuntimeError::UnsafeProcessLock)?;
        validate_owner_lock_file(&path_lock_metadata)?;
        if file_identity(&lock_metadata) != file_identity(&path_lock_metadata) {
            return Err(RuntimeError::UnsafeProcessLock);
        }
        let current_directory_metadata =
            std::fs::symlink_metadata(data_dir).map_err(|_| RuntimeError::UnsafeProcessLock)?;
        if file_identity(&path_metadata) != file_identity(&current_directory_metadata) {
            return Err(RuntimeError::UnsafeProcessLock);
        }

        match file.try_lock() {
            Ok(()) => {}
            Err(TryLockError::WouldBlock) => return Err(RuntimeError::ProcessAlreadyRunning),
            Err(TryLockError::Error(_)) => return Err(RuntimeError::ProcessLockUnavailable),
        }
        if created {
            directory
                .sync_all()
                .map_err(|_| RuntimeError::ProcessStateUnavailable)?;
        }
        let prefix = marker_prefix(identity);
        let clean_marker = marker_with_state(&prefix, b"clean\n");
        let running_marker = marker_with_state(&prefix, b"running\n");
        let dirty_marker = marker_with_state(&prefix, b"dirty\n");
        if [&clean_marker, &running_marker, &dirty_marker]
            .into_iter()
            .any(|value| u64::try_from(value.len()).map_or(true, |length| length > MAX_MARKER_BYTES))
        {
            return Err(RuntimeError::ProcessStateUnavailable);
        }
        let marker = read_marker(&file)?;
        let dirty_on_entry = if (created && marker.is_empty()) || marker == clean_marker {
            false
        } else if marker == running_marker || marker == dirty_marker {
            true
        } else if marker.starts_with(MARKER_DOMAIN) && !marker.starts_with(&prefix) {
            return Err(RuntimeError::ProcessLockIdentityMismatch);
        } else {
            return Err(RuntimeError::ProcessStateUnavailable);
        };
        write_marker(&file, if dirty_on_entry { &dirty_marker } else { &running_marker })?;
        Ok(Self {
            file,
            _directory: directory,
            dirty_on_entry,
            clean_marker,
            dirty_marker,
        })
    }

    #[cfg(not(unix))]
    pub(crate) fn acquire(_data_dir: &Path, _identity: &RuntimeHandlerIdentity) -> Result<Self> {
        Err(RuntimeError::UnsafeProcessLock)
    }

    pub(crate) const fn dirty_on_entry(&self) -> bool {
        self.dirty_on_entry
    }

    pub(crate) fn mark_faulted(&self) -> Result<()> {
        write_marker(&self.file, &self.dirty_marker)
    }

    pub(crate) fn mark_clean(&self) -> Result<()> {
        write_marker(
            &self.file,
            if self.dirty_on_entry {
                &self.dirty_marker
            } else {
                &self.clean_marker
            },
        )
    }
}

#[cfg(unix)]
fn open_directory(path: &Path) -> Result<File> {
    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW);
    options.open(path).map_err(|_| RuntimeError::UnsafeProcessLock)
}

#[cfg(unix)]
fn open_lock_file(path: &Path) -> Result<(File, bool)> {
    let mut create = OpenOptions::new();
    create
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    match create.open(path) {
        Ok(file) => Ok((file, true)),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            let mut existing = OpenOptions::new();
            existing
                .read(true)
                .write(true)
                .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
            existing
                .open(path)
                .map(|file| (file, false))
                .map_err(|_| RuntimeError::ProcessLockUnavailable)
        }
        Err(_) => Err(RuntimeError::ProcessLockUnavailable),
    }
}

#[cfg(unix)]
fn validate_owner_directory(metadata: &std::fs::Metadata) -> Result<()> {
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.mode() & 0o077 != 0
    {
        return Err(RuntimeError::UnsafeProcessLock);
    }
    Ok(())
}

#[cfg(unix)]
fn validate_owner_lock_file(metadata: &std::fs::Metadata) -> Result<()> {
    if metadata.file_type().is_symlink()
        || !metadata.file_type().is_file()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.mode() & 0o777 != 0o600
        || metadata.nlink() != 1
    {
        return Err(RuntimeError::UnsafeProcessLock);
    }
    Ok(())
}

#[cfg(unix)]
fn file_identity(metadata: &std::fs::Metadata) -> (u64, u64) {
    (metadata.dev(), metadata.ino())
}

fn validate_normal_absolute_path(path: &Path) -> Result<()> {
    if !path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::RootDir | Component::Normal(_)))
    {
        return Err(RuntimeError::UnsafeProcessLock);
    }
    Ok(())
}

fn read_marker(file: &File) -> Result<Vec<u8>> {
    let mut file = file.try_clone().map_err(|_| RuntimeError::ProcessStateUnavailable)?;
    file.seek(SeekFrom::Start(0))
        .map_err(|_| RuntimeError::ProcessStateUnavailable)?;
    let mut marker = Vec::new();
    file.take(MAX_MARKER_BYTES.saturating_add(1))
        .read_to_end(&mut marker)
        .map_err(|_| RuntimeError::ProcessStateUnavailable)?;
    if u64::try_from(marker.len()).map_err(|_| RuntimeError::ProcessStateUnavailable)? > MAX_MARKER_BYTES {
        return Err(RuntimeError::ProcessStateUnavailable);
    }
    Ok(marker)
}

fn marker_prefix(identity: &RuntimeHandlerIdentity) -> Vec<u8> {
    format!(
        concat!(
            "{}role={}\n",
            "network={}\n",
            "ledger_chain_id_hex={}\n",
            "deployment_id={}\n",
            "protocol_suite={}\n",
            "bitcoin_genesis={}\n",
            "committee_epoch={}\n",
            "committee_descriptor={}\n",
            "anchor_parameter_suite={}\n",
            "runtime_profile={}\n",
            "finality_profile={}\n",
            "finality_policy={}\n",
            "role_binding={}\n",
            "state="
        ),
        MARKER_DOMAIN_TEXT,
        role_name(identity.role),
        identity.network,
        identity.ledger_chain_id_hex,
        identity.deployment_id_hex,
        identity.protocol_suite_id,
        identity.bitcoin_genesis_hash,
        identity.committee_epoch,
        identity.committee_descriptor_digest,
        identity.anchor_parameter_suite_id,
        hex::encode(identity.runtime_profile_id),
        hex::encode(identity.finality_verifier_profile_id),
        hex::encode(identity.finality_policy_digest),
        identity.role_binding,
    )
    .into_bytes()
}

fn marker_with_state(prefix: &[u8], state: &[u8]) -> Vec<u8> {
    let mut marker = Vec::with_capacity(prefix.len().saturating_add(state.len()));
    marker.extend_from_slice(prefix);
    marker.extend_from_slice(state);
    marker
}

const fn role_name(role: RuntimeRole) -> &'static str {
    match role {
        RuntimeRole::Ledger => "ledger",
        RuntimeRole::Holder => "holder",
        RuntimeRole::Committee => "committee",
    }
}

fn write_marker(file: &File, marker: &[u8]) -> Result<()> {
    let mut file = file.try_clone().map_err(|_| RuntimeError::ProcessStateUnavailable)?;
    file.set_len(0).map_err(|_| RuntimeError::ProcessStateUnavailable)?;
    file.seek(SeekFrom::Start(0))
        .map_err(|_| RuntimeError::ProcessStateUnavailable)?;
    file.write_all(marker)
        .map_err(|_| RuntimeError::ProcessStateUnavailable)?;
    file.sync_all().map_err(|_| RuntimeError::ProcessStateUnavailable)
}
