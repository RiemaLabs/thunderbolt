use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::Read as _;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

use rustls::pki_types::CertificateDer;
use sha2::{Digest, Sha256};
use thunderbolt_cometbft_rpc::OwnerOnlyPemClientIdentity;
use zeroize::Zeroizing;

use crate::types::{
    CometTlsReferences, EffectiveRuntimeConfig, ExternalFileReference, ParsedRuntimeConfig, RuntimePaths,
};
use crate::{ConfigError, Result};

const MAX_CONFIG_BYTES: u64 = 256 * 1_024;
const MAX_REFERENCE_BYTES: u64 = 8 * 1_024 * 1_024;
const MAX_CA_PEM_BYTES: u64 = 512 * 1_024;
const MAX_CA_CERTIFICATES: usize = 8;
const MAX_CA_DER_BYTES: usize = 64 * 1_024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ResourceKind {
    Directory,
    OutputFile,
    ControlSocket,
    PublicReference,
    SecretReference,
    AbsentOutput,
    AbsentSocket,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ResourceReceipt {
    path: PathBuf,
    kind: ResourceKind,
    device: u64,
    inode: u64,
    digest: Option<[u8; 32]>,
    exclusive: bool,
}

/// Live descriptors and inode/digest receipts retained by an effective config.
pub(crate) struct FilesystemAudit {
    receipts: Vec<ResourceReceipt>,
    _handles: Vec<File>,
}

impl FilesystemAudit {
    fn equivalent(&self, other: &Self) -> bool {
        self.receipts == other.receipts
    }

    pub(crate) fn file_identities(&self) -> impl Iterator<Item = ((u64, u64), bool)> + '_ {
        self.receipts.iter().filter_map(|receipt| match receipt.kind {
            ResourceKind::OutputFile
            | ResourceKind::PublicReference
            | ResourceKind::SecretReference
            | ResourceKind::ControlSocket => Some(((receipt.device, receipt.inode), receipt.exclusive)),
            ResourceKind::Directory | ResourceKind::AbsentOutput | ResourceKind::AbsentSocket => None,
        })
    }
}

impl ParsedRuntimeConfig {
    /// Reads an absolute owner-only regular configuration file without
    /// following symlinks, then parses it.
    #[cfg(unix)]
    pub fn load_owner_only(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        require_absolute(path)?;
        let mut file = open_owner_file(path, MAX_CONFIG_BYTES)?;
        let mut bytes = Zeroizing::new(Vec::new());
        file.by_ref()
            .take(MAX_CONFIG_BYTES.saturating_add(1))
            .read_to_end(&mut bytes)?;
        if u64::try_from(bytes.len()).map_err(|_| ConfigError::InputTooLarge)? > MAX_CONFIG_BYTES {
            return Err(ConfigError::InputTooLarge);
        }
        let text = std::str::from_utf8(&bytes).map_err(|_| ConfigError::Invalid("configuration is not UTF-8"))?;
        Self::parse_toml(text)
    }

    /// Fails closed on platforms without owner UID and Unix-path semantics.
    #[cfg(not(unix))]
    pub fn load_owner_only(_path: impl AsRef<Path>) -> Result<Self> {
        Err(ConfigError::UnsupportedPlatform)
    }

    /// Audits live paths and retains exact inode/digest descriptors. Consumers
    /// must still call `EffectiveRuntimeConfig::revalidate_for_handoff`
    /// immediately before downstream constructors open their own paths.
    #[cfg(unix)]
    pub fn validate_filesystem(mut self) -> Result<EffectiveRuntimeConfig> {
        let audit = Arc::new(audit_paths(self.candidate.paths())?);
        self.candidate.install_filesystem_audit(audit);
        Ok(EffectiveRuntimeConfig {
            candidate: self.candidate,
        })
    }

    /// Fails closed on platforms without owner UID and Unix-path semantics.
    #[cfg(not(unix))]
    pub fn validate_filesystem(self) -> Result<EffectiveRuntimeConfig> {
        let _ = self;
        Err(ConfigError::UnsupportedPlatform)
    }
}

#[cfg(unix)]
pub(crate) fn revalidate_effective(config: &EffectiveRuntimeConfig) -> Result<()> {
    let current = audit_paths(config.paths())?;
    if !config.filesystem_audit()?.equivalent(&current) {
        return Err(ConfigError::UnsafePath("filesystem identity changed after validation"));
    }
    Ok(())
}

#[cfg(not(unix))]
pub(crate) fn revalidate_effective(_config: &EffectiveRuntimeConfig) -> Result<()> {
    Err(ConfigError::UnsupportedPlatform)
}

/// Loads exactly constructor-compatible CA DER and client identity material at
/// the final handoff. Secret key bytes remain inside the Comet RPC provider.
#[cfg(unix)]
pub(crate) fn load_comet_tls(
    tls: &CometTlsReferences,
) -> Result<(Vec<CertificateDer<'static>>, OwnerOnlyPemClientIdentity)> {
    let mut certificates = Vec::new();
    for reference in &tls.ca_certificates {
        let bytes = read_public_reference(reference, MAX_CA_PEM_BYTES)?;
        let mut reader = std::io::Cursor::new(bytes);
        let parsed = rustls_pemfile::certs(&mut reader)
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|_| ConfigError::ReferenceMismatch)?;
        for certificate in parsed {
            if certificate.is_empty()
                || certificate.len() > MAX_CA_DER_BYTES
                || certificates.len() >= MAX_CA_CERTIFICATES
            {
                return Err(ConfigError::ReferenceMismatch);
            }
            certificates.push(certificate);
        }
    }
    if certificates.is_empty() {
        return Err(ConfigError::ReferenceMismatch);
    }
    let identity =
        OwnerOnlyPemClientIdentity::load(tls.client_certificate_file.path(), tls.client_private_key_file.path())
            .map_err(|_| ConfigError::ReferenceMismatch)?;
    Ok((certificates, identity))
}

#[cfg(unix)]
pub(crate) fn read_external_reference(reference: &ExternalFileReference) -> Result<Vec<u8>> {
    read_public_reference(reference, MAX_REFERENCE_BYTES)
}

#[cfg(not(unix))]
pub(crate) fn read_external_reference(_reference: &ExternalFileReference) -> Result<Vec<u8>> {
    Err(ConfigError::UnsupportedPlatform)
}

#[cfg(unix)]
pub(crate) fn open_secret_reference(path: &Path) -> Result<File> {
    open_owner_file(path, MAX_REFERENCE_BYTES)
}

#[cfg(not(unix))]
pub(crate) fn open_secret_reference(_path: &Path) -> Result<File> {
    Err(ConfigError::UnsupportedPlatform)
}

#[cfg(not(unix))]
pub(crate) fn load_comet_tls(
    _tls: &CometTlsReferences,
) -> Result<(Vec<CertificateDer<'static>>, OwnerOnlyPemClientIdentity)> {
    Err(ConfigError::UnsupportedPlatform)
}

#[cfg(unix)]
fn audit_paths(paths: &RuntimePaths) -> Result<FilesystemAudit> {
    let mut receipts = Vec::new();
    let mut handles = Vec::new();
    audit_private_directory(&paths.data_dir, true, &mut receipts, &mut handles)?;
    audit_private_directory(&paths.control_dir, true, &mut receipts, &mut handles)?;
    audit_output_file(&paths.service_db, &mut receipts, &mut handles)?;
    audit_control_socket(&paths.control_socket, &mut receipts, &mut handles)?;
    if let Some(path) = &paths.vault_file {
        audit_output_file(path, &mut receipts, &mut handles)?;
    }
    if let Some(path) = &paths.trust_coordinator_db {
        audit_output_file(path, &mut receipts, &mut handles)?;
    }
    audit_secret_reference(&paths.bitcoin_cookie_file.path, false, &mut receipts, &mut handles)?;
    if let Some(reference) = &paths.vault_password_file {
        audit_secret_reference(&reference.path, true, &mut receipts, &mut handles)?;
    }
    audit_public_reference(&paths.committee_descriptor, false, &mut receipts, &mut handles)?;
    audit_public_reference(&paths.anchor_suite_registry, false, &mut receipts, &mut handles)?;
    audit_public_reference(&paths.profile_manifest, false, &mut receipts, &mut handles)?;
    for reference in [
        paths
            .vault_checkpoint_provider
            .as_ref()
            .map(|provider| &provider.manifest),
        paths
            .trust_checkpoint_provider
            .as_ref()
            .map(|provider| &provider.manifest),
        paths.trust_root_light_block.as_ref(),
    ]
    .into_iter()
    .flatten()
    {
        let exclusive = paths
            .trust_root_light_block
            .as_ref()
            .is_none_or(|root| root.path != reference.path);
        audit_public_reference(reference, exclusive, &mut receipts, &mut handles)?;
    }
    if let Some(tls) = &paths.comet_tls {
        for certificate in &tls.ca_certificates {
            audit_public_reference(certificate, false, &mut receipts, &mut handles)?;
        }
        audit_secret_reference(&tls.client_certificate_file.path, true, &mut receipts, &mut handles)?;
        audit_secret_reference(&tls.client_private_key_file.path, true, &mut receipts, &mut handles)?;
        let _ = load_comet_tls(tls)?;
    }
    reject_inode_aliases(&receipts)?;
    Ok(FilesystemAudit {
        receipts,
        _handles: handles,
    })
}

#[cfg(unix)]
fn reject_inode_aliases(receipts: &[ResourceReceipt]) -> Result<()> {
    let mut identities: BTreeMap<(u64, u64), &Path> = BTreeMap::new();
    for receipt in receipts {
        if matches!(receipt.kind, ResourceKind::AbsentOutput | ResourceKind::AbsentSocket) {
            continue;
        }
        if let Some(previous) = identities.insert((receipt.device, receipt.inode), &receipt.path) {
            if previous != receipt.path {
                return Err(ConfigError::UnsafePath(
                    "runtime resources are hard-link or inode aliases",
                ));
            }
        }
    }
    Ok(())
}

#[cfg(unix)]
fn audit_public_reference(
    reference: &ExternalFileReference,
    exclusive: bool,
    receipts: &mut Vec<ResourceReceipt>,
    handles: &mut Vec<File>,
) -> Result<()> {
    let mut file = open_owner_file(&reference.path, MAX_REFERENCE_BYTES)?;
    let digest = hash_reader(&mut file, MAX_REFERENCE_BYTES)?;
    if digest != reference.digest {
        return Err(ConfigError::ReferenceMismatch);
    }
    let (device, inode) = file_identity(&file)?;
    receipts.push(ResourceReceipt {
        path: reference.path.clone(),
        kind: ResourceKind::PublicReference,
        device,
        inode,
        digest: Some(digest),
        exclusive,
    });
    handles.push(file);
    Ok(())
}

#[cfg(unix)]
fn read_public_reference(reference: &ExternalFileReference, maximum: u64) -> Result<Vec<u8>> {
    let mut file = open_owner_file(&reference.path, maximum)?;
    let mut bytes = Vec::new();
    file.by_ref().take(maximum.saturating_add(1)).read_to_end(&mut bytes)?;
    if u64::try_from(bytes.len()).map_err(|_| ConfigError::ReferenceMismatch)? > maximum
        || Sha256::digest(&bytes).as_slice() != reference.digest
    {
        return Err(ConfigError::ReferenceMismatch);
    }
    Ok(bytes)
}

#[cfg(unix)]
fn audit_secret_reference(
    path: &Path,
    exclusive: bool,
    receipts: &mut Vec<ResourceReceipt>,
    handles: &mut Vec<File>,
) -> Result<()> {
    let file = open_owner_file(path, MAX_REFERENCE_BYTES)?;
    let (device, inode) = file_identity(&file)?;
    receipts.push(ResourceReceipt {
        path: path.to_path_buf(),
        kind: ResourceKind::SecretReference,
        device,
        inode,
        digest: None,
        exclusive,
    });
    handles.push(file);
    Ok(())
}

#[cfg(unix)]
fn open_owner_file(path: &Path, max_bytes: u64) -> Result<File> {
    use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};

    require_absolute(path)?;
    validate_private_parent(path)?;
    reject_symlink_components(path)?;
    let before = std::fs::symlink_metadata(path).map_err(|_| ConfigError::ReferenceMismatch)?;
    if !before.file_type().is_file()
        || before.uid() != rustix::process::geteuid().as_raw()
        || before.mode() & 0o400 == 0
        || before.mode() & 0o077 != 0
        || before.mode() & 0o111 != 0
        || before.len() == 0
        || before.len() > max_bytes
    {
        return Err(ConfigError::ReferenceMismatch);
    }
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .map_err(|_| ConfigError::ReferenceMismatch)?;
    let after = file.metadata().map_err(|_| ConfigError::ReferenceMismatch)?;
    if !after.file_type().is_file()
        || before.dev() != after.dev()
        || before.ino() != after.ino()
        || after.uid() != rustix::process::geteuid().as_raw()
        || after.mode() & 0o077 != 0
        || after.mode() & 0o111 != 0
        || after.len() == 0
        || after.len() > max_bytes
    {
        return Err(ConfigError::ReferenceMismatch);
    }
    Ok(file)
}

#[cfg(unix)]
fn audit_private_directory(
    path: &Path,
    exclusive: bool,
    receipts: &mut Vec<ResourceReceipt>,
    handles: &mut Vec<File>,
) -> Result<()> {
    use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};

    require_absolute(path)?;
    validate_private_parent(path)?;
    reject_symlink_components(path)?;
    validate_ancestors(path)?;
    let metadata = std::fs::symlink_metadata(path).map_err(|_| ConfigError::UnsafePath("directory is missing"))?;
    if !metadata.file_type().is_dir()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.mode() & 0o700 != 0o700
        || metadata.mode() & 0o077 != 0
    {
        return Err(ConfigError::UnsafePath("directory must be owner-controlled mode 0700"));
    }
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(path)
        .map_err(|_| ConfigError::UnsafePath("directory open failed"))?;
    let (device, inode) = file_identity(&file)?;
    receipts.push(ResourceReceipt {
        path: path.to_path_buf(),
        kind: ResourceKind::Directory,
        device,
        inode,
        digest: None,
        exclusive,
    });
    handles.push(file);
    Ok(())
}

#[cfg(unix)]
fn audit_output_file(path: &Path, receipts: &mut Vec<ResourceReceipt>, handles: &mut Vec<File>) -> Result<()> {
    use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};

    require_absolute(path)?;
    validate_private_parent(path)?;
    reject_symlink_components(path)?;
    match std::fs::symlink_metadata(path) {
        Ok(metadata)
            if metadata.file_type().is_file()
                && metadata.uid() == rustix::process::geteuid().as_raw()
                && metadata.mode() & 0o600 == 0o600
                && metadata.mode() & 0o077 == 0
                && metadata.mode() & 0o111 == 0 =>
        {
            let file = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
                .open(path)
                .map_err(|_| ConfigError::UnsafePath("runtime file open failed"))?;
            let (device, inode) = file_identity(&file)?;
            receipts.push(ResourceReceipt {
                path: path.to_path_buf(),
                kind: ResourceKind::OutputFile,
                device,
                inode,
                digest: None,
                exclusive: true,
            });
            handles.push(file);
            Ok(())
        }
        Ok(_) => Err(ConfigError::UnsafePath(
            "runtime file must be owner-controlled mode 0600",
        )),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            audit_absent(path, ResourceKind::AbsentOutput, receipts, handles)
        }
        Err(_) => Err(ConfigError::UnsafePath("runtime file metadata is unavailable")),
    }
}

#[cfg(unix)]
fn audit_control_socket(path: &Path, receipts: &mut Vec<ResourceReceipt>, handles: &mut Vec<File>) -> Result<()> {
    use std::os::unix::fs::{FileTypeExt as _, MetadataExt as _};

    require_absolute(path)?;
    validate_private_parent(path)?;
    reject_symlink_components(path)?;
    match std::fs::symlink_metadata(path) {
        Ok(metadata)
            if metadata.file_type().is_socket()
                && metadata.uid() == rustix::process::geteuid().as_raw()
                && metadata.mode() & 0o600 == 0o600
                && metadata.mode() & 0o077 == 0 =>
        {
            receipts.push(ResourceReceipt {
                path: path.to_path_buf(),
                kind: ResourceKind::ControlSocket,
                device: metadata.dev(),
                inode: metadata.ino(),
                digest: None,
                exclusive: true,
            });
            Ok(())
        }
        Ok(_) => Err(ConfigError::UnsafePath("control path is not an owner-only Unix socket")),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            audit_absent(path, ResourceKind::AbsentSocket, receipts, handles)
        }
        Err(_) => Err(ConfigError::UnsafePath("control socket metadata is unavailable")),
    }
}

#[cfg(unix)]
fn audit_absent(
    path: &Path,
    kind: ResourceKind,
    receipts: &mut Vec<ResourceReceipt>,
    handles: &mut Vec<File>,
) -> Result<()> {
    let parent = path
        .parent()
        .ok_or(ConfigError::UnsafePath("runtime path has no parent"))?;
    let before = receipts.len();
    audit_private_directory(parent, true, receipts, handles)?;
    let parent_receipt = receipts
        .pop()
        .ok_or(ConfigError::UnsafePath("parent audit receipt is missing"))?;
    if receipts.len() != before {
        return Err(ConfigError::UnsafePath("parent audit receipt count changed"));
    }
    receipts.push(ResourceReceipt {
        path: path.to_path_buf(),
        kind,
        device: parent_receipt.device,
        inode: parent_receipt.inode,
        digest: None,
        exclusive: true,
    });
    Ok(())
}

#[cfg(unix)]
fn hash_reader(file: &mut File, maximum: u64) -> Result<[u8; 32]> {
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 8 * 1_024];
    let mut total = 0_u64;
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        total = total
            .checked_add(u64::try_from(read).map_err(|_| ConfigError::ReferenceMismatch)?)
            .ok_or(ConfigError::ReferenceMismatch)?;
        if total > maximum {
            return Err(ConfigError::ReferenceMismatch);
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hasher.finalize().into())
}

#[cfg(unix)]
fn file_identity(file: &File) -> Result<(u64, u64)> {
    use std::os::unix::fs::MetadataExt as _;

    let metadata = file.metadata().map_err(|_| ConfigError::ReferenceMismatch)?;
    Ok((metadata.dev(), metadata.ino()))
}

#[cfg(unix)]
fn validate_private_parent(path: &Path) -> Result<()> {
    use std::os::unix::fs::MetadataExt as _;

    let parent = path.parent().ok_or(ConfigError::UnsafePath("path has no parent"))?;
    let metadata = std::fs::symlink_metadata(parent).map_err(|_| ConfigError::UnsafePath("parent is missing"))?;
    if metadata.file_type().is_symlink()
        || !metadata.file_type().is_dir()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.mode() & 0o077 != 0
    {
        return Err(ConfigError::UnsafePath("file parent must be owner-private"));
    }
    validate_ancestors(parent)
}

#[cfg(unix)]
fn validate_ancestors(path: &Path) -> Result<()> {
    use std::os::unix::fs::MetadataExt as _;

    let canonical = std::fs::canonicalize(path).map_err(|_| ConfigError::UnsafePath("path canonicalization failed"))?;
    let effective_uid = rustix::process::geteuid().as_raw();
    for ancestor in canonical.ancestors() {
        let metadata = std::fs::symlink_metadata(ancestor)
            .map_err(|_| ConfigError::UnsafePath("ancestor metadata is unavailable"))?;
        if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() {
            return Err(ConfigError::UnsafePath("ancestor is not a canonical directory"));
        }
        if metadata.uid() != 0 && metadata.uid() != effective_uid {
            return Err(ConfigError::UnsafePath("ancestor has a foreign owner"));
        }
        if metadata.mode() & 0o022 != 0 && metadata.mode() & 0o1000 == 0 {
            return Err(ConfigError::UnsafePath(
                "ancestor is writable without sticky protection",
            ));
        }
    }
    Ok(())
}

#[cfg(unix)]
fn reject_symlink_components(path: &Path) -> Result<()> {
    let mut current = PathBuf::new();
    for component in path.components() {
        match component {
            Component::RootDir => current.push(component.as_os_str()),
            Component::Normal(value) => {
                current.push(value);
                match std::fs::symlink_metadata(&current) {
                    Ok(metadata) if metadata.file_type().is_symlink() => {
                        return Err(ConfigError::UnsafePath("symlink path components are forbidden"));
                    }
                    Ok(_) => {}
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => break,
                    Err(_) => return Err(ConfigError::UnsafePath("path component metadata is unavailable")),
                }
            }
            Component::CurDir | Component::ParentDir | Component::Prefix(_) => {
                return Err(ConfigError::UnsafePath("path is not lexically canonical"));
            }
        }
    }
    Ok(())
}

fn require_absolute(path: &Path) -> Result<()> {
    if !path.is_absolute() {
        return Err(ConfigError::UnsafePath("path must be absolute"));
    }
    Ok(())
}
