use std::ffi::OsString;
use std::fs::{self, File};
use std::path::{Component, Path, PathBuf};

use sha2::{Digest, Sha256};

use crate::error::{NodeError, Result};

#[cfg(unix)]
use std::os::unix::fs::{FileExt, FileTypeExt, MetadataExt, PermissionsExt};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct FileIdentity {
    device: u64,
    inode: u64,
    uid: u32,
}

pub(crate) struct SecureFile {
    path: PathBuf,
    parent: DirectoryGuard,
    file: File,
    identity: FileIdentity,
    digest: [u8; 32],
    bytes: Vec<u8>,
    max_bytes: usize,
    label: &'static str,
}

impl SecureFile {
    pub(crate) fn open(path: &Path, max_bytes: usize, label: &'static str) -> Result<Self> {
        #[cfg(not(unix))]
        {
            let _ = (path, max_bytes, label);
            return Err(NodeError::UnsupportedPlatform);
        }
        #[cfg(unix)]
        {
            require_normalized_absolute(path, label)?;
            let parent = DirectoryGuard::validate(path.parent().ok_or(NodeError::InvalidConfig(label))?, label)?;
            let descriptor = rustix::fs::open(
                path,
                rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::CLOEXEC | rustix::fs::OFlags::NOFOLLOW,
                rustix::fs::Mode::empty(),
            )
            .map_err(|_| NodeError::FileIo(label))?;
            let file = File::from(descriptor);
            let metadata = file.metadata().map_err(|_| NodeError::FileIo(label))?;
            let identity = validate_private_file(&metadata, label)?;
            let path_metadata = fs::symlink_metadata(path).map_err(|_| NodeError::FileIo(label))?;
            if path_metadata.file_type().is_symlink()
                || validate_private_file(&path_metadata, label)? != identity
                || fs::canonicalize(path).map_err(|_| NodeError::FileIo(label))? != path
            {
                return Err(NodeError::InvalidConfig(label));
            }
            let bytes = read_bounded(&file, max_bytes, label)?;
            let digest = Sha256::digest(&bytes).into();
            let value = Self {
                path: path.to_path_buf(),
                parent,
                file,
                identity,
                digest,
                bytes,
                max_bytes,
                label,
            };
            value.revalidate()?;
            Ok(value)
        }
    }

    pub(crate) fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    pub(crate) const fn digest(&self) -> &[u8; 32] {
        &self.digest
    }

    pub(crate) fn revalidate(&self) -> Result<()> {
        #[cfg(not(unix))]
        {
            Err(NodeError::UnsupportedPlatform)
        }
        #[cfg(unix)]
        {
            self.parent.revalidate()?;
            let descriptor_metadata = self.file.metadata().map_err(|_| NodeError::FileIo(self.label))?;
            if validate_private_file(&descriptor_metadata, self.label)? != self.identity {
                return Err(NodeError::InvalidConfig(self.label));
            }
            let path_metadata = fs::symlink_metadata(&self.path).map_err(|_| NodeError::FileIo(self.label))?;
            if path_metadata.file_type().is_symlink()
                || validate_private_file(&path_metadata, self.label)? != self.identity
                || fs::canonicalize(&self.path).map_err(|_| NodeError::FileIo(self.label))? != self.path
            {
                return Err(NodeError::InvalidConfig(self.label));
            }
            let bytes = read_bounded(&self.file, self.max_bytes, self.label)?;
            if Sha256::digest(&bytes).as_slice() != self.digest || bytes != self.bytes {
                return Err(NodeError::InvalidConfig(self.label));
            }
            Ok(())
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct DirectoryGuard {
    path: PathBuf,
    identity: FileIdentity,
    label: &'static str,
}

impl DirectoryGuard {
    pub(crate) fn validate(path: &Path, label: &'static str) -> Result<Self> {
        #[cfg(not(unix))]
        {
            let _ = (path, label);
            return Err(NodeError::UnsupportedPlatform);
        }
        #[cfg(unix)]
        {
            require_normalized_absolute(path, label)?;
            let metadata = fs::symlink_metadata(path).map_err(|_| NodeError::FileIo(label))?;
            let identity = validate_private_directory(&metadata, label)?;
            if fs::canonicalize(path).map_err(|_| NodeError::FileIo(label))? != path {
                return Err(NodeError::InvalidConfig(label));
            }
            validate_ancestry(path, label)?;
            Ok(Self {
                path: path.to_path_buf(),
                identity,
                label,
            })
        }
    }

    pub(crate) fn revalidate(&self) -> Result<()> {
        #[cfg(not(unix))]
        {
            Err(NodeError::UnsupportedPlatform)
        }
        #[cfg(unix)]
        {
            let metadata = fs::symlink_metadata(&self.path).map_err(|_| NodeError::FileIo(self.label))?;
            if validate_private_directory(&metadata, self.label)? != self.identity
                || fs::canonicalize(&self.path).map_err(|_| NodeError::FileIo(self.label))? != self.path
            {
                return Err(NodeError::InvalidConfig(self.label));
            }
            validate_ancestry(&self.path, self.label)
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct DatabasePath {
    path: PathBuf,
    parent: DirectoryGuard,
    initial_identity: Option<FileIdentity>,
}

impl DatabasePath {
    pub(crate) fn validate(path: &Path) -> Result<Self> {
        require_leaf_path(path, "database path")?;
        let file_name = path
            .file_name()
            .and_then(|value| value.to_str())
            .ok_or(NodeError::InvalidConfig("database path"))?;
        if file_name == ":memory:" || file_name.starts_with("file:") || file_name.contains("mode=memory") {
            return Err(NodeError::InvalidConfig("database path"));
        }
        let parent_path = path.parent().ok_or(NodeError::InvalidConfig("database path"))?;
        let parent = DirectoryGuard::validate(parent_path, "database parent")?;
        let initial_identity = existing_private_regular_file(path, "database file")?;
        Ok(Self {
            path: path.to_path_buf(),
            parent,
            initial_identity,
        })
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    pub(crate) fn lock_path(&self) -> Result<PathBuf> {
        database_lock_path(&self.path)
    }

    pub(crate) fn revalidate_before_open(&self) -> Result<()> {
        self.parent.revalidate()?;
        let current = existing_private_regular_file(&self.path, "database file")?;
        if current != self.initial_identity {
            return Err(NodeError::InvalidConfig("database file identity changed"));
        }
        Ok(())
    }

    pub(crate) fn revalidate_after_open(&self) -> Result<()> {
        self.parent.revalidate()?;
        let current = existing_private_regular_file(&self.path, "database file")?
            .ok_or(NodeError::InvalidConfig("database file is missing after open"))?;
        if self.initial_identity.is_some_and(|expected| expected != current) {
            return Err(NodeError::InvalidConfig("database file identity changed during open"));
        }
        Ok(())
    }

    fn parent(&self) -> &DirectoryGuard {
        &self.parent
    }
}

pub(crate) struct DatabaseLease {
    file: File,
    path: PathBuf,
    identity: FileIdentity,
}

impl DatabaseLease {
    pub(crate) fn acquire(database: &DatabasePath) -> Result<Self> {
        #[cfg(not(unix))]
        {
            let _ = database;
            return Err(NodeError::UnsupportedPlatform);
        }
        #[cfg(unix)]
        {
            database.parent().revalidate()?;
            let path = database_lock_path(database.path())?;
            let descriptor = rustix::fs::open(
                &path,
                rustix::fs::OFlags::CREATE
                    | rustix::fs::OFlags::RDWR
                    | rustix::fs::OFlags::CLOEXEC
                    | rustix::fs::OFlags::NOFOLLOW,
                rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
            )
            .map_err(|_| NodeError::FileIo("database ownership lock"))?;
            let file = File::from(descriptor);
            let metadata = file
                .metadata()
                .map_err(|_| NodeError::FileIo("database ownership lock"))?;
            let identity = validate_private_file(&metadata, "database ownership lock")?;
            rustix::fs::flock(&file, rustix::fs::FlockOperation::NonBlockingLockExclusive)
                .map_err(|_| NodeError::InvalidConfig("database is already owned by another Floor node"))?;
            let lease = Self { file, path, identity };
            lease.revalidate()?;
            Ok(lease)
        }
    }

    pub(crate) fn revalidate(&self) -> Result<()> {
        #[cfg(not(unix))]
        {
            Err(NodeError::UnsupportedPlatform)
        }
        #[cfg(unix)]
        {
            let descriptor = self
                .file
                .metadata()
                .map_err(|_| NodeError::FileIo("database ownership lock"))?;
            let path = fs::symlink_metadata(&self.path).map_err(|_| NodeError::FileIo("database ownership lock"))?;
            if validate_private_file(&descriptor, "database ownership lock")? != self.identity
                || path.file_type().is_symlink()
                || validate_private_file(&path, "database ownership lock")? != self.identity
            {
                return Err(NodeError::InvalidConfig("database ownership lock identity"));
            }
            Ok(())
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct UnixSocketPath {
    path: PathBuf,
    parent: DirectoryGuard,
}

impl UnixSocketPath {
    pub(crate) fn validate(path: &Path) -> Result<Self> {
        require_leaf_path(path, "Unix socket path")?;
        let parent = DirectoryGuard::validate(
            path.parent().ok_or(NodeError::InvalidConfig("Unix socket path"))?,
            "Unix socket parent",
        )?;
        validate_existing_socket(path)?;
        Ok(Self {
            path: path.to_path_buf(),
            parent,
        })
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    pub(crate) fn revalidate(&self) -> Result<()> {
        self.parent.revalidate()?;
        validate_existing_socket(&self.path)
    }
}

fn require_leaf_path(path: &Path, label: &'static str) -> Result<()> {
    require_normalized_absolute(path, label)?;
    if path.file_name().is_none() {
        return Err(NodeError::InvalidConfig(label));
    }
    Ok(())
}

fn database_lock_path(database: &Path) -> Result<PathBuf> {
    let name = database.file_name().ok_or(NodeError::InvalidConfig("database path"))?;
    let mut lock_name = OsString::from(name);
    lock_name.push(".floor-node.lock");
    Ok(database.with_file_name(lock_name))
}

fn require_normalized_absolute(path: &Path, label: &'static str) -> Result<()> {
    if !path.is_absolute()
        || path.as_os_str().is_empty()
        || path
            .components()
            .any(|component| !matches!(component, Component::RootDir | Component::Normal(_)))
    {
        return Err(NodeError::InvalidConfig(label));
    }
    Ok(())
}

#[cfg(unix)]
fn validate_private_file(metadata: &fs::Metadata, label: &'static str) -> Result<FileIdentity> {
    let uid = rustix::process::geteuid().as_raw();
    let mode = metadata.permissions().mode();
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.uid() != uid
        || metadata.nlink() != 1
        || mode & 0o077 != 0
        || mode & 0o400 == 0
    {
        return Err(NodeError::InvalidConfig(label));
    }
    Ok(FileIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
        uid,
    })
}

#[cfg(unix)]
fn validate_private_directory(metadata: &fs::Metadata, label: &'static str) -> Result<FileIdentity> {
    let uid = rustix::process::geteuid().as_raw();
    let mode = metadata.permissions().mode();
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != uid
        || mode & 0o077 != 0
        || mode & 0o700 != 0o700
    {
        return Err(NodeError::InvalidConfig(label));
    }
    Ok(FileIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
        uid,
    })
}

#[cfg(unix)]
fn validate_ancestry(path: &Path, label: &'static str) -> Result<()> {
    let uid = rustix::process::geteuid().as_raw();
    for ancestor in path.ancestors() {
        let metadata = fs::symlink_metadata(ancestor).map_err(|_| NodeError::FileIo(label))?;
        let mode = metadata.permissions().mode();
        if !metadata.is_dir()
            || metadata.file_type().is_symlink()
            || (metadata.uid() != 0 && metadata.uid() != uid)
            || (mode & 0o022 != 0 && mode & 0o1000 == 0)
        {
            return Err(NodeError::InvalidConfig(label));
        }
    }
    Ok(())
}

#[cfg(unix)]
fn read_bounded(file: &File, max_bytes: usize, label: &'static str) -> Result<Vec<u8>> {
    let metadata = file.metadata().map_err(|_| NodeError::FileIo(label))?;
    let length = usize::try_from(metadata.len()).map_err(|_| NodeError::InvalidConfig(label))?;
    if length == 0 || length > max_bytes {
        return Err(NodeError::InvalidConfig(label));
    }
    let mut bytes = vec![0_u8; length];
    let mut offset = 0_usize;
    while offset < length {
        let read = file
            .read_at(
                &mut bytes[offset..],
                u64::try_from(offset).map_err(|_| NodeError::InvalidConfig(label))?,
            )
            .map_err(|_| NodeError::FileIo(label))?;
        if read == 0 {
            return Err(NodeError::FileIo(label));
        }
        offset = offset.checked_add(read).ok_or(NodeError::InvalidConfig(label))?;
    }
    if file.metadata().map_err(|_| NodeError::FileIo(label))?.len() != metadata.len() {
        return Err(NodeError::InvalidConfig(label));
    }
    Ok(bytes)
}

#[cfg(unix)]
fn existing_private_regular_file(path: &Path, label: &'static str) -> Result<Option<FileIdentity>> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => validate_private_file(&metadata, label).map(Some),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(_) => Err(NodeError::FileIo(label)),
    }
}

#[cfg(not(unix))]
fn existing_private_regular_file(_path: &Path, _label: &'static str) -> Result<Option<FileIdentity>> {
    Err(NodeError::UnsupportedPlatform)
}

fn validate_existing_socket(path: &Path) -> Result<()> {
    #[cfg(not(unix))]
    {
        let _ = path;
        Err(NodeError::UnsupportedPlatform)
    }
    #[cfg(unix)]
    {
        match fs::symlink_metadata(path) {
            Ok(metadata) => {
                let uid = rustix::process::geteuid().as_raw();
                if !metadata.file_type().is_socket()
                    || metadata.uid() != uid
                    || metadata.nlink() != 1
                    || metadata.permissions().mode() & 0o077 != 0
                {
                    return Err(NodeError::InvalidConfig("Unix socket leaf"));
                }
                Ok(())
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(_) => Err(NodeError::FileIo("Unix socket leaf")),
        }
    }
}
