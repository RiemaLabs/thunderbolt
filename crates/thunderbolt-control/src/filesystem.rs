use std::fs;
use std::os::unix::fs::{FileTypeExt as _, MetadataExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};

use crate::{ControlError, Result};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SocketIdentity {
    device: u64,
    inode: u64,
}

pub(crate) fn current_uid() -> u32 {
    rustix::process::geteuid().as_raw()
}

pub(crate) fn validate_private_parent(socket_path: &Path) -> Result<PathBuf> {
    if !socket_path.is_absolute() {
        return Err(ControlError::UnsafePath {
            path: socket_path.to_path_buf(),
            reason: "socket path must be absolute",
        });
    }
    let parent = socket_path
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .ok_or_else(|| ControlError::UnsafePath {
            path: socket_path.to_path_buf(),
            reason: "socket path must have an explicit parent directory",
        })?;
    let metadata = fs::symlink_metadata(parent).map_err(|source| ControlError::io("inspect socket parent", source))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(ControlError::UnsafePath {
            path: parent.to_path_buf(),
            reason: "socket parent must be a real directory, not a symlink",
        });
    }
    if metadata.uid() != current_uid() {
        return Err(ControlError::UnsafePath {
            path: parent.to_path_buf(),
            reason: "socket parent is not owned by the current UID",
        });
    }
    if metadata.permissions().mode() & 0o077 != 0 {
        return Err(ControlError::UnsafePath {
            path: parent.to_path_buf(),
            reason: "socket parent must not grant group or other permissions",
        });
    }
    let canonical =
        fs::canonicalize(parent).map_err(|source| ControlError::io("canonicalize socket parent", source))?;
    validate_canonical_ancestry(&canonical)?;
    Ok(canonical)
}

pub(crate) fn canonical_socket_path(socket_path: &Path) -> Result<PathBuf> {
    let file_name = socket_path.file_name().ok_or_else(|| ControlError::UnsafePath {
        path: socket_path.to_path_buf(),
        reason: "socket path must end in a filename",
    })?;
    Ok(validate_private_parent(socket_path)?.join(file_name))
}

fn validate_canonical_ancestry(parent: &Path) -> Result<()> {
    let effective_uid = current_uid();
    for ancestor in parent.ancestors() {
        let metadata = fs::symlink_metadata(ancestor)
            .map_err(|source| ControlError::io("inspect canonical socket ancestry", source))?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(ControlError::UnsafePath {
                path: ancestor.to_path_buf(),
                reason: "canonical socket ancestry contains a symlink or non-directory",
            });
        }
        if metadata.uid() != 0 && metadata.uid() != effective_uid {
            return Err(ControlError::UnsafePath {
                path: ancestor.to_path_buf(),
                reason: "socket ancestry contains a directory owned by another UID",
            });
        }
        let mode = metadata.permissions().mode();
        if mode & 0o022 != 0 && mode & 0o1000 == 0 {
            return Err(ControlError::UnsafePath {
                path: ancestor.to_path_buf(),
                reason: "socket ancestry contains a renameable non-sticky directory",
            });
        }
    }
    Ok(())
}

pub(crate) fn inspect_socket(path: &Path) -> Result<Option<SocketIdentity>> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.file_type().is_socket() {
                return Err(ControlError::UnsafePath {
                    path: path.to_path_buf(),
                    reason: "existing socket path is not a real Unix socket",
                });
            }
            if metadata.uid() != current_uid() {
                return Err(ControlError::UnsafePath {
                    path: path.to_path_buf(),
                    reason: "existing socket is not owned by the current UID",
                });
            }
            if metadata.permissions().mode() & 0o077 != 0 {
                return Err(ControlError::UnsafePath {
                    path: path.to_path_buf(),
                    reason: "socket must not grant group or other permissions",
                });
            }
            Ok(Some(SocketIdentity {
                device: metadata.dev(),
                inode: metadata.ino(),
            }))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(source) => Err(ControlError::io("inspect socket path", source)),
    }
}

pub(crate) fn path_identity(path: &Path) -> Result<SocketIdentity> {
    let metadata = fs::symlink_metadata(path).map_err(|source| ControlError::io("inspect path identity", source))?;
    Ok(SocketIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    })
}

pub(crate) fn harden_socket(path: &Path) -> Result<SocketIdentity> {
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .map_err(|source| ControlError::io("set socket permissions", source))?;
    let identity = inspect_socket(path)?.ok_or_else(|| ControlError::UnsafePath {
        path: path.to_path_buf(),
        reason: "newly bound socket disappeared",
    })?;
    let metadata = fs::symlink_metadata(path).map_err(|source| ControlError::io("verify socket", source))?;
    if metadata.permissions().mode() & 0o077 != 0 {
        return Err(ControlError::UnsafePath {
            path: path.to_path_buf(),
            reason: "socket permissions are not owner-only",
        });
    }
    Ok(identity)
}

pub(crate) fn inspect_newly_bound_socket(path: &Path) -> Result<SocketIdentity> {
    let metadata =
        fs::symlink_metadata(path).map_err(|source| ControlError::io("inspect newly bound socket", source))?;
    if metadata.file_type().is_symlink() || !metadata.file_type().is_socket() || metadata.uid() != current_uid() {
        return Err(ControlError::UnsafePath {
            path: path.to_path_buf(),
            reason: "newly bound socket type or owner differs",
        });
    }
    Ok(SocketIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    })
}

pub(crate) fn remove_if_same_newly_bound_socket(path: &Path, expected: SocketIdentity) -> Result<bool> {
    let current = match fs::symlink_metadata(path) {
        Ok(_) => inspect_newly_bound_socket(path)?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(source) => return Err(ControlError::io("inspect newly bound socket for removal", source)),
    };
    if current != expected {
        return Err(ControlError::UnsafePath {
            path: path.to_path_buf(),
            reason: "newly bound socket identity changed before removal",
        });
    }
    fs::remove_file(path).map_err(|source| ControlError::io("remove newly bound socket", source))?;
    Ok(true)
}

pub(crate) fn remove_if_same_socket(path: &Path, expected: SocketIdentity) -> Result<bool> {
    let Some(current) = inspect_socket(path)? else {
        return Ok(false);
    };
    if current != expected {
        return Err(ControlError::UnsafePath {
            path: path.to_path_buf(),
            reason: "socket identity changed before removal",
        });
    }
    fs::remove_file(path).map_err(|source| ControlError::io("remove stale socket", source))?;
    Ok(true)
}
