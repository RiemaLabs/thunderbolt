use std::fmt;
use std::fs::{self, Metadata, OpenOptions};
use std::io::Read as _;
use std::path::Path;
use std::sync::Arc;

#[cfg(unix)]
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};

use rustls::client::ResolvesClientCert;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::sign::CertifiedKey;
use thunderbolt_cometbft_client::PeerIdentity;
use zeroize::Zeroizing;

use crate::{Result, RpcTransportError};

const MAX_CERTIFICATE_PEM_BYTES: usize = 256 * 1024;
const MAX_PRIVATE_KEY_PEM_BYTES: usize = 64 * 1024;

/// Private-key boundary used while building an immutable HTTPS peer.
///
/// Implementations return a rustls resolver rather than raw key bytes. Peer
/// configuration therefore never owns or serializes a client private key.
pub trait ClientIdentityProvider: Send + Sync {
    /// Returns the client-certificate resolver authorized for `peer`.
    fn resolver(&self, peer: &PeerIdentity) -> Result<Arc<dyn ResolvesClientCert>>;
}

/// Client identity loaded once from owner-private PEM files.
///
/// Both paths must be absolute and reside in an owner-only canonical Unix
/// directory. Opens use `O_NOFOLLOW`; the key file must be owner-readable,
/// non-executable, and have no group/other permissions (normally `0400` or
/// `0600`). It is read through a zeroizing buffer. This type has a redacted
/// `Debug` and no serialization implementation.
pub struct OwnerOnlyPemClientIdentity {
    resolver: Arc<dyn ResolvesClientCert>,
}

impl OwnerOnlyPemClientIdentity {
    /// Loads a certificate chain and matching private key from protected files.
    pub fn load(certificate_path: impl AsRef<Path>, private_key_path: impl AsRef<Path>) -> Result<Self> {
        let certificate = read_protected(certificate_path.as_ref(), MAX_CERTIFICATE_PEM_BYTES, false)?;
        let private_key = read_protected(private_key_path.as_ref(), MAX_PRIVATE_KEY_PEM_BYTES, true)?;
        let mut certificate_reader = std::io::Cursor::new(certificate.as_slice());
        let certificates = rustls_pemfile::certs(&mut certificate_reader)
            .collect::<std::result::Result<Vec<CertificateDer<'static>>, _>>()
            .map_err(|_| RpcTransportError::Credential)?;
        if certificates.is_empty() || certificates.len() > 8 {
            return Err(RpcTransportError::Credential);
        }
        let mut key_reader = std::io::Cursor::new(private_key.as_slice());
        let key: PrivateKeyDer<'static> = rustls_pemfile::private_key(&mut key_reader)
            .map_err(|_| RpcTransportError::Credential)?
            .ok_or(RpcTransportError::Credential)?;
        let provider = rustls::crypto::CryptoProvider::get_default()
            .cloned()
            .unwrap_or_else(|| Arc::new(rustls::crypto::aws_lc_rs::default_provider()));
        let certified =
            CertifiedKey::from_der(certificates, key, &provider).map_err(|_| RpcTransportError::Credential)?;
        Ok(Self {
            resolver: Arc::new(StaticClientResolver {
                certified: Arc::new(certified),
            }),
        })
    }
}

impl ClientIdentityProvider for OwnerOnlyPemClientIdentity {
    fn resolver(&self, _peer: &PeerIdentity) -> Result<Arc<dyn ResolvesClientCert>> {
        Ok(Arc::clone(&self.resolver))
    }
}

impl fmt::Debug for OwnerOnlyPemClientIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("OwnerOnlyPemClientIdentity([redacted])")
    }
}

struct StaticClientResolver {
    certified: Arc<CertifiedKey>,
}

impl fmt::Debug for StaticClientResolver {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("StaticClientResolver([redacted])")
    }
}

impl ResolvesClientCert for StaticClientResolver {
    fn resolve(
        &self,
        _root_hint_subjects: &[&[u8]],
        _sigschemes: &[rustls::SignatureScheme],
    ) -> Option<Arc<CertifiedKey>> {
        Some(Arc::clone(&self.certified))
    }

    fn has_certs(&self) -> bool {
        true
    }
}

fn read_protected(path: &Path, maximum: usize, key: bool) -> Result<Zeroizing<Vec<u8>>> {
    validate_private_parent(path)?;
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    let mut file = options.open(path).map_err(|_| RpcTransportError::UnsafePath)?;
    let metadata = file.metadata().map_err(|_| RpcTransportError::UnsafePath)?;
    validate_file(&metadata, key)?;
    let length = usize::try_from(metadata.len()).map_err(|_| RpcTransportError::Credential)?;
    if length == 0 || length > maximum {
        return Err(RpcTransportError::Credential);
    }
    let read_limit = u64::try_from(maximum)
        .map_err(|_| RpcTransportError::Credential)?
        .checked_add(1)
        .ok_or(RpcTransportError::Credential)?;
    let mut bytes = Zeroizing::new(Vec::with_capacity(length));
    file.by_ref()
        .take(read_limit)
        .read_to_end(&mut bytes)
        .map_err(|_| RpcTransportError::Credential)?;
    if bytes.len() > maximum {
        return Err(RpcTransportError::Credential);
    }
    Ok(bytes)
}

fn validate_private_parent(path: &Path) -> Result<()> {
    if !path.is_absolute() {
        return Err(RpcTransportError::UnsafePath);
    }
    #[cfg(not(unix))]
    return Err(RpcTransportError::UnsafePath);
    #[cfg(unix)]
    {
        let parent = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .ok_or(RpcTransportError::UnsafePath)?;
        let metadata = fs::symlink_metadata(parent).map_err(|_| RpcTransportError::UnsafePath)?;
        let effective_uid = rustix::process::geteuid().as_raw();
        if metadata.file_type().is_symlink()
            || !metadata.is_dir()
            || metadata.uid() != effective_uid
            || metadata.permissions().mode() & 0o077 != 0
        {
            return Err(RpcTransportError::UnsafePath);
        }
        let canonical = fs::canonicalize(parent).map_err(|_| RpcTransportError::UnsafePath)?;
        for ancestor in canonical.ancestors() {
            let metadata = fs::symlink_metadata(ancestor).map_err(|_| RpcTransportError::UnsafePath)?;
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                return Err(RpcTransportError::UnsafePath);
            }
            if metadata.uid() != 0 && metadata.uid() != effective_uid {
                return Err(RpcTransportError::UnsafePath);
            }
            let mode = metadata.permissions().mode();
            if mode & 0o022 != 0 && mode & 0o1000 == 0 {
                return Err(RpcTransportError::UnsafePath);
            }
        }
        Ok(())
    }
}

fn validate_file(metadata: &Metadata, key: bool) -> Result<()> {
    if !metadata.is_file() {
        return Err(RpcTransportError::UnsafePath);
    }
    #[cfg(unix)]
    {
        let mode = metadata.permissions().mode();
        if metadata.uid() != rustix::process::geteuid().as_raw()
            || mode & 0o022 != 0
            || (key && mode & 0o077 != 0)
            || mode & 0o400 == 0
            || mode & 0o100 != 0
        {
            return Err(RpcTransportError::UnsafePath);
        }
    }
    Ok(())
}
