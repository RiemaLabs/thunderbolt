use std::fmt;
use std::fs::{self, Metadata, OpenOptions};
use std::io::Read as _;
use std::path::Path;
use std::sync::Arc;

#[cfg(unix)]
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};

use rustls::client::ResolvesClientCert;
use rustls::pki_types::{pem::PemObject as _, CertificateDer, PrivateKeyDer};
use rustls::sign::CertifiedKey;
use sha2::{Digest as _, Sha256};
use thunderbolt_cometbft_client::PeerIdentity;
use zeroize::Zeroizing;

use crate::{Result, RpcTransportError};

const MAX_CERTIFICATE_PEM_BYTES: usize = 256 * 1024;
const MAX_PRIVATE_KEY_PEM_BYTES: usize = 64 * 1024;
const CLIENT_CERTIFICATE_PROFILE_DOMAIN: &[u8] = b"bitcoin-thunderbolt/cometbft-rpc/client-certificate-profile/v1";
const PEER_CLIENT_PROFILE_DOMAIN: &[u8] = b"bitcoin-thunderbolt/cometbft-rpc/peer-client-profile/v1";

/// Private-key boundary used while building an immutable HTTPS peer.
///
/// Implementations return a rustls resolver rather than raw key bytes. Peer
/// configuration therefore never owns or serializes a client private key.
pub trait ClientIdentityProvider: Send + Sync {
    /// Atomically returns the expected public client profile and immutable
    /// resolver authorized for `peer`.
    fn binding(&self, peer: &PeerIdentity) -> Result<ClientIdentityBinding>;
}

/// Atomic public-profile and resolver binding from a client-identity provider.
pub struct ClientIdentityBinding {
    pub(crate) expected_profile: [u8; 32],
    pub(crate) resolver: Arc<dyn ResolvesClientCert>,
}

impl ClientIdentityBinding {
    /// Binds a resolver to the exact public certificate chain and certified-key
    /// SPKI it must return during every TLS handshake.
    pub fn new(
        peer: &PeerIdentity,
        certificate_chain: &[CertificateDer<'_>],
        certified_public_key_spki: &[u8],
        resolver: Arc<dyn ResolvesClientCert>,
    ) -> Result<Self> {
        if !resolver.has_certs() {
            return Err(RpcTransportError::Credential);
        }
        let expected_profile = certified_client_profile(peer, certificate_chain, certified_public_key_spki)?;
        if expected_profile == [0_u8; 32] {
            return Err(RpcTransportError::Credential);
        }
        Ok(Self {
            expected_profile,
            resolver,
        })
    }

    /// Returns the peer-bound expected public client profile.
    pub const fn expected_profile(&self) -> &[u8; 32] {
        &self.expected_profile
    }
}

impl fmt::Debug for ClientIdentityBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ClientIdentityBinding")
            .field("expected_profile", &self.expected_profile)
            .field("resolver", &"[redacted provider]")
            .finish()
    }
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
    certificates: Vec<CertificateDer<'static>>,
    certified_public_key_spki: Vec<u8>,
}

impl OwnerOnlyPemClientIdentity {
    /// Loads a certificate chain and matching private key from protected files.
    pub fn load(certificate_path: impl AsRef<Path>, private_key_path: impl AsRef<Path>) -> Result<Self> {
        let certificate = read_protected(certificate_path.as_ref(), MAX_CERTIFICATE_PEM_BYTES, false)?;
        let private_key = read_protected(private_key_path.as_ref(), MAX_PRIVATE_KEY_PEM_BYTES, true)?;
        let certificates = CertificateDer::pem_slice_iter(certificate.as_slice())
            .collect::<std::result::Result<Vec<CertificateDer<'static>>, _>>()
            .map_err(|_| RpcTransportError::Credential)?;
        if certificates.is_empty() || certificates.len() > 8 {
            return Err(RpcTransportError::Credential);
        }
        let key = PrivateKeyDer::from_pem_slice(private_key.as_slice()).map_err(|_| RpcTransportError::Credential)?;
        let provider = rustls::crypto::CryptoProvider::get_default()
            .cloned()
            .unwrap_or_else(|| Arc::new(rustls::crypto::aws_lc_rs::default_provider()));
        let certified =
            CertifiedKey::from_der(certificates, key, &provider).map_err(|_| RpcTransportError::Credential)?;
        certified.keys_match().map_err(|_| RpcTransportError::Credential)?;
        let public_key = certified.key.public_key().ok_or(RpcTransportError::Credential)?;
        let retained_certificates = certified.cert.clone();
        let certified_public_key_spki = public_key.as_ref().to_vec();
        Ok(Self {
            resolver: Arc::new(StaticClientResolver {
                certified: Arc::new(certified),
            }),
            certificates: retained_certificates,
            certified_public_key_spki,
        })
    }
}

impl ClientIdentityProvider for OwnerOnlyPemClientIdentity {
    fn binding(&self, peer: &PeerIdentity) -> Result<ClientIdentityBinding> {
        ClientIdentityBinding::new(
            peer,
            &self.certificates,
            &self.certified_public_key_spki,
            Arc::clone(&self.resolver),
        )
    }
}

pub(crate) fn certified_client_profile(
    peer: &PeerIdentity,
    certificates: &[CertificateDer<'_>],
    public_key: &[u8],
) -> Result<[u8; 32]> {
    if certificates.is_empty() || public_key.is_empty() {
        return Err(RpcTransportError::Credential);
    }
    let mut hasher = Sha256::new();
    hasher.update(CLIENT_CERTIFICATE_PROFILE_DOMAIN);
    hasher.update(
        u64::try_from(certificates.len())
            .map_err(|_| RpcTransportError::Credential)?
            .to_be_bytes(),
    );
    for certificate in certificates {
        hasher.update(
            u64::try_from(certificate.len())
                .map_err(|_| RpcTransportError::Credential)?
                .to_be_bytes(),
        );
        hasher.update(certificate.as_ref());
    }
    hasher.update(
        u64::try_from(public_key.len())
            .map_err(|_| RpcTransportError::Credential)?
            .to_be_bytes(),
    );
    hasher.update(public_key);
    let base: [u8; 32] = hasher.finalize().into();
    Ok(Sha256::new()
        .chain_update(PEER_CLIENT_PROFILE_DOMAIN)
        .chain_update(base)
        .chain_update(peer.transport_binding())
        .chain_update(peer.node_id().as_bytes())
        .finalize()
        .into())
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
