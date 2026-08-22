use std::future::Future;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::pin::Pin;

use zeroize::Zeroize;

use crate::CredentialError;

/// Maximum accepted Bitcoin Core cookie size.
const MAX_COOKIE_BYTES: usize = 4_096;
const MAX_COOKIE_READ_BYTES: u64 = 4_097;

/// A boxed credential-provider operation.
pub type CredentialProviderFuture<'a> =
    Pin<Box<dyn Future<Output = std::result::Result<RpcCredentials, CredentialError>> + Send + 'a>>;

/// Supplies short-lived Bitcoin Core credentials to the HTTP transport.
///
/// Implementations should acquire credentials for every request so an external
/// secret manager or Bitcoin Core cookie rotation takes effect without a
/// process restart. Implementations must not log credential values.
pub trait CredentialProvider: Send + Sync {
    /// Returns credentials for one RPC attempt.
    fn credentials(&self) -> CredentialProviderFuture<'_>;
}

/// A username/password pair whose contents are zeroed on drop.
///
/// This type intentionally does not implement `Debug` or `Display`.
pub struct RpcCredentials {
    username: String,
    password: String,
}

impl RpcCredentials {
    /// Creates a credential pair for an external provider.
    pub fn new(username: String, password: String) -> std::result::Result<Self, CredentialError> {
        let credentials = Self { username, password };
        validate_component(&credentials.username)?;
        validate_component(&credentials.password)?;
        Ok(credentials)
    }

    pub(crate) fn username(&self) -> &str {
        &self.username
    }

    pub(crate) fn password(&self) -> &str {
        &self.password
    }
}

impl Drop for RpcCredentials {
    fn drop(&mut self) {
        self.username.zeroize();
        self.password.zeroize();
    }
}

fn validate_component(value: &str) -> std::result::Result<(), CredentialError> {
    if value.is_empty() || value.bytes().any(|byte| byte.is_ascii_control()) {
        return Err(CredentialError::InvalidFormat);
    }
    Ok(())
}

/// Reads Bitcoin Core's rotating `.cookie` file on every request.
#[derive(Clone, Debug)]
pub struct CookieCredentialProvider {
    path: PathBuf,
}

impl CookieCredentialProvider {
    /// Creates a provider. Security checks happen on every read to avoid
    /// time-of-check/time-of-use gaps across cookie rotations.
    #[must_use]
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    /// Cookie path, for operator diagnostics. Cookie contents are never exposed.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    #[cfg(unix)]
    fn read_securely(&self) -> std::result::Result<RpcCredentials, CredentialError> {
        use std::fs::OpenOptions;
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

        let before = std::fs::symlink_metadata(&self.path)?;
        if before.file_type().is_symlink() || !before.file_type().is_file() {
            return Err(CredentialError::Insecure(
                "cookie must be a regular file, not a symlink",
            ));
        }
        if before.uid() != rustix::process::geteuid().as_raw() {
            return Err(CredentialError::Insecure("cookie must be owned by the effective user"));
        }
        let mode = before.mode();
        if mode & 0o400 == 0 || mode & 0o077 != 0 {
            return Err(CredentialError::Insecure(
                "cookie must be owner-readable and inaccessible to group and other users",
            ));
        }

        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(&self.path)?;
        let after = file.metadata()?;
        if !after.file_type().is_file() || before.dev() != after.dev() || before.ino() != after.ino() {
            return Err(CredentialError::Insecure("cookie changed while it was being opened"));
        }

        let mut bytes = Vec::new();
        file.by_ref().take(MAX_COOKIE_READ_BYTES).read_to_end(&mut bytes)?;
        if bytes.len() > MAX_COOKIE_BYTES {
            bytes.zeroize();
            return Err(CredentialError::InvalidFormat);
        }

        let parsed = parse_cookie(&bytes);
        bytes.zeroize();
        parsed
    }

    #[cfg(not(unix))]
    fn read_securely(&self) -> std::result::Result<RpcCredentials, CredentialError> {
        Err(CredentialError::UnsupportedPlatform)
    }
}

impl CredentialProvider for CookieCredentialProvider {
    fn credentials(&self) -> CredentialProviderFuture<'_> {
        Box::pin(std::future::ready(self.read_securely()))
    }
}

fn parse_cookie(bytes: &[u8]) -> std::result::Result<RpcCredentials, CredentialError> {
    let text = std::str::from_utf8(bytes).map_err(|_| CredentialError::InvalidFormat)?;
    let text = text
        .strip_suffix("\r\n")
        .or_else(|| text.strip_suffix('\n'))
        .unwrap_or(text);
    if text.contains('\r') || text.contains('\n') {
        return Err(CredentialError::InvalidFormat);
    }
    let (username, password) = text.split_once(':').ok_or(CredentialError::InvalidFormat)?;
    RpcCredentials::new(username.to_owned(), password.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_cookie_without_exposing_it_in_debug() -> std::result::Result<(), CredentialError> {
        let credentials = parse_cookie(b"__cookie__:secret\n")?;
        assert_eq!(credentials.username(), "__cookie__");
        assert_eq!(credentials.password(), "secret");
        Ok(())
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn requires_owner_only_regular_file() -> std::result::Result<(), Box<dyn std::error::Error>> {
        use std::os::unix::fs::{symlink, PermissionsExt};

        let directory = tempfile::tempdir()?;
        let path = directory.path().join(".cookie");
        std::fs::write(&path, b"__cookie__:secret")?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        let provider = CookieCredentialProvider::new(&path);
        provider.credentials().await?;

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640))?;
        assert!(matches!(
            provider.credentials().await,
            Err(CredentialError::Insecure(_))
        ));

        let link = directory.path().join("cookie-link");
        symlink(&path, &link)?;
        let linked = CookieCredentialProvider::new(link);
        assert!(matches!(linked.credentials().await, Err(CredentialError::Insecure(_))));
        Ok(())
    }
}
