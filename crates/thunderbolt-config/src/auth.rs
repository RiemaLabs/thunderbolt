use crate::config::{AuthConfig, TokenScope};
use crate::error::AuthError;
use std::fs::{File, OpenOptions};
use std::io::Read;
use std::path::Path;
use subtle::{Choice, ConstantTimeEq};
use zeroize::Zeroizing;

/// Minimum accepted bearer-token length in bytes.
pub const MIN_TOKEN_BYTES: usize = 32;
/// Maximum accepted bearer-token length in bytes.
pub const MAX_TOKEN_BYTES: usize = 512;

/// Public identity and privileges associated with an authenticated token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthIdentity {
    pub id: String,
    pub scopes: std::collections::BTreeSet<TokenScope>,
}

impl AuthIdentity {
    pub fn allows(&self, required: TokenScope) -> bool {
        self.scopes.iter().copied().any(|granted| granted.allows(required))
    }
}

struct LoadedToken {
    identity: AuthIdentity,
    bytes: Zeroizing<[u8; MAX_TOKEN_BYTES]>,
    len: usize,
}

/// In-memory bearer tokens loaded from owner-only local files.
///
/// The type deliberately does not implement `Debug` or `Clone`, which avoids
/// accidentally copying or formatting token material.
pub struct TokenStore {
    tokens: Vec<LoadedToken>,
}

impl TokenStore {
    /// Loads every configured token, checking file type and Unix mode first.
    pub fn load(config: &AuthConfig) -> Result<Self, AuthError> {
        if !config.enabled {
            return Ok(Self { tokens: Vec::new() });
        }

        let mut tokens = Vec::with_capacity(config.tokens.len());
        for configured in &config.tokens {
            let bytes = load_token_file(&configured.token_file, &configured.id)?;
            let len = bytes.len();
            let mut padded = Zeroizing::new([0_u8; MAX_TOKEN_BYTES]);
            padded[..len].copy_from_slice(&bytes);
            if let Some(existing) = tokens.iter().find(|existing: &&LoadedToken| {
                existing.len == len && bool::from(existing.bytes.as_ref().ct_eq(padded.as_ref()))
            }) {
                return Err(AuthError::DuplicateToken {
                    first_id: existing.identity.id.clone(),
                    second_id: configured.id.clone(),
                });
            }
            tokens.push(LoadedToken {
                identity: AuthIdentity {
                    id: configured.id.clone(),
                    scopes: configured.scopes.clone(),
                },
                bytes: padded,
                len,
            });
        }
        Ok(Self { tokens })
    }

    /// Verifies a presented bearer token and returns only its public identity.
    ///
    /// Every stored token is compared using a fixed-size, constant-time primitive;
    /// the method does not stop at the first match.
    pub fn authenticate(&self, presented: &[u8]) -> Option<AuthIdentity> {
        let mut candidate = Zeroizing::new([0_u8; MAX_TOKEN_BYTES]);
        let copied = presented.len().min(MAX_TOKEN_BYTES);
        candidate[..copied].copy_from_slice(&presented[..copied]);

        let valid_length =
            Choice::from((presented.len() >= MIN_TOKEN_BYTES && presented.len() <= MAX_TOKEN_BYTES) as u8);
        let visible_ascii = Choice::from(
            presented
                .iter()
                .take(MAX_TOKEN_BYTES)
                .fold(true, |valid, byte| valid & byte.is_ascii_graphic()) as u8,
        );

        let mut matched = None;
        for token in &self.tokens {
            let contents_match = token.bytes.as_ref().ct_eq(candidate.as_ref());
            let lengths_match = token.len.ct_eq(&presented.len());
            let is_match = contents_match & lengths_match & valid_length & visible_ascii;
            if bool::from(is_match) {
                matched = Some(token.identity.clone());
            }
        }
        matched
    }

    /// Authenticates and checks the requested privilege in one operation.
    pub fn authorize(&self, presented: &[u8], required: TokenScope) -> bool {
        self.authenticate(presented)
            .is_some_and(|identity| identity.allows(required))
    }

    /// Number of configured credentials. Token material is never exposed.
    pub fn len(&self) -> usize {
        self.tokens.len()
    }

    pub fn is_empty(&self) -> bool {
        self.tokens.is_empty()
    }
}

fn load_token_file(path: &Path, token_id: &str) -> Result<Zeroizing<Vec<u8>>, AuthError> {
    let file = open_token_file(path, token_id)?;
    let metadata = file.metadata().map_err(|source| AuthError::Metadata {
        token_id: token_id.to_owned(),
        source,
    })?;
    if !metadata.file_type().is_file() {
        return Err(AuthError::NotRegularFile {
            token_id: token_id.to_owned(),
        });
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = metadata.permissions().mode() & 0o777;
        if !matches!(mode, 0o400 | 0o600) {
            return Err(AuthError::InsecurePermissions {
                token_id: token_id.to_owned(),
                mode,
            });
        }
    }

    let mut bytes = Zeroizing::new(Vec::with_capacity(MAX_TOKEN_BYTES + 2));
    file.take((MAX_TOKEN_BYTES + 2) as u64)
        .read_to_end(&mut bytes)
        .map_err(|source| AuthError::Read {
            token_id: token_id.to_owned(),
            source,
        })?;
    if bytes.ends_with(b"\n") {
        bytes.pop();
        if bytes.ends_with(b"\r") {
            bytes.pop();
        }
    }
    if bytes.len() < MIN_TOKEN_BYTES {
        return Err(AuthError::InvalidToken {
            token_id: token_id.to_owned(),
            reason: "token is shorter than 32 bytes",
        });
    }
    if bytes.len() > MAX_TOKEN_BYTES {
        return Err(AuthError::InvalidToken {
            token_id: token_id.to_owned(),
            reason: "token is longer than 512 bytes",
        });
    }
    if !bytes.iter().all(u8::is_ascii_graphic) {
        return Err(AuthError::InvalidToken {
            token_id: token_id.to_owned(),
            reason: "token must contain only visible ASCII bytes",
        });
    }
    Ok(bytes)
}

fn open_token_file(path: &Path, token_id: &str) -> Result<File, AuthError> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    }
    options.open(path).map_err(|source| {
        #[cfg(unix)]
        if source.raw_os_error() == Some(libc::ELOOP) {
            return AuthError::NotRegularFile {
                token_id: token_id.to_owned(),
            };
        }
        AuthError::Open {
            token_id: token_id.to_owned(),
            source,
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{TokenConfig, TokenScope};
    use std::collections::BTreeSet;
    use std::fs;
    use std::path::PathBuf;

    const TOKEN: &[u8] = b"d8d15118b8bdf414d9780eab6ee5cb9fe53949d5a4c168f70aceb913dd506c4c";

    fn auth_config(path: PathBuf) -> AuthConfig {
        AuthConfig {
            enabled: true,
            tokens: vec![TokenConfig {
                id: "operator".to_owned(),
                token_file: path,
                scopes: BTreeSet::from([TokenScope::Operator]),
            }],
        }
    }

    #[cfg(unix)]
    fn set_mode(path: &Path, mode: u32) {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).expect("set token mode");
    }

    #[test]
    #[cfg(unix)]
    fn loads_protected_file_and_checks_scope_hierarchy() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("operator.token");
        fs::write(&path, [TOKEN, b"\n"].concat()).expect("write token");
        set_mode(&path, 0o600);

        let store = TokenStore::load(&auth_config(path)).expect("token should load");
        let identity = store.authenticate(TOKEN).expect("token should authenticate");
        assert_eq!(identity.id, "operator");
        assert!(identity.allows(TokenScope::Read));
        assert!(identity.allows(TokenScope::Write));
        assert!(identity.allows(TokenScope::Operator));
        assert!(!identity.allows(TokenScope::Admin));
        assert!(store.authorize(TOKEN, TokenScope::Write));
        assert!(store.authenticate(b"not-the-right-token-not-even-close").is_none());
    }

    #[test]
    #[cfg(unix)]
    fn rejects_group_or_world_readable_token_file() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("operator.token");
        fs::write(&path, TOKEN).expect("write token");
        set_mode(&path, 0o640);

        let error = match TokenStore::load(&auth_config(path)) {
            Ok(_) => panic!("insecure mode must fail"),
            Err(error) => error,
        };
        assert!(matches!(error, AuthError::InsecurePermissions { mode: 0o640, .. }));
    }

    #[test]
    #[cfg(unix)]
    fn rejects_symlinked_token_file() {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir().expect("temporary directory");
        let target = directory.path().join("target.token");
        let link = directory.path().join("operator.token");
        fs::write(&target, TOKEN).expect("write token");
        set_mode(&target, 0o600);
        symlink(&target, &link).expect("make symlink");

        let error = match TokenStore::load(&auth_config(link)) {
            Ok(_) => panic!("symlink must fail"),
            Err(error) => error,
        };
        assert!(matches!(error, AuthError::NotRegularFile { .. }));
    }

    #[test]
    #[cfg(unix)]
    fn mismatched_values_and_lengths_never_authenticate() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("operator.token");
        fs::write(&path, TOKEN).expect("write token");
        set_mode(&path, 0o400);
        let store = TokenStore::load(&auth_config(path)).expect("token should load");

        let mut wrong = TOKEN.to_vec();
        wrong[TOKEN.len() - 1] ^= 1;
        assert!(store.authenticate(&wrong).is_none());
        assert!(store.authenticate(&TOKEN[..TOKEN.len() - 1]).is_none());
        assert!(store.authenticate(&[b'x'; MAX_TOKEN_BYTES + 1]).is_none());
    }

    #[test]
    #[cfg(unix)]
    fn rejects_duplicate_token_contents_across_identities() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let reader_path = directory.path().join("reader.token");
        let admin_path = directory.path().join("admin.token");
        fs::write(&reader_path, TOKEN).expect("write reader token");
        fs::write(&admin_path, TOKEN).expect("write admin token");
        set_mode(&reader_path, 0o600);
        set_mode(&admin_path, 0o600);
        let config = AuthConfig {
            enabled: true,
            tokens: vec![
                TokenConfig {
                    id: "reader".to_owned(),
                    token_file: reader_path,
                    scopes: BTreeSet::from([TokenScope::Read]),
                },
                TokenConfig {
                    id: "administrator".to_owned(),
                    token_file: admin_path,
                    scopes: BTreeSet::from([TokenScope::Admin]),
                },
            ],
        };

        let error = match TokenStore::load(&config) {
            Ok(_) => panic!("duplicate token contents must fail"),
            Err(error) => error,
        };
        assert!(matches!(
            error,
            AuthError::DuplicateToken {
                first_id,
                second_id
            } if first_id == "reader" && second_id == "administrator"
        ));
    }
}
