use std::error::Error;
use std::fmt;

use zeroize::Zeroizing;

/// Maximum decrypted committee vault payload accepted by the runtime.
pub const MAX_VAULT_PLAINTEXT_BYTES: usize = 128 * 1024 * 1024;

/// Error returned before an oversized decrypted vault payload is accepted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VaultPlaintextError {
    actual: usize,
}

impl VaultPlaintextError {
    /// Returns the rejected byte length.
    #[must_use]
    pub const fn actual(self) -> usize {
        self.actual
    }
}

impl fmt::Display for VaultPlaintextError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "decrypted vault payload contains {} bytes; maximum is {MAX_VAULT_PLAINTEXT_BYTES}",
            self.actual
        )
    }
}

impl Error for VaultPlaintextError {}

/// Opaque, zeroizing plaintext exchanged with an encrypted vault backend.
///
/// This type intentionally implements neither `Clone` nor `Debug`. A vault may
/// borrow the bytes only long enough to authenticate and encrypt them. It must
/// never write these bytes directly to durable storage or logs.
pub struct VaultPlaintext(Zeroizing<Vec<u8>>);

impl VaultPlaintext {
    /// Wraps a bounded decrypted payload and arranges to zeroize it on drop.
    pub fn from_secret_bytes(bytes: Vec<u8>) -> std::result::Result<Self, VaultPlaintextError> {
        if bytes.len() > MAX_VAULT_PLAINTEXT_BYTES {
            return Err(VaultPlaintextError { actual: bytes.len() });
        }
        Ok(Self(Zeroizing::new(bytes)))
    }

    pub(crate) fn from_zeroizing(bytes: Zeroizing<Vec<u8>>) -> std::result::Result<Self, VaultPlaintextError> {
        if bytes.len() > MAX_VAULT_PLAINTEXT_BYTES {
            return Err(VaultPlaintextError { actual: bytes.len() });
        }
        Ok(Self(bytes))
    }

    /// Explicitly borrows the secret payload for authenticated encryption or
    /// protocol-state decoding.
    #[must_use]
    pub fn expose_secret(&self) -> &[u8] {
        self.0.as_slice()
    }

    /// Returns the plaintext length without exposing its contents.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns whether the payload is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// One revisioned, decrypted entry returned by a committee vault.
///
/// The revision must be authenticated as associated data by the vault. The
/// entry intentionally implements neither `Clone` nor `Debug`.
pub struct VaultEntry {
    revision: u64,
    plaintext: VaultPlaintext,
}

impl VaultEntry {
    /// Creates a decrypted vault entry.
    #[must_use]
    pub const fn new(revision: u64, plaintext: VaultPlaintext) -> Self {
        Self { revision, plaintext }
    }

    /// Returns the authenticated compare-and-swap revision.
    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    /// Borrows the zeroizing decrypted payload.
    #[must_use]
    pub const fn plaintext(&self) -> &VaultPlaintext {
        &self.plaintext
    }

    /// Consumes the entry and returns its zeroizing payload.
    #[must_use]
    pub fn into_plaintext(self) -> VaultPlaintext {
        self.plaintext
    }
}

/// Failure returned by an atomic vault create or compare-and-swap operation.
#[derive(Debug)]
pub enum VaultStoreError<E> {
    /// The expected revision was absent or no longer current.
    Conflict {
        /// Authenticated revision observed by the vault, if initialized.
        current_revision: Option<u64>,
    },
    /// The backend failed. Its write outcome may be ambiguous.
    Backend(E),
}

impl<E> fmt::Display for VaultStoreError<E>
where
    E: fmt::Display,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Conflict { current_revision } => {
                write!(formatter, "vault revision conflict: current={current_revision:?}")
            }
            Self::Backend(error) => error.fmt(formatter),
        }
    }
}

impl<E> Error for VaultStoreError<E> where E: Error + 'static {}

/// Encrypted, authenticated, crash-safe storage for one committee member.
///
/// Implementations must:
///
/// - encrypt and authenticate every [`VaultPlaintext`] byte at rest;
/// - authenticate the revision and member-file identity as associated data;
/// - create without overwriting an existing record;
/// - make compare-and-swap replacement atomic across crashes;
/// - fsync the new file and its parent directory before reporting success; and
/// - hold an exclusive process lock for the lifetime of the implementation.
///
/// A backend error may occur after a durable rename. The engine therefore
/// becomes fail-closed and requires reopen after any backend write error.
pub trait CommitteeVault {
    /// Backend-specific error that never formats secret material.
    type Error: Error + Send + Sync + 'static;

    /// Loads and authenticates the current decrypted entry, if initialized.
    fn load(&mut self) -> std::result::Result<Option<VaultEntry>, Self::Error>;

    /// Atomically creates revision zero without overwriting an existing entry.
    fn create(&mut self, entry: VaultEntry) -> std::result::Result<(), VaultStoreError<Self::Error>>;

    /// Atomically replaces `expected_revision` with `entry`.
    fn compare_and_swap(
        &mut self,
        expected_revision: u64,
        entry: VaultEntry,
    ) -> std::result::Result<(), VaultStoreError<Self::Error>>;
}
