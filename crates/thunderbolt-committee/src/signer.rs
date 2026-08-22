use std::error::Error;
use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::types::append_bytes;
use crate::{CommitteeEpoch, CommitteeError, CommitteeId, CommitteeMemberId, Result};

/// Maximum encoded public nonce commitment accepted from a future signer.
pub const MAX_NONCE_COMMITMENT_BYTES: usize = 4 * 1024;
const MAX_COORDINATOR_SESSION_ID_BYTES: usize = 128;

/// Domain-separated identifier for one committee signing attempt.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SignerSessionId([u8; 32]);

impl SignerSessionId {
    pub(crate) const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the canonical session digest.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for SignerSessionId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_hex(&self.0, formatter)
    }
}

impl fmt::Display for SignerSessionId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_hex(&self.0, formatter)
    }
}

/// Exact public binding for one future threshold-signing attempt.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignerSessionBinding {
    session_id: SignerSessionId,
    descriptor_id: CommitteeId,
    epoch: CommitteeEpoch,
    member_id: CommitteeMemberId,
    message_digest: [u8; 32],
    coordinator_session_digest: [u8; 32],
}

impl SignerSessionBinding {
    /// Derives a session from committee identity, message, and a unique
    /// coordinator-supplied session identifier.
    pub fn new(
        descriptor_id: CommitteeId,
        epoch: CommitteeEpoch,
        member_id: CommitteeMemberId,
        message_digest: [u8; 32],
        coordinator_session_id: impl AsRef<[u8]>,
    ) -> Result<Self> {
        let coordinator_session_id = coordinator_session_id.as_ref();
        if coordinator_session_id.is_empty() || coordinator_session_id.len() > MAX_COORDINATOR_SESSION_ID_BYTES {
            return Err(CommitteeError::SigningSessionMismatch);
        }
        let mut coordinator_hasher = Sha256::new();
        append_bytes(
            &mut coordinator_hasher,
            b"bitcoin-thunderbolt/signer/coordinator-session/v1",
        );
        append_bytes(&mut coordinator_hasher, coordinator_session_id);
        let coordinator_session_digest: [u8; 32] = coordinator_hasher.finalize().into();

        let mut hasher = Sha256::new();
        append_bytes(&mut hasher, b"bitcoin-thunderbolt/signer-session/v1");
        hasher.update(descriptor_id.as_bytes());
        hasher.update(epoch.get().to_be_bytes());
        hasher.update(member_id.get().to_be_bytes());
        hasher.update(message_digest);
        hasher.update(coordinator_session_digest);
        let session_id = SignerSessionId::from_bytes(hasher.finalize().into());
        Ok(Self {
            session_id,
            descriptor_id,
            epoch,
            member_id,
            message_digest,
            coordinator_session_digest,
        })
    }

    /// Returns the derived session identifier.
    #[must_use]
    pub const fn session_id(&self) -> SignerSessionId {
        self.session_id
    }

    /// Returns the exact committee descriptor identifier.
    #[must_use]
    pub const fn descriptor_id(&self) -> CommitteeId {
        self.descriptor_id
    }

    /// Returns the exact committee epoch.
    #[must_use]
    pub const fn epoch(&self) -> CommitteeEpoch {
        self.epoch
    }

    /// Returns the exact local member identifier.
    #[must_use]
    pub const fn member_id(&self) -> CommitteeMemberId {
        self.member_id
    }

    /// Returns the exact message digest.
    #[must_use]
    pub const fn message_digest(&self) -> &[u8; 32] {
        &self.message_digest
    }

    /// Returns the hashed coordinator session identifier.
    #[must_use]
    pub const fn coordinator_session_digest(&self) -> &[u8; 32] {
        &self.coordinator_session_digest
    }

    pub(crate) const fn from_parts(
        session_id: SignerSessionId,
        descriptor_id: CommitteeId,
        epoch: CommitteeEpoch,
        member_id: CommitteeMemberId,
        message_digest: [u8; 32],
        coordinator_session_digest: [u8; 32],
    ) -> Self {
        Self {
            session_id,
            descriptor_id,
            epoch,
            member_id,
            message_digest,
            coordinator_session_digest,
        }
    }
}

/// Bounded public nonce commitment produced by a future threshold signer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NonceCommitment(Vec<u8>);

impl NonceCommitment {
    /// Accepts a non-empty, bounded canonical signer-specific commitment.
    pub fn new(bytes: Vec<u8>) -> Result<Self> {
        if bytes.is_empty() || bytes.len() > MAX_NONCE_COMMITMENT_BYTES {
            return Err(CommitteeError::InvalidNonceCommitment);
        }
        Ok(Self(bytes))
    }

    /// Returns the public commitment bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub(crate) fn digest(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        append_bytes(&mut hasher, b"bitcoin-thunderbolt/signer-nonce-commitment/v1");
        append_bytes(&mut hasher, &self.0);
        hasher.finalize().into()
    }
}

/// Durable, fail-closed phase of a signing session.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignerSessionPhase {
    /// The session identifier was persisted before asking for a nonce.
    Reserved,
    /// The public nonce commitment was persisted.
    NonceCommitted {
        /// Domain-separated hash of the signer-specific commitment bytes.
        commitment_digest: [u8; 32],
    },
    /// The nonce was durably burned before asking the signer for a share.
    Consumed {
        /// Domain-separated hash of the signer-specific commitment bytes.
        commitment_digest: [u8; 32],
    },
}

/// Fail-closed adapter for a future audited threshold signer.
///
/// This trait deliberately exposes no aggregation or finalization method. The
/// signer implementation owns its secret nonce and signature-share types. It
/// must key nonce storage by [`SignerSessionBinding::session_id`], persist the
/// nonce before returning from `reserve_nonce`, and delete/burn it during
/// `sign_share`. The engine marks the session consumed *before* calling
/// `sign_share`; a crash can lose liveness but cannot authorize a retry.
pub trait CommitteeSigner {
    /// Protocol-specific signing package (for example, a future FROST package).
    type SigningPackage;
    /// Protocol-specific signature share. There is intentionally no aggregate.
    type SignatureShare;
    /// Backend-specific error that never formats nonce or key material.
    type Error: Error + Send + Sync + 'static;

    /// Generates and durably reserves one secret nonce, returning only its
    /// public commitment.
    fn reserve_nonce(&mut self, binding: &SignerSessionBinding) -> std::result::Result<NonceCommitment, Self::Error>;

    /// Consumes the previously reserved nonce and returns one signature share.
    fn sign_share(
        &mut self,
        binding: &SignerSessionBinding,
        package: &Self::SigningPackage,
    ) -> std::result::Result<Self::SignatureShare, Self::Error>;
}

fn write_hex(bytes: &[u8], formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for byte in bytes {
        formatter.write_str(&String::from_iter([
            char::from(HEX[usize::from(byte >> 4)]),
            char::from(HEX[usize::from(byte & 0x0f)]),
        ]))?;
    }
    Ok(())
}
