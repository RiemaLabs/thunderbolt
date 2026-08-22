use std::mem;
use std::path::Path;

use bitcoin::Network as BitcoinNetwork;
use sha2::{Digest, Sha256};
use thunderbolt_keystore::{
    CommitOutcome, CommitteeDescriptorDigest, CommitteeSessionNonce, DeploymentBinding, DeploymentId, ExpectedRecord,
    KdfParams, KeystoreError, Network, NodeId, Password, RecordKey, RecordNamespace, RecordStatus, RecordVersion,
    RecoveryVault, RollbackFloorStore, SecretValue, TransactionId, Vault, VaultCheckpoint, VaultIdentity,
    VaultRevision, VaultRole, MAX_RECORD_VALUE_BYTES,
};
use zeroize::Zeroizing;

use crate::types::append_bytes;
use crate::{
    CommitteeDescriptor, CommitteeMemberId, CommitteeVault, SignerSessionId, VaultEntry, VaultPlaintext,
    VaultStoreError,
};

const STATE_MAGIC: &[u8; 8] = b"TBCVST01";
const IDEMPOTENCY_MAGIC: &[u8; 8] = b"TBCVID01";
const ADAPTER_FORMAT_VERSION: u16 = 1;
const STATE_KEY_DOMAIN: &[u8] = b"bitcoin-thunderbolt/committee/keystore-state-key/v1";
const IDEMPOTENCY_KEY_DOMAIN: &[u8] = b"bitcoin-thunderbolt/committee/keystore-idempotency-key/v1";
const REQUEST_DOMAIN: &[u8] = b"bitcoin-thunderbolt/committee/keystore-request/v1";
const TRANSACTION_DOMAIN: &[u8] = b"bitcoin-thunderbolt/committee/keystore-transaction/v1";
const NODE_DOMAIN: &[u8] = b"bitcoin-thunderbolt/committee/keystore-node/v1";
const MAX_ADAPTER_ENGINE_BYTES: usize = MAX_RECORD_VALUE_BYTES - 128;

/// Fail-closed errors returned by the concrete encrypted committee vault.
#[derive(Debug, thiserror::Error)]
pub enum KeystoreCommitteeVaultError {
    /// The encrypted keystore rejected an operation.
    #[error("committee keystore operation failed: {0}")]
    Keystore(#[source] KeystoreError),

    /// The public committee descriptor cannot be represented by the keystore identity.
    #[error("committee descriptor is not a valid keystore identity")]
    InvalidIdentity,

    /// The authenticated keystore identity differs from the committee descriptor/member.
    #[error("committee keystore identity does not match the expected member binding")]
    IdentityMismatch,

    /// The independent rollback floor is missing, stale, ahead, or unavailable.
    #[error("committee rollback floor is unavailable or inconsistent")]
    FloorMismatch,

    /// The authenticated adapter record is malformed or contradicts its binding.
    #[error("committee keystore adapter record is invalid")]
    InvalidRecord,

    /// Engine and adapter compare-and-swap revisions are not consecutive.
    #[error("committee engine revision does not match the adapter CAS request")]
    RevisionMismatch,

    /// A write or floor result was ambiguous; the handle may no longer be used.
    #[error("committee keystore adapter is poisoned and must be reopened")]
    Poisoned,
}

/// Concrete [`CommitteeVault`] backed by `thunderbolt-keystore` transactions.
///
/// The adapter owns the raw keystore handle and the independent monotonic floor
/// capability. It exposes neither, preventing another component from advancing
/// the encrypted file without advancing the floor. The type intentionally
/// implements neither `Clone` nor `Debug`.
pub struct KeystoreCommitteeVault<F>
where
    F: RollbackFloorStore,
{
    vault: Option<Vault>,
    floor_store: F,
    descriptor_id: [u8; 32],
    member_id: CommitteeMemberId,
    identity: VaultIdentity,
    state_key: RecordKey,
    checkpoint: VaultCheckpoint,
    recovery_candidate: Option<VaultCheckpoint>,
    poisoned: bool,
}

impl<F> KeystoreCommitteeVault<F>
where
    F: RollbackFloorStore,
{
    /// Creates and locks an empty committee keystore. The engine must
    /// immediately provision its revision-zero record through
    /// [`CommitteeMemberEngine::provision`](crate::CommitteeMemberEngine::provision).
    pub fn create(
        path: impl AsRef<Path>,
        descriptor: &CommitteeDescriptor,
        member_id: CommitteeMemberId,
        password: Password,
        params: KdfParams,
        floor_store: F,
    ) -> std::result::Result<Self, KeystoreCommitteeVaultError> {
        let identity = committee_keystore_identity(descriptor, member_id)?;
        if floor_store
            .load_checkpoint(identity)
            .map_err(|_| KeystoreCommitteeVaultError::FloorMismatch)?
            .is_some()
        {
            return Err(KeystoreCommitteeVaultError::FloorMismatch);
        }
        let recovery =
            RecoveryVault::create(path, identity, password, params).map_err(KeystoreCommitteeVaultError::Keystore)?;
        let checkpoint = recovery.checkpoint();
        install_checkpoint(&floor_store, identity, None, checkpoint)?;
        let vault = recovery
            .anchor(&floor_store)
            .map_err(|_| KeystoreCommitteeVaultError::FloorMismatch)?;
        Self::from_parts(vault, descriptor, member_id, floor_store, checkpoint)
    }

    /// Opens a committee keystore at its independently authenticated floor.
    ///
    /// The encrypted file must match the exact external checkpoint. Ambiguous
    /// post-write recovery requires [`Self::reconcile_candidate`] with the
    /// candidate retained by the independent operation journal.
    pub fn open(
        path: impl AsRef<Path>,
        descriptor: &CommitteeDescriptor,
        member_id: CommitteeMemberId,
        password: Password,
        floor_store: F,
    ) -> std::result::Result<Self, KeystoreCommitteeVaultError> {
        let identity = committee_keystore_identity(descriptor, member_id)?;
        let trusted = floor_store
            .load_checkpoint(identity)
            .map_err(|_| KeystoreCommitteeVaultError::FloorMismatch)?
            .ok_or(KeystoreCommitteeVaultError::FloorMismatch)?;
        let recovery = RecoveryVault::open(path, identity, password).map_err(KeystoreCommitteeVaultError::Keystore)?;
        let candidate = recovery.checkpoint();
        if candidate != trusted {
            return Err(KeystoreCommitteeVaultError::FloorMismatch);
        }
        let vault = recovery
            .anchor(&floor_store)
            .map_err(|_| KeystoreCommitteeVaultError::FloorMismatch)?;
        let mut adapter = Self::from_parts(vault, descriptor, member_id, floor_store, candidate)?;
        if candidate.revision().get() > 0 {
            adapter.verify_recovery_record(candidate)?;
        }
        Ok(adapter)
    }

    /// Reconciles one exact post-write candidate retained in the independent
    /// operation journal after an ambiguous adapter error.
    #[allow(clippy::too_many_arguments)]
    pub fn reconcile_candidate(
        path: impl AsRef<Path>,
        descriptor: &CommitteeDescriptor,
        member_id: CommitteeMemberId,
        password: Password,
        floor_store: F,
        expected: VaultCheckpoint,
        candidate: VaultCheckpoint,
    ) -> std::result::Result<Self, KeystoreCommitteeVaultError> {
        let identity = committee_keystore_identity(descriptor, member_id)?;
        let next_revision = expected
            .revision()
            .get()
            .checked_add(1)
            .ok_or(KeystoreCommitteeVaultError::FloorMismatch)?;
        if candidate.revision().get() != next_revision
            || floor_store
                .load_checkpoint(identity)
                .map_err(|_| KeystoreCommitteeVaultError::FloorMismatch)?
                != Some(expected)
        {
            return Err(KeystoreCommitteeVaultError::FloorMismatch);
        }
        let recovery = RecoveryVault::open(path, identity, password).map_err(KeystoreCommitteeVaultError::Keystore)?;
        if recovery.checkpoint() != candidate {
            return Err(KeystoreCommitteeVaultError::FloorMismatch);
        }
        install_checkpoint(&floor_store, identity, Some(expected), candidate)?;
        let vault = recovery
            .anchor(&floor_store)
            .map_err(|_| KeystoreCommitteeVaultError::FloorMismatch)?;
        let mut adapter = Self::from_parts(vault, descriptor, member_id, floor_store, candidate)?;
        adapter.verify_recovery_record(candidate)?;
        Ok(adapter)
    }

    /// Returns the exact authenticated keystore identity.
    #[must_use]
    pub const fn identity(&self) -> VaultIdentity {
        self.identity
    }

    /// Returns the most recent independently confirmed rollback floor.
    pub fn floor_revision(&mut self) -> std::result::Result<VaultRevision, KeystoreCommitteeVaultError> {
        self.ensure_consistent().map(VaultCheckpoint::revision)
    }

    /// Returns the exact independently confirmed encrypted-state checkpoint.
    pub fn checkpoint(&mut self) -> std::result::Result<VaultCheckpoint, KeystoreCommitteeVaultError> {
        self.ensure_consistent()
    }

    /// Returns the non-secret candidate required for explicit post-error
    /// reconciliation, if a local write reached the candidate checkpoint.
    #[must_use]
    pub const fn recovery_candidate(&self) -> Option<VaultCheckpoint> {
        self.recovery_candidate
    }

    /// Creates an authenticated no-clobber backup of the encrypted vault.
    pub fn backup_to(&mut self, target: impl AsRef<Path>) -> std::result::Result<(), KeystoreCommitteeVaultError> {
        self.ensure_consistent()?;
        self.vault_ref()?
            .backup_to(target)
            .map_err(KeystoreCommitteeVaultError::Keystore)
    }

    /// Atomically reserves one immutable signing nonce and advances the
    /// independent floor before returning. The nonce bytes are never returned
    /// by this adapter.
    pub fn reserve_session_nonce(
        &mut self,
        session_id: SignerSessionId,
        nonce: CommitteeSessionNonce,
    ) -> std::result::Result<VaultRevision, KeystoreCommitteeVaultError> {
        let nonce_key =
            RecordKey::session_nonce(session_id.as_bytes().to_vec()).map_err(KeystoreCommitteeVaultError::Keystore)?;
        if self
            .vault_ref()?
            .record_status(&nonce_key)
            .map_err(KeystoreCommitteeVaultError::Keystore)?
            != RecordStatus::Absent
        {
            return Err(KeystoreCommitteeVaultError::RevisionMismatch);
        }
        let nonce_digest: [u8; 32] = Sha256::digest(nonce.expose_secret()).into();
        let nonce_value =
            SecretValue::from_bytes(nonce.expose_secret().to_vec()).map_err(KeystoreCommitteeVaultError::Keystore)?;
        self.commit_nonce_operation(session_id, 2, nonce_digest, Some(nonce_value), None)
    }

    /// Atomically tombstones a reserved signing nonce and advances the
    /// independent floor before returning. Tombstones are never removed or
    /// replaced, so a stale backup cannot authorize nonce reuse.
    pub fn consume_session_nonce(
        &mut self,
        session_id: SignerSessionId,
    ) -> std::result::Result<VaultRevision, KeystoreCommitteeVaultError> {
        let nonce_key =
            RecordKey::session_nonce(session_id.as_bytes().to_vec()).map_err(KeystoreCommitteeVaultError::Keystore)?;
        let view = self
            .vault_ref()?
            .get(&nonce_key)
            .map_err(KeystoreCommitteeVaultError::Keystore)?
            .ok_or(KeystoreCommitteeVaultError::RevisionMismatch)?;
        let nonce_version = view.version();
        let mut operation_hasher = Sha256::new();
        operation_hasher.update(session_id.as_bytes());
        operation_hasher.update(nonce_version.get().to_be_bytes());
        let operation_digest = operation_hasher.finalize().into();
        self.commit_nonce_operation(session_id, 3, operation_digest, None, Some(nonce_version))
    }

    /// Returns the authenticated live/absent/tombstoned nonce status.
    pub fn session_nonce_status(
        &mut self,
        session_id: SignerSessionId,
    ) -> std::result::Result<RecordStatus, KeystoreCommitteeVaultError> {
        self.ensure_consistent()?;
        let key =
            RecordKey::session_nonce(session_id.as_bytes().to_vec()).map_err(KeystoreCommitteeVaultError::Keystore)?;
        self.vault_ref()?
            .record_status(&key)
            .map_err(KeystoreCommitteeVaultError::Keystore)
    }

    fn from_parts(
        vault: Vault,
        descriptor: &CommitteeDescriptor,
        member_id: CommitteeMemberId,
        floor_store: F,
        checkpoint: VaultCheckpoint,
    ) -> std::result::Result<Self, KeystoreCommitteeVaultError> {
        let identity = committee_keystore_identity(descriptor, member_id)?;
        if vault.identity() != identity || identity.role() != VaultRole::CommitteeMember {
            return Err(KeystoreCommitteeVaultError::IdentityMismatch);
        }
        let state_key = state_record_key(descriptor.id().as_bytes(), member_id)?;
        let mut adapter = Self {
            vault: Some(vault),
            floor_store,
            descriptor_id: *descriptor.id().as_bytes(),
            member_id,
            identity,
            state_key,
            checkpoint,
            recovery_candidate: None,
            poisoned: false,
        };
        let actual = adapter
            .vault_ref()?
            .checkpoint()
            .map_err(KeystoreCommitteeVaultError::Keystore)?;
        if actual != checkpoint {
            adapter.poison();
            return Err(KeystoreCommitteeVaultError::FloorMismatch);
        }
        Ok(adapter)
    }

    fn ensure_consistent(&mut self) -> std::result::Result<VaultCheckpoint, KeystoreCommitteeVaultError> {
        if self.poisoned {
            return Err(KeystoreCommitteeVaultError::Poisoned);
        }
        let vault = self.vault_ref()?;
        if vault.identity() != self.identity {
            self.poison();
            return Err(KeystoreCommitteeVaultError::IdentityMismatch);
        }
        let vault_checkpoint = self.vault_ref()?.checkpoint().map_err(|error| {
            self.poison();
            KeystoreCommitteeVaultError::Keystore(error)
        })?;
        let anchored = self
            .floor_store
            .load_checkpoint(self.identity)
            .map_err(|_| {
                self.poison();
                KeystoreCommitteeVaultError::FloorMismatch
            })?
            .ok_or_else(|| {
                self.poison();
                KeystoreCommitteeVaultError::FloorMismatch
            })?;
        if anchored != vault_checkpoint || self.checkpoint != vault_checkpoint {
            self.poison();
            return Err(KeystoreCommitteeVaultError::FloorMismatch);
        }
        Ok(vault_checkpoint)
    }

    fn advance_checkpoint_checked(
        &mut self,
        expected: Option<VaultCheckpoint>,
        checkpoint: VaultCheckpoint,
    ) -> std::result::Result<(), KeystoreCommitteeVaultError> {
        // The backend may report an error after making the CAS durable. Always
        // read it back and accept only the exact encrypted-state checkpoint.
        self.recovery_candidate = Some(checkpoint);
        let _advance_result = self
            .floor_store
            .compare_and_swap_checkpoint(self.identity, expected, checkpoint);
        let observed = match self.floor_store.load_checkpoint(self.identity) {
            Ok(observed) => observed,
            Err(_) => {
                self.poison();
                return Err(KeystoreCommitteeVaultError::FloorMismatch);
            }
        };
        if observed != Some(checkpoint) {
            self.poison();
            return Err(KeystoreCommitteeVaultError::FloorMismatch);
        }
        self.checkpoint = checkpoint;
        self.recovery_candidate = None;
        Ok(())
    }

    fn verify_recovery_record(
        &mut self,
        vault_checkpoint: VaultCheckpoint,
    ) -> std::result::Result<(), KeystoreCommitteeVaultError> {
        let record = self
            .load_state_record()?
            .ok_or(KeystoreCommitteeVaultError::InvalidRecord)?;
        if record.committed_vault_revision != vault_checkpoint.revision().get() {
            self.poison();
            return Err(KeystoreCommitteeVaultError::InvalidRecord);
        }
        let idempotency_key = idempotency_record_key(&record.request_digest)?;
        let view = self
            .vault_ref()?
            .get(&idempotency_key)
            .map_err(KeystoreCommitteeVaultError::Keystore)?
            .ok_or(KeystoreCommitteeVaultError::InvalidRecord)?;
        let bytes = Zeroizing::new(view.expose_secret().to_vec());
        let idempotency = decode_idempotency_record(&bytes, &self.descriptor_id, self.member_id)?;
        if idempotency.request_digest != record.request_digest
            || idempotency.result_engine_revision != record.engine_revision
            || idempotency.committed_vault_revision != record.committed_vault_revision
            || idempotency.state_digest != record.encoded_digest
        {
            self.poison();
            return Err(KeystoreCommitteeVaultError::InvalidRecord);
        }
        Ok(())
    }

    fn load_state_record(&self) -> std::result::Result<Option<DecodedStateRecord>, KeystoreCommitteeVaultError> {
        let Some(view) = self
            .vault_ref()?
            .get(&self.state_key)
            .map_err(KeystoreCommitteeVaultError::Keystore)?
        else {
            return Ok(None);
        };
        let version = view.version();
        let bytes = Zeroizing::new(view.expose_secret().to_vec());
        decode_state_record(&bytes, version, &self.descriptor_id, self.member_id).map(Some)
    }

    fn vault_ref(&self) -> std::result::Result<&Vault, KeystoreCommitteeVaultError> {
        self.vault.as_ref().ok_or(KeystoreCommitteeVaultError::Poisoned)
    }

    fn vault_mut(&mut self) -> std::result::Result<&mut Vault, KeystoreCommitteeVaultError> {
        self.vault.as_mut().ok_or(KeystoreCommitteeVaultError::Poisoned)
    }

    fn poison(&mut self) {
        self.poisoned = true;
        self.vault.take();
    }

    fn poison_after_keystore_error(&mut self, error: &KeystoreError) {
        if let KeystoreError::AmbiguousWrite { candidate, .. } = error {
            self.recovery_candidate = Some(*candidate);
        }
        self.poison();
    }

    fn commit_nonce_operation(
        &mut self,
        session_id: SignerSessionId,
        operation: u8,
        operation_digest: [u8; 32],
        nonce_value: Option<SecretValue>,
        nonce_version: Option<RecordVersion>,
    ) -> std::result::Result<VaultRevision, KeystoreCommitteeVaultError> {
        let base_checkpoint = self.ensure_consistent()?;
        let base_revision = base_checkpoint.revision();
        let current = match self.load_state_record() {
            Ok(Some(current)) => current,
            _ => {
                self.poison();
                return Err(KeystoreCommitteeVaultError::InvalidRecord);
            }
        };
        let committed_revision = base_revision
            .get()
            .checked_add(1)
            .map(VaultRevision::new)
            .ok_or(KeystoreCommitteeVaultError::RevisionMismatch)?;
        let request_digest = request_digest(
            &self.identity,
            operation,
            Some(current.engine_revision),
            current.engine_revision,
            &operation_digest,
        );
        let mut state_record = encode_state_record(
            &self.descriptor_id,
            self.member_id,
            current.engine_revision,
            committed_revision,
            request_digest,
            &current.engine_payload,
        )?;
        let state_digest = Sha256::digest(&state_record).into();
        let mut idempotency = encode_idempotency_record(
            &self.descriptor_id,
            self.member_id,
            request_digest,
            operation,
            Some(current.engine_revision),
            Some(current.record_version),
            current.engine_revision,
            committed_revision,
            state_digest,
        );
        let state_key = self.state_key.clone();
        let idempotency_key = idempotency_record_key(&request_digest)?;
        let nonce_key =
            RecordKey::session_nonce(session_id.as_bytes().to_vec()).map_err(KeystoreCommitteeVaultError::Keystore)?;
        let transaction_id = transaction_id(&self.identity, &request_digest);
        let result = self
            .vault_mut()?
            .transact(base_revision, transaction_id, |transaction| {
                transaction.compare_and_swap(
                    state_key,
                    ExpectedRecord::Version(current.record_version),
                    SecretValue::from_bytes(mem::take(&mut *state_record))?,
                )?;
                transaction.compare_and_swap(
                    idempotency_key,
                    ExpectedRecord::Absent,
                    SecretValue::from_bytes(mem::take(&mut *idempotency))?,
                )?;
                match (nonce_value, nonce_version) {
                    (Some(value), None) => transaction.compare_and_swap(nonce_key, ExpectedRecord::Absent, value)?,
                    (None, Some(version)) => transaction.remove(nonce_key, version)?,
                    _ => return Err(KeystoreError::InvalidFormat),
                }
                Ok(())
            });
        let actual_revision = match result {
            Ok(CommitOutcome::Applied(revision) | CommitOutcome::Replayed(revision)) => revision,
            Err(error) => {
                self.poison_after_keystore_error(&error);
                return Err(KeystoreCommitteeVaultError::Keystore(error));
            }
        };
        let candidate = self
            .vault_ref()?
            .checkpoint()
            .map_err(KeystoreCommitteeVaultError::Keystore)?;
        if actual_revision != committed_revision
            || candidate.revision() != committed_revision
            || self
                .advance_checkpoint_checked(Some(base_checkpoint), candidate)
                .is_err()
        {
            self.poison();
            return Err(KeystoreCommitteeVaultError::Poisoned);
        }
        let stored = match self.load_state_record() {
            Ok(Some(stored)) => stored,
            _ => {
                self.poison();
                return Err(KeystoreCommitteeVaultError::InvalidRecord);
            }
        };
        if stored.encoded_digest != state_digest {
            self.poison();
            return Err(KeystoreCommitteeVaultError::InvalidRecord);
        }
        Ok(actual_revision)
    }
}

impl<F> CommitteeVault for KeystoreCommitteeVault<F>
where
    F: RollbackFloorStore,
{
    type Error = KeystoreCommitteeVaultError;

    fn load(&mut self) -> std::result::Result<Option<VaultEntry>, Self::Error> {
        self.ensure_consistent()?;
        match self.load_state_record() {
            Ok(record) => Ok(record.map(|record| VaultEntry::new(record.engine_revision, record.engine_payload))),
            Err(error) => {
                self.poison();
                Err(error)
            }
        }
    }

    fn create(&mut self, entry: VaultEntry) -> std::result::Result<(), VaultStoreError<Self::Error>> {
        self.ensure_consistent().map_err(VaultStoreError::Backend)?;
        if entry.revision() != 0 {
            return Err(VaultStoreError::Backend(Self::Error::RevisionMismatch));
        }
        if let Some(current) = self.load_state_record().map_err(VaultStoreError::Backend)? {
            return Err(VaultStoreError::Conflict {
                current_revision: Some(current.engine_revision),
            });
        }
        self.commit_engine_record(None, None, entry)
    }

    fn compare_and_swap(
        &mut self,
        expected_revision: u64,
        entry: VaultEntry,
    ) -> std::result::Result<(), VaultStoreError<Self::Error>> {
        self.ensure_consistent().map_err(VaultStoreError::Backend)?;
        let next_revision = expected_revision
            .checked_add(1)
            .ok_or(VaultStoreError::Backend(Self::Error::RevisionMismatch))?;
        if entry.revision() != next_revision {
            return Err(VaultStoreError::Backend(Self::Error::RevisionMismatch));
        }
        let current = self
            .load_state_record()
            .map_err(VaultStoreError::Backend)?
            .ok_or(VaultStoreError::Conflict { current_revision: None })?;
        if current.engine_revision != expected_revision {
            return Err(VaultStoreError::Conflict {
                current_revision: Some(current.engine_revision),
            });
        }
        self.commit_engine_record(Some(expected_revision), Some(current.record_version), entry)
    }
}

impl<F> KeystoreCommitteeVault<F>
where
    F: RollbackFloorStore,
{
    fn commit_engine_record(
        &mut self,
        prior_engine_revision: Option<u64>,
        prior_record_version: Option<RecordVersion>,
        entry: VaultEntry,
    ) -> std::result::Result<(), VaultStoreError<KeystoreCommitteeVaultError>> {
        let base_checkpoint = self.ensure_consistent().map_err(VaultStoreError::Backend)?;
        let base_revision = base_checkpoint.revision();
        let committed_revision = base_revision
            .get()
            .checked_add(1)
            .map(VaultRevision::new)
            .ok_or(VaultStoreError::Backend(KeystoreCommitteeVaultError::RevisionMismatch))?;
        let engine_revision = entry.revision();
        let payload_digest = Sha256::digest(entry.plaintext().expose_secret()).into();
        let request_digest = request_digest(
            &self.identity,
            1,
            prior_engine_revision,
            engine_revision,
            &payload_digest,
        );
        let state_record = encode_state_record(
            &self.descriptor_id,
            self.member_id,
            engine_revision,
            committed_revision,
            request_digest,
            entry.plaintext(),
        )
        .map_err(VaultStoreError::Backend)?;
        let state_digest = Sha256::digest(&state_record).into();
        let idempotency = encode_idempotency_record(
            &self.descriptor_id,
            self.member_id,
            request_digest,
            1,
            prior_engine_revision,
            prior_record_version,
            engine_revision,
            committed_revision,
            state_digest,
        );
        let idempotency_key = idempotency_record_key(&request_digest).map_err(VaultStoreError::Backend)?;
        let transaction_id = transaction_id(&self.identity, &request_digest);
        let state_key = self.state_key.clone();
        let state_expected = prior_record_version.map_or(ExpectedRecord::Absent, ExpectedRecord::Version);
        let mut state_record = state_record;
        let mut idempotency = idempotency;
        let result = self.vault_mut().map_err(VaultStoreError::Backend)?.transact(
            base_revision,
            transaction_id,
            |transaction| {
                transaction.compare_and_swap(
                    state_key,
                    state_expected,
                    SecretValue::from_bytes(mem::take(&mut *state_record))?,
                )?;
                transaction.compare_and_swap(
                    idempotency_key,
                    ExpectedRecord::Absent,
                    SecretValue::from_bytes(mem::take(&mut *idempotency))?,
                )?;
                Ok(())
            },
        );
        let actual_revision = match result {
            Ok(CommitOutcome::Applied(revision) | CommitOutcome::Replayed(revision)) => revision,
            Err(KeystoreError::RevisionConflict | KeystoreError::RecordConflict) => {
                return Err(VaultStoreError::Conflict {
                    current_revision: self
                        .load_state_record()
                        .ok()
                        .flatten()
                        .map(|record| record.engine_revision),
                });
            }
            Err(error) => {
                self.poison_after_keystore_error(&error);
                return Err(VaultStoreError::Backend(KeystoreCommitteeVaultError::Keystore(error)));
            }
        };
        if actual_revision != committed_revision {
            self.poison();
            return Err(VaultStoreError::Backend(KeystoreCommitteeVaultError::InvalidRecord));
        }
        let candidate = self
            .vault_ref()
            .and_then(|vault| vault.checkpoint().map_err(KeystoreCommitteeVaultError::Keystore))
            .map_err(VaultStoreError::Backend)?;
        if candidate.revision() != actual_revision
            || self
                .advance_checkpoint_checked(Some(base_checkpoint), candidate)
                .is_err()
        {
            return Err(VaultStoreError::Backend(KeystoreCommitteeVaultError::Poisoned));
        }
        let stored = match self.load_state_record() {
            Ok(stored) => stored,
            Err(error) => {
                self.poison();
                return Err(VaultStoreError::Backend(error));
            }
        };
        if stored.as_ref().map(|record| record.encoded_digest) != Some(state_digest) {
            self.poison();
            return Err(VaultStoreError::Backend(KeystoreCommitteeVaultError::InvalidRecord));
        }
        Ok(())
    }
}

struct DecodedStateRecord {
    engine_revision: u64,
    committed_vault_revision: u64,
    request_digest: [u8; 32],
    engine_payload: VaultPlaintext,
    record_version: RecordVersion,
    encoded_digest: [u8; 32],
}

struct DecodedIdempotencyRecord {
    request_digest: [u8; 32],
    result_engine_revision: u64,
    committed_vault_revision: u64,
    state_digest: [u8; 32],
}

fn install_checkpoint<F: RollbackFloorStore>(
    floor_store: &F,
    identity: VaultIdentity,
    expected: Option<VaultCheckpoint>,
    next: VaultCheckpoint,
) -> std::result::Result<(), KeystoreCommitteeVaultError> {
    let _cas_result = floor_store.compare_and_swap_checkpoint(identity, expected, next);
    if floor_store
        .load_checkpoint(identity)
        .map_err(|_| KeystoreCommitteeVaultError::FloorMismatch)?
        == Some(next)
    {
        Ok(())
    } else {
        Err(KeystoreCommitteeVaultError::FloorMismatch)
    }
}

/// Derives the exact keystore identity for one descriptor-bound member process.
pub fn committee_keystore_identity(
    descriptor: &CommitteeDescriptor,
    member_id: CommitteeMemberId,
) -> std::result::Result<VaultIdentity, KeystoreCommitteeVaultError> {
    if descriptor.epoch().get() == 0 || descriptor.member(member_id).is_none() {
        return Err(KeystoreCommitteeVaultError::InvalidIdentity);
    }
    let network = keystore_network(descriptor.network())?;
    let deployment_id = DeploymentId::derive(network, descriptor.deployment_id())
        .map_err(|_| KeystoreCommitteeVaultError::InvalidIdentity)?;
    let committee_descriptor = CommitteeDescriptorDigest::new(*descriptor.id().as_bytes())
        .map_err(|_| KeystoreCommitteeVaultError::InvalidIdentity)?;
    let deployment = DeploymentBinding::new(deployment_id, descriptor.epoch().get(), committee_descriptor)
        .map_err(|_| KeystoreCommitteeVaultError::InvalidIdentity)?;
    let mut node_hasher = Sha256::new();
    append_bytes(&mut node_hasher, NODE_DOMAIN);
    node_hasher.update(descriptor.id().as_bytes());
    node_hasher.update(member_id.get().to_be_bytes());
    let node_id = NodeId::new(node_hasher.finalize().into());
    Ok(VaultIdentity::new(
        network,
        VaultRole::CommitteeMember,
        node_id,
        deployment,
    ))
}

fn keystore_network(network: BitcoinNetwork) -> std::result::Result<Network, KeystoreCommitteeVaultError> {
    match network {
        BitcoinNetwork::Bitcoin => Ok(Network::Mainnet),
        BitcoinNetwork::Signet => Ok(Network::Signet),
        BitcoinNetwork::Testnet => Ok(Network::Testnet),
        BitcoinNetwork::Regtest => Ok(Network::Regtest),
        BitcoinNetwork::Testnet4 => Err(KeystoreCommitteeVaultError::InvalidIdentity),
    }
}

fn state_record_key(
    descriptor_id: &[u8; 32],
    member_id: CommitteeMemberId,
) -> std::result::Result<RecordKey, KeystoreCommitteeVaultError> {
    let mut hasher = Sha256::new();
    append_bytes(&mut hasher, STATE_KEY_DOMAIN);
    hasher.update(descriptor_id);
    hasher.update(member_id.get().to_be_bytes());
    RecordKey::new(RecordNamespace::AdapterState, hasher.finalize().to_vec())
        .map_err(KeystoreCommitteeVaultError::Keystore)
}

fn idempotency_record_key(request_digest: &[u8; 32]) -> std::result::Result<RecordKey, KeystoreCommitteeVaultError> {
    let mut hasher = Sha256::new();
    append_bytes(&mut hasher, IDEMPOTENCY_KEY_DOMAIN);
    hasher.update(request_digest);
    RecordKey::new(RecordNamespace::AdapterState, hasher.finalize().to_vec())
        .map_err(KeystoreCommitteeVaultError::Keystore)
}

fn request_digest(
    identity: &VaultIdentity,
    operation: u8,
    prior_engine_revision: Option<u64>,
    result_engine_revision: u64,
    payload_digest: &[u8; 32],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    append_bytes(&mut hasher, REQUEST_DOMAIN);
    append_identity(&mut hasher, identity);
    hasher.update([operation]);
    match prior_engine_revision {
        Some(revision) => {
            hasher.update([1]);
            hasher.update(revision.to_be_bytes());
        }
        None => hasher.update([0]),
    }
    hasher.update(result_engine_revision.to_be_bytes());
    hasher.update(payload_digest);
    hasher.finalize().into()
}

fn transaction_id(identity: &VaultIdentity, request_digest: &[u8; 32]) -> TransactionId {
    let mut hasher = Sha256::new();
    append_bytes(&mut hasher, TRANSACTION_DOMAIN);
    append_identity(&mut hasher, identity);
    hasher.update(request_digest);
    TransactionId::new(hasher.finalize().into())
}

fn append_identity(hasher: &mut Sha256, identity: &VaultIdentity) {
    hasher.update([match identity.network() {
        Network::Regtest => 1,
        Network::Signet => 2,
        Network::Testnet => 3,
        Network::Mainnet => 4,
    }]);
    hasher.update([match identity.role() {
        VaultRole::Holder => 1,
        VaultRole::CommitteeMember => 2,
    }]);
    hasher.update(identity.node_id().as_bytes());
    hasher.update(identity.deployment().deployment_id().as_bytes());
    hasher.update(identity.deployment().committee_epoch().to_be_bytes());
    hasher.update(identity.deployment().committee_descriptor().as_bytes());
}

fn encode_state_record(
    descriptor_id: &[u8; 32],
    member_id: CommitteeMemberId,
    engine_revision: u64,
    committed_vault_revision: VaultRevision,
    request_digest: [u8; 32],
    payload: &VaultPlaintext,
) -> std::result::Result<Zeroizing<Vec<u8>>, KeystoreCommitteeVaultError> {
    if payload.is_empty() || payload.len() > MAX_ADAPTER_ENGINE_BYTES {
        return Err(KeystoreCommitteeVaultError::InvalidRecord);
    }
    let payload_length = u32::try_from(payload.len()).map_err(|_| KeystoreCommitteeVaultError::InvalidRecord)?;
    let mut output = Zeroizing::new(Vec::with_capacity(98 + payload.len()));
    output.extend_from_slice(STATE_MAGIC);
    output.extend_from_slice(&ADAPTER_FORMAT_VERSION.to_be_bytes());
    output.extend_from_slice(descriptor_id);
    output.extend_from_slice(&member_id.get().to_be_bytes());
    output.extend_from_slice(&engine_revision.to_be_bytes());
    output.extend_from_slice(&committed_vault_revision.get().to_be_bytes());
    output.extend_from_slice(&request_digest);
    output.extend_from_slice(&payload_length.to_be_bytes());
    output.extend_from_slice(payload.expose_secret());
    Ok(output)
}

#[allow(clippy::too_many_arguments)]
fn encode_idempotency_record(
    descriptor_id: &[u8; 32],
    member_id: CommitteeMemberId,
    request_digest: [u8; 32],
    operation: u8,
    prior_engine_revision: Option<u64>,
    prior_record_version: Option<RecordVersion>,
    result_engine_revision: u64,
    committed_vault_revision: VaultRevision,
    state_digest: [u8; 32],
) -> Zeroizing<Vec<u8>> {
    let mut output = Zeroizing::new(Vec::with_capacity(180));
    output.extend_from_slice(IDEMPOTENCY_MAGIC);
    output.extend_from_slice(&ADAPTER_FORMAT_VERSION.to_be_bytes());
    output.extend_from_slice(descriptor_id);
    output.extend_from_slice(&member_id.get().to_be_bytes());
    output.extend_from_slice(&request_digest);
    output.push(operation);
    put_optional_u64(&mut output, prior_engine_revision);
    put_optional_u64(&mut output, prior_record_version.map(RecordVersion::get));
    output.extend_from_slice(&result_engine_revision.to_be_bytes());
    output.extend_from_slice(&committed_vault_revision.get().to_be_bytes());
    output.extend_from_slice(&state_digest);
    output
}

fn decode_state_record(
    bytes: &[u8],
    record_version: RecordVersion,
    descriptor_id: &[u8; 32],
    member_id: CommitteeMemberId,
) -> std::result::Result<DecodedStateRecord, KeystoreCommitteeVaultError> {
    let encoded_digest = Sha256::digest(bytes).into();
    let mut cursor = Cursor::new(bytes);
    if cursor.take(STATE_MAGIC.len())? != STATE_MAGIC || cursor.u16()? != ADAPTER_FORMAT_VERSION {
        return Err(KeystoreCommitteeVaultError::InvalidRecord);
    }
    if cursor.array_32()? != *descriptor_id || cursor.u32()? != member_id.get() {
        return Err(KeystoreCommitteeVaultError::InvalidRecord);
    }
    let engine_revision = cursor.u64()?;
    let committed_vault_revision = cursor.u64()?;
    let request_digest = cursor.array_32()?;
    let payload_length = usize::try_from(cursor.u32()?).map_err(|_| KeystoreCommitteeVaultError::InvalidRecord)?;
    if payload_length == 0 || payload_length > MAX_ADAPTER_ENGINE_BYTES {
        return Err(KeystoreCommitteeVaultError::InvalidRecord);
    }
    let engine_payload = VaultPlaintext::from_secret_bytes(cursor.take(payload_length)?.to_vec())
        .map_err(|_| KeystoreCommitteeVaultError::InvalidRecord)?;
    if !cursor.is_empty() || record_version.get() > committed_vault_revision {
        return Err(KeystoreCommitteeVaultError::InvalidRecord);
    }
    Ok(DecodedStateRecord {
        engine_revision,
        committed_vault_revision,
        request_digest,
        engine_payload,
        record_version,
        encoded_digest,
    })
}

fn decode_idempotency_record(
    bytes: &[u8],
    descriptor_id: &[u8; 32],
    member_id: CommitteeMemberId,
) -> std::result::Result<DecodedIdempotencyRecord, KeystoreCommitteeVaultError> {
    let mut cursor = Cursor::new(bytes);
    if cursor.take(IDEMPOTENCY_MAGIC.len())? != IDEMPOTENCY_MAGIC || cursor.u16()? != ADAPTER_FORMAT_VERSION {
        return Err(KeystoreCommitteeVaultError::InvalidRecord);
    }
    if cursor.array_32()? != *descriptor_id || cursor.u32()? != member_id.get() {
        return Err(KeystoreCommitteeVaultError::InvalidRecord);
    }
    let request_digest = cursor.array_32()?;
    let operation = cursor.u8()?;
    let _prior_engine_revision = cursor.optional_u64()?;
    let _prior_record_version = cursor.optional_u64()?;
    let result_engine_revision = cursor.u64()?;
    let committed_vault_revision = cursor.u64()?;
    let state_digest = cursor.array_32()?;
    if !cursor.is_empty() || !(1..=3).contains(&operation) {
        return Err(KeystoreCommitteeVaultError::InvalidRecord);
    }
    Ok(DecodedIdempotencyRecord {
        request_digest,
        result_engine_revision,
        committed_vault_revision,
        state_digest,
    })
}

fn put_optional_u64(output: &mut Vec<u8>, value: Option<u64>) {
    match value {
        Some(value) => {
            output.push(1);
            output.extend_from_slice(&value.to_be_bytes());
        }
        None => output.push(0),
    }
}

struct Cursor<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Cursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    fn take(&mut self, length: usize) -> std::result::Result<&'a [u8], KeystoreCommitteeVaultError> {
        let end = self
            .position
            .checked_add(length)
            .ok_or(KeystoreCommitteeVaultError::InvalidRecord)?;
        let value = self
            .bytes
            .get(self.position..end)
            .ok_or(KeystoreCommitteeVaultError::InvalidRecord)?;
        self.position = end;
        Ok(value)
    }

    fn u8(&mut self) -> std::result::Result<u8, KeystoreCommitteeVaultError> {
        self.take(1)?
            .first()
            .copied()
            .ok_or(KeystoreCommitteeVaultError::InvalidRecord)
    }

    fn u16(&mut self) -> std::result::Result<u16, KeystoreCommitteeVaultError> {
        Ok(u16::from_be_bytes(
            self.take(2)?
                .try_into()
                .map_err(|_| KeystoreCommitteeVaultError::InvalidRecord)?,
        ))
    }

    fn u32(&mut self) -> std::result::Result<u32, KeystoreCommitteeVaultError> {
        Ok(u32::from_be_bytes(
            self.take(4)?
                .try_into()
                .map_err(|_| KeystoreCommitteeVaultError::InvalidRecord)?,
        ))
    }

    fn u64(&mut self) -> std::result::Result<u64, KeystoreCommitteeVaultError> {
        Ok(u64::from_be_bytes(
            self.take(8)?
                .try_into()
                .map_err(|_| KeystoreCommitteeVaultError::InvalidRecord)?,
        ))
    }

    fn array_32(&mut self) -> std::result::Result<[u8; 32], KeystoreCommitteeVaultError> {
        self.take(32)?
            .try_into()
            .map_err(|_| KeystoreCommitteeVaultError::InvalidRecord)
    }

    fn optional_u64(&mut self) -> std::result::Result<Option<u64>, KeystoreCommitteeVaultError> {
        match self.u8()? {
            0 => Ok(None),
            1 => self.u64().map(Some),
            _ => Err(KeystoreCommitteeVaultError::InvalidRecord),
        }
    }

    const fn is_empty(&self) -> bool {
        self.position == self.bytes.len()
    }
}
