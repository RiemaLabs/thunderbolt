use std::collections::BTreeMap;
use std::path::Path;

use bitcoin::Network as BitcoinNetwork;
use libpaillier::{DecryptionKey, EncryptionKey};
use secp::{Point, Scalar};
use sha2::{Digest as _, Sha256};
use thunderbolt_keystore::{
    CheckpointCasOutcome, CommitOutcome, CommitteeDescriptorDigest, DeploymentBinding,
    DeploymentId as KeystoreDeploymentId, ExpectedRecord, KdfParams, KeystoreError, NodeId, Password, RecordKey,
    RecordNamespace, RecordVersion, RecoveryVault, RollbackFloorStore, SecretValue, TransactionId, Vault,
    VaultCheckpoint, VaultIdentity, VaultRevision, VaultRole, MAX_RECORDS, MAX_RECORD_VALUE_BYTES,
};
use thunderbolt_protocol::{Digest, EntryHash};
use thunderbolt_wire::{
    AnchorTransitionV1, BindingContext, CanonicalDigest, DeploymentId as WireDeploymentId, InvoiceEnvelopeV1,
    InvoiceProofV1, InvoiceStatementV1, PaillierCiphertextHex, PaillierNonceHex, PaillierPublicKeyHex, PointHex,
    ProofResponseHex, ShareEnvelopeV1, ShareProofV1, ShareStatementV1, ThresholdDistributionV1,
    ThresholdEncryptedShareV1, ThresholdEnvelopeV1, TransferEnvelopeV1, TransferProofV1, TransferStatementV1,
    ValidateWire, MAX_CHANNEL_ID_BYTES, MAX_COMMITTEE_MEMBERS, MAX_DEPLOYMENT_ID_BYTES, MAX_INVOICE_ID_BYTES,
    MAX_PAILLIER_CIPHERTEXT_BYTES, MAX_PAILLIER_NONCE_BYTES, MAX_PROOF_RESPONSE_BYTES, PAILLIER_MODULUS_BYTES,
    PROTOCOL_VERSION, RECIPIENT_SHARE_MEMBER_ID,
};
use zeroize::Zeroizing;

use crate::engine::derive_identity;
use crate::error::{HolderError, VaultError};
use crate::types::{
    threshold_invoice_package_digest, ChannelKey, CredentialKey, DurableAcknowledgement, InvoiceRecordKey,
};
use crate::vault::{
    CredentialRecord, CredentialState, IdentityRecord, InvoicePublicRecord, InvoiceRecord, InvoiceState,
    OutboundTransferRecord, SecretVault, VaultTransaction,
};

const CODEC_VERSION: u16 = 1;
const IDENTITY_MAGIC: &[u8; 8] = b"TBHID001";
const INVOICE_MAGIC: &[u8; 8] = b"TBHIV001";
const CREDENTIAL_MAGIC: &[u8; 8] = b"TBHCR001";
const OUTBOUND_MAGIC: &[u8; 8] = b"TBHOT001";
const IDENTITY_RECORD_ID: &[u8] = b"bitcoin-thunderbolt/holder/identity/v1";
const OUTBOUND_RECORD_PREFIX: &[u8] = b"outbound/v1/";
const TRANSACTION_DOMAIN: &[u8] = b"bitcoin-thunderbolt/holder/keystore-transaction/v1";

type CodecResult<T> = std::result::Result<T, VaultError>;

/// Derives the exact Holder keystore identity for one deployment and committee
/// epoch. The encrypted vault's deployment identifier is a domain-separated
/// digest, not the raw human-readable deployment name.
///
/// Testnet4 is rejected because the current keystore format has no distinct
/// Testnet4 network tag; silently mapping it to another test network would
/// collapse security domains.
pub fn holder_keystore_identity(
    network: BitcoinNetwork,
    raw_deployment_id: impl AsRef<[u8]>,
    committee_epoch: u64,
    committee_descriptor: CommitteeDescriptorDigest,
    node_id: NodeId,
) -> Result<VaultIdentity, HolderError> {
    let raw_deployment_id = WireDeploymentId::from_bytes("holder keystore deployment id", raw_deployment_id)?;
    let keystore_network = to_keystore_network(network)?;
    let deployment_id =
        KeystoreDeploymentId::derive(keystore_network, raw_deployment_id.as_bytes()).map_err(map_open_error)?;
    let deployment =
        DeploymentBinding::new(deployment_id, committee_epoch, committee_descriptor).map_err(map_open_error)?;
    Ok(VaultIdentity::new(
        keystore_network,
        VaultRole::Holder,
        node_id,
        deployment,
    ))
}

/// Production [`SecretVault`] adapter over an exclusively locked encrypted
/// [`thunderbolt_keystore::Vault`].
///
/// The type intentionally implements neither `Debug` nor `Clone`. Opening a
/// stopped vault requires an exact revision-and-state checkpoint from the
/// supplied floor store, so stale and equal-revision forked files fail before
/// any Holder record is decoded. The adapter cannot establish that store's
/// independence or authenticity; selecting it is an explicit runtime trust
/// decision.
pub struct KeystoreSecretVault<F> {
    vault: Vault,
    floor_store: F,
    checkpoint: VaultCheckpoint,
    poisoned: bool,
}

impl<F: RollbackFloorStore> KeystoreSecretVault<F> {
    /// Creates a new owner-only encrypted Holder vault.
    ///
    /// Creation anchors the exact encrypted revision-zero checkpoint before
    /// returning, preventing another same-identity vault from winning bootstrap.
    pub fn create(
        path: impl AsRef<Path>,
        identity: VaultIdentity,
        password: Password,
        params: KdfParams,
        floor_store: F,
    ) -> Result<Self, HolderError> {
        require_holder_role(identity)?;
        let recovery = RecoveryVault::create(path, identity, password, params).map_err(map_open_error)?;
        let checkpoint = recovery.checkpoint();
        reconcile_checkpoint(&floor_store, identity, None, checkpoint).map_err(HolderError::Vault)?;
        let vault = recovery
            .anchor(&floor_store)
            .map_err(|_| HolderError::Vault(VaultError::CorruptRecord))?;
        Ok(Self {
            vault,
            floor_store,
            checkpoint,
            poisoned: false,
        })
    }

    /// Reopens a Holder vault using a supplied independent rollback-floor
    /// capability. The caller remains responsible for selecting and
    /// authenticating that trust boundary.
    pub fn open_with_floor_store(
        path: impl AsRef<Path>,
        identity: VaultIdentity,
        password: Password,
        floor_store: F,
    ) -> Result<Self, HolderError> {
        require_holder_role(identity)?;
        let recovery = RecoveryVault::open(path, identity, password).map_err(map_open_error)?;
        let checkpoint = recovery.checkpoint();
        let expected = floor_store
            .load_checkpoint(identity)
            .map_err(|_| HolderError::Vault(VaultError::Unavailable))?;
        reconcile_checkpoint(&floor_store, identity, expected, checkpoint).map_err(HolderError::Vault)?;
        let vault = recovery
            .anchor(&floor_store)
            .map_err(|_| HolderError::Vault(VaultError::CorruptRecord))?;
        Ok(Self {
            vault,
            floor_store,
            checkpoint,
            poisoned: false,
        })
    }

    /// Returns the authenticated vault revision. The adapter has already
    /// anchored the corresponding exact state checkpoint before this value is
    /// observable.
    pub fn revision(&self) -> Result<VaultRevision, HolderError> {
        if self.poisoned {
            return Err(HolderError::Vault(VaultError::Unavailable));
        }
        self.vault.revision().map_err(map_open_error)
    }

    /// Returns the public identity authenticated into the encrypted vault.
    pub fn vault_identity(&self) -> VaultIdentity {
        self.vault.identity()
    }

    /// Creates an authenticated no-clobber backup. Reopening or restoring the
    /// backup still requires the independently stored exact checkpoint.
    pub fn backup_to(&self, target: impl AsRef<Path>) -> Result<(), HolderError> {
        if self.poisoned {
            return Err(HolderError::Vault(VaultError::Unavailable));
        }
        self.vault.backup_to(target).map_err(map_open_error)
    }
}

/// One in-memory typed transaction. Dropping it performs no keystore write and
/// zeroizes every decoded record allocation through the contained record
/// wrappers.
pub struct KeystoreVaultTransaction<'a, F> {
    vault: &'a mut Vault,
    floor_store: &'a F,
    checkpoint: &'a mut VaultCheckpoint,
    poisoned: &'a mut bool,
    base_revision: VaultRevision,
    state: HolderState,
    versions: RecordVersions,
    originals: OriginalDigests,
}

#[derive(Default)]
struct HolderState {
    identity: Option<IdentityRecord>,
    invoices: BTreeMap<InvoiceRecordKey, InvoiceRecord>,
    credentials: BTreeMap<CredentialKey, CredentialRecord>,
    outbound: BTreeMap<CredentialKey, OutboundTransferRecord>,
}

#[derive(Default)]
struct RecordVersions {
    identity: Option<RecordVersion>,
    invoices: BTreeMap<InvoiceRecordKey, RecordVersion>,
    credentials: BTreeMap<CredentialKey, RecordVersion>,
    outbound: BTreeMap<CredentialKey, RecordVersion>,
}

#[derive(Default)]
struct OriginalDigests {
    identity: Option<[u8; 32]>,
    invoices: BTreeMap<InvoiceRecordKey, [u8; 32]>,
    credentials: BTreeMap<CredentialKey, [u8; 32]>,
    outbound: BTreeMap<CredentialKey, [u8; 32]>,
}

struct Manifest {
    identity: IdentityRecord,
    invoices: Vec<InvoiceRecordKey>,
    credentials: Vec<CredentialKey>,
    outbound: Vec<CredentialKey>,
}

struct PendingMutation {
    expected: ExpectedRecord,
    encoded: Zeroizing<Vec<u8>>,
}

impl<F: RollbackFloorStore> SecretVault for KeystoreSecretVault<F> {
    type Transaction<'a>
        = KeystoreVaultTransaction<'a, F>
    where
        F: 'a;

    fn begin(&mut self) -> Result<Self::Transaction<'_>, VaultError> {
        if self.poisoned {
            return Err(VaultError::Unavailable);
        }
        load_transaction(
            &mut self.vault,
            &self.floor_store,
            &mut self.checkpoint,
            &mut self.poisoned,
        )
    }
}

impl<F: RollbackFloorStore> VaultTransaction for KeystoreVaultTransaction<'_, F> {
    fn identity(&self) -> Option<&IdentityRecord> {
        self.state.identity.as_ref()
    }

    fn insert_identity(&mut self, record: IdentityRecord) -> Result<(), VaultError> {
        if self.state.identity.is_some() {
            return Err(VaultError::Conflict);
        }
        self.state.identity = Some(record);
        Ok(())
    }

    fn invoice(&self, key: &InvoiceRecordKey) -> Option<&InvoiceRecord> {
        self.state.invoices.get(key)
    }

    fn invoice_mut(&mut self, key: &InvoiceRecordKey) -> Option<&mut InvoiceRecord> {
        self.state.invoices.get_mut(key)
    }

    fn invoice_by_digest_mut(&mut self, digest: &Digest) -> Option<&mut InvoiceRecord> {
        self.state
            .invoices
            .values_mut()
            .find(|record| record.public_digest() == *digest)
    }

    fn insert_invoice(&mut self, record: InvoiceRecord) -> Result<(), VaultError> {
        let key = record.reference().0;
        if self.state.invoices.insert(key, record).is_some() {
            return Err(VaultError::Conflict);
        }
        Ok(())
    }

    fn credential(&self, key: &CredentialKey) -> Option<&CredentialRecord> {
        self.state.credentials.get(key)
    }

    fn credential_mut(&mut self, key: &CredentialKey) -> Option<&mut CredentialRecord> {
        self.state.credentials.get_mut(key)
    }

    fn highest_credential_step(&self, channel: &ChannelKey) -> Option<u64> {
        self.state
            .credentials
            .keys()
            .filter(|key| key.channel() == *channel)
            .map(CredentialKey::step)
            .max()
    }

    fn insert_credential(&mut self, record: CredentialRecord) -> Result<(), VaultError> {
        let key = record.key();
        if self.state.credentials.insert(key, record).is_some() {
            return Err(VaultError::Conflict);
        }
        Ok(())
    }

    fn outbound_transfer(&self, source: &CredentialKey) -> Option<&OutboundTransferRecord> {
        self.state.outbound.get(source)
    }

    fn outbound_transfer_mut(&mut self, source: &CredentialKey) -> Option<&mut OutboundTransferRecord> {
        self.state.outbound.get_mut(source)
    }

    fn insert_outbound_transfer(&mut self, record: OutboundTransferRecord) -> Result<(), VaultError> {
        let key = record.source_credential();
        if self.state.outbound.insert(key, record).is_some() {
            return Err(VaultError::Conflict);
        }
        Ok(())
    }

    fn commit(self) -> Result<(), VaultError> {
        commit_transaction(self)
    }
}

fn require_holder_role(identity: VaultIdentity) -> Result<(), HolderError> {
    if identity.role() != VaultRole::Holder {
        return Err(HolderError::Vault(VaultError::Conflict));
    }
    Ok(())
}

fn map_open_error(error: KeystoreError) -> HolderError {
    HolderError::Vault(map_keystore_error(error, false))
}

fn map_keystore_error(error: KeystoreError, committing: bool) -> VaultError {
    match error {
        KeystoreError::RevisionConflict
        | KeystoreError::RecordConflict
        | KeystoreError::TransactionReplayConflict
        | KeystoreError::Locked
        | KeystoreError::FileReplaced => VaultError::Conflict,
        KeystoreError::AuthenticationFailed
        | KeystoreError::InvalidFormat
        | KeystoreError::IdentityMismatch
        | KeystoreError::CheckpointMismatch
        | KeystoreError::RollbackDetected
        | KeystoreError::InvalidRecordForRole
        | KeystoreError::InvalidSecretRecord => VaultError::CorruptRecord,
        _ if committing => VaultError::CommitFailed,
        _ => VaultError::Unavailable,
    }
}

fn load_transaction<'a, F: RollbackFloorStore>(
    vault: &'a mut Vault,
    floor_store: &'a F,
    checkpoint: &'a mut VaultCheckpoint,
    poisoned: &'a mut bool,
) -> Result<KeystoreVaultTransaction<'a, F>, VaultError> {
    let live_checkpoint = vault.checkpoint().map_err(|error| map_keystore_error(error, false))?;
    if live_checkpoint != *checkpoint {
        *poisoned = true;
        return Err(VaultError::CorruptRecord);
    }
    if !checkpoint_matches_vault(floor_store, vault.identity(), live_checkpoint) {
        *poisoned = true;
        return Err(VaultError::CorruptRecord);
    }
    let base_revision = live_checkpoint.revision();
    let identity_key = identity_record_key()?;
    let Some(view) = vault
        .get(&identity_key)
        .map_err(|error| map_keystore_error(error, false))?
    else {
        return Ok(KeystoreVaultTransaction {
            vault,
            floor_store,
            checkpoint,
            poisoned,
            base_revision,
            state: HolderState::default(),
            versions: RecordVersions::default(),
            originals: OriginalDigests::default(),
        });
    };

    let identity_bytes = Zeroizing::new(view.expose_secret().to_vec());
    let identity_version = view.version();
    let identity_digest = digest_bytes(&identity_bytes);
    let manifest = decode_identity_manifest(&identity_bytes)?;
    let mut state = HolderState {
        identity: Some(manifest.identity),
        ..HolderState::default()
    };
    let mut versions = RecordVersions {
        identity: Some(identity_version),
        ..RecordVersions::default()
    };
    let mut originals = OriginalDigests {
        identity: Some(identity_digest),
        ..OriginalDigests::default()
    };

    for key in manifest.invoices {
        let store_key = invoice_store_key(key)?;
        let (version, digest, record) = load_record(vault, &store_key, |bytes| decode_invoice_record(key, bytes))?;
        if state.invoices.insert(key, record).is_some()
            || versions.invoices.insert(key, version).is_some()
            || originals.invoices.insert(key, digest).is_some()
        {
            return Err(VaultError::CorruptRecord);
        }
    }
    for key in manifest.credentials {
        let store_key = credential_store_key(key)?;
        let (version, digest, record) = load_record(vault, &store_key, |bytes| decode_credential_record(key, bytes))?;
        if state.credentials.insert(key, record).is_some()
            || versions.credentials.insert(key, version).is_some()
            || originals.credentials.insert(key, digest).is_some()
        {
            return Err(VaultError::CorruptRecord);
        }
    }
    for key in manifest.outbound {
        let store_key = outbound_store_key(key)?;
        let (version, digest, record) = load_record(vault, &store_key, |bytes| decode_outbound_record(key, bytes))?;
        if state.outbound.insert(key, record).is_some()
            || versions.outbound.insert(key, version).is_some()
            || originals.outbound.insert(key, digest).is_some()
        {
            return Err(VaultError::CorruptRecord);
        }
    }
    validate_state_identity(&state, vault.identity())?;

    Ok(KeystoreVaultTransaction {
        vault,
        floor_store,
        checkpoint,
        poisoned,
        base_revision,
        state,
        versions,
        originals,
    })
}

fn load_record<T>(
    vault: &Vault,
    key: &RecordKey,
    decode: impl FnOnce(&[u8]) -> CodecResult<T>,
) -> Result<(RecordVersion, [u8; 32], T), VaultError> {
    let view = vault
        .get(key)
        .map_err(|error| map_keystore_error(error, false))?
        .ok_or(VaultError::CorruptRecord)?;
    let buffer = Zeroizing::new(view.expose_secret().to_vec());
    let digest = digest_bytes(&buffer);
    let decoded = decode(&buffer)?;
    Ok((view.version(), digest, decoded))
}

fn commit_transaction<F: RollbackFloorStore>(transaction: KeystoreVaultTransaction<'_, F>) -> Result<(), VaultError> {
    let KeystoreVaultTransaction {
        vault,
        floor_store,
        checkpoint,
        poisoned,
        base_revision,
        state,
        versions,
        originals,
    } = transaction;
    if state.identity.is_none()
        && (!state.invoices.is_empty() || !state.credentials.is_empty() || !state.outbound.is_empty())
    {
        return Err(VaultError::CorruptRecord);
    }
    validate_state_identity(&state, vault.identity())?;

    let mut mutations = BTreeMap::<RecordKey, PendingMutation>::new();
    if let Some(identity) = &state.identity {
        let encoded = encode_identity_manifest(identity, &state.invoices, &state.credentials, &state.outbound)?;
        add_changed(
            &mut mutations,
            identity_record_key()?,
            versions.identity,
            originals.identity,
            encoded,
        )?;
    } else if versions.identity.is_some() || originals.identity.is_some() {
        return Err(VaultError::CorruptRecord);
    }

    for (key, record) in &state.invoices {
        let encoded = encode_invoice_record(record)?;
        add_changed(
            &mut mutations,
            invoice_store_key(*key)?,
            versions.invoices.get(key).copied(),
            originals.invoices.get(key).copied(),
            encoded,
        )?;
    }
    for (key, record) in &state.credentials {
        let encoded = encode_credential_record(record)?;
        add_changed(
            &mut mutations,
            credential_store_key(*key)?,
            versions.credentials.get(key).copied(),
            originals.credentials.get(key).copied(),
            encoded,
        )?;
    }
    for (key, record) in &state.outbound {
        let encoded = encode_outbound_record(record)?;
        add_changed(
            &mut mutations,
            outbound_store_key(*key)?,
            versions.outbound.get(key).copied(),
            originals.outbound.get(key).copied(),
            encoded,
        )?;
    }
    if mutations.is_empty() {
        if !checkpoint_matches_vault(floor_store, vault.identity(), *checkpoint) {
            *poisoned = true;
            return Err(VaultError::CorruptRecord);
        }
        return Ok(());
    }
    if checkpoint.revision() != base_revision {
        *poisoned = true;
        return Err(VaultError::CorruptRecord);
    }

    let transaction_id = transaction_id(base_revision, &mutations)?;
    let result = vault.transact(base_revision, transaction_id, |update| {
        for (key, mut mutation) in mutations {
            let bytes = std::mem::take(&mut *mutation.encoded);
            update.compare_and_swap(key, mutation.expected, SecretValue::from_bytes(bytes)?)?;
        }
        Ok(())
    });
    let committed_revision = match result {
        Ok(CommitOutcome::Applied(revision) | CommitOutcome::Replayed(revision)) => revision,
        Err(error) => {
            let mapped = map_keystore_error(error, true);
            if !matches!(mapped, VaultError::Conflict) {
                *poisoned = true;
            }
            return Err(mapped);
        }
    };
    let identity = vault.identity();
    let committed_checkpoint = vault.checkpoint().map_err(|_| {
        *poisoned = true;
        VaultError::CommitFailed
    })?;
    if committed_checkpoint.revision() != committed_revision
        || reconcile_checkpoint(floor_store, identity, Some(*checkpoint), committed_checkpoint).is_err()
    {
        *poisoned = true;
        return Err(VaultError::CommitFailed);
    }
    *checkpoint = committed_checkpoint;
    Ok(())
}

fn reconcile_checkpoint<F: RollbackFloorStore>(
    floor_store: &F,
    identity: VaultIdentity,
    expected: Option<VaultCheckpoint>,
    next: VaultCheckpoint,
) -> Result<(), VaultError> {
    let outcome = floor_store.compare_and_swap_checkpoint(identity, expected, next);
    let observed = floor_store
        .load_checkpoint(identity)
        .map_err(|_| VaultError::Unavailable)?;
    if observed != Some(next) {
        return match outcome {
            Ok(CheckpointCasOutcome::Conflict(_)) => Err(VaultError::Conflict),
            _ => Err(VaultError::CommitFailed),
        };
    }
    match outcome {
        Ok(CheckpointCasOutcome::Advanced | CheckpointCasOutcome::AlreadyCurrent) | Err(_) => Ok(()),
        Ok(CheckpointCasOutcome::Conflict(_)) => Err(VaultError::Conflict),
    }
}

fn checkpoint_matches_vault<F: RollbackFloorStore>(
    floor_store: &F,
    identity: VaultIdentity,
    checkpoint: VaultCheckpoint,
) -> bool {
    floor_store
        .load_checkpoint(identity)
        .is_ok_and(|stored| stored == Some(checkpoint))
}

fn add_changed(
    mutations: &mut BTreeMap<RecordKey, PendingMutation>,
    key: RecordKey,
    version: Option<RecordVersion>,
    original_digest: Option<[u8; 32]>,
    encoded: Zeroizing<Vec<u8>>,
) -> CodecResult<()> {
    if encoded.is_empty() || encoded.len() > MAX_RECORD_VALUE_BYTES {
        return Err(VaultError::CorruptRecord);
    }
    let digest = digest_bytes(&encoded);
    if original_digest == Some(digest) {
        if version.is_none() {
            return Err(VaultError::CorruptRecord);
        }
        return Ok(());
    }
    if version.is_some() != original_digest.is_some() {
        return Err(VaultError::CorruptRecord);
    }
    let expected = version.map_or(ExpectedRecord::Absent, ExpectedRecord::Version);
    if mutations.insert(key, PendingMutation { expected, encoded }).is_some() {
        return Err(VaultError::CorruptRecord);
    }
    Ok(())
}

fn transaction_id(
    revision: VaultRevision,
    mutations: &BTreeMap<RecordKey, PendingMutation>,
) -> CodecResult<TransactionId> {
    let mut hasher = Sha256::new();
    hasher.update(TRANSACTION_DOMAIN);
    hasher.update(revision.get().to_be_bytes());
    let count = u32::try_from(mutations.len()).map_err(|_| VaultError::CorruptRecord)?;
    hasher.update(count.to_be_bytes());
    for (key, mutation) in mutations {
        hasher.update([namespace_tag(key.namespace())]);
        let key_len = u16::try_from(key.as_bytes().len()).map_err(|_| VaultError::CorruptRecord)?;
        hasher.update(key_len.to_be_bytes());
        hasher.update(key.as_bytes());
        match mutation.expected {
            ExpectedRecord::Absent => hasher.update([0]),
            ExpectedRecord::Version(version) => {
                hasher.update([1]);
                hasher.update(version.get().to_be_bytes());
            }
        }
        hasher.update(digest_bytes(&mutation.encoded));
    }
    Ok(TransactionId::new(hasher.finalize().into()))
}

fn namespace_tag(namespace: RecordNamespace) -> u8 {
    match namespace {
        RecordNamespace::WalletSeed => 1,
        RecordNamespace::PaillierKey => 2,
        RecordNamespace::Channel => 3,
        RecordNamespace::Invoice => 4,
        RecordNamespace::Credential => 5,
        RecordNamespace::CommitteeShare => 6,
        RecordNamespace::SessionNonce => 7,
        RecordNamespace::AdapterState => 8,
    }
}

fn digest_bytes(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn validate_state_identity(state: &HolderState, identity: VaultIdentity) -> CodecResult<()> {
    for invoice in state.invoices.values() {
        match invoice.public() {
            InvoicePublicRecord::Single(envelope) => validate_binding_identity(&envelope.binding, identity)?,
            InvoicePublicRecord::Threshold {
                recipient_share,
                threshold_distribution,
            } => {
                validate_binding_identity(&recipient_share.binding, identity)?;
                validate_binding_identity(&threshold_distribution.binding, identity)?;
            }
        }
    }
    for outbound in state.outbound.values() {
        validate_binding_identity(&outbound.envelope().binding, identity)?;
    }
    Ok(())
}

fn validate_binding_identity(binding: &BindingContext, identity: VaultIdentity) -> CodecResult<()> {
    let deployment = identity.deployment();
    let expected_network = to_keystore_network(binding.network).map_err(|_| VaultError::CorruptRecord)?;
    let derived_deployment = KeystoreDeploymentId::derive(expected_network, binding.deployment_id.as_bytes())
        .map_err(|_| VaultError::CorruptRecord)?;
    if identity.network() != expected_network
        || derived_deployment != deployment.deployment_id()
        || binding.committee_epoch != deployment.committee_epoch()
    {
        return Err(VaultError::CorruptRecord);
    }
    Ok(())
}

fn to_keystore_network(network: BitcoinNetwork) -> Result<thunderbolt_keystore::Network, HolderError> {
    match network {
        BitcoinNetwork::Bitcoin => Ok(thunderbolt_keystore::Network::Mainnet),
        BitcoinNetwork::Testnet => Ok(thunderbolt_keystore::Network::Testnet),
        BitcoinNetwork::Signet => Ok(thunderbolt_keystore::Network::Signet),
        BitcoinNetwork::Regtest => Ok(thunderbolt_keystore::Network::Regtest),
        BitcoinNetwork::Testnet4 => Err(HolderError::InvalidInput {
            reason: "the current keystore format cannot represent Bitcoin Testnet4",
        }),
    }
}

fn identity_record_key() -> CodecResult<RecordKey> {
    RecordKey::new(RecordNamespace::AdapterState, IDENTITY_RECORD_ID.to_vec()).map_err(|_| VaultError::CorruptRecord)
}

fn invoice_store_key(key: InvoiceRecordKey) -> CodecResult<RecordKey> {
    RecordKey::invoice(key.as_bytes().to_vec()).map_err(|_| VaultError::CorruptRecord)
}

fn credential_store_key(key: CredentialKey) -> CodecResult<RecordKey> {
    RecordKey::credential(encode_credential_key_bytes(key).to_vec()).map_err(|_| VaultError::CorruptRecord)
}

fn outbound_store_key(key: CredentialKey) -> CodecResult<RecordKey> {
    let mut id = Vec::with_capacity(OUTBOUND_RECORD_PREFIX.len() + 40);
    id.extend_from_slice(OUTBOUND_RECORD_PREFIX);
    id.extend_from_slice(&encode_credential_key_bytes(key));
    RecordKey::new(RecordNamespace::AdapterState, id).map_err(|_| VaultError::CorruptRecord)
}

fn encode_credential_key_bytes(key: CredentialKey) -> [u8; 40] {
    let mut bytes = [0_u8; 40];
    bytes[..32].copy_from_slice(key.channel().as_bytes());
    bytes[32..].copy_from_slice(&key.step().to_be_bytes());
    bytes
}

struct Encoder {
    bytes: Zeroizing<Vec<u8>>,
}

impl Encoder {
    fn new(magic: &[u8; 8]) -> Self {
        let mut bytes = Zeroizing::new(Vec::with_capacity(256));
        bytes.extend_from_slice(magic);
        bytes.extend_from_slice(&CODEC_VERSION.to_be_bytes());
        Self { bytes }
    }

    fn u8(&mut self, value: u8) {
        self.bytes.push(value);
    }

    fn u16(&mut self, value: u16) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }

    fn u32(&mut self, value: u32) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }

    fn u64(&mut self, value: u64) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }

    fn fixed(&mut self, value: &[u8]) {
        self.bytes.extend_from_slice(value);
    }

    fn bytes_u16(&mut self, value: &[u8]) -> CodecResult<()> {
        let length = u16::try_from(value.len()).map_err(|_| VaultError::CorruptRecord)?;
        self.u16(length);
        self.fixed(value);
        Ok(())
    }

    fn bytes_u32(&mut self, value: &[u8]) -> CodecResult<()> {
        let length = u32::try_from(value.len()).map_err(|_| VaultError::CorruptRecord)?;
        self.u32(length);
        self.fixed(value);
        Ok(())
    }

    fn finish(self) -> Zeroizing<Vec<u8>> {
        self.bytes
    }
}

struct Decoder<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Decoder<'a> {
    fn new(bytes: &'a [u8], magic: &[u8; 8]) -> CodecResult<Self> {
        let mut decoder = Self { bytes, offset: 0 };
        if decoder.take(8)? != magic || decoder.u16()? != CODEC_VERSION {
            return Err(VaultError::CorruptRecord);
        }
        Ok(decoder)
    }

    fn take(&mut self, length: usize) -> CodecResult<&'a [u8]> {
        let end = self.offset.checked_add(length).ok_or(VaultError::CorruptRecord)?;
        let value = self.bytes.get(self.offset..end).ok_or(VaultError::CorruptRecord)?;
        self.offset = end;
        Ok(value)
    }

    fn array<const N: usize>(&mut self) -> CodecResult<[u8; N]> {
        let mut value = [0_u8; N];
        value.copy_from_slice(self.take(N)?);
        Ok(value)
    }

    fn u8(&mut self) -> CodecResult<u8> {
        self.take(1)?.first().copied().ok_or(VaultError::CorruptRecord)
    }

    fn u16(&mut self) -> CodecResult<u16> {
        Ok(u16::from_be_bytes(self.array()?))
    }

    fn u32(&mut self) -> CodecResult<u32> {
        Ok(u32::from_be_bytes(self.array()?))
    }

    fn u64(&mut self) -> CodecResult<u64> {
        Ok(u64::from_be_bytes(self.array()?))
    }

    fn bytes_u16(&mut self, maximum: usize) -> CodecResult<&'a [u8]> {
        let length = usize::from(self.u16()?);
        if length > maximum {
            return Err(VaultError::CorruptRecord);
        }
        self.take(length)
    }

    fn bytes_u32(&mut self, maximum: usize) -> CodecResult<&'a [u8]> {
        let length = usize::try_from(self.u32()?).map_err(|_| VaultError::CorruptRecord)?;
        if length > maximum {
            return Err(VaultError::CorruptRecord);
        }
        self.take(length)
    }

    fn finish(self) -> CodecResult<()> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(VaultError::CorruptRecord)
        }
    }
}

fn encode_identity_manifest(
    identity: &IdentityRecord,
    invoices: &BTreeMap<InvoiceRecordKey, InvoiceRecord>,
    credentials: &BTreeMap<CredentialKey, CredentialRecord>,
    outbound: &BTreeMap<CredentialKey, OutboundTransferRecord>,
) -> CodecResult<Zeroizing<Vec<u8>>> {
    let total = 1_usize
        .checked_add(invoices.len())
        .and_then(|value| value.checked_add(credentials.len()))
        .and_then(|value| value.checked_add(outbound.len()))
        .ok_or(VaultError::CorruptRecord)?;
    if total > MAX_RECORDS {
        return Err(VaultError::CorruptRecord);
    }
    let mut encoder = Encoder::new(IDENTITY_MAGIC);
    encoder.fixed(identity.seed());
    encoder.u32(u32::try_from(invoices.len()).map_err(|_| VaultError::CorruptRecord)?);
    for key in invoices.keys() {
        encoder.fixed(key.as_bytes());
    }
    encoder.u32(u32::try_from(credentials.len()).map_err(|_| VaultError::CorruptRecord)?);
    for key in credentials.keys() {
        encode_credential_key(&mut encoder, *key);
    }
    encoder.u32(u32::try_from(outbound.len()).map_err(|_| VaultError::CorruptRecord)?);
    for key in outbound.keys() {
        encode_credential_key(&mut encoder, *key);
    }
    Ok(encoder.finish())
}

fn decode_identity_manifest(bytes: &[u8]) -> CodecResult<Manifest> {
    let mut decoder = Decoder::new(bytes, IDENTITY_MAGIC)?;
    let seed = Zeroizing::new(decoder.array::<32>()?);
    let identity = derive_identity(&seed).map_err(|_| VaultError::CorruptRecord)?;
    let identity = IdentityRecord::new(identity, seed);

    let invoice_count = decode_count(&mut decoder)?;
    let mut invoices = Vec::with_capacity(invoice_count);
    let mut previous_invoice = None;
    for _ in 0..invoice_count {
        let key = InvoiceRecordKey(decoder.array()?);
        if previous_invoice.is_some_and(|previous| previous >= key) {
            return Err(VaultError::CorruptRecord);
        }
        previous_invoice = Some(key);
        invoices.push(key);
    }

    let credential_count = decode_count(&mut decoder)?;
    let mut credentials = Vec::with_capacity(credential_count);
    let mut previous_credential = None;
    for _ in 0..credential_count {
        let key = decode_credential_key(&mut decoder)?;
        if previous_credential.is_some_and(|previous| previous >= key) {
            return Err(VaultError::CorruptRecord);
        }
        previous_credential = Some(key);
        credentials.push(key);
    }

    let outbound_count = decode_count(&mut decoder)?;
    let total = 1_usize
        .checked_add(invoice_count)
        .and_then(|value| value.checked_add(credential_count))
        .and_then(|value| value.checked_add(outbound_count))
        .ok_or(VaultError::CorruptRecord)?;
    if total > MAX_RECORDS {
        return Err(VaultError::CorruptRecord);
    }
    let mut outbound = Vec::with_capacity(outbound_count);
    let mut previous_outbound = None;
    for _ in 0..outbound_count {
        let key = decode_credential_key(&mut decoder)?;
        if previous_outbound.is_some_and(|previous| previous >= key) {
            return Err(VaultError::CorruptRecord);
        }
        previous_outbound = Some(key);
        outbound.push(key);
    }
    decoder.finish()?;
    Ok(Manifest {
        identity,
        invoices,
        credentials,
        outbound,
    })
}

fn decode_count(decoder: &mut Decoder<'_>) -> CodecResult<usize> {
    let count = usize::try_from(decoder.u32()?).map_err(|_| VaultError::CorruptRecord)?;
    if count > MAX_RECORDS {
        return Err(VaultError::CorruptRecord);
    }
    Ok(count)
}

fn encode_credential_key(encoder: &mut Encoder, key: CredentialKey) {
    encoder.fixed(key.channel().as_bytes());
    encoder.u64(key.step());
}

fn decode_credential_key(decoder: &mut Decoder<'_>) -> CodecResult<CredentialKey> {
    Ok(CredentialKey {
        channel: ChannelKey(decoder.array()?),
        step: decoder.u64()?,
    })
}

fn encode_acknowledgement(encoder: &mut Encoder, acknowledgement: &DurableAcknowledgement) {
    encoder.u64(acknowledgement.sequence());
    encoder.fixed(acknowledgement.entry_hash().as_bytes());
    encoder.fixed(acknowledgement.message_digest().as_bytes());
}

fn decode_acknowledgement(decoder: &mut Decoder<'_>) -> CodecResult<DurableAcknowledgement> {
    Ok(DurableAcknowledgement::new(
        decoder.u64()?,
        EntryHash::from_bytes(decoder.array()?),
        Digest::from_bytes(decoder.array()?),
    ))
}

fn encode_invoice_state(encoder: &mut Encoder, state: &InvoiceState) {
    match state {
        InvoiceState::Prepared => encoder.u8(0),
        InvoiceState::Committed(acknowledgement) => {
            encoder.u8(1);
            encode_acknowledgement(encoder, acknowledgement);
        }
        InvoiceState::Consumed {
            invoice_acknowledgement,
            transfer_acknowledgement,
        } => {
            encoder.u8(2);
            encode_acknowledgement(encoder, invoice_acknowledgement);
            encode_acknowledgement(encoder, transfer_acknowledgement);
        }
    }
}

fn decode_invoice_state(decoder: &mut Decoder<'_>) -> CodecResult<InvoiceState> {
    match decoder.u8()? {
        0 => Ok(InvoiceState::Prepared),
        1 => Ok(InvoiceState::Committed(decode_acknowledgement(decoder)?)),
        2 => Ok(InvoiceState::Consumed {
            invoice_acknowledgement: decode_acknowledgement(decoder)?,
            transfer_acknowledgement: decode_acknowledgement(decoder)?,
        }),
        _ => Err(VaultError::CorruptRecord),
    }
}

fn encode_credential_state(encoder: &mut Encoder, state: &CredentialState) {
    match state {
        CredentialState::Owned => encoder.u8(0),
        CredentialState::Transferred(acknowledgement) => {
            encoder.u8(1);
            encode_acknowledgement(encoder, acknowledgement);
        }
    }
}

fn decode_credential_state(decoder: &mut Decoder<'_>) -> CodecResult<CredentialState> {
    match decoder.u8()? {
        0 => Ok(CredentialState::Owned),
        1 => Ok(CredentialState::Transferred(decode_acknowledgement(decoder)?)),
        _ => Err(VaultError::CorruptRecord),
    }
}

fn encode_binding(encoder: &mut Encoder, binding: &BindingContext) -> CodecResult<()> {
    binding.validate_wire().map_err(|_| VaultError::CorruptRecord)?;
    encoder.u16(binding.protocol_version);
    encoder.u8(bitcoin_network_tag(binding.network));
    encoder.bytes_u16(binding.deployment_id.as_bytes())?;
    encoder.u64(binding.committee_epoch);
    encoder.bytes_u16(binding.channel_id.as_bytes())?;
    encoder.bytes_u16(binding.invoice_id.as_bytes())?;
    match binding.step {
        None => encoder.u8(0),
        Some(step) => {
            encoder.u8(1);
            encoder.u64(step);
        }
    }
    Ok(())
}

fn decode_binding(decoder: &mut Decoder<'_>) -> CodecResult<BindingContext> {
    if decoder.u16()? != PROTOCOL_VERSION {
        return Err(VaultError::CorruptRecord);
    }
    let network = bitcoin_network_from_tag(decoder.u8()?)?;
    let deployment_id = decoder.bytes_u16(MAX_DEPLOYMENT_ID_BYTES)?;
    let committee_epoch = decoder.u64()?;
    let channel_id = decoder.bytes_u16(MAX_CHANNEL_ID_BYTES)?;
    let invoice_id = decoder.bytes_u16(MAX_INVOICE_ID_BYTES)?;
    let step = match decoder.u8()? {
        0 => None,
        1 => Some(decoder.u64()?),
        _ => return Err(VaultError::CorruptRecord),
    };
    BindingContext::new(network, deployment_id, committee_epoch, channel_id, invoice_id, step)
        .map_err(|_| VaultError::CorruptRecord)
}

fn bitcoin_network_tag(network: BitcoinNetwork) -> u8 {
    match network {
        BitcoinNetwork::Bitcoin => 0,
        BitcoinNetwork::Testnet => 1,
        BitcoinNetwork::Testnet4 => 2,
        BitcoinNetwork::Signet => 3,
        BitcoinNetwork::Regtest => 4,
    }
}

fn bitcoin_network_from_tag(tag: u8) -> CodecResult<BitcoinNetwork> {
    match tag {
        0 => Ok(BitcoinNetwork::Bitcoin),
        1 => Ok(BitcoinNetwork::Testnet),
        2 => Ok(BitcoinNetwork::Testnet4),
        3 => Ok(BitcoinNetwork::Signet),
        4 => Ok(BitcoinNetwork::Regtest),
        _ => Err(VaultError::CorruptRecord),
    }
}

fn encode_point(encoder: &mut Encoder, point: &PointHex) {
    encoder.fixed(point.as_bytes());
}

fn decode_point(decoder: &mut Decoder<'_>, field: &'static str) -> CodecResult<PointHex> {
    PointHex::from_bytes(field, decoder.take(33)?).map_err(|_| VaultError::CorruptRecord)
}

fn encode_paillier_key(encoder: &mut Encoder, key: &PaillierPublicKeyHex) {
    encoder.fixed(key.as_bytes());
}

fn decode_paillier_key(decoder: &mut Decoder<'_>, field: &'static str) -> CodecResult<PaillierPublicKeyHex> {
    PaillierPublicKeyHex::from_bytes(field, decoder.take(PAILLIER_MODULUS_BYTES)?)
        .map_err(|_| VaultError::CorruptRecord)
}

fn encode_ciphertext(encoder: &mut Encoder, value: &PaillierCiphertextHex) -> CodecResult<()> {
    encoder.bytes_u16(value.as_bytes())
}

fn decode_ciphertext(decoder: &mut Decoder<'_>, field: &'static str) -> CodecResult<PaillierCiphertextHex> {
    PaillierCiphertextHex::from_bytes(field, decoder.bytes_u16(MAX_PAILLIER_CIPHERTEXT_BYTES)?)
        .map_err(|_| VaultError::CorruptRecord)
}

fn encode_nonce(encoder: &mut Encoder, value: &PaillierNonceHex) -> CodecResult<()> {
    encoder.bytes_u16(value.as_bytes())
}

fn decode_nonce(decoder: &mut Decoder<'_>, field: &'static str) -> CodecResult<PaillierNonceHex> {
    PaillierNonceHex::from_bytes(field, decoder.bytes_u16(MAX_PAILLIER_NONCE_BYTES)?)
        .map_err(|_| VaultError::CorruptRecord)
}

fn encode_response(encoder: &mut Encoder, value: &ProofResponseHex) -> CodecResult<()> {
    encoder.bytes_u16(value.as_bytes())
}

fn decode_response(decoder: &mut Decoder<'_>, field: &'static str) -> CodecResult<ProofResponseHex> {
    ProofResponseHex::from_bytes(field, decoder.bytes_u16(MAX_PROOF_RESPONSE_BYTES)?)
        .map_err(|_| VaultError::CorruptRecord)
}

fn encode_share_proof(encoder: &mut Encoder, proof: &ShareProofV1) -> CodecResult<()> {
    encode_point(encoder, &proof.a_point);
    encode_ciphertext(encoder, &proof.a_ciphertext)?;
    encode_response(encoder, &proof.z)?;
    encode_nonce(encoder, &proof.tau)
}

fn decode_share_proof(decoder: &mut Decoder<'_>) -> CodecResult<ShareProofV1> {
    Ok(ShareProofV1 {
        a_point: decode_point(decoder, "decoded share proof point")?,
        a_ciphertext: decode_ciphertext(decoder, "decoded share proof ciphertext")?,
        z: decode_response(decoder, "decoded share proof response")?,
        tau: decode_nonce(decoder, "decoded share proof nonce")?,
    })
}

fn encode_invoice_envelope(encoder: &mut Encoder, envelope: &InvoiceEnvelopeV1) -> CodecResult<()> {
    envelope.verify().map_err(|_| VaultError::CorruptRecord)?;
    encode_binding(encoder, &envelope.binding)?;
    let statement = &envelope.statement;
    encode_point(encoder, &statement.anchor_base);
    encode_paillier_key(encoder, &statement.bob_key);
    encode_paillier_key(encoder, &statement.committee_key);
    encode_point(encoder, &statement.delta);
    encode_ciphertext(encoder, &statement.bob_ciphertext)?;
    encode_ciphertext(encoder, &statement.committee_ciphertext)?;
    let proof = &envelope.proof;
    encode_point(encoder, &proof.a_delta);
    encode_ciphertext(encoder, &proof.a_bob)?;
    encode_ciphertext(encoder, &proof.a_committee)?;
    encode_response(encoder, &proof.z)?;
    encode_nonce(encoder, &proof.tau_bob)?;
    encode_nonce(encoder, &proof.tau_committee)
}

fn decode_invoice_envelope(decoder: &mut Decoder<'_>) -> CodecResult<InvoiceEnvelopeV1> {
    let envelope = InvoiceEnvelopeV1 {
        binding: decode_binding(decoder)?,
        statement: InvoiceStatementV1 {
            anchor_base: decode_point(decoder, "decoded invoice anchor base")?,
            bob_key: decode_paillier_key(decoder, "decoded invoice recipient key")?,
            committee_key: decode_paillier_key(decoder, "decoded invoice committee key")?,
            delta: decode_point(decoder, "decoded invoice delta")?,
            bob_ciphertext: decode_ciphertext(decoder, "decoded invoice recipient ciphertext")?,
            committee_ciphertext: decode_ciphertext(decoder, "decoded invoice committee ciphertext")?,
        },
        proof: InvoiceProofV1 {
            a_delta: decode_point(decoder, "decoded invoice proof delta")?,
            a_bob: decode_ciphertext(decoder, "decoded invoice proof recipient ciphertext")?,
            a_committee: decode_ciphertext(decoder, "decoded invoice proof committee ciphertext")?,
            z: decode_response(decoder, "decoded invoice proof response")?,
            tau_bob: decode_nonce(decoder, "decoded invoice proof recipient nonce")?,
            tau_committee: decode_nonce(decoder, "decoded invoice proof committee nonce")?,
        },
    };
    envelope.verify().map_err(|_| VaultError::CorruptRecord)?;
    Ok(envelope)
}

fn encode_share_envelope(encoder: &mut Encoder, envelope: &ShareEnvelopeV1) -> CodecResult<()> {
    envelope.verify().map_err(|_| VaultError::CorruptRecord)?;
    encode_binding(encoder, &envelope.binding)?;
    encode_point(encoder, &envelope.statement.anchor_base);
    encode_paillier_key(encoder, &envelope.statement.recipient_key);
    encoder.u32(envelope.statement.member_id);
    encode_point(encoder, &envelope.statement.committed_point);
    encode_ciphertext(encoder, &envelope.statement.ciphertext)?;
    encode_share_proof(encoder, &envelope.proof)
}

fn decode_share_envelope(decoder: &mut Decoder<'_>) -> CodecResult<ShareEnvelopeV1> {
    let envelope = ShareEnvelopeV1 {
        binding: decode_binding(decoder)?,
        statement: ShareStatementV1 {
            anchor_base: decode_point(decoder, "decoded share anchor base")?,
            recipient_key: decode_paillier_key(decoder, "decoded share recipient key")?,
            member_id: decoder.u32()?,
            committed_point: decode_point(decoder, "decoded share committed point")?,
            ciphertext: decode_ciphertext(decoder, "decoded share ciphertext")?,
        },
        proof: decode_share_proof(decoder)?,
    };
    envelope.verify().map_err(|_| VaultError::CorruptRecord)?;
    Ok(envelope)
}

fn encode_threshold_envelope(encoder: &mut Encoder, envelope: &ThresholdEnvelopeV1) -> CodecResult<()> {
    envelope.verify().map_err(|_| VaultError::CorruptRecord)?;
    encode_binding(encoder, &envelope.binding)?;
    let distribution = &envelope.distribution;
    encode_point(encoder, &distribution.anchor_base);
    encoder.u32(distribution.threshold);
    encode_point(encoder, &distribution.delta);
    encoder.u16(u16::try_from(distribution.polynomial_commitments.len()).map_err(|_| VaultError::CorruptRecord)?);
    for commitment in &distribution.polynomial_commitments {
        encode_point(encoder, commitment);
    }
    encoder.u16(u16::try_from(distribution.encrypted_shares.len()).map_err(|_| VaultError::CorruptRecord)?);
    for share in &distribution.encrypted_shares {
        encoder.u32(share.member_id);
        encode_paillier_key(encoder, &share.encryption_key);
        encode_ciphertext(encoder, &share.ciphertext)?;
        encode_share_proof(encoder, &share.proof)?;
    }
    Ok(())
}

fn decode_threshold_envelope(decoder: &mut Decoder<'_>) -> CodecResult<ThresholdEnvelopeV1> {
    let binding = decode_binding(decoder)?;
    let anchor_base = decode_point(decoder, "decoded threshold anchor base")?;
    let threshold = decoder.u32()?;
    let delta = decode_point(decoder, "decoded threshold delta")?;
    let commitment_count = usize::from(decoder.u16()?);
    if commitment_count == 0 || commitment_count > MAX_COMMITTEE_MEMBERS {
        return Err(VaultError::CorruptRecord);
    }
    let mut polynomial_commitments = Vec::with_capacity(commitment_count);
    for _ in 0..commitment_count {
        polynomial_commitments.push(decode_point(decoder, "decoded threshold polynomial commitment")?);
    }
    let share_count = usize::from(decoder.u16()?);
    if share_count == 0 || share_count > MAX_COMMITTEE_MEMBERS {
        return Err(VaultError::CorruptRecord);
    }
    let mut encrypted_shares = Vec::with_capacity(share_count);
    for _ in 0..share_count {
        encrypted_shares.push(ThresholdEncryptedShareV1 {
            member_id: decoder.u32()?,
            encryption_key: decode_paillier_key(decoder, "decoded threshold member key")?,
            ciphertext: decode_ciphertext(decoder, "decoded threshold member ciphertext")?,
            proof: decode_share_proof(decoder)?,
        });
    }
    let envelope = ThresholdEnvelopeV1 {
        binding,
        distribution: ThresholdDistributionV1 {
            anchor_base,
            threshold,
            delta,
            polynomial_commitments,
            encrypted_shares,
        },
    };
    envelope.verify().map_err(|_| VaultError::CorruptRecord)?;
    Ok(envelope)
}

fn encode_transfer_envelope(encoder: &mut Encoder, envelope: &TransferEnvelopeV1) -> CodecResult<()> {
    envelope.verify().map_err(|_| VaultError::CorruptRecord)?;
    encode_binding(encoder, &envelope.binding)?;
    let statement = &envelope.statement;
    encode_point(encoder, &statement.anchor_base);
    encode_paillier_key(encoder, &statement.bob_key);
    encode_point(encoder, &statement.current_anchor);
    encode_ciphertext(encoder, &statement.invoice_ciphertext)?;
    encode_ciphertext(encoder, &statement.next_holder_ciphertext)?;
    let proof = &envelope.proof;
    encode_point(encoder, &proof.a_anchor);
    encode_ciphertext(encoder, &proof.a_ciphertext)?;
    encode_response(encoder, &proof.z)?;
    encode_nonce(encoder, &proof.tau)?;
    encode_point(encoder, &envelope.anchor_transition.current_anchor);
    encode_point(encoder, &envelope.anchor_transition.delta);
    encode_point(encoder, &envelope.anchor_transition.next_anchor);
    Ok(())
}

fn decode_transfer_envelope(decoder: &mut Decoder<'_>) -> CodecResult<TransferEnvelopeV1> {
    let envelope = TransferEnvelopeV1 {
        binding: decode_binding(decoder)?,
        statement: TransferStatementV1 {
            anchor_base: decode_point(decoder, "decoded transfer anchor base")?,
            bob_key: decode_paillier_key(decoder, "decoded transfer recipient key")?,
            current_anchor: decode_point(decoder, "decoded transfer current anchor")?,
            invoice_ciphertext: decode_ciphertext(decoder, "decoded transfer invoice ciphertext")?,
            next_holder_ciphertext: decode_ciphertext(decoder, "decoded transfer next credential")?,
        },
        proof: TransferProofV1 {
            a_anchor: decode_point(decoder, "decoded transfer proof anchor")?,
            a_ciphertext: decode_ciphertext(decoder, "decoded transfer proof ciphertext")?,
            z: decode_response(decoder, "decoded transfer proof response")?,
            tau: decode_nonce(decoder, "decoded transfer proof nonce")?,
        },
        anchor_transition: AnchorTransitionV1 {
            current_anchor: decode_point(decoder, "decoded transition current anchor")?,
            delta: decode_point(decoder, "decoded transition delta")?,
            next_anchor: decode_point(decoder, "decoded transition next anchor")?,
        },
    };
    envelope.verify().map_err(|_| VaultError::CorruptRecord)?;
    Ok(envelope)
}

fn encode_invoice_record(record: &InvoiceRecord) -> CodecResult<Zeroizing<Vec<u8>>> {
    let mut encoder = Encoder::new(INVOICE_MAGIC);
    encoder.fixed(record.reference().0.as_bytes());
    encoder.fixed(record.channel().as_bytes());
    encoder.u64(record.expected_transfer_step());
    match record.public() {
        InvoicePublicRecord::Single(envelope) => {
            encoder.u8(1);
            encode_invoice_envelope(&mut encoder, envelope)?;
        }
        InvoicePublicRecord::Threshold {
            recipient_share,
            threshold_distribution,
        } => {
            encoder.u8(2);
            encode_share_envelope(&mut encoder, recipient_share)?;
            encode_threshold_envelope(&mut encoder, threshold_distribution)?;
        }
    }
    encoder.fixed(record.public_digest().as_bytes());
    encoder.fixed(record.refresh());
    let decryption_key = Zeroizing::new(record.decryption_key().to_bytes());
    encoder.bytes_u32(&decryption_key)?;
    encode_invoice_state(&mut encoder, record.state());
    Ok(encoder.finish())
}

fn decode_invoice_record(expected_key: InvoiceRecordKey, bytes: &[u8]) -> CodecResult<InvoiceRecord> {
    let mut decoder = Decoder::new(bytes, INVOICE_MAGIC)?;
    let encoded_key = InvoiceRecordKey(decoder.array()?);
    if encoded_key != expected_key {
        return Err(VaultError::CorruptRecord);
    }
    let channel = ChannelKey(decoder.array()?);
    let expected_transfer_step = decoder.u64()?;
    if expected_transfer_step == 0 {
        return Err(VaultError::CorruptRecord);
    }
    let public = match decoder.u8()? {
        1 => InvoicePublicRecord::Single(decode_invoice_envelope(&mut decoder)?),
        2 => InvoicePublicRecord::Threshold {
            recipient_share: decode_share_envelope(&mut decoder)?,
            threshold_distribution: decode_threshold_envelope(&mut decoder)?,
        },
        _ => return Err(VaultError::CorruptRecord),
    };
    let public_digest = Digest::from_bytes(decoder.array()?);
    let refresh = Zeroizing::new(decoder.array::<32>()?);
    let decryption_key_bytes = decoder.bytes_u32(256 * 1024)?;
    let decryption_key = DecryptionKey::from_bytes(decryption_key_bytes).map_err(|_| VaultError::CorruptRecord)?;
    let state = decode_invoice_state(&mut decoder)?;
    decoder.finish()?;
    validate_private_invoice_material(&public, public_digest, &refresh, &decryption_key, &state)?;

    let mut record = match public {
        InvoicePublicRecord::Single(envelope) => InvoiceRecord::new_single(
            expected_key,
            channel,
            expected_transfer_step,
            envelope,
            public_digest,
            refresh,
            decryption_key,
        ),
        InvoicePublicRecord::Threshold {
            recipient_share,
            threshold_distribution,
        } => InvoiceRecord::new_threshold(
            expected_key,
            channel,
            expected_transfer_step,
            recipient_share,
            threshold_distribution,
            public_digest,
            refresh,
            decryption_key,
        ),
    };
    record.restore_state(state);
    Ok(record)
}

fn validate_private_invoice_material(
    public: &InvoicePublicRecord,
    public_digest: Digest,
    refresh: &[u8; 32],
    decryption_key: &DecryptionKey,
    state: &InvoiceState,
) -> CodecResult<()> {
    let refresh = Scalar::from_slice(refresh).map_err(|_| VaultError::CorruptRecord)?;
    let recipient_key = EncryptionKey::from(decryption_key);
    let (anchor_base, expected_key, delta, computed_digest) = match public {
        InvoicePublicRecord::Single(envelope) => {
            envelope.verify().map_err(|_| VaultError::CorruptRecord)?;
            let (statement, _) = envelope.to_core().map_err(|_| VaultError::CorruptRecord)?;
            (
                statement.anchor_base,
                statement.bob_key,
                statement.delta,
                Digest::from_bytes(envelope.canonical_digest().map_err(|_| VaultError::CorruptRecord)?),
            )
        }
        InvoicePublicRecord::Threshold {
            recipient_share,
            threshold_distribution,
        } => {
            recipient_share.verify().map_err(|_| VaultError::CorruptRecord)?;
            threshold_distribution.verify().map_err(|_| VaultError::CorruptRecord)?;
            let (recipient, _) = recipient_share.to_core().map_err(|_| VaultError::CorruptRecord)?;
            let distribution = threshold_distribution
                .to_core()
                .map_err(|_| VaultError::CorruptRecord)?;
            if recipient_share.binding != threshold_distribution.binding
                || recipient.member_id != RECIPIENT_SHARE_MEMBER_ID
                || recipient.anchor_base != distribution.anchor_base
                || recipient.committed_point != distribution.delta
            {
                return Err(VaultError::CorruptRecord);
            }
            (
                recipient.anchor_base,
                recipient.recipient_key,
                recipient.committed_point,
                threshold_invoice_package_digest(recipient_share, threshold_distribution)
                    .map_err(|_| VaultError::CorruptRecord)?,
            )
        }
    };
    if public_digest != computed_digest
        || recipient_key.to_bytes() != expected_key.to_bytes()
        || anchor_base * refresh != delta
    {
        return Err(VaultError::CorruptRecord);
    }
    match state {
        InvoiceState::Prepared => {}
        InvoiceState::Committed(acknowledgement)
        | InvoiceState::Consumed {
            invoice_acknowledgement: acknowledgement,
            ..
        } => acknowledgement
            .require_digest(public_digest.to_bytes())
            .map_err(|_| VaultError::CorruptRecord)?,
    }
    Ok(())
}

fn encode_credential_record(record: &CredentialRecord) -> CodecResult<Zeroizing<Vec<u8>>> {
    let mut encoder = Encoder::new(CREDENTIAL_MAGIC);
    encode_credential_key(&mut encoder, record.key());
    encoder.fixed(record.secret());
    encoder.fixed(&record.anchor().serialize());
    encode_acknowledgement(&mut encoder, record.acquired_by());
    encode_credential_state(&mut encoder, record.state());
    Ok(encoder.finish())
}

fn decode_credential_record(expected_key: CredentialKey, bytes: &[u8]) -> CodecResult<CredentialRecord> {
    let mut decoder = Decoder::new(bytes, CREDENTIAL_MAGIC)?;
    let key = decode_credential_key(&mut decoder)?;
    if key != expected_key {
        return Err(VaultError::CorruptRecord);
    }
    let secret = Zeroizing::new(decoder.array::<32>()?);
    Scalar::from_slice(secret.as_ref()).map_err(|_| VaultError::CorruptRecord)?;
    let anchor = Point::from_slice(decoder.take(33)?).map_err(|_| VaultError::CorruptRecord)?;
    let acquired_by = decode_acknowledgement(&mut decoder)?;
    let state = decode_credential_state(&mut decoder)?;
    decoder.finish()?;
    let mut record = CredentialRecord::new(key, secret, anchor, acquired_by);
    record.restore_state(state);
    Ok(record)
}

fn encode_outbound_record(record: &OutboundTransferRecord) -> CodecResult<Zeroizing<Vec<u8>>> {
    let mut encoder = Encoder::new(OUTBOUND_MAGIC);
    encode_credential_key(&mut encoder, record.source_credential());
    encoder.fixed(record.invoice_digest().as_bytes());
    encode_acknowledgement(&mut encoder, record.invoice_acknowledgement());
    encode_transfer_envelope(&mut encoder, record.envelope())?;
    encoder.fixed(record.envelope_digest().as_bytes());
    match record.acknowledgement() {
        None => encoder.u8(0),
        Some(acknowledgement) => {
            encoder.u8(1);
            encode_acknowledgement(&mut encoder, acknowledgement);
        }
    }
    Ok(encoder.finish())
}

fn decode_outbound_record(expected_key: CredentialKey, bytes: &[u8]) -> CodecResult<OutboundTransferRecord> {
    let mut decoder = Decoder::new(bytes, OUTBOUND_MAGIC)?;
    let key = decode_credential_key(&mut decoder)?;
    if key != expected_key {
        return Err(VaultError::CorruptRecord);
    }
    let invoice_digest = Digest::from_bytes(decoder.array()?);
    let invoice_acknowledgement = decode_acknowledgement(&mut decoder)?;
    invoice_acknowledgement
        .require_digest(invoice_digest.to_bytes())
        .map_err(|_| VaultError::CorruptRecord)?;
    let envelope = decode_transfer_envelope(&mut decoder)?;
    let envelope_digest = Digest::from_bytes(decoder.array()?);
    let computed_digest = envelope.canonical_digest().map_err(|_| VaultError::CorruptRecord)?;
    if envelope_digest.as_bytes() != &computed_digest
        || envelope
            .binding
            .require_transfer_scope()
            .map_err(|_| VaultError::CorruptRecord)?
            != key.step().checked_add(1).ok_or(VaultError::CorruptRecord)?
    {
        return Err(VaultError::CorruptRecord);
    }
    let acknowledgement = match decoder.u8()? {
        0 => None,
        1 => Some(decode_acknowledgement(&mut decoder)?),
        _ => return Err(VaultError::CorruptRecord),
    };
    decoder.finish()?;
    if let Some(acknowledgement) = &acknowledgement {
        acknowledgement
            .require_digest(envelope_digest.to_bytes())
            .map_err(|_| VaultError::CorruptRecord)?;
    }
    let mut record =
        OutboundTransferRecord::new(key, invoice_digest, invoice_acknowledgement, envelope, envelope_digest);
    record.restore_acknowledgement(acknowledgement);
    Ok(record)
}
