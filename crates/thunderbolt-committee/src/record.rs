use std::collections::BTreeMap;

use libpaillier::DecryptionKey;
use secp::Point;
use sha2::{Digest, Sha256};
use thunderbolt_protocol::EntryHash;
use zeroize::Zeroizing;

use crate::signer::{SignerSessionBinding, SignerSessionId, SignerSessionPhase};
use crate::types::append_bytes;
use crate::{
    CommitteeEpoch, CommitteeError, CommitteeId, CommitteeMemberId, CommitteeMemberState, RefreshEventId, Result,
    ShamirShare, VaultPlaintext,
};

const VAULT_MAGIC: &[u8; 16] = b"THB-COMMITTEE\0\0\0";
const VAULT_FORMAT_VERSION: u16 = 1;
const MAX_DECRYPTION_KEY_BYTES: usize = 64 * 1024;
pub(crate) const MAX_EVENT_HISTORY: usize = 500_000;
pub(crate) const MAX_SIGNING_HISTORY: usize = 500_000;

/// Exact public event identity persisted before a local share update.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RefreshEventBinding {
    event_id: RefreshEventId,
    threshold_refresh_digest: [u8; 32],
    transfer_digest: [u8; 32],
    invoice_entry_hash: EntryHash,
    transfer_entry_hash: EntryHash,
    committed_head_hash: EntryHash,
    transfer_sequence: u64,
    transfer_step: u64,
}

impl RefreshEventBinding {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        threshold_refresh_digest: [u8; 32],
        transfer_digest: [u8; 32],
        invoice_entry_hash: EntryHash,
        transfer_entry_hash: EntryHash,
        committed_head_hash: EntryHash,
        transfer_sequence: u64,
        transfer_step: u64,
    ) -> Self {
        let mut hasher = Sha256::new();
        append_bytes(&mut hasher, b"bitcoin-thunderbolt/committee-refresh-event/v1");
        hasher.update(threshold_refresh_digest);
        hasher.update(transfer_digest);
        hasher.update(invoice_entry_hash.as_bytes());
        hasher.update(transfer_entry_hash.as_bytes());
        hasher.update(transfer_sequence.to_be_bytes());
        hasher.update(transfer_step.to_be_bytes());
        let event_id = RefreshEventId::from_bytes(hasher.finalize().into());
        Self {
            event_id,
            threshold_refresh_digest,
            transfer_digest,
            invoice_entry_hash,
            transfer_entry_hash,
            committed_head_hash,
            transfer_sequence,
            transfer_step,
        }
    }

    /// Returns the logical transfer event used for durable idempotency.
    #[must_use]
    pub const fn event_id(&self) -> RefreshEventId {
        self.event_id
    }

    /// Returns the exact threshold-refresh wire digest.
    #[must_use]
    pub const fn threshold_refresh_digest(&self) -> &[u8; 32] {
        &self.threshold_refresh_digest
    }

    /// Returns the exact transfer wire digest.
    #[must_use]
    pub const fn transfer_digest(&self) -> &[u8; 32] {
        &self.transfer_digest
    }

    /// Returns the committed invoice-entry hash.
    #[must_use]
    pub const fn invoice_entry_hash(&self) -> EntryHash {
        self.invoice_entry_hash
    }

    /// Returns the committed transfer-entry hash.
    #[must_use]
    pub const fn transfer_entry_hash(&self) -> EntryHash {
        self.transfer_entry_hash
    }

    /// Returns the ledger head under which the transfer was accepted.
    #[must_use]
    pub const fn committed_head_hash(&self) -> EntryHash {
        self.committed_head_hash
    }

    /// Returns the transfer ledger sequence.
    #[must_use]
    pub const fn transfer_sequence(&self) -> u64 {
        self.transfer_sequence
    }

    /// Returns the proof-bound transfer step.
    #[must_use]
    pub const fn transfer_step(&self) -> u64 {
        self.transfer_step
    }
}

/// Crash-recoverable pending refresh retained with the old durable share.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingRefresh {
    binding: RefreshEventBinding,
    staged_revision: u64,
}

impl PendingRefresh {
    pub(crate) const fn new(binding: RefreshEventBinding, staged_revision: u64) -> Self {
        Self {
            binding,
            staged_revision,
        }
    }

    /// Returns the exact pending event binding.
    #[must_use]
    pub const fn binding(&self) -> &RefreshEventBinding {
        &self.binding
    }

    /// Returns the vault revision at which the event became pending.
    #[must_use]
    pub const fn staged_revision(&self) -> u64 {
        self.staged_revision
    }
}

/// Hashed acknowledgement returned only after a share update is durable.
///
/// The acknowledgement exposes event and member metadata, never the old,
/// refresh, or updated Shamir scalar. Its digest commits to the updated public
/// share commitment without placing that commitment in the response.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UpdateAcknowledgement {
    binding: RefreshEventBinding,
    event_id: RefreshEventId,
    descriptor_id: CommitteeId,
    epoch: CommitteeEpoch,
    member_id: CommitteeMemberId,
    durable_revision: u64,
    acknowledgement_digest: [u8; 32],
}

impl UpdateAcknowledgement {
    pub(crate) fn create(
        binding: &RefreshEventBinding,
        descriptor_id: CommitteeId,
        epoch: CommitteeEpoch,
        member_id: CommitteeMemberId,
        durable_revision: u64,
        updated_share_commitment: Point,
    ) -> Self {
        let acknowledgement_digest = acknowledgement_digest(
            binding,
            descriptor_id,
            epoch,
            member_id,
            durable_revision,
            updated_share_commitment,
        );
        Self {
            binding: binding.clone(),
            event_id: binding.event_id,
            descriptor_id,
            epoch,
            member_id,
            durable_revision,
            acknowledgement_digest,
        }
    }

    /// Returns the durably applied event identifier.
    #[must_use]
    pub const fn event_id(&self) -> RefreshEventId {
        self.event_id
    }

    /// Returns the exact accepted ledger and wire binding.
    #[must_use]
    pub const fn binding(&self) -> &RefreshEventBinding {
        &self.binding
    }

    /// Returns the public committee descriptor identifier.
    #[must_use]
    pub const fn descriptor_id(&self) -> CommitteeId {
        self.descriptor_id
    }

    /// Returns the public committee epoch.
    #[must_use]
    pub const fn epoch(&self) -> CommitteeEpoch {
        self.epoch
    }

    /// Returns the acknowledging member identifier.
    #[must_use]
    pub const fn member_id(&self) -> CommitteeMemberId {
        self.member_id
    }

    /// Returns the vault revision containing the updated share and receipt.
    #[must_use]
    pub const fn durable_revision(&self) -> u64 {
        self.durable_revision
    }

    /// Returns the domain-separated durable acknowledgement hash.
    #[must_use]
    pub const fn acknowledgement_digest(&self) -> &[u8; 32] {
        &self.acknowledgement_digest
    }
}

#[derive(Clone)]
pub(crate) struct SignerSessionRecord {
    pub(crate) binding: SignerSessionBinding,
    pub(crate) phase: SignerSessionPhase,
}

#[derive(Clone, Default)]
pub(crate) struct Journal {
    pub(crate) pending: Option<PendingRefresh>,
    pub(crate) applied: BTreeMap<RefreshEventId, UpdateAcknowledgement>,
    pub(crate) signing_sessions: BTreeMap<SignerSessionId, SignerSessionRecord>,
}

pub(crate) struct DecodedRecord {
    pub(crate) revision: u64,
    pub(crate) state: CommitteeMemberState,
    pub(crate) journal: Journal,
}

pub(crate) fn encode_record(
    revision: u64,
    state: &CommitteeMemberState,
    share: &ShamirShare,
    journal: &Journal,
) -> Result<VaultPlaintext> {
    if journal.applied.len() > MAX_EVENT_HISTORY || journal.signing_sessions.len() > MAX_SIGNING_HISTORY {
        return Err(CommitteeError::InvalidVaultRecord(
            "journal count exceeds protocol bound",
        ));
    }
    let key_bytes = Zeroizing::new(
        serde_bare::to_vec(&state.decryption_key)
            .map_err(|_| CommitteeError::InvalidVaultRecord("Paillier key serialization failed"))?,
    );
    if key_bytes.is_empty() || key_bytes.len() > MAX_DECRYPTION_KEY_BYTES {
        return Err(CommitteeError::InvalidVaultRecord(
            "serialized Paillier key is outside the accepted bound",
        ));
    }

    let mut output = Zeroizing::new(Vec::with_capacity(2048));
    output.extend_from_slice(VAULT_MAGIC);
    put_u16(&mut output, VAULT_FORMAT_VERSION);
    put_u64(&mut output, revision);
    output.extend_from_slice(state.descriptor_id.as_bytes());
    put_u64(&mut output, state.epoch.get());
    put_u32(&mut output, state.member_id.get());
    put_bytes(&mut output, &key_bytes)?;
    output.extend_from_slice(share.0.as_ref());
    encode_pending(&mut output, journal.pending.as_ref());
    put_u32(
        &mut output,
        u32::try_from(journal.applied.len())
            .map_err(|_| CommitteeError::InvalidVaultRecord("applied journal count exceeds u32"))?,
    );
    for acknowledgement in journal.applied.values() {
        encode_acknowledgement(&mut output, acknowledgement);
    }
    put_u32(
        &mut output,
        u32::try_from(journal.signing_sessions.len())
            .map_err(|_| CommitteeError::InvalidVaultRecord("signing journal count exceeds u32"))?,
    );
    for record in journal.signing_sessions.values() {
        encode_signer_record(&mut output, record);
    }
    VaultPlaintext::from_zeroizing(output)
        .map_err(|_| CommitteeError::InvalidVaultRecord("encoded vault record exceeds maximum size"))
}

pub(crate) fn decode_record(plaintext: &VaultPlaintext) -> Result<DecodedRecord> {
    let mut cursor = Cursor::new(plaintext.expose_secret());
    if cursor.take(VAULT_MAGIC.len())? != VAULT_MAGIC {
        return Err(CommitteeError::InvalidVaultRecord("vault magic does not match"));
    }
    if cursor.u16()? != VAULT_FORMAT_VERSION {
        return Err(CommitteeError::InvalidVaultRecord("unsupported vault record version"));
    }
    let revision = cursor.u64()?;
    let descriptor_id = CommitteeId::from_bytes(cursor.array_32()?);
    let epoch = CommitteeEpoch::new(cursor.u64()?);
    let member_id = CommitteeMemberId::new(cursor.u32()?)
        .map_err(|_| CommitteeError::InvalidVaultRecord("stored member id is invalid"))?;
    let key_bytes = cursor.bytes(MAX_DECRYPTION_KEY_BYTES)?;
    let decryption_key: DecryptionKey = serde_bare::from_slice(key_bytes)
        .map_err(|_| CommitteeError::InvalidVaultRecord("stored Paillier key is invalid"))?;
    let share = ShamirShare::from_bytes(cursor.array_32()?)
        .map_err(|_| CommitteeError::InvalidVaultRecord("stored Shamir share is invalid"))?;
    let pending = decode_pending(&mut cursor)?;
    let applied_count = cursor.count(MAX_EVENT_HISTORY)?;
    let mut applied = BTreeMap::new();
    for _ in 0..applied_count {
        let acknowledgement = decode_acknowledgement(&mut cursor)?;
        if applied.insert(acknowledgement.event_id, acknowledgement).is_some() {
            return Err(CommitteeError::InvalidVaultRecord("duplicate applied event id"));
        }
    }
    let signing_count = cursor.count(MAX_SIGNING_HISTORY)?;
    let mut signing_sessions = BTreeMap::new();
    for _ in 0..signing_count {
        let record = decode_signer_record(&mut cursor)?;
        if signing_sessions.insert(record.binding.session_id(), record).is_some() {
            return Err(CommitteeError::InvalidVaultRecord("duplicate signing session id"));
        }
    }
    if !cursor.is_empty() {
        return Err(CommitteeError::InvalidVaultRecord("trailing vault record bytes"));
    }
    if pending
        .as_ref()
        .is_some_and(|pending| applied.contains_key(&pending.binding.event_id))
    {
        return Err(CommitteeError::InvalidVaultRecord(
            "an event cannot be pending and applied",
        ));
    }
    Ok(DecodedRecord {
        revision,
        state: CommitteeMemberState {
            descriptor_id,
            epoch,
            member_id,
            decryption_key,
            share,
        },
        journal: Journal {
            pending,
            applied,
            signing_sessions,
        },
    })
}

pub(crate) fn verify_latest_acknowledgement(
    journal: &Journal,
    state: &CommitteeMemberState,
    anchor_base: Point,
) -> Result<()> {
    let Some(latest) = journal.applied.values().max_by_key(|ack| ack.durable_revision) else {
        return Ok(());
    };
    let expected = acknowledgement_digest(
        &latest.binding,
        latest.descriptor_id,
        latest.epoch,
        latest.member_id,
        latest.durable_revision,
        state.current_share_commitment(anchor_base)?,
    );
    if expected != latest.acknowledgement_digest {
        return Err(CommitteeError::InvalidVaultRecord(
            "latest acknowledgement does not bind the current share commitment",
        ));
    }
    Ok(())
}

fn acknowledgement_digest(
    binding: &RefreshEventBinding,
    descriptor_id: CommitteeId,
    epoch: CommitteeEpoch,
    member_id: CommitteeMemberId,
    durable_revision: u64,
    updated_share_commitment: Point,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    append_bytes(&mut hasher, b"bitcoin-thunderbolt/committee-update-acknowledgement/v1");
    hasher.update(descriptor_id.as_bytes());
    hasher.update(epoch.get().to_be_bytes());
    hasher.update(member_id.get().to_be_bytes());
    hasher.update(binding.event_id.as_bytes());
    hasher.update(binding.threshold_refresh_digest);
    hasher.update(binding.transfer_digest);
    hasher.update(binding.invoice_entry_hash.as_bytes());
    hasher.update(binding.transfer_entry_hash.as_bytes());
    hasher.update(binding.committed_head_hash.as_bytes());
    hasher.update(binding.transfer_sequence.to_be_bytes());
    hasher.update(binding.transfer_step.to_be_bytes());
    hasher.update(durable_revision.to_be_bytes());
    hasher.update(updated_share_commitment.serialize());
    hasher.finalize().into()
}

fn encode_pending(output: &mut Vec<u8>, pending: Option<&PendingRefresh>) {
    match pending {
        Some(pending) => {
            output.push(1);
            encode_binding(output, &pending.binding);
            put_u64(output, pending.staged_revision);
        }
        None => output.push(0),
    }
}

fn decode_pending(cursor: &mut Cursor<'_>) -> Result<Option<PendingRefresh>> {
    match cursor.u8()? {
        0 => Ok(None),
        1 => {
            let binding = decode_binding(cursor)?;
            let staged_revision = cursor.u64()?;
            Ok(Some(PendingRefresh::new(binding, staged_revision)))
        }
        _ => Err(CommitteeError::InvalidVaultRecord("invalid pending-state tag")),
    }
}

fn encode_binding(output: &mut Vec<u8>, binding: &RefreshEventBinding) {
    output.extend_from_slice(binding.event_id.as_bytes());
    output.extend_from_slice(&binding.threshold_refresh_digest);
    output.extend_from_slice(&binding.transfer_digest);
    output.extend_from_slice(binding.invoice_entry_hash.as_bytes());
    output.extend_from_slice(binding.transfer_entry_hash.as_bytes());
    output.extend_from_slice(binding.committed_head_hash.as_bytes());
    put_u64(output, binding.transfer_sequence);
    put_u64(output, binding.transfer_step);
}

fn decode_binding(cursor: &mut Cursor<'_>) -> Result<RefreshEventBinding> {
    let stored_event_id = RefreshEventId::from_bytes(cursor.array_32()?);
    let threshold_refresh_digest = cursor.array_32()?;
    let transfer_digest = cursor.array_32()?;
    let invoice_entry_hash = EntryHash::from_bytes(cursor.array_32()?);
    let transfer_entry_hash = EntryHash::from_bytes(cursor.array_32()?);
    let committed_head_hash = EntryHash::from_bytes(cursor.array_32()?);
    let transfer_sequence = cursor.u64()?;
    let transfer_step = cursor.u64()?;
    let binding = RefreshEventBinding::new(
        threshold_refresh_digest,
        transfer_digest,
        invoice_entry_hash,
        transfer_entry_hash,
        committed_head_hash,
        transfer_sequence,
        transfer_step,
    );
    if binding.event_id != stored_event_id {
        return Err(CommitteeError::InvalidVaultRecord("refresh event id is not canonical"));
    }
    Ok(binding)
}

fn encode_acknowledgement(output: &mut Vec<u8>, acknowledgement: &UpdateAcknowledgement) {
    encode_binding(output, &acknowledgement.binding);
    output.extend_from_slice(acknowledgement.event_id.as_bytes());
    output.extend_from_slice(acknowledgement.descriptor_id.as_bytes());
    put_u64(output, acknowledgement.epoch.get());
    put_u32(output, acknowledgement.member_id.get());
    put_u64(output, acknowledgement.durable_revision);
    output.extend_from_slice(&acknowledgement.acknowledgement_digest);
}

fn decode_acknowledgement(cursor: &mut Cursor<'_>) -> Result<UpdateAcknowledgement> {
    let binding = decode_binding(cursor)?;
    let event_id = RefreshEventId::from_bytes(cursor.array_32()?);
    if binding.event_id != event_id {
        return Err(CommitteeError::InvalidVaultRecord(
            "acknowledgement event id does not match its binding",
        ));
    }
    Ok(UpdateAcknowledgement {
        binding,
        event_id,
        descriptor_id: CommitteeId::from_bytes(cursor.array_32()?),
        epoch: CommitteeEpoch::new(cursor.u64()?),
        member_id: CommitteeMemberId::new(cursor.u32()?)
            .map_err(|_| CommitteeError::InvalidVaultRecord("invalid acknowledgement member id"))?,
        durable_revision: cursor.u64()?,
        acknowledgement_digest: cursor.array_32()?,
    })
}

fn encode_signer_record(output: &mut Vec<u8>, record: &SignerSessionRecord) {
    output.extend_from_slice(record.binding.session_id().as_bytes());
    output.extend_from_slice(record.binding.descriptor_id().as_bytes());
    put_u64(output, record.binding.epoch().get());
    put_u32(output, record.binding.member_id().get());
    output.extend_from_slice(record.binding.message_digest());
    output.extend_from_slice(record.binding.coordinator_session_digest());
    match record.phase {
        SignerSessionPhase::Reserved => output.push(1),
        SignerSessionPhase::NonceCommitted { commitment_digest } => {
            output.push(2);
            output.extend_from_slice(&commitment_digest);
        }
        SignerSessionPhase::Consumed { commitment_digest } => {
            output.push(3);
            output.extend_from_slice(&commitment_digest);
        }
    }
}

fn decode_signer_record(cursor: &mut Cursor<'_>) -> Result<SignerSessionRecord> {
    let session_id = SignerSessionId::from_bytes(cursor.array_32()?);
    let descriptor_id = CommitteeId::from_bytes(cursor.array_32()?);
    let epoch = CommitteeEpoch::new(cursor.u64()?);
    let member_id = CommitteeMemberId::new(cursor.u32()?)
        .map_err(|_| CommitteeError::InvalidVaultRecord("invalid signer member id"))?;
    let message_digest = cursor.array_32()?;
    let coordinator_session_digest = cursor.array_32()?;
    let phase = match cursor.u8()? {
        1 => SignerSessionPhase::Reserved,
        2 => SignerSessionPhase::NonceCommitted {
            commitment_digest: cursor.array_32()?,
        },
        3 => SignerSessionPhase::Consumed {
            commitment_digest: cursor.array_32()?,
        },
        _ => return Err(CommitteeError::InvalidVaultRecord("invalid signer-session phase")),
    };
    Ok(SignerSessionRecord {
        binding: SignerSessionBinding::from_parts(
            session_id,
            descriptor_id,
            epoch,
            member_id,
            message_digest,
            coordinator_session_digest,
        ),
        phase,
    })
}

fn put_u16(output: &mut Vec<u8>, value: u16) {
    output.extend_from_slice(&value.to_be_bytes());
}

fn put_u32(output: &mut Vec<u8>, value: u32) {
    output.extend_from_slice(&value.to_be_bytes());
}

fn put_u64(output: &mut Vec<u8>, value: u64) {
    output.extend_from_slice(&value.to_be_bytes());
}

fn put_bytes(output: &mut Vec<u8>, bytes: &[u8]) -> Result<()> {
    let length = u32::try_from(bytes.len())
        .map_err(|_| CommitteeError::InvalidVaultRecord("record field length exceeds u32"))?;
    put_u32(output, length);
    output.extend_from_slice(bytes);
    Ok(())
}

struct Cursor<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Cursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8]> {
        let end = self
            .position
            .checked_add(length)
            .ok_or(CommitteeError::InvalidVaultRecord("record offset overflow"))?;
        let value = self
            .bytes
            .get(self.position..end)
            .ok_or(CommitteeError::InvalidVaultRecord("truncated vault record"))?;
        self.position = end;
        Ok(value)
    }

    fn u8(&mut self) -> Result<u8> {
        self.take(1)?
            .first()
            .copied()
            .ok_or(CommitteeError::InvalidVaultRecord("truncated u8"))
    }

    fn u16(&mut self) -> Result<u16> {
        let bytes =
            <[u8; 2]>::try_from(self.take(2)?).map_err(|_| CommitteeError::InvalidVaultRecord("truncated u16"))?;
        Ok(u16::from_be_bytes(bytes))
    }

    fn u32(&mut self) -> Result<u32> {
        let bytes =
            <[u8; 4]>::try_from(self.take(4)?).map_err(|_| CommitteeError::InvalidVaultRecord("truncated u32"))?;
        Ok(u32::from_be_bytes(bytes))
    }

    fn u64(&mut self) -> Result<u64> {
        let bytes =
            <[u8; 8]>::try_from(self.take(8)?).map_err(|_| CommitteeError::InvalidVaultRecord("truncated u64"))?;
        Ok(u64::from_be_bytes(bytes))
    }

    fn array_32(&mut self) -> Result<[u8; 32]> {
        <[u8; 32]>::try_from(self.take(32)?).map_err(|_| CommitteeError::InvalidVaultRecord("truncated 32-byte field"))
    }

    fn bytes(&mut self, maximum: usize) -> Result<&'a [u8]> {
        let length = usize::try_from(self.u32()?)
            .map_err(|_| CommitteeError::InvalidVaultRecord("record length does not fit usize"))?;
        if length == 0 || length > maximum {
            return Err(CommitteeError::InvalidVaultRecord(
                "record field length is outside its bound",
            ));
        }
        self.take(length)
    }

    fn count(&mut self, maximum: usize) -> Result<usize> {
        let count = usize::try_from(self.u32()?)
            .map_err(|_| CommitteeError::InvalidVaultRecord("record count does not fit usize"))?;
        if count > maximum {
            return Err(CommitteeError::InvalidVaultRecord("record count exceeds its bound"));
        }
        Ok(count)
    }

    const fn is_empty(&self) -> bool {
        self.position == self.bytes.len()
    }
}
