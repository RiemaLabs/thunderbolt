use std::mem;

use libpaillier::EncryptionKey;
use secp::{MaybePoint, MaybeScalar, Point, Scalar};
use thunderbolt_core::paillier::decrypt_to_big_number;
use thunderbolt_core::zkp::types::big_number_to_scalar;
use thunderbolt_wire::{CanonicalDigest, ShareEnvelopeV1, ThresholdEnvelopeV1, TransferEnvelopeV1};
use zeroize::Zeroizing;

use crate::record::{
    decode_record, encode_record, verify_latest_acknowledgement, Journal, SignerSessionRecord, MAX_EVENT_HISTORY,
    MAX_SIGNING_HISTORY,
};
use crate::{
    CommitteeDescriptor, CommitteeError, CommitteeMemberId, CommitteeMemberState, CommitteeSigner, CommitteeVault,
    LedgerCommitmentVerifier, NonceCommitment, PendingRefresh, ProvisionedMemberPackage, RefreshEventBinding,
    RefreshEventId, Result, ShamirShare, SignerSessionBinding, SignerSessionId, SignerSessionPhase,
    UpdateAcknowledgement, VaultEntry, VaultStoreError,
};

/// One committee-member process backed by encrypted crash-safe storage.
///
/// The engine intentionally implements neither `Clone` nor `Debug`. It owns one
/// [`CommitteeMemberState`] and cannot access any other member's secret.
pub struct CommitteeMemberEngine<V>
where
    V: CommitteeVault,
{
    descriptor: CommitteeDescriptor,
    state: CommitteeMemberState,
    journal: Journal,
    revision: u64,
    vault: V,
    recovery_required: bool,
}

impl<V> CommitteeMemberEngine<V>
where
    V: CommitteeVault,
{
    /// Provisions an empty vault from one offline-generated member package.
    ///
    /// This is the only production initialization path. It consumes exactly one
    /// member package and has no committee-secret or reconstruction parameter.
    pub fn provision(mut vault: V, package: ProvisionedMemberPackage) -> Result<Self> {
        let (descriptor, state) = CommitteeMemberState::from_package(package);
        let journal = Journal::default();
        let plaintext = encode_record(0, &state, &state.share, &journal)?;
        match vault.create(VaultEntry::new(0, plaintext)) {
            Ok(()) => Ok(Self {
                descriptor,
                state,
                journal,
                revision: 0,
                vault,
                recovery_required: false,
            }),
            Err(VaultStoreError::Conflict { .. }) => Err(CommitteeError::VaultConflict),
            Err(VaultStoreError::Backend(error)) => Err(CommitteeError::Vault(error.to_string())),
        }
    }

    /// Opens and authenticates an existing encrypted member vault against an
    /// operator-supplied public descriptor.
    pub fn open(mut vault: V, descriptor: CommitteeDescriptor) -> Result<Self> {
        let entry = vault
            .load()
            .map_err(|error| CommitteeError::Vault(error.to_string()))?
            .ok_or(CommitteeError::InvalidVaultRecord("vault is not initialized"))?;
        let outer_revision = entry.revision();
        let decoded = decode_record(entry.plaintext())?;
        if decoded.revision != outer_revision {
            return Err(CommitteeError::InvalidVaultRecord(
                "authenticated revision does not match the encrypted record",
            ));
        }
        validate_opened_record(&descriptor, &decoded.state, &decoded.journal, decoded.revision)?;
        Ok(Self {
            descriptor,
            state: decoded.state,
            journal: decoded.journal,
            revision: decoded.revision,
            vault,
            recovery_required: false,
        })
    }

    /// Returns the public descriptor used by this process.
    #[must_use]
    pub const fn descriptor(&self) -> &CommitteeDescriptor {
        &self.descriptor
    }

    /// Returns the secret-bearing state through a non-debuggable, non-cloneable
    /// reference. Its API exposes public metadata and commitments only.
    #[must_use]
    pub const fn state(&self) -> &CommitteeMemberState {
        &self.state
    }

    /// Returns the current authenticated vault revision.
    #[must_use]
    pub const fn durable_revision(&self) -> u64 {
        self.revision
    }

    /// Returns the crash-recoverable pending event, if any.
    #[must_use]
    pub const fn pending_refresh(&self) -> Option<&PendingRefresh> {
        self.journal.pending.as_ref()
    }

    /// Returns a previously durable acknowledgement by logical event id.
    #[must_use]
    pub fn applied_acknowledgement(&self, event_id: RefreshEventId) -> Option<&UpdateAcknowledgement> {
        self.journal.applied.get(&event_id)
    }

    /// Returns the durable phase for a threshold-signing session.
    #[must_use]
    pub fn signer_session_phase(&self, session_id: SignerSessionId) -> Option<SignerSessionPhase> {
        self.journal
            .signing_sessions
            .get(&session_id)
            .map(|record| record.phase)
    }

    /// Returns the owned vault, for example after a fail-closed write error so a
    /// caller can drop/reopen and reconcile its authenticated state.
    #[must_use]
    pub fn into_vault(self) -> V {
        self.vault
    }

    /// Applies one refresh only after verifying the recipient share proof, its
    /// committee distribution, and the exact committed transfer that consumes
    /// the proven recipient ciphertext.
    ///
    /// The method verifies every public encrypted-share proof but calls Paillier
    /// decryption only for this process's member ciphertext. A successful return
    /// means the updated share and hashed acknowledgement are in the same atomic
    /// encrypted-vault revision.
    pub fn apply_committed_refresh<L>(
        &mut self,
        recipient_share: &ShareEnvelopeV1,
        threshold_refresh: &ThresholdEnvelopeV1,
        transfer: &TransferEnvelopeV1,
        ledger_verifier: &L,
        receipt: &L::Receipt,
    ) -> Result<UpdateAcknowledgement>
    where
        L: LedgerCommitmentVerifier,
    {
        self.ensure_available()?;
        validate_wire_bindings(&self.descriptor, recipient_share, threshold_refresh, transfer)?;
        let recipient_share_digest = recipient_share.canonical_digest()?;
        let threshold_refresh_digest = threshold_refresh.canonical_digest()?;
        let transfer_digest = transfer.canonical_digest()?;
        let committed = ledger_verifier
            .verify_committed(receipt)
            .map_err(|error| CommitteeError::LedgerCommitment(error.to_string()))?;
        let transfer_step = transfer.binding.step.ok_or(CommitteeError::TransferBindingMismatch)?;
        if committed.recipient_share_digest() != &recipient_share_digest
            || committed.threshold_refresh_digest() != &threshold_refresh_digest
            || committed.transfer_digest() != &transfer_digest
            || committed.transfer_step() != transfer_step
        {
            return Err(CommitteeError::LedgerCommitmentMismatch);
        }
        let requested_binding = RefreshEventBinding::new(
            recipient_share_digest,
            threshold_refresh_digest,
            transfer_digest,
            committed.invoice_entry_hash(),
            committed.transfer_entry_hash(),
            committed.committed_head_hash(),
            committed.transfer_sequence(),
            committed.transfer_step(),
        );

        if let Some(acknowledgement) = self.journal.applied.get(&requested_binding.event_id()) {
            return Ok(acknowledgement.clone());
        }

        // A replay with the exact committed event hash returns its durable
        // receipt above. New events must pass every expensive proof before the
        // vault gains pending state.
        recipient_share.verify()?;
        threshold_refresh.verify()?;
        transfer.verify()?;
        validate_exact_member_set(&self.descriptor, threshold_refresh)?;
        if self.journal.applied.len() >= MAX_EVENT_HISTORY {
            return Err(CommitteeError::EventHistoryFull);
        }
        let accepted_binding = match &self.journal.pending {
            Some(pending) if pending.binding().event_id() == requested_binding.event_id() => pending.binding().clone(),
            Some(pending) => {
                return Err(CommitteeError::PendingEventConflict {
                    pending: pending.binding().event_id(),
                    requested: requested_binding.event_id(),
                });
            }
            None => requested_binding,
        };

        let updated_share = self.compute_updated_share(threshold_refresh)?;
        if self.journal.pending.is_none() {
            let staged_revision = self.next_revision()?;
            let mut staged_journal = self.journal.clone();
            staged_journal.pending = Some(PendingRefresh::new(accepted_binding.clone(), staged_revision));
            self.persist_same_share(staged_revision, &staged_journal)?;
            self.journal = staged_journal;
            self.revision = staged_revision;
        }

        let durable_revision = self.next_revision()?;
        let updated_commitment = updated_share.public_commitment(self.descriptor.anchor_base())?;
        let acknowledgement = UpdateAcknowledgement::create(
            &accepted_binding,
            self.descriptor.id(),
            self.descriptor.epoch(),
            self.state.member_id(),
            durable_revision,
            updated_commitment,
        );
        let mut applied_journal = self.journal.clone();
        applied_journal.pending = None;
        applied_journal
            .applied
            .insert(accepted_binding.event_id(), acknowledgement.clone());
        self.persist_with_share(durable_revision, &updated_share, &applied_journal)?;
        let old_share = mem::replace(&mut self.state.share, updated_share);
        drop(old_share);
        self.journal = applied_journal;
        self.revision = durable_revision;
        Ok(acknowledgement)
    }

    /// Reserves a future signer nonce under a durably unique session id.
    ///
    /// If signer reservation fails, the `Reserved` session remains durable and
    /// cannot be retried. This intentionally sacrifices liveness to prevent
    /// nonce reuse after ambiguous crashes.
    pub fn reserve_signing_nonce<S>(
        &mut self,
        signer: &mut S,
        binding: &SignerSessionBinding,
    ) -> Result<NonceCommitment>
    where
        S: CommitteeSigner,
    {
        self.ensure_available()?;
        self.validate_signer_binding(binding)?;
        if self.journal.signing_sessions.contains_key(&binding.session_id()) {
            return Err(CommitteeError::SigningSessionReuse(binding.session_id()));
        }
        if self.journal.signing_sessions.len() >= MAX_SIGNING_HISTORY {
            return Err(CommitteeError::SigningHistoryFull);
        }

        let reserved_revision = self.next_revision()?;
        let mut reserved_journal = self.journal.clone();
        reserved_journal.signing_sessions.insert(
            binding.session_id(),
            SignerSessionRecord {
                binding: binding.clone(),
                phase: SignerSessionPhase::Reserved,
            },
        );
        self.persist_same_share(reserved_revision, &reserved_journal)?;
        self.journal = reserved_journal;
        self.revision = reserved_revision;

        let commitment = signer
            .reserve_nonce(binding)
            .map_err(|error| CommitteeError::Signer(error.to_string()))?;
        let committed_revision = self.next_revision()?;
        let mut committed_journal = self.journal.clone();
        let record = committed_journal
            .signing_sessions
            .get_mut(&binding.session_id())
            .ok_or(CommitteeError::SigningSessionMismatch)?;
        record.phase = SignerSessionPhase::NonceCommitted {
            commitment_digest: commitment.digest(),
        };
        self.persist_same_share(committed_revision, &committed_journal)?;
        self.journal = committed_journal;
        self.revision = committed_revision;
        Ok(commitment)
    }

    /// Burns a reserved nonce durably before asking the signer for one share.
    ///
    /// There is deliberately no aggregation or finalization API in this crate.
    pub fn sign_share_once<S>(
        &mut self,
        signer: &mut S,
        binding: &SignerSessionBinding,
        package: &S::SigningPackage,
    ) -> Result<S::SignatureShare>
    where
        S: CommitteeSigner,
    {
        self.ensure_available()?;
        self.validate_signer_binding(binding)?;
        let record = self
            .journal
            .signing_sessions
            .get(&binding.session_id())
            .ok_or(CommitteeError::SigningSessionMismatch)?;
        if &record.binding != binding {
            return Err(CommitteeError::SigningSessionMismatch);
        }
        let commitment_digest = match record.phase {
            SignerSessionPhase::NonceCommitted { commitment_digest } => commitment_digest,
            SignerSessionPhase::Consumed { .. } => {
                return Err(CommitteeError::SigningSessionReuse(binding.session_id()));
            }
            SignerSessionPhase::Reserved => return Err(CommitteeError::SigningSessionMismatch),
        };

        let consumed_revision = self.next_revision()?;
        let mut consumed_journal = self.journal.clone();
        let consumed_record = consumed_journal
            .signing_sessions
            .get_mut(&binding.session_id())
            .ok_or(CommitteeError::SigningSessionMismatch)?;
        consumed_record.phase = SignerSessionPhase::Consumed { commitment_digest };
        self.persist_same_share(consumed_revision, &consumed_journal)?;
        self.journal = consumed_journal;
        self.revision = consumed_revision;

        signer
            .sign_share(binding, package)
            .map_err(|error| CommitteeError::Signer(error.to_string()))
    }

    fn compute_updated_share(&self, threshold_refresh: &ThresholdEnvelopeV1) -> Result<ShamirShare> {
        let distribution = threshold_refresh.to_core()?;
        let own_share = distribution
            .encrypted_shares
            .iter()
            .find(|share| share.member_id == self.state.member_id().get())
            .ok_or(CommitteeError::MissingOwnShare(self.state.member_id()))?;
        let expected_key = EncryptionKey::from(&self.state.decryption_key);
        if own_share.encryption_key.n() != expected_key.n() {
            return Err(CommitteeError::WrongRecipientKey(self.state.member_id()));
        }
        let committed_point = evaluate_commitments(&distribution.polynomial_commitments, self.state.member_id())?;
        let plaintext = Zeroizing::new(decrypt_to_big_number(
            &self.state.decryption_key,
            &own_share.ciphertext,
        )?);
        let refresh_share = big_number_to_scalar(&plaintext)?;
        if distribution.anchor_base * refresh_share != committed_point {
            return Err(CommitteeError::ShareCommitmentMismatch);
        }
        let current_share = self.state.share.scalar()?;
        let updated_share = (current_share - refresh_share)
            .not_zero()
            .map_err(|_| CommitteeError::ZeroUpdatedShare)?;
        Ok(ShamirShare::from_scalar(updated_share))
    }

    fn validate_signer_binding(&self, binding: &SignerSessionBinding) -> Result<()> {
        if binding.descriptor_id() != self.descriptor.id()
            || binding.epoch() != self.descriptor.epoch()
            || binding.member_id() != self.state.member_id()
        {
            return Err(CommitteeError::SigningSessionMismatch);
        }
        Ok(())
    }

    fn persist_same_share(&mut self, next_revision: u64, journal: &Journal) -> Result<()> {
        let plaintext = encode_record(next_revision, &self.state, &self.state.share, journal)?;
        self.store(next_revision, plaintext)
    }

    fn persist_with_share(&mut self, next_revision: u64, share: &ShamirShare, journal: &Journal) -> Result<()> {
        let plaintext = encode_record(next_revision, &self.state, share, journal)?;
        self.store(next_revision, plaintext)
    }

    fn store(&mut self, next_revision: u64, plaintext: crate::VaultPlaintext) -> Result<()> {
        match self
            .vault
            .compare_and_swap(self.revision, VaultEntry::new(next_revision, plaintext))
        {
            Ok(()) => Ok(()),
            Err(VaultStoreError::Conflict { .. }) => {
                self.recovery_required = true;
                Err(CommitteeError::VaultConflict)
            }
            Err(VaultStoreError::Backend(error)) => {
                self.recovery_required = true;
                Err(CommitteeError::Vault(error.to_string()))
            }
        }
    }

    fn next_revision(&self) -> Result<u64> {
        self.revision.checked_add(1).ok_or(CommitteeError::RevisionExhausted)
    }

    fn ensure_available(&self) -> Result<()> {
        if self.recovery_required {
            Err(CommitteeError::RecoveryRequired)
        } else {
            Ok(())
        }
    }
}

fn validate_opened_record(
    descriptor: &CommitteeDescriptor,
    state: &CommitteeMemberState,
    journal: &Journal,
    revision: u64,
) -> Result<()> {
    if state.descriptor_id() != descriptor.id() || state.epoch() != descriptor.epoch() {
        return Err(CommitteeError::InvalidVaultRecord(
            "stored member identity does not match the public descriptor",
        ));
    }
    let public_member = descriptor
        .member(state.member_id())
        .ok_or(CommitteeError::InvalidVaultRecord(
            "stored member is not in the descriptor",
        ))?;
    let derived_key = EncryptionKey::from(&state.decryption_key);
    if derived_key.n() != public_member.encryption_key().n() {
        return Err(CommitteeError::InvalidVaultRecord(
            "stored Paillier key does not match the descriptor",
        ));
    }
    if journal.applied.is_empty()
        && state.current_share_commitment(descriptor.anchor_base())? != public_member.initial_share_commitment()
    {
        return Err(CommitteeError::InvalidVaultRecord(
            "stored initial share does not open its descriptor commitment",
        ));
    }
    for (event_id, acknowledgement) in &journal.applied {
        if acknowledgement.event_id() != *event_id
            || acknowledgement.descriptor_id() != descriptor.id()
            || acknowledgement.epoch() != descriptor.epoch()
            || acknowledgement.member_id() != state.member_id()
            || acknowledgement.durable_revision() > revision
        {
            return Err(CommitteeError::InvalidVaultRecord(
                "stored acknowledgement has inconsistent identity or revision",
            ));
        }
    }
    for (session_id, record) in &journal.signing_sessions {
        if record.binding.session_id() != *session_id
            || record.binding.descriptor_id() != descriptor.id()
            || record.binding.epoch() != descriptor.epoch()
            || record.binding.member_id() != state.member_id()
        {
            return Err(CommitteeError::InvalidVaultRecord(
                "stored signer session has inconsistent identity",
            ));
        }
    }
    if journal
        .pending
        .as_ref()
        .is_some_and(|pending| pending.staged_revision() > revision)
    {
        return Err(CommitteeError::InvalidVaultRecord(
            "pending event revision exceeds the current vault revision",
        ));
    }
    verify_latest_acknowledgement(journal, state, descriptor.anchor_base())
}

fn validate_wire_bindings(
    descriptor: &CommitteeDescriptor,
    recipient_share: &ShareEnvelopeV1,
    threshold_refresh: &ThresholdEnvelopeV1,
    transfer: &TransferEnvelopeV1,
) -> Result<()> {
    let invoice_binding = &threshold_refresh.binding;
    if recipient_share.binding != *invoice_binding {
        return Err(CommitteeError::RecipientBindingMismatch);
    }
    if recipient_share.statement.member_id != crate::RECIPIENT_SHARE_MEMBER_ID {
        return Err(CommitteeError::WrongRecipientShareId);
    }
    if recipient_share.statement.anchor_base != threshold_refresh.distribution.anchor_base
        || recipient_share.statement.committed_point != threshold_refresh.distribution.delta
    {
        return Err(CommitteeError::RecipientDeltaMismatch);
    }
    let transfer_binding = &transfer.binding;
    if invoice_binding.network != descriptor.network()
        || invoice_binding.deployment_id.as_bytes() != descriptor.deployment_id()
    {
        return Err(CommitteeError::WrongDeployment);
    }
    let actual_epoch = crate::CommitteeEpoch::new(invoice_binding.committee_epoch);
    if actual_epoch != descriptor.epoch() {
        return Err(CommitteeError::WrongEpoch {
            expected: descriptor.epoch(),
            actual: actual_epoch,
        });
    }
    if invoice_binding.protocol_version != transfer_binding.protocol_version
        || invoice_binding.network != transfer_binding.network
        || invoice_binding.deployment_id != transfer_binding.deployment_id
        || invoice_binding.committee_epoch != transfer_binding.committee_epoch
        || invoice_binding.channel_id != transfer_binding.channel_id
        || invoice_binding.invoice_id != transfer_binding.invoice_id
        || invoice_binding.step.is_some()
        || transfer_binding.step.is_none()
    {
        return Err(CommitteeError::TransferBindingMismatch);
    }
    if threshold_refresh.distribution.threshold != descriptor.threshold() {
        return Err(CommitteeError::WrongThreshold {
            expected: descriptor.threshold(),
            actual: threshold_refresh.distribution.threshold,
        });
    }
    if threshold_refresh.distribution.anchor_base.as_bytes() != descriptor.anchor_base().serialize() {
        return Err(CommitteeError::TransferBindingMismatch);
    }
    if threshold_refresh.distribution.delta != transfer.anchor_transition.delta {
        return Err(CommitteeError::TransferDeltaMismatch);
    }
    if recipient_share.statement.recipient_key != transfer.statement.bob_key
        || recipient_share.statement.ciphertext != transfer.statement.invoice_ciphertext
    {
        return Err(CommitteeError::RecipientTransferMismatch);
    }
    Ok(())
}

fn validate_exact_member_set(descriptor: &CommitteeDescriptor, threshold_refresh: &ThresholdEnvelopeV1) -> Result<()> {
    let shares = &threshold_refresh.distribution.encrypted_shares;
    if shares.len() != descriptor.members().len() {
        return Err(CommitteeError::WrongMemberSet);
    }
    for (wire_share, member) in shares.iter().zip(descriptor.members()) {
        if wire_share.member_id != member.id().get()
            || wire_share.encryption_key.as_bytes() != member.encryption_key().to_bytes()
        {
            return Err(CommitteeError::WrongMemberSet);
        }
    }
    Ok(())
}

fn scalar_from_member_id(member_id: CommitteeMemberId) -> Result<Scalar> {
    let mut bytes = [0_u8; 32];
    bytes[28..].copy_from_slice(&member_id.get().to_be_bytes());
    Scalar::from_slice(&bytes).map_err(|_| CommitteeError::InvalidMemberId)
}

fn scalar_pow(base: Scalar, exponent: usize) -> MaybeScalar {
    let mut value = MaybeScalar::one();
    for _ in 0..exponent {
        value *= base;
    }
    value
}

fn evaluate_commitments(commitments: &[Point], member_id: CommitteeMemberId) -> Result<Point> {
    let member_scalar = scalar_from_member_id(member_id)?;
    let mut result = MaybePoint::Infinity;
    for (power, commitment) in commitments.iter().enumerate() {
        result += *commitment * scalar_pow(member_scalar, power);
    }
    result.into_option().ok_or(CommitteeError::ShareCommitmentMismatch)
}
