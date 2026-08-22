use libpaillier::{unknown_order::BigNumber, Ciphertext, DecryptionKey, EncryptionKey, Nonce};
use secp::{MaybePoint, MaybeScalar, Scalar};
use sha2::{Digest as _, Sha256};
use thunderbolt_core::paillier::{
    add_ciphertexts, encrypt_plaintext, random_nonce_in_group, validate_protocol_encryption_key,
};
use thunderbolt_core::threshold::create_threshold_refresh_distribution;
use thunderbolt_core::zkp::types::{reduce_big_number_mod_curve_order, scalar_to_big_number};
use thunderbolt_core::zkp::{
    prove_invoice, prove_share_encryption, prove_transfer, InvoiceStatement, InvoiceWitness, ShareEncryptionStatement,
    ShareEncryptionWitness, TransferStatement, TransferWitness,
};
use thunderbolt_protocol::{Digest, InvoiceId, ParticipantId};
use thunderbolt_wire::{
    CanonicalDigest, InvoiceEnvelopeV1, ShareEnvelopeV1, ThresholdEnvelopeV1, TransferEnvelopeV1,
    RECIPIENT_SHARE_MEMBER_ID,
};
use zeroize::Zeroizing;

use crate::error::{crypto_error, HolderError, VaultError};
use crate::types::{
    invoice_record_key, scalar_from_secret, threshold_invoice_package_digest, ChannelContext, CommittedInvoice,
    CommittedThresholdInvoice, CommittedTransfer, CredentialKey, CredentialSummary, GenesisCredential, HolderIdentity,
    InvoiceRequest, PreparedInvoice, PreparedThresholdInvoice, PreparedTransfer, PrivateInvoiceRecordRef,
    ReceiveDisposition, ThresholdInvoiceRequest, ThresholdRoster, TransferAcknowledgementDisposition, VerifiedInvoice,
    VerifiedInvoiceMessages,
};
use crate::vault::{
    CredentialRecord, CredentialState, IdentityRecord, InvoicePublicRecord, InvoiceRecord, InvoiceState,
    OutboundTransferRecord, SecretVault, VaultTransaction,
};

const IDENTITY_DERIVATION_DOMAIN: &[u8] = b"bitcoin-thunderbolt/holder/identity/v1";
const IDENTITY_ID_DOMAIN: &[u8] = b"bitcoin-thunderbolt/holder/participant-id/v1";

/// Local Holder/Recipient protocol engine backed by a transactional secret
/// vault. Every mutating operation commits all state changes atomically before
/// returning a public artifact.
#[derive(Debug)]
pub struct HolderEngine<V> {
    vault: V,
}

impl<V: SecretVault> HolderEngine<V> {
    pub const fn new(vault: V) -> Self {
        Self { vault }
    }

    pub fn into_vault(self) -> V {
        self.vault
    }

    /// Initializes an idempotent Holder identity from a fresh OS-random seed.
    /// The seed is persisted before the public identity is returned.
    pub fn initialize(&mut self) -> Result<HolderIdentity, HolderError> {
        let mut transaction = self.vault.begin()?;
        if let Some(record) = transaction.identity() {
            let derived = derive_identity(record.seed())?;
            if &derived != record.identity() {
                return Err(VaultError::CorruptRecord.into());
            }
            let identity = record.identity().clone();
            transaction.commit()?;
            return Ok(identity);
        }

        let mut seed = Zeroizing::new([0_u8; 32]);
        getrandom::fill(seed.as_mut()).map_err(|_| HolderError::EntropyUnavailable)?;
        let identity = derive_identity(&seed)?;
        transaction.insert_identity(IdentityRecord::new(identity.clone(), seed))?;
        transaction.commit()?;
        Ok(identity)
    }

    pub fn identity(&mut self) -> Result<HolderIdentity, HolderError> {
        let transaction = self.vault.begin()?;
        let identity = transaction
            .identity()
            .ok_or(HolderError::IdentityNotInitialized)?
            .identity()
            .clone();
        transaction.commit()?;
        Ok(identity)
    }

    /// Installs the already committed initial credential for a channel.
    /// Replaying the exact installation is idempotent; no later credential can
    /// be overwritten or rolled back to step zero.
    pub fn install_genesis_credential(
        &mut self,
        genesis: GenesisCredential,
    ) -> Result<ReceiveDisposition, HolderError> {
        let mut transaction = self.vault.begin()?;
        require_identity(&transaction)?;
        let channel = genesis.channel.key();
        let key = CredentialKey { channel, step: 0 };

        if let Some(existing) = transaction.credential(&key) {
            if existing.anchor() != genesis.anchor || existing.acquired_by() != &genesis.acknowledgement {
                return Err(HolderError::StateConflict);
            }
            transaction.commit()?;
            return Ok(ReceiveDisposition::AlreadyRecorded);
        }
        if transaction.highest_credential_step(&channel).is_some() {
            return Err(HolderError::StateConflict);
        }

        transaction.insert_credential(CredentialRecord::new(
            key,
            genesis.secret.into_bytes(),
            genesis.anchor,
            genesis.acknowledgement,
        ))?;
        transaction.commit()?;
        Ok(ReceiveDisposition::OwnershipRecorded)
    }

    /// Creates and transactionally stores a Recipient Paillier key, refresh,
    /// and Invoice Consistency Proof before returning the public envelope.
    pub fn create_invoice(&mut self, request: InvoiceRequest) -> Result<PreparedInvoice, HolderError> {
        let decryption_key = DecryptionKey::random().ok_or(HolderError::KeyGenerationFailed)?;
        let refresh = random_scalar_secret()?;
        let bob_key = EncryptionKey::from(&decryption_key);
        let bob_nonce = random_nonce_in_group(&bob_key);
        let committee_nonce = random_nonce_in_group(&request.committee_key);
        self.create_invoice_with_material(
            request,
            InvoiceMaterial {
                decryption_key,
                refresh,
                bob_nonce,
                committee_nonce,
            },
        )
    }

    fn create_invoice_with_material(
        &mut self,
        request: InvoiceRequest,
        material: InvoiceMaterial,
    ) -> Result<PreparedInvoice, HolderError> {
        let binding = request.channel.invoice_binding(&request.invoice_id)?;
        let channel_key = request.channel.key();
        let record_key = invoice_record_key(
            channel_key,
            request.invoice_id.as_str().as_bytes(),
            request.expected_transfer_step,
        );
        let mut transaction = self.vault.begin()?;
        require_identity(&transaction)?;

        if let Some(existing) = transaction.invoice(&record_key) {
            let InvoicePublicRecord::Single(envelope) = existing.public() else {
                return Err(HolderError::StateConflict);
            };
            let (statement, _) = envelope.to_core()?;
            if statement.committee_key.to_bytes() != request.committee_key.to_bytes()
                || statement.anchor_base != request.channel.anchor_base()
            {
                return Err(HolderError::StateConflict);
            }
            let prepared = PreparedInvoice {
                envelope: envelope.clone(),
                private_record: existing.reference(),
            };
            transaction.commit()?;
            return Ok(prepared);
        }

        let refresh_scalar = scalar_from_secret(&material.refresh)?;
        let refresh_integer = Zeroizing::new(scalar_to_big_number(refresh_scalar));
        let bob_key = EncryptionKey::from(&material.decryption_key);
        validate_protocol_encryption_key(&bob_key).map_err(|error| crypto_error("recipient key validation", error))?;
        let bob_ciphertext = encrypt_plaintext(&bob_key, &refresh_integer, &material.bob_nonce)
            .map_err(|error| crypto_error("recipient refresh encryption", error))?;
        let committee_ciphertext =
            encrypt_plaintext(&request.committee_key, &refresh_integer, &material.committee_nonce)
                .map_err(|error| crypto_error("committee refresh encryption", error))?;
        let statement = InvoiceStatement {
            context: binding.proof_context()?,
            anchor_base: request.channel.anchor_base(),
            bob_key,
            committee_key: request.committee_key,
            delta: request.channel.anchor_base() * refresh_scalar,
            bob_ciphertext,
            committee_ciphertext,
        };
        let proof = prove_invoice(
            &statement,
            &InvoiceWitness {
                refresh: refresh_scalar,
                bob_nonce: material.bob_nonce,
                committee_nonce: material.committee_nonce,
            },
        )
        .map_err(|error| crypto_error("invoice consistency proof creation", error))?;
        let envelope = InvoiceEnvelopeV1::from_core(binding, &statement, &proof)?;
        let envelope_digest = Digest::from_bytes(envelope.canonical_digest()?);
        let record = InvoiceRecord::new_single(
            record_key,
            channel_key,
            request.expected_transfer_step,
            envelope.clone(),
            envelope_digest,
            material.refresh,
            material.decryption_key,
        );
        let private_record = record.reference();
        transaction.insert_invoice(record)?;
        transaction.commit()?;
        Ok(PreparedInvoice {
            envelope,
            private_record,
        })
    }

    /// Creates the threshold Invoice package over one sampled refresh: a
    /// Recipient `tb/share` proof under the reserved Recipient member id and a
    /// threshold VESS distribution for the exact roster. Both public messages
    /// are returned only after the private refresh/key record is durable.
    ///
    /// The implemented Recipient transcript is `tb/share`; this method does
    /// not claim it is the paper's exact `R_inv^thr` transcript.
    pub fn create_threshold_invoice(
        &mut self,
        request: ThresholdInvoiceRequest,
    ) -> Result<PreparedThresholdInvoice, HolderError> {
        let decryption_key = DecryptionKey::random().ok_or(HolderError::KeyGenerationFailed)?;
        let refresh = random_scalar_secret()?;
        let recipient_key = EncryptionKey::from(&decryption_key);
        let recipient_nonce = random_nonce_in_group(&recipient_key);
        self.create_threshold_invoice_with_material(
            request,
            ThresholdInvoiceMaterial {
                decryption_key,
                refresh,
                recipient_nonce,
            },
        )
    }

    fn create_threshold_invoice_with_material(
        &mut self,
        request: ThresholdInvoiceRequest,
        material: ThresholdInvoiceMaterial,
    ) -> Result<PreparedThresholdInvoice, HolderError> {
        let binding = request.channel.invoice_binding(&request.invoice_id)?;
        let channel_key = request.channel.key();
        let record_key = invoice_record_key(
            channel_key,
            request.invoice_id.as_str().as_bytes(),
            request.expected_transfer_step,
        );
        let mut transaction = self.vault.begin()?;
        require_identity(&transaction)?;

        if let Some(existing) = transaction.invoice(&record_key) {
            let InvoicePublicRecord::Threshold {
                recipient_share,
                threshold_distribution,
            } = existing.public()
            else {
                return Err(HolderError::StateConflict);
            };
            validate_threshold_package(
                &request.channel,
                &request.invoice_id,
                &request.roster,
                recipient_share,
                threshold_distribution,
            )?;
            let prepared = PreparedThresholdInvoice {
                recipient_share: recipient_share.clone(),
                threshold_distribution: threshold_distribution.clone(),
                private_record: existing.reference(),
            };
            transaction.commit()?;
            return Ok(prepared);
        }

        let refresh = scalar_from_secret(&material.refresh)?;
        let context = binding.proof_context()?;
        let distribution = create_threshold_refresh_distribution(
            context.clone(),
            request.channel.anchor_base(),
            request.roster.threshold(),
            refresh,
            request.roster.members(),
        )
        .map_err(|error| crypto_error("threshold refresh distribution creation", error))?;
        let threshold_distribution = ThresholdEnvelopeV1::from_core(binding.clone(), &distribution)?;

        let recipient_key = EncryptionKey::from(&material.decryption_key);
        validate_protocol_encryption_key(&recipient_key)
            .map_err(|error| crypto_error("recipient key validation", error))?;
        let refresh_integer = Zeroizing::new(scalar_to_big_number(refresh));
        let recipient_ciphertext = encrypt_plaintext(&recipient_key, &refresh_integer, &material.recipient_nonce)
            .map_err(|error| crypto_error("recipient refresh encryption", error))?;
        let recipient_statement = ShareEncryptionStatement {
            context,
            anchor_base: request.channel.anchor_base(),
            recipient_key,
            member_id: RECIPIENT_SHARE_MEMBER_ID,
            committed_point: distribution.delta,
            ciphertext: recipient_ciphertext,
        };
        let recipient_proof = prove_share_encryption(
            &recipient_statement,
            &ShareEncryptionWitness {
                secret: refresh,
                nonce: material.recipient_nonce,
            },
        )
        .map_err(|error| crypto_error("threshold Recipient share proof creation", error))?;
        let recipient_share = ShareEnvelopeV1::from_core(binding, &recipient_statement, &recipient_proof)?;
        validate_threshold_package(
            &request.channel,
            &request.invoice_id,
            &request.roster,
            &recipient_share,
            &threshold_distribution,
        )?;
        let public_digest = threshold_invoice_package_digest(&recipient_share, &threshold_distribution)?;
        let record = InvoiceRecord::new_threshold(
            record_key,
            channel_key,
            request.expected_transfer_step,
            recipient_share.clone(),
            threshold_distribution.clone(),
            public_digest,
            material.refresh,
            material.decryption_key,
        );
        let private_record = record.reference();
        transaction.insert_invoice(record)?;
        transaction.commit()?;
        Ok(PreparedThresholdInvoice {
            recipient_share,
            threshold_distribution,
            private_record,
        })
    }

    /// Verifies proof, context, expected transfer step, and durable commit.
    /// The returned capability is required by [`Self::create_transfer`]. If
    /// this engine created the invoice, its private record advances
    /// monotonically from Prepared to Committed in the same transaction.
    pub fn verify_committed_invoice(
        &mut self,
        channel: &ChannelContext,
        invoice_id: &InvoiceId,
        committed: CommittedInvoice,
    ) -> Result<VerifiedInvoice, HolderError> {
        committed.envelope.verify()?;
        if !channel.matches_binding(&committed.envelope.binding)
            || committed.envelope.binding.invoice_id.as_bytes() != invoice_id.as_str().as_bytes()
        {
            return Err(HolderError::PrivateStateMismatch);
        }
        let (statement, _) = committed.envelope.to_core()?;
        if statement.anchor_base != channel.anchor_base() {
            return Err(HolderError::PrivateStateMismatch);
        }
        let digest = committed.envelope.canonical_digest()?;
        committed.acknowledgement.require_digest(digest)?;

        let mut transaction = self.vault.begin()?;
        require_identity(&transaction)?;
        let record_key = invoice_record_key(
            channel.key(),
            invoice_id.as_str().as_bytes(),
            committed.expected_transfer_step,
        );
        let public_digest = Digest::from_bytes(digest);
        if let Some(record) = transaction.invoice_by_digest_mut(&public_digest) {
            if record.reference() != PrivateInvoiceRecordRef(record_key)
                || record.expected_transfer_step() != committed.expected_transfer_step
                || record.public() != &InvoicePublicRecord::Single(committed.envelope.clone())
            {
                return Err(HolderError::PrivateStateMismatch);
            }
            let _ = record.mark_committed(committed.acknowledgement.clone())?;
        }
        transaction.commit()?;

        Ok(VerifiedInvoice {
            channel: channel.clone(),
            invoice_id: invoice_id.clone(),
            messages: VerifiedInvoiceMessages::Single(committed.envelope),
            anchor_base: statement.anchor_base,
            recipient_key: statement.bob_key,
            delta: statement.delta,
            recipient_ciphertext: statement.bob_ciphertext,
            public_digest,
            expected_transfer_step: committed.expected_transfer_step,
            acknowledgement: committed.acknowledgement,
        })
    }

    /// Verifies a committed two-message threshold Invoice against the exact
    /// trusted roster. The returned transfer capability uses the Recipient
    /// ciphertext and delta shared by both messages.
    pub fn verify_committed_threshold_invoice(
        &mut self,
        channel: &ChannelContext,
        invoice_id: &InvoiceId,
        roster: &ThresholdRoster,
        committed: CommittedThresholdInvoice,
    ) -> Result<VerifiedInvoice, HolderError> {
        validate_threshold_package(
            channel,
            invoice_id,
            roster,
            &committed.recipient_share,
            &committed.threshold_distribution,
        )?;
        let (recipient_statement, _) = committed.recipient_share.to_core()?;
        let public_digest =
            threshold_invoice_package_digest(&committed.recipient_share, &committed.threshold_distribution)?;
        committed.acknowledgement.require_digest(public_digest.to_bytes())?;

        let mut transaction = self.vault.begin()?;
        require_identity(&transaction)?;
        let record_key = invoice_record_key(
            channel.key(),
            invoice_id.as_str().as_bytes(),
            committed.expected_transfer_step,
        );
        if let Some(record) = transaction.invoice_by_digest_mut(&public_digest) {
            let expected_public = InvoicePublicRecord::Threshold {
                recipient_share: committed.recipient_share.clone(),
                threshold_distribution: committed.threshold_distribution.clone(),
            };
            if record.reference() != PrivateInvoiceRecordRef(record_key)
                || record.expected_transfer_step() != committed.expected_transfer_step
                || record.public() != &expected_public
            {
                return Err(HolderError::PrivateStateMismatch);
            }
            let _ = record.mark_committed(committed.acknowledgement.clone())?;
        }
        transaction.commit()?;

        Ok(VerifiedInvoice {
            channel: channel.clone(),
            invoice_id: invoice_id.clone(),
            messages: VerifiedInvoiceMessages::Threshold {
                recipient_share: committed.recipient_share,
                threshold_distribution: committed.threshold_distribution,
            },
            anchor_base: recipient_statement.anchor_base,
            recipient_key: recipient_statement.recipient_key,
            delta: recipient_statement.committed_point,
            recipient_ciphertext: recipient_statement.ciphertext,
            public_digest,
            expected_transfer_step: committed.expected_transfer_step,
            acknowledgement: committed.acknowledgement,
        })
    }

    /// Creates the next-holder ciphertext, next anchor, and Transfer
    /// Consistency Proof from the retained current credential. An identical
    /// retry returns the originally stored public envelope, including its
    /// original proof randomness.
    pub fn create_transfer(&mut self, invoice: &VerifiedInvoice) -> Result<PreparedTransfer, HolderError> {
        let bob_nonce = random_nonce_in_group(&invoice.recipient_key);
        self.create_transfer_with_nonce(invoice, bob_nonce)
    }

    fn create_transfer_with_nonce(
        &mut self,
        invoice: &VerifiedInvoice,
        holder_nonce: Nonce,
    ) -> Result<PreparedTransfer, HolderError> {
        validate_verified_invoice(invoice)?;
        invoice
            .acknowledgement
            .require_digest(invoice.public_digest.to_bytes())?;
        let source_step = invoice
            .expected_transfer_step
            .checked_sub(1)
            .ok_or(HolderError::InvalidStep)?;
        let source_key = CredentialKey {
            channel: invoice.channel.key(),
            step: source_step,
        };
        let mut transaction = self.vault.begin()?;
        require_identity(&transaction)?;

        if let Some(existing) = transaction.outbound_transfer(&source_key) {
            if existing.invoice_digest() != invoice.public_digest
                || existing.invoice_acknowledgement() != &invoice.acknowledgement
            {
                return Err(HolderError::StateConflict);
            }
            let prepared = PreparedTransfer {
                envelope: existing.envelope().clone(),
                source_credential: source_key,
            };
            transaction.commit()?;
            return Ok(prepared);
        }

        let credential = transaction
            .credential(&source_key)
            .ok_or(HolderError::CredentialNotFound)?;
        if !matches!(credential.state(), CredentialState::Owned) {
            return Err(HolderError::StateConflict);
        }
        let holder_secret = scalar_from_secret(credential.secret())?;
        let current_anchor = credential.anchor();
        if invoice.channel.anchor_base() * holder_secret != current_anchor {
            return Err(VaultError::CorruptRecord.into());
        }
        if invoice.anchor_base != invoice.channel.anchor_base() {
            return Err(HolderError::PrivateStateMismatch);
        }
        let next_anchor = match current_anchor + invoice.delta {
            MaybePoint::Valid(point) => point,
            MaybePoint::Infinity => return Err(HolderError::PointAtInfinity),
        };
        let holder_integer = Zeroizing::new(scalar_to_big_number(holder_secret));
        let holder_component = encrypt_plaintext(&invoice.recipient_key, &holder_integer, &holder_nonce)
            .map_err(|error| crypto_error("next-holder credential encryption", error))?;
        let next_holder_ciphertext =
            add_ciphertexts(&invoice.recipient_key, &holder_component, &invoice.recipient_ciphertext)
                .map_err(|error| crypto_error("next-holder ciphertext composition", error))?;
        let binding = invoice
            .channel
            .transfer_binding(&invoice.invoice_id, invoice.expected_transfer_step)?;
        let transfer_statement = TransferStatement {
            context: binding.proof_context()?,
            anchor_base: invoice.channel.anchor_base(),
            bob_key: invoice.recipient_key.clone(),
            current_anchor,
            invoice_ciphertext: invoice.recipient_ciphertext.clone(),
            next_holder_ciphertext,
        };
        let proof = prove_transfer(
            &transfer_statement,
            &TransferWitness {
                holder_secret,
                holder_nonce,
            },
        )
        .map_err(|error| crypto_error("transfer consistency proof creation", error))?;
        let envelope =
            TransferEnvelopeV1::from_core(binding, &transfer_statement, &proof, &invoice.delta, &next_anchor)?;
        let envelope_digest = Digest::from_bytes(envelope.canonical_digest()?);
        transaction.insert_outbound_transfer(OutboundTransferRecord::new(
            source_key,
            invoice.public_digest,
            invoice.acknowledgement.clone(),
            envelope.clone(),
            envelope_digest,
        ))?;
        transaction.commit()?;
        Ok(PreparedTransfer {
            envelope,
            source_credential: source_key,
        })
    }

    /// Applies the durable acknowledgement for a previously prepared outbound
    /// transfer. The old credential remains present; only its status advances.
    pub fn acknowledge_committed_transfer(
        &mut self,
        channel: &ChannelContext,
        committed: &CommittedTransfer,
    ) -> Result<TransferAcknowledgementDisposition, HolderError> {
        committed.envelope.verify()?;
        if !channel.matches_binding(&committed.envelope.binding) {
            return Err(HolderError::PrivateStateMismatch);
        }
        let (statement, _) = committed.envelope.to_core()?;
        if statement.anchor_base != channel.anchor_base() {
            return Err(HolderError::PrivateStateMismatch);
        }
        let step = committed.envelope.binding.require_transfer_scope()?;
        let source_key = CredentialKey {
            channel: channel.key(),
            step: step.checked_sub(1).ok_or(HolderError::InvalidStep)?,
        };
        let digest = committed.envelope.canonical_digest()?;
        committed.acknowledgement.require_digest(digest)?;

        let mut transaction = self.vault.begin()?;
        require_identity(&transaction)?;
        let outbound = transaction
            .outbound_transfer_mut(&source_key)
            .ok_or(HolderError::StateConflict)?;
        if outbound.envelope_digest().as_bytes() != &digest {
            return Err(HolderError::PrivateStateMismatch);
        }
        let outbound_changed = outbound.acknowledge(committed.acknowledgement.clone())?;
        let credential = transaction
            .credential_mut(&source_key)
            .ok_or(HolderError::CredentialNotFound)?;
        let credential_changed = credential.mark_transferred(committed.acknowledgement.clone())?;
        if outbound_changed != credential_changed {
            return Err(VaultError::CorruptRecord.into());
        }
        transaction.commit()?;
        Ok(if credential_changed {
            TransferAcknowledgementDisposition::CredentialRetainedAndMarkedTransferred
        } else {
            TransferAcknowledgementDisposition::AlreadyAcknowledged
        })
    }

    /// Decrypts and accepts a committed transfer as Recipient. The new secret
    /// is reduced modulo the secp256k1 group order and must open the committed
    /// next anchor before ownership is stored atomically.
    pub fn receive_committed_transfer(
        &mut self,
        channel: &ChannelContext,
        invoice_id: &InvoiceId,
        committed: &CommittedTransfer,
    ) -> Result<ReceiveDisposition, HolderError> {
        committed.envelope.verify()?;
        if !channel.matches_binding(&committed.envelope.binding)
            || committed.envelope.binding.invoice_id.as_bytes() != invoice_id.as_str().as_bytes()
        {
            return Err(HolderError::PrivateStateMismatch);
        }
        let step = committed.envelope.binding.require_transfer_scope()?;
        if step == 0 {
            return Err(HolderError::InvalidStep);
        }
        let digest = committed.envelope.canonical_digest()?;
        committed.acknowledgement.require_digest(digest)?;
        let (transfer_statement, _) = committed.envelope.to_core()?;
        let (_, _, next_anchor) = committed.envelope.anchor_transition.to_core()?;
        if transfer_statement.anchor_base != channel.anchor_base() {
            return Err(HolderError::PrivateStateMismatch);
        }

        let channel_key = channel.key();
        let invoice_key = invoice_record_key(channel_key, invoice_id.as_str().as_bytes(), step);
        let credential_key = CredentialKey {
            channel: channel_key,
            step,
        };
        let mut transaction = self.vault.begin()?;
        require_identity(&transaction)?;

        if let Some(existing) = transaction.credential(&credential_key) {
            if existing.anchor() != next_anchor || existing.acquired_by() != committed.acknowledgement() {
                return Err(HolderError::StateConflict);
            }
            match transaction.invoice(&invoice_key).map(InvoiceRecord::state) {
                Some(InvoiceState::Consumed {
                    transfer_acknowledgement,
                    ..
                }) if transfer_acknowledgement == committed.acknowledgement() => {
                    transaction.commit()?;
                    return Ok(ReceiveDisposition::AlreadyRecorded);
                }
                _ => return Err(VaultError::CorruptRecord.into()),
            }
        }
        if transaction
            .highest_credential_step(&channel_key)
            .is_some_and(|highest| highest >= step)
        {
            return Err(HolderError::StateConflict);
        }

        let credential_secret = {
            let invoice = transaction.invoice(&invoice_key).ok_or(HolderError::InvoiceNotFound)?;
            if !matches!(invoice.state(), InvoiceState::Committed(_)) {
                return Err(HolderError::InvoiceNotCommitted);
            }
            let invoice_fields =
                validate_invoice_transfer_match(invoice, channel, invoice_id, &transfer_statement, committed)?;
            let refresh = scalar_from_secret(invoice.refresh()).map_err(|_| VaultError::CorruptRecord)?;
            if channel.anchor_base() * refresh != invoice_fields.delta {
                return Err(VaultError::CorruptRecord.into());
            }
            let plaintext = Zeroizing::new(
                invoice
                    .decryption_key()
                    .decrypt(&transfer_statement.next_holder_ciphertext)
                    .ok_or(HolderError::CryptographicOperation {
                        operation: "next-holder credential decryption",
                    })?,
            );
            let integer = Zeroizing::new(BigNumber::from_slice(plaintext.as_slice()));
            let scalar = match reduce_big_number_mod_curve_order(&integer)
                .map_err(|error| crypto_error("decrypted credential reduction", error))?
            {
                MaybeScalar::Valid(scalar) => scalar,
                MaybeScalar::Zero => return Err(HolderError::PointAtInfinity),
            };
            if channel.anchor_base() * scalar != next_anchor {
                return Err(HolderError::AnchorOpeningMismatch);
            }
            Zeroizing::new(scalar.serialize())
        };

        transaction.insert_credential(CredentialRecord::new(
            credential_key,
            credential_secret,
            next_anchor,
            committed.acknowledgement.clone(),
        ))?;
        let invoice = transaction.invoice_mut(&invoice_key).ok_or(VaultError::CorruptRecord)?;
        if !invoice.mark_consumed(committed.acknowledgement.clone())? {
            return Err(VaultError::CorruptRecord.into());
        }
        transaction.commit()?;
        Ok(ReceiveDisposition::OwnershipRecorded)
    }

    /// Returns public credential metadata without exposing its secret.
    pub fn credential_summary(
        &mut self,
        channel: &ChannelContext,
        step: u64,
    ) -> Result<Option<CredentialSummary>, HolderError> {
        let transaction = self.vault.begin()?;
        require_identity(&transaction)?;
        let key = CredentialKey {
            channel: channel.key(),
            step,
        };
        let summary = transaction.credential(&key).map(|record| CredentialSummary {
            step,
            anchor: record.anchor(),
            acquired_by: record.acquired_by().clone(),
            transferred_by: match record.state() {
                CredentialState::Owned => None,
                CredentialState::Transferred(acknowledgement) => Some(acknowledgement.clone()),
            },
        });
        transaction.commit()?;
        Ok(summary)
    }

    #[cfg(test)]
    pub(crate) fn initialize_with_fixture_seed(&mut self, seed: [u8; 32]) -> Result<HolderIdentity, HolderError> {
        let mut transaction = self.vault.begin()?;
        if let Some(record) = transaction.identity() {
            let identity = record.identity().clone();
            transaction.commit()?;
            return Ok(identity);
        }
        let seed = Zeroizing::new(seed);
        let identity = derive_identity(&seed)?;
        transaction.insert_identity(IdentityRecord::new(identity.clone(), seed))?;
        transaction.commit()?;
        Ok(identity)
    }

    #[cfg(test)]
    pub(crate) fn create_invoice_with_fixture(
        &mut self,
        request: InvoiceRequest,
        fixture: InvoiceFixture,
    ) -> Result<PreparedInvoice, HolderError> {
        self.create_invoice_with_material(
            request,
            InvoiceMaterial {
                decryption_key: fixture.decryption_key,
                refresh: Zeroizing::new(fixture.refresh.serialize().to_owned()),
                bob_nonce: fixture.bob_nonce,
                committee_nonce: fixture.committee_nonce,
            },
        )
    }

    #[cfg(test)]
    pub(crate) fn create_threshold_invoice_with_fixture(
        &mut self,
        request: ThresholdInvoiceRequest,
        fixture: ThresholdInvoiceFixture,
    ) -> Result<PreparedThresholdInvoice, HolderError> {
        self.create_threshold_invoice_with_material(
            request,
            ThresholdInvoiceMaterial {
                decryption_key: fixture.decryption_key,
                refresh: Zeroizing::new(fixture.refresh.serialize()),
                recipient_nonce: fixture.recipient_nonce,
            },
        )
    }

    #[cfg(test)]
    pub(crate) fn create_transfer_with_fixture_nonce(
        &mut self,
        invoice: &VerifiedInvoice,
        holder_nonce: Nonce,
    ) -> Result<PreparedTransfer, HolderError> {
        self.create_transfer_with_nonce(invoice, holder_nonce)
    }
}

struct InvoiceMaterial {
    decryption_key: DecryptionKey,
    refresh: Zeroizing<[u8; 32]>,
    bob_nonce: Nonce,
    committee_nonce: Nonce,
}

struct ThresholdInvoiceMaterial {
    decryption_key: DecryptionKey,
    refresh: Zeroizing<[u8; 32]>,
    recipient_nonce: Nonce,
}

#[cfg(test)]
pub(crate) struct InvoiceFixture {
    pub(crate) decryption_key: DecryptionKey,
    pub(crate) refresh: Scalar,
    pub(crate) bob_nonce: Nonce,
    pub(crate) committee_nonce: Nonce,
}

#[cfg(test)]
pub(crate) struct ThresholdInvoiceFixture {
    pub(crate) decryption_key: DecryptionKey,
    pub(crate) refresh: Scalar,
    pub(crate) recipient_nonce: Nonce,
}

fn derive_identity(seed: &[u8; 32]) -> Result<HolderIdentity, HolderError> {
    for counter in 0_u32..=u32::MAX {
        let mut hasher = Sha256::new();
        hasher.update(IDENTITY_DERIVATION_DOMAIN);
        hasher.update(seed);
        hasher.update(counter.to_be_bytes());
        let candidate: [u8; 32] = hasher.finalize().into();
        if let MaybeScalar::Valid(secret) = MaybeScalar::reduce_from(&candidate) {
            let public_key = secret.base_point_mul().serialize();
            let mut id_hasher = Sha256::new();
            id_hasher.update(IDENTITY_ID_DOMAIN);
            id_hasher.update(public_key);
            let participant_digest = Digest::from_bytes(id_hasher.finalize().into());
            let participant_id = ParticipantId::new(participant_digest.to_string())
                .map_err(|_| HolderError::InvalidProtocolIdentifier)?;
            return Ok(HolderIdentity::new(participant_id, public_key));
        }
    }
    Err(HolderError::CryptographicOperation {
        operation: "holder identity derivation",
    })
}

fn random_scalar_secret() -> Result<Zeroizing<[u8; 32]>, HolderError> {
    loop {
        let mut bytes = Zeroizing::new([0_u8; 32]);
        getrandom::fill(bytes.as_mut()).map_err(|_| HolderError::EntropyUnavailable)?;
        if Scalar::from_slice(bytes.as_ref()).is_ok() {
            return Ok(bytes);
        }
    }
}

fn require_identity<T: VaultTransaction>(transaction: &T) -> Result<(), HolderError> {
    if transaction.identity().is_none() {
        return Err(HolderError::IdentityNotInitialized);
    }
    Ok(())
}

struct InvoiceTransferFields {
    anchor_base: secp::Point,
    recipient_key: EncryptionKey,
    delta: secp::Point,
    recipient_ciphertext: Ciphertext,
}

fn validate_invoice_transfer_match(
    invoice: &InvoiceRecord,
    channel: &ChannelContext,
    invoice_id: &InvoiceId,
    transfer: &TransferStatement,
    committed: &CommittedTransfer,
) -> Result<InvoiceTransferFields, HolderError> {
    if invoice.expected_transfer_step() != committed.envelope.binding.require_transfer_scope()? {
        return Err(HolderError::PrivateStateMismatch);
    }
    let expected_invoice_binding = channel.invoice_binding(invoice_id)?;
    let original = invoice_record_fields(invoice)?;
    let binding_matches = match invoice.public() {
        InvoicePublicRecord::Single(envelope) => envelope.binding == expected_invoice_binding,
        InvoicePublicRecord::Threshold {
            recipient_share,
            threshold_distribution,
        } => {
            recipient_share.binding == expected_invoice_binding
                && threshold_distribution.binding == expected_invoice_binding
        }
    };
    let recipient_key = EncryptionKey::from(invoice.decryption_key());
    if !binding_matches
        || original.anchor_base != transfer.anchor_base
        || original.recipient_key.to_bytes() != transfer.bob_key.to_bytes()
        || recipient_key.to_bytes() != transfer.bob_key.to_bytes()
        || original.recipient_ciphertext != transfer.invoice_ciphertext
        || original.delta != committed.envelope.anchor_transition.to_core()?.1
    {
        return Err(HolderError::PrivateStateMismatch);
    }
    Ok(original)
}

fn invoice_record_fields(invoice: &InvoiceRecord) -> Result<InvoiceTransferFields, HolderError> {
    let (fields, computed_digest) = match invoice.public() {
        InvoicePublicRecord::Single(envelope) => {
            envelope.verify()?;
            let (statement, _) = envelope.to_core()?;
            (
                InvoiceTransferFields {
                    anchor_base: statement.anchor_base,
                    recipient_key: statement.bob_key,
                    delta: statement.delta,
                    recipient_ciphertext: statement.bob_ciphertext,
                },
                Digest::from_bytes(envelope.canonical_digest()?),
            )
        }
        InvoicePublicRecord::Threshold {
            recipient_share,
            threshold_distribution,
        } => {
            recipient_share.verify()?;
            threshold_distribution.verify()?;
            let (recipient, _) = recipient_share.to_core()?;
            let distribution = threshold_distribution.to_core()?;
            if recipient_share.binding != threshold_distribution.binding
                || recipient.member_id != RECIPIENT_SHARE_MEMBER_ID
                || recipient.anchor_base != distribution.anchor_base
                || recipient.committed_point != distribution.delta
            {
                return Err(HolderError::PrivateStateMismatch);
            }
            (
                InvoiceTransferFields {
                    anchor_base: recipient.anchor_base,
                    recipient_key: recipient.recipient_key,
                    delta: recipient.committed_point,
                    recipient_ciphertext: recipient.ciphertext,
                },
                threshold_invoice_package_digest(recipient_share, threshold_distribution)?,
            )
        }
    };
    if computed_digest != invoice.public_digest() {
        return Err(VaultError::CorruptRecord.into());
    }
    match invoice.state() {
        InvoiceState::Prepared => {}
        InvoiceState::Committed(acknowledgement)
        | InvoiceState::Consumed {
            invoice_acknowledgement: acknowledgement,
            ..
        } => acknowledgement.require_digest(computed_digest.to_bytes())?,
    }
    Ok(fields)
}

fn validate_threshold_package(
    channel: &ChannelContext,
    invoice_id: &InvoiceId,
    roster: &ThresholdRoster,
    recipient_share: &ShareEnvelopeV1,
    threshold_distribution: &ThresholdEnvelopeV1,
) -> Result<(), HolderError> {
    recipient_share.verify()?;
    threshold_distribution.verify()?;
    let expected_binding = channel.invoice_binding(invoice_id)?;
    if recipient_share.binding != expected_binding || threshold_distribution.binding != expected_binding {
        return Err(HolderError::PrivateStateMismatch);
    }
    let (recipient, _) = recipient_share.to_core()?;
    let distribution = threshold_distribution.to_core()?;
    if recipient.member_id != RECIPIENT_SHARE_MEMBER_ID
        || recipient.anchor_base != channel.anchor_base()
        || distribution.anchor_base != channel.anchor_base()
        || recipient.committed_point != distribution.delta
        || !roster.matches_distribution(threshold_distribution)
    {
        return Err(HolderError::PrivateStateMismatch);
    }
    Ok(())
}

fn validate_verified_invoice(invoice: &VerifiedInvoice) -> Result<(), HolderError> {
    let fields = match &invoice.messages {
        VerifiedInvoiceMessages::Single(envelope) => {
            envelope.verify()?;
            if !invoice.channel.matches_binding(&envelope.binding)
                || envelope.binding.invoice_id.as_bytes() != invoice.invoice_id.as_str().as_bytes()
                || Digest::from_bytes(envelope.canonical_digest()?) != invoice.public_digest
            {
                return Err(HolderError::PrivateStateMismatch);
            }
            let (statement, _) = envelope.to_core()?;
            InvoiceTransferFields {
                anchor_base: statement.anchor_base,
                recipient_key: statement.bob_key,
                delta: statement.delta,
                recipient_ciphertext: statement.bob_ciphertext,
            }
        }
        VerifiedInvoiceMessages::Threshold {
            recipient_share,
            threshold_distribution,
        } => {
            recipient_share.verify()?;
            threshold_distribution.verify()?;
            if !invoice.channel.matches_binding(&recipient_share.binding)
                || recipient_share.binding != threshold_distribution.binding
                || recipient_share.binding.invoice_id.as_bytes() != invoice.invoice_id.as_str().as_bytes()
                || threshold_invoice_package_digest(recipient_share, threshold_distribution)? != invoice.public_digest
            {
                return Err(HolderError::PrivateStateMismatch);
            }
            let (recipient, _) = recipient_share.to_core()?;
            let distribution = threshold_distribution.to_core()?;
            if recipient.member_id != RECIPIENT_SHARE_MEMBER_ID
                || recipient.anchor_base != distribution.anchor_base
                || recipient.committed_point != distribution.delta
            {
                return Err(HolderError::PrivateStateMismatch);
            }
            InvoiceTransferFields {
                anchor_base: recipient.anchor_base,
                recipient_key: recipient.recipient_key,
                delta: recipient.committed_point,
                recipient_ciphertext: recipient.ciphertext,
            }
        }
    };
    if fields.anchor_base != invoice.anchor_base
        || fields.recipient_key.to_bytes() != invoice.recipient_key.to_bytes()
        || fields.delta != invoice.delta
        || fields.recipient_ciphertext != invoice.recipient_ciphertext
    {
        return Err(HolderError::PrivateStateMismatch);
    }
    Ok(())
}
