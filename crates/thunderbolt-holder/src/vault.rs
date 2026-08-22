use std::fmt;

use libpaillier::DecryptionKey;
use secp::Point;
use thunderbolt_protocol::Digest;
use thunderbolt_wire::{InvoiceEnvelopeV1, ShareEnvelopeV1, ThresholdEnvelopeV1, TransferEnvelopeV1};
use zeroize::Zeroizing;

use crate::error::{HolderError, VaultError};
use crate::types::{
    ChannelKey, CredentialKey, DurableAcknowledgement, HolderIdentity, InvoiceRecordKey, PrivateInvoiceRecordRef,
};

/// Private identity material. The seed is zeroized on drop and is never
/// exposed by the public API.
#[derive(Clone)]
pub struct IdentityRecord {
    identity: HolderIdentity,
    seed: Zeroizing<[u8; 32]>,
}

impl IdentityRecord {
    pub(crate) fn new(identity: HolderIdentity, seed: Zeroizing<[u8; 32]>) -> Self {
        Self { identity, seed }
    }

    pub fn identity(&self) -> &HolderIdentity {
        &self.identity
    }

    pub(crate) fn seed(&self) -> &[u8; 32] {
        &self.seed
    }
}

impl fmt::Debug for IdentityRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("IdentityRecord")
            .field("identity", &self.identity)
            .field("seed", &"[REDACTED]")
            .finish()
    }
}

/// Monotonic lifecycle of a private Recipient invoice record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InvoiceState {
    Prepared,
    Committed(DurableAcknowledgement),
    Consumed {
        invoice_acknowledgement: DurableAcknowledgement,
        transfer_acknowledgement: DurableAcknowledgement,
    },
}

/// Public proof package associated with a private Recipient invoice record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InvoicePublicRecord {
    Single(InvoiceEnvelopeV1),
    Threshold {
        recipient_share: ShareEnvelopeV1,
        threshold_distribution: ThresholdEnvelopeV1,
    },
}

/// Recipient-only invoice refresh and Paillier decryption key.
///
/// This record implements neither serde nor any plaintext export method. Its
/// custom `Debug` output redacts all private material.
#[derive(Clone)]
pub struct InvoiceRecord {
    key: InvoiceRecordKey,
    channel: ChannelKey,
    expected_transfer_step: u64,
    public: InvoicePublicRecord,
    public_digest: Digest,
    refresh: Zeroizing<[u8; 32]>,
    decryption_key: DecryptionKey,
    state: InvoiceState,
}

impl InvoiceRecord {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new_single(
        key: InvoiceRecordKey,
        channel: ChannelKey,
        expected_transfer_step: u64,
        envelope: InvoiceEnvelopeV1,
        public_digest: Digest,
        refresh: Zeroizing<[u8; 32]>,
        decryption_key: DecryptionKey,
    ) -> Self {
        Self {
            key,
            channel,
            expected_transfer_step,
            public: InvoicePublicRecord::Single(envelope),
            public_digest,
            refresh,
            decryption_key,
            state: InvoiceState::Prepared,
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new_threshold(
        key: InvoiceRecordKey,
        channel: ChannelKey,
        expected_transfer_step: u64,
        recipient_share: ShareEnvelopeV1,
        threshold_distribution: ThresholdEnvelopeV1,
        public_digest: Digest,
        refresh: Zeroizing<[u8; 32]>,
        decryption_key: DecryptionKey,
    ) -> Self {
        Self {
            key,
            channel,
            expected_transfer_step,
            public: InvoicePublicRecord::Threshold {
                recipient_share,
                threshold_distribution,
            },
            public_digest,
            refresh,
            decryption_key,
            state: InvoiceState::Prepared,
        }
    }

    pub fn reference(&self) -> PrivateInvoiceRecordRef {
        PrivateInvoiceRecordRef(self.key)
    }

    pub fn channel(&self) -> ChannelKey {
        self.channel
    }

    pub fn expected_transfer_step(&self) -> u64 {
        self.expected_transfer_step
    }

    pub fn public(&self) -> &InvoicePublicRecord {
        &self.public
    }

    pub fn public_digest(&self) -> Digest {
        self.public_digest
    }

    pub fn state(&self) -> &InvoiceState {
        &self.state
    }

    pub(crate) fn refresh(&self) -> &[u8; 32] {
        &self.refresh
    }

    pub(crate) fn decryption_key(&self) -> &DecryptionKey {
        &self.decryption_key
    }

    pub(crate) fn restore_state(&mut self, state: InvoiceState) {
        self.state = state;
    }

    pub(crate) fn mark_committed(&mut self, acknowledgement: DurableAcknowledgement) -> Result<bool, HolderError> {
        match &self.state {
            InvoiceState::Prepared => {
                self.state = InvoiceState::Committed(acknowledgement);
                Ok(true)
            }
            InvoiceState::Committed(existing) if existing == &acknowledgement => Ok(false),
            InvoiceState::Consumed {
                invoice_acknowledgement,
                ..
            } if invoice_acknowledgement == &acknowledgement => Ok(false),
            InvoiceState::Committed(_) | InvoiceState::Consumed { .. } => Err(HolderError::StateConflict),
        }
    }

    pub(crate) fn mark_consumed(
        &mut self,
        transfer_acknowledgement: DurableAcknowledgement,
    ) -> Result<bool, HolderError> {
        match &self.state {
            InvoiceState::Prepared => Err(HolderError::InvoiceNotCommitted),
            InvoiceState::Committed(invoice_acknowledgement) => {
                self.state = InvoiceState::Consumed {
                    invoice_acknowledgement: invoice_acknowledgement.clone(),
                    transfer_acknowledgement,
                };
                Ok(true)
            }
            InvoiceState::Consumed {
                transfer_acknowledgement: existing,
                ..
            } if existing == &transfer_acknowledgement => Ok(false),
            InvoiceState::Consumed { .. } => Err(HolderError::StateConflict),
        }
    }
}

impl fmt::Debug for InvoiceRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("InvoiceRecord")
            .field("key", &self.key)
            .field("channel", &self.channel)
            .field("expected_transfer_step", &self.expected_transfer_step)
            .field("public", &self.public)
            .field("public_digest", &self.public_digest)
            .field("refresh", &"[REDACTED]")
            .field("decryption_key", &"[REDACTED]")
            .field("state", &self.state)
            .finish()
    }
}

/// Monotonic lifecycle of a Holder credential. The record itself is retained
/// after acknowledgement; the vault API deliberately has no delete method.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CredentialState {
    Owned,
    Transferred(DurableAcknowledgement),
}

/// One locally owned credential and the public anchor it opens.
#[derive(Clone)]
pub struct CredentialRecord {
    key: CredentialKey,
    secret: Zeroizing<[u8; 32]>,
    anchor: Point,
    acquired_by: DurableAcknowledgement,
    state: CredentialState,
}

impl CredentialRecord {
    pub(crate) fn new(
        key: CredentialKey,
        secret: Zeroizing<[u8; 32]>,
        anchor: Point,
        acquired_by: DurableAcknowledgement,
    ) -> Self {
        Self {
            key,
            secret,
            anchor,
            acquired_by,
            state: CredentialState::Owned,
        }
    }

    pub fn key(&self) -> CredentialKey {
        self.key
    }

    pub fn anchor(&self) -> Point {
        self.anchor
    }

    pub fn acquired_by(&self) -> &DurableAcknowledgement {
        &self.acquired_by
    }

    pub fn state(&self) -> &CredentialState {
        &self.state
    }

    pub(crate) fn secret(&self) -> &[u8; 32] {
        &self.secret
    }

    pub(crate) fn restore_state(&mut self, state: CredentialState) {
        self.state = state;
    }

    pub(crate) fn mark_transferred(&mut self, acknowledgement: DurableAcknowledgement) -> Result<bool, HolderError> {
        match &self.state {
            CredentialState::Owned => {
                self.state = CredentialState::Transferred(acknowledgement);
                Ok(true)
            }
            CredentialState::Transferred(existing) if existing == &acknowledgement => Ok(false),
            CredentialState::Transferred(_) => Err(HolderError::StateConflict),
        }
    }
}

impl fmt::Debug for CredentialRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CredentialRecord")
            .field("key", &self.key)
            .field("secret", &"[REDACTED]")
            .field("anchor", &self.anchor)
            .field("acquired_by", &self.acquired_by)
            .field("state", &self.state)
            .finish()
    }
}

/// Durable local record of a transfer prepared from a still-retained source
/// credential.
#[derive(Clone, Debug)]
pub struct OutboundTransferRecord {
    source_credential: CredentialKey,
    invoice_digest: Digest,
    invoice_acknowledgement: DurableAcknowledgement,
    envelope: TransferEnvelopeV1,
    envelope_digest: Digest,
    acknowledgement: Option<DurableAcknowledgement>,
}

impl OutboundTransferRecord {
    pub(crate) fn new(
        source_credential: CredentialKey,
        invoice_digest: Digest,
        invoice_acknowledgement: DurableAcknowledgement,
        envelope: TransferEnvelopeV1,
        envelope_digest: Digest,
    ) -> Self {
        Self {
            source_credential,
            invoice_digest,
            invoice_acknowledgement,
            envelope,
            envelope_digest,
            acknowledgement: None,
        }
    }

    pub fn source_credential(&self) -> CredentialKey {
        self.source_credential
    }

    pub fn invoice_digest(&self) -> Digest {
        self.invoice_digest
    }

    pub fn invoice_acknowledgement(&self) -> &DurableAcknowledgement {
        &self.invoice_acknowledgement
    }

    pub fn envelope(&self) -> &TransferEnvelopeV1 {
        &self.envelope
    }

    pub fn envelope_digest(&self) -> Digest {
        self.envelope_digest
    }

    pub fn acknowledgement(&self) -> Option<&DurableAcknowledgement> {
        self.acknowledgement.as_ref()
    }

    pub(crate) fn acknowledge(&mut self, acknowledgement: DurableAcknowledgement) -> Result<bool, HolderError> {
        match &self.acknowledgement {
            None => {
                self.acknowledgement = Some(acknowledgement);
                Ok(true)
            }
            Some(existing) if existing == &acknowledgement => Ok(false),
            Some(_) => Err(HolderError::StateConflict),
        }
    }

    pub(crate) fn restore_acknowledgement(&mut self, acknowledgement: Option<DurableAcknowledgement>) {
        self.acknowledgement = acknowledgement;
    }
}

/// A transaction over typed private records.
///
/// Dropping a transaction without calling [`Self::commit`] must roll back all
/// staged mutations. A successful commit must make the entire transaction
/// durable before returning. The interface exposes no record-deletion method.
pub trait VaultTransaction {
    fn identity(&self) -> Option<&IdentityRecord>;
    fn insert_identity(&mut self, record: IdentityRecord) -> Result<(), VaultError>;

    fn invoice(&self, key: &InvoiceRecordKey) -> Option<&InvoiceRecord>;
    fn invoice_mut(&mut self, key: &InvoiceRecordKey) -> Option<&mut InvoiceRecord>;
    fn invoice_by_digest_mut(&mut self, digest: &Digest) -> Option<&mut InvoiceRecord>;
    fn insert_invoice(&mut self, record: InvoiceRecord) -> Result<(), VaultError>;

    fn credential(&self, key: &CredentialKey) -> Option<&CredentialRecord>;
    fn credential_mut(&mut self, key: &CredentialKey) -> Option<&mut CredentialRecord>;
    fn highest_credential_step(&self, channel: &ChannelKey) -> Option<u64>;
    fn insert_credential(&mut self, record: CredentialRecord) -> Result<(), VaultError>;

    fn outbound_transfer(&self, source: &CredentialKey) -> Option<&OutboundTransferRecord>;
    fn outbound_transfer_mut(&mut self, source: &CredentialKey) -> Option<&mut OutboundTransferRecord>;
    fn insert_outbound_transfer(&mut self, record: OutboundTransferRecord) -> Result<(), VaultError>;

    fn commit(self) -> Result<(), VaultError>;
}

/// Backend abstraction for private Holder state.
///
/// A production implementation should use encrypted-at-rest storage and an
/// immediate/write transaction so concurrent engine instances cannot both
/// advance the same credential.
pub trait SecretVault {
    type Transaction<'a>: VaultTransaction
    where
        Self: 'a;

    fn begin(&mut self) -> Result<Self::Transaction<'_>, VaultError>;
}
