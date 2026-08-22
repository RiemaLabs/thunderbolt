use std::fmt;

use bitcoin::Network;
use libpaillier::EncryptionKey;
use secp::{Point, Scalar};
use sha2::{Digest as _, Sha256};
use thunderbolt_protocol::{ChannelId, Digest, EntryHash, InvoiceId, ParticipantId};
use thunderbolt_wire::{BindingContext, CanonicalDigest, InvoiceEnvelopeV1, TransferEnvelopeV1};
use zeroize::Zeroizing;

use crate::error::{crypto_error, HolderError};

/// Public, deployment-scoped context shared by one channel's local records.
#[derive(Clone, Debug)]
pub struct ChannelContext {
    network: Network,
    deployment_id: Vec<u8>,
    committee_epoch: u64,
    channel_id: ChannelId,
    anchor_base: Point,
}

impl ChannelContext {
    /// Creates a channel context using the protocol's full canonical funding
    /// outpoint (`display-order txid || big-endian vout`).
    pub fn new(
        network: Network,
        deployment_id: impl AsRef<[u8]>,
        committee_epoch: u64,
        channel_id: ChannelId,
        anchor_base: Point,
    ) -> Result<Self, HolderError> {
        let deployment_id = deployment_id.as_ref().to_vec();
        // Validate all public bounds now. A real invoice id is supplied later.
        BindingContext::invoice(
            network,
            &deployment_id,
            committee_epoch,
            channel_id.canonical_bytes(),
            b"context-validation",
        )?;
        Ok(Self {
            network,
            deployment_id,
            committee_epoch,
            channel_id,
            anchor_base,
        })
    }

    pub fn network(&self) -> Network {
        self.network
    }

    pub fn deployment_id(&self) -> &[u8] {
        &self.deployment_id
    }

    pub fn committee_epoch(&self) -> u64 {
        self.committee_epoch
    }

    pub fn channel_id(&self) -> ChannelId {
        self.channel_id
    }

    pub fn anchor_base(&self) -> Point {
        self.anchor_base
    }

    pub(crate) fn invoice_binding(&self, invoice_id: &InvoiceId) -> Result<BindingContext, HolderError> {
        Ok(BindingContext::invoice(
            self.network,
            &self.deployment_id,
            self.committee_epoch,
            self.channel_id.canonical_bytes(),
            invoice_id.as_str().as_bytes(),
        )?)
    }

    pub(crate) fn transfer_binding(&self, invoice_id: &InvoiceId, step: u64) -> Result<BindingContext, HolderError> {
        Ok(BindingContext::transfer(
            self.network,
            &self.deployment_id,
            self.committee_epoch,
            self.channel_id.canonical_bytes(),
            invoice_id.as_str().as_bytes(),
            step,
        )?)
    }

    pub(crate) fn matches_binding(&self, binding: &BindingContext) -> bool {
        binding.network == self.network
            && binding.deployment_id.as_bytes() == self.deployment_id
            && binding.committee_epoch == self.committee_epoch
            && binding.channel_id.as_bytes() == self.channel_id.canonical_bytes()
    }

    pub(crate) fn key(&self) -> ChannelKey {
        let mut hasher = Sha256::new();
        hasher.update(b"bitcoin-thunderbolt/holder/channel/v1");
        append_bytes(&mut hasher, &[network_code(self.network)]);
        append_bytes(&mut hasher, &self.deployment_id);
        append_bytes(&mut hasher, &self.committee_epoch.to_be_bytes());
        append_bytes(&mut hasher, &self.channel_id.canonical_bytes());
        append_bytes(&mut hasher, &self.anchor_base.serialize());
        ChannelKey(hasher.finalize().into())
    }
}

/// Public request to create a Recipient invoice.
#[derive(Clone, Debug)]
pub struct InvoiceRequest {
    pub(crate) channel: ChannelContext,
    pub(crate) invoice_id: InvoiceId,
    pub(crate) expected_transfer_step: u64,
    pub(crate) committee_key: EncryptionKey,
}

impl InvoiceRequest {
    pub fn new(
        channel: ChannelContext,
        invoice_id: InvoiceId,
        expected_transfer_step: u64,
        committee_key: EncryptionKey,
    ) -> Result<Self, HolderError> {
        if expected_transfer_step == 0 {
            return Err(HolderError::InvalidStep);
        }
        thunderbolt_core::paillier::validate_protocol_encryption_key(&committee_key)
            .map_err(|error| crypto_error("committee key validation", error))?;
        channel.invoice_binding(&invoice_id)?;
        Ok(Self {
            channel,
            invoice_id,
            expected_transfer_step,
            committee_key,
        })
    }

    pub fn channel(&self) -> &ChannelContext {
        &self.channel
    }

    pub fn invoice_id(&self) -> &InvoiceId {
        &self.invoice_id
    }

    pub fn expected_transfer_step(&self) -> u64 {
        self.expected_transfer_step
    }
}

/// Public holder identity derived from a locally stored OS-random seed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HolderIdentity {
    participant_id: ParticipantId,
    public_key: [u8; 33],
}

impl HolderIdentity {
    pub(crate) fn new(participant_id: ParticipantId, public_key: [u8; 33]) -> Self {
        Self {
            participant_id,
            public_key,
        }
    }

    pub fn participant_id(&self) -> &ParticipantId {
        &self.participant_id
    }

    pub fn public_key(&self) -> &[u8; 33] {
        &self.public_key
    }
}

/// Secret scalar accepted from a trusted local channel-opening flow.
///
/// The type does not implement serialization or `Clone`, and its byte storage
/// is zeroized on drop.
pub struct CredentialSecret(Zeroizing<[u8; 32]>);

impl CredentialSecret {
    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self, HolderError> {
        Scalar::from_slice(&bytes).map_err(|_| HolderError::InvalidInput {
            reason: "credential secret must be a non-zero canonical secp256k1 scalar",
        })?;
        Ok(Self(Zeroizing::new(bytes)))
    }

    pub(crate) fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub(crate) fn into_bytes(self) -> Zeroizing<[u8; 32]> {
        self.0
    }
}

impl fmt::Debug for CredentialSecret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CredentialSecret([REDACTED])")
    }
}

/// A durable ledger acknowledgement bound to one canonical public-message
/// digest. Construction is intentionally separate from ledger verification;
/// only a trusted ledger adapter should create values passed into the engine.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DurableAcknowledgement {
    sequence: u64,
    entry_hash: EntryHash,
    message_digest: Digest,
}

impl DurableAcknowledgement {
    pub const fn new(sequence: u64, entry_hash: EntryHash, message_digest: Digest) -> Self {
        Self {
            sequence,
            entry_hash,
            message_digest,
        }
    }

    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    pub const fn entry_hash(&self) -> EntryHash {
        self.entry_hash
    }

    pub const fn message_digest(&self) -> Digest {
        self.message_digest
    }

    pub(crate) fn require_digest(&self, digest: [u8; 32]) -> Result<(), HolderError> {
        if self.message_digest.as_bytes() != &digest {
            return Err(HolderError::AcknowledgementMismatch);
        }
        Ok(())
    }
}

/// One-time installation of an already committed initial channel credential.
pub struct GenesisCredential {
    pub(crate) channel: ChannelContext,
    pub(crate) secret: CredentialSecret,
    pub(crate) anchor: Point,
    pub(crate) acknowledgement: DurableAcknowledgement,
}

impl GenesisCredential {
    pub fn new(
        channel: ChannelContext,
        secret: CredentialSecret,
        anchor: Point,
        acknowledgement: DurableAcknowledgement,
    ) -> Result<Self, HolderError> {
        let scalar = scalar_from_secret(secret.as_bytes())?;
        if channel.anchor_base * scalar != anchor {
            return Err(HolderError::AnchorOpeningMismatch);
        }
        Ok(Self {
            channel,
            secret,
            anchor,
            acknowledgement,
        })
    }
}

impl fmt::Debug for GenesisCredential {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GenesisCredential")
            .field("channel", &self.channel)
            .field("secret", &"[REDACTED]")
            .field("anchor", &self.anchor)
            .field("acknowledgement", &self.acknowledgement)
            .finish()
    }
}

/// Opaque reference to the private refresh/key record persisted for an invoice.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PrivateInvoiceRecordRef(pub(crate) InvoiceRecordKey);

/// Public invoice plus an opaque reference to its transactionally persisted
/// private refresh/key record.
#[derive(Clone, Debug)]
pub struct PreparedInvoice {
    pub(crate) envelope: InvoiceEnvelopeV1,
    pub(crate) private_record: PrivateInvoiceRecordRef,
}

impl PreparedInvoice {
    pub fn envelope(&self) -> &InvoiceEnvelopeV1 {
        &self.envelope
    }

    pub const fn private_record(&self) -> PrivateInvoiceRecordRef {
        self.private_record
    }
}

/// An invoice accompanied by a durable ledger acknowledgement.
#[derive(Clone, Debug)]
pub struct CommittedInvoice {
    pub(crate) envelope: InvoiceEnvelopeV1,
    pub(crate) expected_transfer_step: u64,
    pub(crate) acknowledgement: DurableAcknowledgement,
}

impl CommittedInvoice {
    pub fn new(
        envelope: InvoiceEnvelopeV1,
        expected_transfer_step: u64,
        acknowledgement: DurableAcknowledgement,
    ) -> Result<Self, HolderError> {
        if expected_transfer_step == 0 {
            return Err(HolderError::InvalidStep);
        }
        let digest = envelope.canonical_digest()?;
        acknowledgement.require_digest(digest)?;
        Ok(Self {
            envelope,
            expected_transfer_step,
            acknowledgement,
        })
    }

    pub fn envelope(&self) -> &InvoiceEnvelopeV1 {
        &self.envelope
    }

    pub fn expected_transfer_step(&self) -> u64 {
        self.expected_transfer_step
    }

    pub fn acknowledgement(&self) -> &DurableAcknowledgement {
        &self.acknowledgement
    }
}

/// A verified committed invoice capability. Only [`crate::HolderEngine`] can
/// construct it, so transfer creation cannot skip committed-invoice checking.
#[derive(Clone, Debug)]
pub struct VerifiedInvoice {
    pub(crate) channel: ChannelContext,
    pub(crate) invoice_id: InvoiceId,
    pub(crate) envelope: InvoiceEnvelopeV1,
    pub(crate) expected_transfer_step: u64,
    pub(crate) acknowledgement: DurableAcknowledgement,
}

impl VerifiedInvoice {
    pub fn envelope(&self) -> &InvoiceEnvelopeV1 {
        &self.envelope
    }

    pub fn channel(&self) -> &ChannelContext {
        &self.channel
    }

    pub fn invoice_id(&self) -> &InvoiceId {
        &self.invoice_id
    }

    pub fn expected_transfer_step(&self) -> u64 {
        self.expected_transfer_step
    }

    pub fn acknowledgement(&self) -> &DurableAcknowledgement {
        &self.acknowledgement
    }
}

/// Public transfer plus the retained source-credential reference.
#[derive(Clone, Debug)]
pub struct PreparedTransfer {
    pub(crate) envelope: TransferEnvelopeV1,
    pub(crate) source_credential: CredentialKey,
}

impl PreparedTransfer {
    pub fn envelope(&self) -> &TransferEnvelopeV1 {
        &self.envelope
    }

    pub const fn source_credential(&self) -> CredentialKey {
        self.source_credential
    }
}

/// A transfer accompanied by a durable ledger acknowledgement.
#[derive(Clone, Debug)]
pub struct CommittedTransfer {
    pub(crate) envelope: TransferEnvelopeV1,
    pub(crate) acknowledgement: DurableAcknowledgement,
}

impl CommittedTransfer {
    pub fn new(envelope: TransferEnvelopeV1, acknowledgement: DurableAcknowledgement) -> Result<Self, HolderError> {
        let digest = envelope.canonical_digest()?;
        acknowledgement.require_digest(digest)?;
        Ok(Self {
            envelope,
            acknowledgement,
        })
    }

    pub fn envelope(&self) -> &TransferEnvelopeV1 {
        &self.envelope
    }

    pub fn acknowledgement(&self) -> &DurableAcknowledgement {
        &self.acknowledgement
    }
}

/// Idempotent result of accepting a committed transfer as Recipient.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReceiveDisposition {
    OwnershipRecorded,
    AlreadyRecorded,
}

/// Idempotent result of acknowledging an outbound transfer as current Holder.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransferAcknowledgementDisposition {
    CredentialRetainedAndMarkedTransferred,
    AlreadyAcknowledged,
}

/// Public view of a local credential; secret material is intentionally absent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CredentialSummary {
    pub(crate) step: u64,
    pub(crate) anchor: Point,
    pub(crate) acquired_by: DurableAcknowledgement,
    pub(crate) transferred_by: Option<DurableAcknowledgement>,
}

impl CredentialSummary {
    pub const fn step(&self) -> u64 {
        self.step
    }

    pub fn anchor(&self) -> Point {
        self.anchor
    }

    pub fn acquired_by(&self) -> &DurableAcknowledgement {
        &self.acquired_by
    }

    pub fn transferred_by(&self) -> Option<&DurableAcknowledgement> {
        self.transferred_by.as_ref()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ChannelKey(pub(crate) [u8; 32]);

impl ChannelKey {
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CredentialKey {
    pub(crate) channel: ChannelKey,
    pub(crate) step: u64,
}

impl CredentialKey {
    pub const fn channel(&self) -> ChannelKey {
        self.channel
    }

    pub const fn step(&self) -> u64 {
        self.step
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct InvoiceRecordKey(pub(crate) [u8; 32]);

impl InvoiceRecordKey {
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

pub(crate) fn invoice_record_key(
    channel: ChannelKey,
    invoice_id: &[u8],
    expected_transfer_step: u64,
) -> InvoiceRecordKey {
    let mut hasher = Sha256::new();
    hasher.update(b"bitcoin-thunderbolt/holder/invoice-record/v1");
    append_bytes(&mut hasher, &channel.0);
    append_bytes(&mut hasher, invoice_id);
    append_bytes(&mut hasher, &expected_transfer_step.to_be_bytes());
    InvoiceRecordKey(hasher.finalize().into())
}

pub(crate) fn scalar_from_secret(bytes: &[u8; 32]) -> Result<Scalar, HolderError> {
    Scalar::from_slice(bytes).map_err(|_| HolderError::InvalidInput {
        reason: "vault contains a non-canonical credential scalar",
    })
}

fn append_bytes(hasher: &mut Sha256, value: &[u8]) {
    hasher.update((value.len() as u64).to_be_bytes());
    hasher.update(value);
}

fn network_code(network: Network) -> u8 {
    match network {
        Network::Bitcoin => 0,
        Network::Testnet => 1,
        Network::Testnet4 => 2,
        Network::Signet => 3,
        Network::Regtest => 4,
    }
}
