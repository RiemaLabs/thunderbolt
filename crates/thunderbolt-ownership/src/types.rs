use std::collections::BTreeMap;

use secp::{MaybeScalar, Point, Scalar};
use sha2::{Digest, Sha256};
use thunderbolt_ledger::{ActorKeyAlgorithmV2, ActorPublicKeyV2, LedgerChainIdV2, ParticipantIdV2, EVENT_BYTES_MAX};
use thunderbolt_protocol::v2::{ChannelPhaseV2, ChannelSnapshotV2};
use thunderbolt_wire::{AnchorParameterSuiteIdV2, ChannelBindingV2, ValidateWire as _};
use zeroize::Zeroizing;

use crate::{OwnershipError, Result};

pub const OWNERSHIP_PROOF_VERSION: u16 = 2;
pub const OWNERSHIP_CODEC_VERSION: u16 = 2;
/// Maximum exact closing transaction accepted by this proof profile.
///
/// The remaining 16 KiB of the Ledger event cap is reserved for canonical
/// Finalize framing, the ownership envelope, and Committee attestation.
pub const MAX_CLOSING_TRANSACTION_BYTES: usize = EVENT_BYTES_MAX - (16 * 1_024);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClosingTransactionDigest(pub(crate) [u8; 32]);

impl ClosingTransactionDigest {
    pub(crate) fn derive(bytes: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(b"bitcoin-thunderbolt/closing-transaction/v2");
        hasher.update(u64::try_from(bytes.len()).unwrap_or(u64::MAX).to_be_bytes());
        hasher.update(bytes);
        Self(hasher.finalize().into())
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// One immutable deployment registration of an anchor-suite identifier and
/// its exact public base `H`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AnchorSuiteParametersV2 {
    suite_id: AnchorParameterSuiteIdV2,
    anchor_base: Point,
}

impl AnchorSuiteParametersV2 {
    pub const fn new(suite_id: AnchorParameterSuiteIdV2, anchor_base: Point) -> Self {
        Self { suite_id, anchor_base }
    }

    pub const fn suite_id(&self) -> &AnchorParameterSuiteIdV2 {
        &self.suite_id
    }

    pub const fn anchor_base(&self) -> Point {
        self.anchor_base
    }
}

/// Immutable anchor-suite lookup supplied by trusted deployment
/// configuration, never by a proof envelope.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AnchorSuiteRegistryV2 {
    suites: BTreeMap<AnchorParameterSuiteIdV2, Point>,
}

impl AnchorSuiteRegistryV2 {
    pub fn new(entries: Vec<AnchorSuiteParametersV2>) -> Result<Self> {
        if entries.is_empty() {
            return Err(OwnershipError::EmptyAnchorSuiteRegistry);
        }
        let mut suites = BTreeMap::new();
        for entry in entries {
            if suites.insert(entry.suite_id, entry.anchor_base).is_some() {
                return Err(OwnershipError::DuplicateAnchorSuite);
            }
        }
        Ok(Self { suites })
    }

    fn resolve(&self, suite_id: &AnchorParameterSuiteIdV2) -> Result<Point> {
        self.suites
            .get(suite_id)
            .copied()
            .ok_or(OwnershipError::UnknownAnchorSuite)
    }
}

/// Stable public statement and stronger operational Fiat-Shamir domain.
///
/// This trusted value can only be derived through [`Self::from_snapshot`]. A
/// decoded ownership envelope carries an untrusted echo of the same fields but
/// cannot construct this capability.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FinalizeSigningContext {
    pub(crate) data: FinalizeContextData,
}

impl FinalizeSigningContext {
    /// Derives the exact ownership statement from authenticated Ledger state
    /// and immutable deployment parameters.
    ///
    /// `holder_key` must be the BIP340 key from the already signature-verified
    /// Finalize proposal. This constructor verifies its participant identity
    /// against the snapshot; the ownership proof itself does not prove
    /// possession of that actor key.
    pub fn from_snapshot(
        snapshot: &ChannelSnapshotV2,
        anchor_suites: &AnchorSuiteRegistryV2,
        holder_key: ActorPublicKeyV2,
        closing_transaction: Vec<u8>,
    ) -> Result<Self> {
        snapshot
            .validate()
            .map_err(|_| OwnershipError::InvalidContext("invalid Ledger channel snapshot"))?;
        if snapshot.phase != ChannelPhaseV2::Active {
            return Err(OwnershipError::InvalidContext("Finalize requires an active snapshot"));
        }
        let anchor_base = anchor_suites.resolve(&snapshot.binding.anchor_parameter_suite_id)?;
        let fixed_lock_key = point_from_snapshot(snapshot.lock_key.as_bytes(), "invalid fixed lock key")?;
        let current_anchor = point_from_snapshot(
            snapshot.current_holder_anchor.as_bytes(),
            "invalid current Holder anchor",
        )?;
        let derived_holder = holder_key
            .participant_id(ActorKeyAlgorithmV2::Bip340V1)
            .map_err(|_| OwnershipError::InvalidContext("invalid Holder key"))?;
        if derived_holder != snapshot.current_holder {
            return Err(OwnershipError::InvalidContext(
                "Holder key does not match the committed Holder",
            ));
        }
        let snapshot_state_hash = *snapshot
            .state_hash()
            .map_err(|_| OwnershipError::InvalidContext("snapshot hash failed"))?
            .as_bytes();
        Ok(Self {
            data: FinalizeContextData::new(
                snapshot.ledger_chain_id.clone(),
                snapshot.binding.clone(),
                snapshot_state_hash,
                snapshot.transfers_completed,
                fixed_lock_key,
                anchor_base,
                current_anchor,
                snapshot.current_holder.clone(),
                holder_key,
                closing_transaction,
            )?,
        })
    }

    pub const fn ledger_chain_id(&self) -> &LedgerChainIdV2 {
        &self.data.ledger_chain_id
    }

    pub const fn channel(&self) -> &ChannelBindingV2 {
        &self.data.channel
    }

    pub const fn channel_context_id(&self) -> &[u8; 32] {
        &self.data.channel_context_id
    }

    pub const fn snapshot_state_hash(&self) -> &[u8; 32] {
        &self.data.snapshot_state_hash
    }

    pub const fn step(&self) -> u64 {
        self.data.step
    }

    pub const fn fixed_lock_key(&self) -> Point {
        self.data.fixed_lock_key
    }

    pub const fn anchor_base(&self) -> Point {
        self.data.anchor_base
    }

    pub const fn current_anchor(&self) -> Point {
        self.data.current_anchor
    }

    pub const fn holder_participant(&self) -> &ParticipantIdV2 {
        &self.data.holder_participant
    }

    pub const fn holder_key(&self) -> &ActorPublicKeyV2 {
        &self.data.holder_key
    }

    pub fn closing_transaction(&self) -> &[u8] {
        &self.data.closing_transaction
    }

    pub const fn closing_digest(&self) -> ClosingTransactionDigest {
        self.data.closing_digest
    }

    pub fn statement_digest(&self) -> Result<[u8; 32]> {
        self.data.statement_digest()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct FinalizeContextData {
    pub(crate) ledger_chain_id: LedgerChainIdV2,
    pub(crate) channel: ChannelBindingV2,
    pub(crate) channel_context_id: [u8; 32],
    pub(crate) snapshot_state_hash: [u8; 32],
    pub(crate) step: u64,
    pub(crate) fixed_lock_key: Point,
    pub(crate) anchor_base: Point,
    pub(crate) current_anchor: Point,
    pub(crate) holder_participant: ParticipantIdV2,
    pub(crate) holder_key: ActorPublicKeyV2,
    pub(crate) closing_transaction: Vec<u8>,
    pub(crate) closing_digest: ClosingTransactionDigest,
}

impl FinalizeContextData {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        ledger_chain_id: LedgerChainIdV2,
        channel: ChannelBindingV2,
        snapshot_state_hash: [u8; 32],
        step: u64,
        fixed_lock_key: Point,
        anchor_base: Point,
        current_anchor: Point,
        holder_participant: ParticipantIdV2,
        holder_key: ActorPublicKeyV2,
        closing_transaction: Vec<u8>,
    ) -> Result<Self> {
        channel
            .validate_wire()
            .map_err(|_| OwnershipError::InvalidContext("invalid channel binding"))?;
        if holder_key
            .participant_id(ActorKeyAlgorithmV2::Bip340V1)
            .map_err(|_| OwnershipError::InvalidContext("invalid Holder key"))?
            != holder_participant
        {
            return Err(OwnershipError::InvalidContext(
                "Holder participant does not match Holder key",
            ));
        }
        if closing_transaction.is_empty() {
            return Err(OwnershipError::InvalidContext("closing transaction is empty"));
        }
        if closing_transaction.len() > MAX_CLOSING_TRANSACTION_BYTES {
            return Err(OwnershipError::ClosingTransactionTooLarge);
        }
        let channel_context_id = channel
            .context_id()
            .map_err(|_| OwnershipError::InvalidContext("channel context id failed"))?;
        let closing_digest = ClosingTransactionDigest::derive(&closing_transaction);
        Ok(Self {
            ledger_chain_id,
            channel,
            channel_context_id,
            snapshot_state_hash,
            step,
            fixed_lock_key,
            anchor_base,
            current_anchor,
            holder_participant,
            holder_key,
            closing_transaction,
            closing_digest,
        })
    }

    pub(crate) fn statement_digest(&self) -> Result<[u8; 32]> {
        let mut hasher = Sha256::new();
        hasher.update(b"bitcoin-thunderbolt/ownership-statement/v2");
        let encoded = crate::codec::encode_transcript_context(self)?;
        hasher.update(u64::try_from(encoded.len()).unwrap_or(u64::MAX).to_be_bytes());
        hasher.update(encoded);
        Ok(hasher.finalize().into())
    }
}

/// Public statement echoed by an untrusted ownership envelope.
///
/// The exact closing transaction is intentionally absent. Its digest is
/// checked against independently trusted bytes before proof verification.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct OwnershipWireStatementV2 {
    pub(crate) ledger_chain_id: LedgerChainIdV2,
    pub(crate) channel: ChannelBindingV2,
    pub(crate) channel_context_id: [u8; 32],
    pub(crate) snapshot_state_hash: [u8; 32],
    pub(crate) step: u64,
    pub(crate) fixed_lock_key: Point,
    pub(crate) anchor_base: Point,
    pub(crate) current_anchor: Point,
    pub(crate) holder_participant: ParticipantIdV2,
    pub(crate) holder_key: ActorPublicKeyV2,
    pub(crate) closing_digest: ClosingTransactionDigest,
}

impl OwnershipWireStatementV2 {
    pub(crate) fn from_trusted(context: &FinalizeContextData) -> Self {
        Self {
            ledger_chain_id: context.ledger_chain_id.clone(),
            channel: context.channel.clone(),
            channel_context_id: context.channel_context_id,
            snapshot_state_hash: context.snapshot_state_hash,
            step: context.step,
            fixed_lock_key: context.fixed_lock_key,
            anchor_base: context.anchor_base,
            current_anchor: context.current_anchor,
            holder_participant: context.holder_participant.clone(),
            holder_key: context.holder_key.clone(),
            closing_digest: context.closing_digest,
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        ledger_chain_id: LedgerChainIdV2,
        channel: ChannelBindingV2,
        encoded_context_id: [u8; 32],
        snapshot_state_hash: [u8; 32],
        step: u64,
        fixed_lock_key: Point,
        anchor_base: Point,
        current_anchor: Point,
        holder_participant: ParticipantIdV2,
        holder_key: ActorPublicKeyV2,
        closing_digest: ClosingTransactionDigest,
    ) -> Result<Self> {
        channel
            .validate_wire()
            .map_err(|_| OwnershipError::InvalidContext("invalid channel binding"))?;
        let channel_context_id = channel
            .context_id()
            .map_err(|_| OwnershipError::InvalidContext("channel context id failed"))?;
        if channel_context_id != encoded_context_id {
            return Err(OwnershipError::MalformedEncoding);
        }
        if holder_key
            .participant_id(ActorKeyAlgorithmV2::Bip340V1)
            .map_err(|_| OwnershipError::InvalidContext("invalid Holder key"))?
            != holder_participant
        {
            return Err(OwnershipError::InvalidContext(
                "Holder participant does not match Holder key",
            ));
        }
        Ok(Self {
            ledger_chain_id,
            channel,
            channel_context_id,
            snapshot_state_hash,
            step,
            fixed_lock_key,
            anchor_base,
            current_anchor,
            holder_participant,
            holder_key,
            closing_digest,
        })
    }
}

fn point_from_snapshot(bytes: &[u8], reason: &'static str) -> Result<Point> {
    if bytes.len() != 33 || !matches!(bytes.first(), Some(2 | 3)) {
        return Err(OwnershipError::InvalidContext(reason));
    }
    Point::from_slice(bytes).map_err(|_| OwnershipError::InvalidContext(reason))
}

/// Zeroizing nonzero scalar witness. It implements neither `Clone` nor `Debug`.
pub struct OwnershipWitness(pub(crate) Zeroizing<[u8; 32]>);

impl OwnershipWitness {
    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self> {
        let bytes = Zeroizing::new(bytes);
        Scalar::from_slice(bytes.as_ref()).map_err(|_| OwnershipError::InvalidWitness)?;
        Ok(Self(bytes))
    }

    pub(crate) fn scalar(&self) -> Result<Scalar> {
        Scalar::from_slice(self.0.as_ref()).map_err(|_| OwnershipError::InvalidWitness)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OwnershipProofV2 {
    pub(crate) version: u16,
    pub(crate) commitment: Point,
    pub(crate) response: [u8; 32],
}

impl OwnershipProofV2 {
    pub const fn version(&self) -> u16 {
        self.version
    }

    pub const fn commitment(&self) -> Point {
        self.commitment
    }

    pub const fn response_bytes(&self) -> &[u8; 32] {
        &self.response
    }

    pub(crate) fn response(&self) -> Result<MaybeScalar> {
        MaybeScalar::from_slice(&self.response).map_err(|_| OwnershipError::MalformedEncoding)
    }
}

/// Untrusted wire envelope. Its embedded statement is only an echo and never
/// establishes the Ledger state or deployment parameters used by verification.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OwnershipEnvelopeV2 {
    pub(crate) statement: OwnershipWireStatementV2,
    pub(crate) proof: OwnershipProofV2,
}

impl OwnershipEnvelopeV2 {
    pub(crate) fn from_parts(statement: OwnershipWireStatementV2, proof: OwnershipProofV2) -> Result<Self> {
        if proof.version != OWNERSHIP_PROOF_VERSION {
            return Err(OwnershipError::UnsupportedVersion);
        }
        let _ = proof.response()?;
        Ok(Self { statement, proof })
    }

    pub const fn proof(&self) -> &OwnershipProofV2 {
        &self.proof
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        crate::codec::encode_envelope(self)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        crate::codec::decode_envelope(bytes)
    }
}

/// Narrow capability proving only accepted knowledge of `x` for the exact
/// trusted statement `X = xH`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedOwnership {
    pub(crate) statement_digest: [u8; 32],
    pub(crate) snapshot_state_hash: [u8; 32],
    pub(crate) channel_context_id: [u8; 32],
    pub(crate) step: u64,
    pub(crate) holder_participant: ParticipantIdV2,
    pub(crate) holder_key: ActorPublicKeyV2,
    pub(crate) anchor_suite_id: AnchorParameterSuiteIdV2,
    pub(crate) fixed_lock_key: Point,
    pub(crate) anchor_base: Point,
    pub(crate) current_anchor: Point,
    pub(crate) closing_digest: ClosingTransactionDigest,
}

impl VerifiedOwnership {
    pub const fn statement_digest(&self) -> &[u8; 32] {
        &self.statement_digest
    }

    pub const fn snapshot_state_hash(&self) -> &[u8; 32] {
        &self.snapshot_state_hash
    }

    pub const fn channel_context_id(&self) -> &[u8; 32] {
        &self.channel_context_id
    }

    pub const fn step(&self) -> u64 {
        self.step
    }

    pub const fn holder_participant(&self) -> &ParticipantIdV2 {
        &self.holder_participant
    }

    pub const fn holder_key(&self) -> &ActorPublicKeyV2 {
        &self.holder_key
    }

    pub const fn anchor_suite_id(&self) -> &AnchorParameterSuiteIdV2 {
        &self.anchor_suite_id
    }

    pub const fn fixed_lock_key(&self) -> Point {
        self.fixed_lock_key
    }

    pub const fn anchor_base(&self) -> Point {
        self.anchor_base
    }

    pub const fn current_anchor(&self) -> Point {
        self.current_anchor
    }

    pub const fn closing_digest(&self) -> ClosingTransactionDigest {
        self.closing_digest
    }
}
