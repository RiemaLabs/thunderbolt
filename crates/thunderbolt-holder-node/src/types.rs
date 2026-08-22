use core::fmt;
use std::io::{self, Write};

use serde::de::{Error as _, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use sha2::{Digest as _, Sha256};
use thunderbolt_ledger::{
    ActorRoleV2, AppHashV2, ChannelContextIdV2, ClientRequestNonceV2, EntryHashV2, EventKindV2, ExecutedBlockV2,
    LedgerChainIdV2, RequestDigestV2,
};
use thunderbolt_protocol::v2::{ChannelBindingV2, ChannelEventV2};

use crate::{HolderNodeError, Result, MAX_FINALITY_ATTESTATION_BYTES, MAX_FINALITY_BATCH, MAX_FINALITY_SEGMENT_BYTES};

/// Caller-generated local idempotency key.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct CommandId([u8; 32]);

impl CommandId {
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for CommandId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CommandId(")?;
        for byte in self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        formatter.write_str(")")
    }
}

/// Immutable identity of a finality policy, application version, and verifier key.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct FinalityVerifierProfileId([u8; 32]);

impl FinalityVerifierProfileId {
    pub const DISABLED: Self = Self([0xff; 32]);

    pub fn new(bytes: [u8; 32]) -> Result<Self> {
        if bytes == [0; 32] {
            Err(HolderNodeError::InvalidConfiguration(
                "finality verifier profile must be nonzero",
            ))
        } else {
            Ok(Self(bytes))
        }
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl<'de> Deserialize<'de> for FinalityVerifierProfileId {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::new(<[u8; 32]>::deserialize(deserializer)?).map_err(D::Error::custom)
    }
}

/// Immutable identity of the crash-safe coordinator mutated by finalization.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct FinalityCoordinatorId([u8; 32]);

impl FinalityCoordinatorId {
    pub const DISABLED: Self = Self([0xff; 32]);

    pub fn new(bytes: [u8; 32]) -> Result<Self> {
        if bytes == [0; 32] {
            Err(HolderNodeError::InvalidConfiguration(
                "finality coordinator identity must be nonzero",
            ))
        } else {
            Ok(Self(bytes))
        }
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl<'de> Deserialize<'de> for FinalityCoordinatorId {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::new(<[u8; 32]>::deserialize(deserializer)?).map_err(D::Error::custom)
    }
}

/// Nonzero digest issued by one exact finality verifier.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct FinalityDigestV2([u8; 32]);

impl FinalityDigestV2 {
    pub fn new(bytes: [u8; 32]) -> Result<Self> {
        if bytes == [0; 32] {
            Err(HolderNodeError::FinalityConflict)
        } else {
            Ok(Self(bytes))
        }
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl<'de> Deserialize<'de> for FinalityDigestV2 {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::new(<[u8; 32]>::deserialize(deserializer)?).map_err(D::Error::custom)
    }
}

/// Bounded authority-free attestation for one exact finalized executed block.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DurableBlockFinalityCapabilityV2 {
    verifier_profile: FinalityVerifierProfileId,
    coordinator_id: FinalityCoordinatorId,
    ledger_chain_id: LedgerChainIdV2,
    block_height: u64,
    app_hash: AppHashV2,
    verifier_digest: FinalityDigestV2,
    attestation: Vec<u8>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DurableBlockFinalityCapabilityInput {
    verifier_profile: FinalityVerifierProfileId,
    coordinator_id: FinalityCoordinatorId,
    ledger_chain_id: LedgerChainIdV2,
    block_height: u64,
    app_hash: AppHashV2,
    verifier_digest: FinalityDigestV2,
    attestation: BoundedAttestation,
}

struct BoundedAttestation(Vec<u8>);

struct AttestationVisitor;

impl<'de> Visitor<'de> for AttestationVisitor {
    type Value = BoundedAttestation;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "at most {MAX_FINALITY_ATTESTATION_BYTES} attestation bytes")
    }

    fn visit_seq<A>(self, mut sequence: A) -> std::result::Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        if sequence
            .size_hint()
            .is_some_and(|size| size > MAX_FINALITY_ATTESTATION_BYTES)
        {
            return Err(A::Error::custom("finality attestation exceeds its byte bound"));
        }
        let mut bytes = Vec::with_capacity(sequence.size_hint().unwrap_or(0).min(MAX_FINALITY_ATTESTATION_BYTES));
        while let Some(byte) = sequence.next_element::<u8>()? {
            if bytes.len() == MAX_FINALITY_ATTESTATION_BYTES {
                return Err(A::Error::custom("finality attestation exceeds its byte bound"));
            }
            bytes.push(byte);
        }
        Ok(BoundedAttestation(bytes))
    }
}

impl<'de> Deserialize<'de> for BoundedAttestation {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_seq(AttestationVisitor)
    }
}

impl DurableBlockFinalityCapabilityV2 {
    pub fn new(
        verifier_profile: FinalityVerifierProfileId,
        coordinator_id: FinalityCoordinatorId,
        ledger_chain_id: LedgerChainIdV2,
        block_height: u64,
        app_hash: AppHashV2,
        verifier_digest: FinalityDigestV2,
        attestation: Vec<u8>,
    ) -> Result<Self> {
        if verifier_profile == FinalityVerifierProfileId::DISABLED
            || coordinator_id == FinalityCoordinatorId::DISABLED
            || block_height == 0
            || app_hash.is_zero()
            || attestation.is_empty()
            || attestation.len() > MAX_FINALITY_ATTESTATION_BYTES
        {
            return Err(HolderNodeError::FinalityConflict);
        }
        Ok(Self {
            verifier_profile,
            coordinator_id,
            ledger_chain_id,
            block_height,
            app_hash,
            verifier_digest,
            attestation,
        })
    }

    pub const fn verifier_profile(&self) -> FinalityVerifierProfileId {
        self.verifier_profile
    }

    pub const fn coordinator_id(&self) -> FinalityCoordinatorId {
        self.coordinator_id
    }

    pub const fn ledger_chain_id(&self) -> &LedgerChainIdV2 {
        &self.ledger_chain_id
    }

    pub const fn block_height(&self) -> u64 {
        self.block_height
    }

    pub const fn app_hash(&self) -> &AppHashV2 {
        &self.app_hash
    }

    pub const fn verifier_digest(&self) -> FinalityDigestV2 {
        self.verifier_digest
    }

    pub fn attestation(&self) -> &[u8] {
        &self.attestation
    }
}

impl<'de> Deserialize<'de> for DurableBlockFinalityCapabilityV2 {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let input = DurableBlockFinalityCapabilityInput::deserialize(deserializer)?;
        Self::new(
            input.verifier_profile,
            input.coordinator_id,
            input.ledger_chain_id,
            input.block_height,
            input.app_hash,
            input.verifier_digest,
            input.attestation.0,
        )
        .map_err(D::Error::custom)
    }
}

/// Exact durable global cursor for the next finalized whole block.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FinalizedBlockCursor {
    verifier_profile: FinalityVerifierProfileId,
    coordinator_id: FinalityCoordinatorId,
    ledger_chain_id: LedgerChainIdV2,
    next_height: u64,
    expected_previous_app_hash: AppHashV2,
    last_finality: Option<DurableBlockFinalityCapabilityV2>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FinalizedBlockCursorInput {
    verifier_profile: FinalityVerifierProfileId,
    coordinator_id: FinalityCoordinatorId,
    ledger_chain_id: LedgerChainIdV2,
    next_height: u64,
    expected_previous_app_hash: AppHashV2,
    last_finality: Option<DurableBlockFinalityCapabilityV2>,
}

impl FinalizedBlockCursor {
    pub fn new(
        verifier_profile: FinalityVerifierProfileId,
        coordinator_id: FinalityCoordinatorId,
        ledger_chain_id: LedgerChainIdV2,
        next_height: u64,
        expected_previous_app_hash: AppHashV2,
        last_finality: Option<DurableBlockFinalityCapabilityV2>,
    ) -> Result<Self> {
        let valid_genesis = next_height == 1 && expected_previous_app_hash.is_zero() && last_finality.is_none();
        let valid_advanced = next_height > 1
            && !expected_previous_app_hash.is_zero()
            && last_finality.as_ref().is_some_and(|capability| {
                capability.verifier_profile == verifier_profile
                    && capability.coordinator_id == coordinator_id
                    && capability.ledger_chain_id == ledger_chain_id
                    && capability.block_height.checked_add(1) == Some(next_height)
                    && capability.app_hash == expected_previous_app_hash
            });
        if verifier_profile == FinalityVerifierProfileId::DISABLED
            || coordinator_id == FinalityCoordinatorId::DISABLED
            || (!valid_genesis && !valid_advanced)
        {
            return Err(HolderNodeError::FinalityConflict);
        }
        Ok(Self {
            verifier_profile,
            coordinator_id,
            ledger_chain_id,
            next_height,
            expected_previous_app_hash,
            last_finality,
        })
    }

    pub fn genesis(
        verifier_profile: FinalityVerifierProfileId,
        coordinator_id: FinalityCoordinatorId,
        ledger_chain_id: LedgerChainIdV2,
    ) -> Result<Self> {
        Self::new(
            verifier_profile,
            coordinator_id,
            ledger_chain_id,
            1,
            AppHashV2::zero(),
            None,
        )
    }

    pub const fn verifier_profile(&self) -> FinalityVerifierProfileId {
        self.verifier_profile
    }

    pub const fn coordinator_id(&self) -> FinalityCoordinatorId {
        self.coordinator_id
    }

    pub const fn ledger_chain_id(&self) -> &LedgerChainIdV2 {
        &self.ledger_chain_id
    }

    pub const fn next_height(&self) -> u64 {
        self.next_height
    }

    pub const fn expected_previous_app_hash(&self) -> &AppHashV2 {
        &self.expected_previous_app_hash
    }

    pub const fn last_finality(&self) -> Option<&DurableBlockFinalityCapabilityV2> {
        self.last_finality.as_ref()
    }
}

impl<'de> Deserialize<'de> for FinalizedBlockCursor {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let input = FinalizedBlockCursorInput::deserialize(deserializer)?;
        Self::new(
            input.verifier_profile,
            input.coordinator_id,
            input.ledger_chain_id,
            input.next_height,
            input.expected_previous_app_hash,
            input.last_finality,
        )
        .map_err(D::Error::custom)
    }
}

struct BoundedExecutedBlockList(Vec<ExecutedBlockV2>);

struct ExecutedBlockListVisitor;

impl<'de> Visitor<'de> for ExecutedBlockListVisitor {
    type Value = BoundedExecutedBlockList;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "between one and {MAX_FINALITY_BATCH} complete executed blocks"
        )
    }

    fn visit_seq<A>(self, mut sequence: A) -> std::result::Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        if sequence.size_hint().is_some_and(|size| size > MAX_FINALITY_BATCH) {
            return Err(A::Error::custom("finality range exceeds the block bound"));
        }
        let mut blocks = Vec::with_capacity(sequence.size_hint().unwrap_or(0).min(MAX_FINALITY_BATCH));
        while let Some(block) = sequence.next_element::<ExecutedBlockV2>()? {
            if blocks.len() == MAX_FINALITY_BATCH {
                return Err(A::Error::custom("finality range exceeds the block bound"));
            }
            blocks.push(block);
        }
        Ok(BoundedExecutedBlockList(blocks))
    }
}

impl<'de> Deserialize<'de> for BoundedExecutedBlockList {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_seq(ExecutedBlockListVisitor)
    }
}

/// Authority-free canonical intent for one non-empty finalized execution range.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FinalityRangeIntentV2 {
    verifier_profile: FinalityVerifierProfileId,
    coordinator_id: FinalityCoordinatorId,
    ledger_chain_id: LedgerChainIdV2,
    start_height: u64,
    expected_previous_app_hash: AppHashV2,
    blocks: Vec<ExecutedBlockV2>,
    next_height: u64,
    next_expected_previous_app_hash: AppHashV2,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FinalityRangeIntentInput {
    verifier_profile: FinalityVerifierProfileId,
    coordinator_id: FinalityCoordinatorId,
    ledger_chain_id: LedgerChainIdV2,
    start_height: u64,
    expected_previous_app_hash: AppHashV2,
    blocks: BoundedExecutedBlockList,
    next_height: u64,
    next_expected_previous_app_hash: AppHashV2,
}

impl FinalityRangeIntentV2 {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        verifier_profile: FinalityVerifierProfileId,
        coordinator_id: FinalityCoordinatorId,
        ledger_chain_id: LedgerChainIdV2,
        start_height: u64,
        expected_previous_app_hash: AppHashV2,
        blocks: Vec<ExecutedBlockV2>,
        next_height: u64,
        next_expected_previous_app_hash: AppHashV2,
    ) -> Result<Self> {
        if verifier_profile == FinalityVerifierProfileId::DISABLED
            || coordinator_id == FinalityCoordinatorId::DISABLED
            || blocks.is_empty()
            || blocks.len() > MAX_FINALITY_BATCH
            || start_height == 0
            || (start_height == 1) != expected_previous_app_hash.is_zero()
        {
            return Err(HolderNodeError::FinalityConflict);
        }
        let first = blocks.first().ok_or(HolderNodeError::FinalityConflict)?;
        if first.ledger_chain_id() != &ledger_chain_id
            || first.height() != start_height
            || first.previous_app_hash() != &expected_previous_app_hash
        {
            return Err(HolderNodeError::FinalityConflict);
        }
        if start_height == 1 {
            first
                .validate_previous_block_time(None)
                .map_err(|_| HolderNodeError::FinalityConflict)?;
        }
        for pair in blocks.windows(2) {
            pair[1]
                .validate_successor(&pair[0])
                .map_err(|_| HolderNodeError::FinalityConflict)?;
        }
        let expected_next = start_height
            .checked_add(u64::try_from(blocks.len()).map_err(|_| HolderNodeError::OutOfRange)?)
            .ok_or(HolderNodeError::OutOfRange)?;
        let last = blocks.last().ok_or(HolderNodeError::FinalityConflict)?;
        if next_height != expected_next || next_expected_previous_app_hash != *last.app_hash() {
            return Err(HolderNodeError::FinalityConflict);
        }
        let value = Self {
            verifier_profile,
            coordinator_id,
            ledger_chain_id,
            start_height,
            expected_previous_app_hash,
            blocks,
            next_height,
            next_expected_previous_app_hash,
        };
        let _ = value.canonical_bytes()?;
        Ok(value)
    }

    pub const fn verifier_profile(&self) -> FinalityVerifierProfileId {
        self.verifier_profile
    }

    pub const fn coordinator_id(&self) -> FinalityCoordinatorId {
        self.coordinator_id
    }

    pub const fn ledger_chain_id(&self) -> &LedgerChainIdV2 {
        &self.ledger_chain_id
    }

    pub const fn start_height(&self) -> u64 {
        self.start_height
    }

    pub const fn expected_previous_app_hash(&self) -> &AppHashV2 {
        &self.expected_previous_app_hash
    }

    pub fn blocks(&self) -> &[ExecutedBlockV2] {
        &self.blocks
    }

    pub const fn next_height(&self) -> u64 {
        self.next_height
    }

    pub const fn next_expected_previous_app_hash(&self) -> &AppHashV2 {
        &self.next_expected_previous_app_hash
    }

    pub fn digest(&self) -> Result<[u8; 32]> {
        let bytes = self.canonical_bytes()?;
        let mut hasher = Sha256::new();
        hasher.update(b"bitcoin-thunderbolt/holder/finality-range-intent/v2");
        hasher.update((bytes.len() as u64).to_be_bytes());
        hasher.update(bytes);
        Ok(hasher.finalize().into())
    }

    pub(crate) fn canonical_bytes(&self) -> Result<Vec<u8>> {
        let mut bytes = Vec::new();
        let mut writer = BoundedWriter::new(&mut bytes, MAX_FINALITY_SEGMENT_BYTES);
        serde_json::to_writer(&mut writer, self)
            .map_err(|_| HolderNodeError::InvalidRequest("finality range intent exceeds the canonical byte bound"))?;
        Ok(bytes)
    }
}

impl<'de> Deserialize<'de> for FinalityRangeIntentV2 {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let input = FinalityRangeIntentInput::deserialize(deserializer)?;
        Self::new(
            input.verifier_profile,
            input.coordinator_id,
            input.ledger_chain_id,
            input.start_height,
            input.expected_previous_app_hash,
            input.blocks.0,
            input.next_height,
            input.next_expected_previous_app_hash,
        )
        .map_err(D::Error::custom)
    }
}

/// Store-issued authority to finalize one exact durably staged range.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StagedFinalityRangeCapabilityV2 {
    store_identity: [u8; 32],
    file_identity: [u8; 32],
    stage_digest: [u8; 32],
    intent: FinalityRangeIntentV2,
}

impl StagedFinalityRangeCapabilityV2 {
    pub(crate) fn issue(
        store_identity: [u8; 32],
        file_identity: [u8; 32],
        intent: FinalityRangeIntentV2,
    ) -> Result<Self> {
        let stage_digest = stage_digest(&store_identity, &file_identity, &intent)?;
        if store_identity == [0; 32] || file_identity == [0; 32] || stage_digest == [0; 32] {
            return Err(HolderNodeError::StorageCorrupt);
        }
        Ok(Self {
            store_identity,
            file_identity,
            stage_digest,
            intent,
        })
    }

    pub const fn store_identity(&self) -> &[u8; 32] {
        &self.store_identity
    }

    pub const fn file_identity(&self) -> &[u8; 32] {
        &self.file_identity
    }

    pub const fn stage_digest(&self) -> &[u8; 32] {
        &self.stage_digest
    }

    pub const fn intent(&self) -> &FinalityRangeIntentV2 {
        &self.intent
    }
}

/// Public handoff used to recover an ambiguous coordinator transition before open.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StagedFinalityRecoveryV2 {
    store_identity: [u8; 32],
    file_identity: [u8; 32],
    stage_digest: [u8; 32],
    intent: FinalityRangeIntentV2,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StagedFinalityRecoveryInput {
    store_identity: [u8; 32],
    file_identity: [u8; 32],
    stage_digest: [u8; 32],
    intent: FinalityRangeIntentV2,
}

impl StagedFinalityRecoveryV2 {
    pub(crate) fn new(capability: &StagedFinalityRangeCapabilityV2) -> Self {
        Self {
            store_identity: capability.store_identity,
            file_identity: capability.file_identity,
            stage_digest: capability.stage_digest,
            intent: capability.intent.clone(),
        }
    }

    pub const fn store_identity(&self) -> &[u8; 32] {
        &self.store_identity
    }

    pub const fn file_identity(&self) -> &[u8; 32] {
        &self.file_identity
    }

    pub const fn stage_digest(&self) -> &[u8; 32] {
        &self.stage_digest
    }

    pub const fn intent(&self) -> &FinalityRangeIntentV2 {
        &self.intent
    }

    pub(crate) fn to_capability(&self) -> Result<StagedFinalityRangeCapabilityV2> {
        let capability =
            StagedFinalityRangeCapabilityV2::issue(self.store_identity, self.file_identity, self.intent.clone())?;
        if capability.stage_digest != self.stage_digest {
            return Err(HolderNodeError::StorageCorrupt);
        }
        Ok(capability)
    }
}

impl<'de> Deserialize<'de> for StagedFinalityRecoveryV2 {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let input = StagedFinalityRecoveryInput::deserialize(deserializer)?;
        let recovery = Self {
            store_identity: input.store_identity,
            file_identity: input.file_identity,
            stage_digest: input.stage_digest,
            intent: input.intent,
        };
        recovery.to_capability().map_err(D::Error::custom)?;
        Ok(recovery)
    }
}

/// Exact finalized capabilities returned after the coordinator commits and reads back.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FinalizedRangeCapabilityV2 {
    stage_digest: [u8; 32],
    blocks: Vec<DurableBlockFinalityCapabilityV2>,
}

impl FinalizedRangeCapabilityV2 {
    pub fn new(stage: &StagedFinalityRangeCapabilityV2, blocks: Vec<DurableBlockFinalityCapabilityV2>) -> Result<Self> {
        if blocks.len() != stage.intent.blocks.len() || blocks.is_empty() {
            return Err(HolderNodeError::FinalityConflict);
        }
        for (executed, finalized) in stage.intent.blocks.iter().zip(&blocks) {
            if finalized.verifier_profile != stage.intent.verifier_profile
                || finalized.coordinator_id != stage.intent.coordinator_id
                || finalized.ledger_chain_id != stage.intent.ledger_chain_id
                || finalized.block_height != executed.height()
                || finalized.app_hash != *executed.app_hash()
            {
                return Err(HolderNodeError::FinalityConflict);
            }
        }
        Ok(Self {
            stage_digest: stage.stage_digest,
            blocks,
        })
    }

    pub const fn stage_digest(&self) -> &[u8; 32] {
        &self.stage_digest
    }

    pub fn blocks(&self) -> &[DurableBlockFinalityCapabilityV2] {
        &self.blocks
    }

    pub fn into_blocks(self) -> Vec<DurableBlockFinalityCapabilityV2> {
        self.blocks
    }
}

fn stage_digest(
    store_identity: &[u8; 32],
    file_identity: &[u8; 32],
    intent: &FinalityRangeIntentV2,
) -> Result<[u8; 32]> {
    let bytes = intent.canonical_bytes()?;
    let mut hasher = Sha256::new();
    hasher.update(b"bitcoin-thunderbolt/holder/staged-finality-range/v2");
    hasher.update(store_identity);
    hasher.update(file_identity);
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
    Ok(hasher.finalize().into())
}

struct BoundedWriter<'a> {
    output: &'a mut Vec<u8>,
    remaining: usize,
}

impl<'a> BoundedWriter<'a> {
    fn new(output: &'a mut Vec<u8>, limit: usize) -> Self {
        Self {
            output,
            remaining: limit,
        }
    }
}

impl Write for BoundedWriter<'_> {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        if buffer.len() > self.remaining {
            return Err(io::Error::other("canonical value exceeds bound"));
        }
        self.output.extend_from_slice(buffer);
        self.remaining -= buffer.len();
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Monotonic finalized head for one locally tracked Ledger channel.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct FinalizedChannelCursor {
    pub channel_context_id: ChannelContextIdV2,
    pub sequence: u64,
    pub entry_hash: EntryHashV2,
}

impl FinalizedChannelCursor {
    pub(crate) fn new(channel_context_id: ChannelContextIdV2, sequence: u64, entry_hash: EntryHashV2) -> Self {
        Self {
            channel_context_id,
            sequence,
            entry_hash,
        }
    }
}

/// Explicit service lifecycle state.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LifecycleState {
    Created,
    Running,
    Draining,
    Stopped,
    Faulted,
}

/// Durable outbox state.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OutboxStatus {
    Queued,
    Submitted,
    Finalized,
    RetryExhausted,
}

impl OutboxStatus {
    pub(crate) const fn code(self) -> i64 {
        match self {
            Self::Queued => 0,
            Self::Submitted => 1,
            Self::Finalized => 2,
            Self::RetryExhausted => 3,
        }
    }

    pub(crate) fn from_code(code: i64) -> crate::Result<Self> {
        match code {
            0 => Ok(Self::Queued),
            1 => Ok(Self::Submitted),
            2 => Ok(Self::Finalized),
            3 => Ok(Self::RetryExhausted),
            _ => Err(HolderNodeError::StorageCorrupt),
        }
    }
}

/// Local command used to construct, sign, and enqueue one v2 proposal.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QueueProposalRequest {
    pub command_id: CommandId,
    pub channel: ChannelBindingV2,
    pub sequence: u64,
    pub previous_entry_hash: EntryHashV2,
    pub request_nonce: ClientRequestNonceV2,
    pub actor_role: ActorRoleV2,
    pub event: ChannelEventV2,
    pub now_ms: u64,
}

/// Result of durable queue insertion.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QueueDisposition {
    Queued,
    AlreadyQueued,
}

/// Public queue result.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QueuedProposal {
    pub disposition: QueueDisposition,
    pub request_digest: RequestDigestV2,
    pub entry_hash: EntryHashV2,
}

/// One service-loop report.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunReport {
    pub submitted: usize,
    pub submit_failures: usize,
    pub finalized: usize,
}

/// Local, secret-free runtime status.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceStatus {
    pub lifecycle: LifecycleState,
    pub recovered_unclean_shutdown: bool,
    pub run_generation: u64,
    pub outbox_queued: usize,
    pub outbox_submitted: usize,
    pub outbox_finalized: usize,
    pub outbox_retry_exhausted: usize,
    pub finalized_channels: usize,
    pub finalized_block_cursor: FinalizedBlockCursor,
    pub staged_finality_range: Option<[u8; 32]>,
}

/// Internal durable outbox row.
pub(crate) struct OutboxRecord {
    pub request_digest: RequestDigestV2,
    pub proposal_bytes: Vec<u8>,
}

pub(crate) fn channel_context_id(channel: &ChannelBindingV2) -> crate::Result<ChannelContextIdV2> {
    let context = channel.context_id().map_err(|_| HolderNodeError::InvalidProposal)?;
    ChannelContextIdV2::from_bytes(context).map_err(crate::HolderNodeError::from)
}

pub(crate) fn event_kind(event: &ChannelEventV2) -> EventKindV2 {
    event.kind()
}
