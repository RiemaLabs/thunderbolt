use core::fmt;
use core::time::Duration;

use serde::de::Visitor;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest as _, Sha256};
use thunderbolt_cometbft::FinalityPolicy;
use thunderbolt_cometbft_client::{
    CoordinatorConfig, CoordinatorLimits, FinalitySummary, HistoryEpochLimits, SourceConfiguration,
    TrustCoordinatorIdentity,
};
use thunderbolt_cometbft_rpc::{RpcTransportConfig, RpcTransportProfileId};
use thunderbolt_ledger::{
    AppHashV2, ChannelContextIdV2, EntryHashV2, EntryMerkleProofV2, ExecutedBlockV2, ExecutedEntryMetadataV2,
    ExecutedEntryV2, LedgerChainIdV2, ParticipantIdV2, RequestDigestV2, MAX_BLOCK_ENTRIES,
};
use thunderbolt_ledger_rpc::{ExecutionRangeCursorV2, MAX_EXECUTION_RANGE_BLOCKS};

use crate::{ClientError, Result};

const REFERENCE_MAGIC: &[u8; 8] = b"TBHER001";
const BLOCK_REFERENCE_MAGIC: &[u8; 8] = b"TBHBR001";
const REFERENCE_CHAIN_BYTES: usize = 50;
const MIN_RPC_TIMEOUT: Duration = Duration::from_millis(100);
const MAX_RPC_TIMEOUT: Duration = Duration::from_secs(120);
const CLIENT_STATIC_PROFILE_DOMAIN: &[u8] = b"bitcoin-thunderbolt/ledger-comet-client/static-profile/v1";
const CLIENT_PROFILE_DOMAIN: &[u8] = b"bitcoin-thunderbolt/ledger-comet-client/profile/v1";
/// Exact fixed-width authority-free historical-reference encoding.
pub const MAX_HISTORICAL_REFERENCE_BYTES: usize = 423;
/// Exact fixed-width authority-free historical whole-block-reference encoding.
pub const MAX_HISTORICAL_BLOCK_REFERENCE_BYTES: usize = 291;
/// Maximum finalized execution blocks inspected by one absence proof.
pub const MAX_LOCATOR_SCAN_BLOCKS: u32 = 4_096;
/// Maximum configured proof bytes inspected by one absence verification.
pub const MAX_LOCATOR_SCAN_BYTES: usize = 64 * 1024 * 1024;
/// Maximum canonical bytes in one authority-free finality recovery intent.
pub const MAX_FINALITY_ADVANCE_INTENT_BYTES: usize = 32 * 1024 * 1024 + 1024;

/// Stable audited client-profile identity.
///
/// The constructor derives this nonzero digest from coordinator policy, the
/// complete allowed peer roster and TLS/authentication profile, and every
/// trace, Ledger RPC, range, scan, byte, and deadline limit.
///
/// ```compile_fail
/// use thunderbolt_ledger_comet_client::ClientProfileIdV2;
/// let _ = ClientProfileIdV2([1_u8; 32]);
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ClientProfileIdV2(pub(crate) [u8; 32]);

impl ClientProfileIdV2 {
    /// Returns the exact profile digest.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Bounded client-local network and locator work policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LedgerCometClientLimits {
    max_range_blocks: u16,
    max_locator_scan_blocks: u32,
    max_locator_scan_bytes: usize,
    rpc_timeout: Duration,
}

impl LedgerCometClientLimits {
    /// Constructs a closed range/scan/deadline policy.
    pub fn new(
        max_range_blocks: u16,
        max_locator_scan_blocks: u32,
        max_locator_scan_bytes: usize,
        rpc_timeout: Duration,
    ) -> Result<Self> {
        if max_range_blocks == 0
            || max_range_blocks > MAX_EXECUTION_RANGE_BLOCKS
            || max_locator_scan_blocks == 0
            || max_locator_scan_blocks > MAX_LOCATOR_SCAN_BLOCKS
            || max_locator_scan_bytes == 0
            || max_locator_scan_bytes > MAX_LOCATOR_SCAN_BYTES
            || !(MIN_RPC_TIMEOUT..=MAX_RPC_TIMEOUT).contains(&rpc_timeout)
        {
            return Err(ClientError::InvalidConfiguration(
                "range, locator, or RPC deadline limit is outside bounds",
            ));
        }
        Ok(Self {
            max_range_blocks,
            max_locator_scan_blocks,
            max_locator_scan_bytes,
            rpc_timeout,
        })
    }

    /// Returns the maximum whole blocks in one exact execution range.
    pub const fn max_range_blocks(self) -> u16 {
        self.max_range_blocks
    }

    /// Returns the maximum local finalized blocks scanned for absence.
    pub const fn max_locator_scan_blocks(self) -> u32 {
        self.max_locator_scan_blocks
    }

    /// Returns the maximum aggregate configured proof bytes scanned for absence.
    pub const fn max_locator_scan_bytes(self) -> usize {
        self.max_locator_scan_bytes
    }

    /// Returns the absolute timeout used by one fixed P3 RPC operation.
    pub const fn rpc_timeout(self) -> Duration {
        self.rpc_timeout
    }
}

/// Identity-free coordinator policy used to derive the durable client identity.
#[derive(Clone, Debug)]
pub struct LedgerCoordinatorPolicyV2 {
    ledger_chain_id: LedgerChainIdV2,
    finality_policy: FinalityPolicy,
    sources: SourceConfiguration,
    busy_timeout: Duration,
    limits: CoordinatorLimits,
    history_limits: HistoryEpochLimits,
}

impl LedgerCoordinatorPolicyV2 {
    /// Constructs the complete coordinator policy before its identity is derived.
    pub fn new(
        ledger_chain_id: LedgerChainIdV2,
        finality_policy: FinalityPolicy,
        sources: SourceConfiguration,
        busy_timeout: Duration,
        limits: CoordinatorLimits,
        history_limits: HistoryEpochLimits,
    ) -> Self {
        Self {
            ledger_chain_id,
            finality_policy,
            sources,
            busy_timeout,
            limits,
            history_limits,
        }
    }

    /// Returns the exact Ledger chain.
    pub const fn ledger_chain_id(&self) -> &LedgerChainIdV2 {
        &self.ledger_chain_id
    }

    /// Returns the light-client finality policy.
    pub const fn finality_policy(&self) -> FinalityPolicy {
        self.finality_policy
    }

    /// Returns the current source roster installed into the coordinator.
    pub const fn sources(&self) -> &SourceConfiguration {
        &self.sources
    }
}

/// Complete immutable concrete-client construction policy.
#[derive(Clone, Debug)]
pub struct LedgerCometClientConfig {
    coordinator: CoordinatorConfig,
    rpc: RpcTransportConfig,
    profile_id: ClientProfileIdV2,
    limits: LedgerCometClientLimits,
}

impl LedgerCometClientConfig {
    /// Constructs a configuration whose current coordinator sources are all
    /// present in the immutable authenticated RPC peer roster. Extra peers are
    /// allowed only as explicitly pinned future rotation candidates.
    pub fn new(
        policy: LedgerCoordinatorPolicyV2,
        rpc: RpcTransportConfig,
        limits: LedgerCometClientLimits,
    ) -> Result<Self> {
        let maximum_range_proof_bytes = usize::from(limits.max_range_blocks())
            .checked_mul(policy.limits.max_proof_bundle_bytes())
            .ok_or(ClientError::InvalidConfiguration("range proof work budget overflows"))?;
        let maximum_range_requests = usize::from(limits.max_range_blocks())
            .checked_mul(MAX_BLOCK_ENTRIES)
            .ok_or(ClientError::InvalidConfiguration("range request work budget overflows"))?;
        let maximum_locator_proof_bytes = usize::try_from(limits.max_locator_scan_blocks())
            .map_err(|_| ClientError::InvalidConfiguration("locator block limit does not fit usize"))?
            .checked_mul(policy.limits.max_proof_bundle_bytes())
            .ok_or(ClientError::InvalidConfiguration("locator proof work budget overflows"))?;
        if usize::from(limits.max_range_blocks()) > policy.history_limits.max_transitions()
            || maximum_range_proof_bytes > policy.history_limits.max_proof_bytes()
            || maximum_range_requests > policy.history_limits.max_requests()
            || maximum_locator_proof_bytes > limits.max_locator_scan_bytes()
        {
            return Err(ClientError::InvalidConfiguration(
                "range or locator work cannot fit its configured proof budget",
            ));
        }
        let peers = rpc.peers();
        let source_present =
            |source: &thunderbolt_cometbft_client::PeerIdentity| peers.iter().any(|peer| peer.identity() == source);
        if !source_present(policy.sources().primary())
            || policy
                .sources()
                .witnesses()
                .iter()
                .any(|source| !source_present(source))
        {
            return Err(ClientError::InvalidConfiguration(
                "coordinator source is absent from the authenticated RPC roster",
            ));
        }
        let static_profile_digest = derive_static_profile(&policy);
        let rpc_profile_id = rpc.profile_id();
        let profile_id = derive_client_profile(static_profile_digest, rpc_profile_id, limits);
        let coordinator_identity = TrustCoordinatorIdentity::new(*profile_id.as_bytes())?;
        let coordinator = CoordinatorConfig::new(
            coordinator_identity,
            policy.ledger_chain_id,
            policy.finality_policy,
            policy.sources,
            policy.busy_timeout,
            policy.limits,
            policy.history_limits,
        )?;
        Ok(Self {
            coordinator,
            rpc,
            profile_id,
            limits,
        })
    }

    /// Returns the crash-safe coordinator configuration.
    pub const fn coordinator(&self) -> &CoordinatorConfig {
        &self.coordinator
    }

    /// Returns the complete allowed authenticated RPC peer configuration.
    pub const fn rpc(&self) -> &RpcTransportConfig {
        &self.rpc
    }

    /// Returns the stable audited client profile.
    pub const fn profile_id(&self) -> ClientProfileIdV2 {
        self.profile_id
    }

    /// Returns bounded client-local work policy.
    pub const fn limits(&self) -> LedgerCometClientLimits {
        self.limits
    }
}

fn derive_static_profile(config: &LedgerCoordinatorPolicyV2) -> [u8; 32] {
    let policy = config.finality_policy;
    let history = config.history_limits;
    let mut hasher = Sha256::new();
    hasher.update(CLIENT_STATIC_PROFILE_DOMAIN);
    append_profile_bytes(&mut hasher, config.ledger_chain_id.as_bytes());
    hasher.update(policy.trusting_period().as_nanos().to_be_bytes());
    hasher.update(policy.clock_drift().as_nanos().to_be_bytes());
    for value in [
        policy.max_validators(),
        policy.max_adjacent_headers(),
        policy.min_witnesses(),
        policy.max_witnesses(),
        config.limits.max_trace_encoded_bytes(),
        config.limits.max_execution_encoded_bytes(),
        config.limits.max_proof_bundle_bytes(),
        history.max_transitions(),
        history.max_proof_bytes(),
        history.max_requests(),
    ] {
        hasher.update(u64::try_from(value).unwrap_or(u64::MAX).to_be_bytes());
    }
    hasher.update(config.busy_timeout.as_nanos().to_be_bytes());
    hasher.update(config.limits.operation_timeout().as_nanos().to_be_bytes());
    hasher.finalize().into()
}

fn derive_client_profile(
    static_profile_digest: [u8; 32],
    rpc_profile_id: RpcTransportProfileId,
    limits: LedgerCometClientLimits,
) -> ClientProfileIdV2 {
    let mut hasher = Sha256::new();
    hasher.update(CLIENT_PROFILE_DOMAIN);
    hasher.update(static_profile_digest);
    hasher.update(rpc_profile_id.as_bytes());
    hasher.update(limits.max_range_blocks().to_be_bytes());
    hasher.update(limits.max_locator_scan_blocks().to_be_bytes());
    hasher.update(
        u64::try_from(limits.max_locator_scan_bytes())
            .unwrap_or(u64::MAX)
            .to_be_bytes(),
    );
    hasher.update(limits.rpc_timeout().as_nanos().to_be_bytes());
    ClientProfileIdV2(hasher.finalize().into())
}

fn append_profile_bytes(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update(u64::try_from(bytes.len()).unwrap_or(u64::MAX).to_be_bytes());
    hasher.update(bytes);
}

/// Fixed-width provider-free historical locator for one complete executed block.
///
/// This value contains no validator receipt, peer identity, entry index, or
/// capability authority. Deserialization proves canonical shape only. Every
/// use must call `LedgerCometClient::revalidate_block_reference` against the
/// externally anchored coordinator history.
#[derive(Clone, PartialEq, Eq)]
pub struct HistoricalBlockReferenceV2 {
    pub(crate) profile_id: ClientProfileIdV2,
    pub(crate) coordinator_identity: TrustCoordinatorIdentity,
    pub(crate) ledger_chain_id: LedgerChainIdV2,
    pub(crate) source_config_version: u64,
    pub(crate) application_version: u64,
    pub(crate) execution_height: u64,
    pub(crate) execution_block_time_ms: u64,
    pub(crate) application_hash: AppHashV2,
    pub(crate) execution_header_hash: [u8; 32],
    pub(crate) committing_height: u64,
    pub(crate) committing_header_hash: [u8; 32],
    pub(crate) proof_digest: [u8; 32],
}

impl HistoricalBlockReferenceV2 {
    pub(crate) fn from_finality(
        profile_id: ClientProfileIdV2,
        coordinator_identity: TrustCoordinatorIdentity,
        summary: &FinalitySummary,
        proof_digest: [u8; 32],
    ) -> Result<Self> {
        let reference = Self {
            profile_id,
            coordinator_identity,
            ledger_chain_id: summary.ledger_chain_id().clone(),
            source_config_version: summary.config_version(),
            application_version: summary.application_version(),
            execution_height: summary.execution_height(),
            execution_block_time_ms: summary.execution_block_time_ms(),
            application_hash: summary.application_hash().clone(),
            execution_header_hash: *summary.execution_header_hash(),
            committing_height: summary.committing_height(),
            committing_header_hash: *summary.committing_header_hash(),
            proof_digest,
        };
        reference.validate_shape()?;
        Ok(reference)
    }

    /// Encodes the sole fixed-width binary representation.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut output = Vec::with_capacity(MAX_HISTORICAL_BLOCK_REFERENCE_BYTES);
        output.extend_from_slice(BLOCK_REFERENCE_MAGIC);
        output.extend_from_slice(self.profile_id.as_bytes());
        output.extend_from_slice(self.coordinator_identity.as_bytes());
        let chain = self.ledger_chain_id.as_bytes();
        output.push(u8::try_from(chain.len()).unwrap_or(u8::MAX));
        output.extend_from_slice(chain);
        output.resize(8 + 32 + 32 + 1 + REFERENCE_CHAIN_BYTES, 0);
        output.extend_from_slice(&self.source_config_version.to_be_bytes());
        output.extend_from_slice(&self.application_version.to_be_bytes());
        output.extend_from_slice(&self.execution_height.to_be_bytes());
        output.extend_from_slice(&self.execution_block_time_ms.to_be_bytes());
        output.extend_from_slice(self.application_hash.as_bytes());
        output.extend_from_slice(&self.execution_header_hash);
        output.extend_from_slice(&self.committing_height.to_be_bytes());
        output.extend_from_slice(&self.committing_header_hash);
        output.extend_from_slice(&self.proof_digest);
        output
    }

    /// Decodes canonical shape without granting finality authority.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != MAX_HISTORICAL_BLOCK_REFERENCE_BYTES
            || bytes.get(..8) != Some(BLOCK_REFERENCE_MAGIC.as_slice())
        {
            return Err(ClientError::BindingMismatch);
        }
        let chain_len = usize::from(*bytes.get(72).ok_or(ClientError::BindingMismatch)?);
        if chain_len == 0 || chain_len > REFERENCE_CHAIN_BYTES {
            return Err(ClientError::BindingMismatch);
        }
        let chain_start = 73;
        let chain_end = chain_start + chain_len;
        if bytes
            .get(chain_end..123)
            .ok_or(ClientError::BindingMismatch)?
            .iter()
            .any(|byte| *byte != 0)
        {
            return Err(ClientError::BindingMismatch);
        }
        let reference = Self {
            profile_id: ClientProfileIdV2(copy_fixed::<32>(bytes, 8)?),
            coordinator_identity: TrustCoordinatorIdentity::new(copy_fixed::<32>(bytes, 40)?)?,
            ledger_chain_id: LedgerChainIdV2::new(
                std::str::from_utf8(bytes.get(chain_start..chain_end).ok_or(ClientError::BindingMismatch)?)
                    .map_err(|_| ClientError::BindingMismatch)?,
            )
            .map_err(|_| ClientError::BindingMismatch)?,
            source_config_version: read_u64(bytes, 123)?,
            application_version: read_u64(bytes, 131)?,
            execution_height: read_u64(bytes, 139)?,
            execution_block_time_ms: read_u64(bytes, 147)?,
            application_hash: AppHashV2::from_bytes(copy_fixed::<32>(bytes, 155)?)
                .map_err(|_| ClientError::BindingMismatch)?,
            execution_header_hash: copy_fixed::<32>(bytes, 187)?,
            committing_height: read_u64(bytes, 219)?,
            committing_header_hash: copy_fixed::<32>(bytes, 227)?,
            proof_digest: copy_fixed::<32>(bytes, 259)?,
        };
        reference.validate_shape()?;
        if reference.canonical_bytes() != bytes {
            return Err(ClientError::BindingMismatch);
        }
        Ok(reference)
    }

    fn validate_shape(&self) -> Result<()> {
        if self.profile_id.0 == [0_u8; 32]
            || self.source_config_version == 0
            || self.application_version != 2
            || self.execution_height == 0
            || self.execution_block_time_ms == 0
            || self.application_hash.is_zero()
            || self.execution_header_hash == [0_u8; 32]
            || self.committing_height
                != self
                    .execution_height
                    .checked_add(1)
                    .ok_or(ClientError::BindingMismatch)?
            || self.committing_header_hash == [0_u8; 32]
            || self.proof_digest == [0_u8; 32]
        {
            return Err(ClientError::BindingMismatch);
        }
        Ok(())
    }

    /// Returns the audited client profile required for revalidation.
    pub const fn profile_id(&self) -> ClientProfileIdV2 {
        self.profile_id
    }

    /// Returns the exact coordinator identity required for revalidation.
    pub const fn coordinator_identity(&self) -> TrustCoordinatorIdentity {
        self.coordinator_identity
    }

    /// Returns the exact Ledger chain.
    pub const fn ledger_chain_id(&self) -> &LedgerChainIdV2 {
        &self.ledger_chain_id
    }

    /// Returns the historical source-roster version.
    pub const fn source_config_version(&self) -> u64 {
        self.source_config_version
    }

    /// Returns the verified application version.
    pub const fn application_version(&self) -> u64 {
        self.application_version
    }

    /// Returns the exact finalized execution height.
    pub const fn execution_height(&self) -> u64 {
        self.execution_height
    }

    /// Returns the exact consensus execution time in milliseconds.
    pub const fn execution_block_time_ms(&self) -> u64 {
        self.execution_block_time_ms
    }

    /// Returns the exact finalized application hash.
    pub const fn application_hash(&self) -> &AppHashV2 {
        &self.application_hash
    }

    /// Returns the verified execution-header hash.
    pub const fn execution_header_hash(&self) -> &[u8; 32] {
        &self.execution_header_hash
    }

    /// Returns the adjacent committing height.
    pub const fn committing_height(&self) -> u64 {
        self.committing_height
    }

    /// Returns the verified committing-header hash.
    pub const fn committing_header_hash(&self) -> &[u8; 32] {
        &self.committing_header_hash
    }

    /// Returns the coordinator integrity digest for the exact proof bundle.
    pub const fn proof_digest(&self) -> &[u8; 32] {
        &self.proof_digest
    }
}

impl fmt::Debug for HistoricalBlockReferenceV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HistoricalBlockReferenceV2")
            .field("profile_id", &self.profile_id)
            .field("ledger_chain_id", &self.ledger_chain_id)
            .field("source_config_version", &self.source_config_version)
            .field("execution_height", &self.execution_height)
            .field("application_version", &self.application_version)
            .field("authority", &"none")
            .finish_non_exhaustive()
    }
}

impl Serialize for HistoricalBlockReferenceV2 {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(self.canonical_bytes()))
    }
}

struct BlockReferenceVisitor;

impl<'de> Visitor<'de> for BlockReferenceVisitor {
    type Value = HistoricalBlockReferenceV2;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "exactly {} lowercase hexadecimal characters",
            MAX_HISTORICAL_BLOCK_REFERENCE_BYTES * 2
        )
    }

    fn visit_borrowed_str<E>(self, value: &'de str) -> std::result::Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        decode_block_reference_hex(value).map_err(E::custom)
    }

    fn visit_str<E>(self, value: &str) -> std::result::Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        decode_block_reference_hex(value).map_err(E::custom)
    }
}

impl<'de> Deserialize<'de> for HistoricalBlockReferenceV2 {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_str(BlockReferenceVisitor)
    }
}

fn decode_block_reference_hex(value: &str) -> Result<HistoricalBlockReferenceV2> {
    if value.len() != MAX_HISTORICAL_BLOCK_REFERENCE_BYTES * 2
        || value
            .bytes()
            .any(|byte| !(byte.is_ascii_digit() || matches!(byte, b'a'..=b'f')))
    {
        return Err(ClientError::BindingMismatch);
    }
    let bytes = hex::decode(value).map_err(|_| ClientError::BindingMismatch)?;
    HistoricalBlockReferenceV2::from_canonical_bytes(&bytes)
}

/// Fixed-width serializable locator with no receipt or capability authority.
///
/// Deserializing this type proves only canonical shape. Every consumer must
/// pass it to `LedgerCometClient::revalidate_reference` before using the
/// referenced entry.
#[derive(Clone, PartialEq, Eq)]
pub struct HistoricalEntryReferenceV2 {
    pub(crate) profile_id: ClientProfileIdV2,
    pub(crate) coordinator_identity: TrustCoordinatorIdentity,
    pub(crate) ledger_chain_id: LedgerChainIdV2,
    pub(crate) source_config_version: u64,
    pub(crate) application_version: u64,
    pub(crate) execution_height: u64,
    pub(crate) execution_block_time_ms: u64,
    pub(crate) application_hash: AppHashV2,
    pub(crate) execution_header_hash: [u8; 32],
    pub(crate) committing_height: u64,
    pub(crate) committing_header_hash: [u8; 32],
    pub(crate) block_index: u32,
    pub(crate) channel_context_id: ChannelContextIdV2,
    pub(crate) participant_id: ParticipantIdV2,
    pub(crate) request_digest: RequestDigestV2,
    pub(crate) entry_hash: EntryHashV2,
    pub(crate) proof_digest: [u8; 32],
}

impl HistoricalEntryReferenceV2 {
    pub(crate) fn from_finality(
        profile_id: ClientProfileIdV2,
        coordinator_identity: TrustCoordinatorIdentity,
        summary: &FinalitySummary,
        metadata: &ExecutedEntryMetadataV2,
        proof_digest: [u8; 32],
    ) -> Result<Self> {
        let reference = Self {
            profile_id,
            coordinator_identity,
            ledger_chain_id: summary.ledger_chain_id().clone(),
            source_config_version: summary.config_version(),
            application_version: summary.application_version(),
            execution_height: summary.execution_height(),
            execution_block_time_ms: summary.execution_block_time_ms(),
            application_hash: summary.application_hash().clone(),
            execution_header_hash: *summary.execution_header_hash(),
            committing_height: summary.committing_height(),
            committing_header_hash: *summary.committing_header_hash(),
            block_index: metadata.block_index(),
            channel_context_id: metadata.channel_context_id().clone(),
            participant_id: metadata.participant_id().clone(),
            request_digest: metadata.request_digest().clone(),
            entry_hash: metadata.entry_hash().clone(),
            proof_digest,
        };
        reference.validate_shape()?;
        Ok(reference)
    }

    /// Encodes the sole fixed-width binary representation.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut output = Vec::with_capacity(MAX_HISTORICAL_REFERENCE_BYTES);
        output.extend_from_slice(REFERENCE_MAGIC);
        output.extend_from_slice(self.profile_id.as_bytes());
        output.extend_from_slice(self.coordinator_identity.as_bytes());
        let chain = self.ledger_chain_id.as_bytes();
        output.push(u8::try_from(chain.len()).unwrap_or(u8::MAX));
        output.extend_from_slice(chain);
        output.resize(8 + 32 + 32 + 1 + REFERENCE_CHAIN_BYTES, 0);
        output.extend_from_slice(&self.source_config_version.to_be_bytes());
        output.extend_from_slice(&self.application_version.to_be_bytes());
        output.extend_from_slice(&self.execution_height.to_be_bytes());
        output.extend_from_slice(&self.execution_block_time_ms.to_be_bytes());
        output.extend_from_slice(self.application_hash.as_bytes());
        output.extend_from_slice(&self.execution_header_hash);
        output.extend_from_slice(&self.committing_height.to_be_bytes());
        output.extend_from_slice(&self.committing_header_hash);
        output.extend_from_slice(&self.block_index.to_be_bytes());
        output.extend_from_slice(self.channel_context_id.as_bytes());
        output.extend_from_slice(self.participant_id.as_bytes());
        output.extend_from_slice(self.request_digest.as_bytes());
        output.extend_from_slice(self.entry_hash.as_bytes());
        output.extend_from_slice(&self.proof_digest);
        output
    }

    /// Decodes canonical shape without granting authority.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != MAX_HISTORICAL_REFERENCE_BYTES || bytes.get(..8) != Some(REFERENCE_MAGIC.as_slice()) {
            return Err(ClientError::BindingMismatch);
        }
        let chain_len = usize::from(*bytes.get(72).ok_or(ClientError::BindingMismatch)?);
        if chain_len == 0 || chain_len > REFERENCE_CHAIN_BYTES {
            return Err(ClientError::BindingMismatch);
        }
        let chain_start = 73;
        let chain_end = chain_start + chain_len;
        if bytes
            .get(chain_end..123)
            .ok_or(ClientError::BindingMismatch)?
            .iter()
            .any(|byte| *byte != 0)
        {
            return Err(ClientError::BindingMismatch);
        }
        let profile_id = ClientProfileIdV2(copy_fixed::<32>(bytes, 8)?);
        let coordinator_identity = TrustCoordinatorIdentity::new(copy_fixed::<32>(bytes, 40)?)?;
        let ledger_chain_id = LedgerChainIdV2::new(
            std::str::from_utf8(bytes.get(chain_start..chain_end).ok_or(ClientError::BindingMismatch)?)
                .map_err(|_| ClientError::BindingMismatch)?,
        )
        .map_err(|_| ClientError::BindingMismatch)?;
        let reference = Self {
            profile_id,
            coordinator_identity,
            ledger_chain_id,
            source_config_version: read_u64(bytes, 123)?,
            application_version: read_u64(bytes, 131)?,
            execution_height: read_u64(bytes, 139)?,
            execution_block_time_ms: read_u64(bytes, 147)?,
            application_hash: AppHashV2::from_bytes(copy_fixed::<32>(bytes, 155)?)
                .map_err(|_| ClientError::BindingMismatch)?,
            execution_header_hash: copy_fixed::<32>(bytes, 187)?,
            committing_height: read_u64(bytes, 219)?,
            committing_header_hash: copy_fixed::<32>(bytes, 227)?,
            block_index: read_u32(bytes, 259)?,
            channel_context_id: ChannelContextIdV2::from_bytes(copy_fixed::<32>(bytes, 263)?)
                .map_err(|_| ClientError::BindingMismatch)?,
            participant_id: ParticipantIdV2::from_bytes(copy_fixed::<32>(bytes, 295)?)
                .map_err(|_| ClientError::BindingMismatch)?,
            request_digest: RequestDigestV2::from_bytes(copy_fixed::<32>(bytes, 327)?)
                .map_err(|_| ClientError::BindingMismatch)?,
            entry_hash: EntryHashV2::from_bytes(copy_fixed::<32>(bytes, 359)?)
                .map_err(|_| ClientError::BindingMismatch)?,
            proof_digest: copy_fixed::<32>(bytes, 391)?,
        };
        reference.validate_shape()?;
        if reference.canonical_bytes() != bytes {
            return Err(ClientError::BindingMismatch);
        }
        Ok(reference)
    }

    fn validate_shape(&self) -> Result<()> {
        if self.profile_id.0 == [0_u8; 32]
            || self.source_config_version == 0
            || self.application_version != 2
            || self.execution_height == 0
            || self.execution_block_time_ms == 0
            || self.application_hash.is_zero()
            || self.execution_header_hash == [0_u8; 32]
            || self.committing_height
                != self
                    .execution_height
                    .checked_add(1)
                    .ok_or(ClientError::BindingMismatch)?
            || self.committing_header_hash == [0_u8; 32]
            || usize::try_from(self.block_index).map_or(true, |index| index >= MAX_BLOCK_ENTRIES)
            || self.entry_hash.is_zero()
            || self.proof_digest == [0_u8; 32]
        {
            return Err(ClientError::BindingMismatch);
        }
        Ok(())
    }

    /// Returns the audited client profile required for revalidation.
    pub const fn profile_id(&self) -> ClientProfileIdV2 {
        self.profile_id
    }

    /// Returns the coordinator identity required for revalidation.
    pub const fn coordinator_identity(&self) -> TrustCoordinatorIdentity {
        self.coordinator_identity
    }

    /// Returns the exact Ledger chain.
    pub const fn ledger_chain_id(&self) -> &LedgerChainIdV2 {
        &self.ledger_chain_id
    }

    /// Returns the historical source-roster version.
    pub const fn source_config_version(&self) -> u64 {
        self.source_config_version
    }

    /// Returns the finalized execution height.
    pub const fn execution_height(&self) -> u64 {
        self.execution_height
    }

    /// Returns the zero-based entry index.
    pub const fn block_index(&self) -> u32 {
        self.block_index
    }

    /// Returns the exact channel context.
    pub const fn channel_context_id(&self) -> &ChannelContextIdV2 {
        &self.channel_context_id
    }

    /// Returns the exact actor request digest.
    pub const fn request_digest(&self) -> &RequestDigestV2 {
        &self.request_digest
    }

    /// Returns the stable entry hash.
    pub const fn entry_hash(&self) -> &EntryHashV2 {
        &self.entry_hash
    }
}

impl fmt::Debug for HistoricalEntryReferenceV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HistoricalEntryReferenceV2")
            .field("profile_id", &self.profile_id)
            .field("ledger_chain_id", &self.ledger_chain_id)
            .field("execution_height", &self.execution_height)
            .field("block_index", &self.block_index)
            .field("request_digest", &self.request_digest)
            .field("entry_hash", &self.entry_hash)
            .finish_non_exhaustive()
    }
}

impl Serialize for HistoricalEntryReferenceV2 {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(self.canonical_bytes()))
    }
}

struct ReferenceVisitor;

impl<'de> Visitor<'de> for ReferenceVisitor {
    type Value = HistoricalEntryReferenceV2;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "exactly {} lowercase hexadecimal characters",
            MAX_HISTORICAL_REFERENCE_BYTES * 2
        )
    }

    fn visit_borrowed_str<E>(self, value: &'de str) -> std::result::Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        decode_reference_hex(value).map_err(E::custom)
    }

    fn visit_str<E>(self, value: &str) -> std::result::Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        decode_reference_hex(value).map_err(E::custom)
    }
}

impl<'de> Deserialize<'de> for HistoricalEntryReferenceV2 {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_str(ReferenceVisitor)
    }
}

fn decode_reference_hex(value: &str) -> Result<HistoricalEntryReferenceV2> {
    if value.len() != MAX_HISTORICAL_REFERENCE_BYTES * 2
        || value
            .bytes()
            .any(|byte| !(byte.is_ascii_digit() || matches!(byte, b'a'..=b'f')))
    {
        return Err(ClientError::BindingMismatch);
    }
    let bytes = hex::decode(value).map_err(|_| ClientError::BindingMismatch)?;
    HistoricalEntryReferenceV2::from_canonical_bytes(&bytes)
}

/// Private in-process finality capability for one exact executed entry.
#[derive(Clone)]
pub struct HolderFinalityCapabilityV2 {
    pub(crate) reference: HistoricalEntryReferenceV2,
    pub(crate) summary: FinalizedExecutionSummaryV2,
    pub(crate) entry: ExecutedEntryV2,
    pub(crate) inclusion_proof: EntryMerkleProofV2,
}

impl HolderFinalityCapabilityV2 {
    /// Returns the non-serializable receipt-derived finality summary.
    pub const fn summary(&self) -> &FinalizedExecutionSummaryV2 {
        &self.summary
    }

    /// Returns the exact signed proposal and executed metadata.
    pub const fn entry(&self) -> &ExecutedEntryV2 {
        &self.entry
    }

    /// Returns the ordered entry inclusion proof.
    pub const fn inclusion_proof(&self) -> &EntryMerkleProofV2 {
        &self.inclusion_proof
    }

    /// Returns an authority-free reference that requires later revalidation.
    pub const fn reference(&self) -> &HistoricalEntryReferenceV2 {
        &self.reference
    }
}

impl fmt::Debug for HolderFinalityCapabilityV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HolderFinalityCapabilityV2")
            .field("reference", &self.reference)
            .field("finality", &"[verified in process]")
            .finish()
    }
}

/// Private in-process finality capability for one complete executed block.
#[derive(Clone)]
pub struct FinalizedBlockCapabilityV2 {
    pub(crate) reference: HistoricalBlockReferenceV2,
    pub(crate) summary: FinalizedExecutionSummaryV2,
    pub(crate) block: ExecutedBlockV2,
}

impl FinalizedBlockCapabilityV2 {
    /// Returns the audited client profile.
    pub const fn profile_id(&self) -> ClientProfileIdV2 {
        self.reference.profile_id
    }

    /// Returns the finality summary bound to the block.
    pub const fn summary(&self) -> &FinalizedExecutionSummaryV2 {
        &self.summary
    }

    /// Returns the complete globally ordered execution block, including an empty entry list.
    pub const fn block(&self) -> &ExecutedBlockV2 {
        &self.block
    }

    /// Returns the coordinator integrity digest for the historical proof bundle.
    pub const fn proof_digest(&self) -> &[u8; 32] {
        &self.reference.proof_digest
    }

    /// Returns the provider-free authority-free historical block reference.
    pub const fn reference(&self) -> &HistoricalBlockReferenceV2 {
        &self.reference
    }
}

impl fmt::Debug for FinalizedBlockCapabilityV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FinalizedBlockCapabilityV2")
            .field("profile_id", &self.reference.profile_id)
            .field("height", &self.block.height())
            .field("entry_count", &self.block.entries().len())
            .field("app_hash", self.block.app_hash())
            .finish()
    }
}

/// One exact finalized whole-block range and mandatory continuation.
pub struct FinalizedRangeV2 {
    pub(crate) blocks: Vec<FinalizedBlockCapabilityV2>,
    pub(crate) next_cursor: ExecutionRangeCursorV2,
}

/// Authority-free exact execution intent retained before a finality mutation.
///
/// It contains no consensus receipt. If checkpoint acknowledgement fails, pass
/// [`Self::execution`] to `LedgerCometClient::recover_finality` after restart.
#[derive(Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FinalityAdvanceIntentV2 {
    pub(crate) profile_id: [u8; 32],
    pub(crate) coordinator_identity: [u8; 32],
    pub(crate) execution: ExecutedBlockV2,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FinalityAdvanceIntentInput {
    profile_id: [u8; 32],
    coordinator_identity: [u8; 32],
    execution: ExecutedBlockV2,
}

impl FinalityAdvanceIntentV2 {
    pub(crate) fn new(
        profile_id: ClientProfileIdV2,
        coordinator_identity: TrustCoordinatorIdentity,
        execution: ExecutedBlockV2,
        max_execution_encoded_bytes: usize,
    ) -> Result<Self> {
        let execution_bytes = serde_json::to_vec(&execution).map_err(|_| ClientError::Codec)?;
        if execution_bytes.is_empty() || execution_bytes.len() > max_execution_encoded_bytes {
            return Err(ClientError::Capacity);
        }
        let intent = Self {
            profile_id: *profile_id.as_bytes(),
            coordinator_identity: *coordinator_identity.as_bytes(),
            execution,
        };
        if intent.to_canonical_bytes()?.len() > MAX_FINALITY_ADVANCE_INTENT_BYTES {
            return Err(ClientError::Capacity);
        }
        Ok(intent)
    }

    /// Returns the exact deterministic execution to retain for recovery.
    pub const fn execution(&self) -> &ExecutedBlockV2 {
        &self.execution
    }

    /// Returns the unique bounded canonical JSON representation.
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>> {
        let bytes = serde_json::to_vec(self).map_err(|_| ClientError::Codec)?;
        if bytes.is_empty() || bytes.len() > MAX_FINALITY_ADVANCE_INTENT_BYTES {
            return Err(ClientError::Capacity);
        }
        Ok(bytes)
    }

    /// Decodes canonical shape without creating finality authority.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.is_empty() || bytes.len() > MAX_FINALITY_ADVANCE_INTENT_BYTES {
            return Err(ClientError::Capacity);
        }
        let input: FinalityAdvanceIntentInput = serde_json::from_slice(bytes).map_err(|_| ClientError::Codec)?;
        if input.profile_id == [0_u8; 32] || input.coordinator_identity == [0_u8; 32] {
            return Err(ClientError::BindingMismatch);
        }
        let intent = Self {
            profile_id: input.profile_id,
            coordinator_identity: input.coordinator_identity,
            execution: input.execution,
        };
        if intent.to_canonical_bytes()? != bytes {
            return Err(ClientError::Codec);
        }
        Ok(intent)
    }
}

impl fmt::Debug for FinalityAdvanceIntentV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FinalityAdvanceIntentV2")
            .field("profile_id", &self.profile_id)
            .field("height", &self.execution.height())
            .field("app_hash", self.execution.app_hash())
            .field("authority", &"none")
            .finish()
    }
}

/// Exact P2 range prepared before any coordinator mutation.
///
/// Callers must durably retain every contained intent before passing this value
/// to `finalize_prepared_range`.
pub struct PreparedExecutionRangeV2 {
    pub(crate) intents: Vec<FinalityAdvanceIntentV2>,
    pub(crate) next_cursor: ExecutionRangeCursorV2,
}

impl PreparedExecutionRangeV2 {
    pub(crate) fn from_staged_blocks(
        profile_id: ClientProfileIdV2,
        coordinator_identity: TrustCoordinatorIdentity,
        blocks: Vec<ExecutedBlockV2>,
        next_cursor: ExecutionRangeCursorV2,
        max_execution_encoded_bytes: usize,
    ) -> Result<Self> {
        if blocks.is_empty() || blocks.len() > usize::from(MAX_EXECUTION_RANGE_BLOCKS) {
            return Err(ClientError::Capacity);
        }
        for pair in blocks.windows(2) {
            pair[1]
                .validate_successor(&pair[0])
                .map_err(|_| ClientError::BindingMismatch)?;
        }
        let intents = blocks
            .into_iter()
            .map(|block| {
                FinalityAdvanceIntentV2::new(profile_id, coordinator_identity, block, max_execution_encoded_bytes)
            })
            .collect::<Result<Vec<_>>>()?;
        let last = intents.last().ok_or(ClientError::Capacity)?;
        if next_cursor.ledger_chain_id() != last.execution().ledger_chain_id()
            || next_cursor.next_height()
                != last
                    .execution()
                    .height()
                    .checked_add(1)
                    .ok_or(ClientError::BindingMismatch)?
            || next_cursor.expected_previous_app_hash() != last.execution().app_hash()
        {
            return Err(ClientError::BindingMismatch);
        }
        Ok(Self { intents, next_cursor })
    }

    /// Returns authority-free exact execution intents in global block order.
    pub fn intents(&self) -> &[FinalityAdvanceIntentV2] {
        &self.intents
    }

    /// Returns the mandatory cursor after the prepared range.
    pub const fn next_cursor(&self) -> &ExecutionRangeCursorV2 {
        &self.next_cursor
    }
}

impl fmt::Debug for PreparedExecutionRangeV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedExecutionRangeV2")
            .field("intent_count", &self.intents.len())
            .field("next_cursor", &self.next_cursor)
            .field("authority", &"none")
            .finish()
    }
}

impl FinalizedRangeV2 {
    /// Returns every finalized whole block in exact order, including empty blocks.
    pub fn blocks(&self) -> &[FinalizedBlockCapabilityV2] {
        &self.blocks
    }

    /// Returns the mandatory cursor immediately after the range.
    pub const fn next_cursor(&self) -> &ExecutionRangeCursorV2 {
        &self.next_cursor
    }
}

impl fmt::Debug for FinalizedRangeV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FinalizedRangeV2")
            .field("block_count", &self.blocks.len())
            .field("next_cursor", &self.next_cursor)
            .finish()
    }
}

/// Finalized absence capability for one exact first-location checkpoint.
#[derive(Clone)]
pub struct FinalizedAbsenceCapabilityV2 {
    pub(crate) profile_id: ClientProfileIdV2,
    pub(crate) channel_context_id: ChannelContextIdV2,
    pub(crate) entry_hash: EntryHashV2,
    pub(crate) through_summary: FinalizedExecutionSummaryV2,
}

impl fmt::Debug for FinalizedAbsenceCapabilityV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FinalizedAbsenceCapabilityV2")
            .field("profile_id", &self.profile_id)
            .field("channel_context_id", &self.channel_context_id)
            .field("entry_hash", &self.entry_hash)
            .field("through_height", &self.through_summary.execution_height())
            .field("finality", &"[verified in process]")
            .finish()
    }
}

impl FinalizedAbsenceCapabilityV2 {
    /// Returns the audited client profile.
    pub const fn profile_id(&self) -> ClientProfileIdV2 {
        self.profile_id
    }

    /// Returns the exact channel context proven absent.
    pub const fn channel_context_id(&self) -> &ChannelContextIdV2 {
        &self.channel_context_id
    }

    /// Returns the exact stable entry hash proven absent.
    pub const fn entry_hash(&self) -> &EntryHashV2 {
        &self.entry_hash
    }

    /// Returns the finalized inclusive checkpoint summary.
    pub const fn through_summary(&self) -> &FinalizedExecutionSummaryV2 {
        &self.through_summary
    }
}

/// Provider-free receipt-derived finalized execution summary.
///
/// This type intentionally implements no serialization. It excludes primary
/// and witness provider identities while retaining every field needed to bind
/// execution to the coordinator's verified headers.
#[derive(Clone, PartialEq, Eq)]
pub struct FinalizedExecutionSummaryV2 {
    ledger_chain_id: LedgerChainIdV2,
    application_version: u64,
    source_config_version: u64,
    execution_height: u64,
    execution_block_time_ms: u64,
    application_hash: AppHashV2,
    execution_header_hash: [u8; 32],
    committing_height: u64,
    committing_header_hash: [u8; 32],
}

impl FinalizedExecutionSummaryV2 {
    pub(crate) fn from_finality(summary: &FinalitySummary) -> Self {
        Self {
            ledger_chain_id: summary.ledger_chain_id().clone(),
            application_version: summary.application_version(),
            source_config_version: summary.config_version(),
            execution_height: summary.execution_height(),
            execution_block_time_ms: summary.execution_block_time_ms(),
            application_hash: summary.application_hash().clone(),
            execution_header_hash: *summary.execution_header_hash(),
            committing_height: summary.committing_height(),
            committing_header_hash: *summary.committing_header_hash(),
        }
    }

    /// Returns the exact Ledger chain.
    pub const fn ledger_chain_id(&self) -> &LedgerChainIdV2 {
        &self.ledger_chain_id
    }

    /// Returns the verified application version.
    pub const fn application_version(&self) -> u64 {
        self.application_version
    }

    /// Returns the historical source-roster version.
    pub const fn source_config_version(&self) -> u64 {
        self.source_config_version
    }

    /// Returns the execution height.
    pub const fn execution_height(&self) -> u64 {
        self.execution_height
    }

    /// Returns the consensus execution time in milliseconds.
    pub const fn execution_block_time_ms(&self) -> u64 {
        self.execution_block_time_ms
    }

    /// Returns the finalized application hash.
    pub const fn application_hash(&self) -> &AppHashV2 {
        &self.application_hash
    }

    /// Returns the verified execution-header hash.
    pub const fn execution_header_hash(&self) -> &[u8; 32] {
        &self.execution_header_hash
    }

    /// Returns the adjacent committing-header height.
    pub const fn committing_height(&self) -> u64 {
        self.committing_height
    }

    /// Returns the verified committing-header hash.
    pub const fn committing_header_hash(&self) -> &[u8; 32] {
        &self.committing_header_hash
    }
}

impl fmt::Debug for FinalizedExecutionSummaryV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FinalizedExecutionSummaryV2")
            .field("ledger_chain_id", &self.ledger_chain_id)
            .field("application_version", &self.application_version)
            .field("source_config_version", &self.source_config_version)
            .field("execution_height", &self.execution_height)
            .field("application_hash", &self.application_hash)
            .field("committing_height", &self.committing_height)
            .finish_non_exhaustive()
    }
}

/// Finalized exact first-location result.
#[derive(Clone, Debug)]
pub enum FinalizedFirstLocationV2 {
    /// The coordinator request index and finalized block agree on the first location.
    Found(Box<HolderFinalityCapabilityV2>),
    /// Every locally retained finalized block through the checkpoint was scanned.
    Absent(Box<FinalizedAbsenceCapabilityV2>),
}

/// Exact reconciliation outcome for a one-shot or ambiguous submission.
#[derive(Clone, Debug)]
pub enum ReconciledSubmissionV2 {
    /// The exact actor request is not present at the queried application height.
    Unknown,
    /// The exact request mapping and coordinator history are finalized.
    Finalized(Box<HolderFinalityCapabilityV2>),
}

fn copy_fixed<const N: usize>(bytes: &[u8], offset: usize) -> Result<[u8; N]> {
    let end = offset.checked_add(N).ok_or(ClientError::BindingMismatch)?;
    bytes
        .get(offset..end)
        .and_then(|slice| slice.try_into().ok())
        .ok_or(ClientError::BindingMismatch)
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64> {
    Ok(u64::from_be_bytes(copy_fixed::<8>(bytes, offset)?))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32> {
    Ok(u32::from_be_bytes(copy_fixed::<4>(bytes, offset)?))
}
