use std::collections::{BTreeMap, BTreeSet};

use secp256k1::{schnorr::Signature, Secp256k1, XOnlyPublicKey};
use sha2::{Digest, Sha256};
use thunderbolt_floor::{FloorCasRequest, FloorLedgerChainId, VaultCheckpoint, VaultIdentity};
use thunderbolt_keystore::{Network, VaultRole};

use crate::{FloorApplicationError, Result};

const IDENTITY_DOMAIN: &[u8] = b"bitcoin-thunderbolt/floor-app/identity/v2";
const REGISTRY_DOMAIN: &[u8] = b"bitcoin-thunderbolt/floor-app/registry/v2";
const GENESIS_DOMAIN: &[u8] = b"bitcoin-thunderbolt/floor-app/genesis/v2";
const AUTHORIZATION_DOMAIN: &[u8] = b"bitcoin-thunderbolt/floor-app/cas-authorization/v2";
const BLOCK_DOMAIN: &[u8] = b"bitcoin-thunderbolt/floor-app/block-input/v2";
const RESULT_DOMAIN: &[u8] = b"bitcoin-thunderbolt/floor-app/result/v2";
/// Maximum immutable operator registry entries.
pub const MAX_REGISTRY_ENTRIES: usize = 4_096;
/// Maximum signed CAS requests in one consensus block.
pub const MAX_BLOCK_REQUESTS: usize = 1_024;
/// Exact actor request nonce width.
pub const ACTOR_REQUEST_NONCE_BYTES: usize = 32;

macro_rules! digest_type {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
        pub struct $name([u8; 32]);

        impl $name {
            /// Constructs a digest from canonical bytes.
            #[must_use]
            pub const fn new(bytes: [u8; 32]) -> Self { Self(bytes) }
            /// Returns canonical digest bytes.
            #[must_use]
            pub const fn as_bytes(&self) -> &[u8; 32] { &self.0 }
        }
    };
}

digest_type!(
    /// Digest of one complete vault identity.
    VaultIdentityDigest
);
digest_type!(
    /// Actor-scoped signed request digest.
    ActorRequestDigest
);
digest_type!(
    /// Immutable authorization registry digest.
    RegistryDigest
);
digest_type!(
    /// Consensus-bound genesis/profile digest.
    GenesisDigest
);
digest_type!(
    /// Deterministic floor block input digest.
    FloorBlockDigest
);
digest_type!(
    /// Deterministic executed result digest.
    FloorResultDigest
);
digest_type!(
    /// Deterministic application hash.
    FloorAppHash
);
digest_type!(
    /// Merkle root over registry-ordered floor state.
    FloorStateRoot
);
digest_type!(
    /// Merkle root over ordered block results.
    FloorResultRoot
);

/// Validated x-only BIP340 operator public key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct FloorOperatorKey([u8; 32]);

impl FloorOperatorKey {
    /// Validates an x-only secp256k1 public key.
    pub fn new(bytes: [u8; 32]) -> Result<Self> {
        XOnlyPublicKey::from_byte_array(bytes).map_err(|_| FloorApplicationError::InvalidInput("operator key"))?;
        Ok(Self(bytes))
    }

    /// Returns canonical key bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    fn x_only(self) -> Result<XOnlyPublicKey> {
        XOnlyPublicKey::from_byte_array(self.0).map_err(|_| FloorApplicationError::InvalidInput("operator key"))
    }
}

/// Nonzero actor-scoped request nonce.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct ActorRequestNonce([u8; ACTOR_REQUEST_NONCE_BYTES]);

impl ActorRequestNonce {
    /// Constructs a nonzero fixed-width nonce.
    pub fn new(bytes: [u8; ACTOR_REQUEST_NONCE_BYTES]) -> Result<Self> {
        if bytes == [0; ACTOR_REQUEST_NONCE_BYTES] {
            return Err(FloorApplicationError::InvalidInput("request nonce is zero"));
        }
        Ok(Self(bytes))
    }

    /// Returns exact nonce bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; ACTOR_REQUEST_NONCE_BYTES] {
        &self.0
    }
}

/// One immutable genesis authorization mapping.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistryEntry {
    identity: VaultIdentity,
    identity_digest: VaultIdentityDigest,
    operator_key: FloorOperatorKey,
}

impl RegistryEntry {
    /// Binds one complete vault identity to one BIP340 operator key.
    pub fn new(identity: VaultIdentity, operator_key: FloorOperatorKey) -> Result<Self> {
        if identity.network() == Network::Mainnet {
            return Err(FloorApplicationError::MainnetDisabled);
        }
        Ok(Self {
            identity,
            identity_digest: digest_identity(identity),
            operator_key,
        })
    }

    /// Returns the complete registered vault identity.
    #[must_use]
    pub const fn identity(&self) -> VaultIdentity {
        self.identity
    }

    /// Returns the canonical identity digest.
    #[must_use]
    pub const fn identity_digest(&self) -> VaultIdentityDigest {
        self.identity_digest
    }

    /// Returns the exact authorized operator key.
    #[must_use]
    pub const fn operator_key(&self) -> FloorOperatorKey {
        self.operator_key
    }
}

/// Static consensus genesis for the independent floor state machine.
#[derive(Debug, Clone)]
pub struct FloorGenesis {
    chain_id: FloorLedgerChainId,
    profile_digest: [u8; 32],
    registry_digest: RegistryDigest,
    genesis_digest: GenesisDigest,
    entries: Vec<RegistryEntry>,
    by_identity: BTreeMap<VaultIdentityDigest, usize>,
}

impl FloorGenesis {
    /// Validates and hashes an immutable sorted authorization registry.
    pub fn new(chain_id: FloorLedgerChainId, profile_digest: [u8; 32], entries: Vec<RegistryEntry>) -> Result<Self> {
        if profile_digest == [0; 32] || entries.is_empty() || entries.len() > MAX_REGISTRY_ENTRIES {
            return Err(FloorApplicationError::InvalidInput("genesis bounds"));
        }
        let mut entries = entries;
        entries.sort_by_key(RegistryEntry::identity_digest);
        let mut seen = BTreeSet::new();
        let mut by_identity = BTreeMap::new();
        for (index, entry) in entries.iter().enumerate() {
            if entry.identity.deployment().committee_epoch() > i64::MAX as u64 {
                return Err(FloorApplicationError::InvalidInput(
                    "committee epoch exceeds storage range",
                ));
            }
            if !seen.insert(entry.identity_digest) {
                return Err(FloorApplicationError::InvalidInput("duplicate registry identity"));
            }
            by_identity.insert(entry.identity_digest, index);
        }
        let registry_digest = hash_registry(&entries);
        let genesis_digest = hash_genesis(&chain_id, profile_digest, registry_digest);
        Ok(Self {
            chain_id,
            profile_digest,
            registry_digest,
            genesis_digest,
            entries,
            by_identity,
        })
    }

    /// Returns the consensus floor chain ID.
    #[must_use]
    pub const fn chain_id(&self) -> &FloorLedgerChainId {
        &self.chain_id
    }

    /// Returns the consensus profile digest.
    #[must_use]
    pub const fn profile_digest(&self) -> &[u8; 32] {
        &self.profile_digest
    }

    /// Returns the static registry digest.
    #[must_use]
    pub const fn registry_digest(&self) -> RegistryDigest {
        self.registry_digest
    }

    /// Returns the complete consensus genesis digest.
    #[must_use]
    pub const fn genesis_digest(&self) -> GenesisDigest {
        self.genesis_digest
    }

    /// Returns registry entries in canonical identity-digest order.
    #[must_use]
    pub fn entries(&self) -> &[RegistryEntry] {
        &self.entries
    }

    /// Finds the immutable registry entry for an identity digest.
    #[must_use]
    pub fn entry(&self, identity_digest: VaultIdentityDigest) -> Option<&RegistryEntry> {
        self.by_identity
            .get(&identity_digest)
            .map(|index| &self.entries[*index])
    }
}

/// Canonical unsigned actor authorization for one floor CAS.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FloorCasAuthorization {
    cas: FloorCasRequest,
    actor_key: FloorOperatorKey,
    nonce: ActorRequestNonce,
    target_height: u64,
    expected_previous_app_hash: FloorAppHash,
    request_digest: ActorRequestDigest,
}

impl FloorCasAuthorization {
    /// Binds CAS bytes, actor key, and nonzero actor nonce.
    pub fn new(
        cas: FloorCasRequest,
        actor_key: FloorOperatorKey,
        nonce: ActorRequestNonce,
        target_height: u64,
        expected_previous_app_hash: FloorAppHash,
    ) -> Result<Self> {
        if target_height == 0 || target_height > i64::MAX as u64 {
            return Err(FloorApplicationError::InvalidInput("authorization target height"));
        }
        let request_digest = hash_authorization(&cas, actor_key, nonce, target_height, expected_previous_app_hash);
        if request_digest.as_bytes() == &[0; 32] {
            return Err(FloorApplicationError::InvalidInput("zero request digest"));
        }
        Ok(Self {
            cas,
            actor_key,
            nonce,
            target_height,
            expected_previous_app_hash,
            request_digest,
        })
    }

    /// Returns the exact floor CAS.
    #[must_use]
    pub const fn cas(&self) -> &FloorCasRequest {
        &self.cas
    }

    /// Returns the signing actor key.
    #[must_use]
    pub const fn actor_key(&self) -> FloorOperatorKey {
        self.actor_key
    }

    /// Returns the actor-scoped nonce.
    #[must_use]
    pub const fn nonce(&self) -> ActorRequestNonce {
        self.nonce
    }

    /// Returns the one consensus height at which this request may execute.
    #[must_use]
    pub const fn target_height(&self) -> u64 {
        self.target_height
    }

    /// Returns the exact prior application hash required for execution.
    #[must_use]
    pub const fn expected_previous_app_hash(&self) -> FloorAppHash {
        self.expected_previous_app_hash
    }

    /// Returns the exact BIP340 signing digest.
    #[must_use]
    pub const fn request_digest(&self) -> ActorRequestDigest {
        self.request_digest
    }

    /// Verifies and attaches a BIP340 signature.
    pub fn authorize(self, signature: [u8; 64]) -> Result<SignedFloorCasRequest> {
        let signed = SignedFloorCasRequest {
            authorization: self,
            signature,
        };
        signed.verify()?;
        Ok(signed)
    }

    /// Returns canonical unsigned signing bytes.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        canonical_authorization(
            &self.cas,
            self.actor_key,
            self.nonce,
            self.target_height,
            self.expected_previous_app_hash,
        )
    }
}

/// BIP340-authenticated floor CAS request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedFloorCasRequest {
    authorization: FloorCasAuthorization,
    signature: [u8; 64],
}

impl SignedFloorCasRequest {
    /// Re-verifies the exact BIP340 signature.
    pub fn verify(&self) -> Result<()> {
        let signature = Signature::from_byte_array(self.signature);
        Secp256k1::verification_only()
            .verify_schnorr(
                &signature,
                self.authorization.request_digest.as_bytes(),
                &self.authorization.actor_key.x_only()?,
            )
            .map_err(|_| FloorApplicationError::InvalidSignature)
    }

    /// Returns the unsigned authorization.
    #[must_use]
    pub const fn authorization(&self) -> &FloorCasAuthorization {
        &self.authorization
    }

    /// Returns canonical signature bytes.
    #[must_use]
    pub const fn signature(&self) -> &[u8; 64] {
        &self.signature
    }

    /// Returns canonical signed bytes for deterministic block hashing.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        self.verify()?;
        let mut output = self.authorization.canonical_bytes();
        append_item(&mut output, b"signature", &self.signature);
        Ok(output)
    }
}

/// Ordered consensus block input.
#[derive(Debug, Clone)]
pub struct FloorBlockInput {
    chain_id: FloorLedgerChainId,
    height: u64,
    block_time_ms: u64,
    previous_app_hash: FloorAppHash,
    requests: Vec<SignedFloorCasRequest>,
    block_digest: FloorBlockDigest,
}

impl FloorBlockInput {
    /// Validates consensus metadata and bounded signed request order.
    pub fn new(
        chain_id: FloorLedgerChainId,
        height: u64,
        block_time_ms: u64,
        previous_app_hash: FloorAppHash,
        requests: Vec<SignedFloorCasRequest>,
    ) -> Result<Self> {
        if height == 0
            || block_time_ms == 0
            || height > i64::MAX as u64
            || block_time_ms > i64::MAX as u64
            || requests.len() > MAX_BLOCK_REQUESTS
        {
            return Err(FloorApplicationError::InvalidInput("block bounds"));
        }
        for request in &requests {
            request.verify()?;
            if request.authorization.cas.chain_id() != &chain_id {
                return Err(FloorApplicationError::InvalidInput("request chain mismatch"));
            }
            if request.authorization.target_height != height
                || request.authorization.expected_previous_app_hash != previous_app_hash
            {
                return Err(FloorApplicationError::InvalidInput("request head mismatch"));
            }
            let cas = request.authorization.cas();
            if cas.next().revision().get() > i64::MAX as u64
                || cas
                    .expected()
                    .is_some_and(|checkpoint| checkpoint.revision().get() > i64::MAX as u64)
            {
                return Err(FloorApplicationError::InvalidInput(
                    "checkpoint revision exceeds storage range",
                ));
            }
        }
        let mut identities = BTreeSet::new();
        if requests
            .iter()
            .any(|request| !identities.insert(digest_identity(request.authorization.cas.identity())))
        {
            return Err(FloorApplicationError::InvalidInput("duplicate identity in block"));
        }
        let block_digest = hash_block_input(&chain_id, height, block_time_ms, previous_app_hash, &requests)?;
        Ok(Self {
            chain_id,
            height,
            block_time_ms,
            previous_app_hash,
            requests,
            block_digest,
        })
    }

    /// Returns the consensus chain ID.
    #[must_use]
    pub const fn chain_id(&self) -> &FloorLedgerChainId {
        &self.chain_id
    }
    /// Returns the positive consensus height.
    #[must_use]
    pub const fn height(&self) -> u64 {
        self.height
    }
    /// Returns consensus time in Unix milliseconds.
    #[must_use]
    pub const fn block_time_ms(&self) -> u64 {
        self.block_time_ms
    }
    /// Returns the exact prior app hash.
    #[must_use]
    pub const fn previous_app_hash(&self) -> FloorAppHash {
        self.previous_app_hash
    }
    /// Returns requests in consensus order.
    #[must_use]
    pub fn requests(&self) -> &[SignedFloorCasRequest] {
        &self.requests
    }
    /// Returns the deterministic complete input digest.
    #[must_use]
    pub const fn block_digest(&self) -> FloorBlockDigest {
        self.block_digest
    }
}

/// Finalized deterministic CAS disposition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FloorCasDisposition {
    /// Expected matched and next was installed.
    Applied,
    /// Next was already current.
    AlreadyCurrent,
    /// Current matched neither expected nor next.
    Conflict,
}

/// Deterministic result for one ordered signed request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutedFloorResult {
    identity_digest: VaultIdentityDigest,
    actor_key: FloorOperatorKey,
    nonce: ActorRequestNonce,
    request_digest: ActorRequestDigest,
    expected: Option<VaultCheckpoint>,
    next: VaultCheckpoint,
    current: Option<VaultCheckpoint>,
    disposition: FloorCasDisposition,
    result_digest: FloorResultDigest,
}

pub(crate) struct ExecutedFloorResultInput {
    pub identity_digest: VaultIdentityDigest,
    pub actor_key: FloorOperatorKey,
    pub nonce: ActorRequestNonce,
    pub request_digest: ActorRequestDigest,
    pub expected: Option<VaultCheckpoint>,
    pub next: VaultCheckpoint,
    pub current: Option<VaultCheckpoint>,
    pub disposition: FloorCasDisposition,
}

impl ExecutedFloorResult {
    pub(crate) fn new(input: ExecutedFloorResultInput) -> Self {
        let mut result = Self {
            identity_digest: input.identity_digest,
            actor_key: input.actor_key,
            nonce: input.nonce,
            request_digest: input.request_digest,
            expected: input.expected,
            next: input.next,
            current: input.current,
            disposition: input.disposition,
            result_digest: FloorResultDigest::new([0; 32]),
        };
        result.result_digest = FloorResultDigest::new(hash(&canonical_result(&result)));
        result
    }

    /// Returns the vault identity digest.
    pub const fn identity_digest(&self) -> VaultIdentityDigest {
        self.identity_digest
    }
    /// Returns the authenticated actor key.
    pub const fn actor_key(&self) -> FloorOperatorKey {
        self.actor_key
    }
    /// Returns the actor request nonce.
    pub const fn nonce(&self) -> ActorRequestNonce {
        self.nonce
    }
    /// Returns the actor request digest.
    pub const fn request_digest(&self) -> ActorRequestDigest {
        self.request_digest
    }
    /// Returns the exact expected checkpoint.
    pub const fn expected(&self) -> Option<VaultCheckpoint> {
        self.expected
    }
    /// Returns the exact requested next checkpoint.
    pub const fn next(&self) -> VaultCheckpoint {
        self.next
    }
    /// Returns current state after execution.
    pub const fn current(&self) -> Option<VaultCheckpoint> {
        self.current
    }
    /// Returns deterministic CAS disposition.
    pub const fn disposition(&self) -> FloorCasDisposition {
        self.disposition
    }
    /// Returns deterministic result digest.
    pub const fn result_digest(&self) -> FloorResultDigest {
        self.result_digest
    }
    /// Returns canonical result bytes.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        canonical_result(self)
    }
}

/// Deterministic executed floor block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutedFloorBlock {
    chain_id: FloorLedgerChainId,
    genesis_digest: GenesisDigest,
    height: u64,
    block_time_ms: u64,
    previous_app_hash: FloorAppHash,
    block_digest: FloorBlockDigest,
    result_root: FloorResultRoot,
    state_root: FloorStateRoot,
    app_hash: FloorAppHash,
    results: Vec<ExecutedFloorResult>,
}

pub(crate) struct StoredFloorBlock {
    pub chain_id: FloorLedgerChainId,
    pub genesis_digest: GenesisDigest,
    pub height: u64,
    pub block_time_ms: u64,
    pub previous_app_hash: FloorAppHash,
    pub block_digest: FloorBlockDigest,
    pub result_root: FloorResultRoot,
    pub state_root: FloorStateRoot,
    pub app_hash: FloorAppHash,
    pub results: Vec<ExecutedFloorResult>,
}

impl ExecutedFloorBlock {
    pub(crate) fn new(
        input: &FloorBlockInput,
        genesis_digest: GenesisDigest,
        result_root: FloorResultRoot,
        state_root: FloorStateRoot,
        results: Vec<ExecutedFloorResult>,
    ) -> Self {
        let app_hash = compute_app_hash(input, genesis_digest, result_root, state_root, results.len());
        Self {
            chain_id: input.chain_id.clone(),
            genesis_digest,
            height: input.height,
            block_time_ms: input.block_time_ms,
            previous_app_hash: input.previous_app_hash,
            block_digest: input.block_digest,
            result_root,
            state_root,
            app_hash,
            results,
        }
    }

    pub(crate) fn from_stored(stored: StoredFloorBlock) -> Self {
        Self {
            chain_id: stored.chain_id,
            genesis_digest: stored.genesis_digest,
            height: stored.height,
            block_time_ms: stored.block_time_ms,
            previous_app_hash: stored.previous_app_hash,
            block_digest: stored.block_digest,
            result_root: stored.result_root,
            state_root: stored.state_root,
            app_hash: stored.app_hash,
            results: stored.results,
        }
    }

    /// Returns the consensus chain ID.
    pub const fn chain_id(&self) -> &FloorLedgerChainId {
        &self.chain_id
    }
    /// Returns the consensus genesis digest.
    pub const fn genesis_digest(&self) -> GenesisDigest {
        self.genesis_digest
    }
    /// Returns consensus height.
    pub const fn height(&self) -> u64 {
        self.height
    }
    /// Returns consensus block time.
    pub const fn block_time_ms(&self) -> u64 {
        self.block_time_ms
    }
    /// Returns prior app hash.
    pub const fn previous_app_hash(&self) -> FloorAppHash {
        self.previous_app_hash
    }
    /// Returns complete block-input digest.
    pub const fn block_digest(&self) -> FloorBlockDigest {
        self.block_digest
    }
    /// Returns ordered result Merkle root.
    pub const fn result_root(&self) -> FloorResultRoot {
        self.result_root
    }
    /// Returns registry-ordered state root.
    pub const fn state_root(&self) -> FloorStateRoot {
        self.state_root
    }
    /// Returns deterministic application hash.
    pub const fn app_hash(&self) -> FloorAppHash {
        self.app_hash
    }
    /// Returns ordered executed results.
    pub fn results(&self) -> &[ExecutedFloorResult] {
        &self.results
    }
    pub(crate) fn recompute_app_hash(&self) -> FloorAppHash {
        compute_app_hash_fields(AppHashFields {
            chain_id: &self.chain_id,
            genesis: self.genesis_digest,
            previous_app_hash: self.previous_app_hash,
            block_digest: self.block_digest,
            height: self.height,
            block_time_ms: self.block_time_ms,
            result_root: self.result_root,
            state_root: self.state_root,
            result_count: self.results.len(),
        })
    }
}

/// Opaque rollback-only preview used for deterministic commit.
#[derive(Debug, Clone)]
pub struct PreparedFloorBlock {
    pub(crate) input: FloorBlockInput,
    pub(crate) block: ExecutedFloorBlock,
}

impl PreparedFloorBlock {
    /// Returns previewed consensus input.
    pub const fn input(&self) -> &FloorBlockInput {
        &self.input
    }
    /// Returns previewed deterministic output.
    pub const fn block(&self) -> &ExecutedFloorBlock {
        &self.block
    }
}

/// Result of a committed block or exact committed-block replay.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FloorBlockExecutionOutcome {
    block: ExecutedFloorBlock,
    replayed_block: bool,
}

impl FloorBlockExecutionOutcome {
    pub(crate) const fn new(block: ExecutedFloorBlock, replayed_block: bool) -> Self {
        Self { block, replayed_block }
    }
    /// Returns deterministic executed block.
    pub const fn block(&self) -> &ExecutedFloorBlock {
        &self.block
    }
    /// Reports exact replay of the committed height.
    pub const fn replayed_block(&self) -> bool {
        self.replayed_block
    }
}

/// Current durable floor application head.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FloorApplicationStatus {
    /// Last committed height.
    pub last_height: u64,
    /// Last consensus block time.
    pub last_block_time_ms: u64,
    /// Last deterministic app hash.
    pub last_app_hash: FloorAppHash,
    /// Static consensus genesis digest.
    pub genesis_digest: GenesisDigest,
}

pub(crate) fn digest_identity(identity: VaultIdentity) -> VaultIdentityDigest {
    let mut bytes = Vec::with_capacity(112);
    append_item(&mut bytes, b"domain", IDENTITY_DOMAIN);
    bytes.push(network_tag(identity.network()));
    bytes.push(role_tag(identity.role()));
    bytes.extend_from_slice(identity.node_id().as_bytes());
    bytes.extend_from_slice(identity.deployment().deployment_id().as_bytes());
    bytes.extend_from_slice(&identity.deployment().committee_epoch().to_be_bytes());
    bytes.extend_from_slice(identity.deployment().committee_descriptor().as_bytes());
    VaultIdentityDigest::new(hash(&bytes))
}

fn hash_registry(entries: &[RegistryEntry]) -> RegistryDigest {
    let mut bytes = Vec::with_capacity(entries.len() * 64 + 64);
    append_item(&mut bytes, b"domain", REGISTRY_DOMAIN);
    bytes.extend_from_slice(&(entries.len() as u64).to_be_bytes());
    for entry in entries {
        bytes.extend_from_slice(entry.identity_digest.as_bytes());
        bytes.extend_from_slice(entry.operator_key.as_bytes());
    }
    RegistryDigest::new(hash(&bytes))
}

fn hash_genesis(chain_id: &FloorLedgerChainId, profile: [u8; 32], registry: RegistryDigest) -> GenesisDigest {
    let mut bytes = Vec::with_capacity(128);
    append_item(&mut bytes, b"domain", GENESIS_DOMAIN);
    bytes.extend_from_slice(&crate::FLOOR_APPLICATION_VERSION_V2.to_be_bytes());
    append_item(&mut bytes, b"chain_id", chain_id.as_bytes());
    bytes.extend_from_slice(&profile);
    bytes.extend_from_slice(registry.as_bytes());
    GenesisDigest::new(hash(&bytes))
}

fn canonical_authorization(
    cas: &FloorCasRequest,
    actor_key: FloorOperatorKey,
    nonce: ActorRequestNonce,
    target_height: u64,
    expected_previous_app_hash: FloorAppHash,
) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(cas.canonical_bytes().len() + 128);
    append_item(&mut bytes, b"domain", AUTHORIZATION_DOMAIN);
    append_item(&mut bytes, b"floor_cas", &cas.canonical_bytes());
    append_item(&mut bytes, b"actor_key", actor_key.as_bytes());
    append_item(&mut bytes, b"request_nonce", nonce.as_bytes());
    append_item(&mut bytes, b"target_height", &target_height.to_be_bytes());
    append_item(
        &mut bytes,
        b"expected_previous_app_hash",
        expected_previous_app_hash.as_bytes(),
    );
    bytes
}

fn hash_authorization(
    cas: &FloorCasRequest,
    actor_key: FloorOperatorKey,
    nonce: ActorRequestNonce,
    target_height: u64,
    expected_previous_app_hash: FloorAppHash,
) -> ActorRequestDigest {
    ActorRequestDigest::new(hash(&canonical_authorization(
        cas,
        actor_key,
        nonce,
        target_height,
        expected_previous_app_hash,
    )))
}

fn hash_block_input(
    chain_id: &FloorLedgerChainId,
    height: u64,
    time: u64,
    previous: FloorAppHash,
    requests: &[SignedFloorCasRequest],
) -> Result<FloorBlockDigest> {
    let mut bytes = Vec::new();
    append_item(&mut bytes, b"domain", BLOCK_DOMAIN);
    append_item(&mut bytes, b"chain_id", chain_id.as_bytes());
    bytes.extend_from_slice(&height.to_be_bytes());
    bytes.extend_from_slice(&time.to_be_bytes());
    bytes.extend_from_slice(previous.as_bytes());
    bytes.extend_from_slice(&(requests.len() as u64).to_be_bytes());
    for request in requests {
        append_item(&mut bytes, b"request", &request.canonical_bytes()?);
    }
    Ok(FloorBlockDigest::new(hash(&bytes)))
}

fn canonical_result(result: &ExecutedFloorResult) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(256);
    append_item(&mut bytes, b"domain", RESULT_DOMAIN);
    bytes.extend_from_slice(result.identity_digest.as_bytes());
    bytes.extend_from_slice(result.actor_key.as_bytes());
    bytes.extend_from_slice(result.nonce.as_bytes());
    bytes.extend_from_slice(result.request_digest.as_bytes());
    append_optional_checkpoint(&mut bytes, result.expected);
    append_checkpoint(&mut bytes, result.next);
    append_optional_checkpoint(&mut bytes, result.current);
    bytes.push(match result.disposition {
        FloorCasDisposition::Applied => 1,
        FloorCasDisposition::AlreadyCurrent => 2,
        FloorCasDisposition::Conflict => 3,
    });
    bytes
}

fn compute_app_hash(
    input: &FloorBlockInput,
    genesis: GenesisDigest,
    result_root: FloorResultRoot,
    state_root: FloorStateRoot,
    result_count: usize,
) -> FloorAppHash {
    compute_app_hash_fields(AppHashFields {
        chain_id: &input.chain_id,
        genesis,
        previous_app_hash: input.previous_app_hash,
        block_digest: input.block_digest,
        height: input.height,
        block_time_ms: input.block_time_ms,
        result_root,
        state_root,
        result_count,
    })
}

struct AppHashFields<'a> {
    chain_id: &'a FloorLedgerChainId,
    genesis: GenesisDigest,
    previous_app_hash: FloorAppHash,
    block_digest: FloorBlockDigest,
    height: u64,
    block_time_ms: u64,
    result_root: FloorResultRoot,
    state_root: FloorStateRoot,
    result_count: usize,
}

fn compute_app_hash_fields(fields: AppHashFields<'_>) -> FloorAppHash {
    let mut bytes = Vec::with_capacity(256);
    append_item(&mut bytes, b"domain", b"bitcoin-thunderbolt/floor-app/app-hash/v2");
    append_item(&mut bytes, b"chain_id", fields.chain_id.as_bytes());
    bytes.extend_from_slice(fields.genesis.as_bytes());
    bytes.extend_from_slice(fields.previous_app_hash.as_bytes());
    bytes.extend_from_slice(fields.block_digest.as_bytes());
    bytes.extend_from_slice(&fields.height.to_be_bytes());
    bytes.extend_from_slice(&fields.block_time_ms.to_be_bytes());
    bytes.extend_from_slice(&(fields.result_count as u64).to_be_bytes());
    bytes.extend_from_slice(fields.result_root.as_bytes());
    bytes.extend_from_slice(fields.state_root.as_bytes());
    FloorAppHash::new(hash(&bytes))
}

pub(crate) fn append_optional_checkpoint(bytes: &mut Vec<u8>, checkpoint: Option<VaultCheckpoint>) {
    if let Some(checkpoint) = checkpoint {
        bytes.push(1);
        append_checkpoint(bytes, checkpoint);
    } else {
        bytes.push(0);
    }
}

pub(crate) fn append_checkpoint(bytes: &mut Vec<u8>, checkpoint: VaultCheckpoint) {
    bytes.extend_from_slice(&checkpoint.revision().get().to_be_bytes());
    bytes.extend_from_slice(checkpoint.state_digest().as_bytes());
}

fn append_item(bytes: &mut Vec<u8>, label: &[u8], value: &[u8]) {
    bytes.extend_from_slice(&(label.len() as u64).to_be_bytes());
    bytes.extend_from_slice(label);
    bytes.extend_from_slice(&(value.len() as u64).to_be_bytes());
    bytes.extend_from_slice(value);
}

pub(crate) fn hash(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

const fn network_tag(network: Network) -> u8 {
    match network {
        Network::Regtest => 1,
        Network::Signet => 2,
        Network::Testnet => 3,
        Network::Mainnet => 4,
    }
}

const fn role_tag(role: VaultRole) -> u8 {
    match role {
        VaultRole::Holder => 1,
        VaultRole::CommitteeMember => 2,
    }
}
