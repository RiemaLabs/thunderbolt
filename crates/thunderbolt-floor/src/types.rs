use sha2::{Digest, Sha256};
use thunderbolt_keystore::{Network, VaultCheckpoint, VaultIdentity, VaultRevision, VaultRole};

use crate::{FloorError, Result};

const READ_DOMAIN: &[u8] = b"bitcoin-thunderbolt/floor/read/v1";
const CAS_DOMAIN: &[u8] = b"bitcoin-thunderbolt/floor/cas/v1";
const DIGEST_DOMAIN: &[u8] = b"bitcoin-thunderbolt/floor/request-digest/v1";
const MAX_CHAIN_ID_BYTES: usize = 128;

/// Digest of one canonical floor Ledger request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FloorRequestDigest([u8; 32]);

impl FloorRequestDigest {
    /// Constructs a digest from canonical bytes.
    #[must_use]
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the canonical digest bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Bounded consensus chain identifier for the independent floor Ledger.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FloorLedgerChainId(Vec<u8>);

impl FloorLedgerChainId {
    /// Constructs a non-empty bounded chain identifier.
    pub fn new(bytes: Vec<u8>) -> Result<Self> {
        if bytes.is_empty() || bytes.len() > MAX_CHAIN_ID_BYTES {
            return Err(FloorError::InvalidChainId);
        }
        Ok(Self(bytes))
    }

    /// Returns the exact configured chain identifier bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Canonical finalized read request for one complete vault identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FloorReadRequest {
    chain_id: FloorLedgerChainId,
    identity: VaultIdentity,
    digest: FloorRequestDigest,
}

impl FloorReadRequest {
    /// Constructs and hashes a canonical identity-bound read request.
    #[must_use]
    pub fn new(chain_id: &FloorLedgerChainId, identity: VaultIdentity) -> Self {
        let canonical = canonical_read(chain_id, identity);
        Self {
            chain_id: chain_id.clone(),
            identity,
            digest: digest(&canonical),
        }
    }

    /// Returns the exact external consensus chain being read.
    #[must_use]
    pub const fn chain_id(&self) -> &FloorLedgerChainId {
        &self.chain_id
    }

    /// Returns the complete vault identity being read.
    #[must_use]
    pub const fn identity(&self) -> VaultIdentity {
        self.identity
    }

    /// Returns the canonical request digest.
    #[must_use]
    pub const fn digest(&self) -> FloorRequestDigest {
        self.digest
    }

    /// Returns the canonical Ledger application bytes.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        canonical_read(&self.chain_id, self.identity)
    }
}

/// Canonical atomic checkpoint compare-and-swap request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FloorCasRequest {
    chain_id: FloorLedgerChainId,
    identity: VaultIdentity,
    expected: Option<VaultCheckpoint>,
    next: VaultCheckpoint,
    digest: FloorRequestDigest,
}

impl FloorCasRequest {
    /// Constructs a canonical request after validating the exact-next transition.
    pub fn new(
        chain_id: &FloorLedgerChainId,
        identity: VaultIdentity,
        expected: Option<VaultCheckpoint>,
        next: VaultCheckpoint,
    ) -> Result<Self> {
        validate_transition(expected, next)?;
        let canonical = canonical_cas(chain_id, identity, expected, next);
        Ok(Self {
            chain_id: chain_id.clone(),
            identity,
            expected,
            next,
            digest: digest(&canonical),
        })
    }

    /// Returns the exact external consensus chain being updated.
    #[must_use]
    pub const fn chain_id(&self) -> &FloorLedgerChainId {
        &self.chain_id
    }

    /// Returns the complete vault identity being updated.
    #[must_use]
    pub const fn identity(&self) -> VaultIdentity {
        self.identity
    }

    /// Returns the exact expected prior checkpoint.
    #[must_use]
    pub const fn expected(&self) -> Option<VaultCheckpoint> {
        self.expected
    }

    /// Returns the exact candidate checkpoint.
    #[must_use]
    pub const fn next(&self) -> VaultCheckpoint {
        self.next
    }

    /// Returns the canonical request digest.
    #[must_use]
    pub const fn digest(&self) -> FloorRequestDigest {
        self.digest
    }

    /// Returns the canonical Ledger application bytes.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        canonical_cas(&self.chain_id, self.identity, self.expected, self.next)
    }
}

/// Consensus-finality anchor proven by the configured verifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FloorFinalityAnchor {
    chain_id: FloorLedgerChainId,
    execution_height: u64,
    execution_time_ms: u64,
    app_hash: [u8; 32],
    committing_header_hash: [u8; 32],
}

impl FloorFinalityAnchor {
    /// Constructs a non-zero finalized block anchor.
    pub fn new(
        chain_id: FloorLedgerChainId,
        execution_height: u64,
        execution_time_ms: u64,
        app_hash: [u8; 32],
        committing_header_hash: [u8; 32],
    ) -> Result<Self> {
        if execution_height == 0 || execution_time_ms == 0 || app_hash == [0; 32] || committing_header_hash == [0; 32] {
            return Err(FloorError::InvalidFinalityAnchor);
        }
        Ok(Self {
            chain_id,
            execution_height,
            execution_time_ms,
            app_hash,
            committing_header_hash,
        })
    }

    /// Returns the finalized consensus chain identifier.
    #[must_use]
    pub const fn chain_id(&self) -> &FloorLedgerChainId {
        &self.chain_id
    }

    /// Returns the positive finalized application-execution height.
    #[must_use]
    pub const fn execution_height(&self) -> u64 {
        self.execution_height
    }

    /// Returns the positive consensus execution time in Unix milliseconds.
    #[must_use]
    pub const fn execution_time_ms(&self) -> u64 {
        self.execution_time_ms
    }

    /// Returns the finalized floor application hash committed at execution.
    #[must_use]
    pub const fn app_hash(&self) -> &[u8; 32] {
        &self.app_hash
    }

    /// Returns the adjacent committing-header hash that finalizes the app hash.
    #[must_use]
    pub const fn committing_header_hash(&self) -> &[u8; 32] {
        &self.committing_header_hash
    }
}

/// Operation result proven by a quorum/light-client finality verifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FinalizedFloorResult {
    /// Finalized current checkpoint returned by a read.
    Read {
        /// Current checkpoint, or `None` before initialization.
        current: Option<VaultCheckpoint>,
    },
    /// Finalized result of an atomic compare-and-swap application.
    CompareAndSwap {
        /// Finalized checkpoint after execution.
        current: Option<VaultCheckpoint>,
        /// Whether this exact request performed the state transition.
        applied: bool,
    },
}

/// Consensus-final response produced only through `LedgerFinalityVerifier`.
///
/// Implementations of that trusted verifier construct this value only after
/// checking validator quorum or a trusted light-client header chain, canonical
/// application inclusion, and the floor state-machine result. The adapter still
/// rechecks every public field against its request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FinalizedFloorResponse {
    request_digest: FloorRequestDigest,
    identity: VaultIdentity,
    result: FinalizedFloorResult,
    finality: FloorFinalityAnchor,
}

impl FinalizedFloorResponse {
    pub(crate) fn new(
        request_digest: FloorRequestDigest,
        identity: VaultIdentity,
        result: FinalizedFloorResult,
        finality: FloorFinalityAnchor,
    ) -> Self {
        Self {
            request_digest,
            identity,
            result,
            finality,
        }
    }

    /// Returns the exact finalized request digest.
    #[must_use]
    pub const fn request_digest(&self) -> FloorRequestDigest {
        self.request_digest
    }

    /// Returns the complete finalized vault identity.
    #[must_use]
    pub const fn identity(&self) -> VaultIdentity {
        self.identity
    }

    /// Returns the finalized application result.
    #[must_use]
    pub const fn result(&self) -> FinalizedFloorResult {
        self.result
    }

    /// Returns the verified consensus-finality anchor.
    #[must_use]
    pub const fn finality(&self) -> &FloorFinalityAnchor {
        &self.finality
    }
}

fn validate_transition(expected: Option<VaultCheckpoint>, next: VaultCheckpoint) -> Result<()> {
    match expected {
        None if next.revision() == VaultRevision::new(0) => Ok(()),
        Some(previous)
            if previous
                .revision()
                .get()
                .checked_add(1)
                .is_some_and(|revision| next.revision() == VaultRevision::new(revision))
                && previous.state_digest() != next.state_digest() =>
        {
            Ok(())
        }
        _ => Err(FloorError::InvalidTransition),
    }
}

fn canonical_read(chain_id: &FloorLedgerChainId, identity: VaultIdentity) -> Vec<u8> {
    let mut output = Vec::with_capacity(160);
    append_item(&mut output, READ_DOMAIN);
    append_item(&mut output, chain_id.as_bytes());
    append_identity(&mut output, identity);
    output
}

fn canonical_cas(
    chain_id: &FloorLedgerChainId,
    identity: VaultIdentity,
    expected: Option<VaultCheckpoint>,
    next: VaultCheckpoint,
) -> Vec<u8> {
    let mut output = Vec::with_capacity(256);
    append_item(&mut output, CAS_DOMAIN);
    append_item(&mut output, chain_id.as_bytes());
    append_identity(&mut output, identity);
    append_optional_checkpoint(&mut output, expected);
    append_checkpoint(&mut output, next);
    output
}

fn append_identity(output: &mut Vec<u8>, identity: VaultIdentity) {
    output.push(network_tag(identity.network()));
    output.push(role_tag(identity.role()));
    output.extend_from_slice(identity.node_id().as_bytes());
    output.extend_from_slice(identity.deployment().deployment_id().as_bytes());
    output.extend_from_slice(&identity.deployment().committee_epoch().to_be_bytes());
    output.extend_from_slice(identity.deployment().committee_descriptor().as_bytes());
}

fn append_optional_checkpoint(output: &mut Vec<u8>, checkpoint: Option<VaultCheckpoint>) {
    match checkpoint {
        Some(checkpoint) => {
            output.push(1);
            append_checkpoint(output, checkpoint);
        }
        None => output.push(0),
    }
}

fn append_checkpoint(output: &mut Vec<u8>, checkpoint: VaultCheckpoint) {
    output.extend_from_slice(&checkpoint.revision().get().to_be_bytes());
    output.extend_from_slice(checkpoint.state_digest().as_bytes());
}

fn append_item(output: &mut Vec<u8>, bytes: &[u8]) {
    output.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
    output.extend_from_slice(bytes);
}

fn digest(canonical: &[u8]) -> FloorRequestDigest {
    let mut hasher = Sha256::new();
    hasher.update(DIGEST_DOMAIN);
    hasher.update((canonical.len() as u64).to_be_bytes());
    hasher.update(canonical);
    FloorRequestDigest::new(hasher.finalize().into())
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
