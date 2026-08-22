use std::collections::BTreeMap;
use std::fs::{self, File, Metadata, OpenOptions};
use std::io::ErrorKind;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::{Path, PathBuf};

#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};

use rusqlite::{params, Connection, OpenFlags, OptionalExtension, Transaction, TransactionBehavior};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tendermint::hash::Hash;
use tendermint::node::Id as NodeId;
use tendermint_light_client_verifier::types::LightBlock;
use thunderbolt_cometbft::{FinalityPolicy, PinnedTrustRoot, THUNDERBOLT_APP_VERSION_V2};
use thunderbolt_ledger::{AppHashV2, ExecutedBlockV2, LedgerChainIdV2, RequestDigestV2};

use crate::types::{
    validate_root, CoordinatorConfig, CoordinatorError, FinalityProofBundle, FinalitySummary, HistoricalFinality,
    HistoricalRequestFinality, HistorySealIntent, HistorySealOutcome, PeerIdentity, RotationOutcome,
    SourceConfiguration, TrustCheckpoint, MAX_HISTORY_EPOCH_TRANSITIONS,
};
use crate::Result;

const SCHEMA_VERSION: i64 = 1;
const SQLITE_APPLICATION_ID: i64 = 0x5442_4343;
const SOURCE_MAGIC: &[u8; 8] = b"TBSRC001";
const SUMMARY_MAGIC: &[u8; 8] = b"TBSUM001";
const ROOT_DOMAIN: &[u8] = b"bitcoin-thunderbolt/cometbft-client/root/v1";
const SOURCE_DOMAIN: &[u8] = b"bitcoin-thunderbolt/cometbft-client/sources/v1";
const EXECUTION_DOMAIN: &[u8] = b"bitcoin-thunderbolt/cometbft-client/execution/v1";
const PROOF_DOMAIN: &[u8] = b"bitcoin-thunderbolt/cometbft-client/proof/v1";
const CHECKPOINT_DOMAIN: &[u8] = b"bitcoin-thunderbolt/cometbft-client/checkpoint/v1";
const HISTORY_MANIFEST_DOMAIN: &[u8] = b"bitcoin-thunderbolt/cometbft-client/history-manifest/v1";
const REQUEST_INDEX_DOMAIN: &[u8] = b"bitcoin-thunderbolt/cometbft-client/request-index/v1";
const FINALITY_OPERATION_DOMAIN: &[u8] = b"bitcoin-thunderbolt/cometbft-client/finality-operation/v1";
const HISTORY_MANIFEST_MAGIC: &[u8; 8] = b"TBHMF001";
pub(crate) const OPERATION_BOOTSTRAP: i64 = 0;
pub(crate) const OPERATION_FINALITY: i64 = 1;
pub(crate) const OPERATION_ROTATION: i64 = 2;
pub(crate) const OPERATION_HISTORY_MANIFEST: i64 = 3;

const SCHEMA: &str = "
CREATE TABLE coordinator_meta (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    schema_version INTEGER NOT NULL,
    coordinator_identity BLOB NOT NULL CHECK (length(coordinator_identity) = 32),
    ledger_chain_id TEXT NOT NULL,
    policy BLOB NOT NULL,
    resource_limits BLOB NOT NULL,
    current_config_version INTEGER NOT NULL CHECK (current_config_version > 0),
    current_config_digest BLOB NOT NULL CHECK (length(current_config_digest) = 32),
    root_height INTEGER NOT NULL CHECK (root_height > 0),
    root_header_hash BLOB NOT NULL CHECK (length(root_header_hash) = 32),
    root_block_json BLOB NOT NULL,
    root_digest BLOB NOT NULL CHECK (length(root_digest) = 32),
    checkpoint_generation INTEGER NOT NULL CHECK (checkpoint_generation >= 0),
    checkpoint_digest BLOB NOT NULL CHECK (length(checkpoint_digest) = 32),
    latest_manifest_generation INTEGER,
    latest_manifest_digest BLOB,
    CHECK ((latest_manifest_generation IS NULL AND latest_manifest_digest IS NULL)
        OR (latest_manifest_generation > 0 AND length(latest_manifest_digest) = 32))
);
CREATE TABLE source_configurations (
    version INTEGER PRIMARY KEY CHECK (version > 0),
    config_blob BLOB NOT NULL,
    config_digest BLOB NOT NULL UNIQUE CHECK (length(config_digest) = 32),
    installed_generation INTEGER NOT NULL UNIQUE CHECK (installed_generation >= 0)
);
CREATE TABLE finality_updates (
    execution_height INTEGER PRIMARY KEY CHECK (execution_height > 0),
    execution_digest BLOB NOT NULL CHECK (length(execution_digest) = 32),
    config_version INTEGER NOT NULL REFERENCES source_configurations(version),
    prior_root_height INTEGER NOT NULL CHECK (prior_root_height > 0),
    prior_root_header_hash BLOB NOT NULL CHECK (length(prior_root_header_hash) = 32),
    prior_root_digest BLOB NOT NULL CHECK (length(prior_root_digest) = 32),
    proof_bundle_json BLOB NOT NULL,
    proof_byte_count INTEGER NOT NULL CHECK (proof_byte_count > 0),
    request_count INTEGER NOT NULL CHECK (request_count >= 0),
    summary_blob BLOB NOT NULL,
    proof_digest BLOB NOT NULL UNIQUE CHECK (length(proof_digest) = 32),
    next_root_height INTEGER NOT NULL UNIQUE CHECK (next_root_height > 0),
    next_root_header_hash BLOB NOT NULL CHECK (length(next_root_header_hash) = 32),
    next_root_block_json BLOB NOT NULL,
    next_root_digest BLOB NOT NULL UNIQUE CHECK (length(next_root_digest) = 32),
    checkpoint_generation INTEGER NOT NULL UNIQUE CHECK (checkpoint_generation > 0)
);
CREATE TABLE request_index (
    request_digest BLOB PRIMARY KEY CHECK (length(request_digest) = 32),
    execution_height INTEGER NOT NULL REFERENCES finality_updates(execution_height),
    block_index INTEGER NOT NULL CHECK (block_index >= 0),
    channel_context_id BLOB NOT NULL CHECK (length(channel_context_id) = 32),
    participant_id BLOB NOT NULL CHECK (length(participant_id) = 32),
    proposal_digest BLOB NOT NULL CHECK (length(proposal_digest) = 32),
    entry_hash BLOB NOT NULL CHECK (length(entry_hash) = 32)
);
CREATE INDEX request_index_height_idx ON request_index(execution_height, block_index);
CREATE TABLE checkpoint_transitions (
    generation INTEGER PRIMARY KEY CHECK (generation >= 0),
    expected_generation INTEGER,
    expected_digest BLOB,
    candidate_digest BLOB NOT NULL UNIQUE CHECK (length(candidate_digest) = 32),
    operation_kind INTEGER NOT NULL CHECK (operation_kind BETWEEN 0 AND 3),
    operation_digest BLOB NOT NULL CHECK (length(operation_digest) = 32),
    CHECK ((expected_generation IS NULL AND expected_digest IS NULL)
        OR (expected_generation >= 0 AND length(expected_digest) = 32))
);
CREATE TABLE history_epoch_manifests (
    manifest_generation INTEGER PRIMARY KEY REFERENCES checkpoint_transitions(generation),
    first_generation INTEGER NOT NULL CHECK (first_generation >= 0),
    last_generation INTEGER NOT NULL CHECK (last_generation >= first_generation),
    previous_manifest_digest BLOB,
    manifest_blob BLOB NOT NULL,
    manifest_digest BLOB NOT NULL UNIQUE CHECK (length(manifest_digest) = 32),
    root_digest BLOB NOT NULL CHECK (length(root_digest) = 32),
    config_digest BLOB NOT NULL CHECK (length(config_digest) = 32),
    CHECK (previous_manifest_digest IS NULL OR length(previous_manifest_digest) = 32)
);
CREATE TABLE history_manifest_requests (
    manifest_generation INTEGER NOT NULL REFERENCES history_epoch_manifests(manifest_generation),
    request_digest BLOB NOT NULL CHECK (length(request_digest) = 32),
    execution_height INTEGER NOT NULL CHECK (execution_height > 0),
    block_index INTEGER NOT NULL CHECK (block_index >= 0),
    channel_context_id BLOB NOT NULL CHECK (length(channel_context_id) = 32),
    participant_id BLOB NOT NULL CHECK (length(participant_id) = 32),
    proposal_digest BLOB NOT NULL CHECK (length(proposal_digest) = 32),
    entry_hash BLOB NOT NULL CHECK (length(entry_hash) = 32),
    PRIMARY KEY(manifest_generation, request_digest)
);
CREATE INDEX history_manifest_request_digest_idx
    ON history_manifest_requests(request_digest, manifest_generation);
";

#[cfg(test)]
thread_local! {
    static FAIL_BOOTSTRAP_AS_AMBIGUOUS_ROLLBACK: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

#[derive(Clone)]
pub(crate) struct StoredHead {
    pub root: PinnedTrustRoot,
    pub digest: [u8; 32],
    pub checkpoint: TrustCheckpoint,
    pub prior_checkpoint: Option<TrustCheckpoint>,
    pub operation_kind: i64,
    pub operation_digest: [u8; 32],
}

pub(crate) struct PreparedUpdate {
    pub bundle: FinalityProofBundle,
    pub summary: FinalitySummary,
    pub next_root: PinnedTrustRoot,
}

pub(crate) struct DurableStore {
    connection: Connection,
    current_checkpoint: TrustCheckpoint,
    current_root_digest: [u8; 32],
    current_config_digest: [u8; 32],
    latest_manifest: Option<(u64, [u8; 32])>,
    prepared_manifest: Option<HistoryManifestPlan>,
    _database_guard: File,
    _lock: File,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct FileIdentity {
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
    #[cfg(not(unix))]
    length: u64,
}

#[derive(Serialize)]
struct ProofBundleOutput<'a> {
    version: u8,
    config_version: u64,
    trusted_root: &'a LightBlock,
    primary_trace: &'a [LightBlock],
    witness_traces: &'a [Vec<LightBlock>],
    execution: &'a ExecutedBlockV2,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProofBundleInput {
    version: u8,
    config_version: u64,
    trusted_root: LightBlock,
    primary_trace: Vec<LightBlock>,
    witness_traces: Vec<Vec<LightBlock>>,
    execution: ExecutedBlockV2,
}

#[derive(Clone)]
struct StoredUpdateRow {
    execution_digest: Vec<u8>,
    config_version: i64,
    prior_root_height: i64,
    prior_root_header_hash: Vec<u8>,
    prior_root_digest: Vec<u8>,
    proof_bundle_json: Vec<u8>,
    proof_byte_count: i64,
    request_count: i64,
    summary_blob: Vec<u8>,
    proof_digest: Vec<u8>,
    next_root_height: i64,
    next_root_header_hash: Vec<u8>,
    next_root_block_json: Vec<u8>,
    next_root_digest: Vec<u8>,
    checkpoint_generation: i64,
}

struct MetadataRow {
    schema_version: i64,
    coordinator_identity: Vec<u8>,
    ledger_chain_id: String,
    policy: Vec<u8>,
    resource_limits: Vec<u8>,
    current_config_version: i64,
    current_config_digest: Vec<u8>,
    root_height: i64,
    root_header_hash: Vec<u8>,
    root_block_json: Vec<u8>,
    root_digest: Vec<u8>,
    checkpoint_generation: i64,
    checkpoint_digest: Vec<u8>,
    latest_manifest_generation: Option<i64>,
    latest_manifest_digest: Option<Vec<u8>>,
}

#[derive(Clone, PartialEq, Eq)]
struct RequestIndexLocation {
    execution_height: i64,
    block_index: i64,
    channel_context_id: Vec<u8>,
    participant_id: Vec<u8>,
    proposal_digest: Vec<u8>,
    entry_hash: Vec<u8>,
}

struct TransitionRow {
    expected_generation: Option<i64>,
    expected_digest: Option<Vec<u8>>,
    candidate_digest: Vec<u8>,
    operation_kind: i64,
    operation_digest: Vec<u8>,
}

#[derive(Clone, Copy)]
struct ManifestEntry {
    generation: u64,
    expected: Option<TrustCheckpoint>,
    candidate: TrustCheckpoint,
    operation_kind: i64,
    operation_digest: [u8; 32],
    request_index_digest: [u8; 32],
}

struct DecodedManifest {
    first_generation: u64,
    last_generation: u64,
    previous_digest: Option<[u8; 32]>,
    entries: Vec<ManifestEntry>,
}

struct LoadedManifest {
    decoded: DecodedManifest,
    root_digest: [u8; 32],
    config_digest: [u8; 32],
}

struct HistoryManifestPlan {
    intent: HistorySealIntent,
    previous_digest: Option<[u8; 32]>,
    manifest_blob: Vec<u8>,
    request_rows: Vec<ManifestRequestRow>,
}

struct ManifestRequestRow {
    request_digest: [u8; 32],
    location: RequestIndexLocation,
}

struct StoredManifestRow {
    first_generation: i64,
    last_generation: i64,
    previous_digest: Option<Vec<u8>>,
    manifest_blob: Vec<u8>,
    manifest_digest: Vec<u8>,
    root_digest: Vec<u8>,
    config_digest: Vec<u8>,
}

#[cfg(test)]
struct TamperProofRow {
    config_digest: Vec<u8>,
    prior_root: Vec<u8>,
    next_root: Vec<u8>,
    bundle: Vec<u8>,
    summary: Vec<u8>,
}

impl DurableStore {
    pub(crate) fn require_update_capacity(&self, config: &CoordinatorConfig, request_count: usize) -> Result<()> {
        ensure_unsealed_capacity(
            &self.connection,
            config,
            1,
            config.max_proof_bundle_bytes(),
            request_count,
        )
    }

    pub(crate) fn create(
        path: &Path,
        config: &CoordinatorConfig,
        root: &PinnedTrustRoot,
    ) -> Result<(Self, StoredHead)> {
        validate_root(root, config)?;
        let source_blob = encode_sources(config.sources())?;
        let source_digest = source_digest(&source_blob);
        let root_blob = encode_light_block(root.light_block(), config.max_trace_encoded_bytes())?;
        let root_digest = root_digest(config, root.height(), root.header_hash(), &root_blob);
        let source_version = to_i64(config.sources().version())?;
        let root_height = to_i64(root.height())?;
        let operation_digest = digest_parts(PROOF_DOMAIN, &[root_digest.as_slice(), source_digest.as_slice()]);
        let checkpoint = checkpoint_digest(
            config,
            0,
            None,
            OPERATION_BOOTSTRAP,
            &operation_digest,
            &root_digest,
            &source_digest,
        );
        let (connection, database_guard, lock) = open_connection(path, config, true)?;
        validate_pristine_database(&connection)?;
        configure_connection(&connection, config)?;
        let transaction = connection.unchecked_transaction()?;
        transaction.execute_batch(SCHEMA)?;
        transaction.pragma_update(None, "application_id", SQLITE_APPLICATION_ID)?;
        transaction.pragma_update(None, "user_version", SCHEMA_VERSION)?;
        transaction.execute(
            "INSERT INTO source_configurations(version, config_blob, config_digest, installed_generation)
             VALUES(?1, ?2, ?3, 0)",
            params![source_version, source_blob, source_digest.as_slice()],
        )?;
        transaction.execute(
            "INSERT INTO checkpoint_transitions(generation, expected_generation, expected_digest,
                                                candidate_digest, operation_kind, operation_digest)
             VALUES(0, NULL, NULL, ?1, ?2, ?3)",
            params![
                checkpoint.state_digest().as_slice(),
                OPERATION_BOOTSTRAP,
                operation_digest.as_slice()
            ],
        )?;
        transaction.execute(
            "INSERT INTO coordinator_meta(singleton, schema_version, coordinator_identity, ledger_chain_id, policy,
                                           resource_limits,
                                           current_config_version, current_config_digest, root_height,
                                           root_header_hash, root_block_json, root_digest,
                                           checkpoint_generation, checkpoint_digest)
             VALUES(1, ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, 0, ?12)",
            params![
                SCHEMA_VERSION,
                config.identity().as_bytes().as_slice(),
                config.ledger_chain_id().as_str(),
                encode_policy(config.policy()),
                encode_resource_limits(config)?,
                source_version,
                source_digest.as_slice(),
                root_height,
                root.header_hash().as_slice(),
                root_blob,
                root_digest.as_slice(),
                checkpoint.state_digest().as_slice(),
            ],
        )?;
        #[cfg(test)]
        if FAIL_BOOTSTRAP_AS_AMBIGUOUS_ROLLBACK.with(|flag| flag.replace(false)) {
            return Err(CoordinatorError::AmbiguousCommit);
        }
        transaction.commit().map_err(|_| CoordinatorError::AmbiguousCommit)?;
        Ok((
            Self {
                connection,
                current_checkpoint: checkpoint,
                current_root_digest: root_digest,
                current_config_digest: source_digest,
                latest_manifest: None,
                prepared_manifest: None,
                _database_guard: database_guard,
                _lock: lock,
            },
            StoredHead {
                root: root.clone(),
                digest: root_digest,
                checkpoint,
                prior_checkpoint: None,
                operation_kind: OPERATION_BOOTSTRAP,
                operation_digest,
            },
        ))
    }

    pub(crate) fn open(path: &Path, config: &CoordinatorConfig) -> Result<(Self, StoredHead)> {
        let (connection, database_guard, lock) = open_connection(path, config, false)?;
        validate_database_header(&connection)?;
        configure_connection(&connection, config)?;

        let meta: MetadataRow = connection
            .query_row(
                "SELECT schema_version, coordinator_identity, ledger_chain_id, policy, resource_limits,
                        current_config_version, current_config_digest, root_height, root_header_hash,
                        root_block_json, root_digest,
                        checkpoint_generation, checkpoint_digest,
                        latest_manifest_generation, latest_manifest_digest
                 FROM coordinator_meta WHERE singleton = 1",
                [],
                |row| {
                    Ok(MetadataRow {
                        schema_version: row.get(0)?,
                        coordinator_identity: row.get(1)?,
                        ledger_chain_id: row.get(2)?,
                        policy: row.get(3)?,
                        resource_limits: row.get(4)?,
                        current_config_version: row.get(5)?,
                        current_config_digest: row.get(6)?,
                        root_height: row.get(7)?,
                        root_header_hash: row.get(8)?,
                        root_block_json: row.get(9)?,
                        root_digest: row.get(10)?,
                        checkpoint_generation: row.get(11)?,
                        checkpoint_digest: row.get(12)?,
                        latest_manifest_generation: row.get(13)?,
                        latest_manifest_digest: row.get(14)?,
                    })
                },
            )
            .optional()?
            .ok_or(CoordinatorError::StorageCorrupt("coordinator metadata is missing"))?;
        if meta.schema_version != SCHEMA_VERSION
            || meta.coordinator_identity.as_slice() != config.identity().as_bytes()
            || meta.ledger_chain_id != config.ledger_chain_id().as_str()
            || meta.policy != encode_policy(config.policy())
            || meta.resource_limits != encode_resource_limits(config)?
            || from_i64(meta.current_config_version)? != config.sources().version()
        {
            return Err(CoordinatorError::StorageCorrupt(
                "database identity or policy differs from configuration",
            ));
        }
        let expected_source_blob = encode_sources(config.sources())?;
        let expected_source_digest = source_digest(&expected_source_blob);
        if fixed::<32>(&meta.current_config_digest)? != expected_source_digest {
            return Err(CoordinatorError::StorageCorrupt(
                "current source configuration differs from the operator pin",
            ));
        }
        validate_source_row(
            &connection,
            config.sources(),
            &expected_source_blob,
            expected_source_digest,
        )?;

        let height = from_i64(meta.root_height)?;
        let header_hash = fixed::<32>(&meta.root_header_hash)?;
        let stored_root_digest = fixed::<32>(&meta.root_digest)?;
        let expected_root_digest = root_digest(config, height, &header_hash, &meta.root_block_json);
        if stored_root_digest != expected_root_digest {
            return Err(CoordinatorError::StorageCorrupt("current root digest differs"));
        }
        let block = decode_light_block(&meta.root_block_json, config.max_trace_encoded_bytes())?;
        let root = PinnedTrustRoot::new(block, config.ledger_chain_id(), height, header_hash, config.policy())?;
        let checkpoint = TrustCheckpoint::new(
            from_i64(meta.checkpoint_generation)?,
            fixed::<32>(&meta.checkpoint_digest)?,
        );
        let latest_manifest = match (meta.latest_manifest_generation, meta.latest_manifest_digest) {
            (None, None) => None,
            (Some(generation), Some(digest)) => Some((from_i64(generation)?, fixed::<32>(&digest)?)),
            _ => {
                return Err(CoordinatorError::StorageCorrupt(
                    "latest history manifest metadata is malformed",
                ));
            }
        };
        validate_latest_manifest_pointer(&connection, latest_manifest, checkpoint.generation())?;
        let (prior_checkpoint, operation_kind, operation_digest) = validate_current_checkpoint(
            &connection,
            config,
            checkpoint,
            &stored_root_digest,
            &expected_source_digest,
        )?;
        let latest: Option<(i64, Vec<u8>)> = connection
            .query_row(
                "SELECT next_root_height, next_root_digest FROM finality_updates
                 ORDER BY execution_height DESC LIMIT 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        if let Some((latest_height, latest_digest)) = latest {
            if from_i64(latest_height)? != height || fixed::<32>(&latest_digest)? != stored_root_digest {
                return Err(CoordinatorError::StorageCorrupt(
                    "current root is not the latest committed update",
                ));
            }
        }
        Ok((
            Self {
                connection,
                current_checkpoint: checkpoint,
                current_root_digest: stored_root_digest,
                current_config_digest: expected_source_digest,
                latest_manifest,
                prepared_manifest: None,
                _database_guard: database_guard,
                _lock: lock,
            },
            StoredHead {
                root,
                digest: stored_root_digest,
                checkpoint,
                prior_checkpoint,
                operation_kind,
                operation_digest,
            },
        ))
    }

    pub(crate) fn historical_by_height(
        &self,
        config: &CoordinatorConfig,
        execution_height: u64,
    ) -> Result<Option<HistoricalFinality>> {
        let row = self.load_update_row(execution_height)?;
        let Some(stored) = row else {
            return Ok(None);
        };
        let generation = from_i64(stored.checkpoint_generation)?;
        let historical = validate_stored_update(&self.connection, config, execution_height, stored)?;
        let authenticated = match authenticate_with_history_manifests(
            &self.connection,
            config,
            generation,
            execution_height,
            historical.proof_digest(),
            self.current_checkpoint,
            &self.current_root_digest,
            &self.current_config_digest,
            self.latest_manifest,
        )? {
            Some(()) => true,
            None => validate_checkpoint_chain(
                &self.connection,
                config,
                self.current_checkpoint,
                &self.current_root_digest,
                &self.current_config_digest,
            )?
            .get(&execution_height)
            .is_some_and(|digest| digest == historical.proof_digest()),
        };
        if !authenticated {
            return Err(CoordinatorError::StorageCorrupt(
                "historical proof differs from the anchored checkpoint chain",
            ));
        }
        Ok(Some(historical))
    }

    pub(crate) fn historical_by_request(
        &self,
        config: &CoordinatorConfig,
        request_digest: &RequestDigestV2,
    ) -> Result<Option<HistoricalRequestFinality>> {
        let live_location: Option<RequestIndexLocation> = self
            .connection
            .query_row(
                "SELECT execution_height, block_index, channel_context_id, participant_id,
                        proposal_digest, entry_hash
                 FROM request_index WHERE request_digest = ?1",
                [request_digest.as_bytes().as_slice()],
                |row| {
                    Ok(RequestIndexLocation {
                        execution_height: row.get(0)?,
                        block_index: row.get(1)?,
                        channel_context_id: row.get(2)?,
                        participant_id: row.get(3)?,
                        proposal_digest: row.get(4)?,
                        entry_hash: row.get(5)?,
                    })
                },
            )
            .optional()?;
        let archived_location: Option<RequestIndexLocation> = self
            .connection
            .query_row(
                "SELECT execution_height, block_index, channel_context_id, participant_id,
                        proposal_digest, entry_hash
                 FROM history_manifest_requests WHERE request_digest = ?1
                 ORDER BY manifest_generation ASC LIMIT 1",
                [request_digest.as_bytes().as_slice()],
                |row| {
                    Ok(RequestIndexLocation {
                        execution_height: row.get(0)?,
                        block_index: row.get(1)?,
                        channel_context_id: row.get(2)?,
                        participant_id: row.get(3)?,
                        proposal_digest: row.get(4)?,
                        entry_hash: row.get(5)?,
                    })
                },
            )
            .optional()?;
        if live_location.is_some() && archived_location.is_some() && live_location != archived_location {
            return Err(CoordinatorError::StorageCorrupt(
                "live and manifested request-index locations differ",
            ));
        }
        let Some(location) = archived_location.or(live_location) else {
            return Ok(None);
        };
        let height = from_i64(location.execution_height)?;
        let index = u32::try_from(location.block_index)
            .map_err(|_| CoordinatorError::StorageCorrupt("request index is invalid"))?;
        let finality = self
            .historical_by_height(config, height)?
            .ok_or(CoordinatorError::StorageCorrupt("request points to a missing update"))?;
        let entry = finality
            .proof()
            .execution()
            .entries()
            .get(usize::try_from(index).map_err(|_| CoordinatorError::StorageCorrupt("request index is invalid"))?)
            .ok_or(CoordinatorError::StorageCorrupt("request block index is out of range"))?;
        let metadata = entry.metadata();
        if metadata.request_digest() != request_digest
            || metadata.channel_context_id().as_bytes() != location.channel_context_id.as_slice()
            || metadata.participant_id().as_bytes() != location.participant_id.as_slice()
            || metadata.proposal_digest().as_bytes() != location.proposal_digest.as_slice()
            || metadata.entry_hash().as_bytes() != location.entry_hash.as_slice()
        {
            return Err(CoordinatorError::StorageCorrupt(
                "request index authenticated binding differs",
            ));
        }
        Ok(Some(HistoricalRequestFinality {
            request_digest: request_digest.clone(),
            block_index: index,
            finality,
        }))
    }

    pub(crate) fn pending_prior_root(
        &self,
        config: &CoordinatorConfig,
        execution_height: u64,
    ) -> Result<PinnedTrustRoot> {
        let row = self
            .load_update_row(execution_height)?
            .ok_or(CoordinatorError::CheckpointConflict)?;
        let prior_height = from_i64(row.prior_root_height)?;
        let prior_hash = fixed::<32>(&row.prior_root_header_hash)?;
        let historical = self
            .historical_by_height(config, execution_height)?
            .ok_or(CoordinatorError::CheckpointConflict)?;
        PinnedTrustRoot::new(
            historical.proof().trusted_root().clone(),
            config.ledger_chain_id(),
            prior_height,
            prior_hash,
            config.policy(),
        )
        .map_err(CoordinatorError::from)
    }

    pub(crate) fn finality_checkpoint_operation_digest(
        &self,
        config: &CoordinatorConfig,
        execution_height: u64,
    ) -> Result<[u8; 32]> {
        let row = self
            .load_update_row(execution_height)?
            .ok_or(CoordinatorError::CheckpointConflict)?;
        let generation = from_i64(row.checkpoint_generation)?;
        let historical = self
            .historical_by_height(config, execution_height)?
            .ok_or(CoordinatorError::CheckpointConflict)?;
        let request_digest = request_index_manifest_digest(&self.connection, config, generation, OPERATION_FINALITY)?;
        Ok(finality_operation_digest(historical.proof_digest(), &request_digest))
    }

    pub(crate) fn validate_pending_history_intent(
        &self,
        config: &CoordinatorConfig,
        head: &StoredHead,
        intent: &HistorySealIntent,
    ) -> Result<()> {
        let prior = head.prior_checkpoint.ok_or(CoordinatorError::CheckpointConflict)?;
        if head.operation_kind != OPERATION_HISTORY_MANIFEST
            || intent.identity != config.identity()
            || intent.expected_checkpoint != prior
            || intent.manifest_digest != head.operation_digest
        {
            return Err(CoordinatorError::CheckpointConflict);
        }
        let previous_manifest: Option<(i64, Vec<u8>)> = self
            .connection
            .query_row(
                "SELECT manifest_generation, manifest_digest FROM history_epoch_manifests
                 WHERE manifest_generation < ?1 ORDER BY manifest_generation DESC LIMIT 1",
                [to_i64(head.checkpoint.generation())?],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        let previous_manifest = previous_manifest
            .map(|(generation, digest)| -> Result<(u64, [u8; 32])> {
                Ok((from_i64(generation)?, fixed::<32>(&digest)?))
            })
            .transpose()?;
        let prior_head = StoredHead {
            root: head.root.clone(),
            digest: head.digest,
            checkpoint: prior,
            prior_checkpoint: None,
            operation_kind: OPERATION_HISTORY_MANIFEST,
            operation_digest: [0_u8; 32],
        };
        let plan = build_history_manifest_plan(
            &self.connection,
            config,
            &prior_head,
            prior,
            &self.current_root_digest,
            &self.current_config_digest,
            previous_manifest,
        )?
        .ok_or(CoordinatorError::CheckpointConflict)?;
        if &plan.intent != intent {
            return Err(CoordinatorError::CheckpointConflict);
        }
        let loaded = load_history_manifest(&self.connection, head.checkpoint.generation(), &intent.manifest_digest)?;
        if loaded.decoded.first_generation != intent.first_generation
            || loaded.decoded.last_generation != intent.last_generation
        {
            return Err(CoordinatorError::CheckpointConflict);
        }
        for entry in &loaded.decoded.entries {
            if entry.operation_kind == OPERATION_FINALITY {
                let archived = archived_request_index_manifest_digest(
                    &self.connection,
                    config,
                    entry.generation,
                    head.checkpoint.generation(),
                )?;
                if archived != entry.request_index_digest {
                    return Err(CoordinatorError::CheckpointConflict);
                }
            }
        }
        Ok(())
    }

    pub(crate) fn commit_update(
        &mut self,
        config: &CoordinatorConfig,
        head: &StoredHead,
        prepared: PreparedUpdate,
    ) -> Result<(HistoricalFinality, StoredHead)> {
        let bundle_blob = encode_bundle(&prepared.bundle, config.max_proof_bundle_bytes())?;
        let proof_byte_count = i64::try_from(bundle_blob.len())
            .map_err(|_| CoordinatorError::InvalidInput("proof bundle length does not fit SQLite"))?;
        let request_count = i64::try_from(prepared.bundle.execution().entries().len())
            .map_err(|_| CoordinatorError::InvalidInput("request count does not fit SQLite"))?;
        let summary_blob = encode_summary(&prepared.summary)?;
        let execution_digest = execution_digest(prepared.bundle.execution())?;
        let next_root_blob = encode_light_block(prepared.next_root.light_block(), config.max_trace_encoded_bytes())?;
        let next_root_digest = root_digest(
            config,
            prepared.next_root.height(),
            prepared.next_root.header_hash(),
            &next_root_blob,
        );
        let source_blob = encode_sources(config.sources())?;
        let config_digest = source_digest(&source_blob);
        let proof_digest = proof_digest(
            &config_digest,
            &head.digest,
            &next_root_digest,
            &bundle_blob,
            &summary_blob,
        );
        let next_generation = head
            .checkpoint
            .generation()
            .checked_add(1)
            .ok_or(CoordinatorError::Capacity)?;
        let execution_height = prepared.bundle.execution().height();
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        validate_transaction_head(&transaction, config, head, &config_digest)?;
        ensure_unsealed_capacity(
            &transaction,
            config,
            1,
            usize::try_from(proof_byte_count)
                .map_err(|_| CoordinatorError::InvalidInput("proof byte count does not fit usize"))?,
            usize::try_from(request_count)
                .map_err(|_| CoordinatorError::InvalidInput("request count does not fit usize"))?,
        )?;
        if transaction
            .query_row(
                "SELECT 1 FROM finality_updates WHERE execution_height = ?1",
                [to_i64(execution_height)?],
                |_| Ok(()),
            )
            .optional()?
            .is_some()
        {
            return Err(CoordinatorError::IdempotencyConflict);
        }
        let request_index_digest = pending_request_index_digest(&transaction, prepared.bundle.execution())?;
        let operation_digest = finality_operation_digest(&proof_digest, &request_index_digest);
        let next_checkpoint = checkpoint_digest(
            config,
            next_generation,
            Some(head.checkpoint),
            OPERATION_FINALITY,
            &operation_digest,
            &next_root_digest,
            &config_digest,
        );
        transaction.execute(
            "INSERT INTO finality_updates(
                 execution_height, execution_digest, config_version, prior_root_height,
                 prior_root_header_hash, prior_root_digest, proof_bundle_json, summary_blob,
                 proof_byte_count, request_count, proof_digest, next_root_height,
                 next_root_header_hash, next_root_block_json, next_root_digest, checkpoint_generation)
             VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16)",
            params![
                to_i64(execution_height)?,
                execution_digest.as_slice(),
                to_i64(config.sources().version())?,
                to_i64(head.root.height())?,
                head.root.header_hash().as_slice(),
                head.digest.as_slice(),
                bundle_blob,
                summary_blob,
                proof_byte_count,
                request_count,
                proof_digest.as_slice(),
                to_i64(prepared.next_root.height())?,
                prepared.next_root.header_hash().as_slice(),
                next_root_blob,
                next_root_digest.as_slice(),
                to_i64(next_generation)?,
            ],
        )?;
        insert_request_indexes(&transaction, prepared.bundle.execution())?;
        insert_checkpoint_transition(
            &transaction,
            next_checkpoint,
            Some(head.checkpoint),
            OPERATION_FINALITY,
            &operation_digest,
        )?;
        let changed = transaction.execute(
            "UPDATE coordinator_meta
             SET root_height = ?1, root_header_hash = ?2, root_block_json = ?3, root_digest = ?4,
                 checkpoint_generation = ?5, checkpoint_digest = ?6
             WHERE singleton = 1 AND root_digest = ?7 AND current_config_digest = ?8
                   AND checkpoint_generation = ?9 AND checkpoint_digest = ?10",
            params![
                to_i64(prepared.next_root.height())?,
                prepared.next_root.header_hash().as_slice(),
                encode_light_block(prepared.next_root.light_block(), config.max_trace_encoded_bytes())?,
                next_root_digest.as_slice(),
                to_i64(next_generation)?,
                next_checkpoint.state_digest().as_slice(),
                head.digest.as_slice(),
                config_digest.as_slice(),
                to_i64(head.checkpoint.generation())?,
                head.checkpoint.state_digest().as_slice(),
            ],
        )?;
        if changed != 1 {
            return Err(CoordinatorError::IdempotencyConflict);
        }
        transaction.commit().map_err(|_| CoordinatorError::AmbiguousCommit)?;
        self.current_checkpoint = next_checkpoint;
        self.current_root_digest = next_root_digest;
        self.prepared_manifest = None;
        let historical = HistoricalFinality {
            summary: prepared.summary,
            proof: prepared.bundle,
            proof_digest,
        };
        Ok((
            historical,
            StoredHead {
                root: prepared.next_root,
                digest: next_root_digest,
                checkpoint: next_checkpoint,
                prior_checkpoint: Some(head.checkpoint),
                operation_kind: OPERATION_FINALITY,
                operation_digest,
            },
        ))
    }

    pub(crate) fn rotate_sources(
        &mut self,
        config: &CoordinatorConfig,
        head: &StoredHead,
        next: &SourceConfiguration,
    ) -> Result<(RotationOutcome, StoredHead)> {
        next.validate_policy(config.policy())?;
        if next.version() == config.sources().version() {
            return if next == config.sources() {
                Ok((
                    RotationOutcome::AlreadyCurrent,
                    StoredHead {
                        root: head.root.clone(),
                        digest: head.digest,
                        checkpoint: head.checkpoint,
                        prior_checkpoint: head.prior_checkpoint,
                        operation_kind: head.operation_kind,
                        operation_digest: head.operation_digest,
                    },
                ))
            } else {
                Err(CoordinatorError::ConfigurationConflict)
            };
        }
        let expected_next = config
            .sources()
            .version()
            .checked_add(1)
            .ok_or(CoordinatorError::ConfigurationConflict)?;
        if next.version() != expected_next {
            return Err(CoordinatorError::ConfigurationConflict);
        }
        let current_blob = encode_sources(config.sources())?;
        let current_digest = source_digest(&current_blob);
        let next_blob = encode_sources(next)?;
        let next_digest = source_digest(&next_blob);
        let next_generation = head
            .checkpoint
            .generation()
            .checked_add(1)
            .ok_or(CoordinatorError::Capacity)?;
        let next_checkpoint = checkpoint_digest(
            config,
            next_generation,
            Some(head.checkpoint),
            OPERATION_ROTATION,
            &next_digest,
            &head.digest,
            &next_digest,
        );
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        ensure_unsealed_capacity(&transaction, config, 1, 0, 0)?;
        let current: (i64, Vec<u8>, i64, Vec<u8>) = transaction.query_row(
            "SELECT current_config_version, current_config_digest, checkpoint_generation, checkpoint_digest
             FROM coordinator_meta WHERE singleton = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )?;
        if from_i64(current.0)? != config.sources().version()
            || fixed::<32>(&current.1)? != current_digest
            || from_i64(current.2)? != head.checkpoint.generation()
            || fixed::<32>(&current.3)? != *head.checkpoint.state_digest()
        {
            return Err(CoordinatorError::ConfigurationConflict);
        }
        if transaction
            .query_row(
                "SELECT 1 FROM source_configurations WHERE version = ?1",
                [to_i64(next.version())?],
                |_| Ok(()),
            )
            .optional()?
            .is_some()
        {
            return Err(CoordinatorError::ConfigurationConflict);
        }
        transaction.execute(
            "INSERT INTO source_configurations(version, config_blob, config_digest, installed_generation)
             VALUES(?1, ?2, ?3, ?4)",
            params![
                to_i64(next.version())?,
                next_blob,
                next_digest.as_slice(),
                to_i64(next_generation)?
            ],
        )?;
        insert_checkpoint_transition(
            &transaction,
            next_checkpoint,
            Some(head.checkpoint),
            OPERATION_ROTATION,
            &next_digest,
        )?;
        let changed = transaction.execute(
            "UPDATE coordinator_meta SET current_config_version = ?1, current_config_digest = ?2,
                                         checkpoint_generation = ?3, checkpoint_digest = ?4
             WHERE singleton = 1 AND current_config_version = ?5 AND current_config_digest = ?6
                   AND checkpoint_generation = ?7 AND checkpoint_digest = ?8",
            params![
                to_i64(next.version())?,
                next_digest.as_slice(),
                to_i64(next_generation)?,
                next_checkpoint.state_digest().as_slice(),
                to_i64(config.sources().version())?,
                current_digest.as_slice(),
                to_i64(head.checkpoint.generation())?,
                head.checkpoint.state_digest().as_slice(),
            ],
        )?;
        if changed != 1 {
            return Err(CoordinatorError::ConfigurationConflict);
        }
        transaction.commit().map_err(|_| CoordinatorError::AmbiguousCommit)?;
        self.current_checkpoint = next_checkpoint;
        self.current_config_digest = next_digest;
        self.prepared_manifest = None;
        Ok((
            RotationOutcome::Applied,
            StoredHead {
                root: head.root.clone(),
                digest: head.digest,
                checkpoint: next_checkpoint,
                prior_checkpoint: Some(head.checkpoint),
                operation_kind: OPERATION_ROTATION,
                operation_digest: next_digest,
            },
        ))
    }

    pub(crate) fn prepare_history_manifest(
        &mut self,
        config: &CoordinatorConfig,
        head: &StoredHead,
    ) -> Result<Option<HistorySealIntent>> {
        let plan = build_history_manifest_plan(
            &self.connection,
            config,
            head,
            self.current_checkpoint,
            &self.current_root_digest,
            &self.current_config_digest,
            self.latest_manifest,
        )?;
        let intent = plan.as_ref().map(|prepared| prepared.intent.clone());
        self.prepared_manifest = plan;
        Ok(intent)
    }

    pub(crate) fn seal_history_manifest(
        &mut self,
        config: &CoordinatorConfig,
        head: &StoredHead,
        intent: &HistorySealIntent,
    ) -> Result<(HistorySealOutcome, StoredHead)> {
        let current_config_digest = self.current_config_digest;
        let plan = self
            .prepared_manifest
            .take()
            .ok_or(CoordinatorError::IdempotencyConflict)?;
        if &plan.intent != intent {
            return Err(CoordinatorError::IdempotencyConflict);
        }
        let transaction = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        validate_transaction_head(&transaction, config, head, &current_config_digest)?;
        let next_generation = head
            .checkpoint
            .generation()
            .checked_add(1)
            .ok_or(CoordinatorError::Capacity)?;
        let next_checkpoint = checkpoint_digest(
            config,
            next_generation,
            Some(head.checkpoint),
            OPERATION_HISTORY_MANIFEST,
            &plan.intent.manifest_digest,
            &head.digest,
            &current_config_digest,
        );
        insert_checkpoint_transition(
            &transaction,
            next_checkpoint,
            Some(head.checkpoint),
            OPERATION_HISTORY_MANIFEST,
            &plan.intent.manifest_digest,
        )?;
        transaction.execute(
            "INSERT INTO history_epoch_manifests(
                 manifest_generation, first_generation, last_generation,
                 previous_manifest_digest, manifest_blob, manifest_digest,
                 root_digest, config_digest)
             VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                to_i64(next_generation)?,
                to_i64(plan.intent.first_generation)?,
                to_i64(plan.intent.last_generation)?,
                plan.previous_digest.map(|digest| digest.to_vec()),
                plan.manifest_blob,
                plan.intent.manifest_digest.as_slice(),
                head.digest.as_slice(),
                current_config_digest.as_slice(),
            ],
        )?;
        insert_manifest_request_rows(&transaction, next_generation, &plan.request_rows)?;
        let changed = transaction.execute(
            "UPDATE coordinator_meta
             SET checkpoint_generation = ?1, checkpoint_digest = ?2,
                 latest_manifest_generation = ?1, latest_manifest_digest = ?3
             WHERE singleton = 1 AND checkpoint_generation = ?4 AND checkpoint_digest = ?5",
            params![
                to_i64(next_generation)?,
                next_checkpoint.state_digest().as_slice(),
                plan.intent.manifest_digest.as_slice(),
                to_i64(head.checkpoint.generation())?,
                head.checkpoint.state_digest().as_slice(),
            ],
        )?;
        if changed != 1 {
            return Err(CoordinatorError::IdempotencyConflict);
        }
        transaction.commit().map_err(|_| CoordinatorError::AmbiguousCommit)?;
        self.current_checkpoint = next_checkpoint;
        self.latest_manifest = Some((next_generation, plan.intent.manifest_digest));
        Ok((
            HistorySealOutcome::Sealed {
                first_generation: plan.intent.first_generation,
                last_generation: plan.intent.last_generation,
            },
            StoredHead {
                root: head.root.clone(),
                digest: head.digest,
                checkpoint: next_checkpoint,
                prior_checkpoint: Some(head.checkpoint),
                operation_kind: OPERATION_HISTORY_MANIFEST,
                operation_digest: plan.intent.manifest_digest,
            },
        ))
    }

    fn load_update_row(&self, execution_height: u64) -> Result<Option<StoredUpdateRow>> {
        load_update_row_by_height(&self.connection, execution_height)
    }
}

fn collect_manifest_entries(
    connection: &Connection,
    config: &CoordinatorConfig,
    first_unsealed: u64,
    current_generation: u64,
) -> Result<Vec<ManifestEntry>> {
    let mut statement = connection.prepare(
        "SELECT generation, expected_generation, expected_digest, candidate_digest,
                operation_kind, operation_digest
         FROM checkpoint_transitions
         WHERE generation >= ?1 AND generation <= ?2 AND operation_kind != ?3
         ORDER BY generation ASC LIMIT ?4",
    )?;
    let rows = statement.query_map(
        params![
            to_i64(first_unsealed)?,
            to_i64(current_generation)?,
            OPERATION_HISTORY_MANIFEST,
            i64::try_from(config.history_limits().max_transitions())
                .map_err(|_| CoordinatorError::InvalidConfiguration("manifest limit does not fit SQLite"))?,
        ],
        |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, Option<i64>>(1)?,
                row.get::<_, Option<Vec<u8>>>(2)?,
                row.get::<_, Vec<u8>>(3)?,
                row.get::<_, i64>(4)?,
                row.get::<_, Vec<u8>>(5)?,
            ))
        },
    )?;
    let mut raw = Vec::new();
    for row in rows {
        raw.push(row?);
    }
    drop(statement);
    let mut entries = Vec::with_capacity(raw.len());
    let mut proof_bytes = 0_usize;
    let mut request_count = 0_usize;
    for (generation, expected_generation, expected_digest, candidate_digest, operation_kind, operation_digest) in raw {
        let generation = from_i64(generation)?;
        let expected = match (expected_generation, expected_digest) {
            (None, None) => None,
            (Some(expected_generation), Some(expected_digest)) => Some(TrustCheckpoint::new(
                from_i64(expected_generation)?,
                fixed::<32>(&expected_digest)?,
            )),
            _ => {
                return Err(CoordinatorError::StorageCorrupt(
                    "manifest source transition predecessor is malformed",
                ));
            }
        };
        let candidate = TrustCheckpoint::new(generation, fixed::<32>(&candidate_digest)?);
        let operation_digest = fixed::<32>(&operation_digest)?;
        let (entry_proof_bytes, entry_requests) = manifest_entry_work(connection, generation, operation_kind)?;
        let next_proof_bytes = proof_bytes
            .checked_add(entry_proof_bytes)
            .ok_or(CoordinatorError::Capacity)?;
        let next_request_count = request_count
            .checked_add(entry_requests)
            .ok_or(CoordinatorError::Capacity)?;
        if next_proof_bytes > config.history_limits().max_proof_bytes()
            || next_request_count > config.history_limits().max_requests()
        {
            if entries.is_empty() {
                return Err(CoordinatorError::Capacity);
            }
            break;
        }
        let request_index_digest = request_index_manifest_digest(connection, config, generation, operation_kind)?;
        entries.push(ManifestEntry {
            generation,
            expected,
            candidate,
            operation_kind,
            operation_digest,
            request_index_digest,
        });
        proof_bytes = next_proof_bytes;
        request_count = next_request_count;
    }
    Ok(entries)
}

fn manifest_entry_work(connection: &Connection, generation: u64, operation_kind: i64) -> Result<(usize, usize)> {
    if operation_kind != OPERATION_FINALITY {
        return Ok((0, 0));
    }
    let (proof_bytes, request_count): (i64, i64) = connection.query_row(
        "SELECT proof_byte_count, request_count FROM finality_updates WHERE checkpoint_generation = ?1",
        [to_i64(generation)?],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    Ok((
        usize::try_from(proof_bytes)
            .map_err(|_| CoordinatorError::StorageCorrupt("manifest proof byte count is invalid"))?,
        usize::try_from(request_count)
            .map_err(|_| CoordinatorError::StorageCorrupt("manifest request count is invalid"))?,
    ))
}

#[allow(clippy::too_many_arguments)]
fn build_history_manifest_plan(
    connection: &Connection,
    config: &CoordinatorConfig,
    head: &StoredHead,
    current_checkpoint: TrustCheckpoint,
    current_root_digest: &[u8; 32],
    current_config_digest: &[u8; 32],
    latest_manifest: Option<(u64, [u8; 32])>,
) -> Result<Option<HistoryManifestPlan>> {
    if head.checkpoint != current_checkpoint
        || head.digest != *current_root_digest
        || source_configuration_digest(config.sources())? != *current_config_digest
    {
        return Err(CoordinatorError::IdempotencyConflict);
    }
    match latest_manifest {
        Some((manifest_generation, manifest_digest)) => {
            let loaded = load_history_manifest(connection, manifest_generation, &manifest_digest)?;
            let _ = validate_checkpoint_tail_from_manifest(
                connection,
                config,
                manifest_generation,
                &manifest_digest,
                loaded,
                current_checkpoint,
                current_root_digest,
                current_config_digest,
            )?;
        }
        None => {
            let _ = validate_checkpoint_chain(
                connection,
                config,
                current_checkpoint,
                current_root_digest,
                current_config_digest,
            )?;
        }
    }
    let first_unsealed = match latest_manifest {
        Some((manifest_generation, digest)) => load_history_manifest(connection, manifest_generation, &digest)?
            .decoded
            .last_generation
            .checked_add(1)
            .ok_or(CoordinatorError::Capacity)?,
        None => 0,
    };
    let entries = collect_manifest_entries(connection, config, first_unsealed, current_checkpoint.generation())?;
    let Some(first) = entries.first().copied() else {
        return Ok(None);
    };
    let last = entries
        .last()
        .copied()
        .ok_or(CoordinatorError::StorageCorrupt("history manifest entries disappeared"))?;
    let previous_digest = latest_manifest.map(|(_, digest)| digest);
    let manifest_blob = encode_history_manifest(first.generation, last.generation, previous_digest, &entries)?;
    let manifest_digest = history_manifest_digest(previous_digest, &manifest_blob);
    let request_rows = collect_manifest_request_rows(connection, config, &entries)?;
    Ok(Some(HistoryManifestPlan {
        intent: HistorySealIntent {
            identity: config.identity(),
            expected_checkpoint: current_checkpoint,
            first_generation: first.generation,
            last_generation: last.generation,
            manifest_digest,
        },
        previous_digest,
        manifest_blob,
        request_rows,
    }))
}

fn request_index_manifest_digest(
    connection: &Connection,
    config: &CoordinatorConfig,
    generation: u64,
    operation_kind: i64,
) -> Result<[u8; 32]> {
    if operation_kind != OPERATION_FINALITY {
        return Ok(digest_parts(REQUEST_INDEX_DOMAIN, &[]));
    }
    let execution_height: i64 = connection
        .query_row(
            "SELECT execution_height FROM finality_updates WHERE checkpoint_generation = ?1",
            [to_i64(generation)?],
            |row| row.get(0),
        )
        .optional()?
        .ok_or(CoordinatorError::StorageCorrupt(
            "manifest finality transition is missing",
        ))?;
    let execution_height = from_i64(execution_height)?;
    let row = load_update_row_by_height(connection, execution_height)?
        .ok_or(CoordinatorError::StorageCorrupt("manifest finality row disappeared"))?;
    let historical = validate_stored_update(connection, config, execution_height, row)?;
    let mut canonical = Vec::new();
    for entry in historical.proof().execution().entries() {
        let metadata = entry.metadata();
        let location = load_request_location(connection, metadata.request_digest())?.ok_or(
            CoordinatorError::StorageCorrupt("manifest request-index row is missing"),
        )?;
        if location.channel_context_id.as_slice() != metadata.channel_context_id().as_bytes()
            || location.participant_id.as_slice() != metadata.participant_id().as_bytes()
            || location.proposal_digest.as_slice() != metadata.proposal_digest().as_bytes()
            || location.entry_hash.as_slice() != metadata.entry_hash().as_bytes()
        {
            return Err(CoordinatorError::StorageCorrupt(
                "manifest request-index binding differs",
            ));
        }
        canonical.extend_from_slice(metadata.request_digest().as_bytes());
        canonical.extend_from_slice(&from_i64(location.execution_height)?.to_be_bytes());
        canonical.extend_from_slice(
            &u64::try_from(location.block_index)
                .map_err(|_| CoordinatorError::StorageCorrupt("manifest block index is negative"))?
                .to_be_bytes(),
        );
        canonical.extend_from_slice(&location.channel_context_id);
        canonical.extend_from_slice(&location.participant_id);
        canonical.extend_from_slice(&location.proposal_digest);
        canonical.extend_from_slice(&location.entry_hash);
    }
    Ok(digest_parts(REQUEST_INDEX_DOMAIN, &[canonical.as_slice()]))
}

fn collect_manifest_request_rows(
    connection: &Connection,
    config: &CoordinatorConfig,
    entries: &[ManifestEntry],
) -> Result<Vec<ManifestRequestRow>> {
    let mut rows = BTreeMap::<[u8; 32], RequestIndexLocation>::new();
    for entry in entries {
        if entry.operation_kind != OPERATION_FINALITY {
            continue;
        }
        let execution_height: i64 = connection.query_row(
            "SELECT execution_height FROM finality_updates WHERE checkpoint_generation = ?1",
            [to_i64(entry.generation)?],
            |row| row.get(0),
        )?;
        let execution_height_u64 = from_i64(execution_height)?;
        let row = load_update_row_by_height(connection, execution_height_u64)?
            .ok_or(CoordinatorError::StorageCorrupt("manifest request source is missing"))?;
        let historical = validate_stored_update(connection, config, execution_height_u64, row)?;
        for executed in historical.proof().execution().entries() {
            let metadata = executed.metadata();
            let location: RequestIndexLocation = connection.query_row(
                "SELECT execution_height, block_index, channel_context_id, participant_id,
                        proposal_digest, entry_hash
                 FROM request_index WHERE request_digest = ?1",
                [metadata.request_digest().as_bytes().as_slice()],
                |row| {
                    Ok(RequestIndexLocation {
                        execution_height: row.get(0)?,
                        block_index: row.get(1)?,
                        channel_context_id: row.get(2)?,
                        participant_id: row.get(3)?,
                        proposal_digest: row.get(4)?,
                        entry_hash: row.get(5)?,
                    })
                },
            )?;
            let digest = *metadata.request_digest().as_bytes();
            if rows.get(&digest).is_some_and(|existing| existing != &location) {
                return Err(CoordinatorError::StorageCorrupt(
                    "manifest request replay location differs",
                ));
            }
            rows.entry(digest).or_insert(location);
        }
    }
    Ok(rows
        .into_iter()
        .map(|(request_digest, location)| ManifestRequestRow {
            request_digest,
            location,
        })
        .collect())
}

fn insert_manifest_request_rows(
    connection: &Connection,
    manifest_generation: u64,
    rows: &[ManifestRequestRow],
) -> Result<()> {
    for row in rows {
        connection.execute(
            "INSERT INTO history_manifest_requests(
                 manifest_generation, request_digest, execution_height, block_index,
                 channel_context_id, participant_id, proposal_digest, entry_hash)
             VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                to_i64(manifest_generation)?,
                row.request_digest.as_slice(),
                row.location.execution_height,
                row.location.block_index,
                row.location.channel_context_id.as_slice(),
                row.location.participant_id.as_slice(),
                row.location.proposal_digest.as_slice(),
                row.location.entry_hash.as_slice(),
            ],
        )?;
    }
    Ok(())
}

fn encode_history_manifest(
    first_generation: u64,
    last_generation: u64,
    previous_digest: Option<[u8; 32]>,
    entries: &[ManifestEntry],
) -> Result<Vec<u8>> {
    if entries.is_empty() || entries.len() > MAX_HISTORY_EPOCH_TRANSITIONS {
        return Err(CoordinatorError::InvalidInput(
            "history manifest entry count is outside its bound",
        ));
    }
    let count = u32::try_from(entries.len())
        .map_err(|_| CoordinatorError::InvalidInput("history manifest entry count does not fit u32"))?;
    let mut output = Vec::with_capacity(64 + entries.len() * 170);
    output.extend_from_slice(HISTORY_MANIFEST_MAGIC);
    output.extend_from_slice(&first_generation.to_be_bytes());
    output.extend_from_slice(&last_generation.to_be_bytes());
    match previous_digest {
        Some(digest) => {
            output.push(1);
            output.extend_from_slice(&digest);
        }
        None => output.push(0),
    }
    output.extend_from_slice(&count.to_be_bytes());
    for entry in entries {
        output.extend_from_slice(&entry.generation.to_be_bytes());
        match entry.expected {
            Some(expected) => {
                output.push(1);
                output.extend_from_slice(&expected.generation().to_be_bytes());
                output.extend_from_slice(expected.state_digest());
            }
            None => output.push(0),
        }
        output.extend_from_slice(&entry.candidate.generation().to_be_bytes());
        output.extend_from_slice(entry.candidate.state_digest());
        output.extend_from_slice(&entry.operation_kind.to_be_bytes());
        output.extend_from_slice(&entry.operation_digest);
        output.extend_from_slice(&entry.request_index_digest);
    }
    Ok(output)
}

fn history_manifest_digest(previous_digest: Option<[u8; 32]>, manifest_blob: &[u8]) -> [u8; 32] {
    let mut previous = [0_u8; 33];
    if let Some(digest) = previous_digest {
        previous[0] = 1;
        previous[1..].copy_from_slice(&digest);
    }
    digest_parts(HISTORY_MANIFEST_DOMAIN, &[previous.as_slice(), manifest_blob])
}

fn load_history_manifest(
    connection: &Connection,
    manifest_generation: u64,
    expected_digest: &[u8; 32],
) -> Result<LoadedManifest> {
    let stored: StoredManifestRow = connection
        .query_row(
            "SELECT first_generation, last_generation, previous_manifest_digest,
                    manifest_blob, manifest_digest, root_digest, config_digest
             FROM history_epoch_manifests WHERE manifest_generation = ?1",
            [to_i64(manifest_generation)?],
            |row| {
                Ok(StoredManifestRow {
                    first_generation: row.get(0)?,
                    last_generation: row.get(1)?,
                    previous_digest: row.get(2)?,
                    manifest_blob: row.get(3)?,
                    manifest_digest: row.get(4)?,
                    root_digest: row.get(5)?,
                    config_digest: row.get(6)?,
                })
            },
        )
        .optional()?
        .ok_or(CoordinatorError::StorageCorrupt("history manifest is missing"))?;
    let previous_digest = stored.previous_digest.as_deref().map(fixed::<32>).transpose()?;
    let stored_digest = fixed::<32>(&stored.manifest_digest)?;
    if stored_digest != *expected_digest
        || history_manifest_digest(previous_digest, &stored.manifest_blob) != stored_digest
    {
        return Err(CoordinatorError::StorageCorrupt("history manifest digest differs"));
    }
    let decoded = decode_history_manifest(&stored.manifest_blob)?;
    if decoded.first_generation != from_i64(stored.first_generation)?
        || decoded.last_generation != from_i64(stored.last_generation)?
        || decoded.previous_digest != previous_digest
    {
        return Err(CoordinatorError::StorageCorrupt("history manifest metadata differs"));
    }
    Ok(LoadedManifest {
        decoded,
        root_digest: fixed::<32>(&stored.root_digest)?,
        config_digest: fixed::<32>(&stored.config_digest)?,
    })
}

fn validate_latest_manifest_pointer(
    connection: &Connection,
    latest: Option<(u64, [u8; 32])>,
    current_generation: u64,
) -> Result<()> {
    let stored: Option<(i64, Vec<u8>)> = connection
        .query_row(
            "SELECT manifest_generation, manifest_digest FROM history_epoch_manifests
             ORDER BY manifest_generation DESC LIMIT 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    let normalized = stored
        .map(|(generation, digest)| -> Result<(u64, [u8; 32])> { Ok((from_i64(generation)?, fixed::<32>(&digest)?)) })
        .transpose()?;
    if normalized != latest || latest.is_some_and(|(generation, _)| generation > current_generation) {
        return Err(CoordinatorError::StorageCorrupt(
            "latest history manifest pointer differs",
        ));
    }
    if let Some((generation, digest)) = latest {
        let _ = load_history_manifest(connection, generation, &digest)?;
    }
    Ok(())
}

fn decode_history_manifest(encoded: &[u8]) -> Result<DecodedManifest> {
    let maximum = 64_usize
        .checked_add(
            MAX_HISTORY_EPOCH_TRANSITIONS
                .checked_mul(170)
                .ok_or(CoordinatorError::StorageCorrupt("manifest bound overflows"))?,
        )
        .ok_or(CoordinatorError::StorageCorrupt("manifest bound overflows"))?;
    if encoded.is_empty() || encoded.len() > maximum {
        return Err(CoordinatorError::StorageCorrupt("history manifest length is invalid"));
    }
    let mut reader = Reader::new(encoded);
    if reader.take::<8>()? != *HISTORY_MANIFEST_MAGIC {
        return Err(CoordinatorError::StorageCorrupt("history manifest magic differs"));
    }
    let first_generation = u64::from_be_bytes(reader.take::<8>()?);
    let last_generation = u64::from_be_bytes(reader.take::<8>()?);
    let previous_digest = match reader.byte()? {
        0 => None,
        1 => Some(reader.take::<32>()?),
        _ => {
            return Err(CoordinatorError::StorageCorrupt(
                "history manifest predecessor tag is invalid",
            ));
        }
    };
    let count = usize::try_from(u32::from_be_bytes(reader.take::<4>()?))
        .map_err(|_| CoordinatorError::StorageCorrupt("history manifest count does not fit usize"))?;
    if count == 0 || count > MAX_HISTORY_EPOCH_TRANSITIONS {
        return Err(CoordinatorError::StorageCorrupt("history manifest count is invalid"));
    }
    let mut entries = Vec::with_capacity(count);
    for _ in 0..count {
        let generation = u64::from_be_bytes(reader.take::<8>()?);
        let expected = match reader.byte()? {
            0 => None,
            1 => Some(TrustCheckpoint::new(
                u64::from_be_bytes(reader.take::<8>()?),
                reader.take::<32>()?,
            )),
            _ => {
                return Err(CoordinatorError::StorageCorrupt(
                    "history manifest expected tag is invalid",
                ));
            }
        };
        let candidate = TrustCheckpoint::new(u64::from_be_bytes(reader.take::<8>()?), reader.take::<32>()?);
        let operation_kind = i64::from_be_bytes(reader.take::<8>()?);
        let operation_digest = reader.take::<32>()?;
        let request_index_digest = reader.take::<32>()?;
        if candidate.generation() != generation || operation_kind == OPERATION_HISTORY_MANIFEST {
            return Err(CoordinatorError::StorageCorrupt("history manifest entry is invalid"));
        }
        entries.push(ManifestEntry {
            generation,
            expected,
            candidate,
            operation_kind,
            operation_digest,
            request_index_digest,
        });
    }
    if !reader.is_empty()
        || entries.first().map(|entry| entry.generation) != Some(first_generation)
        || entries.last().map(|entry| entry.generation) != Some(last_generation)
        || entries.windows(2).any(|pair| pair[0].generation >= pair[1].generation)
    {
        return Err(CoordinatorError::StorageCorrupt("history manifest ordering differs"));
    }
    Ok(DecodedManifest {
        first_generation,
        last_generation,
        previous_digest,
        entries,
    })
}

fn load_update_row_by_height(connection: &Connection, execution_height: u64) -> Result<Option<StoredUpdateRow>> {
    connection
        .query_row(
            "SELECT execution_digest, config_version, prior_root_height, prior_root_header_hash,
                    prior_root_digest, proof_bundle_json, proof_byte_count, request_count,
                    summary_blob, proof_digest,
                    next_root_height, next_root_header_hash, next_root_block_json, next_root_digest,
                    checkpoint_generation
             FROM finality_updates WHERE execution_height = ?1",
            [to_i64(execution_height)?],
            |row| {
                Ok(StoredUpdateRow {
                    execution_digest: row.get(0)?,
                    config_version: row.get(1)?,
                    prior_root_height: row.get(2)?,
                    prior_root_header_hash: row.get(3)?,
                    prior_root_digest: row.get(4)?,
                    proof_bundle_json: row.get(5)?,
                    proof_byte_count: row.get(6)?,
                    request_count: row.get(7)?,
                    summary_blob: row.get(8)?,
                    proof_digest: row.get(9)?,
                    next_root_height: row.get(10)?,
                    next_root_header_hash: row.get(11)?,
                    next_root_block_json: row.get(12)?,
                    next_root_digest: row.get(13)?,
                    checkpoint_generation: row.get(14)?,
                })
            },
        )
        .optional()
        .map_err(CoordinatorError::from)
}

fn open_connection(path: &Path, config: &CoordinatorConfig, create: bool) -> Result<(Connection, File, File)> {
    let canonical_path = canonical_database_path(path)?;
    let lock_path = canonical_path.with_extension("cometbft-client.lock");
    let mut lock_options = OpenOptions::new();
    lock_options.read(true).write(true).create(true);
    #[cfg(unix)]
    lock_options
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    let lock = lock_options
        .open(&lock_path)
        .map_err(|_| CoordinatorError::StorageUnavailable)?;
    validate_regular_owner_only(&lock.metadata().map_err(|_| CoordinatorError::StorageUnavailable)?)?;
    lock.try_lock().map_err(|_| CoordinatorError::StorageUnavailable)?;

    let mut database_options = OpenOptions::new();
    database_options.read(true).write(true);
    #[cfg(unix)]
    database_options
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    let database_guard = if create {
        database_options.create_new(true);
        match database_options.open(&canonical_path) {
            Ok(file) => file,
            Err(error) if error.kind() == ErrorKind::AlreadyExists => {
                let mut existing_options = OpenOptions::new();
                existing_options.read(true).write(true);
                #[cfg(unix)]
                existing_options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
                existing_options
                    .open(&canonical_path)
                    .map_err(|_| CoordinatorError::StorageUnavailable)?
            }
            Err(_) => return Err(CoordinatorError::StorageUnavailable),
        }
    } else {
        database_options
            .open(&canonical_path)
            .map_err(|_| CoordinatorError::StorageUnavailable)?
    };
    let database_metadata = database_guard
        .metadata()
        .map_err(|_| CoordinatorError::StorageUnavailable)?;
    validate_regular_owner_only(&database_metadata)?;
    let database_identity = FileIdentity::from_metadata(&database_metadata);
    let flags = OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NOFOLLOW | OpenFlags::SQLITE_OPEN_FULL_MUTEX;
    let connection = Connection::open_with_flags(&canonical_path, flags).map_err(CoordinatorError::Storage)?;
    if inspect_file_identity(&canonical_path)? != database_identity
        || canonical_database_path(&canonical_path)? != canonical_path
    {
        return Err(CoordinatorError::StorageUnavailable);
    }
    connection.busy_timeout(config.busy_timeout())?;
    Ok((connection, database_guard, lock))
}

fn configure_connection(connection: &Connection, config: &CoordinatorConfig) -> Result<()> {
    connection.busy_timeout(config.busy_timeout())?;
    connection.pragma_update(None, "journal_mode", "WAL")?;
    let journal: String = connection.pragma_query_value(None, "journal_mode", |row| row.get(0))?;
    if !journal.eq_ignore_ascii_case("wal") {
        return Err(CoordinatorError::StorageUnavailable);
    }
    connection.pragma_update(None, "synchronous", "FULL")?;
    let synchronous: i64 = connection.pragma_query_value(None, "synchronous", |row| row.get(0))?;
    if synchronous != 2 {
        return Err(CoordinatorError::StorageUnavailable);
    }
    connection.pragma_update(None, "foreign_keys", "ON")?;
    connection.pragma_update(None, "trusted_schema", "OFF")?;
    Ok(())
}

fn validate_pristine_database(connection: &Connection) -> Result<()> {
    let application_id: i64 = connection.pragma_query_value(None, "application_id", |row| row.get(0))?;
    let user_version: i64 = connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
    let object_count: i64 = connection.query_row(
        "SELECT COUNT(*) FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%'",
        [],
        |row| row.get(0),
    )?;
    if application_id != 0 || user_version != 0 || object_count != 0 {
        return Err(CoordinatorError::StorageUnavailable);
    }
    Ok(())
}

#[cfg(test)]
pub(crate) fn inject_bootstrap_ambiguous_rollback_once() {
    FAIL_BOOTSTRAP_AS_AMBIGUOUS_ROLLBACK.with(|flag| flag.set(true));
}

#[cfg(test)]
pub(crate) fn rewrite_old_proof_and_local_checkpoint_chain_for_test(
    path: &Path,
    config: &CoordinatorConfig,
) -> Result<()> {
    let mut connection = Connection::open(path)?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let proof_row: TamperProofRow = transaction.query_row(
        "SELECT source_configurations.config_digest, finality_updates.prior_root_digest,
                finality_updates.next_root_digest, finality_updates.proof_bundle_json,
                finality_updates.summary_blob
         FROM finality_updates
         JOIN source_configurations ON source_configurations.version = finality_updates.config_version
         WHERE finality_updates.checkpoint_generation = 1",
        [],
        |row| {
            Ok(TamperProofRow {
                config_digest: row.get(0)?,
                prior_root: row.get(1)?,
                next_root: row.get(2)?,
                bundle: row.get(3)?,
                summary: row.get(4)?,
            })
        },
    )?;
    let mut bundle: serde_json::Value = serde_json::from_slice(&proof_row.bundle)
        .map_err(|_| CoordinatorError::StorageCorrupt("test proof bundle cannot be decoded"))?;
    let provider = bundle
        .get_mut("witness_traces")
        .and_then(serde_json::Value::as_array_mut)
        .and_then(|traces| traces.first_mut())
        .and_then(serde_json::Value::as_array_mut)
        .and_then(|trace| trace.first_mut())
        .and_then(serde_json::Value::as_object_mut)
        .and_then(|block| block.get_mut("provider"))
        .ok_or(CoordinatorError::StorageCorrupt(
            "test witness provider path is missing",
        ))?;
    *provider = serde_json::Value::String("eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee".to_owned());
    let changed_bundle = serde_json::to_vec(&bundle)
        .map_err(|_| CoordinatorError::StorageCorrupt("test proof bundle cannot be encoded"))?;
    let config_digest = fixed::<32>(&proof_row.config_digest)?;
    let prior_root = fixed::<32>(&proof_row.prior_root)?;
    let next_root = fixed::<32>(&proof_row.next_root)?;
    let changed_proof = proof_digest(
        &config_digest,
        &prior_root,
        &next_root,
        &changed_bundle,
        &proof_row.summary,
    );
    let first_request_digest = request_index_manifest_digest(&transaction, config, 1, OPERATION_FINALITY)?;
    let first_operation = finality_operation_digest(&changed_proof, &first_request_digest);
    let bootstrap_digest: Vec<u8> = transaction.query_row(
        "SELECT candidate_digest FROM checkpoint_transitions WHERE generation = 0",
        [],
        |row| row.get(0),
    )?;
    let bootstrap = TrustCheckpoint::new(0, fixed::<32>(&bootstrap_digest)?);
    let first = checkpoint_digest(
        config,
        1,
        Some(bootstrap),
        OPERATION_FINALITY,
        &first_operation,
        &next_root,
        &config_digest,
    );
    let (second_proof_bytes, second_root_bytes): (Vec<u8>, Vec<u8>) = transaction.query_row(
        "SELECT proof_digest, next_root_digest FROM finality_updates WHERE checkpoint_generation = 2",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    let second_proof = fixed::<32>(&second_proof_bytes)?;
    let second_root = fixed::<32>(&second_root_bytes)?;
    let second_request_digest = request_index_manifest_digest(&transaction, config, 2, OPERATION_FINALITY)?;
    let second_operation = finality_operation_digest(&second_proof, &second_request_digest);
    let second = checkpoint_digest(
        config,
        2,
        Some(first),
        OPERATION_FINALITY,
        &second_operation,
        &second_root,
        &config_digest,
    );
    transaction.execute(
        "UPDATE finality_updates SET proof_bundle_json = ?1, proof_digest = ?2
         WHERE checkpoint_generation = 1",
        params![changed_bundle, changed_proof.as_slice()],
    )?;
    transaction.execute(
        "UPDATE checkpoint_transitions SET operation_digest = ?1, candidate_digest = ?2
         WHERE generation = 1",
        params![first_operation.as_slice(), first.state_digest().as_slice()],
    )?;
    transaction.execute(
        "UPDATE checkpoint_transitions SET expected_digest = ?1, candidate_digest = ?2
         WHERE generation = 2",
        params![first.state_digest().as_slice(), second.state_digest().as_slice()],
    )?;
    transaction.execute(
        "UPDATE coordinator_meta SET checkpoint_digest = ?1 WHERE singleton = 1",
        [second.state_digest().as_slice()],
    )?;
    transaction.commit()?;
    Ok(())
}

#[cfg(test)]
pub(crate) fn forge_latest_committing_block_for_test(
    path: &Path,
    config: &CoordinatorConfig,
    forged: &LightBlock,
) -> Result<()> {
    let mut connection = Connection::open(path)?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let proof_row: TamperProofRow = transaction.query_row(
        "SELECT source_configurations.config_digest, finality_updates.prior_root_digest,
                finality_updates.next_root_digest, finality_updates.proof_bundle_json,
                finality_updates.summary_blob
         FROM finality_updates
         JOIN source_configurations ON source_configurations.version = finality_updates.config_version
         WHERE finality_updates.checkpoint_generation = 1",
        [],
        |row| {
            Ok(TamperProofRow {
                config_digest: row.get(0)?,
                prior_root: row.get(1)?,
                next_root: row.get(2)?,
                bundle: row.get(3)?,
                summary: row.get(4)?,
            })
        },
    )?;
    let mut bundle: serde_json::Value = serde_json::from_slice(&proof_row.bundle)
        .map_err(|_| CoordinatorError::StorageCorrupt("test proof bundle cannot be decoded"))?;
    let forged_value = serde_json::to_value(forged)
        .map_err(|_| CoordinatorError::StorageCorrupt("test forged block cannot be encoded"))?;
    replace_last_trace_block(&mut bundle, "primary_trace", &forged_value)?;
    let witness_traces = bundle
        .get_mut("witness_traces")
        .and_then(serde_json::Value::as_array_mut)
        .ok_or(CoordinatorError::StorageCorrupt("test witness trace list is missing"))?;
    for witness in witness_traces {
        let last = witness
            .as_array_mut()
            .and_then(|trace| trace.last_mut())
            .ok_or(CoordinatorError::StorageCorrupt("test witness trace is empty"))?;
        *last = forged_value.clone();
    }
    let changed_bundle = serde_json::to_vec(&bundle)
        .map_err(|_| CoordinatorError::StorageCorrupt("test forged bundle cannot be encoded"))?;
    let forged_blob = encode_light_block(forged, config.max_trace_encoded_bytes())?;
    let forged_hash = header_hash(forged)?;
    let next_root = root_digest(
        config,
        forged.signed_header.header.height.value(),
        &forged_hash,
        &forged_blob,
    );
    let mut summary = decode_summary(&proof_row.summary)?;
    summary.committing_header_hash = forged_hash;
    let summary_blob = encode_summary(&summary)?;
    let config_digest = fixed::<32>(&proof_row.config_digest)?;
    let prior_root = fixed::<32>(&proof_row.prior_root)?;
    let proof = proof_digest(&config_digest, &prior_root, &next_root, &changed_bundle, &summary_blob);
    let request_digest = request_index_manifest_digest(&transaction, config, 1, OPERATION_FINALITY)?;
    let operation_digest = finality_operation_digest(&proof, &request_digest);
    let bootstrap_digest: Vec<u8> = transaction.query_row(
        "SELECT candidate_digest FROM checkpoint_transitions WHERE generation = 0",
        [],
        |row| row.get(0),
    )?;
    let bootstrap = TrustCheckpoint::new(0, fixed::<32>(&bootstrap_digest)?);
    let candidate = checkpoint_digest(
        config,
        1,
        Some(bootstrap),
        OPERATION_FINALITY,
        &operation_digest,
        &next_root,
        &config_digest,
    );
    transaction.execute(
        "UPDATE finality_updates
         SET proof_bundle_json = ?1, summary_blob = ?2, proof_digest = ?3,
             next_root_header_hash = ?4, next_root_block_json = ?5, next_root_digest = ?6
         WHERE checkpoint_generation = 1",
        params![
            changed_bundle,
            summary_blob,
            proof.as_slice(),
            forged_hash.as_slice(),
            forged_blob,
            next_root.as_slice(),
        ],
    )?;
    transaction.execute(
        "UPDATE checkpoint_transitions SET operation_digest = ?1, candidate_digest = ?2
         WHERE generation = 1",
        params![operation_digest.as_slice(), candidate.state_digest().as_slice()],
    )?;
    transaction.execute(
        "UPDATE coordinator_meta
         SET root_header_hash = ?1, root_block_json = ?2, root_digest = ?3, checkpoint_digest = ?4
         WHERE singleton = 1",
        params![
            forged_hash.as_slice(),
            encode_light_block(forged, config.max_trace_encoded_bytes())?,
            next_root.as_slice(),
            candidate.state_digest().as_slice(),
        ],
    )?;
    transaction.commit()?;
    Ok(())
}

#[cfg(test)]
fn replace_last_trace_block(
    bundle: &mut serde_json::Value,
    field: &str,
    replacement: &serde_json::Value,
) -> Result<()> {
    let last = bundle
        .get_mut(field)
        .and_then(serde_json::Value::as_array_mut)
        .and_then(|trace| trace.last_mut())
        .ok_or(CoordinatorError::StorageCorrupt("test primary trace is empty"))?;
    *last = replacement.clone();
    Ok(())
}

#[cfg(unix)]
fn canonical_database_path(path: &Path) -> Result<PathBuf> {
    if !path.is_absolute() {
        return Err(CoordinatorError::InvalidConfiguration("SQLite path must be absolute"));
    }
    let file_name = path.file_name().ok_or(CoordinatorError::InvalidConfiguration(
        "SQLite path must end in a filename",
    ))?;
    let parent =
        path.parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .ok_or(CoordinatorError::InvalidConfiguration(
                "SQLite path must have an explicit parent",
            ))?;
    let parent_metadata = fs::symlink_metadata(parent).map_err(|_| CoordinatorError::StorageUnavailable)?;
    validate_private_parent(&parent_metadata)?;
    let canonical_parent = fs::canonicalize(parent).map_err(|_| CoordinatorError::StorageUnavailable)?;
    validate_canonical_ancestry(&canonical_parent)?;
    Ok(canonical_parent.join(file_name))
}

#[cfg(not(unix))]
fn canonical_database_path(_path: &Path) -> Result<PathBuf> {
    Err(CoordinatorError::InvalidConfiguration(
        "secure SQLite trust-state paths currently require Unix file semantics",
    ))
}

#[cfg(unix)]
fn validate_private_parent(metadata: &Metadata) -> Result<()> {
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(CoordinatorError::StorageUnavailable);
    }
    if metadata.uid() != rustix::process::geteuid().as_raw() || metadata.permissions().mode() & 0o077 != 0 {
        return Err(CoordinatorError::StorageUnavailable);
    }
    Ok(())
}

#[cfg(unix)]
fn validate_canonical_ancestry(parent: &Path) -> Result<()> {
    let effective_uid = rustix::process::geteuid().as_raw();
    for ancestor in parent.ancestors() {
        let metadata = fs::symlink_metadata(ancestor).map_err(|_| CoordinatorError::StorageUnavailable)?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(CoordinatorError::StorageUnavailable);
        }
        if metadata.uid() != 0 && metadata.uid() != effective_uid {
            return Err(CoordinatorError::StorageUnavailable);
        }
        let mode = metadata.permissions().mode();
        if mode & 0o022 != 0 && mode & 0o1000 == 0 {
            return Err(CoordinatorError::StorageUnavailable);
        }
    }
    Ok(())
}

fn validate_regular_owner_only(metadata: &Metadata) -> Result<()> {
    if !metadata.is_file() {
        return Err(CoordinatorError::StorageUnavailable);
    }
    #[cfg(unix)]
    if metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.permissions().mode() & 0o077 != 0
        || metadata.permissions().mode() & 0o600 != 0o600
        || metadata.permissions().mode() & 0o100 != 0
    {
        return Err(CoordinatorError::StorageUnavailable);
    }
    Ok(())
}

fn inspect_file_identity(path: &Path) -> Result<FileIdentity> {
    let metadata = fs::symlink_metadata(path).map_err(|_| CoordinatorError::StorageUnavailable)?;
    if metadata.file_type().is_symlink() {
        return Err(CoordinatorError::StorageUnavailable);
    }
    validate_regular_owner_only(&metadata)?;
    Ok(FileIdentity::from_metadata(&metadata))
}

impl FileIdentity {
    fn from_metadata(metadata: &Metadata) -> Self {
        #[cfg(unix)]
        {
            Self {
                device: metadata.dev(),
                inode: metadata.ino(),
            }
        }
        #[cfg(not(unix))]
        {
            Self { length: metadata.len() }
        }
    }
}

fn validate_database_header(connection: &Connection) -> Result<()> {
    let application_id: i64 = connection.pragma_query_value(None, "application_id", |row| row.get(0))?;
    let user_version: i64 = connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
    if application_id != SQLITE_APPLICATION_ID || user_version != SCHEMA_VERSION {
        return Err(CoordinatorError::StorageCorrupt(
            "SQLite application or schema version differs",
        ));
    }
    Ok(())
}

fn validate_source_row(
    connection: &Connection,
    sources: &SourceConfiguration,
    expected_blob: &[u8],
    expected_digest: [u8; 32],
) -> Result<()> {
    let stored: (Vec<u8>, Vec<u8>) = connection
        .query_row(
            "SELECT config_blob, config_digest FROM source_configurations WHERE version = ?1",
            [to_i64(sources.version())?],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?
        .ok_or(CoordinatorError::StorageCorrupt("current source row is missing"))?;
    if stored.0 != expected_blob || fixed::<32>(&stored.1)? != expected_digest {
        return Err(CoordinatorError::StorageCorrupt("source configuration row differs"));
    }
    let decoded = decode_sources(&stored.0)?;
    if &decoded != sources {
        return Err(CoordinatorError::StorageCorrupt(
            "source configuration decoding differs",
        ));
    }
    Ok(())
}

fn validate_transaction_head(
    transaction: &Transaction<'_>,
    config: &CoordinatorConfig,
    head: &StoredHead,
    config_digest: &[u8; 32],
) -> Result<()> {
    let stored: (i64, Vec<u8>, i64, Vec<u8>, i64, Vec<u8>) = transaction.query_row(
        "SELECT root_height, root_digest, current_config_version, current_config_digest,
                checkpoint_generation, checkpoint_digest
         FROM coordinator_meta WHERE singleton = 1",
        [],
        |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
                row.get(5)?,
            ))
        },
    )?;
    if from_i64(stored.0)? != head.root.height()
        || fixed::<32>(&stored.1)? != head.digest
        || from_i64(stored.2)? != config.sources().version()
        || fixed::<32>(&stored.3)? != *config_digest
        || from_i64(stored.4)? != head.checkpoint.generation()
        || fixed::<32>(&stored.5)? != *head.checkpoint.state_digest()
    {
        return Err(CoordinatorError::IdempotencyConflict);
    }
    Ok(())
}

fn ensure_unsealed_capacity(
    connection: &Connection,
    config: &CoordinatorConfig,
    additional_transitions: usize,
    additional_proof_bytes: usize,
    additional_requests: usize,
) -> Result<()> {
    let last_sealed = connection
        .query_row(
            "SELECT last_generation FROM history_epoch_manifests
             ORDER BY manifest_generation DESC LIMIT 1",
            [],
            |row| row.get::<_, i64>(0),
        )
        .optional()?
        .unwrap_or(-1);
    let transition_count: i64 = connection.query_row(
        "SELECT COUNT(*) FROM checkpoint_transitions
         WHERE generation > ?1 AND operation_kind != ?2",
        params![last_sealed, OPERATION_HISTORY_MANIFEST],
        |row| row.get(0),
    )?;
    let (proof_bytes, requests): (i64, i64) = connection.query_row(
        "SELECT COALESCE(SUM(proof_byte_count), 0), COALESCE(SUM(request_count), 0)
         FROM finality_updates WHERE checkpoint_generation > ?1",
        [last_sealed],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    let transition_count = usize::try_from(transition_count)
        .map_err(|_| CoordinatorError::StorageCorrupt("unsealed transition count is invalid"))?;
    let proof_bytes = usize::try_from(proof_bytes)
        .map_err(|_| CoordinatorError::StorageCorrupt("unsealed proof byte count is invalid"))?;
    let requests =
        usize::try_from(requests).map_err(|_| CoordinatorError::StorageCorrupt("unsealed request count is invalid"))?;
    let exceeds = transition_count
        .checked_add(additional_transitions)
        .is_none_or(|count| count > config.history_limits().max_transitions())
        || proof_bytes
            .checked_add(additional_proof_bytes)
            .is_none_or(|bytes| bytes > config.history_limits().max_proof_bytes())
        || requests
            .checked_add(additional_requests)
            .is_none_or(|count| count > config.history_limits().max_requests());
    if exceeds {
        return Err(CoordinatorError::HistorySealRequired);
    }
    Ok(())
}

fn insert_request_indexes(transaction: &Transaction<'_>, execution: &ExecutedBlockV2) -> Result<()> {
    for (index, entry) in execution.entries().iter().enumerate() {
        let metadata = entry.metadata();
        let request = metadata.request_digest();
        let location = load_request_location(transaction, request)?.unwrap_or(RequestIndexLocation {
            execution_height: to_i64(execution.height())?,
            block_index: i64::try_from(index)
                .map_err(|_| CoordinatorError::InvalidInput("entry index does not fit SQLite"))?,
            channel_context_id: metadata.channel_context_id().as_bytes().to_vec(),
            participant_id: metadata.participant_id().as_bytes().to_vec(),
            proposal_digest: metadata.proposal_digest().as_bytes().to_vec(),
            entry_hash: metadata.entry_hash().as_bytes().to_vec(),
        });
        let mut ignored = Vec::new();
        append_request_location(&mut ignored, request, metadata, &location)?;
        transaction.execute(
            "INSERT OR IGNORE INTO request_index(request_digest, execution_height, block_index,
                                                 channel_context_id, participant_id, proposal_digest, entry_hash)
             VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                request.as_bytes().as_slice(),
                location.execution_height,
                location.block_index,
                location.channel_context_id,
                location.participant_id,
                location.proposal_digest,
                location.entry_hash,
            ],
        )?;
    }
    Ok(())
}

fn pending_request_index_digest(connection: &Connection, execution: &ExecutedBlockV2) -> Result<[u8; 32]> {
    let mut canonical = Vec::new();
    for (index, entry) in execution.entries().iter().enumerate() {
        let metadata = entry.metadata();
        let stored = load_request_location(connection, metadata.request_digest())?;
        let location = stored.unwrap_or(RequestIndexLocation {
            execution_height: to_i64(execution.height())?,
            block_index: i64::try_from(index)
                .map_err(|_| CoordinatorError::InvalidInput("entry index does not fit SQLite"))?,
            channel_context_id: metadata.channel_context_id().as_bytes().to_vec(),
            participant_id: metadata.participant_id().as_bytes().to_vec(),
            proposal_digest: metadata.proposal_digest().as_bytes().to_vec(),
            entry_hash: metadata.entry_hash().as_bytes().to_vec(),
        });
        append_request_location(&mut canonical, metadata.request_digest(), metadata, &location)?;
    }
    Ok(digest_parts(REQUEST_INDEX_DOMAIN, &[canonical.as_slice()]))
}

fn load_request_location(
    connection: &Connection,
    request_digest: &RequestDigestV2,
) -> Result<Option<RequestIndexLocation>> {
    let live: Option<RequestIndexLocation> = connection
        .query_row(
            "SELECT execution_height, block_index, channel_context_id, participant_id,
                    proposal_digest, entry_hash
             FROM request_index WHERE request_digest = ?1",
            [request_digest.as_bytes().as_slice()],
            |row| {
                Ok(RequestIndexLocation {
                    execution_height: row.get(0)?,
                    block_index: row.get(1)?,
                    channel_context_id: row.get(2)?,
                    participant_id: row.get(3)?,
                    proposal_digest: row.get(4)?,
                    entry_hash: row.get(5)?,
                })
            },
        )
        .optional()?;
    let archived: Option<RequestIndexLocation> = connection
        .query_row(
            "SELECT execution_height, block_index, channel_context_id, participant_id,
                    proposal_digest, entry_hash
             FROM history_manifest_requests WHERE request_digest = ?1
             ORDER BY manifest_generation ASC LIMIT 1",
            [request_digest.as_bytes().as_slice()],
            |row| {
                Ok(RequestIndexLocation {
                    execution_height: row.get(0)?,
                    block_index: row.get(1)?,
                    channel_context_id: row.get(2)?,
                    participant_id: row.get(3)?,
                    proposal_digest: row.get(4)?,
                    entry_hash: row.get(5)?,
                })
            },
        )
        .optional()?;
    if live.is_some() && archived.is_some() && live != archived {
        return Err(CoordinatorError::StorageCorrupt(
            "live and archived request locations differ",
        ));
    }
    Ok(archived.or(live))
}

fn append_request_location(
    canonical: &mut Vec<u8>,
    request_digest: &RequestDigestV2,
    metadata: &thunderbolt_ledger::ExecutedEntryMetadataV2,
    location: &RequestIndexLocation,
) -> Result<()> {
    if location.channel_context_id.as_slice() != metadata.channel_context_id().as_bytes()
        || location.participant_id.as_slice() != metadata.participant_id().as_bytes()
        || location.proposal_digest.as_slice() != metadata.proposal_digest().as_bytes()
        || location.entry_hash.as_slice() != metadata.entry_hash().as_bytes()
    {
        return Err(CoordinatorError::IdempotencyConflict);
    }
    canonical.extend_from_slice(request_digest.as_bytes());
    canonical.extend_from_slice(&from_i64(location.execution_height)?.to_be_bytes());
    canonical.extend_from_slice(
        &u64::try_from(location.block_index)
            .map_err(|_| CoordinatorError::StorageCorrupt("request block index is negative"))?
            .to_be_bytes(),
    );
    canonical.extend_from_slice(&location.channel_context_id);
    canonical.extend_from_slice(&location.participant_id);
    canonical.extend_from_slice(&location.proposal_digest);
    canonical.extend_from_slice(&location.entry_hash);
    Ok(())
}

fn finality_operation_digest(proof_digest: &[u8; 32], request_index_digest: &[u8; 32]) -> [u8; 32] {
    digest_parts(
        FINALITY_OPERATION_DOMAIN,
        &[proof_digest.as_slice(), request_index_digest.as_slice()],
    )
}

fn insert_checkpoint_transition(
    transaction: &Transaction<'_>,
    candidate: TrustCheckpoint,
    expected: Option<TrustCheckpoint>,
    operation_kind: i64,
    operation_digest: &[u8; 32],
) -> Result<()> {
    let expected_generation = expected.map(|checkpoint| to_i64(checkpoint.generation())).transpose()?;
    let expected_digest = expected.map(|checkpoint| checkpoint.state_digest().to_vec());
    transaction.execute(
        "INSERT INTO checkpoint_transitions(generation, expected_generation, expected_digest,
                                            candidate_digest, operation_kind, operation_digest)
         VALUES(?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            to_i64(candidate.generation())?,
            expected_generation,
            expected_digest,
            candidate.state_digest().as_slice(),
            operation_kind,
            operation_digest.as_slice(),
        ],
    )?;
    Ok(())
}

fn validate_current_checkpoint(
    connection: &Connection,
    config: &CoordinatorConfig,
    checkpoint: TrustCheckpoint,
    root_digest: &[u8; 32],
    config_digest: &[u8; 32],
) -> Result<(Option<TrustCheckpoint>, i64, [u8; 32])> {
    let stored: TransitionRow = connection
        .query_row(
            "SELECT expected_generation, expected_digest, candidate_digest,
                    operation_kind, operation_digest
             FROM checkpoint_transitions WHERE generation = ?1",
            [to_i64(checkpoint.generation())?],
            |row| {
                Ok(TransitionRow {
                    expected_generation: row.get(0)?,
                    expected_digest: row.get(1)?,
                    candidate_digest: row.get(2)?,
                    operation_kind: row.get(3)?,
                    operation_digest: row.get(4)?,
                })
            },
        )
        .optional()?
        .ok_or(CoordinatorError::StorageCorrupt(
            "current checkpoint transition is missing",
        ))?;
    let prior = match (stored.expected_generation, stored.expected_digest) {
        (None, None) => None,
        (Some(generation), Some(digest)) => Some(TrustCheckpoint::new(from_i64(generation)?, fixed::<32>(&digest)?)),
        _ => {
            return Err(CoordinatorError::StorageCorrupt(
                "current checkpoint predecessor is malformed",
            ));
        }
    };
    let operation_digest = fixed::<32>(&stored.operation_digest)?;
    match stored.operation_kind {
        OPERATION_BOOTSTRAP if checkpoint.generation() == 0 && prior.is_none() => {
            if operation_digest != digest_parts(PROOF_DOMAIN, &[root_digest, config_digest]) {
                return Err(CoordinatorError::StorageCorrupt("current bootstrap evidence differs"));
            }
        }
        OPERATION_FINALITY if checkpoint.generation() > 0 && prior.is_some() => {
            let execution_height: i64 = connection
                .query_row(
                    "SELECT execution_height FROM finality_updates WHERE checkpoint_generation = ?1",
                    [to_i64(checkpoint.generation())?],
                    |row| row.get(0),
                )
                .optional()?
                .ok_or(CoordinatorError::StorageCorrupt(
                    "current checkpoint finality update is missing",
                ))?;
            let execution_height = from_i64(execution_height)?;
            let row = load_update_row_by_height(connection, execution_height)?
                .ok_or(CoordinatorError::StorageCorrupt("current finality row disappeared"))?;
            if fixed::<32>(&row.next_root_digest)? != *root_digest {
                return Err(CoordinatorError::StorageCorrupt("current finality root digest differs"));
            }
            let historical = validate_stored_update(connection, config, execution_height, row)?;
            let request_digest =
                request_index_manifest_digest(connection, config, checkpoint.generation(), OPERATION_FINALITY)?;
            if finality_operation_digest(historical.proof_digest(), &request_digest) != operation_digest {
                return Err(CoordinatorError::StorageCorrupt(
                    "current finality proof digest differs",
                ));
            }
        }
        OPERATION_ROTATION if checkpoint.generation() > 0 && prior.is_some() => {
            let installed: Vec<u8> = connection
                .query_row(
                    "SELECT config_digest FROM source_configurations WHERE installed_generation = ?1",
                    [to_i64(checkpoint.generation())?],
                    |row| row.get(0),
                )
                .optional()?
                .ok_or(CoordinatorError::StorageCorrupt(
                    "current checkpoint rotation is missing",
                ))?;
            if fixed::<32>(&installed)? != *config_digest || operation_digest != *config_digest {
                return Err(CoordinatorError::StorageCorrupt(
                    "current checkpoint rotation digest differs",
                ));
            }
        }
        OPERATION_HISTORY_MANIFEST if checkpoint.generation() > 0 && prior.is_some() => {
            let _ = load_history_manifest(connection, checkpoint.generation(), &operation_digest)?;
        }
        _ => {
            return Err(CoordinatorError::StorageCorrupt(
                "current checkpoint operation is invalid",
            ));
        }
    }
    let candidate = checkpoint_digest(
        config,
        checkpoint.generation(),
        prior,
        stored.operation_kind,
        &operation_digest,
        root_digest,
        config_digest,
    );
    if candidate != checkpoint || fixed::<32>(&stored.candidate_digest)? != *checkpoint.state_digest() {
        return Err(CoordinatorError::StorageCorrupt("current checkpoint digest differs"));
    }
    Ok((prior, stored.operation_kind, operation_digest))
}

#[allow(clippy::too_many_arguments)]
fn authenticate_with_history_manifests(
    connection: &Connection,
    config: &CoordinatorConfig,
    target_generation: u64,
    execution_height: u64,
    proof_digest: &[u8; 32],
    current_checkpoint: TrustCheckpoint,
    current_root_digest: &[u8; 32],
    current_config_digest: &[u8; 32],
    latest_manifest: Option<(u64, [u8; 32])>,
) -> Result<Option<()>> {
    let Some((latest_generation, latest_digest)) = latest_manifest else {
        return Ok(None);
    };
    let containing: Option<(i64, Vec<u8>)> = connection
        .query_row(
            "SELECT manifest_generation, manifest_digest FROM history_epoch_manifests
             WHERE first_generation <= ?1 AND last_generation >= ?1
             ORDER BY manifest_generation ASC LIMIT 1",
            [to_i64(target_generation)?],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    let target_sealed = containing.is_some();
    let latest_loaded = load_history_manifest(connection, latest_generation, &latest_digest)?;
    if let Some((containing_generation, containing_digest)) = containing {
        let containing_generation = from_i64(containing_generation)?;
        let containing_digest = fixed::<32>(&containing_digest)?;
        let mut statement = connection.prepare(
            "SELECT manifest_generation, manifest_digest FROM history_epoch_manifests
             WHERE manifest_generation >= ?1 AND manifest_generation <= ?2
             ORDER BY manifest_generation ASC",
        )?;
        let rows = statement.query_map(
            params![to_i64(containing_generation)?, to_i64(latest_generation)?],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, Vec<u8>>(1)?)),
        )?;
        let mut previous = None;
        let mut first = true;
        let mut final_pair = None;
        let mut target_entry = None;
        for row in rows {
            let (generation, digest) = row?;
            let generation = from_i64(generation)?;
            let digest = fixed::<32>(&digest)?;
            let loaded = load_history_manifest(connection, generation, &digest)?;
            if first {
                if generation != containing_generation || digest != containing_digest {
                    return Err(CoordinatorError::StorageCorrupt("history manifest range start differs"));
                }
                target_entry = loaded
                    .decoded
                    .entries
                    .iter()
                    .find(|entry| entry.generation == target_generation)
                    .copied();
                first = false;
            } else if loaded.decoded.previous_digest != previous {
                return Err(CoordinatorError::StorageCorrupt(
                    "history manifest digest chain differs",
                ));
            }
            previous = Some(digest);
            final_pair = Some((generation, digest));
        }
        if final_pair != Some((latest_generation, latest_digest)) {
            return Err(CoordinatorError::StorageCorrupt(
                "history manifest chain does not reach the latest anchor",
            ));
        }
        let entry = target_entry.ok_or(CoordinatorError::StorageCorrupt(
            "history manifest does not contain the target generation",
        ))?;
        if entry.operation_kind != OPERATION_FINALITY
            || entry.operation_digest != finality_operation_digest(proof_digest, &entry.request_index_digest)
        {
            return Err(CoordinatorError::StorageCorrupt(
                "history manifest target proof differs",
            ));
        }
        let request_digest =
            archived_request_index_manifest_digest(connection, config, target_generation, containing_generation)?;
        if request_digest != entry.request_index_digest {
            return Err(CoordinatorError::StorageCorrupt(
                "history manifest request index differs",
            ));
        }
    }
    let tail = validate_checkpoint_tail_from_manifest(
        connection,
        config,
        latest_generation,
        &latest_digest,
        latest_loaded,
        current_checkpoint,
        current_root_digest,
        current_config_digest,
    )?;
    if !target_sealed && tail.get(&execution_height).is_none_or(|digest| digest != proof_digest) {
        return Err(CoordinatorError::StorageCorrupt(
            "unsealed historical proof is absent from the manifest tail",
        ));
    }
    Ok(Some(()))
}

fn archived_request_index_manifest_digest(
    connection: &Connection,
    config: &CoordinatorConfig,
    generation: u64,
    manifest_generation: u64,
) -> Result<[u8; 32]> {
    let execution_height: i64 = connection.query_row(
        "SELECT execution_height FROM finality_updates WHERE checkpoint_generation = ?1",
        [to_i64(generation)?],
        |row| row.get(0),
    )?;
    let execution_height = from_i64(execution_height)?;
    let row = load_update_row_by_height(connection, execution_height)?
        .ok_or(CoordinatorError::StorageCorrupt("manifested finality row is missing"))?;
    let historical = validate_stored_update(connection, config, execution_height, row)?;
    let mut canonical = Vec::new();
    for entry in historical.proof().execution().entries() {
        let metadata = entry.metadata();
        let location: RequestIndexLocation = connection
            .query_row(
                "SELECT execution_height, block_index, channel_context_id, participant_id,
                        proposal_digest, entry_hash
                 FROM history_manifest_requests
                 WHERE manifest_generation = ?1 AND request_digest = ?2",
                params![
                    to_i64(manifest_generation)?,
                    metadata.request_digest().as_bytes().as_slice()
                ],
                |row| {
                    Ok(RequestIndexLocation {
                        execution_height: row.get(0)?,
                        block_index: row.get(1)?,
                        channel_context_id: row.get(2)?,
                        participant_id: row.get(3)?,
                        proposal_digest: row.get(4)?,
                        entry_hash: row.get(5)?,
                    })
                },
            )
            .optional()?
            .ok_or(CoordinatorError::StorageCorrupt(
                "manifested request-index row is missing",
            ))?;
        if location.channel_context_id.as_slice() != metadata.channel_context_id().as_bytes()
            || location.participant_id.as_slice() != metadata.participant_id().as_bytes()
            || location.proposal_digest.as_slice() != metadata.proposal_digest().as_bytes()
            || location.entry_hash.as_slice() != metadata.entry_hash().as_bytes()
        {
            return Err(CoordinatorError::StorageCorrupt(
                "manifested request-index binding differs",
            ));
        }
        canonical.extend_from_slice(metadata.request_digest().as_bytes());
        canonical.extend_from_slice(&from_i64(location.execution_height)?.to_be_bytes());
        canonical.extend_from_slice(
            &u64::try_from(location.block_index)
                .map_err(|_| CoordinatorError::StorageCorrupt("manifested block index is negative"))?
                .to_be_bytes(),
        );
        canonical.extend_from_slice(&location.channel_context_id);
        canonical.extend_from_slice(&location.participant_id);
        canonical.extend_from_slice(&location.proposal_digest);
        canonical.extend_from_slice(&location.entry_hash);
    }
    Ok(digest_parts(REQUEST_INDEX_DOMAIN, &[canonical.as_slice()]))
}

#[allow(clippy::too_many_arguments)]
fn validate_checkpoint_tail_from_manifest(
    connection: &Connection,
    config: &CoordinatorConfig,
    manifest_generation: u64,
    manifest_digest: &[u8; 32],
    loaded_manifest: LoadedManifest,
    current_checkpoint: TrustCheckpoint,
    current_root_digest: &[u8; 32],
    current_config_digest: &[u8; 32],
) -> Result<BTreeMap<u64, [u8; 32]>> {
    let (manifest_transition, manifest_prior) = load_transition(connection, manifest_generation)?;
    let operation_digest = fixed::<32>(&manifest_transition.operation_digest)?;
    if manifest_transition.operation_kind != OPERATION_HISTORY_MANIFEST || operation_digest != *manifest_digest {
        return Err(CoordinatorError::StorageCorrupt(
            "latest manifest checkpoint transition differs",
        ));
    }
    let manifest_candidate = checkpoint_digest(
        config,
        manifest_generation,
        manifest_prior,
        OPERATION_HISTORY_MANIFEST,
        &operation_digest,
        &loaded_manifest.root_digest,
        &loaded_manifest.config_digest,
    );
    if fixed::<32>(&manifest_transition.candidate_digest)? != *manifest_candidate.state_digest() {
        return Err(CoordinatorError::StorageCorrupt(
            "latest manifest checkpoint digest differs",
        ));
    }
    let mut running_checkpoint = manifest_candidate;
    let mut running_root_digest = loaded_manifest.root_digest;
    let mut running_config_digest = loaded_manifest.config_digest;
    let mut authenticated_updates = BTreeMap::new();
    let first_tail = manifest_generation
        .checked_add(1)
        .ok_or(CoordinatorError::StorageCorrupt("manifest generation overflows"))?;
    for generation in first_tail..=current_checkpoint.generation() {
        let (transition, prior) = load_transition(connection, generation)?;
        if prior != Some(running_checkpoint) {
            return Err(CoordinatorError::StorageCorrupt(
                "manifest tail checkpoint predecessor differs",
            ));
        }
        let operation_digest = fixed::<32>(&transition.operation_digest)?;
        match transition.operation_kind {
            OPERATION_FINALITY => {
                let execution_height: i64 = connection
                    .query_row(
                        "SELECT execution_height FROM finality_updates WHERE checkpoint_generation = ?1",
                        [to_i64(generation)?],
                        |row| row.get(0),
                    )
                    .optional()?
                    .ok_or(CoordinatorError::StorageCorrupt(
                        "manifest tail finality update is missing",
                    ))?;
                let execution_height = from_i64(execution_height)?;
                let row = load_update_row_by_height(connection, execution_height)?
                    .ok_or(CoordinatorError::StorageCorrupt("manifest tail update disappeared"))?;
                if fixed::<32>(&row.prior_root_digest)? != running_root_digest {
                    return Err(CoordinatorError::StorageCorrupt("manifest tail prior root differs"));
                }
                let next_root = fixed::<32>(&row.next_root_digest)?;
                let historical = validate_stored_update(connection, config, execution_height, row)?;
                let request_digest = request_index_manifest_digest(connection, config, generation, OPERATION_FINALITY)?;
                if finality_operation_digest(historical.proof_digest(), &request_digest) != operation_digest {
                    return Err(CoordinatorError::StorageCorrupt(
                        "manifest tail finality digest differs",
                    ));
                }
                running_root_digest = next_root;
                authenticated_updates.insert(execution_height, *historical.proof_digest());
            }
            OPERATION_ROTATION => {
                let next_config: Vec<u8> = connection
                    .query_row(
                        "SELECT config_digest FROM source_configurations WHERE installed_generation = ?1",
                        [to_i64(generation)?],
                        |row| row.get(0),
                    )
                    .optional()?
                    .ok_or(CoordinatorError::StorageCorrupt("manifest tail rotation is missing"))?;
                running_config_digest = fixed::<32>(&next_config)?;
                if running_config_digest != operation_digest {
                    return Err(CoordinatorError::StorageCorrupt(
                        "manifest tail rotation digest differs",
                    ));
                }
            }
            OPERATION_HISTORY_MANIFEST => {
                let _ = load_history_manifest(connection, generation, &operation_digest)?;
            }
            _ => {
                return Err(CoordinatorError::StorageCorrupt(
                    "manifest tail operation kind is invalid",
                ));
            }
        }
        let candidate = checkpoint_digest(
            config,
            generation,
            Some(running_checkpoint),
            transition.operation_kind,
            &operation_digest,
            &running_root_digest,
            &running_config_digest,
        );
        if fixed::<32>(&transition.candidate_digest)? != *candidate.state_digest() {
            return Err(CoordinatorError::StorageCorrupt(
                "manifest tail checkpoint digest differs",
            ));
        }
        running_checkpoint = candidate;
    }
    if running_checkpoint != current_checkpoint
        || running_root_digest != *current_root_digest
        || running_config_digest != *current_config_digest
    {
        return Err(CoordinatorError::StorageCorrupt("manifest tail terminal state differs"));
    }
    Ok(authenticated_updates)
}

fn load_transition(connection: &Connection, generation: u64) -> Result<(TransitionRow, Option<TrustCheckpoint>)> {
    let transition: TransitionRow = connection
        .query_row(
            "SELECT expected_generation, expected_digest, candidate_digest,
                    operation_kind, operation_digest
             FROM checkpoint_transitions WHERE generation = ?1",
            [to_i64(generation)?],
            |row| {
                Ok(TransitionRow {
                    expected_generation: row.get(0)?,
                    expected_digest: row.get(1)?,
                    candidate_digest: row.get(2)?,
                    operation_kind: row.get(3)?,
                    operation_digest: row.get(4)?,
                })
            },
        )
        .optional()?
        .ok_or(CoordinatorError::StorageCorrupt("checkpoint transition is missing"))?;
    let prior = match (&transition.expected_generation, &transition.expected_digest) {
        (None, None) => None,
        (Some(generation), Some(digest)) => Some(TrustCheckpoint::new(from_i64(*generation)?, fixed::<32>(digest)?)),
        _ => {
            return Err(CoordinatorError::StorageCorrupt(
                "checkpoint transition predecessor is malformed",
            ));
        }
    };
    Ok((transition, prior))
}

fn validate_checkpoint_chain(
    connection: &Connection,
    config: &CoordinatorConfig,
    checkpoint: TrustCheckpoint,
    current_root_digest: &[u8; 32],
    current_config_digest: &[u8; 32],
) -> Result<BTreeMap<u64, [u8; 32]>> {
    let transition_count: i64 = connection.query_row(
        "SELECT COUNT(*) FROM checkpoint_transitions WHERE generation <= ?1",
        [to_i64(checkpoint.generation())?],
        |row| row.get(0),
    )?;
    let expected_count = checkpoint
        .generation()
        .checked_add(1)
        .ok_or(CoordinatorError::StorageCorrupt("checkpoint generation overflows"))?;
    if from_i64(transition_count)? != expected_count {
        return Err(CoordinatorError::StorageCorrupt(
            "checkpoint transition count or generation has a gap",
        ));
    }
    let bootstrap_config_digest: Vec<u8> = connection
        .query_row(
            "SELECT config_digest FROM source_configurations WHERE installed_generation = 0",
            [],
            |row| row.get(0),
        )
        .optional()?
        .ok_or(CoordinatorError::StorageCorrupt(
            "bootstrap source configuration is missing",
        ))?;
    let mut running_config_digest = fixed::<32>(&bootstrap_config_digest)?;
    let first_prior_root: Option<Vec<u8>> = connection
        .query_row(
            "SELECT prior_root_digest FROM finality_updates ORDER BY checkpoint_generation ASC LIMIT 1",
            [],
            |row| row.get(0),
        )
        .optional()?;
    let mut running_root_digest = first_prior_root
        .as_deref()
        .map(fixed::<32>)
        .transpose()?
        .unwrap_or(*current_root_digest);
    let mut running_checkpoint = None;
    let mut authenticated_updates = BTreeMap::new();
    let mut rotation_count = 0_u64;

    for generation in 0..=checkpoint.generation() {
        let stored: TransitionRow = connection
            .query_row(
                "SELECT expected_generation, expected_digest, candidate_digest,
                        operation_kind, operation_digest
                 FROM checkpoint_transitions WHERE generation = ?1",
                [to_i64(generation)?],
                |row| {
                    Ok(TransitionRow {
                        expected_generation: row.get(0)?,
                        expected_digest: row.get(1)?,
                        candidate_digest: row.get(2)?,
                        operation_kind: row.get(3)?,
                        operation_digest: row.get(4)?,
                    })
                },
            )
            .optional()?
            .ok_or(CoordinatorError::StorageCorrupt("checkpoint transition is missing"))?;
        let stored_prior = match (stored.expected_generation, stored.expected_digest) {
            (None, None) => None,
            (Some(prior_generation), Some(prior_digest)) => Some(TrustCheckpoint::new(
                from_i64(prior_generation)?,
                fixed::<32>(&prior_digest)?,
            )),
            _ => {
                return Err(CoordinatorError::StorageCorrupt(
                    "checkpoint expected value is malformed",
                ));
            }
        };
        if stored_prior != running_checkpoint {
            return Err(CoordinatorError::StorageCorrupt("checkpoint predecessor chain differs"));
        }
        let operation_digest = fixed::<32>(&stored.operation_digest)?;
        match stored.operation_kind {
            OPERATION_BOOTSTRAP if generation == 0 => {
                let expected = digest_parts(
                    PROOF_DOMAIN,
                    &[running_root_digest.as_slice(), running_config_digest.as_slice()],
                );
                if operation_digest != expected {
                    return Err(CoordinatorError::StorageCorrupt(
                        "bootstrap checkpoint evidence differs",
                    ));
                }
            }
            OPERATION_FINALITY if generation > 0 => {
                let execution_height: i64 = connection
                    .query_row(
                        "SELECT execution_height FROM finality_updates WHERE checkpoint_generation = ?1",
                        [to_i64(generation)?],
                        |row| row.get(0),
                    )
                    .optional()?
                    .ok_or(CoordinatorError::StorageCorrupt(
                        "checkpoint finality update is missing",
                    ))?;
                let execution_height = from_i64(execution_height)?;
                let row = load_update_row_by_height(connection, execution_height)?
                    .ok_or(CoordinatorError::StorageCorrupt("checkpoint update disappeared"))?;
                if from_i64(row.checkpoint_generation)? != generation
                    || fixed::<32>(&row.prior_root_digest)? != running_root_digest
                {
                    return Err(CoordinatorError::StorageCorrupt(
                        "checkpoint finality root binding differs",
                    ));
                }
                let next_root = fixed::<32>(&row.next_root_digest)?;
                let historical = validate_stored_update(connection, config, execution_height, row)?;
                let request_digest = request_index_manifest_digest(connection, config, generation, OPERATION_FINALITY)?;
                if finality_operation_digest(historical.proof_digest(), &request_digest) != operation_digest {
                    return Err(CoordinatorError::StorageCorrupt(
                        "checkpoint finality proof digest differs",
                    ));
                }
                running_root_digest = next_root;
                authenticated_updates.insert(execution_height, *historical.proof_digest());
            }
            OPERATION_ROTATION if generation > 0 => {
                let next_config: Vec<u8> = connection
                    .query_row(
                        "SELECT config_digest FROM source_configurations WHERE installed_generation = ?1",
                        [to_i64(generation)?],
                        |row| row.get(0),
                    )
                    .optional()?
                    .ok_or(CoordinatorError::StorageCorrupt(
                        "checkpoint source rotation is missing",
                    ))?;
                let next_config = fixed::<32>(&next_config)?;
                if next_config != operation_digest {
                    return Err(CoordinatorError::StorageCorrupt(
                        "checkpoint source rotation digest differs",
                    ));
                }
                running_config_digest = next_config;
                rotation_count = rotation_count
                    .checked_add(1)
                    .ok_or(CoordinatorError::StorageCorrupt("rotation count overflows"))?;
            }
            OPERATION_HISTORY_MANIFEST if generation > 0 => {
                let _ = load_history_manifest(connection, generation, &operation_digest)?;
            }
            _ => {
                return Err(CoordinatorError::StorageCorrupt(
                    "checkpoint operation kind or generation is invalid",
                ));
            }
        }
        let candidate = checkpoint_digest(
            config,
            generation,
            running_checkpoint,
            stored.operation_kind,
            &operation_digest,
            &running_root_digest,
            &running_config_digest,
        );
        if fixed::<32>(&stored.candidate_digest)? != *candidate.state_digest() {
            return Err(CoordinatorError::StorageCorrupt("checkpoint candidate digest differs"));
        }
        running_checkpoint = Some(candidate);
    }
    let update_count: i64 = connection.query_row(
        "SELECT COUNT(*) FROM finality_updates WHERE checkpoint_generation <= ?1",
        [to_i64(checkpoint.generation())?],
        |row| row.get(0),
    )?;
    let source_count: i64 = connection.query_row(
        "SELECT COUNT(*) FROM source_configurations WHERE installed_generation <= ?1",
        [to_i64(checkpoint.generation())?],
        |row| row.get(0),
    )?;
    if running_checkpoint != Some(checkpoint)
        || running_root_digest != *current_root_digest
        || running_config_digest != *current_config_digest
        || from_i64(update_count)?
            != u64::try_from(authenticated_updates.len())
                .map_err(|_| CoordinatorError::StorageCorrupt("authenticated update count overflows"))?
        || from_i64(source_count)?
            != rotation_count
                .checked_add(1)
                .ok_or(CoordinatorError::StorageCorrupt("source count overflows"))?
    {
        return Err(CoordinatorError::StorageCorrupt(
            "anchored checkpoint graph terminal state differs",
        ));
    }
    Ok(authenticated_updates)
}

fn validate_stored_update(
    connection: &Connection,
    config: &CoordinatorConfig,
    execution_height: u64,
    row: StoredUpdateRow,
) -> Result<HistoricalFinality> {
    let config_version = from_i64(row.config_version)?;
    let (source_blob, stored_source_digest): (Vec<u8>, Vec<u8>) = connection
        .query_row(
            "SELECT config_blob, config_digest FROM source_configurations WHERE version = ?1",
            [row.config_version],
            |sqlite_row| Ok((sqlite_row.get(0)?, sqlite_row.get(1)?)),
        )
        .optional()?
        .ok_or(CoordinatorError::StorageCorrupt(
            "proof source configuration is missing",
        ))?;
    let source_digest = source_digest(&source_blob);
    if fixed::<32>(&stored_source_digest)? != source_digest {
        return Err(CoordinatorError::StorageCorrupt(
            "proof source configuration digest differs",
        ));
    }
    let sources = decode_sources(&source_blob)?;
    sources.validate_policy(config.policy())?;
    if sources.version() != config_version {
        return Err(CoordinatorError::StorageCorrupt("proof source version differs"));
    }
    let prior_height = from_i64(row.prior_root_height)?;
    let prior_hash = fixed::<32>(&row.prior_root_header_hash)?;
    let prior_digest = fixed::<32>(&row.prior_root_digest)?;
    let proof = decode_bundle(&row.proof_bundle_json, config)?;
    if usize::try_from(row.proof_byte_count)
        .map_err(|_| CoordinatorError::StorageCorrupt("proof byte count is invalid"))?
        != row.proof_bundle_json.len()
        || usize::try_from(row.request_count)
            .map_err(|_| CoordinatorError::StorageCorrupt("request count is invalid"))?
            != proof.execution().entries().len()
    {
        return Err(CoordinatorError::StorageCorrupt("stored proof work counters differ"));
    }
    if proof.config_version() != config_version || proof.execution().height() != execution_height {
        return Err(CoordinatorError::StorageCorrupt("proof bundle identity differs"));
    }
    let trusted_blob = encode_light_block(proof.trusted_root(), config.max_trace_encoded_bytes())?;
    if root_digest(config, prior_height, &prior_hash, &trusted_blob) != prior_digest {
        return Err(CoordinatorError::StorageCorrupt("proof prior root digest differs"));
    }
    PinnedTrustRoot::new(
        proof.trusted_root().clone(),
        config.ledger_chain_id(),
        prior_height,
        prior_hash,
        config.policy(),
    )?;
    if fixed::<32>(&row.execution_digest)? != execution_digest(proof.execution())? {
        return Err(CoordinatorError::StorageCorrupt("execution digest differs"));
    }
    let summary = decode_summary(&row.summary_blob)?;
    let next_height = from_i64(row.next_root_height)?;
    let next_hash = fixed::<32>(&row.next_root_header_hash)?;
    let next_digest = fixed::<32>(&row.next_root_digest)?;
    if root_digest(config, next_height, &next_hash, &row.next_root_block_json) != next_digest {
        return Err(CoordinatorError::StorageCorrupt("next root digest differs"));
    }
    let next_block = decode_light_block(&row.next_root_block_json, config.max_trace_encoded_bytes())?;
    PinnedTrustRoot::new(
        next_block.clone(),
        config.ledger_chain_id(),
        next_height,
        next_hash,
        config.policy(),
    )?;
    validate_bundle_summary(config, &sources, prior_height, &proof, &summary, &next_block)?;
    let expected_proof_digest = proof_digest(
        &source_digest,
        &prior_digest,
        &next_digest,
        &row.proof_bundle_json,
        &row.summary_blob,
    );
    if fixed::<32>(&row.proof_digest)? != expected_proof_digest {
        return Err(CoordinatorError::StorageCorrupt("proof record digest differs"));
    }
    Ok(HistoricalFinality {
        summary,
        proof,
        proof_digest: expected_proof_digest,
    })
}

fn validate_bundle_summary(
    config: &CoordinatorConfig,
    sources: &SourceConfiguration,
    prior_height: u64,
    proof: &FinalityProofBundle,
    summary: &FinalitySummary,
    next_block: &LightBlock,
) -> Result<()> {
    if summary.ledger_chain_id() != config.ledger_chain_id()
        || summary.application_version() != THUNDERBOLT_APP_VERSION_V2
        || summary.config_version() != proof.config_version()
        || summary.execution_height() != proof.execution().height()
        || summary.execution_block_time_ms() != proof.execution().block_time_ms()
        || summary.application_hash() != proof.execution().app_hash()
        || summary.primary_peer_id() != sources.primary().node_id()
        || summary.witness_peer_ids().len() < config.policy().min_witnesses()
        || summary.witness_peer_ids().len() > config.policy().max_witnesses()
        || summary.witness_peer_ids().len() != proof.witness_traces().len()
    {
        return Err(CoordinatorError::StorageCorrupt("proof summary binding differs"));
    }
    let mut seen_witnesses = std::collections::BTreeSet::new();
    for witness in summary.witness_peer_ids() {
        if !seen_witnesses.insert(*witness)
            || !sources
                .witnesses()
                .iter()
                .any(|expected| expected.node_id() == *witness)
        {
            return Err(CoordinatorError::StorageCorrupt("proof witness subset differs"));
        }
    }
    let expected_len = summary
        .committing_height()
        .checked_sub(prior_height)
        .and_then(|value| usize::try_from(value).ok())
        .ok_or(CoordinatorError::StorageCorrupt("proof trace distance is invalid"))?;
    if proof.primary_trace().len() != expected_len
        || proof.witness_traces().iter().any(|trace| trace.len() != expected_len)
        || proof.primary_trace().last() != Some(next_block)
        || summary.committing_height() != next_block.signed_header.header.height.value()
        || header_hash(next_block)? != *summary.committing_header_hash()
    {
        return Err(CoordinatorError::StorageCorrupt("proof trace or next root differs"));
    }
    let execution_block = if prior_height == proof.execution().height() {
        proof.trusted_root()
    } else {
        let offset = proof
            .execution()
            .height()
            .checked_sub(prior_height)
            .and_then(|distance| distance.checked_sub(1))
            .and_then(|index| usize::try_from(index).ok())
            .ok_or(CoordinatorError::StorageCorrupt("execution header position is invalid"))?;
        proof
            .primary_trace()
            .get(offset)
            .ok_or(CoordinatorError::StorageCorrupt("execution header is missing"))?
    };
    if header_hash(execution_block)? != *summary.execution_header_hash() {
        return Err(CoordinatorError::StorageCorrupt("execution header digest differs"));
    }
    Ok(())
}

pub(crate) fn execution_digest(execution: &ExecutedBlockV2) -> Result<[u8; 32]> {
    let encoded = serde_json::to_vec(execution)
        .map_err(|_| CoordinatorError::InvalidInput("execution output cannot be encoded"))?;
    Ok(digest_parts(EXECUTION_DOMAIN, &[encoded.as_slice()]))
}

pub(crate) fn source_configuration_digest(sources: &SourceConfiguration) -> Result<[u8; 32]> {
    Ok(source_digest(&encode_sources(sources)?))
}

fn encode_bundle(bundle: &FinalityProofBundle, limit: usize) -> Result<Vec<u8>> {
    let output = ProofBundleOutput {
        version: 1,
        config_version: bundle.config_version,
        trusted_root: &bundle.trusted_root,
        primary_trace: &bundle.primary_trace,
        witness_traces: &bundle.witness_traces,
        execution: &bundle.execution,
    };
    let encoded =
        serde_json::to_vec(&output).map_err(|_| CoordinatorError::InvalidInput("proof bundle cannot be encoded"))?;
    if encoded.is_empty() || encoded.len() > limit {
        return Err(CoordinatorError::InvalidInput("proof bundle exceeds its byte bound"));
    }
    Ok(encoded)
}

fn decode_bundle(encoded: &[u8], config: &CoordinatorConfig) -> Result<FinalityProofBundle> {
    if encoded.is_empty() || encoded.len() > config.max_proof_bundle_bytes() {
        return Err(CoordinatorError::StorageCorrupt("proof bundle byte length is invalid"));
    }
    let input: ProofBundleInput = serde_json::from_slice(encoded)
        .map_err(|_| CoordinatorError::StorageCorrupt("proof bundle cannot be decoded"))?;
    if input.version != 1
        || input.primary_trace.is_empty()
        || input.primary_trace.len() > config.policy().max_adjacent_headers()
        || input.witness_traces.len() < config.policy().min_witnesses()
        || input.witness_traces.len() > config.policy().max_witnesses()
        || input.witness_traces.iter().any(|trace| {
            trace.is_empty()
                || trace.len() != input.primary_trace.len()
                || trace.len() > config.policy().max_adjacent_headers()
        })
    {
        return Err(CoordinatorError::StorageCorrupt("proof bundle shape is invalid"));
    }
    Ok(FinalityProofBundle {
        config_version: input.config_version,
        trusted_root: input.trusted_root,
        primary_trace: input.primary_trace,
        witness_traces: input.witness_traces,
        execution: input.execution,
    })
}

fn encode_light_block(block: &LightBlock, limit: usize) -> Result<Vec<u8>> {
    let encoded =
        serde_json::to_vec(block).map_err(|_| CoordinatorError::InvalidInput("light block cannot be encoded"))?;
    if encoded.is_empty() || encoded.len() > limit {
        return Err(CoordinatorError::InvalidInput("light block exceeds its byte bound"));
    }
    Ok(encoded)
}

fn decode_light_block(encoded: &[u8], limit: usize) -> Result<LightBlock> {
    if encoded.is_empty() || encoded.len() > limit {
        return Err(CoordinatorError::StorageCorrupt("light-block byte length is invalid"));
    }
    serde_json::from_slice(encoded).map_err(|_| CoordinatorError::StorageCorrupt("light block cannot be decoded"))
}

fn encode_sources(sources: &SourceConfiguration) -> Result<Vec<u8>> {
    let witness_count = u8::try_from(sources.witnesses().len())
        .map_err(|_| CoordinatorError::InvalidConfiguration("witness count does not fit u8"))?;
    let mut output = Vec::with_capacity(8 + 8 + 52 * (sources.witnesses().len() + 1));
    output.extend_from_slice(SOURCE_MAGIC);
    output.extend_from_slice(&sources.version().to_be_bytes());
    encode_peer(&mut output, sources.primary());
    output.push(witness_count);
    for witness in sources.witnesses() {
        encode_peer(&mut output, witness);
    }
    Ok(output)
}

fn encode_peer(output: &mut Vec<u8>, peer: &PeerIdentity) {
    output.extend_from_slice(peer.transport_binding());
    output.extend_from_slice(peer.node_id().as_bytes());
}

fn decode_sources(encoded: &[u8]) -> Result<SourceConfiguration> {
    let mut reader = Reader::new(encoded);
    if reader.take::<8>()? != *SOURCE_MAGIC {
        return Err(CoordinatorError::StorageCorrupt("source configuration magic differs"));
    }
    let version = u64::from_be_bytes(reader.take::<8>()?);
    let primary = decode_peer(&mut reader)?;
    let witness_count = usize::from(reader.byte()?);
    if witness_count == 0 || witness_count > thunderbolt_cometbft::MAX_WITNESSES {
        return Err(CoordinatorError::StorageCorrupt("source witness count is invalid"));
    }
    let mut witnesses = Vec::with_capacity(witness_count);
    for _ in 0..witness_count {
        witnesses.push(decode_peer(&mut reader)?);
    }
    if !reader.is_empty() {
        return Err(CoordinatorError::StorageCorrupt(
            "source configuration has trailing bytes",
        ));
    }
    SourceConfiguration::new(version, primary, witnesses)
        .map_err(|_| CoordinatorError::StorageCorrupt("source configuration fields are invalid"))
}

fn decode_peer(reader: &mut Reader<'_>) -> Result<PeerIdentity> {
    let binding = reader.take::<32>()?;
    let node_id = NodeId::new(reader.take::<20>()?);
    PeerIdentity::new(binding, node_id).map_err(|_| CoordinatorError::StorageCorrupt("source peer identity is invalid"))
}

fn encode_summary(summary: &FinalitySummary) -> Result<Vec<u8>> {
    let chain = summary.ledger_chain_id().as_str().as_bytes();
    let chain_len = u8::try_from(chain.len())
        .map_err(|_| CoordinatorError::InvalidInput("Ledger chain id length does not fit u8"))?;
    let witness_count = u8::try_from(summary.witness_peer_ids().len())
        .map_err(|_| CoordinatorError::InvalidInput("witness count does not fit u8"))?;
    let mut output = Vec::with_capacity(200);
    output.extend_from_slice(SUMMARY_MAGIC);
    output.push(chain_len);
    output.extend_from_slice(chain);
    output.extend_from_slice(&summary.application_version().to_be_bytes());
    output.extend_from_slice(&summary.config_version().to_be_bytes());
    output.extend_from_slice(&summary.execution_height().to_be_bytes());
    output.extend_from_slice(&summary.execution_block_time_ms().to_be_bytes());
    output.extend_from_slice(summary.application_hash().as_bytes());
    output.extend_from_slice(summary.execution_header_hash());
    output.extend_from_slice(&summary.committing_height().to_be_bytes());
    output.extend_from_slice(summary.committing_header_hash());
    output.extend_from_slice(summary.primary_peer_id().as_bytes());
    output.push(witness_count);
    for witness in summary.witness_peer_ids() {
        output.extend_from_slice(witness.as_bytes());
    }
    Ok(output)
}

fn decode_summary(encoded: &[u8]) -> Result<FinalitySummary> {
    let mut reader = Reader::new(encoded);
    if reader.take::<8>()? != *SUMMARY_MAGIC {
        return Err(CoordinatorError::StorageCorrupt("summary magic differs"));
    }
    let chain_len = usize::from(reader.byte()?);
    let chain_bytes = reader.bytes(chain_len)?;
    let chain = std::str::from_utf8(chain_bytes)
        .map_err(|_| CoordinatorError::StorageCorrupt("summary chain id is not UTF-8"))?;
    let ledger_chain_id =
        LedgerChainIdV2::new(chain).map_err(|_| CoordinatorError::StorageCorrupt("summary chain id is invalid"))?;
    let application_version = u64::from_be_bytes(reader.take::<8>()?);
    let config_version = u64::from_be_bytes(reader.take::<8>()?);
    let execution_height = u64::from_be_bytes(reader.take::<8>()?);
    let execution_block_time_ms = u64::from_be_bytes(reader.take::<8>()?);
    let application_hash = AppHashV2::from_bytes(reader.take::<32>()?)
        .map_err(|_| CoordinatorError::StorageCorrupt("summary application hash is invalid"))?;
    let execution_header_hash = reader.take::<32>()?;
    let committing_height = u64::from_be_bytes(reader.take::<8>()?);
    let committing_header_hash = reader.take::<32>()?;
    let primary_peer_id = NodeId::new(reader.take::<20>()?);
    let witness_count = usize::from(reader.byte()?);
    if witness_count == 0 || witness_count > thunderbolt_cometbft::MAX_WITNESSES {
        return Err(CoordinatorError::StorageCorrupt("summary witness count is invalid"));
    }
    let mut witness_peer_ids = Vec::with_capacity(witness_count);
    for _ in 0..witness_count {
        witness_peer_ids.push(NodeId::new(reader.take::<20>()?));
    }
    if !reader.is_empty() {
        return Err(CoordinatorError::StorageCorrupt("summary has trailing bytes"));
    }
    Ok(FinalitySummary {
        ledger_chain_id,
        application_version,
        config_version,
        execution_height,
        execution_block_time_ms,
        application_hash,
        execution_header_hash,
        committing_height,
        committing_header_hash,
        primary_peer_id,
        witness_peer_ids,
    })
}

fn encode_policy(policy: FinalityPolicy) -> Vec<u8> {
    let mut encoded = Vec::with_capacity(49);
    encoded.extend_from_slice(&policy.trusting_period().as_secs().to_be_bytes());
    encoded.extend_from_slice(&u64::from(policy.trusting_period().subsec_nanos()).to_be_bytes());
    encoded.extend_from_slice(&policy.clock_drift().as_secs().to_be_bytes());
    encoded.extend_from_slice(&u64::from(policy.clock_drift().subsec_nanos()).to_be_bytes());
    encoded.extend_from_slice(&u64::try_from(policy.max_validators()).unwrap_or(u64::MAX).to_be_bytes());
    encoded.extend_from_slice(
        &u64::try_from(policy.max_adjacent_headers())
            .unwrap_or(u64::MAX)
            .to_be_bytes(),
    );
    encoded.extend_from_slice(&u64::try_from(policy.min_witnesses()).unwrap_or(u64::MAX).to_be_bytes());
    encoded.extend_from_slice(&u64::try_from(policy.max_witnesses()).unwrap_or(u64::MAX).to_be_bytes());
    encoded
}

fn encode_resource_limits(config: &CoordinatorConfig) -> Result<Vec<u8>> {
    let mut encoded = Vec::with_capacity(96);
    for value in [
        config.max_trace_encoded_bytes(),
        config.max_execution_encoded_bytes(),
        config.max_proof_bundle_bytes(),
        config.history_limits().max_transitions(),
        config.history_limits().max_proof_bytes(),
        config.history_limits().max_requests(),
    ] {
        encoded.extend_from_slice(
            &u64::try_from(value)
                .map_err(|_| CoordinatorError::InvalidConfiguration("resource limit does not fit u64"))?
                .to_be_bytes(),
        );
    }
    encoded.extend_from_slice(&config.operation_timeout().as_secs().to_be_bytes());
    encoded.extend_from_slice(&u64::from(config.operation_timeout().subsec_nanos()).to_be_bytes());
    Ok(encoded)
}

fn root_digest(config: &CoordinatorConfig, height: u64, header_hash: &[u8; 32], block_blob: &[u8]) -> [u8; 32] {
    let policy = encode_policy(config.policy());
    digest_parts(
        ROOT_DOMAIN,
        &[
            config.ledger_chain_id().as_str().as_bytes(),
            policy.as_slice(),
            &height.to_be_bytes(),
            header_hash,
            block_blob,
        ],
    )
}

fn source_digest(source_blob: &[u8]) -> [u8; 32] {
    digest_parts(SOURCE_DOMAIN, &[source_blob])
}

fn proof_digest(
    source_digest: &[u8; 32],
    prior_root_digest: &[u8; 32],
    next_root_digest: &[u8; 32],
    bundle_blob: &[u8],
    summary_blob: &[u8],
) -> [u8; 32] {
    digest_parts(
        PROOF_DOMAIN,
        &[
            source_digest,
            prior_root_digest,
            next_root_digest,
            bundle_blob,
            summary_blob,
        ],
    )
}

fn checkpoint_digest(
    config: &CoordinatorConfig,
    generation: u64,
    expected: Option<TrustCheckpoint>,
    operation_kind: i64,
    operation_digest: &[u8; 32],
    root_digest: &[u8; 32],
    config_digest: &[u8; 32],
) -> TrustCheckpoint {
    let mut expected_bytes = Vec::with_capacity(41);
    match expected {
        Some(checkpoint) => {
            expected_bytes.push(1);
            expected_bytes.extend_from_slice(&checkpoint.generation().to_be_bytes());
            expected_bytes.extend_from_slice(checkpoint.state_digest());
        }
        None => expected_bytes.push(0),
    }
    let policy = encode_policy(config.policy());
    let digest = digest_parts(
        CHECKPOINT_DOMAIN,
        &[
            config.identity().as_bytes(),
            config.ledger_chain_id().as_str().as_bytes(),
            policy.as_slice(),
            &generation.to_be_bytes(),
            expected_bytes.as_slice(),
            &operation_kind.to_be_bytes(),
            operation_digest,
            root_digest,
            config_digest,
        ],
    );
    TrustCheckpoint::new(generation, digest)
}

fn digest_parts(domain: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(u64::try_from(domain.len()).unwrap_or(u64::MAX).to_be_bytes());
    hasher.update(domain);
    for part in parts {
        hasher.update(u64::try_from(part.len()).unwrap_or(u64::MAX).to_be_bytes());
        hasher.update(part);
    }
    hasher.finalize().into()
}

fn header_hash(block: &LightBlock) -> Result<[u8; 32]> {
    let hash = catch_unwind(AssertUnwindSafe(|| block.signed_header.header.hash()))
        .map_err(|_| CoordinatorError::StorageCorrupt("stored header hashing unwound"))?;
    match hash {
        Hash::Sha256(bytes) => Ok(bytes),
        Hash::None => Err(CoordinatorError::StorageCorrupt("stored header hash is empty")),
    }
}

fn to_i64(value: u64) -> Result<i64> {
    i64::try_from(value).map_err(|_| CoordinatorError::InvalidInput("value does not fit SQLite INTEGER"))
}

fn from_i64(value: i64) -> Result<u64> {
    u64::try_from(value).map_err(|_| CoordinatorError::StorageCorrupt("negative SQLite integer"))
}

fn fixed<const N: usize>(bytes: &[u8]) -> Result<[u8; N]> {
    bytes
        .try_into()
        .map_err(|_| CoordinatorError::StorageCorrupt("fixed-width database field has wrong length"))
}

struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn byte(&mut self) -> Result<u8> {
        let byte = *self
            .bytes
            .get(self.offset)
            .ok_or(CoordinatorError::StorageCorrupt("record is truncated"))?;
        self.offset = self
            .offset
            .checked_add(1)
            .ok_or(CoordinatorError::StorageCorrupt("record offset overflow"))?;
        Ok(byte)
    }

    fn take<const N: usize>(&mut self) -> Result<[u8; N]> {
        let bytes = self.bytes(N)?;
        bytes
            .try_into()
            .map_err(|_| CoordinatorError::StorageCorrupt("record field has wrong length"))
    }

    fn bytes(&mut self, length: usize) -> Result<&'a [u8]> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(CoordinatorError::StorageCorrupt("record offset overflow"))?;
        let bytes = self
            .bytes
            .get(self.offset..end)
            .ok_or(CoordinatorError::StorageCorrupt("record is truncated"))?;
        self.offset = end;
        Ok(bytes)
    }

    fn is_empty(&self) -> bool {
        self.offset == self.bytes.len()
    }
}
