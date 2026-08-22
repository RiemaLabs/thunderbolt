use std::collections::BTreeMap;
use std::error::Error;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Barrier};

use bitcoin::Network;
use proptest::prelude::*;
use secp::Scalar;
use secp256k1::{Keypair, Secp256k1, SecretKey};
use sha2::{Digest as _, Sha256};
use tempfile::TempDir;
use thunderbolt_committee::insecure_regtest::dealer_bootstrap;
use thunderbolt_committee::{
    CommitteeEpoch, CommitteeMemberEngine, CommitteeMemberId, CommitteeVault, KeystoreCommitteeVault, VaultEntry,
    VaultPlaintext, VaultStoreError,
};
use thunderbolt_keystore::{
    CheckpointCasOutcome, KdfParams, Password, RollbackFloorStore, VaultCheckpoint, VaultIdentity,
    MIN_ARGON2_ITERATIONS, MIN_ARGON2_MEMORY_KIB,
};
use thunderbolt_ledger::{
    ActorKeyAlgorithmV2, ActorPublicKeyV2, ActorRoleV2, ActorSignatureV2, AppHashV2, CanonicalEventV2,
    ClientRequestNonceV2, EntryHashV2, ExecutedBlockCommitmentV2, ExecutedBlockV2, LedgerChainIdV2, PendingBlockV2,
    ProposalBodyV2, SignedProposalV2,
};
use thunderbolt_protocol::v2::{ArtifactV2, ChannelEventV2, InvoiceEventV2, TransferEventV2};
use thunderbolt_wire::{
    to_json_vec, AnchorParameterSuiteIdV2, AnchorTransitionV2, BitcoinGenesisHashV2, ChannelBindingV2,
    CommitteeDescriptorDigestV2, FundingOutpointV2, OperationBindingV2, PaillierCiphertextBytesV2,
    PaillierModulusBytesV2, PaillierModulusProfileV2, PaillierNonceBytesV2, PointHex, ProofResponseBytesV2,
    ProtocolSuiteIdV2, PublicMessageV2, RecipientShareEnvelopeV2, RecipientShareStatementV2, ShareProofV2,
    ThresholdDistributionV2, ThresholdEncryptedShareV2, ThresholdEnvelopeV2, ThresholdPackageBindingV2,
    ThresholdRosterMemberV2, ThresholdRosterV2, TransferEnvelopeV2, TransferProofV2, TransferStatementV2,
    PAILLIER_V2_CIPHERTEXT_BYTES, PAILLIER_V2_MODULUS_BYTES, PROOF_RESPONSE_V2_BYTES, RECIPIENT_SHARE_MEMBER_ID,
};

use crate::storage::{InboxWrite, PendingInvoiceWrite, ScanCommit, ScanCommitOutcome, SqliteQueue};
use crate::*;

fn config() -> Result<NodeConfig> {
    NodeConfig::new(
        LedgerChainIdV2::new("committee-node-regtest").map_err(|_| NodeError::InvalidLedgerArtifact)?,
        FinalityVerifierProfileId::new([0x81; 32])?,
        FinalityCoordinatorId::new([0x91; 32])?,
        32,
        32,
        8,
    )
}

fn open_queue(directory: &TempDir) -> Result<SqliteQueue> {
    let path = temp_path(directory, "committee-node.sqlite")
        .map_err(|_| NodeError::InvalidConfiguration("test directory cannot be canonicalized"))?;
    open_queue_path(path)
}

fn temp_path(directory: &TempDir, name: &str) -> std::io::Result<std::path::PathBuf> {
    use std::os::unix::fs::PermissionsExt as _;

    let root = std::fs::canonicalize(directory.path())?;
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700))?;
    Ok(root.join(name))
}

fn open_queue_path(path: impl AsRef<std::path::Path>) -> Result<SqliteQueue> {
    SqliteQueue::open(path, &config()?, b"deployment", 7, &[0x41; 32], 1)
}

#[test]
fn network_and_sqlite_identity_fail_closed() -> std::result::Result<(), Box<dyn Error>> {
    assert!(NodeConfig::validate_network(Network::Regtest).is_ok());
    assert!(NodeConfig::validate_network(Network::Bitcoin).is_err());
    assert!(NodeConfig::validate_network(Network::Testnet4).is_err());
    let directory = TempDir::new()?;
    let path = temp_path(&directory, "committee-node.sqlite")?;
    drop(SqliteQueue::open(&path, &config()?, b"deployment", 7, &[0x41; 32], 1)?);
    assert!(matches!(
        SqliteQueue::open(&path, &config()?, b"other", 7, &[0x41; 32], 1),
        Err(NodeError::IdentityMismatch)
    ));
    let wrong_profile = NodeConfig::new(
        LedgerChainIdV2::new("committee-node-regtest")?,
        FinalityVerifierProfileId::new([0x82; 32])?,
        FinalityCoordinatorId::new([0x91; 32])?,
        32,
        32,
        8,
    )?;
    assert!(matches!(
        SqliteQueue::open(&path, &wrong_profile, b"deployment", 7, &[0x41; 32], 1),
        Err(NodeError::IdentityMismatch)
    ));
    Ok(())
}

#[cfg(unix)]
#[test]
fn durable_sqlite_path_rejects_ephemeral_alias_and_unsafe_modes_and_restarts() -> std::result::Result<(), Box<dyn Error>>
{
    use std::os::unix::fs::{symlink, PermissionsExt as _};

    assert!(open_queue_path(":memory:").is_err());
    assert!(open_queue_path("relative.sqlite").is_err());
    let directory = TempDir::new()?;
    let path = temp_path(&directory, "durable.sqlite")?;
    let queue = open_queue_path(&path)?;
    let (staged, next) = dummy_stage(&queue, 1, EntryHashV2::from_bytes([0x45; 32])?)?;
    queue.commit_scan(dummy_scan(None, &next, &staged, [0x42; 32], b"durable-record".to_vec()))?;
    drop(queue);
    let reopened = open_queue_path(&path)?;
    assert_eq!(reopened.cursor()?, Some(next));
    drop(reopened);

    let link = temp_path(&directory, "symlink.sqlite")?;
    symlink(&path, &link)?;
    assert!(open_queue_path(&link).is_err());
    let hardlink = temp_path(&directory, "hardlink.sqlite")?;
    std::fs::hard_link(&path, &hardlink)?;
    assert!(open_queue_path(&path).is_err());
    std::fs::remove_file(&hardlink)?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644))?;
    assert!(open_queue_path(&path).is_err());
    Ok(())
}

#[cfg(unix)]
#[test]
fn staged_recovery_handoff_rejects_valid_replacement_and_copied_database() -> std::result::Result<(), Box<dyn Error>> {
    let directory = TempDir::new()?;
    let path = temp_path(&directory, "staged.sqlite")?;
    let runtime = test_runtime()?;
    let descriptor = runtime.descriptor();
    let deployment_id = descriptor.deployment_id().to_vec();
    let epoch = descriptor.epoch().get();
    let descriptor_id = *descriptor.id().as_bytes();
    let member_id = runtime.member_id().get();
    let queue = SqliteQueue::open(&path, &config()?, &deployment_id, epoch, &descriptor_id, member_id)?;
    let first = PendingBlockV2::new(
        LedgerChainIdV2::new("committee-node-regtest")?,
        1,
        10,
        AppHashV2::zero(),
    )?
    .execute()?;
    let second = PendingBlockV2::new(
        LedgerChainIdV2::new("committee-node-regtest")?,
        1,
        11,
        AppHashV2::zero(),
    )?
    .execute()?;
    queue.stage_finality_range(&segment(vec![first])?)?;
    drop(queue);
    let original = CommitteeNode::inspect_staged_finality_recovery(&path, &runtime, &config()?)?
        .ok_or("original staged recovery")?;

    let queue = SqliteQueue::open(&path, &config()?, &deployment_id, epoch, &descriptor_id, member_id)?;
    rusqlite::Connection::open(&path)?.execute("DELETE FROM staged_finality_range", [])?;
    queue.stage_finality_range(&segment(vec![second])?)?;
    drop(queue);
    let replacement = CommitteeNode::inspect_staged_finality_recovery(&path, &runtime, &config()?)?
        .ok_or("replacement staged recovery")?;
    assert_ne!(replacement, original);
    assert!(matches!(
        CommitteeNode::open_with_staged_recovery(&path, runtime, config()?, &original),
        Err(NodeError::CursorConflict)
    ));

    rusqlite::Connection::open(&path)?.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")?;
    let copied = temp_path(&directory, "copied.sqlite")?;
    std::fs::copy(&path, &copied)?;
    assert!(matches!(
        SqliteQueue::open(&copied, &config()?, &deployment_id, epoch, &descriptor_id, member_id),
        Err(NodeError::IdentityMismatch)
    ));
    Ok(())
}

#[test]
fn legacy_rows_reject_and_empty_v2_migrates_to_staged_schema() -> std::result::Result<(), Box<dyn Error>> {
    let occupied = TempDir::new()?;
    let path = temp_path(&occupied, "committee-node.sqlite")?;
    drop(open_queue(&occupied)?);
    let connection = rusqlite::Connection::open(&path)?;
    connection.execute(
        "INSERT INTO inbox(item_id,invoice_entry_hash,request_digest,record_digest,record_json,status) VALUES(?1,?2,?3,?4,?5,0)",
        rusqlite::params![
            [1_u8; 32].as_slice(),
            [4_u8; 32].as_slice(),
            [2_u8; 32].as_slice(),
            [3_u8; 32].as_slice(),
            b"legacy"
        ],
    )?;
    connection.pragma_update(None, "user_version", 2)?;
    drop(connection);
    assert!(matches!(open_queue(&occupied), Err(NodeError::LegacyEvidenceRecords)));
    let connection = rusqlite::Connection::open(&path)?;
    let version: i64 = connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
    assert_eq!(version, 2);

    let advanced = TempDir::new()?;
    let advanced_path = temp_path(&advanced, "committee-node.sqlite")?;
    let advanced_queue = open_queue(&advanced)?;
    let (advanced_stage, advanced_cursor) = dummy_stage(&advanced_queue, 0, EntryHashV2::zero())?;
    advanced_queue.commit_scan(ScanCommit {
        expected_cursor: None,
        next_cursor: &advanced_cursor,
        staged: &advanced_stage,
        segment_digest: [0x7a; 32],
        expire_through_ms: 10,
        pending_writes: Vec::new(),
        pending_removals: Vec::new(),
        inbox_writes: Vec::new(),
    })?;
    drop(advanced_queue);
    let connection = rusqlite::Connection::open(&advanced_path)?;
    connection.pragma_update(None, "user_version", 2)?;
    drop(connection);
    assert!(matches!(open_queue(&advanced), Err(NodeError::LegacyEvidenceRecords)));

    let empty = TempDir::new()?;
    let empty_path = temp_path(&empty, "committee-node.sqlite")?;
    drop(open_queue(&empty)?);
    let connection = rusqlite::Connection::open(&empty_path)?;
    connection.pragma_update(None, "user_version", 2)?;
    drop(connection);
    drop(open_queue(&empty)?);
    let connection = rusqlite::Connection::open(&empty_path)?;
    let version: i64 = connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
    assert_eq!(version, 4);
    Ok(())
}

fn dummy_scan<'a>(
    expected: Option<&'a LedgerCursor>,
    next: &'a LedgerCursor,
    staged: &'a StagedFinalityRangeCapabilityV2,
    segment_digest: [u8; 32],
    record: Vec<u8>,
) -> ScanCommit<'a> {
    ScanCommit {
        expected_cursor: expected,
        next_cursor: next,
        staged,
        segment_digest,
        expire_through_ms: 10,
        pending_writes: vec![PendingInvoiceWrite {
            entry_hash: [0x31; 32],
            expires_at_ms: 100,
            record: b"pending-invoice".to_vec(),
        }],
        pending_removals: Vec::new(),
        inbox_writes: vec![InboxWrite {
            item_id: [0x21; 32],
            invoice_entry_hash: [0x23; 32],
            request_digest: [0x22; 32],
            record,
        }],
    }
}

fn dummy_stage(
    queue: &SqliteQueue,
    refresh_count: u64,
    last_refresh: EntryHashV2,
) -> std::result::Result<(StagedFinalityRangeCapabilityV2, LedgerCursor), Box<dyn Error>> {
    let block = PendingBlockV2::new(
        LedgerChainIdV2::new("committee-node-regtest")?,
        1,
        10,
        AppHashV2::zero(),
    )?
    .execute()?;
    let staged = queue.stage_finality_range(&segment(vec![block.clone()])?)?;
    let next = LedgerCursor {
        next_height: 2,
        expected_previous_app_hash: block.app_hash().clone(),
        processed_refresh_count: refresh_count,
        last_refresh_entry_hash: last_refresh,
        last_finality: block_capability(AcceptFinality.profile_id(), &block)?,
    };
    Ok((staged, next))
}

#[test]
fn scan_commit_is_atomic_bounded_and_idempotent() -> std::result::Result<(), Box<dyn Error>> {
    let directory = TempDir::new()?;
    let queue = open_queue(&directory)?;
    let (staged, next) = dummy_stage(&queue, 1, EntryHashV2::from_bytes([0x45; 32])?)?;
    assert!(matches!(
        queue.commit_scan(dummy_scan(None, &next, &staged, [0x51; 32], b"compact-record".to_vec()))?,
        ScanCommitOutcome::Applied { inbox_added: 1 }
    ));
    assert!(matches!(
        queue.commit_scan(dummy_scan(None, &next, &staged, [0x51; 32], b"compact-record".to_vec()))?,
        ScanCommitOutcome::Replayed
    ));
    assert!(matches!(
        queue.commit_scan(dummy_scan(None, &next, &staged, [0x52; 32], b"other".to_vec())),
        Err(NodeError::CursorConflict)
    ));
    assert_eq!(queue.cursor()?, Some(next));
    assert_eq!(
        queue.pending_invoice([0x31; 32])?.ok_or("pending")?.record,
        b"pending-invoice"
    );
    assert_eq!(queue.next_pending()?.ok_or("inbox")?.record, b"compact-record");

    let fresh = TempDir::new()?;
    let fresh_queue = open_queue(&fresh)?;
    let (fresh_staged, fresh_next) = dummy_stage(&fresh_queue, 0, EntryHashV2::zero())?;
    let huge = vec![0_u8; MAX_INBOX_RECORD_BYTES + 1];
    assert!(matches!(
        fresh_queue.commit_scan(dummy_scan(None, &fresh_next, &fresh_staged, [0x53; 32], huge)),
        Err(NodeError::InvalidLedgerArtifact)
    ));
    Ok(())
}

#[test]
fn same_inode_second_instance_is_rejected_until_close() -> std::result::Result<(), Box<dyn Error>> {
    let directory = TempDir::new()?;
    let first = open_queue(&directory)?;
    assert!(matches!(
        open_queue(&directory),
        Err(NodeError::InvalidConfiguration(_))
    ));
    drop(first);
    drop(open_queue(&directory)?);
    Ok(())
}

#[test]
fn inbox_digest_tamper_property_is_fail_closed() -> std::result::Result<(), Box<dyn Error>> {
    let directory = TempDir::new()?;
    let path = temp_path(&directory, "committee-node.sqlite")?;
    let queue = open_queue(&directory)?;
    let (staged, next) = dummy_stage(&queue, 1, EntryHashV2::from_bytes([0x45; 32])?)?;
    let original = b"canonical-record-for-property".to_vec();
    queue.commit_scan(dummy_scan(None, &next, &staged, [0x71; 32], original.clone()))?;
    let connection = rusqlite::Connection::open(path)?;
    let mut runner = proptest::test_runner::TestRunner::new(proptest::test_runner::Config::with_cases(96));
    runner.run(&(0..original.len(), 1_u8..=u8::MAX), |(index, mask)| {
        let mut changed = original.clone();
        changed[index] ^= mask;
        connection
            .execute("UPDATE inbox SET record_json=?1", [changed])
            .map_err(|error| TestCaseError::fail(error.to_string()))?;
        prop_assert!(matches!(queue.next_pending(), Err(NodeError::CorruptState)));
        connection
            .execute("UPDATE inbox SET record_json=?1", [&original])
            .map_err(|error| TestCaseError::fail(error.to_string()))?;
        Ok(())
    })?;
    Ok(())
}

#[derive(Debug)]
struct TestError;
impl std::fmt::Display for TestError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("test rejection")
    }
}
impl Error for TestError {}

struct AcceptFinality;
impl LedgerFinalityVerifier for AcceptFinality {
    type Error = TestError;
    fn profile_id(&self) -> FinalityVerifierProfileId {
        FinalityVerifierProfileId::new([0x81; 32]).unwrap_or(FinalityVerifierProfileId::DISABLED)
    }
    fn coordinator_id(&self) -> FinalityCoordinatorId {
        FinalityCoordinatorId::new([0x91; 32]).unwrap_or(FinalityCoordinatorId::DISABLED)
    }
    fn finalize_staged_range<'a>(
        &'a mut self,
        staged: &'a StagedFinalityRangeCapabilityV2,
    ) -> LedgerFuture<'a, FinalizedRangeCapabilityV2, Self::Error> {
        let result = finalized_range(
            staged,
            self.profile_id(),
            self.coordinator_id(),
            &BTreeMap::new(),
            OccurrenceMode::Exact,
            false,
        );
        Box::pin(async move { result })
    }
    fn verify_durable_capability<'a>(
        &'a self,
        capability: &'a DurableBlockFinalityCapability,
    ) -> LedgerFuture<'a, (), Self::Error> {
        let expected = block_attestation(capability.block_height(), capability.app_hash());
        let result = (capability.attestation() == expected
            && capability.verifier_digest() == FinalityDigest::new(Sha256::digest(&expected).into()))
        .then_some(())
        .ok_or(TestError);
        Box::pin(async move { result })
    }
}

struct WrongProfileFinality;
impl LedgerFinalityVerifier for WrongProfileFinality {
    type Error = TestError;
    fn profile_id(&self) -> FinalityVerifierProfileId {
        FinalityVerifierProfileId::new([0x82; 32]).unwrap_or(FinalityVerifierProfileId::DISABLED)
    }
    fn coordinator_id(&self) -> FinalityCoordinatorId {
        FinalityCoordinatorId::new([0x91; 32]).unwrap_or(FinalityCoordinatorId::DISABLED)
    }
    fn finalize_staged_range<'a>(
        &'a mut self,
        staged: &'a StagedFinalityRangeCapabilityV2,
    ) -> LedgerFuture<'a, FinalizedRangeCapabilityV2, Self::Error> {
        let result = finalized_range(
            staged,
            self.profile_id(),
            self.coordinator_id(),
            &BTreeMap::new(),
            OccurrenceMode::Exact,
            false,
        );
        Box::pin(async move { result })
    }
    fn verify_durable_capability<'a>(
        &'a self,
        _: &'a DurableBlockFinalityCapability,
    ) -> LedgerFuture<'a, (), Self::Error> {
        Box::pin(async { Err(TestError) })
    }
}

struct WrongBlockFinality;
impl LedgerFinalityVerifier for WrongBlockFinality {
    type Error = TestError;
    fn profile_id(&self) -> FinalityVerifierProfileId {
        FinalityVerifierProfileId::new([0x81; 32]).unwrap_or(FinalityVerifierProfileId::DISABLED)
    }
    fn coordinator_id(&self) -> FinalityCoordinatorId {
        FinalityCoordinatorId::new([0x91; 32]).unwrap_or(FinalityCoordinatorId::DISABLED)
    }
    fn finalize_staged_range<'a>(
        &'a mut self,
        staged: &'a StagedFinalityRangeCapabilityV2,
    ) -> LedgerFuture<'a, FinalizedRangeCapabilityV2, Self::Error> {
        let result = finalized_range(
            staged,
            self.profile_id(),
            self.coordinator_id(),
            &BTreeMap::new(),
            OccurrenceMode::Exact,
            true,
        );
        Box::pin(async move { result })
    }
    fn verify_durable_capability<'a>(
        &'a self,
        _: &'a DurableBlockFinalityCapability,
    ) -> LedgerFuture<'a, (), Self::Error> {
        Box::pin(async { Err(TestError) })
    }
}

struct BlockingFinality {
    block_next: AtomicBool,
    entered: Arc<tokio::sync::Notify>,
    release: Arc<tokio::sync::Notify>,
}

impl BlockingFinality {
    fn new() -> Self {
        Self {
            block_next: AtomicBool::new(true),
            entered: Arc::new(tokio::sync::Notify::new()),
            release: Arc::new(tokio::sync::Notify::new()),
        }
    }
}

impl LedgerFinalityVerifier for BlockingFinality {
    type Error = TestError;

    fn profile_id(&self) -> FinalityVerifierProfileId {
        AcceptFinality.profile_id()
    }
    fn coordinator_id(&self) -> FinalityCoordinatorId {
        AcceptFinality.coordinator_id()
    }
    fn finalize_staged_range<'a>(
        &'a mut self,
        staged: &'a StagedFinalityRangeCapabilityV2,
    ) -> LedgerFuture<'a, FinalizedRangeCapabilityV2, Self::Error> {
        let should_block = self.block_next.swap(false, Ordering::SeqCst);
        let entered = Arc::clone(&self.entered);
        let release = Arc::clone(&self.release);
        let result = finalized_range(
            staged,
            self.profile_id(),
            self.coordinator_id(),
            &BTreeMap::new(),
            OccurrenceMode::Exact,
            false,
        );
        Box::pin(async move {
            if should_block {
                entered.notify_one();
                release.notified().await;
            }
            result
        })
    }

    fn verify_durable_capability<'a>(
        &'a self,
        capability: &'a DurableBlockFinalityCapability,
    ) -> LedgerFuture<'a, (), Self::Error> {
        AcceptFinality.verify_durable_capability(capability)
    }
}

fn block_attestation(_height: u64, _app_hash: &AppHashV2) -> Vec<u8> {
    vec![0x80; 64]
}

#[derive(Clone, Copy)]
enum OccurrenceMode {
    Exact,
    OmitFirst,
    FlipFirst,
}

struct ConfiguredFinality {
    first_locations: BTreeMap<[u8; 32], (u64, u32)>,
    mode: OccurrenceMode,
}

impl ConfiguredFinality {
    fn new(first_locations: BTreeMap<[u8; 32], (u64, u32)>) -> Self {
        Self {
            first_locations,
            mode: OccurrenceMode::Exact,
        }
    }

    fn with_mode(mode: OccurrenceMode) -> Self {
        Self {
            first_locations: BTreeMap::new(),
            mode,
        }
    }
}

impl LedgerFinalityVerifier for ConfiguredFinality {
    type Error = TestError;

    fn profile_id(&self) -> FinalityVerifierProfileId {
        AcceptFinality.profile_id()
    }

    fn coordinator_id(&self) -> FinalityCoordinatorId {
        AcceptFinality.coordinator_id()
    }

    fn finalize_staged_range<'a>(
        &'a mut self,
        staged: &'a StagedFinalityRangeCapabilityV2,
    ) -> LedgerFuture<'a, FinalizedRangeCapabilityV2, Self::Error> {
        let result = finalized_range(
            staged,
            self.profile_id(),
            self.coordinator_id(),
            &self.first_locations,
            self.mode,
            false,
        );
        Box::pin(async move { result })
    }

    fn verify_durable_capability<'a>(
        &'a self,
        capability: &'a DurableBlockFinalityCapability,
    ) -> LedgerFuture<'a, (), Self::Error> {
        AcceptFinality.verify_durable_capability(capability)
    }
}

fn finalized_range(
    staged: &StagedFinalityRangeCapabilityV2,
    profile: FinalityVerifierProfileId,
    coordinator: FinalityCoordinatorId,
    first_locations: &BTreeMap<[u8; 32], (u64, u32)>,
    occurrence_mode: OccurrenceMode,
    wrong_block: bool,
) -> std::result::Result<FinalizedRangeCapabilityV2, TestError> {
    let intent = staged.intent();
    let mut blocks = Vec::with_capacity(intent.blocks().len());
    let mut occurrences = Vec::new();
    for block in intent.blocks() {
        let finality = if wrong_block {
            let app_hash = AppHashV2::from_bytes([0xee; 32]).map_err(|_| TestError)?;
            DurableBlockFinalityCapability::new(
                profile,
                coordinator,
                block.ledger_chain_id().clone(),
                block.height(),
                app_hash,
                FinalityDigest::new([0xef; 32]),
                b"wrong-block".to_vec(),
            )
            .map_err(|_| TestError)?
        } else {
            block_capability_for(profile, coordinator, block).map_err(|_| TestError)?
        };
        for entry in block.entries() {
            if !matches!(
                entry.metadata().event_kind(),
                thunderbolt_ledger::EventKindV2::Invoice | thunderbolt_ledger::EventKindV2::Transfer
            ) {
                continue;
            }
            let metadata = entry.metadata();
            let entry_hash = *metadata.entry_hash().as_bytes();
            let (first_height, first_index) = first_locations
                .get(&entry_hash)
                .copied()
                .unwrap_or((metadata.block_height(), metadata.block_index()));
            occurrences.push(VerifiedEntryOccurrenceV2 {
                kind: if (first_height, first_index) == (metadata.block_height(), metadata.block_index()) {
                    EntryOccurrenceKindV2::First
                } else {
                    EntryOccurrenceKindV2::Replay
                },
                ledger_chain_id: block.ledger_chain_id().clone(),
                channel_context_id: metadata.channel_context_id().clone(),
                entry_hash: metadata.entry_hash().clone(),
                semantic_digest: test_semantic_digest(entry).map_err(|_| TestError)?,
                observed_height: metadata.block_height(),
                observed_index: metadata.block_index(),
                first_height,
                first_index,
                through_height: intent.next_height().saturating_sub(1),
                expected_through_app_hash: intent.next_expected_previous_app_hash().clone(),
                verifier_profile: profile,
                coordinator_id: coordinator,
                verifier_digest: FinalityDigest::new([0xa5; 32]),
            });
        }
        blocks.push(FinalizedBlockV2 {
            block: block.clone(),
            finality,
        });
    }
    match occurrence_mode {
        OccurrenceMode::Exact => {}
        OccurrenceMode::OmitFirst => {
            if !occurrences.is_empty() {
                occurrences.remove(0);
            }
        }
        OccurrenceMode::FlipFirst => {
            if let Some(first) = occurrences.first_mut() {
                first.kind = match first.kind {
                    EntryOccurrenceKindV2::First => EntryOccurrenceKindV2::Replay,
                    EntryOccurrenceKindV2::Replay => EntryOccurrenceKindV2::First,
                };
            }
        }
    }
    FinalizedRangeCapabilityV2::new(staged, blocks, occurrences).map_err(|_| TestError)
}

fn block_capability(
    profile: FinalityVerifierProfileId,
    block: &ExecutedBlockV2,
) -> Result<DurableBlockFinalityCapability> {
    block_capability_for(profile, FinalityCoordinatorId::new([0x91; 32])?, block)
}

fn block_capability_for(
    profile: FinalityVerifierProfileId,
    coordinator: FinalityCoordinatorId,
    block: &ExecutedBlockV2,
) -> Result<DurableBlockFinalityCapability> {
    let attestation = block_attestation(block.height(), block.app_hash());
    DurableBlockFinalityCapability::new(
        profile,
        coordinator,
        block.ledger_chain_id().clone(),
        block.height(),
        block.app_hash().clone(),
        FinalityDigest::new(Sha256::digest(&attestation).into()),
        attestation,
    )
}

struct TestRuntime {
    descriptor: thunderbolt_committee::CommitteeDescriptor,
    member_id: CommitteeMemberId,
    revision: u64,
    applied: BTreeMap<[u8; 32], AcknowledgementRecord>,
}

impl CommitteeRuntime for TestRuntime {
    fn descriptor(&self) -> &thunderbolt_committee::CommitteeDescriptor {
        &self.descriptor
    }
    fn member_id(&self) -> CommitteeMemberId {
        self.member_id
    }
    fn validate_verified_refresh(&self, _refresh: &VerifiedV2Refresh) -> Result<()> {
        Ok(())
    }
    fn apply_verified_refresh(&mut self, refresh: &VerifiedV2Refresh) -> Result<RuntimeRefreshOutcome> {
        let event_id = test_refresh_event_id(refresh.commitment());
        if let Some(acknowledgement) = self.applied.get(&event_id) {
            return Ok(RuntimeRefreshOutcome {
                acknowledgement: acknowledgement.clone(),
                replay: true,
            });
        }
        self.revision = self.revision.checked_add(1).ok_or(NodeError::NumericRange)?;
        let acknowledgement_digest: [u8; 32] =
            Sha256::digest([event_id.as_slice(), self.revision.to_be_bytes().as_slice()].concat()).into();
        let acknowledgement = AcknowledgementRecord {
            event_id,
            descriptor_id: *self.descriptor.id().as_bytes(),
            epoch: self.descriptor.epoch().get(),
            member_id: self.member_id.get(),
            durable_revision: self.revision,
            acknowledgement_digest,
        };
        self.applied.insert(event_id, acknowledgement.clone());
        Ok(RuntimeRefreshOutcome {
            acknowledgement,
            replay: false,
        })
    }
}

fn test_runtime() -> std::result::Result<TestRuntime, Box<dyn Error>> {
    let dealer = dealer_bootstrap(
        Network::Regtest,
        b"node-deployment",
        CommitteeEpoch::new(7),
        1,
        1,
        scalar(41)?.base_point_mul(),
        scalar(23)?,
    )?;
    let descriptor = dealer.descriptor().clone();
    let member_id = descriptor.members().first().ok_or("missing member")?.id();
    Ok(TestRuntime {
        descriptor,
        member_id,
        revision: 0,
        applied: BTreeMap::new(),
    })
}

fn scalar(value: u8) -> std::result::Result<Scalar, Box<dyn Error>> {
    let mut bytes = [0_u8; 32];
    bytes[31] = value.max(1);
    Ok(Scalar::from_slice(&bytes)?)
}
fn point(value: u8) -> std::result::Result<PointHex, Box<dyn Error>> {
    Ok(PointHex::from_bytes(
        "test point",
        scalar(value)?.base_point_mul().serialize(),
    )?)
}
fn modulus(seed: u32) -> std::result::Result<PaillierModulusBytesV2, Box<dyn Error>> {
    let mut bytes = vec![0_u8; PAILLIER_V2_MODULUS_BYTES];
    bytes[0] = 0x80 | u8::try_from(seed & 0x7f)?;
    bytes[PAILLIER_V2_MODULUS_BYTES - 1] = u8::try_from(seed & 0xff)? | 1;
    Ok(PaillierModulusBytesV2::from_bytes("test modulus", bytes)?)
}
fn ciphertext(seed: u32) -> std::result::Result<PaillierCiphertextBytesV2, Box<dyn Error>> {
    let mut bytes = vec![0_u8; PAILLIER_V2_CIPHERTEXT_BYTES];
    bytes[PAILLIER_V2_CIPHERTEXT_BYTES - 1] = u8::try_from(seed & 0xff)?.max(1);
    Ok(PaillierCiphertextBytesV2::from_bytes("test ciphertext", bytes)?)
}
fn nonce(seed: u32) -> std::result::Result<PaillierNonceBytesV2, Box<dyn Error>> {
    let mut bytes = vec![0_u8; PAILLIER_V2_MODULUS_BYTES];
    bytes[PAILLIER_V2_MODULUS_BYTES - 1] = u8::try_from(seed & 0xff)?.max(1);
    Ok(PaillierNonceBytesV2::from_bytes("test nonce", bytes)?)
}
fn response(seed: u32) -> std::result::Result<ProofResponseBytesV2, Box<dyn Error>> {
    let mut bytes = vec![0_u8; PROOF_RESPONSE_V2_BYTES];
    bytes[PROOF_RESPONSE_V2_BYTES - 1] = u8::try_from(seed & 0xff)?;
    Ok(ProofResponseBytesV2::from_bytes("test response", bytes)?)
}

fn actor(index: u8) -> std::result::Result<Keypair, Box<dyn Error>> {
    let mut bytes = [0_u8; 32];
    bytes[31] = index.max(1);
    let secret = SecretKey::from_byte_array(bytes)?;
    Ok(Keypair::from_secret_key(&Secp256k1::signing_only(), &secret))
}

fn signed(
    event: &ChannelEventV2,
    binding: ChannelBindingV2,
    sequence: u64,
    previous: EntryHashV2,
    role: ActorRoleV2,
    actor_index: u8,
) -> std::result::Result<SignedProposalV2, Box<dyn Error>> {
    let keypair = actor(actor_index)?;
    let (public, _) = keypair.x_only_public_key();
    let body = ProposalBodyV2::new(
        LedgerChainIdV2::new("committee-node-regtest")?,
        binding,
        sequence,
        previous,
        ClientRequestNonceV2::from_bytes([actor_index; 16])?,
        ActorKeyAlgorithmV2::Bip340V1,
        ActorPublicKeyV2::from_bytes(public.serialize())?,
        role,
        event.kind(),
        CanonicalEventV2::from_bytes(event.canonical_bytes()?)?,
    )?;
    let signature = Secp256k1::signing_only().sign_schnorr_no_aux_rand(body.proposal_digest()?.as_bytes(), &keypair);
    Ok(SignedProposalV2::new(
        body,
        ActorSignatureV2::from_bytes(signature.to_byte_array())?,
    )?)
}

fn make_artifacts(
    binding: &ChannelBindingV2,
    invoice_id: &[u8],
    anchor_base: PointHex,
    member_count: usize,
) -> std::result::Result<(RecipientShareEnvelopeV2, ThresholdEnvelopeV2, TransferEnvelopeV2), Box<dyn Error>> {
    let invoice_binding = OperationBindingV2::invoice(binding.clone(), invoice_id)?;
    let members = (1..=member_count)
        .map(|index| {
            Ok(ThresholdRosterMemberV2 {
                member_id: u32::try_from(index)?,
                encryption_key: modulus(u32::try_from(index)?)?,
            })
        })
        .collect::<std::result::Result<Vec<_>, Box<dyn Error>>>()?;
    let roster = ThresholdRosterV2::new(1, members)?;
    let package = ThresholdPackageBindingV2::new(&invoice_binding, 1, roster.clone())?;
    let delta = point(7)?;
    let recipient_key = modulus(401)?;
    let recipient_ciphertext = ciphertext(402)?;
    let recipient = RecipientShareEnvelopeV2 {
        binding: invoice_binding.clone(),
        paillier_profile: PaillierModulusProfileV2::ProtocolV2Production3072,
        package: package.clone(),
        statement: RecipientShareStatementV2 {
            anchor_base: anchor_base.clone(),
            recipient_key: recipient_key.clone(),
            member_id: RECIPIENT_SHARE_MEMBER_ID,
            committed_point: delta.clone(),
            ciphertext: recipient_ciphertext.clone(),
        },
        proof: ShareProofV2 {
            a_point: point(8)?,
            a_ciphertext: ciphertext(403)?,
            z: response(404)?,
            tau: nonce(405)?,
        },
    };
    let encrypted_shares = roster
        .members
        .iter()
        .map(|member| {
            Ok(ThresholdEncryptedShareV2 {
                member_id: member.member_id,
                encryption_key: member.encryption_key.clone(),
                ciphertext: ciphertext(member.member_id)?,
                proof: ShareProofV2 {
                    a_point: point(u8::try_from(member.member_id & 0xff)?.max(1))?,
                    a_ciphertext: ciphertext(member.member_id.wrapping_add(1))?,
                    z: response(member.member_id.wrapping_add(2))?,
                    tau: nonce(member.member_id.wrapping_add(3))?,
                },
            })
        })
        .collect::<std::result::Result<Vec<_>, Box<dyn Error>>>()?;
    let threshold = ThresholdEnvelopeV2 {
        binding: invoice_binding,
        paillier_profile: PaillierModulusProfileV2::ProtocolV2Production3072,
        package,
        distribution: ThresholdDistributionV2 {
            anchor_base: anchor_base.clone(),
            threshold: 1,
            delta: delta.clone(),
            polynomial_commitments: vec![delta.clone()],
            encrypted_shares,
        },
    };
    let current_anchor = point(9)?;
    let transfer = TransferEnvelopeV2 {
        binding: OperationBindingV2::transfer(binding.clone(), invoice_id, 1)?,
        paillier_profile: PaillierModulusProfileV2::ProtocolV2Production3072,
        statement: TransferStatementV2 {
            anchor_base,
            recipient_key,
            current_anchor: current_anchor.clone(),
            invoice_ciphertext: recipient_ciphertext,
            next_holder_ciphertext: ciphertext(406)?,
        },
        proof: TransferProofV2 {
            a_anchor: point(10)?,
            a_ciphertext: ciphertext(407)?,
            z: response(408)?,
            tau: nonce(409)?,
        },
        anchor_transition: AnchorTransitionV2 {
            current_anchor,
            delta,
            next_anchor: point(11)?,
        },
    };
    Ok((recipient, threshold, transfer))
}

fn build_blocks(
    runtime: &TestRuntime,
    member_count: usize,
    same_block: bool,
    include_empty: bool,
    wrong_artifact: bool,
) -> std::result::Result<Vec<ExecutedBlockV2>, Box<dyn Error>> {
    let binding = ChannelBindingV2::new(
        ProtocolSuiteIdV2::from_bytes([0x11; 32])?,
        Network::Regtest,
        BitcoinGenesisHashV2::for_network(Network::Regtest)?,
        runtime.descriptor.deployment_id(),
        FundingOutpointV2::new([0x44; 32], 7)?,
        runtime.descriptor.epoch().get(),
        CommitteeDescriptorDigestV2::from_bytes(*runtime.descriptor.id().as_bytes())?,
        AnchorParameterSuiteIdV2::from_bytes([0x33; 32])?,
    )?;
    let invoice_id = b"invoice-9";
    let anchor = PointHex::from_bytes("descriptor anchor", runtime.descriptor.anchor_base().serialize())?;
    let (recipient, threshold, transfer_proof) = make_artifacts(&binding, invoice_id, anchor, member_count)?;
    let invoice_artifact = if wrong_artifact {
        to_json_vec(&PublicMessageV2::Transfer(transfer_proof.clone()))?
    } else {
        to_json_vec(&PublicMessageV2::RecipientShare(recipient.clone()))?
    };
    let invoice_event = ChannelEventV2::Invoice(InvoiceEventV2 {
        invoice_id: thunderbolt_wire::InvoiceId::from_bytes("invoice", invoice_id)?,
        holder_step: 0,
        recipient_encryption_key: ArtifactV2::new(recipient.statement.recipient_key.as_bytes().to_vec())?,
        public_delta: ArtifactV2::new(recipient.statement.committed_point.as_bytes().to_vec())?,
        recipient_ciphertext: ArtifactV2::new(recipient.statement.ciphertext.as_bytes().to_vec())?,
        committee_package: ArtifactV2::new(to_json_vec(&PublicMessageV2::ThresholdRefresh(threshold))?)?,
        invoice_proof: ArtifactV2::new(invoice_artifact)?,
        expires_at_ms: 100_000,
    });
    let invoice_signed = signed(
        &invoice_event,
        binding.clone(),
        1,
        EntryHashV2::from_bytes([0x55; 32])?,
        ActorRoleV2::Recipient,
        2,
    )?;
    let invoice_hash = invoice_signed.body().entry_hash()?;
    let transfer_event = ChannelEventV2::Transfer(TransferEventV2 {
        invoice_id: thunderbolt_wire::InvoiceId::from_bytes("invoice", invoice_id)?,
        invoice_entry_hash: invoice_hash.clone(),
        next_holder_anchor: ArtifactV2::new(transfer_proof.anchor_transition.next_anchor.as_bytes().to_vec())?,
        next_holder_ciphertext: ArtifactV2::new(transfer_proof.statement.next_holder_ciphertext.as_bytes().to_vec())?,
        transfer_proof: ArtifactV2::new(to_json_vec(&PublicMessageV2::Transfer(transfer_proof))?)?,
    });
    let transfer_signed = signed(&transfer_event, binding, 2, invoice_hash, ActorRoleV2::Holder, 3)?;
    if same_block {
        let mut pending = PendingBlockV2::new(
            LedgerChainIdV2::new("committee-node-regtest")?,
            1,
            10_000,
            AppHashV2::zero(),
        )?;
        pending.push(invoice_signed)?;
        pending.push(transfer_signed)?;
        return Ok(vec![pending.execute()?]);
    }
    let mut invoice_pending = PendingBlockV2::new(
        LedgerChainIdV2::new("committee-node-regtest")?,
        1,
        10_000,
        AppHashV2::zero(),
    )?;
    invoice_pending.push(invoice_signed)?;
    let invoice_block = invoice_pending.execute()?;
    let mut blocks = vec![invoice_block];
    if include_empty {
        let empty = PendingBlockV2::new(
            LedgerChainIdV2::new("committee-node-regtest")?,
            2,
            10_001,
            blocks.last().ok_or("invoice")?.app_hash().clone(),
        )?
        .execute()?;
        blocks.push(empty);
    }
    let height = u64::try_from(blocks.len())?.checked_add(1).ok_or("height")?;
    let mut transfer_pending = PendingBlockV2::new(
        LedgerChainIdV2::new("committee-node-regtest")?,
        height,
        10_002,
        blocks.last().ok_or("predecessor")?.app_hash().clone(),
    )?;
    transfer_pending.push(transfer_signed)?;
    blocks.push(transfer_pending.execute()?);
    Ok(blocks)
}

fn replay_block(
    proposal: SignedProposalV2,
    height: u64,
    block_time_ms: u64,
    previous_app_hash: AppHashV2,
) -> std::result::Result<ExecutedBlockV2, Box<dyn Error>> {
    let mut pending = PendingBlockV2::new(
        LedgerChainIdV2::new("committee-node-regtest")?,
        height,
        block_time_ms,
        previous_app_hash,
    )?;
    pending.push(proposal)?;
    Ok(pending.execute()?)
}

fn resign(
    proposal: &SignedProposalV2,
    actor_index: u8,
    auxiliary: [u8; 32],
) -> std::result::Result<SignedProposalV2, Box<dyn Error>> {
    let body = proposal.body().clone();
    let signature = Secp256k1::signing_only().sign_schnorr_with_aux_rand(
        body.proposal_digest()?.as_bytes(),
        &actor(actor_index)?,
        &auxiliary,
    );
    let resigned = SignedProposalV2::new(body, ActorSignatureV2::from_bytes(signature.to_byte_array())?)?;
    if resigned.signature() == proposal.signature() {
        return Err("alternate signature unexpectedly matched".into());
    }
    Ok(resigned)
}

fn segment(blocks: Vec<ExecutedBlockV2>) -> std::result::Result<FinalityRangeIntentV2, Box<dyn Error>> {
    let first = blocks.first().ok_or("empty fixture")?;
    let last = blocks.last().ok_or("empty fixture")?;
    let ledger_chain_id = first.ledger_chain_id().clone();
    let start_height = first.height();
    let expected_previous = first.previous_app_hash().clone();
    let next_height = last.height().checked_add(1).ok_or("next height")?;
    let next_previous = last.app_hash().clone();
    Ok(FinalityRangeIntentV2::new(
        FinalityVerifierProfileId::new([0x81; 32])?,
        FinalityCoordinatorId::new([0x91; 32])?,
        ledger_chain_id,
        start_height,
        expected_previous,
        blocks,
        next_height,
        next_previous,
    )?)
}

async fn poll_intent<R, V>(
    node: &mut CommitteeNode<R>,
    intent: FinalityRangeIntentV2,
    finality: &mut V,
) -> Result<usize>
where
    R: CommitteeRuntime,
    V: LedgerFinalityVerifier,
{
    let mut client = BlockingClient::new(Some(intent));
    node.poll(&mut client, finality).await
}

fn test_refresh_event_id(commitment: thunderbolt_committee::CommittedTransfer) -> [u8; 32] {
    let mut hasher = Sha256::new();
    let domain = b"bitcoin-thunderbolt/committee-refresh-event/v2";
    hasher.update((domain.len() as u64).to_be_bytes());
    hasher.update(domain);
    hasher.update(commitment.recipient_share_digest());
    hasher.update(commitment.threshold_refresh_digest());
    hasher.update(commitment.transfer_digest());
    hasher.update(commitment.invoice_entry_hash().as_bytes());
    hasher.update(commitment.transfer_entry_hash().as_bytes());
    hasher.update(commitment.transfer_sequence().to_be_bytes());
    hasher.update(commitment.transfer_step().to_be_bytes());
    hasher.finalize().into()
}

#[tokio::test]
async fn contiguous_scan_pending_pair_empty_block_crash_and_restart() -> std::result::Result<(), Box<dyn Error>> {
    let directory = TempDir::new()?;
    let runtime = test_runtime()?;
    let blocks = build_blocks(&runtime, 1, false, true, false)?;
    let invoice_page = segment(vec![blocks[0].clone()])?;
    let transfer_page = segment(blocks[1..].to_vec())?;
    let db = temp_path(&directory, "node.sqlite")?;
    let mut node = CommitteeNode::open(&db, runtime, config()?)?;
    assert_eq!(poll_intent(&mut node, invoice_page, &mut AcceptFinality).await?, 0);
    let first_cursor = node.control(ControlRequest::Status, true)?;
    let ControlResponse::Status(first_status) = first_cursor else {
        return Err("status".into());
    };
    assert_eq!(first_status.cursor.ok_or("cursor")?.next_height, 2);
    let cursor_connection = rusqlite::Connection::open(&db)?;
    let (cursor_json, cursor_digest): (Vec<u8>, Vec<u8>) = cursor_connection.query_row(
        "SELECT finality_json,finality_digest FROM finalized_cursor",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    let cursor_capability: DurableBlockFinalityCapability = serde_json::from_slice(&cursor_json)?;
    let wrong_attestation = vec![0x81; 64];
    let wrong_capability = DurableBlockFinalityCapability::new(
        cursor_capability.verifier_profile(),
        cursor_capability.coordinator_id(),
        cursor_capability.ledger_chain_id().clone(),
        cursor_capability.block_height(),
        cursor_capability.app_hash().clone(),
        FinalityDigest::new(Sha256::digest(&wrong_attestation).into()),
        wrong_attestation,
    )?;
    let wrong_json = serde_json::to_vec(&wrong_capability)?;
    cursor_connection.execute(
        "UPDATE finalized_cursor SET finality_json=?1,finality_digest=?2",
        rusqlite::params![wrong_json, wrong_capability.verifier_digest().as_bytes().as_slice()],
    )?;
    assert!(matches!(
        poll_intent(&mut node, transfer_page.clone(), &mut AcceptFinality).await,
        Err(NodeError::FinalityRejected)
    ));
    cursor_connection.execute(
        "UPDATE finalized_cursor SET finality_json=?1,finality_digest=?2",
        rusqlite::params![cursor_json, cursor_digest],
    )?;
    drop(cursor_connection);
    assert_eq!(poll_intent(&mut node, transfer_page, &mut AcceptFinality).await?, 1);
    let connection = rusqlite::Connection::open(&db)?;
    let pending: i64 = connection.query_row("SELECT count(*) FROM pending_invoices", [], |row| row.get(0))?;
    let record: Vec<u8> = connection.query_row("SELECT record_json FROM inbox", [], |row| row.get(0))?;
    assert_eq!(pending, 0);
    assert!(!std::str::from_utf8(&record)?.contains("RAW-RECEIPT"));
    let decoded: VerifiedRefreshRecordV2 = serde_json::from_slice(&record)?;
    let swapped_blocks = match decoded.blocks {
        RefreshBlockCommitmentsV2::Distinct { invoice, transfer } => RefreshBlockCommitmentsV2::Distinct {
            invoice: transfer,
            transfer: invoice,
        },
        RefreshBlockCommitmentsV2::Shared { .. } => return Err("expected distinct commitments".into()),
    };
    let tampered = serde_json::to_vec(&VerifiedRefreshRecordV2 {
        blocks: swapped_blocks,
        invoice: decoded.invoice,
        transfer: decoded.transfer,
        invoice_semantic_digest: decoded.invoice_semantic_digest,
        transfer_semantic_digest: decoded.transfer_semantic_digest,
        finality: decoded.finality,
    })?;
    let tampered_digest: [u8; 32] = Sha256::digest(&tampered).into();
    connection.execute(
        "UPDATE inbox SET record_json=?1,record_digest=?2",
        rusqlite::params![tampered, tampered_digest.as_slice()],
    )?;
    assert!(matches!(
        node.process_next(&AcceptFinality).await,
        Err(NodeError::InvalidLedgerArtifact | NodeError::FinalityRejected)
    ));
    let record_digest: [u8; 32] = Sha256::digest(&record).into();
    connection.execute(
        "UPDATE inbox SET record_json=?1,record_digest=?2",
        rusqlite::params![&record, record_digest.as_slice()],
    )?;
    drop(connection);
    node.inject_crash_after_runtime_once();
    assert!(matches!(
        node.process_next(&AcceptFinality).await,
        Err(NodeError::InjectedCrash)
    ));
    let runtime = node.into_runtime();
    let mut restarted = CommitteeNode::open(&db, runtime, config()?)?;
    assert_eq!(
        restarted.process_next(&AcceptFinality).await?,
        ProcessDisposition::Replay
    );
    let ControlResponse::Status(status) = restarted.control(ControlRequest::Status, true)? else {
        return Err("status".into());
    };
    let cursor = status.cursor.ok_or("cursor")?;
    assert_eq!(cursor.next_height, 4);
    assert_eq!(cursor.processed_refresh_count, 1);
    assert_eq!(cursor.last_refresh_entry_hash, record_transfer_hash(&record)?);
    Ok(())
}

#[tokio::test]
async fn exact_invoice_and_transfer_replays_keep_first_semantics_across_pages_and_restart(
) -> std::result::Result<(), Box<dyn Error>> {
    let directory = TempDir::new()?;
    let runtime = test_runtime()?;
    let originals = build_blocks(&runtime, 1, false, true, false)?;
    let invoice_proposal = originals[0].entries()[0].proposal().clone();
    let transfer_proposal = originals[2].entries()[0].proposal().clone();
    let invoice_hash = *originals[0].entries()[0].metadata().entry_hash().as_bytes();
    let transfer_hash = *originals[2].entries()[0].metadata().entry_hash().as_bytes();
    let mut first_locations = BTreeMap::from([(invoice_hash, (1, 0))]);
    let db = temp_path(&directory, "replay-node.sqlite")?;
    let mut node = CommitteeNode::open(&db, runtime, config()?)?;
    let mut finality = ConfiguredFinality::new(first_locations.clone());
    assert_eq!(
        poll_intent(&mut node, segment(vec![originals[0].clone()])?, &mut finality).await?,
        0
    );

    let invoice_replay = replay_block(
        resign(&invoice_proposal, 2, [0x11; 32])?,
        2,
        10_001,
        originals[0].app_hash().clone(),
    )?;
    assert_eq!(
        poll_intent(&mut node, segment(vec![invoice_replay.clone()])?, &mut finality).await?,
        0
    );
    first_locations.insert(transfer_hash, (3, 0));
    finality = ConfiguredFinality::new(first_locations.clone());
    let transfer_first = replay_block(transfer_proposal.clone(), 3, 10_002, invoice_replay.app_hash().clone())?;
    assert_eq!(
        poll_intent(&mut node, segment(vec![transfer_first.clone()])?, &mut finality).await?,
        1
    );

    let runtime = node.into_runtime();
    let mut restarted = CommitteeNode::open(&db, runtime, config()?)?;
    let invoice_after_consumption = replay_block(
        resign(&invoice_proposal, 2, [0x12; 32])?,
        4,
        10_003,
        transfer_first.app_hash().clone(),
    )?;
    assert_eq!(
        poll_intent(
            &mut restarted,
            segment(vec![invoice_after_consumption.clone()])?,
            &mut finality,
        )
        .await?,
        0
    );
    let transfer_replay = replay_block(
        resign(&transfer_proposal, 3, [0x13; 32])?,
        5,
        10_004,
        invoice_after_consumption.app_hash().clone(),
    )?;
    assert_eq!(
        poll_intent(&mut restarted, segment(vec![transfer_replay])?, &mut finality).await?,
        0
    );
    let ControlResponse::Status(status) = restarted.control(ControlRequest::Status, true)? else {
        return Err("status".into());
    };
    let cursor = status.cursor.ok_or("cursor")?;
    assert_eq!(cursor.next_height, 6);
    assert_eq!(cursor.processed_refresh_count, 1);
    assert_eq!(cursor.last_refresh_entry_hash.as_bytes(), &transfer_hash);
    let stored: Vec<u8> =
        rusqlite::Connection::open(&db)?.query_row("SELECT record_json FROM inbox", [], |row| row.get(0))?;
    let stored: VerifiedRefreshRecordV2 = serde_json::from_slice(&stored)?;
    assert_eq!(stored.blocks.invoice().height(), 1);
    assert_eq!(stored.blocks.transfer().height(), 3);
    assert_eq!(
        restarted.process_next(&AcceptFinality).await?,
        ProcessDisposition::Applied
    );
    Ok(())
}

#[tokio::test]
async fn expired_invoice_replay_is_noop_without_a_tombstone() -> std::result::Result<(), Box<dyn Error>> {
    let directory = TempDir::new()?;
    let runtime = test_runtime()?;
    let originals = build_blocks(&runtime, 1, false, false, false)?;
    let invoice = originals[0].entries()[0].proposal().clone();
    let invoice_hash = *originals[0].entries()[0].metadata().entry_hash().as_bytes();
    let first_locations = BTreeMap::from([(invoice_hash, (1, 0))]);
    let db = temp_path(&directory, "expired-replay.sqlite")?;
    let mut node = CommitteeNode::open(&db, runtime, config()?)?;
    let mut finality = ConfiguredFinality::new(first_locations.clone());
    assert_eq!(
        poll_intent(&mut node, segment(vec![originals[0].clone()])?, &mut finality).await?,
        0
    );
    let expired = PendingBlockV2::new(
        LedgerChainIdV2::new("committee-node-regtest")?,
        2,
        100_000,
        originals[0].app_hash().clone(),
    )?
    .execute()?;
    assert_eq!(
        poll_intent(&mut node, segment(vec![expired.clone()])?, &mut finality).await?,
        0
    );
    let pending: i64 =
        rusqlite::Connection::open(&db)?.query_row("SELECT count(*) FROM pending_invoices", [], |row| row.get(0))?;
    assert_eq!(pending, 0);
    let replay = replay_block(resign(&invoice, 2, [0x21; 32])?, 3, 100_001, expired.app_hash().clone())?;
    assert_eq!(poll_intent(&mut node, segment(vec![replay])?, &mut finality).await?, 0);
    let ControlResponse::Status(status) = node.control(ControlRequest::Status, true)? else {
        return Err("status".into());
    };
    assert_eq!(status.cursor.ok_or("cursor")?.next_height, 4);
    Ok(())
}

#[tokio::test]
async fn pruned_transfer_replay_is_noop_without_a_tombstone() -> std::result::Result<(), Box<dyn Error>> {
    let directory = TempDir::new()?;
    let runtime = test_runtime()?;
    let original = build_blocks(&runtime, 1, true, false, false)?;
    let transfer = original[0].entries()[1].proposal().clone();
    let transfer_hash = *original[0].entries()[1].metadata().entry_hash().as_bytes();
    let first_locations = BTreeMap::from([(transfer_hash, (1, 1))]);
    let db = temp_path(&directory, "pruned-replay.sqlite")?;
    let mut node = CommitteeNode::open(&db, runtime, config()?)?;
    let mut finality = ConfiguredFinality::new(first_locations.clone());
    assert_eq!(
        poll_intent(&mut node, segment(original.clone())?, &mut finality).await?,
        1
    );
    rusqlite::Connection::open(&db)?.execute("DELETE FROM inbox", [])?;
    let replay = replay_block(
        resign(&transfer, 3, [0x22; 32])?,
        2,
        10_001,
        original[0].app_hash().clone(),
    )?;
    assert_eq!(poll_intent(&mut node, segment(vec![replay])?, &mut finality).await?, 0);
    let ControlResponse::Status(status) = node.control(ControlRequest::Status, true)? else {
        return Err("status".into());
    };
    let cursor = status.cursor.ok_or("cursor")?;
    assert_eq!(cursor.processed_refresh_count, 1);
    assert_eq!(cursor.last_refresh_entry_hash.as_bytes(), &transfer_hash);
    Ok(())
}

fn record_transfer_hash(record: &[u8]) -> std::result::Result<EntryHashV2, Box<dyn Error>> {
    let record: VerifiedRefreshRecordV2 = serde_json::from_slice(record)?;
    Ok(record.transfer.entry.metadata().entry_hash().clone())
}

fn test_semantic_digest(entry: &thunderbolt_ledger::ExecutedEntryV2) -> std::result::Result<[u8; 32], Box<dyn Error>> {
    let bytes = entry.proposal().body().canonical_bytes()?;
    let mut hasher = Sha256::new();
    hasher.update(b"bitcoin-thunderbolt/committee-node/entry-semantic/v2");
    hasher.update(u64::try_from(bytes.len())?.to_be_bytes());
    hasher.update(bytes);
    Ok(hasher.finalize().into())
}

#[tokio::test]
async fn wrong_profile_block_artifact_and_gap_leave_cursor_unchanged() -> std::result::Result<(), Box<dyn Error>> {
    let runtime = test_runtime()?;
    let directory = TempDir::new()?;
    let blocks = build_blocks(&runtime, 1, false, true, false)?;
    let mut node = CommitteeNode::open(temp_path(&directory, "profile.sqlite")?, runtime, config()?)?;
    assert!(matches!(
        poll_intent(&mut node, segment(blocks.clone())?, &mut WrongProfileFinality).await,
        Err(NodeError::FinalityRejected)
    ));
    let ControlResponse::Status(status) = node.control(ControlRequest::Status, true)? else {
        return Err("status".into());
    };
    assert!(status.cursor.is_none());
    drop(node);

    let role_path = temp_path(&directory, "wrong-block.sqlite")?;
    let mut node = CommitteeNode::open(&role_path, test_runtime()?, config()?)?;
    assert!(matches!(
        poll_intent(&mut node, segment(blocks.clone())?, &mut WrongBlockFinality).await,
        Err(NodeError::FinalityRejected)
    ));
    let staged_count: i64 =
        rusqlite::Connection::open(&role_path)?
            .query_row("SELECT count(*) FROM staged_finality_range", [], |row| row.get(0))?;
    assert_eq!(staged_count, 1);
    let recovery_runtime = node.into_runtime();
    let recovery = CommitteeNode::inspect_staged_finality_recovery(&role_path, &recovery_runtime, &config()?)?
        .ok_or("staged recovery")?;
    assert_eq!(recovery.intent(), &segment(blocks.clone())?);
    let role_blocks = build_blocks(&recovery_runtime, 1, false, true, false)?;
    let role_wrong_artifact = build_blocks(&recovery_runtime, 1, false, false, true)?;
    rusqlite::Connection::open(&role_path)?.execute("DELETE FROM staged_finality_range", [])?;
    let mut node = CommitteeNode::open(&role_path, recovery_runtime, config()?)?;
    let mut missing = ConfiguredFinality::with_mode(OccurrenceMode::OmitFirst);
    assert!(matches!(
        poll_intent(&mut node, segment(role_blocks.clone())?, &mut missing).await,
        Err(NodeError::InvalidLedgerArtifact)
    ));
    rusqlite::Connection::open(&role_path)?.execute("DELETE FROM staged_finality_range", [])?;
    let mut wrong_location = ConfiguredFinality::with_mode(OccurrenceMode::FlipFirst);
    assert!(matches!(
        poll_intent(&mut node, segment(role_blocks.clone())?, &mut wrong_location).await,
        Err(NodeError::FinalityRejected)
    ));
    rusqlite::Connection::open(&role_path)?.execute("DELETE FROM staged_finality_range", [])?;
    assert!(matches!(
        poll_intent(&mut node, segment(role_wrong_artifact)?, &mut AcceptFinality).await,
        Err(NodeError::RefreshBindingMismatch)
    ));
    rusqlite::Connection::open(&role_path)?.execute("DELETE FROM staged_finality_range", [])?;
    let gap = segment(role_blocks[1..].to_vec())?;
    assert!(matches!(
        poll_intent(&mut node, gap, &mut AcceptFinality).await,
        Err(NodeError::CursorConflict)
    ));
    let ControlResponse::Status(status) = node.control(ControlRequest::Status, true)? else {
        return Err("status".into());
    };
    assert!(status.cursor.is_none());
    Ok(())
}

#[test]
fn compact_256_member_record_is_measured_below_bound() -> std::result::Result<(), Box<dyn Error>> {
    let runtime = test_runtime()?;
    let blocks = build_blocks(&runtime, 256, true, false, false)?;
    let block = blocks.first().ok_or("block")?;
    let commitment = ExecutedBlockCommitmentV2::from_executed_block(block)?;
    let block_cap = block_capability(AcceptFinality.profile_id(), block)?;
    let record = VerifiedRefreshRecordV2 {
        blocks: RefreshBlockCommitmentsV2::Shared {
            commitment: commitment.clone(),
        },
        invoice: ExecutedEntryEvidenceV2 {
            entry: block.entries()[0].clone(),
            inclusion_proof: block.entry_proof(0)?,
        },
        transfer: ExecutedEntryEvidenceV2 {
            entry: block.entries()[1].clone(),
            inclusion_proof: block.entry_proof(1)?,
        },
        invoice_semantic_digest: test_semantic_digest(&block.entries()[0])?,
        transfer_semantic_digest: test_semantic_digest(&block.entries()[1])?,
        finality: DurableFinalityCapability::new(
            &RefreshBlockCommitmentsV2::Shared { commitment },
            block_cap.clone(),
            block_cap,
        )?,
    };
    let shared_measured = serde_json::to_vec(&record)?.len();
    assert_eq!(shared_measured, 3_397_957);
    assert!(shared_measured < MAX_INBOX_RECORD_BYTES);

    let distinct = build_blocks(&runtime, 256, false, false, false)?;
    let invoice_block = &distinct[0];
    let transfer_block = &distinct[1];
    let commitments = RefreshBlockCommitmentsV2::Distinct {
        invoice: ExecutedBlockCommitmentV2::from_executed_block(invoice_block)?,
        transfer: ExecutedBlockCommitmentV2::from_executed_block(transfer_block)?,
    };
    let invoice_cap = block_capability(AcceptFinality.profile_id(), invoice_block)?;
    let transfer_cap = block_capability(AcceptFinality.profile_id(), transfer_block)?;
    let record = VerifiedRefreshRecordV2 {
        blocks: commitments.clone(),
        invoice: ExecutedEntryEvidenceV2 {
            entry: invoice_block.entries()[0].clone(),
            inclusion_proof: invoice_block.entry_proof(0)?,
        },
        transfer: ExecutedEntryEvidenceV2 {
            entry: transfer_block.entries()[0].clone(),
            inclusion_proof: transfer_block.entry_proof(0)?,
        },
        invoice_semantic_digest: test_semantic_digest(&invoice_block.entries()[0])?,
        transfer_semantic_digest: test_semantic_digest(&transfer_block.entries()[0])?,
        finality: DurableFinalityCapability::new(&commitments, invoice_cap, transfer_cap)?,
    };
    let distinct_measured = serde_json::to_vec(&record)?.len();
    assert_eq!(distinct_measured, 3_398_991);
    assert!(distinct_measured < MAX_INBOX_RECORD_BYTES);
    assert!(shared_measured < distinct_measured);
    Ok(())
}

#[derive(Default)]
struct MemoryVault(Option<(u64, Vec<u8>)>);
impl CommitteeVault for MemoryVault {
    type Error = TestError;
    fn load(&mut self) -> std::result::Result<Option<VaultEntry>, Self::Error> {
        self.0
            .as_ref()
            .map(|(revision, bytes)| {
                VaultPlaintext::from_secret_bytes(bytes.clone())
                    .map(|plaintext| VaultEntry::new(*revision, plaintext))
                    .map_err(|_| TestError)
            })
            .transpose()
    }
    fn create(&mut self, entry: VaultEntry) -> std::result::Result<(), VaultStoreError<Self::Error>> {
        if self.0.is_some() {
            return Err(VaultStoreError::Conflict {
                current_revision: self.0.as_ref().map(|value| value.0),
            });
        }
        self.0 = Some((entry.revision(), entry.plaintext().expose_secret().to_vec()));
        Ok(())
    }
    fn compare_and_swap(
        &mut self,
        expected_revision: u64,
        entry: VaultEntry,
    ) -> std::result::Result<(), VaultStoreError<Self::Error>> {
        if self.0.as_ref().map(|value| value.0) != Some(expected_revision) {
            return Err(VaultStoreError::Conflict {
                current_revision: self.0.as_ref().map(|value| value.0),
            });
        }
        self.0 = Some((entry.revision(), entry.plaintext().expose_secret().to_vec()));
        Ok(())
    }
}

struct CountingClient {
    calls: Arc<AtomicUsize>,
}

struct BlockingClient {
    intent: Option<FinalityRangeIntentV2>,
    block_next: Arc<std::sync::atomic::AtomicBool>,
    entered: Arc<tokio::sync::Notify>,
    release: Arc<tokio::sync::Notify>,
}

impl BlockingClient {
    fn new(intent: Option<FinalityRangeIntentV2>) -> Self {
        Self {
            intent,
            block_next: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            entered: Arc::new(tokio::sync::Notify::new()),
            release: Arc::new(tokio::sync::Notify::new()),
        }
    }

    fn block_next(&self) {
        self.block_next.store(true, Ordering::SeqCst);
    }
}

impl SignedV2LedgerClient for BlockingClient {
    type Error = TestError;

    fn profile_id(&self) -> FinalityVerifierProfileId {
        AcceptFinality.profile_id()
    }

    fn coordinator_id(&self) -> FinalityCoordinatorId {
        AcceptFinality.coordinator_id()
    }

    fn prepare_finalized_execution<'a>(
        &'a mut self,
        _: Option<&'a LedgerCursor>,
        _: u16,
    ) -> LedgerFuture<'a, Option<FinalityRangeIntentV2>, Self::Error> {
        Box::pin(async move {
            if self.block_next.swap(false, Ordering::SeqCst) {
                self.entered.notify_one();
                self.release.notified().await;
            }
            Ok(self.intent.take())
        })
    }

    fn submit_signed_proposal<'a>(
        &'a mut self,
        _: &'a SignedProposalV2,
    ) -> LedgerFuture<'a, SubmissionStatus, Self::Error> {
        Box::pin(async { Err(TestError) })
    }
}
impl SignedV2LedgerClient for CountingClient {
    type Error = TestError;
    fn profile_id(&self) -> FinalityVerifierProfileId {
        AcceptFinality.profile_id()
    }
    fn coordinator_id(&self) -> FinalityCoordinatorId {
        AcceptFinality.coordinator_id()
    }
    fn prepare_finalized_execution<'a>(
        &'a mut self,
        _: Option<&'a LedgerCursor>,
        _: u16,
    ) -> LedgerFuture<'a, Option<FinalityRangeIntentV2>, Self::Error> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Box::pin(async { Err(TestError) })
    }
    fn submit_signed_proposal<'a>(
        &'a mut self,
        _: &'a SignedProposalV2,
    ) -> LedgerFuture<'a, SubmissionStatus, Self::Error> {
        Box::pin(async { Err(TestError) })
    }
}

#[tokio::test]
async fn legacy_engine_fails_before_fetch_or_cursor_advance() -> std::result::Result<(), Box<dyn Error>> {
    let directory = TempDir::new()?;
    let dealer = dealer_bootstrap(
        Network::Regtest,
        b"legacy-runtime",
        CommitteeEpoch::new(7),
        1,
        1,
        scalar(31)?.base_point_mul(),
        scalar(17)?,
    )?;
    let package = dealer.into_packages().into_iter().next().ok_or("package")?;
    let engine = CommitteeMemberEngine::provision(MemoryVault::default(), package)?;
    let calls = Arc::new(AtomicUsize::new(0));
    let mut client = CountingClient { calls: calls.clone() };
    let mut node = CommitteeNode::open(temp_path(&directory, "legacy.sqlite")?, engine, config()?)?;
    assert!(matches!(
        node.poll(&mut client, &mut AcceptFinality).await,
        Err(NodeError::V2RuntimeUnavailable)
    ));
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    let ControlResponse::Status(status) = node.control(ControlRequest::Status, true)? else {
        return Err("status".into());
    };
    assert!(!status.v2_runtime_available);
    assert!(status.cursor.is_none());
    Ok(())
}

#[tokio::test]
async fn missing_finality_capability_fails_before_async_fetch() -> std::result::Result<(), Box<dyn Error>> {
    let directory = TempDir::new()?;
    let calls = Arc::new(AtomicUsize::new(0));
    let mut client = CountingClient { calls: calls.clone() };
    let mut node = CommitteeNode::open(
        temp_path(&directory, "disabled-finality.sqlite")?,
        test_runtime()?,
        config()?,
    )?;
    assert!(matches!(
        node.poll(&mut client, &mut DisabledFinalityVerifier).await,
        Err(NodeError::FinalityUnavailable)
    ));
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    let ControlResponse::Status(status) = node.control(ControlRequest::Status, false)? else {
        return Err("status".into());
    };
    assert!(status.cursor.is_none());
    Ok(())
}

#[tokio::test]
async fn missing_ledger_capability_fails_before_cursor_access() -> std::result::Result<(), Box<dyn Error>> {
    let directory = TempDir::new()?;
    let mut client = DisabledSignedV2LedgerClient;
    let mut node = CommitteeNode::open(
        temp_path(&directory, "disabled-ledger.sqlite")?,
        test_runtime()?,
        config()?,
    )?;
    assert!(matches!(
        node.poll(&mut client, &mut AcceptFinality).await,
        Err(NodeError::FinalityUnavailable)
    ));
    let ControlResponse::Status(status) = node.control(ControlRequest::Status, false)? else {
        return Err("status".into());
    };
    assert!(status.cursor.is_none());
    Ok(())
}

#[tokio::test]
async fn cancelled_finality_verification_leaves_cursor_empty_then_replays_exact_page(
) -> std::result::Result<(), Box<dyn Error>> {
    let directory = TempDir::new()?;
    let runtime = test_runtime()?;
    let blocks = build_blocks(&runtime, 1, false, true, false)?;
    let page = segment(blocks)?;
    let path = temp_path(&directory, "async-finality.sqlite")?;
    let mut node = CommitteeNode::open(&path, runtime, config()?)?;
    let mut client = BlockingClient::new(Some(page.clone()));
    let mut finality = BlockingFinality::new();
    let entered = Arc::clone(&finality.entered);
    let release = Arc::clone(&finality.release);
    let mut ingesting = Box::pin(node.poll(&mut client, &mut finality));
    tokio::select! {
        () = entered.notified() => {}
        result = &mut ingesting => {
            return Err(format!("ingest returned before finality cancellation barrier: {result:?}").into());
        }
    }
    drop(ingesting);
    release.notify_one();
    let ControlResponse::Status(status) = node.control(ControlRequest::Status, true)? else {
        return Err("status".into());
    };
    assert!(status.cursor.is_none());
    let runtime = node.into_runtime();
    let recovery =
        CommitteeNode::inspect_staged_finality_recovery(&path, &runtime, &config()?)?.ok_or("staged recovery")?;
    assert_eq!(recovery.intent(), &page);
    let mut node = CommitteeNode::open_with_staged_recovery(&path, runtime, config()?, &recovery)?;
    assert_eq!(node.poll(&mut client, &mut finality).await?, 1);
    let ControlResponse::Status(status) = node.control(ControlRequest::Status, true)? else {
        return Err("status".into());
    };
    assert_eq!(status.cursor.ok_or("cursor")?.next_height, 4);
    Ok(())
}

#[tokio::test]
async fn cancelled_async_fetch_leaves_cursor_empty_then_exact_empty_block_page_replays(
) -> std::result::Result<(), Box<dyn Error>> {
    let directory = TempDir::new()?;
    let runtime = test_runtime()?;
    let blocks = build_blocks(&runtime, 1, false, true, false)?;
    assert!(blocks[1].entries().is_empty());
    let page = segment(blocks)?;
    let path = temp_path(&directory, "async-poll.sqlite")?;
    let mut node = CommitteeNode::open(&path, runtime, config()?)?;
    let mut client = BlockingClient::new(Some(page.clone()));
    client.block_next();
    let entered = Arc::clone(&client.entered);
    let release = Arc::clone(&client.release);
    let mut finality = AcceptFinality;
    let mut polling = Box::pin(node.poll(&mut client, &mut finality));
    tokio::select! {
        () = entered.notified() => {}
        result = &mut polling => return Err(format!("poll returned before cancellation barrier: {result:?}").into()),
    }
    drop(polling);
    release.notify_one();
    let ControlResponse::Status(status) = node.control(ControlRequest::Status, true)? else {
        return Err("status".into());
    };
    assert!(status.cursor.is_none());
    let staged_count: i64 =
        rusqlite::Connection::open(&path)?
            .query_row("SELECT count(*) FROM staged_finality_range", [], |row| row.get(0))?;
    assert_eq!(staged_count, 0);
    let runtime = node.into_runtime();
    let mut node = CommitteeNode::open(&path, runtime, config()?)?;

    assert_eq!(node.poll(&mut client, &mut finality).await?, 1);
    let ControlResponse::Status(status) = node.control(ControlRequest::Status, true)? else {
        return Err("status".into());
    };
    let cursor = status.cursor.ok_or("cursor")?;
    assert_eq!(cursor.next_height, 4);
    assert_eq!(
        &cursor.expected_previous_app_hash,
        page.next_expected_previous_app_hash()
    );

    let mut no_page = BlockingClient::new(None);
    assert_eq!(node.poll(&mut no_page, &mut finality).await?, 0);
    let ControlResponse::Status(after_none) = node.control(ControlRequest::Status, true)? else {
        return Err("status".into());
    };
    assert_eq!(after_none.cursor, Some(cursor));
    Ok(())
}

#[derive(Clone, Default)]
struct CheckpointStore(Arc<std::sync::Mutex<Option<(VaultIdentity, VaultCheckpoint)>>>);
#[derive(Debug)]
struct CheckpointError;
impl std::fmt::Display for CheckpointError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("checkpoint conflict")
    }
}
impl Error for CheckpointError {}
impl RollbackFloorStore for CheckpointStore {
    type Error = CheckpointError;
    fn load_checkpoint(&self, identity: VaultIdentity) -> std::result::Result<Option<VaultCheckpoint>, Self::Error> {
        let state = self.0.lock().map_err(|_| CheckpointError)?;
        Ok(state
            .as_ref()
            .and_then(|(stored, checkpoint)| (*stored == identity).then_some(*checkpoint)))
    }
    fn compare_and_swap_checkpoint(
        &self,
        identity: VaultIdentity,
        expected: Option<VaultCheckpoint>,
        next: VaultCheckpoint,
    ) -> std::result::Result<CheckpointCasOutcome, Self::Error> {
        let mut state = self.0.lock().map_err(|_| CheckpointError)?;
        let current = state
            .as_ref()
            .and_then(|(stored, checkpoint)| (*stored == identity).then_some(*checkpoint));
        if current == Some(next) {
            return Ok(CheckpointCasOutcome::AlreadyCurrent);
        }
        if current != expected {
            return Ok(CheckpointCasOutcome::Conflict(current));
        }
        *state = Some((identity, next));
        Ok(CheckpointCasOutcome::Advanced)
    }
}

fn vault_password() -> thunderbolt_keystore::Result<Password> {
    Password::from_bytes(b"committee node fork password".to_vec())
}

#[test]
fn copied_member_vaults_cannot_both_win_next_checkpoint() -> std::result::Result<(), Box<dyn Error>> {
    let directory = TempDir::new()?;
    let dealer = dealer_bootstrap(
        Network::Regtest,
        b"fork-deployment",
        CommitteeEpoch::new(9),
        1,
        1,
        scalar(31)?.base_point_mul(),
        scalar(17)?,
    )?;
    let descriptor = dealer.descriptor().clone();
    let member_id = descriptor.members().first().ok_or("member")?.id();
    let package = dealer.into_packages().into_iter().next().ok_or("package")?;
    let floor = CheckpointStore::default();
    let original = directory.path().join("member.vault");
    let copy = directory.path().join("member-copy.vault");
    let adapter = KeystoreCommitteeVault::create(
        &original,
        &descriptor,
        member_id,
        vault_password()?,
        KdfParams::new(MIN_ARGON2_MEMORY_KIB, MIN_ARGON2_ITERATIONS, 1)?,
        floor.clone(),
    )?;
    let engine = CommitteeMemberEngine::provision(adapter, package)?;
    let mut adapter = engine.into_vault();
    adapter.backup_to(&copy)?;
    drop(adapter);
    let first = KeystoreCommitteeVault::open(&original, &descriptor, member_id, vault_password()?, floor.clone())?;
    let second = KeystoreCommitteeVault::open(&copy, &descriptor, member_id, vault_password()?, floor.clone())?;
    let barrier = Arc::new(Barrier::new(2));
    let one = barrier.clone();
    let first_thread = std::thread::spawn(move || {
        let mut vault = first;
        one.wait();
        CommitteeVault::compare_and_swap(
            &mut vault,
            0,
            VaultEntry::new(1, VaultPlaintext::from_secret_bytes(vec![0xa1; 32]).ok()?),
        )
        .ok()
    });
    let second_thread = std::thread::spawn(move || {
        let mut vault = second;
        barrier.wait();
        CommitteeVault::compare_and_swap(
            &mut vault,
            0,
            VaultEntry::new(1, VaultPlaintext::from_secret_bytes(vec![0xb2; 32]).ok()?),
        )
        .ok()
    });
    let first_won = first_thread.join().map_err(|_| "first panic")?.is_some();
    let second_won = second_thread.join().map_err(|_| "second panic")?.is_some();
    assert_ne!(first_won, second_won);
    let losing_path = if first_won { copy } else { original };
    assert!(KeystoreCommitteeVault::open(losing_path, &descriptor, member_id, vault_password()?, floor).is_err());
    Ok(())
}
