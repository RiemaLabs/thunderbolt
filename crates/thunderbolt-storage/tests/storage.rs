use std::convert::Infallible;
use std::fs;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Barrier};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rusqlite::{params, Connection};
use tempfile::TempDir;
use thunderbolt_protocol::{
    Actor, ActorRole, Artifact, BitcoinTxid, ChannelEvent, ChannelId, ChannelSnapshot, Committee, Digest, EntryHash,
    EventKind, IdempotencyKey, ImplementationId, InvoiceEvent, InvoiceId, LedgerEntry, OpenEvent, ParticipantId,
    ProtocolError, ProtocolLimits, TransferEvent, VerificationEvidence, VerificationKind, MAX_ARTIFACT_BYTES,
};
use thunderbolt_storage::{
    ProposalDigest, SqliteStorage, StorageError, StorageOptions, VerifiedAppendError, CURRENT_SCHEMA_VERSION,
    MAX_PAGE_BYTES, MAX_PAGE_LIMIT,
};

fn participant(value: &str) -> ParticipantId {
    ParticipantId::new(value).expect("valid test participant")
}

fn artifact(byte: u8) -> Artifact {
    Artifact::new([byte]).expect("non-empty test artifact")
}

fn channel(byte: u8) -> ChannelId {
    ChannelId::new(BitcoinTxid::from_bytes([byte; 32]), 0)
}

fn evidence(kind: VerificationKind, at: u64) -> VerificationEvidence {
    VerificationEvidence::verified(
        kind,
        participant("verifier:local"),
        ImplementationId::new("thunderbolt-node/1.0.0").expect("valid implementation"),
        Digest::from_bytes([kind as u8 + 1; 32]),
        at,
    )
}

fn required_evidence(event: EventKind, at: u64) -> Vec<VerificationEvidence> {
    let kinds: &[VerificationKind] = match event {
        EventKind::Open => &[
            VerificationKind::FundingTransaction,
            VerificationKind::InitialState,
            VerificationKind::CommitteeQuorum,
        ],
        EventKind::Invoice => &[VerificationKind::InvoiceConsistencyProof],
        EventKind::Transfer => &[
            VerificationKind::TransferConsistencyProof,
            VerificationKind::AnchorTransition,
        ],
        EventKind::Finalize => &[
            VerificationKind::HolderOwnershipProof,
            VerificationKind::CommitteeQuorum,
        ],
    };
    kinds.iter().map(|kind| evidence(*kind, at)).collect()
}

fn open_entry(channel_id: ChannelId, at: u64) -> LedgerEntry {
    let holder = participant("holder:0");
    LedgerEntry::new(
        channel_id,
        0,
        EntryHash::ZERO,
        IdempotencyKey::new("open-0").expect("valid key"),
        Actor::new(holder.clone(), ActorRole::Holder),
        at,
        ChannelEvent::Open(OpenEvent {
            initial_holder: holder,
            committee: Committee::new(participant("committee:main"), 5, 3).expect("valid committee"),
            capacity_sat: 1_000_000,
            lock_key: artifact(1),
            initial_holder_anchor: artifact(2),
            initial_holder_ciphertext: artifact(3),
            verification: required_evidence(EventKind::Open, at),
        }),
    )
}

fn maximum_artifact_open_entry(channel_id: ChannelId, at: u64) -> LedgerEntry {
    let mut entry = open_entry(channel_id, at);
    let ChannelEvent::Open(event) = &mut entry.event else {
        unreachable!("open_entry always returns Open");
    };
    event.lock_key = Artifact::new(vec![1; MAX_ARTIFACT_BYTES]).expect("maximum lock key");
    event.initial_holder_anchor = Artifact::new(vec![2; MAX_ARTIFACT_BYTES]).expect("maximum anchor");
    event.initial_holder_ciphertext = Artifact::new(vec![3; MAX_ARTIFACT_BYTES]).expect("maximum ciphertext");
    entry
}

fn invoice_entry(
    snapshot: &ChannelSnapshot,
    invoice: &str,
    recipient_name: &str,
    idempotency_key: &str,
    at: u64,
) -> LedgerEntry {
    let recipient = participant(recipient_name);
    LedgerEntry::new(
        snapshot.channel_id,
        snapshot.next_sequence().expect("test sequence available"),
        snapshot.head_hash,
        IdempotencyKey::new(idempotency_key).expect("valid key"),
        Actor::new(recipient.clone(), ActorRole::Recipient),
        at,
        ChannelEvent::Invoice(InvoiceEvent {
            invoice_id: InvoiceId::new(invoice).expect("valid invoice"),
            recipient,
            recipient_encryption_key: artifact(4),
            public_delta: artifact(5),
            recipient_ciphertext: artifact(6),
            committee_package: artifact(7),
            invoice_proof: artifact(8),
            expires_at_ms: None,
            verification: required_evidence(EventKind::Invoice, at),
        }),
    )
}

fn transfer_entry(snapshot: &ChannelSnapshot, invoice: &str, recipient_name: &str, at: u64) -> LedgerEntry {
    LedgerEntry::new(
        snapshot.channel_id,
        snapshot.next_sequence().expect("test sequence available"),
        snapshot.head_hash,
        IdempotencyKey::new(format!("transfer-{invoice}")).expect("valid key"),
        Actor::new(snapshot.current_holder.clone(), ActorRole::Holder),
        at,
        ChannelEvent::Transfer(TransferEvent {
            invoice_id: InvoiceId::new(invoice).expect("valid invoice"),
            sender: snapshot.current_holder.clone(),
            recipient: participant(recipient_name),
            next_holder_anchor: artifact(9),
            next_holder_ciphertext: artifact(10),
            transfer_proof: artifact(11),
            verification: required_evidence(EventKind::Transfer, at),
        }),
    )
}

fn without_evidence(mut entry: LedgerEntry) -> LedgerEntry {
    match &mut entry.event {
        ChannelEvent::Open(event) => event.verification.clear(),
        ChannelEvent::Invoice(event) => event.verification.clear(),
        ChannelEvent::Transfer(event) => event.verification.clear(),
        ChannelEvent::Finalize(event) => event.verification.clear(),
    }
    entry
}

fn accept_proposal(
    context: thunderbolt_storage::VerifiedProposalContext<'_>,
) -> Result<Vec<VerificationEvidence>, Infallible> {
    Ok(required_evidence(
        context.proposal().event.kind(),
        context.ledger_time_ms(),
    ))
}

#[test]
fn append_read_paginate_and_reopen() {
    let directory = TempDir::new().expect("temp dir");
    let path = directory.path().join("node.db");
    let channel_id = channel(1);
    let storage = SqliteStorage::open(&path).expect("open storage");

    let open = open_entry(channel_id, 1_000);
    let opened = storage.append_entry(&open).expect("append open");
    assert_eq!(opened.sequence, 0);
    assert!(!opened.replayed);

    let invoice = invoice_entry(&opened.snapshot, "inv-1", "holder:1", "invoice-1", 2_000);
    let invoiced = storage.append_entry(&invoice).expect("append invoice");
    let transfer = transfer_entry(&invoiced.snapshot, "inv-1", "holder:1", 3_000);
    let transferred = storage.append_entry(&transfer).expect("append transfer");

    assert_eq!(
        storage.get_channel(&channel_id).expect("get channel"),
        Some(transferred.snapshot)
    );
    assert_eq!(
        storage.get_entry(&channel_id, 0).expect("get entry"),
        Some(open.clone())
    );
    assert_eq!(
        storage
            .find_entry_by_idempotency_key(&channel_id, &invoice.idempotency_key)
            .expect("idempotency lookup"),
        Some(invoice.clone())
    );
    assert_eq!(
        storage
            .get_entry_by_hash(&channel_id, &transfer.entry_hash())
            .expect("hash lookup"),
        Some(transfer.clone())
    );

    let first_page = storage.list_entries(&channel_id, None, 2).expect("first page");
    assert_eq!(first_page, vec![open.clone(), invoice.clone()]);
    let second_page = storage.list_entries(&channel_id, Some(1), 2).expect("second page");
    assert_eq!(second_page, vec![transfer.clone()]);
    assert!(matches!(
        storage.list_entries(&channel_id, None, 0),
        Err(StorageError::InvalidInput(_))
    ));
    assert!(matches!(
        storage.list_entries(&channel_id, None, MAX_PAGE_LIMIT + 1),
        Err(StorageError::InvalidInput(_))
    ));
    drop(storage);

    let reopened = SqliteStorage::open(&path).expect("reopen storage");
    assert_eq!(
        reopened
            .list_entries(&channel_id, None, 10)
            .expect("list after restart")
            .len(),
        3
    );
    assert_eq!(
        reopened.integrity_check().expect("integrity after restart"),
        thunderbolt_storage::IntegrityReport {
            channels_checked: 1,
            entries_checked: 3,
        }
    );
}

#[test]
fn pagination_enforces_a_serialized_byte_budget_for_maximum_artifacts() {
    let directory = TempDir::new().expect("temp dir");
    let storage = SqliteStorage::open(directory.path().join("large-pages.db")).expect("open storage");
    for index in 20_u8..23_u8 {
        storage
            .append_entry(&maximum_artifact_open_entry(channel(index), u64::from(index)))
            .expect("append maximum-size open entry");
    }

    assert!(matches!(
        storage.list_channels(None, 3),
        Err(StorageError::PageByteBudgetExceeded { .. })
    ));
    let first_page = storage.list_channels(None, 2).expect("bounded first page");
    assert_eq!(
        first_page.len(),
        2,
        "the third maximum snapshot must cross the byte budget"
    );
    let serialized_bytes: usize = first_page
        .iter()
        .map(|snapshot| serde_json::to_vec(snapshot).expect("serialize snapshot").len())
        .sum();
    assert!(serialized_bytes <= MAX_PAGE_BYTES);
    let second_page = storage
        .list_channels(Some(&first_page[1].channel_id), 3)
        .expect("bounded second page");
    assert_eq!(second_page.len(), 1);
}

#[test]
fn idempotency_is_exact_and_scoped_to_a_channel() {
    let directory = TempDir::new().expect("temp dir");
    let storage = SqliteStorage::open(directory.path().join("node.db")).expect("open storage");
    let first = open_entry(channel(2), 10);
    let second_channel = open_entry(channel(3), 10);

    let first_result = storage.append_entry(&first).expect("first append");
    let replay = storage.append_entry(&first).expect("exact replay");
    assert!(replay.replayed);
    assert_eq!(replay.snapshot, first_result.snapshot);

    let mut conflict = first.clone();
    conflict.occurred_at_ms += 1;
    assert!(matches!(
        storage.append_entry(&conflict),
        Err(StorageError::Protocol(ProtocolError::IdempotencyConflict { .. }))
    ));

    // Both Open entries deliberately use `open-0`; keys are channel-scoped.
    storage
        .append_entry(&second_channel)
        .expect("same key on another channel");
    let channels = storage.list_channels(None, 10).expect("list channels");
    assert_eq!(channels.len(), 2);
    let next = storage
        .list_channels(Some(&channels[0].channel_id), 1)
        .expect("next channel page");
    assert_eq!(next, vec![channels[1].clone()]);
}

#[test]
fn invoice_ids_remain_unique_after_consumption() {
    let directory = TempDir::new().expect("temp dir");
    let storage = SqliteStorage::open(directory.path().join("node.db")).expect("open storage");
    let opened = storage.append_entry(&open_entry(channel(4), 10)).expect("open");
    let invoice = invoice_entry(&opened.snapshot, "once", "holder:1", "invoice-once", 20);
    let invoiced = storage.append_entry(&invoice).expect("invoice");
    let transfer = transfer_entry(&invoiced.snapshot, "once", "holder:1", 30);
    let transferred = storage.append_entry(&transfer).expect("transfer");
    let reuse = invoice_entry(&transferred.snapshot, "once", "holder:2", "invoice-reuse", 40);

    assert!(matches!(
        storage.append_entry(&reuse),
        Err(StorageError::Protocol(ProtocolError::InvoiceAlreadyUsed { .. }))
    ));
    assert_eq!(
        storage
            .list_entries(&channel(4), None, 10)
            .expect("unchanged ledger")
            .len(),
        3
    );
}

#[test]
fn failed_snapshot_write_rolls_back_the_ledger_insert() {
    let directory = TempDir::new().expect("temp dir");
    let path = directory.path().join("node.db");
    let storage = SqliteStorage::open(&path).expect("open storage");
    let external = Connection::open(&path).expect("external connection");
    external
        .execute_batch(
            "CREATE TRIGGER test_reject_snapshot
             BEFORE INSERT ON channel_snapshots
             BEGIN SELECT RAISE(ABORT, 'injected snapshot failure'); END;",
        )
        .expect("install failure trigger");

    assert!(matches!(
        storage.append_entry(&open_entry(channel(5), 10)),
        Err(StorageError::Database(_))
    ));
    let ledger_rows: i64 = external
        .query_row("SELECT count(*) FROM ledger_entries", [], |row| row.get(0))
        .expect("count ledger");
    let snapshots: i64 = external
        .query_row("SELECT count(*) FROM channel_snapshots", [], |row| row.get(0))
        .expect("count snapshots");
    assert_eq!((ledger_rows, snapshots), (0, 0));

    external
        .execute_batch("DROP TRIGGER test_reject_snapshot")
        .expect("remove failure trigger");
    storage
        .append_entry(&open_entry(channel(5), 10))
        .expect("append after rollback");
}

#[test]
fn immediate_transactions_prevent_channel_forks() {
    let directory = TempDir::new().expect("temp dir");
    let path = directory.path().join("node.db");
    let initial = SqliteStorage::open(&path).expect("open storage");
    let opened = initial.append_entry(&open_entry(channel(6), 10)).expect("open");
    drop(initial);

    let left_entry = invoice_entry(&opened.snapshot, "left", "holder:left", "left-key", 20);
    let right_entry = invoice_entry(&opened.snapshot, "right", "holder:right", "right-key", 20);
    let barrier = Arc::new(Barrier::new(3));
    let mut handles = Vec::new();
    for entry in [left_entry, right_entry] {
        let path = path.clone();
        let barrier = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            let storage = SqliteStorage::open(path).expect("open concurrent storage");
            barrier.wait();
            storage.append_entry(&entry)
        }));
    }
    barrier.wait();
    let results: Vec<_> = handles
        .into_iter()
        .map(|handle| handle.join().expect("join writer"))
        .collect();
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);

    let storage = SqliteStorage::open(&path).expect("reopen");
    assert_eq!(
        storage
            .list_entries(&channel(6), None, 10)
            .expect("one successor")
            .len(),
        2
    );
    storage.integrity_check().expect("unforked ledger");
}

#[test]
fn trusted_ledger_time_is_sampled_after_waiting_for_the_writer_lock() {
    let directory = TempDir::new().expect("temp dir");
    let path = directory.path().join("ledger-time.db");
    let storage = Arc::new(SqliteStorage::open(&path).expect("open storage"));
    let blocker = Connection::open(&path).expect("blocking connection");
    blocker.execute_batch("BEGIN IMMEDIATE").expect("hold writer lock");

    let (ready_sender, ready_receiver) = mpsc::channel();
    let append_storage = Arc::clone(&storage);
    let handle = thread::spawn(move || {
        ready_sender.send(()).expect("signal append start");
        append_storage.append_entry(&open_entry(channel(12), 10))
    });
    ready_receiver.recv().expect("append started");
    thread::sleep(Duration::from_millis(75));
    let released_at_ms = u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock after epoch")
            .as_millis(),
    )
    .expect("timestamp fits u64");
    blocker.execute_batch("COMMIT").expect("release writer lock");

    let outcome = handle.join().expect("join append").expect("append after wait");
    assert!(
        outcome.snapshot.opened_at_ms >= released_at_ms,
        "ledger time must include time spent waiting for BEGIN IMMEDIATE"
    );
}

#[test]
fn verified_append_persists_evidence_snapshot_and_request_mapping_atomically() {
    let directory = TempDir::new().expect("temp dir");
    let path = directory.path().join("verified.db");
    let storage = SqliteStorage::open(&path).expect("open storage");
    let proposal = without_evidence(open_entry(channel(20), 10));
    let expected_digest = ProposalDigest::from_proposal(&proposal).expect("proposal digest");
    let observed_time = Arc::new(std::sync::Mutex::new(None));
    let callback_time = Arc::clone(&observed_time);

    let outcome = storage
        .append_verified_proposal(&proposal, |context| {
            assert_eq!(context.proposal(), &proposal);
            assert!(context.snapshot().is_none());
            assert!(context.pending_invoice_head().is_none());
            *callback_time.lock().expect("time lock") = Some(context.ledger_time_ms());
            accept_proposal(context)
        })
        .expect("verified append");
    let ledger_time = observed_time.lock().expect("time lock").expect("callback time");
    assert_eq!(outcome.proposal_digest, expected_digest);
    assert_eq!(outcome.snapshot.opened_at_ms, ledger_time);
    assert_eq!(outcome.snapshot.last_occurred_at_ms, ledger_time);
    assert!(!outcome.replayed);

    let committed = storage
        .get_entry(&proposal.channel_id, 0)
        .expect("read committed entry")
        .expect("committed entry");
    assert_eq!(committed.event.verification().len(), 3);
    assert!(committed
        .event
        .verification()
        .iter()
        .all(|evidence| evidence.verified_at_ms == ledger_time));
    let connection = Connection::open(&path).expect("raw connection");
    let counts = (
        connection
            .query_row("SELECT count(*) FROM ledger_entries", [], |row| row.get::<_, i64>(0))
            .expect("ledger count"),
        connection
            .query_row("SELECT count(*) FROM verification_evidence", [], |row| {
                row.get::<_, i64>(0)
            })
            .expect("evidence count"),
        connection
            .query_row("SELECT count(*) FROM channel_snapshots", [], |row| row.get::<_, i64>(0))
            .expect("snapshot count"),
        connection
            .query_row("SELECT count(*) FROM verified_requests", [], |row| row.get::<_, i64>(0))
            .expect("request count"),
    );
    assert_eq!(counts, (1, 3, 1, 1));
    let request_identity: (String, String) = connection
        .query_row("SELECT actor_id, idempotency_key FROM verified_requests", [], |row| {
            Ok((row.get(0)?, row.get(1)?))
        })
        .expect("request identity");
    assert_eq!(request_identity, ("holder:0".to_string(), "open-0".to_string()));
    storage.integrity_check().expect("verified records are consistent");
}

#[test]
fn verified_append_retry_uses_stable_digest_without_reinvoking_verifier() {
    let directory = TempDir::new().expect("temp dir");
    let path = directory.path().join("replay.db");
    let storage = SqliteStorage::open(&path).expect("open storage");
    let proposal = without_evidence(open_entry(channel(21), 10));
    let first = storage
        .append_verified_proposal(&proposal, accept_proposal)
        .expect("first append");
    drop(storage);
    let storage = SqliteStorage::open(&path).expect("reopen storage");
    let replay = storage
        .append_verified_proposal(&proposal, |_| -> Result<Vec<VerificationEvidence>, Infallible> {
            panic!("an exact committed proposal must not be verified twice")
        })
        .expect("idempotent replay");

    assert!(replay.replayed);
    assert_eq!(replay.proposal_digest, first.proposal_digest);
    assert_eq!(replay.entry_hash, first.entry_hash);
    assert_eq!(replay.snapshot, first.snapshot);
}

#[test]
fn conflicting_channel_request_key_is_rejected_before_verification() {
    let directory = TempDir::new().expect("temp dir");
    let storage = SqliteStorage::open(directory.path().join("request-conflict.db")).expect("open storage");
    let proposal = without_evidence(open_entry(channel(29), 10));
    storage
        .append_verified_proposal(&proposal, accept_proposal)
        .expect("first append");
    let mut conflict = proposal;
    conflict.occurred_at_ms += 1;
    let invoked = AtomicBool::new(false);

    let result = storage.append_verified_proposal(&conflict, |_| {
        invoked.store(true, Ordering::SeqCst);
        Ok::<_, Infallible>(Vec::new())
    });
    assert!(matches!(
        result,
        Err(VerifiedAppendError::Storage(StorageError::VerifiedRequestConflict(_)))
    ));
    assert!(!invoked.load(Ordering::SeqCst));
}

#[test]
fn client_evidence_is_rejected_before_the_verifier_callback() {
    let directory = TempDir::new().expect("temp dir");
    let storage = SqliteStorage::open(directory.path().join("client-evidence.db")).expect("open storage");
    let proposal = open_entry(channel(22), 10);
    let invoked = AtomicBool::new(false);

    let result = storage.append_verified_proposal(&proposal, |_| {
        invoked.store(true, Ordering::SeqCst);
        Ok::<_, Infallible>(Vec::new())
    });
    assert!(matches!(
        result,
        Err(VerifiedAppendError::Storage(StorageError::ClientVerificationEvidence))
    ));
    assert!(!invoked.load(Ordering::SeqCst));
}

#[test]
fn oversized_verifier_evidence_is_rejected_before_entry_preparation() {
    let directory = TempDir::new().expect("temp dir");
    let path = directory.path().join("oversized-evidence.db");
    let storage = SqliteStorage::open(&path).expect("open storage");
    let proposal = without_evidence(open_entry(channel(30), 10));
    let limit = ProtocolLimits::default().max_verifications_per_event;

    let result = storage.append_verified_proposal(&proposal, |context| {
        Ok::<_, Infallible>(vec![
            evidence(
                VerificationKind::FundingTransaction,
                context.ledger_time_ms(),
            );
            limit + 1
        ])
    });
    assert!(matches!(
        result,
        Err(VerifiedAppendError::Storage(
            StorageError::VerifierEvidenceLimitExceeded {
                limit: found_limit,
                found,
            }
        )) if found_limit == limit && found == limit + 1
    ));
    let connection = Connection::open(&path).expect("raw connection");
    for table in [
        "ledger_entries",
        "verification_evidence",
        "channel_snapshots",
        "verified_requests",
    ] {
        let count: i64 = connection
            .query_row(&format!("SELECT count(*) FROM {table}"), [], |row| row.get(0))
            .expect("table count");
        assert_eq!(count, 0, "{table} must remain empty");
    }
    drop(connection);
    storage
        .append_verified_proposal(&proposal, accept_proposal)
        .expect("same proposal remains retryable");
}

#[test]
fn verifier_rejection_rolls_back_and_leaves_the_digest_retryable() {
    let directory = TempDir::new().expect("temp dir");
    let path = directory.path().join("verifier-rollback.db");
    let storage = SqliteStorage::open(&path).expect("open storage");
    let proposal = without_evidence(open_entry(channel(23), 10));

    let rejected = storage.append_verified_proposal(&proposal, |_| {
        Err::<Vec<VerificationEvidence>, _>("rejected by test verifier")
    });
    assert!(matches!(
        rejected,
        Err(VerifiedAppendError::Verification("rejected by test verifier"))
    ));
    let connection = Connection::open(&path).expect("raw connection");
    for table in [
        "ledger_entries",
        "verification_evidence",
        "channel_snapshots",
        "verified_requests",
    ] {
        let count: i64 = connection
            .query_row(&format!("SELECT count(*) FROM {table}"), [], |row| row.get(0))
            .expect("table count");
        assert_eq!(count, 0, "{table} must roll back");
    }
    drop(connection);

    let retry = storage
        .append_verified_proposal(&proposal, accept_proposal)
        .expect("retry after verifier rejection");
    assert!(!retry.replayed);
}

#[test]
fn evidence_persistence_failure_rolls_back_every_verified_append_record() {
    let directory = TempDir::new().expect("temp dir");
    let path = directory.path().join("evidence-rollback.db");
    let storage = SqliteStorage::open(&path).expect("open storage");
    let connection = Connection::open(&path).expect("raw connection");
    connection
        .execute_batch(
            "CREATE TRIGGER test_reject_evidence
             BEFORE INSERT ON verification_evidence
             BEGIN SELECT RAISE(ABORT, 'injected evidence failure'); END;",
        )
        .expect("install failure trigger");
    let proposal = without_evidence(open_entry(channel(24), 10));

    assert!(matches!(
        storage.append_verified_proposal(&proposal, accept_proposal),
        Err(VerifiedAppendError::Storage(StorageError::Database(_)))
    ));
    for table in [
        "ledger_entries",
        "verification_evidence",
        "channel_snapshots",
        "verified_requests",
    ] {
        let count: i64 = connection
            .query_row(&format!("SELECT count(*) FROM {table}"), [], |row| row.get(0))
            .expect("table count");
        assert_eq!(count, 0, "{table} must roll back");
    }
    connection
        .execute_batch("DROP TRIGGER test_reject_evidence")
        .expect("drop failure trigger");
    storage
        .append_verified_proposal(&proposal, accept_proposal)
        .expect("append after rollback");
}

#[test]
fn request_mapping_failure_rolls_back_entry_evidence_and_snapshot() {
    let directory = TempDir::new().expect("temp dir");
    let path = directory.path().join("request-rollback.db");
    let storage = SqliteStorage::open(&path).expect("open storage");
    let connection = Connection::open(&path).expect("raw connection");
    connection
        .execute_batch(
            "CREATE TRIGGER test_reject_request_mapping
             BEFORE INSERT ON verified_requests
             BEGIN SELECT RAISE(ABORT, 'injected request mapping failure'); END;",
        )
        .expect("install failure trigger");
    let proposal = without_evidence(open_entry(channel(28), 10));

    assert!(matches!(
        storage.append_verified_proposal(&proposal, accept_proposal),
        Err(VerifiedAppendError::Storage(StorageError::Database(_)))
    ));
    for table in [
        "ledger_entries",
        "verification_evidence",
        "channel_snapshots",
        "verified_requests",
    ] {
        let count: i64 = connection
            .query_row(&format!("SELECT count(*) FROM {table}"), [], |row| row.get(0))
            .expect("table count");
        assert_eq!(count, 0, "{table} must roll back");
    }
}

#[test]
fn concurrent_verified_retries_invoke_the_verifier_exactly_once() {
    let directory = TempDir::new().expect("temp dir");
    let path = directory.path().join("verified-race.db");
    drop(SqliteStorage::open(&path).expect("initialize storage"));
    let proposal = Arc::new(without_evidence(open_entry(channel(25), 10)));
    let invocations = Arc::new(AtomicUsize::new(0));
    let barrier = Arc::new(Barrier::new(3));
    let mut handles = Vec::new();
    for _ in 0..2 {
        let path = path.clone();
        let proposal = Arc::clone(&proposal);
        let invocations = Arc::clone(&invocations);
        let barrier = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            let storage = SqliteStorage::open(path).expect("open concurrent storage");
            barrier.wait();
            storage.append_verified_proposal(&proposal, |context| {
                invocations.fetch_add(1, Ordering::SeqCst);
                accept_proposal(context)
            })
        }));
    }
    barrier.wait();
    let outcomes: Vec<_> = handles
        .into_iter()
        .map(|handle| handle.join().expect("join writer").expect("verified retry"))
        .collect();

    assert_eq!(invocations.load(Ordering::SeqCst), 1);
    assert_eq!(outcomes.iter().filter(|outcome| outcome.replayed).count(), 1);
    assert_eq!(outcomes[0].proposal_digest, outcomes[1].proposal_digest);
    assert_eq!(outcomes[0].entry_hash, outcomes[1].entry_hash);
    assert_eq!(outcomes[0].snapshot, outcomes[1].snapshot);
}

#[test]
fn transfer_callback_receives_the_exact_pending_invoice_head() {
    let directory = TempDir::new().expect("temp dir");
    let storage = SqliteStorage::open(directory.path().join("pending-head.db")).expect("open storage");
    let opened = storage
        .append_entry(&open_entry(channel(26), 10))
        .expect("open channel");
    let invoice_proposal = without_evidence(invoice_entry(
        &opened.snapshot,
        "invoice-head",
        "holder:next",
        "invoice-head-request",
        20,
    ));
    let invoiced = storage
        .append_verified_proposal(&invoice_proposal, accept_proposal)
        .expect("append invoice");
    let transfer_proposal = without_evidence(transfer_entry(&invoiced.snapshot, "invoice-head", "holder:next", 30));

    let transferred = storage
        .append_verified_proposal(&transfer_proposal, |context| {
            let snapshot = context.snapshot().expect("authoritative snapshot");
            let invoice_head = context.pending_invoice_head().expect("pending invoice head");
            assert_eq!(invoice_head.channel_id, snapshot.channel_id);
            assert_eq!(invoice_head.sequence, snapshot.last_sequence);
            assert_eq!(invoice_head.entry_hash(), snapshot.head_hash);
            let ChannelEvent::Invoice(invoice) = &invoice_head.event else {
                panic!("pending head must be an invoice")
            };
            assert_eq!(invoice.invoice_id.as_str(), "invoice-head");
            accept_proposal(context)
        })
        .expect("append transfer");
    assert_eq!(transferred.snapshot.current_holder, participant("holder:next"));
    assert!(transferred.snapshot.pending_invoice.is_none());
    storage.integrity_check().expect("integrity after transfer");
}

#[test]
fn verified_ledger_time_is_sampled_after_waiting_for_the_writer_lock() {
    let directory = TempDir::new().expect("temp dir");
    let path = directory.path().join("verified-ledger-time.db");
    let storage = Arc::new(SqliteStorage::open(&path).expect("open storage"));
    let blocker = Connection::open(&path).expect("blocking connection");
    blocker.execute_batch("BEGIN IMMEDIATE").expect("hold writer lock");
    let proposal = without_evidence(open_entry(channel(27), 10));
    let (time_sender, time_receiver) = mpsc::channel();
    let append_storage = Arc::clone(&storage);
    let handle = thread::spawn(move || {
        append_storage.append_verified_proposal(&proposal, |context| {
            time_sender.send(context.ledger_time_ms()).expect("send callback time");
            accept_proposal(context)
        })
    });
    thread::sleep(Duration::from_millis(75));
    let released_at_ms = u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock after epoch")
            .as_millis(),
    )
    .expect("timestamp fits u64");
    blocker.execute_batch("COMMIT").expect("release writer lock");

    let outcome = handle.join().expect("join append").expect("append after wait");
    let callback_time = time_receiver.recv().expect("callback time");
    assert!(callback_time >= released_at_ms);
    assert_eq!(outcome.snapshot.opened_at_ms, callback_time);
}

#[test]
fn simultaneous_first_open_applies_the_initial_migration_once() {
    let directory = TempDir::new().expect("temp dir");
    for attempt in 0..12 {
        let path = directory.path().join(format!("fresh-{attempt}.db"));
        let barrier = Arc::new(Barrier::new(3));
        let mut handles = Vec::new();
        for _ in 0..2 {
            let path = path.clone();
            let barrier = Arc::clone(&barrier);
            handles.push(thread::spawn(move || {
                barrier.wait();
                SqliteStorage::open(path)
            }));
        }
        barrier.wait();
        for handle in handles {
            drop(handle.join().expect("join opener").expect("concurrent first open"));
        }
        let connection = Connection::open(&path).expect("raw connection");
        let migrations: i64 = connection
            .query_row("SELECT count(*) FROM schema_migrations", [], |row| row.get(0))
            .expect("count migrations");
        assert_eq!(migrations, CURRENT_SCHEMA_VERSION);
    }
}

#[test]
fn version_one_database_is_upgraded_to_verified_append_schema() {
    let directory = TempDir::new().expect("temp dir");
    let path = directory.path().join("upgrade-v1.db");
    drop(SqliteStorage::open(&path).expect("create current database"));
    let connection = Connection::open(&path).expect("raw connection");
    connection
        .execute_batch(
            "DROP TABLE verified_requests;
             DROP TABLE verification_evidence;
             DELETE FROM schema_migrations WHERE version = 2;
             PRAGMA user_version = 1;",
        )
        .expect("construct version-one fixture");
    drop(connection);

    drop(SqliteStorage::open(&path).expect("upgrade version-one database"));
    let connection = Connection::open(&path).expect("inspect upgraded database");
    let version: i64 = connection
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .expect("schema version");
    let migrations: i64 = connection
        .query_row("SELECT count(*) FROM schema_migrations", [], |row| row.get(0))
        .expect("migration count");
    let verified_tables: i64 = connection
        .query_row(
            "SELECT count(*) FROM sqlite_schema
             WHERE type = 'table' AND name IN ('verified_requests', 'verification_evidence')",
            [],
            |row| row.get(0),
        )
        .expect("verified table count");
    assert_eq!(version, CURRENT_SCHEMA_VERSION);
    assert_eq!(migrations, CURRENT_SCHEMA_VERSION);
    assert_eq!(verified_tables, 2);
}

#[test]
fn upgraded_version_one_request_key_fails_before_verification() {
    let directory = TempDir::new().expect("temp dir");
    let path = directory.path().join("upgrade-v1-request.db");
    let imported_entry = open_entry(channel(31), 10);
    let storage = SqliteStorage::open(&path).expect("create current database");
    storage.append_entry(&imported_entry).expect("append imported entry");
    drop(storage);

    let connection = Connection::open(&path).expect("raw connection");
    connection
        .execute_batch(
            "DROP TABLE verified_requests;
             DROP TABLE verification_evidence;
             DELETE FROM schema_migrations WHERE version = 2;
             PRAGMA user_version = 1;",
        )
        .expect("construct populated version-one fixture");
    drop(connection);

    let storage = SqliteStorage::open(&path).expect("upgrade populated version-one database");
    let proposal = without_evidence(imported_entry);
    let invoked = AtomicBool::new(false);
    let result = storage.append_verified_proposal(&proposal, |_| {
        invoked.store(true, Ordering::SeqCst);
        Ok::<_, Infallible>(Vec::new())
    });
    assert!(matches!(
        result,
        Err(VerifiedAppendError::Storage(
            StorageError::MissingVerifiedRequestMapping
        ))
    ));
    assert!(!invoked.load(Ordering::SeqCst));
}

#[test]
fn backup_is_verified_restartable_and_never_overwrites() {
    let directory = TempDir::new().expect("temp dir");
    let source = directory.path().join("node.db");
    let backup = directory.path().join("backup.db");
    let storage = SqliteStorage::open(&source).expect("open storage");
    storage
        .append_entry(&open_entry(channel(7), 10))
        .expect("append WAL-resident entry");

    let report = storage.backup_to(&backup).expect("online backup");
    assert_eq!(report.channels_checked, 1);
    let restored = SqliteStorage::open(&backup).expect("reopen backup");
    assert!(restored.get_channel(&channel(7)).expect("read backup").is_some());
    drop(restored);

    let sentinel = directory.path().join("sentinel.db");
    fs::write(&sentinel, b"do-not-overwrite").expect("write sentinel");
    assert!(matches!(
        storage.backup_to(&sentinel),
        Err(StorageError::BackupDestinationExists(_))
    ));
    assert_eq!(fs::read(&sentinel).expect("read sentinel"), b"do-not-overwrite");
    assert!(matches!(
        storage.backup_to(&source),
        Err(StorageError::BackupDestinationExists(_))
    ));
}

#[cfg(unix)]
#[test]
fn backup_does_not_follow_or_replace_an_existing_symlink() {
    use std::os::unix::fs::symlink;

    let directory = TempDir::new().expect("temp dir");
    let source = directory.path().join("node.db");
    let target = directory.path().join("target.txt");
    let link = directory.path().join("backup-link.db");
    let storage = SqliteStorage::open(&source).expect("open storage");
    storage.append_entry(&open_entry(channel(8), 10)).expect("append");
    fs::write(&target, b"sentinel").expect("write target");
    symlink(&target, &link).expect("create symlink");

    assert!(matches!(
        storage.backup_to(&link),
        Err(StorageError::BackupDestinationExists(_))
    ));
    assert_eq!(fs::read(&target).expect("read target"), b"sentinel");
    assert!(fs::symlink_metadata(&link)
        .expect("link metadata")
        .file_type()
        .is_symlink());
}

#[test]
fn migrations_refuse_future_unrecognized_and_tampered_databases() {
    let directory = TempDir::new().expect("temp dir");

    let future = directory.path().join("future.db");
    let connection = Connection::open(&future).expect("future database");
    connection
        .pragma_update(None, "user_version", 999_i64)
        .expect("set future version");
    drop(connection);
    assert!(matches!(
        SqliteStorage::open(&future),
        Err(StorageError::UnsupportedSchema { found: 999, .. })
    ));

    let negative = directory.path().join("negative.db");
    let connection = Connection::open(&negative).expect("negative database");
    connection
        .pragma_update(None, "user_version", -1_i64)
        .expect("set negative version");
    drop(connection);
    assert!(matches!(
        SqliteStorage::open(&negative),
        Err(StorageError::InvalidSchemaVersion { found: -1 })
    ));

    let unrelated = directory.path().join("unrelated.db");
    Connection::open(&unrelated)
        .expect("unrelated database")
        .execute("CREATE TABLE unrelated(value TEXT)", [])
        .expect("create unrelated table");
    assert!(matches!(
        SqliteStorage::open(&unrelated),
        Err(StorageError::UnrecognizedDatabase(_))
    ));

    let tampered = directory.path().join("tampered.db");
    drop(SqliteStorage::open(&tampered).expect("create database"));
    Connection::open(&tampered)
        .expect("open raw database")
        .execute(
            "UPDATE schema_migrations SET checksum = zeroblob(32) WHERE version = 1",
            [],
        )
        .expect("tamper checksum");
    assert!(matches!(
        SqliteStorage::open(&tampered),
        Err(StorageError::MigrationChecksumMismatch { version: 1 })
    ));
}

#[test]
fn reducer_limits_are_persisted_and_must_match_on_reopen() {
    let directory = TempDir::new().expect("temp dir");
    let path = directory.path().join("limits.db");
    let protocol_limits = ProtocolLimits::new(100, 8).expect("valid limits");
    let options = StorageOptions {
        busy_timeout: Duration::from_secs(3),
        protocol_limits,
    };
    drop(SqliteStorage::open_with_options(&path, options.clone()).expect("create with limits"));

    assert!(matches!(
        SqliteStorage::open(&path),
        Err(StorageError::ProtocolLimitsMismatch {
            stored_entries: 100,
            stored_verifications: 8,
            ..
        })
    ));
    drop(SqliteStorage::open_with_options(&path, options).expect("reopen with same limits"));
}

#[test]
fn integrity_and_backup_reject_metadata_tampering() {
    let directory = TempDir::new().expect("temp dir");
    let path = directory.path().join("node.db");
    let backup = directory.path().join("must-not-publish.db");
    let storage = SqliteStorage::open(&path).expect("open storage");
    storage.append_entry(&open_entry(channel(10), 10)).expect("append");
    Connection::open(&path)
        .expect("external connection")
        .execute(
            "UPDATE schema_migrations SET checksum = zeroblob(32) WHERE version = 1",
            [],
        )
        .expect("tamper migration metadata");

    assert!(matches!(
        storage.integrity_check(),
        Err(StorageError::MigrationChecksumMismatch { version: 1 })
    ));
    assert!(matches!(
        storage.backup_to(&backup),
        Err(StorageError::MigrationChecksumMismatch { version: 1 })
    ));
    assert!(!backup.exists());
}

#[test]
fn ledger_rows_cannot_be_replaced_through_raw_sql() {
    let directory = TempDir::new().expect("temp dir");
    let path = directory.path().join("node.db");
    let storage = SqliteStorage::open(&path).expect("open storage");
    let entry = open_entry(channel(11), 10);
    storage.append_entry(&entry).expect("append");
    let external = Connection::open(&path).expect("external connection");
    let replacement = external.execute_batch(
        "INSERT OR REPLACE INTO ledger_entries(
             channel_id, sequence, entry_hash, previous_entry_hash, idempotency_key,
             created_invoice_id, protocol_version, occurred_at_ms, entry_json, recorded_at_ms
         )
         SELECT channel_id, sequence, entry_hash, previous_entry_hash, idempotency_key,
                created_invoice_id, protocol_version, occurred_at_ms, x'7b7d', recorded_at_ms
         FROM ledger_entries;",
    );
    assert!(replacement.is_err());
    assert_eq!(
        storage.get_entry(&entry.channel_id, 0).expect("read entry"),
        Some(entry)
    );
    storage.integrity_check().expect("ledger stayed intact");
}

#[test]
fn no_replace_checks_use_exact_unique_index_probes() {
    let directory = TempDir::new().expect("temp dir");
    let path = directory.path().join("plans.db");
    drop(SqliteStorage::open(&path).expect("create schema"));
    let connection = Connection::open(path).expect("raw connection");

    let plans = [
        (
            "EXPLAIN QUERY PLAN SELECT 1 FROM ledger_entries AS existing \
             WHERE existing.channel_id = ?1 AND existing.sequence = ?2",
            "channel_id=? AND sequence=?",
        ),
        (
            "EXPLAIN QUERY PLAN SELECT 1 FROM ledger_entries AS existing \
             WHERE existing.channel_id = ?1 AND existing.entry_hash = ?2",
            "channel_id=? AND entry_hash=?",
        ),
        (
            "EXPLAIN QUERY PLAN SELECT 1 FROM ledger_entries AS existing \
             WHERE existing.channel_id = ?1 AND existing.idempotency_key = ?2",
            "channel_id=? AND idempotency_key=?",
        ),
        (
            "EXPLAIN QUERY PLAN SELECT 1 FROM ledger_entries AS existing \
             WHERE existing.channel_id = ?1 AND existing.created_invoice_id = ?2",
            "channel_id=? AND created_invoice_id=?",
        ),
    ];
    for (sql, expected_probe) in plans {
        let detail: String = connection
            .query_row(sql, params![channel(1).to_string(), "probe"], |row| row.get(3))
            .expect("query plan");
        assert!(
            detail.contains(expected_probe),
            "expected exact indexed probe {expected_probe}, got: {detail}"
        );
    }
}

#[test]
fn integrity_check_detects_tampered_snapshot_json() {
    let directory = TempDir::new().expect("temp dir");
    let path = directory.path().join("node.db");
    let storage = SqliteStorage::open(&path).expect("open storage");
    storage.append_entry(&open_entry(channel(9), 10)).expect("append");
    let external = Connection::open(&path).expect("external connection");
    external
        .execute("UPDATE channel_snapshots SET snapshot_json = x'7b7d'", [])
        .expect("tamper snapshot JSON");

    assert!(matches!(
        storage.integrity_check(),
        Err(StorageError::IntegrityCheckFailed(_))
    ));
}
