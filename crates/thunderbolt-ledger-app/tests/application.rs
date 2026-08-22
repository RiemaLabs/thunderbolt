mod common;

use std::error::Error;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

use common::*;
use tempfile::TempDir;
use thunderbolt_ledger::{ActorRoleV2, AppHashV2, EntryHashV2};
use thunderbolt_ledger_app::{
    ApplicationError, ApplicationOptions, BlockInputV2, LedgerApplication, APPLICATION_VERSION_V2,
};
use thunderbolt_protocol::v2::{
    ExternalVerifierV2, FinalizeVerificationRequestV2, InvoiceVerificationRequestV2, OpenVerificationRequestV2,
    ProtocolLimitsV2, TransferVerificationRequestV2,
};

#[derive(Debug, Default)]
struct AcceptAll;

impl ExternalVerifierV2 for AcceptAll {
    type Error = ();

    fn verify_open(&self, _request: OpenVerificationRequestV2<'_>) -> Result<(), Self::Error> {
        Ok(())
    }

    fn verify_invoice(&self, _request: InvoiceVerificationRequestV2<'_>) -> Result<(), Self::Error> {
        Ok(())
    }

    fn verify_transfer(&self, _request: TransferVerificationRequestV2<'_>) -> Result<(), Self::Error> {
        Ok(())
    }

    fn verify_finalize(&self, _request: FinalizeVerificationRequestV2<'_>) -> Result<(), Self::Error> {
        Ok(())
    }
}

#[derive(Debug)]
struct RejectInvoiceAt {
    calls: AtomicUsize,
    reject_at: usize,
}

#[derive(Debug, Default)]
struct RejectAll {
    calls: AtomicUsize,
}

impl RejectAll {
    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }

    fn reject(&self) -> Result<(), ()> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Err(())
    }
}

impl ExternalVerifierV2 for RejectAll {
    type Error = ();

    fn verify_open(&self, _request: OpenVerificationRequestV2<'_>) -> Result<(), Self::Error> {
        self.reject()
    }

    fn verify_invoice(&self, _request: InvoiceVerificationRequestV2<'_>) -> Result<(), Self::Error> {
        self.reject()
    }

    fn verify_transfer(&self, _request: TransferVerificationRequestV2<'_>) -> Result<(), Self::Error> {
        self.reject()
    }

    fn verify_finalize(&self, _request: FinalizeVerificationRequestV2<'_>) -> Result<(), Self::Error> {
        self.reject()
    }
}

impl RejectInvoiceAt {
    fn new(reject_at: usize) -> Self {
        Self {
            calls: AtomicUsize::new(0),
            reject_at,
        }
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

impl ExternalVerifierV2 for RejectInvoiceAt {
    type Error = ();

    fn verify_open(&self, _request: OpenVerificationRequestV2<'_>) -> Result<(), Self::Error> {
        Ok(())
    }

    fn verify_invoice(&self, _request: InvoiceVerificationRequestV2<'_>) -> Result<(), Self::Error> {
        let call = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
        if call == self.reject_at {
            Err(())
        } else {
            Ok(())
        }
    }

    fn verify_transfer(&self, _request: TransferVerificationRequestV2<'_>) -> Result<(), Self::Error> {
        Ok(())
    }

    fn verify_finalize(&self, _request: FinalizeVerificationRequestV2<'_>) -> Result<(), Self::Error> {
        Ok(())
    }
}

fn application(directory: &TempDir) -> Result<LedgerApplication, Box<dyn Error>> {
    Ok(LedgerApplication::open(
        directory.path().join("ledger-app.sqlite3"),
        chain_id(),
        ApplicationOptions::default(),
    )?)
}

fn block(
    height: u64,
    time: u64,
    previous: AppHashV2,
    proposals: Vec<thunderbolt_ledger::SignedProposalV2>,
) -> Result<BlockInputV2, Box<dyn Error>> {
    Ok(BlockInputV2::new(chain_id(), height, time, previous, proposals)?)
}

fn open_proposal(channel_byte: u8) -> thunderbolt_ledger::SignedProposalV2 {
    proposal(
        binding(channel_byte),
        &open_event(),
        0,
        EntryHashV2::zero(),
        1,
        ActorRoleV2::Holder,
        [1; 16],
    )
}

fn sqlite_bytes(path: &Path) -> Result<Vec<Vec<u8>>, Box<dyn Error>> {
    let mut paths = vec![path.to_path_buf()];
    let mut wal = OsString::from(path.as_os_str());
    wal.push("-wal");
    paths.push(PathBuf::from(wal));
    paths
        .into_iter()
        .filter(|candidate| candidate.exists())
        .map(|candidate| std::fs::read(candidate).map_err(Into::into))
        .collect()
}

#[test]
fn preview_is_byte_exact_until_prepared_commit() -> Result<(), Box<dyn Error>> {
    let directory = TempDir::new()?;
    let path = directory.path().join("ledger-app.sqlite3");
    let app = application(&directory)?;
    let input = block(1, 1_000, zero_app_hash(), vec![open_proposal(21)])?;
    let before = sqlite_bytes(&path)?;

    let prepared = app.preview_block(input, &AcceptAll)?;
    assert_eq!(prepared.outcome().block().height(), 1);
    assert_eq!(sqlite_bytes(&path)?, before);
    assert_eq!(app.status()?.last_height(), 0);
    assert!(app.block(1)?.is_none());
    assert!(app.channel(&binding(21))?.is_none());

    let committed = app.commit_prepared_block(prepared, &AcceptAll)?;
    assert_eq!(committed.block().height(), 1);
    assert_eq!(app.status()?.last_app_hash(), committed.block().app_hash());
    assert!(app.channel(&binding(21))?.is_some());
    Ok(())
}

#[test]
fn rejected_preview_and_rejected_commit_leave_no_state() -> Result<(), Box<dyn Error>> {
    let directory = TempDir::new()?;
    let app = application(&directory)?;
    let input = block(1, 1_000, zero_app_hash(), vec![open_proposal(22)])?;
    assert!(matches!(
        app.preview_block(input.clone(), &RejectAll::default()),
        Err(ApplicationError::Protocol(_))
    ));
    assert_eq!(app.status()?.last_height(), 0);

    let prepared = app.preview_block(input, &AcceptAll)?;
    assert!(matches!(
        app.commit_prepared_block(prepared.clone(), &RejectAll::default()),
        Err(ApplicationError::Protocol(_))
    ));
    assert_eq!(app.status()?.last_height(), 0);
    let committed = app.commit_prepared_block(prepared, &AcceptAll)?;
    assert_eq!(committed.block().height(), 1);
    Ok(())
}

#[test]
fn prepared_commit_rejects_a_concurrent_conflicting_tip() -> Result<(), Box<dyn Error>> {
    let directory = TempDir::new()?;
    let app = application(&directory)?;
    let prepared = app.preview_block(block(1, 1_000, zero_app_hash(), vec![open_proposal(23)])?, &AcceptAll)?;
    let competing = app.apply_block(block(1, 1_001, zero_app_hash(), vec![open_proposal(24)])?, &AcceptAll)?;
    assert!(matches!(
        app.commit_prepared_block(prepared, &AcceptAll),
        Err(ApplicationError::BlockConflict { height: 1 })
    ));
    assert_eq!(app.status()?.last_app_hash(), competing.block().app_hash());
    assert!(app.channel(&binding(23))?.is_none());
    assert!(app.channel(&binding(24))?.is_some());
    Ok(())
}

#[test]
fn prepared_block_reexecutes_after_application_restart() -> Result<(), Box<dyn Error>> {
    let directory = TempDir::new()?;
    let prepared = {
        let app = application(&directory)?;
        app.preview_block(block(1, 1_000, zero_app_hash(), vec![open_proposal(25)])?, &AcceptAll)?
    };
    let reopened = application(&directory)?;
    assert_eq!(reopened.status()?.last_height(), 0);
    let committed = reopened.commit_prepared_block(prepared, &AcceptAll)?;
    assert_eq!(committed.block().height(), 1);
    drop(reopened);
    assert_eq!(application(&directory)?.status()?.last_height(), 1);
    Ok(())
}

#[test]
fn committed_block_restarts_and_replays_exactly() -> Result<(), Box<dyn Error>> {
    let directory = TempDir::new()?;
    let app = application(&directory)?;
    assert_eq!(app.application_version(), APPLICATION_VERSION_V2);
    let input = block(1, 1_000, zero_app_hash(), vec![open_proposal(1)])?;
    let committed = app.apply_block(input.clone(), &AcceptAll)?;
    assert!(!committed.replayed_block());
    assert_eq!(committed.applied_entries(), 1);
    assert_eq!(committed.replayed_entries(), 0);
    assert_eq!(committed.block().height(), 1);
    assert_eq!(committed.app_hash_for_next_header(), committed.block().app_hash());

    let replay = app.apply_block(input.clone(), &RejectInvoiceAt::new(1))?;
    assert!(replay.replayed_block());
    assert_eq!(replay.block(), committed.block());
    drop(app);

    let reopened = application(&directory)?;
    let replay = reopened.apply_block(input, &RejectInvoiceAt::new(1))?;
    assert!(replay.replayed_block());
    assert_eq!(reopened.status()?.last_height(), 1);
    assert_eq!(reopened.status()?.last_app_hash(), committed.block().app_hash());
    let report = reopened.integrity_check()?;
    assert_eq!(report.blocks, 1);
    assert_eq!(report.entries, 1);
    assert_eq!(report.channels, 1);
    Ok(())
}

#[test]
fn channel_and_request_reads_are_bound_to_one_exact_head() -> Result<(), Box<dyn Error>> {
    let directory = TempDir::new()?;
    let app = application(&directory)?;
    let open = open_proposal(26);
    let context = thunderbolt_ledger::ChannelContextIdV2::from_bytes(open.body().channel().context_id()?)?;
    let participant = open.body().participant_id()?;
    let request_digest = open.body().request_id().digest().clone();
    let before_channel = app.channel_at_head(&context)?;
    let before_request = app.request_at_head(&context, &participant, &request_digest)?;
    assert_eq!(before_channel.status().last_height(), 0);
    assert!(before_channel.channel().is_none());
    assert_eq!(before_request.status().last_height(), 0);
    assert!(before_request.request().is_none());

    let committed = app.apply_block(block(1, 1_000, zero_app_hash(), vec![open])?, &AcceptAll)?;
    let channel = app.channel_at_head(&context)?;
    let request = app.request_at_head(&context, &participant, &request_digest)?;
    assert_eq!(channel.status().last_height(), 1);
    assert_eq!(channel.status().last_app_hash(), committed.block().app_hash());
    assert!(channel.channel().is_some());
    assert_eq!(request.status(), channel.status());
    assert_eq!(request.request().ok_or("request")?.first_height(), 1);
    Ok(())
}

#[test]
fn actor_request_replay_in_a_new_block_skips_external_verification() -> Result<(), Box<dyn Error>> {
    let directory = TempDir::new()?;
    let app = application(&directory)?;
    let open = open_proposal(7);
    let first = app.apply_block(block(1, 1_000, zero_app_hash(), vec![open.clone()])?, &AcceptAll)?;
    let reject = RejectAll::default();
    let replay = app.apply_block(block(2, 1_001, first.block().app_hash().clone(), vec![open])?, &reject)?;
    assert!(!replay.replayed_block());
    assert_eq!(replay.applied_entries(), 0);
    assert_eq!(replay.replayed_entries(), 1);
    assert_eq!(reject.calls(), 0);
    let snapshot = app.channel(&binding(7))?.ok_or("Open snapshot")?;
    assert_eq!(snapshot.last_sequence, 0);
    assert_eq!(app.integrity_check()?.requests, 1);
    Ok(())
}

#[test]
fn late_sqlite_failure_rolls_back_request_and_channel_rows() -> Result<(), Box<dyn Error>> {
    let directory = TempDir::new()?;
    let path = directory.path().join("ledger-app.sqlite3");
    let app = application(&directory)?;
    let blocker = rusqlite::Connection::open(&path)?;
    blocker.execute_batch(
        "CREATE TRIGGER injected_block_failure
         BEFORE INSERT ON blocks
         BEGIN SELECT RAISE(ABORT, 'injected block failure'); END;",
    )?;
    let open = open_proposal(8);
    assert!(matches!(
        app.preview_block(block(1, 1_000, zero_app_hash(), vec![open.clone()])?, &AcceptAll),
        Err(ApplicationError::Database(_))
    ));
    assert_eq!(app.status()?.last_height(), 0);
    assert!(matches!(
        app.apply_block(block(1, 1_000, zero_app_hash(), vec![open.clone()])?, &AcceptAll),
        Err(ApplicationError::Database(_))
    ));
    assert_eq!(app.status()?.last_height(), 0);
    assert!(app.channel(&binding(8))?.is_none());
    let context = thunderbolt_ledger::ChannelContextIdV2::from_bytes(open.body().channel().context_id()?)?;
    assert!(app
        .request(
            &context,
            &open.body().participant_id()?,
            open.body().request_id().digest()
        )?
        .is_none());
    blocker.execute_batch("DROP TRIGGER injected_block_failure")?;
    let applied = app.apply_block(block(1, 1_000, zero_app_hash(), vec![open])?, &AcceptAll)?;
    assert_eq!(applied.applied_entries(), 1);
    Ok(())
}

#[test]
fn block_rejection_rolls_back_requests_invoices_and_state() -> Result<(), Box<dyn Error>> {
    let directory = TempDir::new()?;
    let app = application(&directory)?;
    let open = open_proposal(2);
    let first = app.apply_block(block(1, 1_000, zero_app_hash(), vec![open.clone()])?, &AcceptAll)?;
    let channel = binding(2);
    let invoice_one = invoice_event(1, 0, 10_000);
    let signed_one = proposal(
        channel.clone(),
        &invoice_one,
        1,
        open.body().entry_hash()?,
        2,
        ActorRoleV2::Recipient,
        [2; 16],
    );
    let invoice_two = invoice_event(2, 0, 10_000);
    let signed_two = proposal(
        channel.clone(),
        &invoice_two,
        2,
        signed_one.body().entry_hash()?,
        3,
        ActorRoleV2::Recipient,
        [3; 16],
    );
    let verifier = RejectInvoiceAt::new(2);
    let result = app.apply_block(
        block(
            2,
            1_001,
            first.block().app_hash().clone(),
            vec![signed_one.clone(), signed_two.clone()],
        )?,
        &verifier,
    );
    assert!(matches!(result, Err(ApplicationError::Protocol(_))));
    assert_eq!(verifier.calls(), 2);
    assert_eq!(app.status()?.last_height(), 1);
    assert!(app.block(2)?.is_none());
    let snapshot = app.channel(&channel)?.ok_or("Open snapshot")?;
    assert!(snapshot.pending_invoices.is_empty());
    for signed in [&signed_one, &signed_two] {
        let context = thunderbolt_ledger::ChannelContextIdV2::from_bytes(signed.body().channel().context_id()?)?;
        let participant = signed.body().participant_id()?;
        assert!(app
            .request(&context, &participant, signed.body().request_id().digest())?
            .is_none());
    }
    Ok(())
}

#[test]
fn conflicting_request_fails_before_external_verification() -> Result<(), Box<dyn Error>> {
    let directory = TempDir::new()?;
    let app = application(&directory)?;
    let open = open_proposal(3);
    let block_one = app.apply_block(block(1, 1_000, zero_app_hash(), vec![open.clone()])?, &AcceptAll)?;
    let channel = binding(3);
    let invoice = invoice_event(10, 0, 10_000);
    let first = proposal(
        channel.clone(),
        &invoice,
        1,
        open.body().entry_hash()?,
        2,
        ActorRoleV2::Recipient,
        [9; 16],
    );
    let block_two = app.apply_block(
        block(2, 1_001, block_one.block().app_hash().clone(), vec![first.clone()])?,
        &AcceptAll,
    )?;

    let conflicting_event = invoice_event(11, 0, 10_001);
    let conflict = proposal(
        channel,
        &conflicting_event,
        2,
        first.body().entry_hash()?,
        2,
        ActorRoleV2::Recipient,
        [9; 16],
    );
    assert_eq!(
        conflict.body().request_id().digest(),
        first.body().request_id().digest()
    );
    let verifier = RejectInvoiceAt::new(1);
    let result = app.apply_block(
        block(3, 1_002, block_two.block().app_hash().clone(), vec![conflict])?,
        &verifier,
    );
    assert!(matches!(result, Err(ApplicationError::RequestConflict)));
    assert_eq!(verifier.calls(), 0);
    assert_eq!(app.status()?.last_height(), 2);
    Ok(())
}

#[test]
fn concurrent_invoices_transfer_and_lifetime_history_are_exact() -> Result<(), Box<dyn Error>> {
    let directory = TempDir::new()?;
    let app = application(&directory)?;
    let open = open_proposal(4);
    let one = app.apply_block(block(1, 1_000, zero_app_hash(), vec![open.clone()])?, &AcceptAll)?;
    let channel = binding(4);
    let invoice_one = invoice_event(1, 0, 10_000);
    let first = proposal(
        channel.clone(),
        &invoice_one,
        1,
        open.body().entry_hash()?,
        2,
        ActorRoleV2::Recipient,
        [11; 16],
    );
    let invoice_two = invoice_event(2, 0, 10_000);
    let second = proposal(
        channel.clone(),
        &invoice_two,
        2,
        first.body().entry_hash()?,
        3,
        ActorRoleV2::Recipient,
        [12; 16],
    );
    let two = app.apply_block(
        block(
            2,
            1_001,
            one.block().app_hash().clone(),
            vec![first.clone(), second.clone()],
        )?,
        &AcceptAll,
    )?;
    let snapshot = app.channel(&channel)?.ok_or("Invoice snapshot")?;
    assert_eq!(snapshot.pending_invoices.len(), 2);

    let transfer = transfer_event(&snapshot, 1);
    let signed_transfer = proposal(
        channel.clone(),
        &transfer,
        3,
        second.body().entry_hash()?,
        1,
        ActorRoleV2::Holder,
        [13; 16],
    );
    let three = app.apply_block(
        block(3, 1_002, two.block().app_hash().clone(), vec![signed_transfer])?,
        &AcceptAll,
    )?;
    let snapshot = app.channel(&channel)?.ok_or("Transfer snapshot")?;
    assert_eq!(snapshot.transfers_completed, 1);
    assert!(snapshot.pending_invoices.is_empty());

    let repeated = invoice_event(1, 1, 10_100);
    let repeated = proposal(
        channel,
        &repeated,
        4,
        three.block().entries()[0].metadata().entry_hash().clone(),
        4,
        ActorRoleV2::Recipient,
        [14; 16],
    );
    let result = app.apply_block(
        block(4, 1_003, three.block().app_hash().clone(), vec![repeated])?,
        &AcceptAll,
    );
    assert!(matches!(result, Err(ApplicationError::Protocol(_))));
    assert_eq!(app.status()?.last_height(), 3);
    let report = app.integrity_check()?;
    assert_eq!(report.invoices, 2);
    Ok(())
}

#[test]
fn chain_height_hash_and_consensus_time_are_external_and_exact() -> Result<(), Box<dyn Error>> {
    assert!(BlockInputV2::new(chain_id(), 1, 0, zero_app_hash(), Vec::new()).is_err());
    let directory = TempDir::new()?;
    let app = application(&directory)?;
    let one = app.apply_block(block(1, 50, zero_app_hash(), Vec::new())?, &AcceptAll)?;
    let wrong_chain = BlockInputV2::new(
        thunderbolt_ledger::LedgerChainIdV2::new("other-chain")?,
        2,
        51,
        one.block().app_hash().clone(),
        Vec::new(),
    )?;
    assert!(matches!(
        app.apply_block(wrong_chain, &AcceptAll),
        Err(ApplicationError::LedgerChainMismatch)
    ));
    assert!(matches!(
        app.apply_block(block(3, 51, one.block().app_hash().clone(), Vec::new())?, &AcceptAll),
        Err(ApplicationError::HeightGap { .. })
    ));
    assert!(matches!(
        app.apply_block(block(2, 51, AppHashV2::from_bytes([9; 32])?, Vec::new())?, &AcceptAll),
        Err(ApplicationError::AppHashMismatch)
    ));
    assert!(matches!(
        app.apply_block(block(2, 49, one.block().app_hash().clone(), Vec::new())?, &AcceptAll),
        Err(ApplicationError::BlockTimeRegression { .. })
    ));
    let two = app.apply_block(block(2, 50, one.block().app_hash().clone(), Vec::new())?, &AcceptAll)?;
    assert_eq!(two.block().block_time_ms(), 50);
    assert_eq!(app.status()?.last_height(), 2);
    Ok(())
}

#[test]
fn schema_reopen_pins_chain_and_protocol_limits() -> Result<(), Box<dyn Error>> {
    let directory = TempDir::new()?;
    let path = directory.path().join("pinned.sqlite3");
    let limits = ProtocolLimitsV2::new(500, 4, 60_000)?;
    let options = ApplicationOptions {
        protocol_limits: limits,
        ..ApplicationOptions::default()
    };
    let app = LedgerApplication::open(&path, chain_id(), options.clone())?;
    assert_eq!(app.status()?.last_height(), 0);
    drop(app);
    let reopened = LedgerApplication::open(&path, chain_id(), options)?;
    assert_eq!(reopened.status()?.application_version(), APPLICATION_VERSION_V2);
    drop(reopened);

    assert!(matches!(
        LedgerApplication::open(
            &path,
            thunderbolt_ledger::LedgerChainIdV2::new("different-chain")?,
            ApplicationOptions {
                protocol_limits: limits,
                ..ApplicationOptions::default()
            },
        ),
        Err(ApplicationError::ConfigurationMismatch)
    ));
    assert!(matches!(
        LedgerApplication::open(
            &path,
            chain_id(),
            ApplicationOptions {
                protocol_limits: ProtocolLimitsV2::new(501, 4, 60_000)?,
                ..ApplicationOptions::default()
            },
        ),
        Err(ApplicationError::ConfigurationMismatch)
    ));

    let profiled_path = directory.path().join("profiled.sqlite3");
    let profile = [0x51; 32];
    let profiled = LedgerApplication::open(
        &profiled_path,
        chain_id(),
        ApplicationOptions {
            consensus_profile_digest: Some(profile),
            ..ApplicationOptions::default()
        },
    )?;
    assert_eq!(profiled.consensus_profile_digest(), Some(&profile));
    drop(profiled);
    assert!(matches!(
        LedgerApplication::open(
            &profiled_path,
            chain_id(),
            ApplicationOptions {
                consensus_profile_digest: Some([0x52; 32]),
                ..ApplicationOptions::default()
            },
        ),
        Err(ApplicationError::ConfigurationMismatch)
    ));

    let executed_unprofiled_path = directory.path().join("executed-unprofiled.sqlite3");
    let executed_unprofiled =
        LedgerApplication::open(&executed_unprofiled_path, chain_id(), ApplicationOptions::default())?;
    let _ = executed_unprofiled.apply_block(block(1, 1_000, zero_app_hash(), Vec::new())?, &AcceptAll)?;
    drop(executed_unprofiled);
    assert!(matches!(
        LedgerApplication::open(
            &executed_unprofiled_path,
            chain_id(),
            ApplicationOptions {
                consensus_profile_digest: Some(profile),
                ..ApplicationOptions::default()
            },
        ),
        Err(ApplicationError::ConfigurationMismatch)
    ));
    Ok(())
}
