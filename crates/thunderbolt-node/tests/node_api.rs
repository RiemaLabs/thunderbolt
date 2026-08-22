use std::collections::BTreeSet;
use std::fs;
use std::future::pending;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use reqwest::header::AUTHORIZATION;
use reqwest::{Client, StatusCode};
use tempfile::TempDir;
use thunderbolt_config::{Config, Environment, Network, NodeRole, TokenConfig, TokenScope};
use thunderbolt_node::{
    AppendResponse, EventPage, InvoiceProposalContext, NodeOptions, NodeServer, ProposalVerifier,
    ProposalVerifierError, TransferProposalContext, VerifiedProposalEvidence,
};
use thunderbolt_protocol::{
    Actor, ActorRole, Artifact, BitcoinTxid, ChannelEvent, ChannelId, Committee, Digest, EntryHash, FinalizeEvent,
    IdempotencyKey, ImplementationId, InvoiceEvent, InvoiceId, LedgerEntry, OpenEvent, ParticipantId, TransferEvent,
    VerificationEvidence, VerificationKind,
};
use thunderbolt_storage::SqliteStorage;
use tokio::task::JoinHandle;

const ADMIN_TOKEN: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const READ_TOKEN: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const ALICE_TOKEN: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
const BOB_TOKEN: &str = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";

struct RunningNode {
    address: SocketAddr,
    task: JoinHandle<Result<(), thunderbolt_node::NodeError>>,
}

impl RunningNode {
    async fn launch(config: Config, options: NodeOptions) -> Self {
        let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind ephemeral loopback listener");
        let server = NodeServer::from_listener(listener, config, options)
            .await
            .expect("construct node server");
        let address = server.local_addr().expect("read local address");
        let task = tokio::spawn(server.run(pending()));
        Self { address, task }
    }

    async fn launch_with_verifier(config: Config, verifier: Arc<dyn ProposalVerifier>) -> Self {
        let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind verifier loopback listener");
        let server = NodeServer::from_listener_with_verifier(listener, config, NodeOptions::default(), verifier)
            .await
            .expect("construct verified node server");
        let address = server.local_addr().expect("read local address");
        let task = tokio::spawn(server.run(pending()));
        Self { address, task }
    }

    fn url(&self, path: &str) -> String {
        format!("http://{}{}", self.address, path)
    }

    async fn expect_clean_stop(self) {
        tokio::time::timeout(Duration::from_secs(3), self.task)
            .await
            .expect("server stopped before deadline")
            .expect("server task joined")
            .expect("server stopped cleanly");
    }
}

#[tokio::test]
async fn authenticated_lifecycle_is_idempotent_durable_bounded_and_graceful() {
    let temporary = TempDir::new().expect("create temporary node directory");
    let config = test_config(temporary.path(), Environment::Development, Network::Regtest, 1_024);
    let options = NodeOptions {
        allow_unverified_demo_events: true,
    };
    let node = RunningNode::launch(config.clone(), options).await;
    let client = Client::new();

    assert_eq!(
        client
            .get(node.url("/v1/health/live"))
            .send()
            .await
            .expect("liveness response")
            .status(),
        StatusCode::OK
    );
    assert_eq!(
        client
            .get(node.url("/v1/info"))
            .send()
            .await
            .expect("missing-auth response")
            .status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        client
            .get(node.url("/v1/info"))
            .header(AUTHORIZATION, "Bearer not-a-valid-token")
            .send()
            .await
            .expect("invalid-auth response")
            .status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        client
            .get(node.url("/v1/info"))
            .header(AUTHORIZATION, format!("Bearer {READ_TOKEN}"))
            .send()
            .await
            .expect("read-auth response")
            .status(),
        StatusCode::OK
    );

    let channel_id = ChannelId::new(BitcoinTxid::from_bytes([7; 32]), 0);
    let open = open_entry(channel_id);
    assert_eq!(
        post_entry(&client, &node, &open, READ_TOKEN).await.status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        post_entry(&client, &node, &open, ADMIN_TOKEN).await.status(),
        StatusCode::FORBIDDEN
    );

    let oversized = vec![b' '; 1_025];
    let oversized_status = client
        .post(node.url(&format!("/v1/channels/{channel_id}/events")))
        .header(AUTHORIZATION, format!("Bearer {ADMIN_TOKEN}"))
        .header("content-type", "application/json")
        .body(oversized)
        .send()
        .await
        .expect("oversized response")
        .status();
    assert_eq!(oversized_status, StatusCode::PAYLOAD_TOO_LARGE);

    let response = post_entry(&client, &node, &open, ALICE_TOKEN).await;
    assert_eq!(response.status(), StatusCode::CREATED);
    let open_result: AppendResponse = response.json().await.expect("decode open result");
    assert!(!open_result.replayed);
    let committed_open: LedgerEntry = client
        .get(node.url(&format!("/v1/channels/{channel_id}/events/0")))
        .header(AUTHORIZATION, format!("Bearer {ADMIN_TOKEN}"))
        .send()
        .await
        .expect("committed demo event response")
        .error_for_status()
        .expect("committed demo event status")
        .json()
        .await
        .expect("decode committed demo event");
    assert!(committed_open
        .event
        .verification()
        .iter()
        .all(|evidence| evidence.verified_at_ms == open_result.snapshot.opened_at_ms));
    assert_ne!(open_result.snapshot.opened_at_ms, open.occurred_at_ms);

    let replay = post_entry(&client, &node, &open, ALICE_TOKEN).await;
    assert_eq!(replay.status(), StatusCode::OK);
    let replay_result: AppendResponse = replay.json().await.expect("decode replay result");
    assert!(replay_result.replayed);
    assert_eq!(replay_result.entry_hash, open_result.entry_hash);

    let invoice = invoice_entry(channel_id, open_result.entry_hash);
    let invoice_result = append(&client, &node, &invoice).await;
    let transfer = transfer_entry(channel_id, invoice_result.entry_hash);
    let transfer_result = append(&client, &node, &transfer).await;
    let finalize = finalize_entry(channel_id, transfer_result.entry_hash);
    let finalize_result = append(&client, &node, &finalize).await;
    assert_eq!(finalize_result.snapshot.phase.to_string(), "finalized");

    let event_page: EventPage = client
        .get(node.url(&format!("/v1/channels/{channel_id}/events?limit=2")))
        .header(AUTHORIZATION, format!("Bearer {ADMIN_TOKEN}"))
        .send()
        .await
        .expect("event page response")
        .error_for_status()
        .expect("event page status")
        .json()
        .await
        .expect("decode event page");
    assert_eq!(event_page.events.len(), 2);
    assert_eq!(event_page.next_after_sequence, Some(1));

    let all_events: EventPage = client
        .get(node.url(&format!("/v1/channels/{channel_id}/events?limit=10")))
        .header(AUTHORIZATION, format!("Bearer {ADMIN_TOKEN}"))
        .send()
        .await
        .expect("all-events response")
        .error_for_status()
        .expect("all-events status")
        .json()
        .await
        .expect("decode all events");
    assert_eq!(all_events.events.len(), 4);

    let integrity = client
        .post(node.url("/v1/database/integrity"))
        .header(AUTHORIZATION, format!("Bearer {ADMIN_TOKEN}"))
        .json(&serde_json::json!({}))
        .send()
        .await
        .expect("integrity response");
    assert_eq!(integrity.status(), StatusCode::OK);

    let backup = client
        .post(node.url("/v1/database/backup"))
        .header(AUTHORIZATION, format!("Bearer {ADMIN_TOKEN}"))
        .json(&serde_json::json!({ "filename": "integration.sqlite3" }))
        .send()
        .await
        .expect("backup response");
    assert_eq!(backup.status(), StatusCode::CREATED);
    assert!(temporary.path().join("backups/integration.sqlite3").exists());

    let stop = client
        .post(node.url("/v1/admin/stop"))
        .header(AUTHORIZATION, format!("Bearer {ADMIN_TOKEN}"))
        .json(&serde_json::json!({}))
        .send()
        .await
        .expect("stop response");
    assert_eq!(stop.status(), StatusCode::ACCEPTED);
    node.expect_clean_stop().await;

    let restarted = RunningNode::launch(config, options).await;
    let snapshot = client
        .get(restarted.url(&format!("/v1/channels/{channel_id}")))
        .header(AUTHORIZATION, format!("Bearer {ADMIN_TOKEN}"))
        .send()
        .await
        .expect("restart snapshot response")
        .error_for_status()
        .expect("restart snapshot status")
        .json::<thunderbolt_protocol::ChannelSnapshot>()
        .await
        .expect("decode restarted snapshot");
    assert_eq!(snapshot.last_sequence, 3);
    assert_eq!(snapshot.head_hash, finalize_result.entry_hash);
    client
        .post(restarted.url("/v1/admin/stop"))
        .header(AUTHORIZATION, format!("Bearer {ADMIN_TOKEN}"))
        .json(&serde_json::json!({}))
        .send()
        .await
        .expect("restart stop response")
        .error_for_status()
        .expect("restart stop status");
    restarted.expect_clean_stop().await;
}

#[derive(Clone, Debug)]
struct RecordingVerifier {
    state: Arc<RecordingVerifierState>,
}

#[derive(Debug, Default)]
struct RecordingVerifierState {
    invoice_calls: AtomicUsize,
    transfer_calls: AtomicUsize,
    reject_invoice: AtomicBool,
    invoice_context: Mutex<Option<InvoiceContextRecord>>,
    transfer_context: Mutex<Option<TransferContextRecord>>,
}

#[derive(Clone, Copy, Debug)]
struct InvoiceContextRecord {
    proposal_sequence: u64,
    snapshot_sequence: u64,
    snapshot_hash: EntryHash,
    ledger_time_ms: u64,
}

#[derive(Clone, Debug)]
struct TransferContextRecord {
    snapshot_sequence: u64,
    snapshot_hash: EntryHash,
    pending_sequence: u64,
    pending_hash: EntryHash,
    pending_invoice_id: String,
    ledger_time_ms: u64,
}

impl ProposalVerifier for RecordingVerifier {
    fn verify_invoice(
        &self,
        context: InvoiceProposalContext<'_>,
    ) -> Result<VerifiedProposalEvidence, ProposalVerifierError> {
        self.state.invoice_calls.fetch_add(1, Ordering::SeqCst);
        *self.state.invoice_context.lock().expect("invoice context lock") = Some(InvoiceContextRecord {
            proposal_sequence: context.proposal().sequence,
            snapshot_sequence: context.snapshot().last_sequence,
            snapshot_hash: context.snapshot().head_hash,
            ledger_time_ms: context.ledger_time_ms(),
        });
        if self.state.reject_invoice.load(Ordering::SeqCst) {
            return Err(ProposalVerifierError::Rejected {
                reason: "injected verifier rejection",
            });
        }
        VerifiedProposalEvidence::invoice(
            test_evidence(VerificationKind::InvoiceConsistencyProof, context.ledger_time_ms(), 21),
            context.ledger_time_ms(),
        )
    }

    fn verify_transfer(
        &self,
        context: TransferProposalContext<'_>,
    ) -> Result<VerifiedProposalEvidence, ProposalVerifierError> {
        self.state.transfer_calls.fetch_add(1, Ordering::SeqCst);
        *self.state.transfer_context.lock().expect("transfer context lock") = Some(TransferContextRecord {
            snapshot_sequence: context.snapshot().last_sequence,
            snapshot_hash: context.snapshot().head_hash,
            pending_sequence: context.pending_invoice_head().sequence,
            pending_hash: context.pending_invoice_head().entry_hash(),
            pending_invoice_id: context.pending_invoice().invoice_id.to_string(),
            ledger_time_ms: context.ledger_time_ms(),
        });
        VerifiedProposalEvidence::transfer(
            test_evidence(VerificationKind::TransferConsistencyProof, context.ledger_time_ms(), 22),
            test_evidence(VerificationKind::AnchorTransition, context.ledger_time_ms(), 23),
            context.ledger_time_ms(),
        )
    }
}

#[tokio::test]
async fn verified_append_deduplicates_before_callback_and_uses_authoritative_context() {
    let temporary = TempDir::new().expect("create temporary verified-node directory");
    let config = test_config(temporary.path(), Environment::Development, Network::Regtest, 4_096);
    let channel_id = ChannelId::new(BitcoinTxid::from_bytes([10; 32]), 2);
    let storage = SqliteStorage::open(&config.paths.database_path).expect("open seed storage");
    let mut open = open_entry(channel_id);
    install_test_evidence(&mut open);
    let opened = storage.append_entry(&open).expect("seed trusted Open");
    drop(storage);

    let verifier_state = Arc::new(RecordingVerifierState::default());
    let verifier: Arc<dyn ProposalVerifier> = Arc::new(RecordingVerifier {
        state: Arc::clone(&verifier_state),
    });
    let node = RunningNode::launch_with_verifier(config, verifier).await;
    let client = Client::new();

    let unsupported_open = open_entry(ChannelId::new(BitcoinTxid::from_bytes([11; 32]), 0));
    assert_eq!(
        post_entry(&client, &node, &unsupported_open, ALICE_TOKEN)
            .await
            .status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(verifier_state.invoice_calls.load(Ordering::SeqCst), 0);
    assert_eq!(verifier_state.transfer_calls.load(Ordering::SeqCst), 0);

    let mut invoice = invoice_entry(channel_id, opened.entry_hash);
    invoice.occurred_at_ms = unix_time_ms();
    let mut client_evidence = invoice.clone();
    client_evidence.idempotency_key = idempotency("client-evidence");
    if let ChannelEvent::Invoice(event) = &mut client_evidence.event {
        event.verification.push(test_evidence(
            VerificationKind::InvoiceConsistencyProof,
            client_evidence.occurred_at_ms,
            24,
        ));
    }
    assert_eq!(
        post_entry(&client, &node, &client_evidence, BOB_TOKEN).await.status(),
        StatusCode::UNPROCESSABLE_ENTITY
    );
    assert_eq!(verifier_state.invoice_calls.load(Ordering::SeqCst), 0);

    verifier_state.reject_invoice.store(true, Ordering::SeqCst);
    assert_eq!(
        post_entry(&client, &node, &invoice, BOB_TOKEN).await.status(),
        StatusCode::UNPROCESSABLE_ENTITY
    );
    assert_eq!(verifier_state.invoice_calls.load(Ordering::SeqCst), 1);
    let snapshot_after_rejection = client
        .get(node.url(&format!("/v1/channels/{channel_id}")))
        .header(AUTHORIZATION, format!("Bearer {ADMIN_TOKEN}"))
        .send()
        .await
        .expect("snapshot after rejection")
        .error_for_status()
        .expect("snapshot status after rejection")
        .json::<thunderbolt_protocol::ChannelSnapshot>()
        .await
        .expect("decode snapshot after rejection");
    assert_eq!(snapshot_after_rejection.last_sequence, 0);

    verifier_state.reject_invoice.store(false, Ordering::SeqCst);
    let invoice_response = post_entry(&client, &node, &invoice, BOB_TOKEN).await;
    assert_eq!(invoice_response.status(), StatusCode::CREATED);
    let invoice_result: AppendResponse = invoice_response.json().await.expect("decode verified invoice");
    assert_eq!(verifier_state.invoice_calls.load(Ordering::SeqCst), 2);

    let exact_replay = post_entry(&client, &node, &invoice, BOB_TOKEN).await;
    assert_eq!(exact_replay.status(), StatusCode::OK);
    assert_eq!(verifier_state.invoice_calls.load(Ordering::SeqCst), 2);

    let mut conflict = invoice.clone();
    conflict.occurred_at_ms = conflict.occurred_at_ms.saturating_add(1);
    assert_eq!(
        post_entry(&client, &node, &conflict, BOB_TOKEN).await.status(),
        StatusCode::CONFLICT
    );
    assert_eq!(verifier_state.invoice_calls.load(Ordering::SeqCst), 2);

    let invoice_context = verifier_state
        .invoice_context
        .lock()
        .expect("invoice context lock")
        .expect("recorded invoice context");
    assert_eq!(invoice_context.proposal_sequence, 1);
    assert_eq!(invoice_context.snapshot_sequence, 0);
    assert_eq!(invoice_context.snapshot_hash, opened.entry_hash);
    assert!(invoice_context.ledger_time_ms >= invoice.occurred_at_ms);

    let mut transfer = transfer_entry(channel_id, invoice_result.entry_hash);
    transfer.occurred_at_ms = unix_time_ms();
    let transfer_response = post_entry(&client, &node, &transfer, ALICE_TOKEN).await;
    assert_eq!(transfer_response.status(), StatusCode::CREATED);
    let transfer_result: AppendResponse = transfer_response.json().await.expect("decode verified transfer");
    assert_eq!(verifier_state.transfer_calls.load(Ordering::SeqCst), 1);
    let transfer_context = verifier_state
        .transfer_context
        .lock()
        .expect("transfer context lock")
        .clone()
        .expect("recorded transfer context");
    assert_eq!(transfer_context.snapshot_sequence, 1);
    assert_eq!(transfer_context.snapshot_hash, invoice_result.entry_hash);
    assert_eq!(transfer_context.pending_sequence, 1);
    assert_eq!(transfer_context.pending_hash, invoice_result.entry_hash);
    assert_eq!(transfer_context.pending_invoice_id, "invoice-1");
    assert!(transfer_context.ledger_time_ms >= transfer.occurred_at_ms);

    let mut finalize = finalize_entry(channel_id, transfer_result.entry_hash);
    finalize.occurred_at_ms = unix_time_ms();
    assert_eq!(
        post_entry(&client, &node, &finalize, BOB_TOKEN).await.status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(verifier_state.transfer_calls.load(Ordering::SeqCst), 1);

    client
        .post(node.url("/v1/admin/stop"))
        .header(AUTHORIZATION, format!("Bearer {ADMIN_TOKEN}"))
        .json(&serde_json::json!({}))
        .send()
        .await
        .expect("verified node stop response")
        .error_for_status()
        .expect("verified node stop status");
    node.expect_clean_stop().await;
}

#[tokio::test]
async fn production_like_modes_reject_unverified_and_client_asserted_evidence() {
    let temporary = TempDir::new().expect("create temporary node directory");
    let config = test_config(temporary.path(), Environment::Staging, Network::Signet, 4_096);
    let node = RunningNode::launch(config, NodeOptions::default()).await;
    let client = Client::new();
    let channel_id = ChannelId::new(BitcoinTxid::from_bytes([8; 32]), 1);
    let mut open = open_entry(channel_id);

    let unverified = post_entry(&client, &node, &open, ALICE_TOKEN).await;
    assert_eq!(unverified.status(), StatusCode::SERVICE_UNAVAILABLE);

    if let ChannelEvent::Open(event) = &mut open.event {
        event.verification.push(VerificationEvidence::verified(
            VerificationKind::FundingTransaction,
            participant("claimed-verifier"),
            ImplementationId::new("claimed-implementation").expect("implementation id"),
            Digest::ZERO,
            1,
        ));
    }
    let asserted = post_entry(&client, &node, &open, ALICE_TOKEN).await;
    assert_eq!(asserted.status(), StatusCode::UNPROCESSABLE_ENTITY);

    client
        .post(node.url("/v1/admin/stop"))
        .header(AUTHORIZATION, format!("Bearer {ADMIN_TOKEN}"))
        .json(&serde_json::json!({}))
        .send()
        .await
        .expect("stop response")
        .error_for_status()
        .expect("stop status");
    node.expect_clean_stop().await;

    let mut mainnet = test_config(temporary.path(), Environment::Development, Network::Mainnet, 4_096);
    mainnet.paths.database_path = temporary.path().join("mainnet.sqlite3");
    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind mainnet listener");
    let result = NodeServer::from_listener(listener, mainnet, NodeOptions::default()).await;
    assert!(result.is_err());

    let mut holder = test_config(temporary.path(), Environment::Development, Network::Regtest, 4_096);
    holder.node.role = NodeRole::Holder;
    holder.paths.database_path = temporary.path().join("holder.sqlite3");
    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind holder listener");
    let result = NodeServer::from_listener(listener, holder, NodeOptions::default()).await;
    assert!(result.is_err());
}

fn test_config(root: &Path, environment: Environment, network: Network, max_body: u64) -> Config {
    fs::create_dir_all(root.join("auth")).expect("create auth directory");
    write_token(&root.join("auth/admin.token"), ADMIN_TOKEN);
    write_token(&root.join("auth/read.token"), READ_TOKEN);
    write_token(&root.join("auth/alice.token"), ALICE_TOKEN);
    write_token(&root.join("auth/bob.token"), BOB_TOKEN);
    let mut config = Config::default();
    config.node.role = NodeRole::Ledger;
    config.deployment.environment = environment;
    config.deployment.network = network;
    config.node.listen_address = IpAddr::V4(Ipv4Addr::LOCALHOST);
    config.admin.bind_address = IpAddr::V4(Ipv4Addr::LOCALHOST);
    config.paths.data_dir = root.to_path_buf();
    config.paths.log_dir = root.join("logs");
    config.paths.database_path = root.join("thunderbolt.sqlite3");
    config.paths.socket_path = root.join("thunderboltd.sock");
    config.backup.directory = root.join("backups");
    config.metrics.enabled = false;
    config.limits.max_request_body_bytes = max_body;
    config.auth.tokens = vec![
        TokenConfig {
            id: "administrator".to_owned(),
            token_file: root.join("auth/admin.token"),
            scopes: BTreeSet::from([TokenScope::Admin]),
        },
        TokenConfig {
            id: "reader".to_owned(),
            token_file: root.join("auth/read.token"),
            scopes: BTreeSet::from([TokenScope::Read]),
        },
        TokenConfig {
            id: "alice".to_owned(),
            token_file: root.join("auth/alice.token"),
            scopes: BTreeSet::from([TokenScope::Write]),
        },
        TokenConfig {
            id: "bob".to_owned(),
            token_file: root.join("auth/bob.token"),
            scopes: BTreeSet::from([TokenScope::Write]),
        },
    ];
    config
}

fn write_token(path: &Path, token: &str) {
    fs::write(path, format!("{token}\n")).expect("write token");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).expect("secure token permissions");
    }
}

fn open_entry(channel_id: ChannelId) -> LedgerEntry {
    LedgerEntry::new(
        channel_id,
        0,
        EntryHash::ZERO,
        idempotency("open"),
        Actor::new(participant("alice"), ActorRole::Holder),
        1,
        ChannelEvent::Open(OpenEvent {
            initial_holder: participant("alice"),
            committee: Committee::new(participant("committee"), 3, 2).expect("committee"),
            capacity_sat: 100_000,
            lock_key: artifact(1),
            initial_holder_anchor: artifact(2),
            initial_holder_ciphertext: artifact(3),
            verification: Vec::new(),
        }),
    )
}

fn invoice_entry(channel_id: ChannelId, previous: EntryHash) -> LedgerEntry {
    LedgerEntry::new(
        channel_id,
        1,
        previous,
        idempotency("invoice"),
        Actor::new(participant("bob"), ActorRole::Recipient),
        2,
        ChannelEvent::Invoice(InvoiceEvent {
            invoice_id: InvoiceId::new("invoice-1").expect("invoice id"),
            recipient: participant("bob"),
            recipient_encryption_key: artifact(4),
            public_delta: artifact(5),
            recipient_ciphertext: artifact(6),
            committee_package: artifact(7),
            invoice_proof: artifact(8),
            expires_at_ms: None,
            verification: Vec::new(),
        }),
    )
}

fn transfer_entry(channel_id: ChannelId, previous: EntryHash) -> LedgerEntry {
    LedgerEntry::new(
        channel_id,
        2,
        previous,
        idempotency("transfer"),
        Actor::new(participant("alice"), ActorRole::Holder),
        3,
        ChannelEvent::Transfer(TransferEvent {
            invoice_id: InvoiceId::new("invoice-1").expect("invoice id"),
            sender: participant("alice"),
            recipient: participant("bob"),
            next_holder_anchor: artifact(9),
            next_holder_ciphertext: artifact(10),
            transfer_proof: artifact(11),
            verification: Vec::new(),
        }),
    )
}

fn finalize_entry(channel_id: ChannelId, previous: EntryHash) -> LedgerEntry {
    LedgerEntry::new(
        channel_id,
        3,
        previous,
        idempotency("finalize"),
        Actor::new(participant("bob"), ActorRole::Holder),
        4,
        ChannelEvent::Finalize(FinalizeEvent {
            holder: participant("bob"),
            closing_txid: BitcoinTxid::from_bytes([9; 32]),
            ownership_proof: artifact(12),
            committee_attestation: artifact(13),
            verification: Vec::new(),
        }),
    )
}

async fn append(client: &Client, node: &RunningNode, entry: &LedgerEntry) -> AppendResponse {
    let token = match entry.actor.participant_id.as_str() {
        "alice" => ALICE_TOKEN,
        "bob" => BOB_TOKEN,
        other => panic!("no test token for actor {other}"),
    };
    let response = post_entry(client, node, entry, token).await;
    assert_eq!(response.status(), StatusCode::CREATED);
    response.json().await.expect("decode append response")
}

async fn post_entry(client: &Client, node: &RunningNode, entry: &LedgerEntry, token: &str) -> reqwest::Response {
    client
        .post(node.url(&format!("/v1/channels/{}/events", entry.channel_id)))
        .header(AUTHORIZATION, format!("Bearer {token}"))
        .json(entry)
        .send()
        .await
        .expect("append response")
}

fn participant(value: &str) -> ParticipantId {
    ParticipantId::new(value).expect("participant id")
}

fn idempotency(value: &str) -> IdempotencyKey {
    IdempotencyKey::new(value).expect("idempotency key")
}

fn artifact(value: u8) -> Artifact {
    Artifact::new(vec![value]).expect("artifact")
}

fn test_evidence(kind: VerificationKind, verified_at_ms: u64, digest_byte: u8) -> VerificationEvidence {
    VerificationEvidence::verified(
        kind,
        participant("trusted-test-verifier"),
        ImplementationId::new("trusted-test-verifier/v1").expect("implementation id"),
        Digest::from_bytes([digest_byte; 32]),
        verified_at_ms,
    )
}

fn install_test_evidence(entry: &mut LedgerEntry) {
    let evidence: Vec<_> = entry
        .event
        .required_verifications()
        .iter()
        .copied()
        .enumerate()
        .map(|(index, kind)| {
            let digest_byte = u8::try_from(index + 1).expect("small evidence count");
            test_evidence(kind, entry.occurred_at_ms, digest_byte)
        })
        .collect();
    match &mut entry.event {
        ChannelEvent::Open(event) => event.verification = evidence,
        ChannelEvent::Invoice(event) => event.verification = evidence,
        ChannelEvent::Transfer(event) => event.verification = evidence,
        ChannelEvent::Finalize(event) => event.verification = evidence,
    }
}

fn unix_time_ms() -> u64 {
    u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock after Unix epoch")
            .as_millis(),
    )
    .expect("Unix time fits u64")
}

trait ChannelPhaseName {
    fn to_string(&self) -> &'static str;
}

impl ChannelPhaseName for thunderbolt_protocol::ChannelPhase {
    fn to_string(&self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::InvoicePending => "invoice_pending",
            Self::TransferComplete => "transfer_complete",
            Self::Finalized => "finalized",
        }
    }
}
