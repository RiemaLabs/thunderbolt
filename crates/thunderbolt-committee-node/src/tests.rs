use std::error::Error;
use std::sync::{Arc, Barrier};

use bitcoin::Network;
use libpaillier::{DecryptionKey, EncryptionKey};
use secp::Scalar;
use secp256k1::{Keypair, Secp256k1, SecretKey};
use sha2::Digest as _;
use tempfile::TempDir;
use thunderbolt_committee::insecure_regtest::dealer_bootstrap;
use thunderbolt_committee::{
    CommitteeEpoch, CommitteeMemberEngine, CommitteeVault, KeystoreCommitteeVault, VaultEntry, VaultPlaintext,
    VaultStoreError,
};
use thunderbolt_core::paillier::{add_ciphertexts, encrypt_plaintext, random_nonce_in_group};
use thunderbolt_core::threshold::{create_threshold_refresh_distribution, ThresholdMemberPublicKey};
use thunderbolt_core::zkp::types::scalar_to_big_number;
use thunderbolt_core::zkp::{
    prove_share_encryption, prove_transfer, ShareEncryptionStatement, ShareEncryptionWitness, TransferStatement,
    TransferWitness,
};
use thunderbolt_keystore::{
    CheckpointCasOutcome, KdfParams, Password, RollbackFloorStore, VaultCheckpoint, VaultIdentity,
    MIN_ARGON2_ITERATIONS, MIN_ARGON2_MEMORY_KIB,
};
use thunderbolt_ledger::{
    ActorKeyAlgorithmV2, ActorPublicKeyV2, ActorRoleV2, ActorSignatureV2, AppHashV2, CanonicalEventV2,
    ClientRequestNonceV2, EntryHashV2, LedgerChainIdV2, PendingBlockV2, ProposalBodyV2, SignedProposalV2,
};
use thunderbolt_protocol::{
    v2::{ChannelEventV2, InvoiceEventV2, TransferEventV2},
    Artifact,
};
use thunderbolt_wire::{
    AnchorParameterSuiteIdV2, BindingContext, BitcoinGenesisHashV2, ChannelBindingV2, CommitteeDescriptorDigestV2,
    FundingOutpointV2, ProtocolSuiteIdV2, ShareEnvelopeV1, ThresholdEnvelopeV1, TransferEnvelopeV1,
};

use crate::storage::SqliteQueue;
use crate::*;

fn config() -> Result<NodeConfig> {
    NodeConfig::new(
        LedgerChainIdV2::new("committee-node-regtest").map_err(|_| NodeError::InvalidLedgerArtifact)?,
        FinalityVerifierProfileId::new([0x81; 32])?,
        32,
        32,
        8,
    )
}

fn cursor(height: u64, index: u32, byte: u8) -> Result<LedgerCursor> {
    Ok(LedgerCursor {
        refresh_ordinal: 1,
        previous_refresh_entry_hash: EntryHashV2::zero(),
        block_height: height,
        block_index: index,
        app_hash: AppHashV2::from_bytes([byte; 32]).map_err(|_| NodeError::InvalidLedgerArtifact)?,
        entry_hash: EntryHashV2::from_bytes([byte.wrapping_add(1); 32])
            .map_err(|_| NodeError::InvalidLedgerArtifact)?,
        finality_digest: FinalityDigest::new([byte.wrapping_add(2); 32]),
    })
}

fn open_queue(directory: &TempDir) -> Result<SqliteQueue> {
    SqliteQueue::open(
        directory.path().join("committee-node.sqlite"),
        &config()?,
        b"deployment",
        7,
        &[0x41; 32],
        1,
    )
}

#[test]
fn production_network_policy_rejects_mainnet_and_testnet4() {
    assert!(NodeConfig::validate_network(Network::Regtest).is_ok());
    assert!(NodeConfig::validate_network(Network::Signet).is_ok());
    assert!(NodeConfig::validate_network(Network::Testnet).is_ok());
    assert!(NodeConfig::validate_network(Network::Bitcoin).is_err());
    assert!(NodeConfig::validate_network(Network::Testnet4).is_err());
}

#[test]
fn sqlite_identity_binds_deployment_epoch_descriptor_and_member() -> std::result::Result<(), Box<dyn Error>> {
    let directory = TempDir::new()?;
    let path = directory.path().join("committee-node.sqlite");
    drop(SqliteQueue::open(&path, &config()?, b"deployment", 7, &[0x41; 32], 1)?);
    for (deployment, epoch, descriptor, member) in [
        (b"other".as_slice(), 7, [0x41; 32], 1),
        (b"deployment".as_slice(), 8, [0x41; 32], 1),
        (b"deployment".as_slice(), 7, [0x42; 32], 1),
        (b"deployment".as_slice(), 7, [0x41; 32], 2),
    ] {
        assert!(matches!(
            SqliteQueue::open(&path, &config()?, deployment, epoch, &descriptor, member),
            Err(NodeError::IdentityMismatch)
        ));
    }
    let wrong_profile = NodeConfig::new(
        LedgerChainIdV2::new("committee-node-regtest")?,
        FinalityVerifierProfileId::new([0x82; 32])?,
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

#[test]
fn schema_v1_pending_inbox_is_rejected_without_partial_migration() -> std::result::Result<(), Box<dyn Error>> {
    let directory = TempDir::new()?;
    let path = directory.path().join("committee-node.sqlite");
    let queue = open_queue(&directory)?;
    queue.ingest(
        [0x61; 32],
        [0x62; 32],
        b"legacy-pending-bundle".to_vec(),
        &cursor(5, 0, 0x63)?,
    )?;
    drop(queue);
    let connection = rusqlite::Connection::open(&path)?;
    connection.execute_batch(
        "ALTER TABLE node_settings DROP COLUMN finality_verifier_profile;
         PRAGMA user_version=1;",
    )?;
    let before: Vec<u8> = connection.query_row("SELECT bundle_json FROM inbox WHERE status=0", [], |row| row.get(0))?;
    drop(connection);

    assert!(matches!(open_queue(&directory), Err(NodeError::LegacyPendingRecords)));

    let connection = rusqlite::Connection::open(&path)?;
    let version: i64 = connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
    let profile_columns: i64 = connection.query_row(
        "SELECT count(*) FROM pragma_table_info('node_settings') WHERE name='finality_verifier_profile'",
        [],
        |row| row.get(0),
    )?;
    let after: Vec<u8> = connection.query_row("SELECT bundle_json FROM inbox WHERE status=0", [], |row| row.get(0))?;
    assert_eq!(version, 1);
    assert_eq!(profile_columns, 0);
    assert_eq!(after, before);
    Ok(())
}

#[test]
fn sqlite_inbox_duplicate_conflict_and_restart_are_deterministic() -> std::result::Result<(), Box<dyn Error>> {
    let directory = TempDir::new()?;
    let queue = open_queue(&directory)?;
    let first_cursor = cursor(10, 0, 0x11)?;
    assert_eq!(
        queue.ingest([0x21; 32], [0x31; 32], b"bundle-one".to_vec(), &first_cursor)?,
        IngestDisposition::Accepted
    );
    assert_eq!(
        queue.ingest([0x21; 32], [0x31; 32], b"bundle-one".to_vec(), &first_cursor)?,
        IngestDisposition::Replay
    );
    assert!(matches!(
        queue.ingest([0x22; 32], [0x31; 32], b"different".to_vec(), &cursor(10, 1, 0x11)?),
        Err(NodeError::ReplayConflict)
    ));
    drop(queue);
    let reopened = open_queue(&directory)?;
    let pending = reopened.next_pending()?.ok_or("missing durable inbox item")?;
    assert_eq!(pending.id, [0x21; 32]);
    assert_eq!(pending.bundle, b"bundle-one");
    Ok(())
}

#[test]
fn cursor_rejects_backward_and_same_height_forks() -> std::result::Result<(), Box<dyn Error>> {
    let directory = TempDir::new()?;
    let queue = open_queue(&directory)?;
    let current = cursor(20, 2, 0x20)?;
    queue.ingest([1; 32], [2; 32], b"one".to_vec(), &current)?;
    let mut back = cursor(19, 0, 0x19)?;
    back.refresh_ordinal = 2;
    back.previous_refresh_entry_hash = current.entry_hash.clone();
    assert!(matches!(
        queue.ingest([3; 32], [4; 32], b"back".to_vec(), &back),
        Err(NodeError::CursorConflict)
    ));
    let mut fork = cursor(20, 3, 0x21)?;
    fork.refresh_ordinal = 2;
    fork.previous_refresh_entry_hash = current.entry_hash.clone();
    assert!(matches!(
        queue.ingest([5; 32], [6; 32], b"fork".to_vec(), &fork),
        Err(NodeError::CursorConflict)
    ));
    let mut gap = cursor(21, 0, 0x22)?;
    gap.refresh_ordinal = 3;
    gap.previous_refresh_entry_hash = current.entry_hash.clone();
    assert!(matches!(
        queue.ingest([7; 32], [8; 32], b"gap".to_vec(), &gap),
        Err(NodeError::CursorConflict)
    ));
    let mut next = cursor(21, 0, 0x22)?;
    next.refresh_ordinal = 2;
    next.previous_refresh_entry_hash = current.entry_hash;
    assert_eq!(
        queue.ingest([9; 32], [10; 32], b"next".to_vec(), &next)?,
        IngestDisposition::Accepted
    );
    Ok(())
}

#[test]
fn two_sqlite_instances_converge_on_one_inbox_item() -> std::result::Result<(), Box<dyn Error>> {
    let directory = TempDir::new()?;
    let first = open_queue(&directory)?;
    let second = open_queue(&directory)?;
    let barrier = Arc::new(Barrier::new(2));
    let one = barrier.clone();
    let first_thread = std::thread::spawn(move || {
        one.wait();
        first
            .ingest([9; 32], [10; 32], b"same".to_vec(), &cursor(30, 0, 0x30).ok()?)
            .ok()
    });
    let second_thread = std::thread::spawn(move || {
        barrier.wait();
        second
            .ingest([9; 32], [10; 32], b"same".to_vec(), &cursor(30, 0, 0x30).ok()?)
            .ok()
    });
    let left = first_thread
        .join()
        .map_err(|_| "first SQLite thread panicked")?
        .ok_or("first failed")?;
    let right = second_thread
        .join()
        .map_err(|_| "second SQLite thread panicked")?
        .ok_or("second failed")?;
    assert!(matches!(
        (left, right),
        (IngestDisposition::Accepted, IngestDisposition::Replay)
            | (IngestDisposition::Replay, IngestDisposition::Accepted)
    ));
    Ok(())
}

#[test]
fn applied_ack_and_outbox_commit_atomically_and_idempotently() -> std::result::Result<(), Box<dyn Error>> {
    let directory = TempDir::new()?;
    let queue = open_queue(&directory)?;
    queue.ingest([0x51; 32], [0x52; 32], b"pending".to_vec(), &cursor(40, 0, 0x40)?)?;
    let ack = AcknowledgementRecord {
        event_id: [1; 32],
        descriptor_id: [2; 32],
        epoch: 7,
        member_id: 1,
        durable_revision: 2,
        acknowledgement_digest: [3; 32],
    };
    queue.mark_applied([0x51; 32], &ack)?;
    queue.mark_applied([0x51; 32], &ack)?;
    let mut conflicting = ack.clone();
    conflicting.acknowledgement_digest[0] ^= 1;
    assert!(matches!(
        queue.mark_applied([0x51; 32], &conflicting),
        Err(NodeError::ReplayConflict)
    ));
    assert!(queue.next_pending()?.is_none());
    let outbox = queue.list_outbox(10)?;
    assert_eq!(outbox.len(), 1);
    assert_eq!(outbox[0].acknowledgement, ack);
    assert_eq!(outbox[0].status, OutboxStatus::AwaitingSignature);
    Ok(())
}

#[test]
fn signing_and_finality_defaults_are_fail_closed() {
    let verifier = DisabledFinalityVerifier;
    assert!(!<DisabledFinalityVerifier as LedgerFinalityVerifier<()>>::is_available(
        &verifier
    ));
    let signer = DisabledProposalSigner;
    assert!(!signer.is_available());
    let _sign_method: fn(&mut DisabledProposalSigner, &ProposalBodyV2) -> std::result::Result<_, _> =
        DisabledProposalSigner::sign;
}

#[derive(Debug)]
struct MemoryVaultError;
impl std::fmt::Display for MemoryVaultError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("memory vault error")
    }
}
impl Error for MemoryVaultError {}

#[derive(Default)]
struct MemoryVault(Option<(u64, Vec<u8>)>);
impl CommitteeVault for MemoryVault {
    type Error = MemoryVaultError;
    fn load(&mut self) -> std::result::Result<Option<VaultEntry>, Self::Error> {
        self.0
            .as_ref()
            .map(|(revision, bytes)| {
                VaultPlaintext::from_secret_bytes(bytes.clone())
                    .map(|plaintext| VaultEntry::new(*revision, plaintext))
                    .map_err(|_| MemoryVaultError)
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

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
struct TestReceipt([u8; 32]);

struct AcceptFinality;
impl LedgerFinalityVerifier<TestReceipt> for AcceptFinality {
    type Error = MemoryVaultError;
    fn profile_id(&self) -> FinalityVerifierProfileId {
        FinalityVerifierProfileId::new([0x81; 32]).unwrap_or(FinalityVerifierProfileId::DISABLED)
    }
    fn verify_finalized_refresh(
        &self,
        invoice: &FinalizedEntryV2<TestReceipt>,
        transfer: &FinalizedEntryV2<TestReceipt>,
    ) -> std::result::Result<DurableFinalityCapability, Self::Error> {
        let invoice_entry = invoice.entry().map_err(|_| MemoryVaultError)?;
        let transfer_entry = transfer.entry().map_err(|_| MemoryVaultError)?;
        DurableFinalityCapability::new(
            self.profile_id(),
            transfer.block.ledger_chain_id().clone(),
            invoice_entry.metadata().block_height(),
            invoice_entry.metadata().block_index(),
            invoice_entry.metadata().entry_hash().clone(),
            transfer_entry.metadata().block_height(),
            transfer_entry.metadata().block_index(),
            transfer_entry.metadata().entry_hash().clone(),
            transfer.block.app_hash().clone(),
            1,
            EntryHashV2::zero(),
            FinalityDigest::new([0x91; 32]),
            b"stable-test-attestation".to_vec(),
        )
        .map_err(|_| MemoryVaultError)
    }
    fn verify_durable_capability(
        &self,
        capability: &DurableFinalityCapability,
    ) -> std::result::Result<(), Self::Error> {
        if capability.attestation() == b"stable-test-attestation"
            && capability.verifier_digest() == FinalityDigest::new([0x91; 32])
        {
            Ok(())
        } else {
            Err(MemoryVaultError)
        }
    }
}

struct WrongPairFinality;
impl LedgerFinalityVerifier<TestReceipt> for WrongPairFinality {
    type Error = MemoryVaultError;
    fn profile_id(&self) -> FinalityVerifierProfileId {
        FinalityVerifierProfileId::new([0x81; 32]).unwrap_or(FinalityVerifierProfileId::DISABLED)
    }
    fn verify_finalized_refresh(
        &self,
        invoice: &FinalizedEntryV2<TestReceipt>,
        transfer: &FinalizedEntryV2<TestReceipt>,
    ) -> std::result::Result<DurableFinalityCapability, Self::Error> {
        let invoice_entry = invoice.entry().map_err(|_| MemoryVaultError)?;
        let transfer_entry = transfer.entry().map_err(|_| MemoryVaultError)?;
        DurableFinalityCapability::new(
            self.profile_id(),
            transfer.block.ledger_chain_id().clone(),
            invoice_entry.metadata().block_height(),
            invoice_entry.metadata().block_index(),
            EntryHashV2::from_bytes([0xee; 32]).map_err(|_| MemoryVaultError)?,
            transfer_entry.metadata().block_height(),
            transfer_entry.metadata().block_index(),
            transfer_entry.metadata().entry_hash().clone(),
            transfer.block.app_hash().clone(),
            1,
            EntryHashV2::zero(),
            FinalityDigest::new([0x92; 32]),
            b"wrong-pair".to_vec(),
        )
        .map_err(|_| MemoryVaultError)
    }
    fn verify_durable_capability(
        &self,
        _capability: &DurableFinalityCapability,
    ) -> std::result::Result<(), Self::Error> {
        Err(MemoryVaultError)
    }
}

struct WrongProfileFinality;
impl LedgerFinalityVerifier<TestReceipt> for WrongProfileFinality {
    type Error = MemoryVaultError;
    fn profile_id(&self) -> FinalityVerifierProfileId {
        FinalityVerifierProfileId::new([0x82; 32]).unwrap_or(FinalityVerifierProfileId::DISABLED)
    }
    fn verify_finalized_refresh(
        &self,
        _invoice: &FinalizedEntryV2<TestReceipt>,
        _transfer: &FinalizedEntryV2<TestReceipt>,
    ) -> std::result::Result<DurableFinalityCapability, Self::Error> {
        Err(MemoryVaultError)
    }
    fn verify_durable_capability(
        &self,
        _capability: &DurableFinalityCapability,
    ) -> std::result::Result<(), Self::Error> {
        Err(MemoryVaultError)
    }
}

fn test_scalar(value: u8) -> std::result::Result<Scalar, Box<dyn Error>> {
    let mut bytes = [0_u8; 32];
    bytes[31] = value;
    Ok(Scalar::from_slice(&bytes)?)
}

fn actor(index: u8) -> std::result::Result<Keypair, Box<dyn Error>> {
    let mut bytes = [0_u8; 32];
    bytes[31] = index;
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

#[test]
fn crash_after_private_update_replays_into_one_outbox_record() -> std::result::Result<(), Box<dyn Error>> {
    let directory = TempDir::new()?;
    let anchor = test_scalar(41)?.base_point_mul();
    let dealer = dealer_bootstrap(
        Network::Regtest,
        b"node-deployment",
        CommitteeEpoch::new(7),
        1,
        1,
        anchor,
        test_scalar(23)?,
    )?;
    let descriptor = dealer.descriptor().clone();
    let package = dealer.into_packages().into_iter().next().ok_or("missing package")?;
    let engine = CommitteeMemberEngine::provision(MemoryVault::default(), package)?;
    let outpoint = FundingOutpointV2::new([0x44; 32], 7)?;
    let channel_bytes = outpoint.canonical_bytes();
    let v1_binding = BindingContext::invoice(
        Network::Regtest,
        descriptor.deployment_id(),
        descriptor.epoch().get(),
        channel_bytes,
        b"invoice-9",
    )?;
    let refresh = test_scalar(5)?;
    let recipients = descriptor
        .members()
        .iter()
        .map(|member| ThresholdMemberPublicKey {
            member_id: member.id().get(),
            encryption_key: member.encryption_key().clone(),
        })
        .collect::<Vec<_>>();
    let distribution =
        create_threshold_refresh_distribution(v1_binding.proof_context()?, anchor, 1, refresh, &recipients)?;
    let threshold_distribution = ThresholdEnvelopeV1::from_core(v1_binding.clone(), &distribution)?;
    let bob_secret = DecryptionKey::random().ok_or("Bob key generation failed")?;
    let bob_key = EncryptionKey::from(&bob_secret);
    let invoice_nonce = random_nonce_in_group(&bob_key);
    let invoice_ciphertext = encrypt_plaintext(&bob_key, &scalar_to_big_number(refresh), &invoice_nonce)?;
    let recipient_statement = ShareEncryptionStatement {
        context: v1_binding.proof_context()?,
        anchor_base: anchor,
        recipient_key: bob_key.clone(),
        member_id: thunderbolt_committee::RECIPIENT_SHARE_MEMBER_ID,
        committed_point: distribution.delta,
        ciphertext: invoice_ciphertext.clone(),
    };
    let recipient_proof = prove_share_encryption(
        &recipient_statement,
        &ShareEncryptionWitness {
            secret: refresh,
            nonce: invoice_nonce,
        },
    )?;
    let recipient_share = ShareEnvelopeV1::from_core(v1_binding.clone(), &recipient_statement, &recipient_proof)?;
    let transfer_binding = BindingContext::transfer(
        Network::Regtest,
        descriptor.deployment_id(),
        descriptor.epoch().get(),
        channel_bytes,
        b"invoice-9",
        1,
    )?;
    let holder_secret = test_scalar(11)?;
    let holder_nonce = random_nonce_in_group(&bob_key);
    let holder_component = encrypt_plaintext(&bob_key, &scalar_to_big_number(holder_secret), &holder_nonce)?;
    let next_ciphertext = add_ciphertexts(&bob_key, &holder_component, &invoice_ciphertext)?;
    let current_anchor = anchor * holder_secret;
    let next_anchor = (current_anchor + distribution.delta)
        .into_option()
        .ok_or("infinite anchor")?;
    let transfer_statement = TransferStatement {
        context: transfer_binding.proof_context()?,
        anchor_base: anchor,
        bob_key,
        current_anchor,
        invoice_ciphertext,
        next_holder_ciphertext: next_ciphertext,
    };
    let transfer_proof_core = prove_transfer(
        &transfer_statement,
        &TransferWitness {
            holder_secret,
            holder_nonce,
        },
    )?;
    let transfer_proof = TransferEnvelopeV1::from_core(
        transfer_binding,
        &transfer_statement,
        &transfer_proof_core,
        &distribution.delta,
        &next_anchor,
    )?;
    let binding = ChannelBindingV2::new(
        ProtocolSuiteIdV2::from_bytes([0x11; 32])?,
        Network::Regtest,
        BitcoinGenesisHashV2::for_network(Network::Regtest)?,
        descriptor.deployment_id(),
        outpoint,
        descriptor.epoch().get(),
        CommitteeDescriptorDigestV2::from_bytes(*descriptor.id().as_bytes())?,
        AnchorParameterSuiteIdV2::from_bytes([0x33; 32])?,
    )?;
    let invoice_event = ChannelEventV2::Invoice(InvoiceEventV2 {
        invoice_id: thunderbolt_wire::InvoiceId::from_bytes("invoice", b"invoice-9")?,
        holder_step: 0,
        recipient_encryption_key: Artifact::new(recipient_statement.recipient_key.to_bytes())?,
        public_delta: Artifact::new(distribution.delta.serialize())?,
        recipient_ciphertext: Artifact::new(recipient_statement.ciphertext.to_bytes())?,
        committee_package: Artifact::new(thunderbolt_wire::to_json_vec(
            &thunderbolt_wire::PublicMessageV1::ThresholdRefresh(threshold_distribution.clone()),
        )?)?,
        invoice_proof: Artifact::new(thunderbolt_wire::to_json_vec(
            &thunderbolt_wire::PublicMessageV1::Share(recipient_share.clone()),
        )?)?,
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
        invoice_id: thunderbolt_wire::InvoiceId::from_bytes("invoice", b"invoice-9")?,
        invoice_entry_hash: invoice_hash.clone(),
        next_holder_anchor: Artifact::new(next_anchor.serialize())?,
        next_holder_ciphertext: Artifact::new(transfer_statement.next_holder_ciphertext.to_bytes())?,
        transfer_proof: Artifact::new(thunderbolt_wire::to_json_vec(
            &thunderbolt_wire::PublicMessageV1::Transfer(transfer_proof.clone()),
        )?)?,
    });
    let transfer_signed = signed(&transfer_event, binding, 2, invoice_hash, ActorRoleV2::Holder, 3)?;
    let mut invoice_pending = PendingBlockV2::new(
        LedgerChainIdV2::new("committee-node-regtest")?,
        10,
        10_000,
        AppHashV2::from_bytes([0x77; 32])?,
    )?;
    invoice_pending.push(invoice_signed)?;
    let invoice_block = invoice_pending.execute()?;
    let mut transfer_pending = PendingBlockV2::new(
        LedgerChainIdV2::new("committee-node-regtest")?,
        11,
        10_001,
        invoice_block.app_hash().clone(),
    )?;
    transfer_pending.push(transfer_signed)?;
    let transfer_block = transfer_pending.execute()?;
    let bundle = FinalizedRefreshBundleV2 {
        invoice: FinalizedEntryV2 {
            inclusion_proof: invoice_block.entry_proof(0)?,
            block: invoice_block,
            entry_index: 0,
            receipt: TestReceipt([1; 32]),
        },
        transfer: FinalizedEntryV2 {
            inclusion_proof: transfer_block.entry_proof(0)?,
            block: transfer_block,
            entry_index: 0,
            receipt: TestReceipt([2; 32]),
        },
        recipient_share,
        threshold_distribution,
        transfer_proof,
    };
    let db = directory.path().join("node.sqlite");
    let mut node = CommitteeNode::open(&db, engine, config()?)?;
    assert!(matches!(
        node.ingest(bundle.clone(), &WrongProfileFinality),
        Err(NodeError::FinalityRejected)
    ));
    assert!(matches!(
        node.ingest(bundle.clone(), &WrongPairFinality),
        Err(NodeError::FinalityRejected)
    ));
    assert_eq!(
        node.ingest(bundle.clone(), &AcceptFinality)?,
        IngestDisposition::Accepted
    );
    assert!(matches!(
        node.process_next::<TestReceipt, _>(&WrongProfileFinality),
        Err(NodeError::FinalityRejected)
    ));
    let tamper = rusqlite::Connection::open(&db)?;
    let original: Vec<u8> = tamper.query_row("SELECT bundle_json FROM inbox LIMIT 1", [], |row| row.get(0))?;
    let mut value: serde_json::Value = serde_json::from_slice(&original)?;
    value["finality"]["attestation"] = serde_json::json!([0, 1, 2]);
    let tampered = serde_json::to_vec(&value)?;
    let tampered_digest: [u8; 32] = sha2::Sha256::digest(&tampered).into();
    tamper.execute(
        "UPDATE inbox SET bundle_json=?1,bundle_digest=?2",
        rusqlite::params![tampered, tampered_digest.as_slice()],
    )?;
    assert!(matches!(
        node.process_next::<TestReceipt, _>(&AcceptFinality),
        Err(NodeError::FinalityRejected)
    ));
    let original_digest: [u8; 32] = sha2::Sha256::digest(&original).into();
    tamper.execute(
        "UPDATE inbox SET bundle_json=?1,bundle_digest=?2",
        rusqlite::params![original, original_digest.as_slice()],
    )?;
    drop(tamper);
    node.inject_crash_after_runtime_once();
    assert!(matches!(
        node.process_next::<TestReceipt, _>(&AcceptFinality),
        Err(NodeError::InjectedCrash)
    ));
    let runtime = node.into_runtime();
    let mut restarted = CommitteeNode::open(&db, runtime, config()?)?;
    assert_eq!(
        restarted.process_next::<TestReceipt, _>(&AcceptFinality)?,
        ProcessDisposition::Applied
    );
    let ControlResponse::Outbox(outbox) = restarted.control(ControlRequest::ListOutbox { limit: 10 }, true)? else {
        return Err("wrong control response".into());
    };
    assert_eq!(outbox.len(), 1);
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
        test_scalar(31)?.base_point_mul(),
        test_scalar(17)?,
    )?;
    let descriptor = dealer.descriptor().clone();
    let member_id = descriptor.members().first().ok_or("missing member")?.id();
    let package = dealer.into_packages().into_iter().next().ok_or("missing package")?;
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
    let first_won = first_thread
        .join()
        .map_err(|_| "first vault thread panicked")?
        .is_some();
    let second_won = second_thread
        .join()
        .map_err(|_| "second vault thread panicked")?
        .is_some();
    assert_ne!(first_won, second_won);
    let losing_path = if first_won { copy } else { original };
    assert!(KeystoreCommitteeVault::open(losing_path, &descriptor, member_id, vault_password()?, floor,).is_err());
    Ok(())
}
