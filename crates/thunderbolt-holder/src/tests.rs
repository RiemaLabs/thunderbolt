use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use std::sync::{Arc, Mutex};

use bitcoin::Network;
use libpaillier::{unknown_order::BigNumber, DecryptionKey, EncryptionKey};
use proptest::prelude::*;
use secp::{MaybeScalar, Scalar};
use static_assertions::assert_not_impl_any;
use tempfile::TempDir;
use thunderbolt_keystore::{
    AnchoredMutationError, CheckpointCasOutcome, CommitteeDescriptorDigest, ExpectedRecord, KdfParams, KeystoreError,
    NodeId, Password, RecordKey, RecordNamespace, RecoveryVault, RollbackFloorStore, SecretValue, TransactionId, Vault,
    VaultCheckpoint, VaultIdentity, VaultRevision, MAX_TRANSACTION_RECEIPTS, MIN_ARGON2_ITERATIONS,
    MIN_ARGON2_MEMORY_KIB,
};
use thunderbolt_protocol::{BitcoinTxid, ChannelId, Digest, EntryHash, InvoiceId};
use thunderbolt_wire::{
    from_json_slice, to_json_vec, CanonicalDigest, PaillierCiphertextHex, PaillierPublicKeyHex, ProofResponseHex,
    TransferEnvelopeV1,
};

use super::*;
use crate::engine::{derive_identity, InvoiceFixture, ThresholdInvoiceFixture};

assert_not_impl_any!(KeystoreSecretVault<TestFloor>: Clone, std::fmt::Debug);

#[derive(Clone, Default)]
struct TestFloor {
    state: Arc<Mutex<TestFloorState>>,
}

#[derive(Default)]
struct TestFloorState {
    identity: Option<VaultIdentity>,
    checkpoint: Option<VaultCheckpoint>,
    fail_before_advance: bool,
    fail_after_advance: bool,
}

#[derive(Debug, thiserror::Error)]
#[error("test rollback floor failure")]
struct TestFloorError;

impl TestFloor {
    fn fail_before_advance_once(&self) -> Result<(), TestFloorError> {
        let mut state = self.state.lock().map_err(|_| TestFloorError)?;
        state.fail_before_advance = true;
        Ok(())
    }

    fn fail_after_advance_once(&self) -> Result<(), TestFloorError> {
        let mut state = self.state.lock().map_err(|_| TestFloorError)?;
        state.fail_after_advance = true;
        Ok(())
    }

    fn checkpoint(&self) -> Result<Option<VaultCheckpoint>, TestFloorError> {
        let state = self.state.lock().map_err(|_| TestFloorError)?;
        Ok(state.checkpoint)
    }
}

impl RollbackFloorStore for TestFloor {
    type Error = TestFloorError;

    fn load_checkpoint(&self, identity: VaultIdentity) -> Result<Option<VaultCheckpoint>, Self::Error> {
        let state = self.state.lock().map_err(|_| TestFloorError)?;
        if state.identity.is_some_and(|stored| stored != identity) {
            return Ok(None);
        }
        Ok(state.checkpoint)
    }

    fn compare_and_swap_checkpoint(
        &self,
        identity: VaultIdentity,
        expected: Option<VaultCheckpoint>,
        next: VaultCheckpoint,
    ) -> Result<CheckpointCasOutcome, Self::Error> {
        let mut state = self.state.lock().map_err(|_| TestFloorError)?;
        if state.identity.is_some_and(|stored| stored != identity) {
            return Ok(CheckpointCasOutcome::Conflict(None));
        }
        if state.checkpoint == Some(next) {
            return Ok(CheckpointCasOutcome::AlreadyCurrent);
        }
        let valid_transition = match (state.checkpoint, expected) {
            (None, None) => next.revision().get() == 0,
            (Some(current), Some(expected)) if current == expected => current
                .revision()
                .get()
                .checked_add(1)
                .is_some_and(|revision| revision == next.revision().get()),
            _ => false,
        };
        if !valid_transition {
            return Ok(CheckpointCasOutcome::Conflict(state.checkpoint));
        }
        if state.fail_before_advance {
            state.fail_before_advance = false;
            return Err(TestFloorError);
        }
        state.identity = Some(identity);
        state.checkpoint = Some(next);
        if state.fail_after_advance {
            state.fail_after_advance = false;
            return Err(TestFloorError);
        }
        Ok(CheckpointCasOutcome::Advanced)
    }
}

// Public deterministic test primes, split into short literals so secret
// scanners do not mistake cryptographic fixtures for deployable credentials.
const RECIPIENT_P: &str = concat!(
    "f0279bfbc34571a0",
    "fc9d0439b3254db9",
    "4901ac0555e9aa99",
    "ed8d68b4665c302d",
    "eab5b561906f6688",
    "acb6070f531fbbf5",
    "d422dc72a6c7ad5b",
    "4612354579e124b8",
    "193b7faf11b67b14",
    "1041a655f4f710af",
    "3db824aed33bf7d3",
    "bcb5016102c396e0",
    "04af261d6f5434e1",
    "bd228ca79d528706",
    "6eba477265c7720e",
    "f95ca74a44feb8e3",
);
const RECIPIENT_Q: &str = concat!(
    "f497c9a28ba4260a",
    "e1f8a8e8d7dec036",
    "8df5199946e7d43e",
    "8638029457bf7bf6",
    "9849bcb1b085a79c",
    "4e187cd8e6c16301",
    "d7f868a293851f22",
    "0fbd6338e735f29e",
    "dc45a0aa95969752",
    "e21193086cfb24e8",
    "2a16e2ece297c404",
    "b448448617d4eeda",
    "a3a551e7c36770b4",
    "5263d311ceb4e49e",
    "8256307d145c73cb",
    "d632824f5f026c0b",
);
const COMMITTEE_P: &str = concat!(
    "f8416be1b9c94935",
    "23bdb3ad032d2f58",
    "bdfecbb9f2e17285",
    "501021d552613dd3",
    "c97ba4334f141d5e",
    "ec58d76428e58443",
    "952f72014d4cf98f",
    "cabdf7db1d4bf551",
    "21e06904514d6fe3",
    "217ce84791fa0dbb",
    "041591a9fc0993f1",
    "938ad3a3ad58ab7b",
    "5156383d50c9208a",
    "d804e279a2026084",
    "9aa7a3c6aa5fdea2",
    "a6b7d28856fda285",
);
const COMMITTEE_Q: &str = concat!(
    "e8813683d059ce40",
    "71584b39a54f0391",
    "e26dc6f14f10c1c3",
    "373ac9b12febbdd8",
    "54b24d22d778b20c",
    "e00ef812c943e29b",
    "62aacbe76e8c31b5",
    "892ce6d833d83e07",
    "f5b82370cf91d31c",
    "ec361d49f9b3a204",
    "3cee207eb04e3f1e",
    "5e7af1e6e388f822",
    "ad14d88d640e1ee5",
    "17f1c6d2266252b0",
    "9bb3dc60f98796a5",
    "3c5e3253c8f4993f",
);
const MEMBER_TWO_P: &str = concat!(
    "f140e15b8a40c453",
    "77a11136b8983bcf",
    "30959cd6a807873a",
    "63d83525c8b53e37",
    "1a7620369c5b1fb5",
    "facbbef931ac56d9",
    "4e95c741e10c094c",
    "e64e9873e70a562d",
    "ab4b304f2ac2668f",
    "7cd4599b5d2caf33",
    "14bf0a8acbb1bc33",
    "5efe484793bc2283",
    "76bc1076831158af",
    "2393473ecefd030b",
    "4d431ab5dcd01fb1",
    "03b146a178b0e169",
);
const MEMBER_TWO_Q: &str = concat!(
    "f3e46053c59c1b12",
    "0daa3a6267e68aea",
    "1dc784f84e8cd310",
    "cd6baa5035888736",
    "e9958c5d5d470a56",
    "fc0557cf26a1ba00",
    "46b3ca8e9822e323",
    "b38e06ca71f2be55",
    "21fb586e84a0f515",
    "17ff918686536c5c",
    "62a3f655ac5b53ba",
    "0575b7caa05be290",
    "5ab5aa7d6aaa4462",
    "93f9d2f4e661efe2",
    "5ba15a41f9180bb7",
    "e0c4477f07bd020f",
);

#[derive(Clone, Debug, Default)]
struct MemoryData {
    identity: Option<IdentityRecord>,
    invoices: BTreeMap<InvoiceRecordKey, InvoiceRecord>,
    credentials: BTreeMap<CredentialKey, CredentialRecord>,
    outbound: BTreeMap<CredentialKey, OutboundTransferRecord>,
}

#[derive(Clone, Debug, Default)]
struct MemoryVault {
    data: MemoryData,
}

struct MemoryTransaction<'a> {
    vault: &'a mut MemoryVault,
    staged: MemoryData,
}

impl SecretVault for MemoryVault {
    type Transaction<'a> = MemoryTransaction<'a>;

    fn begin(&mut self) -> Result<Self::Transaction<'_>, VaultError> {
        let staged = self.data.clone();
        Ok(MemoryTransaction { vault: self, staged })
    }
}

impl VaultTransaction for MemoryTransaction<'_> {
    fn identity(&self) -> Option<&IdentityRecord> {
        self.staged.identity.as_ref()
    }

    fn insert_identity(&mut self, record: IdentityRecord) -> Result<(), VaultError> {
        if self.staged.identity.is_some() {
            return Err(VaultError::Conflict);
        }
        self.staged.identity = Some(record);
        Ok(())
    }

    fn invoice(&self, key: &InvoiceRecordKey) -> Option<&InvoiceRecord> {
        self.staged.invoices.get(key)
    }

    fn invoice_mut(&mut self, key: &InvoiceRecordKey) -> Option<&mut InvoiceRecord> {
        self.staged.invoices.get_mut(key)
    }

    fn invoice_by_digest_mut(&mut self, digest: &Digest) -> Option<&mut InvoiceRecord> {
        self.staged
            .invoices
            .values_mut()
            .find(|record| record.public_digest() == *digest)
    }

    fn insert_invoice(&mut self, record: InvoiceRecord) -> Result<(), VaultError> {
        let key = record.reference().0;
        if self.staged.invoices.contains_key(&key) {
            return Err(VaultError::Conflict);
        }
        self.staged.invoices.insert(key, record);
        Ok(())
    }

    fn credential(&self, key: &CredentialKey) -> Option<&CredentialRecord> {
        self.staged.credentials.get(key)
    }

    fn credential_mut(&mut self, key: &CredentialKey) -> Option<&mut CredentialRecord> {
        self.staged.credentials.get_mut(key)
    }

    fn highest_credential_step(&self, channel: &ChannelKey) -> Option<u64> {
        self.staged
            .credentials
            .keys()
            .filter(|key| key.channel() == *channel)
            .map(CredentialKey::step)
            .max()
    }

    fn insert_credential(&mut self, record: CredentialRecord) -> Result<(), VaultError> {
        let key = record.key();
        if self.staged.credentials.contains_key(&key) {
            return Err(VaultError::Conflict);
        }
        self.staged.credentials.insert(key, record);
        Ok(())
    }

    fn outbound_transfer(&self, source: &CredentialKey) -> Option<&OutboundTransferRecord> {
        self.staged.outbound.get(source)
    }

    fn outbound_transfer_mut(&mut self, source: &CredentialKey) -> Option<&mut OutboundTransferRecord> {
        self.staged.outbound.get_mut(source)
    }

    fn insert_outbound_transfer(&mut self, record: OutboundTransferRecord) -> Result<(), VaultError> {
        let key = record.source_credential();
        if self.staged.outbound.contains_key(&key) {
            return Err(VaultError::Conflict);
        }
        self.staged.outbound.insert(key, record);
        Ok(())
    }

    fn commit(self) -> Result<(), VaultError> {
        self.vault.data = self.staged;
        Ok(())
    }
}

fn scalar(value: u16) -> Result<Scalar, HolderError> {
    let mut bytes = [0_u8; 32];
    bytes[30..].copy_from_slice(&value.to_be_bytes());
    Scalar::from_slice(&bytes).map_err(|_| HolderError::InvalidInput {
        reason: "test scalar is invalid",
    })
}

fn fixed_key(p: &str, q: &str) -> Result<DecryptionKey, HolderError> {
    let p = hex::decode(p).map_err(|_| HolderError::InvalidInput {
        reason: "test prime is invalid hex",
    })?;
    let q = hex::decode(q).map_err(|_| HolderError::InvalidInput {
        reason: "test prime is invalid hex",
    })?;
    DecryptionKey::with_primes_unchecked(&BigNumber::from_slice(&p), &BigNumber::from_slice(&q))
        .ok_or(HolderError::KeyGenerationFailed)
}

fn recipient_key() -> Result<DecryptionKey, HolderError> {
    fixed_key(RECIPIENT_P, RECIPIENT_Q)
}

fn committee_key() -> Result<DecryptionKey, HolderError> {
    fixed_key(COMMITTEE_P, COMMITTEE_Q)
}

fn member_two_key() -> Result<DecryptionKey, HolderError> {
    fixed_key(MEMBER_TWO_P, MEMBER_TWO_Q)
}

fn threshold_roster() -> Result<ThresholdRoster, HolderError> {
    let first = committee_key()?;
    let second = member_two_key()?;
    ThresholdRoster::new(
        2,
        vec![
            ThresholdMemberPublicKey {
                member_id: 2,
                encryption_key: EncryptionKey::from(&second),
            },
            ThresholdMemberPublicKey {
                member_id: 1,
                encryption_key: EncryptionKey::from(&first),
            },
        ],
    )
}

fn wrong_key_roster() -> Result<ThresholdRoster, HolderError> {
    let first = committee_key()?;
    let wrong = recipient_key()?;
    ThresholdRoster::new(
        2,
        vec![
            ThresholdMemberPublicKey {
                member_id: 1,
                encryption_key: EncryptionKey::from(&first),
            },
            ThresholdMemberPublicKey {
                member_id: 2,
                encryption_key: EncryptionKey::from(&wrong),
            },
        ],
    )
}

fn channel(tag: u8) -> Result<ChannelContext, HolderError> {
    let channel_id = ChannelId::new(BitcoinTxid::from_bytes([tag; 32]), u32::from(tag));
    ChannelContext::new(
        Network::Regtest,
        b"test-deployment",
        7,
        channel_id,
        scalar(17)?.base_point_mul(),
    )
}

fn keystore_channel(tag: u8) -> Result<ChannelContext, HolderError> {
    let channel_id = ChannelId::new(BitcoinTxid::from_bytes([tag; 32]), u32::from(tag));
    ChannelContext::new(
        Network::Regtest,
        b"thunderbolt-regtest-v1",
        7,
        channel_id,
        scalar(17)?.base_point_mul(),
    )
}

fn keystore_identity(node_tag: u8) -> Result<VaultIdentity, Box<dyn std::error::Error>> {
    Ok(holder_keystore_identity(
        Network::Regtest,
        b"thunderbolt-regtest-v1",
        7,
        CommitteeDescriptorDigest::new([0x44; 32])?,
        NodeId::new([node_tag; 32]),
    )?)
}

fn keystore_password() -> Result<Password, Box<dyn std::error::Error>> {
    Ok(Password::from_bytes(b"holder adapter test password".to_vec())?)
}

fn keystore_params() -> Result<KdfParams, Box<dyn std::error::Error>> {
    Ok(KdfParams::new(MIN_ARGON2_MEMORY_KIB, MIN_ARGON2_ITERATIONS, 1)?)
}

fn create_keystore_adapter(
    path: &Path,
    node_tag: u8,
    floor: TestFloor,
) -> Result<KeystoreSecretVault<TestFloor>, Box<dyn std::error::Error>> {
    Ok(KeystoreSecretVault::create(
        path,
        keystore_identity(node_tag)?,
        keystore_password()?,
        keystore_params()?,
        floor,
    )?)
}

fn reopen_keystore_adapter(
    path: &Path,
    node_tag: u8,
    floor: TestFloor,
) -> Result<KeystoreSecretVault<TestFloor>, Box<dyn std::error::Error>> {
    Ok(KeystoreSecretVault::open_with_floor_store(
        path,
        keystore_identity(node_tag)?,
        keystore_password()?,
        floor,
    )?)
}

fn invoice_id(tag: u8) -> Result<InvoiceId, HolderError> {
    InvoiceId::new(format!("invoice-{tag}")).map_err(|_| HolderError::InvalidProtocolIdentifier)
}

fn acknowledgement(digest: [u8; 32], sequence: u64, tag: u8) -> DurableAcknowledgement {
    DurableAcknowledgement::new(sequence, EntryHash::from_bytes([tag; 32]), Digest::from_bytes(digest))
}

fn genesis_ack(tag: u8) -> DurableAcknowledgement {
    DurableAcknowledgement::new(0, EntryHash::from_bytes([tag; 32]), Digest::from_bytes([tag; 32]))
}

fn prepared_invoice<V: SecretVault>(
    recipient: &mut HolderEngine<V>,
    channel: &ChannelContext,
    invoice_id: &InvoiceId,
    refresh: Scalar,
) -> Result<PreparedInvoice, HolderError> {
    let recipient_sk = recipient_key()?;
    let committee_sk = committee_key()?;
    recipient.create_invoice_with_fixture(
        InvoiceRequest::new(
            channel.clone(),
            invoice_id.clone(),
            1,
            EncryptionKey::from(&committee_sk),
        )?,
        InvoiceFixture {
            decryption_key: recipient_sk,
            refresh,
            bob_nonce: BigNumber::from(2_u32),
            committee_nonce: BigNumber::from(3_u32),
        },
    )
}

fn prepared_threshold_invoice<V: SecretVault>(
    recipient: &mut HolderEngine<V>,
    channel: &ChannelContext,
    invoice_id: &InvoiceId,
    roster: ThresholdRoster,
    refresh: Scalar,
) -> Result<PreparedThresholdInvoice, HolderError> {
    recipient.create_threshold_invoice_with_fixture(
        ThresholdInvoiceRequest::new(channel.clone(), invoice_id.clone(), 1, roster)?,
        ThresholdInvoiceFixture {
            decryption_key: recipient_key()?,
            refresh,
            recipient_nonce: BigNumber::from(7_u32),
        },
    )
}

fn initialize_engine(tag: u8) -> Result<HolderEngine<MemoryVault>, HolderError> {
    let mut engine = HolderEngine::new(MemoryVault::default());
    let _ = engine.initialize_with_fixture_seed([tag; 32])?;
    Ok(engine)
}

struct Flow {
    sender: HolderEngine<MemoryVault>,
    recipient: HolderEngine<MemoryVault>,
    channel: ChannelContext,
    invoice_id: InvoiceId,
    invoice_envelope: thunderbolt_wire::InvoiceEnvelopeV1,
    prepared_transfer: PreparedTransfer,
}

fn prepare_flow(holder: u16, refresh: u16, tag: u8) -> Result<Flow, HolderError> {
    let channel = channel(tag)?;
    let invoice_id = invoice_id(tag)?;
    let mut sender = initialize_engine(tag.wrapping_add(1))?;
    let mut recipient = initialize_engine(tag.wrapping_add(2))?;
    let holder_secret = scalar(holder)?;
    let anchor = channel.anchor_base() * holder_secret;
    let _ = sender.install_genesis_credential(GenesisCredential::new(
        channel.clone(),
        CredentialSecret::from_bytes(holder_secret.serialize().to_owned())?,
        anchor,
        genesis_ack(tag),
    )?)?;
    let prepared_invoice = prepared_invoice(&mut recipient, &channel, &invoice_id, scalar(refresh)?)?;
    let invoice_envelope = prepared_invoice.envelope().clone();
    let invoice_digest = prepared_invoice.envelope().canonical_digest()?;
    let committed_invoice = CommittedInvoice::new(
        prepared_invoice.envelope().clone(),
        1,
        acknowledgement(invoice_digest, 1, tag.wrapping_add(3)),
    )?;
    let _ = recipient.verify_committed_invoice(&channel, &invoice_id, committed_invoice.clone())?;
    let verified = sender.verify_committed_invoice(&channel, &invoice_id, committed_invoice)?;
    let prepared_transfer = sender.create_transfer_with_fixture_nonce(&verified, BigNumber::from(5_u32))?;
    Ok(Flow {
        sender,
        recipient,
        channel,
        invoice_id,
        invoice_envelope,
        prepared_transfer,
    })
}

struct ThresholdFlow {
    sender: HolderEngine<MemoryVault>,
    recipient: HolderEngine<MemoryVault>,
    channel: ChannelContext,
    invoice_id: InvoiceId,
    roster: ThresholdRoster,
    prepared_invoice: PreparedThresholdInvoice,
    prepared_transfer: PreparedTransfer,
}

fn prepare_threshold_flow(holder: u16, refresh: u16, tag: u8) -> Result<ThresholdFlow, HolderError> {
    let channel = channel(tag)?;
    let invoice_id = invoice_id(tag)?;
    let roster = threshold_roster()?;
    let mut sender = initialize_engine(tag.wrapping_add(11))?;
    let mut recipient = initialize_engine(tag.wrapping_add(12))?;
    let holder_secret = scalar(holder)?;
    let _ = sender.install_genesis_credential(GenesisCredential::new(
        channel.clone(),
        CredentialSecret::from_bytes(holder_secret.serialize())?,
        channel.anchor_base() * holder_secret,
        genesis_ack(tag.wrapping_add(10)),
    )?)?;
    let prepared_invoice =
        prepared_threshold_invoice(&mut recipient, &channel, &invoice_id, roster.clone(), scalar(refresh)?)?;
    let package_digest = prepared_invoice.package_digest()?;
    let committed_invoice = CommittedThresholdInvoice::new(
        prepared_invoice.recipient_share().clone(),
        prepared_invoice.threshold_distribution().clone(),
        1,
        acknowledgement(package_digest.to_bytes(), 1, tag.wrapping_add(13)),
    )?;
    let _ = recipient.verify_committed_threshold_invoice(&channel, &invoice_id, &roster, committed_invoice.clone())?;
    let verified = sender.verify_committed_threshold_invoice(&channel, &invoice_id, &roster, committed_invoice)?;
    let prepared_transfer = sender.create_transfer_with_fixture_nonce(&verified, BigNumber::from(11_u32))?;
    Ok(ThresholdFlow {
        sender,
        recipient,
        channel,
        invoice_id,
        roster,
        prepared_invoice,
        prepared_transfer,
    })
}

fn committed_transfer(prepared: &PreparedTransfer, tag: u8) -> Result<CommittedTransfer, HolderError> {
    let digest = prepared.envelope().canonical_digest()?;
    CommittedTransfer::new(prepared.envelope().clone(), acknowledgement(digest, 2, tag))
}

fn prop_result<T>(result: Result<T, HolderError>) -> Result<T, TestCaseError> {
    result.map_err(|error| TestCaseError::fail(error.to_string()))
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(4))]

    #[test]
    fn algebraic_transfer_and_public_wire_roundtrip(
        holder in 1_u16..=120,
        refresh in 1_u16..=120,
        tag in 1_u8..=200,
    ) {
        let mut flow = prop_result(prepare_flow(holder, refresh, tag))?;
        let invoice_json = to_json_vec(&flow.invoice_envelope)
            .map_err(|error| TestCaseError::fail(error.to_string()))?;
        let decoded_invoice = from_json_slice::<thunderbolt_wire::InvoiceEnvelopeV1>(&invoice_json)
            .map_err(|error| TestCaseError::fail(error.to_string()))?;
        prop_assert_eq!(decoded_invoice, flow.invoice_envelope.clone());
        let transfer_json = to_json_vec(flow.prepared_transfer.envelope())
            .map_err(|error| TestCaseError::fail(error.to_string()))?;
        let decoded_transfer = from_json_slice::<TransferEnvelopeV1>(&transfer_json)
            .map_err(|error| TestCaseError::fail(error.to_string()))?;
        prop_assert_eq!(decoded_transfer, flow.prepared_transfer.envelope().clone());

        let committed = prop_result(committed_transfer(&flow.prepared_transfer, tag.wrapping_add(4)))?;
        let disposition = prop_result(flow.recipient.receive_committed_transfer(&flow.channel, &flow.invoice_id, &committed))?;
        prop_assert_eq!(disposition, ReceiveDisposition::OwnershipRecorded);
        let summary = prop_result(flow.recipient.credential_summary(&flow.channel, 1))?
            .ok_or_else(|| TestCaseError::fail("recipient credential missing"))?;
        let sum = scalar(holder).map_err(|error| TestCaseError::fail(error.to_string()))?
            + scalar(refresh).map_err(|error| TestCaseError::fail(error.to_string()))?;
        let expected_anchor = match sum {
            MaybeScalar::Valid(value) => flow.channel.anchor_base() * value,
            MaybeScalar::Zero => return Err(TestCaseError::fail("test range unexpectedly summed to zero")),
        };
        prop_assert_eq!(summary.anchor(), expected_anchor);
    }

    #[test]
    fn invoice_tamper_wrong_context_and_wrong_private_step_are_rejected(
        mutation in 0_u8..3,
        tag in 1_u8..=200,
    ) {
        let channel = prop_result(channel(tag))?;
        let invoice_id = prop_result(invoice_id(tag))?;
        let mut recipient = prop_result(initialize_engine(tag.wrapping_add(1)))?;
        let refresh = prop_result(scalar(9))?;
        let prepared = prop_result(prepared_invoice(&mut recipient, &channel, &invoice_id, refresh))?;
        let retry = prop_result(prepared_invoice(&mut recipient, &channel, &invoice_id, refresh))?;
        prop_assert_eq!(retry.envelope(), prepared.envelope());
        prop_assert_eq!(retry.private_record(), prepared.private_record());
        let mut envelope = prepared.envelope().clone();
        let expected_step = if mutation == 2 { 2 } else { 1 };
        if mutation == 0 {
            envelope.binding.committee_epoch = envelope.binding.committee_epoch.saturating_add(1);
        } else if mutation == 1 {
            envelope.proof.z = ProofResponseHex::from_bytes("tampered proof response", [1_u8])
                .map_err(|error| TestCaseError::fail(error.to_string()))?;
        }
        let digest = envelope.canonical_digest().map_err(|error| TestCaseError::fail(error.to_string()))?;
        let committed = prop_result(CommittedInvoice::new(
            envelope,
            expected_step,
            acknowledgement(digest, 1, tag.wrapping_add(2)),
        ))?;
        prop_assert!(recipient.verify_committed_invoice(&channel, &invoice_id, committed).is_err());
    }

    #[test]
    fn transfer_tamper_and_wrong_step_are_rejected(
        mutation in 0_u8..3,
        tag in 1_u8..=200,
    ) {
        let mut flow = prop_result(prepare_flow(11, 7, tag))?;
        let mut envelope = flow.prepared_transfer.envelope().clone();
        if mutation == 0 {
            envelope.binding.step = Some(2);
        } else if mutation == 1 {
            envelope.anchor_transition.next_anchor = envelope.anchor_transition.current_anchor.clone();
        } else {
            envelope.statement.next_holder_ciphertext = PaillierCiphertextHex::from_bytes(
                "tampered ciphertext",
                [1_u8],
            ).map_err(|error| TestCaseError::fail(error.to_string()))?;
        }
        let digest = envelope.canonical_digest().map_err(|error| TestCaseError::fail(error.to_string()))?;
        let committed = prop_result(CommittedTransfer::new(
            envelope,
            acknowledgement(digest, 2, tag.wrapping_add(5)),
        ))?;
        prop_assert!(flow.recipient.receive_committed_transfer(&flow.channel, &flow.invoice_id, &committed).is_err());
        prop_assert!(flow.sender.acknowledge_committed_transfer(&flow.channel, &committed).is_err());
    }

    #[test]
    fn monotonic_state_machine_is_idempotent_and_retains_old_credential(
        pre_ack_checks in 0_usize..4,
        transfer_retries in 0_usize..4,
        tag in 1_u8..=200,
    ) {
        let mut flow = prop_result(prepare_flow(13, 5, tag))?;
        for _ in 0..pre_ack_checks {
            let before = prop_result(flow.sender.credential_summary(&flow.channel, 0))?;
            prop_assert!(before.and_then(|summary| summary.transferred_by().cloned()).is_none());
        }
        let committed = prop_result(committed_transfer(&flow.prepared_transfer, tag.wrapping_add(6)))?;
        for index in 0..=transfer_retries {
            let received = prop_result(flow.recipient.receive_committed_transfer(&flow.channel, &flow.invoice_id, &committed))?;
            let acknowledged = prop_result(flow.sender.acknowledge_committed_transfer(&flow.channel, &committed))?;
            if index == 0 {
                prop_assert_eq!(received, ReceiveDisposition::OwnershipRecorded);
                prop_assert_eq!(acknowledged, TransferAcknowledgementDisposition::CredentialRetainedAndMarkedTransferred);
            } else {
                prop_assert_eq!(received, ReceiveDisposition::AlreadyRecorded);
                prop_assert_eq!(acknowledged, TransferAcknowledgementDisposition::AlreadyAcknowledged);
            }
        }
        let old = prop_result(flow.sender.credential_summary(&flow.channel, 0))?
            .ok_or_else(|| TestCaseError::fail("old credential was deleted"))?;
        prop_assert_eq!(old.transferred_by(), Some(committed.acknowledgement()));
        prop_assert!(prop_result(flow.recipient.credential_summary(&flow.channel, 1))?.is_some());
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2))]

    #[test]
    fn threshold_restart_idempotency_wrong_key_and_transfer_roundtrip(
        holder in 1_u16..=80,
        refresh in 1_u16..=80,
        tag in 1_u8..=200,
    ) {
        let flow = prop_result(prepare_threshold_flow(holder, refresh, tag))?;
        let ThresholdFlow {
            mut sender,
            recipient,
            channel,
            invoice_id,
            roster,
            prepared_invoice,
            prepared_transfer,
        } = flow;

        let mut restarted = HolderEngine::new(recipient.into_vault());
        let wrong_retry = prepared_threshold_invoice(
            &mut restarted,
            &channel,
            &invoice_id,
            prop_result(wrong_key_roster())?,
            prop_result(scalar(refresh))?,
        );
        prop_assert!(wrong_retry.is_err());

        let retry = prop_result(prepared_threshold_invoice(
            &mut restarted,
            &channel,
            &invoice_id,
            roster,
            prop_result(scalar(refresh))?,
        ))?;
        prop_assert_eq!(retry.recipient_share(), prepared_invoice.recipient_share());
        prop_assert_eq!(retry.threshold_distribution(), prepared_invoice.threshold_distribution());
        prop_assert_eq!(retry.private_record(), prepared_invoice.private_record());

        let committed = prop_result(committed_transfer(&prepared_transfer, tag.wrapping_add(14)))?;
        let received = prop_result(restarted.receive_committed_transfer(&channel, &invoice_id, &committed))?;
        prop_assert_eq!(received, ReceiveDisposition::OwnershipRecorded);
        let acknowledged = prop_result(sender.acknowledge_committed_transfer(&channel, &committed))?;
        prop_assert_eq!(
            acknowledged,
            TransferAcknowledgementDisposition::CredentialRetainedAndMarkedTransferred
        );
        let old = prop_result(sender.credential_summary(&channel, 0))?
            .ok_or_else(|| TestCaseError::fail("threshold path deleted the old credential"))?;
        prop_assert_eq!(old.transferred_by(), Some(committed.acknowledgement()));
        let next = prop_result(restarted.credential_summary(&channel, 1))?
            .ok_or_else(|| TestCaseError::fail("threshold Recipient credential missing"))?;
        let sum = prop_result(scalar(holder))? + prop_result(scalar(refresh))?;
        let expected_anchor = match sum {
            MaybeScalar::Valid(value) => channel.anchor_base() * value,
            MaybeScalar::Zero => return Err(TestCaseError::fail("test range unexpectedly summed to zero")),
        };
        prop_assert_eq!(next.anchor(), expected_anchor);
    }

    #[test]
    fn threshold_package_tamper_roster_and_wrong_keys_are_rejected(tag in 1_u8..=200) {
        let channel = prop_result(channel(tag))?;
        let invoice_id = prop_result(invoice_id(tag))?;
        let roster = prop_result(threshold_roster())?;
        let mut recipient = prop_result(initialize_engine(tag.wrapping_add(21)))?;
        let prepared = prop_result(prepared_threshold_invoice(
            &mut recipient,
            &channel,
            &invoice_id,
            roster.clone(),
            prop_result(scalar(19))?,
        ))?;

        for mutation in 0_u8..5 {
            let mut recipient_share = prepared.recipient_share().clone();
            let mut threshold_distribution = prepared.threshold_distribution().clone();
            let expected_roster = if mutation == 4 {
                prop_result(wrong_key_roster())?
            } else {
                roster.clone()
            };
            match mutation {
                0 => {
                    recipient_share.proof.z = ProofResponseHex::from_bytes("tampered Recipient response", [1_u8])
                        .map_err(|error| TestCaseError::fail(error.to_string()))?;
                }
                1 => {
                    threshold_distribution.distribution.encrypted_shares[0].proof.z =
                        ProofResponseHex::from_bytes("tampered member response", [1_u8])
                            .map_err(|error| TestCaseError::fail(error.to_string()))?;
                }
                2 => {
                    let wrong_key = prop_result(recipient_key())?;
                    threshold_distribution.distribution.encrypted_shares[0].encryption_key =
                        PaillierPublicKeyHex::from_bytes(
                            "wrong threshold member key",
                            EncryptionKey::from(&wrong_key).to_bytes(),
                        ).map_err(|error| TestCaseError::fail(error.to_string()))?;
                }
                3 => {
                    threshold_distribution.binding.committee_epoch =
                        threshold_distribution.binding.committee_epoch.saturating_add(1);
                }
                4 => {}
                _ => return Err(TestCaseError::fail("unreachable threshold mutation")),
            }

            let attempt = (|| -> Result<VerifiedInvoice, HolderError> {
                let digest = threshold_invoice_package_digest(&recipient_share, &threshold_distribution)?;
                let committed = CommittedThresholdInvoice::new(
                    recipient_share,
                    threshold_distribution,
                    1,
                    acknowledgement(digest.to_bytes(), 1, tag.wrapping_add(mutation)),
                )?;
                recipient.verify_committed_threshold_invoice(
                    &channel,
                    &invoice_id,
                    &expected_roster,
                    committed,
                )
            })();
            prop_assert!(attempt.is_err(), "accepted threshold mutation {mutation}");
        }
    }

    #[test]
    fn threshold_roster_rejects_invalid_shapes(kind in 0_u8..3) {
        let first = prop_result(committee_key())?;
        let second = prop_result(member_two_key())?;
        let (threshold, first_id, second_id) = match kind {
            0 => (2, 1, 1),
            1 => (2, thunderbolt_wire::RECIPIENT_SHARE_MEMBER_ID, 2),
            2 => (3, 1, 2),
            _ => return Err(TestCaseError::fail("unreachable roster mutation")),
        };
        let result = ThresholdRoster::new(
            threshold,
            vec![
                ThresholdMemberPublicKey {
                    member_id: first_id,
                    encryption_key: EncryptionKey::from(&first),
                },
                ThresholdMemberPublicKey {
                    member_id: second_id,
                    encryption_key: EncryptionKey::from(&second),
                },
            ],
        );
        prop_assert!(result.is_err());
    }
}

#[test]
fn release_candidate_parameter_and_debug_redaction_are_explicit() -> Result<(), HolderError> {
    assert_eq!(RC_PAILLIER_MODULUS_BITS, 2048);
    let secret = CredentialSecret::from_bytes(scalar(7)?.serialize().to_owned())?;
    assert_eq!(format!("{secret:?}"), "CredentialSecret([REDACTED])");

    let channel = channel(9)?;
    let genesis = GenesisCredential::new(
        channel.clone(),
        CredentialSecret::from_bytes(scalar(7)?.serialize().to_owned())?,
        channel.anchor_base() * scalar(7)?,
        genesis_ack(9),
    )?;
    let debug = format!("{genesis:?}");
    assert!(debug.contains("[REDACTED]"));
    assert!(!debug.contains(&hex::encode(scalar(7)?.serialize())));
    Ok(())
}

#[test]
fn os_random_identity_is_persisted_and_idempotent() -> Result<(), HolderError> {
    let mut first = HolderEngine::new(MemoryVault::default());
    let identity = first.initialize()?;
    assert_eq!(first.initialize()?, identity);
    assert_eq!(first.identity()?, identity);

    let mut second = HolderEngine::new(MemoryVault::default());
    let second_identity = second.initialize()?;
    assert_ne!(second_identity, identity);
    Ok(())
}

#[test]
fn real_keystore_single_invoice_transfer_receive_survives_restart() -> Result<(), Box<dyn std::error::Error>> {
    let directory = TempDir::new()?;
    let sender_path = directory.path().join("sender.vault");
    let recipient_path = directory.path().join("recipient.vault");
    let sender_floor = TestFloor::default();
    let recipient_floor = TestFloor::default();
    let mut sender = HolderEngine::new(create_keystore_adapter(&sender_path, 0x51, sender_floor.clone())?);
    let mut recipient = HolderEngine::new(create_keystore_adapter(&recipient_path, 0x52, recipient_floor.clone())?);
    let _ = sender.initialize_with_fixture_seed([0x61; 32])?;
    let _ = recipient.initialize_with_fixture_seed([0x62; 32])?;

    let channel = keystore_channel(31)?;
    let invoice_id = invoice_id(31)?;
    let holder_secret = scalar(23)?;
    assert_eq!(
        sender.install_genesis_credential(GenesisCredential::new(
            channel.clone(),
            CredentialSecret::from_bytes(holder_secret.serialize())?,
            channel.anchor_base() * holder_secret,
            genesis_ack(31),
        )?)?,
        ReceiveDisposition::OwnershipRecorded
    );
    let prepared_invoice = prepared_invoice(&mut recipient, &channel, &invoice_id, scalar(13)?)?;
    let invoice_digest = prepared_invoice.envelope().canonical_digest()?;
    let committed_invoice = CommittedInvoice::new(
        prepared_invoice.envelope().clone(),
        1,
        acknowledgement(invoice_digest, 1, 0x63),
    )?;
    let _ = recipient.verify_committed_invoice(&channel, &invoice_id, committed_invoice.clone())?;
    let verified = sender.verify_committed_invoice(&channel, &invoice_id, committed_invoice)?;
    let prepared_transfer = sender.create_transfer_with_fixture_nonce(&verified, BigNumber::from(17_u32))?;

    drop(sender);
    drop(recipient);
    let mut sender = HolderEngine::new(reopen_keystore_adapter(&sender_path, 0x51, sender_floor.clone())?);
    let mut recipient = HolderEngine::new(reopen_keystore_adapter(&recipient_path, 0x52, recipient_floor.clone())?);
    let committed = committed_transfer(&prepared_transfer, 0x64)?;
    assert_eq!(
        recipient.receive_committed_transfer(&channel, &invoice_id, &committed)?,
        ReceiveDisposition::OwnershipRecorded
    );
    assert_eq!(
        sender.acknowledge_committed_transfer(&channel, &committed)?,
        TransferAcknowledgementDisposition::CredentialRetainedAndMarkedTransferred
    );
    assert_eq!(
        recipient.receive_committed_transfer(&channel, &invoice_id, &committed)?,
        ReceiveDisposition::AlreadyRecorded
    );

    drop(sender);
    drop(recipient);
    let mut sender = HolderEngine::new(reopen_keystore_adapter(&sender_path, 0x51, sender_floor)?);
    let mut recipient = HolderEngine::new(reopen_keystore_adapter(&recipient_path, 0x52, recipient_floor)?);
    assert!(sender
        .credential_summary(&channel, 0)?
        .and_then(|summary| summary.transferred_by().cloned())
        .is_some());
    assert!(recipient.credential_summary(&channel, 1)?.is_some());
    Ok(())
}

#[test]
fn real_keystore_threshold_invoice_transfer_receive_survives_restart() -> Result<(), Box<dyn std::error::Error>> {
    let directory = TempDir::new()?;
    let sender_path = directory.path().join("threshold-sender.vault");
    let recipient_path = directory.path().join("threshold-recipient.vault");
    let sender_floor = TestFloor::default();
    let recipient_floor = TestFloor::default();
    let mut sender = HolderEngine::new(create_keystore_adapter(&sender_path, 0x71, sender_floor.clone())?);
    let mut recipient = HolderEngine::new(create_keystore_adapter(&recipient_path, 0x72, recipient_floor.clone())?);
    let _ = sender.initialize_with_fixture_seed([0x73; 32])?;
    let _ = recipient.initialize_with_fixture_seed([0x74; 32])?;
    let channel = keystore_channel(41)?;
    let invoice_id = invoice_id(41)?;
    let roster = threshold_roster()?;
    let holder_secret = scalar(29)?;
    let _ = sender.install_genesis_credential(GenesisCredential::new(
        channel.clone(),
        CredentialSecret::from_bytes(holder_secret.serialize())?,
        channel.anchor_base() * holder_secret,
        genesis_ack(41),
    )?)?;
    let prepared = prepared_threshold_invoice(&mut recipient, &channel, &invoice_id, roster.clone(), scalar(17)?)?;
    let committed_invoice = CommittedThresholdInvoice::new(
        prepared.recipient_share().clone(),
        prepared.threshold_distribution().clone(),
        1,
        acknowledgement(prepared.package_digest()?.to_bytes(), 1, 0x75),
    )?;
    let _ = recipient.verify_committed_threshold_invoice(&channel, &invoice_id, &roster, committed_invoice.clone())?;
    let verified = sender.verify_committed_threshold_invoice(&channel, &invoice_id, &roster, committed_invoice)?;
    let prepared_transfer = sender.create_transfer_with_fixture_nonce(&verified, BigNumber::from(19_u32))?;
    drop(sender);
    drop(recipient);

    let mut sender = HolderEngine::new(reopen_keystore_adapter(&sender_path, 0x71, sender_floor)?);
    let mut recipient = HolderEngine::new(reopen_keystore_adapter(&recipient_path, 0x72, recipient_floor)?);
    let committed = committed_transfer(&prepared_transfer, 0x76)?;
    assert_eq!(
        recipient.receive_committed_transfer(&channel, &invoice_id, &committed)?,
        ReceiveDisposition::OwnershipRecorded
    );
    assert_eq!(
        sender.acknowledge_committed_transfer(&channel, &committed)?,
        TransferAcknowledgementDisposition::CredentialRetainedAndMarkedTransferred
    );
    Ok(())
}

#[test]
fn keystore_dropped_transaction_rolls_back_and_second_open_is_locked() -> Result<(), Box<dyn std::error::Error>> {
    let directory = TempDir::new()?;
    let path = directory.path().join("rollback.vault");
    let twin_path = directory.path().join("same-identity-twin.vault");
    let floor = TestFloor::default();
    let mut adapter = create_keystore_adapter(&path, 0x81, floor.clone())?;
    assert!(matches!(
        create_keystore_adapter(&twin_path, 0x81, floor.clone()),
        Err(error) if matches!(error.downcast_ref::<HolderError>(), Some(HolderError::Vault(VaultError::Conflict)))
    ));
    {
        let mut transaction = adapter.begin()?;
        let seed = zeroize::Zeroizing::new([0x82; 32]);
        transaction.insert_identity(IdentityRecord::new(derive_identity(&seed)?, seed))?;
    }
    {
        let transaction = adapter.begin()?;
        assert!(transaction.identity().is_none());
        transaction.commit()?;
    }
    let mut engine = HolderEngine::new(adapter);
    let _ = engine.initialize_with_fixture_seed([0x83; 32])?;
    let adapter = engine.into_vault();
    assert!(matches!(
        KeystoreSecretVault::open_with_floor_store(&path, keystore_identity(0x81)?, keystore_password()?, floor,),
        Err(HolderError::Vault(VaultError::Conflict))
    ));
    drop(adapter);
    Ok(())
}

#[test]
fn keystore_checkpoint_cas_rejects_divergent_copied_paths() -> Result<(), Box<dyn std::error::Error>> {
    let directory = TempDir::new()?;
    let first_path = directory.path().join("fork-a.vault");
    let second_path = directory.path().join("fork-b.vault");
    let floor = TestFloor::default();
    let mut bootstrap = HolderEngine::new(create_keystore_adapter(&first_path, 0x86, floor.clone())?);
    let _ = bootstrap.initialize_with_fixture_seed([0x87; 32])?;
    bootstrap.into_vault().backup_to(&second_path)?;

    let first = reopen_keystore_adapter(&first_path, 0x86, floor.clone())?;
    assert!(matches!(
        reopen_keystore_adapter(&second_path, 0x86, floor),
        Err(error) if matches!(error.downcast_ref::<HolderError>(), Some(HolderError::Vault(VaultError::Conflict)))
    ));
    let mut first = HolderEngine::new(first);
    let first_channel = keystore_channel(71)?;
    let first_secret = scalar(43)?;
    let _ = first.install_genesis_credential(GenesisCredential::new(
        first_channel.clone(),
        CredentialSecret::from_bytes(first_secret.serialize())?,
        first_channel.anchor_base() * first_secret,
        genesis_ack(71),
    )?)?;
    assert!(first.credential_summary(&first_channel, 0)?.is_some());
    Ok(())
}

#[test]
fn keystore_failed_inserts_remain_non_mutating_after_commit() -> Result<(), Box<dyn std::error::Error>> {
    let directory = TempDir::new()?;
    let path = directory.path().join("failed-inserts.vault");
    let floor = TestFloor::default();
    let mut engine = HolderEngine::new(create_keystore_adapter(&path, 0x88, floor.clone())?);
    let _ = engine.initialize_with_fixture_seed([0x89; 32])?;
    let channel = keystore_channel(73)?;
    let invoice_id = invoice_id(73)?;
    let holder_secret = scalar(53)?;
    let _ = engine.install_genesis_credential(GenesisCredential::new(
        channel.clone(),
        CredentialSecret::from_bytes(holder_secret.serialize())?,
        channel.anchor_base() * holder_secret,
        genesis_ack(73),
    )?)?;
    let prepared_invoice = prepared_invoice(&mut engine, &channel, &invoice_id, scalar(11)?)?;
    let invoice_digest = prepared_invoice.envelope().canonical_digest()?;
    let committed_invoice = CommittedInvoice::new(
        prepared_invoice.envelope().clone(),
        1,
        acknowledgement(invoice_digest, 1, 0x8a),
    )?;
    let verified = engine.verify_committed_invoice(&channel, &invoice_id, committed_invoice)?;
    let prepared_transfer = engine.create_transfer_with_fixture_nonce(&verified, BigNumber::from(23_u32))?;
    let invoice_key = prepared_invoice.private_record().0;
    let credential_key = prepared_transfer.source_credential();
    let outbound_key = credential_key;
    let mut adapter = engine.into_vault();

    let (original_invoice, original_credential, original_outbound) = {
        let transaction = adapter.begin()?;
        let invoice = transaction
            .invoice(&invoice_key)
            .ok_or("missing original invoice")?
            .clone();
        let credential = transaction
            .credential(&credential_key)
            .ok_or("missing original credential")?
            .clone();
        let outbound = transaction
            .outbound_transfer(&outbound_key)
            .ok_or("missing original outbound transfer")?
            .clone();
        transaction.commit()?;
        (invoice, credential, outbound)
    };
    let revision_before_conflict = adapter.revision()?;

    let transfer_digest = prepared_transfer.envelope().canonical_digest()?;
    let transfer_acknowledgement = acknowledgement(transfer_digest, 2, 0x8b);
    let mut rejected_invoice = original_invoice.clone();
    rejected_invoice.restore_state(InvoiceState::Prepared);
    let mut rejected_credential = original_credential.clone();
    rejected_credential.restore_state(CredentialState::Transferred(transfer_acknowledgement.clone()));
    let mut rejected_outbound = original_outbound.clone();
    rejected_outbound.restore_acknowledgement(Some(transfer_acknowledgement));

    {
        let mut transaction = adapter.begin()?;
        assert!(matches!(
            transaction.insert_invoice(rejected_invoice),
            Err(VaultError::Conflict)
        ));
        assert!(matches!(
            transaction.insert_credential(rejected_credential),
            Err(VaultError::Conflict)
        ));
        assert!(matches!(
            transaction.insert_outbound_transfer(rejected_outbound),
            Err(VaultError::Conflict)
        ));
        transaction.commit()?;
    }
    assert_eq!(
        adapter.revision()?.get(),
        revision_before_conflict
            .get()
            .checked_add(1)
            .ok_or("test revision exhausted")?
    );
    drop(adapter);

    let mut adapter = reopen_keystore_adapter(&path, 0x88, floor)?;
    let transaction = adapter.begin()?;
    assert_eq!(
        transaction
            .invoice(&invoice_key)
            .ok_or("invoice lost after conflict")?
            .state(),
        original_invoice.state()
    );
    assert_eq!(
        transaction
            .credential(&credential_key)
            .ok_or("credential lost after conflict")?
            .state(),
        original_credential.state()
    );
    assert_eq!(
        transaction
            .outbound_transfer(&outbound_key)
            .ok_or("outbound transfer lost after conflict")?
            .acknowledgement(),
        original_outbound.acknowledgement()
    );
    transaction.commit()?;
    Ok(())
}

#[test]
fn keystore_identity_accepts_raw_deployment_names_and_rejects_testnet4() -> Result<(), Box<dyn std::error::Error>> {
    let descriptor = CommitteeDescriptorDigest::new([0x44; 32])?;
    let identity = holder_keystore_identity(
        Network::Regtest,
        b"thunderbolt-regtest-v1",
        7,
        descriptor,
        NodeId::new([0x84; 32]),
    )?;
    assert_eq!(identity, keystore_identity(0x84)?);
    assert!(matches!(
        holder_keystore_identity(
            Network::Testnet4,
            b"thunderbolt-testnet4-v1",
            7,
            descriptor,
            NodeId::new([0x85; 32]),
        ),
        Err(HolderError::InvalidInput { .. })
    ));
    Ok(())
}

#[test]
fn keystore_open_completes_exact_empty_revision_zero_bootstrap() -> Result<(), Box<dyn std::error::Error>> {
    let directory = TempDir::new()?;
    let path = directory.path().join("crashed-after-c0.vault");
    let floor = TestFloor::default();
    let identity = keystore_identity(0x98)?;
    let recovery = RecoveryVault::create(&path, identity, keystore_password()?, keystore_params()?)?;
    let checkpoint = recovery.checkpoint();
    assert_eq!(checkpoint.revision().get(), 0);
    assert!(matches!(
        floor.compare_and_swap_checkpoint(identity, None, checkpoint)?,
        CheckpointCasOutcome::Advanced
    ));
    drop(recovery);

    let mut engine = HolderEngine::new(reopen_keystore_adapter(&path, 0x98, floor.clone())?);
    let expected = engine.initialize_with_fixture_seed([0x99; 32])?;
    drop(engine);
    let mut engine = HolderEngine::new(reopen_keystore_adapter(&path, 0x98, floor)?);
    assert_eq!(engine.identity()?, expected);
    Ok(())
}

#[test]
fn keystore_open_rejects_missing_manifest_and_unindexed_adapter_state() -> Result<(), Box<dyn std::error::Error>> {
    let directory = TempDir::new()?;

    let missing_path = directory.path().join("missing-manifest.vault");
    let missing_floor = TestFloor::default();
    let mut engine = HolderEngine::new(create_keystore_adapter(&missing_path, 0x8e, missing_floor.clone())?);
    let _ = engine.initialize_with_fixture_seed([0x8f; 32])?;
    drop(engine);
    let mut raw = Vault::open_anchored(
        &missing_path,
        keystore_identity(0x8e)?,
        keystore_password()?,
        &missing_floor,
    )?;
    let manifest_key = RecordKey::new(
        RecordNamespace::AdapterState,
        b"bitcoin-thunderbolt/holder/identity/v1".to_vec(),
    )?;
    let checkpoint = raw.checkpoint()?;
    let _ = raw.transact(
        checkpoint,
        TransactionId::new([0x90; 32]),
        &missing_floor,
        |transaction| {
            let version = transaction
                .get(&manifest_key)
                .ok_or(thunderbolt_keystore::KeystoreError::InvalidFormat)?
                .version();
            transaction.remove(manifest_key, version)?;
            Ok(())
        },
    )?;
    drop(raw);
    let missing_floor_before = missing_floor.checkpoint()?;
    let missing_file_before =
        RecoveryVault::open(&missing_path, keystore_identity(0x8e)?, keystore_password()?)?.checkpoint();
    assert!(matches!(
        reopen_keystore_adapter(&missing_path, 0x8e, missing_floor.clone()),
        Err(error) if matches!(error.downcast_ref::<HolderError>(), Some(HolderError::Vault(VaultError::CorruptRecord)))
    ));
    assert_eq!(missing_floor.checkpoint()?, missing_floor_before);
    assert_eq!(
        RecoveryVault::open(&missing_path, keystore_identity(0x8e)?, keystore_password()?,)?.checkpoint(),
        missing_file_before
    );

    let generic_path = directory.path().join("generic-state.vault");
    let generic_floor = TestFloor::default();
    let mut engine = HolderEngine::new(create_keystore_adapter(&generic_path, 0x91, generic_floor.clone())?);
    let _ = engine.initialize_with_fixture_seed([0x92; 32])?;
    drop(engine);
    let mut raw = Vault::open_anchored(
        &generic_path,
        keystore_identity(0x91)?,
        keystore_password()?,
        &generic_floor,
    )?;
    let generic_key = RecordKey::new(RecordNamespace::AdapterState, b"unindexed-generic-state".to_vec())?;
    let checkpoint = raw.checkpoint()?;
    let _ = raw.transact(
        checkpoint,
        TransactionId::new([0x93; 32]),
        &generic_floor,
        |transaction| {
            transaction.compare_and_swap(
                generic_key,
                ExpectedRecord::Absent,
                SecretValue::from_bytes(vec![0x94; 32])?,
            )?;
            Ok(())
        },
    )?;
    drop(raw);
    let generic_floor_before = generic_floor.checkpoint()?;
    let generic_file_before =
        RecoveryVault::open(&generic_path, keystore_identity(0x91)?, keystore_password()?)?.checkpoint();
    assert!(matches!(
        reopen_keystore_adapter(&generic_path, 0x91, generic_floor.clone()),
        Err(error) if matches!(error.downcast_ref::<HolderError>(), Some(HolderError::Vault(VaultError::CorruptRecord)))
    ));
    assert_eq!(generic_floor.checkpoint()?, generic_floor_before);
    assert_eq!(
        RecoveryVault::open(&generic_path, keystore_identity(0x91)?, keystore_password()?,)?.checkpoint(),
        generic_file_before
    );
    Ok(())
}

#[test]
fn keystore_receipt_pruning_is_checkpoint_anchored_and_restart_safe() -> Result<(), Box<dyn std::error::Error>> {
    let directory = TempDir::new()?;
    let path = directory.path().join("receipt-pruning.vault");
    let floor = TestFloor::default();
    let mut engine = HolderEngine::new(create_keystore_adapter(&path, 0x8c, floor.clone())?);
    let expected_identity = engine.initialize_with_fixture_seed([0x8d; 32])?;
    assert_eq!(engine.identity()?, expected_identity);
    let mut adapter = engine.into_vault();
    let before = adapter.revision()?;
    let through = VaultRevision::new(before.get().checked_sub(1).ok_or("missing receipt revision")?);
    let after = adapter.prune_finalized_receipts(through)?;
    assert!(after > before);
    drop(adapter);

    let mut engine = HolderEngine::new(reopen_keystore_adapter(&path, 0x8c, floor)?);
    assert_eq!(engine.identity()?, expected_identity);
    Ok(())
}

#[test]
fn keystore_hard_receipt_cap_requires_finalized_prune_before_restart() -> Result<(), Box<dyn std::error::Error>> {
    let directory = TempDir::new()?;
    let path = directory.path().join("receipt-cap.vault");
    let floor = TestFloor::default();
    let mut engine = HolderEngine::new(create_keystore_adapter(&path, 0x9a, floor.clone())?);
    let expected_identity = engine.initialize_with_fixture_seed([0x9b; 32])?;
    drop(engine);

    let identity = keystore_identity(0x9a)?;
    let mut raw = Vault::open_anchored(&path, identity, keystore_password()?, &floor)?;
    let mut saturated = false;
    for index in 0..=MAX_TRANSACTION_RECEIPTS {
        let mut transaction_id = [0_u8; 32];
        transaction_id[0] = 0xa5;
        transaction_id[24..].copy_from_slice(
            &u64::try_from(index)
                .map_err(|_| "receipt index does not fit u64")?
                .to_be_bytes(),
        );
        let checkpoint = raw.checkpoint()?;
        match raw.transact(checkpoint, TransactionId::new(transaction_id), &floor, |_| Ok(())) {
            Ok(_) => {}
            Err(AnchoredMutationError::Keystore(KeystoreError::TransactionReceiptLimitExceeded)) => {
                saturated = true;
                break;
            }
            Err(error) => return Err(Box::new(error)),
        }
    }
    assert!(saturated, "did not reach the hard transaction receipt cap");
    let saturated_checkpoint = raw.checkpoint()?;
    drop(raw);

    assert!(matches!(
        reopen_keystore_adapter(&path, 0x9a, floor.clone()),
        Err(error) if matches!(error.downcast_ref::<HolderError>(), Some(HolderError::Vault(VaultError::CommitFailed)))
    ));
    let adapter = KeystoreSecretVault::open_with_finalized_prune(
        &path,
        identity,
        keystore_password()?,
        floor.clone(),
        saturated_checkpoint.revision(),
    )?;
    let mut engine = HolderEngine::new(adapter);
    assert_eq!(engine.identity()?, expected_identity);
    drop(engine);

    let mut engine = HolderEngine::new(reopen_keystore_adapter(&path, 0x9a, floor)?);
    assert_eq!(engine.identity()?, expected_identity);
    Ok(())
}

#[test]
fn keystore_open_rejects_legacy_v1_adapter_records() -> Result<(), Box<dyn std::error::Error>> {
    let directory = TempDir::new()?;
    let path = directory.path().join("legacy-v1.vault");
    let floor = TestFloor::default();
    let mut engine = HolderEngine::new(create_keystore_adapter(&path, 0x95, floor.clone())?);
    let _ = engine.initialize_with_fixture_seed([0x96; 32])?;
    drop(engine);

    let mut raw = Vault::open_anchored(&path, keystore_identity(0x95)?, keystore_password()?, &floor)?;
    let manifest_key = RecordKey::new(
        RecordNamespace::AdapterState,
        b"bitcoin-thunderbolt/holder/identity/v1".to_vec(),
    )?;
    let mut legacy = Vec::new();
    legacy.extend_from_slice(b"TBHID001");
    legacy.extend_from_slice(&1_u16.to_be_bytes());
    legacy.extend_from_slice(&[0x96; 32]);
    legacy.extend_from_slice(&0_u32.to_be_bytes());
    legacy.extend_from_slice(&0_u32.to_be_bytes());
    legacy.extend_from_slice(&0_u32.to_be_bytes());
    let checkpoint = raw.checkpoint()?;
    let _ = raw.transact(checkpoint, TransactionId::new([0x97; 32]), &floor, |transaction| {
        let version = transaction
            .get(&manifest_key)
            .ok_or(thunderbolt_keystore::KeystoreError::InvalidFormat)?
            .version();
        transaction.compare_and_swap(
            manifest_key,
            ExpectedRecord::Version(version),
            SecretValue::from_bytes(legacy)?,
        )?;
        Ok(())
    })?;
    drop(raw);
    let floor_before = floor.checkpoint()?;
    assert!(matches!(
        reopen_keystore_adapter(&path, 0x95, floor.clone()),
        Err(error) if matches!(error.downcast_ref::<HolderError>(), Some(HolderError::Vault(VaultError::CorruptRecord)))
    ));
    assert_eq!(floor.checkpoint()?, floor_before);
    Ok(())
}

#[test]
fn keystore_tamper_and_old_backup_rollback_fail_closed() -> Result<(), Box<dyn std::error::Error>> {
    let directory = TempDir::new()?;
    let tamper_path = directory.path().join("tamper.vault");
    let tamper_floor = TestFloor::default();
    let mut tamper_engine = HolderEngine::new(create_keystore_adapter(&tamper_path, 0x91, tamper_floor.clone())?);
    let _ = tamper_engine.initialize_with_fixture_seed([0x92; 32])?;
    drop(tamper_engine);
    let mut tampered = fs::read(&tamper_path)?;
    let last = tampered.last_mut().ok_or("empty keystore")?;
    *last ^= 0x80;
    fs::write(&tamper_path, tampered)?;
    assert!(matches!(
        reopen_keystore_adapter(&tamper_path, 0x91, tamper_floor),
        Err(error) if matches!(error.downcast_ref::<HolderError>(), Some(HolderError::Vault(VaultError::CorruptRecord)))
    ));

    let live_path = directory.path().join("live.vault");
    let backup_path = directory.path().join("old.backup");
    let floor = TestFloor::default();
    let mut engine = HolderEngine::new(create_keystore_adapter(&live_path, 0x93, floor.clone())?);
    let _ = engine.initialize_with_fixture_seed([0x94; 32])?;
    engine.into_vault().backup_to(&backup_path)?;
    let mut engine = HolderEngine::new(reopen_keystore_adapter(&live_path, 0x93, floor.clone())?);
    let channel = keystore_channel(51)?;
    let secret = scalar(31)?;
    let _ = engine.install_genesis_credential(GenesisCredential::new(
        channel.clone(),
        CredentialSecret::from_bytes(secret.serialize())?,
        channel.anchor_base() * secret,
        genesis_ack(51),
    )?)?;
    drop(engine);
    fs::copy(&backup_path, &live_path)?;
    assert!(matches!(
        reopen_keystore_adapter(&live_path, 0x93, floor),
        Err(error) if matches!(error.downcast_ref::<HolderError>(), Some(HolderError::Vault(VaultError::Conflict)))
    ));
    Ok(())
}

#[test]
fn keystore_floor_fault_poisoning_and_reconciliation_are_fail_closed() -> Result<(), Box<dyn std::error::Error>> {
    let directory = TempDir::new()?;
    let path = directory.path().join("floor-fault.vault");
    let floor = TestFloor::default();
    let mut engine = HolderEngine::new(create_keystore_adapter(&path, 0xa1, floor.clone())?);
    let _ = engine.initialize_with_fixture_seed([0xa2; 32])?;
    floor.fail_before_advance_once()?;
    let channel = keystore_channel(61)?;
    let secret = scalar(37)?;
    let result = engine.install_genesis_credential(GenesisCredential::new(
        channel.clone(),
        CredentialSecret::from_bytes(secret.serialize())?,
        channel.anchor_base() * secret,
        genesis_ack(61),
    )?);
    assert!(matches!(result, Err(HolderError::Vault(VaultError::CommitFailed))));
    assert!(matches!(
        engine.credential_summary(&channel, 0),
        Err(HolderError::Vault(VaultError::Unavailable))
    ));
    drop(engine);
    assert!(matches!(
        reopen_keystore_adapter(&path, 0xa1, floor),
        Err(error) if matches!(error.downcast_ref::<HolderError>(), Some(HolderError::Vault(VaultError::Conflict)))
    ));

    let after_path = directory.path().join("floor-fault-after.vault");
    let after_floor = TestFloor::default();
    let mut engine = HolderEngine::new(create_keystore_adapter(&after_path, 0xa3, after_floor.clone())?);
    let _ = engine.initialize_with_fixture_seed([0xa4; 32])?;
    let mut adapter = engine.into_vault();
    let second_channel = keystore_channel(62)?;
    let second_secret = scalar(41)?;
    let mut transaction = adapter.begin()?;
    after_floor.fail_after_advance_once()?;
    transaction.insert_credential(CredentialRecord::new(
        CredentialKey {
            channel: second_channel.key(),
            step: 0,
        },
        zeroize::Zeroizing::new(second_secret.serialize()),
        second_channel.anchor_base() * second_secret,
        genesis_ack(62),
    ))?;
    transaction.commit()?;
    drop(adapter);
    let mut engine = HolderEngine::new(reopen_keystore_adapter(&after_path, 0xa3, after_floor)?);
    assert!(engine.credential_summary(&second_channel, 0)?.is_some());
    Ok(())
}
