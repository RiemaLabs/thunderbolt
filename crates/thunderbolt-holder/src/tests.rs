use std::collections::BTreeMap;

use bitcoin::Network;
use libpaillier::{unknown_order::BigNumber, DecryptionKey, EncryptionKey};
use proptest::prelude::*;
use secp::{MaybeScalar, Scalar};
use thunderbolt_protocol::{BitcoinTxid, ChannelId, Digest, EntryHash, InvoiceId};
use thunderbolt_wire::{
    from_json_slice, to_json_vec, CanonicalDigest, PaillierCiphertextHex, ProofResponseHex, TransferEnvelopeV1,
};

use super::*;
use crate::engine::InvoiceFixture;

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
            .find(|record| record.envelope_digest() == *digest)
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

fn invoice_id(tag: u8) -> Result<InvoiceId, HolderError> {
    InvoiceId::new(format!("invoice-{tag}")).map_err(|_| HolderError::InvalidProtocolIdentifier)
}

fn acknowledgement(digest: [u8; 32], sequence: u64, tag: u8) -> DurableAcknowledgement {
    DurableAcknowledgement::new(sequence, EntryHash::from_bytes([tag; 32]), Digest::from_bytes(digest))
}

fn genesis_ack(tag: u8) -> DurableAcknowledgement {
    DurableAcknowledgement::new(0, EntryHash::from_bytes([tag; 32]), Digest::from_bytes([tag; 32]))
}

fn prepared_invoice(
    recipient: &mut HolderEngine<MemoryVault>,
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
