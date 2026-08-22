#![allow(dead_code)]

use std::sync::OnceLock;

use bitcoin::Network;
use libpaillier::{DecryptionKey, EncryptionKey};
use secp::Scalar;
use thunderbolt_core::paillier::{add_ciphertexts, encrypt_plaintext, random_nonce_in_group};
use thunderbolt_core::threshold::{create_threshold_refresh_distribution, ThresholdMemberPublicKey};
use thunderbolt_core::zkp::types::{canonical_big_number_bytes, scalar_to_big_number};
use thunderbolt_core::zkp::{
    prove_invoice, prove_share_encryption, prove_transfer, InvoiceStatement, InvoiceWitness, ShareEncryptionStatement,
    ShareEncryptionWitness, TransferStatement, TransferWitness,
};
use thunderbolt_protocol::{
    Actor, ActorRole, Artifact, BitcoinTxid, ChannelEvent, ChannelId, ChannelReducer, ChannelSnapshot, Committee,
    Digest, EntryHash, EventKind, HistoryContext, IdempotencyKey, ImplementationId, InvoiceEvent, InvoiceId,
    LedgerEntry, OpenEvent, ParticipantId, TransferEvent, VerificationEvidence, VerificationKind,
};
use thunderbolt_verifier::{
    CommitteeBinding, DeploymentContext, TrustedVerifier, VerificationOutput, VerifierIdentity,
    RECIPIENT_SHARE_MEMBER_ID,
};
use thunderbolt_wire::{
    to_json_vec, BindingContext, InvoiceEnvelopeV1, PublicMessageV1, ShareEnvelopeV1, ThresholdEnvelopeV1,
    TransferEnvelopeV1,
};

pub const INVOICE_LEDGER_TIME: u64 = 1_100;
pub const TRANSFER_LEDGER_TIME: u64 = 1_200;

#[derive(Clone, Debug)]
pub struct SingleFixture {
    pub verifier: TrustedVerifier,
    pub open_snapshot: ChannelSnapshot,
    pub invoice_entry: LedgerEntry,
    pub invoice_output: VerificationOutput,
    pub committed_invoice: LedgerEntry,
    pub invoice_snapshot: ChannelSnapshot,
    pub transfer_entry: LedgerEntry,
    pub invoice_message: PublicMessageV1,
    pub transfer_message: PublicMessageV1,
}

#[derive(Clone, Debug)]
pub struct ThresholdFixture {
    pub verifier: TrustedVerifier,
    pub open_snapshot: ChannelSnapshot,
    pub invoice_entry: LedgerEntry,
    pub recipient_message: PublicMessageV1,
    pub threshold_message: PublicMessageV1,
}

pub fn single_fixture() -> &'static SingleFixture {
    static FIXTURE: OnceLock<SingleFixture> = OnceLock::new();
    FIXTURE.get_or_init(build_single_fixture)
}

pub fn threshold_fixture() -> &'static ThresholdFixture {
    static FIXTURE: OnceLock<ThresholdFixture> = OnceLock::new();
    FIXTURE.get_or_init(build_threshold_fixture)
}

pub fn scalar(value: u8) -> Scalar {
    let mut bytes = [0_u8; 32];
    bytes[31] = value;
    Scalar::from_slice(&bytes).expect("fixture scalar is nonzero and in range")
}

pub fn replace_invoice_proof(entry: &mut LedgerEntry, message: &PublicMessageV1) {
    let ChannelEvent::Invoice(event) = &mut entry.event else {
        panic!("fixture is an invoice")
    };
    event.invoice_proof = artifact(to_json_vec(message).expect("valid fixture wire JSON"));
}

fn build_single_fixture() -> SingleFixture {
    let channel_id = ChannelId::new(BitcoinTxid::from_bytes([0x11; 32]), 7);
    let invoice_id = InvoiceId::new("invoice-single-1").expect("valid fixture invoice id");
    let holder = ParticipantId::new("holder:alice").expect("valid fixture participant");
    let recipient = ParticipantId::new("recipient:bob").expect("valid fixture participant");
    let committee_id = ParticipantId::new("committee:single").expect("valid fixture participant");
    let anchor_base = scalar(41).base_point_mul();
    let holder_secret = scalar(11);
    let current_anchor = anchor_base * holder_secret;

    let bob_secret = DecryptionKey::random().expect("generate fixture recipient key");
    let bob_key = EncryptionKey::from(&bob_secret);
    let committee_secret = DecryptionKey::random().expect("generate fixture committee key");
    let committee_key = EncryptionKey::from(&committee_secret);

    let committee = Committee::new(committee_id.clone(), 1, 1).expect("valid fixture committee");
    let open_snapshot = make_open_snapshot(channel_id, holder.clone(), committee, current_anchor);
    let committee_binding =
        CommitteeBinding::single(committee_id, committee_key.to_bytes()).expect("valid single committee binding");
    let deployment = DeploymentContext::new(
        Network::Regtest,
        b"fixture-deployment",
        9,
        anchor_base.serialize(),
        committee_binding,
    )
    .expect("valid fixture deployment");
    let verifier = TrustedVerifier::new(deployment, verifier_identity());

    let binding = BindingContext::invoice(
        Network::Regtest,
        b"fixture-deployment",
        9,
        channel_id.canonical_bytes(),
        invoice_id.as_str().as_bytes(),
    )
    .expect("valid invoice binding");
    let refresh = scalar(7);
    let refresh_integer = scalar_to_big_number(refresh);
    let bob_nonce = random_nonce_in_group(&bob_key);
    let committee_nonce = random_nonce_in_group(&committee_key);
    let invoice_statement = InvoiceStatement {
        context: binding.proof_context().expect("invoice proof context"),
        anchor_base,
        bob_key: bob_key.clone(),
        committee_key: committee_key.clone(),
        delta: anchor_base * refresh,
        bob_ciphertext: encrypt_plaintext(&bob_key, &refresh_integer, &bob_nonce)
            .expect("recipient invoice ciphertext"),
        committee_ciphertext: encrypt_plaintext(&committee_key, &refresh_integer, &committee_nonce)
            .expect("committee invoice ciphertext"),
    };
    let invoice_proof = prove_invoice(
        &invoice_statement,
        &InvoiceWitness {
            refresh,
            bob_nonce,
            committee_nonce,
        },
    )
    .expect("valid invoice proof");
    let invoice_envelope =
        InvoiceEnvelopeV1::from_core(binding, &invoice_statement, &invoice_proof).expect("valid invoice envelope");
    let invoice_message = PublicMessageV1::Invoice(invoice_envelope);
    let invoice_entry = LedgerEntry::new(
        channel_id,
        open_snapshot.next_sequence().expect("next fixture sequence"),
        open_snapshot.head_hash,
        IdempotencyKey::new("invoice-single-1").expect("valid idempotency key"),
        Actor::new(recipient.clone(), ActorRole::Recipient),
        1_050,
        ChannelEvent::Invoice(InvoiceEvent {
            invoice_id: invoice_id.clone(),
            recipient: recipient.clone(),
            recipient_encryption_key: artifact(bob_key.to_bytes()),
            public_delta: artifact(invoice_statement.delta.serialize()),
            recipient_ciphertext: artifact(canonical_big_number_bytes(&invoice_statement.bob_ciphertext)),
            committee_package: artifact(canonical_big_number_bytes(&invoice_statement.committee_ciphertext)),
            invoice_proof: artifact(to_json_vec(&invoice_message).expect("valid compact invoice JSON")),
            expires_at_ms: Some(5_000),
            verification: Vec::new(),
        }),
    );
    let invoice_output = verifier
        .verify_invoice(&invoice_entry, &open_snapshot, INVOICE_LEDGER_TIME)
        .expect("fixture invoice verifies");
    let mut committed_invoice = invoice_entry.clone();
    let ChannelEvent::Invoice(event) = &mut committed_invoice.event else {
        panic!("fixture is an invoice")
    };
    event.verification = invoice_output.evidence().to_vec();
    let invoice_snapshot = ChannelReducer::default()
        .apply(
            Some(&open_snapshot),
            &committed_invoice,
            HistoryContext::empty(INVOICE_LEDGER_TIME),
        )
        .expect("commit fixture invoice")
        .snapshot;

    let transfer_binding = BindingContext::transfer(
        Network::Regtest,
        b"fixture-deployment",
        9,
        channel_id.canonical_bytes(),
        invoice_id.as_str().as_bytes(),
        1,
    )
    .expect("valid transfer binding");
    let holder_nonce = random_nonce_in_group(&bob_key);
    let holder_component = encrypt_plaintext(&bob_key, &scalar_to_big_number(holder_secret), &holder_nonce)
        .expect("holder ciphertext component");
    let next_holder_ciphertext = add_ciphertexts(&bob_key, &holder_component, &invoice_statement.bob_ciphertext)
        .expect("next holder ciphertext");
    let next_anchor = (current_anchor + invoice_statement.delta)
        .into_option()
        .expect("finite next anchor");
    let transfer_statement = TransferStatement {
        context: transfer_binding.proof_context().expect("transfer proof context"),
        anchor_base,
        bob_key,
        current_anchor,
        invoice_ciphertext: invoice_statement.bob_ciphertext,
        next_holder_ciphertext: next_holder_ciphertext.clone(),
    };
    let transfer_proof = prove_transfer(
        &transfer_statement,
        &TransferWitness {
            holder_secret,
            holder_nonce,
        },
    )
    .expect("valid transfer proof");
    let transfer_envelope = TransferEnvelopeV1::from_core(
        transfer_binding,
        &transfer_statement,
        &transfer_proof,
        &invoice_statement.delta,
        &next_anchor,
    )
    .expect("valid transfer envelope");
    let transfer_message = PublicMessageV1::Transfer(transfer_envelope);
    let transfer_entry = LedgerEntry::new(
        channel_id,
        invoice_snapshot.next_sequence().expect("next fixture sequence"),
        invoice_snapshot.head_hash,
        IdempotencyKey::new("transfer-single-1").expect("valid idempotency key"),
        Actor::new(holder.clone(), ActorRole::Holder),
        1_150,
        ChannelEvent::Transfer(TransferEvent {
            invoice_id,
            sender: holder,
            recipient,
            next_holder_anchor: artifact(next_anchor.serialize()),
            next_holder_ciphertext: artifact(canonical_big_number_bytes(&next_holder_ciphertext)),
            transfer_proof: artifact(to_json_vec(&transfer_message).expect("valid compact transfer JSON")),
            verification: Vec::new(),
        }),
    );

    SingleFixture {
        verifier,
        open_snapshot,
        invoice_entry,
        invoice_output,
        committed_invoice,
        invoice_snapshot,
        transfer_entry,
        invoice_message,
        transfer_message,
    }
}

fn build_threshold_fixture() -> ThresholdFixture {
    let channel_id = ChannelId::new(BitcoinTxid::from_bytes([0x22; 32]), 3);
    let invoice_id = InvoiceId::new("invoice-threshold-1").expect("valid fixture invoice id");
    let holder = ParticipantId::new("holder:carol").expect("valid fixture participant");
    let recipient = ParticipantId::new("recipient:dave").expect("valid fixture participant");
    let committee_id = ParticipantId::new("committee:threshold").expect("valid fixture participant");
    let anchor_base = scalar(43).base_point_mul();
    let current_anchor = anchor_base * scalar(12);
    let committee = Committee::new(committee_id.clone(), 2, 2).expect("valid fixture committee");
    let open_snapshot = make_open_snapshot(channel_id, holder, committee, current_anchor);

    let member_keys = (1_u32..=2)
        .map(|member_id| {
            let secret = DecryptionKey::random().expect("generate fixture member key");
            ThresholdMemberPublicKey {
                member_id,
                encryption_key: EncryptionKey::from(&secret),
            }
        })
        .collect::<Vec<_>>();
    let committee_binding = CommitteeBinding::threshold(
        committee_id,
        2,
        member_keys
            .iter()
            .map(|member| (member.member_id, member.encryption_key.to_bytes())),
    )
    .expect("valid threshold committee binding");
    let deployment = DeploymentContext::new(
        Network::Regtest,
        b"fixture-deployment",
        10,
        anchor_base.serialize(),
        committee_binding,
    )
    .expect("valid fixture deployment");
    let verifier = TrustedVerifier::new(deployment, verifier_identity());

    let binding = BindingContext::invoice(
        Network::Regtest,
        b"fixture-deployment",
        10,
        channel_id.canonical_bytes(),
        invoice_id.as_str().as_bytes(),
    )
    .expect("valid threshold invoice binding");
    let bob_secret = DecryptionKey::random().expect("generate fixture recipient key");
    let bob_key = EncryptionKey::from(&bob_secret);
    let refresh = scalar(8);
    let refresh_integer = scalar_to_big_number(refresh);
    let bob_nonce = random_nonce_in_group(&bob_key);
    let delta = anchor_base * refresh;
    let bob_ciphertext =
        encrypt_plaintext(&bob_key, &refresh_integer, &bob_nonce).expect("threshold recipient ciphertext");
    let recipient_statement = ShareEncryptionStatement {
        context: binding.proof_context().expect("recipient proof context"),
        anchor_base,
        recipient_key: bob_key.clone(),
        member_id: RECIPIENT_SHARE_MEMBER_ID,
        committed_point: delta,
        ciphertext: bob_ciphertext.clone(),
    };
    let recipient_proof = prove_share_encryption(
        &recipient_statement,
        &ShareEncryptionWitness {
            secret: refresh,
            nonce: bob_nonce,
        },
    )
    .expect("valid recipient share proof");
    let recipient_envelope = ShareEnvelopeV1::from_core(binding.clone(), &recipient_statement, &recipient_proof)
        .expect("valid recipient share envelope");
    let recipient_message = PublicMessageV1::Share(recipient_envelope);

    let distribution = create_threshold_refresh_distribution(
        binding.proof_context().expect("threshold proof context"),
        anchor_base,
        2,
        refresh,
        &member_keys,
    )
    .expect("valid threshold distribution");
    let threshold_envelope = ThresholdEnvelopeV1::from_core(binding, &distribution).expect("valid threshold envelope");
    let threshold_message = PublicMessageV1::ThresholdRefresh(threshold_envelope);

    let invoice_entry = LedgerEntry::new(
        channel_id,
        open_snapshot.next_sequence().expect("next fixture sequence"),
        open_snapshot.head_hash,
        IdempotencyKey::new("invoice-threshold-1").expect("valid idempotency key"),
        Actor::new(recipient.clone(), ActorRole::Recipient),
        1_050,
        ChannelEvent::Invoice(InvoiceEvent {
            invoice_id,
            recipient,
            recipient_encryption_key: artifact(bob_key.to_bytes()),
            public_delta: artifact(delta.serialize()),
            recipient_ciphertext: artifact(canonical_big_number_bytes(&bob_ciphertext)),
            committee_package: artifact(to_json_vec(&threshold_message).expect("valid threshold JSON")),
            invoice_proof: artifact(to_json_vec(&recipient_message).expect("valid recipient proof JSON")),
            expires_at_ms: Some(5_000),
            verification: Vec::new(),
        }),
    );

    ThresholdFixture {
        verifier,
        open_snapshot,
        invoice_entry,
        recipient_message,
        threshold_message,
    }
}

fn make_open_snapshot(
    channel_id: ChannelId,
    holder: ParticipantId,
    committee: Committee,
    current_anchor: secp::Point,
) -> ChannelSnapshot {
    let at = 1_000;
    let open = LedgerEntry::new(
        channel_id,
        0,
        EntryHash::ZERO,
        IdempotencyKey::new("open-fixture").expect("valid idempotency key"),
        Actor::new(holder.clone(), ActorRole::Holder),
        at,
        ChannelEvent::Open(OpenEvent {
            initial_holder: holder,
            committee,
            capacity_sat: 100_000,
            lock_key: artifact([0x02; 33]),
            initial_holder_anchor: artifact(current_anchor.serialize()),
            initial_holder_ciphertext: artifact([0x01]),
            verification: required_evidence(EventKind::Open, at),
        }),
    );
    ChannelReducer::default()
        .apply(None, &open, HistoryContext::empty(at))
        .expect("commit fixture open")
        .snapshot
}

fn required_evidence(kind: EventKind, at: u64) -> Vec<VerificationEvidence> {
    let kinds: &[VerificationKind] = match kind {
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
            VerificationKind::ClosingTransaction,
        ],
    };
    kinds
        .iter()
        .copied()
        .map(|verification_kind| {
            VerificationEvidence::verified(
                verification_kind,
                ParticipantId::new("verifier:fixture").expect("valid verifier id"),
                ImplementationId::new("thunderbolt-verifier/fixture").expect("valid implementation id"),
                Digest::ZERO,
                at,
            )
        })
        .collect()
}

fn verifier_identity() -> VerifierIdentity {
    VerifierIdentity::new(
        ParticipantId::new("verifier:fixture").expect("valid verifier id"),
        ImplementationId::new("thunderbolt-verifier/fixture").expect("valid implementation id"),
    )
}

fn artifact(bytes: impl Into<Vec<u8>>) -> Artifact {
    Artifact::new(bytes).expect("valid nonempty bounded fixture artifact")
}
