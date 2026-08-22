use crate::{
    Actor, ActorRole, Artifact, ChannelEvent, Committee, FinalizeEvent, InvoiceEvent, LedgerEntry, OpenEvent,
    TransferEvent, VerificationEvidence, VerificationKind, VerificationOutcome, HASH_FORMAT_VERSION,
};

/// Canonical binary encoder used exclusively by the ledger-entry hash.
///
/// It is intentionally independent from serde. Fixed-width integers are big
/// endian, variable byte strings use an unsigned 64-bit byte length, optionals
/// use a one-byte presence tag, and enum tags below are permanent wire values.
pub(crate) fn encode_entry(entry: &LedgerEntry) -> Vec<u8> {
    let mut writer = CanonicalWriter::default();
    writer.bytes(b"bitcoin-thunderbolt/ledger-entry");
    writer.u16(HASH_FORMAT_VERSION);
    writer.u16(entry.protocol_version);
    writer.fixed_bytes(entry.channel_id.txid().as_bytes());
    writer.u32(entry.channel_id.vout());
    writer.u64(entry.sequence);
    writer.fixed_bytes(entry.previous_entry_hash.as_bytes());
    writer.bytes(entry.idempotency_key.as_str().as_bytes());
    encode_actor(&mut writer, &entry.actor);
    writer.u64(entry.occurred_at_ms);
    encode_event(&mut writer, &entry.event);
    writer.finish()
}

#[derive(Default)]
struct CanonicalWriter {
    bytes: Vec<u8>,
}

impl CanonicalWriter {
    fn finish(self) -> Vec<u8> {
        self.bytes
    }

    fn u8(&mut self, value: u8) {
        self.bytes.push(value);
    }

    fn u16(&mut self, value: u16) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }

    fn u32(&mut self, value: u32) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }

    fn u64(&mut self, value: u64) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }

    fn fixed_bytes(&mut self, value: &[u8]) {
        self.bytes.extend_from_slice(value);
    }

    fn bytes(&mut self, value: &[u8]) {
        self.u64(value.len() as u64);
        self.fixed_bytes(value);
    }

    fn artifact(&mut self, artifact: &Artifact) {
        self.bytes(artifact.as_bytes());
    }

    fn optional_u64(&mut self, value: Option<u64>) {
        match value {
            Some(value) => {
                self.u8(1);
                self.u64(value);
            }
            None => self.u8(0),
        }
    }
}

fn encode_actor(writer: &mut CanonicalWriter, actor: &Actor) {
    writer.bytes(actor.participant_id.as_str().as_bytes());
    writer.u8(match actor.role {
        ActorRole::Holder => 1,
        ActorRole::Recipient => 2,
        ActorRole::Committee => 3,
        ActorRole::LedgerOperator => 4,
    });
}

fn encode_committee(writer: &mut CanonicalWriter, committee: &Committee) {
    writer.bytes(committee.committee_id().as_str().as_bytes());
    writer.u16(committee.member_count());
    writer.u16(committee.threshold());
}

fn encode_event(writer: &mut CanonicalWriter, event: &ChannelEvent) {
    match event {
        ChannelEvent::Open(event) => {
            writer.u8(1);
            encode_open(writer, event);
        }
        ChannelEvent::Invoice(event) => {
            writer.u8(2);
            encode_invoice(writer, event);
        }
        ChannelEvent::Transfer(event) => {
            writer.u8(3);
            encode_transfer(writer, event);
        }
        ChannelEvent::Finalize(event) => {
            writer.u8(4);
            encode_finalize(writer, event);
        }
    }
}

fn encode_open(writer: &mut CanonicalWriter, event: &OpenEvent) {
    writer.bytes(event.initial_holder.as_str().as_bytes());
    encode_committee(writer, &event.committee);
    writer.u64(event.capacity_sat);
    writer.artifact(&event.lock_key);
    writer.artifact(&event.initial_holder_anchor);
    writer.artifact(&event.initial_holder_ciphertext);
    encode_verification(writer, &event.verification);
}

fn encode_invoice(writer: &mut CanonicalWriter, event: &InvoiceEvent) {
    writer.bytes(event.invoice_id.as_str().as_bytes());
    writer.bytes(event.recipient.as_str().as_bytes());
    writer.artifact(&event.recipient_encryption_key);
    writer.artifact(&event.public_delta);
    writer.artifact(&event.recipient_ciphertext);
    writer.artifact(&event.committee_package);
    writer.artifact(&event.invoice_proof);
    writer.optional_u64(event.expires_at_ms);
    encode_verification(writer, &event.verification);
}

fn encode_transfer(writer: &mut CanonicalWriter, event: &TransferEvent) {
    writer.bytes(event.invoice_id.as_str().as_bytes());
    writer.bytes(event.sender.as_str().as_bytes());
    writer.bytes(event.recipient.as_str().as_bytes());
    writer.artifact(&event.next_holder_anchor);
    writer.artifact(&event.next_holder_ciphertext);
    writer.artifact(&event.transfer_proof);
    encode_verification(writer, &event.verification);
}

fn encode_finalize(writer: &mut CanonicalWriter, event: &FinalizeEvent) {
    writer.bytes(event.holder.as_str().as_bytes());
    writer.fixed_bytes(event.closing_txid.as_bytes());
    writer.artifact(&event.ownership_proof);
    writer.artifact(&event.committee_attestation);
    encode_verification(writer, &event.verification);
}

fn encode_verification(writer: &mut CanonicalWriter, evidence: &[VerificationEvidence]) {
    writer.u64(evidence.len() as u64);
    for item in evidence {
        writer.u8(match item.kind {
            VerificationKind::FundingTransaction => 1,
            VerificationKind::InitialState => 2,
            VerificationKind::InvoiceConsistencyProof => 3,
            VerificationKind::TransferConsistencyProof => 4,
            VerificationKind::AnchorTransition => 5,
            VerificationKind::HolderOwnershipProof => 6,
            VerificationKind::CommitteeQuorum => 7,
            VerificationKind::ClosingTransaction => 8,
        });
        writer.bytes(item.verifier.as_str().as_bytes());
        writer.bytes(item.implementation.as_str().as_bytes());
        writer.fixed_bytes(item.statement_digest.as_bytes());
        writer.u64(item.verified_at_ms);
        writer.u8(match item.outcome {
            VerificationOutcome::Verified => 1,
            VerificationOutcome::Rejected => 2,
        });
    }
}
