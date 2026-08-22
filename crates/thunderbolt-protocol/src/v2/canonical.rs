use thunderbolt_ledger::EntryHashV2;
use thunderbolt_wire::{CanonicalDigest as _, HexBytes, InvoiceId};

use super::{
    ArtifactV2, ChannelEventV2, ChannelPhaseV2, ChannelSnapshotV2, FinalizeEventV2, InvoiceEventV2, OpenEventV2,
    TransferEventV2, V2Error, HASH_FORMAT_VERSION_V2,
};

const EVENT_DOMAIN: &[u8] = b"bitcoin-thunderbolt/protocol-event/v2";

pub(crate) fn encoded_event_len(event: &ChannelEventV2) -> Option<usize> {
    let mut length = event_prefix_len()?;
    match event {
        ChannelEventV2::Open(event) => {
            add_len(&mut length, 12)?;
            add_bytes_len(&mut length, event.lock_key.as_bytes())?;
            add_bytes_len(&mut length, event.initial_holder_anchor.as_bytes())?;
            add_bytes_len(&mut length, event.initial_holder_ciphertext.as_bytes())?;
            add_bytes_len(&mut length, event.open_proof.as_bytes())?;
        }
        ChannelEventV2::Invoice(event) => add_invoice_len(&mut length, event)?,
        ChannelEventV2::Transfer(event) => {
            add_bytes_len(&mut length, event.invoice_id.as_bytes())?;
            add_len(&mut length, 32)?;
            add_bytes_len(&mut length, event.next_holder_anchor.as_bytes())?;
            add_bytes_len(&mut length, event.next_holder_ciphertext.as_bytes())?;
            add_bytes_len(&mut length, event.transfer_proof.as_bytes())?;
        }
        ChannelEventV2::Finalize(event) => {
            add_len(&mut length, 32)?;
            add_bytes_len(&mut length, event.closing_transaction.as_bytes())?;
            add_bytes_len(&mut length, event.ownership_proof.as_bytes())?;
            add_bytes_len(&mut length, event.committee_attestation.as_bytes())?;
        }
    }
    Some(length)
}

pub(crate) fn encoded_invoice_event_len(event: &InvoiceEventV2) -> Option<usize> {
    let mut length = event_prefix_len()?;
    add_invoice_len(&mut length, event)?;
    Some(length)
}

fn event_prefix_len() -> Option<usize> {
    8_usize.checked_add(EVENT_DOMAIN.len())?.checked_add(3)
}

fn add_invoice_len(length: &mut usize, event: &InvoiceEventV2) -> Option<()> {
    add_bytes_len(length, event.invoice_id.as_bytes())?;
    add_len(length, 16)?;
    add_bytes_len(length, event.recipient_encryption_key.as_bytes())?;
    add_bytes_len(length, event.public_delta.as_bytes())?;
    add_bytes_len(length, event.recipient_ciphertext.as_bytes())?;
    add_bytes_len(length, event.committee_package.as_bytes())?;
    add_bytes_len(length, event.invoice_proof.as_bytes())
}

fn add_len(length: &mut usize, amount: usize) -> Option<()> {
    *length = length.checked_add(amount)?;
    Some(())
}

fn add_bytes_len(length: &mut usize, value: &[u8]) -> Option<()> {
    add_len(length, 8_usize.checked_add(value.len())?)
}

pub(crate) fn encode_event(event: &ChannelEventV2) -> Vec<u8> {
    let mut writer = CanonicalWriter::default();
    writer.bytes(EVENT_DOMAIN);
    writer.u16(HASH_FORMAT_VERSION_V2);
    match event {
        ChannelEventV2::Open(event) => {
            writer.u8(1);
            encode_open(&mut writer, event);
        }
        ChannelEventV2::Invoice(event) => {
            writer.u8(2);
            encode_invoice(&mut writer, event);
        }
        ChannelEventV2::Transfer(event) => {
            writer.u8(3);
            encode_transfer(&mut writer, event);
        }
        ChannelEventV2::Finalize(event) => {
            writer.u8(4);
            encode_finalize(&mut writer, event);
        }
    }
    writer.finish()
}

pub(crate) fn decode_event(bytes: &[u8]) -> Result<ChannelEventV2, V2Error> {
    let mut reader = CanonicalReader::new(bytes);
    if reader.bytes()? != b"bitcoin-thunderbolt/protocol-event/v2" {
        return Err(V2Error::InvalidCanonicalEvent);
    }
    if reader.u16()? != HASH_FORMAT_VERSION_V2 {
        return Err(V2Error::InvalidCanonicalEvent);
    }
    let event = match reader.u8()? {
        1 => ChannelEventV2::Open(OpenEventV2 {
            committee_member_count: reader.u16()?,
            committee_threshold: reader.u16()?,
            capacity_sat: reader.u64()?,
            lock_key: reader.artifact()?,
            initial_holder_anchor: reader.artifact()?,
            initial_holder_ciphertext: reader.artifact()?,
            open_proof: reader.artifact()?,
        }),
        2 => ChannelEventV2::Invoice(InvoiceEventV2 {
            invoice_id: reader.invoice_id()?,
            holder_step: reader.u64()?,
            recipient_encryption_key: reader.artifact()?,
            public_delta: reader.artifact()?,
            recipient_ciphertext: reader.artifact()?,
            committee_package: reader.artifact()?,
            invoice_proof: reader.artifact()?,
            expires_at_ms: reader.u64()?,
        }),
        3 => ChannelEventV2::Transfer(TransferEventV2 {
            invoice_id: reader.invoice_id()?,
            invoice_entry_hash: reader.entry_hash()?,
            next_holder_anchor: reader.artifact()?,
            next_holder_ciphertext: reader.artifact()?,
            transfer_proof: reader.artifact()?,
        }),
        4 => ChannelEventV2::Finalize(FinalizeEventV2 {
            closing_txid: reader.fixed()?,
            closing_transaction: reader.artifact()?,
            ownership_proof: reader.artifact()?,
            committee_attestation: reader.artifact()?,
        }),
        _ => return Err(V2Error::InvalidCanonicalEvent),
    };
    if !reader.is_empty() {
        return Err(V2Error::InvalidCanonicalEvent);
    }
    Ok(event)
}

pub(crate) fn encode_state(snapshot: &ChannelSnapshotV2) -> Result<Vec<u8>, V2Error> {
    let binding_digest = snapshot
        .binding
        .canonical_digest()
        .map_err(|_| V2Error::InvalidSnapshot {
            reason: "channel binding has no canonical digest",
        })?;
    let mut writer = CanonicalWriter::default();
    writer.bytes(b"bitcoin-thunderbolt/protocol-state/v2");
    writer.u16(HASH_FORMAT_VERSION_V2);
    writer.u16(snapshot.protocol_version);
    writer.bytes(snapshot.ledger_chain_id.as_bytes());
    writer.fixed(&binding_digest);
    writer.u8(match snapshot.phase {
        ChannelPhaseV2::Active => 1,
        ChannelPhaseV2::Finalized => 2,
    });
    writer.u64(snapshot.capacity_sat);
    writer.u16(snapshot.committee_member_count);
    writer.u16(snapshot.committee_threshold);
    writer.artifact(&snapshot.lock_key);
    writer.fixed(snapshot.current_holder.as_bytes());
    writer.artifact(&snapshot.current_holder_anchor);
    writer.artifact(&snapshot.current_holder_ciphertext);
    writer.u64(snapshot.transfers_completed);
    writer.u64(snapshot.pending_invoices.len() as u64);
    for (invoice_id, invoice) in &snapshot.pending_invoices {
        writer.bytes(invoice_id.as_bytes());
        let event = ChannelEventV2::Invoice(invoice.event.clone());
        writer.bytes(&event.canonical_bytes()?);
        writer.fixed(invoice.recipient.as_bytes());
        writer.u64(invoice.holder_step);
        writer.u64(invoice.created_at_ms);
        writer.u64(invoice.expires_at_ms);
        writer.fixed(invoice.committed_entry_hash.as_bytes());
    }
    match &snapshot.last_consumed_invoice_id {
        Some(invoice_id) => {
            writer.u8(1);
            writer.bytes(invoice_id.as_bytes());
        }
        None => writer.u8(0),
    }
    writer.u64(snapshot.last_sequence);
    writer.fixed(snapshot.head_entry_hash.as_bytes());
    writer.u64(snapshot.opened_at_ms);
    writer.u64(snapshot.last_block_time_ms);
    writer.optional_u64(snapshot.finalized_at_ms);
    Ok(writer.finish())
}

fn encode_open(writer: &mut CanonicalWriter, event: &OpenEventV2) {
    writer.u16(event.committee_member_count);
    writer.u16(event.committee_threshold);
    writer.u64(event.capacity_sat);
    writer.artifact(&event.lock_key);
    writer.artifact(&event.initial_holder_anchor);
    writer.artifact(&event.initial_holder_ciphertext);
    writer.artifact(&event.open_proof);
}

fn encode_invoice(writer: &mut CanonicalWriter, event: &InvoiceEventV2) {
    writer.bytes(event.invoice_id.as_bytes());
    writer.u64(event.holder_step);
    writer.artifact(&event.recipient_encryption_key);
    writer.artifact(&event.public_delta);
    writer.artifact(&event.recipient_ciphertext);
    writer.artifact(&event.committee_package);
    writer.artifact(&event.invoice_proof);
    writer.u64(event.expires_at_ms);
}

fn encode_transfer(writer: &mut CanonicalWriter, event: &TransferEventV2) {
    writer.bytes(event.invoice_id.as_bytes());
    writer.fixed(event.invoice_entry_hash.as_bytes());
    writer.artifact(&event.next_holder_anchor);
    writer.artifact(&event.next_holder_ciphertext);
    writer.artifact(&event.transfer_proof);
}

fn encode_finalize(writer: &mut CanonicalWriter, event: &FinalizeEventV2) {
    writer.fixed(&event.closing_txid);
    writer.artifact(&event.closing_transaction);
    writer.artifact(&event.ownership_proof);
    writer.artifact(&event.committee_attestation);
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

    fn u64(&mut self, value: u64) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }

    fn fixed(&mut self, value: &[u8]) {
        self.bytes.extend_from_slice(value);
    }

    fn bytes(&mut self, value: &[u8]) {
        self.u64(value.len() as u64);
        self.fixed(value);
    }

    fn artifact(&mut self, artifact: &ArtifactV2) {
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

struct CanonicalReader<'a> {
    remaining: &'a [u8],
}

impl<'a> CanonicalReader<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { remaining: bytes }
    }

    const fn is_empty(&self) -> bool {
        self.remaining.is_empty()
    }

    fn u8(&mut self) -> Result<u8, V2Error> {
        let value = *self.remaining.first().ok_or(V2Error::InvalidCanonicalEvent)?;
        self.remaining = &self.remaining[1..];
        Ok(value)
    }

    fn u16(&mut self) -> Result<u16, V2Error> {
        Ok(u16::from_be_bytes(self.fixed()?))
    }

    fn u64(&mut self) -> Result<u64, V2Error> {
        Ok(u64::from_be_bytes(self.fixed()?))
    }

    fn fixed<const N: usize>(&mut self) -> Result<[u8; N], V2Error> {
        let (value, remaining) = self
            .remaining
            .split_at_checked(N)
            .ok_or(V2Error::InvalidCanonicalEvent)?;
        self.remaining = remaining;
        <[u8; N]>::try_from(value).map_err(|_| V2Error::InvalidCanonicalEvent)
    }

    fn bytes(&mut self) -> Result<&'a [u8], V2Error> {
        let length = usize::try_from(self.u64()?).map_err(|_| V2Error::InvalidCanonicalEvent)?;
        let (value, remaining) = self
            .remaining
            .split_at_checked(length)
            .ok_or(V2Error::InvalidCanonicalEvent)?;
        self.remaining = remaining;
        Ok(value)
    }

    fn artifact(&mut self) -> Result<ArtifactV2, V2Error> {
        ArtifactV2::new(self.bytes()?).map_err(|_| V2Error::InvalidCanonicalEvent)
    }

    fn invoice_id(&mut self) -> Result<InvoiceId, V2Error> {
        HexBytes::from_bytes("canonical Invoice id", self.bytes()?).map_err(|_| V2Error::InvalidCanonicalEvent)
    }

    fn entry_hash(&mut self) -> Result<EntryHashV2, V2Error> {
        EntryHashV2::from_bytes(self.fixed::<32>()?).map_err(|_| V2Error::InvalidCanonicalEvent)
    }
}
