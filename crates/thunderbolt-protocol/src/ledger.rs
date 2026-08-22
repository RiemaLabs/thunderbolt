use crate::{canonical::encode_entry, Actor, ChannelEvent, ChannelId, EntryHash, IdempotencyKey, InvoiceId};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

/// Current serde protocol schema understood by this crate.
pub const PROTOCOL_VERSION: u16 = 1;

/// Version of the domain-separated canonical binary entry-hash encoding.
///
/// This version is independent of JSON field ordering and formatting.
pub const HASH_FORMAT_VERSION: u16 = 1;

/// One immutable entry in a channel's append-only Thunderbolt Ledger.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LedgerEntry {
    /// Protocol schema version. Reducers currently accept only version 1.
    pub protocol_version: u16,
    /// Funding outpoint that permanently identifies this channel.
    pub channel_id: ChannelId,
    /// Per-channel sequence, starting at zero for Open.
    pub sequence: u64,
    /// Hash of the previous entry, or [`EntryHash::ZERO`] at sequence zero.
    pub previous_entry_hash: EntryHash,
    /// Per-channel caller key used to make append retries idempotent.
    pub idempotency_key: IdempotencyKey,
    /// Authenticated participant identity and asserted role.
    pub actor: Actor,
    /// Externally supplied Unix timestamp in milliseconds.
    pub occurred_at_ms: u64,
    /// State transition payload.
    pub event: ChannelEvent,
}

impl LedgerEntry {
    /// Constructs a version-one entry. No clock or randomness is consulted.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        channel_id: ChannelId,
        sequence: u64,
        previous_entry_hash: EntryHash,
        idempotency_key: IdempotencyKey,
        actor: Actor,
        occurred_at_ms: u64,
        event: ChannelEvent,
    ) -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION,
            channel_id,
            sequence,
            previous_entry_hash,
            idempotency_key,
            actor,
            occurred_at_ms,
            event,
        }
    }

    /// Stable, versioned, domain-separated bytes committed by [`Self::entry_hash`].
    ///
    /// The format is deliberately independent of serde and must only change
    /// under a new [`HASH_FORMAT_VERSION`].
    pub fn canonical_bytes(&self) -> Vec<u8> {
        encode_entry(self)
    }

    /// Computes the canonical SHA-256 ledger-entry hash.
    pub fn entry_hash(&self) -> EntryHash {
        EntryHash::from_bytes(Sha256::digest(self.canonical_bytes()).into())
    }

    /// Returns the invoice id created by this entry, if this is Invoice.
    pub fn created_invoice_id(&self) -> Option<&InvoiceId> {
        self.event.created_invoice_id()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ActorRole, Artifact, BitcoinTxid, Committee, Digest, ImplementationId, OpenEvent, ParticipantId,
        VerificationEvidence, VerificationKind,
    };

    fn fixture() -> LedgerEntry {
        let holder = ParticipantId::new("holder:alice").unwrap();
        let verifier = ParticipantId::new("verifier:node-1").unwrap();
        let implementation = ImplementationId::new("thunderbolt-node/1.0.0").unwrap();
        let evidence = [
            VerificationKind::FundingTransaction,
            VerificationKind::InitialState,
            VerificationKind::CommitteeQuorum,
        ]
        .into_iter()
        .enumerate()
        .map(|(index, kind)| {
            VerificationEvidence::verified(
                kind,
                verifier.clone(),
                implementation.clone(),
                Digest::from_bytes([(index + 1) as u8; 32]),
                1_700_000_000_000,
            )
        })
        .collect();

        LedgerEntry::new(
            ChannelId::new(BitcoinTxid::from_bytes([0x11; 32]), 7),
            0,
            EntryHash::ZERO,
            IdempotencyKey::new("open-fixture-1").unwrap(),
            Actor::new(holder.clone(), ActorRole::Holder),
            1_700_000_000_000,
            ChannelEvent::Open(OpenEvent {
                initial_holder: holder,
                committee: Committee::new(ParticipantId::new("committee:main").unwrap(), 3, 2).unwrap(),
                capacity_sat: 50_000,
                lock_key: Artifact::new([0x21, 0x22]).unwrap(),
                initial_holder_anchor: Artifact::new([0x31, 0x32]).unwrap(),
                initial_holder_ciphertext: Artifact::new([0x41, 0x42]).unwrap(),
                verification: evidence,
            }),
        )
    }

    #[test]
    fn canonical_hash_matches_version_one_golden_vector() {
        assert_eq!(
            fixture().entry_hash().to_string(),
            "4a89b2744b828aeaef0df288e247dc0341bd04b629445cb8be8517c3616dd60b"
        );
    }

    #[test]
    fn hash_is_independent_of_json_formatting() {
        let entry = fixture();
        let compact = serde_json::to_string(&entry).unwrap();
        let pretty = serde_json::to_string_pretty(&entry).unwrap();
        assert_ne!(compact.as_bytes(), pretty.as_bytes());

        let from_compact: LedgerEntry = serde_json::from_str(&compact).unwrap();
        let from_pretty: LedgerEntry = serde_json::from_str(&pretty).unwrap();
        assert_eq!(from_compact.entry_hash(), entry.entry_hash());
        assert_eq!(from_pretty.entry_hash(), entry.entry_hash());
    }

    #[test]
    fn hash_commits_top_level_fields_payload_and_evidence_order() {
        let original = fixture();
        let expected = original.entry_hash();
        let mut mutations = Vec::new();

        let mut entry = original.clone();
        entry.protocol_version = 2;
        mutations.push(entry);

        let mut entry = original.clone();
        entry.channel_id = ChannelId::new(BitcoinTxid::from_bytes([0x12; 32]), 7);
        mutations.push(entry);

        let mut entry = original.clone();
        entry.sequence = 1;
        mutations.push(entry);

        let mut entry = original.clone();
        entry.previous_entry_hash = EntryHash::from_bytes([0x01; 32]);
        mutations.push(entry);

        let mut entry = original.clone();
        entry.idempotency_key = IdempotencyKey::new("open-fixture-2").unwrap();
        mutations.push(entry);

        let mut entry = original.clone();
        entry.actor.participant_id = ParticipantId::new("holder:bob").unwrap();
        mutations.push(entry);

        let mut entry = original.clone();
        entry.occurred_at_ms += 1;
        mutations.push(entry);

        let mut entry = original.clone();
        let ChannelEvent::Open(event) = &mut entry.event else {
            unreachable!()
        };
        event.lock_key = Artifact::new([0x21, 0x23]).unwrap();
        mutations.push(entry);

        let mut entry = original;
        let ChannelEvent::Open(event) = &mut entry.event else {
            unreachable!()
        };
        event.verification.swap(0, 1);
        mutations.push(entry);

        for mutation in mutations {
            assert_ne!(mutation.entry_hash(), expected);
        }
    }

    #[test]
    fn serde_rejects_unknown_entry_fields() {
        let mut value = serde_json::to_value(fixture()).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .insert("unrecognized".to_owned(), serde_json::Value::Bool(true));
        assert!(serde_json::from_value::<LedgerEntry>(value).is_err());
    }
}
