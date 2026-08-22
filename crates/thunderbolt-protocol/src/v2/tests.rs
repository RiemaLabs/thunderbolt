use super::*;
use crate::Artifact;
use bitcoin::Network;
use proptest::prelude::*;
use secp256k1::{Keypair, Secp256k1, SecretKey};
use thunderbolt_ledger::{
    ActorKeyAlgorithmV2, ActorPublicKeyV2, ActorRoleV2, ActorSignatureV2, AppHashV2, CanonicalEventV2,
    ClientRequestNonceV2, EntryHashV2, LedgerChainIdV2, PendingBlockV2, ProposalBodyV2, SignedProposalV2,
    EVENT_BYTES_MAX,
};
use thunderbolt_wire::{
    AnchorParameterSuiteIdV2, BitcoinGenesisHashV2, ChannelBindingV2, CommitteeDescriptorDigestV2, FundingOutpointV2,
    HexBytes, ProtocolSuiteIdV2,
};

#[derive(Debug)]
struct AcceptAll;

const TEST_CHAIN_ID: &str = "thunderbolt-regtest-1";

#[derive(Debug)]
struct TestHistory {
    history: HistoryContextV2,
    block_time_ms: u64,
}

fn test_history(block_time_ms: u64) -> TestHistory {
    TestHistory {
        history: HistoryContextV2::fresh(),
        block_time_ms,
    }
}

fn test_existing_history(
    existing_request_entry_hash: Option<EntryHashV2>,
    invoice_id_already_used: bool,
    block_time_ms: u64,
) -> TestHistory {
    TestHistory {
        history: HistoryContextV2::new(existing_request_entry_hash, invoice_id_already_used),
        block_time_ms,
    }
}

fn test_reducer() -> V2Reducer {
    V2Reducer::new(
        LedgerChainIdV2::new(TEST_CHAIN_ID).expect("test chain id"),
        ProtocolLimitsV2::default(),
    )
    .expect("test reducer")
}

fn test_reducer_with_limits(limits: ProtocolLimitsV2) -> V2Reducer {
    V2Reducer::new(LedgerChainIdV2::new(TEST_CHAIN_ID).expect("test chain id"), limits).expect("test reducer")
}

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

fn artifact(byte: u8) -> Artifact {
    Artifact::new([byte]).expect("bounded public test artifact")
}

fn invoice_id(index: u32) -> InvoiceIdV2 {
    HexBytes::from_bytes("test invoice id", index.to_be_bytes()).expect("bounded test invoice id")
}

fn keypair(index: u64) -> Keypair {
    let mut secret = [0_u8; 32];
    secret[24..].copy_from_slice(&index.max(1).to_be_bytes());
    let secret = SecretKey::from_byte_array(secret).expect("nonzero bounded test secret");
    Keypair::from_secret_key(&Secp256k1::signing_only(), &secret)
}

fn actor_public_key(keypair: &Keypair) -> ActorPublicKeyV2 {
    let (public_key, _) = keypair.x_only_public_key();
    ActorPublicKeyV2::from_bytes(public_key.serialize()).expect("valid test actor key")
}

fn binding() -> ChannelBindingV2 {
    ChannelBindingV2::new(
        ProtocolSuiteIdV2::from_bytes([0x11; 32]).expect("protocol suite"),
        Network::Regtest,
        BitcoinGenesisHashV2::for_network(Network::Regtest).expect("regtest genesis"),
        b"protocol-v2-tests",
        FundingOutpointV2::new([0x44; 32], 7).expect("funding outpoint"),
        9,
        CommitteeDescriptorDigestV2::from_bytes([0x22; 32]).expect("committee descriptor"),
        AnchorParameterSuiteIdV2::from_bytes([0x33; 32]).expect("anchor suite"),
    )
    .expect("stable test binding")
}

fn sign(body: ProposalBodyV2, keypair: &Keypair) -> SignedProposalV2 {
    let digest = body.proposal_digest().expect("proposal digest");
    let signature = Secp256k1::signing_only().sign_schnorr_no_aux_rand(digest.as_bytes(), keypair);
    SignedProposalV2::new(
        body,
        ActorSignatureV2::from_bytes(signature.to_byte_array()).expect("signature bytes"),
    )
    .expect("valid signed proposal")
}

#[allow(clippy::too_many_arguments)]
fn proposal(
    event: &ChannelEventV2,
    sequence: u64,
    previous: EntryHashV2,
    actor_index: u64,
    role: ActorRoleV2,
    nonce_byte: u8,
) -> SignedProposalV2 {
    let keypair = keypair(actor_index);
    let body = ProposalBodyV2::new(
        LedgerChainIdV2::new(TEST_CHAIN_ID).expect("chain id"),
        binding(),
        sequence,
        previous,
        ClientRequestNonceV2::from_bytes([nonce_byte.max(1); 16]).expect("request nonce"),
        ActorKeyAlgorithmV2::Bip340V1,
        actor_public_key(&keypair),
        role,
        event.kind(),
        CanonicalEventV2::from_bytes(event.canonical_bytes().expect("canonical event"))
            .expect("bounded canonical event"),
    )
    .expect("valid proposal body");
    sign(body, &keypair)
}

fn open_event() -> ChannelEventV2 {
    ChannelEventV2::Open(OpenEventV2 {
        committee_member_count: 5,
        committee_threshold: 3,
        capacity_sat: 1_000_000,
        lock_key: artifact(1),
        initial_holder_anchor: artifact(2),
        initial_holder_ciphertext: artifact(3),
        open_proof: artifact(4),
    })
}

fn invoice_event(index: u32, holder_step: u64, expires_at_ms: Option<u64>) -> ChannelEventV2 {
    ChannelEventV2::Invoice(InvoiceEventV2 {
        invoice_id: invoice_id(index),
        holder_step,
        recipient_encryption_key: artifact(5),
        public_delta: artifact(6),
        recipient_ciphertext: artifact(7),
        committee_package: artifact(8),
        invoice_proof: artifact(9),
        expires_at_ms: expires_at_ms.unwrap_or(10_000_000),
    })
}

fn transfer_event(snapshot: &ChannelSnapshotV2, index: u32) -> ChannelEventV2 {
    let committed_entry_hash = snapshot
        .pending_invoices
        .get(&invoice_id(index))
        .expect("test Invoice is pending")
        .committed_entry_hash
        .clone();
    ChannelEventV2::Transfer(TransferEventV2 {
        invoice_id: invoice_id(index),
        invoice_entry_hash: committed_entry_hash,
        next_holder_anchor: artifact(10),
        next_holder_ciphertext: artifact(11),
        transfer_proof: artifact(12),
    })
}

fn finalize_event(byte: u8) -> ChannelEventV2 {
    ChannelEventV2::Finalize(FinalizeEventV2 {
        closing_txid: [byte; 32],
        closing_transaction: artifact(15),
        ownership_proof: artifact(13),
        committee_attestation: artifact(14),
    })
}

fn apply(
    reducer: &V2Reducer,
    current: Option<&ChannelSnapshotV2>,
    signed: &SignedProposalV2,
    event: &ChannelEventV2,
    history: TestHistory,
) -> Result<ReductionV2, V2Error> {
    let mut block = PendingBlockV2::new(
        signed.body().ledger_chain_id().clone(),
        1,
        history.block_time_ms,
        AppHashV2::zero(),
    )
    .map_err(|_| V2Error::InvalidBlockTime)?;
    block
        .push(signed.clone())
        .map_err(|_| V2Error::ProposalAuthenticationFailed)?;
    let consensus = ConsensusEntryV2::from_pending_block(&block, 0, event)?;
    reducer.apply(current, &consensus, history.history, &AcceptAll)
}

fn opened() -> (V2Reducer, ChannelSnapshotV2) {
    let reducer = test_reducer();
    let event = open_event();
    let signed = proposal(&event, 0, EntryHashV2::zero(), 1, ActorRoleV2::Holder, 1);
    let snapshot = apply(&reducer, None, &signed, &event, test_history(1_000))
        .expect("Open applies")
        .snapshot;
    (reducer, snapshot)
}

fn add_invoice(
    reducer: &V2Reducer,
    snapshot: &ChannelSnapshotV2,
    index: u32,
    recipient_key: u64,
    time: u64,
    expires_at_ms: Option<u64>,
) -> (ChannelSnapshotV2, SignedProposalV2, ChannelEventV2) {
    let event = invoice_event(index, snapshot.transfers_completed, expires_at_ms);
    let signed = proposal(
        &event,
        snapshot.next_sequence().expect("next sequence"),
        snapshot.head_entry_hash.clone(),
        recipient_key,
        ActorRoleV2::Recipient,
        u8::try_from(index % 250 + 2).expect("bounded nonce"),
    );
    let next = apply(reducer, Some(snapshot), &signed, &event, test_history(time))
        .expect("Invoice applies")
        .snapshot;
    (next, signed, event)
}

#[test]
fn serialized_event_rejects_client_verification_evidence() {
    let mut value = serde_json::to_value(invoice_event(1, 0, None)).expect("serialize event");
    value["data"]["verification"] = serde_json::json!([{"outcome": "verified"}]);
    assert!(serde_json::from_value::<ChannelEventV2>(value).is_err());

    let mut value = serde_json::to_value(invoice_event(1, 0, None)).expect("serialize event");
    value["verification"] = serde_json::json!([{"outcome": "verified"}]);
    assert!(serde_json::from_value::<ChannelEventV2>(value).is_err());
}

#[test]
fn canonical_event_codec_round_trips_every_kind_and_rejects_trailing_bytes() {
    let mut events = vec![open_event(), invoice_event(1, 0, Some(2_000))];
    events.push(ChannelEventV2::Transfer(TransferEventV2 {
        invoice_id: invoice_id(1),
        invoice_entry_hash: EntryHashV2::from_bytes([0x77; 32]).expect("entry hash"),
        next_holder_anchor: artifact(10),
        next_holder_ciphertext: artifact(11),
        transfer_proof: artifact(12),
    }));
    events.push(finalize_event(0x88));

    for event in events {
        let bytes = event.canonical_bytes().expect("canonical bytes");
        assert_eq!(
            ChannelEventV2::from_canonical_bytes(&bytes).expect("canonical decode"),
            event
        );
        let mut trailing = bytes;
        trailing.push(0);
        assert_eq!(
            ChannelEventV2::from_canonical_bytes(trailing).expect_err("trailing byte rejected"),
            V2Error::InvalidCanonicalEvent
        );
    }
}

#[test]
fn authenticated_event_requires_exact_kind_and_bytes() {
    let event = open_event();
    let signed = proposal(&event, 0, EntryHashV2::zero(), 1, ActorRoleV2::Holder, 1);
    let other = finalize_event(1);
    assert_eq!(
        AuthenticatedEntryV2::from_signed(&signed, &other).expect_err("mismatch rejected"),
        V2Error::AuthenticatedEventMismatch
    );
}

#[test]
fn finalize_is_ordered_and_not_vetoed_by_pending_invoices() {
    let (reducer, snapshot) = opened();
    let (snapshot, _, _) = add_invoice(&reducer, &snapshot, 1, 2, 1_001, None);
    let (snapshot, _, _) = add_invoice(&reducer, &snapshot, 2, 3, 1_002, None);
    assert_eq!(snapshot.pending_invoices.len(), 2);

    let event = finalize_event(0x55);
    let signed = proposal(
        &event,
        snapshot.next_sequence().expect("next sequence"),
        snapshot.head_entry_hash.clone(),
        1,
        ActorRoleV2::Holder,
        50,
    );
    let finalized = apply(&reducer, Some(&snapshot), &signed, &event, test_history(1_003))
        .expect("Finalize is not blocked by unrelated invoices")
        .snapshot;
    assert_eq!(finalized.phase, ChannelPhaseV2::Finalized);
    assert!(finalized.pending_invoices.is_empty());
}

#[test]
fn lifetime_invoice_id_cannot_return_after_transfer_invalidation() {
    let (reducer, snapshot) = opened();
    let (snapshot, _, _) = add_invoice(&reducer, &snapshot, 7, 2, 1_001, None);
    let transfer = transfer_event(&snapshot, 7);
    let signed_transfer = proposal(
        &transfer,
        snapshot.next_sequence().expect("next sequence"),
        snapshot.head_entry_hash.clone(),
        1,
        ActorRoleV2::Holder,
        70,
    );
    let snapshot = apply(
        &reducer,
        Some(&snapshot),
        &signed_transfer,
        &transfer,
        test_history(1_002),
    )
    .expect("Transfer applies")
    .snapshot;

    let repeated = invoice_event(7, 1, None);
    let repeated_signed = proposal(
        &repeated,
        snapshot.next_sequence().expect("next sequence"),
        snapshot.head_entry_hash.clone(),
        3,
        ActorRoleV2::Recipient,
        71,
    );
    let error = apply(
        &reducer,
        Some(&snapshot),
        &repeated_signed,
        &repeated,
        test_existing_history(None, true, 1_003),
    )
    .expect_err("lifetime reuse rejected");
    assert_eq!(error, V2Error::InvoiceAlreadyUsed);
}

#[test]
fn transfer_rejects_tampered_committed_invoice_hash() {
    let (reducer, snapshot) = opened();
    let (snapshot, _, _) = add_invoice(&reducer, &snapshot, 9, 2, 1_001, None);
    let mut transfer = transfer_event(&snapshot, 9);
    let ChannelEventV2::Transfer(event) = &mut transfer else {
        unreachable!("fixture is Transfer")
    };
    event.invoice_entry_hash = EntryHashV2::from_bytes([0xaa; 32]).expect("test entry hash");
    let signed = proposal(
        &transfer,
        snapshot.next_sequence().expect("next sequence"),
        snapshot.head_entry_hash.clone(),
        1,
        ActorRoleV2::Holder,
        72,
    );
    assert_eq!(
        apply(&reducer, Some(&snapshot), &signed, &transfer, test_history(1_002),)
            .expect_err("mismatched committed Invoice hash rejected"),
        V2Error::InvoiceEntryHashMismatch
    );
}

#[test]
fn finalize_raw_transaction_is_covered_by_authenticated_event_bytes() {
    let (_, snapshot) = opened();
    let original = finalize_event(0x71);
    let signed = proposal(
        &original,
        snapshot.next_sequence().expect("next sequence"),
        snapshot.head_entry_hash,
        1,
        ActorRoleV2::Holder,
        73,
    );
    let mut tampered = original;
    let ChannelEventV2::Finalize(event) = &mut tampered else {
        unreachable!("fixture is Finalize")
    };
    event.closing_transaction = artifact(0xff);
    assert_eq!(
        AuthenticatedEntryV2::from_signed(&signed, &tampered).expect_err("raw transaction tamper rejected"),
        V2Error::AuthenticatedEventMismatch
    );
}

#[test]
fn zero_consensus_time_is_rejected() {
    let reducer = test_reducer();
    let event = open_event();
    let signed = proposal(&event, 0, EntryHashV2::zero(), 1, ActorRoleV2::Holder, 74);
    assert_eq!(
        apply(&reducer, None, &signed, &event, test_history(0)).expect_err("zero block time rejected"),
        V2Error::InvalidBlockTime
    );
}

#[test]
fn pending_invoice_set_obeys_configured_bound() {
    let reducer = V2Reducer::new(
        LedgerChainIdV2::new(TEST_CHAIN_ID).expect("chain id"),
        ProtocolLimitsV2::new(100, 2, DEFAULT_MAX_INVOICE_TTL_MS_V2).expect("limits"),
    )
    .expect("reducer");
    let event = open_event();
    let signed = proposal(&event, 0, EntryHashV2::zero(), 1, ActorRoleV2::Holder, 75);
    let mut snapshot = apply(&reducer, None, &signed, &event, test_history(1_000))
        .expect("Open applies")
        .snapshot;
    for index in 1..=2 {
        snapshot = add_invoice(
            &reducer,
            &snapshot,
            index,
            u64::from(index) + 1,
            1_000 + u64::from(index),
            None,
        )
        .0;
    }
    let third = invoice_event(3, 0, None);
    let signed = proposal(
        &third,
        snapshot.next_sequence().expect("next sequence"),
        snapshot.head_entry_hash.clone(),
        4,
        ActorRoleV2::Recipient,
        78,
    );
    assert_eq!(
        apply(&reducer, Some(&snapshot), &signed, &third, test_history(1_003),)
            .expect_err("third pending Invoice rejected"),
        V2Error::PendingInvoiceLimitReached { limit: 2 }
    );
}

#[test]
fn committee_topology_matches_active_wire_bound() {
    assert!(super::types::validate_committee_topology(MAX_COMMITTEE_MEMBERS_V2, 171).is_ok());
    assert_eq!(
        super::types::validate_committee_topology(MAX_COMMITTEE_MEMBERS_V2 + 1, 171).expect_err("257 members rejected"),
        V2Error::InvalidCommitteeTopology
    );
}

#[test]
fn reducer_rejects_another_ledger_chain() {
    let reducer = V2Reducer::new(
        LedgerChainIdV2::new("another-regtest-chain").expect("other chain"),
        ProtocolLimitsV2::default(),
    )
    .expect("other-chain reducer");
    let event = open_event();
    let signed = proposal(&event, 0, EntryHashV2::zero(), 1, ActorRoleV2::Holder, 79);
    assert_eq!(
        apply(&reducer, None, &signed, &event, test_history(1_000)).expect_err("wrong chain rejected"),
        V2Error::LedgerChainMismatch
    );
}

#[test]
fn executed_entry_issues_consensus_capability() {
    let reducer = test_reducer();
    let event = open_event();
    let signed = proposal(&event, 0, EntryHashV2::zero(), 1, ActorRoleV2::Holder, 84);
    let mut block = PendingBlockV2::new(
        LedgerChainIdV2::new(TEST_CHAIN_ID).expect("chain id"),
        1,
        1_000,
        AppHashV2::zero(),
    )
    .expect("pending block");
    block.push(signed).expect("proposal accepted");
    let executed = block.execute().expect("executed block");
    let consensus = ConsensusEntryV2::from_executed_entry(&executed.entries()[0], &event).expect("executed capability");
    let reduction = reducer
        .apply(None, &consensus, HistoryContextV2::fresh(), &AcceptAll)
        .expect("executed Open applies");
    assert_eq!(reduction.snapshot.opened_at_ms, 1_000);
    assert_eq!(consensus.block_height(), 1);
    assert_eq!(consensus.block_index(), 0);
}

#[test]
fn invoice_ttl_is_bounded_and_terminal_position_is_reserved() {
    assert!(ProtocolLimitsV2::new(1, 1, 100).is_err());
    let reducer = test_reducer_with_limits(ProtocolLimitsV2::new(3, 2, 100).expect("limits"));
    let event = open_event();
    let signed = proposal(&event, 0, EntryHashV2::zero(), 1, ActorRoleV2::Holder, 80);
    let snapshot = apply(&reducer, None, &signed, &event, test_history(1_000))
        .expect("Open applies")
        .snapshot;

    let too_long = invoice_event(1, 0, Some(1_101));
    let signed = proposal(
        &too_long,
        1,
        snapshot.head_entry_hash.clone(),
        2,
        ActorRoleV2::Recipient,
        81,
    );
    assert_eq!(
        apply(&reducer, Some(&snapshot), &signed, &too_long, test_history(1_000)).expect_err("TTL +1 rejected"),
        V2Error::InvoiceTtlTooLong {
            ttl_ms: 101,
            limit_ms: 100,
        }
    );

    let (snapshot, _, _) = add_invoice(&reducer, &snapshot, 1, 2, 1_001, Some(1_101));
    let blocked = invoice_event(2, 0, Some(1_102));
    let signed = proposal(
        &blocked,
        2,
        snapshot.head_entry_hash.clone(),
        3,
        ActorRoleV2::Recipient,
        82,
    );
    assert_eq!(
        apply(&reducer, Some(&snapshot), &signed, &blocked, test_history(1_002))
            .expect_err("nonterminal event cannot consume reserved slot"),
        V2Error::EntryLimitReached { limit: 3 }
    );

    let finalize = finalize_event(0x91);
    let signed = proposal(
        &finalize,
        2,
        snapshot.head_entry_hash.clone(),
        1,
        ActorRoleV2::Holder,
        83,
    );
    assert_eq!(
        apply(&reducer, Some(&snapshot), &signed, &finalize, test_history(1_002))
            .expect("Finalize uses reserved slot")
            .snapshot
            .phase,
        ChannelPhaseV2::Finalized
    );
}

#[test]
fn snapshot_validation_rejects_unreachable_pending_state() {
    let (reducer, snapshot) = opened();
    let (mut snapshot, _, _) = add_invoice(&reducer, &snapshot, 1, 2, 1_001, Some(1_100));
    snapshot.transfers_completed = 1;
    snapshot.last_consumed_invoice_id = Some(invoice_id(99));
    assert!(snapshot.validate().is_err());
    assert!(snapshot.state_hash().is_err());

    snapshot.transfers_completed = 0;
    snapshot.last_consumed_invoice_id = None;
    snapshot.last_block_time_ms = 1_100;
    assert!(snapshot.validate().is_err());
}

#[test]
fn canonical_event_size_is_checked_before_encoding() {
    let mut event = open_event();
    let baseline = event.canonical_bytes().expect("baseline event").len();
    let ChannelEventV2::Open(open) = &mut event else {
        unreachable!("fixture is Open")
    };
    let exact_proof_len = 1 + (EVENT_BYTES_MAX - baseline);
    open.open_proof = Artifact::new(vec![0x5a; exact_proof_len]).expect("exact-size proof");
    assert_eq!(
        event.canonical_bytes().expect("exact maximum event").len(),
        EVENT_BYTES_MAX
    );
    let ChannelEventV2::Open(open) = &mut event else {
        unreachable!("fixture is Open")
    };
    open.open_proof = Artifact::new(vec![0x5a; exact_proof_len + 1]).expect("maximum plus one proof");
    assert_eq!(
        event.canonical_bytes().expect_err("oversized event rejected"),
        V2Error::InvalidCanonicalEvent
    );
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(96))]

    #[test]
    fn canonical_invoice_codec_round_trips(
        invoice in prop::collection::vec(any::<u8>(), 1..33),
        artifact_bytes in prop::collection::vec(any::<u8>(), 1..65),
        step in any::<u64>(),
        expiry in 1_u64..u64::MAX,
    ) {
        let artifact = Artifact::new(artifact_bytes).expect("bounded generated artifact");
        let event = ChannelEventV2::Invoice(InvoiceEventV2 {
            invoice_id: HexBytes::from_bytes("generated Invoice id", invoice).expect("bounded Invoice id"),
            holder_step: step,
            recipient_encryption_key: artifact.clone(),
            public_delta: artifact.clone(),
            recipient_ciphertext: artifact.clone(),
            committee_package: artifact.clone(),
            invoice_proof: artifact,
            expires_at_ms: expiry,
        });
        let bytes = event.canonical_bytes().expect("canonical event");
        prop_assert_eq!(
            ChannelEventV2::from_canonical_bytes(bytes).expect("canonical decode"),
            event
        );
    }

    #[test]
    fn multiple_invoices_are_bounded_and_selected_transfer_wins(
        count in 2_u32..9,
        selector in 0_u32..100,
    ) {
        let (reducer, mut snapshot) = opened();
        let selected = selector % count;
        let mut selected_recipient = None;
        for index in 0..count {
            let recipient_key = u64::from(index) + 2;
            let (next, signed, _) = add_invoice(
                &reducer,
                &snapshot,
                index + 1,
                recipient_key,
                1_001 + u64::from(index),
                None,
            );
            if index == selected {
                selected_recipient = Some(signed.body().participant_id().expect("participant id"));
            }
            snapshot = next;
        }
        prop_assert_eq!(snapshot.pending_invoices.len(), count as usize);

        let selected_id = selected + 1;
        let event = transfer_event(&snapshot, selected_id);
        let signed = proposal(
            &event,
            snapshot.next_sequence().expect("next sequence"),
            snapshot.head_entry_hash.clone(),
            1,
            ActorRoleV2::Holder,
            100,
        );
        let next = apply(
            &reducer,
            Some(&snapshot),
            &signed,
            &event,
            test_history(2_000),
        ).expect("selected Transfer applies").snapshot;
        let expected_recipient = selected_recipient.expect("selected recipient");
        prop_assert_eq!(&next.current_holder, &expected_recipient);
        prop_assert_eq!(next.last_consumed_invoice_id.as_ref(), Some(&invoice_id(selected_id)));
        prop_assert!(next.pending_invoices.is_empty());
        prop_assert_eq!(next.transfers_completed, 1);
        prop_assert!(next.validate().is_ok());
    }

    #[test]
    fn exact_replay_is_idempotent_and_changed_body_conflicts(delta in 1_u8..=200) {
        let (reducer, snapshot) = opened();
        let event = invoice_event(1, 0, None);
        let signed = proposal(
            &event,
            1,
            snapshot.head_entry_hash.clone(),
            2,
            ActorRoleV2::Recipient,
            2,
        );
        let applied = apply(
            &reducer,
            Some(&snapshot),
            &signed,
            &event,
            test_history(1_001),
        ).expect("Invoice applies");
        let original_hash = signed.body().entry_hash().expect("entry hash");
        let replay = apply(
            &reducer,
            Some(&applied.snapshot),
            &signed,
            &event,
            test_existing_history(Some(original_hash.clone()), true, 9_999),
        ).expect("exact replay succeeds");
        prop_assert_eq!(replay.disposition, ApplyDispositionV2::Replay);
        prop_assert_eq!(&replay.snapshot, &applied.snapshot);

        let mut changed = invoice_event(1, 0, None);
        let ChannelEventV2::Invoice(changed_invoice) = &mut changed else {
            unreachable!("fixture is Invoice")
        };
        changed_invoice.invoice_proof = Artifact::new([delta, 0]).expect("distinct changed proof");
        let changed_signed = proposal(
            &changed,
            1,
            snapshot.head_entry_hash.clone(),
            2,
            ActorRoleV2::Recipient,
            2,
        );
        let conflict = apply(
            &reducer,
            Some(&applied.snapshot),
            &changed_signed,
            &changed,
            test_existing_history(Some(original_hash), true, 1_002),
        );
        prop_assert_eq!(conflict.expect_err("changed request conflicts"), V2Error::IdempotencyConflict);
    }

    #[test]
    fn expiry_uses_exclusive_trusted_block_time(
        ttl in 1_u64..500,
        attempt_delta in 0_u64..1_000,
    ) {
        let (reducer, snapshot) = opened();
        let expires_at = 2_000 + ttl;
        let (snapshot, _, _) = add_invoice(&reducer, &snapshot, 1, 2, 2_000, Some(expires_at));
        let event = transfer_event(&snapshot, 1);
        let signed = proposal(
            &event,
            snapshot.next_sequence().expect("next sequence"),
            snapshot.head_entry_hash.clone(),
            1,
            ActorRoleV2::Holder,
            3,
        );
        let attempt_at = 2_000 + attempt_delta;
        let result = apply(
            &reducer,
            Some(&snapshot),
            &signed,
            &event,
            test_history(attempt_at),
        );
        if attempt_at < expires_at {
            prop_assert!(result.is_ok());
        } else {
            prop_assert_eq!(
                result.expect_err("expired Transfer rejected"),
                V2Error::InvoiceExpired { expires_at_ms: expires_at }
            );
        }
    }

    #[test]
    fn arbitrary_valid_chains_preserve_state_invariants(
        choices in prop::collection::vec(any::<u8>(), 1..14)
    ) {
        let (reducer, mut snapshot) = opened();
        let mut next_invoice = 1_u32;
        let mut time = 1_001_u64;
        let mut holder_key = 1_u64;
        for (cycle_index, choice) in choices.into_iter().enumerate() {
            let count = u32::from(choice % 3) + 1;
            let selected_offset = u32::from(choice) % count;
            let first_invoice = next_invoice;
            for _ in 0..count {
                let recipient_key = u64::from(next_invoice) + 10;
                let (next, _, _) = add_invoice(
                    &reducer,
                    &snapshot,
                    next_invoice,
                    recipient_key,
                    time,
                    None,
                );
                snapshot = next;
                next_invoice += 1;
                time += 1;
            }
            let selected_id = first_invoice + selected_offset;
            let selected_key = u64::from(selected_id) + 10;
            let event = transfer_event(&snapshot, selected_id);
            let signed = proposal(
                &event,
                snapshot.next_sequence().expect("next sequence"),
                snapshot.head_entry_hash.clone(),
                holder_key,
                ActorRoleV2::Holder,
                u8::try_from((selected_id % 250) + 1).expect("bounded nonce"),
            );
            snapshot = apply(
                &reducer,
                Some(&snapshot),
                &signed,
                &event,
                test_history(time),
            ).expect("generated Transfer applies").snapshot;
            holder_key = selected_key;
            let expected_transfers = u64::try_from(cycle_index + 1).expect("bounded property chain");
            time += 1;
            let expected_holder = actor_public_key(&keypair(holder_key))
                .participant_id(ActorKeyAlgorithmV2::Bip340V1)
                .expect("selected participant");
            prop_assert_eq!(&snapshot.current_holder, &expected_holder);
            prop_assert_eq!(snapshot.transfers_completed, expected_transfers);
            prop_assert!(snapshot.pending_invoices.is_empty());
            prop_assert!(snapshot.validate().is_ok());
            prop_assert!(snapshot.state_hash().is_ok());
        }
    }
}

#[test]
fn transfer_and_finalize_compete_at_one_total_order_position() {
    let (reducer, snapshot) = opened();
    let (snapshot, recipient_signed, _) = add_invoice(&reducer, &snapshot, 1, 2, 1_001, None);
    let recipient = recipient_signed.body().participant_id().expect("recipient id");

    let transfer = transfer_event(&snapshot, 1);
    let signed_transfer = proposal(
        &transfer,
        snapshot.next_sequence().expect("sequence"),
        snapshot.head_entry_hash.clone(),
        1,
        ActorRoleV2::Holder,
        80,
    );
    let finalize = finalize_event(0x66);
    let signed_finalize = proposal(
        &finalize,
        snapshot.next_sequence().expect("sequence"),
        snapshot.head_entry_hash.clone(),
        1,
        ActorRoleV2::Holder,
        81,
    );

    let finalized = apply(
        &reducer,
        Some(&snapshot),
        &signed_finalize,
        &finalize,
        test_history(1_002),
    )
    .expect("Finalize wins position")
    .snapshot;
    assert_eq!(
        apply(
            &reducer,
            Some(&finalized),
            &signed_transfer,
            &transfer,
            test_history(1_003),
        )
        .expect_err("Transfer after Finalize rejected"),
        V2Error::ChannelFinalized
    );

    let transferred = apply(
        &reducer,
        Some(&snapshot),
        &signed_transfer,
        &transfer,
        test_history(1_002),
    )
    .expect("Transfer wins position")
    .snapshot;
    assert_eq!(transferred.current_holder, recipient);
    let later_finalize = finalize_event(0x67);
    let later_signed = proposal(
        &later_finalize,
        transferred.next_sequence().expect("sequence"),
        transferred.head_entry_hash.clone(),
        2,
        ActorRoleV2::Holder,
        82,
    );
    let result = apply(
        &reducer,
        Some(&transferred),
        &later_signed,
        &later_finalize,
        test_history(1_003),
    )
    .expect("new Holder finalizes after winning Transfer");
    assert_eq!(result.snapshot.phase, ChannelPhaseV2::Finalized);
}

#[test]
fn event_and_state_hashes_have_golden_vectors() {
    let event = open_event();
    assert_eq!(
        event.event_digest().expect("event digest").to_hex(),
        "11330e4556cc6e1d6701396a2e7a310455c1e40cc7758818956d5d5049db2220"
    );
    let (_, snapshot) = opened();
    assert_eq!(
        snapshot.state_hash().expect("state hash").to_string(),
        "7a0ac5e07f0ad3ca2176816dfece5d1e1d903f43f70718471b71fa13616eaabd"
    );
}
