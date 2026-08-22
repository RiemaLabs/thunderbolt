use std::{collections::BTreeMap, error::Error};

use bitcoin::Network;
use proptest::prelude::*;
use secp::Scalar;
use thunderbolt_ledger::{
    ActorKeyAlgorithmV2, ActorPublicKeyV2, EntryHashV2, LedgerChainIdV2, ParticipantIdV2, EVENT_BYTES_MAX,
};
use thunderbolt_protocol::{
    v2::{ChannelEventV2, ChannelPhaseV2, ChannelSnapshotV2, FinalizeEventV2},
    Artifact,
};
use thunderbolt_wire::{
    AnchorParameterSuiteIdV2, BitcoinGenesisHashV2, ChannelBindingV2, CommitteeDescriptorDigestV2, FundingOutpointV2,
    InvoiceId, ProtocolSuiteIdV2,
};

use crate::proof::prove_context_with_nonce_bytes;
use crate::*;

fn scalar(value: u64) -> Result<Scalar> {
    let mut bytes = [0_u8; 32];
    bytes[24..].copy_from_slice(&value.max(1).to_be_bytes());
    Scalar::from_slice(&bytes).map_err(|_| OwnershipError::InvalidWitness)
}

fn scalar_bytes(value: u64) -> [u8; 32] {
    let mut bytes = [0_u8; 32];
    bytes[24..].copy_from_slice(&value.max(1).to_be_bytes());
    bytes
}

fn holder_key(value: u64) -> Result<(ActorPublicKeyV2, ParticipantIdV2)> {
    let point = scalar(value)?.base_point_mul().serialize();
    let key =
        ActorPublicKeyV2::from_bytes(&point[1..]).map_err(|_| OwnershipError::InvalidContext("test Holder key"))?;
    let participant = key
        .participant_id(ActorKeyAlgorithmV2::Bip340V1)
        .map_err(|_| OwnershipError::InvalidContext("test participant"))?;
    Ok((key, participant))
}

fn anchor_suite() -> Result<AnchorParameterSuiteIdV2> {
    AnchorParameterSuiteIdV2::from_bytes([0x33; 32]).map_err(|_| OwnershipError::InvalidContext("test anchor suite"))
}

fn channel(anchor_suite: AnchorParameterSuiteIdV2) -> Result<ChannelBindingV2> {
    ChannelBindingV2::new(
        ProtocolSuiteIdV2::from_bytes([0x11; 32]).map_err(|_| OwnershipError::InvalidContext("test protocol suite"))?,
        Network::Regtest,
        BitcoinGenesisHashV2::for_network(Network::Regtest)
            .map_err(|_| OwnershipError::InvalidContext("test genesis"))?,
        b"ownership-tests",
        FundingOutpointV2::new([0x44; 32], 7).map_err(|_| OwnershipError::InvalidContext("test outpoint"))?,
        9,
        CommitteeDescriptorDigestV2::from_bytes([0x22; 32])
            .map_err(|_| OwnershipError::InvalidContext("test committee"))?,
        anchor_suite,
    )
    .map_err(|_| OwnershipError::InvalidContext("test channel"))
}

fn snapshot(secret: Scalar, step: u64) -> Result<(ChannelSnapshotV2, ActorPublicKeyV2)> {
    let suite = anchor_suite()?;
    let binding = channel(suite)?;
    let anchor_base = scalar(13)?.base_point_mul();
    let (holder_key, current_holder) = holder_key(19)?;
    let last_consumed_invoice_id = if step == 0 {
        None
    } else {
        Some(
            InvoiceId::from_bytes("test_invoice_id", b"consumed-invoice")
                .map_err(|_| OwnershipError::InvalidContext("test invoice"))?,
        )
    };
    let mut head = [0x55; 32];
    head[24..].copy_from_slice(&step.to_be_bytes());
    Ok((
        ChannelSnapshotV2 {
            protocol_version: thunderbolt_protocol::v2::PROTOCOL_VERSION_V2,
            ledger_chain_id: LedgerChainIdV2::new("ownership-regtest-1")
                .map_err(|_| OwnershipError::InvalidContext("test chain"))?,
            binding,
            phase: ChannelPhaseV2::Active,
            capacity_sat: 100_000,
            committee_member_count: 3,
            committee_threshold: 2,
            lock_key: Artifact::new(scalar(23)?.base_point_mul().serialize())
                .map_err(|_| OwnershipError::InvalidContext("test lock key"))?,
            current_holder,
            current_holder_anchor: Artifact::new((anchor_base * secret).serialize())
                .map_err(|_| OwnershipError::InvalidContext("test anchor"))?,
            current_holder_ciphertext: Artifact::new([0x99])
                .map_err(|_| OwnershipError::InvalidContext("test ciphertext"))?,
            transfers_completed: step,
            pending_invoices: BTreeMap::new(),
            last_consumed_invoice_id,
            last_sequence: step,
            head_entry_hash: EntryHashV2::from_bytes(head).map_err(|_| OwnershipError::InvalidContext("test head"))?,
            opened_at_ms: 1_000,
            last_block_time_ms: 1_000,
            finalized_at_ms: None,
        },
        holder_key,
    ))
}

fn trusted_context(secret: Scalar, step: u64, closing: Vec<u8>) -> Result<FinalizeSigningContext> {
    let (snapshot, holder_key) = snapshot(secret, step)?;
    let registry = AnchorSuiteRegistryV2::new(vec![AnchorSuiteParametersV2::new(
        anchor_suite()?,
        scalar(13)?.base_point_mul(),
    )])?;
    FinalizeSigningContext::from_snapshot(&snapshot, &registry, holder_key, closing)
}

fn prop_result<T>(result: Result<T>) -> std::result::Result<T, TestCaseError> {
    result.map_err(|error| TestCaseError::fail(error.to_string()))
}

#[test]
fn step_zero_and_os_random_proofs_verify_without_exposing_witness() -> std::result::Result<(), Box<dyn Error>> {
    let witness = OwnershipWitness::from_bytes(scalar_bytes(5))?;
    let context = trusted_context(scalar(5)?, 0, vec![0x51; 120])?;
    let first = prove_ownership(&context, &witness)?;
    let second = prove_ownership(&context, &witness)?;
    assert_ne!(first, second);
    let verified = verify_ownership(&context, &first)?;
    assert_eq!(verified.step(), 0);
    assert_eq!(verified.channel_context_id(), context.channel_context_id());
    assert_eq!(verified.snapshot_state_hash(), context.snapshot_state_hash());
    assert_eq!(verified.anchor_base(), context.anchor_base());
    assert_eq!(verified.current_anchor(), context.current_anchor());
    assert_eq!(verified.closing_digest(), context.closing_digest());
    Ok(())
}

#[test]
fn wrong_witness_and_oversized_transaction_fail_closed() -> std::result::Result<(), Box<dyn Error>> {
    let context = trusted_context(scalar(5)?, 1, vec![1])?;
    let wrong = OwnershipWitness::from_bytes(scalar_bytes(6))?;
    assert_eq!(prove_ownership(&context, &wrong), Err(OwnershipError::WitnessMismatch));
    assert_eq!(
        trusted_context(scalar(5)?, 1, vec![0; MAX_CLOSING_TRANSACTION_BYTES + 1]),
        Err(OwnershipError::ClosingTransactionTooLarge)
    );
    Ok(())
}

#[test]
fn maximum_sized_transaction_round_trips() -> std::result::Result<(), Box<dyn Error>> {
    let context = trusted_context(scalar(5)?, u64::MAX, vec![0x51; MAX_CLOSING_TRANSACTION_BYTES])?;
    let witness = OwnershipWitness::from_bytes(scalar_bytes(5))?;
    let envelope = prove_context_with_nonce_bytes(context.data.clone(), &witness, scalar_bytes(7))?;
    let encoded = envelope.to_bytes()?;
    assert!(encoded.len() < 2_048);
    let decoded = OwnershipEnvelopeV2::from_bytes(&encoded)?;
    verify_ownership(&context, &decoded)?;
    assert_eq!(context.closing_transaction().len(), MAX_CLOSING_TRANSACTION_BYTES);
    assert_eq!(context.step(), u64::MAX);
    Ok(())
}

#[test]
fn maximum_transaction_and_proof_fit_exact_protocol_event_cap() -> std::result::Result<(), Box<dyn Error>> {
    let closing = vec![0x51; MAX_CLOSING_TRANSACTION_BYTES];
    let context = trusted_context(scalar(5)?, 0, closing.clone())?;
    let witness = OwnershipWitness::from_bytes(scalar_bytes(5))?;
    let envelope = prove_context_with_nonce_bytes(context.data.clone(), &witness, scalar_bytes(7))?;
    let ownership_proof = Artifact::new(envelope.to_bytes()?)?;
    let mut event = ChannelEventV2::Finalize(FinalizeEventV2 {
        closing_txid: [0x42; 32],
        closing_transaction: Artifact::new(closing)?,
        ownership_proof,
        committee_attestation: Artifact::new([0x01])?,
    });
    let baseline = event.canonical_bytes()?.len();
    assert!(baseline < EVENT_BYTES_MAX);
    let remaining = EVENT_BYTES_MAX - baseline;
    let ChannelEventV2::Finalize(finalize) = &mut event else {
        return Err(OwnershipError::InvalidContext("test Finalize event").into());
    };
    finalize.committee_attestation = Artifact::new(vec![0x01; 1 + remaining])?;
    assert_eq!(event.canonical_bytes()?.len(), EVENT_BYTES_MAX);
    Ok(())
}

#[test]
fn fixed_codec_vector() -> std::result::Result<(), Box<dyn Error>> {
    let context = trusted_context(scalar(5)?, 0, vec![0x01, 0x02, 0x03])?;
    let witness = OwnershipWitness::from_bytes(scalar_bytes(5))?;
    let envelope = prove_context_with_nonce_bytes(context.data.clone(), &witness, scalar_bytes(7))?;
    assert_eq!(
        hex::encode(envelope.to_bytes()?),
        "54424f574e5630320002000001e000136f776e6572736869702d726567746573742d3100021111111111111111111111111111111111111111111111111111111111111111040f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206000f6f776e6572736869702d7465737473444444444444444444444444444444444444444444444444444444444444444400000007000000000000000922222222222222222222222222222222222222222222222222222222222222223333333333333333333333333333333333333333333333333333333333333333cf77a76ef3de0f706e6885e502d5b0e9827471bf0b2716f3b6037f0d964a72d73fc67f642212a3f4ca04f72a833665bfbc5ebfe642d434d2111e7520bc4e4c7b0000000000000000032fa2104d6b38d11b0230010559879124e42ab8dfeff5ff29dc9cdadd4ecacc3f03f28773c2d975288bc7d1d205c3748651b075fbc6610e58cddeeddf8f19405aa803186b483d056a033826ae73d88f732985c4ccb1f32ba35f4b4cc47fdcf04aa6eb60d0b13e238cdaf11851d2eeb7c99dfb8545084bd1f31a96333be07ccf5df1b62b4ea0a797a443d293ef5cff444f4979f06acfebd7e86d277475656138385b6c64c6cc1e01190c5899913fcf1571e44e8691386e13bd8bb0eb2044960eaf87e40002031624d84780732860ce1c78fcbfefe08b2b29823db913f6493975ba0ff484761099cec536918e1217b74ad2ec842b629b8692217223c14a16b7ab81c3f1ed2ad4"
    );
    Ok(())
}

#[test]
fn self_chosen_base_cannot_mint_trusted_ownership() -> std::result::Result<(), Box<dyn Error>> {
    let trusted = trusted_context(scalar(5)?, 0, vec![1, 2, 3])?;
    let mut attacker_context = trusted.data.clone();
    attacker_context.anchor_base = attacker_context.current_anchor;
    let attacker_witness = OwnershipWitness::from_bytes(scalar_bytes(1))?;
    let envelope = prove_context_with_nonce_bytes(attacker_context, &attacker_witness, scalar_bytes(7))?;
    assert_eq!(
        verify_ownership(&trusted, &envelope),
        Err(OwnershipError::ContextMismatch)
    );
    Ok(())
}

#[test]
fn cross_snapshot_and_registry_substitution_fail_closed() -> std::result::Result<(), Box<dyn Error>> {
    let witness = OwnershipWitness::from_bytes(scalar_bytes(5))?;
    let original = trusted_context(scalar(5)?, 0, vec![1, 2, 3])?;
    let envelope = prove_context_with_nonce_bytes(original.data.clone(), &witness, scalar_bytes(7))?;

    let (mut changed_snapshot, holder_key) = snapshot(scalar(5)?, 0)?;
    changed_snapshot.head_entry_hash = EntryHashV2::from_bytes([0x77; 32])?;
    let real_registry = AnchorSuiteRegistryV2::new(vec![AnchorSuiteParametersV2::new(
        anchor_suite()?,
        scalar(13)?.base_point_mul(),
    )])?;
    let changed_state =
        FinalizeSigningContext::from_snapshot(&changed_snapshot, &real_registry, holder_key.clone(), vec![1, 2, 3])?;
    assert_eq!(
        verify_ownership(&changed_state, &envelope),
        Err(OwnershipError::ContextMismatch)
    );

    let wrong_registry = AnchorSuiteRegistryV2::new(vec![AnchorSuiteParametersV2::new(
        anchor_suite()?,
        scalar(17)?.base_point_mul(),
    )])?;
    let wrong_base =
        FinalizeSigningContext::from_snapshot(&changed_snapshot, &wrong_registry, holder_key, vec![1, 2, 3])?;
    assert_eq!(
        verify_ownership(&wrong_base, &envelope),
        Err(OwnershipError::ContextMismatch)
    );
    let wrong_close = trusted_context(scalar(5)?, 0, vec![1, 2, 4])?;
    assert_eq!(
        verify_ownership(&wrong_close, &envelope),
        Err(OwnershipError::ContextMismatch)
    );
    Ok(())
}

#[test]
fn registry_and_holder_binding_reject_configuration_drift() -> std::result::Result<(), Box<dyn Error>> {
    let suite = anchor_suite()?;
    assert_eq!(
        AnchorSuiteRegistryV2::new(Vec::new()),
        Err(OwnershipError::EmptyAnchorSuiteRegistry)
    );
    assert_eq!(
        AnchorSuiteRegistryV2::new(vec![
            AnchorSuiteParametersV2::new(suite.clone(), scalar(13)?.base_point_mul()),
            AnchorSuiteParametersV2::new(suite, scalar(17)?.base_point_mul()),
        ]),
        Err(OwnershipError::DuplicateAnchorSuite)
    );
    let (snapshot, _) = snapshot(scalar(5)?, 0)?;
    let (wrong_key, _) = holder_key(29)?;
    let registry = AnchorSuiteRegistryV2::new(vec![AnchorSuiteParametersV2::new(
        anchor_suite()?,
        scalar(13)?.base_point_mul(),
    )])?;
    assert!(FinalizeSigningContext::from_snapshot(&snapshot, &registry, wrong_key, vec![1]).is_err());
    Ok(())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(128))]

    #[test]
    fn proof_and_codec_round_trip_for_relation(
        witness_value in 1_u64..=u64::MAX,
        nonce_value in 1_u64..=u64::MAX,
        step in any::<u64>(),
        closing in prop::collection::vec(any::<u8>(), 1..129),
    ) {
        let witness = prop_result(OwnershipWitness::from_bytes(scalar_bytes(witness_value)))?;
        let context = prop_result(trusted_context(prop_result(scalar(witness_value))?, step, closing))?;
        let envelope = prop_result(prove_context_with_nonce_bytes(
            context.data.clone(),
            &witness,
            scalar_bytes(nonce_value),
        ))?;
        let encoded = prop_result(envelope.to_bytes())?;
        let decoded = prop_result(OwnershipEnvelopeV2::from_bytes(&encoded))?;
        prop_assert_eq!(&decoded, &envelope);
        prop_assert!(verify_ownership(&context, &decoded).is_ok());
        prop_assert_eq!(context.step(), step);
    }

    #[test]
    fn every_operational_binding_and_proof_component_is_bound(
        witness_value in 1_u64..=u64::MAX,
        nonce_value in 1_u64..=u64::MAX,
        selector in 0_u8..11,
    ) {
        let witness = prop_result(OwnershipWitness::from_bytes(scalar_bytes(witness_value)))?;
        let context = prop_result(trusted_context(prop_result(scalar(witness_value))?, 0, vec![1,2,3]))?;
        let envelope = prop_result(prove_context_with_nonce_bytes(
            context.data.clone(),
            &witness,
            scalar_bytes(nonce_value),
        ))?;
        let mut changed = envelope.clone();
        match selector {
            0 => changed.statement.step = 1,
            1 => changed.statement.fixed_lock_key = prop_result(scalar(29))?.base_point_mul(),
            2 => changed.statement.anchor_base = prop_result(scalar(31))?.base_point_mul(),
            3 => changed.statement.current_anchor = prop_result(scalar(37))?.base_point_mul(),
            4 => changed.statement.holder_participant = prop_result(ParticipantIdV2::from_bytes([0x88; 32]).map_err(|_| OwnershipError::InvalidContext("test participant")))?,
            5 => changed.statement.channel_context_id[0] ^= 1,
            6 => changed.proof.commitment = prop_result(scalar(41))?.base_point_mul(),
            7 => changed.proof.response[31] ^= 1,
            8 => changed.statement.channel.committee_epoch += 1,
            9 => changed.statement.closing_digest.0[0] ^= 1,
            _ => changed.statement.snapshot_state_hash[0] ^= 1,
        }
        prop_assert!(verify_ownership(&context, &changed).is_err());
    }

    #[test]
    fn arbitrary_codec_input_never_panics(bytes in prop::collection::vec(any::<u8>(), 0..2048)) {
        let _ = OwnershipEnvelopeV2::from_bytes(&bytes);
    }

    #[test]
    fn any_single_byte_tamper_fails_decode_or_trusted_verify(
        witness_value in 1_u64..=u64::MAX,
        nonce_value in 1_u64..=u64::MAX,
        index in any::<usize>(),
    ) {
        let witness = prop_result(OwnershipWitness::from_bytes(scalar_bytes(witness_value)))?;
        let context = prop_result(trusted_context(prop_result(scalar(witness_value))?, 7, vec![9,8,7]))?;
        let envelope = prop_result(prove_context_with_nonce_bytes(
            context.data.clone(),
            &witness,
            scalar_bytes(nonce_value),
        ))?;
        let mut encoded = prop_result(envelope.to_bytes())?;
        let position = index % encoded.len();
        encoded[position] ^= 1;
        if let Ok(decoded) = OwnershipEnvelopeV2::from_bytes(&encoded) {
            prop_assert!(verify_ownership(&context, &decoded).is_err());
        }
    }
}
