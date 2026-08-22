use bitcoin::hashes::Hash as _;
use bitcoin::{Network, OutPoint, Txid};
use proptest::prelude::*;
use thunderbolt_wire::{
    from_json_slice, to_json_vec, AnchorParameterSuiteIdV2, BindingContext, BitcoinGenesisHashV2, CanonicalDigest,
    ChannelBindingV2, CommitteeDescriptorDigestV2, DeploymentId, FundingOutpointV2, OperationBindingV2,
    ProtocolSuiteIdV2, ValidateWire, WireError, FUNDING_OUTPOINT_BYTES,
};

fn nonzero(mut bytes: [u8; 32]) -> [u8; 32] {
    bytes[0] |= 1;
    bytes
}

fn channel_fixture() -> ChannelBindingV2 {
    ChannelBindingV2::new(
        ProtocolSuiteIdV2::from_bytes([0x11; 32]).expect("suite id"),
        Network::Regtest,
        BitcoinGenesisHashV2::for_network(Network::Regtest).expect("regtest genesis hash"),
        b"local-deployment",
        FundingOutpointV2::new([0x44; 32], 0x5566_7788).expect("outpoint"),
        7,
        CommitteeDescriptorDigestV2::from_bytes([0x22; 32]).expect("committee descriptor"),
        AnchorParameterSuiteIdV2::from_bytes([0x33; 32]).expect("anchor suite"),
    )
    .expect("channel binding")
}

fn network_strategy() -> impl Strategy<Value = Network> {
    prop_oneof![
        Just(Network::Bitcoin),
        Just(Network::Testnet),
        Just(Network::Testnet4),
        Just(Network::Signet),
        Just(Network::Regtest),
    ]
}

fn channel_strategy() -> impl Strategy<Value = ChannelBindingV2> {
    (
        any::<[u8; 32]>(),
        network_strategy(),
        prop::collection::vec(any::<u8>(), 1..=64),
        any::<[u8; 32]>(),
        any::<u32>(),
        1_u64..=u64::MAX,
        any::<[u8; 32]>(),
        any::<[u8; 32]>(),
    )
        .prop_map(|(suite, network, deployment, txid, vout, epoch, committee, anchor)| {
            ChannelBindingV2::new(
                ProtocolSuiteIdV2::from_bytes(nonzero(suite)).expect("generated suite id"),
                network,
                BitcoinGenesisHashV2::for_network(network).expect("generated network genesis hash"),
                deployment,
                FundingOutpointV2::new(txid, vout).expect("generated outpoint"),
                epoch,
                CommitteeDescriptorDigestV2::from_bytes(nonzero(committee)).expect("generated committee descriptor"),
                AnchorParameterSuiteIdV2::from_bytes(nonzero(anchor)).expect("generated anchor suite"),
            )
            .expect("generated channel binding")
        })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(96))]

    #[test]
    fn operation_codec_round_trips_and_context_stays_stable(
        channel in channel_strategy(),
        invoice_id in prop::collection::vec(any::<u8>(), 1..=128),
        step in 1_u64..=u64::MAX,
    ) {
        let invoice = OperationBindingV2::invoice(channel.clone(), &invoice_id).expect("invoice binding");
        let transfer = OperationBindingV2::transfer(channel, &invoice_id, step).expect("transfer binding");

        let invoice_json = to_json_vec(&invoice).expect("invoice JSON");
        let transfer_json = to_json_vec(&transfer).expect("transfer JSON");
        let decoded_invoice: OperationBindingV2 = from_json_slice(&invoice_json).expect("invoice decode");
        let decoded_transfer: OperationBindingV2 = from_json_slice(&transfer_json).expect("transfer decode");

        prop_assert_eq!(&decoded_invoice, &invoice);
        prop_assert_eq!(&decoded_transfer, &transfer);
        prop_assert_eq!(invoice.channel().context_id()?, transfer.channel().context_id()?);

        let invoice_context = invoice.proof_context()?;
        let transfer_context = transfer.proof_context()?;
        prop_assert_eq!(invoice_context.ctx_id(), transfer_context.ctx_id());
        prop_assert_eq!(invoice_context.inv_id(), transfer_context.inv_id());
        prop_assert_eq!(invoice_context.step(), None);
        prop_assert_eq!(transfer_context.step(), Some(step));
        prop_assert_ne!(invoice.canonical_digest()?, transfer.canonical_digest()?);
    }

    #[test]
    fn formatting_does_not_change_operation_digest(
        channel in channel_strategy(),
        invoice_id in prop::collection::vec(any::<u8>(), 1..=128),
    ) {
        let operation = OperationBindingV2::invoice(channel, invoice_id).expect("invoice binding");
        let compact = to_json_vec(&operation).expect("compact JSON");
        let value: serde_json::Value = serde_json::from_slice(&compact).expect("JSON value");
        let pretty = serde_json::to_vec_pretty(&value).expect("pretty JSON");
        let decoded: OperationBindingV2 = from_json_slice(&pretty).expect("pretty decode");
        prop_assert_eq!(decoded.canonical_digest()?, operation.canonical_digest()?);
    }
}

#[test]
fn every_stable_field_is_authenticated() {
    let original = channel_fixture();
    let expected = original.context_id().expect("original context id");

    let mut wrong_version = original.clone();
    wrong_version.protocol_version = 1;
    assert!(matches!(
        wrong_version.context_id(),
        Err(WireError::UnsupportedVersion { expected: 2, actual: 1 })
    ));

    let mut changed = original.clone();
    changed.protocol_suite_id = ProtocolSuiteIdV2::from_bytes([0x12; 32]).expect("suite id");
    assert_ne!(changed.context_id().expect("suite context"), expected);

    let mut changed = original.clone();
    changed.network = Network::Signet;
    assert!(changed.context_id().is_err());

    let mut changed = original.clone();
    changed.bitcoin_genesis_hash = BitcoinGenesisHashV2::for_network(Network::Signet).expect("signet genesis hash");
    assert!(changed.context_id().is_err());

    let mut changed = original.clone();
    changed.deployment_id = DeploymentId::from_bytes("deployment_id", b"other-deployment").expect("deployment id");
    assert_ne!(changed.context_id().expect("deployment context"), expected);

    let mut changed = original.clone();
    changed.funding_outpoint = FundingOutpointV2::new([0x45; 32], 0x5566_7788).expect("outpoint");
    assert_ne!(changed.context_id().expect("txid context"), expected);

    let mut changed = original.clone();
    changed.funding_outpoint = FundingOutpointV2::new([0x44; 32], 0x5566_7789).expect("outpoint");
    assert_ne!(changed.context_id().expect("vout context"), expected);

    let mut changed = original.clone();
    changed.committee_epoch = 8;
    assert_ne!(changed.context_id().expect("epoch context"), expected);

    let mut changed = original.clone();
    changed.committee_descriptor_digest =
        CommitteeDescriptorDigestV2::from_bytes([0x23; 32]).expect("committee descriptor");
    assert_ne!(changed.context_id().expect("committee context"), expected);

    let mut changed = original;
    changed.anchor_parameter_suite_id = AnchorParameterSuiteIdV2::from_bytes([0x34; 32]).expect("anchor suite");
    assert_ne!(changed.context_id().expect("anchor context"), expected);
}

#[test]
fn operation_fields_do_not_change_the_stable_context() {
    let channel = channel_fixture();
    let invoice = OperationBindingV2::invoice(channel.clone(), b"invoice-a").expect("invoice binding");
    let other_invoice = OperationBindingV2::invoice(channel.clone(), b"invoice-b").expect("invoice binding");
    let transfer_one = OperationBindingV2::transfer(channel.clone(), b"invoice-a", 1).expect("transfer binding");
    let transfer_two = OperationBindingV2::transfer(channel, b"invoice-a", 2).expect("transfer binding");

    let stable = invoice.channel().context_id().expect("stable context");
    assert_eq!(other_invoice.channel().context_id().expect("stable context"), stable);
    assert_eq!(transfer_one.channel().context_id().expect("stable context"), stable);
    assert_eq!(transfer_two.channel().context_id().expect("stable context"), stable);

    assert_ne!(
        invoice.canonical_digest().expect("digest"),
        other_invoice.canonical_digest().expect("digest")
    );
    assert_ne!(
        transfer_one.canonical_digest().expect("digest"),
        transfer_two.canonical_digest().expect("digest")
    );
    assert!(invoice
        .matches_core(&other_invoice.proof_context().expect("other context"))
        .is_err());
    assert!(transfer_one
        .matches_core(&transfer_two.proof_context().expect("other context"))
        .is_err());
}

#[test]
fn invalid_version_epoch_ids_and_operation_shapes_are_rejected() {
    for all_zero in [
        ProtocolSuiteIdV2::from_bytes([0_u8; 32]).is_err(),
        BitcoinGenesisHashV2::from_bytes([0_u8; 32]).is_err(),
        CommitteeDescriptorDigestV2::from_bytes([0_u8; 32]).is_err(),
        AnchorParameterSuiteIdV2::from_bytes([0_u8; 32]).is_err(),
    ] {
        assert!(all_zero);
    }

    let channel = channel_fixture();
    let mut value = serde_json::to_value(&channel).expect("channel JSON");
    value["protocol_version"] = serde_json::json!(1);
    assert!(from_json_slice::<ChannelBindingV2>(&serde_json::to_vec(&value).expect("JSON bytes")).is_err());

    let mut value = serde_json::to_value(&channel).expect("channel JSON");
    value["committee_epoch"] = serde_json::json!(0);
    assert!(from_json_slice::<ChannelBindingV2>(&serde_json::to_vec(&value).expect("JSON bytes")).is_err());

    let invoice = OperationBindingV2::invoice(channel.clone(), b"invoice-a").expect("invoice binding");
    let mut value = serde_json::to_value(&invoice).expect("invoice JSON");
    value["step"] = serde_json::json!(1);
    assert!(from_json_slice::<OperationBindingV2>(&serde_json::to_vec(&value).expect("JSON bytes")).is_err());

    let transfer = OperationBindingV2::transfer(channel, b"invoice-a", 1).expect("transfer binding");
    let mut value = serde_json::to_value(&transfer).expect("transfer JSON");
    value.as_object_mut().expect("JSON object").remove("step");
    assert!(from_json_slice::<OperationBindingV2>(&serde_json::to_vec(&value).expect("JSON bytes")).is_err());
}

#[test]
fn transfer_step_zero_is_rejected_at_every_public_boundary() {
    let channel = channel_fixture();
    assert!(OperationBindingV2::transfer(channel.clone(), b"invoice-a", 0).is_err());

    let valid = OperationBindingV2::transfer(channel, b"invoice-a", 1).expect("transfer binding");
    let mut value = serde_json::to_value(&valid).expect("transfer JSON");
    value["step"] = serde_json::json!(0);
    let bytes = serde_json::to_vec(&value).expect("JSON bytes");
    assert!(serde_json::from_slice::<OperationBindingV2>(&bytes).is_err());
    assert!(from_json_slice::<OperationBindingV2>(&bytes).is_err());

    let mut mutated = valid;
    let OperationBindingV2::Transfer { step, .. } = &mut mutated else {
        panic!("fixture is a transfer");
    };
    *step = 0;
    assert!(mutated.validate_wire().is_err());
    assert!(mutated.proof_context().is_err());
    assert!(mutated.canonical_digest().is_err());
}

#[test]
fn funding_outpoint_has_one_exact_canonical_encoding() {
    let outpoint = FundingOutpointV2::new([0xab; 32], 0x0102_0304).expect("outpoint");
    let bytes = outpoint.canonical_bytes();
    assert_eq!(bytes.len(), FUNDING_OUTPOINT_BYTES);
    assert_eq!(&bytes[..32], &[0xab; 32]);
    assert_eq!(&bytes[32..], &[1, 2, 3, 4]);
    assert_eq!(
        FundingOutpointV2::from_canonical_bytes(bytes).expect("decode"),
        outpoint
    );
    assert!(FundingOutpointV2::from_canonical_bytes([0_u8; FUNDING_OUTPOINT_BYTES - 1]).is_err());
    assert!(FundingOutpointV2::from_canonical_bytes([0_u8; FUNDING_OUTPOINT_BYTES + 1]).is_err());
}

#[test]
fn rust_bitcoin_hash_and_outpoint_conversions_are_explicit_and_lossless() {
    for network in [
        Network::Bitcoin,
        Network::Testnet,
        Network::Testnet4,
        Network::Signet,
        Network::Regtest,
    ] {
        let hash = bitcoin::constants::genesis_block(network).block_hash();
        let wire = BitcoinGenesisHashV2::from_block_hash(hash).expect("genesis hash");
        assert_eq!(wire.to_hex(), hash.to_string());
        assert_eq!(
            wire,
            BitcoinGenesisHashV2::for_network(network).expect("network genesis hash")
        );
        assert_eq!(wire.to_block_hash(), hash);
    }

    let txid = Txid::from_byte_array([0x42; 32]);
    let outpoint = OutPoint::new(txid, 17);
    let wire = FundingOutpointV2::from_outpoint(outpoint).expect("non-null outpoint");
    assert_eq!(wire.to_outpoint(), outpoint);

    let display = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    let txid: Txid = display.parse().expect("non-palindromic txid");
    let wire = FundingOutpointV2::from_outpoint(OutPoint::new(txid, 9)).expect("non-null outpoint");
    assert_eq!(hex::encode(wire.txid()), display);
    assert_eq!(wire.to_outpoint().txid.to_string(), display);
}

#[test]
fn network_and_genesis_hash_must_match() {
    let result = ChannelBindingV2::new(
        ProtocolSuiteIdV2::from_bytes([0x11; 32]).expect("suite id"),
        Network::Regtest,
        BitcoinGenesisHashV2::for_network(Network::Signet).expect("signet genesis hash"),
        b"local-deployment",
        FundingOutpointV2::new([0x44; 32], 1).expect("outpoint"),
        7,
        CommitteeDescriptorDigestV2::from_bytes([0x22; 32]).expect("committee descriptor"),
        AnchorParameterSuiteIdV2::from_bytes([0x33; 32]).expect("anchor suite"),
    );
    assert!(result.is_err());

    let mut value = serde_json::to_value(channel_fixture()).expect("channel JSON");
    value["bitcoin_genesis_hash"] =
        serde_json::to_value(BitcoinGenesisHashV2::for_network(Network::Signet).expect("signet genesis hash"))
            .expect("genesis JSON");
    assert!(serde_json::from_value::<ChannelBindingV2>(value).is_err());
}

#[test]
fn bitcoin_null_outpoint_is_rejected_without_banning_synthetic_txids() {
    assert!(FundingOutpointV2::new([0_u8; 32], u32::MAX).is_err());

    let mut null_bytes = [0_u8; FUNDING_OUTPOINT_BYTES];
    null_bytes[32..].copy_from_slice(&u32::MAX.to_be_bytes());
    assert!(FundingOutpointV2::from_canonical_bytes(null_bytes).is_err());

    let null_json = serde_json::json!({
        "txid": "00".repeat(32),
        "vout": u32::MAX,
    });
    assert!(serde_json::from_value::<FundingOutpointV2>(null_json).is_err());

    assert!(FundingOutpointV2::new([0_u8; 32], 0).is_ok());
}

#[test]
fn version_one_and_version_two_hashes_are_locked() {
    let version_one =
        BindingContext::transfer(Network::Regtest, b"local-deployment", 7, b"channel-42", b"invoice-9", 1)
            .expect("version 1 binding");
    let channel = channel_fixture();
    let operation = OperationBindingV2::transfer(channel.clone(), b"invoice-9", 1).expect("version 2 operation");

    assert_eq!(
        hex::encode(version_one.context_id().expect("v1 context")),
        "9cdf69b7b1adc292bab1b9e75783973c6ef63a7354fd1d29a97d7519dd58643f"
    );
    assert_eq!(
        hex::encode(version_one.canonical_digest().expect("v1 digest")),
        "8409d29bcbd0b22e352094f97b3fbb3e85110eb3793e5baf294621831be3cff9"
    );
    assert_eq!(
        hex::encode(channel.context_id().expect("v2 context")),
        "75f0a05030b09288f2165d892ea8f58b3558fd8dff785bfafcc8ed98cfe80dae"
    );
    assert_eq!(
        hex::encode(channel.canonical_digest().expect("v2 digest")),
        "1250930e587d82f8fe28c9fd0fbba875c2d52b50c919fb5c8f67a9e2afe3b531"
    );
    assert_eq!(
        hex::encode(operation.canonical_digest().expect("v2 operation digest")),
        "97c9819815d6eb01481964b4490a4ccfdc2561df4b85cdbcfc4f36f5fa48959e"
    );
}
