use std::collections::BTreeMap;

use bitcoin::Network;
use secp256k1::{Keypair, Secp256k1, SecretKey};
use thunderbolt_ledger::{
    ActorKeyAlgorithmV2, ActorPublicKeyV2, ActorRoleV2, ActorSignatureV2, AppHashV2, CanonicalEventV2,
    ChannelContextIdV2, ClientRequestNonceV2, EntryHashV2, LedgerChainIdV2, PendingBlockV2, ProposalBodyV2,
    SignedProposalV2, EVENT_BYTES_MAX, MAX_SIGNED_PROPOSAL_JSON_BYTES,
};
use thunderbolt_ledger_rpc::{
    ChannelExecutionPositionV2, ChannelStatusRequestV2, ChannelStatusResponseV2, FinalityStatusV2,
    FinalityVerifierProfileIdV2, FinalizedEntryBundleV2, OpaqueConsensusReceiptV2, RequestLifecycleV2,
    RequestStatusRequestV2, RequestStatusResponseV2, RpcRequestV2, RpcResponseV2, SnapshotBytesV2,
    SubmitProposalRequestV2, MAX_CONSENSUS_RECEIPT_BYTES, MAX_RPC_REQUEST_BYTES, MAX_RPC_RESPONSE_BYTES,
    MAX_SNAPSHOT_BYTES,
};
use thunderbolt_protocol::v2::{
    ArtifactV2, ChannelEventV2, ChannelPhaseV2, ChannelSnapshotV2, InvoiceEventV2, PendingInvoiceV2,
    MAX_ARTIFACT_BYTES_V2, PROTOCOL_VERSION_V2,
};
use thunderbolt_wire::{
    to_json_vec, validate_threshold_package_v2, AnchorParameterSuiteIdV2, BitcoinGenesisHashV2, ChannelBindingV2,
    CommitteeDescriptorDigestV2, FundingOutpointV2, InvoiceId, OperationBindingV2, PaillierCiphertextBytesV2,
    PaillierModulusBytesV2, PaillierModulusProfileV2, PaillierNonceBytesV2, PointHex, ProofResponseBytesV2,
    ProtocolSuiteIdV2, PublicMessageV2, RecipientShareEnvelopeV2, RecipientShareStatementV2, ShareProofV2,
    ThresholdDistributionV2, ThresholdEncryptedShareV2, ThresholdEnvelopeV2, ThresholdPackageBindingV2,
    ThresholdRosterMemberV2, ThresholdRosterV2, MAX_COMMITTEE_MEMBERS, MAX_DEPLOYMENT_ID_BYTES, MAX_INVOICE_ID_BYTES,
    PAILLIER_V2_CIPHERTEXT_BYTES, PAILLIER_V2_MODULUS_BYTES, PROOF_RESPONSE_V2_BYTES, RECIPIENT_SHARE_MEMBER_ID,
};

const RECIPIENT_MESSAGE_BYTES: usize = 212_661;
const THRESHOLD_MESSAGE_BYTES: usize = 1_491_757;
const MAX_TOPOLOGY_EVENT_BYTES: usize = 1_705_843;
const MAX_TOPOLOGY_SIGNED_PROPOSAL_BYTES: usize = 3_413_182;
const MAX_TOPOLOGY_RPC_REQUEST_BYTES: usize = 3_413_339;
const MAX_COMPACT_FINALITY_RESPONSE_BYTES: usize = 5_512_342;

#[test]
fn maximum_topology_is_closed_across_event_signed_abci_and_rpc_caps() -> Result<(), Box<dyn std::error::Error>> {
    let (recipient, threshold) = maximum_threshold_pair()?;
    validate_threshold_package_v2(&recipient, &threshold)?;
    let recipient_bytes = to_json_vec(&PublicMessageV2::RecipientShare(recipient.clone()))?;
    let threshold_bytes = to_json_vec(&PublicMessageV2::ThresholdRefresh(threshold))?;
    assert_eq!(recipient_bytes.len(), RECIPIENT_MESSAGE_BYTES);
    assert_eq!(threshold_bytes.len(), THRESHOLD_MESSAGE_BYTES);
    assert!(threshold_bytes.len() <= MAX_ARTIFACT_BYTES_V2);

    let channel = recipient.binding.channel().clone();
    let invoice_id = recipient.binding.invoice_id().clone();
    let event = ChannelEventV2::Invoice(InvoiceEventV2 {
        invoice_id,
        holder_step: u64::MAX,
        recipient_encryption_key: ArtifactV2::new(recipient.statement.recipient_key.as_bytes().to_vec())?,
        public_delta: ArtifactV2::new(recipient.statement.committed_point.as_bytes().to_vec())?,
        recipient_ciphertext: ArtifactV2::new(recipient.statement.ciphertext.as_bytes().to_vec())?,
        committee_package: ArtifactV2::new(threshold_bytes)?,
        invoice_proof: ArtifactV2::new(recipient_bytes)?,
        expires_at_ms: u64::MAX,
    });
    let event_bytes = event.canonical_bytes()?;
    assert_eq!(event_bytes.len(), MAX_TOPOLOGY_EVENT_BYTES);
    assert!(event_bytes.len() <= EVENT_BYTES_MAX);

    let chain = LedgerChainIdV2::new("a".repeat(50))?;
    let proposal = sign_invoice(
        chain.clone(),
        channel.clone(),
        event.clone(),
        event_bytes,
        u64::MAX,
        ActorRoleV2::Recipient,
    )?;
    let proposal_bytes = serde_json::to_vec(&proposal)?;
    assert_eq!(proposal_bytes.len(), MAX_TOPOLOGY_SIGNED_PROPOSAL_BYTES);
    assert!(proposal_bytes.len() <= MAX_SIGNED_PROPOSAL_JSON_BYTES);

    let mut pending = PendingBlockV2::new(chain.clone(), 2, u64::MAX, AppHashV2::from_bytes([0x75; 32])?)?;
    pending.push(proposal.clone())?;
    let block = pending.execute()?;
    let commitment = block.commitment()?;
    let entry = block.entries()[0].clone();
    let proof = block.entry_proof(0)?;
    let receipt = OpaqueConsensusReceiptV2::new(
        FinalityVerifierProfileIdV2::from_bytes([0x76; 32])?,
        vec![0x77; MAX_CONSENSUS_RECEIPT_BYTES],
    )?;
    let bundle = FinalizedEntryBundleV2::new(commitment, entry, proof, receipt)?;
    let metadata = bundle.entry().metadata();
    let finality_query = RequestStatusRequestV2::new(
        metadata.ledger_chain_id().clone(),
        metadata.channel_context_id().clone(),
        metadata.participant_id().clone(),
        metadata.request_digest().clone(),
    );
    let finality_response = RpcResponseV2::RequestStatus(Box::new(RequestStatusResponseV2::new(
        &finality_query,
        RequestLifecycleV2::FinalityReceiptAvailable {
            bundle: Box::new(bundle),
        },
    )?));
    let finality_bytes = finality_response.to_canonical_bytes()?;
    assert_eq!(finality_bytes.len(), MAX_COMPACT_FINALITY_RESPONSE_BYTES);
    assert!(finality_bytes.len() <= MAX_RPC_RESPONSE_BYTES);
    let finality_value: serde_json::Value = serde_json::from_slice(&finality_bytes)?;
    let finality_bundle = &finality_value["response"]["result"]["lifecycle"]["bundle"];
    assert!(finality_bundle.get("commitment").is_some());
    assert!(finality_bundle.get("block").is_none());
    let finality_request = RpcRequestV2::RequestStatus(finality_query);
    assert_eq!(
        RpcResponseV2::from_canonical_bytes_for(&finality_bytes, &finality_request)?.response(),
        &finality_response
    );
    assert!(OpaqueConsensusReceiptV2::new(
        FinalityVerifierProfileIdV2::from_bytes([0x76; 32])?,
        vec![0x77; MAX_CONSENSUS_RECEIPT_BYTES + 1],
    )
    .is_err());

    let snapshot = four_invoice_snapshot(&chain, &channel, &proposal, &event)?;
    let snapshot_bytes = SnapshotBytesV2::from_snapshot(&snapshot)?;
    assert_eq!(snapshot_bytes.as_bytes().len(), 6_824_594);
    assert!(snapshot_bytes.as_bytes().len() <= MAX_SNAPSHOT_BYTES);
    assert_eq!(snapshot_bytes.decode(&channel)?, snapshot);
    let status_request =
        ChannelStatusRequestV2::new(chain.clone(), ChannelContextIdV2::from_bytes(channel.context_id()?)?);
    let status_response = ChannelStatusResponseV2::new(
        &status_request,
        channel,
        ChannelExecutionPositionV2::new(1, 0, proposal.body().entry_hash()?)?,
        snapshot.state_hash()?,
        snapshot_bytes,
        FinalityStatusV2::Unfinalized,
    )?;
    let response_bytes = RpcResponseV2::ChannelStatus(Box::new(status_response)).to_canonical_bytes()?;
    assert_eq!(response_bytes.len(), 13_650_331);
    assert!(response_bytes.len() <= MAX_RPC_RESPONSE_BYTES);

    let request = RpcRequestV2::SubmitProposal(SubmitProposalRequestV2::new(chain, proposal)?);
    let request_bytes = request.to_canonical_bytes()?;
    assert_eq!(request_bytes.len(), MAX_TOPOLOGY_RPC_REQUEST_BYTES);
    assert!(request_bytes.len() <= MAX_RPC_REQUEST_BYTES);
    assert_eq!(RpcRequestV2::from_canonical_bytes(&request_bytes)?, request);
    Ok(())
}

fn four_invoice_snapshot(
    chain: &LedgerChainIdV2,
    channel: &ChannelBindingV2,
    proposal: &SignedProposalV2,
    event: &ChannelEventV2,
) -> Result<ChannelSnapshotV2, Box<dyn std::error::Error>> {
    let ChannelEventV2::Invoice(invoice) = event else {
        return Err(std::io::Error::other("capacity event is not Invoice").into());
    };
    let participant = proposal.body().participant_id()?;
    let entry_hash = proposal.body().entry_hash()?;
    let mut pending_invoices = BTreeMap::new();
    for index in 1_u8..=4 {
        let mut event = invoice.clone();
        event.invoice_id = InvoiceId::from_bytes("capacity snapshot invoice", [index; MAX_INVOICE_ID_BYTES])?;
        let invoice_id = event.invoice_id.clone();
        pending_invoices.insert(
            invoice_id.clone(),
            PendingInvoiceV2 {
                event,
                invoice_id,
                recipient: participant.clone(),
                holder_step: u64::MAX,
                created_at_ms: 1,
                expires_at_ms: u64::MAX,
                committed_entry_hash: entry_hash.clone(),
            },
        );
    }
    let snapshot = ChannelSnapshotV2 {
        protocol_version: PROTOCOL_VERSION_V2,
        ledger_chain_id: chain.clone(),
        binding: channel.clone(),
        phase: ChannelPhaseV2::Active,
        capacity_sat: 1,
        committee_member_count: u16::try_from(MAX_COMMITTEE_MEMBERS)?,
        committee_threshold: u16::try_from(MAX_COMMITTEE_MEMBERS)?,
        lock_key: ArtifactV2::new([1])?,
        current_holder: participant,
        current_holder_anchor: ArtifactV2::new([2])?,
        current_holder_ciphertext: ArtifactV2::new([3])?,
        transfers_completed: u64::MAX,
        pending_invoices,
        last_consumed_invoice_id: Some(InvoiceId::from_bytes("capacity consumed invoice", [0xff])?),
        last_sequence: u64::MAX,
        head_entry_hash: entry_hash,
        opened_at_ms: 1,
        last_block_time_ms: 1,
        finalized_at_ms: None,
    };
    snapshot.validate()?;
    assert_eq!(snapshot.pending_invoice_event_bytes()?, 4 * MAX_TOPOLOGY_EVENT_BYTES);
    Ok(snapshot)
}

#[test]
fn exact_event_limit_stays_closed_and_one_more_byte_is_rejected() -> Result<(), Box<dyn std::error::Error>> {
    let (recipient, threshold) = maximum_threshold_pair()?;
    let recipient_bytes = to_json_vec(&PublicMessageV2::RecipientShare(recipient.clone()))?;
    let threshold_bytes = to_json_vec(&PublicMessageV2::ThresholdRefresh(threshold))?;
    let channel = recipient.binding.channel().clone();
    let invoice_id = recipient.binding.invoice_id().clone();
    let mut event = ChannelEventV2::Invoice(InvoiceEventV2 {
        invoice_id,
        holder_step: u64::MAX,
        recipient_encryption_key: ArtifactV2::new(recipient.statement.recipient_key.as_bytes().to_vec())?,
        public_delta: ArtifactV2::new(recipient.statement.committed_point.as_bytes().to_vec())?,
        recipient_ciphertext: ArtifactV2::new(recipient.statement.ciphertext.as_bytes().to_vec())?,
        committee_package: ArtifactV2::new(threshold_bytes)?,
        invoice_proof: ArtifactV2::new(recipient_bytes)?,
        expires_at_ms: u64::MAX,
    });
    let baseline = event.canonical_bytes()?.len();
    let ChannelEventV2::Invoice(invoice) = &mut event else {
        unreachable!("fixture is Invoice")
    };
    let exact_package_len = invoice
        .committee_package
        .as_bytes()
        .len()
        .checked_add(EVENT_BYTES_MAX - baseline)
        .ok_or_else(|| std::io::Error::other("event capacity overflow"))?;
    invoice.committee_package = ArtifactV2::new(vec![0x5a; exact_package_len])?;
    let exact_event_bytes = event.canonical_bytes()?;
    assert_eq!(exact_event_bytes.len(), EVENT_BYTES_MAX);

    let chain = LedgerChainIdV2::new("a".repeat(50))?;
    let mut channel = channel;
    channel.network = Network::Testnet4;
    channel.bitcoin_genesis_hash = BitcoinGenesisHashV2::for_network(Network::Testnet4)?;
    // Transport closure uses the longest valid enum spelling; role authorization
    // remains a separate reducer/static-verifier decision.
    let proposal = sign_invoice(
        chain.clone(),
        channel,
        event.clone(),
        exact_event_bytes,
        u64::MAX,
        ActorRoleV2::LedgerOperator,
    )?;
    let proposal_len = serde_json::to_vec(&proposal)?.len();
    assert!(proposal_len <= MAX_SIGNED_PROPOSAL_JSON_BYTES);
    let request = RpcRequestV2::SubmitProposal(SubmitProposalRequestV2::new(chain, proposal)?);
    assert!(request.to_canonical_bytes()?.len() <= MAX_RPC_REQUEST_BYTES);

    let ChannelEventV2::Invoice(invoice) = &mut event else {
        unreachable!("fixture is Invoice")
    };
    invoice.committee_package = ArtifactV2::new(vec![0x5a; exact_package_len + 1])?;
    assert!(event.canonical_bytes().is_err());
    Ok(())
}

fn maximum_threshold_pair() -> Result<(RecipientShareEnvelopeV2, ThresholdEnvelopeV2), Box<dyn std::error::Error>> {
    let channel = maximum_channel()?;
    let operation = OperationBindingV2::invoice(channel, [0xee; MAX_INVOICE_ID_BYTES])?;
    let members = (1..=MAX_COMMITTEE_MEMBERS)
        .map(|index| {
            Ok(ThresholdRosterMemberV2 {
                member_id: u32::try_from(index)?,
                encryption_key: modulus(index as u8)?,
            })
        })
        .collect::<Result<Vec<_>, Box<dyn std::error::Error>>>()?;
    let roster = ThresholdRosterV2::new(u32::try_from(MAX_COMMITTEE_MEMBERS)?, members)?;
    let package = ThresholdPackageBindingV2::new(&operation, u64::MAX, roster.clone())?;
    let delta = point()?;
    let recipient = RecipientShareEnvelopeV2 {
        binding: operation.clone(),
        paillier_profile: PaillierModulusProfileV2::ProtocolV2Production3072,
        package: package.clone(),
        statement: RecipientShareStatementV2 {
            anchor_base: point()?,
            recipient_key: modulus(91)?,
            member_id: RECIPIENT_SHARE_MEMBER_ID,
            committed_point: delta.clone(),
            ciphertext: ciphertext(92)?,
        },
        proof: share_proof(93)?,
    };
    let encrypted_shares = roster
        .members
        .iter()
        .map(|member| {
            Ok(ThresholdEncryptedShareV2 {
                member_id: member.member_id,
                encryption_key: member.encryption_key.clone(),
                ciphertext: ciphertext(member.member_id as u8)?,
                proof: share_proof(member.member_id.wrapping_add(1) as u8)?,
            })
        })
        .collect::<Result<Vec<_>, Box<dyn std::error::Error>>>()?;
    let threshold = ThresholdEnvelopeV2 {
        binding: operation,
        paillier_profile: PaillierModulusProfileV2::ProtocolV2Production3072,
        package,
        distribution: ThresholdDistributionV2 {
            anchor_base: point()?,
            threshold: u32::try_from(MAX_COMMITTEE_MEMBERS)?,
            delta: delta.clone(),
            polynomial_commitments: vec![delta; MAX_COMMITTEE_MEMBERS],
            encrypted_shares,
        },
    };
    Ok((recipient, threshold))
}

fn maximum_channel() -> Result<ChannelBindingV2, Box<dyn std::error::Error>> {
    Ok(ChannelBindingV2::new(
        ProtocolSuiteIdV2::from_bytes([0x11; 32])?,
        Network::Regtest,
        BitcoinGenesisHashV2::for_network(Network::Regtest)?,
        [0xff; MAX_DEPLOYMENT_ID_BYTES],
        FundingOutpointV2::new([0xdd; 32], u32::MAX)?,
        u64::MAX,
        CommitteeDescriptorDigestV2::from_bytes([0x22; 32])?,
        AnchorParameterSuiteIdV2::from_bytes([0x33; 32])?,
    )?)
}

fn point() -> Result<PointHex, Box<dyn std::error::Error>> {
    Ok(PointHex::from_bytes(
        "capacity point",
        hex::decode("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")?,
    )?)
}

fn modulus(seed: u8) -> Result<PaillierModulusBytesV2, Box<dyn std::error::Error>> {
    let mut bytes = vec![0_u8; PAILLIER_V2_MODULUS_BYTES];
    bytes[0] = 0x40 | (seed & 0x3f);
    bytes[PAILLIER_V2_MODULUS_BYTES - 1] = seed | 1;
    Ok(PaillierModulusBytesV2::from_bytes("capacity modulus", bytes)?)
}

fn ciphertext(seed: u8) -> Result<PaillierCiphertextBytesV2, Box<dyn std::error::Error>> {
    let mut bytes = vec![0_u8; PAILLIER_V2_CIPHERTEXT_BYTES];
    bytes[PAILLIER_V2_CIPHERTEXT_BYTES - 1] = seed.max(1);
    Ok(PaillierCiphertextBytesV2::from_bytes("capacity ciphertext", bytes)?)
}

fn nonce(seed: u8) -> Result<PaillierNonceBytesV2, Box<dyn std::error::Error>> {
    let mut bytes = vec![0_u8; PAILLIER_V2_MODULUS_BYTES];
    bytes[PAILLIER_V2_MODULUS_BYTES - 1] = seed.max(1);
    Ok(PaillierNonceBytesV2::from_bytes("capacity nonce", bytes)?)
}

fn response(seed: u8) -> Result<ProofResponseBytesV2, Box<dyn std::error::Error>> {
    let mut bytes = vec![0_u8; PROOF_RESPONSE_V2_BYTES];
    bytes[PROOF_RESPONSE_V2_BYTES - 1] = seed.max(1);
    Ok(ProofResponseBytesV2::from_bytes("capacity response", bytes)?)
}

fn share_proof(seed: u8) -> Result<ShareProofV2, Box<dyn std::error::Error>> {
    Ok(ShareProofV2 {
        a_point: point()?,
        a_ciphertext: ciphertext(seed)?,
        z: response(seed.wrapping_add(1))?,
        tau: nonce(seed.wrapping_add(2))?,
    })
}

fn sign_invoice(
    chain: LedgerChainIdV2,
    channel: ChannelBindingV2,
    event: ChannelEventV2,
    event_bytes: Vec<u8>,
    sequence: u64,
    actor_role: ActorRoleV2,
) -> Result<SignedProposalV2, Box<dyn std::error::Error>> {
    let secp = Secp256k1::new();
    let keypair = Keypair::from_secret_key(&secp, &SecretKey::from_byte_array([1_u8; 32])?);
    let (public_key, _) = keypair.x_only_public_key();
    let body = ProposalBodyV2::new(
        chain,
        channel,
        sequence,
        EntryHashV2::from_bytes([0xaa; 32])?,
        ClientRequestNonceV2::from_bytes([0xbb; 64])?,
        ActorKeyAlgorithmV2::Bip340V1,
        ActorPublicKeyV2::from_bytes(public_key.serialize())?,
        actor_role,
        event.kind(),
        CanonicalEventV2::from_bytes(event_bytes)?,
    )?;
    let signature = secp.sign_schnorr_no_aux_rand(body.proposal_digest()?.as_bytes(), &keypair);
    Ok(SignedProposalV2::new(
        body,
        ActorSignatureV2::from_bytes(signature.to_byte_array())?,
    )?)
}
