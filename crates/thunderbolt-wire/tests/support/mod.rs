#![allow(dead_code)]

use bitcoin::Network;
use secp::Scalar;
use thunderbolt_wire::{
    AnchorParameterSuiteIdV2, AnchorTransitionV2, BitcoinGenesisHashV2, ChannelBindingV2, CommitteeDescriptorDigestV2,
    FundingOutpointV2, HexBytes, InvoiceEnvelopeV2, InvoiceProofV2, InvoiceStatementV2, OperationBindingV2,
    PaillierCiphertextBytesV2, PaillierModulusBytesV2, PaillierModulusProfileV2, PaillierNonceBytesV2, PointHex,
    ProofResponseBytesV2, ProtocolSuiteIdV2, RecipientShareEnvelopeV2, RecipientShareStatementV2, ShareProofV2,
    ThresholdDistributionV2, ThresholdEncryptedShareV2, ThresholdEnvelopeV2, ThresholdPackageBindingV2,
    ThresholdRosterMemberV2, ThresholdRosterV2, TransferEnvelopeV2, TransferProofV2, TransferStatementV2,
    PAILLIER_V2_CIPHERTEXT_BYTES, PAILLIER_V2_MODULUS_BYTES, PROOF_RESPONSE_V2_BYTES, RECIPIENT_SHARE_MEMBER_ID,
};

pub(crate) fn point(seed: u8) -> PointHex {
    let mut scalar_bytes = [0_u8; 32];
    scalar_bytes[31] = seed.max(1);
    let scalar = Scalar::from_slice(&scalar_bytes).expect("fixture scalar is valid");
    PointHex::from_bytes("fixture point", scalar.base_point_mul().serialize()).expect("fixture point is exact width")
}

pub(crate) fn modulus(seed: u8) -> PaillierModulusBytesV2 {
    let mut bytes = vec![0_u8; PAILLIER_V2_MODULUS_BYTES];
    bytes[0] = 0x40 | (seed & 0x3f);
    bytes[PAILLIER_V2_MODULUS_BYTES - 1] = seed | 1;
    PaillierModulusBytesV2::from_bytes("fixture modulus", bytes).expect("fixture modulus is exact width")
}

pub(crate) fn ciphertext(seed: u8) -> PaillierCiphertextBytesV2 {
    let mut bytes = vec![0_u8; PAILLIER_V2_CIPHERTEXT_BYTES];
    bytes[PAILLIER_V2_CIPHERTEXT_BYTES - 1] = seed.max(1);
    PaillierCiphertextBytesV2::from_bytes("fixture ciphertext", bytes).expect("fixture ciphertext is exact width")
}

pub(crate) fn nonce(seed: u8) -> PaillierNonceBytesV2 {
    let mut bytes = vec![0_u8; PAILLIER_V2_MODULUS_BYTES];
    bytes[PAILLIER_V2_MODULUS_BYTES - 1] = seed.max(1);
    PaillierNonceBytesV2::from_bytes("fixture nonce", bytes).expect("fixture nonce is exact width")
}

pub(crate) fn response(seed: u8) -> ProofResponseBytesV2 {
    let mut bytes = vec![0_u8; PROOF_RESPONSE_V2_BYTES];
    bytes[PROOF_RESPONSE_V2_BYTES - 1] = seed;
    ProofResponseBytesV2::from_bytes("fixture response", bytes).expect("fixture response is exact width")
}

pub(crate) fn channel(seed: u8, deployment: &[u8]) -> ChannelBindingV2 {
    ChannelBindingV2::new(
        ProtocolSuiteIdV2::from_bytes([seed.max(1); 32]).expect("suite id"),
        Network::Regtest,
        BitcoinGenesisHashV2::for_network(Network::Regtest).expect("genesis"),
        deployment,
        FundingOutpointV2::new([seed.wrapping_add(1).max(1); 32], u32::from(seed)).expect("funding outpoint"),
        u64::from(seed) + 1,
        CommitteeDescriptorDigestV2::from_bytes([seed.wrapping_add(2).max(1); 32]).expect("committee descriptor"),
        AnchorParameterSuiteIdV2::from_bytes([seed.wrapping_add(3).max(1); 32]).expect("anchor suite"),
    )
    .expect("channel fixture")
}

pub(crate) fn invoice(seed: u8) -> InvoiceEnvelopeV2 {
    let binding =
        OperationBindingV2::invoice(channel(seed, b"v2-deployment"), [seed.max(1); 32]).expect("invoice operation");
    InvoiceEnvelopeV2 {
        binding,
        paillier_profile: PaillierModulusProfileV2::ProtocolV2Production3072,
        expected_transfer_step: u64::from(seed) + 1,
        statement: InvoiceStatementV2 {
            anchor_base: point(1),
            recipient_key: modulus(seed.wrapping_add(10)),
            committee_key: modulus(seed.wrapping_add(11)),
            delta: point(2),
            recipient_ciphertext: ciphertext(seed.wrapping_add(12)),
            committee_ciphertext: ciphertext(seed.wrapping_add(13)),
        },
        proof: InvoiceProofV2 {
            a_delta: point(3),
            a_recipient: ciphertext(seed.wrapping_add(14)),
            a_committee: ciphertext(seed.wrapping_add(15)),
            z: response(seed.wrapping_add(16)),
            tau_recipient: nonce(seed.wrapping_add(17)),
            tau_committee: nonce(seed.wrapping_add(18)),
        },
    }
}

pub(crate) fn transfer(seed: u8) -> TransferEnvelopeV2 {
    let binding = OperationBindingV2::transfer(channel(seed, b"v2-deployment"), [seed.max(1); 32], u64::from(seed) + 1)
        .expect("transfer operation");
    let current_anchor = point(4);
    TransferEnvelopeV2 {
        binding,
        paillier_profile: PaillierModulusProfileV2::ProtocolV2Production3072,
        statement: TransferStatementV2 {
            anchor_base: point(1),
            recipient_key: modulus(seed.wrapping_add(20)),
            current_anchor: current_anchor.clone(),
            invoice_ciphertext: ciphertext(seed.wrapping_add(21)),
            next_holder_ciphertext: ciphertext(seed.wrapping_add(22)),
        },
        proof: TransferProofV2 {
            a_anchor: point(5),
            a_ciphertext: ciphertext(seed.wrapping_add(23)),
            z: response(seed.wrapping_add(24)),
            tau: nonce(seed.wrapping_add(25)),
        },
        anchor_transition: AnchorTransitionV2 {
            current_anchor,
            delta: point(2),
            next_anchor: point(6),
        },
    }
}

pub(crate) fn threshold_pair(
    seed: u8,
    member_count: usize,
    threshold: u32,
) -> (RecipientShareEnvelopeV2, ThresholdEnvelopeV2) {
    let operation = OperationBindingV2::invoice(
        channel(seed, b"threshold-deployment"),
        [seed.wrapping_add(30).max(1); 32],
    )
    .expect("threshold operation");
    let members = (1..=member_count)
        .map(|index| ThresholdRosterMemberV2 {
            member_id: u32::try_from(index).expect("fixture member id"),
            encryption_key: modulus(index as u8),
        })
        .collect::<Vec<_>>();
    let roster = ThresholdRosterV2::new(threshold, members).expect("threshold roster");
    let package = ThresholdPackageBindingV2::new(&operation, u64::from(seed) + 1, roster.clone())
        .expect("threshold package binding");
    let delta = point(7);
    let recipient = RecipientShareEnvelopeV2 {
        binding: operation.clone(),
        paillier_profile: PaillierModulusProfileV2::ProtocolV2Production3072,
        package: package.clone(),
        statement: RecipientShareStatementV2 {
            anchor_base: point(1),
            recipient_key: modulus(seed.wrapping_add(40)),
            member_id: RECIPIENT_SHARE_MEMBER_ID,
            committed_point: delta.clone(),
            ciphertext: ciphertext(seed.wrapping_add(41)),
        },
        proof: ShareProofV2 {
            a_point: point(8),
            a_ciphertext: ciphertext(seed.wrapping_add(42)),
            z: response(seed.wrapping_add(43)),
            tau: nonce(seed.wrapping_add(44)),
        },
    };
    let encrypted_shares = roster
        .members
        .iter()
        .map(|member| ThresholdEncryptedShareV2 {
            member_id: member.member_id,
            encryption_key: member.encryption_key.clone(),
            ciphertext: ciphertext(member.member_id as u8),
            proof: ShareProofV2 {
                a_point: point(member.member_id as u8),
                a_ciphertext: ciphertext(member.member_id.wrapping_add(1) as u8),
                z: response(member.member_id.wrapping_add(2) as u8),
                tau: nonce(member.member_id.wrapping_add(3) as u8),
            },
        })
        .collect();
    let mut polynomial_commitments = vec![delta.clone()];
    for index in 1..threshold {
        polynomial_commitments.push(point(index.wrapping_add(8) as u8));
    }
    let distribution = ThresholdEnvelopeV2 {
        binding: operation,
        paillier_profile: PaillierModulusProfileV2::ProtocolV2Production3072,
        package,
        distribution: ThresholdDistributionV2 {
            anchor_base: point(1),
            threshold,
            delta,
            polynomial_commitments,
            encrypted_shares,
        },
    };
    (recipient, distribution)
}

pub(crate) fn replace_binding(invoice: &mut InvoiceEnvelopeV2, deployment: Vec<u8>, invoice_id: Vec<u8>) {
    invoice.binding = OperationBindingV2::invoice(channel(91, &deployment), invoice_id).expect("generated binding");
}

pub(crate) fn raw_hex<const N: usize>(byte: u8) -> HexBytes<N, N> {
    HexBytes::from_bytes("fixture raw bytes", vec![byte; N]).expect("fixture exact width")
}
