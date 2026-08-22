use bitcoin::Network;
use secp::Point;
use thunderbolt_ledger::{ActorPublicKeyV2, LedgerChainIdV2, ParticipantIdV2};
use thunderbolt_wire::{
    AnchorParameterSuiteIdV2, BitcoinGenesisHashV2, ChannelBindingV2, CommitteeDescriptorDigestV2, FundingOutpointV2,
    ProtocolSuiteIdV2,
};

use crate::{
    types::{FinalizeContextData, OwnershipWireStatementV2},
    ClosingTransactionDigest, OwnershipEnvelopeV2, OwnershipError, OwnershipProofV2, Result, OWNERSHIP_CODEC_VERSION,
};

const MAGIC: &[u8; 8] = b"TBOWNV02";
const MAX_CHAIN_ID_BYTES: usize = 50;
// The v2 wire statement has only fixed-size fields plus bounded chain and
// deployment identifiers. It never carries the closing transaction.
const MAX_OWNERSHIP_ENVELOPE_BYTES: usize = 2_048;

pub(crate) fn encode_transcript_context(context: &FinalizeContextData) -> Result<Vec<u8>> {
    let statement = OwnershipWireStatementV2::from_trusted(context);
    let mut output = encode_statement(&statement)?;
    let tx_len =
        u32::try_from(context.closing_transaction.len()).map_err(|_| OwnershipError::ClosingTransactionTooLarge)?;
    output.extend_from_slice(&tx_len.to_be_bytes());
    output.extend_from_slice(&context.closing_transaction);
    Ok(output)
}

fn encode_statement(statement: &OwnershipWireStatementV2) -> Result<Vec<u8>> {
    let chain = statement.ledger_chain_id.as_bytes();
    let chain_len = u16::try_from(chain.len()).map_err(|_| OwnershipError::InvalidContext("chain id too long"))?;
    let deployment = statement.channel.deployment_id.as_bytes();
    let deployment_len =
        u16::try_from(deployment.len()).map_err(|_| OwnershipError::InvalidContext("deployment id too long"))?;
    let mut output = Vec::with_capacity(640);
    output.extend_from_slice(&chain_len.to_be_bytes());
    output.extend_from_slice(chain);
    output.extend_from_slice(&statement.channel.protocol_version.to_be_bytes());
    output.extend_from_slice(statement.channel.protocol_suite_id.as_bytes());
    output.push(network_code(statement.channel.network));
    output.extend_from_slice(statement.channel.bitcoin_genesis_hash.as_bytes());
    output.extend_from_slice(&deployment_len.to_be_bytes());
    output.extend_from_slice(deployment);
    output.extend_from_slice(&statement.channel.funding_outpoint.canonical_bytes());
    output.extend_from_slice(&statement.channel.committee_epoch.to_be_bytes());
    output.extend_from_slice(statement.channel.committee_descriptor_digest.as_bytes());
    output.extend_from_slice(statement.channel.anchor_parameter_suite_id.as_bytes());
    output.extend_from_slice(&statement.channel_context_id);
    output.extend_from_slice(&statement.snapshot_state_hash);
    output.extend_from_slice(&statement.step.to_be_bytes());
    output.extend_from_slice(&statement.fixed_lock_key.serialize());
    output.extend_from_slice(&statement.anchor_base.serialize());
    output.extend_from_slice(&statement.current_anchor.serialize());
    output.extend_from_slice(statement.holder_participant.as_bytes());
    output.extend_from_slice(statement.holder_key.as_bytes());
    output.extend_from_slice(statement.closing_digest.as_bytes());
    Ok(output)
}

pub(crate) fn encode_envelope(envelope: &OwnershipEnvelopeV2) -> Result<Vec<u8>> {
    let statement = encode_statement(&envelope.statement)?;
    let statement_len = u32::try_from(statement.len()).map_err(|_| OwnershipError::MalformedEncoding)?;
    let mut output = Vec::with_capacity(MAGIC.len() + 2 + 4 + statement.len() + 2 + 33 + 32);
    output.extend_from_slice(MAGIC);
    output.extend_from_slice(&OWNERSHIP_CODEC_VERSION.to_be_bytes());
    output.extend_from_slice(&statement_len.to_be_bytes());
    output.extend_from_slice(&statement);
    output.extend_from_slice(&envelope.proof().version.to_be_bytes());
    output.extend_from_slice(&envelope.proof().commitment.serialize());
    output.extend_from_slice(&envelope.proof().response);
    Ok(output)
}

pub(crate) fn decode_envelope(bytes: &[u8]) -> Result<OwnershipEnvelopeV2> {
    if bytes.len() > MAX_OWNERSHIP_ENVELOPE_BYTES {
        return Err(OwnershipError::MalformedEncoding);
    }
    let mut cursor = Cursor::new(bytes);
    if cursor.take(MAGIC.len())? != MAGIC || cursor.u16()? != OWNERSHIP_CODEC_VERSION {
        return Err(OwnershipError::UnsupportedVersion);
    }
    let statement_len = cursor.length_u32(MAX_OWNERSHIP_ENVELOPE_BYTES)?;
    let statement_bytes = cursor.take(statement_len)?;
    let statement = decode_statement(statement_bytes)?;
    let version = cursor.u16()?;
    let commitment = point(cursor.take(33)?)?;
    let response = cursor.array_32()?;
    if !cursor.is_empty() {
        return Err(OwnershipError::MalformedEncoding);
    }
    OwnershipEnvelopeV2::from_parts(
        statement,
        OwnershipProofV2 {
            version,
            commitment,
            response,
        },
    )
}

fn decode_statement(bytes: &[u8]) -> Result<OwnershipWireStatementV2> {
    let mut cursor = Cursor::new(bytes);
    let chain_len = cursor.length_u16(MAX_CHAIN_ID_BYTES)?;
    let chain = std::str::from_utf8(cursor.take(chain_len)?).map_err(|_| OwnershipError::MalformedEncoding)?;
    let ledger_chain_id = LedgerChainIdV2::new(chain).map_err(|_| OwnershipError::MalformedEncoding)?;
    let protocol_version = cursor.u16()?;
    if protocol_version != thunderbolt_wire::PROTOCOL_VERSION_V2 {
        return Err(OwnershipError::UnsupportedVersion);
    }
    let protocol_suite_id =
        ProtocolSuiteIdV2::from_bytes(cursor.take(32)?).map_err(|_| OwnershipError::MalformedEncoding)?;
    let network = decode_network(cursor.u8()?)?;
    let genesis = BitcoinGenesisHashV2::from_bytes(cursor.take(32)?).map_err(|_| OwnershipError::MalformedEncoding)?;
    let deployment_len = cursor.length_u16(thunderbolt_wire::MAX_DEPLOYMENT_ID_BYTES)?;
    let deployment = cursor.take(deployment_len)?;
    let funding =
        FundingOutpointV2::from_canonical_bytes(cursor.take(36)?).map_err(|_| OwnershipError::MalformedEncoding)?;
    let epoch = cursor.u64()?;
    let committee =
        CommitteeDescriptorDigestV2::from_bytes(cursor.take(32)?).map_err(|_| OwnershipError::MalformedEncoding)?;
    let anchor_suite =
        AnchorParameterSuiteIdV2::from_bytes(cursor.take(32)?).map_err(|_| OwnershipError::MalformedEncoding)?;
    let encoded_context_id = cursor.array_32()?;
    let snapshot_state_hash = cursor.array_32()?;
    let step = cursor.u64()?;
    let fixed_lock_key = point(cursor.take(33)?)?;
    let anchor_base = point(cursor.take(33)?)?;
    let current_anchor = point(cursor.take(33)?)?;
    let holder_participant =
        ParticipantIdV2::from_bytes(cursor.array_32()?).map_err(|_| OwnershipError::MalformedEncoding)?;
    let holder_key = ActorPublicKeyV2::from_bytes(cursor.take(32)?).map_err(|_| OwnershipError::MalformedEncoding)?;
    let closing_digest = ClosingTransactionDigest(cursor.array_32()?);
    if !cursor.is_empty() {
        return Err(OwnershipError::MalformedEncoding);
    }
    let channel = ChannelBindingV2::new(
        protocol_suite_id,
        network,
        genesis,
        deployment,
        funding,
        epoch,
        committee,
        anchor_suite.clone(),
    )
    .map_err(|_| OwnershipError::MalformedEncoding)?;
    OwnershipWireStatementV2::new(
        ledger_chain_id,
        channel,
        encoded_context_id,
        snapshot_state_hash,
        step,
        fixed_lock_key,
        anchor_base,
        current_anchor,
        holder_participant,
        holder_key,
        closing_digest,
    )
}

fn point(bytes: &[u8]) -> Result<Point> {
    if !matches!(bytes.first(), Some(2 | 3)) {
        return Err(OwnershipError::MalformedEncoding);
    }
    Point::from_slice(bytes).map_err(|_| OwnershipError::MalformedEncoding)
}

fn network_code(network: Network) -> u8 {
    match network {
        Network::Bitcoin => 0,
        Network::Testnet => 1,
        Network::Testnet4 => 2,
        Network::Signet => 3,
        Network::Regtest => 4,
    }
}

fn decode_network(code: u8) -> Result<Network> {
    match code {
        0 => Ok(Network::Bitcoin),
        1 => Ok(Network::Testnet),
        2 => Ok(Network::Testnet4),
        3 => Ok(Network::Signet),
        4 => Ok(Network::Regtest),
        _ => Err(OwnershipError::MalformedEncoding),
    }
}

struct Cursor<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Cursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }
    fn take(&mut self, len: usize) -> Result<&'a [u8]> {
        let end = self
            .position
            .checked_add(len)
            .ok_or(OwnershipError::MalformedEncoding)?;
        let value = self
            .bytes
            .get(self.position..end)
            .ok_or(OwnershipError::MalformedEncoding)?;
        self.position = end;
        Ok(value)
    }
    fn u8(&mut self) -> Result<u8> {
        self.take(1)?.first().copied().ok_or(OwnershipError::MalformedEncoding)
    }
    fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_be_bytes(
            self.take(2)?
                .try_into()
                .map_err(|_| OwnershipError::MalformedEncoding)?,
        ))
    }
    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_be_bytes(
            self.take(4)?
                .try_into()
                .map_err(|_| OwnershipError::MalformedEncoding)?,
        ))
    }
    fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_be_bytes(
            self.take(8)?
                .try_into()
                .map_err(|_| OwnershipError::MalformedEncoding)?,
        ))
    }
    fn array_32(&mut self) -> Result<[u8; 32]> {
        self.take(32)?.try_into().map_err(|_| OwnershipError::MalformedEncoding)
    }
    fn length_u16(&mut self, max: usize) -> Result<usize> {
        let value = usize::from(self.u16()?);
        if value == 0 || value > max {
            Err(OwnershipError::MalformedEncoding)
        } else {
            Ok(value)
        }
    }
    fn length_u32(&mut self, max: usize) -> Result<usize> {
        let value = usize::try_from(self.u32()?).map_err(|_| OwnershipError::MalformedEncoding)?;
        if value == 0 || value > max {
            Err(OwnershipError::MalformedEncoding)
        } else {
            Ok(value)
        }
    }
    const fn is_empty(&self) -> bool {
        self.position == self.bytes.len()
    }
}
