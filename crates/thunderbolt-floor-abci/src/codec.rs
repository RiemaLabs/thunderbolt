use thunderbolt_floor::{FloorCasRequest, FloorLedgerChainId, VaultCheckpoint};
use thunderbolt_floor_app::{
    ActorRequestNonce, FloorAppHash, FloorCasAuthorization, FloorOperatorKey, SignedFloorCasRequest,
};
use thunderbolt_keystore::{
    CommitteeDescriptorDigest, DeploymentBinding, DeploymentId, Network, NodeId, VaultIdentity, VaultRevision,
    VaultRole, VaultStateDigest,
};

use crate::{FloorAbciError, Result};

/// Eight-byte canonical signed-CAS transaction magic.
pub const FLOOR_TRANSACTION_MAGIC: &[u8; 8] = b"TBFLCAS2";
/// Canonical transaction codec version.
pub const FLOOR_TRANSACTION_CODEC_VERSION: u16 = 2;
/// Minimum encoded signed-CAS transaction bytes.
pub const MIN_TRANSACTION_BYTES: usize = 329;
/// Maximum encoded signed-CAS transaction bytes.
pub const MAX_TRANSACTION_BYTES: usize = 496;

const CAS_KIND: u8 = 1;
const EXPECTED_PRESENT: u8 = 1;

/// Encodes one verified signed Floor CAS into its unique bounded binary form.
pub fn encode_signed_cas(request: &SignedFloorCasRequest) -> Result<Vec<u8>> {
    request
        .verify()
        .map_err(|_| FloorAbciError::InvalidTransaction("BIP340 signature is invalid"))?;
    let authorization = request.authorization();
    let chain = authorization.cas().chain_id().as_bytes();
    let expected = authorization.cas().expected();
    let length = 328_usize
        .checked_add(chain.len())
        .and_then(|value| value.checked_add(expected.map_or(0, |_| 40)))
        .ok_or(FloorAbciError::InvalidTransaction("transaction length overflows"))?;
    if !(MIN_TRANSACTION_BYTES..=MAX_TRANSACTION_BYTES).contains(&length) || chain.len() > 128 {
        return Err(FloorAbciError::InvalidTransaction(
            "transaction length is outside bounds",
        ));
    }
    let mut output = Vec::new();
    output
        .try_reserve_exact(length)
        .map_err(|_| FloorAbciError::InvalidTransaction("transaction allocation failed"))?;
    output.extend_from_slice(FLOOR_TRANSACTION_MAGIC);
    output.extend_from_slice(&FLOOR_TRANSACTION_CODEC_VERSION.to_be_bytes());
    output.push(CAS_KIND);
    output.push(if expected.is_some() { EXPECTED_PRESENT } else { 0 });
    output.extend_from_slice(
        &u16::try_from(chain.len())
            .map_err(|_| FloorAbciError::InvalidTransaction("chain identifier exceeds u16"))?
            .to_be_bytes(),
    );
    output.extend_from_slice(chain);
    append_identity(&mut output, authorization.cas().identity())?;
    if let Some(expected) = expected {
        append_checkpoint(&mut output, expected);
    }
    append_checkpoint(&mut output, authorization.cas().next());
    output.extend_from_slice(authorization.actor_key().as_bytes());
    output.extend_from_slice(authorization.nonce().as_bytes());
    output.extend_from_slice(&authorization.target_height().to_be_bytes());
    output.extend_from_slice(authorization.expected_previous_app_hash().as_bytes());
    output.extend_from_slice(request.signature());
    if output.len() != length {
        return Err(FloorAbciError::InvalidTransaction(
            "transaction length invariant failed",
        ));
    }
    Ok(output)
}

/// Decodes, validates, signature-verifies, and canonicality-checks one signed CAS.
pub fn decode_signed_cas(bytes: &[u8]) -> Result<SignedFloorCasRequest> {
    if !(MIN_TRANSACTION_BYTES..=MAX_TRANSACTION_BYTES).contains(&bytes.len()) {
        return Err(FloorAbciError::InvalidTransaction(
            "transaction length is outside bounds",
        ));
    }
    let mut cursor = Cursor::new(bytes);
    if cursor.array::<8>()? != *FLOOR_TRANSACTION_MAGIC
        || cursor.u16()? != FLOOR_TRANSACTION_CODEC_VERSION
        || cursor.u8()? != CAS_KIND
    {
        return Err(FloorAbciError::InvalidTransaction("transaction header is invalid"));
    }
    let flags = cursor.u8()?;
    if flags & !EXPECTED_PRESENT != 0 {
        return Err(FloorAbciError::InvalidTransaction("transaction flags are invalid"));
    }
    let chain_len = usize::from(cursor.u16()?);
    if !(1..=128).contains(&chain_len) {
        return Err(FloorAbciError::InvalidTransaction("chain identifier length is invalid"));
    }
    let mut chain = Vec::new();
    chain
        .try_reserve_exact(chain_len)
        .map_err(|_| FloorAbciError::InvalidTransaction("chain identifier allocation failed"))?;
    chain.extend_from_slice(cursor.take(chain_len)?);
    let chain_id = FloorLedgerChainId::new(chain)
        .map_err(|_| FloorAbciError::InvalidTransaction("chain identifier is invalid"))?;
    let identity = decode_identity(&mut cursor)?;
    let expected = if flags & EXPECTED_PRESENT != 0 {
        Some(decode_checkpoint(&mut cursor)?)
    } else {
        None
    };
    let next = decode_checkpoint(&mut cursor)?;
    let actor = FloorOperatorKey::new(cursor.array::<32>()?)
        .map_err(|_| FloorAbciError::InvalidTransaction("operator key is invalid"))?;
    let nonce = ActorRequestNonce::new(cursor.array::<32>()?)
        .map_err(|_| FloorAbciError::InvalidTransaction("request nonce is invalid"))?;
    let target_height = cursor.u64()?;
    let previous_app_hash = FloorAppHash::new(cursor.array::<32>()?);
    let signature = cursor.array::<64>()?;
    if !cursor.is_empty() {
        return Err(FloorAbciError::InvalidTransaction("transaction has trailing bytes"));
    }
    let cas = FloorCasRequest::new(&chain_id, identity, expected, next)
        .map_err(|_| FloorAbciError::InvalidTransaction("checkpoint transition is invalid"))?;
    let authorization = FloorCasAuthorization::new(cas, actor, nonce, target_height, previous_app_hash)
        .map_err(|_| FloorAbciError::InvalidTransaction("authorization binding is invalid"))?;
    let signed = authorization
        .authorize(signature)
        .map_err(|_| FloorAbciError::InvalidTransaction("BIP340 signature is invalid"))?;
    if encode_signed_cas(&signed)? != bytes {
        return Err(FloorAbciError::InvalidTransaction("transaction is not canonical"));
    }
    Ok(signed)
}

fn append_identity(output: &mut Vec<u8>, identity: VaultIdentity) -> Result<()> {
    output.push(match identity.network() {
        Network::Regtest => 1,
        Network::Signet => 2,
        Network::Testnet => 3,
        Network::Mainnet => return Err(FloorAbciError::InvalidTransaction("Mainnet is disabled")),
    });
    output.push(match identity.role() {
        VaultRole::Holder => 1,
        VaultRole::CommitteeMember => 2,
    });
    output.extend_from_slice(identity.node_id().as_bytes());
    output.extend_from_slice(identity.deployment().deployment_id().as_bytes());
    output.extend_from_slice(&identity.deployment().committee_epoch().to_be_bytes());
    output.extend_from_slice(identity.deployment().committee_descriptor().as_bytes());
    Ok(())
}

fn decode_identity(cursor: &mut Cursor<'_>) -> Result<VaultIdentity> {
    let network = match cursor.u8()? {
        1 => Network::Regtest,
        2 => Network::Signet,
        3 => Network::Testnet,
        4 => return Err(FloorAbciError::InvalidTransaction("Mainnet is disabled")),
        _ => return Err(FloorAbciError::InvalidTransaction("network tag is invalid")),
    };
    let role = match cursor.u8()? {
        1 => VaultRole::Holder,
        2 => VaultRole::CommitteeMember,
        _ => return Err(FloorAbciError::InvalidTransaction("role tag is invalid")),
    };
    let node = NodeId::new(cursor.array::<32>()?);
    let deployment = DeploymentId::new(cursor.array::<32>()?)
        .map_err(|_| FloorAbciError::InvalidTransaction("deployment identifier is invalid"))?;
    let epoch = cursor.u64()?;
    let descriptor = CommitteeDescriptorDigest::new(cursor.array::<32>()?)
        .map_err(|_| FloorAbciError::InvalidTransaction("committee descriptor is invalid"))?;
    let binding = DeploymentBinding::new(deployment, epoch, descriptor)
        .map_err(|_| FloorAbciError::InvalidTransaction("deployment binding is invalid"))?;
    Ok(VaultIdentity::new(network, role, node, binding))
}

fn append_checkpoint(output: &mut Vec<u8>, checkpoint: VaultCheckpoint) {
    output.extend_from_slice(&checkpoint.revision().get().to_be_bytes());
    output.extend_from_slice(checkpoint.state_digest().as_bytes());
}

fn decode_checkpoint(cursor: &mut Cursor<'_>) -> Result<VaultCheckpoint> {
    Ok(VaultCheckpoint::new(
        VaultRevision::new(cursor.u64()?),
        VaultStateDigest::new(cursor.array::<32>()?),
    ))
}

struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8]> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(FloorAbciError::InvalidTransaction("transaction cursor overflows"))?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(FloorAbciError::InvalidTransaction("transaction is truncated"))?;
        self.offset = end;
        Ok(value)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        self.take(N)?
            .try_into()
            .map_err(|_| FloorAbciError::InvalidTransaction("transaction field width is invalid"))
    }

    fn u8(&mut self) -> Result<u8> {
        self.take(1)?
            .first()
            .copied()
            .ok_or(FloorAbciError::InvalidTransaction("transaction byte is missing"))
    }

    fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_be_bytes(self.array()?))
    }

    fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_be_bytes(self.array()?))
    }

    fn is_empty(&self) -> bool {
        self.offset == self.bytes.len()
    }
}
