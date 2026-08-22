use bitcoin::Network;
use serde::{Deserialize, Deserializer, Serialize};
use sha2::{Digest, Sha256};
use thunderbolt_core::zkp::ProofContext;

use crate::codec::{CanonicalDigest, CanonicalHasher, ValidateWire};
use crate::hex::HexBytes;
use crate::{Result, WireError};

pub const PROTOCOL_VERSION: u16 = 1;
pub const MAX_DEPLOYMENT_ID_BYTES: usize = 64;
/// Canonical Bitcoin outpoint width: 32-byte txid plus 4-byte vout.
pub const MAX_CHANNEL_ID_BYTES: usize = 36;
/// Matches the protocol-layer invoice identifier bound.
pub const MAX_INVOICE_ID_BYTES: usize = 128;

pub type DeploymentId = HexBytes<1, MAX_DEPLOYMENT_ID_BYTES>;
pub type ChannelId = HexBytes<1, MAX_CHANNEL_ID_BYTES>;
pub type InvoiceId = HexBytes<1, MAX_INVOICE_ID_BYTES>;

/// Public domain separation shared by every statement and proof envelope.
///
/// `deployment_id`, `channel_id`, and `invoice_id` are opaque byte identifiers
/// rendered as lowercase hex. `step` is absent for invoice/share/threshold
/// proofs and present for transfers.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BindingContext {
    pub protocol_version: u16,
    pub network: Network,
    pub deployment_id: DeploymentId,
    pub committee_epoch: u64,
    pub channel_id: ChannelId,
    pub invoice_id: InvoiceId,
    pub step: Option<u64>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BindingContextInput {
    protocol_version: u16,
    network: Network,
    deployment_id: DeploymentId,
    committee_epoch: u64,
    channel_id: ChannelId,
    invoice_id: InvoiceId,
    step: Option<u64>,
}

impl<'de> Deserialize<'de> for BindingContext {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let input = BindingContextInput::deserialize(deserializer)?;
        if input.protocol_version != PROTOCOL_VERSION {
            return Err(serde::de::Error::custom(WireError::UnsupportedVersion {
                expected: PROTOCOL_VERSION,
                actual: input.protocol_version,
            }));
        }
        Ok(Self {
            protocol_version: input.protocol_version,
            network: input.network,
            deployment_id: input.deployment_id,
            committee_epoch: input.committee_epoch,
            channel_id: input.channel_id,
            invoice_id: input.invoice_id,
            step: input.step,
        })
    }
}

impl BindingContext {
    pub fn new(
        network: Network,
        deployment_id: impl AsRef<[u8]>,
        committee_epoch: u64,
        channel_id: impl AsRef<[u8]>,
        invoice_id: impl AsRef<[u8]>,
        step: Option<u64>,
    ) -> Result<Self> {
        Ok(Self {
            protocol_version: PROTOCOL_VERSION,
            network,
            deployment_id: DeploymentId::from_bytes("deployment_id", deployment_id)?,
            committee_epoch,
            channel_id: ChannelId::from_bytes("channel_id", channel_id)?,
            invoice_id: InvoiceId::from_bytes("invoice_id", invoice_id)?,
            step,
        })
    }

    pub fn invoice(
        network: Network,
        deployment_id: impl AsRef<[u8]>,
        committee_epoch: u64,
        channel_id: impl AsRef<[u8]>,
        invoice_id: impl AsRef<[u8]>,
    ) -> Result<Self> {
        Self::new(network, deployment_id, committee_epoch, channel_id, invoice_id, None)
    }

    pub fn transfer(
        network: Network,
        deployment_id: impl AsRef<[u8]>,
        committee_epoch: u64,
        channel_id: impl AsRef<[u8]>,
        invoice_id: impl AsRef<[u8]>,
        step: u64,
    ) -> Result<Self> {
        Self::new(
            network,
            deployment_id,
            committee_epoch,
            channel_id,
            invoice_id,
            Some(step),
        )
    }

    /// Hash all deployment and protocol fields into the core `ctx_id`.
    pub fn context_id(&self) -> Result<[u8; 32]> {
        self.validate_wire()?;
        let mut hasher = Sha256::new();
        hasher.update(b"bitcoin-thunderbolt/proof-binding/v1");
        append_len_prefixed(&mut hasher, &self.protocol_version.to_be_bytes());
        append_len_prefixed(&mut hasher, &[network_code(self.network)]);
        append_len_prefixed(&mut hasher, self.deployment_id.as_bytes());
        append_len_prefixed(&mut hasher, &self.committee_epoch.to_be_bytes());
        append_len_prefixed(&mut hasher, self.channel_id.as_bytes());
        append_len_prefixed(&mut hasher, self.invoice_id.as_bytes());
        match self.step {
            Some(step) => {
                append_len_prefixed(&mut hasher, &[1]);
                append_len_prefixed(&mut hasher, &step.to_be_bytes());
            }
            None => append_len_prefixed(&mut hasher, &[0]),
        }
        Ok(hasher.finalize().into())
    }

    pub fn proof_context(&self) -> Result<ProofContext> {
        let context_id = self.context_id()?;
        Ok(match self.step {
            Some(step) => ProofContext::transfer(context_id, step, self.invoice_id.as_bytes()),
            None => ProofContext::invoice(context_id, self.invoice_id.as_bytes()),
        })
    }

    pub fn require_invoice_scope(&self) -> Result<()> {
        self.validate_wire()?;
        if self.step.is_some() {
            return Err(WireError::InvalidBinding {
                reason: "invoice, share, and threshold messages must not carry a transfer step",
            });
        }
        Ok(())
    }

    pub fn require_transfer_scope(&self) -> Result<u64> {
        self.validate_wire()?;
        self.step.ok_or(WireError::InvalidBinding {
            reason: "transfer messages must carry an explicit step",
        })
    }

    pub fn matches_core(&self, context: &ProofContext) -> Result<()> {
        let expected = self.proof_context()?;
        if expected.ctx_id() != context.ctx_id()
            || expected.inv_id() != context.inv_id()
            || expected.step() != context.step()
        {
            return Err(WireError::InvalidBinding {
                reason: "wire binding does not match the core proof context",
            });
        }
        Ok(())
    }

    pub(crate) fn append_canonical(&self, hasher: &mut CanonicalHasher) {
        hasher.u16(self.protocol_version);
        hasher.u8(network_code(self.network));
        hasher.bytes(self.deployment_id.as_bytes());
        hasher.u64(self.committee_epoch);
        hasher.bytes(self.channel_id.as_bytes());
        hasher.bytes(self.invoice_id.as_bytes());
        match self.step {
            Some(step) => {
                hasher.u8(1);
                hasher.u64(step);
            }
            None => hasher.u8(0),
        }
    }
}

impl ValidateWire for BindingContext {
    fn validate_wire(&self) -> Result<()> {
        if self.protocol_version != PROTOCOL_VERSION {
            return Err(WireError::UnsupportedVersion {
                expected: PROTOCOL_VERSION,
                actual: self.protocol_version,
            });
        }
        Ok(())
    }
}

impl CanonicalDigest for BindingContext {
    fn canonical_digest(&self) -> Result<[u8; 32]> {
        self.validate_wire()?;
        let mut hasher = CanonicalHasher::new(b"binding_context");
        self.append_canonical(&mut hasher);
        Ok(hasher.finish())
    }
}

fn append_len_prefixed(hasher: &mut Sha256, value: &[u8]) {
    hasher.update((value.len() as u64).to_be_bytes());
    hasher.update(value);
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
