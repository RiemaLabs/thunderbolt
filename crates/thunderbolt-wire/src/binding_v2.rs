use bitcoin::Network;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};
use thunderbolt_core::zkp::ProofContext;

use crate::codec::{CanonicalDigest, CanonicalHasher, ValidateWire};
use crate::hex::HexBytes;
use crate::{DeploymentId, InvoiceId, Result, WireError};

/// Protocol version carried by stable version 2 channel bindings.
pub const PROTOCOL_VERSION_V2: u16 = 2;
/// Exact byte width of a canonical funding outpoint.
pub const FUNDING_OUTPOINT_BYTES: usize = 36;
/// Exact byte width of every version 2 suite, descriptor, or chain identifier.
pub const BINDING_ID_BYTES: usize = 32;

macro_rules! fixed_binding_id {
    ($(#[$meta:meta])* $name:ident, $field:literal) => {
        $(#[$meta])*
        #[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(HexBytes<BINDING_ID_BYTES, BINDING_ID_BYTES>);

        impl $name {
            /// Parses an exact, non-zero 32-byte identifier.
            pub fn from_bytes(bytes: impl AsRef<[u8]>) -> Result<Self> {
                let value = HexBytes::from_bytes($field, bytes)?;
                if value.as_bytes().iter().all(|byte| *byte == 0) {
                    return Err(WireError::InvalidBinding {
                        reason: concat!($field, " must not be all zero"),
                    });
                }
                Ok(Self(value))
            }

            /// Borrows the canonical 32-byte identifier.
            pub fn as_bytes(&self) -> &[u8] {
                self.0.as_bytes()
            }

            /// Returns lowercase hexadecimal for configuration and logs.
            pub fn to_hex(&self) -> String {
                self.0.to_hex()
            }
        }

        impl std::fmt::Debug for $name {
            fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.debug_tuple(stringify!($name)).field(&self.to_hex()).finish()
            }
        }

        impl Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                self.0.serialize(serializer)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                let value = HexBytes::<BINDING_ID_BYTES, BINDING_ID_BYTES>::deserialize(deserializer)?;
                Self::from_bytes(value.as_bytes()).map_err(serde::de::Error::custom)
            }
        }
    };
}

fixed_binding_id!(
    /// Digest of the canonical protocol-suite descriptor selected by the deployment.
    ProtocolSuiteIdV2,
    "protocol_suite_id"
);
fixed_binding_id!(
    /// Display-order bytes of the exact Bitcoin genesis block pinned by the deployment.
    BitcoinGenesisHashV2,
    "bitcoin_genesis_hash"
);
fixed_binding_id!(
    /// Digest of the complete, ordered committee descriptor for this epoch.
    CommitteeDescriptorDigestV2,
    "committee_descriptor_digest"
);
fixed_binding_id!(
    /// Digest of the canonical anchor parameter-suite descriptor, including its base.
    AnchorParameterSuiteIdV2,
    "anchor_parameter_suite_id"
);

/// A funding outpoint encoded as display-order txid bytes and a `u32` vout.
///
/// Its canonical 36-byte representation is the 32 txid bytes followed by the
/// output index in big-endian order. This matches
/// `thunderbolt_protocol::ChannelId::canonical_bytes` without introducing a
/// dependency from the wire crate back to the protocol crate.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FundingOutpointV2 {
    txid: HexBytes<32, 32>,
    vout: u32,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FundingOutpointV2Input {
    txid: HexBytes<32, 32>,
    vout: u32,
}

impl<'de> Deserialize<'de> for FundingOutpointV2 {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let input = FundingOutpointV2Input::deserialize(deserializer)?;
        Self::new(input.txid.as_bytes(), input.vout).map_err(serde::de::Error::custom)
    }
}

impl FundingOutpointV2 {
    /// Constructs an outpoint from a display-order transaction id and vout.
    pub fn new(txid: impl AsRef<[u8]>, vout: u32) -> Result<Self> {
        let txid = HexBytes::from_bytes("funding_outpoint.txid", txid)?;
        if vout == u32::MAX && txid.as_bytes().iter().all(|byte| *byte == 0) {
            return Err(WireError::InvalidBinding {
                reason: "funding outpoint must not be Bitcoin's null outpoint",
            });
        }
        Ok(Self { txid, vout })
    }

    /// Parses the canonical 36-byte funding-outpoint encoding.
    pub fn from_canonical_bytes(bytes: impl AsRef<[u8]>) -> Result<Self> {
        let bytes = bytes.as_ref();
        if bytes.len() != FUNDING_OUTPOINT_BYTES {
            return Err(WireError::InvalidLength {
                field: "funding_outpoint",
                min: FUNDING_OUTPOINT_BYTES,
                max: FUNDING_OUTPOINT_BYTES,
                actual: bytes.len(),
            });
        }
        let mut vout = [0_u8; 4];
        vout.copy_from_slice(&bytes[32..]);
        Self::new(&bytes[..32], u32::from_be_bytes(vout))
    }

    /// Borrows the display-order funding transaction id bytes.
    pub fn txid(&self) -> &[u8] {
        self.txid.as_bytes()
    }

    /// Returns the funding output index.
    pub const fn vout(&self) -> u32 {
        self.vout
    }

    /// Returns display-order txid bytes followed by big-endian vout.
    pub fn canonical_bytes(&self) -> [u8; FUNDING_OUTPOINT_BYTES] {
        let mut bytes = [0_u8; FUNDING_OUTPOINT_BYTES];
        bytes[..32].copy_from_slice(self.txid.as_bytes());
        bytes[32..].copy_from_slice(&self.vout.to_be_bytes());
        bytes
    }
}

/// Stable deployment and channel scope for version 2 proof contexts.
///
/// The resulting `context_id` deliberately excludes invoice identifiers and
/// transfer steps. Those values live in [`OperationBindingV2`] and remain
/// explicit inputs to the core proof transcript.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ChannelBindingV2 {
    pub protocol_version: u16,
    pub protocol_suite_id: ProtocolSuiteIdV2,
    pub network: Network,
    pub bitcoin_genesis_hash: BitcoinGenesisHashV2,
    pub deployment_id: DeploymentId,
    pub funding_outpoint: FundingOutpointV2,
    pub committee_epoch: u64,
    pub committee_descriptor_digest: CommitteeDescriptorDigestV2,
    pub anchor_parameter_suite_id: AnchorParameterSuiteIdV2,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ChannelBindingV2Input {
    protocol_version: u16,
    protocol_suite_id: ProtocolSuiteIdV2,
    network: Network,
    bitcoin_genesis_hash: BitcoinGenesisHashV2,
    deployment_id: DeploymentId,
    funding_outpoint: FundingOutpointV2,
    committee_epoch: u64,
    committee_descriptor_digest: CommitteeDescriptorDigestV2,
    anchor_parameter_suite_id: AnchorParameterSuiteIdV2,
}

impl<'de> Deserialize<'de> for ChannelBindingV2 {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let input = ChannelBindingV2Input::deserialize(deserializer)?;
        let binding = Self {
            protocol_version: input.protocol_version,
            protocol_suite_id: input.protocol_suite_id,
            network: input.network,
            bitcoin_genesis_hash: input.bitcoin_genesis_hash,
            deployment_id: input.deployment_id,
            funding_outpoint: input.funding_outpoint,
            committee_epoch: input.committee_epoch,
            committee_descriptor_digest: input.committee_descriptor_digest,
            anchor_parameter_suite_id: input.anchor_parameter_suite_id,
        };
        binding.validate_wire().map_err(serde::de::Error::custom)?;
        Ok(binding)
    }
}

impl ChannelBindingV2 {
    /// Constructs a complete, stable channel binding.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        protocol_suite_id: ProtocolSuiteIdV2,
        network: Network,
        bitcoin_genesis_hash: BitcoinGenesisHashV2,
        deployment_id: impl AsRef<[u8]>,
        funding_outpoint: FundingOutpointV2,
        committee_epoch: u64,
        committee_descriptor_digest: CommitteeDescriptorDigestV2,
        anchor_parameter_suite_id: AnchorParameterSuiteIdV2,
    ) -> Result<Self> {
        let binding = Self {
            protocol_version: PROTOCOL_VERSION_V2,
            protocol_suite_id,
            network,
            bitcoin_genesis_hash,
            deployment_id: DeploymentId::from_bytes("deployment_id", deployment_id)?,
            funding_outpoint,
            committee_epoch,
            committee_descriptor_digest,
            anchor_parameter_suite_id,
        };
        binding.validate_wire()?;
        Ok(binding)
    }

    /// Hashes only stable deployment and channel fields into the core `ctx_id`.
    pub fn context_id(&self) -> Result<[u8; 32]> {
        self.validate_wire()?;
        let mut hasher = Sha256::new();
        append_len_prefixed(&mut hasher, b"bitcoin-thunderbolt/stable-channel-binding/v2");
        append_len_prefixed(&mut hasher, &self.protocol_version.to_be_bytes());
        append_len_prefixed(&mut hasher, self.protocol_suite_id.as_bytes());
        append_len_prefixed(&mut hasher, &[network_code(self.network)]);
        append_len_prefixed(&mut hasher, self.bitcoin_genesis_hash.as_bytes());
        append_len_prefixed(&mut hasher, self.deployment_id.as_bytes());
        append_len_prefixed(&mut hasher, &self.funding_outpoint.canonical_bytes());
        append_len_prefixed(&mut hasher, &self.committee_epoch.to_be_bytes());
        append_len_prefixed(&mut hasher, self.committee_descriptor_digest.as_bytes());
        append_len_prefixed(&mut hasher, self.anchor_parameter_suite_id.as_bytes());
        Ok(hasher.finalize().into())
    }

    fn append_canonical(&self, hasher: &mut CanonicalHasher) {
        hasher.u16(self.protocol_version);
        hasher.bytes(self.protocol_suite_id.as_bytes());
        hasher.u8(network_code(self.network));
        hasher.bytes(self.bitcoin_genesis_hash.as_bytes());
        hasher.bytes(self.deployment_id.as_bytes());
        hasher.bytes(&self.funding_outpoint.canonical_bytes());
        hasher.u64(self.committee_epoch);
        hasher.bytes(self.committee_descriptor_digest.as_bytes());
        hasher.bytes(self.anchor_parameter_suite_id.as_bytes());
    }
}

impl ValidateWire for ChannelBindingV2 {
    fn validate_wire(&self) -> Result<()> {
        if self.protocol_version != PROTOCOL_VERSION_V2 {
            return Err(WireError::UnsupportedVersion {
                expected: PROTOCOL_VERSION_V2,
                actual: self.protocol_version,
            });
        }
        if self.committee_epoch == 0 {
            return Err(WireError::InvalidBinding {
                reason: "committee_epoch must be positive",
            });
        }
        Ok(())
    }
}

impl CanonicalDigest for ChannelBindingV2 {
    fn canonical_digest(&self) -> Result<[u8; 32]> {
        self.validate_wire()?;
        let mut hasher = CanonicalHasher::new(b"channel_binding_v2");
        self.append_canonical(&mut hasher);
        Ok(hasher.finish())
    }
}

/// Operation-specific proof scope layered over a stable channel binding.
///
/// The tagged enum makes it impossible to construct an invoice with a step or
/// a transfer without one through the public constructors or JSON codec.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub enum OperationBindingV2 {
    Invoice {
        channel: ChannelBindingV2,
        invoice_id: InvoiceId,
    },
    Transfer {
        channel: ChannelBindingV2,
        invoice_id: InvoiceId,
        step: u64,
    },
}

#[derive(Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
enum OperationBindingV2Input {
    Invoice {
        channel: ChannelBindingV2,
        invoice_id: InvoiceId,
    },
    Transfer {
        channel: ChannelBindingV2,
        invoice_id: InvoiceId,
        step: u64,
    },
}

impl<'de> Deserialize<'de> for OperationBindingV2 {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let input = OperationBindingV2Input::deserialize(deserializer)?;
        let binding = match input {
            OperationBindingV2Input::Invoice { channel, invoice_id } => Self::Invoice { channel, invoice_id },
            OperationBindingV2Input::Transfer {
                channel,
                invoice_id,
                step,
            } => Self::Transfer {
                channel,
                invoice_id,
                step,
            },
        };
        binding.validate_wire().map_err(serde::de::Error::custom)?;
        Ok(binding)
    }
}

impl OperationBindingV2 {
    /// Creates an invoice binding over a stable channel context.
    pub fn invoice(channel: ChannelBindingV2, invoice_id: impl AsRef<[u8]>) -> Result<Self> {
        channel.validate_wire()?;
        Ok(Self::Invoice {
            channel,
            invoice_id: InvoiceId::from_bytes("invoice_id", invoice_id)?,
        })
    }

    /// Creates a transfer binding over a stable channel context.
    pub fn transfer(channel: ChannelBindingV2, invoice_id: impl AsRef<[u8]>, step: u64) -> Result<Self> {
        channel.validate_wire()?;
        if step == 0 {
            return Err(WireError::InvalidBinding {
                reason: "transfer step must be positive",
            });
        }
        Ok(Self::Transfer {
            channel,
            invoice_id: InvoiceId::from_bytes("invoice_id", invoice_id)?,
            step,
        })
    }

    /// Returns the stable channel scope shared by all channel operations.
    pub const fn channel(&self) -> &ChannelBindingV2 {
        match self {
            Self::Invoice { channel, .. } | Self::Transfer { channel, .. } => channel,
        }
    }

    /// Returns the operation's recipient-generated invoice identifier.
    pub const fn invoice_id(&self) -> &InvoiceId {
        match self {
            Self::Invoice { invoice_id, .. } | Self::Transfer { invoice_id, .. } => invoice_id,
        }
    }

    /// Returns the transfer step, or `None` for an invoice.
    pub const fn step(&self) -> Option<u64> {
        match self {
            Self::Invoice { .. } => None,
            Self::Transfer { step, .. } => Some(*step),
        }
    }

    /// Builds the core proof context with a stable channel `ctx_id`.
    pub fn proof_context(&self) -> Result<ProofContext> {
        self.validate_wire()?;
        let context_id = self.channel().context_id()?;
        Ok(match self {
            Self::Invoice { invoice_id, .. } => ProofContext::invoice(context_id, invoice_id.as_bytes()),
            Self::Transfer { invoice_id, step, .. } => ProofContext::transfer(context_id, *step, invoice_id.as_bytes()),
        })
    }

    /// Rejects a core proof context that differs in channel, invoice, or step.
    pub fn matches_core(&self, context: &ProofContext) -> Result<()> {
        let expected = self.proof_context()?;
        if expected.ctx_id() != context.ctx_id()
            || expected.inv_id() != context.inv_id()
            || expected.step() != context.step()
        {
            return Err(WireError::InvalidBinding {
                reason: "version 2 wire binding does not match the core proof context",
            });
        }
        Ok(())
    }
}

impl ValidateWire for OperationBindingV2 {
    fn validate_wire(&self) -> Result<()> {
        self.channel().validate_wire()?;
        if matches!(self, Self::Transfer { step: 0, .. }) {
            return Err(WireError::InvalidBinding {
                reason: "transfer step must be positive",
            });
        }
        Ok(())
    }
}

impl CanonicalDigest for OperationBindingV2 {
    fn canonical_digest(&self) -> Result<[u8; 32]> {
        self.validate_wire()?;
        let mut hasher = CanonicalHasher::new(b"operation_binding_v2");
        self.channel().append_canonical(&mut hasher);
        match self {
            Self::Invoice { invoice_id, .. } => {
                hasher.u8(0);
                hasher.bytes(invoice_id.as_bytes());
            }
            Self::Transfer { invoice_id, step, .. } => {
                hasher.u8(1);
                hasher.bytes(invoice_id.as_bytes());
                hasher.u64(*step);
            }
        }
        Ok(hasher.finish())
    }
}

fn append_len_prefixed(hasher: &mut Sha256, value: &[u8]) {
    hasher.update(u64::try_from(value.len()).unwrap_or(u64::MAX).to_be_bytes());
    hasher.update(value);
}

const fn network_code(network: Network) -> u8 {
    match network {
        Network::Bitcoin => 0,
        Network::Testnet => 1,
        Network::Testnet4 => 2,
        Network::Signet => 3,
        Network::Regtest => 4,
    }
}
