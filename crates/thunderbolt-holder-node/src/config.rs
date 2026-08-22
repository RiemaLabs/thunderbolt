use std::time::Duration;

use bitcoin::Network;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use thunderbolt_ledger::{LedgerChainIdV2, MAX_SIGNED_PROPOSAL_JSON_BYTES};
use thunderbolt_wire::{ChannelBindingV2, ValidateWire as _};

use crate::{HolderNodeError, Result};

/// Maximum retained outbox rows, including finalized rows.
pub const MAX_OUTBOX_ROWS: usize = 10_000;
/// Maximum retained local command aliases.
pub const MAX_COMMAND_ROWS: usize = 20_000;
/// Maximum encoded signed proposal stored in one row.
pub const MAX_PROPOSAL_BYTES: usize = MAX_SIGNED_PROPOSAL_JSON_BYTES;
/// Maximum receipts accepted in one finality poll.
pub const MAX_FINALITY_BATCH: usize = 128;
const MAX_BUSY_TIMEOUT: Duration = Duration::from_secs(60);

/// Bounded exponential retry policy for Ledger submission.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetryPolicy {
    pub initial_delay_ms: u64,
    pub maximum_delay_ms: u64,
    pub maximum_attempts: u32,
}

impl RetryPolicy {
    pub fn validate(self) -> Result<Self> {
        if self.initial_delay_ms == 0
            || self.maximum_delay_ms < self.initial_delay_ms
            || self.maximum_delay_ms > 3_600_000
            || self.maximum_attempts == 0
            || self.maximum_attempts > 1_000
        {
            return Err(HolderNodeError::InvalidConfiguration(
                "retry policy is outside safety bounds",
            ));
        }
        Ok(self)
    }

    pub(crate) fn delay_after(self, attempts: u32) -> u64 {
        let shift = attempts.saturating_sub(1).min(31);
        self.initial_delay_ms
            .saturating_mul(1_u64 << shift)
            .min(self.maximum_delay_ms)
    }
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            initial_delay_ms: 1_000,
            maximum_delay_ms: 60_000,
            maximum_attempts: 12,
        }
    }
}

/// Validated Holder service configuration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HolderNodeConfig {
    network: Network,
    ledger_chain_id: LedgerChainIdV2,
    deployment: HolderDeploymentPolicy,
    retry: RetryPolicy,
    submit_batch: usize,
    finality_batch: usize,
    busy_timeout: Duration,
}

impl HolderNodeConfig {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        network: Network,
        ledger_chain_id: LedgerChainIdV2,
        deployment: HolderDeploymentPolicy,
        retry: RetryPolicy,
        submit_batch: usize,
        finality_batch: usize,
        busy_timeout: Duration,
    ) -> Result<Self> {
        if matches!(network, Network::Bitcoin | Network::Testnet4) {
            return Err(HolderNodeError::InvalidConfiguration(
                "mainnet and Testnet4 Holder services are disabled",
            ));
        }
        if deployment.network != network {
            return Err(HolderNodeError::InvalidConfiguration(
                "deployment policy network does not match service network",
            ));
        }
        if submit_batch == 0
            || submit_batch > MAX_FINALITY_BATCH
            || finality_batch == 0
            || finality_batch > MAX_FINALITY_BATCH
        {
            return Err(HolderNodeError::InvalidConfiguration(
                "batch size is outside safety bounds",
            ));
        }
        if busy_timeout.is_zero() || busy_timeout > MAX_BUSY_TIMEOUT {
            return Err(HolderNodeError::InvalidConfiguration(
                "SQLite busy timeout is outside safety bounds",
            ));
        }
        Ok(Self {
            network,
            ledger_chain_id,
            deployment,
            retry: retry.validate()?,
            submit_batch,
            finality_batch,
            busy_timeout,
        })
    }

    pub const fn network(&self) -> Network {
        self.network
    }

    pub const fn ledger_chain_id(&self) -> &LedgerChainIdV2 {
        &self.ledger_chain_id
    }

    pub const fn deployment(&self) -> &HolderDeploymentPolicy {
        &self.deployment
    }

    pub const fn retry(&self) -> RetryPolicy {
        self.retry
    }

    pub const fn submit_batch(&self) -> usize {
        self.submit_batch
    }

    pub const fn finality_batch(&self) -> usize {
        self.finality_batch
    }

    pub const fn busy_timeout(&self) -> Duration {
        self.busy_timeout
    }
}

/// Exact deployment/committee/suite scope accepted by this Holder process.
/// Funding outpoints are deliberately excluded so one deployment can host
/// multiple channels.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HolderDeploymentPolicy {
    network: Network,
    protocol_suite_id: Vec<u8>,
    bitcoin_genesis_hash: Vec<u8>,
    deployment_id: Vec<u8>,
    committee_epoch: u64,
    committee_descriptor_digest: Vec<u8>,
    anchor_parameter_suite_id: Vec<u8>,
}

impl HolderDeploymentPolicy {
    pub fn from_channel(channel: &ChannelBindingV2) -> Result<Self> {
        channel
            .validate_wire()
            .map_err(|_| HolderNodeError::InvalidConfiguration("invalid deployment channel template"))?;
        Ok(Self {
            network: channel.network,
            protocol_suite_id: channel.protocol_suite_id.as_bytes().to_vec(),
            bitcoin_genesis_hash: channel.bitcoin_genesis_hash.as_bytes().to_vec(),
            deployment_id: channel.deployment_id.as_bytes().to_vec(),
            committee_epoch: channel.committee_epoch,
            committee_descriptor_digest: channel.committee_descriptor_digest.as_bytes().to_vec(),
            anchor_parameter_suite_id: channel.anchor_parameter_suite_id.as_bytes().to_vec(),
        })
    }

    pub fn matches(&self, channel: &ChannelBindingV2) -> bool {
        channel.validate_wire().is_ok()
            && channel.network == self.network
            && channel.protocol_suite_id.as_bytes() == self.protocol_suite_id
            && channel.bitcoin_genesis_hash.as_bytes() == self.bitcoin_genesis_hash
            && channel.deployment_id.as_bytes() == self.deployment_id
            && channel.committee_epoch == self.committee_epoch
            && channel.committee_descriptor_digest.as_bytes() == self.committee_descriptor_digest
            && channel.anchor_parameter_suite_id.as_bytes() == self.anchor_parameter_suite_id
    }

    pub(crate) fn digest(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"bitcoin-thunderbolt/holder-node/deployment-policy/v1");
        hasher.update([network_tag(self.network)]);
        append(&mut hasher, &self.protocol_suite_id);
        append(&mut hasher, &self.bitcoin_genesis_hash);
        append(&mut hasher, &self.deployment_id);
        hasher.update(self.committee_epoch.to_be_bytes());
        append(&mut hasher, &self.committee_descriptor_digest);
        append(&mut hasher, &self.anchor_parameter_suite_id);
        hasher.finalize().into()
    }
}

fn append(hasher: &mut Sha256, value: &[u8]) {
    hasher.update((value.len() as u64).to_be_bytes());
    hasher.update(value);
}

fn network_tag(network: Network) -> u8 {
    match network {
        Network::Bitcoin => 0,
        Network::Testnet => 1,
        Network::Testnet4 => 2,
        Network::Signet => 3,
        Network::Regtest => 4,
    }
}
