use std::collections::HashSet;

use sha2::{Digest, Sha256};
use tendermint_proto::v0_38::abci::ValidatorUpdate;
use tendermint_proto::v0_38::crypto::public_key;
use thunderbolt_floor::FloorLedgerChainId;
use thunderbolt_floor_app::FloorGenesis;

use crate::{compiled_resource_profile_values, FloorAbciError, Result, APPLICATION_VERSION, MAX_COMMIT_VOTES};

const VALIDATOR_DOMAIN: &[u8] = b"bitcoin-thunderbolt/floor-abci/validator-genesis/v2";
const PROFILE_DOMAIN: &[u8] = b"bitcoin-thunderbolt/floor-abci/consensus-profile/v2";
const GENESIS_MAGIC: &[u8; 8] = b"TBFLGEN2";
const MAX_TOTAL_VOTING_POWER: u64 = (i64::MAX / 8) as u64;

/// Exact bounded ordered validator set admitted by InitChain.
#[derive(Clone, Debug, PartialEq)]
pub struct FloorValidatorGenesisV2 {
    validators: Vec<ValidatorUpdate>,
    digest: [u8; 32],
}

impl FloorValidatorGenesisV2 {
    /// Validates an exact nonempty Ed25519 validator list and voting-power bound.
    pub fn new(validators: Vec<ValidatorUpdate>) -> Result<Self> {
        if validators.is_empty() || validators.len() > MAX_COMMIT_VOTES {
            return Err(FloorAbciError::InvalidRequest(
                "genesis validator count is outside bounds",
            ));
        }
        let mut keys = HashSet::with_capacity(validators.len());
        let mut total_power = 0_u64;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(VALIDATOR_DOMAIN.len() + 8 + validators.len() * 41)
            .map_err(|_| FloorAbciError::InvalidRequest("validator profile allocation failed"))?;
        bytes.extend_from_slice(VALIDATOR_DOMAIN);
        bytes.extend_from_slice(
            &u64::try_from(validators.len())
                .map_err(|_| FloorAbciError::InvalidRequest("validator count exceeds u64"))?
                .to_be_bytes(),
        );
        for validator in &validators {
            let key = match validator.pub_key.as_ref().and_then(|key| key.sum.as_ref()) {
                Some(public_key::Sum::Ed25519(key)) if key.len() == 32 => <[u8; 32]>::try_from(key.as_slice())
                    .map_err(|_| FloorAbciError::InvalidRequest("validator key width is invalid"))?,
                _ => {
                    return Err(FloorAbciError::InvalidRequest(
                        "only 32-byte Ed25519 validators are supported",
                    ))
                }
            };
            if tendermint::PublicKey::from_raw_ed25519(&key).is_none() {
                return Err(FloorAbciError::InvalidRequest("validator Ed25519 key is malformed"));
            }
            if validator.power <= 0 || !keys.insert(key) {
                return Err(FloorAbciError::InvalidRequest(
                    "validator key or voting power is invalid",
                ));
            }
            let power = u64::try_from(validator.power)
                .map_err(|_| FloorAbciError::InvalidRequest("validator power is negative"))?;
            total_power = total_power
                .checked_add(power)
                .filter(|total| *total <= MAX_TOTAL_VOTING_POWER)
                .ok_or(FloorAbciError::InvalidRequest(
                    "total validator power exceeds CometBFT bound",
                ))?;
            bytes.extend_from_slice(&key);
            bytes.extend_from_slice(&validator.power.to_be_bytes());
        }
        Ok(Self {
            validators,
            digest: Sha256::digest(bytes).into(),
        })
    }

    /// Returns validators in exact consensus genesis order.
    pub fn validators(&self) -> &[ValidatorUpdate] {
        &self.validators
    }

    /// Returns the canonical ordered validator-set digest.
    pub const fn digest(&self) -> &[u8; 32] {
        &self.digest
    }
}

/// Immutable digest binding chain, validator policy, and compiled ABCI resources.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct FloorConsensusProfileV2 {
    digest: [u8; 32],
    validator_digest: [u8; 32],
}

impl FloorConsensusProfileV2 {
    /// Derives the profile used to construct `FloorGenesis.profile_digest`.
    pub fn derive(chain_id: &FloorLedgerChainId, validators: &FloorValidatorGenesisV2) -> Result<Self> {
        crate::validate_compiled_resource_limits()?;
        let chain = chain_id.as_bytes();
        let mut hasher = Sha256::new();
        hasher.update(PROFILE_DOMAIN);
        hasher.update(
            u64::try_from(chain.len())
                .map_err(|_| FloorAbciError::InvalidRequest("floor chain length exceeds u64"))?
                .to_be_bytes(),
        );
        hasher.update(chain);
        hasher.update(validators.digest());
        for value in compiled_resource_profile_values() {
            hasher.update(value.to_be_bytes());
        }
        Ok(Self {
            digest: hasher.finalize().into(),
            validator_digest: *validators.digest(),
        })
    }

    /// Returns the exact digest required by FloorGenesis.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.digest
    }

    /// Returns the committed validator-genesis digest.
    pub const fn validator_digest(&self) -> &[u8; 32] {
        &self.validator_digest
    }

    /// Returns canonical fixed-width InitChain app-state bytes.
    pub fn genesis_app_state_bytes(&self, genesis: &FloorGenesis) -> Result<Vec<u8>> {
        if genesis.profile_digest() != self.as_bytes() {
            return Err(FloorAbciError::InvalidRequest("Floor genesis profile differs"));
        }
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(144)
            .map_err(|_| FloorAbciError::InvalidRequest("genesis app-state allocation failed"))?;
        bytes.extend_from_slice(GENESIS_MAGIC);
        bytes.extend_from_slice(&APPLICATION_VERSION.to_be_bytes());
        bytes.extend_from_slice(self.as_bytes());
        bytes.extend_from_slice(genesis.genesis_digest().as_bytes());
        bytes.extend_from_slice(genesis.registry_digest().as_bytes());
        bytes.extend_from_slice(self.validator_digest());
        if bytes.len() != 144 {
            return Err(FloorAbciError::InvalidRequest(
                "genesis app-state width invariant failed",
            ));
        }
        Ok(bytes)
    }
}
