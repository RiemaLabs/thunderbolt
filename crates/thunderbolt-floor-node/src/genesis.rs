use serde_json::{json, Value};
use tendermint_proto::google::protobuf::Duration as ProtoDuration;
use tendermint_proto::v0_38::types::{
    AbciParams, BlockParams, ConsensusParams, EvidenceParams, ValidatorParams, VersionParams,
};
use thunderbolt_floor_abci::{
    APPLICATION_VERSION, COMET_EVIDENCE_MAX_AGE_BLOCKS, COMET_EVIDENCE_MAX_AGE_SECONDS, COMET_EVIDENCE_MAX_BYTES,
    COMET_MAX_BLOCK_BYTES, COMET_MAX_BLOCK_GAS,
};

use crate::config::ValidatedConfig;
use crate::error::{NodeError, Result};

pub(crate) fn canonical_genesis_json(config: &ValidatedConfig) -> Result<String> {
    let app_state_bytes = config
        .profile()
        .genesis_app_state_bytes(config.genesis())
        .map_err(|_| NodeError::GenesisEncoding)?;
    let app_state: Value = serde_json::from_slice(&app_state_bytes).map_err(|_| NodeError::GenesisEncoding)?;
    if serde_json::to_vec(&app_state).map_err(|_| NodeError::GenesisEncoding)? != app_state_bytes {
        return Err(NodeError::GenesisEncoding);
    }
    let validators = serde_json::to_value(config.comet_validators()).map_err(|_| NodeError::GenesisEncoding)?;
    let document = json!({
        "app_hash": "",
        "app_state": app_state,
        "chain_id": config.comet_chain_id(),
        "consensus_params": consensus_parameters_json()?,
        "genesis_time": config.genesis_time().to_rfc3339(),
        "initial_height": "1",
        "validators": validators,
    });
    let encoded = serde_json::to_string(&document).map_err(|_| NodeError::GenesisEncoding)?;
    let decoded: Value = serde_json::from_str(&encoded).map_err(|_| NodeError::GenesisEncoding)?;
    if decoded != document
        || serde_json::to_vec(&decoded["app_state"]).map_err(|_| NodeError::GenesisEncoding)? != app_state_bytes
    {
        return Err(NodeError::GenesisEncoding);
    }
    Ok(encoded)
}

pub(crate) fn consensus_parameters() -> ConsensusParams {
    ConsensusParams {
        block: Some(BlockParams {
            max_bytes: COMET_MAX_BLOCK_BYTES,
            max_gas: COMET_MAX_BLOCK_GAS,
        }),
        evidence: Some(EvidenceParams {
            max_age_num_blocks: COMET_EVIDENCE_MAX_AGE_BLOCKS,
            max_age_duration: Some(ProtoDuration {
                seconds: COMET_EVIDENCE_MAX_AGE_SECONDS,
                nanos: 0,
            }),
            max_bytes: COMET_EVIDENCE_MAX_BYTES,
        }),
        validator: Some(ValidatorParams {
            pub_key_types: vec!["ed25519".to_owned()],
        }),
        version: Some(VersionParams {
            app: APPLICATION_VERSION,
        }),
        abci: Some(AbciParams {
            vote_extensions_enable_height: 0,
        }),
    }
}

fn consensus_parameters_json() -> Result<Value> {
    let evidence_duration_nanos = COMET_EVIDENCE_MAX_AGE_SECONDS
        .checked_mul(1_000_000_000)
        .map(|value| value.to_string())
        .ok_or(NodeError::GenesisEncoding)?;
    Ok(json!({
        "abci": {
            "vote_extensions_enable_height": "0",
        },
        "block": {
            "max_bytes": COMET_MAX_BLOCK_BYTES.to_string(),
            "max_gas": COMET_MAX_BLOCK_GAS.to_string(),
        },
        "evidence": {
            "max_age_duration": evidence_duration_nanos,
            "max_age_num_blocks": COMET_EVIDENCE_MAX_AGE_BLOCKS.to_string(),
            "max_bytes": COMET_EVIDENCE_MAX_BYTES.to_string(),
        },
        "validator": {
            "pub_key_types": ["ed25519"],
        },
        "version": {
            "app": APPLICATION_VERSION.to_string(),
        },
    }))
}
